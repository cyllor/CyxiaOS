#!/usr/bin/env python3
"""Exercise normal boot, epoch write/FLUSH refusal and real EL0 model corruption.

Only the fixed preboot config range is written. Stopped physical captures and
raw QMP/serial are retained; no kernel control/authorization result is rewritten.
This regression does not by itself enrol A01 in the formal acceptance catalogue.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from build_unified import code_source_map
from check_elf import inspect_elf, symbol
from run_qemu import Qmp
from run_v13_a02 import inject_config
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, MAGIC, MODES, require, verify_samples

ROOT = Path(__file__).resolve().parents[1]
DEBUG_SYMBOLS = {'model-debug': 'A01_BOOT_MODEL_DEBUG',
                 'control-settlement': 'CONTROL_SETTLEMENT_EVIDENCE',
                 'smp-fault': 'SMP_FAULT_EVIDENCE'}
MODEL_DEBUG_FIELDS = {8: 'steps', 9: 'admissions', 10: 'no_credit', 11: 'admission_error',
    12: 'settlement_busy', 13: 'settlement_error', 14: 'credit_sequence', 15: 'reserved_ns',
    16: 'actual_ns', 17: 'total_cpu_ns', 18: 'finished_ns', 19: 'exit_kind',
    20: 'entry_pc', 21: 'exit_pc', 22: 'model_result', 23: 'terminal_cause',
    24: 'last_admission_ns', 25: 'stage', 26: 'credit_window', 27: 'settlement',
    28: 'bill_pending', 29: 'entry_ns', 30: 'return_ns', 31: 'cpu_before', 32: 'cpu_after',
    48: 'requested_ns', 49: 'cancelled_ns', 50: 'cancel_won'}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def stopped_boot_state(sample, config):
    """Decode a stopped diagnostic only; never returns an acceptance verdict."""
    require(len(sample) == len(config) == 512, 'invalid stopped boot record size')
    words, identity = (struct.unpack('<64Q', value) for value in (sample, config))
    require(identity[:2] == (CONFIG_MAGIC, 1) and identity[2] in MODES.values(),
            'invalid diagnostic config')
    require(words[:2] == (MAGIC, 1) and words[2] % 2 == 0,
            'unsealed stopped boot diagnostic')
    require(words[5] == identity[2] and words[32:46] == identity[4:18],
            'mixed diagnostic boot/source/input/image')
    fields = {2: 'sequence', 3: 'state', 4: 'reason', 5: 'mode', 6: 'epoch',
              7: 'epoch_durable_ticks', 9: 'online_mask', 14: 'model_passed_ticks',
              15: 'active_ticks', 20: 'model_checkpoint_cpu_ns', 21: 'model_exit_kind',
              22: 'model_cpu', 23: 'model_turns', 24: 'model_checkpoint_result'}
    result = {name: words[index] for index, name in fields.items()}
    result['reason_name'] = {0: 'none', 1: 'already-attempted', 2: 'device',
                             3: 'mount', 4: 'epoch', 5: 'model-selftest'}.get(words[4], 'unknown')
    result['scope'] = 'stopped diagnostic, not native acceptance'
    return result


def capture_failure(qmp, save, symbols, config, decoder, raw, text):
    """Best-effort stopped evidence; never masks the original run failure.

    A partially published boot record still has diagnostic bytes worth keeping.
    Its decoder failure must not suppress the other authority buffers or serial.
    This function never resumes the guest, rewrites memory or assigns PASS.
    """
    report, errors = {}, {}
    caught = (OSError, ValueError, RuntimeError, KeyError, TypeError)
    try:
        qmp.execute('stop')
        require(qmp.execute('query-status')['status'] == 'paused', 'failure capture not stopped')
    except caught as error:
        return {'failure_capture_errors': {'stop': str(error)}}
    captures = [('boot', 512), ('control', 4096), ('runtime', 8192), ('unified', 4096)]
    captures += [(key, symbols[key].get('size')) for key in DEBUG_SYMBOLS if key in symbols]
    for key, size in captures:
        try:
            require(type(size) is int and 0 < size <= 8192 and size % 8 == 0,
                    'invalid diagnostic buffer size')
            sample = save('failure-' + key + '.bin', symbols[key]['pa'], size)
            if key == 'boot':
                report['failure_capture'] = stopped_boot_state(sample, config)
            elif key in DEBUG_SYMBOLS:
                require(len(sample) == size, 'short diagnostic buffer')
                words = struct.unpack('<' + str(size // 8) + 'Q', sample)
                details = {'words': list(words), 'scope': 'stopped diagnostic, not acceptance'}
                if key == 'model-debug' and len(words) == 64:
                    details['fields'] = {name: words[index] for index, name in MODEL_DEBUG_FIELDS.items()}
                report.setdefault('failure_diagnostics', {})[key] = details
        except caught as error:
            errors[key] = str(error)
    try:
        chunk = base64.b64decode(qmp.execute('ringbuf-read',
            dict(device='cyxlog', size=1048576, format='base64')), validate=True)
        require(len(raw) + len(chunk) <= 8*1024*1024, 'failure serial capture overflow')
        raw.extend(chunk)
        for payload in decoder.feed(chunk):
            text.extend(payload + b'\n')
    except caught as error:
        errors['serial'] = str(error)
    if errors:
        report['failure_capture_errors'] = errors
    return report


def run_case(build, output, formatter, qemu, qemu_source, mode, timeout):
    output.mkdir(parents=True, exist_ok=False)
    sources = code_source_map(ROOT)
    manifest = json.loads((build/'build-manifest.json').read_text())
    require(manifest['profiles']['selftest'] is True and manifest['profiles']['fault'] == 'normal'
            and manifest['profiles'].get('service_fault', 'none') == 'none'
            and not manifest['profiles'].get('storage_fault', False), 'wrong native build profile')
    require(manifest['code_source_map'] == sources
            and manifest['builder_sha256'] == sha(ROOT/'tools/build_unified.py'), 'source/build mismatch')
    image = build/'node-a.elf'
    require(sha(image) == manifest['artifacts']['node-a.elf']['sha256'], 'image hash mismatch')
    data = image.read_bytes(); inspect_elf(data)
    names = {'boot': 'A01_BOOT_EVIDENCE', 'config': 'A01_BOOT_CONFIG',
             'control': 'DOMAIN_CONTROL_EVIDENCE', 'runtime': 'RUNTIME_V13_EVIDENCE',
             'unified': 'UNIFIED_EVIDENCE'}
    symbols = {k: symbol(data, v) for k, v in names.items()}
    require(symbols['boot']['size'] == symbols['config']['size'] == 512, 'wrong capture layout')
    shutil.copyfile(image, output/'node-a.elf')
    shutil.copyfile(build/'build-manifest.json', output/'build-manifest.json')
    write_json(output/'source-manifest.json', sources)
    nonce = secrets.token_bytes(16)
    write_json(output/'input.json', dict(scope='A01-boot-recovery-regression', mode=mode,
               nonce=nonce.hex(), timeout_seconds=timeout, sample_gap_seconds=.5))
    config = (struct.pack('<4Q', CONFIG_MAGIC, 1, mode, 0) + nonce
              + bytes.fromhex(sha(image)) + bytes.fromhex(sha(output/'input.json'))
              + bytes.fromhex(sha(output/'source-manifest.json')) + bytes(368))
    require(len(config) == 512, 'config size')
    (output/'config.bin').write_bytes(config)
    write_json(output/'tools.json', attest_qemu(str(qemu), qemu_source))
    disk = output/'disk.raw'
    formatted = subprocess.run([str(formatter), str(disk), secrets.token_hex(16)],
                               capture_output=True, timeout=60, check=True)
    (output/'format.log').write_bytes(formatted.stdout+formatted.stderr)
    write_json(output/'disk-before.json', dict(sha256=sha(disk), bytes=disk.stat().st_size))
    decoder, raw, text = FrameDecoder(), bytearray(), bytearray()
    proc = sock = qmp = None
    result = dict(status='FAIL', mode=mode, native_acceptance_status='NOT_RUN')

    def save(name, address, size):
        dest = output/name
        qmp.execute('pmemsave', dict(val=address, size=size, filename=str(dest)))
        return dest.read_bytes()

    try:
        with tempfile.TemporaryDirectory(prefix='cyx-boot-') as temp, (output/'qemu-stderr.log').open('wb') as errors:
            qpath, gpath = str(Path(temp)/'q.sock'), str(Path(temp)/'g.sock')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
            argv = [str(qemu), '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                '-drive', f'if=none,id=disk0,format=raw,file={disk},cache=writeback',
                '-device', 'virtio-blk-device,drive=disk0',
                '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
                '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
                '-object', 'rng-random,id=rng0,filename=/dev/urandom',
                '-device', 'virtio-rng-device,rng=rng0',
                '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                '-qmp', f'unix:{qpath},server=on,wait=off', '-gdb', f'unix:{gpath},server=on,wait=off',
                '-kernel', str(output/'node-a.elf'), '-no-reboot']
            write_json(output/'launch.json', dict(argv=argv, symbols=symbols))
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors)
            end = time.monotonic()+timeout
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None and time.monotonic()<end, 'QMP startup failed')
                try: sock.connect(qpath); break
                except (FileNotFoundError, ConnectionRefusedError): time.sleep(.01)
            qmp = Qmp(sock); require('QMP' in qmp.receive(end), 'no QMP greeting')
            qmp.execute('qmp_capabilities')
            cpus = qmp.execute('query-cpus-fast'); memory=qmp.execute('query-memory-size-summary')
            require(len(cpus)==4 and memory['base-memory']==1024**3, 'platform mismatch')
            write_json(output/'platform.json', dict(cpus=cpus, memory=memory))
            header = save('dtb-header.bin', 0x40000000, 40)
            magic, size = struct.unpack_from('>2I', header)
            require(magic==0xd00dfeed and 40<=size<=2*1024*1024, 'bad DTB')
            save('platform.dtb', 0x40000000, size)
            write_json(output/'config-injection.json', inject_config(gpath,config,symbols['config']['pa']))
            require(save('config-observed.bin', symbols['config']['pa'],512)==config, 'config not observed')
            qmp.execute('cont')
            first = None; second_at = None
            while time.monotonic()<end:
                require(proc.poll() is None, 'guest exited')
                chunk=base64.b64decode(qmp.execute('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64')),validate=True)
                raw.extend(chunk)
                require(len(raw)<=8*1024*1024, 'serial capture overflow')
                for payload in decoder.feed(chunk): text.extend(payload+b'\n')
                require(not any(x in text for x in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')), 'native boot fault')
                probe=save('pending-boot.bin',symbols['boot']['pa'],512)
                words=struct.unpack('<64Q',probe)
                target=3 if mode==0 else 2
                progressed=mode==0 or words[10]>0 and words[11]>0
                if (words[0]==MAGIC and words[3] in (2, 3) and words[2]%2==0
                        and (words[3]!=target or progressed)):
                    if first is None or time.monotonic()>=second_at:
                        qmp.execute('stop')
                        require(qmp.execute('query-status')['status']=='paused','capture not stopped')
                        name='first.bin' if first is None else 'last.bin'
                        sample=save(name,symbols['boot']['pa'],512)
                        if struct.unpack('<64Q',sample)[2]%2:
                            qmp.execute('cont'); time.sleep(.005); continue
                        diagnostic = stopped_boot_state(sample, config)
                        if diagnostic['state'] != target:
                            result['diagnostics'] = diagnostic
                            raise RuntimeError('unexpected boot terminal: '
                                f"state={diagnostic['state']} expected={target} "
                                f"reason={diagnostic['reason_name']}({diagnostic['reason']})")
                        if first is None:
                            first=sample; second_at=time.monotonic()+.5
                            qmp.execute('cont')
                        else:
                            control=save('control.bin',symbols['control']['pa'],4096)
                            runtime=save('runtime.bin',symbols['runtime']['pa'],8192)
                            unified=save('unified.bin',symbols['unified']['pa'],4096)
                            decoded=verify_samples(first,sample,control,runtime,unified,config)
                            require(code_source_map(ROOT)==sources and sha(image)==sha(output/'node-a.elf'), 'source drift')
                            require(decoder.loss==decoder.corrupt==0,'serial loss/corruption')
                            result.update(status='PASS', observations=decoded)
                            break
                time.sleep(.01)
            else: raise TimeoutError('boot recovery did not reach the required state/progress')
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        result['error']=str(error)
    finally:
        if qmp and result['status'] != 'PASS' and proc is not None and proc.poll() is None:
            diagnostic_symbols = dict(symbols)
            for key, name in DEBUG_SYMBOLS.items():
                try:
                    diagnostic_symbols[key] = symbol(data, name)
                except (KeyError, ValueError) as error:
                    result.setdefault('failure_symbol_errors', {})[key] = str(error)
            result.update(capture_failure(qmp, save, diagnostic_symbols, config, decoder, raw, text))
        if qmp:
            try: qmp.execute('quit')
            except Exception: pass
            write_json(output/'qmp-transcript.json', qmp.transcript)
        if proc:
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
        if sock: sock.close()
        (output/'serial.bin').write_bytes(raw); (output/'serial.txt').write_bytes(text)
        result['files']={p.name:dict(bytes=p.stat().st_size,sha256=sha(p)) for p in output.iterdir() if p.is_file()}
        write_json(output/'summary.json',result)
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','output','formatter','qemu','qemu-source'):
        p.add_argument('--'+name, required=True,type=Path)
    p.add_argument('--timeout',type=float,default=30)
    a=p.parse_args(argv)
    require(5<=a.timeout<=120,'invalid bounded timeout')
    paths={k: v.resolve() if isinstance(v,Path) else v for k,v in vars(a).items()}
    root=paths['output']; root.mkdir(parents=True,exist_ok=False)
    report={'scope':'A01 native boot recovery regression; not formal A01 acceptance', 'cases':{}}
    for name,mode in MODES.items():
        try:
            report['cases'][name]=run_case(paths['build'],root/name,paths['formatter'],paths['qemu'],paths['qemu_source'],mode,a.timeout)
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            report['cases'][name]=dict(status='FAIL',error=str(error),native_acceptance_status='NOT_RUN')
        write_json(root/'summary.json',report)
    report['status']='PASS' if all(x['status']=='PASS' for x in report['cases'].values()) else 'FAIL'
    write_json(root/'summary.json',report)
    print(json.dumps({name:case['status'] for name,case in report['cases'].items()},indent=2))
    return int(report['status']!='PASS')

if __name__=='__main__':
    sys.exit(main())
