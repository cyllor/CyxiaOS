#!/usr/bin/env python3
"""Execute A02 against a selftest-enabled unified image and capture EL1 memory.

The fixture module tests the decoder only. This runner owns the QEMU process,
injects only frozen run identities before boot, and takes the sealed stream and
independent counters from stopped physical memory. It never rewrites captures.
The 1 MiB trace reservation is kernel test instrumentation, outside the control
pool. This permission case does not certify training, throughput or A03/A04.
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
import tempfile
import time

from build_unified import code_source_map
from verify_unified import attest_qemu
from check_elf import boot_profile, inspect_elf, symbol
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import ROOT, require, sha
from verify_v13_a02 import verify, verify_native_receipt, execution_flags, MAX_EVENTS, TRACE_MAGIC
from check_prototype_evidence import read_json
from verify_v13_model import loaded_bytes
from check_v13_disk import inspect as inspect_disk


def config_bytes(image_hash: str, input_hash: str, source_hash: str, nonce: bytes) -> bytes:
    require(len(nonce) == 16 and any(nonce), 'invalid run nonce')
    hashes = []
    for value in (image_hash, input_hash, source_hash):
        require(isinstance(value, str) and len(value) == 64
                and set(value) <= set('0123456789abcdef') and value != '0' * 64,
                'invalid artifact digest')
        hashes.append(bytes.fromhex(value))
    return struct.pack('<2Q', 0x4359584130324346, 2) + nonce + b''.join(hashes) + bytes(384)


def config_write_packet(config: bytes, address: int) -> bytes:
    require(len(config) == 512 and address > 0 and address % 8 == 0, 'invalid config injection')
    payload = f'M{address:x},200:{config.hex()}'.encode('ascii')
    return b'$' + payload + f'#{sum(payload) % 256:02x}'.encode('ascii')


def inject_config(endpoint: str, config: bytes, address: int) -> dict:
    # The VM has not executed its first instruction (-S); MMU is off. Only
    # this exact configuration range is written, never trace/counters/code.
    packet = config_write_packet(config, address)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as debugger:
        debugger.settimeout(5)
        debugger.connect(endpoint)
        debugger.sendall(packet)
        received = bytearray()
        while b'$OK#9a' not in received:
            chunk = debugger.recv(4096)
            require(chunk and len(received) + len(chunk) <= 4096, 'preboot debugger write failed')
            received.extend(chunk)
            require(b'-' not in received and b'$E' not in received, 'debugger rejected config write')
        require(bytes(received).lstrip(b'+') == b'$OK#9a', 'unexpected preboot debugger response')
        debugger.sendall(b'+')
    return dict(request_hex=packet.hex(), received_hex=bytes(received).hex(), ack_hex='2b')


def profile(image: bytes) -> dict:
    inspect_elf(image)
    require(boot_profile(image)['ram_mib'] == 1024, 'A02 requires 1 GiB unified image')
    config = symbol(image, 'A02_CONFIG')
    capture = symbol(image, 'A02_CAPTURE')
    layout = symbol(image, 'A02_CAPTURE_LAYOUT')
    require(config['size'] == 512 and layout['size'] == 64, 'invalid native capture symbols')
    words = struct.unpack('<8Q', loaded_bytes(image, layout['va'], layout['size']))
    require(words[0] == 2 and 0 < words[1] <= MAX_EVENTS and words[2] >= 64
            and words[3:5] == (512, 128) and words[5] == 512 + words[1] * 128
            and words[6] == 512 and words[7] == capture['size'], 'invalid native capture layout')
    model = symbol(image, 'A02_BOOT_MODEL')
    require(model['size'] == 2772, 'invalid model artifact')
    return dict(config=config, capture=capture, counter_offset=words[5], max_events=words[1],
                instrumentation_bytes=capture['size'] + 512, model=model,
                control=symbol(image, 'DOMAIN_CONTROL_EVIDENCE'),
                control_credit=symbol(image, 'CONTROL_CREDIT_EVIDENCE'),
                task_overrun=symbol(image, 'TASK_OVERRUN_EVIDENCE'))


def _json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(build: Path, output: Path, formatter: Path, timeout: float = 90, *,
        qemu: Path | None = None, qemu_source: Path | None = None) -> dict:
    require(5 <= timeout <= 300, 'invalid bounded runtime')
    build = build.resolve(strict=True)
    output = output.resolve()
    formatter = formatter.resolve(strict=True)
    require(not output.exists(), 'refuse to reuse evidence output')
    output.mkdir(parents=True, mode=0o700)
    manifest = read_json(build / 'build-manifest.json')
    require(manifest.get('schema_version') == 1 and manifest.get('status') == 'BUILT_NOT_RUN'
            and manifest['profiles']['fault'] == 'normal' and manifest['profiles']['selftest'] is True,
            'A02 requires the normal unified build with its ordinary EL0 client enabled')
    sources = code_source_map()
    require(manifest['code_source_map'] == sources, 'image/source build provenance mismatch')
    require(manifest['builder_sha256'] == sha(ROOT / 'tools/build_unified.py'), 'native builder revision changed')
    require({'cargo', 'rustc', 'clang'} <= manifest['tools'].keys(), 'missing build tool provenance')
    image = build / 'node-a.elf'
    require(manifest['artifacts'][image.name]['sha256'] == sha(image), 'image differs from build')
    layout = profile(image.read_bytes())
    for name in ('node-a.elf', 'service-a.elf', 'task.elf', 'build-manifest.json'):
        shutil.copyfile(build / name, output / name)
    _json(output / 'source-manifest.json', sources)
    nonce = secrets.token_bytes(16)
    _json(output / 'input.json', dict(test_id='A02', specification='1.3',
        clause=['14.1/A02', '13/I1', '1.2', '14.4'], seed=nonce.hex(),
        injection='ordinary EL0 prototype-client syscall21, requested affinity=2',
        expected='E_AUTH; no business entry on C/T/Q', clock='wallclock',
        max_trace_events=layout['max_events'], instrumentation_bytes=layout['instrumentation_bytes']))
    (output / 'config.bin').write_bytes(config_bytes(sha(image), sha(output / 'input.json'),
                                      sha(output / 'source-manifest.json'), nonce))
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                 'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs'):
        source = ROOT / name
        if source.is_file():
            target = output / 'build-inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    for name in ('run_v13_a02.py', 'verify_v13_a02.py'):
        shutil.copyfile(ROOT / 'tools' / name, output / name)
    model = layout['model']
    (output / 'model.bin').write_bytes(loaded_bytes(image.read_bytes(), model['va'], model['size']))
    report = dict(test_id='A02', status='FAIL', native_acceptance_status='NOT_RUN',
                  **execution_flags(False), native_runner_available=True,
                  verifier_version='a02-native-v4', run_nonce=nonce.hex(),
                  scope='A02 affinity authorization and complete EL0 scheduling trace',
                  clock_profile='wallclock', full_v13_acceptance=False)
    qmp = sock = proc = None
    raw, serial = bytearray(), bytearray()
    decoder = FrameDecoder()
    argv = []
    started = time.monotonic()
    try:
        disk = output / 'disk.raw'
        filesystem_id = secrets.token_hex(16)
        formatted = subprocess.run([str(formatter), str(disk), filesystem_id],
                                  capture_output=True, check=True, timeout=30)
        (output / 'format.log').write_bytes(formatted.stdout + formatted.stderr)
        require(disk.stat().st_size == 512 * 1024 * 1024, 'disk size mismatch')
        # A newly formatted volume has no allocated BootEpoch yet. The durable
        # decoder deliberately rejects epoch zero; decode after the real boot.
        _json(output / 'disk-before.json', dict(sha256=sha(disk), boot_epoch=0, uuid=filesystem_id))
        binary = str(qemu.resolve(strict=True)) if qemu is not None else shutil.which('qemu-system-aarch64')
        require(binary is not None, 'QEMU is missing')
        qemu_identity = attest_qemu(binary, qemu_source)
        if qemu_identity['qemu_pmu_patch_attested']:
            qemu_identity['qemu_source_directory'] = str(qemu_source.resolve(strict=True))
        _json(output / 'tools.json', dict(**qemu_identity,
              formatter_sha256=sha(formatter), build_tools=manifest['tools']))
        with tempfile.TemporaryDirectory(prefix='cyx-a02-') as temporary, \
                (output / 'qemu-stderr.log').open('wb') as errors:
            endpoint = str(Path(temporary) / 'q.sock')
            debugger_endpoint = str(Path(temporary) / 'g.sock')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            argv = [binary, '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                '-drive', f'if=none,id=disk0,format=raw,file={disk},cache=writeback',
                '-device', 'virtio-blk-device,drive=disk0',
                '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
                '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
                '-object', 'rng-random,id=rng0,filename=/dev/urandom',
                '-device', 'virtio-rng-device,rng=rng0',
                '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                '-qmp', f'unix:{endpoint},server=on,wait=off',
                '-gdb', f'unix:{debugger_endpoint},server=on,wait=off',
                '-kernel', str(output / 'node-a.elf'),
                '-no-reboot']
            _json(output / 'launch.json', dict(argv=argv, symbols=layout))
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors)
            deadline = time.monotonic() + timeout
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None, 'QEMU exited before handshake')
                if time.monotonic() >= deadline: raise TimeoutError('QMP startup deadline')
                try: sock.connect(endpoint); break
                except (FileNotFoundError, ConnectionRefusedError): time.sleep(.01)
            qmp = Qmp(sock)
            require('QMP' in qmp.receive(deadline), 'missing QMP greeting')
            qmp.execute('qmp_capabilities')
            cpus = qmp.execute('query-cpus-fast')
            memory = qmp.execute('query-memory-size-summary')
            require(len(cpus) == 4 and memory['base-memory'] == 1024 ** 3, 'wrong platform')
            _json(output / 'platform.json', dict(cpus=cpus, memory=memory))
            def save(name, address, size):
                path = output / name
                qmp.execute('pmemsave', dict(val=address, size=size, filename=str(path)))
                return path.read_bytes()
            dtb = save('dtb-header.bin', 0x40000000, 40)
            magic, size = struct.unpack_from('>2I', dtb)
            require(magic == 0xd00dfeed and 40 <= size <= 2 * 1024 * 1024, 'invalid guest DTB')
            save('platform.dtb', 0x40000000, size)
            _json(output / 'config-injection.json', inject_config(debugger_endpoint,
                  (output / 'config.bin').read_bytes(), layout['config']['pa']))
            require(save('config-observed.bin', layout['config']['pa'], 512)
                    == (output / 'config.bin').read_bytes(), 'preboot injection not observed')
            qmp.execute('cont')
            while time.monotonic() < deadline:
                require(proc.poll() is None, 'QEMU exited during A02')
                chunk = base64.b64decode(qmp.execute('ringbuf-read',
                    dict(device='cyxlog', size=1048576, format='base64')), validate=True)
                raw.extend(chunk)
                require(len(raw) <= 8 * 1024 * 1024, 'serial limit exceeded')
                for payload in decoder.feed(chunk): serial.extend(payload + b'\n')
                require(not any(word in serial for word in (b'PANIC', b'SMP_ERROR', b'FAIL')),
                        'native guest reported failure')
                # A live header read is only a seal probe. Pausing every poll
                # would contaminate the guest's real wallclock budget windows.
                header = struct.unpack('<64Q', save('pending-header.bin', layout['capture']['pa'], 512))
                if header[0] == TRACE_MAGIC and header[5] == 2:
                    qmp.execute('stop')
                    require(qmp.execute('query-status')['status'] == 'paused', 'guest did not stop for capture')
                    require(0 < header[3] <= layout['max_events'], 'invalid sealed event count')
                    trace = save('trace.bin', layout['capture']['pa'], 512 + 128 * header[3])
                    counters = save('counters.bin', layout['capture']['pa'] + layout['counter_offset'], 512)
                    control = save('control-header.bin', layout['control']['pa'], 4096)
                    credit = save('control-credit.bin', layout['control_credit']['pa'], layout['control_credit']['size'])
                    overrun = save('task-overrun.bin', layout['task_overrun']['pa'], layout['task_overrun']['size'])
                    report['other_runtime_diagnostics'] = dict(
                        control_credit_failure_observed=bool(struct.unpack_from('<2Q', credit)[1]),
                        task_overrun_words=list(struct.unpack('<32Q', overrun)))
                    observation = verify(trace, counters, image_sha256=sha(output / 'node-a.elf'),
                        input_sha256=sha(output / 'input.json'), source_sha256=sha(output / 'source-manifest.json'))
                    require(trace[56:72] == nonce, 'capture run nonce mismatch')
                    words = struct.unpack_from('<25Q', control)
                    require(words[0] == 0x435958444f4d3031 and words[2] == header[6]
                            and control[128:160].hex() == sha(output / 'model.bin')
                            and control[160:192].hex() == sources['crates/prototype/src/features.rs'],
                            'native model/schema/boot identity mismatch')
                    require(code_source_map() == sources and sha(image) == sha(output / 'node-a.elf'),
                            'source or image changed during native execution')
                    require(decoder.loss == decoder.corrupt == 0, 'serial transport loss/corruption')
                    report.update(status='PASS', native_acceptance_status='PASS', **execution_flags(False),
                                  observations=observation, boot_epoch=header[6], model_sha256=sha(output / 'model.bin'),
                                  schema_sha256=control[160:192].hex())
                    break
                time.sleep(.05)
            else: raise TimeoutError('no sealed native A02 capture before deadline')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, struct.error, KeyError) as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        if proc is not None and proc.poll() is None:
            try:
                if qmp: qmp.execute('quit')
            except (OSError, ValueError, RuntimeError): pass
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=2)
        if sock: sock.close()
        if qmp:
            (output / 'qmp.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in qmp.transcript))
        (output / 'serial.bin').write_bytes(raw)
        (output / 'serial.txt').write_bytes(serial)
        report['qemu_exit'] = proc.returncode if proc else None
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if report['status'] == 'PASS':
        try:
            durable = inspect_disk(output / 'disk.raw')
            require(durable['boot_epoch'] == report['boot_epoch'], 'durable epoch differs from captured boot')
            report['durable_disk'] = durable
        except (OSError, ValueError) as error:
            report.update(status='FAIL', native_acceptance_status='NOT_RUN', **execution_flags(False),
                          error=str(error))
    report['artifacts'] = {str(p.relative_to(output)): sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    _json(output / 'summary.json', report)
    if report['status'] == 'PASS':
        try:
            report['independent_receipt'] = verify_native_receipt(output, qemu_source=qemu_source)
            report.update(execution_flags(True))
        except (OSError, ValueError, KeyError, struct.error) as error:
            report.update(status='FAIL', native_acceptance_status='NOT_RUN', **execution_flags(False),
                          error=f'independent native receipt: {error}')
        _json(output / 'summary.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--formatter', required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=90)
    parser.add_argument('--qemu', type=Path, help='explicit pinned QEMU binary')
    parser.add_argument('--qemu-source', type=Path, help='exact source for the pinned PMU-patched build')
    args = parser.parse_args()
    try:
        result = run(args.build, args.output, args.formatter, args.timeout,
                     qemu=args.qemu, qemu_source=args.qemu_source)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'PASS' else 1
    except (OSError, ValueError, KeyError) as error:
        print(f'a02-runner: {error}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
