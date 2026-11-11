#!/usr/bin/env python3
"""Capture the typed Full-profile two-group frontier; never confer full A03 PASS."""
from __future__ import annotations
import argparse
import base64
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

from boot_reboot_contract import prepare_disk
from check_elf import symbol
from doctor import env
from run_qemu import Qmp
from run_v13_a02 import inject_config
from run_v16_a03_data import WireSocket, close_owned
from transport import FrameDecoder
from verify_v13_boot_recovery import CONFIG_MAGIC, require
from verify_v13_model import loaded_bytes
from v16_a03_full_frontier import (VERSION, BANKS, TOOL_ROOT, sha, write_json, trusted_context,
    frontier_boundary, frontier_deviation, stopped_frontier, fatal_evidence, verify_capture, bounded_inventory, launch_argv)


def finalize_capture(result,label,operation):
    """A failed evidence write invalidates success, including the final summary."""
    try: return operation()
    except Exception as error:
        message=label+': '+str(error)
        result.setdefault('cleanup_errors',[]).append(message)
        result.setdefault('error',message)
        result.update(status='FAIL',frontier_verified=False,capture_complete=False)
        if label=='summary':
            print('Full frontier summary persistence failed: '+message,file=sys.stderr)


def observe(qmp, save, symbols, proc, deadline, decoder, raw, text):
    qmp.execute('cont'); stops = 0; next_serial = 0
    while time.monotonic() < deadline:
        require(proc.poll() is None,'Full frontier process exited before terminal scene')
        if time.monotonic() >= next_serial:
            chunk = base64.b64decode(qmp.execute('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64')),validate=True)
            raw.extend(chunk); require(len(raw) <= 8*1024**2,'Full frontier serial overflow')
            for payload in decoder.feed(chunk): text.extend(payload+b'\n')
            require(not any(x in raw or x in text for x in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')),'Full frontier native fault')
            next_serial = time.monotonic()+1
        live = save('pending-replay.bin',symbols['replay']['pa'],512)
        collection = save('pending-collection.bin',symbols['collection']['pa'],512)
        control = save('pending-control.bin',symbols['control']['pa'],BANKS['control'][1])
        deviation = frontier_deviation(live)
        require(deviation is None,deviation or 'Full frontier deviation')
        fatal_evidence(live,control)
        if frontier_boundary(live,collection) is not None:
            require(stops < 64,'Full frontier stopped probe bound')
            qmp.execute('stop'); require(qmp.execute('query-status')['status'] == 'paused','Full frontier stop not paused')
            stops += 1
            probe = {key:save(f'probe-{stops:02d}-{key}.bin',symbols[key]['pa'],size)
                for key,(_,size) in BANKS.items() if key != 'config'}
            frontier = stopped_frontier(probe)
            if frontier is None:
                qmp.execute('cont'); time.sleep(.1); continue
            for key,value in probe.items():
                require(save(key+'.bin',symbols[key]['pa'],len(value)) == value,'Full frontier stopped bytes changed')
            return dict(stopped_attempts=stops,frontier=frontier)
        time.sleep(.1)
    raise TimeoutError('Full two-group frontier did not close within host window')


def run(build_manifest, output, *, source_root, formatter, qemu_binary, qemu_source, timeout=600):
    require(type(timeout) in (int,float) and 5 <= timeout <= 600,'Full frontier host timeout bound')
    context = trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source)
    paths = {k:Path(v) for k,v in context['paths'].items()}
    output = Path(output).resolve(); require(not output.exists(),'refuse reused Full frontier output')
    output.mkdir(mode=0o700,parents=True)
    result = dict(version=VERSION,status='FAIL',frontier_verified=False,capture_complete=False,
        native_acceptance_status='NOT_RUN',A03_complete=False,model_trained=False,
        accepted_training_sample_verified=False,applied_owner_verified=False)
    proc = sock = qmp = None; started = None
    raw = bytearray(); text = bytearray(); decoder = FrameDecoder(); symbols = context['symbols']
    def save(name,address,size):
        path = output/name
        qmp.execute('pmemsave',dict(val=address,size=size,filename=str(path)))
        value = path.read_bytes(); require(len(value) == size,'short Full frontier physical read')
        return value
    def finish(label, operation):
        return finalize_capture(result,label,operation)
    try:
        write_json(output/'native-context.json',context)
        for name in ('build-manifest.json','base-build-manifest.json'):
            shutil.copyfile(paths['build_manifest'].parent/name,output/name)
        for name in context['artifacts']: shutil.copyfile(paths['build_manifest'].parent/name,output/name)
        for prefix,key,source in (('source-inputs','source_map',paths['source_root']),('producer-tools','tools',TOOL_ROOT)):
            for name in context[key]:
                target = output/prefix/name; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source/name,target)
        write_json(output/'source-manifest.json',context['source_map'])
        image = (output/'node-a.elf').read_bytes(); model = symbol(image,'A02_BOOT_MODEL')
        (output/'model.bin').write_bytes(loaded_bytes(image,model['va'],model['size']))
        uuid = secrets.token_hex(16)
        write_json(output/'formatter-command.json',dict(argv=[str(paths['formatter']),str(output/'disk.raw'),uuid]))
        origin = prepare_disk(output,paths['formatter'],uuid)
        write_json(output/'disk-before.json',dict(bytes=(output/'disk.raw').stat().st_size,sha256=sha(output/'disk.raw')))
        inputs = dict(version=VERSION,mode=0,collection_profile='full',frontier_groups=2,
            nonce=secrets.token_hex(16),disk_uuid=uuid,disk_origin=origin,
            timeout_seconds=timeout,poll_seconds=.1,serial_seconds=1,max_stopped_attempts=64,
            scope='Full profile first two stored groups only; no complete dataset or training authority')
        write_json(output/'input.json',inputs)
        config = struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+bytes.fromhex(inputs['nonce'])+bytes.fromhex(context['artifacts']['node-a.elf'])+bytes.fromhex(sha(output/'input.json'))+bytes.fromhex(sha(output/'source-manifest.json'))+bytes(368)
        (output/'config.bin').write_bytes(config)
        require(trusted_context(**paths) == context,'Full frontier identity changed before spawn')
        with tempfile.TemporaryDirectory(prefix='cyx-a03-full-') as temp, (output/'qemu-stderr.log').open('wb') as errors:
            qpath = str(Path(temp)/'q.sock'); gpath = str(Path(temp)/'g.sock')
            with socket.socket() as listener: listener.bind(('127.0.0.1',0)); port = listener.getsockname()[1]
            argv = launch_argv(paths['qemu_binary'],output,qpath,gpath,port)
            write_json(output/'launch.json',dict(argv=argv,qmp=qpath,gdb=gpath,port=port,symbols=symbols))
            started = time.monotonic_ns(); proc = subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=errors,env=env())
            deadline = time.monotonic()+timeout; connection = socket.socket(socket.AF_UNIX); sock = WireSocket(connection,output)
            while True:
                require(proc.poll() is None and time.monotonic() < deadline,'Full frontier QMP startup failed')
                try: connection.connect(qpath); break
                except (FileNotFoundError,ConnectionRefusedError): time.sleep(.01)
            qmp = Qmp(sock); require('QMP' in qmp.receive(deadline),'missing Full frontier QMP greeting')
            qmp.execute('qmp_capabilities')
            cpus = qmp.execute('query-cpus-fast'); memory = qmp.execute('query-memory-size-summary')
            require(len(cpus) == 4 and memory['base-memory'] == 1024**3,'Full frontier platform mismatch')
            write_json(output/'platform.json',dict(cpus=cpus,memory=memory))
            header = save('dtb-header.bin',0x40000000,40); magic,size = struct.unpack_from('>2I',header)
            require(magic == 0xd00dfeed and 40 <= size <= 2*1024**2,'Full frontier DTB bound')
            save('platform.dtb',0x40000000,size)
            write_json(output/'config-injection.json',inject_config(gpath,config,symbols['config']['pa']))
            require(save('config-observed.bin',symbols['config']['pa'],512) == config,'Full frontier config not observed')
            result['boundary'] = observe(qmp,save,symbols,proc,deadline,decoder,raw,text)
            result['capture_complete'] = True
    except (OSError,ValueError,RuntimeError,TimeoutError,KeyError,struct.error,subprocess.SubprocessError) as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        if qmp is not None and proc is not None and proc.poll() is None:
            if not result['capture_complete']:
                def diagnostic():
                    qmp.execute('stop'); require(qmp.execute('query-status')['status'] == 'paused','ordinary failure guest not paused')
                    for key,(_,size) in BANKS.items():
                        if key != 'config': finish('failure '+key,lambda key=key,size=size:save('failure-'+key+'.bin',symbols[key]['pa'],size))
                finish('failure stopped banks',diagnostic)
            def serial_tail():
                chunk = base64.b64decode(qmp.execute('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64')),validate=True)
                raw.extend(chunk); require(len(raw) <= 8*1024**2,'Full frontier serial overflow')
                for payload in decoder.feed(chunk): text.extend(payload+b'\n')
            finish('final serial',serial_tail)
        process = close_owned(proc,sock,qmp,started_ns=started)
        finish('process exit',lambda:write_json(output/'process-exit.json',process))
        if process['errors'] or process['forced'] or process['returncode'] != 0 or not process['quit_ok'] or not process['eof']:
            result.setdefault('error','Full frontier owned process lacks normal quit/EOF/wait0')
        if qmp: finish('QMP transcript',lambda:write_json(output/'qmp-transcript.json',qmp.transcript))
        finish('raw serial',lambda:(output/'serial.bin').write_bytes(raw))
        finish('decoded serial',lambda:(output/'serial.txt').write_bytes(text))
        if (output/'disk.raw').exists():
            finish('disk custody',lambda:write_json(output/'disk-after.json',dict(bytes=(output/'disk.raw').stat().st_size,sha256=sha(output/'disk.raw'))))
    try:
        require('error' not in result,result.get('error','Full frontier capture failed'))
        require(trusted_context(**paths) == context,'Full frontier identity changed during capture')
        checked = verify_capture(output,**paths,allow_unsaved_exports=True)
        exports = output/'frontier-archives'; exports.mkdir(mode=0o700)
        for name,value in checked.pop('archive_files').items():
            with (exports/name).open('xb') as stream: stream.write(value)
        write_json(exports/'manifest.json',checked.pop('archive_manifest'))
        result['verification'] = verify_capture(output,**paths)
        result['verification'].pop('archive_files'); result['verification'].pop('archive_manifest')
        require(result['verification']['frontier_verified'] is True,'Full frontier independent scene verification incomplete')
        result.update(status='FULL_TWO_GROUP_FRONTIER_VERIFIED',frontier_verified=True)
    except (OSError,ValueError,RuntimeError,KeyError,struct.error,subprocess.SubprocessError) as error:
        result.setdefault('error',type(error).__name__+': '+str(error)); result['status'] = 'FAIL'
    finish('inventory',lambda:result.update(artifacts=bounded_inventory(output)))
    finish('summary',lambda:write_json(output/'summary.json',result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','build-manifest','output','formatter','qemu-binary','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=600)
    args = parser.parse_args(argv)
    result = run(**vars(args))
    print(json.dumps({k:result.get(k) for k in ('status','frontier_verified','native_acceptance_status','error')},indent=2))
    return int(not result['frontier_verified'])


if __name__ == '__main__': sys.exit(main())
