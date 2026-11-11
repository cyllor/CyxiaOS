#!/usr/bin/env python3
"""Capture the unchanged dual-node Full collection and native validation handoff."""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import fcntl
import json
import math
import os
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
from v16_a03_full_collection import (VERSION, BANKS, LIVE_BANKS, POLL_SECONDS,
    TIMEOUT_DEFAULT, MAX_TIMEOUT, MAX_SERIAL_BYTES, trusted_context, launch_argv,
    terminal_hint, terminal_boundary, fatal_evidence, progress_snapshot,
    verify_capture, bounded_inventory, sha, write_json)


TOOL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NATIVE_LOCK = TOOL_ROOT/'artifacts/v016-focus-a03-a10-20261109-r9/native-session.lock'
MAX_STOPPED_ATTEMPTS = 64
NODES = ('a','b')


@dataclass
class Guest:
    node: str
    folder: Path
    symbols: dict
    proc: object = None
    sock: object = None
    qmp: object = None
    started_ns: int | None = None
    decoder: FrameDecoder = field(default_factory=FrameDecoder)
    raw: bytearray = field(default_factory=bytearray)
    text: bytearray = field(default_factory=bytearray)

    def save(self, name, address, size):
        path = self.folder/name
        self.qmp.execute('pmemsave',dict(val=address,size=size,filename=str(path)))
        value = path.read_bytes()
        require(len(value) == size,'short Full collection physical read: '+self.node+'/'+name)
        return value


def fail_capture(result, message):
    result.setdefault('error',message)
    result.update(status='FAIL',capture_complete=False,full_collection_verified=False,
        validation_handoff_observed=False)


def finalize_capture(result, label, operation):
    """Preserve the first error while a failed evidence write revokes success."""
    try:
        return operation()
    except Exception as error:
        message=label+': '+str(error)
        result.setdefault('cleanup_errors',[]).append(message)
        fail_capture(result,message)
        if label == 'summary':
            print('Full collection summary persistence failed: '+message,file=sys.stderr)


def atomic_json(path, value):
    temporary=path.with_name(path.name+'.tmp')
    with temporary.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,sort_keys=True,indent=2,allow_nan=False)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())
    temporary.replace(path)


@contextmanager
def native_lease(path):
    path=Path(path)
    require(path.parent.is_dir() and not path.is_symlink(),'Full collection native lock parent/target')
    flags=os.O_RDWR|os.O_CREAT|os.O_APPEND|getattr(os,'O_NOFOLLOW',0)
    with os.fdopen(os.open(path,flags,0o600),'a') as lease:
        fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield


def idle_native_host():
    rows=subprocess.run(['ps','-axo','pid=,comm='],capture_output=True,text=True,check=True).stdout
    busy=[row.strip() for row in rows.splitlines() if row.split()
        and Path(row.strip().split(None,1)[-1]).name in
            ('qemu-system-aarch64','cargo','rustc','clang')]
    require(not busy,'Full collection native/build exclusion: '+repr(busy))


def pause_all(guests):
    """Issue every stop before any status query or diagnostic physical read."""
    available=[];paused=set();errors=[]
    for guest in guests:
        try:
            if guest.qmp is not None and guest.proc is not None and guest.proc.poll() is None:
                available.append(guest)
        except Exception as error:
            errors.append(guest.node+' process poll: '+str(error))
    for guest in available:
        try:
            guest.qmp.execute('stop')
        except Exception as error:
            errors.append(guest.node+' stop: '+str(error))
    for guest in available:
        try:
            require(guest.qmp.execute('query-status')['status'] == 'paused',
                'Full collection guest not paused: '+guest.node)
            paused.add(guest.node)
        except Exception as error:
            errors.append(guest.node+' query-status: '+str(error))
    return paused,errors


def drain_serial(guest):
    chunk=base64.b64decode(guest.qmp.execute('ringbuf-read',
        dict(device='cyxlog',size=1048576,format='base64')),validate=True)
    guest.raw.extend(chunk)
    require(len(guest.raw) <= MAX_SERIAL_BYTES,'Full collection serial overflow: '+guest.node)
    for payload in guest.decoder.feed(chunk):guest.text.extend(payload+b'\n')
    require(not any(value in guest.raw or value in guest.text
        for value in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')),
        'Full collection native fault: '+guest.node)


def observe(guests, deadline, *, until='validated', progress=None):
    """Live banks are hints; both stopped guests own every terminal capture."""
    require(tuple(guest.node for guest in guests) == NODES,'Full collection requires both ordered nodes')
    require(until in ('validated','collected'),'unsupported Full collection terminal')
    stopped=0;previous=None
    try:
        for guest in guests:guest.qmp.execute('cont')
        while time.monotonic() < deadline:
            live={}
            for guest in guests:
                require(guest.proc.poll() is None,'Full collection process exited: '+guest.node)
                drain_serial(guest)
                live[guest.node]={key:guest.save('pending-'+key+'.bin',guest.symbols[key]['pa'],size)
                    for key,size in LIVE_BANKS.items()}
                fatal_evidence(live[guest.node])
            state=dict(version=VERSION,until=until,stopped_attempts=stopped,
                nodes={node:progress_snapshot(live[node]) for node in NODES})
            if state != previous:
                if progress is not None:progress(state)
                previous=state
            if terminal_hint(live['a'],until) is not None:
                require(stopped < MAX_STOPPED_ATTEMPTS,'Full collection stopped probe bound')
                paused,errors=pause_all(guests)
                require(not errors and paused == set(NODES),
                    'Full collection stop-all failed: '+repr(errors))
                stopped+=1;probes={}
                for guest in guests:
                    probes[guest.node]={key:guest.save(f'probe-{stopped:02d}-{key}.bin',
                        guest.symbols[key]['pa'],size)
                        for key,(_,size) in BANKS.items()}
                for guest in guests:
                    for key,value in probes[guest.node].items():
                        require(guest.save(f'probe-{stopped:02d}-confirm-{key}.bin',
                            guest.symbols[key]['pa'],len(value)) == value,
                            'Full collection stopped bytes changed: '+guest.node+'/'+key)
                    fatal_evidence(probes[guest.node])
                boundary=terminal_boundary(probes['a'],until)
                if boundary is not None:
                    for guest in guests:
                        for key,value in probes[guest.node].items():
                            (guest.folder/(key+'.bin')).write_bytes(value)
                    return dict(stopped_attempts=stopped,until=until,terminal=boundary)
                for guest in guests:guest.qmp.execute('cont')
            time.sleep(min(POLL_SECONDS,max(0,deadline-time.monotonic())))
        raise TimeoutError('Full collection did not reach '+until+' within host window')
    except BaseException:
        pause_all(guests)
        raise


def prepare_capture(output, context, paths, *, timeout, until):
    write_json(output/'native-context.json',context)
    write_json(output/'capture.json',dict(version=VERSION,until=until,timeout_seconds=timeout,nodes=list(NODES)))
    for name in ('build-manifest.json','base-build-manifest.json'):
        shutil.copyfile(paths['build_manifest'].parent/name,output/name)
    for name in context['artifacts']:
        shutil.copyfile(paths['build_manifest'].parent/name,output/name)
    for prefix,key,source in (('source-inputs','source_map',paths['source_root']),
            ('producer-tools','tools',TOOL_ROOT)):
        for name in context[key]:
            target=output/prefix/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source/name,target)
    write_json(output/'source-manifest.json',context['source_map'])
    guests=[];nonces=set();uuids=set()
    for node in NODES:
        folder=output/('node-'+node);folder.mkdir(mode=0o700)
        guest=Guest(node,folder,context['node_symbols'][node]);guests.append(guest)
        image_name='node-'+node+'.elf';shutil.copyfile(output/image_name,folder/image_name)
        image=(folder/image_name).read_bytes();model=symbol(image,'A02_BOOT_MODEL')
        (folder/'model.bin').write_bytes(loaded_bytes(image,model['va'],model['size']))
        uuid=secrets.token_hex(16);nonce=secrets.token_hex(16)
        require(uuid not in uuids and nonce not in nonces,'Full collection duplicate node identity')
        uuids.add(uuid);nonces.add(nonce)
        write_json(folder/'formatter-command.json',dict(argv=[str(paths['formatter']),str(folder/'disk.raw'),uuid]))
        origin=prepare_disk(folder,paths['formatter'],uuid)
        write_json(folder/'disk-before.json',dict(bytes=(folder/'disk.raw').stat().st_size,sha256=sha(folder/'disk.raw')))
        inputs=dict(version=VERSION,until=until,timeout_seconds=timeout,poll_seconds=POLL_SECONDS,
            serial_seconds=POLL_SECONDS,max_stopped_attempts=MAX_STOPPED_ATTEMPTS,
            nonce=nonce,disk_uuid=uuid,disk_origin=origin,mode=0,collection_profile='full',node=node)
        write_json(folder/'input.json',inputs)
        config=(struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+bytes.fromhex(nonce)
            +bytes.fromhex(context['artifacts'][image_name])+bytes.fromhex(sha(folder/'input.json'))
            +bytes.fromhex(sha(output/'source-manifest.json'))+bytes(368))
        (folder/'config.bin').write_bytes(config)
    return guests


def launch_guest(guest, paths, temp, port, deadline, errors):
    qpath=str(Path(temp)/(guest.node+'q.sock'));gpath=str(Path(temp)/(guest.node+'g.sock'))
    argv=launch_argv(paths['qemu_binary'],guest.folder,qpath,gpath,port,guest.node)
    write_json(guest.folder/'launch.json',dict(argv=argv,qmp=qpath,gdb=gpath,port=port,symbols=guest.symbols))
    guest.started_ns=time.monotonic_ns()
    guest.proc=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=errors,env=env())
    connection=socket.socket(socket.AF_UNIX)
    guest.sock=WireSocket(connection,guest.folder)
    while True:
        require(guest.proc.poll() is None and time.monotonic() < deadline,
            'Full collection QMP startup failed: '+guest.node)
        try:
            connection.connect(qpath);break
        except (FileNotFoundError,ConnectionRefusedError):time.sleep(.01)
    guest.qmp=Qmp(guest.sock)
    require('QMP' in guest.qmp.receive(deadline),'missing Full collection QMP greeting: '+guest.node)
    guest.qmp.execute('qmp_capabilities')
    cpus=guest.qmp.execute('query-cpus-fast');memory=guest.qmp.execute('query-memory-size-summary')
    require(len(cpus) == 4 and memory['base-memory'] == 1024**3,
        'Full collection platform mismatch: '+guest.node)
    write_json(guest.folder/'platform.json',dict(cpus=cpus,memory=memory))
    header=guest.save('dtb-header.bin',0x40000000,40);magic,size=struct.unpack_from('>2I',header)
    require(magic == 0xd00dfeed and 40 <= size <= 2*1024**2,'Full collection DTB bound')
    guest.save('platform.dtb',0x40000000,size)
    config=(guest.folder/'config.bin').read_bytes()
    write_json(guest.folder/'config-injection.json',inject_config(gpath,config,guest.symbols['config']['pa']))
    require(guest.save('config-observed.bin',guest.symbols['config']['pa'],512) == config,
        'Full collection config not observed: '+guest.node)


def cleanup_guests(guests, result):
    def finish(label, operation):return finalize_capture(result,label,operation)
    if not result['capture_complete']:
        paused,errors=pause_all(guests)
        for error in errors:
            result.setdefault('cleanup_errors',[]).append(error);fail_capture(result,error)
        for guest in guests:
            if guest.node in paused:
                for key,(_,size) in BANKS.items():
                    finish(guest.node+' failure '+key,lambda guest=guest,key=key,size=size:
                        guest.save('failure-'+key+'.bin',guest.symbols[key]['pa'],size))
    for guest in guests:
        if guest.qmp is not None and guest.proc is not None:
            def tail(guest=guest):
                if guest.proc.poll() is None:drain_serial(guest)
            finish(guest.node+' final serial',tail)
    processes={}
    for guest in guests:
        processes[guest.node]=finish(guest.node+' owned cleanup',lambda guest=guest:
            close_owned(guest.proc,guest.sock,guest.qmp,started_ns=guest.started_ns))
    for guest in guests:
        process=processes[guest.node]
        if process is not None:
            finish(guest.node+' process exit',lambda guest=guest,process=process:
                write_json(guest.folder/'process-exit.json',process))
            if (process['errors'] or process['forced'] or process['returncode'] != 0
                    or not process['quit_ok'] or not process['eof']):
                fail_capture(result,'Full collection owned process lacks normal quit/EOF/wait0: '+guest.node)
        if guest.qmp is not None:
            finish(guest.node+' QMP transcript',lambda guest=guest:
                write_json(guest.folder/'qmp-transcript.json',guest.qmp.transcript))
        finish(guest.node+' raw serial',lambda guest=guest:(guest.folder/'serial.bin').write_bytes(guest.raw))
        finish(guest.node+' decoded serial',lambda guest=guest:(guest.folder/'serial.txt').write_bytes(guest.text))
        if (guest.folder/'disk.raw').exists():
            finish(guest.node+' disk custody',lambda guest=guest:write_json(guest.folder/'disk-after.json',
                dict(bytes=(guest.folder/'disk.raw').stat().st_size,sha256=sha(guest.folder/'disk.raw'))))


def run(build_manifest, output, *, source_root, formatter, qemu_binary, qemu_source,
        timeout=TIMEOUT_DEFAULT, until='validated', native_lock=DEFAULT_NATIVE_LOCK):
    require(type(timeout) in (int,float) and 5 <= timeout <= MAX_TIMEOUT and math.isfinite(timeout),
        'Full collection host timeout must be finite and bounded')
    require(until in ('validated','collected'),'unsupported Full collection terminal')
    output=Path(output)
    require(not output.is_symlink() and not output.exists(),'refuse reused Full collection output')
    output=output.resolve()
    with native_lease(native_lock):
        idle_native_host()
        context=trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
            qemu_binary=qemu_binary,qemu_source=qemu_source)
        paths={key:Path(value) for key,value in context['paths'].items()}
        output.mkdir(mode=0o700,parents=True)
        result=dict(version=VERSION,until=until,status='FAIL',capture_complete=False,
            full_collection_verified=False,validation_handoff_observed=False,full_dataset_verified=False,
            model_trained=False,active_model_verified=False,A03_complete=False,native_acceptance_status='NOT_RUN')
        guests=[]
        try:
            guests=prepare_capture(output,context,paths,timeout=timeout,until=until)
            require(trusted_context(**paths) == context,'Full collection identity changed before spawn')
            idle_native_host()
            # Socket paths and stderr handles outlive every owned quit/EOF/wait.
            with tempfile.TemporaryDirectory(prefix='cyx-a03-all-') as temp, ExitStack() as resources:
                try:
                    with socket.socket() as listener:
                        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
                    deadline=time.monotonic()+timeout
                    for guest in guests:
                        errors=resources.enter_context((guest.folder/'qemu-stderr.log').open('xb'))
                        launch_guest(guest,paths,temp,port,deadline,errors)
                    result['boundary']=observe(guests,deadline,until=until,
                        progress=lambda value:atomic_json(output/'progress.json',value))
                    result['capture_complete']=True
                except BaseException as error:
                    fail_capture(result,type(error).__name__+': '+str(error))
                    if not isinstance(error,(Exception,KeyboardInterrupt)):raise
                finally:
                    cleanup_guests(guests,result)
        except (Exception,KeyboardInterrupt) as error:
            fail_capture(result,type(error).__name__+': '+str(error))
        try:
            require('error' not in result,result.get('error','Full collection capture failed'))
            require(trusted_context(**paths) == context,'Full collection identity changed during capture')
            checked=verify_capture(output,**paths,allow_unsaved_exports=True)
            exports=output/'collection-archives';exports.mkdir(mode=0o700)
            for name,value in checked['archive_files'].items():
                relative=Path(name)
                require(not relative.is_absolute() and bool(relative.parts) and '..' not in relative.parts,
                    'Full collection external archive export')
                target=exports/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with target.open('xb') as stream:stream.write(value)
            write_json(exports/'manifest.json',checked['archive_manifest'])
            verification=verify_capture(output,**paths)
            require(verification['capture_complete'] is True and verification['full_collection_verified'] is True,
                'Full collection independent terminal verification incomplete')
            result['verification']={key:value for key,value in verification.items()
                if key not in ('archive_files','archive_manifest')}
            result.update(status='FULL_COLLECTION_VERIFIED',capture_complete=True,full_collection_verified=True,
                validation_handoff_observed=verification.get('validation_handoff_observed',until=='validated'))
        except (Exception,KeyboardInterrupt) as error:
            fail_capture(result,type(error).__name__+': '+str(error))
        def final_inventory():
            inventory=bounded_inventory(output)
            if result['capture_complete'] and result['full_collection_verified']:
                require(inventory==result['verification']['captured_inventory'],
                    'Full collection evidence changed after verification')
            result['artifacts']=inventory
        finalize_capture(result,'inventory',final_inventory)
        finalize_capture(result,'summary',lambda:write_json(output/'summary.json',result))
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','build-manifest','output','formatter','qemu-binary','qemu-source'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=TIMEOUT_DEFAULT)
    parser.add_argument('--until',choices=('validated','collected'),default='validated')
    parser.add_argument('--native-lock',type=Path,default=DEFAULT_NATIVE_LOCK)
    args=parser.parse_args(argv)
    try:
        result=run(**vars(args))
    except (Exception,KeyboardInterrupt) as error:
        result=dict(status='FAIL',capture_complete=False,full_collection_verified=False,
            validation_handoff_observed=False,native_acceptance_status='NOT_RUN',
            error=type(error).__name__+': '+str(error))
    print(json.dumps({key:result.get(key) for key in ('status','capture_complete',
        'full_collection_verified','validation_handoff_observed','native_acceptance_status','error')},indent=2))
    return int(not (result['capture_complete'] and result['full_collection_verified']))


if __name__ == '__main__':sys.exit(main())
