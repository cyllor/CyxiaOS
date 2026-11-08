#!/usr/bin/env python3
"""Live four-CPU architectural register context subcase; never enrol complete A06."""
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
import tempfile
import time

from build_unified import ROOT, code_source_map, sha
from check_elf import symbol
from check_prototype_evidence import require
from run_qemu import Qmp
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v15_registers import WORDS, make_config


def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def packet(config,address):
    require(len(config)==128 and address%64==0,'invalid fixed register config write')
    payload=f'M{address:x},80:{config.hex()}'.encode()
    return b'$'+payload+f'#{sum(payload)%256:02x}'.encode()


def inject(endpoint,config,address):
    request=packet(config,address)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(5);s.connect(endpoint);s.sendall(request);response=bytearray()
        while b'$OK#9a' not in response:
            part=s.recv(4096)
            require(part and len(response)+len(part)<=4096,'fixed config write failed')
            response.extend(part)
        require(bytes(response).lstrip(b'+')==b'$OK#9a','unexpected GDB response')
        s.sendall(b'+')
    return dict(request_hex=request.hex(),received_hex=response.hex(),ack_hex='2b')


def run(build,output,qemu,trusted,timeout):
    from verify_v15_registers import verify_native, TOOL_FILES, verify_build
    require(5<=timeout<=60,'invalid bounded register timeout')
    verify_build(build,ROOT)
    output=output.resolve();output.mkdir(parents=True,exist_ok=False)
    image=build/'registers.elf';shutil.copyfile(image,output/'registers.elf')
    shutil.copyfile(build/'build-manifest.json',output/'build-manifest.json')
    sources=code_source_map(ROOT);write(output/'source-manifest.json',sources)
    nonce=secrets.token_bytes(16)
    write(output/'input.json',dict(scope='A06-register-context',nonce=nonce.hex(),timeout_seconds=timeout,sample_gap_seconds=.1))
    config=make_config(nonce,bytes.fromhex(sha(image)),bytes.fromhex(sha(output/'source-manifest.json')),bytes.fromhex(sha(output/'input.json')))
    (output/'config.bin').write_bytes(config)
    symbols={k:symbol(image.read_bytes(),v) for k,v in
             [('config','REGISTER_V15_CONFIG'),('capture','REGISTER_V15_EVIDENCE')]}
    require(symbols['config']['size']==128 and symbols['capture']['size']==WORDS*8,'wrong register profile')
    require(qemu.resolve()==(trusted/'build/qemu-system-aarch64').resolve(),'explicit QEMU build mismatch')
    identity=attest_qemu(str(qemu),trusted)
    identity['qemu_source_directory']=str(trusted.resolve(strict=True))
    write(output/'tools.json',identity)
    (output/'tooling').mkdir()
    for name in TOOL_FILES:shutil.copyfile(ROOT/'tools'/name,output/'tooling'/name)
    proc=sock=qmp=None;started=None;forced=False;raw=bytearray();decoder=FrameDecoder();text=bytearray()
    report=dict(status='FAIL',native_acceptance_status='NOT_RUN',full_a06_verified=False)
    try:
        with tempfile.TemporaryDirectory(prefix='cyx-reg-') as tmp,(output/'qemu-stderr.log').open('wb') as errors:
            qpath,gpath=str(Path(tmp)/'q.sock'),str(Path(tmp)/'g.sock')
            argv=[str(qemu),'-machine','virt-10.2,gic-version=2,secure=off,virtualization=off',
                  '-cpu','cortex-a53','-smp','4','-m','1024M','-accel','tcg,thread=multi',
                  '-S','-display','none','-monitor','none','-nic','none',
                  '-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog',
                  '-qmp',f'unix:{qpath},server=on,wait=off','-gdb',f'unix:{gpath},server=on,wait=off',
                  '-kernel',str(output/'registers.elf'),'-no-reboot']
            write(output/'launch.json',dict(argv=argv,symbols=symbols))
            started=time.monotonic_ns();proc=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=errors)
            end=time.monotonic()+timeout;sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None and time.monotonic()<end,'QMP startup failed')
                try:sock.connect(qpath);break
                except (FileNotFoundError,ConnectionRefusedError):time.sleep(.01)
            qmp=Qmp(sock);require('QMP' in qmp.receive(end),'missing QMP greeting');qmp.execute('qmp_capabilities')
            def save(name,address,size):
                qmp.execute('pmemsave',dict(val=address,size=size,filename=str(output/name)))
                return (output/name).read_bytes()
            platform=dict(cpus=qmp.execute('query-cpus-fast'),memory=qmp.execute('query-memory-size-summary'))
            require(len(platform['cpus'])==4 and platform['memory']['base-memory']==1024**3,'wrong platform')
            write(output/'platform.json',platform)
            header=save('dtb-header.bin',0x40000000,40);magic,size=struct.unpack_from('>2I',header)
            require(magic==0xd00dfeed and 40<=size<=2*1024*1024,'invalid DTB')
            save('platform.dtb',0x40000000,size)
            write(output/'config-injection.json',inject(gpath,config,symbols['config']['pa']))
            require(save('config-observed.bin',symbols['config']['pa'],128)==config,'config not observed')
            qmp.execute('cont')
            while time.monotonic()<end:
                require(proc.poll() is None,'guest exited')
                chunk=base64.b64decode(qmp.execute('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64')),validate=True)
                raw.extend(chunk);require(len(raw)<=2*1024*1024,'serial overflow')
                for payload in decoder.feed(chunk):text.extend(payload+b'\n')
                require(not any(x in text for x in (b'PANIC',b'SMP_ERROR',b'FAIL')),'guest fault')
                if b'REGISTER_CONTEXT_DONE a=0 b=6 c=0\n' in text:
                    for name in ('first.bin','last.bin'):
                        qmp.execute('stop');require(qmp.execute('query-status')['status']=='paused','capture not stopped')
                        save(name,symbols['capture']['pa'],WORDS*8)
                        if name=='first.bin':qmp.execute('cont');time.sleep(.1)
                    break
                time.sleep(.01)
            else:raise TimeoutError('register native deadline')
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        report['error']=str(error)
        if qmp:
            try:
                qmp.execute('stop');qmp.execute('query-status')
                qmp.execute('pmemsave',dict(val=symbols['capture']['pa'],size=WORDS*8,filename=str(output/'failure.bin')))
            except (OSError,ValueError,RuntimeError):pass
    finally:
        if proc:
            if proc.poll() is None:
                try:
                    if qmp:qmp.execute('quit')
                    proc.wait(timeout=3)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                    forced=True;proc.kill();proc.wait(timeout=3)
            write(output/'process-exit.json',dict(schema=1,started_ns=started,exited_ns=time.monotonic_ns(),returncode=proc.returncode,forced=forced))
        if sock:sock.close()
        if qmp:write(output/'qmp-transcript.json',qmp.transcript)
        (output/'serial.bin').write_bytes(raw);(output/'serial.txt').write_bytes(text)
    files={p.relative_to(output).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in output.rglob('*') if p.is_file()}
    write(output/'inventory.json',dict(schema=1,files=files))
    if 'error' not in report:
        try:report.update(verify_native(output,build=build,source_root=ROOT,qemu_source=trusted))
        except (OSError,ValueError,RuntimeError,KeyError) as error:report['error']=str(error)
    write(output/'summary.json',report);return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('build','output','qemu','qemu-source'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--timeout',type=float,default=30);a=p.parse_args(argv)
    r=run(a.build.resolve(strict=True),a.output,a.qemu.resolve(strict=True),a.qemu_source.resolve(strict=True),a.timeout)
    print(json.dumps(r,indent=2));return int(r['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
