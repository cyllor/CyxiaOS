#!/usr/bin/env python3
"""Execute A09 ordinary anonymous clients, with three stopped physical snapshots."""
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
from build_unified import ROOT,code_source_map,sha
from check_prototype_evidence import require
from memory_v15_custody import verify_build,verify_native,TOOL_FILES
from verify_v15_memory import WORDS,PRIVATE_VAS,PA_MASK
from verify_v13_boot_recovery import CONFIG_MAGIC
from verify_unified import attest_qemu
from run_v13_a02 import inject_config
from run_qemu import Qmp
from transport import FrameDecoder


def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def run(build,output,formatter,qemu,trusted,timeout):
    require(5<=timeout<=600,'A09 bounded fixed-work collector timeout')
    _,symbols,_=verify_build(build,ROOT)
    output=output.resolve();output.mkdir(parents=True,exist_ok=False);output.chmod(0o700)
    require(qemu.resolve()==(trusted/'build/qemu-system-aarch64').resolve(),'A09 requires explicit trusted QEMU source build')
    for name,target in [('node-a.elf','node-a.elf'),('memory-client-a.elf','memory-client.elf'),('build-manifest.json','build-manifest.json')]:
        shutil.copyfile(build/name,output/target);(output/target).chmod(0o600)
    write(output/'source-manifest.json',code_source_map(ROOT));nonce=secrets.token_bytes(16)
    write(output/'input.json',dict(scope='A09-memory-cache-pressure',nonce=nonce.hex(),timeout_seconds=timeout,
         file_pages=4097,checkpoint_wait_ns=2_000_000_000,poll_interval_ns=100_000_000,formatter_sha256=sha(formatter)))
    formatted=subprocess.run([str(formatter),str(output/'disk.raw'),nonce.hex()],capture_output=True,timeout=120)
    (output/'format.log').write_bytes(formatted.stdout+formatted.stderr)
    require(formatted.returncode==0,'A09 formatter failed; preserve format.log')
    write(output/'disk-before.json',dict(bytes=(output/'disk.raw').stat().st_size,sha256=sha(output/'disk.raw')))
    config=(struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+nonce+bytes.fromhex(sha(output/'node-a.elf'))
        +bytes.fromhex(sha(output/'input.json'))+bytes.fromhex(sha(output/'source-manifest.json'))+bytes(368))
    (output/'config.bin').write_bytes(config)
    identity=attest_qemu(str(qemu),trusted);identity['qemu_source_directory']=str(trusted.resolve());write(output/'tools.json',identity)
    (output/'tooling').mkdir()
    for name in TOOL_FILES:shutil.copyfile(ROOT/'tools'/name,output/'tooling'/name)
    proc=sock=qmp=None;started=None;forced=False;raw=bytearray();text=bytearray();decoder=FrameDecoder();capture_map={}
    report=dict(status='FAIL',test_id='A09',native_acceptance_status='NOT_RUN')
    try:
        with tempfile.TemporaryDirectory(prefix='cyx-a09-') as temp,(output/'qemu-stderr.log').open('wb') as errors:
            qpath,gpath=str(Path(temp)/'q.sock'),str(Path(temp)/'g.sock')
            with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            argv=[str(qemu),'-machine','virt-10.2,gic-version=2,secure=off,virtualization=off',
                '-cpu','cortex-a53','-smp','4','-m','1024M','-accel','tcg,thread=multi','-S','-display','none','-monitor','none',
                '-global','virtio-mmio.force-legacy=false','-drive',f'if=none,id=disk0,format=raw,file={output/"disk.raw"},cache=writeback',
                '-device','virtio-blk-device,drive=disk0','-netdev',f'socket,id=net0,listen=127.0.0.1:{port}',
                '-device','virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
                '-object','rng-random,id=rng0,filename=/dev/urandom','-device','virtio-rng-device,rng=rng0',
                '-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog',
                '-qmp',f'unix:{qpath},server=on,wait=off','-gdb',f'unix:{gpath},server=on,wait=off',
                '-kernel',str(output/'node-a.elf'),'-no-reboot']
            write(output/'launch.json',dict(argv=argv,symbols=symbols));started=time.monotonic_ns()
            proc=subprocess.Popen(argv,stdout=subprocess.DEVNULL,stderr=errors);end=time.monotonic()+timeout
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None and time.monotonic()<end,'A09 QMP startup deadline')
                try:sock.connect(qpath);break
                except (FileNotFoundError,ConnectionRefusedError):time.sleep(.01)
            qmp=Qmp(sock);require('QMP' in qmp.receive(end),'A09 missing QMP greeting');qmp.execute('qmp_capabilities')
            def save(name,address,size):
                require(type(address) is int and type(size) is int and size>0,'invalid A09 capture range')
                qmp.execute('pmemsave',dict(val=address,size=size,filename=str(output/name)))
                capture_map[name]=[address,size];return (output/name).read_bytes()
            platform=dict(cpus=qmp.execute('query-cpus-fast'),memory=qmp.execute('query-memory-size-summary'))
            require(len(platform['cpus'])==4 and platform['memory']['base-memory']==1024**3,'A09 wrong native platform')
            write(output/'platform.json',platform)
            header=save('dtb-header.bin',0x40000000,40);magic,size=struct.unpack_from('>2I',header)
            require(magic==0xd00dfeed and 40<=size<=2*1024**2,'A09 bad DTB')
            save('platform.dtb',0x40000000,size)
            write(output/'config-injection.json',inject_config(gpath,config,symbols['config']['pa']))
            require(save('config-observed.bin',symbols['config']['pa'],512)==config,'A09 unobserved config')
            qmp.execute('cont');stage=1
            while time.monotonic()<end:
                require(proc.poll() is None,'A09 guest exited')
                chunk=base64.b64decode(qmp.execute('ringbuf-read',dict(device='cyxlog',size=1048576,format='base64')),validate=True)
                raw.extend(chunk);require(len(raw)<=8*1024**2,'A09 UART overflow')
                for payload in decoder.feed(chunk):text.extend(payload+b'\n')
                require(not any(x in text for x in (b'PANIC',b'UNIFIED_FAIL',b'SMP_ERROR')),'A09 guest failure')
                bank=save('pending-memory.bin',symbols['memory']['pa'],WORDS*8);w=struct.unpack('<%dQ'%WORDS,bank)
                require(w[6]==0,'A09 ordinary client reported failure')
                if w[4]<stage or w[2]%2:time.sleep(.1);continue
                require(w[4]==stage,'A09 missed an immutable zero/sentinel barrier')
                qmp.execute('stop');require(qmp.execute('query-status')['status']=='paused','A09 capture not stopped')
                bank=save(f'{stage}-memory.bin',symbols['memory']['pa'],WORDS*8);w=struct.unpack('<%dQ'%WORDS,bank)
                require(w[4]==stage and w[2]%2==0,'A09 checkpoint changed before stop')
                if stage in (1,3):save('boot-first.bin' if stage==1 else 'boot-last.bin',symbols['boot']['pa'],512)
                for role in (1,2):
                    address=w[64+(role-1)*192+3]
                    for kind in ('root','mid','leaf'):
                        require(address%4096==0 and 0x40200000<=address<0x44000000,'A09 invalid task page-table address')
                        data=save(f'{stage}-{role}-{kind}.bin',address,4096)
                        if kind!='leaf':address=struct.unpack_from('<Q',data)[0]&PA_MASK
                    leaf=struct.unpack('<512Q',data)
                    for page,va in enumerate(PRIVATE_VAS):
                        pa=leaf[va//4096]&PA_MASK;require(0x40200000<=pa<0x44000000,'A09 unmapped private page')
                        save(f'{stage}-{role}-page{page}.bin',pa,4096)
                    for page in range(4):
                        pa=leaf[16+page]&PA_MASK;require(0x40200000<=pa<0x44000000,'A09 unmapped client code')
                        save(f'{stage}-{role}-code{page}.bin',pa,4096)
                if stage==3:
                    for name,key,size in [('control.bin','control',4096),('runtime.bin','runtime',8192),('unified.bin','unified',4096)]:save(name,symbols[key]['pa'],size)
                    break
                stage+=1;qmp.execute('cont')
            else:raise TimeoutError('A09 ordinary memory/cache execution deadline')
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
        report['error']=str(error)
        if qmp:
            try:
                qmp.execute('stop');qmp.execute('query-status')
                failed=save('failure-memory.bin',symbols['memory']['pa'],WORDS*8)
                frozen=struct.unpack('<%dQ'%WORDS,failed)
                diagnostics={}
                for role in (1,2):
                    try:
                        address=frozen[64+(role-1)*192+3]
                        for kind in ('root','mid','leaf'):
                            require(0x40200000<=address<0x44000000 and address%4096==0,'failure task table no longer resident')
                            data=save(f'failure-{role}-{kind}.bin',address,4096)
                            if kind!='leaf':address=struct.unpack_from('<Q',data)[0]&PA_MASK
                        leaf=struct.unpack('<512Q',data);pa=leaf[0x30]&PA_MASK
                        require(0x40200000<=pa<0x44000000,'failure progress page no longer mapped')
                        progress=save(f'failure-{role}-progress.bin',pa,4096)
                        diagnostics[str(role)]={'progress_words':list(struct.unpack_from('<16Q',progress)),
                            'progress_page_mapped':True,'exit_code':None,
                            'scope':'actual stopped user progress; task lifecycle not exported for this package'}
                    except (OSError,ValueError,RuntimeError) as error:diagnostics[str(role)]={'error':str(error)}
                for name,key,size in [('failure-runtime.bin','runtime',8192),('failure-control.bin','control',4096),('failure-unified.bin','unified',4096),('failure-tasks.bin','tasks',256),('failure-file.bin','file',512)]:save(name,symbols[key]['pa'],size)
                task=struct.unpack('<32Q',(output/'failure-tasks.bin').read_bytes())
                diagnostics['actual_role1_task']={
                    'key':list(task[9:11]),'life':task[11],'entered':task[12],
                    'exit_code':None if task[13]==2**64-1 else task[13],
                    'pc':task[15],'exception_kind':task[16],'esr':task[17],'far':task[18],
                    'blocked':task[19],'return_pending':task[20],'file_pending':task[21],
                    'file_busy':task[22],'file_done':task[23],'x0':task[29],'syscall':task[30]}
                write(output/'failure-progress.json',diagnostics)
            except (OSError,ValueError,RuntimeError):pass
    finally:
        if proc:
            if proc.poll() is None:
                try:
                    if qmp:qmp.execute('quit')
                    proc.wait(timeout=3)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):forced=True;proc.kill();proc.wait(timeout=3)
            write(output/'process-exit.json',dict(schema=1,started_ns=started,exited_ns=time.monotonic_ns(),returncode=proc.returncode,forced=forced))
        if sock:sock.close()
        if qmp:write(output/'qmp-transcript.json',qmp.transcript)
        (output/'serial.bin').write_bytes(raw);(output/'serial.txt').write_bytes(text);write(output/'capture-map.json',capture_map)
    require(code_source_map(ROOT)==read_json_map(output/'source-manifest.json'),'A09 source changed during native execution')
    inventory={p.relative_to(output).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in output.rglob('*') if p.is_file()}
    write(output/'inventory.json',dict(schema=1,files=inventory))
    if 'error' not in report:
        try:report=verify_native(output,build=build,source_root=ROOT,qemu_source=trusted)
        except (OSError,ValueError,RuntimeError,KeyError) as error:report['error']=str(error)
    write(output/'summary.json',report);return report


def read_json_map(path):return json.loads(path.read_text())


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('build','output','formatter','qemu','qemu-source'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--timeout',type=float,default=60);a=p.parse_args()
    r=run(a.build.resolve(strict=True),a.output,a.formatter.resolve(strict=True),a.qemu.resolve(strict=True),a.qemu_source.resolve(strict=True),a.timeout)
    print(json.dumps(r,indent=2));return int(r['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
