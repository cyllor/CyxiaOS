#!/usr/bin/env python3
"""Sample a continuing native CACP, then resume and sample again.

This verifier covers fixed-core EL0 isolation, actual timer scheduling, immutable
bootstrap inference and restart containment. It does not close the 1.3 full gates.
"""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid
from check_elf import boot_profile, inspect_elf, symbol
from check_v13_disk import inspect as inspect_disk
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha
from verify_v13_model import loaded_bytes, reference

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x43595852554e3133
EVIDENCE_BYTES = 8192
START = b'RUNTIME_V13_STARTED mode=continuous ownership=fixed model=untrained\n'


def model_bytes() -> bytes:
    model=bytearray(2772)
    for offset,value in ((0,64),(1,192),(2048,64),(2560,64)): model[offset]=value
    return bytes(model)


def sample(page: bytes, epoch: int) -> dict:
    require(len(page)==EVIDENCE_BYTES,'incomplete runtime evidence')
    words=struct.unpack('<1024Q',page);h=words[:64]
    require(h[0]==MAGIC and h[1]==1 and h[2]>0 and h[2]%2==0,'incomplete runtime publication')
    require(h[4]>=1000 and h[3]>h[30] and h[5]>0,'invalid native clock')
    require(h[6:11]==(2,13,0,0,1),'runtime fixed-core ownership changed')
    require(h[11]>0 and h[12]==1+h[15] and h[13]>=12 and h[14]>=10,'missing controller progress')
    require(h[15]<=1 and h[17]==h[18]==0,'controller rejection or budget overrun')
    require(h[19]>0 and h[20]>0 and h[21]>0 and h[22]>0,'missing actual business execution')
    require(all(400<=v<=900 and v%100==0 for v in h[23:25]),'business debit exceeds budget')
    require(h[25:27] in ((2,1),(1,2)) and 0<h[27]<=h[13],'invalid applied policy')
    require(h[28]==4 and h[29] in (0,1),'missing protected mappings or invalid fault mode')
    require(h[31]==h[14]+h[15]+h[17] and h[13]-h[31] in (0,1),'lost request receipt')
    require(h[32]==epoch and epoch>0 and (h[33] or h[34]),'wrong durable boot identity')
    require(100<=h[35]<=700 and h[35]%100==0 and h[36]>0 and h[37]>=h[35]
            and h[38]==0 and all(0<v<=h[4]//100 for v in h[39:42]),'control timer budget exceeded')
    require(h[42]>=4 and not any(h[43:]),'nonzero reserved evidence')
    require((h[29]==0 and h[15]==0) or (h[29]==1 and h[15]==1),'fault was not contained exactly once')
    records=[]
    first=max(1,h[31]-31)
    for sequence in range(first,h[31]+1):
        at=64+((sequence-1)%32)*24;r=words[at:at+24]
        require(r[0]==sequence and r[1] in (1,2) and h[30]<=r[2]<r[3]<=h[3],
                'invalid request sequence/service/timing')
        require(r[17]==1 and r[18]>0 and r[22:]==(0,0),'invalid request generation/reserved')
        if records:
            previous=records[-1]
            require(r[4]>=previous[4] and r[5]>=previous[5]
                    and (r[4]-previous[4],r[5]-previous[5])==r[6:8],
                    'telemetry does not match consecutive observed progress')
        if r[16]==1:
            candidate0=[min(r[7],32767),min(r[6],32767)]+[0]*62
            candidate1=[candidate0[1],candidate0[0]]+[0]*62
            scores=[reference(model_bytes(),c)[2] for c in (candidate0,candidate1)]
            selected=int(scores[1]>scores[0])
            require(r[8]==selected and r[9:11]==tuple(scores),'EL0 model candidate/score mismatch')
            require(r[11:13]==((2,1) if selected==0 else (1,2)),'accepted model policy differs from selection')
            require(r[13]==8 and r[14]>>26==0x15 and r[14]&0xffff==0x541 and r[19]<=100,
                    'invalid native EL0 completion/freshness')
            require(r[1]==(2 if h[29] and sequence>5 else 1),'service generation mismatch')
        else:
            require(h[29]==1 and sequence==5 and r[16]==2 and r[1]==1
                    and r[13]==9 and r[15]>0 and r[19]>=100 and r[3]-r[2]>=h[4]//10
                    and r[20]>0 and r[21]>0,
                    'missing timer containment or business progress during fault')
        records.append(r)
    require(len(records)>=10,'insufficient captured requests')
    if h[31]<=32:
        require(h[16]==sum(r[15] for r in records),'timer preemption total differs from receipts')
    accepted={r[0]:r for r in records if r[16]==1}
    windows=[]
    for index in range(max(0,h[42]-12),h[42]):
        at=832+(index%12)*16;w=words[at:at+16]
        require(w[0]>0 and h[30]<=w[1]<w[2]<=h[3] and w[2]-w[1]==h[4]//10
                and w[14:]==(0,0),'invalid completed budget window')
        if windows: require(w[0]>windows[-1][0] and w[1]>=windows[-1][2],'overlapping windows')
        if w[3]==0: require(w[4:6]==(1,1),'invalid baseline window')
        else:
            require(w[3] in accepted and w[4:6]==accepted[w[3]][11:13]
                    and accepted[w[3]][3]<=w[1],'window used unpublished policy')
        for cpu in (0,1):
            debit,ticks,completed,expired=(w[6+cpu],w[8+cpu],w[10+cpu],w[12+cpu])
            require(debit<=w[4+cpu]*400 and debit<=900 and debit==100*(completed+expired),
                    'execution credits do not match actual applied policy')
            require((completed==0 and ticks==0) or (completed>0 and 0<ticks<=completed*(h[4]//100)),
                    'actual window time exceeded reserved credits')
        windows.append(w)
    require(any(w[3]>0 and w[10]>0 and w[11]>0 for w in windows),'no actual model-controlled dispatch')
    return dict(words=h,records=records,windows=windows)


def validate(serial: bytes, pages: list[bytes], cpus: int, epoch: int) -> dict:
    require(cpus==4,'exactly four vCPUs required')
    require(len(pages)==2,'two independent live samples required')
    lines=serial.splitlines()
    require(all(lines.count(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode())==1 for cpu in (1,2,3))
            and lines.count(b'SMP_BOOT_OK a=4 b=15 c=0')==1,'missing secondary boot handshakes')
    require(lines.count(START.rstrip())==1,'missing/duplicate continuous-runtime start')
    require(lines.count(b'STORAGE_V13_BOOT_DURABLE')==1
            and lines.index(b'STORAGE_V13_BOOT_DURABLE')<lines.index(START.rstrip()),
            'durable BootEpoch must precede AI startup')
    require(not any(marker in serial for marker in (b'FAIL',b'SMP_ERROR',b'PANIC')),'guest failure')
    samples=[sample(page,epoch) for page in pages]
    a,b=[s['words'] for s in samples]
    require(b[2]>a[2] and b[3]>a[3] and b[5]>a[5] and b[14]>=a[14]+8
            and b[19]>a[19] and b[20]>a[20] and b[21]>a[21] and b[22]>a[22],
            'runtime did not continue after first observation')
    require(a[4]==b[4] and a[30]==b[30] and a[32:35]==b[32:35],'boot identity or timer origin changed')
    require(a[29]==b[29] and a[15]==b[15] and b[11]>a[11], 'budget ledger reset on recovery')
    return dict(continuous_runtime_verified=True,production_isolation_verified=False,
        core_transition_verified=False,trained_model_verified=False,native_cluster_verified=False,
        guaranteed_minimum_service_verified=False,full_policy_envelope_verified=False,
        full_control_cost_accounted=False,
        workload='two isolated always-runnable CPU loops',model='hand-authored untrained bootstrap',
        control_mask=2,business_mask=13,boot_epoch=epoch,service_generation=b[12],
        requests=b[13],successful_inferences=b[14],controller_faults=b[15],timer_preemptions=b[16],
        business_quanta=[b[19],b[20]],business_elapsed_ticks=[b[21],b[22]],
        maximum_predebited_milli=[b[23],b[24]],timer_frequency=b[4],protection_faults=b[28],control_el0_ticks=b[36],
        maximum_control_predebited_milli=b[35],maximum_slice_ticks=list(b[39:42]),
        captured_applied_windows=[list(w[:14]) for w in samples[1]['windows']])


def profile(elf: bytes) -> dict:
    inspect_elf(elf)
    require(boot_profile(elf)['ram_mib']==1024,'runtime requires 1 GiB')
    location=symbol(elf,'RUNTIME_V13_EVIDENCE')
    require(location['size']==EVIDENCE_BYTES and location['pa']%4096==0,'invalid evidence symbol')
    embedded=symbol(elf,'RUNTIME_SERVICE_ELF')
    service=loaded_bytes(elf,embedded['va'],embedded['size'])
    require(loaded_bytes(service,0x90000,2772)==model_bytes(),'immutable bootstrap package mismatch')
    return location


def run(elf: Path, output: Path, timeout: float=180, disk: Path|None=None, epoch: int=1) -> dict:
    require(5<=timeout<=300 and epoch>0,'invalid timeout or epoch')
    elf=elf.resolve(strict=True);output=output.resolve()
    require(not output.exists(),'refuse to reuse evidence output');output.mkdir(parents=True)
    before=manifest();(output/'source-manifest.json').write_text(json.dumps(before,indent=2)+'\n')
    report=dict(status='FAIL',scope='continuous-native-fixed-core-runtime',
        continuous_runtime_verified=False,production_isolation_verified=False,
        core_transition_verified=False,trained_model_verified=False,native_cluster_verified=False,
        runtime_truth_attested=False,elf_sha256=sha(elf),
        source_manifest_sha256=sha(output/'source-manifest.json'))
    proc=sock=qmp=None;raw=bytearray();serial=bytearray();decoder=FrameDecoder()
    args=[];cpus=[];memory={};pages=[];started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='cyx-runtime-') as td,(output/'qemu-stderr.log').open('wb') as errors:
        try:
            location=profile(elf.read_bytes());image=output/'disk.raw'
            if disk is not None:
                require(disk.resolve(strict=True).stat().st_size==512*1024*1024,'disk must be 512 MiB')
                shutil.copyfile(disk,image)
            else:
                require(epoch==1,'fresh disk begins at BootEpoch 1')
                cargo=shutil.which('cargo') or str(Path.home()/'.cargo/bin/cargo')
                with (output/'format.log').open('wb') as log:
                    subprocess.run([cargo,'run','--locked','--offline','-p','cyxia-prototype',
                        '--example','prototype-disk','--',str(image),uuid.uuid4().hex],
                        cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
            report['disk_before_sha256']=sha(image)
            binary=shutil.which('qemu-system-aarch64');require(binary is not None,'QEMU missing')
            version=subprocess.check_output([binary,'--version'],timeout=10,text=True)
            require(version.splitlines()[0] in ('QEMU emulator version 10.2.2',
                'QEMU emulator version 10.2.2 (v10.2.2)'),'unverified QEMU version')
            report.update(qemu_version=version,qemu_sha256=sha(Path(binary)))
            path=str(Path(td)/'q.sock')
            args=[binary,'-machine','virt-10.2,gic-version=2,secure=off,virtualization=off',
                '-cpu','cortex-a53','-smp','4','-m','1024M','-accel','tcg,thread=multi','-S',
                '-display','none','-monitor','none','-nic','none','-chardev','ringbuf,id=cyxlog,size=1048576',
                '-serial','chardev:cyxlog','-qmp',f'unix:{path},server=on,wait=off',
                '-drive',f'if=none,id=store,file={image},format=raw,cache=writeback',
                '-global','virtio-mmio.force-legacy=false','-device','virtio-blk-device,drive=store',
                '-kernel',str(elf),'-no-reboot']
            proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=errors)
            end=time.monotonic()+timeout;sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None,'QEMU exited before handshake')
                if time.monotonic()>=end: raise TimeoutError('QMP startup deadline')
                try: sock.connect(path);break
                except (FileNotFoundError,ConnectionRefusedError): time.sleep(.01)
            qmp=Qmp(sock);require('QMP' in qmp.receive(end),'invalid QMP greeting')
            qmp.execute('qmp_capabilities');cpus=qmp.execute('query-cpus-fast')
            memory=qmp.execute('query-memory-size-summary')
            require(memory['base-memory']==1024*1024*1024,'incorrect native memory')
            qmp.execute('cont')
            while time.monotonic()<end:
                require(proc.poll() is None,'QEMU exited before live samples')
                chunk=base64.b64decode(qmp.execute('ringbuf-read',
                    {'device':'cyxlog','size':1048576,'format':'base64'}),validate=True)
                raw.extend(chunk);require(len(raw)<=2*1024*1024,'serial limit exceeded')
                for frame in decoder.feed(chunk):serial.extend(frame)
                require(not any(marker in serial for marker in (b'FAIL',b'SMP_ERROR',b'PANIC')),'guest failure')
                if START in serial:
                    qmp.execute('stop');path=output/'pending-page.bin'
                    qmp.execute('pmemsave',{'val':location['pa'],'size':EVIDENCE_BYTES,'filename':str(path)})
                    page=path.read_bytes();header=struct.unpack_from('<35Q',page)
                    if header[0]==MAGIC and header[2]>0 and not header[2]%2:
                        require(header[18]==0,'actual business slice exceeded its predebit')
                        threshold=12 if not pages else struct.unpack_from('<1024Q',pages[0])[14]+10
                        if header[14]>=threshold:
                            sample(page,epoch)
                            pages.append(page);path.rename(output/f'native-page-{len(pages)}.bin')
                    if len(pages)==2:
                        require(decoder.loss==decoder.corrupt==0 and not decoder.buffer,'corrupt framed UART')
                        report['observations']=validate(bytes(serial),pages,len(cpus),epoch)
                        require(sha(elf)==report['elf_sha256'],'ELF changed during run')
                        require(before==manifest(),'source changed during run')
                        report.update(status='PASS',continuous_runtime_verified=True)
                        break
                    qmp.execute('cont')
                time.sleep(.05)
            else: raise TimeoutError('continuous native runtime deadline')
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError,struct.error) as error:
            report['error']=type(error).__name__+': '+str(error)
            if 'observations' in report: report['observations']['continuous_runtime_verified']=False
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    if qmp:qmp.execute('quit')
                except (OSError,ValueError,RuntimeError):pass
                try:proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
            if sock:sock.close()
            (output/'serial.bin').write_bytes(raw);(output/'serial.txt').write_bytes(serial)
            if qmp:(output/'qmp.jsonl').write_text(''.join(json.dumps(m)+'\n' for m in qmp.transcript))
            (output/'launch.json').write_text(json.dumps(dict(argv=args,cpus=cpus,memory=memory,
                exit=proc.returncode if proc is not None else None),indent=2)+'\n')
    if report['status']=='PASS':
        try:
            decoded=inspect_disk(output/'disk.raw')
            header=struct.unpack_from('<1024Q',pages[-1])
            require(decoded['boot_epoch']==epoch
                    and decoded['uuid']==struct.pack('<2Q',*header[33:35]).hex(),
                    'durable disk and running boot identity disagree')
            report['durable_disk']=decoded
        except (OSError,ValueError,struct.error) as error:
            report.update(status='FAIL',continuous_runtime_verified=False,error=str(error))
            report['observations']['continuous_runtime_verified']=False
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['evidence_sha256']={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=180);parser.add_argument('--disk',type=Path)
    parser.add_argument('--expected-epoch',type=int,default=1)
    args=parser.parse_args()
    try:result=run(args.elf,args.output,args.timeout,args.disk,args.expected_epoch)
    except (OSError,ValueError) as error:
        print(str(error),file=__import__('sys').stderr);return 1
    print(json.dumps(result,indent=2));return int(result['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
