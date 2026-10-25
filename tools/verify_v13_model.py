#!/usr/bin/env python3
"""Native EL0 integer engineering fixtures; no training or production isolation claim."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from check_elf import boot_profile, inspect_elf, symbol
from run_qemu import Qmp
from transport import FrameDecoder
from verify_smp import manifest, require, sha

ROOT = Path(__file__).resolve().parents[1]
MAGIC = 0x4359584D4C503133
INPUT_MAGIC = 0x435958494E503133
OUTPUT_MAGIC = 0x4359584F55543133
MODEL_BYTES = 2772
CASES = 8
RECORD_BYTES = 1536
EVIDENCE_BYTES = 16384


def fixtures():
    """Explicit sparse engineering inputs; this performs no training/inference."""
    models = [bytearray(MODEL_BYTES) for _ in range(6)]
    def weight(m, off, value): models[m][off] = value & 255
    def bias(m, row, value): struct.pack_into('<i', models[m],2576+4*row,value)
    for off,value in [(0,32),(1,-16),(63,1),(64,-64),(31*64+1,-64),
                      (2048,32),(2049,64),(2079,-16),(2528,-16),(2559,64),
                      (2560,-32),(2561,-128),(2575,16)]: weight(0,off,value)
    for row,value in [(0,3),(1,1),(31,-2),(32,-1),(33,-1),(47,2),(48,-3)]: bias(0,row,value)
    for m,weights in [(1,(64,64,-1)),(2,(127,1,64)),(3,(64,127,1)),(4,(64,64,-64))]:
        for off,value in zip((0,2048,2560),weights): weight(m,off,value)
    models[5][:2048] = bytes([128])*2048
    models[5][2048:2560] = bytes([127])*512
    models[5][2560:2576] = bytes([1])*16
    for row in range(48): bias(5,row,2147483647)
    def x(value): return [value]+[0]*63
    sparse = x(256); sparse[1]=-128;sparse[63]=64
    cases = [(0,[sparse]),(0,[x(0)]),(1,[x(v) for v in (31,32,33,96)]),
             (2,[x(32767)]),(3,[x(32767)]),(4,[x(v) for v in (300,100,100)]),
             (5,[[-32768]*64]),(4,[x(0)]*4)]
    requests = bytearray()
    for seq,(m,inputs) in enumerate(cases,1):
        requests += struct.pack('<8Q',INPUT_MAGIC,1,m,len(inputs),seq,0,0,0)
        for inp in inputs+[[0]*64]*(4-len(inputs)): requests += struct.pack('<64h',*inp)
    package = b''.join(models)
    metadata = dict(version=1,synthetic=True,trained=False,model_count=6,model_bytes=2772,
                    cases=8,candidates=16,format='W1/W2/W3 int8; b1/b2/b3 little-endian int32',
                    cases_description=['sparse multilayer','sparse zero input','negative halves',
                    'hidden1 saturation','hidden2 saturation','first maximum negative tie',
                    'full-range accumulation','all-candidate tie'],
                    model_sha256=[hashlib.sha256(m).hexdigest() for m in models],
                    bundle_sha256=hashlib.sha256(package).hexdigest(),
                    requests_sha256=hashlib.sha256(requests).hexdigest())
    return package, bytes(requests), metadata


def reference(model: bytes, inputs: list[int]):
    """Independent arbitrary-precision matrix evaluation, no Rust implementation calls."""
    require(len(model)==MODEL_BYTES,'invalid model length')
    require(len(inputs)==64 and all(type(v) is int and -32768<=v<=32767 for v in inputs),
            'invalid Q8.8 input')
    weights = struct.unpack('<2576b',model[:2576])
    biases = struct.unpack('<49i',model[2576:])
    activation = list(inputs); layers=[]; woff=boff=0
    for rows,columns in [(32,64),(16,32),(1,16)]:
        layer=[]
        for row in range(rows):
            accumulator = sum(a*w for a,w in zip(activation,
                weights[woff+row*columns:woff+(row+1)*columns])) + 64*biases[boff+row]
            magnitude,remainder = divmod(abs(accumulator),64)
            rounded = (magnitude + int(remainder>=32)) * (-1 if accumulator<0 else 1)
            bounded = min(32767,max(-32768,rounded))
            layer.append(max(0,bounded) if rows!=1 else bounded)
        layers.append(layer);activation=layer;woff+=rows*columns;boff+=rows
    return layers[0],layers[1],layers[2][0]


def expected_output(request: bytes, models: bytes) -> bytes:
    magic,version,m,count,seq,*reserved=struct.unpack_from('<8Q',request)
    require(magic==INPUT_MAGIC and version==1 and m<6 and 1<=count<=4 and not any(reserved),
            'invalid fixture request')
    model=models[m*MODEL_BYTES:(m+1)*MODEL_BYTES]
    traces=[reference(model,list(struct.unpack_from('<64h',request,64+i*128))) for i in range(count)]
    scores=[t[2] for t in traces]; selected=max(range(count),key=scores.__getitem__)
    out=bytearray(512);struct.pack_into('<8Q',out,0,OUTPUT_MAGIC,1,seq,selected,count,m,0,0)
    for i,(h1,h2,result) in enumerate(traces): struct.pack_into('<49h',out,64+112*i,*(h1+h2+[result]))
    return bytes(out)


def validate(serial: bytes, page: bytes, cpus: int) -> dict:
    require(cpus==4,'exactly four vCPUs required')
    require(len(page)==EVIDENCE_BYTES,'incomplete model evidence')
    h=struct.unpack_from('<16Q',page)
    require(h[:5]==(MAGIC,1,1,1,CASES),'incomplete model evidence header')
    require(h[5]>=1 and h[6]==4,'missing timer containment or protection probes')
    require(h[7]>0 and h[8]>0 and h[9]>0 and h[10]>0,'missing business progress/timing')
    require(h[11]==6 and h[12]==0 and h[13]!=h[14] and h[13]%4096==h[14]%4096==0
            and h[13]>0 and h[14]>0 and h[15]==0,'invalid mapping/error evidence')
    for i,(address,fsc) in enumerate([(0xa0000,0x4f),(0x90000,0x4f),(0xb0000,0x47),(0x30000,0x07)]):
        mode,kind,esr,far=struct.unpack_from('<4Q',page,256+i*32)
        require(mode==i+1 and kind==8 and esr>>26==0x24 and esr&0x7f==fsc and far==address,
                'incorrect protection fault')
    require(not any(page[128:256]) and not any(page[384:4096]),'nonzero reserved header')
    models,requests,_=fixtures();preemptions=0;timing=[]
    for i in range(CASES):
        record=page[4096+i*RECORD_BYTES:4096+(i+1)*RECORD_BYTES]
        request=requests[i*576:(i+1)*576]
        require(record[:576]==request,'captured request differs from frozen engineering input')
        require(record[576:1088]==expected_output(request,models),'EL0 layer/candidate mismatch')
        start,end,count,cpu,kind,esr,far,reserved=struct.unpack_from('<8Q',record,1088)
        require(start>0 and end>start and cpu==1 and kind==8 and esr>>26==0x15
                and esr&0xffff==0x531 and reserved==0,'invalid EL0 completion/timing')
        require(not any(record[1152:]),'nonzero reserved record')
        preemptions+=count;timing.append(end-start)
    require(serial.splitlines().count(b'MODEL_V13_READY cases=8 cpu=1')==1,'missing/duplicate serial completion')
    lines=serial.splitlines()
    require(all(lines.count(f'SMP_CPU_ON a={cpu} b={cpu} c=0'.encode())==1 for cpu in (1,2,3))
            and lines.count(b'SMP_BOOT_OK a=4 b=15 c=0')==1,
            'missing/duplicate native secondary boot handshakes')
    require(not any(s in serial for s in (b'FAIL',b'SMP_ERROR',b'PANIC')),'guest failure')
    return dict(native_integer_fixture_verified=True,production_isolation_verified=False,
                trained_model_verified=False,native_cluster_verified=False,synthetic=True,
                models=6,cases=8,captured_candidates=16,protection_probes=4,
                forced_stall_preemptions=h[5],inference_preemptions=preemptions,
                timer_frequency=h[9],inference_ticks=timing,business_progress=[h[7],h[8]])


def loaded_bytes(data: bytes, va: int, size: int) -> bytes:
    require(len(data)>=64,'truncated ELF')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    require(header[0][:7]==b'\x7fELF\x02\x01\x01' and header[2]==183 and header[9]==56,
            'invalid embedded AArch64 ELF')
    for index in range(header[10]):
        typ,flags,off,address,_,filesz,_,_=struct.unpack_from('<IIQQQQQQ',data,header[5]+56*index)
        if typ==1 and address<=va and va+size<=address+filesz:
            require(not flags&2,'fixture package must be read-only in ELF')
            result=data[off+va-address:off+va-address+size]
            require(len(result)==size,'truncated loaded bytes')
            return result
    raise ValueError('fixture bytes absent from ELF load image')


def profile(data: bytes) -> tuple[dict,bytes]:
    inspect_elf(data)
    require(boot_profile(data)['ram_mib']==1024,'model profile requires 1 GiB')
    evidence=symbol(data,'MODEL_V13_EVIDENCE')
    require(evidence['pa']%4096==0 and evidence['size']==EVIDENCE_BYTES,'invalid model evidence symbol')
    location=symbol(data,'PROTOTYPE_SERVICE_ELF')
    service=loaded_bytes(data,location['va'],location['size'])
    require(len(service)<=512*1024,'embedded service exceeds native loader limit')
    models,requests,metadata=fixtures()
    require(loaded_bytes(service,0x90000,len(models))==models,'embedded models differ from frozen fixture bytes')
    require((ROOT/'ports/prototype/models.bin').read_bytes()==models,'model fixture changed')
    require((ROOT/'ports/prototype/requests.bin').read_bytes()==requests,'input fixture changed')
    require(json.loads((ROOT/'ports/prototype/engineering-vectors.json').read_text())==metadata,
            'fixture metadata changed')
    return evidence,service


def run(elf: Path, output: Path, timeout: float=30) -> dict:
    require(1<=timeout<=60,'invalid execution deadline')
    elf=elf.resolve(strict=True);output=output.resolve()
    require(not output.exists(),'refuse to reuse evidence output')
    output.mkdir(parents=True)
    before=manifest();(output/'source-manifest.json').write_text(json.dumps(before,indent=2)+'\n')
    report=dict(status='FAIL',scope='native-el0-integer-engineering-fixtures',synthetic=True,
                native_integer_fixture_verified=False,production_isolation_verified=False,
                trained_model_verified=False,native_cluster_verified=False,runtime_truth_attested=False,
                elf_sha256=sha(elf),source_manifest_sha256=sha(output/'source-manifest.json'))
    started=time.monotonic();proc=sock=qmp=None;raw=bytearray();serial=bytearray();decoder=FrameDecoder()
    args=[];cpus=[];memory={}
    with tempfile.TemporaryDirectory(prefix='cyx-model-') as td, (output/'qemu-stderr.log').open('wb') as errors:
        try:
            location,service=profile(elf.read_bytes())
            (output/'prototype-control.elf').write_bytes(service)
            report['service_sha256']=sha(output/'prototype-control.elf')
            report['package']=fixtures()[2]
            binary=shutil.which('qemu-system-aarch64');require(binary is not None,'QEMU missing')
            version=subprocess.check_output([binary,'--version'],timeout=10,text=True)
            require(version.splitlines()[0] in ('QEMU emulator version 10.2.2',
                    'QEMU emulator version 10.2.2 (v10.2.2)'),'unverified QEMU version')
            report.update(qemu_version=version,qemu_sha256=sha(Path(binary)))
            path=str(Path(td)/'q.sock')
            args=[binary,'-machine','virt-10.2,gic-version=2,secure=off,virtualization=off',
                  '-cpu','cortex-a53','-smp','4','-m','1024M','-accel','tcg,thread=multi',
                  '-S','-display','none','-monitor','none','-nic','none',
                  '-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog',
                  '-qmp',f'unix:{path},server=on,wait=off','-kernel',str(elf),'-no-reboot']
            end=started+timeout
            proc=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=errors)
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None,'QEMU exited before handshake')
                if time.monotonic()>=end: raise TimeoutError('QMP startup deadline')
                try: sock.connect(path);break
                except (FileNotFoundError,ConnectionRefusedError): time.sleep(.01)
            qmp=Qmp(sock);require('QMP' in qmp.receive(end),'invalid QMP greeting')
            qmp.execute('qmp_capabilities');cpus=qmp.execute('query-cpus-fast')
            memory=qmp.execute('query-memory-size-summary')
            require(memory['base-memory']==1024*1024*1024,'wrong native RAM size')
            qmp.execute('cont')
            while time.monotonic()<end:
                require(proc.poll() is None,'QEMU exited before acceptance')
                chunk=base64.b64decode(qmp.execute('ringbuf-read',
                    {'device':'cyxlog','size':1048576,'format':'base64'}),validate=True)
                raw.extend(chunk);require(len(raw)<=2*1024*1024,'serial budget exceeded')
                for frame in decoder.feed(chunk):serial.extend(frame)
                require(not any(s in serial for s in (b'FAIL',b'SMP_ERROR',b'PANIC')),'guest failure')
                if b'MODEL_V13_READY cases=8 cpu=1\n' in serial:
                    qmp.execute('stop');page=output/'native-page.bin'
                    qmp.execute('pmemsave',{'val':location['pa'],'size':EVIDENCE_BYTES,'filename':str(page)})
                    require(decoder.loss==decoder.corrupt==0 and not decoder.buffer,'corrupt framed UART')
                    observations=validate(bytes(serial),page.read_bytes(),len(cpus))
                    require(sha(elf)==report['elf_sha256'],'ELF changed during run')
                    require(before==manifest(),'source changed during run')
                    report.update(status='PASS',native_integer_fixture_verified=True,observations=observations)
                    break
                time.sleep(.01)
            else: raise TimeoutError('native EL0 fixture deadline')
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError,struct.error) as error:
            report['error']=type(error).__name__+': '+str(error)
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    if qmp:qmp.execute('quit')
                except (OSError,ValueError,RuntimeError): pass
                try:proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
            if sock:sock.close()
            (output/'serial.bin').write_bytes(raw);(output/'serial.txt').write_bytes(serial)
            if qmp:(output/'qmp.jsonl').write_text(''.join(json.dumps(m)+'\n' for m in qmp.transcript))
            (output/'launch.json').write_text(json.dumps(dict(argv=args,cpus=cpus,memory=memory,
                exit=proc.returncode if proc is not None else None,
                transport=dict(frames=decoder.frames,lost=decoder.loss,corrupt=decoder.corrupt)),indent=2)+'\n')
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['evidence_sha256']={str(p.relative_to(output)):sha(p) for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--timeout',type=float,default=30)
    args=parser.parse_args()
    try:result=run(args.elf,args.output,args.timeout)
    except (OSError,ValueError) as error:
        print(str(error),file=__import__('sys').stderr);return 1
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
