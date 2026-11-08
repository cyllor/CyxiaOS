#!/usr/bin/env python3
"""Strict A06 register-boundary subcase. Raw fixtures cannot establish native PASS."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct

from check_prototype_evidence import require

MAGIC=0x4359585245473031
CONFIG_MAGIC=0x4359585245474346
ROW=928
EVENT=112
WORDS=64+6*ROW
TOOL_FILES=('run_v15_registers.py','verify_v15_registers.py','build_v15_registers.py',
            'run_qemu.py','build_unified.py','check_elf.py','verify_v13_boot_receipt.py',
            'verify_v13_a02.py','verify_unified.py','verify_v13_model.py',
            'check_prototype_evidence.py','transport.py','boot_reboot_contract.py','doctor.py',
            'verify_v13_a10_native_receipt.py')


def require_platform_queries(seen):
    require(seen=={'query-cpus-fast','query-memory-size-summary'},'missing required native platform query')


def observe_platform_query(command,response,args,platform,seen,state):
    require(state=='preboot' and command not in seen and not args
            and command in ('query-cpus-fast','query-memory-size-summary'),'late/duplicate platform query')
    require(response==platform['cpus' if command=='query-cpus-fast' else 'memory'],'platform transcript differs')
    seen.add(command)


def validate_platform_dtb(data):
    from verify_v13_a10_native_receipt import validate_dtb
    validate_dtb(data)


def verify_build(build,source_root):
    from build_unified import code_source_map
    from check_prototype_evidence import read_json,sha256,safe_path
    from check_elf import symbol,inspect_elf
    from verify_v13_model import loaded_bytes
    build=Path(build).resolve(strict=True);source_root=Path(source_root).resolve(strict=True)
    m=read_json(safe_path(build,'build-manifest.json'))
    require(m.get('schema')==1 and m.get('profile')=='register-v15-selftest'
            and m['code_source_map']==code_source_map(source_root),'source/profile build mismatch')
    require(m['builder_sha256']==sha256(source_root/'tools/build_v15_registers.py')
            and m['image_sha256']==sha256(safe_path(build,'registers.elf'))
            and m['build_log_sha256']==sha256(safe_path(build,'build.log')),'build artifact identity mismatch')
    require(m['rustc'].startswith('rustc 1.95.0 ') and m['cargo'].startswith('cargo 1.95.0 '),'untrusted toolchain')
    require(m['command'][1:]==['build','--locked','--offline','--release','-p','cyxia-kernel',
              '--target','aarch64-unknown-none-softfloat','--no-default-features','--features',
              'register-v15-selftest','--message-format=json-render-diagnostics'],'wrong build flags')
    image=safe_path(build,'registers.elf').read_bytes();p=symbol(image,'REGISTER_V15_PROFILE')
    require(p['size']==32 and struct.unpack('<4Q',loaded_bytes(image,p['va'],32))==(1,4,6,WORDS),'wrong ELF register marker')
    c=symbol(image,'REGISTER_V15_CONFIG')
    require(c['size']==128 and any(s['pa']<=c['pa'] and c['pa']+128<=s['pa']+s['size']
            for s in inspect_elf(image)['loads']), 'preboot config is erased by BSS zeroing')
    segment=next(s for s in inspect_elf(image)['loads'] if s['pa']<=c['pa'] and c['pa']+128<=s['pa']+s['size'])
    require(struct.unpack_from('<2Q',image,segment['offset']+c['pa']-segment['pa'])==(CONFIG_MAGIC,1),
            'invalid file-backed register config')
    return m


def verify_native(root,*,build,source_root,qemu_source):
    """Replay custody from caller-selected build/source/tools; ignore producer verdicts."""
    import base64
    import re
    from build_unified import code_source_map
    from check_elf import symbol,inspect_elf,boot_profile
    from check_prototype_evidence import read_json,sha256,safe_path
    from verify_v13_a02 import verify_native_qemu,verify_stopped_status
    from verify_v13_boot_receipt import _exchanges
    from boot_reboot_contract import verify_process
    from transport import FrameDecoder
    from run_v15_registers import packet
    root=Path(root).resolve(strict=True);source_root=Path(source_root).resolve(strict=True)
    build=Path(build).resolve(strict=True);qemu_source=Path(qemu_source).resolve(strict=True)
    path=lambda n:safe_path(root,n)
    doc=lambda n:read_json(path(n))
    inv=doc('inventory.json');files=inv.get('files')
    mandatory={'registers.elf','build-manifest.json','source-manifest.json','config.bin',
       'input.json','tools.json','launch.json','platform.json','dtb-header.bin','platform.dtb',
       'config-injection.json','config-observed.bin','first.bin','last.bin',
       'qmp-transcript.json','process-exit.json','serial.bin','serial.txt','qemu-stderr.log'}
    mandatory|={'tooling/'+n for n in TOOL_FILES}
    require(inv.get('schema')==1 and type(files) is dict and set(files)==mandatory,'incomplete register inventory')
    for n,item in files.items():
        require(type(item) is dict and set(item)=={'bytes','sha256'}
                and type(item['bytes']) is int and 0<=item['bytes']<=64*1024*1024
                and path(n).stat().st_size==item['bytes'] and sha256(path(n))==item['sha256'],
                'changed register artifact '+n)
    for n in TOOL_FILES:
        require(sha256(path('tooling/'+n))==sha256(source_root/'tools'/n),'capture tool changed '+n)
    expected=verify_build(build,source_root)
    require(doc('build-manifest.json')==expected and sha256(path('registers.elf'))==expected['image_sha256'],
            'archived image differs from explicit trusted build')
    require(doc('source-manifest.json')==code_source_map(source_root),'capture source differs')
    image=path('registers.elf').read_bytes();loads=inspect_elf(image)['loads']
    require(boot_profile(image)['ram_mib']==1024,'wrong RAM boot ABI')
    symbols={k:symbol(image,n) for k,n in [('config','REGISTER_V15_CONFIG'),('capture','REGISTER_V15_EVIDENCE')]}
    require(symbols['config']['size']==128 and symbols['capture']['size']==WORDS*8,'capture symbol size')
    for s in symbols.values():
        require(s['pa']%64==0 and any(seg['flags']==6 and seg['pa']<=s['pa']
                and s['pa']+s['size']<=seg['pa']+seg['mem'] for seg in loads),'unprotected register evidence')
    inputs=doc('input.json');config=path('config.bin').read_bytes()
    require(inputs.keys()=={'scope','nonce','timeout_seconds','sample_gap_seconds'}
            and inputs['scope']=='A06-register-context' and type(inputs['timeout_seconds']) in (int,float)
            and 5<=inputs['timeout_seconds']<=60 and inputs['sample_gap_seconds']==.1,'wrong register input')
    require(config==make_config(bytes.fromhex(inputs['nonce']),bytes.fromhex(sha256(path('registers.elf'))),
            bytes.fromhex(sha256(path('source-manifest.json'))),bytes.fromhex(sha256(path('input.json'))))
            and config==path('config-observed.bin').read_bytes(),'unbound register config')
    injection=doc('config-injection.json')
    require(injection.keys()=={'request_hex','received_hex','ack_hex'}
            and injection['request_hex']==packet(config,symbols['config']['pa']).hex()
            and injection['ack_hex']=='2b' and bytes.fromhex(injection['received_hex']).lstrip(b'+')==b'$OK#9a',
            'write outside fixed preboot register config')
    launch=doc('launch.json');argv=launch['argv']
    require(launch.keys()=={'argv','symbols'} and launch['symbols']==symbols and type(argv) is list,'wrong register launch')
    qemu=qemu_source/'build/qemu-system-aarch64'
    require(argv[0]==str(qemu.resolve(strict=True)),'archive-selected emulator')
    verify_native_qemu(doc('tools.json'),qemu,qemu_source=qemu_source)
    fixed=['-machine','virt-10.2,gic-version=2,secure=off,virtualization=off','-cpu','cortex-a53',
           '-smp','4','-m','1024M','-accel','tcg,thread=multi','-S','-display','none','-monitor','none',
           '-nic','none','-chardev','ringbuf,id=cyxlog,size=1048576','-serial','chardev:cyxlog']
    require(argv[1:22]==fixed and len(argv)==29 and argv[22]=='-qmp' and argv[24]=='-gdb'
            and argv[26]=='-kernel' and argv[28:]==['-no-reboot'], 'unexpected register launch flags')
    # Indexes are derived below rather than trusting paths embedded in the receipt.
    require(argv[-3]=='-kernel' and Path(argv[-2]).is_absolute() and Path(argv[-2]).name=='registers.elf','wrong image path')
    captured=Path(argv[-2]).parent
    sockets=[]
    for value,name in ((argv[23],'q.sock'),(argv[25],'g.sock')):
        match=re.fullmatch(r'unix:([^,]+),server=on,wait=off',value)
        require(match is not None and Path(match[1]).is_absolute() and Path(match[1]).name==name,'invalid debug socket')
        sockets.append(Path(match[1]))
    require(sockets[0].parent==sockets[1].parent,'mixed debug socket roots')
    platform=doc('platform.json');require(len(platform['cpus'])==4 and platform['memory']['base-memory']==1024**3,'wrong native platform')
    require(sorted(c['cpu-index'] for c in platform['cpus'])==list(range(4)),'duplicate CPUs')
    header=path('dtb-header.bin').read_bytes();dtb=path('platform.dtb').read_bytes()
    require(len(header)==40 and dtb[:40]==header and 40<=len(dtb)<=2*1024*1024
            and struct.unpack_from('>2I',header)==(0xd00dfeed,len(dtb)),'invalid captured DTB')
    validate_platform_dtb(dtb)
    exchanges=_exchanges(doc('qmp-transcript.json'));state='preboot';stopped=False;seen=[];serial=bytearray();status=False
    queries=set()
    specs={'dtb-header.bin':(0x40000000,40),'platform.dtb':(0x40000000,len(dtb)),
           'config-observed.bin':(symbols['config']['pa'],128),
           'first.bin':(symbols['capture']['pa'],WORDS*8),'last.bin':(symbols['capture']['pa'],WORDS*8)}
    for i,(request,response) in enumerate(exchanges):
        cmd=request['execute'];args=request.get('arguments',{})
        if cmd=='qmp_capabilities':require(i==0 and not args,'late capabilities')
        elif cmd in ('query-cpus-fast','query-memory-size-summary'):
            observe_platform_query(cmd,response,args,platform,queries,state)
        elif cmd=='pmemsave':
            require(type(args) is dict and args.keys()=={'val','size','filename'} and response=={},'unexpected memory operation')
            name=Path(args['filename']).name
            require(name in specs and name not in seen and args['filename']==str(captured/name)
                    and (args['val'],args['size'])==specs[name],'wrong capture address/path/count')
            if name in ('first.bin','last.bin'):
                require(stopped and status and state=='running','memory captured before stop acknowledgment')
            else:require(state=='preboot','late preboot capture')
            seen.append(name)
        elif cmd=='cont':
            require_platform_queries(queries)
            require(not args and (state=='preboot' and seen==list(specs)[:3] or stopped and seen[-1]=='first.bin'),'unexpected resume')
            state='running';stopped=False;status=False
        elif cmd=='stop':require(state=='running' and not stopped and not args,'unexpected stop');stopped=True;status=False
        elif cmd=='query-status':
            require(stopped and not status and not args,'unexpected stopped status');verify_stopped_status([response]);status=True
        elif cmd=='ringbuf-read':
            require(state=='running' and not stopped and args==dict(device='cyxlog',size=1048576,format='base64'),'unexpected UART operation')
            serial.extend(base64.b64decode(response,validate=True));require(len(serial)<=2*1024*1024,'serial overflow')
        elif cmd=='quit':require(i==len(exchanges)-1 and stopped and seen==list(specs) and not args,'premature quit')
        else:raise ValueError('unexpected QMP operation '+cmd)
    require(exchanges[-1][0]['execute']=='quit' and seen==list(specs),'incomplete capture transcript')
    require(bytes(serial)==path('serial.bin').read_bytes(),'serial differs from QMP')
    decoder=FrameDecoder();text=b''.join(p+b'\n' for p in decoder.feed(bytes(serial)))
    require(not decoder.buffer and decoder.loss==decoder.corrupt==0 and text==path('serial.txt').read_bytes()
            and text.count(b'REGISTER_CONTEXT_DONE a=0 b=6 c=0\n')==1
            and text.count(b'SMP_BOOT_OK a=4 b=15 c=0\n')==1
            and not any(x in text for x in (b'PANIC',b'FAIL',b'SMP_ERROR')),'failed/incomplete framed guest execution')
    verify_process(doc('process-exit.json'))
    first,last=(path(n).read_bytes() for n in ('first.bin','last.bin'))
    require(first==last,'register bank changed after completion')
    result=check(first,config)
    result.update(status='PASS',native_execution_verified=True,register_subcase_status='PASS',
                  native_acceptance_status='NOT_RUN',runtime_truth_attested=False)
    return result


def make_config(nonce, image, source, inputs):
    require(len(nonce)==16 and all(len(x)==32 for x in (image,source,inputs)), 'config digest size')
    return struct.pack('<2Q',CONFIG_MAGIC,1)+nonce+image+source+inputs


def expected_seed(identity,j):
    x=identity[3]
    return ((identity[2]^((x<<17)|(x>>47)))&0xffff0000)+(j+1)*0x100000000+j+1


def check(data, config):
    require(len(data)==WORDS*8 and len(config)==128,'register evidence size')
    w=struct.unpack('<%dQ'%WORDS,data); identity=struct.unpack('<16Q',config)
    require(identity[:2]==(CONFIG_MAGIC,1) and any(identity[2:4]),'register config identity')
    require(w[:6]==(MAGIC,1,2,15,6,0) and w[6]>0 and w[7]>0,'unsealed or failed register evidence')
    require(w[8:24]==identity and not any(w[24:64]),'register run identity/reserved')
    roots=set(); counts=[]
    for j in range(6):
        b=64+j*ROW; r=w[b:b+ROW]; cpu=j//2+1; local=j%2
        seed=expected_seed(identity,j)
        require(r[:3]==(cpu,local,seed) and r[3]%4096==0 and 0x40200000<=r[3]<0x44000000,
                'register task identity/root')
        require(r[3] not in roots,'shared register task address space'); roots.add(r[3])
        require(r[4:8]==(4,4,1,1) and 8<=r[8]<=256 and r[9:12]==(0,8,0)
                and not any(r[12:32]),'incomplete fresh/ready/timer/SVC evidence')
        seen=set(); previous=0
        for k in range(8):
            e=r[32+k*EVENT:32+(k+1)*EVENT]; c=e[8:]
            require(e[0]>0 and e[0]%2==(local+1)%2 and e[0]<=r[8] and e[0] not in seen,
                    'duplicate or wrong alternating task turn')
            seen.add(e[0])
            # Events are grouped by boundary type; their turn numbers retain real order.
            require(e[1]>0 and e[2]>e[1] and e[3:6]==(1 if k<4 else 2,j,1)
                    and e[6]==e[0]-1 and e[7]==(1 if k<4 else 0),'entry/return/other-task boundary')
            require(c[19:30]==tuple(seed+x for x in range(19,30)), 'x19-x29 preservation')
            require(c[37]==seed, 'TPIDR preservation')
            require(c[38:102]==tuple(v for q in range(32) for v in (seed+128+q,seed+256+q)),
                    'complete SIMD bank preservation')
            require(c[102:104]==((seed&3)<<22,seed%31+1),'FPCR/FPSR preservation')
            require(0x10000<=c[31]<0x11000 and c[31]%4==0 and c[33]==0x31000
                    and c[32]&~0xf0000000==0,'invalid EL0 return PC/SP/PSTATE')
            if k<4:
                require(c[36]==9,'non-timer counted as preemption')
            else:
                require(c[36]==8 and c[34]>>26==0x15 and c[34]&0xffff==0x606,
                        'fault/unknown SVC counted as successful syscall boundary')
        counts.append({'cpu':cpu,'context':local,'timer':r[4],'svc':r[5],'turns':r[8]})
    return dict(status='STRUCTURE_VALID',native_acceptance_status='NOT_RUN',
                scope='A06 register context subcase only',contexts=counts,
                full_a06_verified=False,syscall_scope='architectural SVC, not POSIX syscall dispatch')


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path);p.add_argument('--config',type=Path)
    for name in ('build','source-root','qemu-source'):p.add_argument('--'+name,type=Path)
    a=p.parse_args(argv)
    if a.config:
        require(a.build is a.source_root is a.qemu_source is None,'mixed raw/native verification')
        result=check(a.capture.read_bytes(),a.config.read_bytes())
    else:
        require(all(x is not None for x in (a.build,a.source_root,a.qemu_source)),
                'native replay needs explicit trusted build/source/QEMU')
        result=verify_native(a.capture,build=a.build,source_root=a.source_root,qemu_source=a.qemu_source)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
