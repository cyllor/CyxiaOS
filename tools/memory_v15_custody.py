"""A09 source/build/ELF and stopped-memory custody, independent of producer verdicts."""
import base64
import ast
import json
from pathlib import Path
import struct
from build_unified import code_source_map
from check_elf import symbol,inspect_elf,boot_profile
from check_prototype_evidence import read_json,safe_path,sha256,require
from verify_v13_boot_receipt import verify_launch,_exchanges
from verify_v13_a02 import verify_native_qemu,verify_stopped_status
from verify_v13_a10_native_receipt import validate_dtb
from verify_v13_boot_recovery import CONFIG_MAGIC,verify_samples
from boot_reboot_contract import verify_process
from transport import FrameDecoder
from verify_v15_memory import WORDS,PRIVATE_VAS,PA_MASK,verify_raw
from memory_v15_client import current_code,user_code

def _local_tool_dependencies(roots):
    """Bind imported local modules, including a builder's cache/lock helpers."""
    directory=Path(__file__).resolve().parent;pending=list(roots);seen=set()
    while pending:
        name=pending.pop()
        if name in seen:continue
        seen.add(name)
        for node in ast.walk(ast.parse((directory/name).read_text())):
            modules=([node.module] if isinstance(node,ast.ImportFrom) and node.module else
                [item.name for item in node.names] if isinstance(node,ast.Import) else [])
            for module in modules:
                dependency=module.split('.')[0]+'.py'
                if (directory/dependency).is_file() and dependency not in seen:pending.append(dependency)
    return tuple(sorted(seen))


TOOL_FILES=_local_tool_dependencies(('memory_v15_custody.py','memory_v15_client.py','verify_v15_memory.py','run_v15_memory.py','build_unified.py',
 'run_qemu.py','run_v13_a02.py','verify_v13_a02.py','verify_unified.py','check_elf.py',
 'check_prototype_evidence.py','verify_v13_boot_receipt.py','verify_v13_boot_recovery.py',
 'verify_v13_a10_native_receipt.py','boot_reboot_contract.py','transport.py'))
SYMBOLS={'memory':'MEMORY_V15_EVIDENCE','boot':'A01_BOOT_EVIDENCE','config':'A01_BOOT_CONFIG',
 'control':'DOMAIN_CONTROL_EVIDENCE','runtime':'RUNTIME_V13_EVIDENCE','unified':'UNIFIED_EVIDENCE',
 'tasks':'DOMAIN_TASK_EVIDENCE','file':'FILE_SERVICE_EVIDENCE'}


def verify_build(build,source):
    build=Path(build).resolve(strict=True);source=Path(source).resolve(strict=True)
    m=read_json(safe_path(build,'build-manifest.json'));p=m['profiles']
    require(m.get('schema_version')==1 and m.get('status')=='BUILT_NOT_RUN' and p.get('memory_probe') is True
            and p.get('selftest') is True and p.get('fault')=='normal' and p.get('service_fault')=='none'
            and p.get('storage_fault') is False and p.get('leave') is False,'wrong A09 normal mechanism profile')
    require(m['code_source_map']==code_source_map(source)
            and m['builder_sha256']==sha256(source/'tools/build_unified.py'),'A09 source/build mismatch')
    for name in ('node-a.elf','memory-client-a.elf'):
        item=m['artifacts'][name];path=safe_path(build,name)
        require(item==dict(bytes=path.stat().st_size,sha256=sha256(path)),'changed A09 build image')
    image=(build/'node-a.elf').read_bytes();inspect_elf(image)
    require(boot_profile(image)['ram_mib']==1024 and (build/'memory-client-a.elf').read_bytes() in image,
            'ordinary A09 ELF not embedded in actual 1GiB image')
    marker=symbol(image,'MEMORY_V15_PROFILE')
    from verify_v13_model import loaded_bytes
    require(marker['size']==40 and struct.unpack('<5Q',loaded_bytes(image,marker['va'],40))==(1,1,2,4097,WORDS),
            'wrong A09 immutable profile marker')
    symbols={k:symbol(image,n) for k,n in SYMBOLS.items()}
    require(symbols['memory']['size']==WORDS*8 and symbols['config']['size']==symbols['boot']['size']==512,'wrong A09 bank symbols')
    code=user_code((build/'memory-client-a.elf').read_bytes())
    require(code==current_code(source),'actual archived ordinary client differs from freshly compiled current source')
    return m,symbols,code


def phase_names(stage):
    names=[f'{stage}-memory.bin']
    if stage in (1,3):names.append('boot-first.bin' if stage==1 else 'boot-last.bin')
    for role in (1,2):
        names += [f'{stage}-{role}-{x}.bin' for x in ('root','mid','leaf')]
        names += [f'{stage}-{role}-page{p}.bin' for p in range(len(PRIVATE_VAS))]
        names += [f'{stage}-{role}-code{p}.bin' for p in range(4)]
    if stage==3:names+=['control.bin','runtime.bin','unified.bin']
    return names


def verify_native(root,*,build,source_root,qemu_source):
    root=Path(root).resolve(strict=True);source=Path(source_root).resolve(strict=True);qemu_source=Path(qemu_source).resolve(strict=True)
    path=lambda n:safe_path(root,n);doc=lambda n:read_json(path(n))
    manifest,symbols,code=verify_build(build,source)
    mandatory={'node-a.elf','memory-client.elf','build-manifest.json','source-manifest.json','input.json',
        'config.bin','config-observed.bin','config-injection.json','tools.json','launch.json','platform.json',
        'platform.dtb','dtb-header.bin','disk.raw','disk-before.json','format.log','capture-map.json',
        'pending-memory.bin','qmp-transcript.json','serial.bin','serial.txt','qemu-stderr.log','process-exit.json'}
    mandatory|={n for s in (1,2,3) for n in phase_names(s)}|{'tooling/'+n for n in TOOL_FILES}
    inventory=doc('inventory.json');require(inventory.get('schema')==1 and set(inventory['files'])==mandatory,'incomplete A09 inventory')
    for name,item in inventory['files'].items():
        require(type(item) is dict and set(item)=={'bytes','sha256'} and type(item['bytes']) is int
                and 0<=item['bytes']<=512*1024**2 and path(name).stat().st_size==item['bytes']
                and sha256(path(name))==item['sha256'],'A09 changed artifact '+name)
    for n in TOOL_FILES:require(sha256(path('tooling/'+n))==sha256(source/'tools'/n),'A09 unreviewed tooling '+n)
    require(doc('build-manifest.json')==manifest and sha256(path('node-a.elf'))==manifest['artifacts']['node-a.elf']['sha256']
            and sha256(path('memory-client.elf'))==manifest['artifacts']['memory-client-a.elf']['sha256']
            and doc('source-manifest.json')==code_source_map(source),'A09 archive differs from caller-selected source/build')
    inputs=doc('input.json');config=path('config.bin').read_bytes()
    require(inputs.keys()=={'scope','nonce','timeout_seconds','file_pages','checkpoint_wait_ns','poll_interval_ns','formatter_sha256'}
            and inputs['scope']=='A09-memory-cache-pressure' and inputs['file_pages']==4097
            and inputs['checkpoint_wait_ns']==2_000_000_000 and inputs['poll_interval_ns']==100_000_000
            and 5<=inputs['timeout_seconds']<=600,'A09 frozen workload differs')
    expected=(struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+bytes.fromhex(inputs['nonce'])
        +bytes.fromhex(sha256(path('node-a.elf')))+bytes.fromhex(sha256(path('input.json')))
        +bytes.fromhex(sha256(path('source-manifest.json')))+bytes(368))
    require(config==expected==path('config-observed.bin').read_bytes(),'A09 unbound config')
    from run_v13_a02 import config_write_packet
    injection=doc('config-injection.json')
    require(injection.keys()=={'request_hex','received_hex','ack_hex'} and injection['request_hex']==config_write_packet(config,symbols['config']['pa']).hex()
            and injection['ack_hex']=='2b' and bytes.fromhex(injection['received_hex']).lstrip(b'+')==b'$OK#9a','A09 write outside preboot identity config')
    launch=doc('launch.json');require(launch.keys()=={'argv','symbols'} and launch['symbols']==symbols,'A09 capture symbols differ from actual ELF')
    captured=verify_launch(launch['argv']);qemu=qemu_source/'build/qemu-system-aarch64'
    require(launch['argv'][0]==str(qemu.resolve(strict=True)),'A09 archive-selected emulator')
    verify_native_qemu(doc('tools.json'),qemu,qemu_source=qemu_source)
    platform=doc('platform.json');require(len(platform['cpus'])==4 and sorted(x['cpu-index'] for x in platform['cpus'])==list(range(4))
        and platform['memory']['base-memory']==1024**3,'A09 native platform mismatch')
    dtb=path('platform.dtb').read_bytes();validate_dtb(dtb);require(dtb[:40]==path('dtb-header.bin').read_bytes(),'A09 DTB header differs')
    before=doc('disk-before.json');require(before.keys()=={'bytes','sha256'} and before['bytes']==512*1024**2 and path('disk.raw').stat().st_size==before['bytes'],'A09 wrong disk input capacity')
    require(f'nonce={inputs["nonce"]}'.encode() in path('format.log').read_bytes() and b'A09_INPUT fixture_pages=4097 file_limit_pages=2048 ' in path('format.log').read_bytes(),'A09 wrong provisioned workload')
    captures={};specs={'dtb-header.bin':(0x40000000,40),'platform.dtb':(0x40000000,len(dtb)),
        'config-observed.bin':(symbols['config']['pa'],512),'pending-memory.bin':(symbols['memory']['pa'],WORDS*8)}
    banks=[]
    for stage in (1,2,3):
        bank=path(f'{stage}-memory.bin').read_bytes();require(len(bank)==WORDS*8,'short A09 bank');banks.append(bank)
        w=struct.unpack('<%dQ'%WORDS,bank);specs[f'{stage}-memory.bin']=(symbols['memory']['pa'],WORDS*8)
        if stage in (1,3):specs['boot-first.bin' if stage==1 else 'boot-last.bin']=(symbols['boot']['pa'],512)
        for role in (1,2):
            b=64+(role-1)*192;addresses=[w[b+3]]
            for kind in ('root','mid','leaf'):
                name=f'{stage}-{role}-{kind}.bin';data=path(name).read_bytes();require(len(data)==4096,'short A09 table')
                captures[name]=data;specs[name]=(addresses[-1],4096)
                if kind!='leaf':addresses.append(struct.unpack_from('<Q',data)[0]&PA_MASK)
            captures[f'{stage}-{role}-table-addresses']=addresses
            leaf=struct.unpack('<512Q',captures[f'{stage}-{role}-leaf.bin'])
            for p,va in enumerate(PRIVATE_VAS):
                name=f'{stage}-{role}-page{p}.bin';captures[name]=path(name).read_bytes();specs[name]=(leaf[va//4096]&PA_MASK,4096)
            for p in range(4):
                name=f'{stage}-{role}-code{p}.bin';require(path(name).read_bytes()==code[p*4096:p*4096+4096],'A09 executed client code differs from source-built ELF')
                specs[name]=(leaf[16+p]&PA_MASK,4096)
    for name,key,size in [('control.bin','control',4096),('runtime.bin','runtime',8192),('unified.bin','unified',4096)]:specs[name]=(symbols[key]['pa'],size)
    require(doc('capture-map.json')=={n:list(v) for n,v in specs.items()},'A09 producer capture map differs from actual physical walk')
    result=verify_raw(banks,captures,config)
    groups=[];pre=set();queries=set();running=False;started=False;status=False;serial=bytearray()
    exchanges=_exchanges(doc('qmp-transcript.json'))
    for position,(request,response) in enumerate(exchanges):
        cmd=request['execute'];args=request.get('arguments')
        if cmd=='qmp_capabilities':require(position==0 and args is None and response=={},'A09 invalid QMP setup')
        elif cmd in ('query-cpus-fast','query-memory-size-summary'):
            require(not started and cmd not in queries and args is None and response==platform['cpus' if cmd=='query-cpus-fast' else 'memory'],'A09 missing/duplicate native platform query');queries.add(cmd)
        elif cmd=='cont':
            require(args is None and response=={} and not running and pre=={'dtb-header.bin','platform.dtb','config-observed.bin'} and len(queries)==2,'A09 invalid preboot/resume')
            if started:require(status and len(groups) in (1,2) and groups[-1]==phase_names(len(groups)),'A09 incomplete stage before resume')
            started=running=True;status=False
        elif cmd=='stop':require(running and args is None and response=={},'A09 invalid stop');running=False;status=False;groups.append([])
        elif cmd=='query-status':require(started and not running and not status and args is None,'A09 invalid stopped status order');verify_stopped_status([response]);status=True
        elif cmd=='pmemsave':
            require(type(args) is dict and args.keys()=={'val','size','filename'} and response=={},'A09 unexpected memory command')
            name=Path(args['filename']).name
            require(name in specs and args==dict(val=specs[name][0],size=specs[name][1],filename=str(captured/name)),'A09 wrong physical address/capture')
            if name in ('dtb-header.bin','platform.dtb','config-observed.bin'):
                require(not started and name not in pre,'A09 late/duplicate preboot sample');pre.add(name)
            elif name=='pending-memory.bin':require(running,'A09 readiness bytes are not stopped evidence')
            else:require(started and not running and status and name not in groups[-1],'A09 memory captured while running');groups[-1].append(name)
        elif cmd=='ringbuf-read':
            require(running and args==dict(device='cyxlog',size=1048576,format='base64') and type(response) is str,'A09 invalid UART read')
            serial.extend(base64.b64decode(response,validate=True));require(len(serial)<=8*1024**2,'A09 serial budget')
        elif cmd=='quit':require(position==len(exchanges)-1 and not running and status and groups==[phase_names(s) for s in (1,2,3)] and args is None and response=={},'A09 incomplete stopped capture groups')
        else:raise ValueError('A09 forbidden QMP operation '+cmd)
    require(exchanges[-1][0]['execute']=='quit' and bytes(serial)==path('serial.bin').read_bytes(),'A09 missing closed transcript/serial')
    decoder=FrameDecoder();text=b''.join(p+b'\n' for p in decoder.feed(bytes(serial)))
    require(text==path('serial.txt').read_bytes() and not decoder.buffer and decoder.loss==decoder.corrupt==0
        and text.count(b'SMP_BOOT_OK a=4 b=15 c=0\n')==1 and not any(x in text for x in (b'PANIC',b'UNIFIED_FAIL',b'SMP_ERROR')),'A09 failed/incomplete actual guest execution')
    verify_process(doc('process-exit.json'))
    verify_samples(*(path(n).read_bytes() for n in ('boot-first.bin','boot-last.bin','control.bin','runtime.bin','unified.bin','config.bin')))
    result.update(status='PASS',test_id='A09',native_execution_verified=True,native_acceptance_status='PASS',
        full_a09_verified=True,actual_cache_pressure_verified=True,
        scope='ordinary EL0 anonymous faults and full 4097-page cache pressure with stopped physical ownership/content and native custody',
        runtime_truth_attested=False,verifier_version='v15-a09-memory-v1',source_sha256=sha256(path('source-manifest.json')),
        image_sha256=sha256(path('node-a.elf')),run_nonce=inputs['nonce'])
    return result
