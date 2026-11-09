"""Independent ordinary A03 scene custody; never a full A03 acceptance gate."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

from boot_reboot_contract import DISK_BYTES, verify_origin
from build_unified import code_source_map
from build_v16_a03_demand import LAYOUT, elf_profile
from check_elf import boot_profile, inspect_elf, symbol
from check_prototype_evidence import read_json, _pairs
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, require, verify_samples
from verify_v13_model import loaded_bytes
from v16_a03_focus import bounded_inventory, launch_argv, sha, write_json

VERSION = 'v16-a03-ordinary-demand-capture-v2'
TOOL_ROOT = Path(__file__).resolve().parents[1]
BANKS = {'publication-cost':('DOMAIN_PUBLICATION_COST',1024), 'boot':('A01_BOOT_EVIDENCE',512), 'config':('A01_BOOT_CONFIG',512),
    'control':('DOMAIN_CONTROL_EVIDENCE',(512+64*640)*8),
    'runtime':('RUNTIME_V13_EVIDENCE',8192), 'unified':('UNIFIED_EVIDENCE',4096),
    'demand':('A03_DEMAND_V16_EVIDENCE',1024), 'quiet-model':('A03_QUIET_MODEL_V16_EVIDENCE',5120),
    'ownership':('OWNERSHIP_V15_EVIDENCE',(128+8*896)*8),
    'tasks':('DOMAIN_TASK_EVIDENCE',256), 'credit':('CONTROL_CREDIT_EVIDENCE',512),
    'settlement':('CONTROL_SETTLEMENT_EVIDENCE',512)}


def closure(root=TOOL_ROOT, entries=None):
    root = Path(root).resolve(strict=True)
    pending = list(entries or ('run_v16_a03_demand','v16_a03_demand','verify_v16_a03_demand'))
    found = {}
    while pending:
        name = pending.pop()
        if name in found: continue
        require(len(found) < 128, 'demand tool closure bound')
        path = root/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(), 'missing/linked trusted demand tool')
        found[name] = sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports = ([node.module] if isinstance(node,ast.ImportFrom) else
                [item.name for item in node.names] if isinstance(node,ast.Import) else [])
            for item in imports:
                if item and (root/'tools'/(item+'.py')).is_file(): pending.append(item)
    result = {'tools/'+name+'.py':digest for name,digest in sorted(found.items())}
    if entries is None:
        patch = 'tools/qemu/cyxia-per-vcpu-pmu.patch'; result[patch] = sha(root/patch)
    return result


def trusted_context(*, source_root, build_manifest, formatter, qemu_binary, qemu_source, producer_tools_root=None):
    values = dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source)
    require(all(not Path(v).is_symlink() for v in values.values()), 'linked demand trust input')
    paths = {k:Path(v).resolve(strict=True) for k,v in values.items()}
    source = paths['source_root']; build = paths['build_manifest']
    for name in ('formatter','qemu_binary'):
        require(paths[name].is_file() and os.access(paths[name],os.X_OK), 'demand trusted tool not executable')
    sources = code_source_map(source); manifest = read_json(build)
    require(manifest.get('schema_version') == 1 and manifest.get('contract') == 'v16-a03-ordinary-demand-build-v1'
        and manifest.get('status') == 'BUILT_NOT_RUN' and manifest.get('demand_profile') == 'ordinary-rise-fall'
        and manifest.get('profile_environment') == {'CYXIA_A03_DEMAND':'ordinary-rise-fall','CYXIA_LEARNING_COLLECTION':'full'},
        'wrong explicit ordinary demand build')
    base_path = build.parent/'base-build-manifest.json'; base = read_json(base_path)
    require(manifest.get('base_manifest') == dict(path=base_path.name,bytes=base_path.stat().st_size,sha256=sha(base_path)),
        'ordinary demand base manifest mismatch')
    p = base['profiles']
    require(base['schema_version'] == 1 and base['status'] == 'BUILT_NOT_RUN' and p['fault'] == 'normal'
        and p['selftest'] is True and p.get('service_fault','none') == 'none'
        and p.get('service_fault_nodes',{'a':'none','b':'none'}) == {'a':'none','b':'none'}
        and all(p.get(k,False) is False for k in ('leave','storage_fault','memory_probe')),
        'conflicting ordinary demand base profile')
    source_hash = hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    require(manifest['code_source_map'] == base['code_source_map'] == sources
        and manifest['code_source_sha256'] == base['code_source_sha256'] == source_hash
        and base['builder_sha256'] == sha(source/'tools/build_unified.py')
        and base['own_private_key_only_verified'] is True
        and manifest['builder_sources'] == closure(source,('build_v16_a03_demand',)), 'ordinary demand source/builder mismatch')
    artifacts = {}
    for name in ('node-a.elf','node-b.elf','service-a.elf','task.elf','node-a.pub'):
        path = build.parent/name
        require(path.is_file() and not path.is_symlink() and base['artifacts'][name]['sha256'] == sha(path)
            and base['artifacts'][name]['bytes'] == path.stat().st_size, 'ordinary demand artifact mismatch')
        artifacts[name] = sha(path)
    image = (build.parent/'node-a.elf').read_bytes(); inspect_elf(image)
    require(boot_profile(image) == dict(version=1,ram_mib=1024,heap_pages=2048), 'ordinary demand boot profile mismatch')
    require(manifest['elf_layouts'] == {n:elf_profile(build.parent/f'node-{n}.elf') for n in ('a','b')}, 'demand ELF layout mismatch')
    symbols = {k:symbol(image,name) for k,(name,_) in BANKS.items()}
    require(all(symbols[k]['size'] == size for k,(_,size) in BANKS.items()), 'demand bank ABI mismatch')
    model_symbol = symbol(image,'A02_BOOT_MODEL')
    require(model_symbol['size'] == 2772, 'demand model size mismatch')
    model = loaded_bytes(image,model_symbol['va'],2772)
    qemu = attest_qemu(str(paths['qemu_binary']),paths['qemu_source'])
    require(qemu.get('qemu_pmu_patch_attested') is True, 'demand requires source-attested QEMU PMU')
    return dict(version=VERSION,paths={k:str(v) for k,v in paths.items()},source_map=sources,
        build_sha256=sha(build),base_build_sha256=sha(base_path),artifacts=artifacts,symbols=symbols,
        model_sha256=hashlib.sha256(model).hexdigest(),formatter_sha256=sha(paths['formatter']),qemu=qemu,
        tools=closure(TOOL_ROOT if producer_tools_root is None else producer_tools_root))


def decode_scene(raw):
    require(len(raw) == 1024, 'ordinary demand scene bank width')
    w = struct.unpack('<128Q',raw)
    require(w[:4] == (LAYOUT[0],1,128,1) and w[4] > 0 and w[4] % 2 == 0
        and w[5] == 6 and w[14] == 0 and w[15] == 0 and w[12:14] == LAYOUT[4:]
        and w[7] > 0 and w[8] == w[7]+w[12] and w[8] <= w[9] <= w[10]
        and w[11] >= w[10]+w[13] and w[6] >= w[11], 'ordinary demand has no closed high/withdraw/drain/quiet boundary')
    require(w[16] == 1 and w[17] == w[21] == w[25] == 100 and w[18:21] == (0,0,0)
        and w[22] > 0 and w[22]+w[23] == 100 and w[24] > 0 and w[26:28] == (0x434f5245,1)
        and not any(w[28:32]) and any(w[32:36]) and any(w[36:40]),
        'ordinary demand has missing actual jobs, outstanding runtime custody or target identity')
    require(w[40] > 0 and w[41] > 0 and w[10] < w[43] <= w[42] <= w[11]
        and w[44] == 1 and not any(w[45:]), 'quiet lacks a later ordinary model input/reply')
    h = hashlib.sha256(b'CYXIA_A03_ORDINARY_DEMAND_V1\0'+struct.pack('<2Q',*LAYOUT[4:])+
        b'100-owned-arrivals;relative=((id-1)/10)*1000000000+((id-1)%10)*1000;deadline=5000000000;no-publication\0').hexdigest()
    require(raw[32*8:36*8].hex() == h, 'ordinary demand frozen schedule digest mismatch')
    return dict(phase='COMPLETE',first_ns=w[7],withdrawn_ns=w[9],drained_ns=w[10],complete_ns=w[11],
        quiet_ns=w[13],released=w[17],retired=w[21],completed=w[22],rejected=w[23],
        reported_worker_ns=w[24],quiet_job=w[40],quiet_version=w[41],quiet_observed_ns=w[42],quiet_input_ns=w[43],
        schedule_sha256=h,applied_owner_verified=False)


def decode_quiet_record(raw, scene):
    require(len(raw) == 5120, 'retained quiet model record width')
    q = struct.unpack('<640Q',raw)
    require(q[0] == q[1] == scene['quiet_job'] and q[639] > 0 and q[639] % 2 == 0
        and q[13] == scene['quiet_version'] and q[13] > 0 and q[14] in (1,2) and q[15] == 0
        and q[19] == q[30] == 1 and q[36] == scene['quiet_input_ns'],
        'retained quiet model record/scene/root completion binding mismatch')
    # The source's publication cap includes reply decode and publication. Python
    # arbitrary precision rejects both arithmetic overflow and a sum over cap.
    publication = q[29]+q[12]
    inference = q[10]+q[11]+q[29]
    require(publication <= 500_000 and inference <= 2_000_000 and q[18] == 0,
        'quiet decode/publication or inference exceeded unchanged native budget')
    require(scene['drained_ns'] < q[36] <= q[8] <= q[9] <= scene['quiet_observed_ns']
        and q[9]-q[8] <= 50_000_000,'quiet model input/receipt predates drain or exceeds wall deadline')
    return dict(publication_with_decode_ns=publication,inference_with_encoding_decode_ns=inference,
        row_publication_ns=q[12],row_decode_ns=q[29],actual_bank_state=q[14],
        bank_applied_verified=False,scope='original root model receipt; Applied ownership verified separately')


def verify_qmp(root, context, rows, platform, dtb):
    root = Path(root); require(rows and rows[0]['direction'] == 'receive' and 'QMP' in rows[0]['message'], 'missing demand QMP greeting')
    pending = None; running = paused = resumed = quit_seen = False; stops = 0; last_id = 0
    setup = set(); preboot = set(); probes = {}; captures = set(); serial = bytearray(); responses = {}
    events_allowed = set(); required = set(BANKS)-{'config'}
    allowed = {'qmp_capabilities','query-cpus-fast','query-memory-size-summary','pmemsave','ringbuf-read','cont','stop','query-status','quit'}
    for row in rows[1:]:
        require(row.get('direction') in ('send','receive') and type(row.get('message')) is dict, 'malformed demand QMP row')
        m = row['message']
        if row['direction'] == 'receive':
            if 'event' in m:
                e = m['event']; require(e in {'STOP','RESUME','SHUTDOWN'} and {'STOP':'stop','RESUME':'cont','SHUTDOWN':'quit'}[e] in events_allowed, 'unordered demand QMP event')
                require((e == 'STOP' and not running) or (e == 'RESUME' and running) or (e == 'SHUTDOWN' and quit_seen), 'contradictory demand QMP event')
                if e == 'SHUTDOWN': require(m.get('data') == {'guest':False,'reason':'host-qmp-quit'}, 'unexpected guest shutdown')
                else: require(m.get('data',{}) == {}, 'unexpected lifecycle event data')
                continue
            require(pending is not None and m.get('id') == pending['id'] and 'return' in m and 'error' not in m, 'unmatched/failed demand QMP command')
            name = pending['execute']
            if name == 'query-status': require(m['return'].get('status') == 'paused','demand guest not confirmed paused'); paused = True
            elif name == 'ringbuf-read': serial.extend(base64.b64decode(m['return'],validate=True)); require(len(serial) <= 8*1024**2,'demand serial bound')
            elif name in ('query-cpus-fast','query-memory-size-summary'): responses[name] = m['return']
            pending = None; continue
        require(not quit_seen and pending is None and m.get('execute') in allowed and type(m.get('id')) is int
            and m['id'] == last_id+1 and set(m) <= {'execute','id','arguments'}, 'unauthorized/outstanding demand QMP command')
        last_id = m['id']; pending = m; name = m['execute']
        if name not in ('pmemsave','ringbuf-read'): require('arguments' not in m, 'unexpected demand QMP arguments')
        if name in ('qmp_capabilities','query-cpus-fast','query-memory-size-summary'):
            require(not resumed and name not in setup and (name == 'qmp_capabilities' or 'qmp_capabilities' in setup), 'demand setup order'); setup.add(name)
        elif name == 'ringbuf-read': require(resumed and m.get('arguments') == dict(device='cyxlog',size=1048576,format='base64'),'demand serial read profile')
        elif name == 'query-status': require(stops > 0 and not running,'demand status without stop')
        if name in ('cont','stop','quit'): events_allowed.add(name)
        if name == 'cont':
            require(not running and not captures and preboot == {'dtb-header.bin','platform.dtb','config-observed.bin'}
                and setup == {'qmp_capabilities','query-cpus-fast','query-memory-size-summary'}, 'demand resume before setup or after final capture')
            if resumed:
                require(paused and set(probes[stops]) == required, 'incomplete demand stopped probe')
                try: decode_scene(probes[stops]['demand'])
                except ValueError: pass
                else: require(False,'resumed completed ordinary demand')
            running = resumed = True; paused = False
        elif name == 'stop':
            require(resumed and running and not captures and stops < 64,'demand stop outside running/probe bound')
            running = paused = False; stops += 1; probes[stops] = {}
        elif name == 'pmemsave':
            a = m.get('arguments',{}); target = Path(a.get('filename',''))
            require(set(a) == {'val','size','filename'} and type(a['val']) is int and type(a['size']) is int
                and target.parent == root and not target.is_symlink(), 'external demand physical read')
            key = None
            if target.name in ('dtb-header.bin','platform.dtb','config-observed.bin'):
                require(not resumed and target.name not in preboot,'duplicate/late demand setup read')
                address,size = (context['symbols']['config']['pa'],512) if target.name == 'config-observed.bin' else (0x40000000,40 if target.name == 'dtb-header.bin' else len(dtb))
                require(target.name == 'dtb-header.bin' or 'dtb-header.bin' in preboot,'demand DTB read order'); preboot.add(target.name)
            elif target.name == 'pending-demand.bin':
                require(running and not paused and not captures,'demand live hint after stop'); key = 'demand'
            else:
                match = re.fullmatch(r'probe-([0-9]{2})-(.+)\.bin',target.name)
                if match:
                    key = match[2]; require(paused and not running and int(match[1]) == stops and key in required
                        and key not in probes[stops],'unbound/duplicate demand stopped probe')
                    probes[stops][key] = target.read_bytes()
                elif target.name in {k+'.bin' for k in required}:
                    key = target.stem
                    require(paused and not running and set(probes[stops]) == required and key not in captures,'demand final bytes before complete stopped probe')
                    decode_scene(probes[stops]['demand'])
                    require(target.read_bytes() == probes[stops][key],'demand final bytes differ from stopped probe'); captures.add(key)
                else: require(False,'unknown demand physical capture')
            if key is not None: address,size = context['symbols'][key]['pa'],BANKS[key][1]
            require(a['val'] == address and a['size'] == size and target.stat().st_size == size,'demand physical range/width mismatch')
        elif name == 'quit':
            require(paused and not running and captures == required, 'demand quit before all stopped evidence'); quit_seen = True
    require(quit_seen and pending is None and resumed and stops > 0 and set(probes[stops]) == required,'incomplete demand QMP lifecycle')
    require(responses.get('query-cpus-fast') == platform['cpus'] and responses.get('query-memory-size-summary') == platform['memory'],'demand QMP/platform mismatch')
    return bytes(serial)


def verify_capture(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                   producer_tools_root=None, replay_model=True):
    root = Path(directory); require(not root.is_symlink(),'linked demand capture root'); root = root.resolve(strict=True)
    inventory = bounded_inventory(root)
    context = trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    doc = lambda name: read_json(root/name)
    require(doc('native-context.json') == context,'demand caller/source/tool context mismatch')
    for name,digest in context['artifacts'].items(): require(sha(root/name) == digest,'demand captured artifact changed')
    require(sha(root/'build-manifest.json') == context['build_sha256'] and sha(root/'base-build-manifest.json') == context['base_build_sha256'],'demand captured manifests changed')
    require(doc('source-manifest.json') == context['source_map'],'demand source map changed')
    for prefix,key in (('source-inputs','source_map'),('producer-tools','tools')):
        for name,digest in context[key].items(): require(sha(root/prefix/name) == digest,'demand captured source/tool bytes changed')
    require(sha(root/'model.bin') == context['model_sha256'],'demand captured model changed')
    inputs = doc('input.json')
    require(inputs.get('version') == VERSION and type(inputs.get('mode')) is int and inputs['mode'] == 0
        and type(inputs.get('timeout_seconds')) in (int,float) and 5 <= inputs['timeout_seconds'] <= 600
        and inputs['poll_seconds'] == .1 and inputs['serial_seconds'] == 1 and inputs['max_stopped_attempts'] == 64,'demand capture profile mismatch')
    nonce = bytes.fromhex(inputs['nonce']); require(len(nonce) == 16 and any(nonce),'demand nonce mismatch')
    config = struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+nonce+bytes.fromhex(context['artifacts']['node-a.elf'])+bytes.fromhex(sha(root/'input.json'))+bytes.fromhex(sha(root/'source-manifest.json'))+bytes(368)
    require((root/'config.bin').read_bytes() == config == (root/'config-observed.bin').read_bytes(),'demand config mismatch')
    injection = doc('config-injection.json')
    require(injection == dict(request_hex=config_write_packet(config,context['symbols']['config']['pa']).hex(),received_hex=injection['received_hex'],ack_hex='2b')
        and bytes.fromhex(injection['received_hex']).lstrip(b'+') == b'$OK#9a','demand preboot injection mismatch')
    process = doc('process-exit.json')
    require(process['schema'] == 1 and type(process['pid']) is int and process['pid'] > 0 and process['peer_pid'] == process['pid']
        and process['returncode'] == 0 and process['forced'] is False and process['quit_ok'] is True and process['eof'] is True and not process['errors']
        and type(process['started_ns']) is int and type(process['exited_ns']) is int and 0 < process['started_ns'] < process['exited_ns'], 'demand owned process lacks quit/EOF/wait0')
    launch = doc('launch.json')
    require(type(launch['port']) is int and 0 < launch['port'] < 65536 and launch['qmp'] != launch['gdb']
        and launch['symbols'] == context['symbols'] and launch['argv'] == launch_argv(context['paths']['qemu_binary'],root,launch['qmp'],launch['gdb'],launch['port']), 'demand exact launch mismatch')
    require(doc('formatter-command.json') == dict(argv=[context['paths']['formatter'],str(root/'disk.raw'),inputs['disk_uuid']])
        and len(bytes.fromhex(inputs['disk_uuid'])) == 16,'demand formatter command mismatch')
    verify_origin(inputs['disk_origin'],doc('disk-before.json'),(root/'format.log').read_bytes())
    require(doc('disk-after.json') == dict(bytes=(root/'disk.raw').stat().st_size,sha256=sha(root/'disk.raw'))
        and (root/'disk.raw').stat().st_size == DISK_BYTES,'demand final disk custody mismatch')
    platform = doc('platform.json')
    require(len(platform['cpus']) == 4 and {c['cpu-index'] for c in platform['cpus']} == set(range(4))
        and platform['memory']['base-memory'] == 1024**3,'demand platform mismatch')
    dtb = (root/'platform.dtb').read_bytes(); header = (root/'dtb-header.bin').read_bytes()
    require(header == dtb[:40] and len(header) == 40 and 40 <= len(dtb) <= 2*1024**2
        and struct.unpack_from('>2I',dtb) == (0xd00dfeed,len(dtb)),'demand DTB mismatch')
    rows = doc('qmp-transcript.json')
    for direction,name in (('send','qmp-sent.bin'),('receive','qmp-received.bin')):
        raw = (root/name).read_bytes(); require(len(raw) <= 128*1024**2,'demand raw QMP bound')
        require([json.loads(line,object_pairs_hook=_pairs) for line in raw.splitlines() if line.strip()] == [r['message'] for r in rows if r['direction'] == direction],'demand raw QMP/transcript mismatch')
    serial = verify_qmp(root,context,rows,platform,dtb)
    decoder = FrameDecoder(); text = b''.join(payload+b'\n' for payload in decoder.feed(serial))
    require(serial == (root/'serial.bin').read_bytes() and text == (root/'serial.txt').read_bytes()
        and decoder.loss == decoder.corrupt == 0 and not decoder.buffer
        and not any(x in serial or x in text for x in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')), 'demand serial loss/fault')
    boot,control,runtime,unified = ((root/(key+'.bin')).read_bytes() for key in ('boot','control','runtime','unified'))
    verify_samples(boot,boot,control[:4096],runtime,unified,config)
    scene = decode_scene((root/'demand.bin').read_bytes())
    quiet = decode_quiet_record((root/'quiet-model.bin').read_bytes(),scene)
    model_replay = None
    if replay_model:
        from doctor import env, RUST_BIN
        source = Path(source_root).resolve(strict=True); target = source/'target/a03-demand-verifier'
        command = [str(RUST_BIN/'cargo'),'build','--locked','--offline','--manifest-path',str(source/'Cargo.toml'),
            '--target-dir',str(target),'-p','cyxia-prototype','--example','verify-a03-demand-evidence']
        environment = env(); environment.pop('RUSTFLAGS',None); environment.pop('CARGO_ENCODED_RUSTFLAGS',None)
        built = subprocess.run(command,cwd=source,env=environment,capture_output=True,text=True,timeout=180)
        require(built.returncode == 0,'trusted quiet model verifier build failed: '+built.stderr[-2000:])
        checker = target/'debug/examples/verify-a03-demand-evidence'
        checked = subprocess.run([str(checker),str(root/'quiet-model.bin'),str(root/'model.bin'),str(root/'demand.bin'),str(root/'control.bin')],
            cwd=source,env=environment,capture_output=True,text=True,timeout=15)
        require(checked.returncode == 0,'quiet full MLP/Plan replay failed: '+checked.stderr[-2000:])
        model_replay = json.loads(checked.stdout)
        require(model_replay['status'] == 'QUIET_MODEL_REPLAY_VALID' and model_replay['full_integer_mlp'] is True
            and model_replay['job'] == scene['quiet_job'] and model_replay['version'] == scene['quiet_version'], 'quiet model replay result mismatch')
        model_replay['checker_sha256'] = sha(checker)
    require(bounded_inventory(root) == inventory,'demand capture changed during independent replay')
    owner = struct.unpack('<'+str((128+8*896))+'Q',(root/'ownership.bin').read_bytes())
    require(owner[:3] == (0x43594f574e313531,1,128+8*896) and owner[4] <= 8 and owner[6] == 0
        and (root/'ownership.bin').read_bytes()[16*8:30*8] == config[32:144], 'ordinary owner observer has wrong profile/run binding')
    owner_rows = []
    for index in range(owner[4]):
        r = owner[128+index*896:128+(index+1)*896]
        owner_rows.append(dict(publication=r[0],flags=r[1],desired_control=r[8],
            before_control=r[34],published_control=r[66],completed_control=r[82],
            complete_row=bool(r[0] > 0 and r[0] % 2 == 0 and r[1] == 31)))
    return dict(status='ORDINARY_STIMULUS_VERIFIED' if replay_model else 'ORDINARY_STIMULUS_CUSTODY_VERIFIED',
        version=VERSION,stimulus_verified=bool(replay_model),scene_custody_verified=True,scene=scene,quiet_receipt=quiet,model_replay=model_replay,
        native_acceptance_status='NOT_RUN',A03_complete=False,model_trained=False,accepted_training_sample_verified=False,
        applied_owner_verified=False,actual_owner_transition_count=owner[4],owner_observations=owner_rows,
        source_sha256=read_json(Path(build_manifest))['code_source_sha256'],
        captured_inventory=inventory,scope='Ordinary paid demand and retained quiet model reply only; full A03 ownership and trained-model obligations remain.')
