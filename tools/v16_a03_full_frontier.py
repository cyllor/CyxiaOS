"""Typed Full-profile two-group frontier; no dataset, sample import or training authority."""
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
from build_v16_learning_collection import elf_profile
from check_elf import boot_profile, inspect_elf, symbol
from check_prototype_evidence import EvidenceError, read_json, _finite_float, _pairs
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, require, verify_samples
from verify_v13_model import loaded_bytes
from v16_a03_focus import bounded_inventory, launch_argv, sha, write_json

from v16_learning_pair import fatal_evidence
from v16_a03_focus import paid_bank_facts
from v16_learning_archive import SCHEMAS, MAX_FILE, OWNER, _record, _closing, _request, digest, word, words, _schema_context, _exports
from v16_learning_reward import OBSERVATION_NS, _adoptions, performance, cpu_union, reward_values
from check_v13_disk import BLOCK, committed_volume
from check_v13_filesystem import inspect_committed

VERSION = 'v16-a03-full-frontier-capture-v1'
CHECKER_VERSION = 'v16-a03-full-frontier-checker-v1'
TOOL_ROOT = Path(__file__).resolve().parents[1]
BANKS = {'boot':('A01_BOOT_EVIDENCE',512), 'config':('A01_BOOT_CONFIG',512),
    'replay':('REPLAY_V13_EVIDENCE',512), 'collection':('LEARNING_COLLECTION_V16_EVIDENCE',512),
    'control':('DOMAIN_CONTROL_EVIDENCE',(512+64*640)*8),
    'runtime':('RUNTIME_V13_EVIDENCE',8192), 'unified':('UNIFIED_EVIDENCE',4096),
    'root-diagnostic':('REPLAY_ROOT_EVIDENCE',256), 'publication-cost':('DOMAIN_PUBLICATION_COST',1024),
    'tasks':('DOMAIN_TASK_EVIDENCE',256), 'credit':('CONTROL_CREDIT_EVIDENCE',512),
    'settlement':('CONTROL_SETTLEMENT_EVIDENCE',512)}

# The transcript mirrors the raw QMP streams this tool already bounds at 128 MiB
# and re-checks row by row, and it grows with the host window, so a complete
# capture outgrows read_json's generic 4 MiB bound; verify_v13_a02 bounds the
# same artifact at 16 MiB.
QMP_TRANSCRIPT_BYTES = 16*1024**2


def read_transcript(path):
    require(path.stat().st_size <= QMP_TRANSCRIPT_BYTES,'Full frontier QMP transcript exceeds bounded size')
    return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=_pairs,parse_float=_finite_float,
        parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError(f'Invalid number {value}')))


def require_full_profile(manifest):
    require(type(manifest) is dict and manifest.get('schema_version') == 1
        and manifest.get('contract') == 'v16-learning-collection-build-v1'
        and manifest.get('status') == 'BUILT_NOT_RUN' and manifest.get('collection_profile') == 'full'
        and type(manifest.get('profile_id')) is int and manifest['profile_id'] == 0
        and manifest.get('profile_environment') == {'CYXIA_LEARNING_COLLECTION':'full'},
        'wrong explicit Full collection build')


def raw_qmp_messages(raw):
    require(isinstance(raw,bytes) and len(raw) <= 128*1024**2, 'full raw QMP bound')
    return [json.loads(line,object_pairs_hook=_pairs) for line in raw.splitlines() if line.strip()]


def frontier_deviation(replay):
    """A coherent live hint may cause failure diagnostics, never success."""
    if len(replay) != 512: return None
    w=struct.unpack('<64Q',replay)
    if not w[0] or w[0]%2 or w[1] != 0x435952504c593133: return None
    if w[11] or w[12] or w[21]:
        return f'Full clean frontier excluded/error: excluded={w[11]}, owner_error={w[12]}, data_error={w[21]}'
    if w[19]>2 or w[3:5]!=(1,1) or w[5]>2 or w[7]>5 or w[10]>4 or w[17]>4:
        return f'Full clean two-group frontier passed: paired={w[19]}, family={w[3:5]}, group={w[5]}, trial={w[7]}, verified={w[10]}, archived={w[17]}'
    return None


def frontier_boundary(replay, collection):
    if len(replay) != 512 or len(collection) != 512: return None
    w = struct.unpack('<64Q',replay); c = struct.unpack('<64Q',collection)
    if (not w[0] or w[0]%2 or w[1] != 0x435952504c593133 or w[2:8] != (0,1,1,2,2,5)
        or w[10] != 4 or w[17] != 4 or w[18:20] != (1,2)
        or any(w[k] for k in (9,11,12,13,14,15,16,20,21,22,23,63))
        or w[24:42] != (2,)+(0,)*17 or any(w[42:60])): return None
    if (not c[0] or c[0]%2 or c[1:13] != (0x43594c434f4c3136,1,0,0,0,1,1,2,4,4,2,0)
        or c[13] not in (0,1) or c[14] != 1 or any(c[15:47]) or not c[47] or any(c[48:])): return None
    return dict(publication=w[0],collection_publication=c[0],profile_id=0,phase='PREPARE',
        frontier_family=[1,1],frontier_group=2,next_trial_id=5,verified=4,archived=4,paired=2,
        training_per_family=list(w[24:42]),validation_per_family=list(w[42:60]),
        work_quiescent=True,collection_owner_all_resources_clear=bool(c[13]),
        final_credit_release_verified=False,full_dataset_verified=False,
        scope='Two actual stored pairs and next-group frontier; Full collection remains incomplete.')


def stopped_frontier(probe):
    value = frontier_boundary(probe['replay'],probe['collection'])
    if value is None: return None
    for key in ('boot','runtime'):
        if len(probe[key]) != BANKS[key][1]: return None
    # A01_BOOT_EVIDENCE word2 is published only inside boot_recovery::run, the
    # non-returning SAFE_EXEC loop, so a clean boot that reached this frontier
    # necessarily reads 0; an odd value is the only torn boot publication here.
    if word(probe['boot'],16)%2: return None
    runtime_seq = word(probe['runtime'],16)
    if not runtime_seq or runtime_seq%2: return None
    fatal_evidence(probe['replay'],probe['control'])
    return value


def closure(root=TOOL_ROOT, entries=None):
    root = Path(root).resolve(strict=True)
    pending = list(entries or ('run_v16_a03_full_frontier','v16_a03_full_frontier','verify_v16_a03_full_frontier'))
    found = {}
    while pending:
        name = pending.pop()
        if name in found: continue
        require(len(found) < 128, 'Full frontier tool closure bound')
        path = root/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink(), 'missing/linked trusted Full frontier tool')
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
    require(all(not Path(v).is_symlink() for v in values.values()), 'linked Full frontier trust input')
    paths = {k:Path(v).resolve(strict=True) for k,v in values.items()}
    source = paths['source_root']; build = paths['build_manifest']
    for name in ('formatter','qemu_binary'):
        require(paths[name].is_file() and os.access(paths[name],os.X_OK), 'Full frontier trusted tool not executable')
    sources = code_source_map(source); manifest = read_json(build)
    require_full_profile(manifest)
    base_path = build.parent/'base-build-manifest.json'; base = read_json(base_path)
    require(manifest.get('base_manifest') == dict(path=base_path.name,bytes=base_path.stat().st_size,sha256=sha(base_path)),
        'Full frontier base manifest mismatch')
    p = base['profiles']
    require(base['schema_version'] == 1 and base['status'] == 'BUILT_NOT_RUN' and p['fault'] == 'normal'
        and p['selftest'] is True and p.get('service_fault','none') == 'none'
        and p.get('service_fault_nodes',{'a':'none','b':'none'}) == {'a':'none','b':'none'}
        and all(p.get(k,False) is False for k in ('leave','storage_fault','memory_probe')),
        'conflicting Full frontier base profile')
    source_hash = hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    require(manifest['code_source_map'] == base['code_source_map'] == sources
        and manifest['code_source_sha256'] == base['code_source_sha256'] == source_hash
        and base['builder_sha256'] == sha(source/'tools/build_unified.py')
        and base['own_private_key_only_verified'] is True
        and manifest['builder_sources'] == closure(source,('build_v16_learning_collection',)), 'Full frontier source/builder mismatch')
    artifacts = {}
    for name in ('node-a.elf','node-b.elf','service-a.elf','task.elf','node-a.pub'):
        path = build.parent/name
        require(path.is_file() and not path.is_symlink() and base['artifacts'][name]['sha256'] == sha(path)
            and base['artifacts'][name]['bytes'] == path.stat().st_size, 'Full frontier artifact mismatch')
        artifacts[name] = sha(path)
    require(sha(build.parent/'node-a.pub') == base['nodes']['a']['node_id'],'Full node ID differs from build')
    image = (build.parent/'node-a.elf').read_bytes(); inspect_elf(image)
    require(boot_profile(image) == dict(version=1,ram_mib=1024,heap_pages=2048), 'Full frontier boot profile mismatch')
    require(manifest['elf_layouts'] == {n:elf_profile(build.parent/f'node-{n}.elf','full') for n in ('a','b')}, 'Full frontier ELF layout mismatch')
    ordinary = symbol(image,'A03_DEMAND_V16_LAYOUT')
    require(ordinary['size'] == 48 and struct.unpack('<6Q',loaded_bytes(image,ordinary['va'],48)) == (0x4359413033443136,1,0,1024,10000000000,2000000000), 'ordinary stimulus cannot masquerade as Full collector')
    symbols = {k:symbol(image,name) for k,(name,_) in BANKS.items()}
    require(all(symbols[k]['size'] == size for k,(_,size) in BANKS.items()), 'Full frontier bank ABI mismatch')
    model_symbol = symbol(image,'A02_BOOT_MODEL')
    require(model_symbol['size'] == 2772, 'Full frontier model size mismatch')
    model = loaded_bytes(image,model_symbol['va'],2772)
    qemu = attest_qemu(str(paths['qemu_binary']),paths['qemu_source'])
    require(qemu.get('qemu_pmu_patch_attested') is True, 'Full frontier requires source-attested QEMU PMU')
    return dict(version=VERSION,paths={k:str(v) for k,v in paths.items()},source_map=sources,
        build_sha256=sha(build),base_build_sha256=sha(base_path),artifacts=artifacts,symbols=symbols,
        model_sha256=hashlib.sha256(model).hexdigest(),model_generation=1,schema_hash=sha(source/'crates/prototype/src/features.rs'),node_id=sha(build.parent/'node-a.pub'),formatter_sha256=sha(paths['formatter']),qemu=qemu,
        tools=closure(TOOL_ROOT if producer_tools_root is None else producer_tools_root))

def verify_qmp(root, context, rows, platform, dtb):
    root = Path(root); require(rows and rows[0]['direction'] == 'receive' and 'QMP' in rows[0]['message'], 'missing Full frontier QMP greeting')
    pending = None; running = paused = resumed = quit_seen = False; stops = 0; last_id = 0
    setup = set(); preboot = set(); probes = {}; captures = set(); serial = bytearray(); responses = {}
    events_allowed = set(); required = set(BANKS)-{'config'}
    allowed = {'qmp_capabilities','query-cpus-fast','query-memory-size-summary','pmemsave','ringbuf-read','cont','stop','query-status','quit'}
    for row in rows[1:]:
        require(row.get('direction') in ('send','receive') and type(row.get('message')) is dict, 'malformed Full frontier QMP row')
        m = row['message']
        if row['direction'] == 'receive':
            if 'event' in m:
                e = m['event']; require(e in {'STOP','RESUME','SHUTDOWN'} and {'STOP':'stop','RESUME':'cont','SHUTDOWN':'quit'}[e] in events_allowed, 'unordered Full frontier QMP event')
                require((e == 'STOP' and not running) or (e == 'RESUME' and running) or (e == 'SHUTDOWN' and quit_seen), 'contradictory Full frontier QMP event')
                if e == 'SHUTDOWN': require(m.get('data') == {'guest':False,'reason':'host-qmp-quit'}, 'unexpected guest shutdown')
                else: require(m.get('data',{}) == {}, 'unexpected lifecycle event data')
                continue
            require(pending is not None and m.get('id') == pending['id'] and 'return' in m and 'error' not in m, 'unmatched/failed Full frontier QMP command')
            name = pending['execute']
            if name == 'query-status': require(m['return'].get('status') == 'paused','Full frontier guest not confirmed paused'); paused = True
            elif name == 'ringbuf-read': serial.extend(base64.b64decode(m['return'],validate=True)); require(len(serial) <= 8*1024**2,'Full frontier serial bound')
            elif name in ('query-cpus-fast','query-memory-size-summary'): responses[name] = m['return']
            pending = None; continue
        require(not quit_seen and pending is None and m.get('execute') in allowed and type(m.get('id')) is int
            and m['id'] == last_id+1 and set(m) <= {'execute','id','arguments'}, 'unauthorized/outstanding Full frontier QMP command')
        last_id = m['id']; pending = m; name = m['execute']
        if name not in ('pmemsave','ringbuf-read'): require('arguments' not in m, 'unexpected Full frontier QMP arguments')
        if name in ('qmp_capabilities','query-cpus-fast','query-memory-size-summary'):
            require(not resumed and name not in setup and (name == 'qmp_capabilities' or 'qmp_capabilities' in setup), 'Full frontier setup order'); setup.add(name)
        elif name == 'ringbuf-read': require(resumed and m.get('arguments') == dict(device='cyxlog',size=1048576,format='base64'),'Full frontier serial read profile')
        elif name == 'query-status': require(stops > 0 and not running,'Full frontier status without stop')
        if name in ('cont','stop','quit'): events_allowed.add(name)
        if name == 'cont':
            require(not running and not captures and preboot == {'dtb-header.bin','platform.dtb','config-observed.bin'}
                and setup == {'qmp_capabilities','query-cpus-fast','query-memory-size-summary'}, 'Full frontier resume before setup or after final capture')
            if resumed:
                require(paused and set(probes[stops]) == required, 'incomplete Full frontier stopped probe')
                require(stopped_frontier(probes[stops]) is None,'resumed already-complete Full frontier')
            running = resumed = True; paused = False
        elif name == 'stop':
            require(resumed and running and not captures and stops < 64,'Full frontier stop outside running/probe bound')
            running = paused = False; stops += 1; probes[stops] = {}
        elif name == 'pmemsave':
            a = m.get('arguments',{}); target = Path(a.get('filename',''))
            require(set(a) == {'val','size','filename'} and type(a['val']) is int and type(a['size']) is int
                and target.parent == root and not target.is_symlink(), 'external Full frontier physical read')
            key = None
            if target.name in ('dtb-header.bin','platform.dtb','config-observed.bin'):
                require(not resumed and target.name not in preboot,'duplicate/late Full frontier setup read')
                address,size = (context['symbols']['config']['pa'],512) if target.name == 'config-observed.bin' else (0x40000000,40 if target.name == 'dtb-header.bin' else len(dtb))
                require(target.name == 'dtb-header.bin' or 'dtb-header.bin' in preboot,'Full frontier DTB read order'); preboot.add(target.name)
            elif target.name in ('pending-replay.bin','pending-collection.bin','pending-control.bin'):
                require(running and not paused and not captures,'Full frontier live hint after stop'); key = target.stem[len('pending-'):]
            else:
                match = re.fullmatch(r'probe-([0-9]{2})-(.+)\.bin',target.name)
                if match:
                    key = match[2]; require(paused and not running and int(match[1]) == stops and key in required
                        and key not in probes[stops],'unbound/duplicate Full frontier stopped probe')
                    probes[stops][key] = target.read_bytes()
                elif target.name in {k+'.bin' for k in required}:
                    key = target.stem
                    require(paused and not running and set(probes[stops]) == required and key not in captures,'Full frontier final bytes before complete stopped probe')
                    require(stopped_frontier(probes[stops]) is not None,'final reads lack stopped Full frontier')
                    require(target.read_bytes() == probes[stops][key],'Full frontier final bytes differ from stopped probe'); captures.add(key)
                else: require(False,'unknown Full frontier physical capture')
            if key is not None: address,size = context['symbols'][key]['pa'],BANKS[key][1]
            require(a['val'] == address and a['size'] == size and target.stat().st_size == size,'Full frontier physical range/width mismatch')
        elif name == 'quit':
            require(paused and not running and captures == required, 'Full frontier quit before all stopped evidence'); quit_seen = True
    require(quit_seen and pending is None and resumed and stops > 0 and set(probes[stops]) == required,'incomplete Full frontier QMP lifecycle')
    require(responses.get('query-cpus-fast') == platform['cpus'] and responses.get('query-memory-size-summary') == platform['memory'],'Full frontier QMP/platform mismatch')
    return bytes(serial)

def finish_custody(root, inventory, context, checker, trusted):
    """Revalidate caller roots and every captured byte at the real return seam."""
    require(trusted_context(**trusted) == context, 'Full final trusted context changed')
    require(closure() == checker, 'Full final checker closure changed')
    require(bounded_inventory(root) == inventory, 'Full final captured inventory changed')


def verify_capture(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                   producer_tools_root=None, allow_unsaved_exports=False):
    require(type(allow_unsaved_exports) is bool, 'invalid Full export mode')
    root = Path(directory); require(not root.is_symlink(),'linked Full frontier capture root'); root = root.resolve(strict=True)
    inventory = bounded_inventory(root)
    checker = closure()
    context = trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    doc = lambda name: read_json(root/name)
    require(doc('native-context.json') == context,'Full frontier caller/source/tool context mismatch')
    for name,digest in context['artifacts'].items(): require(sha(root/name) == digest,'Full frontier captured artifact changed')
    require(sha(root/'build-manifest.json') == context['build_sha256'] and sha(root/'base-build-manifest.json') == context['base_build_sha256'],'Full frontier captured manifests changed')
    require(doc('source-manifest.json') == context['source_map'],'Full frontier source map changed')
    for prefix,key in (('source-inputs','source_map'),('producer-tools','tools')):
        for name,digest in context[key].items(): require(sha(root/prefix/name) == digest,'Full frontier captured source/tool bytes changed')
    require(sha(root/'model.bin') == context['model_sha256'],'Full frontier captured model changed')
    inputs = doc('input.json')
    require(inputs.get('version') == VERSION and type(inputs.get('mode')) is int and inputs['mode'] == 0
        and inputs.get('collection_profile') == 'full' and type(inputs.get('frontier_groups')) is int
        and inputs['frontier_groups'] == 2
        and type(inputs.get('timeout_seconds')) in (int,float) and 5 <= inputs['timeout_seconds'] <= 600
        and inputs['poll_seconds'] == .1 and inputs['serial_seconds'] == 1 and inputs['max_stopped_attempts'] == 64,'Full frontier capture profile mismatch')
    nonce = bytes.fromhex(inputs['nonce']); require(len(nonce) == 16 and any(nonce),'Full frontier nonce mismatch')
    config = struct.pack('<4Q',CONFIG_MAGIC,1,0,0)+nonce+bytes.fromhex(context['artifacts']['node-a.elf'])+bytes.fromhex(sha(root/'input.json'))+bytes.fromhex(sha(root/'source-manifest.json'))+bytes(368)
    require((root/'config.bin').read_bytes() == config == (root/'config-observed.bin').read_bytes(),'Full frontier config mismatch')
    injection = doc('config-injection.json')
    require(injection == dict(request_hex=config_write_packet(config,context['symbols']['config']['pa']).hex(),received_hex=injection['received_hex'],ack_hex='2b')
        and bytes.fromhex(injection['received_hex']).lstrip(b'+') == b'$OK#9a','Full frontier preboot injection mismatch')
    process = doc('process-exit.json')
    require(process['schema'] == 1 and type(process['pid']) is int and process['pid'] > 0 and process['peer_pid'] == process['pid']
        and process['returncode'] == 0 and process['forced'] is False and process['quit_ok'] is True and process['eof'] is True and not process['errors']
        and type(process['started_ns']) is int and type(process['exited_ns']) is int and 0 < process['started_ns'] < process['exited_ns'], 'Full frontier owned process lacks quit/EOF/wait0')
    launch = doc('launch.json')
    require(type(launch['port']) is int and 0 < launch['port'] < 65536 and launch['qmp'] != launch['gdb']
        and launch['symbols'] == context['symbols'] and launch['argv'] == launch_argv(context['paths']['qemu_binary'],root,launch['qmp'],launch['gdb'],launch['port']), 'Full frontier exact launch mismatch')
    require(doc('formatter-command.json') == dict(argv=[context['paths']['formatter'],str(root/'disk.raw'),inputs['disk_uuid']])
        and len(bytes.fromhex(inputs['disk_uuid'])) == 16,'Full frontier formatter command mismatch')
    verify_origin(inputs['disk_origin'],doc('disk-before.json'),(root/'format.log').read_bytes())
    require(doc('disk-after.json') == dict(bytes=(root/'disk.raw').stat().st_size,sha256=sha(root/'disk.raw'))
        and (root/'disk.raw').stat().st_size == DISK_BYTES,'Full frontier final disk custody mismatch')
    platform = doc('platform.json')
    require(len(platform['cpus']) == 4 and {c['cpu-index'] for c in platform['cpus']} == set(range(4))
        and platform['memory']['base-memory'] == 1024**3,'Full frontier platform mismatch')
    dtb = (root/'platform.dtb').read_bytes(); header = (root/'dtb-header.bin').read_bytes()
    require(header == dtb[:40] and len(header) == 40 and 40 <= len(dtb) <= 2*1024**2
        and struct.unpack_from('>2I',dtb) == (0xd00dfeed,len(dtb)),'Full frontier DTB mismatch')
    rows = read_transcript(root/'qmp-transcript.json')
    for direction,name in (('send','qmp-sent.bin'),('receive','qmp-received.bin')):
        raw = (root/name).read_bytes(); require(len(raw) <= 128*1024**2,'Full frontier raw QMP bound')
        require(raw_qmp_messages(raw) == [r['message'] for r in rows if r['direction'] == direction],'Full frontier raw QMP/transcript mismatch')
    serial = verify_qmp(root,context,rows,platform,dtb)
    decoder = FrameDecoder(); text = b''.join(payload+b'\n' for payload in decoder.feed(serial))
    require(serial == (root/'serial.bin').read_bytes() and text == (root/'serial.txt').read_bytes()
        and decoder.loss == decoder.corrupt == 0 and not decoder.buffer
        and not any(x in serial or x in text for x in (b'PANIC',b'SMP_ERROR',b'UNIFIED_FAIL')), 'Full frontier serial loss/fault')
    boot,control,runtime,unified = ((root/(key+'.bin')).read_bytes() for key in ('boot','control','runtime','unified'))
    verify_samples(boot,boot,control[:4096],runtime,unified,config)
    frontier = stopped_frontier({key:(root/(key+'.bin')).read_bytes() for key in BANKS if key != 'config'})
    require(frontier is not None,'stopped Full frontier not proved')
    paid = paid_bank_facts((root/'tasks.bin').read_bytes(),(root/'credit.bin').read_bytes(),(root/'settlement.bin').read_bytes())
    epoch = word(boot,48)
    require(epoch == 1,'Full frontier requires actual first boot')
    trusted = _schema_context(dict(context,boot_epoch=epoch))
    pairs = extract_frontier_pairs(root/'disk.raw',trusted=trusted,disk_uuid=inputs['disk_uuid'])
    numeric = [numeric_frontier_pair(p['candidate']['raw_bytes'],p['baseline']['raw_bytes'],(root/'model.bin').read_bytes()) for p in pairs]
    require(len(pairs) == frontier['paired'] == 2,'stored count differs from committed side pairs')
    manifest, files = _exports(pairs)
    exports = root/'frontier-archives'
    if exports.exists():
        require(exports.is_dir() and not exports.is_symlink() and {p.name for p in exports.iterdir()} == set(files)|{'manifest.json'},'Full raw archive export inventory mismatch')
        require(read_json(exports/'manifest.json') == manifest,'Full archive export manifest changed')
        for name,value in files.items(): require((exports/name).read_bytes() == value,'Full saved archive differs from committed disk')
    else:
        require(allow_unsaved_exports, 'missing Full four-side raw archive exports')
    finish_custody(root,inventory,context,checker,dict(source_root=source_root,
        build_manifest=build_manifest,formatter=formatter,qemu_binary=qemu_binary,
        qemu_source=qemu_source,producer_tools_root=producer_tools_root))
    return dict(version=VERSION,checker_version=CHECKER_VERSION,status='FULL_TWO_GROUP_FRONTIER_VERIFIED',
        frontier_verified=True,capture_complete=True,frontier=frontier,committed_pair_count=2,
        archive_manifest=manifest,archive_files=files,numeric=numeric,paid_banks_no_failure=True,
        capture_sha256=sha(root/'native-context.json'),source_sha256=hashlib.sha256(json.dumps(context['source_map'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        final_credit_release_verified=False,full_dataset_verified=False,accepted_training_sample_verified=False,
        protected_sample_export_verified=False,model_trained=False,native_acceptance_status='NOT_RUN',A03_complete=False,
        source_event_hash_recomputed=False,source_custody_replay_verified=False,
        initial_image_reexecution_verified=False,
        resource_scope='Scratch input loan retained by Full collector; final collection release is not proved. Per-side model pins were released before archive.',
        checker_identity=dict(version=CHECKER_VERSION,tools=checker),captured_inventory=inventory)


def workload_digest(seed):
    require(type(seed) is int and 1 <= seed <= 2,'unsupported frontier seed')
    h=hashlib.sha256(b'CYXIA_ORDINARY_REPLAY_PAYLOADS_1.3\0'+struct.pack('<HHQ',1,1,seed))
    for identity in range(1,101):
        relative=(identity-1)//10*1000000000+(identity-1)%10*1000
        h.update(words(identity,relative,5000000000))
        h.update(words(seed^identity,(identity-1)%16,32768))
        values=[((((seed<<j)|(seed>>(64-j))) if j else seed)^identity*17^j)&0xffff for j in range(8)]
        h.update(hashlib.sha256(words(*values)).digest())
    return h.hexdigest()


def frontier_side(raw, context):
    require(len(raw) >= 2048, 'truncated archive header')
    h = raw[:2048]
    require(h[:17] == b'CYXIA_REPLAY_1.3\0' and not any(h[17:32])
            and not any(h[232:256]) and not any(h[1280:1792]), 'unsupported archive header')
    boot, trial, generation, domain, kind, target, target_gen, seed, first, warm, observation, closing = struct.unpack_from('<12Q', h, 32)
    records, cpu, requests, candidate = struct.unpack_from('<4Q', h, 128)
    require(boot == context['boot_epoch'] and trial > 0 and generation > 0 and 1 <= seed <= 2
            and (domain, kind, target, target_gen) == (1, 1, 12, 1)
            and candidate in (0, 1) and 0 < first < observation < closing
            and observation == first + 6000000000 and warm == observation - 1000000000
            and closing >= observation + 10000000000, 'unsupported archive run identity/timing')
    require(1 <= records <= 64 and cpu <= 8192 and requests == 100
            and all(word(h, i) == 0 for i in (160, 168, 192, 224, 608, 624, 744, 752))
            and word(h, 632) == 2048, 'unsupported archive counts/peer/prewarm/exclusion')
    length = 2048 + records * 6144 + cpu * 64 + requests * 128
    require(length <= MAX_FILE and length <= len(raw), 'truncated/unbounded archive side')
    require(tuple(h[448 + i * 32:480 + i * 32].hex() for i in range(4)) == tuple(context['schema_hashes'])
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4
            and h[640:672].hex() == context['node_id'], 'archive schema/node mismatch')
    require(h[256:288].hex() == workload_digest(seed)
            and all(any(h[i:i + 32]) for i in (288, 320, 352, 384, 416)), 'archive group/hash mismatch')
    count = word(h, 616)
    require(0 < count <= 16 and not any(h[768 + count * 32:1280])
            and word(h, 728) == 100 and word(h, 736) == count, 'archive source closure mismatch')
    sources = [struct.unpack_from('<4Q', h, 768 + i * 32) for i in range(count)]
    require(sources == [(12, 1, 0, 7), (12, 1, 1, 15), (OWNER, 1, 2, 1),
                        (0x5245504c5453, 1, 2, 9)], 'unsupported D01 source manifest')
    coverage = struct.unpack_from('<7Q', h, 672)
    require(coverage == (first, observation, observation + 10000000000, closing, 3, 3, 1),
            'invalid local coverage')
    _closing(h[1792:], boot, closing)
    result = dict(boot_epoch=boot, trial_id=trial, capture_generation=generation,
                  family=[1, 1], target=[12, 1], seed=seed, side='Candidate' if candidate else 'Baseline',
                  first_ns=first, observation_ns=observation, closing_ns=closing, length=length,
                  workload_sha256=h[256:288].hex(), initial_image_sha256=h[288:320].hex(),
                  frozen_other_domains_sha256=h[320:352].hex(), frozen_scope_sha256=h[352:384].hex(),
                  event_sha256=h[384:416].hex(), producer_verification_sha256=h[416:448].hex(),
                  schema_hashes=list(context['schema_hashes']), node_id=context['node_id'])
    result['records'] = [_record(raw[2048 + i * 6144:2048 + (i + 1) * 6144], result, context) for i in range(records)]
    require(any(r['kind'] == result['side'] for r in result['records']), 'missing adopted/baseline history')
    at = 2048 + records * 6144
    for i in range(cpu):
        row = raw[at + i * 64:at + (i + 1) * 64]
        core, start, end, cls = struct.unpack_from('<4Q', row, 32)
        require(row[:32] == h[640:672] and core < 4 and cls <= 2
                and first <= start <= end <= closing
                and any(s[2] == cls and s[3] & (1 << core) for s in sources), 'invalid local CPU row')
    at += cpu * 64
    canonical = bytearray(b'CYXIA_NATIVE_WORKLOAD_SCOPE_1.3\0')
    canonical += words(boot, trial, domain, kind, target, target_gen, seed, first, observation) + h[256:352]
    for source in sources:
        canonical += words(*source)
    arrivals = []
    for i in range(requests):
        row = raw[at + i * 128:at + (i + 1) * 128]
        identity, owner, gen, relative = _request(row, i, first, observation, closing)
        canonical += words(identity, owner, gen, relative)
        arrivals.append([identity, relative])
    require(digest(canonical) == h[352:384].hex(), 'frozen scope integrity mismatch')
    result.update(relative_arrivals=arrivals, scope_hash_recomputed=True,
                  sha256=digest(raw[:length]), raw_bytes=bytes(raw[:length]))
    return result

def extract_frontier_pairs(disk_path, *, trusted, disk_uuid):
    before=sha(disk_path); sides=[]; segments=[]
    with committed_volume(Path(disk_path)) as (current,metadata):
        volume=inspect_committed(current,metadata)
        require(volume['uuid']==disk_uuid and volume['boot_epoch']==1,'Full committed volume identity mismatch')
        for name in sorted(set(volume['files'])|set(volume['directories'])):
            if not any(part.startswith('lr-') for part in name.split('/')): continue
            match=re.fullmatch(r'/lr-0000000000000001-([0-9a-f]{4})',name)
            require(match is not None and name in volume['files'],'unexpected Full frontier archive path')
            segments.append(int(match[1],16)); node=volume['files'][name]
            require(0<node['size']<=MAX_FILE and node['durable_write_seq']>0,'uncommitted/unbounded Full side archive')
            raw=bytearray()
            for _,start,blocks in node['extents']:
                for block in range(start,start+blocks): raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            require(len(raw)==node['size'] and digest(raw)==node['sha256'],'Full committed archive hash mismatch')
            offset=0
            while offset<len(raw):
                side=frontier_side(memoryview(raw)[offset:],trusted)
                side.update(path=name,inode=node['inode'],inode_generation=node['generation'],durable_write_seq=node['durable_write_seq'],offset=offset,archive_sha256=node['sha256'],archive_bytes=bytes(raw))
                sides.append(side);offset+=side['length']
    require(sha(disk_path)==before and segments==list(range(len(segments))) and len(sides)==4,'Full disk changed/missing segments/four sides')
    groups={}; identities=set()
    for side in sides:
        identity=(side['trial_id'],side['capture_generation'])
        require(identity not in identities,'duplicate Full trial/generation');identities.add(identity)
        group=groups.setdefault(side['seed'],{})
        require(side['side'] not in group,'duplicate Full side');group[side['side']]=side
    require(set(groups)=={1,2},'Full frontier requires seed groups 1 and 2')
    pairs=[]
    for seed,group in sorted(groups.items()):
        require(set(group)=={'Baseline','Candidate'},'missing Full side pair')
        baseline,candidate=group['Baseline'],group['Candidate']
        require((baseline['trial_id'],candidate['trial_id'])==(seed*2-1,seed*2),'Full original trial order changed')
        for key in ('boot_epoch','family','target','seed','workload_sha256','initial_image_sha256','frozen_other_domains_sha256','schema_hashes','node_id','relative_arrivals'):
            require(baseline[key]==candidate[key],'Full pair identity differs: '+key)
        pairs.append(dict(baseline=baseline,candidate=candidate,model_sha256=trusted['model_sha256'],accepted_training_sample_verified=False,model_trained=False,native_acceptance_status='NOT_RUN'))
    return pairs


def numeric_frontier_side(raw, model):
    """Recompute the retained Trial only; caller custody is checked separately."""
    require(isinstance(raw, (bytes, bytearray)) and len(raw) >= 2048, 'truncated numeric side')
    require(isinstance(model, (bytes, bytearray)) and len(model) == 2772, 'invalid model length')
    raw = bytes(raw)
    context = dict(boot_epoch=1, model_generation=1, model_sha256=digest(model),
                   schema_hash=SCHEMAS[0], schema_hashes=SCHEMAS, node_id=raw[640:672].hex())
    side = frontier_side(raw, context)
    require(len(raw) == side['length'], 'extra numeric side bytes')
    h = raw[:2048]
    observation, closing = word(h, 112), word(h, 120)
    require(closing - observation - OBSERVATION_NS <= 5_000_000_000
            and word(h, 760) <= 1024 * 1024, 'closing/workspace bound')
    rows = [raw[2048 + i * 6144:2048 + (i + 1) * 6144] for i in range(word(h, 128))]
    adopted, evaluated = _adoptions(rows, h, model)
    # Probe records carry candidate registration, not published inference
    # scores. The existing structural checker validates their raw binding;
    # only actual adopted rows enter the Trial and the score comparison.
    at = 2048 + len(rows) * 6144
    intervals = []
    raw_four = [0] * 4
    for i in range(word(h, 136)):
        row = raw[at + i * 64:at + (i + 1) * 64]
        core, start, end, cls = struct.unpack_from('<4Q', row, 32)
        if cls == 2:
            require(observation <= start <= end <= observation + OBSERVATION_NS,
                    'work CPU outside observation')
        raw_four[cls] += end - start
        intervals.append((row[:32], core, start, end, cls))
    require(raw_four[0] == word(h, 200) and raw_four[1] == word(h, 208)
            and raw_four[2] + word(h, 176) + word(h, 184) == word(h, 216)
            and raw_four[3] == word(h, 224), 'raw CPU/warm/later totals disagree')
    at += len(intervals) * 64
    requests = [struct.unpack_from('<4Q', raw, at + i * 128) for i in range(word(h, 144))]
    perf = performance(requests, observation)
    cpu = cpu_union(intervals)
    candidate = side['side'] == 'Candidate'
    canonical = bytearray(b'CYXIA_FULL_CPU_TRIAL_1.3\0') + bytes([candidate])
    canonical += words(word(h, 40), 1, 1, word(h, 88), observation,
                       observation + OBSERVATION_NS, word(h, 104), closing,
                       word(h, 176), word(h, 184), word(h, 760))
    canonical += h[256:352]
    for i in range(4):
        canonical += words(word(h, 576 + 8 * i)) + h[448 + 32 * i:480 + 32 * i]
    node = h[640:672]
    canonical += node + words(1) + node
    canonical += words(len(adopted) if candidate else 0, 0 if candidate else len(adopted),
                       len(requests), 1, len(intervals), 0)
    input64 = None
    for index, row in enumerate(adopted):
        count, selected = struct.unpack_from('<HH', row, 204)
        weight = struct.unpack_from('<H', row, 512 + 24 * selected + 10)[0]
        if candidate:
            e = evaluated[index]
            for inp, score in zip(e['inputs'], e['scores']):
                canonical += struct.pack('<64hh', *inp, score)
            if index == 0:
                input64 = e['inputs'][selected]
            canonical += words(word(row, 8), *(word(row, p) for p in range(272, 320, 8)),
                               word(row, 344), word(row, 392), word(row, 352), word(row, 360),
                               word(row, 368), word(row, 376), 0, word(row, 400), word(row, 416),
                               word(row, 336), word(row, 384), selected, count, 1, 0)
            canonical += row[1280:1328]
            canonical += row[16:48] + row[88:152] + words(word(row, 80))
        else:
            canonical += words(*(word(row, p) for p in (344, 8, 184, 192, 392, 152, 160, 176, 168,
                                                        352, 360)), 0,
                               *(word(row, p) for p in (400, 416, 376, 384)))
        canonical += struct.pack('<4H', 1, 1, 0, weight)
    for identity, arrived, code, finished in requests:
        canonical += words(identity, arrived, code - 1, finished)
    canonical += node + words(*(word(h, p) for p in range(672, 720, 8)))
    for node, core, start, end, cls in intervals:
        canonical += node + words(core, start, end, cls)
    calculated = digest(canonical)
    require(calculated == h[416:448].hex(), 'Trial canonical differs from original native offset416')
    return dict(trial_id=word(h, 40), trial_canonical_sha256=calculated,
                original_native_canonical_sha256=h[416:448].hex(),
                original_source_event_sha256=h[384:416].hex(),
                performance=perf, cpu=cpu, input64=input64,
                model_scores=[e for e in evaluated if e is not None],
                warm_cpu_ns=word(h, 176), later_cpu_ns=word(h, 184),
                raw_source_tagged_ns=[word(h, p) for p in (200, 208, 216, 224)])

def numeric_frontier_pair(candidate_raw, baseline_raw, model):
    require(len(candidate_raw) >= 2048 and len(baseline_raw) >= 2048, 'truncated pair')
    require(word(candidate_raw, 152) == 1 and word(baseline_raw, 152) == 0,
            'wrong candidate/baseline sides')
    for begin, end in ((32, 40), (56, 96), (256, 352), (448, 608), (640, 672)):
        require(candidate_raw[begin:end] == baseline_raw[begin:end], 'pair identity mismatch')
    require(word(candidate_raw, 40) != word(baseline_raw, 40)
            and word(candidate_raw, 48) != word(baseline_raw, 48), 'same trial/generation pair')
    candidate, baseline = (numeric_frontier_side(raw, model) for raw in (candidate_raw, baseline_raw))
    # The fixed archive schedule checker already checks all 100 relative
    # arrivals independently on each side, so their pairing is exact here.
    cp, bp = candidate['performance'], baseline['performance']
    calculated = reward_values(cp, bp, candidate['cpu']['union_ns'])
    reward = calculated['value']
    evidence = digest(b'CYXIA_PAIRED_LABEL_1.3\0' + bytes.fromhex(candidate['trial_canonical_sha256'])
                      + bytes.fromhex(baseline['trial_canonical_sha256']) + words(reward.bits))
    return dict(schema=1, family=[1, 1], candidate=candidate, baseline=baseline,
                reward={name: value.report() for name, value in calculated.items()},
                prospective_paired_label_sha256=evidence,
                model_sha256=digest(model), model_scores_verified=True,
                reward_numeric_verified=True, trial_canonical_matches_native=True,
                native_acceptance_inferred_from_trusted_producer=False,
                source_event_hash_recomputed=False, event_hash_recomputed=False,
                source_custody_replay_verified=False, protected_sample_export_verified=False,
                accepted_training_sample_verified=False, reward_replay_verified=False,
                native_label_imported=False, model_trained=False, native_acceptance_status='NOT_RUN',
                formal_acceptance={name: 'NOT_RUN' for name in ('A03', 'A08', 'A10', 'A16')})

