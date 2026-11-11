"""Bounded original Full D01 retries; preserve exclusions without dataset authority."""
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
from check_prototype_evidence import read_json, _pairs
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, require, verify_samples
from verify_v13_model import loaded_bytes
from v16_a03_focus import bounded_inventory, launch_argv, sha, write_json

from v16_a03_focus import paid_bank_facts
from v16_learning_archive import SCHEMAS, MAX_FILE, OWNER, EMPTY_SHARED, _action, _closing, _request, digest, word, words, _schema_context, _exports
from v16_learning_reward import OBSERVATION_NS, _adoptions, performance, cpu_union, reward_values, encode_weight_features, select_model
from check_v13_disk import BLOCK, committed_volume
from check_v13_filesystem import inspect_committed

VERSION = 'v16-a03-full-retry-capture-v2'
CHECKER_VERSION = 'v16-a03-full-retry-checker-v2'
MAX_EXCLUSIONS = 8
MAX_SIDES = 4 + 2 * MAX_EXCLUSIONS
MAX_ARCHIVE_BYTES = MAX_SIDES * (2048 + 64 * 6144 + 8192 * 64 + 100 * 128)
# Regular, frozen D01 failures only. Preparation and resource/safety failures
# deliberately remain outside this typed producer's replay authority.
RETRY_ERRORS = {7: 'DataIncomplete', 13: 'Stale', 16: 'Deadline'}
TOOL_ROOT = Path(__file__).resolve().parents[1]
BANKS = {'boot':('A01_BOOT_EVIDENCE',512), 'config':('A01_BOOT_CONFIG',512),
    'replay':('REPLAY_V13_EVIDENCE',512), 'collection':('LEARNING_COLLECTION_V16_EVIDENCE',512),
    'control':('DOMAIN_CONTROL_EVIDENCE',(512+64*640)*8),
    'runtime':('RUNTIME_V13_EVIDENCE',8192), 'unified':('UNIFIED_EVIDENCE',4096),
    'root-diagnostic':('REPLAY_ROOT_EVIDENCE',256), 'publication-cost':('DOMAIN_PUBLICATION_COST',1024),
    'tasks':('DOMAIN_TASK_EVIDENCE',256), 'credit':('CONTROL_CREDIT_EVIDENCE',512),
    'settlement':('CONTROL_SETTLEMENT_EVIDENCE',512)}


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
    """Raw regular exclusions are pending work, never an accepted sample."""
    if len(replay) != 512: return None
    w=struct.unpack('<64Q',replay)
    if not w[0] or w[0]%2 or w[1] != 0x435952504c593133: return None
    if w[2] in (18,19,20,21,22,23,24,25,26,27):
        return f'unsupported Full retry phase={w[2]} (Failed/preparation/final collection)'
    if w[11] > MAX_EXCLUSIONS or w[7] > MAX_SIDES+1 or w[17] > MAX_SIDES:
        return 'Full retry exclusion/archive bound exceeded'
    if w[12] not in (0,*RETRY_ERRORS) or w[21]:
        return f'unsupported Full retry fault: owner_error={w[12]}, data_error={w[21]}'
    if w[19]>2 or w[3:5]!=(1,1) or w[5]>2:
        return f'Full retry two-group frontier passed: paired={w[19]}, family={w[3:5]}, group={w[5]}'
    return None


def fatal_evidence(replay, control, tasks=None):
    reason = frontier_deviation(replay)
    require(reason is None, reason or 'Full retry fault')
    if len(control) >= 192*8:
        w = struct.unpack('<'+str(len(control)//8)+'Q',control)
        require(not(w[160]==0x43594f5053540001 and w[161]==1 and w[162]>0
                    and w[191]>0 and not w[191]%2),'native optimization-stop observed')
    if tasks is not None:
        require(len(tasks)==256,'Full retry task bank width')
        w=struct.unpack('<32Q',tasks)
        require(not w[2] and not w[3],'Full retry CPU quarantine/overrun')


def frontier_boundary(replay, collection):
    if len(replay) != 512 or len(collection) != 512: return None
    w = struct.unpack('<64Q',replay); c = struct.unpack('<64Q',collection)
    if (not w[0] or w[0]%2 or w[1] != 0x435952504c593133 or w[2:7] != (0,1,1,2,2)
        or not 0 <= w[11] <= MAX_EXCLUSIONS or not 4 <= w[10] <= 4+w[11]
        or w[17] != w[10]+w[11] or not 4 <= w[17] <= MAX_SIDES
        or w[7] != w[17]+1 or w[18:20] != (1,2)
        or any(w[k] for k in (9,12,13,14,15,16,20,21,22,23,63))
        or w[24:42] != (2,)+(0,)*17 or any(w[42:60])): return None
    if (not c[0] or c[0]%2 or c[1:9] != (0x43594c434f4c3136,1,0,0,0,1,1,2)
        or c[9:13] != (w[10],w[17],2,0)
        or c[13] not in (0,1) or c[14] != 1 or any(c[15:47]) or not c[47] or any(c[48:])): return None
    return dict(publication=w[0],collection_publication=c[0],profile_id=0,phase='PREPARE',
        frontier_family=[1,1],frontier_group=2,next_trial_id=w[7],verified=w[10],archived=w[17],paired=2,
        exclusions=w[11],max_exclusions=MAX_EXCLUSIONS,
        training_per_family=list(w[24:42]),validation_per_family=list(w[42:60]),
        work_quiescent=True,collection_owner_all_resources_clear=bool(c[13]),
        final_credit_release_verified=False,full_dataset_verified=False,
        scope='Two actual stored pairs and next-group frontier; Full collection remains incomplete.')


def stopped_frontier(probe):
    value = frontier_boundary(probe['replay'],probe['collection'])
    if value is None: return None
    for key in ('boot','runtime'):
        if len(probe[key]) != BANKS[key][1]: return None
        seq = word(probe[key],16)
        if not seq or seq%2: return None
    fatal_evidence(probe['replay'],probe['control'],probe['tasks'])
    return value


def closure(root=TOOL_ROOT, entries=None):
    root = Path(root).resolve(strict=True)
    pending = list(entries or ('run_v16_a03_full_retry_v2','v16_a03_full_retry_v2','verify_v16_a03_full_retry_v2'))
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
            elif target.name in ('pending-replay.bin','pending-collection.bin','pending-control.bin','pending-tasks.bin'):
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
        and inputs['frontier_groups'] == 2 and inputs.get('max_exclusions') == MAX_EXCLUSIONS
        and inputs.get('max_archive_bytes') == MAX_ARCHIVE_BYTES
        and type(inputs.get('timeout_seconds')) in (int,float) and 5 <= inputs['timeout_seconds'] <= 1200
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
    rows = doc('qmp-transcript.json')
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
    archive = extract_retry_archive(root/'disk.raw',trusted=trusted,disk_uuid=inputs['disk_uuid'],model=(root/'model.bin').read_bytes())
    pairs = archive['pairs']
    require(len(archive['sides']) == frontier['archived']
        and len(archive['excluded']) == frontier['exclusions']
        and sum(not side['excluded'] for side in archive['sides']) == frontier['verified'],
        'Full retry stopped counters differ from complete committed chronology')
    numeric = [numeric_frontier_pair(p['candidate']['raw_bytes'],p['baseline']['raw_bytes'],(root/'model.bin').read_bytes()) for p in pairs]
    require(len(pairs) == frontier['paired'] == 2,'stored count differs from committed side pairs')
    manifest, files = _exports([archive])
    manifest.update(version=VERSION,checker_version=CHECKER_VERSION,global_refusal_free=False)
    exports = root/'retry-archives'
    if exports.exists():
        require(exports.is_dir() and not exports.is_symlink() and {p.name for p in exports.iterdir()} == set(files)|{'manifest.json'},'Full raw archive export inventory mismatch')
        require(read_json(exports/'manifest.json') == manifest,'Full archive export manifest changed')
        for name,value in files.items(): require((exports/name).read_bytes() == value,'Full saved archive differs from committed disk')
    else:
        require(allow_unsaved_exports, 'missing complete Full retry raw archive exports')
    finish_custody(root,inventory,context,checker,dict(source_root=source_root,
        build_manifest=build_manifest,formatter=formatter,qemu_binary=qemu_binary,
        qemu_source=qemu_source,producer_tools_root=producer_tools_root))
    return dict(version=VERSION,checker_version=CHECKER_VERSION,status='FULL_RETRY_TWO_GROUP_FRONTIER_VERIFIED',
        frontier_verified=True,capture_complete=True,frontier=frontier,committed_pair_count=2,
        archive_manifest=manifest,archive_files=files,numeric=numeric,paid_banks_no_failure=True,
        regular_exclusions_verified=len(archive['excluded']),global_refusal_free=False,
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


def retry_record(row, header, context):
    flags = word(row, 0)
    require(flags in (40, 31, 27, 64), 'unsupported history flags')
    target = tuple(word(row, x) for x in (184, 192))
    require(target == (12, 1) and all(word(row, x) > 0 for x in (8, 152, 160, 168, 176)),
            'history snapshot/target mismatch')
    count, selected = struct.unpack_from('<HH', row, 204)
    require(1 <= count <= 4 and selected < count, 'candidate alternatives bound')
    weights = [_action(row[512 + i * 24:536 + i * 24], i) for i in range(count)]
    require(not any(row[512 + count * 24:1280]), 'unused history action slots')
    if flags == 40:
        require(header['side'] == 'Baseline' and count == 1 and selected == 0
                and row[200:204] == bytes(4) and not any(row[16:152])
                and word(row, 344) == header['boot_epoch'] and word(row, 440) == 0,
                'baseline metadata mismatch')
        retry_execution(row, header)
        return dict(kind='Baseline', sha256=digest(row), model_binding='trusted capture context')
    require(header['side'] == 'Candidate' and row[200:204] == b'\x01\0\x01\0'
            and word(row, 80) == context['model_generation']
            and row[88:120].hex() == context['model_sha256']
            and row[120:152].hex() == context['schema_hash'], 'history model/family mismatch')
    require(weights == sorted(set(weights)), 'unsorted/duplicate candidate alternatives')
    inp = row[2048:]
    require(digest(inp) == row[48:80].hex(), 'raw input hash mismatch')
    w = struct.unpack('<512Q', inp)
    expected_magic = int.from_bytes(b'CXPROBE1', 'little') if flags == 64 else 0x4359585254494e31
    require(w[0] == expected_magic and w[1] == 3 and w[2] == word(row, 8)
            and w[4] == word(row, 160) and (w[6], w[7]) == (word(row, 176), word(row, 168))
            and w[8:12] == (1, 1, 12, 1) and w[13:16] == (1, header['boot_epoch'], count)
            and inp[128:160] == row[88:120] and inp[160:192] == row[16:48]
            and w[40] == 15 and w[31] <= 1, 'input identity/features mismatch')
    canonical = bytearray(b'CYXIA_CANDIDATES_V1.3\0')
    canonical += words(*(word(row, i) for i in (152, 160, 168, 176, 184, 192, 80)), count)
    canonical += row[88:152]
    for i, weight in enumerate(weights):
        at = 64 + 10 * i
        payload = inp[(at + 1) * 8:(at + 3) * 8]
        require(w[at] == 4 and payload[:4] == struct.pack('<HH', i, weight)
                and not any(payload[4:]) and w[at + 7] <= 15 and w[at + 8] == w[at + 9] == 0,
                'candidate input action/target mismatch')
        canonical += struct.pack('<5H', 1, 1, 4, i, weight) + words(*w[24:36]) + bytes([w[40]])
        for j in range(4):
            present = (w[at + 7] >> j) & 1
            value = w[at + 3 + j]
            require((present or value == 0) and (j != 3 or value <= 1), 'illegal target features')
            canonical += bytes([present]) + words(value)
        canonical += bytes(9)  # absent control capacity
    require(digest(canonical) == row[16:48].hex(), 'CandidateSet integrity mismatch')
    prior = inp[405 * 8:407 * 8]
    require(w[404] == 4 and prior[:2] == bytes(2) and not any(prior[4:])
            and struct.unpack_from('<H', prior, 2)[0] in weights, 'invalid prior action')
    if flags == 64:
        require(selected == 0 and word(row, 8) == word(row, 152)
                and not any(row[208:512]) and not any(row[1280:2048])
                and all(w[i] == 0 for i in (3, 5, 12, 36, 37, 38, 39)), 'probe has publication fields')
    else:
        apply = tuple(word(row, i) for i in range(272, 320, 8))
        require(apply[0] == header['boot_epoch'] and apply[1] == w[3] > 0 and apply[2] > 0
                and apply[3:] == (0, 12, 1) and row[1280:1328] == row[272:320]
                and not any(row[1328:2048]) and word(row, 440) == 1 and word(row, 480) == 0
                and row[448:480] == EMPTY_SHARED and word(row, 496) in (0, 1)
                and not any(row[504:512]), 'unsupported publication/shared action')
        retry_execution(row, header)
    return dict(execution_state=word(row,424),execution_error=word(row,432),flags=flags,kind='Probe' if flags == 64 else 'Candidate', sha256=digest(row),
                candidate_set_sha256=row[16:48].hex(), input_sha256=row[48:80].hex(),
                candidate_set_integrity_verified=True)



def retry_execution(row, header):
    issued,accepted,started,finished=(word(row,p) for p in (352,360,400,416))
    state,error=word(row,424),word(row,432)
    flags=word(row,0)
    require(0 < issued <= accepted <= finished <= header['closing_ns'], 'invalid execution custody times')
    if state == 1:
        require(accepted <= started <= finished <= word(row,384)
                and word(row,392)>0 and error==0 and flags in (31,40), 'invalid Applied execution')
    else:
        require(header['excluded'] and state==3 and 0<=error<=19
                and flags in (27,31) and bool(flags&4)==bool(started)
                and (accepted<=started<=finished if started else word(row,392)==0),
                'unsupported/nonterminal excluded execution')
    if header['side']=='Candidate':
        require(word(row,320)==word(row,344)>0 and word(row,328)==word(row,160)
                and word(row,336)==word(row,376)==word(row,160)+OBSERVATION_NS
                and accepted<=word(row,368)<=word(row,160)+100_000_000
                and word(row,488)==0, 'invalid published exclusion stamp/expiry')


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
    exclusion, verification_error = word(h,160), word(h,168)
    excluded = bool(exclusion or verification_error)
    require(exclusion in (0,*RETRY_ERRORS) and verification_error in (0,*RETRY_ERRORS)
            and (not any(h[416:448]) if excluded else any(h[416:448])), 'excluded/canonical mismatch')
    require(1 <= records <= 64 and cpu <= 8192 and requests == 100
            and all(word(h, i) == 0 for i in (192, 224, 608, 624, 744, 752))
            and word(h, 632) == 2048, 'unsupported archive counts/peer/prewarm/exclusion')
    length = 2048 + records * 6144 + cpu * 64 + requests * 128
    require(length <= MAX_FILE and length <= len(raw), 'truncated/unbounded archive side')
    require(tuple(h[448 + i * 32:480 + i * 32].hex() for i in range(4)) == tuple(context['schema_hashes'])
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4
            and h[640:672].hex() == context['node_id'], 'archive schema/node mismatch')
    require(h[256:288].hex() == workload_digest(seed)
            and all(any(h[i:i + 32]) for i in (288, 320, 352, 384)), 'archive group/hash mismatch')
    count = word(h, 616)
    require(0 < count <= 16 and not any(h[768 + count * 32:1280])
            and word(h, 728) == 100 and word(h, 736) == count, 'archive source closure mismatch')
    sources = [struct.unpack_from('<4Q', h, 768 + i * 32) for i in range(count)]
    require(sources == [(12, 1, 0, 7), (12, 1, 1, 15), (OWNER, 1, 2, 1),
                        (0x5245504c5453, 1, 2, 9)], 'unsupported D01 source manifest')
    coverage = struct.unpack_from('<7Q', h, 672)
    require(coverage == (first, observation, observation + 10000000000, closing, 3, 3, 1)
            or (excluded and coverage == (0,)*7),
            'invalid local coverage')
    require((word(h,720)==1 and any(coverage)) or (excluded and word(h,720)==0 and not any(coverage)),
            'inconsistent retained coverage availability')
    _closing(h[1792:], boot, closing)
    result = dict(boot_epoch=boot, trial_id=trial, capture_generation=generation,
                  family=[1, 1], target=[12, 1], seed=seed, excluded=excluded,
                  exclusion_error_plus1=exclusion,verification_error_plus1=verification_error,
                  coverage_present=bool(word(h,720)),
                  accepted_training_sample_verified=False, side='Candidate' if candidate else 'Baseline',
                  first_ns=first, observation_ns=observation, closing_ns=closing, length=length,
                  workload_sha256=h[256:288].hex(), initial_image_sha256=h[288:320].hex(),
                  frozen_other_domains_sha256=h[320:352].hex(), frozen_scope_sha256=h[352:384].hex(),
                  event_sha256=h[384:416].hex(), producer_verification_sha256=h[416:448].hex(),
                  schema_hashes=list(context['schema_hashes']), node_id=context['node_id'])
    result['records'] = [retry_record(raw[2048 + i * 6144:2048 + (i + 1) * 6144], result, context) for i in range(records)]
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

def extract_retry_archive(disk_path, *, trusted, disk_uuid, model):
    before=sha(disk_path); sides=[]; segments=[]; total=0
    with committed_volume(Path(disk_path)) as (current,metadata):
        volume=inspect_committed(current,metadata)
        require(volume['uuid']==disk_uuid and volume['boot_epoch']==1,'Full committed volume identity mismatch')
        for name in sorted(set(volume['files'])|set(volume['directories'])):
            if not any(part.startswith('lr-') for part in name.split('/')): continue
            match=re.fullmatch(r'/lr-0000000000000001-([0-9a-f]{4})',name)
            require(match is not None and name in volume['files'],'unexpected Full frontier archive path')
            segments.append(int(match[1],16)); node=volume['files'][name]
            require(0<node['size']<=MAX_FILE and node['durable_write_seq']>0,'uncommitted/unbounded Full side archive')
            total+=node['size']; require(total<=MAX_ARCHIVE_BYTES,'Full retry total archive byte bound')
            raw=bytearray()
            for _,start,blocks in node['extents']:
                for block in range(start,start+blocks): raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            require(len(raw)==node['size'] and digest(raw)==node['sha256'],'Full committed archive hash mismatch')
            offset=0
            while offset<len(raw):
                side=frontier_side(memoryview(raw)[offset:],trusted)
                side.update(path=name,inode=node['inode'],inode_generation=node['generation'],durable_write_seq=node['durable_write_seq'],offset=offset,archive_sha256=node['sha256'],archive_bytes=bytes(raw))
                sides.append(side); require(len(sides)<=MAX_SIDES,'Full retry side bound'); offset+=side['length']
    require(sha(disk_path)==before and segments==list(range(len(segments))), 'Full retry disk changed/missing segments')
    result=match_retry_sides(sides,model)
    return dict(result,total_archive_bytes=total)


def match_retry_sides(sides, model):
    """Original Full chronological transitions, with no trial-number guesswork."""
    require(4<=len(sides)<=MAX_SIDES,'Full retry bounded side inventory')
    expected_seed=1; pending=None; pairs=[]; excluded=[]; superseded=[]; previous=None
    for side in sides:
        identity=(side['trial_id'],side['capture_generation'])
        require(side['seed']==expected_seed and expected_seed<=2,'Full retry reordered/missing group')
        require(previous is None or (identity[0]==previous[0]+1 and identity[1]>previous[1]),
                'Full retry trial chronology/generation changed')
        if previous is None:require(identity[0]==1,'Full retry first trial missing')
        previous=identity
        expected='Baseline' if pending is None else 'Candidate'
        require(side['side']==expected,'Full retry missing/duplicated side transition')
        if side['excluded']:
            require(len(excluded)<MAX_EXCLUSIONS,'Full retry exclusion bound')
            verify_excluded_side(side,model)
            excluded.append(side)
            if pending is not None:
                # This valid baseline belongs to the excluded attempt, not to
                # the next success. Preserve its Trial, numeric and raw custody.
                superseded.append(dict(baseline=pending,excluded_by_trial=side['trial_id']))
            pending=None
            continue
        numeric_frontier_side(side['raw_bytes'],model)
        if pending is None:
            pending=side
            continue
        for key in ('boot_epoch','family','target','seed','workload_sha256','initial_image_sha256',
                    'frozen_other_domains_sha256','schema_hashes','node_id','relative_arrivals'):
            require(pending[key]==side[key],'Full retry pair identity differs: '+key)
        pairs.append(dict(baseline=pending,candidate=side,model_sha256=digest(model),
            accepted_training_sample_verified=False,model_trained=False,native_acceptance_status='NOT_RUN'))
        pending=None; expected_seed+=1
    require(len(pairs)==2 and expected_seed==3 and pending is None,'Full retry missing complete seed1/2 pairs')
    return dict(pairs=pairs,sides=sides,excluded=excluded,superseded_baselines=superseded,
        global_refusal_free=False,accepted_training_sample_verified=False,model_trained=False)


def verify_excluded_side(side,model):
    require(side['excluded'] and side['producer_verification_sha256']=='00'*32,
            'excluded side gained canonical/acceptance')
    raw=side['raw_bytes']; h=raw[:2048]
    published=[]
    for i,parsed in enumerate(side['records']):
        row=raw[2048+i*6144:2048+(i+1)*6144]
        if parsed['kind']=='Candidate':
            count,selected=struct.unpack_from('<HH',row,204)
            scores,best=select_model(model,[encode_weight_features(row,j) for j in range(count)])
            require(scores==list(struct.unpack_from('<'+'h'*count,row,208)) and best==selected,
                    'excluded actual integer MLP mismatch')
            published.append(dict(sequence=word(row,8),version=word(row,344),state=word(row,424),
                error=word(row,432),scores=scores,selected=selected,started_ns=word(row,400),
                finished_ns=word(row,416),raw_sha256=digest(row)))
    side['exclusion_replay']=dict(original_exclusion_error_plus1=word(h,160),
        original_verification_error_plus1=word(h,168),native_canonical_zero=True,
        failed_publications=[r for r in published if r['state']==3],published=published,
        trial_reward_replay='NOT_APPLICABLE_EXCLUDED',accepted_training_sample_verified=False)
    return side['exclusion_replay']


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

