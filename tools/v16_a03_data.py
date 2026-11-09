"""Explicit bounded CoreSet data profile; exclusions are never labels."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import struct

from build_unified import code_source_map
from check_elf import inspect_elf, symbol, boot_profile
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, require, verify_samples
from verify_v13_model import loaded_bytes
import v16_a03_focus as strict
from v16_a03_focus import (sha,write_json,bounded_inventory,launch_argv,digest,word,words,
    archive_ref,sample_witness,core_image,numeric_core_pair,match_sample_witness,_schema_context,
    actual_candidate_runtime,paid_bank_facts,builder_source_closure)

VERSION='v16-a03-coreset-data-one-pair-v3'
CHECKER_VERSION='v16-a03-bounded-data-checker-v3'
DIAGNOSTIC_VERSION='v16-a03-bounded-data-diagnostics-v2'
SCHEMAS=tuple(schema for schema in strict.SCHEMAS)
TOOL_ROOT=Path(__file__).resolve().parents[1]
MAX_ATTEMPTS=6
HOST_TIMEOUT_SECONDS=600
MAX_FILE=8*1024**2
COLLECTION_MAGIC=strict.COLLECTION_MAGIC


def require_data_profile(manifest):
    require(type(manifest) is dict and manifest.get('schema_version')==1
        and manifest.get('contract')=='v16-learning-collection-build-v2'
        and manifest.get('status')=='BUILT_NOT_RUN'
        and manifest.get('collection_profile')=='coreset-data-one-pair'
        and type(manifest.get('profile_id')) is int and manifest['profile_id']==2
        and type(manifest.get('bounded_data_schema')) is int and manifest['bounded_data_schema']==2,
        'wrong explicit bounded-data build profile')
    return manifest['collection_profile']

DATA_MAGIC=0x4359424441543136
RETRY_DOMAIN=frozenset((0,8,10,11,20))
RETRY_LEARNING=frozenset((7,16,17))
HARD_DOMAIN=frozenset(range(1,21))-frozenset((8,10,11,20))
OUTCOMES={1:'excluded',2:'unpaired_baseline',3:'selected_baseline',4:'selected_candidate',5:'superseded_baseline'}


def data_reference(raw,*,preparation=False):
    require(len(raw)==96,'data journal reference width')
    if not any(raw):return None
    boot,trial,generation,obj,objgen,offset,length=struct.unpack_from('<7Q',raw)
    require(boot>0 and 1<=trial<=MAX_ATTEMPTS and obj>0 and objgen>0 and 0<length<=MAX_FILE
        and offset+length<=MAX_FILE and any(raw[56:88]) and not any(raw[88:])
        and (generation==0 if preparation else generation>0),'data journal key/range/hash mismatch')
    return dict(boot_epoch=boot,trial_id=trial,generation=generation,object_id=obj,
        object_generation=objgen,offset=offset,bytes=length,sha256=raw[56:88].hex())


def decode_data_ledger(raw):
    require(len(raw)==8192,'bounded-data bank width')
    w=struct.unpack('<1024Q',raw)
    require(w[0]>0 and not w[0]%2 and w[1:4]==(DATA_MAGIC,2,2)
        and w[4] in (25,26,27) and 1<=w[5]<=MAX_ATTEMPTS and w[6]==MAX_ATTEMPTS
        and all(w[index] in (0,1) for index in (7,8,9,13,14,15,16,17,26))
        and w[9]==w[15]==w[16]==w[17]==w[26]==1 and w[14]==0
        and w[18]>0 and w[19]>0 and w[20]==4096 and any(raw[168:200])
        and w[25]>0 and w[30]==w[5] and w[31]>0 and not any(w[528:]),
        'bounded-data is not a closed durable paid terminal boundary')
    stored=bool(w[7]);phase=w[4]
    hard_words=w[524:528];hard_present=any(hard_words);stored_before=False;hard_stop=None
    if hard_present:
        hard_trial,hard_code,hard_time,hard_phase=hard_words;stored_before=bool(hard_phase>>63)
        require(1<=hard_trial==w[5]<=MAX_ATTEMPTS and hard_code in HARD_DOMAIN
            and 0<hard_time<=w[31] and hard_phase&((1<<63)-1)<=27 and stored_before==stored
            and phase==27,'hard fault permits postfatal admission/store or false success/exhaustion')
        hard_stop=dict(trial_id=hard_trial,incoming_domain_error_code=hard_code,observed_ns=hard_time,
            native_phase=hard_phase&((1<<63)-1),stored_before_fatal=stored_before)
    require((phase==25 and stored and not w[8] and w[13]==1)
        or (phase==26 and not stored and w[8]==1 and w[5]==MAX_ATTEMPTS and w[13]==0)
        or (phase==27 and w[8]==int(not stored and w[5]==MAX_ATTEMPTS) and w[13]==int(stored)
            and (not stored or hard_present and stored_before)),'contradictory data success/exhaustion/stopped state')
    attempts=[];prepids=set();ranges=[];nonretryable=False;fatal_trials=[]
    for index in range(MAX_ATTEMPTS):
        at=(32+56*index)*8;r=w[32+56*index:32+56*(index+1)]
        if index>=w[5]:
            require(not any(r),'post-bound/post-store attempt payload');continue
        trial,prep,boot,kind,generation,original,learning,outcome,release,required,journals,retired=r[:12]
        require(trial==index+1 and prep>0 and prep not in prepids and boot>0 and kind in (1,2)
            and outcome in (1,3,4,5) and retired==1 and release==required and required in (7,31)
            and r[53]>0 and (r[54]==0 or r[53]<=r[54]<=w[31]) and r[55] in HARD_DOMAIN|{0},
            'invalid/missing/unclosed/reused attempt identity')
        prepids.add(prep)
        if r[55]:fatal_trials.append(trial)
        if original in HARD_DOMAIN:require(r[55]!=0,'original hard cause lacks schema2 incoming-hard proof')
        regular=data_reference(raw[at+128:at+224]);preparation=data_reference(raw[at+224:at+320],preparation=True)
        late=data_reference(raw[at+320:at+416])
        require((regular is None)!=(preparation is None) and journals==1+int(late is not None)
            and (required==7 and generation==0 if preparation else required==31 and generation>0),
            'missing/contradictory regular/preparation/late journal')
        for ref in (regular,preparation,late):
            if ref is None:continue
            require((ref['boot_epoch'],ref['trial_id'])==(boot,trial)
                and ref['generation']==(0 if ref is preparation else generation),'attempt/reference RunKey mismatch')
            identity=(ref['object_id'],ref['object_generation']);start=ref['offset'];end=start+ref['bytes']
            require(all(identity!=old or end<=left or right<=start for old,left,right in ranges),'aliased/reused journal range')
            ranges.append((identity,start,end))
        canonical=raw[at+96:at+128].hex()
        retryable=original in RETRY_DOMAIN and learning in RETRY_LEARNING
        if preparation is not None:require(outcome==1 and original>0,'preparation exclusion has no authentic Domain error')
        if outcome==1:
            require(learning>0 and (original==0 or r[54]>0),'excluded attempt lacks its own error/time')
            nonretryable |= not retryable
            if not retryable:fatal_trials.append(trial)
            require(retryable or phase==27,'nonretryable/integrity/resource exclusion cannot be collection progress')
        else:
            stopped_superseded=(phase==27 and outcome==5 and hard_present and trial==hard_stop['trial_id']
                and original==r[55]==hard_stop['incoming_domain_error_code'])
            require(learning==0 and (original==0 or stopped_superseded) and regular is not None and any(raw[at+96:at+128])
                and (kind==1 if outcome==4 else kind==2),'unverified/excluded/superseded side selected as data')
        if outcome in (3,4):require(late is None and r[52]>0,'selected side has late failure or no Root token')
        attempts.append(dict(trial_id=trial,preparation_id=prep,boot_epoch=boot,kind=kind,generation=generation,
            original_domain_error_code=original,learning_error_code=learning,outcome=OUTCOMES[outcome],
            release_mask=release,required_release_mask=required,journal_count=journals,references_retired=True,
            verified_canonical_sha256=canonical,regular=regular,preparation=preparation,late=late,
            hard_domain_error_code=r[55],root_token=r[52],preparation_started_ns=r[53],first_failure_ns=r[54],retryable_exclusion=retryable if outcome==1 else None))
    require(len({a['boot_epoch'] for a in attempts})==1 and w[10]==sum(a['outcome']=='excluded' for a in attempts)
        and w[11]==sum(a['outcome']!='excluded' for a in attempts)
        and w[12]==w[29]==sum(a['journal_count'] for a in attempts)
        and ((nonretryable or hard_present) if phase==27 else not nonretryable and not hard_present),'ledger counters/errors were cleared or contradict attempts')
    require(not fatal_trials or min(fatal_trials)==w[5],'postfatal admission after nonretryable attempt')
    if hard_present:
        require(attempts[-1]['hard_domain_error_code']==hard_stop['incoming_domain_error_code']
            and attempts[-1]['preparation_started_ns']<=hard_stop['observed_ns']
            and all(not a['hard_domain_error_code'] for a in attempts[:-1]),'hard-stop row/global original incoming cause mismatch')
    else:require(all(not a['hard_domain_error_code'] for a in attempts),'row hard fault has no global schema2 stop proof')
    witness_raw=bytes(raw[368*8:496*8]);witness_hash=bytes(raw[496*8:500*8]);witness=None
    refs=[data_reference(raw[500*8:512*8]),data_reference(raw[512*8:524*8])]
    if stored:
        require(digest(witness_raw)==witness_hash.hex(),'protected bounded-data witness digest mismatch')
        witness=sample_witness(witness_raw)
        b,c=witness['baseline_id'],witness['candidate_id']
        require([b,c]==list(w[27:29]) and 1<=b<c==w[5] and c==b+1
            and [attempts[b-1]['outcome'],attempts[c-1]['outcome']]==['selected_baseline','selected_candidate']
            and refs==[attempts[b-1]['regular'],attempts[c-1]['regular']]
            and witness['baseline_canonical']==attempts[b-1]['verified_canonical_sha256']
            and witness['candidate_canonical']==attempts[c-1]['verified_canonical_sha256']
            and sum(a['outcome'].startswith('selected_') for a in attempts)==2,
            'witness selects wrong/superseded/nonfinal pair or post-store trial')
    else:
        require(not any(witness_raw) and not any(witness_hash) and refs==[None,None]
            and w[27]==w[28]==0 and all(not a['outcome'].startswith('selected_') for a in attempts),
            'failed/exhausted collection fabricated a selected sample')
    return dict(status={25:'SAMPLE_COLLECTED',26:'EXHAUSTED',27:'STOPPED'}[phase],phase=phase,
        collection_succeeded=phase==25,credited_samples=int(phase==25),hard_stop=hard_stop,
        attempt_count=w[5],bound=MAX_ATTEMPTS,stored=stored,exhausted=bool(w[8]),attempts=attempts,
        excluded=w[10],verified=w[11],archived=w[12],journal_count=w[29],closed_attempt_count=w[30],
        selected_trials=list(w[27:29]),selected_references=refs,witness=witness,witness_raw=witness_raw,
        supplement_object=[w[18],w[19]],supplement_bytes=4096,supplement_sha256=raw[168:200].hex(),
        paid_turn_ticket=w[25],paid_turn_acknowledged=True,sampled_ns=w[31],
        per_attempt_physical_ack_claimed=False,raw_bytes=bytes(raw))


def error_schema(source_root):
    root=Path(source_root)
    def names(relative):
        text=(root/relative).read_text();match=re.search(r'pub enum Error\s*\{([^}]+)\}',text)
        require(match is not None,'unsupported typed error enum')
        fields=[item.strip() for item in match[1].split(',') if item.strip()]
        require(all(re.fullmatch('[A-Za-z]+',item) for item in fields),'noncanonical error enum')
        return {name:index+1 for index,name in enumerate(fields)}
    domain=names('crates/prototype/src/domains/types.rs');learning=names('crates/prototype/src/learning.rs')
    require({key:domain.get(key) for key in ('Expired','Busy','Again','NotReady','Stale','Auth','Budget','Capacity','Io')}
        ==dict(Expired=8,Busy=10,Again=11,NotReady=20,Stale=4,Auth=2,Budget=6,Capacity=5,Io=18)
        and {key:learning.get(key) for key in ('DataIncomplete','Deadline','Unknown')}
        ==dict(DataIncomplete=7,Deadline=16,Unknown=17),'source error enum differs from bounded retry contract')
    return dict(domain=domain,learning=learning)


def tool_closure(tool_root=TOOL_ROOT):
    """Static transitive local imports, including function-local imports."""
    root = Path(tool_root).resolve(strict=True)
    pending = ['run_v16_a03_data', 'v16_a03_data', 'verify_v16_a03_data']
    found = {}
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path = root / 'tools' / (name + '.py')
        require(path.is_file() and not path.is_symlink(), 'missing/linked trusted tool ' + name)
        found[name] = sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports = ([node.module] if isinstance(node, ast.ImportFrom) else
                       [x.name for x in node.names] if isinstance(node, ast.Import) else [])
            for item in imports:
                if item and (root / 'tools' / (item + '.py')).is_file():
                    pending.append(item)
    result = {'tools/' + name + '.py': digest for name, digest in sorted(found.items())}
    patch = 'tools/qemu/cyxia-per-vcpu-pmu.patch'
    result[patch] = sha(root / patch)
    return result

def trusted_context(*, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                    producer_tools_root=None):
    """Only caller-selected paths authorize executable/source/build identities."""
    # Preserve the original native-context schema: this optional caller trust
    # root selects only producer hashes, never an executable or captured path.
    require(all(not Path(value).is_symlink() for value in (source_root,build_manifest,formatter,qemu_binary,qemu_source)), 'linked trusted input')
    paths = {name: Path(value).resolve(strict=True) for name, value in dict(
        source_root=source_root, build_manifest=build_manifest, formatter=formatter,
        qemu_binary=qemu_binary, qemu_source=qemu_source).items()}
    source = paths['source_root']; build = paths['build_manifest']
    for name in ('formatter', 'qemu_binary'):
        require(paths[name].is_file() and os.access(paths[name], os.X_OK), 'not executable: ' + name)
    sources = code_source_map(source)
    error_schema(source)
    manifest = json.loads(build.read_text())
    require_data_profile(manifest)
    base_path = build.parent / 'base-build-manifest.json'
    base_ref = manifest['base_manifest']
    require(base_ref == dict(path=base_path.name, bytes=base_path.stat().st_size, sha256=sha(base_path)),
            'base build manifest mismatch')
    base = json.loads(base_path.read_text())
    p = base['profiles']
    require(base['schema_version'] == 1 and base['status'] == 'BUILT_NOT_RUN'
            and p['selftest'] is True and p['fault'] == 'normal'
            and p.get('service_fault','none') == 'none'
            and p.get('service_fault_nodes',{'a':'none','b':'none'}) == {'a':'none','b':'none'}
            and all(p.get(k,False) is False for k in ('leave','storage_fault','memory_probe')),
            'conflicting collection base profile')
    require(base.get('own_private_key_only_verified') is True
            and manifest['code_source_sha256'] == base['code_source_sha256']
            == hashlib.sha256(json.dumps(sources,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            and manifest['code_source_map'] == base['code_source_map'] == sources
            and base['builder_sha256'] == sha(source/'tools/build_unified.py'), 'source/build mismatch')
    require(manifest['builder_sources'] == builder_source_closure(source), 'collection builder closure changed')
    artifacts = {}
    for name in ('node-a.elf', 'service-a.elf', 'task.elf', 'node-a.pub'):
        path = build.parent / name
        require(path.is_file() and not path.is_symlink()
                and base['artifacts'][name]['sha256'] == sha(path)
                and base['artifacts'][name]['bytes'] == path.stat().st_size, 'build artifact mismatch: ' + name)
        artifacts[name] = sha(path)
    image = (build.parent / 'node-a.elf').read_bytes()
    inspect_elf(image)
    layout = symbol(image, 'LEARNING_COLLECTION_V16_LAYOUT')
    require(layout['size'] == 40 and struct.unpack('<5Q', loaded_bytes(image, layout['va'], 40))
            == (COLLECTION_MAGIC, 2, 2, 1024, 96), 'ELF collection identity mismatch')
    require(manifest['elf_layouts']['a'] == dict(symbol='LEARNING_COLLECTION_V16_LAYOUT',
        address=layout['va'],words=[COLLECTION_MAGIC,2,2,1024,96],
        sha256=hashlib.sha256(struct.pack('<5Q',COLLECTION_MAGIC,2,2,1024,96)).hexdigest()),
        'manifest/ELF collection layout mismatch')
    require(boot_profile(image) == dict(version=1, ram_mib=1024, heap_pages=2048), 'wrong boot profile')
    symbols = {key: symbol(image, name) for key, (name, size) in BANKS.items()}
    for key, (_, size) in BANKS.items():
        require(symbols[key]['size'] >= size and
                (key == 'control' or symbols[key]['size'] == size), 'wrong bank size: ' + key)
    from run_v13_boot_recovery import DEBUG_SYMBOLS
    diagnostics = {}
    for key, name in {**DEBUG_SYMBOLS, **{key: name for key, (name, _) in BANKS.items()}}.items():
        try:
            diagnostics[key] = symbol(image, name)
        except ValueError:
            continue
    diagnostics.update(focus_diagnostic_symbols(image))
    model_symbol = symbol(image, 'A02_BOOT_MODEL')
    require(model_symbol['size'] == 2772, 'wrong embedded model layout')
    model = loaded_bytes(image, model_symbol['va'], model_symbol['size'])
    node_id = hashlib.sha256((build.parent / 'node-a.pub').read_bytes()).hexdigest()
    require(node_id == base['nodes']['a']['node_id'], 'build node identity mismatch')
    proof = attest_qemu(str(paths['qemu_binary']), paths['qemu_source'])
    require(proof.get('qemu_pmu_patch_attested') is True, 'learning capture requires fixed patched QEMU')
    return dict(version=VERSION, paths={k: str(v) for k, v in paths.items()},
                source_map=sources, build_sha256=sha(build), base_build_sha256=sha(base_path), artifacts=artifacts, symbols=symbols,
                diagnostic_symbols=diagnostics, diagnostic_contract=DIAGNOSTIC_VERSION,
                model_sha256=hashlib.sha256(model).hexdigest(), model_generation=1,
                schema_hash=sha(source / 'crates/prototype/src/features.rs'), node_id=node_id,
                formatter_sha256=sha(paths['formatter']), qemu=proof,
                tools=tool_closure(TOOL_ROOT if producer_tools_root is None else producer_tools_root))

def _verify_data_capture_custody(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                            producer_tools_root=None, terminal_contract):
    """Replay fixed local code against explicit caller context, never archived commands.

    This verifier reads recorded commands as evidence only. It never executes
    archived code, subprocess arguments, checker names, or summary booleans.
    An optional caller-selected producer root is read/AST-hashed only; current
    fixed checker functions execute, with their separate identity in the result.
    """
    from boot_reboot_contract import verify_origin, DISK_BYTES
    require(terminal_contract in ('bounded-data-terminal','bounded-data-interrupted'), 'unknown terminal custody contract')
    failure_contract = terminal_contract == 'bounded-data-interrupted'
    root = Path(directory)
    require(not root.is_symlink(), 'linked capture directory')
    root = root.resolve(strict=True)
    initial_inventory = bounded_inventory(root)
    def document(name):
        path = root / name
        require(path.is_file() and path.stat().st_size <= 128 * 1024**2, 'missing/unbounded capture document')
        return json.loads(path.read_text())
    context = trusted_context(source_root=source_root, build_manifest=build_manifest, formatter=formatter,
                              qemu_binary=qemu_binary, qemu_source=qemu_source,
                              producer_tools_root=producer_tools_root)
    require(document('native-context.json') == context, 'caller/source/build/tool context mismatch')
    for name, digest in context['artifacts'].items():
        require(sha(root / name) == digest, 'captured image/input mismatch: ' + name)
    require(sha(root / 'build-manifest.json') == context['build_sha256'], 'captured build mismatch')
    require(document('source-manifest.json') == context['source_map'], 'captured source map mismatch')
    for name, digest in context['source_map'].items():
        require(sha(root / 'source-inputs' / name) == digest, 'captured source bytes mismatch')
    for name, digest in context['tools'].items():
        require(sha(root / 'producer-tools' / name) == digest, 'captured tool closure mismatch')
    require(sha(root / 'model.bin') == context['model_sha256'], 'captured model mismatch')
    require(sha(root/'base-build-manifest.json') == context['base_build_sha256'], 'captured base build mismatch')
    inputs = document('input.json')
    require(inputs['version'] == VERSION and type(inputs['mode']) is int and inputs['mode'] == 0
            and type(inputs['timeout_seconds']) in (int, float) and 5 <= inputs['timeout_seconds'] <= 600
            and inputs['poll_seconds'] == .1 and inputs['serial_seconds'] == 1
            and inputs['max_stopped_attempts'] == 64, 'wrong capture observation profile')
    nonce = bytes.fromhex(inputs['nonce'])
    require(len(nonce) == 16 and any(nonce), 'invalid capture nonce')
    expected_config = (struct.pack('<4Q', CONFIG_MAGIC, 1, 0, 0) + nonce
        + bytes.fromhex(context['artifacts']['node-a.elf']) + bytes.fromhex(sha(root / 'input.json'))
        + bytes.fromhex(sha(root / 'source-manifest.json')) + bytes(368))
    config = (root / 'config.bin').read_bytes()
    require(config == expected_config == (root / 'config-observed.bin').read_bytes(), 'capture config mismatch')
    injection = document('config-injection.json')
    require(injection == dict(request_hex=config_write_packet(config, context['symbols']['config']['pa']).hex(),
                              received_hex=injection['received_hex'], ack_hex='2b')
            and bytes.fromhex(injection['received_hex']).lstrip(b'+') == b'$OK#9a', 'wrong preboot injection')
    process = document('process-exit.json')
    require(process['schema'] == 1 and type(process['pid']) is int and process['pid'] > 0
            and process['peer_pid'] == process['pid'] and process['returncode'] == 0
            and process['forced'] is False and process['quit_ok'] is True and process['eof'] is True and not process['errors']
            and type(process['started_ns']) is int and type(process['exited_ns']) is int
            and 0 < process['started_ns'] < process['exited_ns'], 'owned process did not exit normally')
    launch = document('launch.json')
    require(type(launch['port']) is int and 0 < launch['port'] < 65536
            and launch['qmp'] != launch['gdb'] and launch['symbols'] == context['symbols']
            and launch['argv'] == launch_argv(context['paths']['qemu_binary'], root,
                launch['qmp'], launch['gdb'], launch['port']), 'exact launch/platform mismatch')
    require(document('formatter-command.json') == dict(argv=[context['paths']['formatter'],
            str(root / 'disk.raw'), inputs['disk_uuid']]), 'formatter command mismatch')
    require(len(bytes.fromhex(inputs['disk_uuid'])) == 16, 'invalid disk UUID')
    verify_origin(inputs['disk_origin'], document('disk-before.json'), (root / 'format.log').read_bytes())
    disk = document('disk-after.json')
    require(disk == dict(bytes=(root / 'disk.raw').stat().st_size, sha256=sha(root / 'disk.raw'))
            and disk['bytes'] == DISK_BYTES, 'final disk custody mismatch')
    platform = document('platform.json')
    require(len(platform['cpus']) == 4 and {c['cpu-index'] for c in platform['cpus']} == set(range(4))
            and platform['memory']['base-memory'] == 1024**3, 'captured platform mismatch')
    dtb = (root / 'platform.dtb').read_bytes(); header = (root / 'dtb-header.bin').read_bytes()
    require(len(header) == 40 and header == dtb[:40] and 40 <= len(dtb) <= 2 * 1024**2
            and struct.unpack_from('>2I', dtb) == (0xd00dfeed, len(dtb)), 'captured DTB mismatch')
    rows = document('qmp-transcript.json')
    for direction, name in (('send', 'qmp-sent.bin'), ('receive', 'qmp-received.bin')):
        wire = root / name
        require(wire.stat().st_size <= 128 * 1024**2, 'QMP wire bound')
        decoded = [json.loads(line) for line in wire.read_bytes().splitlines() if line.strip()]
        require(decoded == [r['message'] for r in rows if r['direction'] == direction], 'raw QMP transcript mismatch')
    require(rows and rows[0]['direction'] == 'receive' and 'QMP' in rows[0]['message'], 'missing raw QMP greeting')
    pending = None; running = False; paused = False; quit_seen = False; resumed = False
    stops = 0; captures = set(); serial = bytearray(); responses = {}; last_id = 0
    preboot = set(); setup = set(); event_commands = set()
    attempts = {}; current_attempt = None; selected_attempt = None
    required_banks = set(BANKS) - {'config'}
    def stopped_attempt(number):
        require(number in attempts and set(attempts[number]) == required_banks,
                'incomplete stopped probe bank set')
        probe = attempts[number]
        fatal_evidence(probe['replay'], probe['control'])
        return stopped_data_ready(probe)
    allowed = {'qmp_capabilities', 'query-cpus-fast', 'query-memory-size-summary', 'pmemsave',
               'ringbuf-read', 'cont', 'stop', 'query-status', 'quit'}
    for row in rows[1:]:
        require(row['direction'] in ('send', 'receive') and type(row['message']) is dict, 'invalid QMP row')
        message = row['message']
        if row['direction'] == 'receive':
            if 'event' in message:
                event = message['event']
                require(event in {'STOP', 'RESUME', 'SHUTDOWN'}
                        and {'STOP': 'stop', 'RESUME': 'cont', 'SHUTDOWN': 'quit'}[event] in event_commands,
                        'unknown/out-of-order native QMP event')
                require((event == 'STOP' and not running or event == 'RESUME' and running
                         or event == 'SHUTDOWN' and quit_seen), 'QMP event contradicts lifecycle')
                timestamp = message.get('timestamp')
                require(type(timestamp) is dict and set(timestamp) == {'seconds', 'microseconds'}
                        and all(type(v) is int and v >= 0 for v in timestamp.values())
                        and timestamp['microseconds'] < 1000000, 'invalid QMP event timestamp')
                if event == 'SHUTDOWN':
                    require(message.get('data') == {'guest': False, 'reason': 'host-qmp-quit'},
                            'unexpected guest shutdown')
                else:
                    require(message.get('data', {}) == {}, 'unexpected lifecycle event data')
                continue
            require(pending is not None and message.get('id') == pending['id'] and 'error' not in message
                    and 'return' in message, 'unmatched/failed QMP command')
            name = pending['execute']; result = message['return']
            if name == 'query-status':
                require(result.get('status') == 'paused', 'QMP stop was not paused')
                paused = True
            elif name == 'ringbuf-read':
                serial.extend(base64.b64decode(result, validate=True))
                require(len(serial) <= 8 * 1024**2, 'raw serial bound')
            elif name in ('query-cpus-fast', 'query-memory-size-summary'):
                responses[name] = result
            pending = None
            continue
        require(not quit_seen and pending is None and message.get('execute') in allowed
                and type(message.get('id')) is int and message['id'] == last_id + 1
                and set(message) <= {'execute', 'id', 'arguments'}, 'unauthorized/outstanding QMP command')
        last_id = message['id']
        name = message['execute']; pending = message
        if name not in {'pmemsave', 'ringbuf-read'}:
            require('arguments' not in message, 'unexpected QMP command arguments')
        if name in {'qmp_capabilities', 'query-cpus-fast', 'query-memory-size-summary'}:
            require(not resumed and name not in setup and (name == 'qmp_capabilities' or 'qmp_capabilities' in setup),
                    'out-of-order platform setup')
            setup.add(name)
        elif name == 'ringbuf-read':
            require(resumed and message.get('arguments') ==
                    dict(device='cyxlog', size=1048576, format='base64'), 'unexpected ringbuf arguments')
        elif name == 'query-status':
            require(stops > 0 and not running, 'status without stopped guest')
        if name in {'cont', 'stop', 'quit'}:
            event_commands.add(name)
        if name == 'cont':
            require(not running and (not resumed or paused) and not captures and preboot == {'dtb-header.bin', 'platform.dtb', 'config-observed.bin'}
                    and setup == {'qmp_capabilities', 'query-cpus-fast', 'query-memory-size-summary'},
                    'resume after final evidence or before preboot setup')
            if resumed:
                require(not stopped_attempt(current_attempt), 'resumed a valid released stopped probe')
            running = resumed = True; paused = False; current_attempt = None
        elif name == 'stop':
            require(resumed and (running or paused and (failure_contract or captures == set(BANKS) - {'config'})),
                    'stop outside run/final diagnostic boundary')
            if running:
                current_attempt = len(attempts) + 1
                require(current_attempt <= 64, 'stopped attempt bound exceeded')
                attempts[current_attempt] = {}
            running = False; paused = False; stops += 1
            require(stops <= 65, 'stopped probe bound exceeded')
        elif name == 'pmemsave':
            args = message['arguments']; target = Path(args['filename'])
            require(set(args) == {'val', 'size', 'filename'} and type(args['val']) is int
                    and target.parent == root and not target.is_symlink()
                    and type(args['size']) is int and 0 < args['size'] <= 2 * 1024**2,
                    'external/unbounded physical capture')
            key = None; size = None; address = None
            if target.name in {'dtb-header.bin', 'platform.dtb', 'config-observed.bin'}:
                require(not resumed and target.name not in preboot, 'preboot read after resume/duplicate')
                if target.name == 'config-observed.bin':
                    require({'dtb-header.bin', 'platform.dtb'} <= preboot, 'config read before DTB')
                    address, size = context['symbols']['config']['pa'], 512
                else:
                    require(target.name == 'dtb-header.bin' or 'dtb-header.bin' in preboot, 'DTB before header')
                    address, size = 0x40000000, 40 if target.name == 'dtb-header.bin' else len(dtb)
                preboot.add(target.name)
            elif target.name in {'pending-replay.bin','pending-control.bin','pending-collection.bin','pending-bounded_data.bin','pending-tasks.bin'}:
                require(running and not paused and not captures, 'live probe after stop')
                key = target.stem.removeprefix('pending-')
            elif re.fullmatch(r'probe-[0-9]{2}-(boot|replay|control|runtime|unified|collection|tasks|credit|settlement|bounded_data)\.bin', target.name):
                require(paused and not running and not captures and int(target.name[6:8]) == stops,
                        'probe without confirmed bounded stop')
                key = target.stem[9:]
                require(current_attempt == stops and key not in attempts[current_attempt],
                        'duplicate/unmatched stopped probe')
                require(target.is_file() and target.stat().st_size == BANKS[key][1],
                        'missing or short stopped probe artifact')
                attempts[current_attempt][key] = target.read_bytes()
            elif target.name.startswith('diagnostic-') and target.suffix == '.bin':
                require(paused and not running, 'diagnostic before pause')
                diagnostic = target.stem.removeprefix('diagnostic-')
                require(diagnostic in context['diagnostic_symbols'], 'unknown diagnostic bank')
                location = context['diagnostic_symbols'][diagnostic]
                address, size = location['pa'], location['size']
            elif target.name in {key + '.bin' for key in BANKS if key != 'config'}:
                key = target.stem
            else:
                require(False, 'unknown physical capture name')
            if key is not None:
                address, size = context['symbols'][key]['pa'], (4096 if target.name=='pending-control.bin' else BANKS[key][1])
            require(args['val'] == address and args['size'] == size, 'unauthorized physical capture range')
            if target.name in {key + '.bin' for key in BANKS if key != 'config'}:
                key = target.stem
                require(paused and not running and key not in captures
                        and args['val'] == context['symbols'][key]['pa']
                        and args['size'] == BANKS[key][1], 'final evidence saved before confirmed pause')
                require(stopped_attempt(current_attempt), 'final banks require released stopped probe')
                if selected_attempt is None:
                    selected_attempt = current_attempt
                require(selected_attempt == current_attempt, 'mixed selected stopped attempts')
                require(target.stat().st_size == args['size']
                        and target.read_bytes() == attempts[selected_attempt][key],
                        'final bank differs from selected stopped probe')
                captures.add(key)
        elif name == 'quit':
            require(paused and not running and (not captures if failure_contract else captures == set(BANKS) - {'config'}), 'quit outside terminal custody contract')
            quit_seen = True
    require(quit_seen and pending is None and resumed and stops > 0, 'incomplete QMP lifecycle')
    if failure_contract:
        require(not captures and selected_attempt is None and len(attempts) <= 64
            and set(attempts) == set(range(1,len(attempts)+1)), 'failure capture has released final banks')
        require(all(set(probe) == required_banks or (not probe and number == max(attempts))
            for number,probe in attempts.items()), 'incomplete retained failure stopped attempt')
        diagnostic_reads = verify_failure_diagnostic_reads(rows,root,context)
    else:
        require(selected_attempt is not None and set(attempts) == set(range(1,selected_attempt+1)),
                'incomplete released QMP lifecycle')
        require(all(set(probe) == required_banks for probe in attempts.values()), 'incomplete retained stopped attempt')
        diagnostic_reads = verify_focus_diagnostic_reads(rows,root,context)
    require(responses.get('query-cpus-fast') == platform['cpus']
            and responses.get('query-memory-size-summary') == platform['memory'], 'platform/QMP mismatch')
    require(bytes(serial) == (root / 'serial.bin').read_bytes(), 'serial/QMP mismatch')
    decoder = FrameDecoder(); text = b''.join(payload + b'\n' for payload in decoder.feed(bytes(serial)))
    require(text == (root / 'serial.txt').read_bytes() and decoder.loss == decoder.corrupt == 0
            and not decoder.buffer and not any(x in text or x in serial for x in (b'PANIC', b'SMP_ERROR', b'UNIFIED_FAIL')),
            'native serial fault/loss/corruption')
    if failure_contract:
        boot,replay,control,runtime,unified = ((root/('diagnostic-'+key+'.bin')).read_bytes()
            for key in ('boot','replay','control','runtime','unified'))
        require(data_terminal_candidate((root/'diagnostic-bounded_data.bin').read_bytes()) is None, 'terminal data collection cannot be called interrupted')
        verify_samples(boot,boot,control[:4096],runtime,unified,config)
        require(bounded_inventory(root)==initial_inventory,'capture changed during base custody replay')
        return dict(version=VERSION,terminal_contract=terminal_contract,trusted_context=context,
            boot_epoch=struct.unpack('<64Q',boot)[6],diagnostic_reads=diagnostic_reads,
            raw_inventory=initial_inventory,process_cleanup_verified=True,base_custody_verified=True)
    boot, replay, control, runtime, unified = ((root / (key + '.bin')).read_bytes()
                                             for key in ('boot', 'replay', 'control', 'runtime', 'unified'))
    boundary = decode_data_ledger((root/'bounded_data.bin').read_bytes())
    verify_replay_terminal(replay,boundary)
    fatal_evidence(replay, control)
    verify_samples(boot, boot, control[:4096], runtime, unified, config)
    epoch = struct.unpack('<64Q', boot)[6]
    trusted = dict(context, boot_epoch=epoch, input_sha256=sha(root / 'input.json'),
                   config_sha256=sha(root / 'config.bin'), nonce=inputs['nonce'], disk_uuid=inputs['disk_uuid'],
                   disk_sha256=disk['sha256'], released_boundary=boundary,
                   stopped_banks={key: sha(root / (key + '.bin')) for key in captures})
    return dict(version=VERSION, released_pair_observed=boundary['collection_succeeded'], capture_complete=False,
                diagnostic_reads=diagnostic_reads, reward_replay_verified=False, native_acceptance_status='NOT_RUN',
                boot_epoch=epoch, boundary=boundary, trusted_context=trusted,
                producer_tools_root=str(Path(TOOL_ROOT if producer_tools_root is None
                                             else producer_tools_root).resolve(strict=True)),
                checker_identity=dict(version=CHECKER_VERSION, tools_root=str(TOOL_ROOT),
                                      tools=tool_closure()))

BANKS={**strict.BANKS,'bounded_data':('CORESET_BOUNDED_DATA_EVIDENCE',8192)}
FOCUS_DIAGNOSTICS={**strict.FOCUS_DIAGNOSTICS,
    'replay_root':('REPLAY_ROOT_EVIDENCE',256),
    'replay_config':('REPLAY_CONFIG_EVIDENCE',256),
    'baseline_publication':('BASELINE_PUBLICATION_FIRST_CAUSE',3072),
    'preparation_progress':('REPLAY_PREPARATION_PROGRESS',6144)}


def _preparation_result(encoded):
    tag=encoded&255;error=encoded>>8
    require((tag in (1,2) and error==0) or (tag==3 and 1<=error<=20),
        'preparation progress result/error encoding')
    return tag,error


def _preparation_cursors(stage,before,end,after):
    require(all(0<=v<=512 and v%8==0 for v in (before,end,after)),
        'preparation progress cursor bound/alignment')
    valid=(before==end==after==0 if stage in (1,2,3) else
        before==after==512 and end==0 if stage==4 else
        before<512 and end==after==0 if stage==5 else
        before<512 and end==before+8 and after==0 if stage==6 else
        end==before+8 and after==end<512 if stage==7 else
        before==504 and end==after==512 if stage==8 else False)
    require(valid,'preparation progress original stage/cursor contradiction')


def _preparation_snapshot(row,total):
    if not any(row):return None
    ordinal,entry,packed,cursors=row[:4]
    require(0<ordinal<=total and packed>>30==0 and cursors>>30==0,
        'preparation progress snapshot ordinal/reserved bits')
    kind=packed&255;stage=(packed>>8)&255;tag=(packed>>16)&3;error=(packed>>18)&255
    flags=(packed>>26)&15
    before=cursors&1023;end=(cursors>>10)&1023;after=(cursors>>20)&1023
    _preparation_result(tag|(error<<8));_preparation_cursors(stage,before,end,after)
    require((kind,stage,tag)==(1,1,3) or (kind,stage,tag) in ((3,5,1),(4,6,1)),
        'preparation progress historical snapshot kind/stage/result')
    require(flags==(0 if kind==1 else (2|int(bool(flags&1))) if kind==3 else 14),
        'preparation progress explicit operand presence')
    result=dict(visit_ordinal=ordinal,service_entry_ns=entry,kind=kind,stage=stage,result_tag=tag,
        original_domain_error_code=error,cursor_before=before,scan_end=end,cursor_after=after,
        cursor_observed=bool(flags&2),scan_end_observed=bool(flags&4),blocker_present=bool(flags&8),
        raw_words=list(row),authorizes_replay=False)
    if kind==1:
        require(not any(row[4:]),'preparation auth snapshot unexpected operands')
    elif kind==3:
        require(row[4] in (0,1) and row[5]<=16 and (row[4] or row[5])
            and (row[4] or not any(row[6:]) and not flags&1),
            'preparation job/prepared reset presence')
        if row[4]:
            require(row[8]<4 and row[9] in (0,1) and row[15] in (0,1)
                and ((1<=row[10]<=16 and row[11] in ((1,2) if row[10] in (1,16) else (1,)))
                    if flags&1 else row[10]==row[11]==0),
                'preparation original job operands/family')
        result.update(job_present=bool(row[4]),prepared_count=row[5],job_first_family_present=bool(flags&1),
            job_controller=row[6],job_sequence=row[7],job_cpu=row[8],job_read_only=bool(row[9]),
            job_family=list(row[10:12]),job_target=list(row[12:14]),job_started_ns=row[14],
            job_completion_present=bool(row[15]))
    else:
        state=row[15];state_tag=(state>>16)&3;state_error=(state>>18)&255
        started=bool(state&(1<<26));observed=bool(state&(1<<27));predicate=bool(state&(1<<28))
        require(before<=row[4]-1<end<=512 and row[5] in (1,2,4) and state>>29==0 and (state&65535)<16
            and ((1<=state_error<=20) if state_tag==2 else state_error==0)
            and predicate==(row[5]==4) and (predicate or row[14]==0),
            'preparation original Desired blocker operands/presence')
        require((row[5]==1 and state_tag in (0,3))
            or (row[5]==2 and state_tag==1 and not observed)
            or (row[5]==4 and (state_tag==2 or state_tag==1 and observed)
                and row[11]>0 and row[12]<=row[14]<row[13]),
            'preparation original Desired blocking predicate contradiction')
        result.update(slot=row[4]-1,reason=row[5],apply_boot_epoch=row[6],controller=row[7],plan_sequence=row[8],
            target=list(row[9:11]),stamp_version=row[11],snapshot_ns=row[12],lease_until_ns=row[13],
            predicate_ns=row[14],predicate_present=predicate,action_index=state&65535,state_tag=state_tag,
            failed_domain_error_code=state_error,started=started,execution_observed=observed)
    return result


def decode_preparation_progress(raw):
    """Six scoped historical observations, never a readiness or authority proof.

    Existing service-entry operands have no reconstructed monotonic timeline.
    Only a record at the latest actual ordinal is bound to the latest scalar.
    """
    require(len(raw)==6144,'preparation progress bank width')
    slots=[];identities=set();preparation_keys=set();seen_empty=False
    names=('auth_error','other_error','job_prepared_reset','desired_reset','advance','already_ready','scan_complete')
    historical=('first_auth','last_auth','first_reset','last_reset','first_blocker','last_blocker')
    latest_kind={1:1,2:2,3:2,4:6,5:3,6:4,7:5,8:7}
    for index in range(6):
        part=raw[index*1024:(index+1)*1024];w=struct.unpack('<128Q',part)
        base=dict(slot=index,publication=w[0],raw_sha256=digest(part),raw_words=list(w),authorizes_replay=False)
        if not any(w):
            seen_empty=True;slots.append(dict(base,state='empty',observed=False));continue
        require(not seen_empty and w[0]>0,'preparation progress empty hole/unpublished payload')
        if w[0]%2:
            slots.append(dict(base,state='partial',observed=False));continue
        require(w[1:4]==(0x4359505250473031,1,128),'preparation progress magic/version/slot width')
        require(w[4]==8,'preparation progress provenance flags invalid: '+hex(w[4]))
        identity=w[5:15];key=identity[:2]
        require(w[5]>0 and w[6]>0 and 1<=w[7]<=MAX_ATTEMPTS and w[8]>0 and w[9]>0
            and w[10:13]==(1,2,1) and w[13] in (1,2) and w[14]>0
            and identity not in identities and key not in preparation_keys,
            'preparation progress duplicate/conflicting typed identity')
        identities.add(identity);preparation_keys.add(key)
        require(w[15]>0 and not w[16] and not w[31] and sum(w[17:24])==w[15]
            and w[24]<=512 and w[24]%8==0,'preparation progress counter/reserved/max cursor contradiction')
        tag,error=_preparation_result(w[27]);stage=w[26]
        require(stage in latest_kind and tag==(3 if stage in (1,2,3) else 2 if stage in (4,8) else 1)
            and w[16+latest_kind[stage]]>0,'preparation progress latest stage/result/count contradiction')
        _preparation_cursors(stage,*w[28:31])
        require(w[24]>=max(w[28],w[30]),'preparation progress maximum cursor loses observed progress')
        records={name:_preparation_snapshot(w[32+i*16:48+i*16],w[15]) for i,name in enumerate(historical)}
        counts=(w[17],w[19]+w[20],w[20]);types=((1,),(3,4),(4,))
        for pair,count,allowed in zip((historical[:2],historical[2:4],historical[4:6]),counts,types):
            first,last=(records[name] for name in pair)
            require(bool(first)==bool(last)==bool(count),'preparation progress count/first-last presence')
            if not count:continue
            a,b=first['visit_ordinal'],last['visit_ordinal']
            require(first['kind'] in allowed and last['kind'] in allowed and a<=b<=w[15] and b-a+1>=count
                and ((first['raw_words']==last['raw_words']) if count==1 else a<b),
                'preparation progress immutable first/last/count contradiction')
        by_ordinal={}
        for record in records.values():
            if record is None:continue
            require(w[24]>=max(record['cursor_before'],record['cursor_after']),
                'preparation progress maximum cursor loses historical observation')
            ordinal=record['visit_ordinal']
            require(ordinal not in by_ordinal or by_ordinal[ordinal]==record['raw_words'],
                'preparation progress conflicting observations at same visit')
            by_ordinal[ordinal]=record['raw_words']
            if ordinal==w[15]:
                require((record['kind'],record['stage'],record['result_tag'],record['original_domain_error_code'],
                    record['service_entry_ns'],record['cursor_before'],record['scan_end'],record['cursor_after'])
                    ==(latest_kind[stage],stage,tag,error,w[25],*w[28:31]),
                    'preparation progress latest snapshot/scalar time or operand mismatch')
        if records['first_blocker']:
            require(records['first_reset']['visit_ordinal']<=records['first_blocker']['visit_ordinal']
                and records['last_blocker']['visit_ordinal']<=records['last_reset']['visit_ordinal'],
                'preparation progress Desired/reset chronological ordinals')
            for prefix in ('first','last'):
                if records[prefix+'_reset']['kind']==4:
                    require(records[prefix+'_reset']['raw_words']==records[prefix+'_blocker']['raw_words'],
                        'preparation progress immutable Desired/reset first-last mismatch')
        required_last='last_auth' if stage==1 else 'last_reset' if stage in (5,6) else None
        if required_last:
            require(records[required_last]['visit_ordinal']==w[15],
                'preparation progress matching latest historical record missing')
        if stage==6:require(records['last_blocker']['visit_ordinal']==w[15],
            'preparation progress latest Desired blocker missing')
        slots.append(dict(base,state='published',observed=True,provenance_valid=True,
            boot_epoch=w[5],preparation_id=w[6],trial_id=w[7],owner=[w[8],w[9]],family=[w[10],w[11]],
            seed=w[12],trial_kind=w[13],preparation_started_ns=w[14],total_visits=w[15],
            counters=dict(zip(names,w[17:24])),maximum_observed_cursor=w[24],last_service_entry_ns=w[25],
            last_stage=stage,last_result_tag=tag,last_original_domain_error_code=error,
            last_cursor_before=w[28],last_scan_end=w[29],last_cursor_after=w[30],
            outer_gate_refusals_observed=False,**records))
    return dict(version=DIAGNOSTIC_VERSION,bank='preparation_progress',slots=slots,raw_sha256=digest(raw),
        outer_gate_refusals_observed=False,readiness_verified=False,authorizes_replay=False)


def focus_diagnostic_symbols(image):
    result={};ranges=[]
    for key,(name,width) in FOCUS_DIAGNOSTICS.items():
        location=symbol(image,name)
        require(location['size']==width and location['pa']%64==0
            and 0x40200000<=location['pa']<location['pa']+width<=0x44000000,'wrong data diagnostic symbol ABI: '+name)
        require(all(location['pa']+width<=start or end<=location['pa'] for start,end in ranges),'aliased data diagnostic symbols')
        ranges.append((location['pa'],location['pa']+width));result[key]=location
    return result


def decode_focus_diagnostic(key,raw):
    require(key in FOCUS_DIAGNOSTICS and len(raw)==FOCUS_DIAGNOSTICS[key][1],'wrong data diagnostic width/key')
    if key in strict.FOCUS_DIAGNOSTICS:return strict.decode_focus_diagnostic(key,raw)
    if key=='preparation_progress':return decode_preparation_progress(raw)
    if key=='baseline_publication':
        slots=[]
        for index in range(MAX_ATTEMPTS):
            part=raw[index*512:(index+1)*512];w=struct.unpack('<64Q',part)
            item=dict(trial_slot=index+1,raw_sha256=digest(part),raw_words=list(w),authorizes_replay=False)
            if not any(w):slots.append(dict(item,state='empty',observed=False));continue
            require(w[0] in (1,2),'baseline cause latch sequence')
            if w[0]==1:slots.append(dict(item,state='partial',observed=False));continue
            require(w[1:3]==(0x4359425043413136,1) and w[3]==index+1 and w[4]>0
                and w[5:7]==(0x43595355424d0001,1) and w[9]==2 and w[10]>0
                and w[32]<=6 and w[35]<4 and w[36]>0 and w[46]>0 and w[47]==0 and w[48]==1
                and w[51] in (0,1) and w[52] in (0,1,3)
                and ((w[49] in (2,6) and w[50] in (2,6)) if w[52]&2 else (w[49]==w[50]==w[51]==0))
                and not any(w[53:]),
                'invalid original per-trial failed baseline callback cause')
            slots.append(dict(item,state='published',observed=True,trial_id=w[3],root_token=w[4],
                submission_words=list(w[5:32]),service_read_reason=w[32],view_published_ns=w[33],
                originally_observed_ns=w[34],cpu=w[35],boot_epoch=w[36],first_sequence=w[37],first_taken_ns=w[38],
                ledger_generation=w[39],core_generation=w[40],plan_sequence=w[41],plan_sha256=part[336:368].hex(),
                original_domain_error_code=w[46],receipt_version=w[47],action_count=w[48],requested_mask=w[49],
                current_mask=w[50],core_pending=bool(w[51]),operand_presence_flags=w[52]))
        return dict(version=DIAGNOSTIC_VERSION,bank=key,slots=slots,authorizes_replay=False,raw_sha256=digest(raw))
    w=struct.unpack('<32Q',raw);base=dict(version=DIAGNOSTIC_VERSION,bank=key,raw_words=list(w),raw_sha256=digest(raw),authorizes_replay=False)
    if not any(w):return dict(base,state='empty',observed=False)
    require(w[0]>0,'unpublished data diagnostic payload')
    if w[0]%2:return dict(base,state='partial',observed=False)
    require(w[1]==(0x435952524f543133 if key=='replay_root' else 0x4359524346473133),'data Root/config diagnostic magic')
    if key=='replay_config':require(w[2]==1,'config diagnostic schema')
    return dict(base,state='published',observed=True)


def verify_focus_diagnostic_reads(rows,root,context):
    return strict._verify_required_diagnostic_reads(rows,root,context,{key:width for key,(_,width) in FOCUS_DIAGNOSTICS.items()})


def verify_failure_diagnostic_reads(rows,root,context):
    required={key:width for key,(_,width) in FOCUS_DIAGNOSTICS.items()}
    required.update({key:size for key,(_,size) in BANKS.items() if key!='config'})
    return strict._verify_required_diagnostic_reads(rows,root,context,required)


def fatal_evidence(replay,control,tasks=None):
    # Exclusion counters are ledger data only under profile2. Sticky global
    # optimization/resource/stability faults retain their original stop rule.
    strict.fatal_evidence(bytes(512),control)
    if len(control)>=4096:
        w=struct.unpack('<'+'Q'*(len(control)//8),control)
        if w[0]==0x435958444f4d3031:require(w[25]==w[28]==0,'native global resource/stability fault')
    if tasks is not None and len(tasks)==256:
        w=struct.unpack('<32Q',tasks)
        if w[0]==0x43595441534b0001:require(w[2]==w[3]==0,'native global task resource fault')
    if len(replay)==512:
        w=struct.unpack('<64Q',replay)
        if w[0]>0 and not w[0]%2 and w[1]==0x435952504c593133:
            require(w[2]!=18,'native bounded-data owner failed before closed ledger')


def data_terminal_candidate(raw):
    try:ledger=decode_data_ledger(raw)
    except (ValueError,struct.error):return None
    return {key:ledger[key] for key in ('status','phase','attempt_count','stored','exhausted','excluded','verified','archived','paid_turn_ticket','collection_succeeded','credited_samples','hard_stop')}


def released_pair_candidate(raw):
    if len(raw)!=512:return None
    w=struct.unpack('<64Q',raw)
    if w[0]>0 and not w[0]%2 and w[1]==0x435952504c593133 and w[2] in (25,26,27):
        return dict(publication=w[0],phase=w[2],verified=w[10],archived=w[17],paired=w[19])
    return None


def stopped_data_ready(probe):
    fatal_evidence(probe['replay'],probe['control'],probe['tasks'])
    try:
        ledger=decode_data_ledger(probe['bounded_data'])
        verify_replay_terminal(probe['replay'],ledger)
    except (ValueError,struct.error):return False
    return (len(probe['runtime'])==8192 and word(probe['runtime'],16)>0
        and not word(probe['runtime'],16)%2 and not word(probe['boot'],16)%2)


def verify_supplement(raw,ledger):
    require(len(raw)==4096 and digest(raw)==ledger['supplement_sha256'],'data supplement length/hash mismatch')
    bank=ledger['raw_bytes'];h=struct.unpack_from('<16Q',raw)
    expected=(DATA_MAGIC,2,2,ledger['attempt_count'],6,int(ledger['stored']),*ledger['selected_trials'],
        ledger['closed_attempt_count'],ledger['excluded'],ledger['verified'],ledger['archived'],
        ledger['paid_turn_ticket'],1,int(ledger['stored']),0)
    require(h==expected and raw[128:2816]==bank[32*8:368*8]
        and raw[2816:3872]==bank[368*8:500*8]
        and raw[3872:4064]==bank[500*8:524*8] and raw[4064:4096]==bank[524*8:528*8],
        'durable ledger rows/witness/selection/counters/ticket mismatch')


def rejection_rows(raw,attempt,context):
    facts=[]
    for index in range(word(raw,128)):
        row=raw[2048+6144*index:2048+6144*(index+1)]
        if word(row,0)!=128:continue
        size=word(row,312);plan=row[2048:2048+size]
        require(64<=size<=384 and row[296:304]==b'CYREJCT1' and word(row,304)==1
            and word(row,320)==word(row,328)==0 and word(row,424)==3
            and word(row,432)+1==attempt['original_domain_error_code']>0
            and word(row,80)==context['model_generation'] and row[88:120].hex()==context['model_sha256']
            and row[120:152].hex()==context['schema_hash'] and digest(plan)==row[48:80].hex()
            and struct.unpack_from('<3H',row,200)==(1,2,1)
            and (word(row,184),word(row,192))==(0x434f5245,1)
            and word(row,160)<=word(row,352)<=word(row,336)<=word(raw,120)
            and all(word(row,p)>0 for p in (272,280,288,152,168,176))
            and not any(row[2048+size:]),'changed/missing original sealed negative Plan/receipt/error')
        facts.append(dict(plan_id=[word(row,p) for p in (272,280,288)],plan_sha256=row[48:80].hex(),
            first_sequence=word(row,152),first_taken_ns=word(row,160),ledger_generation=word(row,168),
            core_generation=word(row,176),original_domain_error_code=word(row,432)+1,
            requested_mask=struct.unpack_from('<Q',plan,len(plan)-8)[0]))
    require(len({tuple(f['plan_id']) for f in facts})==len(facts),'reused sealed PlanID in attempt')
    return facts


def parse_attempt_journal(raw,attempt,kind,context):
    require(0<len(raw)<=MAX_FILE,'journal byte bound')
    if kind=='preparation':
        require(len(raw)>=1024 and raw[:15]==b'CYXIA_PREP_1.3\0' and not any(raw[15:32])
            and (word(raw,32),word(raw,40),word(raw,64))==(attempt['preparation_id'],attempt['boot_epoch'],attempt['trial_id'])
            and (word(raw,72),word(raw,80),word(raw,88),word(raw,96))==(1,2,1,int(attempt['kind']==1))
            and word(raw,104)==attempt['preparation_started_ns']
            and word(raw,104)<=word(raw,112)<=word(raw,120)
            and attempt['first_failure_ns']<=word(raw,112)
            and word(raw,128)==attempt['original_domain_error_code']>0
            and word(raw,136)<=word(raw,144)<=word(raw,120)
            and word(raw,200)<=768 and word(raw,208) in (0,1)
            and word(raw,456)<=16 and word(raw,464)==len(raw) and word(raw,472)==word(raw,1000)==0
            and len(raw)==1024+word(raw,200)*64+word(raw,208)*100*32,
            'preparation journal original identity/error/closure/length mismatch')
        require(raw[352:384].hex()==context['model_sha256'],'preparation frozen model mismatch')
        if word(raw,416):
            require(word(raw,416)==1 and word(raw,424)==attempt['root_token']
                and word(raw,432)==attempt['boot_epoch'],'preparation Root handoff mismatch')
        else:require(attempt['root_token']==0,'missing preparation Root provenance')
        return dict(kind=kind,trial_id=attempt['trial_id'],original_domain_error_verified=True,
            closed_ns=word(raw,120),negative_plans=[],raw_sha256=digest(raw),native_replay_authority_reconstructed=False)
    if kind=='late':
        require(len(raw)>=256 and raw[:15]==b'CYXIA_LATE_1.3\0' and word(raw,16)==1
            and word(raw,24)==256 and word(raw,32)==len(raw)
            and tuple(word(raw,p) for p in (40,48,56))==(attempt['boot_epoch'],attempt['trial_id'],attempt['generation'])
            and 0<word(raw,112)<=8192 and len(raw)==256+((word(raw,112)+255)//256)*256,
            'late packet journal RunKey/length mismatch')
        return dict(kind=kind,trial_id=attempt['trial_id'],closed_ns=word(raw,80),negative_plans=[],raw_sha256=digest(raw),
            original_domain_error_verified=False,native_replay_authority_reconstructed=False)
    require(kind=='regular' and len(raw)>=2048 and raw[:17]==b'CYXIA_REPLAY_1.3\0'
        and tuple(word(raw,p) for p in (32,40,48))==(attempt['boot_epoch'],attempt['trial_id'],attempt['generation'])
        and tuple(word(raw,p) for p in (56,64,72,80,88,152))==(1,2,0x434f5245,1,1,int(attempt['kind']==1))
        and word(raw,128)<=64 and word(raw,136)<=8192 and word(raw,144)==100
        and word(raw,624)==word(raw,744)==0 and word(raw,752)<=768
        and len(raw)==2048+word(raw,128)*6144+word(raw,136)*64+100*128+word(raw,752)*64,
        'regular journal original RunKey/family/count/length mismatch')
    if attempt['outcome']!='excluded':
        side=strict._side(raw,context)
        require(side['producer_verification_sha256']==attempt['verified_canonical_sha256'], 'successful journal canonical differs from ledger')
        return dict(kind=kind,trial_id=attempt['trial_id'],closed_ns=side['closing_ns'],negative_plans=[],
            raw_sha256=digest(raw),side=side,original_domain_error_verified=attempt['original_domain_error_code']==0,native_replay_authority_reconstructed=False)
    require(word(raw,168)==attempt['learning_error_code'] and word(raw,168)>0 and not any(raw[416:448]),
            'excluded journal verification error differs from attempt ledger')
    require(0<word(raw,96)<=word(raw,112)<word(raw,120),'excluded journal closing timeline')
    closing=raw[1792:2048]
    require(closing[:8] in (b'CYNOPUB1',b'CYCLOSE1'),'missing excluded closing/unpublished proof')
    if closing[:8]==b'CYNOPUB1':
        require((word(closing,8),word(closing,16))==(attempt['root_token'],attempt['boot_epoch'])
            and (word(closing,40),word(closing,48),word(closing,56),word(closing,64))==(1,2,0x434f5245,1)
            and word(closing,80)==word(raw,96) and word(closing,104)<=word(raw,120),'excluded unpublished close identity mismatch')
    if closing[:8]==b'CYCLOSE1':strict._closing(closing,attempt['boot_epoch'],word(raw,120))
    negatives=rejection_rows(raw,attempt,context)
    require(attempt['original_domain_error_code']!=0 or not negatives,'zero Domain error conceals actual rejected Plan')
    return dict(kind=kind,trial_id=attempt['trial_id'],closed_ns=word(raw,120),negative_plans=negatives,
        raw_sha256=digest(raw),original_domain_error_verified=bool(negatives),native_replay_authority_reconstructed=False)


def read_committed_data(disk,context,ledger):
    from check_v13_disk import committed_volume,BLOCK
    from check_v13_filesystem import inspect_committed
    require(sha(disk)==context['disk_sha256'],'data disk custody mismatch')
    files={};total=0
    with committed_volume(Path(disk)) as (current,metadata):
        volume=inspect_committed(current,metadata)
        require(volume['uuid']==context['disk_uuid'] and volume['boot_epoch']==context['boot_epoch'], 'data volume identity mismatch')
        for name in sorted(set(volume['files'])|set(volume['directories'])):
            if not any(part.startswith(('lr-','lp-','lf-','ld-','ls-')) for part in name.split('/')):continue
            require(name in volume['files'] and re.fullmatch(r'/(?:l[rpf]-[0-9a-f]{16}-[0-9a-f]{4}|ld-[0-9a-f]{16})',name), 'unknown/malformed data journal path')
            node=volume['files'][name];require(0<node['size']<=MAX_FILE and node['durable_write_seq']>0,'journal not bounded/durable')
            total+=node['size'];require(total<=MAX_ATTEMPTS*2*MAX_FILE+4096,'expanded data journal bound')
            raw=bytearray()
            for _,start,blocks in node['extents']:
                require(blocks<=MAX_FILE//BLOCK,'journal extent bound')
                for block in range(start,start+blocks):raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            require(len(raw)==node['size'] and digest(raw)==node['sha256'],'committed data journal hash mismatch')
            key=(node['inode'],node['generation']);require(key not in files,'aliased data journal object')
            files[key]=dict(path=name,node=node,raw=bytes(raw),used=[])
    supplement_key=tuple(ledger['supplement_object']);require(supplement_key in files,'missing durable data supplement object')
    supplement=files.pop(supplement_key)
    require(supplement['path']=='/ld-%016x'%context['boot_epoch'],'wrong supplement path/boot')
    verify_supplement(supplement['raw'],ledger)
    journals=[];selected={};plan_ids=set()
    for attempt in ledger['attempts']:
        require(attempt['boot_epoch']==context['boot_epoch'],'attempt belongs to another boot')
        for kind in ('regular','preparation','late'):
            ref=attempt[kind]
            if ref is None:continue
            key=(ref['object_id'],ref['object_generation']);require(key in files,'missing excluded/preparation/late journal object')
            file=files[key];raw=file['raw'];start=ref['offset'];end=start+ref['bytes']
            prefix={'regular':'lr','preparation':'lp','late':'lf'}[kind]
            require(re.fullmatch('/'+prefix+'-%016x-[0-9a-f]{4}'%context['boot_epoch'],file['path']) is not None
                and end<=len(raw) and digest(raw[start:end])==ref['sha256'],'journal object/path/range/hash mismatch')
            parsed=parse_attempt_journal(raw[start:end],attempt,kind,context)
            require(parsed['closed_ns']<=ledger['sampled_ns'],'journal closure follows terminal boundary')
            for negative in parsed['negative_plans']:
                identity=tuple(negative['plan_id']);require(identity not in plan_ids,'sealed PlanID reused across attempts');plan_ids.add(identity)
            file['used'].append((start,end));journals.append(parsed)
            if attempt['outcome'].startswith('selected_'):selected[attempt['outcome']]=parsed['side']
    for file in files.values():
        cursor=0
        for start,end in sorted(file['used']):require(start==cursor,'orphan/gapped/reused excluded journal range');cursor=end
        require(cursor==len(file['raw']),'unreferenced failed/preparation/late journal bytes')
    require(sha(disk)==context['disk_sha256'],'disk changed during data extraction')
    return journals,selected


def focus_diagnostic_files(root):
    facts={}
    for key,(_,width) in FOCUS_DIAGNOSTICS.items():
        path=Path(root)/('diagnostic-'+key+'.bin')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size==width,'missing data diagnostic raw bank: '+key)
        facts[key]=decode_focus_diagnostic(key,path.read_bytes())
    return facts


def baseline_provenance(ledger,journals,diagnostics):
    slots=diagnostics['baseline_publication']['slots'];matched=0
    for attempt in ledger['attempts']:
        negative=[n for journal in journals if journal['trial_id']==attempt['trial_id'] for n in journal['negative_plans']]
        slot=slots[attempt['trial_id']-1]
        if slot['state']=='published':
            require(slot['root_token']==attempt['root_token'] and slot['boot_epoch']==attempt['boot_epoch']
                and slot['original_domain_error_code']==attempt['original_domain_error_code'], 'baseline cause belongs to another attempt/error')
            matching=[n for n in negative if n['plan_id'][0]==slot['boot_epoch'] and n['plan_id'][2]==slot['plan_sequence']
                and n['plan_sha256']==slot['plan_sha256'] and n['first_sequence']==slot['first_sequence']
                and n['first_taken_ns']==slot['first_taken_ns'] and n['ledger_generation']==slot['ledger_generation']
                and n['core_generation']==slot['core_generation']
                and (not slot['operand_presence_flags']&2 or n['requested_mask']==slot['requested_mask'])
                and n['original_domain_error_code']==slot['original_domain_error_code']]
            require(len(matching)==1,'baseline original callback is not bound to sealed negative Plan/receipt')
            matched+=1
        elif negative and attempt['kind']==2:
            require(False,'failed baseline Registry lacks actual per-trial callback cause')
    for slot in slots:
        require(not slot.get('observed') or slot['trial_id']<=ledger['attempt_count'],'post-bound baseline resources')
    return matched


def verify_data_capture(directory,*,source_root,build_manifest,formatter,qemu_binary,qemu_source,producer_tools_root=None):
    root=Path(directory);require(not root.is_symlink(),'linked data capture root');root=root.resolve(strict=True)
    before=bounded_inventory(root)
    paths=dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,qemu_binary=qemu_binary,
        qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    checked=_verify_data_capture_custody(root,terminal_contract='bounded-data-terminal',**paths)
    context=_schema_context(checked['trusted_context']);ledger=decode_data_ledger((root/'bounded_data.bin').read_bytes())
    diagnostics=focus_diagnostic_files(root);journals,selected=read_committed_data(root/'disk.raw',context,ledger)
    negative_count=baseline_provenance(ledger,journals,diagnostics)
    numeric=None;image=None;runtime=None
    collected=ledger['collection_succeeded']
    if collected:
        require(set(selected)=={'selected_baseline','selected_candidate'},'actual final pair is missing')
        b,c=selected['selected_baseline'],selected['selected_candidate'];model=(root/'model.bin').read_bytes()
        numeric=numeric_core_pair(c['raw_bytes'],b['raw_bytes'],model)
        match_sample_witness(ledger['witness'],numeric,b,c)
        image=core_image(b,model)
        for side in (b,c):
            raw=side['raw_bytes'];masks=[strict.core_action(raw[2048+i*6144+512:2048+i*6144+536],0)
                for i in range(word(raw,128)) if word(raw,2048+i*6144)==40]
            if side is b:require(masks==[image['control']],'selected baseline changed actual original CoreImage')
            require(struct.unpack_from('<Q',raw,1792+34)[0]==image['control'],'selected close did not restore original actual CoreImage')
        runtime=actual_candidate_runtime((root/'control.bin').read_bytes(),(root/'runtime.bin').read_bytes(),c,context)
        paid_bank_facts((root/'tasks.bin').read_bytes(),(root/'credit.bin').read_bytes(),(root/'settlement.bin').read_bytes())
    common={k:v for k,v in checked['trusted_context'].items() if k not in ('boot_epoch','input_sha256','config_sha256','nonce','disk_uuid','disk_sha256','released_boundary','stopped_banks')}
    require(trusted_context(**paths)==common and bounded_inventory(root)==before,'data source/tool/capture changed during replay')
    public_ledger={key:value for key,value in ledger.items() if key not in ('raw_bytes','witness_raw')}
    public_journals=[{key:value for key,value in journal.items() if key!='side'} for journal in journals]
    return dict(version=VERSION,status=ledger['status'],profile='coreset-data-one-pair',profile_id=2,
        data_collection_verified=collected,closed_bounded_collection_verified=True,
        capture_complete=collected,released_pair_observed=collected,samples=int(collected),
        retained_stored_sample_observed=ledger['stored'] and not collected,
        ledger=public_ledger,journals=public_journals,diagnostic_facts=diagnostics,baseline_rejections_bound=negative_count,
        original_core_image=image,numeric=numeric,native_runtime=runtime,
        protected_sample_export_verified=collected,reward_numeric_verified=collected,
        trial_canonical_matches_native=collected,model_scores_verified=collected,
        native_acceptance_inferred_from_trusted_producer=collected,
        native_exclusion_authority_reconstructed=False,source_event_hash_recomputed=False,event_hash_recomputed=False,
        accepted_training_sample_verified=False,source_custody_replay_verified=False,native_label_imported=False,
        model_trained=False,native_acceptance_status='NOT_RUN',ordinary_demand_verified=False,
        minimum_training_samples=144,minimum_validation_samples=72,family_count_required=18,
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},raw_inventory=before,
        checker_identity=dict(version=CHECKER_VERSION,tools=tool_closure()))


def verify_replay_terminal(raw,ledger):
    """Source-defined joint terminal facts; neither bank alone proves completion."""
    require(len(raw)==512,'terminal replay bank width')
    w=struct.unpack('<64Q',raw)
    require(w[0]>0 and not w[0]%2 and w[1]==0x435952504c593133
        and w[2]==ledger['phase'] and w[3:6]==(1,2,0)
        and (w[10],w[11],w[17],w[19],w[20])==(
            ledger['verified'],ledger['excluded'],ledger['archived'],int(ledger['stored']),0)
        and all(w[index]==0 for index in (9,12,13,14,15,16,21,63))
        and w[18]==1 and list(w[24:42])==[0,int(ledger['stored'])]+[0]*16
        and not any(w[42:60]),'replay/data terminal phase/counters/paired/pending/closure contradiction')
    return True


def verify_diagnostic_capture(directory, *, source_root, build_manifest, formatter, qemu_binary,qemu_source,
                              producer_tools_root=None):
    """Verify custody of an expected FAIL; never infer a pair/sample acceptance."""
    trusted=dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    checked=_verify_data_capture_custody(directory,terminal_contract='bounded-data-interrupted',**trusted)
    root=Path(directory).resolve(strict=True);path=root/'summary.json'
    require(path.is_file() and path.stat().st_size<=128*1024**2,'missing/bounded original failure summary')
    summary=json.loads(path.read_text())
    require(summary.get('version')==VERSION and summary.get('status')=='FAIL'
        and summary.get('capture_complete') is False and summary.get('released_pair_observed') is False
        and type(summary.get('error')) is str and bool(summary['error']), 'missing original capture FAIL')
    inventory=checked['raw_inventory']
    require(type(summary.get('artifacts')) is dict
        and summary['artifacts']=={name:digest for name,digest in inventory.items() if name!='summary.json'},
        'original failure inventory bytes/membership mismatch')
    facts={}; parser_errors={}
    for key in FOCUS_DIAGNOSTICS:
        raw=(root/('diagnostic-'+key+'.bin')).read_bytes()
        try:
            facts[key]=decode_focus_diagnostic(key,raw)
        except (ValueError,struct.error) as error:
            parser_errors[key]=type(error).__name__+': '+str(error)
            facts[key]=dict(state='invalid',observed=False,authorizes_replay=False,raw_sha256=digest(raw))
    require(trusted_context(**trusted)==checked['trusted_context'],'trusted closure changed during failure verification')
    require(bounded_inventory(root)==inventory,'failure capture changed during verification')
    return dict(version=VERSION,status='FAIL',original_failure=summary['error'],
        diagnostic_custody_verified=True,base_custody_verified=True,process_cleanup_verified=True,
        collection_status='INTERRUPTED',data_collection_verified=False,closed_bounded_collection_verified=False,
        samples=0,unresolved_obligations_may_remain=True,
        capture_complete=False,released_pair_observed=False,reward_replay_verified=False,
        reward_numeric_verified=False,trial_canonical_matches_native=False,
        protected_sample_export_verified=False,native_acceptance_inferred_from_trusted_producer=False,
        accepted_training_sample_verified=False,source_event_hash_recomputed=False,source_custody_replay_verified=False,
        native_label_imported=False,model_trained=False,native_acceptance_status='NOT_RUN',
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},
        diagnostic_contract=DIAGNOSTIC_VERSION,diagnostic_facts=facts,diagnostic_parser_errors=parser_errors,
        diagnostic_reads=checked['diagnostic_reads'],boot_epoch=checked['boot_epoch'],raw_inventory=inventory,
        checker_identity=dict(version=CHECKER_VERSION,tools=tool_closure()),authorizes_replay=False,
        bounded_data_snapshot=dict(raw_sha256=sha(root/'diagnostic-bounded_data.bin'),
            raw_words=list(struct.unpack('<1024Q',(root/'diagnostic-bounded_data.bin').read_bytes())),
            authorizes_replay=False))
