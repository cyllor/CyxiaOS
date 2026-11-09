"""Typed CoreSetOnePair capture custody. No host acceptance authority."""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import struct

from build_unified import code_source_map
from check_elf import inspect_elf, symbol, boot_profile
from run_v13_a02 import config_write_packet
from transport import FrameDecoder
from verify_unified import attest_qemu
from verify_v13_boot_recovery import CONFIG_MAGIC, require, verify_samples
from verify_v13_model import loaded_bytes

VERSION = 'v16-a03-coreset-one-pair-progress-v1'
CHECKER_VERSION = 'v16-a03-focus-progress-checker-v1'
TOOL_ROOT = Path(__file__).resolve().parents[1]
BANKS = {'boot': ('A01_BOOT_EVIDENCE', 512), 'config': ('A01_BOOT_CONFIG', 512),
         'replay': ('REPLAY_V13_EVIDENCE', 512), 'control': ('DOMAIN_CONTROL_EVIDENCE', (512+64*640)*8),
         'runtime': ('RUNTIME_V13_EVIDENCE', 8192), 'unified': ('UNIFIED_EVIDENCE', 4096),
         'collection': ('LEARNING_COLLECTION_V16_EVIDENCE', 512),
         'tasks': ('DOMAIN_TASK_EVIDENCE',256), 'credit': ('CONTROL_CREDIT_EVIDENCE',512),
         'settlement': ('CONTROL_SETTLEMENT_EVIDENCE',512)}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


def released_pair_candidate(raw_replay: bytes) -> dict | None:
    if len(raw_replay) != 512: return None
    w = struct.unpack('<64Q', raw_replay)
    if (not w[0] or w[0] % 2 or w[1] != 0x435952504c593133 or w[2] != 25
        or (w[3], w[4], w[5], w[10], w[17], w[19]) != (1, 2, 0, 2, 2, 1)
        or any(w[i] for i in (9,11,12,13,14,15,16,20,21,63))): return None
    return dict(publication=w[0], phase=w[2], verified=w[10], archived=w[17], paired=w[19])


def fatal_evidence(replay, control):
    if len(replay) == 512:
        w = struct.unpack('<64Q', replay)
        if w[0] > 0 and not w[0] % 2 and w[1] == 0x435952504c593133:
            require(not any(w[i] for i in (11, 12, 21)), 'native replay error/exclusion')
    if len(control) >= 192 * 8:
        w = struct.unpack('<' + str(len(control) // 8) + 'Q', control)
        require(not (w[160] == 0x43594f5053540001 and w[161] == 1
                     and w[162] > 0 and w[191] > 0 and w[191] % 2 == 0),
                'native optimization-stop observed')


def tool_closure(tool_root=TOOL_ROOT):
    """Static transitive local imports, including function-local imports."""
    root = Path(tool_root).resolve(strict=True)
    pending = ['run_v16_a03_focus', 'v16_a03_focus', 'verify_v16_a03_focus']
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
    manifest = json.loads(build.read_text())
    require(manifest.get('contract') == 'v16-learning-collection-build-v1'
            and manifest.get('collection_profile') == 'coreset-one-pair'
            and type(manifest.get('profile_id')) is int and manifest['profile_id'] == 1
            and manifest.get('status') == 'BUILT_NOT_RUN', 'wrong explicit collection build')
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
            == (COLLECTION_MAGIC, 1, 1, 1024, 96), 'ELF collection identity mismatch')
    require(manifest['elf_layouts']['a'] == dict(symbol='LEARNING_COLLECTION_V16_LAYOUT',
        address=layout['va'],words=[COLLECTION_MAGIC,1,1,1024,96],
        sha256=hashlib.sha256(struct.pack('<5Q',COLLECTION_MAGIC,1,1,1024,96)).hexdigest()),
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


def launch_argv(qemu, output, qpath, gpath, port):
    return [str(qemu), '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
            '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
            '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
            '-drive', f'if=none,id=disk0,format=raw,file={output / "disk.raw"},cache=writeback',
            '-device', 'virtio-blk-device,drive=disk0',
            '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
            '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
            '-object', 'rng-random,id=rng0,filename=/dev/urandom', '-device', 'virtio-rng-device,rng=rng0',
            '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
            '-qmp', f'unix:{qpath},server=on,wait=off', '-gdb', f'unix:{gpath},server=on,wait=off',
            '-kernel', str(output / 'node-a.elf'), '-no-reboot']


def _verify_capture_custody(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                            producer_tools_root=None, terminal_contract):
    """Replay fixed local code against explicit caller context, never archived commands.

    This verifier reads recorded commands as evidence only. It never executes
    archived code, subprocess arguments, checker names, or summary booleans.
    An optional caller-selected producer root is read/AST-hashed only; current
    fixed checker functions execute, with their separate identity in the result.
    """
    from boot_reboot_contract import verify_origin, DISK_BYTES
    require(terminal_contract in ('released-collection','pre-collection-diagnostic-failure'), 'unknown terminal custody contract')
    failure_contract = terminal_contract == 'pre-collection-diagnostic-failure'
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
        return stopped_collection_ready(probe)
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
            elif target.name in {'pending-replay.bin', 'pending-control.bin', 'pending-collection.bin'}:
                require(running and not paused and not captures, 'live probe after stop')
                key = target.stem.removeprefix('pending-')
            elif re.fullmatch(r'probe-[0-9]{2}-(boot|replay|control|runtime|unified|collection|tasks|credit|settlement)\.bin', target.name):
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
        collection=(root/'diagnostic-collection.bin').read_bytes()
        rw=struct.unpack('<64Q',replay);cw=struct.unpack('<64Q',collection)
        require(rw[0]>0 and not rw[0]%2 and rw[1]==0x435952504c593133
            and cw[0]>0 and not cw[0]%2 and cw[1:4]==(COLLECTION_MAGIC,1,1)
            and cw[5]==0 and released_pair_candidate(replay) is None
            and collection_boundary(collection) is None, 'diagnostic failure was already a released collection')
        verify_samples(boot,boot,control[:4096],runtime,unified,config)
        require(bounded_inventory(root)==initial_inventory,'capture changed during base custody replay')
        return dict(version=VERSION,terminal_contract=terminal_contract,trusted_context=context,
            boot_epoch=struct.unpack('<64Q',boot)[6],diagnostic_reads=diagnostic_reads,
            raw_inventory=initial_inventory,process_cleanup_verified=True,base_custody_verified=True)
    boot, replay, control, runtime, unified = ((root / (key + '.bin')).read_bytes()
                                             for key in ('boot', 'replay', 'control', 'runtime', 'unified'))
    boundary = released_pair_candidate(replay)
    require(boundary is not None and collection_boundary((root/'collection.bin').read_bytes()) is not None, 'stopped CoreSet pair is not released')
    fatal_evidence(replay, control)
    verify_samples(boot, boot, control[:4096], runtime, unified, config)
    epoch = struct.unpack('<64Q', boot)[6]
    trusted = dict(context, boot_epoch=epoch, input_sha256=sha(root / 'input.json'),
                   config_sha256=sha(root / 'config.bin'), nonce=inputs['nonce'], disk_uuid=inputs['disk_uuid'],
                   disk_sha256=disk['sha256'], released_boundary=boundary,
                   stopped_banks={key: sha(root / (key + '.bin')) for key in captures})
    return dict(version=VERSION, released_pair_observed=True, capture_complete=False,
                diagnostic_reads=diagnostic_reads, reward_replay_verified=False, native_acceptance_status='NOT_RUN',
                boot_epoch=epoch, boundary=boundary, trusted_context=trusted,
                producer_tools_root=str(Path(TOOL_ROOT if producer_tools_root is None
                                             else producer_tools_root).resolve(strict=True)),
                checker_identity=dict(version=CHECKER_VERSION, tools_root=str(TOOL_ROOT),
                                      tools=tool_closure()))

# Explicit closed CoreSetOnePair ABI, independent of the old (1,1) admission.
COLLECTION_MAGIC = 0x43594c434f4c3136
# Frozen FAMILIES order: CoreSet index1; MIN_TRAIN_PER_FAMILY remains8.
CORESET_FIRST_TRAINING_SLOT = 1 * 8
MAX_FILE = 8 * 1024**2


def bounded_inventory(directory):
    root = Path(directory)
    require(not root.is_symlink() and root.is_dir(), 'linked/missing evidence root')
    files = {}; pending = [(root, 0)]; entries = 0; total = 0; inodes = set()
    while pending:
        parent, depth = pending.pop()
        require(depth <= 24, 'evidence tree depth bound')
        for path in parent.iterdir():
            entries += 1
            require(entries <= 12000 and not path.is_symlink(), 'evidence tree/link bound')
            if path.is_dir(): pending.append((path, depth+1)); continue
            require(path.is_file(), 'nonregular evidence artifact')
            stat = path.stat(); identity = (stat.st_dev, stat.st_ino)
            require(identity not in inodes and stat.st_nlink == 1, 'aliased evidence artifact')
            inodes.add(identity)
            limit = 512 * 1024**2 if path.name == 'disk.raw' else 128 * 1024**2
            require(stat.st_size <= limit, 'evidence artifact byte bound')
            total += stat.st_size
            require(total <= 1024**3, 'expanded evidence byte bound')
            files[path.relative_to(root).as_posix()] = sha(path)
    return files


def archive_ref(raw):
    require(len(raw) == 96, 'archive ref width')
    boot, trial, generation, obj, objgen, offset, length = struct.unpack_from('<7Q',raw)
    require(all((boot, trial, generation, obj, objgen, length)) and length <= MAX_FILE
            and offset + length <= MAX_FILE and any(raw[56:88]) and not any(raw[88:]),
            'invalid archive ref identity/range/hash')
    return dict(boot_epoch=boot,trial_id=trial,generation=generation,object_id=obj,
                object_generation=objgen,offset=offset,bytes=length,sha256=raw[56:88].hex())


def collection_boundary(raw):
    if len(raw) != 512: return None
    w=struct.unpack('<64Q',raw)
    if (not w[0] or w[0]%2 or w[1:16] != (COLLECTION_MAGIC,1,1,25,1,1,2,0,2,2,1,0,1,1,1)
            or not w[16] or not w[17] or w[18] != 2048 or not any(raw[152:184])
            or not w[47] or not w[48] or w[49]!=1 or any(w[50:])): return None
    try: refs=[archive_ref(raw[184:280]),archive_ref(raw[280:376])]
    except ValueError: return None
    if refs[0]['boot_epoch'] != refs[1]['boot_epoch'] or refs[0]['trial_id'] == refs[1]['trial_id']: return None
    return dict(publication=w[0],profile='coreset-one-pair',phase=25,family=[1,2],group=0,
                verified=2,archived=2,paired=1,owner_clear=True,work_quiescent=True,
                witness_durable=True,final_paid_turn_ticket=w[48],final_paid_turn_settled=True,witness_object=[w[16],w[17]],witness_bytes=2048,
                witness_sha256=raw[152:184].hex(),references=refs,sampled_ns=w[47])


def core_action(slot,index):
    require(len(slot)==24, 'CoreSet slot width')
    domain,kind,length,reserved,candidate,mask=struct.unpack_from('<5HQ',slot)
    require((domain,kind,length,reserved,candidate)==(1,2,10,0,index)
            and mask in (2,6) and not any(slot[18:]), 'invalid explicit CoreSet action')
    return mask


def sample_witness(raw):
    require(len(raw)==1024 and raw[:16]==b'CYXIA_SAMPLE_16\0' and not any(raw[16:32])
            and not any(raw[816:]), 'protected sample witness magic/padding/width')
    get=lambda at: struct.unpack_from('<Q',raw,at)[0]
    require(get(32)>0 and get(40)>0 and get(32)!=get(40)
            and (get(112),get(120),get(128),get(360),get(368))==(1,2,1,0,CORESET_FIRST_TRAINING_SLOT),
            'protected witness family/group/split/slot')
    return dict(slot=get(368),baseline_id=get(32),candidate_id=get(40),baseline_canonical=raw[48:80].hex(),
        candidate_canonical=raw[80:112].hex(),workload=raw[136:168].hex(),image=raw[168:200].hex(),
        schemas=[(get(200+40*i),raw[208+40*i:240+40*i].hex()) for i in range(4)],
        input64=list(struct.unpack_from('<64h',raw,376)),
        candidate_performance=list(struct.unpack_from('<8Q',raw,504)),
        baseline_performance=list(struct.unpack_from('<8Q',raw,568)),
        candidate_cpu=list(struct.unpack_from('<7Q',raw,632)),
        baseline_cpu=list(struct.unpack_from('<7Q',raw,688)),
        reward_bits=list(struct.unpack_from('<5Q',raw,744)),evidence_hash=raw[784:816].hex())

from v16_learning_archive import SCHEMAS, EMPTY_SHARED, digest, word, words, _schema_context
OWNER = 0x5245504c4159

def coreset_workload_hash():
    h=hashlib.sha256(b'CYXIA_ORDINARY_REPLAY_PAYLOADS_1.3\0'+struct.pack('<HHQ',1,2,1))
    for i in range(100):
        relative=i//10*1000000000+i%10*1000
        h.update(words(i+1,relative,5000000000))
        h.update(hashlib.sha256(b'CYXIA_CORESET_CACP_WORK_1.3\0'+words(1,i+1,relative,5000000000)
            +b'actual-protected-candidates;isolated-full-mlp;root-checked-no-background-publication\0').digest())
    return h.hexdigest()

def _record(row, header, context):
    flags = word(row, 0)
    require(flags in (40, 31, 64), 'unsupported history flags')
    target = tuple(word(row, x) for x in (184, 192))
    require(target == (0x434f5245, 1) and all(word(row, x) > 0 for x in (8, 152, 160, 168, 176)),
            'history snapshot/target mismatch')
    count, selected = struct.unpack_from('<HH', row, 204)
    require(1 <= count <= 2 and selected < count, 'candidate alternatives bound')
    weights = [core_action(row[512 + i * 24:536 + i * 24], i) for i in range(count)]
    require(not any(row[512 + count * 24:1280]), 'unused history action slots')
    if flags == 40:
        require(header['side'] == 'Baseline' and count == 1 and selected == 0
                and row[200:204] == bytes(4) and not any(row[16:152])
                and word(row, 344) == header['boot_epoch'] and word(row, 440) == 1,
                'baseline metadata mismatch')
        _execution(row, header)
        return dict(kind='Baseline', sha256=digest(row), model_binding='trusted capture context')
    require(header['side'] == 'Candidate' and row[200:204] == b'\x01\0\x02\0'
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
            and w[8:12] == (1, 2, 0x434f5245, 1) and w[13:16] == (1, header['boot_epoch'], count)
            and inp[128:160] == row[88:120] and inp[160:192] == row[16:48]
            and w[40] == 15 and w[31] <= 1, 'input identity/features mismatch')
    canonical = bytearray(b'CYXIA_CANDIDATES_V1.3\0')
    canonical += words(*(word(row, i) for i in (152, 160, 168, 176, 184, 192, 80)), count)
    canonical += row[88:152]
    for i, weight in enumerate(weights):
        at = 64 + 10 * i
        payload = inp[(at + 1) * 8:(at + 3) * 8]
        require(w[at] == 10 and payload[:10] == struct.pack('<HQ', i, weight)
                and not any(payload[10:]) and w[at + 7] <= 15 and w[at + 8] == 1 and w[at + 9] == weight.bit_count()*1000,
                'candidate input action/target mismatch')
        canonical += struct.pack('<4HQ', 1, 2, 10, i, weight) + words(*w[24:36]) + bytes([w[40]])
        for j in range(4):
            present = (w[at + 7] >> j) & 1
            value = w[at + 3 + j]
            require((present or value == 0) and (j != 3 or value <= 1), 'illegal target features')
            canonical += bytes([present]) + words(value)
        canonical += bytes([1]) + words(w[at+9])
    require(digest(canonical) == row[16:48].hex(), 'CandidateSet integrity mismatch')
    prior = inp[405 * 8:407 * 8]
    require(w[404] == 10 and prior[:2] == bytes(2) and not any(prior[10:])
            and struct.unpack_from('<Q', prior, 2)[0] in (2,6), 'invalid prior action')
    if flags == 64:
        require(selected == 0 and word(row, 8) == word(row, 152)
                and not any(row[208:512]) and not any(row[1280:2048])
                and all(w[i] == 0 for i in (3, 5, 12, 36, 37, 38, 39)), 'probe has publication fields')
    else:
        apply = tuple(word(row, i) for i in range(272, 320, 8))
        require(apply[0] == header['boot_epoch'] and apply[1] == w[3] > 0 and apply[2] > 0
                and apply[3:] == (0, 0x434f5245, 1) and row[1280:1328] == row[272:320]
                and not any(row[1328:2048]) and word(row, 440) == 1 and word(row, 480) == 0
                and row[448:480] == EMPTY_SHARED and word(row, 496) in (0, 1)
                and not any(row[504:512]), 'unsupported publication/shared action')
        _execution(row, header)
    return dict(kind='Probe' if flags == 64 else 'Candidate', sha256=digest(row),
                candidate_set_sha256=row[16:48].hex(), input_sha256=row[48:80].hex(),
                candidate_set_integrity_verified=True)


def _execution(row, header):
    issued, accepted, started, finished = (word(row, i) for i in (352, 360, 400, 416))
    require(0 < issued <= accepted <= started <= finished <= header['closing_ns']
            and finished <= word(row, 384) and word(row, 392) > 0
            and word(row, 424) == 1 and word(row, 432) == 0, 'nonterminal/invalid execution')


def _side(raw, context):
    require(len(raw) >= 2048, 'truncated archive header')
    h = raw[:2048]
    require(h[:17] == b'CYXIA_REPLAY_1.3\0' and not any(h[17:32])
            and not any(h[232:256]) and not any(h[1280:1792]), 'unsupported archive header')
    boot, trial, generation, domain, kind, target, target_gen, seed, first, warm, observation, closing = struct.unpack_from('<12Q', h, 32)
    records, cpu, requests, candidate = struct.unpack_from('<4Q', h, 128)
    require(boot == context['boot_epoch'] and trial > 0 and generation > 0 and seed == 1
            and (domain, kind, target, target_gen) == (1, 2, 0x434f5245, 1)
            and candidate in (0, 1) and 0 < first == observation < closing
            and warm == observation - 1000000000
            and closing >= observation + 10000000000, 'unsupported archive run identity/timing')
    require(1 <= records <= 64 and cpu <= 8192 and requests == 100
            and all(word(h, i) == 0 for i in (160, 168, 192, 224, 608, 624, 744))
            and word(h, 632) == 2048, 'unsupported archive counts/peer/prewarm/exclusion')
    prewarm = word(h,752)
    require(prewarm <= 768, "prewarm row bound")
    length = 2048 + records * 6144 + cpu * 64 + requests * 128 + prewarm * 64
    require(length <= MAX_FILE and length <= len(raw), 'truncated/unbounded archive side')
    require(tuple(h[448 + i * 32:480 + i * 32].hex() for i in range(4)) == tuple(context['schema_hashes'])
            and struct.unpack_from('<4Q', h, 576) == (13,) * 4
            and h[640:672].hex() == context['node_id'], 'archive schema/node mismatch')
    require(h[256:288].hex() == coreset_workload_hash()
            and all(any(h[i:i + 32]) for i in (288, 320, 352, 384, 416)), 'archive group/hash mismatch')
    count = word(h, 616)
    require(0 < count <= 16 and not any(h[768 + count * 32:1280])
            and word(h, 728) == 100 and word(h, 736) == count, 'archive source closure mismatch')
    sources = [struct.unpack_from('<4Q', h, 768 + i * 32) for i in range(count)]
    require(sources == [(0x434f5245, 1, 0, 7), (0x434f5245, 1, 1, 15), (OWNER, 1, 2, 1),
                        (0x5245504c434f, 1, 2, 6)], 'unsupported CoreSet source manifest')
    coverage = struct.unpack_from('<7Q', h, 672)
    require(coverage == (first, observation, observation + 10000000000, closing, 3, 3, 1),
            'invalid local coverage')
    _closing(h[1792:], boot, closing)
    result = dict(boot_epoch=boot, trial_id=trial, capture_generation=generation,
                  family=[1, 2], target=[0x434f5245, 1], seed=seed, side='Candidate' if candidate else 'Baseline',
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
    _prewarm(raw[at+requests*128:length], h)
    require(digest(canonical) == h[352:384].hex(), 'frozen scope integrity mismatch')
    result.update(relative_arrivals=arrivals, scope_hash_recomputed=True,
                  sha256=digest(raw[:length]), raw_bytes=bytes(raw[:length]))
    return result


def _request(row, index, first, observation, closing):
    """A scheduled CoreSet request records original queue custody before release."""
    identity, arrived, code, finished, rawcode, rawfinished, owner, gen, frozen, present, issued, scheduled = struct.unpack_from('<12Q', row)
    relative = index // 10 * 1000000000 + index % 10 * 1000
    require(identity == index + 1 and arrived == frozen == observation + relative
            and (owner, gen) == (OWNER, 1) and scheduled == 1 and present == 1
            and 0 < issued <= first <= arrived
            and code in (1, 2, 3, 4) and rawcode in (0, 1, 2, 3, 4)
            and (arrived <= finished <= closing if code == 1 else finished == 0)
            and (arrived <= rawfinished <= closing if rawcode == 1 else rawfinished == 0)
            and not any(row[96:]), 'invalid CoreSet request/schedule/result')
    return identity, owner, gen, relative


def _closing(row, boot, closing):
    # Restoration is a separate terminal fact. Native poll retains Applied even
    # when observation is later than its execution deadline. Adoption deadlines
    # remain enforced by _execution; a closing receipt proves no numeric result.
    require(row[:8] == b'CYCLOSE1' and tuple(word(row, i) for i in (8, 16, 24)) == (1, 2, 10)
            and struct.unpack_from('<HH', row, 32)[0] == 0
            and struct.unpack_from('<Q', row, 34)[0] in (2,6)
            and not any(row[42:48]) and word(row, 48) == boot
            and all(word(row, i) > 0 for i in (56, 64, 96, 120, 136, 144, 160))
            and word(row, 72) == 0 and (word(row, 80), word(row, 88)) == (0x434f5245, 1)
            and word(row, 152) == 1 and word(row, 184) == 1 and word(row, 216) == 0
            and 0 < word(row, 168) <= word(row, 176) <= word(row, 192) <= word(row, 200) <= closing
            and word(row,176)<=word(row,208)<=word(row,176)+200000000
            and word(row,192)<=word(row,208) and not any(row[224:]), 'invalid closing restoration receipt')



def core_image(side, model):
    """Match the retained image digest to legal original owner states, not mask2."""
    target=side['target']; seed=side['seed']
    queue=hashlib.sha256(b'CYXIA_EMPTY_REAL_CACP_QUEUE_1.3\0'+words(*target,1)
        +hashlib.sha256(model).digest()+bytes.fromhex(SCHEMAS[0])+words(seed)
        +b'100-owned-relative-arrivals;no-running-context;no-outstanding-output\0').digest()
    matches=[]
    for control in (2,6):
        for business in range(16):
            for healthy in range(16):
                if control&business or control&healthy!=control or not business&healthy: continue
                image=hashlib.sha256(b'CYXIA_ORIGINAL_CORESET_IMAGE_1.3\0'
                    +words(*target,control,business,healthy,0)).digest()
                calculated=digest(b'CYXIA_REPLAY_RESTORED_WORKING_SET_1.3\0'+queue+image)
                if calculated==side['initial_image_sha256']:
                    matches.append(dict(control=control,business=business,healthy=healthy,draining=0))
    require(len(matches)==1,'original actual CoreImage digest has no unique legal state')
    return matches[0]


def extract_coreset_pair(disk_path, context, boundary, model):
    from check_v13_disk import committed_volume, BLOCK
    from check_v13_filesystem import inspect_committed
    require(sha(disk_path)==context['disk_sha256'],'trusted disk hash mismatch')
    sides=[]; supplement=None; segments=[]
    with committed_volume(Path(disk_path)) as (current,metadata):
        volume=inspect_committed(current,metadata)
        require(volume['uuid']==context['disk_uuid'] and volume['boot_epoch']==context['boot_epoch']==1,
                'committed volume identity mismatch')
        for name in sorted(set(volume['files'])|set(volume['directories'])):
            if not any(p.startswith(('lr-','ls-')) for p in name.split('/')): continue
            side_match=re.fullmatch(r'/lr-0000000000000001-([0-9a-f]{4})',name)
            label=name=='/ls-0000000000000001'
            require((side_match or label) and name in volume['files'],'wrong typed archive path')
            node=volume['files'][name]
            require(0<node['size']<=MAX_FILE and node['durable_write_seq']>0,'archive byte/durable bound')
            raw=bytearray()
            for _,start,blocks in node['extents']:
                require(blocks <= MAX_FILE//BLOCK, 'archive extent bound')
                for block in range(start,start+blocks):
                    raw+=current(block)[:min(BLOCK,node['size']-len(raw))]
            require(len(raw)==node['size'] and digest(raw)==node['sha256'],'committed archive content mismatch')
            if label:
                require(supplement is None,'duplicate label supplement')
                supplement=(bytes(raw),node); continue
            segments.append(int(side_match[1],16)); at=0
            while at<len(raw):
                side=_side(memoryview(raw)[at:],context)
                side.update(path=name,inode=node['inode'],inode_generation=node['generation'],offset=at)
                sides.append(side); at+=side['length']
    require(segments==list(range(len(segments))) and len(sides)==2 and supplement is not None,
            'missing/extra typed pair archive')
    by_kind={s['side']:s for s in sides}
    require(set(by_kind)=={'Baseline','Candidate'},'missing/duplicate typed side')
    b,c=by_kind['Baseline'],by_kind['Candidate']
    for key in ('boot_epoch','family','target','seed','workload_sha256','initial_image_sha256',
                'frozen_other_domains_sha256','schema_hashes','node_id','relative_arrivals'):
        require(b[key]==c[key],'pair mismatch: '+key)
    for side,ref in zip((b,c),boundary['references']):
        expected=dict(boot_epoch=side['boot_epoch'],trial_id=side['trial_id'],generation=side['capture_generation'],
            object_id=side['inode'],object_generation=side['inode_generation'],offset=side['offset'],
            bytes=side['length'],sha256=side['sha256'])
        require(ref==expected,'bank/archive object/key/range/hash mismatch')
    raw,node=supplement
    require(len(raw)==2048 and raw[:16]==b'CYXIA_LABEL_16\0\0' and word(raw,16)==1
            and word(raw,24)==2048 and not any(raw[1280:])
            and [node['inode'],node['generation']]==boundary['witness_object']
            and digest(raw)==boundary['witness_sha256']
            and digest(raw[32:1056])==raw[1056:1088].hex(), 'durable protected supplement mismatch')
    require([archive_ref(raw[1088:1184]),archive_ref(raw[1184:1280])]==boundary['references'],
            'supplement/archive references mismatch')
    original=core_image(b,model)
    baseline_actions=[core_action(b['raw_bytes'][2048+i*6144+512:2048+i*6144+536],0)
        for i in range(word(b['raw_bytes'],128)) if word(b['raw_bytes'],2048+i*6144)==40]
    require(baseline_actions==[original['control']], 'baseline did not preserve actual original control')
    require(sha(disk_path)==context['disk_sha256'],'disk changed during extraction')
    return b,c,sample_witness(raw[32:1056]),original


def _prewarm(raw, header):
    require(len(raw)%64==0 and len(raw)//64==word(header,752), 'prewarm section width')
    seen=set(); last={}; total=0
    for at in range(0,len(raw),64):
        owner,gen,core,event,start,end=struct.unpack_from('<6Q',raw,at)
        require((owner,gen)==(0x5245504c434f,1) and core in (1,2) and event>0 and event not in seen
            and word(header,104)<=start<=end<=word(header,96) and not any(raw[at+48:at+64])
            and start>=last.get(core,0),'invalid actual CoreSet prewarm row')
        seen.add(event); last[core]=end; total+=end-start
    require(total==word(header,176),'prewarm raw CPU total mismatch')


from v16_learning_reward import OBSERVATION_NS, select_model, performance, cpu_union, reward_values


def encode_core_features(row,index):
    w=struct.unpack('<512Q',row[2048:]); at=64+10*index
    mask=core_action(row[512+24*index:536+24*index],index)
    out=[0]*64; out[0]=256
    def normalize(position,value,limit): out[position]=(512*min(value,limit)+limit)//(2*limit)
    for i,limit in enumerate((1000,1000,64,1000,1000,1000,100,1)): normalize(16+i,w[24+i],limit)
    for i,limit in enumerate((64,100000,1000,10000)):
        require(w[40]&(1<<i),'missing CoreSet domain feature')
        normalize(24+i,w[32+i],limit); out[32+i]=256
    normalize(40,2,255); normalize(41,mask.bit_count(),4)
    require(w[at+8]==1 and w[at+9]==mask.bit_count()*1000,'CoreSet actual capacity binding')
    normalize(42,w[at+9],4000); out[48]=out[49]=out[50]=256
    for i,limit in enumerate((4000,1000,100000,1)):
        if w[at+7]&(1<<i): normalize(56+i,w[at+3+i],limit); out[60+i]=256
    return out


def _core_adoptions(rows,header,model):
    candidate=bool(word(header,152)); adopted=[r for r in rows if word(r,0)==(31 if candidate else 40)]
    require(len(adopted)==1,'CoreSet one-shot requires one actual adoption')
    row=adopted[0]; count,selected=struct.unpack_from('<HH',row,204)
    received,accepted,started,finished=(word(row,p) for p in (352,360,400,416))
    issued=word(row,488) if candidate else received
    require(word(row,160)==word(header,96)==word(header,112)==issued and issued<=received<=accepted<=started<=finished
        and finished<=word(row,384) and 0<=word(row,384)-accepted<=200000000
        and finished-accepted<=200000000 and word(row,376)==0,'CoreSet one-shot timing/receipt mismatch')
    if candidate:
        require(word(row,320)==word(row,344)>0 and word(row,328)==word(row,160)
            and word(row,336)==0 and accepted<=word(row,368)<=word(row,160)+100000000
            and word(row,480)==0 and word(row,496)==1,'CoreSet candidate stamp/expiry mismatch')
        inputs=[encode_core_features(row,i) for i in range(count)]
        scores,best=select_model(model,inputs)
        require(scores==list(struct.unpack_from('<'+'h'*count,row,208)) and best==selected,
                'CoreSet full integer MLP/first maximum mismatch')
        evaluated=[dict(inputs=inputs,scores=scores,selected=selected)]
    else:
        require(word(row,440)==1,'CoreSet baseline request binding')
        evaluated=[None]
    return adopted,evaluated


def numeric_core_side(raw, model):
    """Recompute the retained Trial only; caller custody is checked separately."""
    require(isinstance(raw, (bytes, bytearray)) and len(raw) >= 2048, 'truncated numeric side')
    require(isinstance(model, (bytes, bytearray)) and len(model) == 2772, 'invalid model length')
    raw = bytes(raw)
    context = dict(boot_epoch=1, model_generation=1, model_sha256=digest(model),
                   schema_hash=SCHEMAS[0], schema_hashes=SCHEMAS, node_id=raw[640:672].hex())
    side = _side(raw, context)
    require(len(raw) == side['length'], 'extra numeric side bytes')
    h = raw[:2048]
    observation, closing = word(h, 112), word(h, 120)
    require(closing - observation - OBSERVATION_NS <= 5_000_000_000
            and word(h, 760) <= 1024 * 1024, 'closing/workspace bound')
    rows = [raw[2048 + i * 6144:2048 + (i + 1) * 6144] for i in range(word(h, 128))]
    adopted, evaluated = _core_adoptions(rows, h, model)
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
    canonical += words(word(h, 40), 1, 2, word(h, 88), observation,
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
        weight = core_action(row[512+24*selected:536+24*selected], selected)
        if candidate:
            e = evaluated[index]
            for inp, score in zip(e['inputs'], e['scores']):
                canonical += struct.pack('<64hh', *inp, score)
            if index == 0:
                input64 = e['inputs'][selected]
            canonical += words(word(row, 8), *(word(row, p) for p in range(272, 320, 8)),
                               word(row, 344), word(row, 392), word(row, 488), word(row, 360),
                               word(row, 368), word(row, 376), 1, word(row, 400), word(row, 416),
                               word(row, 336), word(row, 384), selected, count, 1, 0)
            canonical += row[1280:1328]
            canonical += row[16:48] + row[88:152] + words(word(row, 80))
        else:
            canonical += words(*(word(row, p) for p in (344, 8, 184, 192, 392, 152, 160, 176, 168,
                                                        352, 360)), word(row,440),
                               *(word(row, p) for p in (400, 416, 376, 384)))
        canonical += struct.pack('<3HQ', 1, 2, 0, weight)
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


def numeric_core_pair(candidate_raw, baseline_raw, model):
    require(len(candidate_raw) >= 2048 and len(baseline_raw) >= 2048, 'truncated pair')
    require(word(candidate_raw, 152) == 1 and word(baseline_raw, 152) == 0,
            'wrong candidate/baseline sides')
    for begin, end in ((32, 40), (56, 96), (256, 352), (448, 608), (640, 672)):
        require(candidate_raw[begin:end] == baseline_raw[begin:end], 'pair identity mismatch')
    require(word(candidate_raw, 40) != word(baseline_raw, 40)
            and word(candidate_raw, 48) != word(baseline_raw, 48), 'same trial/generation pair')
    candidate, baseline = (numeric_core_side(raw, model) for raw in (candidate_raw, baseline_raw))
    # The fixed archive schedule checker already checks all 100 relative
    # arrivals independently on each side, so their pairing is exact here.
    cp, bp = candidate['performance'], baseline['performance']
    calculated = reward_values(cp, bp, candidate['cpu']['union_ns'])
    reward = calculated['value']
    evidence = digest(b'CYXIA_PAIRED_LABEL_1.3\0' + bytes.fromhex(candidate['trial_canonical_sha256'])
                      + bytes.fromhex(baseline['trial_canonical_sha256']) + words(reward.bits))
    return dict(schema=1, family=[1, 2], candidate=candidate, baseline=baseline,
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



def match_sample_witness(witness,numeric,baseline,candidate):
    require(witness['baseline_id']==baseline['trial_id'] and witness['candidate_id']==candidate['trial_id']
        and witness['baseline_canonical']==numeric['baseline']['trial_canonical_sha256']
        and witness['candidate_canonical']==numeric['candidate']['trial_canonical_sha256']
        and witness['workload']==baseline['workload_sha256'] and witness['image']==baseline['initial_image_sha256']
        and witness['schemas']==[(13,s) for s in SCHEMAS]
        and witness['input64']==numeric['candidate']['input64'], 'actual protected sample identity/input mismatch')
    def perf(p):
        return [p[k] for k in ('emitted','completed','rejected','timed_out','pending','penalty_p99_ns')]+[
            int(p['actual_completed_p99_ns'] is not None),p['actual_completed_p99_ns'] or 0]
    def cost(c):
        return [c[k] for k in ('union_ns','policy_ns','executor_ns','optional_ns')]+c['raw_tagged_ns']
    for kind in ('candidate','baseline'):
        require(witness[kind+'_performance']==perf(numeric[kind]['performance'])
            and witness[kind+'_cpu']==cost(numeric[kind]['cpu']), 'actual protected sample integer totals mismatch')
    bits=[int(numeric['reward'][name]['bits'],16) for name in
          ('raw_cost','clipped_cost','delta_throughput','delta_latency','value')]
    require(witness['reward_bits']==bits and witness['evidence_hash']==numeric['prospective_paired_label_sha256'],
            'actual protected reward bits/evidence hash mismatch')
    return True


def verify_focus_capture(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                         producer_tools_root=None):
    root=Path(directory)
    require(not root.is_symlink(),'linked capture directory')
    root=root.resolve(strict=True)
    before=bounded_inventory(root)
    checked=verify_capture(root,source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    diagnostic_facts=focus_diagnostic_files(root)
    context=_schema_context(checked['trusted_context'])
    boundary=collection_boundary((root/'collection.bin').read_bytes())
    require(boundary is not None,'collection not durably released')
    model=(root/'model.bin').read_bytes()
    baseline,candidate,witness,image=extract_coreset_pair(root/'disk.raw',context,boundary,model)
    runtime_facts=actual_candidate_runtime((root/'control.bin').read_bytes(),
        (root/'runtime.bin').read_bytes(),candidate,context)
    paid_bank_facts((root/'tasks.bin').read_bytes(),(root/'credit.bin').read_bytes(),
        (root/'settlement.bin').read_bytes())
    numeric=numeric_core_pair(candidate['raw_bytes'],baseline['raw_bytes'],model)
    match_sample_witness(witness,numeric,baseline,candidate)
    require(boundary['sampled_ns']>=max(baseline['closing_ns'],candidate['closing_ns']),
            'collection release predates side close')
    for side in (baseline,candidate):
        closing_mask=struct.unpack_from('<Q',side['raw_bytes'],1792+34)[0]
        require(closing_mask==image['control'],'closing did not restore original actual CoreImage')
    require(bounded_inventory(root)==before,'capture tree changed during independent verification')
    require(trusted_context(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
        == {k:v for k,v in checked['trusted_context'].items() if k not in
            ('boot_epoch','input_sha256','config_sha256','nonce','disk_uuid','disk_sha256','released_boundary','stopped_banks')},
        'trusted closure changed during verification')
    numeric.update(protected_sample_export_verified=True,native_acceptance_inferred_from_trusted_producer=True,
        native_acceptance_inference_basis='Frozen native pair acceptance/store, durable witness/readback and released owner bank; no imported source authority.')
    return dict(version=VERSION,capture_complete=True,released_pair_observed=True,
        profile='coreset-one-pair',family=[1,2],groups=1,pairs=1,samples=1,
        protected_sample_export_verified=True,reward_numeric_verified=True,trial_canonical_matches_native=True,
        model_scores_verified=True,source_event_hash_recomputed=False,event_hash_recomputed=False,
        accepted_training_sample_verified=False,source_custody_replay_verified=False,
        native_label_imported=False,model_trained=False,native_acceptance_status='NOT_RUN',
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},
        minimum_training_samples=144,minimum_validation_samples=72,family_count_required=18,
        ordinary_demand_verified=False,initial_image_reexecution_verified=False,
        boundary=boundary,original_core_image=image,native_runtime=runtime_facts,numeric=numeric,
        checker_identity=checked['checker_identity'],producer_tools_root=checked['producer_tools_root'],
        diagnostic_contract=DIAGNOSTIC_VERSION,diagnostic_facts=diagnostic_facts,raw_inventory=before)


def actual_candidate_runtime(control,runtime,candidate,context):
    from verify_domains import parse_control
    facts=parse_control(control,context['boot_epoch'])
    require(facts is not None,'missing complete native control bank')
    cw=struct.unpack('<'+'Q'*(len(control)//8),control)
    require(cw[14]==context['model_generation'] and control[16*8:20*8].hex()==context['model_sha256']
            and control[20*8:24*8].hex()==context['schema_hash'] and cw[24]==0,
            'native runtime changed seed/model/schema identity')
    raw=candidate['raw_bytes']; rows=[raw[2048+i*6144:2048+(i+1)*6144] for i in range(word(raw,128))]
    adopted=[row for row in rows if word(row,0)==31]
    require(len(adopted)==1,'missing actual candidate runtime link')
    row=adopted[0]; matching=[]
    for slot in range(64):
        at=512+slot*640; r=cw[at:at+640]
        if r[0]!=word(row,8):continue
        require(r[639]>0 and not r[639]%2 and r[0]==r[1]
            and r[2:6]==(1,2,0x434f5245,1) and r[7]==context['boot_epoch']
            and r[13]==word(row,344) and r[14]==2 and r[15]==0 and r[19]==1 and r[30]==1
            and r[16:18]==struct.unpack_from('<HH',row,204)
            and struct.pack('<512Q',*r[32:544])==row[2048:]
            and struct.pack('<4Q',*r[608:612])==row[48:80]
            and r[10]>0 and r[11]>0 and r[10]+r[11]+r[29]<=2000000
            and r[12]<=500000 and r[18]==0,'actual native full MLP/publication receipt mismatch')
        matching.append(dict(slot=slot,sequence=r[0],inference_cpu_ns=r[10],encoding_cpu_ns=r[11],
            decoding_cpu_ns=r[29],publication_cpu_ns=r[12],approved_version=r[13]))
    require(len(matching)==1,'actual candidate publication missing/overwritten in bounded native bank')
    r=struct.unpack('<1024Q',runtime)
    require(r[0]==0x43595852554e3133 and r[1]==3 and r[2]>0 and not r[2]%2 and r[32]==context['boot_epoch']
        and r[14]>0 and r[19]>0 and r[20]>0 and r[28]>=4 and r[29]==0
        and all(r[i]==0 for i in (9,15,17,18,38,56))
        and r[4]>=1000 and all(v<=r[4]//100 for v in r[39:42]) and r[35]<=700,
        'native runtime fault/quarantine/cost/model execution mismatch')
    return dict(candidate=matching[0],runtime_publication=r[2],inferences=r[14],
                control_mask=r[6],business_mask=r[7],quarantined_mask=r[9])


def stopped_collection_ready(probe):
    """A live done hint cannot authorize a torn stopped publication."""
    if not collection_boundary(probe['collection']) or not released_pair_candidate(probe['replay']): return False
    if len(probe['boot'])!=512 or len(probe['runtime'])!=8192:return False
    boot_seq=word(probe['boot'],16); runtime_seq=word(probe['runtime'],16)
    return not boot_seq%2 and runtime_seq>0 and not runtime_seq%2


def builder_source_closure(source_root):
    """Exact static local builder imports; never import captured builder code."""
    root=Path(source_root).resolve(strict=True); pending=['build_v16_learning_collection']; found={}
    while pending:
        name=pending.pop()
        if name in found:continue
        require(len(found)<128,'builder closure bound')
        path=root/'tools'/(name+'.py')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size<=MAX_FILE,
                'linked/missing/unbounded builder dependency')
        found[name]=sha(path)
        for node in ast.walk(ast.parse(path.read_text())):
            imports=([node.module] if isinstance(node,ast.ImportFrom) else
                [item.name for item in node.names] if isinstance(node,ast.Import) else [])
            for item in imports:
                if item and '.' not in item and (root/'tools'/(item+'.py')).is_file():pending.append(item)
    return {'tools/'+name+'.py':value for name,value in sorted(found.items())}


def paid_bank_facts(tasks,credit,settlement):
    from verify_domains import parse_tasks, parse_control_credit, parse_control_settlements
    facts=parse_tasks(tasks)
    require(facts is not None,'missing initialized native task publication')
    require(not parse_control_credit(credit) and not parse_control_settlements(settlement),
            'native paid credit/settlement failure')
    return facts


DIAGNOSTIC_VERSION = 'v16-a03-prewarm-progress-diagnostics-v1'
FOCUS_DIAGNOSTICS = {
    'replay_owner_first': ('REPLAY_OWNER_EVIDENCE', 256),
    'prewarm_first_failure': ('LEARNING_PREWARM_FIRST_FAILURE', 256),
    'prewarm_progress': ('CORESET_PREWARM_PROGRESS', 1024),
}


def focus_diagnostic_symbols(image):
    """Required exact ABI symbols from the caller-selected inspected ELF."""
    result={}; ranges=[]
    for key,(name,width) in FOCUS_DIAGNOSTICS.items():
        location=symbol(image,name)
        require(location['size']==width and location['pa']%64==0
            and 0x40200000<=location['pa']<location['pa']+width<=0x44000000,
            'missing/wrong focus diagnostic symbol ABI: '+name)
        require(all(location['pa']+width<=start or end<=location['pa'] for start,end in ranges),
                'aliased focus diagnostic symbol')
        ranges.append((location['pa'],location['pa']+width)); result[key]=location
    return result


def decode_focus_diagnostic(key,raw):
    """Bounded observation only; missing/partial latch cannot grant authority."""
    require(key in FOCUS_DIAGNOSTICS and len(raw)==FOCUS_DIAGNOSTICS[key][1],
            'unknown/short focus diagnostic ABI')
    if key=='prewarm_progress':return decode_prewarm_progress(raw)
    w=struct.unpack('<32Q',raw)
    base=dict(version=DIAGNOSTIC_VERSION,bank=key,authorizes_replay=False,
              raw_sha256=digest(raw),raw_words=list(w))
    if not any(w):return dict(base,state='empty',observed=False)
    require(w[0] in (1,2),'invalid first diagnostic latch sequence')
    if w[0]==1:return dict(base,state='partial',observed=False)
    if key=='prewarm_first_failure':
        require(w[1:3]==(0x4359505746413136,1) and w[3] in (1,2,3,4)
            and (w[5] < 4 or w[5]==(1<<64)-1) and w[6]<4
            and w[19] in (0,1) and w[20] in (0,1) and w[25] in (0,1)
            and w[26]&~15==0 and not any(w[30:])
            and (bool(w[26]&1) or w[12]==0)
            and (w[4]==0 if w[3]==1 else w[4]>0),'invalid published prewarm first-cause ABI')
        names=('attempt_session','current_session','first_ns','last_ns','earliest_ns','observed_clock_ns',
               'head','tail','capacity','old_last_ns','cutoff_ns','open_attempts','active','lost',
               'completed','last_completed_ns','frozen_first_ns','started_ns','finish_attempted','flags',
               'boot_epoch','trial_id','capture_generation')
        fields=dict(zip(names,w[7:30]))
        return dict(base,state='published',observed=True,
            site={1:'pending_drop',2:'finish_auth',3:'full_ring_capacity',4:'freeze_lost'}[w[3]],
            original_error_code=w[4],source_bank=None if w[5]==(1<<64)-1 else w[5],
            observed_cpu=w[6],clock_observed=bool(w[26]&1),ring_operands_original=bool(w[26]&2),
            old_last_original=bool(w[26]&4),current_session_observed=bool(w[26]&8),**fields)
    require(w[1:3]==(0x4359524f574e3133,1) and w[3]>0
        and w[4] in (1,2,10,11,12,13,20,21,22,23,24,25,26,27,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,50,60)
        and w[5]>0 and w[6]>0 and w[31]>0 and w[9]>=w[31]
        and w[25]&~15==0 and w[29]<=4,'invalid published replay owner first-cause ABI')
    return dict(base,state='published',observed=True,phase_plus_one=w[3],site_code=w[4],
        original_error_code=w[5],retained_error_code=w[6],evidence_error_category=w[7],
        nested_learning_error_code=w[8],failed_ns=w[9],trial_id=w[10],boot_epoch=w[11],
        capture_generation=w[12],root_token=w[13],family=[w[14],w[15]],trial_kind=w[16],
        target=[w[17],w[18]],cursor=w[19],baseline_sequence=w[20],first_ns=w[21],
        observation_ns=w[22],root_phase_plus_one=w[23],retained_root_fault_code=w[24],
        entry_flags=w[25],request_id=w[26],receipt_plan=w[27],receipt_version=w[28],
        receipt_state=w[29],receipt_error_code=w[30],service_entry_ns=w[31])


def focus_diagnostic_files(root):
    facts={}
    for key,(_,width) in FOCUS_DIAGNOSTICS.items():
        path=Path(root)/('diagnostic-'+key+'.bin')
        require(path.is_file() and not path.is_symlink() and path.stat().st_size==width,
                'missing/short required focus diagnostic raw bank: '+key)
        facts[key]=decode_focus_diagnostic(key,path.read_bytes())
    return facts


def _verify_required_diagnostic_reads(rows,root,context,required):
    """Bind each fixed raw file to a successful read in the final paused epoch."""
    root=Path(root); pending=None; stopped=False; paused=False; quit_seen=False; quit_ack=False; reads={}
    require(rows and rows[0]['direction']=='receive' and 'QMP' in rows[0]['message'], 'missing diagnostic QMP greeting')
    names={'diagnostic-'+key+'.bin':key for key in required}
    for row in rows[1:]:
        message=row['message']
        if row['direction']=='receive':
            if 'event' in message:continue  # The shared base validates event causality and payload.
            require(pending is not None and message.get('id')==pending['id']
                and 'error' not in message and 'return' in message,'unacknowledged diagnostic QMP read')
            name=pending['execute']
            if name=='stop':stopped=True
            elif name=='query-status':
                require(stopped and message['return'].get('status')=='paused','diagnostic pause not confirmed')
                paused=True
            elif name=='pmemsave':
                args=pending['arguments']; key=names.get(Path(args['filename']).name)
                if key:
                    require(key not in reads,'duplicate required diagnostic read')
                    path=root/('diagnostic-'+key+'.bin')
                    require(path.is_file() and not path.is_symlink() and path.stat().st_size==required[key],
                            'required diagnostic raw file absent/short')
                    reads[key]=dict(path=path.name,bytes=required[key],sha256=sha(path),pa=args['val'],command_id=pending['id'])
            elif name=='quit':quit_ack=True
            pending=None;continue
        require(row['direction']=='send' and not quit_seen and pending is None,
                'diagnostic read after quit or outstanding command')
        pending=message;name=message.get('execute')
        if name=='cont':
            require(not reads,'resumed after final diagnostic read')
            stopped=paused=False
        elif name=='stop':stopped=paused=False
        elif name=='query-status':require(stopped,'diagnostic status without stop ACK')
        elif name=='pmemsave':
            args=message.get('arguments',{});target=Path(args.get('filename',''))
            key=names.get(target.name)
            if key:
                location=context['diagnostic_symbols'][key]
                require(paused and set(args)=={'val','size','filename'}
                    and type(args['val']) is int and type(args['size']) is int
                    and args['val']==location['pa'] and args['size']==location['size']==required[key]
                    and target==root/('diagnostic-'+key+'.bin'), 'required diagnostic read range/path/pause mismatch')
        elif name=='quit':
            require(paused and set(reads)==set(required),'quit before both exact paused diagnostic reads')
            quit_seen=True
    require(quit_seen and quit_ack and pending is None and set(reads)==set(required),
            'missing required final diagnostic QMP custody')
    return reads


def verify_focus_diagnostic_reads(rows,root,context):
    return _verify_required_diagnostic_reads(rows,root,context,{key:width for key,(_,width) in FOCUS_DIAGNOSTICS.items()})


def verify_failure_diagnostic_reads(rows,root,context):
    required={key:width for key,(_,width) in FOCUS_DIAGNOSTICS.items()}
    required.update({key:BANKS[key][1] for key in ('boot','replay','control','runtime','unified','collection')})
    return _verify_required_diagnostic_reads(rows,root,context,required)


def verify_capture(directory, **trusted):
    """The released-collection contract retains every original release predicate."""
    return _verify_capture_custody(directory,terminal_contract='released-collection',**trusted)


def verify_diagnostic_capture(directory, *, source_root, build_manifest, formatter, qemu_binary,qemu_source,
                              producer_tools_root=None):
    """Verify custody of an expected FAIL; never infer a pair/sample acceptance."""
    trusted=dict(source_root=source_root,build_manifest=build_manifest,formatter=formatter,
        qemu_binary=qemu_binary,qemu_source=qemu_source,producer_tools_root=producer_tools_root)
    checked=_verify_capture_custody(directory,terminal_contract='pre-collection-diagnostic-failure',**trusted)
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
        capture_complete=False,released_pair_observed=False,reward_replay_verified=False,
        reward_numeric_verified=False,trial_canonical_matches_native=False,
        protected_sample_export_verified=False,native_acceptance_inferred_from_trusted_producer=False,
        accepted_training_sample_verified=False,source_event_hash_recomputed=False,source_custody_replay_verified=False,
        native_label_imported=False,model_trained=False,native_acceptance_status='NOT_RUN',
        formal_acceptance={name:'NOT_RUN' for name in ('A03','A08','A10','A16')},
        diagnostic_contract=DIAGNOSTIC_VERSION,diagnostic_facts=facts,diagnostic_parser_errors=parser_errors,
        diagnostic_reads=checked['diagnostic_reads'],boot_epoch=checked['boot_epoch'],raw_inventory=inventory,
        checker_identity=dict(version=CHECKER_VERSION,tools=tool_closure()),authorizes_replay=False)


def decode_prewarm_progress(raw):
    """Positive sampled observations, never an assertion of Root-first readiness."""
    require(len(raw)==1024,'wrong positive prewarm status ABI width')
    w=struct.unpack('<128Q',raw)
    base=dict(version=DIAGNOSTIC_VERSION,bank='prewarm_progress',authorizes_replay=False,
        readiness_asserted=False,raw_sha256=digest(raw),raw_words=list(w))
    if not any(w):return dict(base,state='empty',observed=False)
    require(w[0]>0,'unpublished positive prewarm status payload')
    if w[0]%2:return dict(base,state='partial',observed=False)
    require(w[1:3]==(0x4359505750523136,1) and w[3]>0 and w[8] in (0,1,2)
        and all(w[index] in (0,1) for index in (23,24,25,27,34,40,44,46,77,82,86))
        and w[28]<=3 and w[37]<=3 and w[32]<=2 and w[38]<=2 and w[76]<=3
        and w[81]&~255==0 and not any(w[91:]),'invalid published positive prewarm status ABI')
    sampled=w[3];times=list(w[52:68]);within=[at for at in times if at and max(0,sampled-1000000000)<=at<=sampled]
    # Count only this observed array as of the native sample timestamp. No
    # temporal claim is made about the protected Root's distinct first_ns.
    window=dict(sampled_ns=sampled,window_ns=1000000000,within_one_second_count=len(within),
        earliest_within_window_ns=min(within) if within else None,
        latest_within_window_ns=max(within) if within else None,
        timestamps_after_sample_count=sum(at>sampled for at in times),
        array_atomicity_asserted=False)
    return dict(base,state='published',observed=True,publication=w[0],sampled_ns=sampled,
        producer_phase=w[4],family=[w[5],w[6]],group=w[7],trial_kind=w[8],
        preparation=dict(id=w[9],boot_epoch=w[10],trial_id=w[11],started_ns=w[12]),
        root_token=dict(id=w[13],boot_epoch=w[14]),target=[w[15],w[16]],seed=w[17],
        queue=dict(serial=w[18],model_generation=w[19],seed=w[20],target=[w[21],w[22]],
            has_scope=bool(w[23]),has_first=bool(w[24]),stopped=bool(w[25]),fault_code=w[26],warm_queued=bool(w[27])),
        warm=dict(phase=w[28],serial=w[29],release_ns=w[30],at_ns=w[31],result_tag=w[32],error_code=w[33],
            reported=bool(w[34]),root_ns=w[35],result_ns=w[36]),
        primary=dict(phase=w[37],result_tag=w[38],error_code=w[39],reported=bool(w[40]),root_ns=w[41],result_ns=w[42]),
        prewarm=dict(session=w[43],active=bool(w[44]),open=w[45],lost=bool(w[46]),completed_before=w[47],
            completed_after=w[48],last_completed_ns=w[49],started_ns=w[50],frozen_first_ns=w[51],
            completion_times_ns=times,heads=list(w[68:72]),tails=list(w[72:76])),
        hint_reason={0:'none',1:'enqueue_due',2:'retired_ready',3:'freeze_retry'}[w[76]],
        owned_eligible_hint=bool(w[77]),
        last_readiness_observation=dict(first_ns=w[78],recent=w[79],earliest_ns=w[80],reason_mask=w[81]),
        coherent_count_observed=bool(w[82]),owner_flags=w[83],root_phase_plus_one=w[84],
        last_service_outcome_code=w[85],
        primary_preparation_claim=dict(present=bool(w[86]),sequence=w[87],snapshot_taken_ns=w[88],
            original_deadline_ns=w[89],last_retire_reason_code=w[90]),
        completion_window_as_of_sample=window)
