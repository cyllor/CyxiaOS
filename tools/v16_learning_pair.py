"""Standalone released-pair evidence; raw custody is separate from numeric replay."""
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

VERSION = 'v16-learning-pair-v1'
CHECKER_VERSION = 'v16-learning-checker-v2'
TOOL_ROOT = Path(__file__).resolve().parents[1]
BANKS = {'boot': ('A01_BOOT_EVIDENCE', 512), 'config': ('A01_BOOT_CONFIG', 512),
         'replay': ('REPLAY_V13_EVIDENCE', 512), 'control': ('DOMAIN_CONTROL_EVIDENCE', 4096),
         'runtime': ('RUNTIME_V13_EVIDENCE', 8192), 'unified': ('UNIFIED_EVIDENCE', 4096)}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n')


def released_pair_candidate(raw_replay: bytes) -> dict | None:
    if len(raw_replay) != 512:
        return None
    w = struct.unpack('<64Q', raw_replay)
    if (w[0] == 0 or w[0] % 2 or w[1] != 0x435952504c593133 or w[2] not in (0, 17)
            or w[10] < 2 or w[17] < 2 or w[19] < 1
            or any(w[i] for i in (9, 11, 12, 13, 14, 15, 16, 20, 21, 63))):
        return None
    # Current trial/group/boot can already describe the NEXT preparation.
    # The first pair identity must instead come from committed side headers.
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
    pending = ['run_v16_learning_pair', 'v16_learning_pair']
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
    paths = {name: Path(value).resolve(strict=True) for name, value in dict(
        source_root=source_root, build_manifest=build_manifest, formatter=formatter,
        qemu_binary=qemu_binary, qemu_source=qemu_source).items()}
    source = paths['source_root']; build = paths['build_manifest']
    for name in ('formatter', 'qemu_binary'):
        require(paths[name].is_file() and os.access(paths[name], os.X_OK), 'not executable: ' + name)
    sources = code_source_map(source)
    manifest = json.loads(build.read_text())
    p = manifest['profiles']
    require(set(p) <= {'fault', 'service_fault', 'service_fault_nodes', 'leave', 'unix_seconds',
                       'selftest', 'storage_fault', 'memory_probe'}, 'unknown native build profile')
    require(manifest['schema_version'] == 1 and manifest['status'] == 'BUILT_NOT_RUN', 'invalid build')
    require(p['selftest'] is True and p['fault'] == 'normal'
            and p.get('service_fault', 'none') == 'none'
            and p.get('service_fault_nodes', {'a': 'none', 'b': 'none'}) == {'a': 'none', 'b': 'none'}
            and all(p.get(k, False) is False for k in ('leave', 'storage_fault', 'memory_probe')),
            'wrong learning-pair normal selftest profile')
    require(manifest['code_source_map'] == sources
            and manifest['builder_sha256'] == sha(source / 'tools/build_unified.py'), 'source/build mismatch')
    artifacts = {}
    for name in ('node-a.elf', 'service-a.elf', 'task.elf', 'node-a.pub'):
        path = build.parent / name
        require(path.is_file() and not path.is_symlink()
                and manifest['artifacts'][name]['sha256'] == sha(path)
                and manifest['artifacts'][name]['bytes'] == path.stat().st_size, 'build artifact mismatch: ' + name)
        artifacts[name] = sha(path)
    image = (build.parent / 'node-a.elf').read_bytes()
    inspect_elf(image)
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
    model_symbol = symbol(image, 'A02_BOOT_MODEL')
    require(model_symbol['size'] == 2772, 'wrong embedded model layout')
    model = loaded_bytes(image, model_symbol['va'], model_symbol['size'])
    node_id = hashlib.sha256((build.parent / 'node-a.pub').read_bytes()).hexdigest()
    require(node_id == manifest['nodes']['a']['node_id'], 'build node identity mismatch')
    proof = attest_qemu(str(paths['qemu_binary']), paths['qemu_source'])
    require(proof.get('qemu_pmu_patch_attested') is True, 'learning capture requires fixed patched QEMU')
    return dict(version=VERSION, paths={k: str(v) for k, v in paths.items()},
                source_map=sources, build_sha256=sha(build), artifacts=artifacts, symbols=symbols,
                diagnostic_symbols=diagnostics,
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


def verify_capture(directory, *, source_root, build_manifest, formatter, qemu_binary, qemu_source,
                   producer_tools_root=None):
    """Replay fixed local code against explicit caller context, never archived commands.

    This verifier reads recorded commands as evidence only. It never executes
    archived code, subprocess arguments, checker names, or summary booleans.
    An optional caller-selected producer root is read/AST-hashed only; current
    fixed checker functions execute, with their separate identity in the result.
    """
    from boot_reboot_contract import verify_origin, DISK_BYTES
    root = Path(directory)
    require(not root.is_symlink(), 'linked capture directory')
    root = root.resolve(strict=True)
    require(all(not p.is_symlink() for p in root.rglob('*')), 'linked capture artifact')
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
        return (released_pair_candidate(probe['replay']) is not None
                and struct.unpack('<64Q', probe['boot'])[2] % 2 == 0)
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
            require(resumed and (running or paused and captures == set(BANKS) - {'config'}),
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
            elif target.name in {'pending-replay.bin', 'pending-control.bin'}:
                require(running and not paused and not captures, 'live probe after stop')
                key = target.stem.removeprefix('pending-')
            elif re.fullmatch(r'probe-[0-9]{2}-(boot|replay|control|runtime|unified)\.bin', target.name):
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
                address, size = context['symbols'][key]['pa'], BANKS[key][1]
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
            require(paused and not running and captures == set(BANKS) - {'config'}, 'quit before final stopped evidence')
            quit_seen = True
    require(quit_seen and pending is None and resumed and stops > 0 and selected_attempt is not None
            and set(attempts) == set(range(1, selected_attempt + 1)), 'incomplete QMP lifecycle')
    require(all(set(probe) == required_banks for probe in attempts.values()), 'incomplete retained stopped attempt')
    require(responses.get('query-cpus-fast') == platform['cpus']
            and responses.get('query-memory-size-summary') == platform['memory'], 'platform/QMP mismatch')
    require(bytes(serial) == (root / 'serial.bin').read_bytes(), 'serial/QMP mismatch')
    decoder = FrameDecoder(); text = b''.join(payload + b'\n' for payload in decoder.feed(bytes(serial)))
    require(text == (root / 'serial.txt').read_bytes() and decoder.loss == decoder.corrupt == 0
            and not decoder.buffer and not any(x in text or x in serial for x in (b'PANIC', b'SMP_ERROR', b'UNIFIED_FAIL')),
            'native serial fault/loss/corruption')
    boot, replay, control, runtime, unified = ((root / (key + '.bin')).read_bytes()
                                             for key in ('boot', 'replay', 'control', 'runtime', 'unified'))
    boundary = released_pair_candidate(replay)
    require(boundary is not None, 'stopped pair is not released')
    fatal_evidence(replay, control)
    verify_samples(boot, boot, control, runtime, unified, config)
    epoch = struct.unpack('<64Q', boot)[6]
    trusted = dict(context, boot_epoch=epoch, input_sha256=sha(root / 'input.json'),
                   config_sha256=sha(root / 'config.bin'), nonce=inputs['nonce'], disk_uuid=inputs['disk_uuid'],
                   disk_sha256=disk['sha256'], released_boundary=boundary,
                   stopped_banks={key: sha(root / (key + '.bin')) for key in captures})
    return dict(version=VERSION, released_pair_observed=True, capture_complete=False,
                reward_replay_verified=False, native_acceptance_status='NOT_RUN',
                boot_epoch=epoch, boundary=boundary, trusted_context=trusted,
                producer_tools_root=str(Path(TOOL_ROOT if producer_tools_root is None
                                             else producer_tools_root).resolve(strict=True)),
                checker_identity=dict(version=CHECKER_VERSION, tools_root=str(TOOL_ROOT),
                                      tools=tool_closure()))
