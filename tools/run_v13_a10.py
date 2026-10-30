#!/usr/bin/env python3
"""Capture one real EL0 filesystem mode through volatile NBD.

This is not the full A10 fault/replay/eviction matrix. Clean completion requires
protected task exits and file replies plus an independent disk oracle. Cuts
retain diagnostic prefixes, never synthesized clean completion. The runner
copies an existing disk; only the guest performs filesystem operations.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from build_unified import code_source_map
from artifact_store import materialize
from check_elf import boot_profile, inspect_elf, symbol
from check_prototype_evidence import read_json, safe_path
from check_v13_fault_disk import inspect as inspect_nbd
from check_v13_filesystem import inspect as inspect_filesystem
from doctor import ROOT, env
from run_v13_a02 import inject_config
from transport import FrameDecoder
from v13_fault_disk import Backend, Server
from v13_a10_budget import scenario_budget
from verify_smp import require, sha
from verify_v13_a10 import decode, payload, verify_boot, verify_consumption, verify_filesystem
from verify_v13_model import loaded_bytes
from verify_v13_storage_faults import copy_sparse
from verify_unified import attest_qemu

LAYOUT = (1, 512, 768, 384, 295424, 299008, 512, 512)
CONTROL_EVIDENCE_BYTES = (512 + 64 * 640) * 8
EXIT_MAGIC = 0x4359584131305052
PENDING_DIAGNOSTICS = ('domain-task', 'unified-runtime', 'unified-service-stage')
TOOL_NAMES = ('run_v13_a10.py', 'verify_v13_a10.py', 'run_v13_a02.py',
    'run_v13_a10_matrix.py', 'verify_v13_a10_matrix.py', 'verify_v13_a10_faults.py',
    'artifact_store.py', 'check_v13_preparation_stack.py',
    'v13_fault_disk.py', 'check_v13_fault_disk.py', 'check_v13_filesystem.py',
    'check_v13_disk.py', 'verify_v13_storage_faults.py', 'verify_v13_storage.py',
    'build_unified.py', 'check_elf.py', 'verify_v13_model.py', 'run_qemu.py',
    'transport.py', 'verify_smp.py', 'doctor.py', 'check_prototype_evidence.py',
    'v13_a10_budget.py', 'v13_a10_fault_scope.py',
    'verify_unified.py')


def config_bytes(binding: dict) -> bytes:
    mode, epoch = binding['mode'], binding['boot_epoch']
    require(type(mode) is int and mode in (1, 2, 3, 4)
            and type(epoch) is int and 0 < epoch < 2**64, 'invalid A10 mode/epoch')
    def identity(key, width):
        value = binding[key]
        require(type(value) is str and re.fullmatch(f'[0-9a-f]{{{width * 2}}}', value)
                and value != '0' * (width * 2), 'invalid A10 identity: ' + key)
        return bytes.fromhex(value)
    return (struct.pack('<4Q', 0x4359584131304346, 1, mode, epoch)
            + identity('nonce', 16) + identity('image_sha256', 32)
            + identity('input_sha256', 32) + identity('source_sha256', 32)
            + identity('uuid', 16) + bytes(352))


def terminal_ready(raw: bytes, mode: int) -> bool:
    require(len(raw) == 512 and mode in (1, 2, 3, 4), 'invalid A10 exit probe')
    roles = (1,) if mode >= 3 else (0, 1)
    return all(struct.unpack_from('<Q', raw, role * 256)[0] == EXIT_MAGIC for role in roles)


def validate_capture_commands(transcript: list, *, cut_observed: bool):
    commands = [row['message']['execute'] for row in transcript if row['direction'] == 'send']
    require(commands.count('cont') == 1 and 'quit' not in commands,
            'missing single start or graceful shutdown would inject host FLUSH')
    require(commands.count('stop') <= int(cut_observed),
            'clean capture stop would inject host FLUSH')
    if 'stop' in commands:
        require(commands.index('cont') < commands.index('stop'), 'cut stop precedes execution')


def validate_build_profile(manifest: dict):
    profile = manifest.get('profiles', {})
    require(manifest.get('schema_version') == 1 and manifest.get('status') == 'BUILT_NOT_RUN'
            and profile.get('selftest') is True and profile.get('storage_fault') is True
            and profile.get('fault') == 'normal' and profile.get('leave') is False,
            'A10 requires unified --selftest --storage-fault normal profile')


def validate_start(oracle: dict, mode: int) -> dict:
    require(type(mode) is int and mode in (1, 2, 3, 4), 'invalid A10 mode')
    epoch = oracle['boot_epoch']
    require(type(epoch) is int and 0 <= epoch < 2**64 - 1, 'invalid initial BootEpoch')
    value = oracle['files'].get('/a10/value')
    prior = None
    if mode == 1:
        require(epoch == 0 and value is None and '/a10' not in oracle['directories'],
                'preparation requires a fresh volume without ordinary A10 objects')
    else:
        require(epoch > 0 and value is not None, 'overwrite/recovery requires the original file')
        sequence = value['durable_write_seq']
        require((sequence == 2 if mode == 2 else sequence in (2, 3))
                and value['inode'] > 0 and value['generation'] > 0 and value['size'] == 4096
                and value['sha256'] == hashlib.sha256(payload(sequence)).hexdigest(),
                'starting image has wrong acknowledged object/version/content')
        prior = value['inode'], value['generation']
    return dict(mode=mode, boot_epoch=epoch + 1, uuid=oracle['uuid'], prior_object=prior)


def verify_unchanged(files: dict[Path, str]):
    for path, expected in files.items():
        require(sha(path) == expected, 'changed frozen execution file: ' + str(path))


def validate_cut_oracle(before: dict, after: dict, mode: int):
    require(after['uuid'] == before['uuid']
            and before['boot_epoch'] <= after['boot_epoch'] <= before['boot_epoch'] + 1,
            'cut changed volume identity or durable boot prefix')
    if mode == 1:
        return
    old, new = before['files']['/a10/value'], after['files'].get('/a10/value')
    require(new is not None and (new['inode'], new['generation']) == (old['inode'], old['generation'])
            and new['size'] == 4096 and old['durable_write_seq'] <= new['durable_write_seq'] <= 3
            and new['durable_write_seq'] in (2, 3)
            and new['sha256'] == hashlib.sha256(payload(new['durable_write_seq'])).hexdigest(),
            'cut lost or replaced previously acknowledged file prefix')


def result_scope(cut: bool) -> dict:
    return dict(test_id='A10', native_acceptance_status='NOT_RUN', A10_complete=False,
        native_filesystem_fault_matrix_complete=False, runtime_truth_attested=False,
        scope=('one injected native prefix; no clean task completion inferred' if cut else
               'one ordinary EL0 clean mode; complete fault/replay/eviction matrix remains unrun'))


def sample_interval(sample_ms: int) -> float:
    require(type(sample_ms) is int and 100 <= sample_ms <= 30_000,
            'A10 sample interval must be 100..30000 ms')
    return sample_ms / 1000


def request_merging(mode: int, cut: int) -> str:
    return 'on' if cut == 0 and mode in (1, 4) else 'off'


def diagnostic_specs() -> tuple[tuple[str, str, int], ...]:
    return (('STORAGE_V13_EVIDENCE', 'storage-boot', 4096),
            ('DOMAIN_CONTROL_EVIDENCE', 'control-header', CONTROL_EVIDENCE_BYTES),
            ('CONTROL_CREDIT_EVIDENCE', 'control-credit', 512),
            ('TASK_OVERRUN_EVIDENCE', 'task-overrun', 256),
            ('DOMAIN_TASK_EVIDENCE', 'domain-task', 256),
            ('RUNTIME_V13_EVIDENCE', 'runtime-v13', 8192),
            ('DYNAMIC_V13_EVIDENCE', 'dynamic-v13', 4096),
            ('UNIFIED_SERVICE_STAGE', 'unified-service-stage', 8),
            ('UNIFIED_EVIDENCE', 'unified-runtime', 4096))


def resolve_qemu(qemu: Path | None, qemu_source: Path | None) -> tuple[Path, dict]:
    selected = qemu or shutil.which('qemu-system-aarch64', path=env()['PATH'])
    require(selected is not None, 'QEMU missing')
    binary = Path(selected).resolve(strict=True)
    return binary, attest_qemu(binary, qemu_source)


def profile(image: bytes) -> dict:
    inspect_elf(image)
    require(boot_profile(image)['ram_mib'] == 1024, 'A10 requires 1 GiB unified image')
    config, capture, progress, consumption, layout = (symbol(image, name) for name in
        ('A10_CONFIG', 'A10_CAPTURE', 'A10_PROGRESS', 'A10_CONSUMPTION', 'A10_CAPTURE_LAYOUT'))
    require(config['size'] == 512 and progress['size'] == 512 and consumption['size'] == 256
            and layout['size'] == 64
            and config['pa'] % 8 == progress['pa'] % 8 == consumption['pa'] % 8 == 0,
            'invalid A10 protected symbols')
    require(struct.unpack('<8Q', loaded_bytes(image, layout['va'], 64)) == LAYOUT
            and capture['size'] == LAYOUT[5], 'unknown A10 capture layout')
    diagnostics = {}
    for name, key, size in diagnostic_specs():
        location = symbol(image, name)
        require(location['size'] == size, 'wrong diagnostic symbol: ' + name)
        diagnostics[key] = location
    model = symbol(image, 'A02_BOOT_MODEL')
    require(model['size'] == 2772, 'unknown boot model artifact')
    return dict(config=config, capture=capture, progress=progress, consumption=consumption,
                diagnostics=diagnostics, model=model,
                instrumentation_bytes=capture['size'] + 1280)


def _json(path: Path, document):
    # Canonical scenario bytes bind the input hash injected before first guest instruction.
    path.write_text(json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n')


def run(build_manifest: Path, initial_disk: Path, output: Path, *, mode: int,
        source_root: Path = ROOT, timeout: float | None = None, cut: int = 0,
        phase: str = 'before', unflushed: str = 'drop', reverse_replies: bool = False,
        artifact_cache: Path | None = None, sample_ms: int = 100,
        qemu: Path | None = None, qemu_source: Path | None = None) -> dict:
    from v13_a10_native_capture import NativeQmp, Witness, close_capture
    from verify_v13_a10_native_receipt import VERSION, capture_limits, qemu_identity, tool_closure
    source_root = source_root.resolve(strict=True)
    budget = scenario_budget(source_root, mode)
    if timeout is None:
        timeout = budget['capture_timeout_seconds']
    require(type(timeout) in (int, float) and not isinstance(timeout, bool)
            and 5 <= timeout <= budget['capture_timeout_seconds']
            and type(cut) is int and cut >= 0, 'invalid bounded capture request')
    require(phase in ('before', 'after-ack') and unflushed in ('drop', 'reverse-half'), 'invalid cut policy')
    interval = sample_interval(sample_ms)
    merging = request_merging(mode, cut)
    build_manifest, initial_disk = build_manifest.resolve(strict=True), initial_disk.resolve(strict=True)
    output = output.resolve()
    require(len(json.dumps(str(output))) <= 1024, 'A10 capture-root length exceeds native transcript budget')
    if artifact_cache is not None: artifact_cache = artifact_cache.resolve()
    require(not output.exists(), 'refuse to reuse A10 evidence output')
    manifest = read_json(build_manifest)
    manifest_hash = sha(build_manifest)
    validate_build_profile(manifest)
    sources = code_source_map(source_root)
    require(manifest['code_source_map'] == sources, 'A10 build/source mismatch')
    require(manifest['builder_sha256'] == sha(safe_path(source_root, 'tools/build_unified.py')),
            'A10 frozen builder mismatch')
    require({'cargo', 'rustc', 'clang'} <= manifest['tools'].keys(), 'missing native build tools')
    image_path = safe_path(build_manifest.parent, 'node-a.elf')
    image = image_path.read_bytes()
    layout = profile(image)
    before = inspect_filesystem(initial_disk)
    start = validate_start(before, mode)
    binary, qemu_proof = resolve_qemu(qemu, qemu_source)
    require(qemu_source is not None and qemu_proof.get('qemu_pmu_patch_attested') is True,
            'A10 native capture requires caller-selected patched QEMU source')
    output.mkdir(parents=True, mode=0o700)
    frozen_files = {build_manifest: manifest_hash, output / 'build-manifest.json': manifest_hash}
    for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
        path = safe_path(build_manifest.parent, name)
        require(manifest['artifacts'][name]['sha256'] == sha(path), 'changed built artifact: ' + name)
        materialize(path, output / name, manifest['artifacts'][name]['sha256'], artifact_cache)
        frozen_files[path] = frozen_files[output / name] = manifest['artifacts'][name]['sha256']
    shutil.copyfile(build_manifest, output / 'build-manifest.json')
    _json(output / 'source-manifest.json', sources)
    tool_hashes = {name: sha(ROOT / 'tools' / name) for name in TOOL_NAMES}
    for name in TOOL_NAMES:
        target = output / 'tools' / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / 'tools' / name, target)
        frozen_files[ROOT / 'tools' / name] = frozen_files[target] = tool_hashes[name]
    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
                 'crates/prototype/src/features.rs', 'crates/prototype/src/policy_wire.rs'):
        target = output / 'build-inputs' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(safe_path(source_root, name), target)
    copy_sparse(initial_disk, output / 'initial.raw')
    copy_sparse(output / 'initial.raw', output / 'disk.raw')
    initial_hash = sha(output / 'initial.raw')
    require(initial_hash == sha(initial_disk), 'starting disk changed during copy')
    frozen_files[initial_disk] = frozen_files[output / 'initial.raw'] = initial_hash
    nonce = secrets.token_hex(16)
    _json(output / 'input.json', dict(test_id='A10', specification='1.3', mode=mode,
        expected_boot_epoch=start['boot_epoch'], uuid=start['uuid'], nonce=nonce,
        build_manifest_sha256=manifest_hash,
        initial_disk_sha256=initial_hash, initial_object=start['prior_object'],
        scenario='ordinary EL0 same-home versions and independent reader',
        payload='LE u64 0xa100000000000000 | version<<32 | word_index, 512 words',
        clock='wallclock', client_deadline_ns=budget['client_deadline_ns'],
        capture_margin_ns=budget['capture_margin_ns'], capture_timeout_seconds=timeout,
        client_poll_ns=budget['client_poll_ns'],
        sample_ms=sample_ms,
        qemu_request_merging=merging,
        cut=cut, phase=phase, unflushed=unflushed, reverse_replies=reverse_replies,
        immutable_artifact_cache=str(artifact_cache) if artifact_cache is not None else None,
        max_events=LAYOUT[3], instrumentation_bytes=layout['instrumentation_bytes']))
    binding = {key: start[key] for key in ('mode', 'boot_epoch', 'uuid')}
    binding.update(nonce=nonce, image_sha256=sha(output / 'node-a.elf'),
        input_sha256=sha(output / 'input.json'), source_sha256=sha(output / 'source-manifest.json'))
    _json(output / 'binding.json', binding)
    _json(output / 'disk-before.json', before)
    (output / 'config.bin').write_bytes(config_bytes(binding))
    model = layout['model']
    (output / 'model.bin').write_bytes(loaded_bytes(image, model['va'], model['size']))
    frozen_files[binary] = qemu_proof['qemu_sha256']
    _json(output / 'tools.json', dict(qemu_proof,
          build_tools=manifest['tools'], capture_tools=tool_hashes))
    native_tools = tool_closure()
    _json(output / 'native-tools.json', native_tools)
    for name in native_tools:
        target = output / 'native-tools' / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / 'tools' / name, target)
        frozen_files[ROOT / 'tools' / name] = frozen_files[target] = native_tools[name]
    qemu_source_identity = qemu_identity(binary, qemu_source)
    _json(output / 'qemu-source.json', qemu_source_identity)
    (output / 'qemu-version.txt').write_text(qemu_proof['qemu_version'])
    identity = dict(source_sha256=binding['source_sha256'], build_sha256=manifest_hash,
                    input_sha256=binding['input_sha256'], initial_sha256=initial_hash,
                    image_sha256=binding['image_sha256'], qemu=qemu_source_identity, tools=native_tools)
    _json(output / 'native-identity.json', identity)
    for name in ('input.json', 'binding.json', 'config.bin', 'model.bin', 'source-manifest.json',
                 'native-tools.json', 'qemu-source.json', 'qemu-version.txt', 'native-identity.json'):
        frozen_files[output / name] = sha(output / name)
    for path in (output / 'build-inputs').rglob('*'):
        if path.is_file():
            frozen_files[path] = sha(path)
    limits = capture_limits(dict(sample_ms=sample_ms, capture_timeout_seconds=timeout))
    witness = Witness(output / 'native-provenance.jsonl', byte_limit=limits['bytes'],
                      row_limit=limits['witness_rows'])
    witness.record('identity-before', identity=identity)
    report = dict(result_scope(bool(cut)), status='FAIL', capture_status='INCOMPLETE',
        verifier_version='a10-single-mode-v1', binding=binding, source_root=str(source_root),
        clock_profile='wallclock', scenario_budget=budget, sample_ms=sample_ms,
        qemu_request_merging=merging,
        build_manifest_sha256=manifest_hash,
        native_mode_verified=False, cut_observed=False)
    proc = sock = qmp = backend = server = None
    raw, serial = bytearray(), bytearray()
    decoder = FrameDecoder()
    trace = progress = consumption = b''
    started = time.monotonic()
    try:
        verify_unchanged(frozen_files)
        backend = Backend(output / 'disk.raw', output / 'nbd', cut=cut, phase=phase,
                          unflushed=unflushed, reverse_replies=reverse_replies, compress=True,
                          witness=witness.record, event_clock='host-monotonic-ns-v1')
        witness.record('backend-open', path=str(output / 'disk.raw'),
                       run_id=backend.meta['run_id'], sha256=backend.meta['disk_initial_sha256'],
                       size=backend.size)
        with tempfile.TemporaryDirectory(prefix='cyx-a10-') as temporary, \
                (output / 'qemu-stderr.log').open('wb') as errors:
            endpoint = str(Path(temporary) / 'q.sock')
            debugger = str(Path(temporary) / 'g.sock')
            server = Server(backend, Path(temporary) / 'disk.sock')
            witness.record('endpoint-created', endpoint=str(server.path), run_id=backend.meta['run_id'])
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            argv = [str(binary), '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
                '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
                '-S', '-display', 'none', '-monitor', 'none', '-global', 'virtio-mmio.force-legacy=false',
                '-drive', f'if=none,id=disk0,file=nbd:unix:{server.path},format=raw,cache=writeback',
                '-device', f'virtio-blk-device,drive=disk0,request-merging={merging}',
                '-netdev', f'socket,id=net0,listen=127.0.0.1:{port}',
                '-device', 'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:01',
                '-object', 'rng-random,id=rng0,filename=/dev/urandom',
                '-device', 'virtio-rng-device,rng=rng0',
                '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
                '-qmp', f'unix:{endpoint},server=on,wait=off',
                '-gdb', f'unix:{debugger},server=on,wait=off',
                '-kernel', str(output / 'node-a.elf'), '-no-reboot']
            _json(output / 'launch.json', dict(argv=argv, symbols=layout,
                termination='SIGKILL own QEMU; no clean QMP stop/quit/host flush'))
            deadline = time.monotonic() + timeout
            proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors, env=env())
            witness.record('spawn', pid=proc.pid)
            _json(output / 'native-context.json', dict(version=VERSION, capture_root=str(output),
                initial_source=str(initial_disk), binary=str(binary), binary_sha256=qemu_proof['qemu_sha256'],
                private_dir=temporary, private_mode=Path(temporary).stat().st_mode & 0o777,
                endpoints=dict(qmp=endpoint, gdb=debugger, nbd=str(server.path)),
                backend_run_id=backend.meta['run_id'], backing_path=str(output / 'disk.raw'),
                backing_sha256=backend.meta['disk_initial_sha256'], backing_size=backend.size,
                network_port=port, pid=proc.pid, host_platform=sys.platform))
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while True:
                require(proc.poll() is None, 'QEMU exited before handshake')
                if time.monotonic() >= deadline: raise TimeoutError('A10 QMP startup deadline')
                try: sock.connect(endpoint); break
                except (FileNotFoundError, ConnectionRefusedError): time.sleep(.01)
            qmp = NativeQmp(sock, witness, journal_path=output / 'qmp.jsonl',
                            byte_limit=limits['bytes'], command_limit=limits['commands'])
            require('QMP' in qmp.receive(deadline), 'missing QMP greeting')
            qmp.execute('qmp_capabilities')
            qmp.execute('query-status')
            cpus, memory = qmp.execute('query-cpus-fast'), qmp.execute('query-memory-size-summary')
            require(len(cpus) == 4 and memory['base-memory'] == 1024 ** 3, 'wrong native platform')
            _json(output / 'platform.json', dict(cpus=cpus, memory=memory))
            def save(name, address, size):
                path = output / name
                qmp.execute('pmemsave', dict(val=address, size=size, filename=str(path)))
                data = path.read_bytes()
                require(len(data) == size, 'short native memory capture: ' + name)
                witness.record('save', id=qmp.seq, name=name, size=size,
                               sha256=hashlib.sha256(data).hexdigest())
                return data
            def capture_diagnostics():
                for name, location in layout['diagnostics'].items():
                    save(name + '.bin', location['pa'], location['size'])
            dtb = save('dtb-header.bin', 0x40000000, 40)
            magic, size = struct.unpack_from('>2I', dtb)
            require(magic == 0xd00dfeed and 40 <= size <= 2 * 1024 * 1024, 'invalid native DTB')
            save('platform.dtb', 0x40000000, size)
            config = (output / 'config.bin').read_bytes()
            _json(output / 'config-injection.json', inject_config(debugger, config, layout['config']['pa']))
            witness.record('injection')
            require(save('config-observed.bin', layout['config']['pa'], 512) == config,
                    'A10 preboot injection not observed')
            qmp.execute('cont')
            qmp.execute('query-status')
            def read_serial():
                chunk = base64.b64decode(qmp.execute('ringbuf-read',
                    dict(device='cyxlog', size=1048576, format='base64')), validate=True)
                raw.extend(chunk)
                require(len(raw) <= 8 * 1024 * 1024, 'serial capture limit')
                for body in decoder.feed(chunk): serial.extend(body + b'\n')
                return chunk
            while time.monotonic() < deadline:
                require(proc.poll() is None, 'QEMU exited during A10')
                read_serial()
                if backend.cut_event.is_set():
                    report['cut_observed'] = True
                    # The volatile backend has already disconnected; this stop
                    # cannot turn pending guest sectors into durable bytes.
                    qmp.execute('stop')
                    qmp.execute('query-status')
                    trace = save('trace.bin', layout['capture']['pa'], layout['capture']['size'])
                    progress = save('progress.bin', layout['progress']['pa'], 512)
                    consumption = save('consumption.bin', layout['consumption']['pa'], 256)
                    capture_diagnostics()
                    report['capture_status'] = 'FAULT_CAPTURED'
                    break
                require(not any(word in serial for word in (b'PANIC', b'SMP_ERROR', b'FAIL')),
                        'native guest reported failure')
                progress = save('pending-progress.bin', layout['progress']['pa'], 512)
                for name in PENDING_DIAGNOSTICS:
                    location = layout['diagnostics'][name]
                    save('pending-' + name + '.bin', location['pa'], location['size'])
                if terminal_ready(progress, mode):
                    # Both selected endpoints have actually exited. Their file
                    # trace and progress are now immutable while VM keeps running.
                    trace = save('trace.bin', layout['capture']['pa'], layout['capture']['size'])
                    progress = save('progress.bin', layout['progress']['pa'], 512)
                    consumption = save('consumption.bin', layout['consumption']['pa'], 256)
                    capture_diagnostics()
                    require(save('trace-confirm.bin', layout['capture']['pa'], layout['capture']['size']) == trace
                            and save('progress-confirm.bin', layout['progress']['pa'], 512) == progress
                            and save('consumption-confirm.bin', layout['consumption']['pa'], 256) == consumption,
                            'A10 terminal capture changed during live read')
                    drained = False
                    # Ring capacity/read size are 1 MiB, total serial is 8 MiB.
                    # Eight attempts are a fail-closed cap, never proof of empty.
                    for _ in range(8):
                        if not read_serial() and not decoder.buffer:
                            drained = True
                            break
                    qmp.execute('query-status')
                    require(drained and decoder.loss == decoder.corrupt == 0 and not decoder.buffer,
                            'serial transport loss/corruption/trailing frame')
                    report['capture_status'] = 'TERMINAL_CAPTURED'
                    break
                time.sleep(interval)
            else:
                # Preserve raw state without inferring a successful terminal.
                trace = save('diagnostic-trace.bin', layout['capture']['pa'], layout['capture']['size'])
                capture_diagnostics()
                raise TimeoutError('A10 roles did not exit before bounded capture deadline')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, struct.error) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        # QMP stop/quit and graceful termination can trigger host-originated
        # FLUSH. Kill only our process, then discard NBD's remaining volatility.
        close_capture(proc, sock, server, qmp, backend, witness, report)
        (output / 'serial.bin').write_bytes(raw)
        (output / 'serial.txt').write_bytes(serial)
        report.update(qemu_exit=proc.returncode if proc else None,
                      elapsed_seconds=round(time.monotonic() - started, 3))
    try:
        require('error' not in report, report.get('error', 'native capture failed'))
        validate_capture_commands(qmp.capture_commands, cut_observed=report['cut_observed'])
        require(report['cut_observed'] == bool(cut), 'requested cut was not reached')
        require(code_source_map(source_root) == sources and sha(image_path) == binding['image_sha256']
                and tool_hashes == {name: sha(ROOT / 'tools' / name) for name in TOOL_NAMES},
                'source/image/capture tools changed during execution')
        verify_unchanged(frozen_files)
        require(attest_qemu(binary, qemu_source) == qemu_proof,
                'QEMU source attestation changed during execution')
        require(qemu_identity(binary, qemu_source) == qemu_source_identity
                and tool_closure() == native_tools, 'native provenance changed during execution')
        witness.record('final-disk', sha256=sha(output / 'disk.raw'),
                       size=(output / 'disk.raw').stat().st_size)
        witness.record('identity-after', identity=identity)
        report['nbd_trace'] = inspect_nbd(output / 'initial.raw', output / 'disk.raw', output / 'nbd')
        from v13_a10_fault_scope import mutation_scope, require_post_resume_cut
        report['mutation_scope'] = (require_post_resume_cut(output, cut) if cut
                                    else mutation_scope(output))
        oracle = inspect_filesystem(output / 'disk.raw')
        _json(output / 'disk-after.json', oracle)
        if report['cut_observed']:
            validate_cut_oracle(before, oracle, mode)
            report['status'] = 'NOT_RUN'
            try: report['partial_capture'] = decode(trace, binding)
            except ValueError as error: report['partial_capture_error'] = str(error)
            if 'partial_capture' in report:
                try:
                    report['consumption_boundary'] = verify_consumption(
                        consumption, binding, report['partial_capture'])
                except ValueError as error:
                    report['consumption_boundary_error'] = str(error)
        else:
            require(report['capture_status'] == 'TERMINAL_CAPTURED', 'missing actual native exits')
            report['storage_boot'] = verify_boot((output / 'storage-boot.bin').read_bytes(), before, bytes(serial))
            verified = verify_filesystem(trace, binding, progress, oracle, consumption)
            require(start['prior_object'] is None or tuple(verified['object']) == start['prior_object'],
                    'overwrite/recovery replaced the original file object')
            report.update(status='PASS', capture_status='VERIFIED', native_mode_verified=True,
                          observation=verified)
        credit = (output / 'control-credit.bin').read_bytes()
        overrun = (output / 'task-overrun.bin').read_bytes()
        report['other_runtime_diagnostics'] = dict(
            control_credit_failure_observed=bool(struct.unpack_from('<2Q', credit)[1]),
            control_credit_words=list(struct.unpack('<64Q', credit)),
            task_overrun_words=list(struct.unpack('<32Q', overrun)))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, struct.error) as error:
        report.update(status='FAIL', native_mode_verified=False,
                      error=type(error).__name__ + ': ' + str(error))
    report['artifacts'] = {str(path.relative_to(output)): sha(path)
        for path in sorted(output.rglob('*')) if path.is_file() and path.name != 'summary.json'}
    _json(output / 'summary.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--initial-disk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--mode', type=int, choices=(1, 2, 3, 4), required=True)
    parser.add_argument('--timeout', type=float,
                        help='diagnostic cap; default is the source-bound per-mode budget')
    parser.add_argument('--cut', type=int, default=0)
    parser.add_argument('--phase', choices=('before', 'after-ack'), default='before')
    parser.add_argument('--unflushed', choices=('drop', 'reverse-half'), default='drop')
    parser.add_argument('--reverse-replies', action='store_true')
    parser.add_argument('--sample-ms', type=int, default=100)
    parser.add_argument('--qemu', type=Path)
    parser.add_argument('--qemu-source', type=Path)
    parser.add_argument('--artifact-cache', type=Path, help='optional private content-addressed store for immutable build bytes only')
    args = parser.parse_args()
    try:
        report = run(args.build_manifest, args.initial_disk, args.output, mode=args.mode,
            source_root=args.source_root, timeout=args.timeout, cut=args.cut, phase=args.phase,
            unflushed=args.unflushed, reverse_replies=args.reverse_replies,
            artifact_cache=args.artifact_cache, sample_ms=args.sample_ms,
            qemu=args.qemu, qemu_source=args.qemu_source)
        print(json.dumps(report, indent=2))
        return 0 if report['status'] in ('PASS', 'NOT_RUN') else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, struct.error) as error:
        print('a10-runner: ' + type(error).__name__ + ': ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
