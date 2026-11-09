#!/usr/bin/env python3
"""One strict versioned reordered mode2/3 WRITE cut; no complete A10 PASS.

Independent static producer. v1 is not changed, dynamically rebound or used as
an execution identity. Shared helpers remain fixed caller-local imports.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,re,secrets,shutil,socket,struct,subprocess,sys,tempfile,time
from pathlib import Path
from run_v13_a10 import (ROOT, PENDING_DIAGNOSTICS, LAYOUT, TOOL_NAMES as BASE_TOOLS,
    config_bytes, profile, validate_build_profile, validate_start, inspect_filesystem,
    resolve_qemu, sha, read_json, code_source_map, safe_path, materialize, copy_sparse,
    loaded_bytes, attest_qemu, sample_interval, request_merging, result_scope,
    verify_unchanged, validate_cut_oracle, decode, verify_consumption, verify_boot,
    verify_filesystem, terminal_ready, env, FrameDecoder, _json, A10_DISK_NODE_NAME)
from run_v13_a02 import inject_config
from check_v13_fault_disk import inspect as inspect_nbd
from v13_fault_disk import Backend
from v16_a10_reordered_write_v3 import (Server, validate_capture_commands, validate_selector,
    bounded_inventory, BUILD_INPUTS, CAPTURE_DIRS)
from v13_a10_budget import scenario_budget
from verify_smp import require
TOOL_NAMES=BASE_TOOLS+('run_v16_a10_reordered_write_v3.py','v16_a10_reordered_write_v3.py','verify_v16_a10_reordered_write_v3.py')

def finalize_report(output,report):
    """Persist failure diagnostics even when the final artifact inventory fails."""
    try:
        artifacts={str(path.relative_to(output)):sha(path)
            for path,_ in sorted(bounded_inventory(output,allowed_dirs=CAPTURE_DIRS))
            if path.name!='summary.json'}
        report.update(artifacts=artifacts,artifact_inventory_complete=True)
    except (OSError,ValueError) as error:
        report.update(status='FAIL',native_mode_verified=False,artifacts=None,
            artifact_inventory_complete=False,
            artifact_inventory_error=type(error).__name__+': '+str(error))
        report.setdefault('error',report['artifact_inventory_error'])
    _json(output/'summary.json',report)
    return report


def run(build_manifest: Path, initial_disk: Path, output: Path, *, mode: int,
        source_root: Path = ROOT, timeout: float | None = None, cut: int = 0,
        phase: str = 'before', unflushed: str = 'drop', reverse_replies: bool = False,
        artifact_cache: Path | None = None, sample_ms: int = 100,
        qemu: Path | None = None, qemu_source: Path | None = None, expected_write: dict | None = None) -> dict:
    from v16_a10_reordered_write_v3 import Qmp as NativeQmp, Witness, close_capture
    from verify_v16_a10_reordered_write_v3 import VERSION, capture_limits, qemu_identity, tool_closure
    source_root = source_root.resolve(strict=True)
    require(type(mode) is int and mode in (2,3) and type(cut) is int and cut > 0 and phase == 'before'
            and unflushed == 'reverse-half' and reverse_replies is True and type(sample_ms) is int and sample_ms == 30000, 'v3 fixed WRITE profile')
    require(type(expected_write) is dict and expected_write.keys() == {'cut','offset','length','data_sha256'}
            and expected_write['cut'] == cut, 'v3 caller-selected WRITE required')
    validate_selector(expected_write)
    budget = scenario_budget(source_root, mode)
    require(timeout in (None, 1920) and budget['capture_timeout_seconds'] == 1920, 'v3 original source budget')
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
    _json(output / 'input.json', dict(test_id='A10', specification='1.3', mode=mode, caller_write=expected_write,
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
        cut=cut, cut_scope='post-arm-v1', phase=phase, unflushed=unflushed,
        reverse_replies=reverse_replies,
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
    for path,_ in bounded_inventory(output/'build-inputs',allowed_files=BUILD_INPUTS):
        frozen_files[path] = sha(path)
    limits = capture_limits(dict(sample_ms=sample_ms, capture_timeout_seconds=timeout))
    witness = Witness(output / 'native-provenance.jsonl', byte_limit=limits['bytes'],
                      row_limit=limits['witness_rows'])
    witness.record('identity-before', identity=identity)
    report = dict(result_scope(bool(cut)), status='FAIL', capture_status='INCOMPLETE',
        verifier_version='a10-reordered-single-write-v3', binding=binding, source_root=str(source_root),
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
                          witness=witness.record, event_clock='host-monotonic-ns-v1',
                          arm_input_sha256=binding['input_sha256'])
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
                '-drive', f'if=none,id=disk0,node-name={A10_DISK_NODE_NAME},file=nbd:unix:{server.path},format=raw,cache=writeback',
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
                termination='QMP quit only after actual NBD shutdown/close; complete QMP EOF and owned wait0'))
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
            # GDB's vm_stop path can flush before the first guest instruction.
            # Drain/ack that preparation, then arm without resetting raw ids.
            # Mount and recovery writes remain in scope from the first cont.
            backend.arm()
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
                server.completed.wait(interval)
            else:
                # Preserve raw state without inferring a successful terminal.
                trace = save('diagnostic-trace.bin', layout['capture']['pa'], layout['capture']['size'])
                capture_diagnostics()
                raise TimeoutError('A10 roles did not exit before bounded capture deadline')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError, struct.error) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        # v3 normal quit is permitted only after the one NBD accepted
        # connection is actually shut/closed. No host FLUSH can reach backing.
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
        report.update(status='FAIL',native_mode_verified=False)
        report.setdefault('error',type(error).__name__+': '+str(error))
    return finalize_report(output,report)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','build-manifest','initial-disk','output','qemu','qemu-source'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('cut','write-offset','write-length'):p.add_argument('--'+name,type=int,required=True)
    p.add_argument('--write-sha256',required=True)
    p.add_argument('--mode',type=int,choices=(2,3),required=True)
    a=p.parse_args()
    expected=dict(cut=a.cut,offset=a.write_offset,length=a.write_length,data_sha256=a.write_sha256)
    result=run(a.build_manifest,a.initial_disk,a.output,mode=a.mode,source_root=a.source_root,
        timeout=1920,cut=a.cut,phase='before',unflushed='reverse-half',reverse_replies=True,
        sample_ms=30000,qemu=a.qemu,qemu_source=a.qemu_source,expected_write=expected)
    from verify_v16_a10_reordered_write_v3 import verify_native_reordered_write_child
    checked=verify_native_reordered_write_child(a.output,source_root=a.source_root,build_manifest=a.build_manifest,
        qemu_binary=a.qemu,qemu_source=a.qemu_source,initial_disk=a.initial_disk,expected_write=expected,expected_mode=a.mode)
    print(json.dumps(dict(status='VERIFIED_NATIVE_WRITE_CUT',native_reordered_write_cut_custody_verified=True,
        native_acceptance_status='NOT_RUN',A10_complete=False,summary=checked.summary),indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
