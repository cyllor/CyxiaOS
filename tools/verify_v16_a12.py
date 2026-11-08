#!/usr/bin/env python3
"""Replay A12's native boot/discovery/auth/config/admission conjunction.

Version 1 supports the reviewed C4 normal-pair capture and genuine Local
admission. A13's remote STARTED/result/ACK/close predicate remains separate.
Producer verdicts, READY, client exit0, host fixtures and passive TLS packet
inspection cannot independently establish this result.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

from build_unified import (build_cache_context, cache_artifact, code_source_map,
                           parse_cargo_build_messages)
from check_prototype_evidence import require, sha256
from v16_a12_local import verify_local_admission
from v16_a12_pair import verify_pair_components
import verify_domains
import verify_unified

VERSION = 'v16-a12-local-native-v1'
ROOT = Path(__file__).resolve().parents[1]
# Fixed transitive local-module closure for the independent replay,
# including parsers and signature verification; never selected by a receipt.
VERIFIER_FILES = (
    'tools/build_unified.py',
    'tools/check_elf.py',
    'tools/check_prototype_evidence.py',
    'tools/check_v13_boot_disk.py',
    'tools/check_v13_disk.py',
    'tools/check_v13_filesystem.py',
    'tools/check_v13_preparation_stack.py',
    'tools/cluster_native_journal.py',
    'tools/decode_application_requests.py',
    'tools/decode_capture_provenance.py',
    'tools/decode_discovery.py',
    'tools/decode_local_requests.py',
    'tools/decode_replay_quiescing.py',
    'tools/decode_runtime_loop.py',
    'tools/decode_session_activity.py',
    'tools/decode_session_exits.py',
    'tools/discovery_capture.py',
    'tools/doctor.py',
    'tools/memory_v15_client.py',
    'tools/publication_cost.py',
    'tools/run_qemu.py',
    'tools/transport.py',
    'tools/v16_a12_local.py',
    'tools/v16_a12_pair.py',
    'tools/verify_domains.py',
    'tools/verify_smp.py',
    'tools/verify_unified.py',
    'tools/verify_unified_capture.py',
    'tools/verify_unified_disk.py',
    'tools/verify_v13_tcp.py',
    'tools/verify_v16_a12.py',
)
NORMAL_PROFILE = dict(fault='normal', leave=False, memory_probe=False,
                      selftest=True, service_fault='none',
                      service_fault_nodes={'a': 'none', 'b': 'none'},
                      storage_fault=False, unix_seconds=1794056286)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _json(path, maximum=4 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size <= maximum, 'missing/oversized JSON input')
    return json.loads(path.read_bytes(), object_pairs_hook=_unique)


def _path(root, relative, *, directory=False):
    require(type(relative) is str, 'relative artifact path required')
    pure = PurePosixPath(relative)
    require(relative and not pure.is_absolute() and '..' not in pure.parts
            and pure.as_posix() == relative and '\\' not in relative,
            'unsafe artifact path')
    path = root / relative
    require(path.resolve(strict=True).is_relative_to(root)
            and not any(p.is_symlink() for p in [path, *path.parents]),
            'linked/escaping artifact path')
    require(path.is_dir() if directory else path.is_file(), 'artifact type differs')
    return path


def _inventory(capture, summary):
    inventory = summary.get('evidence_sha256')
    require(type(inventory) is dict and 0 < len(inventory) <= 2000,
            'missing/oversized capture inventory')
    for relative, digest in inventory.items():
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest),
                'invalid capture SHA256')
        require(relative != 'summary.json', 'capture inventory hashes itself')
        path = _path(capture, relative)
        require(sha256(path) == digest, 'capture file hash differs: ' + relative)
    actual = {str(p.relative_to(capture)) for p in capture.rglob('*') if p.is_file()}
    require(actual == set(inventory) | {'summary.json'}, 'incomplete/extra capture inventory')
    return inventory


def _argv(capture, build, qemu_source):
    """Reject extra loader/config/device options, not only wrong -kernel."""
    ports, sockets = [], []
    for node, name in ((1, 'a'), (2, 'b')):
        folder = capture / f'node-{node}'
        launch = _json(folder / 'launch.json')
        argv = launch['argv']
        require(type(argv) is list and all(type(v) is str for v in argv), 'launch argv type')
        require(argv.count('-netdev') == argv.count('-qmp') == 1, 'launch endpoint count')
        link = argv[argv.index('-netdev') + 1]
        match = re.fullmatch(r'socket,id=net0,' + ('listen' if node == 1 else 'connect')
                             + r'=127\.0\.0\.1:([0-9]+)', link)
        require(match is not None and 1024 <= int(match[1]) <= 65535, 'native pair link differs')
        ports.append(int(match[1]))
        qmp = argv[argv.index('-qmp') + 1]
        endpoint = re.fullmatch(r'unix:([^,\x00]+/q' + str(node)
                                + r'\.sock),server=on,wait=off', qmp)
        require(endpoint is not None and Path(endpoint[1]).is_absolute(), 'QMP endpoint differs')
        sockets.append(str(Path(endpoint[1]).parent))
        expected = [str(qemu_source / 'build/qemu-system-aarch64'),
            '-machine', 'virt-10.2,gic-version=2,secure=off,virtualization=off',
            '-cpu', 'cortex-a53', '-smp', '4', '-m', '1024M', '-accel', 'tcg,thread=multi',
            '-S', '-display', 'none', '-monitor', 'none',
            '-global', 'virtio-mmio.force-legacy=false',
            '-drive', f'if=none,id=disk0,format=raw,file={folder / "disk.raw"},cache=writeback',
            '-device', 'virtio-blk-device,drive=disk0', '-netdev', link,
            '-device', f'virtio-net-device,id=eth0,netdev=net0,mac=02:00:00:00:00:0{node}',
            '-object', f'filter-dump,id=capture,netdev=net0,file={folder / "ethernet.pcap"}',
            '-chardev', 'ringbuf,id=cyxlog,size=1048576', '-serial', 'chardev:cyxlog',
            '-qmp', qmp, '-kernel', str(build['caller_paths'][f'node-{name}.elf']),
            '-no-reboot', '-object', 'rng-random,id=rng0,filename=/dev/urandom',
            '-device', 'virtio-rng-device,rng=rng0']
        require(argv == expected, 'unreviewed native launch option/order')
    require(ports[0] == ports[1] and sockets[0] == sockets[1], 'nodes are not the same native pair')


def _actor_join(join, task, bound_ms):
    require(join['actor'] == task['probe_object']
            and join['submitted_ns'] <= join['completion_ns'] <= join['original_deadline_ns'],
            'Local request actor/deadline does not match protected native task')
    # Both clocks originate from this node's Board clock. Exclude the same
    # millisecond conservatively; this does not synchronize the two nodes.
    require(bound_ms and join['submitted_ns'] // 1_000_000 > min(bound_ms),
            'Local admission was not observed after this node became BOUND')


def verify_capture(capture, *, source_root, build_manifest, formatter, qemu_source):
    source_root = Path(source_root).resolve(strict=True)
    capture = Path(capture).resolve(strict=True)
    require(capture.is_relative_to(source_root) and capture != source_root,
            'capture must be inside caller source root')
    _path(source_root, str(capture.relative_to(source_root)), directory=True)
    build_manifest = Path(build_manifest).resolve(strict=True)
    formatter = Path(formatter).resolve(strict=True)
    qemu_source = Path(qemu_source).resolve(strict=True)
    require(formatter.is_file() and os.access(formatter, os.X_OK), 'caller formatter is not executable')
    summary = _json(capture / 'summary.json')
    summary_sha = sha256(capture / 'summary.json')
    manifest_sha = sha256(build_manifest)
    require(summary.get('expect') == 'normal' and summary.get('nodes') == 2
            and summary.get('linked') is True and summary.get('entropy_device') is True
            and summary.get('reconnect') is False and summary.get('recover') is False
            and summary.get('clock_profile') == 'wallclock'
            and summary.get('tcg_threads') == 'multi' and summary.get('icount_shift') is None,
            'not the reviewed normal native pair scenario')
    inventory = _inventory(capture, summary)
    before = code_source_map(source_root)
    build = _json(build_manifest)
    require(build['code_source_map'] == before and build['profiles'] == NORMAL_PROFILE,
            'caller build is not the current reviewed normal source/profile')
    require(build['builder_sha256'] == sha256(source_root / 'tools/build_unified.py'),
            'builder source differs')
    require((capture / 'build-manifest.json').read_bytes() == build_manifest.read_bytes(),
            'capture chooses a different build')
    paths = {name: build_manifest.parent / name for name in
             ('node-a.elf', 'node-b.elf', 'node-a.pub', 'node-b.pub', 'task.elf')}
    cache = build_cache_context(source_root / 'target', source_root, before)
    require(build['build_cache'] == cache, 'build cache not derived from caller root/source')
    for node in ('a', 'b'):
        log = build_manifest.parent / f'kernel-{node}.log'
        require(sha256(log) == build['artifacts'][log.name]['sha256'], 'Cargo log differs')
        executable, out_dir = parse_cargo_build_messages(log.read_text())
        cache_artifact(executable, cache['effective'])
        cache_artifact(out_dir, cache['effective'])
    captured_sources = _json(capture / 'source-manifest.json')
    require(sha256(capture / 'source-manifest.json') == summary['source_manifest_sha256']
            and all(captured_sources.get(name) == value for name, value in before.items()),
            'capture native source differs')
    # These fixed tools actually produced/decoded the native capture. New A12
    # receipt/catalogue entrypoints were not executed during that earlier run.
    capture_tools = ('verify_unified.py', 'verify_domains.py', 'build_unified.py',
                     'check_elf.py', 'transport.py', 'check_v13_boot_disk.py',
                     'check_v13_disk.py', 'check_v13_filesystem.py',
                     'cluster_native_journal.py', 'verify_unified_capture.py',
                     'verify_v13_tcp.py', 'decode_discovery.py', 'discovery_capture.py',
                     'verify_unified_disk.py', 'verify_smp.py')
    for name in capture_tools:
        require(captured_sources.get('tools/' + name) == sha256(source_root / 'tools' / name),
                'bound capture tool changed: ' + name)
    publics = [paths['node-a.pub'], paths['node-b.pub']]
    binding = verify_unified.bind_build(build_manifest, paths['node-a.elf'],
                paths['node-b.elf'], publics, paths['task.elf'], 'normal')
    require(summary['build_binding'] == binding
            and summary['elf_sha256'] == sha256(paths['node-a.elf'])
            and summary['peer_elf_sha256'] == sha256(paths['node-b.elf']), 'capture image binding differs')
    qemu = verify_unified.attest_qemu(qemu_source / 'build/qemu-system-aarch64', qemu_source)
    require(qemu['qemu_pmu_patch_attested'] is True
            and all(summary.get(k) == v for k, v in qemu.items()), 'captured QEMU differs')
    formatter_sha = sha256(formatter)
    require(summary['formatter_sha256'] == formatter_sha, 'caller formatter differs')
    before_images = []
    with tempfile.TemporaryDirectory(prefix='cyx-a12-before-') as directory:
        for node in (1, 2):
            expected = _json(capture / f'node-{node}/disk-before.json')
            fresh = Path(directory) / f'node-{node}.raw'
            subprocess.run([str(formatter), str(fresh), expected['uuid']], check=True,
                           capture_output=True, timeout=30)
            require(fresh.stat().st_size == 512 * 1024 * 1024
                    and sha256(fresh) == expected['sha256'] and expected['boot_epoch'] == 0,
                    'fresh caller formatter does not reproduce captured boot0 image')
            before_images.append(dict(node=node, uuid=expected['uuid'], sha256=expected['sha256']))
    require(sha256(formatter) == formatter_sha, 'formatter changed during replay')
    context = dict(build, caller_paths=paths, caller_manifest_path=build_manifest)
    _argv(capture, context, qemu_source)
    paired = verify_pair_components(capture, source_root, context, qemu_source, inventory)
    local = verify_local_admission(capture, source_root, context, inventory)
    task_raw = (capture / 'node-1/final-DOMAIN_TASK_EVIDENCE.bin').read_bytes()
    task = verify_domains.parse_tasks(task_raw)
    require(task is not None and task['probe_entered'] and task['service_admitted'],
            'missing native ordinary actor admission')
    for join in local['joined_requests']:
        _actor_join(join, task, paired['nodes'][0]['bound_ms'])
    for component in (paired['used_capture_sha256'], local['rawfiles_used']):
        require(all(inventory.get(name) == value for name, value in component.items()),
                'component used uninventoried raw bytes')
    require(_inventory(capture, summary) == inventory
            and sha256(capture / 'summary.json') == summary_sha
            and sha256(build_manifest) == manifest_sha,
            'capture or caller build changed during A12 verification')
    require(code_source_map(source_root) == before, 'source changed during A12 verification')
    return dict(test_id='A12', native_acceptance_status='PASS',
                native_execution_verified=True, full_a12_verified=True,
                runtime_truth_attested=False, verifier_version=VERSION,
                admission_scope='legitimate-native-Local',
                after_local_bound_observed=True,
                compiled_source_sha256=build['code_source_sha256'],
                capture_summary_sha256=summary_sha,
                build_manifest_sha256=manifest_sha, qemu_sha256=qemu['qemu_sha256'],
                formatter_sha256=formatter_sha, before_images=before_images,
                pair_components=paired, local_admission=local,
                original_integration_status=summary['status'],
                original_integration_error=summary.get('error'),
                original_integration_rewritten=False, remote_lifecycle_verified=False,
                a13_a14_verified=False, other_runtime_failures_fixed=False)


def verify_native(receipt_directory, *, source_root=ROOT, build_manifest, formatter, qemu_source):
    root = Path(source_root).resolve(strict=True)
    directory = Path(receipt_directory).resolve(strict=True)
    require(directory.is_relative_to(root), 'A12 receipt outside source root')
    receipt = _json(directory / 'summary.json')
    require(set(receipt) == {'schema_version', 'test_id', 'verifier_version', 'capture',
                            'verifier_files_sha256', 'verification'}, 'A12 receipt keys differ')
    require(receipt['schema_version'] == 1 and receipt['test_id'] == 'A12'
            and receipt['verifier_version'] == VERSION, 'wrong A12 receipt version')
    expected = {name: sha256(root / name) for name in VERIFIER_FILES}
    require(receipt['verifier_files_sha256'] == expected, 'A12 fixed verifier source differs')
    capture = _path(root, receipt['capture'], directory=True)
    observed = verify_capture(capture, source_root=root, build_manifest=build_manifest,
                              formatter=formatter, qemu_source=qemu_source)
    require({name: sha256(root / name) for name in VERIFIER_FILES} == expected,
            'A12 verifier changed during replay')
    require(receipt['verification'] == observed, 'A12 receipt differs from independent raw replay')
    return observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--formatter', type=Path, required=True)
    parser.add_argument('--qemu-source', type=Path, required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capture', type=Path, help='replay actual capture and issue a new receipt')
    group.add_argument('--receipt', type=Path, help='independently verify existing receipt directory')
    parser.add_argument('--output', type=Path, help='new receipt directory for --capture')
    args = parser.parse_args(argv)
    try:
        root = args.source_root.resolve(strict=True)
        context = dict(source_root=root, build_manifest=args.build_manifest,
                       formatter=args.formatter, qemu_source=args.qemu_source)
        if args.capture:
            require(args.output is not None and not args.output.exists(), 'fresh --output required')
            verifier_files = {name: sha256(root / name) for name in VERIFIER_FILES}
            observed = verify_capture(args.capture, **context)
            require({name: sha256(root / name) for name in VERIFIER_FILES} == verifier_files,
                    'A12 verifier changed during receipt issuance')
            receipt = dict(schema_version=1, test_id='A12', verifier_version=VERSION,
                           capture=str(args.capture.resolve().relative_to(root)),
                           verifier_files_sha256=verifier_files,
                           verification=observed)
            args.output.mkdir(parents=True)
            with (args.output / 'summary.json').open('x') as f:
                json.dump(receipt, f, indent=2)
                f.write('\n')
        else:
            observed = verify_native(args.receipt, **context)
        print(json.dumps({k: observed[k] for k in ('test_id', 'native_acceptance_status',
                         'native_execution_verified', 'full_a12_verified', 'admission_scope',
                         'original_integration_status', 'remote_lifecycle_verified')}, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('a12-native: ' + str(error), file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
