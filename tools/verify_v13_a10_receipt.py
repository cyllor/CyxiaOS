#!/usr/bin/env python3
"""Replay A10 matrix bytes with fixed local decoders, without native promotion.

The matrix coverage checker validates child inventories but trusts their derived
observations. This adapter additionally reconstructs the NBD durability stream,
filesystem oracles, protected file replies, receipt consumption and boot state.
Archive code is never imported or executed. Native launch/capture provenance is
not yet independently reviewed here, so even a complete raw matrix stays NOT_RUN
for catalogue admission. A host fixture can exercise these contracts, not prove
that a native guest executed them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from build_unified import code_source_map
from check_prototype_evidence import read_json, require, safe_path, sha256
from check_v13_fault_disk import inspect as inspect_nbd, trace_encoding
from check_v13_filesystem import inspect as inspect_filesystem
from doctor import ROOT
from run_v13_a10 import (TOOL_NAMES, config_bytes, validate_build_profile,
                         validate_cut_oracle, validate_start)
from transport import FrameDecoder
from verify_unified import (PATCHED_QEMU_SOURCE_SHA256, PINNED_QEMU_COMMIT,
                            PINNED_QEMU_PATCH_SHA256)
from verify_v13_a10 import decode, verify_boot, verify_consumption, verify_filesystem
from verify_v13_a10_matrix import (LOSSES, PHASES, mutation_schedule, review,
                                   select_points)

VERSION = 'a10-offline-v1'
NATIVE_ADMISSION_BLOCKERS = ('native launch, preboot injection and QMP capture provenance '
                             'do not yet have a reviewed independent A10 receipt contract',)


def document(root: Path, name: str):
    try:
        return read_json(safe_path(root, name))
    except ValueError as error:
        raise ValueError(f'A10 {name}: {error}') from error


def normalized(value):
    """Match JSON's representation of tuples in independently derived results."""
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


def verify_matrix_identity(root: Path, source_root: Path) -> dict:
    request = document(root, 'matrix-input.json')
    build = document(root, 'build-manifest.json')
    sources = document(root, 'source-manifest.json')
    validate_build_profile(build)
    require(build.get('profiles', {}).get('service_fault', 'none') == 'none',
            'A10 matrix has an unrelated service fault profile')
    require(request.get('build_manifest_sha256') == sha256(safe_path(root, 'build-manifest.json'))
            and request.get('source_manifest_sha256') == sha256(safe_path(root, 'source-manifest.json'))
            and build.get('code_source_map') == sources == code_source_map(source_root),
            'A10 matrix build/source identity mismatch')
    encoded = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()
    require(build.get('code_source_sha256') == hashlib.sha256(encoded).hexdigest(),
            'A10 matrix source digest mismatch')
    require(build.get('builder_sha256') == sha256(safe_path(source_root, 'tools/build_unified.py')),
            'A10 matrix builder revision changed')
    expected_tools = {name: sha256(safe_path(ROOT, 'tools/' + name)) for name in TOOL_NAMES}
    require(request.get('tools') == expected_tools,
            'A10 matrix tool revisions are not the fixed reviewed local tools')
    for name, digest in expected_tools.items():
        require(sha256(safe_path(root, 'tools/' + name)) == digest
                and sha256(safe_path(source_root, 'tools/' + name)) == digest,
                'A10 matrix archived/caller tool mismatch: ' + name)
    proof = request.get('qemu_attestation', {})
    require(type(proof) is dict and proof.get('qemu_pmu_patch_attested') is True
            and proof.get('qemu_source_commit') == PINNED_QEMU_COMMIT
            and proof.get('qemu_patch_sha256') == PINNED_QEMU_PATCH_SHA256
            and proof.get('qemu_source_sha256') == PATCHED_QEMU_SOURCE_SHA256
            and type(proof.get('qemu_sha256')) is str
            and re.fullmatch(r'[0-9a-f]{64}', proof['qemu_sha256']) is not None,
            'A10 matrix lacks the pinned QEMU source/patch identity')
    # Do not execute the receipt-selected qemu_binary, qemu_source or tools.
    # Recorded identities alone do not attest their use by a native process.
    return request


def replay_transport(root: Path) -> dict:
    start, inputs = document(root, 'nbd/start.json'), document(root, 'input.json')
    # Coverage is indexed by the frozen input, while durability reconstruction
    # uses the backend's recorded policy. Bind both before accepting that row;
    # rehashing input/summary must not relabel one loss mode as another.
    policy = ('cut', 'phase', 'unflushed')
    require(all(key in inputs and key in start
                and type(inputs[key]) is type(start[key]) and inputs[key] == start[key]
                for key in policy), 'A10 raw NBD fault policy differs from frozen input')
    compressed = trace_encoding(root / 'nbd') == 'gzip'
    for name in ('events.jsonl', 'requests.bin'):
        safe_path(root, 'nbd/' + name + ('.gz' if compressed else ''))
    if compressed or (root / 'nbd/capture.json').exists():
        safe_path(root, 'nbd/capture.json')
    return inspect_nbd(safe_path(root, 'initial.raw'), safe_path(root, 'disk.raw'), root / 'nbd')


def replay_serial(root: Path, *, complete: bool) -> bytes:
    raw = safe_path(root, 'serial.bin')
    require(raw.stat().st_size <= 8 * 1024 * 1024, 'A10 serial capture limit')
    decoder = FrameDecoder()
    lines = bytearray()
    with raw.open('rb') as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b''):
            for body in decoder.feed(chunk):
                lines.extend(body + b'\n')
    require(bytes(lines) == safe_path(root, 'serial.txt').read_bytes(),
            'A10 decoded serial differs from framed raw capture')
    if complete:
        require(decoder.loss == decoder.corrupt == 0, 'A10 serial transport loss/corruption')
        require(not decoder.buffer, 'incomplete A10 serial frame at capture end')
    return bytes(lines)


def replay_file_observation(root: Path, binding: dict, before: dict, after: dict, *, cut: bool) -> dict:
    """Pure byte/oracle replay; the caller must separately bind their provenance."""
    trace = safe_path(root, 'trace.bin').read_bytes()
    consumption = safe_path(root, 'consumption.bin').read_bytes()
    if cut:
        validate_cut_oracle(before, after, binding['mode'])
        result = {}
        try:
            partial = decode(trace, binding)
        except ValueError as error:
            result['partial_capture_error'] = str(error)
        else:
            result['partial_capture'] = partial
            try:
                result['consumption_boundary'] = verify_consumption(consumption, binding, partial)
            except ValueError as error:
                result['consumption_boundary_error'] = str(error)
        return result
    serial = replay_serial(root, complete=True)
    boot = verify_boot(safe_path(root, 'storage-boot.bin').read_bytes(), before, serial)
    observed = verify_filesystem(trace, binding, safe_path(root, 'progress.bin').read_bytes(),
                                 after, consumption)
    start = validate_start(before, binding['mode'])
    require(start['prior_object'] is None or tuple(observed['object']) == start['prior_object'],
            'A10 overwrite/recovery replaced the original file object')
    return dict(storage_boot=boot, observation=observed)


def verify_child_identity(root: Path, matrix: dict) -> None:
    summary = document(root, 'summary.json')
    artifacts = summary.get('artifacts')
    required = {'initial.raw', 'disk.raw', 'trace.bin', 'progress.bin', 'consumption.bin',
                'binding.json', 'input.json', 'source-manifest.json', 'build-manifest.json',
                'node-a.elf', 'service-a.elf', 'task.elf', 'config.bin', 'config-observed.bin',
                'serial.bin', 'serial.txt', 'disk-before.json', 'disk-after.json', 'tools.json'}
    require(type(artifacts) is dict and required <= artifacts.keys(),
            'incomplete A10 raw child artifact inventory')
    actual_names = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'A10 child archive contains a symlink')
        if path.is_file() and path.name != 'summary.json':
            actual_names.add(path.relative_to(root).as_posix())
    require(actual_names == set(artifacts), 'A10 child artifact inventory changed')
    for name, digest in artifacts.items():
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None
                and sha256(safe_path(root, name)) == digest, 'A10 child artifact changed: ' + name)
    build = document(root, 'build-manifest.json')
    require(sha256(safe_path(root, 'build-manifest.json')) == matrix['build_manifest_sha256']
            and sha256(safe_path(root, 'source-manifest.json')) == matrix['source_manifest_sha256'],
            'A10 child build/source identity mismatch')
    for name in ('node-a.elf', 'service-a.elf', 'task.elf'):
        require(build.get('artifacts', {}).get(name, {}).get('sha256') == sha256(safe_path(root, name)),
                'A10 child built artifact mismatch: ' + name)
    binding, inputs = document(root, 'binding.json'), document(root, 'input.json')
    require(binding == summary.get('binding')
            and binding.get('input_sha256') == sha256(safe_path(root, 'input.json'))
            and binding.get('source_sha256') == matrix['source_manifest_sha256']
            and binding.get('image_sha256') == sha256(safe_path(root, 'node-a.elf'))
            and binding.get('uuid') == inputs.get('uuid') == matrix['filesystem_uuid']
            and binding.get('mode') == inputs.get('mode')
            and binding.get('boot_epoch') == inputs.get('expected_boot_epoch')
            and binding.get('nonce') == inputs.get('nonce')
            and inputs.get('initial_disk_sha256') == sha256(safe_path(root, 'initial.raw')),
            'A10 child protected binding mismatch')
    require(safe_path(root, 'config.bin').read_bytes()
            == safe_path(root, 'config-observed.bin').read_bytes() == config_bytes(binding),
            'A10 child observed config mismatch')


def replay_child(root: Path, matrix: dict) -> dict:
    verify_child_identity(root, matrix)
    summary = document(root, 'summary.json')
    binding = summary['binding']
    cut = bool(summary['cut_observed'])
    transport = replay_transport(root)
    require(normalized(transport) == summary.get('nbd_trace'), 'A10 derived NBD observation changed')
    before = inspect_filesystem(safe_path(root, 'initial.raw'))
    after = inspect_filesystem(safe_path(root, 'disk.raw'))
    require(normalized(before) == document(root, 'disk-before.json')
            and normalized(after) == document(root, 'disk-after.json'),
            'A10 derived disk oracle changed')
    start = validate_start(before, binding['mode'])
    require(binding['boot_epoch'] == start['boot_epoch'] and binding['uuid'] == start['uuid'],
            'A10 derived starting volume identity changed')
    observed = replay_file_observation(root, binding, before, after, cut=cut)
    derived_keys = {'storage_boot', 'observation', 'partial_capture', 'partial_capture_error',
                    'consumption_boundary', 'consumption_boundary_error'}
    require({key: summary[key] for key in derived_keys if key in summary} == normalized(observed),
            'A10 derived file observation changed')
    require((transport['cut'] is not None) == cut, 'A10 actual cut differs from child summary')
    # The fixed coverage reviewer consumes this projection only after every
    # derived field it relies on has been rebuilt from raw bytes.
    return summary


def verify_matrix_receipt(directory: Path, *, source_root: Path = ROOT) -> dict:
    root, project = Path(directory).resolve(strict=True), Path(source_root).resolve(strict=True)
    matrix = verify_matrix_identity(root, project)
    checked = set()

    def child(name):
        require(name not in checked, 'duplicate A10 raw child')
        safe_path(root, name + '/summary.json')
        checked.add(name)
        replay_child(root / name, matrix)

    for name in ('prepare', 'overwrite-probe', 'cache-eviction'):
        child(name)
    overwrite_rows = mutation_schedule(root / 'overwrite-probe')
    for point in select_points(matrix['overwrite_points'], overwrite_rows):
        for phase in PHASES:
            for loss in LOSSES:
                name = f'overwrite/p{point:04}-{phase}-{loss}'
                child(name + '/cut')
                child(name + '/recovery-probe')
                recovery_rows = mutation_schedule(root / name / 'recovery-probe')
                for recovery in select_points(matrix['recovery_points'], recovery_rows):
                    for recovery_phase in PHASES:
                        for recovery_loss in LOSSES:
                            prefix = name + f'/recovery/r{recovery:04}-{recovery_phase}-{recovery_loss}'
                            child(prefix + '/cut')
                            child(prefix + '/final')
    coverage = review(root)
    return dict(schema_version=1, test_id='A10', verifier_version=VERSION,
                status='NOT_RUN', native_acceptance_status='NOT_RUN',
                raw_matrix_verified=True, replayed_children=len(checked),
                matrix_coverage=coverage, native_execution_verified=False,
                native_filesystem_fault_matrix_complete=False, runtime_truth_attested=False,
                native_admission_blockers=list(NATIVE_ADMISSION_BLOCKERS),
                scope='Raw A10 matrix reconstruction only; native catalogue admission remains closed.')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        result = verify_matrix_receipt(args.evidence, source_root=args.source_root)
        print(json.dumps(result, indent=2))
        return 2
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        print('a10-receipt: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
