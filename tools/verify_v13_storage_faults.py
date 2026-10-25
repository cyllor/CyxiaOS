#!/usr/bin/env python3
"""Native boot/journal faults through volatile NBD; not the complete A10 matrix.

QEMU performs every filesystem operation. Host code only supplies block storage,
injects faults, captures bytes and independently reads the resulting images.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import uuid
from build_unified import code_source_map
from check_v13_disk import inspect as inspect_disk
from check_v13_fault_disk import inspect as inspect_trace, read_events
from doctor import ROOT, env
from v13_fault_disk import Backend, Server
from verify_smp import require, sha
from verify_v13_storage import boot, validate, validate_recovery


def copy_sparse(source: Path, target: Path):
    with source.open('rb') as input, target.open('xb') as output:
        output.truncate(source.stat().st_size)
        while block := input.read(1024*1024):
            if block != bytes(len(block)):
                output.write(block)
            else:
                output.seek(len(block), 1)


def validate_schedule(rows, native):
    require(sum(row['kind'] == 3 for row in rows) == native['flushes'], 'host or missing FLUSH in native trace')
    require([row['mutation'] for row in rows] == list(range(1, len(rows)+1))
            and sum(row['kind'] == 1 for row in rows) == native['writes']*8
            and all((row['kind'] == 1 and row['length'] == 512 and row['offset'] % 512 == 0)
                    or (row['kind'] == 3 and row['offset'] == row['length'] == 0) for row in rows),
            'merged or incomplete native sector schedule')


def mutation_schedule(directory):
    rows = read_events(directory/'nbd')
    return [{key: row[key] for key in ('mutation', 'kind', 'offset', 'length')}
            for row in rows if row['event'] == 'request' and row['mutation']]


def native(elf, initial, disk, directory, timeout, **fault):
    directory.mkdir()
    backend = Backend(disk, directory/'nbd', **fault)
    with tempfile.TemporaryDirectory(prefix='cyx-nbd-') as temporary:
        server = Server(backend, Path(temporary)/'disk.sock')
        try:
            observation = boot(elf, disk, directory/'guest', timeout,
                backend_uri=f'nbd:unix:{server.path}', cut_event=backend.cut_event)
        finally:
            server.close()
        require(server.error is None, f'NBD backend failed: {server.error}')
    trace = inspect_trace(initial, disk, directory/'nbd')
    (directory/'trace-summary.json').write_text(json.dumps(trace, indent=2)+'\n')
    return observation, trace


def run(elf: Path, build_manifest: Path, output: Path, *, points='flushes', timeout=120,
        source_root: Path = ROOT):
    require(1 <= timeout <= 300, 'invalid native deadline')
    elf, build_manifest, output = elf.resolve(strict=True), build_manifest.resolve(strict=True), output.resolve()
    require(not output.exists(), 'refuse to overwrite evidence')
    build = json.loads(build_manifest.read_text())
    source_root = source_root.resolve(strict=True)
    source = code_source_map(source_root)
    require(build['version'] == 1 and build['profile'] == 'storage-v13-selftest'
            and build['elf_sha256'] == sha(elf) and build['code_source_map'] == source,
            'storage source/build/image mismatch')
    output.mkdir(parents=True)
    (output/'build-manifest.json').write_bytes(build_manifest.read_bytes())
    tool_names = ['verify_v13_storage_faults.py', 'verify_v13_storage.py', 'v13_fault_disk.py',
                  'check_v13_fault_disk.py', 'check_v13_disk.py', 'check_elf.py', 'run_qemu.py',
                  'transport.py', 'doctor.py', 'verify_smp.py', 'build_unified.py']
    tool_hashes = {name: sha(ROOT/'tools'/name) for name in tool_names}
    report = dict(version=1, status='FAIL', scope='native-boot-journal-faults',
                  elf_sha256=sha(elf), build_manifest_sha256=sha(build_manifest), tools=tool_hashes,
                  source_root=str(source_root),
                  native_powercut_verified=False, native_boot_fault_matrix_complete=False,
                  native_filesystem_fault_matrix_complete=False, A10_complete=False,
                  runtime_truth_attested=False, cases=[])
    try:
        identity = uuid.uuid4().bytes
        formatted = output/'formatted.raw'
        command = ['cargo', 'run', '--locked', '--offline', '-p', 'cyxia-prototype', '--example',
                   'prototype-disk', '--', str(formatted), identity.hex()]
        provision = subprocess.run(command, cwd=source_root,
            env=dict(env(), CARGO_TARGET_DIR=str(ROOT/'target')), capture_output=True, text=True, timeout=60)
        (output/'provision.log').write_text(provision.stdout+provision.stderr)
        require(provision.returncode == 0, 'formatter failed')
        base = output/'boot-1.raw'; copy_sparse(formatted, base)
        observed, trace = native(elf, formatted, base, output/'boot-1', timeout)
        report['boot_1'] = validate(*observed, 1, identity)
        validate_schedule(mutation_schedule(output/'boot-1'), report['boot_1'])
        report['boot_1']['independent_disk'] = before = inspect_disk(base)
        require(before['boot_epoch'] == 1 and before['last_commit_lsn'] == 6, 'wrong first durable boot')
        probe = output/'probe.raw'; copy_sparse(base, probe)
        observed, trace = native(elf, base, probe, output/'probe', timeout, reverse_replies=True)
        report['probe'] = validate_recovery(*observed, before)
        report['probe']['trace'] = trace
        mutations = mutation_schedule(output/'probe')
        validate_schedule(mutations, report['probe'])
        available = [row['mutation'] for row in mutations]
        selected = available if points == 'all' else [row['mutation'] for row in mutations if row['kind'] == 3] if points == 'flushes' else [int(value) for value in points.split(',')]
        require(selected and len(selected) == len(set(selected)) and set(selected) <= set(available), 'invalid/unobserved cut points')
        report['observed_mutation_boundaries'] = [{key: row[key] for key in ('mutation', 'kind', 'offset', 'length')} for row in mutations]
        report['selected_points'] = selected
        for point in selected:
            for phase in ('before', 'after-ack'):
                for unflushed in ('drop', 'reverse-half'):
                    name = f'cut-{point:04}-{phase}-{unflushed}'
                    case = output/name; case.mkdir()
                    damaged = case/'cut.raw'; copy_sparse(base, damaged)
                    _, fault_trace = native(elf, base, damaged, case/'cut', timeout,
                        cut=point, phase=phase, unflushed=unflushed, reverse_replies=True)
                    require(mutation_schedule(case/'cut') == mutations[:point], 'native cut mutation prefix changed')
                    durable = inspect_disk(damaged)
                    require(durable['uuid'] == identity.hex() and durable['boot_epoch'] in (1, 2)
                            and durable['last_commit_lsn'] == (6 if durable['boot_epoch'] == 1 else 10),
                            'cut did not preserve a valid acknowledged prefix')
                    recovered = case/'recovered.raw'; copy_sparse(damaged, recovered)
                    observed, recovery_trace = native(elf, damaged, recovered, case/'recovery', timeout, reverse_replies=True)
                    recovered_observation = validate_recovery(*observed, durable)
                    validate_schedule(mutation_schedule(case/'recovery'), recovered_observation)
                    after = inspect_disk(recovered)
                    require(after['boot_epoch'] == recovered_observation['epoch']
                            and after['last_commit_lsn'] == recovered_observation['commit_lsn']
                            and after['uuid'] == identity.hex(), 'recovered disk disagrees with native evidence')
                    report['cases'].append(dict(name=name, point=point, phase=phase, unflushed=unflushed,
                        cut_trace=fault_trace, durable_prefix=durable, recovery=recovered_observation,
                        recovery_trace=recovery_trace, recovered_disk=after))
                    (output/'progress.json').write_text(json.dumps(report, indent=2)+'\n')
                    print(f'{name}: recovered BootEpoch {after["boot_epoch"]}, LSN {after["last_commit_lsn"]}', flush=True)
        require(source == code_source_map(source_root) and sha(elf) == report['elf_sha256']
                and tool_hashes == {name: sha(ROOT/'tools'/name) for name in tool_names}, 'source/image/tools changed during capture')
        report.update(status='PASS', native_powercut_verified=True,
                      native_boot_fault_matrix_complete=set(selected) == set(available))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        report['error'] = type(error).__name__+': '+str(error)
    report['artifacts'] = {str(path.relative_to(output)):sha(path) for path in sorted(output.rglob('*'))
                           if path.is_file() and path.name not in ('summary.json', 'progress.json')}
    (output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--points', default='flushes', help='all, flushes, or comma-separated observed mutation indices')
    parser.add_argument('--source-root', type=Path, default=ROOT, help='exact source checkout used for the storage build')
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    result = run(args.elf, args.build_manifest, args.output, points=args.points, timeout=args.timeout,
                 source_root=args.source_root)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)
