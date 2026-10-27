#!/usr/bin/env python3
"""Execute the complete native A10 ordinary-file crash/recovery matrix."""
from __future__ import annotations
import argparse
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import uuid

from build_unified import code_source_map
from check_prototype_evidence import read_json
from doctor import ROOT, env
from run_v13_a10 import (TOOL_NAMES, resolve_qemu, run as run_mode, sample_interval,
                         validate_build_profile)
from verify_smp import require, sha
from verify_v13_a10 import decode
from verify_v13_a10_faults import overwrite_window
from verify_v13_a10_matrix import (LOSSES, PHASES, load_run, mutation_schedule, review,
                                   select_points)
from v13_a10_budget import scenario_budgets

MATRIX_TOOLS = TOOL_NAMES


def _json(path: Path, document):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n')
    temporary.replace(path)


def validate_progress(document: dict) -> list[str]:
    completed = document.get('completed')
    require(document.get('schema_version') == 1
            and document.get('status') in ('RUNNING', 'COMPLETE')
            and type(completed) is list
            and all(type(name) is str for name in completed)
            and len(completed) == len(set(completed)),
            'invalid A10 matrix progress')
    for name in completed:
        path = PurePosixPath(name)
        require(name not in ('', '.') and not path.is_absolute()
                and path.as_posix() == name and '..' not in path.parts,
                'unsafe A10 matrix progress path')
    abandoned = document.get('abandoned', [])
    require(type(abandoned) is list and all(type(name) is str for name in abandoned),
            'invalid A10 matrix abandoned attempts')
    return completed


def _archive_attempt(root: Path, directory: Path, name: str, progress: dict):
    archive = root / '_abandoned'
    index = len(progress.setdefault('abandoned', [])) + 1
    destination = archive / f'{index:06}' / name
    while destination.exists():
        index += 1
        destination = archive / f'{index:06}' / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(directory), str(destination))
    progress['abandoned'].append(str(destination.relative_to(root)))
    _json(root / 'progress.json', progress)


def _resume_request(root: Path, build_manifest: Path, sources: dict, tools: dict, *,
                    overwrite_points: str, recovery_points: str, timeout: float | None,
                    artifact_cache: Path | None, qemu_binary: Path, qemu_source: Path | None,
                    qemu_proof: dict, sample_ms: int) -> tuple[dict, dict, dict, Path | None]:
    request = json.loads((root / 'matrix-input.json').read_text())
    progress = json.loads((root / 'progress.json').read_text())
    validate_progress(progress)
    require(request.get('schema_version') == 1 and request.get('test_id') == 'A10'
            and request.get('specification') == '1.3'
            and request.get('overwrite_points') == overwrite_points
            and request.get('recovery_points') == recovery_points
            and request.get('phases') == list(PHASES)
            and request.get('losses') == list(LOSSES)
            and request.get('reverse_replies') is True
            and request.get('source_root') == str(ROOT)
            and request.get('build_manifest_sha256') == sha(build_manifest)
            and sha(root / 'build-manifest.json') == sha(build_manifest)
            and request.get('source_manifest_sha256') == sha(root / 'source-manifest.json')
            and json.loads((root / 'source-manifest.json').read_text()) == sources
            and request.get('tools') == tools
            and request.get('scenario_budgets') == scenario_budgets(ROOT)
            and request.get('sample_ms') == sample_ms
            and request.get('qemu_binary') == str(qemu_binary)
            and request.get('qemu_source') == (str(qemu_source) if qemu_source else None)
            and request.get('qemu_attestation') == qemu_proof
            and all(sha(root / 'tools' / name) == digest for name, digest in tools.items())
            and sha(root / 'formatted.raw') == request.get('formatted_disk_sha256')
            and sha(root / 'provision.log') == request.get('provision_log_sha256'),
            'A10 matrix resume request/evidence mismatch')
    require(timeout is None, 'A10 matrix uses fixed source-bound per-mode budgets')
    budgets = request['scenario_budgets']
    recorded_cache = request.get('immutable_artifact_cache')
    require(recorded_cache is None or type(recorded_cache) is str,
            'invalid recorded A10 artifact cache')
    if artifact_cache is not None:
        require(str(artifact_cache) == recorded_cache, 'A10 matrix resume artifact-cache mismatch')
    elif recorded_cache is not None:
        artifact_cache = Path(recorded_cache)
    return request, progress, budgets, artifact_cache


def _child(build_manifest: Path, initial: Path, output: Path, *, mode: int,
           budgets: dict, artifact_cache: Path | None, cut: int = 0,
           phase: str = 'before', loss: str = 'drop', qemu: Path | None = None,
           qemu_source: Path | None = None, sample_ms: int = 30_000) -> dict:
    timeout = budgets[str(mode)]['capture_timeout_seconds']
    result = run_mode(build_manifest, initial, output, mode=mode, timeout=timeout,
                      cut=cut, phase=phase, unflushed=loss, reverse_replies=True,
                      artifact_cache=artifact_cache, qemu=qemu, qemu_source=qemu_source,
                      sample_ms=sample_ms)
    expected = 'NOT_RUN' if cut else 'PASS'
    require(result['status'] == expected, f'{output.name} returned {result["status"]}')
    print(f'{output}: {expected}', flush=True)
    return result


def run(build_manifest: Path, output: Path, *, overwrite_points: str = 'all',
        recovery_points: str = 'all', timeout: float | None = None,
        artifact_cache: Path | None = None, resume: bool = False,
        qemu: Path | None = None, qemu_source: Path | None = None,
        sample_ms: int = 30_000) -> dict:
    require(timeout is None, 'A10 matrix uses fixed source-bound per-mode budgets')
    sample_interval(sample_ms)
    require(sample_ms == 30_000, 'A10 matrix requires the frozen low-observer sample interval')
    build_manifest = build_manifest.resolve(strict=True)
    output = output.resolve()
    if artifact_cache is not None:
        artifact_cache = artifact_cache.resolve()
    build = read_json(build_manifest)
    validate_build_profile(build)
    sources = code_source_map(ROOT)
    require(build['code_source_map'] == sources, 'matrix build/source mismatch')
    tools = {name: sha(ROOT / 'tools' / name) for name in MATRIX_TOOLS}
    if resume:
        preview = json.loads((output / 'matrix-input.json').read_text())
        if qemu is None:
            qemu = Path(preview.get('qemu_binary', ''))
        if qemu_source is None and preview.get('qemu_source'):
            qemu_source = Path(preview['qemu_source'])
    if qemu_source is not None:
        qemu_source = qemu_source.resolve(strict=True)
    qemu_binary, qemu_proof = resolve_qemu(qemu, qemu_source)
    require(qemu_proof.get('qemu_pmu_patch_attested') is True,
            'A10 matrix requires the source-attested QEMU PMU patch')
    if resume:
        require(output.is_dir(), 'A10 matrix resume output does not exist')
        request, progress, budgets, artifact_cache = _resume_request(
            output, build_manifest, sources, tools, overwrite_points=overwrite_points,
            recovery_points=recovery_points, timeout=timeout, artifact_cache=artifact_cache,
            qemu_binary=qemu_binary, qemu_source=qemu_source, qemu_proof=qemu_proof,
            sample_ms=sample_ms)
        progress['status'] = 'RUNNING'
        _json(output / 'progress.json', progress)
    else:
        require(not output.exists(), 'refuse to reuse A10 matrix output without --resume')
        budgets = scenario_budgets(ROOT)
        output.mkdir(parents=True, mode=0o700)
        shutil.copyfile(build_manifest, output / 'build-manifest.json')
        _json(output / 'source-manifest.json', sources)
        for name in MATRIX_TOOLS:
            target = output / 'tools' / name
            target.parent.mkdir(exist_ok=True)
            shutil.copyfile(ROOT / 'tools' / name, target)
        identity = uuid.uuid4().bytes
        formatted = output / 'formatted.raw'
        command = ['rustup', 'run', 'stable', 'cargo', 'run', '--locked', '--offline',
                   '-p', 'cyxia-prototype', '--example', 'prototype-disk', '--',
                   str(formatted), identity.hex()]
        provision = subprocess.run(command, cwd=ROOT, env=env(), capture_output=True,
                                   text=True, timeout=120)
        (output / 'provision.log').write_text(provision.stdout + provision.stderr)
        require(provision.returncode == 0, 'A10 matrix formatter failed')
        request = dict(schema_version=1, test_id='A10', specification='1.3',
                       build_manifest_sha256=sha(build_manifest), source_root=str(ROOT),
                       source_manifest_sha256=sha(output / 'source-manifest.json'),
                       filesystem_uuid=identity.hex(), overwrite_points=overwrite_points,
                       recovery_points=recovery_points, phases=list(PHASES), losses=list(LOSSES),
                       reverse_replies=True, scenario_budgets=budgets, tools=tools,
                       sample_ms=sample_ms, qemu_binary=str(qemu_binary),
                       qemu_source=str(qemu_source) if qemu_source else None,
                       qemu_attestation=qemu_proof,
                       formatted_disk_sha256=sha(formatted),
                       provision_log_sha256=sha(output / 'provision.log'),
                       immutable_artifact_cache=(str(artifact_cache)
                                                 if artifact_cache is not None else None))
        _json(output / 'matrix-input.json', request)
        progress = dict(schema_version=1, status='RUNNING', completed=[], abandoned=[])
        _json(output / 'progress.json', progress)
    report = dict(schema_version=1, status='FAIL', test_id='A10', A10_complete=False,
                  native_filesystem_fault_matrix_complete=False,
                  runtime_truth_attested=False)
    try:
        formatted = output / 'formatted.raw'
        completed = set(validate_progress(progress))
        visited = set()

        def child(name: str, initial: Path, *, mode: int, cut: int = 0,
                  phase: str = 'before', loss: str = 'drop') -> tuple[Path, dict]:
            directory = output / name
            expected = 'NOT_RUN' if cut else 'PASS'
            initial_hash = sha(initial)
            require(name not in visited, 'duplicate A10 matrix child name')
            visited.add(name)
            if name in completed:
                result, _ = load_run(directory, mode=mode, cut=cut, phase=phase, loss=loss,
                                     initial_sha256=initial_hash, status=expected, matrix=request)
                print(f'{directory}: RESUME {expected}', flush=True)
                return directory, result
            if directory.exists():
                try:
                    result, _ = load_run(directory, mode=mode, cut=cut, phase=phase, loss=loss,
                                         initial_sha256=initial_hash, status=expected,
                                         matrix=request)
                except (OSError, ValueError, RuntimeError, KeyError):
                    _archive_attempt(output, directory, name, progress)
                else:
                    progress['completed'].append(name)
                    completed.add(name)
                    _json(output / 'progress.json', progress)
                    print(f'{directory}: ADOPT {expected}', flush=True)
                    return directory, result
            result = _child(build_manifest, initial, directory, mode=mode, budgets=budgets,
                            artifact_cache=artifact_cache, cut=cut, phase=phase, loss=loss,
                            qemu=qemu_binary, qemu_source=qemu_source, sample_ms=sample_ms)
            progress['completed'].append(name)
            completed.add(name)
            _json(output / 'progress.json', progress)
            return directory, result

        prepare_dir, _ = child('prepare', formatted, mode=1)
        prepared = prepare_dir / 'disk.raw'
        probe_dir, probe = child('overwrite-probe', prepared, mode=2)
        probe_capture = decode((probe_dir / 'trace.bin').read_bytes(), probe['binding'])
        overwrite_rows = mutation_schedule(probe_dir)
        overwrite_window(probe_capture, overwrite_rows)
        selected_overwrite = select_points(overwrite_points, overwrite_rows)
        child('cache-eviction', probe_dir / 'disk.raw', mode=4)

        for point in selected_overwrite:
            for phase in PHASES:
                for loss in LOSSES:
                    case_name = f'overwrite/p{point:04}-{phase}-{loss}'
                    cut_dir, _ = child(case_name + '/cut', prepared, mode=2, cut=point,
                                       phase=phase, loss=loss)
                    damaged = cut_dir / 'disk.raw'
                    recovery_probe, _ = child(case_name + '/recovery-probe', damaged, mode=3)
                    recovery_rows = mutation_schedule(recovery_probe)
                    selected_recovery = select_points(recovery_points, recovery_rows)
                    for recovery_point in selected_recovery:
                        for recovery_phase in PHASES:
                            for recovery_loss in LOSSES:
                                recovery_name = (case_name +
                                    f'/recovery/r{recovery_point:04}-{recovery_phase}-{recovery_loss}')
                                recovery_cut, _ = child(
                                    recovery_name + '/cut', damaged, mode=3,
                                    cut=recovery_point, phase=recovery_phase,
                                    loss=recovery_loss)
                                child(recovery_name + '/final', recovery_cut / 'disk.raw', mode=3)

        require(code_source_map(ROOT) == sources
                and tools == {name: sha(ROOT / 'tools' / name) for name in MATRIX_TOOLS}
                and sha(build_manifest) == request['build_manifest_sha256'],
                'matrix source/tools/build changed during execution')
        require(completed == visited, 'A10 matrix progress contains unexpected children')
        report = review(output)
        progress['status'] = 'COMPLETE'
        _json(output / 'progress.json', progress)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    report['matrix_input_sha256'] = sha(output / 'matrix-input.json')
    report['build_manifest_sha256'] = sha(output / 'build-manifest.json')
    report['progress_sha256'] = sha(output / 'progress.json')
    report['abandoned_attempts'] = list(progress.get('abandoned', []))
    report['child_summaries'] = {
        str(path.relative_to(output)): sha(path)
        for path in sorted(output.rglob('summary.json')) if path != output / 'summary.json'
    }
    _json(output / 'summary.json', report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--overwrite-points', default='all',
                        help='all, flushes, or comma-separated observed overwrite points')
    parser.add_argument('--recovery-points', default='all',
                        help='all, flushes, or comma-separated observed recovery points')
    parser.add_argument('--timeout', type=float,
                        help='per-run seconds; omitted on resume to reuse the recorded value')
    parser.add_argument('--artifact-cache', type=Path)
    parser.add_argument('--qemu', type=Path)
    parser.add_argument('--qemu-source', type=Path)
    parser.add_argument('--sample-ms', type=int, default=30_000)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    try:
        result = run(args.build_manifest, args.output,
                     overwrite_points=args.overwrite_points,
                     recovery_points=args.recovery_points, timeout=args.timeout,
                     artifact_cache=args.artifact_cache, resume=args.resume,
                     qemu=args.qemu, qemu_source=args.qemu_source,
                     sample_ms=args.sample_ms)
        print(json.dumps(result, indent=2))
        diagnostic = args.overwrite_points != 'all' or args.recovery_points != 'all'
        return 0 if result['status'] == 'PASS' or (diagnostic and result['status'] == 'NOT_RUN') else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyError) as error:
        print('a10-matrix: ' + type(error).__name__ + ': ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
