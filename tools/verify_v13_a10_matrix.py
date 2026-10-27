"""Independently review an executed A10 ordinary-filesystem fault matrix."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

from check_v13_fault_disk import read_events
from doctor import ROOT
from verify_smp import require, sha
from verify_v13_a10 import decode
from verify_v13_a10_faults import overwrite_window
from v13_a10_budget import scenario_budgets

PHASES = ('before', 'after-ack')
LOSSES = ('drop', 'reverse-half')


def mutation_schedule(directory: Path) -> list[dict]:
    rows = read_events(directory / 'nbd')
    result = [{key: row[key] for key in ('mutation', 'kind', 'offset', 'length')}
              for row in rows if row['event'] == 'request' and row['mutation']]
    require(result and [row['mutation'] for row in result] == list(range(1, len(result) + 1)),
            'missing/noncontiguous matrix mutation schedule')
    return result


def select_points(spec: str, rows: list[dict], allowed: list[int] | None = None) -> list[int]:
    available = [row['mutation'] for row in rows]
    if allowed is not None:
        require(allowed and len(allowed) == len(set(allowed)) and set(allowed) <= set(available),
                'invalid declared mutation window')
        available = list(allowed)
    if spec == 'all':
        selected = available
    elif spec == 'flushes':
        selected = [row['mutation'] for row in rows
                    if row['mutation'] in available and row['kind'] == 3]
    else:
        try:
            selected = [int(value) for value in spec.split(',')]
        except ValueError as error:
            raise ValueError('invalid matrix point selector') from error
    require(selected and len(selected) == len(set(selected)) and set(selected) <= set(available),
            'invalid/unobserved matrix points')
    return selected


def _files(directory: Path) -> dict[str, str]:
    return {str(path.relative_to(directory)): sha(path) for path in sorted(directory.rglob('*'))
            if path.is_file() and path.name != 'summary.json'}


def load_run(directory: Path, *, mode: int, cut: int, phase: str, loss: str,
             initial_sha256: str, status: str, matrix: dict) -> tuple[dict, dict]:
    summary_path = directory / 'summary.json'
    require(summary_path.is_file(), 'missing A10 child summary: ' + str(directory))
    summary = json.loads(summary_path.read_text())
    input_path = directory / 'input.json'
    run_input = json.loads(input_path.read_text())
    binding = json.loads((directory / 'binding.json').read_text())
    tools = json.loads((directory / 'tools.json').read_text())
    budget = matrix.get('scenario_budgets', {}).get(str(mode), {})
    qemu = {key: value for key, value in tools.items()
            if key not in ('build_tools', 'capture_tools')}
    require(summary.get('test_id') == 'A10' and summary.get('A10_complete') is False
            and summary.get('native_filesystem_fault_matrix_complete') is False
            and summary.get('status') == status and summary.get('binding') == binding
            and binding.get('mode') == mode
            and run_input.get('mode') == mode and run_input.get('cut') == cut
            and run_input.get('phase') == phase and run_input.get('unflushed') == loss
            and run_input.get('initial_disk_sha256') == initial_sha256
            and run_input.get('reverse_replies') is True
            and run_input.get('client_deadline_ns') == budget.get('client_deadline_ns')
            and run_input.get('capture_margin_ns') == budget.get('capture_margin_ns')
            and run_input.get('client_poll_ns') == budget.get('client_poll_ns')
            and run_input.get('capture_timeout_seconds')
                == budget.get('capture_timeout_seconds')
            and summary.get('scenario_budget') == budget
            and run_input.get('sample_ms') == matrix.get('sample_ms')
            and summary.get('sample_ms') == matrix.get('sample_ms')
            and run_input.get('immutable_artifact_cache')
                == matrix.get('immutable_artifact_cache')
            and run_input.get('build_manifest_sha256') == matrix.get('build_manifest_sha256')
            and run_input.get('expected_boot_epoch') == binding.get('boot_epoch')
            and run_input.get('nonce') == binding.get('nonce')
            and summary.get('build_manifest_sha256') == matrix.get('build_manifest_sha256')
            and sha(directory / 'build-manifest.json') == matrix.get('build_manifest_sha256')
            and binding.get('input_sha256') == sha(input_path)
            and binding.get('source_sha256') == matrix.get('source_manifest_sha256')
            and binding.get('image_sha256') == sha(directory / 'node-a.elf')
            and binding.get('uuid') == matrix.get('filesystem_uuid')
            and run_input.get('uuid') == matrix.get('filesystem_uuid')
            and sha(directory / 'source-manifest.json') == matrix.get('source_manifest_sha256')
            and tools.get('capture_tools') == matrix.get('tools')
            and qemu == matrix.get('qemu_attestation'),
            'A10 child run identity/status mismatch: ' + str(directory))
    if cut:
        require(summary.get('cut_observed') is True
                and summary.get('capture_status') == 'FAULT_CAPTURED'
                and summary.get('native_mode_verified') is False,
                'matrix cut was presented as a clean native completion')
        observed = summary.get('nbd_trace', {}).get('cut') or {}
        require(observed.get('mutation') == cut and observed.get('phase') == phase,
                'matrix cut trace disagrees with requested boundary')
    else:
        require(summary.get('cut_observed') is False
                and summary.get('capture_status') == 'VERIFIED'
                and summary.get('native_mode_verified') is True,
                'matrix clean/recovery run lacks verified native completion')
    require(summary.get('artifacts') == _files(directory),
            'A10 child artifacts changed: ' + str(directory))
    return summary, run_input


def _case_name(point: int, phase: str, loss: str) -> str:
    return f'p{point:04}-{phase}-{loss}'


def _recovery_name(point: int, phase: str, loss: str) -> str:
    return f'r{point:04}-{phase}-{loss}'


def result_scope(request: dict, overwrite_points: list[int], observed_points: list[int],
                 primary_cases: int, recovery_mutations: int, secondary_cases: int,
                 consumed_cut: bool, reordered: bool) -> dict:
    complete = (request.get('overwrite_points') == request.get('recovery_points') == 'all'
                and overwrite_points == observed_points
                and primary_cases == len(overwrite_points) * len(PHASES) * len(LOSSES)
                and recovery_mutations >= primary_cases
                and secondary_cases == recovery_mutations * len(PHASES) * len(LOSSES)
                and consumed_cut and reordered)
    return dict(schema_version=1,status='PASS' if complete else 'NOT_RUN',test_id='A10',
                native_powercut_verified=primary_cases > 0,
                native_filesystem_fault_matrix_complete=complete,A10_complete=complete,
                runtime_truth_attested=complete,overwrite_points=len(overwrite_points),
                overwrite_cases=primary_cases,recovery_point_selections=recovery_mutations,
                interrupted_recovery_cases=secondary_cases,
                consumed_cut_observed=consumed_cut,reordered_replies_observed=reordered,
                cache_eviction_verified=True,
                scope=('complete ordinary-file overwrite/recovery-interruption/cache matrix'
                       if complete else 'diagnostic subset; mandatory A10 matrix remains incomplete'))


def review(root: Path) -> dict:
    root = root.resolve(strict=True)
    request = json.loads((root / 'matrix-input.json').read_text())
    require(request.get('schema_version') == 1 and request.get('test_id') == 'A10'
            and request.get('specification') == '1.3'
            and request.get('phases') == list(PHASES)
            and request.get('losses') == list(LOSSES)
            and request.get('reverse_replies') is True
            and request.get('scenario_budgets') == scenario_budgets(ROOT)
            and request.get('sample_ms') == 30_000
            and type(request.get('qemu_binary')) is str
            and request.get('qemu_binary')
            and type(request.get('qemu_source')) is str
            and request.get('qemu_source')
            and type(request.get('qemu_attestation')) is dict
            and request['qemu_attestation'].get('qemu_pmu_patch_attested') is True
            and (request.get('immutable_artifact_cache') is None
                 or type(request.get('immutable_artifact_cache')) is str)
            and re.fullmatch(r'[0-9a-f]{32}', request.get('filesystem_uuid', '')),
            'invalid A10 matrix input')
    build_manifest = root / 'build-manifest.json'
    require(sha(build_manifest) == request.get('build_manifest_sha256'),
            'matrix build manifest changed')
    source_manifest = root / 'source-manifest.json'
    require(sha(source_manifest) == request.get('source_manifest_sha256')
            and json.loads(source_manifest.read_text())
                == json.loads(build_manifest.read_text()).get('code_source_map')
            and sha(root / 'formatted.raw') == request.get('formatted_disk_sha256')
            and sha(root / 'provision.log') == request.get('provision_log_sha256'),
            'matrix source/provisioning evidence changed')
    tools = request.get('tools')
    require(type(tools) is dict and tools
            and all(type(name) is str and Path(name).name == name for name in tools)
            and all(sha(root / 'tools' / name) == digest for name, digest in tools.items()),
            'matrix verifier/runner tools changed')

    formatted = root / 'formatted.raw'
    formatted_sha = sha(formatted)
    prepare, _ = load_run(root / 'prepare', mode=1, cut=0, phase='before', loss='drop',
                          initial_sha256=formatted_sha, status='PASS', matrix=request)
    require(prepare['observation']['consumption_boundary']['present'] is True,
            'preparation lacks protected sequence-2 consumption')
    prepared_disk = root / 'prepare' / 'disk.raw'
    prepared_sha = sha(prepared_disk)

    probe_dir = root / 'overwrite-probe'
    probe, _ = load_run(probe_dir, mode=2, cut=0, phase='before', loss='drop',
                        initial_sha256=prepared_sha, status='PASS', matrix=request)
    require(probe['observation']['consumption_boundary']['present'] is True,
            'overwrite probe lacks reordered transport or protected consumption')
    capture = decode((probe_dir / 'trace.bin').read_bytes(), probe['binding'])
    overwrite_rows = mutation_schedule(probe_dir)
    window = overwrite_window(capture, overwrite_rows)
    overwrite_points = select_points(request['overwrite_points'], overwrite_rows)

    cache_dir = root / 'cache-eviction'
    cache, _ = load_run(cache_dir, mode=4, cut=0, phase='before', loss='drop',
                        initial_sha256=sha(probe_dir / 'disk.raw'), status='PASS', matrix=request)
    require(cache['observation'].get('cache_eviction_verified') is True
            and cache['observation'].get('pressure_pages') == 4096,
            'same-boot cache eviction was not independently verified')

    reordered = bool(probe.get('nbd_trace', {}).get('reordered_replies'))
    consumed_cut = False
    primary_cases = secondary_cases = 0
    recovery_mutations = 0
    for point in overwrite_points:
        for phase in PHASES:
            for loss in LOSSES:
                case = root / 'overwrite' / _case_name(point, phase, loss)
                cut_dir = case / 'cut'
                cut, _ = load_run(cut_dir, mode=2, cut=point, phase=phase, loss=loss,
                                  initial_sha256=prepared_sha, status='NOT_RUN', matrix=request)
                consumed_cut |= cut.get('consumption_boundary', {}).get('present') is True
                reordered |= bool(cut.get('nbd_trace', {}).get('reordered_replies'))
                primary_cases += 1

                damaged = cut_dir / 'disk.raw'
                recovery_probe_dir = case / 'recovery-probe'
                recovery, _ = load_run(
                    recovery_probe_dir, mode=3, cut=0, phase='before', loss='drop',
                    initial_sha256=sha(damaged), status='PASS', matrix=request)
                require(recovery['observation']['consumption_boundary']['present'] is False,
                        'recovery probe has wrong role/transport evidence')
                reordered |= bool(recovery.get('nbd_trace', {}).get('reordered_replies'))
                recovery_rows = mutation_schedule(recovery_probe_dir)
                recovery_points = select_points(request['recovery_points'], recovery_rows)
                recovery_mutations += len(recovery_points)
                for recovery_point in recovery_points:
                    for recovery_phase in PHASES:
                        for recovery_loss in LOSSES:
                            interrupted = case / 'recovery' / _recovery_name(
                                recovery_point, recovery_phase, recovery_loss)
                            recovery_cut_dir = interrupted / 'cut'
                            recovery_cut, _ = load_run(
                                recovery_cut_dir, mode=3, cut=recovery_point,
                                phase=recovery_phase, loss=recovery_loss,
                                initial_sha256=sha(damaged), status='NOT_RUN', matrix=request)
                            reordered |= bool(recovery_cut.get('nbd_trace', {}).get('reordered_replies'))
                            final_dir = interrupted / 'final'
                            final, _ = load_run(
                                final_dir, mode=3, cut=0, phase='before', loss='drop',
                                initial_sha256=sha(recovery_cut_dir / 'disk.raw'), status='PASS',
                                matrix=request)
                            require(final['observation']['consumption_boundary']['present'] is False,
                                    'third boot did not independently recover the acknowledged prefix')
                            reordered |= bool(final.get('nbd_trace', {}).get('reordered_replies'))
                            secondary_cases += 1

    require(set(window['points']) <= set(overwrite_points) if request['overwrite_points'] == 'all' else True,
            'full matrix omitted the protected overwrite transaction')
    return result_scope(request, overwrite_points,
                        [row['mutation'] for row in overwrite_rows], primary_cases,
                        recovery_mutations, secondary_cases, consumed_cut, reordered)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    try:
        result = review(args.evidence)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'PASS' else 1
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print('a10-matrix-review: ' + type(error).__name__ + ': ' + str(error))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
