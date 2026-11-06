#!/usr/bin/env python3
"""Six independently runnable engineering lanes; never native A acceptance.

Each lane executes real named component targets, not an A-ID substring filter.
The native catalogue is read-only and stays subject to its independent verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from doctor import ROOT, RUST_BIN
from prototype import run_steps

LANES = {
    'W1': {
        'ids': ('A01', 'A02', 'A03', 'A04'), 'issue': 11,
        'rust': ('boot', 'boot_fault_matrix', 'boot_model', 'cores',
                 'native_core_replay', 'native_irq_replay', 'native_irq_sources'),
        'python': (('tools', 'test_verify_v13_boot_cpus.py'),
                   ('tools', 'test_verify_v13_boot_receipt.py'),
                   ('tools', 'test_v14_native_workflow.py')),
    },
    'W2': {
        'ids': ('A05', 'A08'), 'issue': 12,
        'rust': ('feature_normalization', 'features_validation', 'model',
                 'native_domain_evidence', 'native_latency_samples',
                 'learning_reward', 'learning_replay_bounded',
                 'learning_replay_verified', 'learning_replay_schemas',
                 'learning_replay_target'),
        'python': (('tools', 'test_decode_runtime_loop.py'),
                   ('tests/host', 'test_prehash_decision_budget.py')),
    },
    'W3': {
        'ids': ('A06', 'A07', 'A09', 'A11', 'A15'), 'issue': 13,
        'rust': ('control_pool', 'control_extra_budget', 'dependency_admission',
                 'domain_policy', 'domain_policy_baseline', 'domain_policy_canary',
                 'domain_policy_model_change', 'domain_policy_one_shot',
                 'domain_maintenance', 'domain_ipc_grants', 'domain_tasks',
                 'domain_stability', 'spawn_reservation', 'task_receipt_expiry'),
        'python': (('tools', 'test_v13_a_reporting.py'),
                   ('tools', 'test_v14_workstreams.py'),
                   ('tools', 'test_v14_source_seal.py')),
    },
    'W4': {
        'ids': ('A10',), 'issue': 14,
        'rust': ('journal', 'storage', 'domain_storage', 'native_storage_replay',
                 'native_file_diagnostics'),
        'python': (('tools', 'test_a10_fault_arming.py'),
                   ('tools', 'test_verify_v13_a10_matrix.py'),
                   ('tools', 'test_v14_fault_numbers.py')),
    },
    'W5': {
        'ids': ('A12', 'A13', 'A14'), 'issue': 15,
        'rust': ('cluster_engine', 'cluster_volume', 'cluster_wire',
                 'domain_network_dependencies', 'domain_network_placement',
                 'domain_network_quote_stop', 'domain_network_requests',
                 'native_task_owner_gate', 'native_task_lifecycle'),
        'python': (),
    },
    'W6': {
        'ids': ('A16',), 'issue': 16,
        'rust': ('learning_softfloat', 'learning_train', 'learning_validation',
                 'learning_capture', 'learning_capture_init', 'learning_worker',
                 'learning_governance', 'learning_governance_init',
                 'learning_coordinator_decision', 'learning_coordinator_wire',
                 'learning_native_driver', 'learning_native_history',
                 'learning_native_producer', 'learning_native_session',
                 'learning_review_capture', 'learning_review_evidence',
                 'learning_review_governance', 'learning_score_worker',
                 'native_canary_console_baseline', 'native_canary_measurements',
                 'native_canary_publication_clock', 'native_learning_receipt',
                 'model_bank', 'learning_governance_faults'),
        'python': (),
    },
}


def validate_lanes(lanes=LANES, root: Path = ROOT) -> None:
    ids = [case for lane in lanes.values() for case in lane['ids']]
    if sorted(ids) != [f'A{i:02}' for i in range(1, 17)]:
        raise ValueError('lanes must cover each A01-A16 exactly once')
    targets = []
    for lane in lanes.values():
        if not lane['rust']:
            raise ValueError('empty Rust component lane')
        for target in lane['rust']:
            if not (root / 'crates/prototype/tests' / (target + '.rs')).is_file():
                raise ValueError('missing Rust target: ' + target)
            targets.append(target)
        for directory, filename in lane['python']:
            if not (root / directory / filename).is_file():
                raise ValueError('missing Python target: ' + filename)
    if len(set(targets)) != len(targets):
        raise ValueError('Rust target owned by multiple lanes')


def steps_for(lane: str) -> list[tuple[str, list[str]]]:
    validate_lanes()
    selected = LANES[lane]
    cargo = str(RUST_BIN / 'cargo')
    args = [cargo, 'test', '--locked', '--offline', '-p', 'cyxia-prototype']
    for target in selected['rust']:
        args.extend(('--test', target))
    steps = [('rust-components', args)]
    if lane == 'W5':
        steps.append(('tls-components', [cargo, 'test', '--locked', '--offline',
                      '-p', 'cyxia-cluster-transport', '--features', 'tls']))
    for directory, filename in selected['python']:
        steps.append((Path(filename).stem, [sys.executable, '-B', '-m', 'unittest',
                      'discover', '-s', directory, '-p', filename, '-v']))
    return steps


def source_identity(root: Path = ROOT) -> dict:
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root, text=True).strip()
    commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('source must be clean, including untracked files, for exact-source evidence')
    return {'commit': commit, 'tree': tree, 'tracked_dirty': False}


def run_lane(lane: str, output: Path) -> int:
    steps = steps_for(lane)
    source = source_identity()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'scope': 'component-workstream-validation',
              'lane': lane, 'issue': LANES[lane]['issue'],
              'requirements': list(LANES[lane]['ids']), 'source': source,
              'status': 'RUNNING', 'source_verified_after_checks': False,
              'native_execution_attempted': False,
              'native_acceptance_status': 'NOT_RUN',
              'release_acceptance_verified': False, 'log_sha256': {}}

    def save():
        (output / 'workstream.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    try:
        code = run_steps(steps, output / 'checks')
        summary = json.loads((output / 'checks/summary.json').read_text())
        rows = summary['steps']
        complete = (len(rows) == len(steps) and
                    all(row['name'] == name and row['argv'] == argv and
                        row['status'] == 'PASS' and row['returncode'] == 0
                        for row, (name, argv) in zip(rows, steps)))
        for path in sorted((output / 'checks').glob('*.log')):
            report['log_sha256'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        after = source_identity()
        report['source_after_checks'] = after
        if after != source:
            raise ValueError('source identity changed during component checks')
        report['source_verified_after_checks'] = True
        report['status'] = 'PASS' if code == 0 and complete else 'FAIL'
        save()
        return code if code else int(not complete)
    except BaseException as error:
        report['status'] = 'FAIL'
        report['error'] = f'{type(error).__name__}: {error}'
        save()
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lane', choices=tuple(LANES), required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args(argv)
    if args.plan:
        print(json.dumps({'lane': args.lane, 'requirements': LANES[args.lane]['ids'],
                          'steps': steps_for(args.lane),
                          'native_acceptance_status': 'NOT_RUN'}, indent=2))
        return 0
    if args.output is None:
        parser.error('--output is required unless --plan is used')
    return run_lane(args.lane, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
