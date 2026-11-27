#!/usr/bin/env python3
"""Check H04 advice expiry, credit custody, and rule-only progress.

The input is the stdout from the v0199_h04_model_check Rust example. The
state space is bounded to one monitored AdviceKey, explicit saturation
and archive transitions, and one actual deterministic publication/claim.
This host checker neither executes a guest action nor issues a Verdict.
"""

import argparse
import csv
import hashlib
import io
import itertools
import json
import platform
import struct
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = 'docs/design/baselines/v0.19.9-implementation-spec.txt'
DESIGN_SHA256 = '16a53c5c4f89df55425ce6c3898e00175c05c9c1185e8926a9abd6c737782843'
HARNESS = 'crates/kernel-core/examples/v0199_h04_model_check.rs'
CONTROL_PLANE = 'crates/kernel-core/src/control_plane/'
SOURCES = ('Cargo.lock', *(CONTROL_PLANE + name + '.rs' for name in (
    'advice_envelope_v1', 'advice_ledger_v0199', 'advice_disposition_v1',
    'registered_gate_v3', 'desired_plan_v0199', 'apply_work_v1',
)))
ADMISSION = (
    'fresh', 'exact', 'conflict', 'reordered', 'short', 'stale_boot', 'stale_advisor',
    'stale_model', 'stale_resources', 'stale_cores', 'stale_target',
    'stale_snapshot', 'stale_sender',
)
TERMINAL = ('skip', 'observe', 'expire', 'stale_supervisor')
ARCHIVE = ('archived', 'refused', 'stale_supervisor')
COLUMNS = (
    'fill now admission terminal archive plan_order admitted after_admit version_at_pressure '
    'registered published publish_calls finished released archive_calls custody after_archive '
    'replay replacement replay_refreshed stale_refreshed final_pending final_version '
    'work_sha256 work_retry work_calls'
).split()
CAPACITY = 64
MAX_RAW_BYTES = 2 * 1024 * 1024


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def pack(fmt, *args):
    return struct.pack('<' + fmt, *args)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cases():
    return itertools.product((1, 63, 64), (199, 200), ADMISSION, TERMINAL, ARCHIVE, ('before', 'peak'))


def expected_custody(state, now):
    """Independent literal encoding of the oldest archived key's two objects."""
    candidates = bytes([4]) * 32
    advice = (
        pack('IHH9Q4H', 0x43594131, 1, 152, 3, 2, 4, 17, 6, 3, 4, 200, 7, 1, 1, 0, 2)
        + bytes([3]) * 32 + candidates
    )
    reason = {4: 4, 5: 6}[state]
    expiry_or_observation = (
        pack('IHH10Q', 0x43594144, 1, 240, 2, 3, 2, 4, 0, 0, 17, 6, 7, now)
        + pack('4HI4HI', 1, 1, state, reason, 0, 65535, 0, 65535, 65535, 0)
        + candidates + hashlib.sha256(advice).digest() + bytes(64)
    )
    return f'{state}:{sha(advice + expiry_or_observation)}'


# One accepted deterministic plan, generation-6 target 17, executor
# generation 2, PlanID (boot 2, controller 3, seq 1), D01 weight 2.
EXPECTED_WORK = sha(
    pack('IHH3Q4H4QII', 0x43594157, 1, 80, 2, 3, 1, 0, 1, 1, 0, 17, 6, 2, 1, 2, 0)
    + bytes([2, 0])
)


def expected_steps(case):
    fill, at, admission, terminal, archive, order = case
    expired = at == 200
    # A retained exact retry and an old/altered key are not fresh queue work.
    invalid = {
        'exact': 'ExactRetry',
        'conflict': 'err_Denied',
        'reordered': 'err_Stale',
        'short': 'err_Invalid',
        'stale_boot': 'err_Stale',
        'stale_advisor': 'err_Stale',
    }
    if admission == 'fresh':
        accepted = not expired and fill < CAPACITY
        admission_result = 'Recorded' if accepted else 'err_Denied' if expired else 'err_Exhausted'
    else:
        accepted = False
        admission_result = invalid.get(admission, 'err_Denied')
    pending = fill + int(accepted)
    after_admit = pending

    # Authority and exclusive deadline determine whether the retained key
    # can become terminal. Retained terminal evidence still owns its slot.
    disposition = 0
    if terminal == 'observe':
        if not expired:
            disposition = 5
        finalization = 'err_Expired' if expired else 'Finalized'
    elif terminal == 'expire':
        if expired:
            disposition = 4
        finalization = 'Finalized' if expired else 'err_Denied'
    else:
        finalization = 'skip' if terminal == 'skip' else 'err_Denied'
    archive_calls = int(disposition != 0 and archive != 'stale_supervisor')
    released = archive_calls == 1 and archive == 'archived'
    archive_result = ('Released' if released else
                      'err_Denied' if archive == 'stale_supervisor' else 'err_NotReady')
    custody = expected_custody(disposition, at) if archive_calls else '-'
    pending -= int(released)
    after_archive = pending

    # Query results can survive either boundary. No old entry allocates.
    query = 'err_Stale' if released else 'Finalized' if disposition else 'ExactRetry'
    replacement = 'Recorded' if pending < CAPACITY else 'err_Exhausted'
    pending += int(replacement == 'Recorded')

    return (
        admission_result, after_admit, int(order == 'before'),
        'Frozen', 'AdapterAccepted', 1, finalization, archive_result, archive_calls,
        custody, after_archive, query, replacement, query, 'err_Denied', pending,
        1, EXPECTED_WORK, 'err_Busy', 1,
    )


def verify(raw):
    rows = csv.reader(io.StringIO(raw.decode('ascii')), delimiter='\t', strict=True)
    require(next(rows, None) == COLUMNS, 'wrong raw trace columns')
    missing = set(cases())
    count = Counter()
    for row in rows:
        require(len(row) == len(COLUMNS) and all(row), f'line {rows.line_num}: wrong raw row shape')
        fill, now = map(int, row[:2])
        case = fill, now, *row[2:6]
        require(case in missing, f'line {rows.line_num}: duplicate or outside state space {case}')
        missing.remove(case)
        expected = tuple(map(str, expected_steps(case)))
        for field, got, want in zip(COLUMNS[6:], row[6:], expected, strict=True):
            require(got == want, f'{case}: {field} expected {want}, saw {got}')
        observed = dict(zip(COLUMNS[6:], row[6:], strict=True))
        count['cases'] += 1
        count['full_at_publication_or_pressure'] += observed['after_admit'] == '64'
        count['full_rejection'] += observed['admitted'] == 'err_Exhausted'
        count['expired_fresh_rejection'] += row[2] == 'fresh' and now == 200
        count['stale_scope_or_sender_rejection'] += row[2].startswith('stale_')
        count['stale_replays_after_archive'] += observed['replay_refreshed'] == 'err_Stale'
        count['refused_archives_keeping_custody'] += row[4] == 'refused' and observed['archive_calls'] == '1'
        count['full_queue_rule_publications'] += observed['after_admit'] == '64' and row[5] == 'peak'
        count['accepted_old_plan_claims'] += row[5] == 'before'
        count['full_queues_reused_after_archive'] += (
            observed['after_admit'] == '64' and observed['released'] == 'Released'
            and observed['replacement'] == 'Recorded'
        )
    require(not missing, f'missing {len(missing)} states, first {min(missing) if missing else None}')
    require(all(count[key] > 0 for key in (
        'full_queue_rule_publications', 'stale_replays_after_archive', 'refused_archives_keeping_custody',
        'full_queues_reused_after_archive', 'accepted_old_plan_claims',
    )), 'vacuous publication, terminal custody or credit witness')
    return dict(sorted(count.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observed', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {
        'test_id': 'H04',
        'intended_proof_class': 'MODEL_CHECK',
        'formal_status': 'NOT_RUN',
        'scope': 'advice custody and one independent rule-only publication/claim, hosted',
        'checker_version': 1,
        'design_sections': ['main §6.1', 'main §11.2 H04', 'security §7.4'],
        'baseline_sha256': DESIGN_SHA256,
        'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'input_sources_sha256': {p: sha((ROOT / p).read_bytes()) for p in SOURCES},
        'checker_sha256': sha(Path(__file__).read_bytes()),
        'harness_source_sha256': sha((ROOT / HARNESS).read_bytes()),
        'harness_binary_sha256': sha(args.harness.read_bytes()),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], cwd=ROOT, text=True).strip(),
        'cargo': subprocess.check_output(['cargo', '-V'], cwd=ROOT, text=True).strip(),
        'finite_domain': {
            'initial_advice_slots': [1, 63, 64],
            'first_attempt_ns': [199, 200],
            'advice_deadline_ns': 200,
            'admission_paths': ADMISSION,
            'terminal_paths': TERMINAL,
            'archive_paths': ARCHIVE,
            'publication_orders': ['before advice pressure', 'while advice pressure is retained'],
        },
        'assumptions': [
            'serialized owners and synthetic authenticated identity/time',
            'one monitored AdviceKey and current-scope replacement, bounded queue occupancy',
            'archive success is a controlled callback outcome, without physical persistence',
            'one D01 RULE_ONLY action; no EL0 trap, device work, or APPLIED receipt',
            'new advice scope represents admission only, with no actual business-owner epoch transition',
        ],
    }
    try:
        require(sha((ROOT / DESIGN).read_bytes()) == DESIGN_SHA256, 'baseline content differs')
        with args.observed.open('rb') as raw_file:
            raw = raw_file.read(MAX_RAW_BYTES + 1)
        require(len(raw) <= MAX_RAW_BYTES, 'raw trace exceeds fixed extent')
        report['raw_trace_sha256'] = sha(raw)
        report['coverage'] = verify(raw)
        report['bounded_check'] = 'MATCHED'
    except (OSError, ValueError, csv.Error) as error:
        report['bounded_check'] = 'COUNTEREXAMPLE_OR_INVALID_TRACE'
        report['detail'] = str(error)
    with args.output.open('x', encoding='utf-8') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps(report, indent=2))
    return int(report['bounded_check'] != 'MATCHED')


if __name__ == '__main__':
    raise SystemExit(main())
