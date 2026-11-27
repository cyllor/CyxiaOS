#!/usr/bin/env python3
"""Independent finite oracle for one H05 MODEL_CHECK obligation.

Check the raw output of:
  cargo run --locked --offline -p cyxia-kernel-core --example v0199_h05_model_check

The checker models an empty DesiredBank, independently frozen rules and a
single decision. It examines subsequent publication and an exact repeat.
It checks real library transitions with controlled host authority inputs.
It does not run an AArch64 guest, settle work, or issue a Verdict.
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
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = 'docs/design/baselines/v0.19.9-implementation-spec.txt'
DESIGN_SHA256 = '16a53c5c4f89df55425ce6c3898e00175c05c9c1185e8926a9abd6c737782843'
HARNESS = 'crates/kernel-core/examples/v0199_h05_model_check.rs'
CONTROL_PLANE = 'crates/kernel-core/src/control_plane/'
INPUT_SOURCES = ('Cargo.lock', *(CONTROL_PLANE + name + '.rs' for name in (
    'action_schema_v2', 'candidate_registry_v0199', 'rule_profile_v2',
    'advice_ledger_v0199', 'advice_disposition_v1', 'decision_record_v3', 'plan_wire_v2',
    'svc_bridge_v3', 'registered_gate_v3', 'desired_plan_v0199',
)))
SENSITIVE = {6, 11, 12, 14}

# Normative ordinary actions from main §8 and the ActionSchema v2 tables.
# D12's 4/s and 8/s are reserved for a trial and absent from this table.
PAYLOADS = {
    domain: tuple(map(bytes.fromhex, wire.split()))
    for domain, wire in enumerate((
        '0100 0200 0400 0800',
        '0100 0200 0400 0800',
        '400000000400 000100001000 000400002000 001000004000',
        '00000400 02000800 08001000 10002000',
        '080001 200004 400008 800010',
        '0100 0200 0300',
        '0000 3200 c800 e803',
        '01 02 04 08',
        '6400 fa00 f401 ee02',
        '01 04 08 10',
        '01 02 04 08',
        '1000 2000',
        '3200 6400 c800 9001',
        '0000 0100 0200',
        '0100 0800 2000 4000',
    ), 1)
}
MODES = ('rule', 'shadow_rule', 'shadow_proposal', 'assisted', 'model_closed')
STEPS = ('skip', 'publish', 'advice_end', 'decision_end', 'operations')
COLUMNS = ('domain reverse mask mode index step advice after_advice register after_register '
           'retained publish replay version accept_calls gate_published bank_published payload '
           'candidates_sha256 rules_sha256 plan_sha256 decision_sha256 advice_sha256').split()
REJECTED = frozenset(('err_Denied', 'err_Stale', 'err_Invalid'))
MAX_RAW_BYTES = 32 * 1024 * 1024


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def pack(fmt, *values):
    return struct.pack('<' + fmt, *values)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ordinals(domain):
    return (13, 16) if domain == 12 else tuple(7 + 3*i for i in range(len(PAYLOADS[domain])))


@lru_cache(maxsize=None)
def candidate_digest(domain):
    snapshot = pack('IHH7QHHI', 0x4359534e, 3, 72, 3, 1, 5, 6, 17, 1, 100, domain, 12, 0)
    snapshot += b''.join(pack('HB5xQ', field, 0, 0) for field in range(16, 28))
    catalog = bytes.fromhex(sha(b'CYX/H05/MODEL-CHECK/FIXTURE-CATALOG'))
    fields = b''.join(pack('BQ', value is not None, value or 0)
                      for value in (None, None, None, None, 7, None, 1))
    choices = b''.join(pack('HB', ordinal, len(payload)) + payload
                       for ordinal, payload in zip(ordinals(domain), PAYLOADS[domain], strict=True))
    return bytes.fromhex(sha(b'CYX/REGISTERED-CANDIDATES/v0199' + catalog + snapshot + bytes(1)
                             + fields + pack('H', len(PAYLOADS[domain])) + choices))


@lru_cache(maxsize=None)
def rule(scope):
    domain, reverse, mask = scope
    allowed = [i for i in range(len(PAYLOADS[domain])) if mask & (1 << i)]
    if reverse:
        allowed.reverse()
    choices = b''.join(pack('HHI', ordinals(domain)[i], rank, 0) for rank, i in enumerate(allowed))
    size = 64 + len(choices)
    policy = int(domain not in SENSITIVE)
    raw = (pack('IHHQIIQ', 0x43595255, 2, 32, 7, 1, size, 0)
           + pack('IHHQHHHHII', 1, domain, 1, 17, policy, 0, len(allowed), 0, size-32, 0)
           + choices)
    return allowed, policy, bytes.fromhex(sha(raw))


@lru_cache(maxsize=None)
def expected_frames(domain, reverse, mask, mode, index):
    allowed, policy, rules = rule((domain, reverse, mask))
    fallback = allowed[0]
    proposal = mode in ('shadow_proposal', 'assisted', 'model_closed')
    n = len(PAYLOADS[domain])
    selected = min(index, n-1) if proposal else fallback
    payload = PAYLOADS[domain][selected]
    candidate = candidate_digest(domain)
    model = bytes([3]) * 32
    advice = (pack('IHH9Q4H', 0x43594131, 1, 152, 1, 1, 3, 17, 1, 5, 6, 200, 9,
                   domain, 1, index, n) + model + candidate)
    plan = (pack('IHHIHH6Q', 0x43594c31, 2, 64, 210+len(payload), 1, int(proposal),
                 1, 0, 9 if proposal else 0, 2, 3, 0 if domain == 14 else 10_000_000_100)
            + pack('IHHHHI8Q', 0x43595031, 2, 144, domain, 1, 2+len(payload),
                   2, 4, 3, 17, 1, 5, 6, 300)
            + (model if proposal else bytes(32)) + candidate + pack('H', selected) + payload)
    mode_byte = 2 if proposal else int(mode == 'shadow_rule')
    decision = (
        pack('IHH10Q', 0x43594431, 3, 256, 1, 2, 4, 1, 3, 17, 1, 5, 6, 7)
        + pack('IHHH4B3HI', 1, 0, domain, 1, mode_byte, int(proposal), int(proposal),
               int(proposal), selected, index if proposal else 65535, 0, 8 if proposal else 2)
        + pack('5QIHH', int(proposal), int(proposal), 9 if proposal else 0, 0, 300,
               mask | (1 << selected), fallback, 1 if proposal else policy)
        + rules + bytes.fromhex(sha(plan)) + candidate
    )
    return (
        candidate.hex(), rules.hex(), sha(plan), sha(decision),
        '-' if mode == 'rule' else sha(advice), proposal, payload.hex(),
    )


def expected_keys():
    for domain, payloads in PAYLOADS.items():
        n = len(payloads)
        for reverse, mask, mode in itertools.product((0, 1), range(1, 1 << n), MODES):
            for index, step in itertools.product((n,) if mode == 'rule' else range(n+1), STEPS):
                yield domain, reverse, mask, mode, index, step


def verify(raw):
    rows = csv.DictReader(io.StringIO(raw.decode('ascii')), delimiter='\t', strict=True)
    require(rows.fieldnames == COLUMNS, 'wrong raw trace columns')
    expected = set(expected_keys())
    counters = Counter()
    assisted_action_sets = {}
    shadow_plans = {}
    for row in rows:
        require(None not in row and all(row.values()), f'line {rows.line_num}: invalid raw trace row')
        try:
            domain, reverse, mask, index = (int(row[name]) for name in ('domain', 'reverse', 'mask', 'index'))
        except ValueError as error:
            raise ValueError(f'line {rows.line_num}: invalid state coordinates') from error
        mode, step = row['mode'], row['step']
        key = domain, reverse, mask, mode, index, step
        require(key in expected, f'line {rows.line_num}: duplicate or out-of-bound state {key}')
        expected.remove(key)
        candidates, rules, plan, decision, advice, proposal, payload = expected_frames(*key[:5])
        require(tuple(row[field] for field in COLUMNS[-5:]) == (candidates, rules, plan, decision, advice),
                f'{key}: frozen bytes differ from independent schema projection')
        seen = index < len(PAYLOADS[domain])
        require(row['advice'] == ('skip' if mode == 'rule' else 'Recorded' if seen else 'err_Invalid'),
                f'{key}: advice admission differs')
        # Oracle state transition: a protected decision may select the rule
        # fallback or one authorized candidate in the independently allowed set.
        register = not proposal or (
            mode == 'assisted' and domain not in SENSITIVE and seen and bool(mask & (1 << index))
        )
        if register:
            require(row['register'] == 'Frozen' and row['retained'] == decision,
                    f'{key}: valid approval or exact protected copy missing')
        else:
            require(row['register'] in REJECTED and row['retained'] == 'err_Stale',
                    f'{key}: denied proposal left decision custody')
        require(row['after_advice'] == row['after_register'] == '0',
                f'{key}: advice or registration changed desired metadata')
        published = register and (step == 'publish' or (step == 'advice_end' and not proposal))
        if published:
            require(row['publish'] == 'AdapterAccepted' and row['replay'] == 'ReplayNoEffect',
                    f'{key}: publication or exact retry differs')
        elif step == 'skip':
            require(row['publish'] == row['replay'] == 'skip', f'{key}: unrequested publication')
        else:
            require(row['publish'] in REJECTED and row['replay'] in REJECTED,
                    f'{key}: denied publication or retry accepted')
        require(all(row[field] == str(int(published))
                    for field in ('version', 'accept_calls', 'gate_published', 'bank_published'))
                and row['payload'] == (payload if published else '-'),
                f'{key}: desired-owner change differs from the exact protected publication')
        counters['cases'] += 1
        counters['registered'] += register
        counters['published_once'] += published
        counters['skipped_publication'] += step == 'skip'
        counters['outside_set_denials'] += mode == 'assisted' and seen and not bool(mask & (1 << index))
        counters['sensitive_proposal_denials'] += proposal and domain in SENSITIVE
        counters['expired_assisted_denials'] += register and proposal and step == 'advice_end'
        counters['expired_decision_denials'] += register and step == 'decision_end'
        counters['wrong_publisher_denials'] += register and step == 'operations'
        if published and step == 'publish':
            scope = domain, reverse, mask
            if mode == 'assisted':
                assisted_action_sets.setdefault(scope, set()).add(payload)
            elif mode in ('rule', 'shadow_rule'):
                shadow_plans.setdefault(scope, set()).add(plan)
    require(not expected, f'missing {len(expected)} states, first {min(expected) if expected else None}')
    require(all(len(plans) == 1 for plans in shadow_plans.values())
            and len(shadow_plans) == sum(2*((1 << len(p))-1) for p in PAYLOADS.values()),
            'advice changed a shadow fallback plan')
    both = {
        d for (d, _, mask), actions in assisted_action_sets.items()
        if mask.bit_count() > 1 and len(actions) == mask.bit_count()
    }
    require(both == set(PAYLOADS) - SENSITIVE, 'in-set choice witness is vacuous')
    counters['shadow_rule_scopes'] = len(shadow_plans)
    counters['assisted_distinct_action_scopes'] = sum(len(v) > 1 for v in assisted_action_sets.values())
    return dict(sorted(counters.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observed', type=Path, required=True)
    parser.add_argument('--harness', type=Path, required=True, help='exact local binary that emitted the trace')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {
        'test_id': 'H05',
        'intended_proof_class': 'MODEL_CHECK',
        'formal_status': 'NOT_RUN',
        'scope': 'single decision, synthetic trusted scope, desired metadata only',
        'checker_version': 1,
        'baseline_sha256': DESIGN_SHA256,
        'design_sections': ['main §6.3', 'main §11.2 H05', 'security §7.4'],
        'input_sources_sha256': {path: sha((ROOT / path).read_bytes()) for path in INPUT_SOURCES},
        'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'checker_sha256': sha(Path(__file__).read_bytes()),
        'harness_source_sha256': sha((ROOT / HARNESS).read_bytes()),
        'harness_binary_sha256': sha(args.harness.read_bytes()),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], cwd=ROOT, text=True).strip(),
        'cargo': subprocess.check_output(['cargo', '-V'], cwd=ROOT, text=True).strip(),
        'finite_domain': {
            'domains': list(PAYLOADS),
            'allowed_masks': 'all nonempty sets over 2–4 ordinary candidates',
            'rank_orders': ['ascending ordinals', 'descending ordinals'],
            'advice_modes': MODES,
            'publication_steps': STEPS,
            'times_ns': {'sample': 100, 'register': 150, 'publish_live': 151,
                         'advice_deadline': 200, 'decision_deadline': 300},
        },
        'assumptions': [
            'fresh gate and empty desired bank for every trace',
            'single action, fixed boot, controller, resource, and target generations',
            'fixture-provided attestation inputs, no external signatures',
            'no EL0 trap, real-work execution, restart, concurrency, or APPLIED path',
        ],
    }
    try:
        require(sha((ROOT / DESIGN).read_bytes()) == DESIGN_SHA256, 'baseline content differs')
        with args.observed.open('rb') as source:
            raw = source.read(MAX_RAW_BYTES + 1)
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
