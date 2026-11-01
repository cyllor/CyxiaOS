"""Bind A10 fault candidates to explicit arming and the real QMP resume.

Legacy v1 archives keep their absolute mutation ids. New v2 archives keep the
same absolute raw_mutation stream, but mutation is an independent post-arm
ordinal. Preparation traffic is retained and replayed; it never consumes cut=1.
Arming precedes cont so the first guest write, including mount recovery, is in
scope. Neither an arm event nor a host timestamp proves filesystem correctness.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from check_prototype_evidence import _pairs, read_json
from check_v13_fault_disk import read_events
from verify_smp import require

EVENT_CLOCK = 'host-monotonic-ns-v1'
MAX_JSONL_BYTES = 128 * 1024 * 1024
MAX_JSONL_ROWS = 1_000_000


def _rows(path: Path) -> list[dict]:
    require(path.is_file() and path.stat().st_size <= MAX_JSONL_BYTES,
            'missing/oversized A10 lifecycle evidence')
    result = []
    total = 0
    with path.open('rb') as stream:
        for line in stream:
            total += len(line)
            require(total <= MAX_JSONL_BYTES and line.endswith(b'\n'),
                    'invalid A10 lifecycle framing')
            value = json.loads(line, object_pairs_hook=_pairs,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError('invalid A10 lifecycle number: ' + token)))
            require(type(value) is dict and len(result) < MAX_JSONL_ROWS,
                    'invalid/bounded A10 lifecycle row')
            result.append(value)
    require(result, 'empty A10 lifecycle evidence')
    return result


def mutation_scope(directory: Path) -> dict:
    """Reconstruct eligible fault ids; never trust a producer's selected list."""
    directory = directory.resolve(strict=True)
    start = read_json(directory / 'nbd' / 'start.json')
    require(start.get('event_clock') == EVENT_CLOCK,
            'A10 NBD trace lacks the source-bound resume clock')
    version = start.get('version', 1)
    require(type(version) is int and version in (1, 2), 'unknown A10 mutation numbering version')
    qmp = _rows(directory / 'qmp.jsonl')
    resume = [row['message']['id'] for row in qmp
              if row.get('direction') == 'send'
              and type(row.get('message')) is dict
              and row['message'].get('execute') == 'cont']
    require(len(resume) == 1 and type(resume[0]) is int and resume[0] > 0,
            'missing/ambiguous A10 QMP resume')
    resume_id = resume[0]
    witness = _rows(directory / 'native-provenance.jsonl')
    requests = [row for row in witness if row.get('event') == 'qmp-request'
                and row.get('id') == resume_id]
    responses = [row for row in witness if row.get('event') == 'qmp-response'
                 and row.get('id') == resume_id]
    require(len(requests) == len(responses) == 1
            and type(requests[0].get('seq')) is int
            and type(responses[0].get('seq')) is int
            and type(requests[0].get('monotonic_ns')) is int
            and type(responses[0].get('monotonic_ns')) is int
            and requests[0]['seq'] < responses[0]['seq']
            and requests[0]['monotonic_ns'] <= responses[0]['monotonic_ns'],
            'A10 QMP resume witness is missing or unordered')
    resume_ns = requests[0]['monotonic_ns']
    events = read_events(directory / 'nbd')
    previous_ns = -1
    for row in events:
        at = row.get('monotonic_ns')
        require(type(at) is int and at >= 0 and at >= previous_ns,
                'unordered/missing A10 NBD event clock')
        previous_ns = at
    mutation_rows = [row for row in events
                     if row.get('event') == 'request' and row.get('mutation')]
    mutations = [row['mutation'] for row in mutation_rows]
    require(mutations and all(type(value) is int for value in mutations)
            and mutations == list(range(1, len(mutations) + 1)),
            'missing/noncontiguous A10 mutation stream')
    common = dict(version=version, event_clock=EVENT_CLOCK, resume_qmp_id=resume_id,
                  resume_monotonic_ns=resume_ns)
    if version == 1:
        require(not any(row.get('event') == 'arm' for row in events)
                and 'mutation_scope' not in start, 'legacy trace contains an arming contract')
        if (directory / 'input.json').is_file():
            require('cut_scope' not in read_json(directory / 'input.json'),
                    'armed input was downgraded to legacy mutation numbering')
        before = [row['mutation'] for row in mutation_rows if row['monotonic_ns'] < resume_ns]
        after = [row['mutation'] for row in mutation_rows if row['monotonic_ns'] >= resume_ns]
        require(after and not (set(before) & set(after)) and before + after == mutations,
                'A10 resume boundary does not partition the mutation stream')
        return dict(common, raw_mutations=mutations, pre_resume_points=before, post_resume_points=after)

    inputs = read_json(directory / 'input.json')
    digest = hashlib.sha256((directory / 'input.json').read_bytes()).hexdigest()
    arms = [row for row in events if row.get('event') == 'arm']
    require(inputs.get('cut_scope') == start.get('mutation_scope') == 'post-arm-v1'
            and start.get('arm_input_sha256') == digest and len(arms) == 1
            and arms[0].get('input_sha256') == digest,
            'A10 arming/input binding is missing, duplicated or changed')
    arm = arms[0]
    readbacks = [row for row in witness if row.get('event') == 'save'
                 and row.get('name') == 'config-observed.bin']
    injections = [row for row in witness if row.get('event') == 'injection']
    require(len(readbacks) == len(injections) == 1
            and type(readbacks[0].get('monotonic_ns')) is int
            and type(injections[0].get('seq')) is int and type(readbacks[0].get('seq')) is int
            and injections[0]['seq'] < readbacks[0]['seq'] < requests[0]['seq']
            and readbacks[0]['monotonic_ns'] <= arm['monotonic_ns'] <= resume_ns,
            'A10 arm must follow config readback and precede guest resume')
    arm_at = events.index(arm)
    prefix, suffix = events[:arm_at], events[arm_at + 1:]
    setup = [row for row in prefix if row.get('event') == 'request']
    active = [row for row in suffix if row.get('event') == 'request']
    require(all(row.get('scope') == 'prepare' and row.get('mutation') == 0
                and row.get('kind') in (0, 3) for row in setup),
            'A10 preparation contains a write or counted fault candidate')
    require(active and all(row.get('scope') == 'armed'
                           and row['monotonic_ns'] >= resume_ns for row in active),
            'A10 armed request occurred before actual guest resume')
    raw_rows = [row for row in setup + active if row.get('kind') in (1, 3)]
    raw_ids = [row.get('raw_mutation') for row in raw_rows]
    require(all(type(value) is int for value in raw_ids)
            and raw_ids == list(range(1, len(raw_ids) + 1)),
            'A10 raw mutation sequence was removed or renumbered')
    setup_raw = [row['raw_mutation'] for row in setup if row['kind'] == 3]
    active_raw = [row['raw_mutation'] for row in active if row['kind'] in (1, 3)]
    setup_acks = [row['id'] for row in prefix if row.get('event') == 'ack']
    require(type(arm.get('raw_mutations')) is int and arm['raw_mutations'] == len(setup_raw)
            and type(arm.get('requests')) is int and arm['requests'] == len(setup)
            and type(arm.get('acks')) is int and arm['acks'] == len(setup_acks) == len(setup)
            and len(set(setup_acks)) == len(setup_acks)
            and set(setup_acks) == {row['id'] for row in setup}
            and arm.get('pending_sectors') == 0,
            'A10 arming crossed an unacknowledged preparation request')
    require([row['mutation'] for row in active if row['kind'] in (1, 3)] == mutations
            and all(row['mutation'] == 0 and row.get('raw_mutation') == 0
                    for row in active if row['kind'] not in (1, 3)),
            'A10 scoped mutation numbering differs from raw operation order')
    return dict(common, mutation_scope='post-arm-v1', arm_monotonic_ns=arm['monotonic_ns'],
                raw_mutations=raw_ids, pre_resume_points=[], pre_resume_raw_points=setup_raw,
                post_resume_points=mutations, post_resume_raw_points=active_raw)


def require_post_resume_cut(directory: Path, mutation: int) -> dict:
    scope = mutation_scope(directory)
    require(type(mutation) is int and mutation in scope['post_resume_points'],
            'A10 cut targeted device startup before guest resume')
    return scope
