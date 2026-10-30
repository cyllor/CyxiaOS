"""Bind A10 fault points to mutations observed after the real QMP resume.

The volatile NBD transcript intentionally retains device-startup traffic.  That
traffic is evidence, but it is not an executable guest filesystem boundary.  A
matrix cut therefore uses the absolute mutation id from the raw transcript only
after independently proving that the request was observed after the one real
QMP ``cont`` request.  No mutation is renumbered or removed from the archive.
"""
from __future__ import annotations

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
    """Return immutable raw mutation ids split around the actual resume request."""
    directory = directory.resolve(strict=True)
    start = read_json(directory / 'nbd' / 'start.json')
    require(start.get('event_clock') == EVENT_CLOCK,
            'A10 NBD trace lacks the source-bound resume clock')

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
    mutation_rows = []
    for row in events:
        at = row.get('monotonic_ns')
        require(type(at) is int and at >= 0 and at >= previous_ns,
                'unordered/missing A10 NBD event clock')
        previous_ns = at
        if row.get('event') == 'request' and row.get('mutation'):
            require(type(row.get('mutation')) is int and row['mutation'] > 0,
                    'invalid A10 mutation identity')
            mutation_rows.append(row)
    mutations = [row['mutation'] for row in mutation_rows]
    require(mutations and mutations == list(range(1, len(mutations) + 1)),
            'missing/noncontiguous A10 mutation stream')
    before = [row['mutation'] for row in mutation_rows if row['monotonic_ns'] < resume_ns]
    after = [row['mutation'] for row in mutation_rows if row['monotonic_ns'] >= resume_ns]
    require(after and not (set(before) & set(after))
            and before + after == mutations,
            'A10 resume boundary does not partition the mutation stream')
    return dict(version=1, event_clock=EVENT_CLOCK, resume_qmp_id=resume_id,
                resume_monotonic_ns=resume_ns, raw_mutations=mutations,
                pre_resume_points=before, post_resume_points=after)


def require_post_resume_cut(directory: Path, mutation: int) -> dict:
    scope = mutation_scope(directory)
    require(type(mutation) is int and mutation in scope['post_resume_points'],
            'A10 cut targeted device startup before guest resume')
    return scope
