#!/usr/bin/env python3
"""Decode incomplete paid invocation observations, never admission/CPU evidence."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct


def decode(data: bytes, expected_run: tuple[int, int, int] | None = None) -> dict:
    if len(data) != 1024:
        raise ValueError('source diagnostics require exactly 1024 bytes')
    w = struct.unpack('<128Q', data)
    if not any(w):
        return {'present': False, 'attribution_complete': False}
    if w[:2] != (0x4359535243450001, 2) or w[2] & 1:
        raise ValueError('unsupported schema or concurrent source diagnostics')
    run = w[3:6]
    if any(v == 0 for v in run) or expected_run is not None and run != expected_run:
        raise ValueError('source diagnostics run identity mismatch')
    if not w[6] or not 1 <= w[11] <= 4 or sum(w[7:9]) != w[6] or w[9] > w[6] or w[14] > 1:
        raise ValueError('invalid bounded observation counts')
    if w[13] or w[15] or any(w[16+w[11]*24:112]):
        raise ValueError('reserved header or unused bucket contains foreign fields')
    if bool(w[10]) != bool(w[14]) or w[10] and w[11] != 4:
        raise ValueError('overflow requires four populated buckets and its sample')
    if not w[14] and any(w[112:]):
        raise ValueError('unused overflow tail contains foreign fields')

    def source(offered, direct, present):
        if present not in (0, 1) or (present and (direct != offered or not all(direct))) or (not present and any(direct)):
            raise ValueError('invalid direct roster source; aliases stay unresolved')
        return list(direct) if present else None

    def identity(values, present):
        if present not in (0, 1) or not present and any(values) or values[5] > 0xffff:
            raise ValueError('invalid task identity presence')
        return {'caller': list(values[:2]), 'request': values[2],
                'child': list(values[3:5]), 'recipe': values[5]} if present else None

    rows = []
    keys = set()
    for i in range(w[11]):
        r = w[16+i*24:40+i*24]
        if r[4] > 3 or r[5] != 0 or r[6] not in (2, 3, 4, 5) or not r[7] or r[8] > r[9] or any(r[18:]):
            raise ValueError('invalid paid CPU0 observation')
        if r[:7] in keys:
            raise ValueError('duplicate producer bucket')
        keys.add(r[:7])
        rows.append({'offered_owner': list(r[:2]), 'direct_source': source(r[:2], r[2:4], r[10]),
                     'class': r[4], 'core': r[5], 'site': r[6], 'observations': r[7],
                     'first_start_cpu_ticks': r[8], 'latest_start_cpu_ticks': r[9],
                     'task_identity': identity(r[12:18], r[11])})
    if sum(r['observations'] for r in rows) + w[10] != w[6]:
        raise ValueError('observation bucket overflow accounting mismatch')
    overflow = None
    if w[14]:
        r = w[112:128]
        if not w[10] or r[4] > 3 or r[5] != 0 or r[6] not in (2, 3, 4, 5):
            raise ValueError('invalid overflow observation')
        if r[:7] in keys:
            raise ValueError('overflow source already has a producer bucket')
        overflow = {'offered_owner': list(r[:2]), 'direct_source': source(r[:2], r[2:4], r[8]),
                    'class': r[4], 'core': r[5], 'site': r[6], 'start_cpu_ticks': r[7],
                    'task_identity': identity(r[10:16], r[9])}
    known_min = sum(r['observations'] for r in rows if r['direct_source'] is not None)
    unresolved_min = sum(r['observations'] for r in rows if r['direct_source'] is None)
    unknown_task_min = sum(r['task_identity'] is None for r in rows)
    known_task_min = sum(r['task_identity'] is not None for r in rows)
    if overflow:
        known_min += overflow['direct_source'] is not None
        unresolved_min += overflow['direct_source'] is None
        unknown_task_min += overflow['task_identity'] is None
        known_task_min += overflow['task_identity'] is not None
    if w[7] < known_min or w[8] < unresolved_min or not unknown_task_min <= w[9] <= w[6]-known_task_min:
        raise ValueError('header totals cannot describe observed producer samples')
    return {'present': True, 'schema': 2, 'run': list(run), 'attribution_complete': False,
            'scope': 'paid CPU0 cleanup/recipe/deferred-return/serviceIO invocation observations; last successfully observed run; contended probes omitted',
            'admission_known': False, 'completion_known': False,
            'observations': w[6], 'direct_known_observations': w[7],
            'unresolved_observations': w[8], 'task_identity_unknown_observations': w[9],
            'bucket_overflow_observations': w[10], 'replaced_runs': w[12],
            'sources': rows, 'overflow_observation': overflow}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bank', type=Path)
    parser.add_argument('--run', type=int, nargs=3, metavar=('BOOT', 'TRIAL', 'GENERATION'))
    args = parser.parse_args()
    print(json.dumps(decode(args.bank.read_bytes(), tuple(args.run) if args.run else None), indent=2))


if __name__ == '__main__':
    main()
