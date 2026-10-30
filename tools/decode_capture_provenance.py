#!/usr/bin/env python3
"""Decode bounded producer diagnostics; never establish accepted CPU evidence."""
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
    if w[:2] != (0x4359535243450001, 1) or w[2] & 1:
        raise ValueError('unsupported or concurrent source diagnostics')
    run = w[3:6]
    if any(value == 0 for value in run) or expected_run is not None and run != expected_run:
        raise ValueError('source diagnostics run identity mismatch')
    if w[11] > 4 or sum(w[7:10]) != w[6] or w[14] > 2:
        raise ValueError('invalid bounded source counts')
    rows = []
    for i in range(w[11]):
        r = w[16 + i * 24:40 + i * 24]
        if r[4] > 3 or r[13] > 1 or r[8] > r[9] or r[10] > r[11]:
            raise ValueError('invalid source interval or identity presence')
        rows.append({
            'original_owner': list(r[:2]), 'resolved_source': list(r[2:4]),
            'class': r[4], 'core': r[5], 'record_calls': r[6],
            'raw_duration_ns': r[7], 'first_interval_ns': list(r[8:10]),
            'sample_interval_ns': list(r[10:12]), 'sample_result': r[12],
            'sample_frozen_at_capacity': bool(r[23]),
            'site': r[14],
            'task_identity': {'caller': list(r[15:17]), 'request': r[17],
                              'child': list(r[18:20]), 'recipe': r[20]} if r[13] else None,
            'first_capacity_interval_ns': list(r[21:23]) if r[23] else None,
            'capacity_calls': r[23],
        })
    if sum(row['record_calls'] for row in rows) + w[10] != w[6]:
        raise ValueError('source bucket overflow accounting mismatch')
    overflow = None
    if w[14]:
        r = w[112:128]
        if (r[4] & 0xffff) > 3 or r[5] > r[6] or r[8] > 1 or not w[10]:
            raise ValueError('invalid overflow sample')
        overflow = {'original_owner': list(r[:2]), 'resolved_source': list(r[2:4]),
                    'class': r[4] & 0xffff, 'core': r[4] >> 16,
                    'interval_ns': list(r[5:7]), 'result': r[7],
                    'frozen_at_capacity': w[14] == 2, 'site': r[9],
                    'task_identity': {'caller': list(r[10:12]), 'request': r[12],
                                      'child': list(r[13:15]), 'recipe': r[15]} if r[8] else None}
    return {'present': True, 'run': list(run), 'attribution_complete': False,
            'scope': 'definitive OwnerAttempt record calls only; last recorded run',
            'record_calls': w[6], 'accepted_calls': w[7], 'capacity_calls': w[8],
            'other_error_calls': w[9], 'bucket_overflow_calls': w[10],
            'replaced_runs': w[12], 'task_identity_unknown_calls': w[13],
            'sources': rows, 'overflow_sample': overflow}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bank', type=Path)
    parser.add_argument('--run', type=int, nargs=3, metavar=('BOOT', 'TRIAL', 'GENERATION'))
    args = parser.parse_args()
    print(json.dumps(decode(args.bank.read_bytes(), tuple(args.run) if args.run else None), indent=2))

if __name__ == '__main__':
    main()
