#!/usr/bin/env python3
"""Decode the bounded EL0 runtime-loop timing snapshot."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = 0x4359_5254_4c4f_4f31


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_runtime_loop(data):
    require(len(data) == 512, 'runtime-loop evidence must be exactly 512 bytes')
    words = struct.unpack('<64Q', data)
    require(words[0] > 0 and words[0] % 2 == 0, 'runtime-loop publication is incomplete')
    require(words[1] == MAGIC and words[2] == 1 and words[3] > 0,
            'invalid runtime-loop header')
    require(words[4] > 0 and words[5] > 0 and words[6] > 0 and words[7] == 0,
            'invalid runtime-loop identity')
    r = words[8:40]
    require(r[0] == 1 and r[1] == words[6] and r[2] > 0 and r[31] == 0,
            'invalid runtime-loop record')

    def interval(name, offset):
        duration, started, finished = r[offset:offset + 3]
        require((duration == started == finished == 0)
                or (r[3] <= started <= finished <= r[28]
                    and duration == finished - started),
                f'invalid {name} interval')
        return {'duration_ns': duration, 'started_ns': started, 'finished_ns': finished}

    require(0 < r[3] <= r[4] <= r[5] <= r[28], 'invalid runtime-loop bounds')
    loop_gap = interval('loop_gap', 6)
    segments = {
        name: interval(name, offset) for name, offset in (
            ('receive', 9), ('ingest', 12), ('handle', 15),
            ('post_admission', 18), ('tick', 21), ('egress', 24),
        )
    }
    require(r[27] == 0 or r[3] <= r[27] <= r[28], 'invalid liveness attempt time')
    return {
        'scope': ('latest terminal session maxima, never the current active session; '
                  'stopped snapshot; non-authoritative; '
                  'shared clock refreshes only at EL1/SVC boundaries, so pure EL0 work and '
                  'host descheduling may be underestimated and zero does not exclude them'),
        'boot_epoch': words[4], 'service_generation': words[5],
        'connection_epoch': words[6], 'reports': words[3], 'loops': r[2],
        'session_started_ns': r[3],
        'last_loop': {'started_ns': r[4], 'finished_ns': r[5]},
        'max_loop_gap': loop_gap, 'segments': segments,
        'last_liveness_attempt_ns': r[27],
        'exit': {'at_ns': r[28], 'reason': r[29], 'result': r[30]},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    print(json.dumps(decode_runtime_loop(args.snapshot.read_bytes()), indent=2))
