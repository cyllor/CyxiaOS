"""Decode actual local broker diagnostics; never task admission authority."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = 0x4359_4c52_4551_3031
ROWS, ROW_WORDS = 8, 32
WORDS = 8 + ROWS * ROW_WORDS
STATES = ('Queued', 'Created', 'Failed', 'Unknown', 'Cancelled')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(data):
    require(len(data) == WORDS * 8, 'local-request evidence size differs')
    words = struct.unpack(f'<{WORDS}Q', data)
    if not any(words):
        return {'present': False, 'native_acceptance_verified': False}
    require(words[0] > 0 and not words[0] & 1,
            'local-request publication is incomplete')
    require(words[1:5] == (MAGIC, 1, ROWS, ROW_WORDS)
            and words[0] == 2 * words[5] and words[7] == 0,
            'local-request header differs')
    rows = []
    for slot in range(ROWS):
        row = words[8 + slot * ROW_WORDS:8 + (slot + 1) * ROW_WORDS]
        if not any(row):
            continue
        require(all(row[i] > 0 for i in (0, 1, 2))
                and (row[2] - 1) % ROWS == slot
                and row[3] in (11, 12, 27) and row[4] <= 5
                and row[5] <= 24 and row[6] == 0,
                'local-request identity/return differs')
        require(row[8] < len(STATES) and row[7] <= 20 and row[9] <= 20
                and all(row[i] in (0, 1) for i in (12, 13, 14))
                and row[15] > 0 and row[16] <= row[17]
                and 0 < row[26] <= 3984 and row[26] % 8 == 0,
                'local-request state/timing differs')
        require((row[8] == 1 and row[10] > 0 and row[11] > 0)
                or (row[8] != 1 and row[10] == row[11] == 0),
                'local-request task identity differs')
        require((row[8] == 2 and row[9] > 0) or (row[8] != 2 and row[9] == 0),
                'local-request failure state differs')
        require(not row[12] or row[8] == 3,
                'local-request retry permission differs')
        counts = row[18:21]
        phase_index = {11: 0, 12: 1, 27: 2}[row[3]]
        require(counts[phase_index] > 0 and 0 < sum(counts) <= words[5]
                and row[21] <= counts[0] and row[22] <= sum(counts),
                'local-request phase counters differ')
        require(row[23] in (0, 11, 12)
                and (row[24] < len(STATES) or row[24] == 2**64 - 1)
                and row[25] <= 20,
                'local-request owner outcome differs')
        require((row[23] == 0 and row[24] == 2**64 - 1 and row[25] == row[7] == 0)
                or (row[23] != 0 and (
                    (row[25] > 0 and row[24] == 2**64 - 1 and row[7] == row[25])
                    or (row[7] == 0 and row[24] < len(STATES)
                        and ((row[24] == 2 and row[25] > 0)
                             or (row[24] != 2 and row[25] == 0))))),
                'local-request owner result binding differs')
        require(row[27] in (0, 1, 2) and row[13] == (row[27] != 0)
                and (not row[14] or row[13] and row[8] == 1)
                and ((row[27] == 1 and row[29] == 0 and row[28] <= row[17])
                     or (row[27] == 2 and row[28] == 0 and 0 < row[29] <= 20)
                     or (row[27] == 0 and row[28] == row[29] == 0))
                and row[30:] == (0, 0),
                'local-request completion/reserved differs')
        rows.append({
            'request': list(row[:2]), 'spawn_id': row[2], 'phase': row[3],
            'reply': list(row[4:7]), 'owner_error': row[7] or None,
            'spawn_state': STATES[row[8]], 'spawn_error': row[9] or None,
            'task': list(row[10:12]), 'retryable': bool(row[12]),
            'completion_retained': bool(row[13]), 'acknowledged': bool(row[14]),
            'deadline_ns': row[15], 'started_ns': row[16], 'finished_ns': row[17],
            'phase_calls': dict(zip(('11', '12', '27'), counts)),
            'submit_calls': row[21], 'query_calls': row[22],
            'owner_operation': row[23],
            'owner_spawn_state': STATES[row[24]] if row[24] < len(STATES) else None,
            'completion_outcome': row[27] or None,
            'completion_finished_ns': row[28] if row[27] == 1 else None,
            'completion_error': row[29] or None,
        })
    return {'present': True,
            'scope': 'bounded latest CPU0 local broker returns; never execution authority',
            'publications': words[5], 'replacements': words[6],
            'complete_history': False, 'native_acceptance_verified': False,
            'rows': rows}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    print(json.dumps(decode(parser.parse_args().snapshot.read_bytes()), indent=2))
