"""Decode bounded application-queue diagnostics; never admission evidence."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = 0x4359_4150_5051_3031
ROWS, ROW_WORDS = 32, 24
WORDS = 8 + ROWS * ROW_WORDS
STAGES = ('submit', 'next', 'acknowledge', 'status', 'finish',
          'reserve', 'release', 'cancel')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(data):
    require(len(data) == WORDS * 8, 'application-request evidence size differs')
    words = struct.unpack(f'<{WORDS}Q', data)
    if not any(words):
        return {'present': False, 'native_acceptance_verified': False}
    require(words[0] > 0 and not words[0] & 1,
            'application-request publication is incomplete')
    require(words[1:5] == (MAGIC, 1, ROWS, ROW_WORDS)
            and words[0] == 2 * words[5] and words[7] == 0,
            'application-request header differs')
    rows = []
    for slot in range(ROWS):
        row = words[8 + slot * ROW_WORDS:8 + (slot + 1) * ROW_WORDS]
        if not any(row):
            continue
        require(row[0] >= 4097 and (row[0] - 4097) % ROWS == slot
                and all(row[i] > 0 for i in (1, 2, 3, 4)),
                'application-request identity differs')
        require(row[5] <= row[6] and row[8] == 0
                and 1 <= row[7] <= len(STAGES)
                and row[14] & ~7 == 0,
                'application-request timing/stage differs')
        state, target = row[9], row[10:12]
        require(state in (0, 1, 2, 3, 4, 5)
                and (target == (0, 0) if state in (0, 1, 5) else
                     target[0] > 0 and (target[1] == 0 if state == 4 else target[1] > 0)),
                'application-request state/target differs')
        complete = bool(row[14] & 4)
        require((complete and row[12] in (1, 2) and row[5] <= row[13] <= row[6])
                or (not complete and row[12] == row[13] == 0),
                'application-request completion differs')
        counts = row[15:23]
        require(counts[0] + counts[5] > 0 and counts[row[7] - 1] > 0
                and 0 < sum(counts) <= words[5]
                and row[5] <= row[23] <= row[6],
                'application-request counters differ')
        rows.append({
            'request': list(row[:2]), 'actor': list(row[2:4]),
            'sequence': row[4], 'submitted_ns': row[5], 'observed_ns': row[6],
            'last_stage': STAGES[row[7] - 1], 'state': state,
            'target': list(target), 'available': bool(row[14] & 1),
            'cancelled': bool(row[14] & 2),
            'completion_outcome': row[12] if complete else None,
            'completion_finished_ns': row[13] if complete else None,
            'stage_counts': dict(zip(STAGES, counts)),
            'last_state_change_ns': row[23],
        })
    return {'present': True,
            'scope': 'latest sampled queue observations; replacement and sampling omit history',
            'publications': words[5], 'replacements': words[6],
            'complete_history': False, 'native_acceptance_verified': False,
            'rows': rows}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    print(json.dumps(decode(parser.parse_args().snapshot.read_bytes()), indent=2))
