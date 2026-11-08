"""Decode actual EL1 phase-9 observations; no session authority is granted."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = 0x4359_5853_4143_5431
WORDS, ROW_WORDS = 104, 24
SLOTS = ('first_registered', 'first_activity_failure', 'latest_activity', 'latest')
REASONS = {0: 'accepted', 1: 'transport_or_epoch', 2: 'invalid',
           3: 'not_ready', 255: 'other'}
MAX = 2**64 - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def authority(words):
    return dict(zip(('epoch', 'level', 'last_rx_ms', 'generation'), words))


def completed(row, slot, total, *, boot, version):
    require(0 < row[1] <= total and row[2] > 0 and row[6] in (0, 1)
            and row[12] in (0, 3) and row[13] in REASONS
            and not any(row[21:] if version == 2 else row[18:]),
            'invalid session-activity record')
    if boot is not None:
        require(row[2] == boot, 'session-activity BootEpoch mismatch')
    require((row[12] == 0) == (row[13] == 0),
            'session-activity status/reason mismatch')
    before, after = row[8:12], row[14:18]
    require(before[1] <= 2 and after[1] <= 2
            and before[3] > 0 and after[3] > 0
            and before[3] <= after[3] <= min(MAX, before[3] + 1)
            and (not before[1] or before[0] > 0)
            and (not after[1] or after[0] > 0),
            'invalid session-activity authority state')
    token, requested, live, connected, fresh = row[3:8]
    if version == 2:
        require(row[18] <= row[19] <= row[20] <= fresh,
                'session-activity broker time ordering differs')
    if slot == 0:
        require(token == 1 and row[12] == 0 and row[0] == 2,
                'invalid first session registration')
    elif slot == 1:
        require(token == 3 and row[12] == 3 and row[0] == 2,
                'invalid first activity failure')
    elif slot == 2:
        require(token == 3, 'latest activity is not token 3')

    def disconnected():
        return (before[0], 0, before[2], min(MAX, before[3] + bool(before[1])))

    if row[13] == 1:
        require(token != 0 and (not connected or requested != live)
                and after == disconnected(), 'invalid transport/epoch rejection')
    else:
        require(token == 0 or connected and requested == live,
                'session-activity transport guard was bypassed')
        if row[12] == 0:
            if token == 0:
                require(after == disconnected(), 'disconnect did not close authority')
            elif token == 3:
                require(live > 0 and before[0] == live and before[1] > 0
                        and before[3] != MAX and fresh >= before[2]
                        and fresh - before[2] < 1500
                        and after == (before[0], before[1], fresh, before[3]),
                        'activity renewed expired or foreign authority')
            else:
                require(token in (1, 2) and live > 0
                        and after[0] == live and after[1] == token
                        and after[2] == fresh and fresh >= before[2],
                        'invalid accepted session registration')
        elif row[13] == 2:
            require(token != 3 and after == before,
                    'invalid rejection mutated authority')
        elif row[13] == 3:
            require(token in (2, 3) and after == disconnected(),
                    'not-ready rejection renewed authority')
    result = {
        'publication': row[0], 'ordinal': row[1], 'boot_epoch': row[2],
        'token': token, 'requested_epoch': requested, 'live_epoch': live,
        'connected': bool(connected), 'fresh_ms': fresh,
        'before': authority(before), 'after': authority(after),
        'status': row[12], 'reason': REASONS[row[13]],
    }
    if version == 2:
        result['broker_timing'] = dict(zip(
            ('request_entry_ms', 'network_finished_ms', 'credit_acquired_ms'), row[18:21]))
    return result


def decode(data, *, boot=None):
    require(len(data) == WORDS * 8, 'session-activity evidence must be 832 bytes')
    words = struct.unpack(f'<{WORDS}Q', data)
    if not any(words):
        return {'present': False, 'status': 'not_published',
                'native_acceptance_verified': False}
    require(words[0] == MAGIC and words[1] in (1, 2)
            and words[2:4] == (WORDS, ROW_WORDS),
            'invalid session-activity header')
    total, activity, rejected, accepted = words[4:8]
    require(rejected + accepted <= activity <= total
            and activity - rejected - accepted <= 1,
            'invalid session-activity counters')
    records, pending = {}, []
    for slot, name in enumerate(SLOTS):
        row = words[8 + slot * ROW_WORDS:8 + (slot + 1) * ROW_WORDS]
        if row[0] & 1:
            pending.append(name)
        elif row[0] == 0:
            require(not any(row), 'unpublished session-activity row is nonzero')
        else:
            records[name] = completed(row, slot, total, boot=boot, version=words[1])
    current = records.get('latest')
    # The CPU0 writer increments counters before publishing its four rows.
    # A stopped read may be between either operation; there is no bank lock.
    counters_pending = rejected + accepted != activity
    counters_pending |= bool(total and (current is None or current['ordinal'] != total))
    if 'latest_activity' in records and current is not None:
        counters_pending |= records['latest_activity']['ordinal'] > current['ordinal']
    return {
        'present': True,
        'scope': 'bounded actual EL1 broker observations; not admission or execution authority',
        'status': 'in_progress' if pending or counters_pending else (
            'not_published' if not total else 'sampled'),
        'counts': {'total': total, 'activity': activity,
                   'rejected_activity': rejected, 'accepted_activity': accepted},
        'records': records, 'in_progress_rows': pending,
        'counters_in_progress': bool(counters_pending),
        'complete_history': False, 'native_acceptance_verified': False,
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--boot', type=int)
    args = parser.parse_args()
    print(json.dumps(decode(args.snapshot.read_bytes(), boot=args.boot), indent=2))
