"""Strict integrity decode of bounded root Quiescing gate diagnostics."""
import argparse
import json
from pathlib import Path
import struct

MAGIC = 0x4359_5155_4945_3031
STATES = ('Pending', 'Applied', 'Failed', 'Unknown')
GATES = ('', 'job', 'execution', 'live_lease', 'partial_scan', 'fixture_wait',
         'scanning_entered', 'fixture_error')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def decode(data):
    require(len(data) == 512, 'Quiescing diagnostic size differs')
    w = struct.unpack('<64Q', data)
    base = dict(native_acceptance_verified=False, complete_history=False)
    if not any(w):
        return dict(base, status='not_published')
    if w[0] & 1:
        # An interrupted first header may contain only its original prefix.
        require(w[1:4] in ((0, 0, 0), (MAGIC, 0, 0), (MAGIC, 1, 0),
                            (MAGIC, 1, 64)), 'Quiescing diagnostic header differs')
        return dict(base, status='in_progress')
    require(w[0] > 0 and w[1:4] == (MAGIC, 1, 64)
            and w[0] == 2 * w[4] and not any(w[5:8]),
            'Quiescing diagnostic header differs')
    p = w[8:]
    require(p[0] > 0 and p[1] > 0 and p[7] == 0 and 1 <= p[8] <= 7
            and p[10] <= 512 and p[11] <= 512 and p[12] <= 512
            and not any(p[44:]), 'Quiescing identity/stage/reserved differs')
    require((p[2] > 0 and 1 <= p[3] <= 16 and p[4] > 0 and p[5] > 0 and p[6] > 0)
            or not any(p[2:7]), 'Quiescing request identity differs')
    require(all(p[i] in (0, 1) for i in (26, 27, 28, 35, 40, 41, 42))
            and p[43] <= 20, 'Quiescing flags/error differ')
    stage = p[8]
    if stage in (2, 3):
        require(p[10] < p[13] <= p[11] <= min(p[10] + 8, 512) and p[12] == 0
                and p[24] < 4 and p[15] == p[0] and 0 < p[16] and 0 < p[17]
                and 0 < p[19] and 0 < p[20] and p[22] <= p[23]
                and 1 <= p[29] <= 16 and p[30] > 0
                and not any(p[35:44]), 'Quiescing desired binding differs')
        require((p[24] == 2 and 1 <= p[25] <= 20) or (p[24] != 2 and p[25] == 0),
                'Quiescing execution error differs')
        require((stage == 2 and ((p[14] == 1 and p[24] in (0, 3))
                                 or (p[14] == 2 and p[24] == 1 and p[26] == 0)))
                or (stage == 3 and p[14] == 4 and p[28] == 0 and p[9] < p[23]
                    and (p[24] == 2 or p[24] == 1 and p[26] == 1)),
                'Quiescing blocker predicate differs')
    else:
        require(not any(p[13:35]), 'Quiescing non-desired stage retains unrelated desired')
        if stage == 1:
            require(p[11] == 0 and p[12] == p[10] and p[35] == 1
                    and p[36] > 0 and p[37] > 0 and p[38] < 4
                    and not any(p[41:44]), 'Quiescing job gate differs')
        else:
            require(not any(p[35:41]), 'Quiescing non-job stage retains unrelated job')
            if stage == 7:
                require(p[9] == p[11] == p[41] == p[42] == 0
                        and p[12] == p[10] and p[43] > 0,
                        'Quiescing fixture error differs')
            else:
                require(p[43] == 0 and p[10] <= p[11] <= min(p[10] + 8, 512),
                        'Quiescing scan boundary differs')
                require((stage == 4 and p[12] == p[11] < 512 and p[41] == p[42] == 0)
                        or (stage == 5 and p[11] == p[12] == 512 and p[41] == 1 and p[42] == 0)
                        or (stage == 6 and p[11] == 512 and p[12] == 0 and p[41] == p[42] == 1),
                        'Quiescing fixture/scan result differs')
    return dict(base, status='observed', publications=w[4], boot_epoch=p[0],
                root_token=p[1], trial_id=p[2], family=list(p[3:5]),
                target=list(p[5:7]), gate=GATES[stage], predicate_ns=p[9] or None,
                cursor=list(p[10:13]), slot=p[13] - 1 if p[13] else None,
                blocker_reason=p[14] or None, apply=list(p[15:21]) if stage in (2, 3) else None,
                stamp=list(p[21:24]) if stage in (2, 3) else None,
                execution_state=STATES[p[24]] if stage in (2, 3) else None,
                execution_error=p[25] or None, execution_observed=bool(p[26]),
                started=bool(p[27]), one_shot=bool(p[28]), action_family=list(p[29:31]),
                desired_job=p[31] or None, owner_times=list(p[32:35]),
                job=list(p[36:41]) if p[35] else None,
                fixture_ready=bool(p[42]) if p[41] else None, fixture_error=p[43] or None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    print(json.dumps(decode(parser.parse_args().snapshot.read_bytes()), indent=2))
