"""Select observed ordinary-file fault points; this is not a matrix verdict.

Callers must first verify the clean mode-2 capture and its original raw NBD
transcript. These indices are device requests, never EL0-consumption labels.
"""
from __future__ import annotations
import hashlib
from verify_smp import require
from verify_v13_a10 import payload

MAX_REQUEST_COUNTER_SKEW = 9


def overwrite_window(capture: dict, rows: list[dict]) -> dict:
    require(capture['mode'] == 2, 'fault selector requires clean overwrite mode')
    writer = capture['writer']
    calls = [row for row in capture['records'] if row['owner'] == writer and row['result'] == 0]
    writes = [row for row in calls if row['operation'] == 4]
    receipts = [row for row in calls if row['operation'] == 5 and row['durable_seq'] == 3]
    require(len(writes) == len(receipts) == 1, 'missing/ambiguous overwrite invocation')
    write, receipt = writes[0], receipts[0]
    require(write['data_length'] == 4096 and write['offset'] == 0
            and write['data_sha256'] == hashlib.sha256(payload(3)).hexdigest()
            and write['sequence'] < receipt['sequence'], 'wrong overwrite bytes/receipt order')
    # This bounded scenario changes one allocated page and its existing inode:
    # BEGIN, two two-block REDOs, COMMIT, and two durability barriers. A native
    # checkpoint or any additional I/O requires another explicitly reviewed
    # window rather than silently inheriting these fault-point labels.
    require(receipt['writes'] - write['writes'] == 6 and receipt['flushes'] - write['flushes'] == 2,
            'overwrite is not the declared two-REDO transaction')
    first = write['writes'] * 8 + write['flushes']
    end = receipt['writes'] * 8 + receipt['flushes']
    require(0 <= first < end <= len(rows), 'native counters exceed captured mutation stream')
    require([row['mutation'] for row in rows] == list(range(1,len(rows)+1))
            and all((row['kind'] == 1 and row['length'] == 512 and row['offset'] % 512 == 0)
                    or (row['kind'] == 3 and row['offset'] == row['length'] == 0) for row in rows),
            'merged/missing/invalid native sector boundaries')
    for boundary, event in ((first,write),(end,receipt)):
        observed = rows[:boundary]
        require(sum(row['kind'] == 1 for row in observed) == event['writes'] * 8
                and sum(row['kind'] == 3 for row in observed) == event['flushes'],
                'native reply I/O counters disagree with device prefix')

    # The protected counters advance only after a complete logical operation,
    # while NBD records each request on receipt. With reversed replies the raw
    # request stream may therefore be ahead by one bounded native batch. Select
    # only the unique six-block journal shape: five records, durability barrier,
    # COMMIT record, durability barrier. Never infer a boundary from the shift.
    shape = [1] * 40 + [3] + [1] * 8 + [3]
    candidates = []
    for skew in range(MAX_REQUEST_COUNTER_SKEW + 1):
        selected = rows[first + skew:end + skew]
        if len(selected) != len(shape) or [row['kind'] for row in selected] != shape:
            continue
        writes_in_window = [row for row in selected if row['kind'] == 1]
        if all(right['offset'] == left['offset'] + 512
               for left,right in zip(writes_in_window,writes_in_window[1:])):
            candidates.append((skew,selected))
    require(len(candidates) == 1, 'missing/ambiguous native two-REDO journal request window')
    skew,selected = candidates[0]
    return dict(points=[row['mutation'] for row in selected],
                flush_points=[row['mutation'] for row in selected if row['kind'] == 3],
                writer=writer,write_event=write['sequence'],fsync_event=receipt['sequence'],
                before=dict(writes=write['writes'],flushes=write['flushes']),
                after=dict(writes=receipt['writes'],flushes=receipt['flushes']),
                request_counter_skew=skew,
                boundary_semantics={'before':'request not executed','after-ack':'device reply sent'},
                A10_complete=False,scope='planned cuts from one verified native overwrite; no executed matrix')
