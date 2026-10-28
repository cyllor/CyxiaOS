# First-trial execution milestones

These read-only diagnostics distinguish demand, scheduling, settlement and control observation. They grant no authority, change no receipt timestamp and supply no accepted replay label. Their 3,328 bytes are included in the existing learning workspace bound.

The first successful capture start binds the exact boot/trial/capture generation, family, target and original first timestamp. A seal closes collection. Later trials cannot replace the first scope. The three banks have independent seqlocks; they are not one simultaneous cross-owner snapshot. Only interpret an even, stable publication word. An empty field alone is not proof that the corresponding operation never happened.

| Bank | Bytes / publication word | Writer |
| --- | --- | --- |
| `TRACE_CONTROL_EVIDENCE` | 1,792 / 223 | CPU0, under control-owner exclusion |
| `TRACE_TASK_EVIDENCE` | 1,024 / 127 | Existing task-owner gate, including CPU3 settlement |
| `TRACE_WORK_EVIDENCE` | 512 / 63 | CPU0 workload owner |

All words are little-endian u64. Raw banks survive in the node directory and final functional report, including failed observations.

Control header words 2–7 contain boot, trial, capture generation, first timestamp and target key. Word 8 is retained identity count, 9 counts attempts whose identity exceeded the eight-row diagnostic limit, 10 is collecting/closed (1/2), 11 is close time, 12–13 are family, 14 counts invalid/conflicting events and 15 counts CPU-total overflow. Rows begin at word 16 with stride 24:

| Row words | Meaning |
| --- | --- |
| 0–6 | Full ApplyId followed by policy version |
| 7–10 | Family, first callback entry, latest callback entry |
| 11–12 | Apply and reconcile call counts |
| 13–17 | First/latest callback result, first Applied observation, measured callback CPU sum, latest observation |
| 18, 21, 23 | Canonical action payload upper/lower u64 and encoded length |
| 19–20 | Original snapshot and publication time |
| 22 | Busy/Again callback count |

Result tags are Pending=1, Applied=2, Unknown=3, Failed=4, callback Err=5. Failed/Err also carry `(error enum + 1) << 8`. Canonical action bytes include the zero candidate index used by the wire encoder. Conflicting action bytes cannot contribute to the original identity's counters. CPU totals describe the measured callback segment; diagnostic reporting overhead is outside that segment.

The task bank binds only the first exact CPU-weight installation whose target and snapshot match this scope. Header words 3–7 retain target, policy version, snapshot and installation observation. Words 8–15 count selections, unused cancellations, settlement attempts, receipt advances, reconciliation queries, settlement errors, group-matching child creations and receipt-query errors. Fixed records retain:

| Start | Meaning |
| --- | --- |
| 16 | First selected dispatch: sequence, thread key, CPU, original dispatch start, reserved CPU, window, policy version |
| 24 | First cancelled sequence and cancellation observation |
| 32 | First nonzero completion: sequence, thread key, CPU, original dispatch start, physical finish, actual CPU, settlement observation |
| 40 | First receipt advance: version, dispatch sequence, physical finish, settlement observation, before/after receipt, settlement error, retained-active flag |
| 48 / 56 | First reconciliation / first Applied reconciliation: observation, observed version, in-flight flag, result, expected version, snapshot |
| 64 | First group-matching created child: key, request ID, creation observation, group key, parent key |
| 80 | First failed receipt query: observation, dispatch sequence, before/after query error codes |

Physical finish and actual CPU come from the original pending completion fields. The original dispatch start is an admission timestamp, not a reconstructed wall start of execution. Receipt advance is observed after actual Scheduler settlement. A failed receipt query remains explicit and cannot manufacture acknowledgement. Inactive or unrelated completions do not perform extra diagnostic receipt queries. Attribute a child only after comparing its request and parent identity with the workload; a matching group alone is insufficient.

The work bank retains exact scope in words 2–7. Words 8–9 record activation count/first completion; 10–13 record first warm-request creation and deadline; 14–19 record submit count, first request/entry/result and first successful return/request. Word 29 separately retains the first submit return. Words 20–22 retain first outcome observation, request and result; word 30 retains the returned actual completion timestamp on success. Words 23–28 retain poll count, first/latest opportunity and longest gap/endpoints.

The host regression executes the actual task gate and `complete_locked`, control polling and warm-work functions against a real Scheduler. Hardware, transport, history and stability callbacks are controlled boundaries. Independent removal of each reporting hook fails its named assertion; storage tests distinguish physical completion, settlement and observation, identity overflow, conflicting actions and later-trial replacement. Native timing and causality still require the instrumented run.

The separate `BASELINE_SERVICE_EVIDENCE` bank now follows the protected scheduling hint through real Pending/Unknown baseline, renewal and closing receipts, including faulted restoration. One helper opportunity can contain two separately billed pieces: replay service, then at most one bounded queued admission if replay returned successfully and the hint remains set. Its diagnostic ticket, body timings and final credit fields describe the replay piece only; that ticket closes before the admission piece begins. Actual Scheduler billing and replay capture account for both pieces. A stale hint supplies no execution authority, and Candidate initial execution is not covered by the baseline receipt cache.
