# First-trial execution milestones

These read-only diagnostics distinguish demand, scheduling, settlement and control observation. They grant no authority, change no receipt timestamp and supply no accepted replay label. Their 5,376 bytes are included in the existing learning workspace bound. Earlier images contain only the original four banks, totaling 3,840 bytes.

The first successful capture start binds the exact boot/trial/capture generation, family, target and original first timestamp. A seal closes collection. Later trials cannot replace the first scope. The banks have independent seqlocks; they are not one simultaneous cross-owner snapshot. Only interpret an even, stable publication word. An empty field alone is not proof that the corresponding operation never happened. Extensions are available only in images containing their symbols; historical images leave newly used reserved words uninterpreted.

| Bank | Bytes / publication word | Writer |
| --- | --- | --- |
| `TRACE_CONTROL_EVIDENCE` | 1,792 / 223 | CPU0, under control-owner exclusion |
| `TRACE_TASK_EVIDENCE` | 1,024 / 127 | Existing task-owner gate, including CPU3 settlement |
| `TRACE_WORK_EVIDENCE` | 512 / 63 | CPU0 workload owner |
| `TRACE_CLOSING_EVIDENCE` | 512 / 63 | CPU0 root, helper and task-owner boundaries |
| `TRACE_DRAIN_WORK_EVIDENCE` | 512 / 63 | CPU0, final predicate under Work exclusion |
| `TRACE_DRAIN_TASK_EVIDENCE` | 1,024 / 127 | Existing TaskGuard, query/lifecycle/cleanup |

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

The separate `BASELINE_SERVICE_EVIDENCE` bank follows the protected scheduling hint through real Pending/Unknown baseline, renewal and closing receipts, including faulted restoration. An independent replay-owner projection also retains the hint for initialized Drain with a scope, token and entered work activation, even after Root completes. The projection publishes before releasing the replay gate; it reads no other owner and supplies no authority. Run, CloseSources and absent ownership clear that reason. Candidate initial execution is not covered by the baseline receipt cache.

One helper opportunity can contain two separately billed pieces: replay service, then at most one bounded queued construction and one 4 KiB launch cleanup if replay returned Ok or Again and the hint remains set. Again can indicate either a full launch cache or full admission queue; other errors do not receive this exception. Cleanup requires a positive Created, Failed or Cancelled receipt. Queued, Unknown and query errors retain custody. Both pieces retain the original IDs and deadlines, and the second requires fresh service credit after the first bill settles. The diagnostic ticket, body timings and final credit fields describe the replay piece only; that ticket closes before the admission piece begins. Actual Scheduler billing and replay capture account for both pieces.

The closing extension keeps the first published closing identity. Root publishes its full ApplyId, version, snapshot and approved deadline before asynchronous executor work. A Release store of the version arms task-side matching; task writers retain their existing task gate. A different closing identity increments an explicit conflict count rather than replacing the first. Repeated closing attempts and other families therefore cannot be inferred from one retained chain.

Additional task-bank words are:

| Words | Meaning |
| --- | --- |
| 72–79 | Closing probe child: same eight fields as the original child row, matched by group, request ID and full caller key |
| 88–90 / 91 | Closing installation version/snapshot/time; count of mismatching installation snapshots |
| 92–95 | Closing cancellations, selections, settlements and reconciliation counts |
| 96–103 | First closing selection, same format as word 16 |
| 104–111 | First nonzero closing physical completion and settlement, same format as word 32 |
| 112–119 | First closing receipt advance, same format as word 40 |
| 120–125 / 126 | First Applied closing reconciliation, same format as word 56; failed settlement receipt-query count |

The production `complete_locked` qualification includes first and closing versions. Each lane's writer uses its own predicate, so closing observations do not inflate first-policy counters. The actual-function regression passes through the real task gate and Scheduler; restoring the old first-only qualification fails its closing assertion. A physical completion row describes one dispatch segment, not the entire child's exit.

Additional work-bank words are:

| Words | Meaning |
| --- | --- |
| 31–33 | Drain calls and first/latest entry |
| 34–36 | Poll error count, first original domain error+1 and observation |
| 37–39 | First closing version, plan sequence and mismatching probe-version count |
| 40–42 | First probe ID, original deadline and creation observation |
| 43–46 | First submit entry/return/result, then first successful return |
| 47–49 | First actual outcome observation, returned physical finish on success, result |
| 50–55 | First blocker/time, latest blocker/time, first workload observation of closing Applied, first completed drain |
| 56–58 | Probe submit count, latest return and result |
| 59–62 | Probe queue-selection count, latest SpawnState tag/time and actual service dispatch sequence |

Work blocker tags are measurement wait-all=1, probe wait=2, core=3, tasks=4, storage=5, IRQ=6, echo=7, prewarm=8 and timer=9. Submit/outcome result tags use the existing result encoder. Busy retries keep the original ID and deadline. Poll errors propagate unchanged; diagnostics do not turn NotReady, Capacity or Budget into permission to continue.

The closing bank has this layout:

| Words | Meaning |
| --- | --- |
| 0–7 | Magic/version, boot/trial/generation, first timestamp and target key |
| 8–18 | Full ApplyId, policy version, snapshot, publication, approved deadline and arm observation |
| 19–24 | Helper opportunities, eligible second pieces, second pieces without an entered service body, task-gated admission entries, first actual body sequence/time |
| 25–29 / 30–34 | First selected request / first selected probe: ID, caller key, SpawnState tag and observation |
| 35–39 | All selected attempts, Queued/Deferred results, Created results, other results, latest helper opportunity |
| 40–47 | First task-drain blocker time/reason and six raw detail fields |
| 48–51 | Latest task-drain blocker/time, blocker count and first clear observation |
| 52–55 | First original poll failure stage/code/time and total tagged failure count |
| 56–60 | Latest root-success/pending/Again bits (1/2/4), latest second-piece return, identity conflicts, first-selected sequence and first-probe-selected sequence |
| 61–62 | Exact probe caller ObjectKey, bound in actual replay `spawn` before queue submission |

SpawnState tags are Queued=1, Created=2, Failed=`3 | ((error+1)<<8)`, Unknown=4, Cancelled=5. The normal selector and targeted helper both emit actual selections. Aggregate selection counts cover the armed scope through seal; they are not all necessarily targeted-helper selections or pre-Applied work. Compare the recorded service sequences before attributing a queue choice to a helper body. No service body and no task-gated admission entry are distinct observations.

Task-drain blocker reasons are child task=1, queued launch=2, retained exit=3, vector=4, local spawn=5, endpoint queue/reservation=6 and send lease=7. Details identify the corresponding task/request/exit or endpoint. The first and latest blocker can differ. Clear means this task owner returned no blocker, not that every other owner or capture source has drained.

Original evidence failure stages 1–4 are request lookup for arming, arm, request lookup for result, and result publication. Codes 1–5 name evidence NotReady/Busy/Owner/Stale/Capacity; `0x100 + learning_error + 1` preserves the inner Capture error. Domain stages 5–8 name root poll, pending-closing probe query, post-Applied probe query, and task drain, with code `0x10000 + domain_error + 1`. Not every earlier return has a stage tag: absent PollOrigin does not prove success. The work poll return remains separately recorded before propagation.

The two Drain custody banks are armed only for the same first scope after closing publication. The original Work completion predicate is unchanged. A diagnostic scan of its fixed 100 requests records Queued, Active and Settled-but-unreported counts. It calls no other owner. Work words 0–7 hold magic/version, boot/trial/generation, original first timestamp, blocked count and first clear observation. First and latest blocked snapshots start at 8 and 32; each contains:

| Relative words | Meaning |
| --- | --- |
| 0–3 | Observation, Queued count, Active count, Settled-but-unreported count |
| 4–8 | First unmet original request ID, phase (Queued=1/Active=2/Settled=3), armed/reported bits (1/2), outcome, physical finish if Completed |
| 9–11 | Warm original ID, original deadline and active flag; zero ID means absent |
| 12–13 | Background settled flag, watched ID (first unmet request, else warm) |

Outcome tags are Completed=1, Rejected=2, TimedOut=3, Pending=4. First/last records are blocked snapshots, not a ledger of all changing blockers. Once clear is recorded the most recent blocked snapshot remains available. Later trials cannot replace it.

Task uses one bounded atomic read of Work's publication and both watch identities, with an acquire fence before checking that publication is unchanged and even. It acquires no Work lock. A query or lifecycle event may therefore be omitted under concurrent publication; no authority depends on a diagnostic. Each retained event includes the watch snapshot time it matched. The first-watch lane stores the **latest event for the first watched ID**, not that ID's first event. The latest-watch lane can lag Work's changing latest watch. Compare times and identities before attributing a wait.

Task header words 0–7 hold magic/version, exact scope and caller key; 8–10 count matched queries, lifecycle calls and cleanup calls, while 12 counts rejected caller conflicts. Query lanes start at 16 and 32. Their relative words 0–15 are observation, original request ID, caller key, query tag, full child key, Life, flags, original request deadline, exit code, exit finish, cached-result tag, cached physical finish, matching watch time and reserved zero. Life is absent=0, Free=1, Ready=2, Running=3, Waiting=4, Exiting=5. Flag bits are pending return=1, file busy=2, active dispatch=4, actual ExitRecord present=8. Query tags retain SpawnState's existing 1–5 encoding, cached delivery=6 and query error=`7 | ((error+1)<<8)`. Cached delivery performs no new admission query. The actual query's single exit-position lookup is reused for diagnostics and original consumption.

Lifecycle lanes start at 48/64 and cleanup lanes at 80/96. Each stores entry/return observations, original request ID, original child key, caller key, entry Life/flags, original task deadline, reserved zero, cleanup result (or zero for lifecycle), post-Life, reserved zero, matching watch time and reserved zero. Cleanup result uses the existing result encoder (Ok=2, error=`5 | ((error+1)<<8)`). Original identity is copied before the operation, so successful cleanup cannot replace it with the cleared task. These hooks neither schedule extra work nor reconstruct completion times.

Actual-source host regressions execute Work poll, TaskGuard/SpawnAdmission query, lifecycle and cleanup wrapper. Hardware cleanup, return processing and Work request outcomes are controlled boundaries; real Scheduler dispatch exercises the active-child flag. Cached and error queries retain their original behavior. Separate removal of each of the four reporting hooks fails its named assertion. Native timing, hardware cleanup and which blocker controls the remaining tail require native evidence.
