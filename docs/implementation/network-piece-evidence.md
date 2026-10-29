# Network piece provenance

These diagnostics identify operations belonging to an original CPU0 physical reservation. They grant no credit, acknowledge no work and supply no accepted learning evidence. Two fixed 512-byte banks plus CPU0 scalar context occupy at most 1,536 bytes of global kernel storage. They do not enlarge the learning workspace, interval bank, queue or CPU budgets.

The existing TaskGuard copies each actual service Dispatch before its CPU origin is sampled. After the original revalidation, `network_turn` matches its returned Credit with that copy. A mismatch records a diagnostic error and does not change execution. Each checkpoint freezes the original measured CPU and finish time, clears the live marker, then follows the original completion, mechanism progress and fresh-credit path. The resumed piece begins with an Unknown stage and empty mask. No checkpoint, clock read or device operation is added by a marker. Marker writes inside a piece contribute to its measured CPU; setup and bank publication follow the existing diagnostic convention outside that interval.

CPU0 owns `NETWORK_PIECE_EVIDENCE`. All access to its live `UnsafeCell` context checks CPU0 first; the Board contract already excludes these queues from IRQ handlers. The marker copies only volatile scalars, with no owner query, lock or progress callback. Non-network helpers between reservations cannot mark a completed network piece. Existing TaskGuard exclusion owns the separate `NETWORK_SETTLEMENT_EVIDENCE` writer. Its reader makes one bounded seqlock attempt and checks the complete Dispatch, actual CPU and finish. An odd, changing, malformed or mismatched snapshot is skipped, without waiting or altering the original Scheduler result.

All words are little-endian u64. Both banks use publication word 63; only interpret a stable even publication. Their independent publications are not an atomic cross-owner snapshot. Raw symbols and final report fields survive failed runs. Latest rows may advance after a host observer's last live sample; compare full identities before relating them.

The piece bank has magic/version at 0–1, completed-piece count at 2, binding errors at 3 and active-context mismatches at 4. Its record starts at 8. The settlement bank has magic/version at 0–1, matching settlement attempts at 2, unavailable snapshots at 3, identity/measurement mismatches at 4 and qualifying physical overrun count at 5. Its latest record starts at 8 and its immutable first physical overrun starts at 36.

| Relative words | Meaning |
| --- | --- |
| 0–4 | Original dispatch sequence, full thread key and full group key |
| 5–9 | CPU, core generation, window, original dispatch start and reserved CPU |
| 10–12 | Dispatch reason (Minimum=0, Weighted=1, FairRecovery=2, Service=3), waited ns and policy version |
| 13–14 | Network-turn identity and original checkpoint ordinal (initial piece=0) |
| 15–18 | First stage, last stage, union mask (`1 << stage`) and mark count |
| 19–20 | Original actual CPU ns and finish ns passed to completion |
| 21–22 | Settlement records only: original Scheduler result and still-active flag |

Result is Ok=1 or `2 | ((domain_error+1)<<8)`. The first-overrun lane freezes only when the original Scheduler returns Budget, actual CPU exceeds the reservation and the dispatch is no longer active. An arbitrary Budget code or retained-active error does not qualify. Later success and later overruns cannot replace that first record. Other service dispatches with a different sequence are ignored rather than mislabelled as network work.

| Stage codes | Operations |
| --- | --- |
| 0 | Unknown continuation; no operation marker retained |
| 1–5 | TCP health, clock validation, time publication, Ethernet TX, Ethernet RX |
| 6–10 | RX poll, virtio header, delivery predicate, copy, release/rearm |
| 11–15 | Queue status, flush due, used-index cache acquisition, idle IRQ ACK, used-element cache acquisition |
| 16–20 | Queue decode, validation, payload cache acquisition, copy/completion publication, completion IRQ ACK |
| 21–28 | TCP flush, socket snapshot, ingress, ingress result, egress, remote state, IPC drain, TCP abort |

First/last/mask identify participating operations, not each operation's CPU share. Queue stages can be used by TX or RX; retain the whole stage set and calling context. These records alone do not prove WCET, loss freedom or the cause of the earlier unbound stage-44 overrun. A matching sticky Task overrun receipt is required to attribute a concrete physical overrun.

Actual-source host regressions first fail independently on missing kernel, driver and TCP facts. The kernel fixture executes `network_turn`, its checkpoint/resume flow, the real TaskGuard and real Scheduler completion; TCP/device behavior and capture are explicit boundaries. Library fixtures execute the actual Queue, RX and TCP paths with the original 8/10/12 checkpoint counts and the one-checkpoint clock-error path. Coverage includes delayed old bills, nested independently paid helpers, denied credit, bad binding, foreign-CPU markers, Unknown error continuations, malformed pending snapshots, multiple stages in one bill, exact CPU/finish per piece, real quarantine and first-overrun retention after legitimate new-generation recovery. Controlled result injections separately exercise retained-active and nonphysical Budget serialization. Host tests do not establish native SMP/IRQ behavior or timing.
