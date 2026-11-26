# V0.20.1 kernel algorithms — wave 3

Baseline for this wave: a198013264ad4cbe06c7ebec14f5a1424b9d229b.

Wave 2 (d8c8b11, Actions run 45817307702) completed all eight matrix lanes: D02 5, console 6, FramePool 18, control-model 5, D07 5, FrameMeta 25, contiguous frames 9, prototype MLP 1. Total 74 passed, 0 failed; integration was blocked by the one rustfmt diagnostic in the shared model. Commit a198013 applies the exact formatting fix. Full regression for that fix is separately tracked by run 45818071935.

## Scope and decisions

- T15 IPC send: a request strictly above send_hi cannot be a retained replay; bypass the history scan only for that case. All existing identity/generation checks, payload validation, old-key conflict detection, DONE receipt custody, capacity checks and FIFO are preserved. New sends have O(1) queue lookup cost instead of O(N), excluding O(payload) copying. Old-key replay is still bounded O(N).
- T16 file structure: memoize parent paths to root with three-state marks local to each scan. No recursion, one 256-byte scratch array; each previously unseen edge is validated once and marked once. Reachability falls from worst-case O(N^2) to O(N) for fixed system-object count, not the entire mount scan. Retain independent reference checks, system-object exclusion, parent generation, inode/bitmap and content verification. No format, journal or FLUSH change. Public mount test exercises a 256-inode fixture with a deep tree and a disconnected cycle, and a repeated scan after failure.
- T17 D15: two contiguous byte copies and matching timestamp fills per enqueue; preserve per-byte arrival age, admission checks, clock order, write receipts and hardware pump behavior. No change to MMIO or fault semantics.
- T18 D07: registration checks the occupied prefix, including permanent tombstones, once. Only registration writes Some, unregister never removes a slot. Compute minimum raw slack then convert to microseconds once. Retain generations, authorization callback and hard deadline behavior. Full-registry regression verifies stale and exhaustion errors, failed verification, higher-generation reuse, and slack values.
- T19 CI: 11 module matrix lanes, independent mandatory format job, full host regression after module checks. Keep prior commit runs separate by commit SHA instead of cancelling them on every new branch push. A failed format job still fails the workflow; it no longer prevents collecting host integration evidence.

## Evidence ledger

Executed reference model checks in the orchestration runtime: 138,125 functional/typed parent graphs, 128,000 IPC send/receive state transitions, 314,160 ring input/wrap combinations, 66,049 timer slot selections; all matched the old rules. The graph and IPC checks are simplified state models, not native authorization tests. New Rust interface regressions added before staging the implementation, but local Rust RED/GREEN execution remains unavailable; CI must provide real compilation and regression evidence. Self-review against current V0.20 spec and source; no independent reviewer or native ARM/x86 performance measurement. No claim of G1/G4/G5 or release readiness.

Ruling: leave the disk wire format, resource authority, fixed CPU0, isolated advisory brains and single-device scope unchanged. Do not rewrite scheduling or protected allocation interfaces in the absence of native validation. Do not merge into V0.20.
