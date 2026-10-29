# Recovery phase and TaskGuard evidence

The preceding stopped run binds the preparation barrier to RecoveryRecipe
ApplyId `[1,1,443,0,4153,14]`, version 406, started/Unknown. Its last recorded
state transition is not its last poll: repeated equal Control states suppress
ordinary evidence updates. Control reconcile queries the receipt; Services
supervisor polls actually call the recovery backend. A root-cause decision
therefore needs the original supervisor step and the matching resource facts.

This change adds passive evidence, not a recovery shortcut. The generic
supervisor invokes an optional default-empty observer after the original step
and record update. It supplies the original receipt/policy, passed time, phase
and issued flags before/after, original mapped step result and states before/
after. Default backends remain unchanged. The native observer writes only
bounded metadata under the existing Services owner gate.

Task readonly-drain, stopped and running preserve their original short-circuit
order. Each FILE/vector/IPC/memory/active predicate is evaluated once if reached.
The evidence reuses that value; it adds no query, clock, lock or dispatch.
IPC errors still propagate. Memory results which originally became booleans
still do so. The matching full Dispatch is copied from the original active
lookup. Running binds `start_apply`; drain/stopped bind `stop_apply`. A
missing identity, gate Busy or recovery-index failure produces no new Task row.

Unknown retains custody and continues through its original phase. Io/NotReady
at an ambiguous stop/start retains issued and is queried rather than reissued;
Again/Busy keeps its original retry behavior. No new lifecycle opportunity,
probe, request, generation or completion is created. All budgets and deadlines
are unchanged.

## Header layout

The existing `DOMAIN_CONTROL_EVIDENCE` header's reserved words 256–511 are
reused; no static bank or workspace allocation is added. Ranges below include
both endpoints. Each lane has its own seqlock and owner-serialized writer.

| Lane | Recipe 1 | Recipe 2 |
| --- | --- | --- |
| Services base | 256 | 320 |
| Latest 26-word step | 264–289 | 328–353 |
| First Unknown in current ApplyId | 292–317 | 356–381 |
| Services publication | 319 | 383 |
| Task base | 384 | 448 |
| Latest 48-word predicate | 392–439 | 456–503 |
| First-blocked summary | 440–445 | 504–509 |
| Task publication | 447 | 511 |

Each base has magic at +0, schema 1 at +1, total observations at +2, current
ApplyId observations at +3, identity changes at +4 and first-record presence
at +5. Services magic is `0x4359525356430001`; Task magic is
`0x43595254534b0001`. Full six-field ApplyId changes clear the old first row
and current count. These are bounded latest/current-identity diagnostics, not
an append-only recovery journal or a global first-failure record.

Services offsets 0–25:

| Offsets | Fields |
| --- | --- |
| 0–5 | ApplyId: boot, controller, plan, action index, target id/generation |
| 6–10 | Recipe, policy version (0 absent), next generation, original start, passed now |
| 11–14 | Phase before, issued before, phase after, issued after |
| 15–17 | Method, mapped result, error+1 |
| 18–22 | State before/error, state after/error, finished time |
| 23–25 | Policy snapshot, installed-until, observing CPU |

Methods 1–6 are close admission, readonly drain, request stop, stopped query,
start generation and running query. Result 1 is Ok(true), 2 Ok(false), 3 Err.
Successful asynchronous stop/start is mapped by the original supervisor to
Ok(false) with issued=true; it is not a refusal. State tags are Pending=1,
Applied=2, Failed=3, Unknown=4. Passed now is the original caller's time, not
a new backend-entry/finish clock measurement.

Task offsets 0–47:

| Offsets | Fields |
| --- | --- |
| 0–7 | Full original ApplyId; checked task id/generation |
| 8–11 | Method (1 drain,2 stopped,3 running), first blocker, result, error+1 |
| 12–18 | Life+1, pending, closed, heartbeat, endpoint id/generation, queried mask |
| 19–23 | FILE busy, vector complete, IPC depth, memory result kind/value |
| 24–37 | Active-present plus the full original Dispatch (13 words) |
| 38–44 | Deadline, task CPU/group, start/stop ApplyId match flags, recipe |
| 45–47 | Reserved zero |

The queried mask is FILE=1, vector=2, IPC=4, memory=8, active=16. An unset bit
means unavailable, not false/healthy. Memory kind 1 stores Ok page count; kind
2 stores error+1. It may legitimately retain Stale while the original stopped
predicate succeeds. Life tags are Free=1, Ready=2, Running=3, Waiting=4,
Exiting=5.

Drain blocker codes are not closed=1, pending=2, FILE busy=3, vector=4,
IPC depth=5, active dispatch=6. Stopped codes are life=1, endpoint=2, remaining
memory owner=3, active dispatch=4. Running codes are life=1, no heartbeat=2,
no endpoint=3, memory query failure=4. Code 8 accompanies a propagated query
error. The first-blocked summary stores reason, method, checked key, observation
count and result tag. It does not retain the full first error/Dispatch; those
belong only to latest.

Services and Task lanes are **not one atomic or exact-call snapshot**. Full
identity, method/result and counter comparisons provide bounded correlation.
A Busy or pre-step return can leave an older Task row; a reader must not
substitute it for a new call. Terminal queries, lookup/time-regression errors
and other pre-step supervisor returns do not invoke the observer. Counts are
successful nonterminal step observations, not every API/owner entry. Odd,
missing or mismatched lanes are unavailable evidence and never acceptance.

## Regression evidence

Source journeys derive from the existing v1.3 acceptance plan's retained
Unknown custody and real recovery requirements. Before production changes,
`python3 tests/host/test_recovery_observation.py` compiles both groups and
fails behaviorally for missing phase/backend evidence and missing TaskGuard
predicate evidence. RED is committed as `842d939`; GREEN is `6c35c62`.

The final two groups exercise three actual supervisor/kernel-backend scenarios
and two paid TaskGuard scenarios. They cover repeated Unknown, receipt queries
without progress, original times, phase/issued, Again/Busy vs Io/NotReady,
recipe/full-identity separation, actual pending/FILE/vector/IPC/active blockers,
unchanged IPC errors, exact dispatch identity, one original 35 us settlement,
real partial 64-page cleanup and memory-owner release, and denied/retained
service credit. Nine independent negative controls remove hooks, corrupt
identity/short circuit, overwrite first Unknown, stop progression on Unknown,
reissue ambiguous work or collapse IPC error into success. Each fails its
named behavioral assertion.

The paid fixture retains real Scheduler, Memory, IPC and cleanup. ELF/context
construction, EL0 return, vector completion, file/TLB hardware and transport
authorization are explicit controlled boundaries. There is no all-true
drained/stopped/running substitute. The supervisor-only group deliberately
controls backend resource effects; it is not end-to-end recovery. These checks
prove neither native SMP timing nor WCET or repair of the previous Apply443.

Independent read-only review finds no Critical/Important issue. Its suggested
IPC error and Task full-identity reset coverage is added and passes. All nine
v46 configured engineering checks pass: **701 host tests (two environment
skips)**, **84 tooling tests**, Rust/TLS, formats and configured Clippy. Both
node images build; selected preparation stacks are **33,104/65,536 bytes**.
The frozen source SHA-256 is
`d5e08548cab4163dfd2e064f942a81c520554bd2a8be64c4c99c44aba1b48559`.
Fresh native diagnosis follows. Full prototype acceptance remains unfinished.
