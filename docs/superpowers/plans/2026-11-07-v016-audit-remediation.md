# V0.16 Audit Remediation Implementation Plan

> **For agentic workers:** Use the Superpowers isolated-workspace, test-driven-development, task-review, and completion-verification workflow. Steps use checkbox syntax; the controller records evidence and integration decisions in the scoped ledger.

**Goal:** Create `CyxiaOS-V0.16` / `0.16.0-dev` from V0.15 commit `32057802e6e7d9239d04f1e7e3fed4f82f90db7e`, correcting the nine confirmed full-audit and Superpowers recheck findings.

**Architecture:** Preserve the existing Rust/AArch64 design and asynchronous separation between control and execution. Repair the existing bounded state machines and ownership rules; keep source correctness, host evidence, and native acceptance distinct.

**Tech Stack:** Rust 2024, Python 3, GitHub Actions, existing workspace and cluster application test suites.

**Spec:** `CyxiaOS_Minimal_Prototype_Design_Final.docx` (design v1.3), `docs/implementation/v13-requirements.json`, and the V0.15 full-audit/Superpowers recheck of commit `32057802`. The controller retains the original report and reproducibility evidence outside this worktree; findings R01–R09 below are the implementation requirements.

## Global Constraints

- Baseline commit: `32057802e6e7d9239d04f1e7e3fed4f82f90db7e`; baseline tree: `db337d179974761aae837e373b1d708d198aac2e`.
- Software version `0.16.0-dev`; specification version `1.3`; package kind `development-source-only`.
- Rust and AArch64 remain the implementation platform. All official cluster members natively run CyxiaOS.
- Preserve 16 equal AI-capable domains, 18 action families, and dynamic dedicated control-core allocation.
- Business hot paths consume verified policy asynchronously and never synchronously wait for a model.
- Keep capacity bounds, identity/generation checks, unknown obligations, deterministic boot, isolation and fault recovery.
- No historical native verdict is inherited. The 51 A/T/E catalogue cases and 18 families retain their actual recorded status until corresponding native execution occurs.
- No unrelated dependency churn, vendor rewrite, generated binary commit, or modification of the V0.15 branch.
- Regression tests must exercise production behavior. Record an expected failing result against V0.15 before the fix and a passing result after it. Environment failures are recorded, never converted into PASS.

## Review Focus

- Reconnect histories beyond one output batch: progress must survive partial egress and another reconnect without duplicate execution (Task 1).
- Concurrent incoming/outgoing contracts: each reply must remain bound to its own identity, payload and resource obligation (Task 1).
- Unknown policy feedback and temporarily busy target views: mirrors and replay scope must not silently regress or omit eligible targets (Task 2).
- Process leaders exiting before descendants and DMA completion across clock sampling: cleanup/deadline decisions must follow actual resource ownership (Task 3).
- Persistent log cursor invalidation, EOF followed by append, random/repeated reads and corruption: bounded recovery must preserve content and error semantics (Task 4).

### Task 1: Cluster reconnect and duplex contract state (R01, R03)

**Owner/files:** Cluster worker owns `user/prototype-cluster/src/driver.rs`, `user/prototype-cluster/src/driver/`, and focused cluster application tests. Notify the controller before changing shared `crates/prototype` interfaces. Do not modify kernel storage or version files.

**Interfaces:** Preserve `Driver` public transport/application interfaces and journal wire compatibility. Reconnect replay is a bounded, resumable operation over retained received results. Incoming and outgoing contract context must be keyed by direction/contract identity rather than overwrite one shared `terms`/hash/reservation.

- [x] Reproduce R01 with terminal received-result histories of 15, 16 and at least 32 records: a Bound HELLO plus closure replay must not fail because 32 reserved frames are exceeded. Exercise partial drain, fragmented/coalesced input and reconnect restart. Record RED.
- [x] Reproduce R03 through ordinary application submission in both directions and both arrival orders; verify PREPARE_REPLY and COMMIT_REPLY associations and eventual exact-once resource release. Record RED.
- [x] Replace eager closure emission with capacity-aware resumable work serviced between egress opportunities; queue pressure is retryable and does not discard required closure work. Preserve proof/protocol progress capacity.
- [x] Separate incoming and outgoing contract data for preparation, replies, execution, persistence and recovery. Avoid publishing intent/custody before a request rejected by any temporary admission rule.
- [x] Run focused regressions, existing cluster application tests and relevant real-TLS tests offline; record commands, counts and limitations. Review changed call sites and recovery invariants.
- [x] Write the task report with exact file list, RED/GREEN evidence and remaining concerns; controller commits after independent review.

### Task 2: Control state and complete target enumeration (R02, R08, R09)

**Owner/files:** Control worker owns `kernel/src/domain_control.rs`, `kernel/src/domain_control/`, `kernel/src/domain_tasks.rs`, `kernel/src/domain_tasks/`, `kernel/src/domain_services/target_projection.rs`, and necessary focused host/production control tests. Changes to `crates/prototype/src/policy.rs` or target batch contracts require controller notification. Do not modify storage, cluster application or version files.

**Interfaces:** Preserve Registry monotonic reconciliation and existing service/action identity checks. Ordinary D5 target enumeration must include every live ordinary endpoint, with generation-aware open/close/reopen behavior. Replay scanning must distinguish transient Busy/NotReady errors from exhausted target enumeration.

- [x] Add a real poll-bound regression for started Unknown followed by late Pending before the deadline: Registry, desired/admission mirrors and history remain consistent, no second APPLY, terminal feedback still converges; retain foreign identity and deadline controls. Record RED.
- [x] Normalize a late Pending/Busy/Again against prior Unknown before publishing view state, without extending the action deadline. Preserve actual executor-entry custody, first-entry time, history and candidate terminal retirement even if later Registry bookkeeping rejects the receipt; a rejected bookkeeping update must not cause another APPLY. This closes the confirmed transition defect without claiming general transactional atomicity across arbitrary Registry errors.
- [x] Add D5 regressions for an ordinary third endpoint, close/reopen generations, bounded continuation, and transient unavailable views; preserve per-family due/object state on Busy while rotating the global family cursor so other owners remain schedulable. Record RED before repairing the fixed two-target projection.
- [x] Publish/read a bounded consistent roster of all ordinary IPC endpoints on all lifecycle paths, or use the owner-authoritative bounded target batch. Do not introduce model waits on the endpoint hot path.
- [x] Add a safe targeted regression for typed replay target enumeration: Busy leaves scan family/ordinal unchanged and cannot freeze an incomplete eligible roster; later success resumes correctly. Preserve intentional exclusion of the current trial target and ephemeral placement actions.
- [x] Carry typed enumeration errors through replay Scanning; do not use `.ok()` to equate unavailable views with end-of-list. Preserve existing replay quiescence and publication gates and the four-step scanning budget.
- [x] Run relevant control/prototype tests and report exact RED/GREEN evidence, source integration and native limitations. Controller commits after independent review.

### Task 3: Bounded tools and Virtio RNG (R04, R05, R07)

**Owner/files:** Tools/driver worker owns `tools/build_cosmic.py`, `tools/verify_pty.py`, their focused host tests, `crates/driver-virtio/src/rng/batched.rs` and its tests. Do not edit version metadata or shared workflow files.

**Interfaces:** Preserve `run_bounded` result/error and lock lifetime contract; cleanup covers the owned process group independently of leader state. `verify_pty` rejects nonpositive run counts at both CLI and callable boundaries. RNG timeout decisions must use a time sample taken before checking for completion, while retaining original submission deadlines.

- [x] Add a bounded subprocess fixture whose leader exits on TERM and child ignores TERM; assert no live owned child remains when timeout cleanup returns. Keep fixture self-termination, final cleanup and reaping. Verify expected RED.
- [x] Ensure TERM/KILL process-group cleanup runs even when the leader exits early, treats ESRCH correctly, and finishes before the caller releases its build lock. Retain normal success and ordinary timeout tests.
- [x] Add zero/negative PTY count tests at function and CLI boundaries; assert nonzero/rejected validation and no PASS report, plus positive-count completion accounting. Verify RED and fix input validation before guest execution.
- [x] Add RNG completion-between-empty-poll-and-clock-sample regression using the existing test platform; verify original code fails while true silent-device timeout and late-consumption controls retain their semantics.
- [x] Sample deadline time before polling, following the established block-driver ordering; do not refresh submission start time or reclaim device-owned DMA early.
- [x] Run relevant host tests, full driver crate tests and tools tests where available. Report RED/GREEN, fixture cleanup and environment restrictions. Controller commits after independent review.

### Task 4: Linear journal recovery (R06)

**Owner/files:** Controller owns `kernel/src/unified_store.rs`, a focused host-compatible test harness that includes the production module, and the minimum test runner integration.

**Interfaces:** Preserve `peer_log` read/write behavior, the stable record key sequence, fragment-cache results, error reporting and persistent journal format. Cache sequential cursor position only while bound to the initialized volume lifetime; permit nonsequential fallback.

- [x] Add regressions reading legal recovered histories at increasing sizes through production `Log.read`: returned bytes and EOF must agree with a single-cursor reference and block reads must grow linearly within a conservative explicit bound. Verify RED.
- [x] Add repeated/fragmented key reads, random access, reinitialization and EOF-followed-by-append cases; cover corruption/error behavior supported by the storage fixture.
- [x] Persist the sequential `Cursor` and next ordinal across adjacent reads; reset on initialization, rewind on random access as needed, and retain valid position when a failed read/append could otherwise skip content.
- [x] Run the regression and existing storage/prototype tests; record results and review cursor ownership/invalidation.

### Task 5: V0.16 baseline, integration and final verification

**Owner/files:** Controller owns `VERSION`, `README.md`, `docs/implementation/v16-source-baseline.json`, `docs/implementation/v16-source-summary.md`, a V0.16 source workflow and existing workflow branch selectors. Historical V0.15 provenance stays intact.

**Interfaces:** Source metadata records the immutable V0.15 parent and audit basis; CI creates source artifacts from the triggering commit and records its tree/hash. Development-source creation never sets native/release acceptance to PASS.

- [x] Update current version and create V0.16 provenance/status documentation mapping R01–R09 to fixes and regression evidence.
- [x] Add V0.16 to relevant engineering/component/native workflow triggers and add a source archive workflow with immutable event identity, checksums and always-uploaded failure logs.
- [x] Validate metadata, archives and workflow consistency with existing repository conventions; do not add prose-only change-detector tests.
- [x] Run the project engineering command and meaningful targeted suites on the integrated branch; classify missing tools/dependencies separately from product failures and preserve full logs.
- [x] Obtain independent task reviews and a fresh whole-branch review, resolve material findings, and record the final source identity and verification limits.
- [ ] Commit coherent changes on `CyxiaOS-V0.16`; create the corresponding remote development branch only after exact source and tests are reviewable. Do not merge into V0.15/default branches or mark a release accepted.

## Completion record

Implementation, regression verification and independent whole-branch review are complete. No Critical/Important source issue remains from that review; complete engineering verification retains FAIL for the recorded environment restrictions, and native acceptance remains NOT_RUN. This plan records the pre-commit state, so the final commit/remote-save checkbox remains pending here. The actual saved outcome is established by the Git branch and the V0.16 source workflow commit/tree/archive records, not by a self-referential checkbox. The final verification record binds the reviewed source files.
