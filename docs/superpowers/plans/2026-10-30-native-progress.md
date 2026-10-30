# Native prototype progress: publication, sessions and capture

Goal: continue the native configuration-1.3 prototype by removing evidenced blockers, with independent parallel work and original runtime evidence.

Spec: `CyxiaOS_Minimal_Prototype_Design_Final.docx`, SHA-256 `01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0`. Relevant clauses: 3.2, 5.3, 6.2–6.3, 7.3, 8.2, 8.8, 10–13, 14.4–14.5. The prior findings and record identities are in `docs/implementation/v012-parallel-execution.md` and `v012-native-learning-archive-inspection.md`.

## Global Constraints

- Native AArch64, four vCPUs, 1 GiB RAM, distinct per-node 512 MiB disks and private identities. Host tools provide emulation, injection and independent verification, never protocol decisions, inference or guest recovery.
- Work CPU <=2 ms; all IPC/validation/publication CPU <=500,000 ns; original wall deadline 50 ms. Keep the 61 ms mandatory / 70 ms total per-control-core window constraints and actual CPU accounting. Do not increase budgets, refresh deadlines or omit costs to pass.
- Retain every generation/identity/permission/model/selection/dependency check and Registry result. Diagnostic information grants no authority.
- Preserve fixed capture workspace and 8,192 interval limit. Keep full P/E/O CPU union and actual physical intervals; no dropping, gap filling, synthetic labels or accepting Capacity/Deadline as complete evidence.
- Complete prototype requires all 51 IDs, 18 action families and filesystem fault cases. Host tests and this diagnostic run do not close native cases. Missing or truncated raw evidence remains incomplete.
- Implementers use isolated worktrees, no subagents, local task commits only, no push. Shared integration surfaces are controlled by the coordinator. Build/test lanes stop during native timing runs.

## Review Focus

- Original successful Registry receipts must survive a final cumulative publication-budget stop.
- Instrumentation must preserve original clocks, operation/capture identities and functional predicates; any added CPU remains charged.
- Session reconnect must not erase persistent membership, task/result custody or change BootEpoch.
- Capture attribution may explain an excluded side, but cannot change interval admission, collection or acceptance merely to fit capacity.
- An archive's complete disk bytes are not a read-back/close/export receipt. Failures, retained obligations and exclusions remain explicit.

### Task 1: Attribute and repair publication CPU hot paths

Owner: publication implementer; write scope `kernel/src/domain_control.rs`, new narrowly scoped `kernel/src/domain_control/publication_cost*.rs`, dedicated publication-cost host tests/harnesses and independent decoder module. `tools/verify_domains.py` and kernel module registration are coordinator-owned integration surfaces.

Input: stopped run `/Users/robin/CyxiaOS-V0.12/artifacts/v012-parallel-native-pair-20261029`. Stop-bank facts: node1 Job402/D8 ServiceBatch, decode 93,875 + remaining publication 425,416 = 519,291 ns; node2 Job317/D2 SpawnTokens, 84,419 + 416,331 = 500,750 ns. Original versions 309/234 remain Applied. Task overruns/quarantine are zero. No stage-level causal conclusion is yet justified.

1. Trace the real accept/Executor/Registry/final-release paths and existing clock samples. State one evidence-based hypothesis before changing behavior.
2. Write and observe a failing actual-source regression for the minimal missing stage/identity/cost evidence, including successful Registry return followed by final cap failure. Negative controls must compile and fail the named behavior assertion.
3. Implement bounded, diagnostic-only attribution using original samples/identities where possible; retain precommit, Registry return, release and final cumulative boundaries. Do not alter publication results or retries. If investigation establishes a redundant or incorrect operation, fix it separately through RED→GREEN; otherwise deliver sufficient bounded attribution for the next native run rather than guessing an optimization.
4. Verify original Job/CPU/debit and receipt semantics, no manufactured CPU intervals or duplicate owner queries, explicit conflict/overflow handling, and existing publication/retry regressions.

Acceptance: actual-source evidence behavior RED→GREEN; existing budget/receipt behavior preserved; focused tests pass; new raw decoder rejects mismatched identities/malformed snapshots. Runtime performance is only claimed after a new native run.

### Task 2: Diagnose and repair authenticated-session exits

Owner: session implementer; write scope `user/prototype-cluster/src/runtime.rs`, narrowly related driver/broker code, `kernel/src/unified.rs`, independent session diagnostic helper/decoder and dedicated tests. Existing public billing/capture APIs, `tools/verify_domains.py` and shared ABI changes are coordinator-owned.

Input: stopped run `/Users/robin/CyxiaOS-V0.12/artifacts/v012-parallel-native-pair-20261029`. Node1 event count 201 exceeded a 200-slot prefix; among retained events: authenticated/connect=73, session teardown=74, proof binding=50, no READY and no remote task start/finish. Complete framed serial has only the same 200 service events and a 16-byte partial tail, so the missing event cannot be reconstructed. Independent CI run40927380240 failed its first pair on governance fault1793 and five restart profiles on TCP deadlines; do not conflate those causes.

1. Trace each real runtime/session exit and timeout branch, compare a successful host driver flow, and identify which original branch information is currently lost.
2. Reproduce a specific defect with real runtime/driver behavior where evidence permits. Otherwise first write a failing behavioral regression for bounded exit-origin retention, including original result, protocol stage, session/service/boot identity and last message context without key/plaintext leakage.
3. Add the smallest original-branch diagnostics and any independently proven root fix. Reuse bounded reserved evidence when practical. Keep the current overflow and truncation rejection; do not accept this old run through a relaxed prefix rule. A full streaming archive requires a separate complete sequence/provenance contract if introduced.
4. Verify normal/reconnect/failed READY and stale-session/custody paths, plus existing unified acceptance/restart tests. Shared ABI changes require coordination before implementation.

Acceptance: real branch/driver RED→GREEN; preserved identity/membership/custody; fresh exit reasons distinguish protocol, timeout and local lifecycle failures; no old READY/native PASS fabricated. Independent source/tool decoder can reject malformed or cross-generation evidence.

### Task 3: Attribute CPU0 capture pressure and cleanup delays

Owner: capture implementer; write scope `kernel/src/learning_evidence.rs`, its dedicated helper modules, `kernel/src/domain_tasks/execution.rs`, `kernel/src/domain_tasks/replay.rs`, narrowly scoped `kernel/src/learning_replay/` diagnostics and dedicated tests/decoder. Do not edit shared `domain_control.rs`, `unified.rs`, runtime or existing public billing signatures without coordinator agreement.

Input: stopped run `/Users/robin/CyxiaOS-V0.12/artifacts/v012-parallel-native-pair-20261029`. Three length-complete baseline archives hit exactly 8,192 intervals, with CPU0 ExecutorWork counts 7,959/7,930/7,980. Another side has 241 intervals and seal 8.404986 s after observation end, beyond the original five-second cleanup bound. Owner error14 means retained Conflict and does not identify the active blocker. Node1 has three complete disk ranges but only two completed exports; preserve trial3 pending readback/close custody.

1. Trace actual owner/capture source keys and billing boundaries behind ExecutorWork and existing Work/Task/closing diagnostics. Inspect original raw intervals rather than assuming all CPU0 cost is networking.
2. Write and observe failing actual-source tests for the missing source/identity attribution or a reproducible progress bug. Expected facts must be derived independently, not copied from source constants.
3. Implement bounded provenance or a proven minimal scheduling/progress correction without changing actual interval collection, CPU union semantics, workspace, capacity or cleanup bounds. Preserve existing public APIs; propose any cross-lane hook to the coordinator first.
4. Verify explicit Capacity and Deadline exclusions, original counters/intervals unchanged by diagnostics, full trial/request/caller identity, no cross-owner lock queries or manufactured completion, and existing handoff/drain/owner tests.

Acceptance: actual-source RED→GREEN; fixed capacity and all cost/UNKNOWN/custody semantics preserved; bounded evidence identifies the producing source or original progress blocker. Only a new source-bound native run can establish reduced pressure or completed paired replay.

### Task 4: Integrate, independently review and run native evidence

Owner: coordinator. Review every task against its exact brief and full diff, resolve shared interfaces once, and integrate only reviewed changes. Run the standard host/tool/Rust/Clippy gates, dual native/governance builds and selected-stack/source bindings. Freeze compiled source and stop all heavy tasks before the patched-QEMU native run. Inspect stopped records and update the durable ledger and implementation record. Keep all failed attempts and original artifacts; catalogue stays NOT_RUN unless its fixed independent native verifier proves the full case.

Acceptance: task spec/quality reviews and broad final review recorded; fresh relevant gates and builds recorded; native result honestly classified with original causes. No automatic shared-branch push or publication.
