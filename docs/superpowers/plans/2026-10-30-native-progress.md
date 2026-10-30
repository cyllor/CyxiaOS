# Native prototype progress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax for tracking.

**Architecture:** Independent isolated lanes change the native session producer, exact-native task publication, and explicitly paid capture observations. The coordinator owns integration and host evidence retention; only a frozen source-bound native run can establish runtime progress.

**Tech Stack:** Rust AArch64 kernel and native service, Python independent verification, patched QEMU dual-node emulation.

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

Approved scope correction after actual accounting audit: post-record publication at the definitive boundary adds CPU after original interval/debit samples on some paths. Replace it with explicitly incomplete paid invocation observations. Every opt-in hook, identity copy and diagnostic gate/store must lie inside both original physical interval and ledger samples; remove completion/import hooks. A single nonblocking acquisition of the existing collector gate may inspect immutable configuration/roster without classifier/owner queries or capture mutation. Keep the fixed1024-byte bank and full RunKey/offered owner/site/available TaskGuard identity. Known direct roster source and unresolved source are distinct. Entry observations cannot claim record admission, Capacity/result, or a physical end; local PMCC ticks cannot masquerade as wall intervals. Cover real37ns body+17ns recorder inclusion and compile-valid post-sample counterexamples, unchanged original8192/Deadline/Capacity/handoff behavior, and no added completion/import publication. Omit any site whose actual enclosing ledger/capture samples cannot be proven.

### Task 4: Integrate, independently review and run native evidence

Owner: coordinator. Review every task against its exact brief and full diff, resolve shared interfaces once, and integrate only reviewed changes. Run the standard host/tool/Rust/Clippy gates, dual native/governance builds and selected-stack/source bindings. Freeze compiled source and stop all heavy tasks before the patched-QEMU native run. Inspect stopped records and update the durable ledger and implementation record. Keep all failed attempts and original artifacts; catalogue stays NOT_RUN unless its fixed independent native verifier proves the full case.

Acceptance: task spec/quality reviews and broad final review recorded; fresh relevant gates and builds recorded; native result honestly classified with original causes. No automatic shared-branch push or publication.

## Runtime iteration after the diagnostic phase

Tasks1–4 implementation and source reviews are complete. Composite host gates passed (Rust1173, TLS26, host745+2 skipped, tools97); the source-bound native run `artifacts/v012-superpowers-native-pair-20261030` failed after426.139656917s on event201. Both nodes still have zero labels. These are newly observed runtime defects, so tasks5–8 are a distinct implementation/review phase; the earlier final review and one final validation fix wave are closed, not reset or represented as native acceptance.

Fresh base for tasks5–7: `299da19d7d0a5b4c3750b42247db8eda67cbb620`, isolated integration branch. Prior failed run and all raw artifacts remain immutable. The user's explicit parallel continuation remains the execution method. The five Review Focus conditions above apply; additionally, delayed formation crossing500ms, asymmetric BOUND/CONFIRMED recovery, custom D02 callback registration, paid observer contention, and replaced source runs must each have an owning regression below.

### Task 5: Correct session formation and recovery ordering

**Files:** Modify `user/prototype-cluster/src/driver.rs`; test `user/prototype-cluster/tests/driver_host.rs` (confirm actual path before editing). No runtime, wire-schema, Engine or kernel authority changes without coordinator-reviewed design. Report in this plan's SDD workspace `task-5-report.md`.

**Interfaces:** Existing `Driver::tick(now:u64)->Result<(),()>`, `Driver::ingest(bytes:&[u8],now:u64)->Result<usize,()>`, `Engine::bind(Proof)` and real persistent journals stay authoritative. Preserve type1–6 wire kinds, strict sequence and boot/config/session binding, current500ms/1500ms cadence, CONFIRMED lock, durable proof then reconciliation then active READY. STATUS cannot grant BOUND or READY by itself.

Read the authoritative spec §10.3/11.1/11.2 and the coordinator's causal report first. Two independently evidenced failures are STATUS19 before proof during initial formation and STATUS431 before PROOF on BOUND↔CONFIRMED reconnect. A bare proof/member gate can silently suppress the specified heartbeat: before code edits, propose the smallest legal forming heartbeat/retransmission contract with real receiver behavior and exact state/header semantics, and obtain coordinator resolution. Do not invent acceptance exceptions or assume the spec waives pre-BOUND heartbeat. In-scope actual-source RED tests may proceed during design review.

Coordinator design resolution: reuse immutable initial113-byte HELLO as a post-HELLO/pre-proof heartbeat. Cache local/peer initial bodies per connection; only local Standalone/Confirmed without proof sends repeated kind1, fresh increasing sequence/request, zero cluster/epoch and exact known boots every500ms. Receiver requires byte-exact cached initial peer HELLO whose original member was Standalone/Confirmed; distinct `Engine::accept_formation_heartbeat(&Header)->Result<(),Error>` requires kind1, zero cluster/epoch, nonisolated, exact boots, increasing sequence and local Standalone/Confirmed/Bound (not Leaving). Normal accept_header unchanged. Receipt only advances accepted sequence/existing last_rx; never call hello again, reset session/challenge, change member/config/counter/lock/reconciliation/READY or grant resources. A queued pre-proof heartbeat remains legal after local bind. Initial peer-HELLO absence retains original1500ms timeout, no unknown receiver retry. Approved additional files: `crates/prototype/src/cluster/engine.rs` and dedicated engine tests. Tests reject modified body/challenge/counter/member, duplicate/old seq, wrong boot/config/kind, isolated, original Bound/Leaving sender and prove no authority/reset/persistence effects. BOUND HELLO may send PROOF alone, with existing validated PROOF/CONFIRM continuation emitting STATUS; real-journal tests must prove eventual reconciliation in both directions. A further real reboot counterexample exposed `(21,true)` using transient task_key despite resume_closure sending durable ACK_RESULT: approved response repair parses exact key/hash/end, verifies `engine.ack_ready(key)==hash`, then sends CLOSE for that contract only. Add real recovered-response RED plus wrongkey/hash/short/trailing rejections; Engine close/ack custody predicates stay unchanged.

- [ ] Step1: Add `delayed_formation_crosses_heartbeat_without_proofless_reconciliation`: exchange genuine HELLO, hold genuine formation frames across500ms but below1500ms, tick both real drivers, then restore FIFO. Assert legal cadence, no invalid reconciliation, matching durable proofs and eventual active READY, no remote start before READY. Observe behavioral RED, not compilation failure.
- [ ] Step2: Add `bound_confirmed_reconnect_sends_proof_before_status` using actual journals and one-sided BOUND, both delivery orders and split frames. Observe current real handler rejection; pin identical proof through unchanged Engine binding/persistence and no STATUS authority.
- [ ] Step3: After coordinator accepts the heartbeat contract, implement only the producer ordering/necessary precisely scoped heartbeat behavior in existing Driver methods. Keep invalid proof/session/sequence/config/boot,1500ms isolation and custody rejections intact.
- [ ] Step4: Run focused real-driver tests and full native-service host suite using `/Users/robin/.cargo/bin/cargo test --locked --offline --manifest-path user/prototype-cluster/Cargo.toml`; preserve failed READY/stale-session/recovery safety controls. Report every skip/failure and design tradeoff.
- [ ] Step5: Self-review, commit locally with `fix(cluster): preserve formation and recovery message order`, and report exact base/head, RED/GREEN commands, diff, remaining native limitations.

### Task 6: Test and optimize exact-native D02 owner acquisition

**Files:** Modify `kernel/src/domain_tasks/publication.rs`, reexports in `kernel/src/domain_tasks.rs`, and `kernel/src/domain_control.rs`; create dedicated `tests/host/test_active_spawn_publication.py` plus actual-source Rust harness. Necessary existing host facade adaptations may be proposed first. No changes to policy algorithm, clocks or limits.

**Interfaces:** Preserve `reserve_scheduler_publication(Action)->Result<Option<SchedulerPublication>,Error>` as D01-only, including existing SpawnTokens→Ok(None) contract. Add distinct `SpawnPublication`, `reserve_spawn_publication(Action)->Result<Option<SpawnPublication>,Error>`, and `spawn_publication_matches(consumer:&Family,resolver:Option<fn(ObjectKey)->Result<[Option<Prerequisite>;2],Error>>,has_custom_binder:bool)->bool`. Exact native D02/domain2kind1 registration, Tasks target source and every replaced callback identity must match; resolver and custom binder must both be absent. Its validate/current/legal_options methods keep existing argument/result types and call the existing *_locked logic on one live owner borrow. ActiveQueries may keep separate optional scheduler/spawn views; preserve fallback callbacks for every ineligible registration.

The frozen native stops Job49/322 were D02, charged510415/524872ns with successful versions36/232. This does not prove owner-query dominance or a timing cure. Treat removal of repeated physical owner acquisitions as a separately testable optimization hypothesis; no performance claim until native evidence.

- [ ] Step1: Build an actual-source Admission/Scheduler+Registry+Executor/selection regression for native SpawnTokens; explicitly control only hardware clock/CPU and acquisition observation. Assert one physical owner acquisition through both validations/revalidation/final selection, real unchanged receipt, and release before completion/delivery. Current code must compile and fail that acquisition assertion.
- [ ] Step2: Add parity controls for unchanged-current, minhold/frozen/nonadjacent tier, wrong generation/control CPU, custom callback/binder/resolver fallback, Busy before Registry identity allocation, retry debit/original deadline, and published receipt retained on paid outer overrun. Preserve existing D01 exclusion and no recursive owner gate.
- [ ] Step3: Implement the distinct exact-native D02 view above without bypassing Registry/model/selection/dependency/permission/identity checks or changing samples. Release every successful/failure borrow inside original charged boundaries; unsupported/custom paths retain old behavior.
- [ ] Step4: Run the new test plus existing active_scheduler_publication, scheduler_publication_contract, active_selection, active_scope, active_accept_retry and native publication clock/provenance tests; run relevant Rust suite and cargo fmt check. Capture compile-valid controls; no host-duration performance assertion.
- [ ] Step5: Self-review, commit locally with `perf(tasks): share exact-native spawn publication owner view`, report RED/GREEN/acquisition evidence and unproven native cost. If actual-source experiment cannot prove redundancy and parity, report the failing experiment rather than guessing a change.

### Task 7: Observe the ordinary workload poll inside paid samples

**Files:** Modify `kernel/src/learning_evidence.rs`, `kernel/src/learning_workload/owner.rs`, narrowly required `kernel/src/learning_evidence/provenance.rs` scope validation, `tools/decode_capture_provenance.py`; create dedicated actual-source poll paid-cost host regression/harness. Existing necessary test facades may be adapted narrowly. No global generic measure/completion/import hooks or scheduler changes.

**Interfaces:** Reuse `measure_paid_task<R>(ObjectKey,CpuClass,impl FnOnce(Option<PaidEntry<'_>>)->R)->R`; add `PaidEntry::observe_workload_poll(self)` to record site6 with identityNone. Only the main measured closure in ordinary `owner.rs::poll` opts in before `within_work`, inside original inner PMCC sample and outer service_segment debit. Preserve return/queue/request behavior. Fixed1024B schema2 bank and four buckets remain; decoder accepts site6 with unknown task identity and all original consistency checks. Existing sites2–5 unchanged;1 and unsupported sites rejected. No extra clock/read/classifier/owner query/capture mutation/allocation/capacity/workspace.

- [ ] Step1: Extract actual ordinary poll body, actual helper/observer/collector, original service_segment/interval finisher and real Scheduler in a dedicated test. Queue arrivals for the future so a legitimate no-new-work poll occurs. Expect one site6 OWNER observation, fullRunKey, direct roster source and unknown task identity; current source must compile and fail the observation assertion.
- [ ] Step2: Implement the narrow opt-in. Controlled body37ns+recorder17ns must produce original inner54ns and actual debit including54; separately modeled dependency costs counted explicitly. A second paid invocation after63ns produces0..54 and117..171, debit108, no filled gap. Preserve original result/queue.
- [ ] Step3: Compile/run negative controls moving observation after physical sample and after ledger sample; each must compile and fail the intended duration/debit assertion. Cover absent context/nonCPU0/contention no observation, generic/completion/import zero hooks, strict decoder malformed/reserved/full identity/site checks, unchanged8192/Capacity behavior.
- [ ] Step4: Run dedicated regression, existing capture_paid_cost/provenance/owner/handoff suites, relevant Rust tests and formatter. Self-review and commit locally with `feat(evidence): observe paid ordinary workload polls`; explicitly report incomplete invocation scope, no admission/duration/completion inference and no proven scheduling cure.

### Task 8: Retain bounded source-run samples and validate the runtime fixes

**Files:** Coordinator only `tools/verify_domains.py`, dedicated host tool regression, durable implementation record and this ledger. No guest scheduling or acceptance rule changes.

**Interfaces:** Reuse each already-read1024B TRACE_SOURCE_EVIDENCE snapshot, full boot/run/sequence identity and the strict decoder. Retain stable present even-sequence raw samples per RunKey, bounded to64 distinct runs per node, replacing only that run's latest sample. Never merge observations across runs. Report explicit retained scope/limit/overflow and raw SHA256; odd/absent/invalid/foreign boot samples do not become history. Files are diagnostic-only; old raw snapshots and fatal-failure evidence remain intact. Do not add VM reads or extend guest clocks. Current-run mismatch remains explicit.

- [ ] Step1: Add real-verifier tests demonstrating replaced Capacity-era RunKey samples currently disappear, stable later samples replace only same-run entry, malformed/odd/foreign samples omitted, and65th distinct run reports overflow without evicting/misidentifying retained evidence. Observe behavioral RED.
- [ ] Step2: Implement bounded retention using existing snapshot bytes before ordinary fatal classification, no inference/classification/guest authority. Verify final fail paths retain history and absent new bank clears current fields without deleting history.
- [ ] Step3: Review each worker's exact base→head changes with fresh scoped reviewers and fix loop; integrate sequentially, run required9 gates and source-bound dual build/accounting/selected-stack audits. Broad final source review covers the whole new phase; at most one final fix wave for that phase. Preserve all historical failures/skips.
- [ ] Step4: Freeze sources; stop all build/test/review/heavy work; reattest patched QEMU, run original dual-node configuration within original600s runner limit, inspect raw/session/publication/source/archive evidence. Failures remain failures. Do not mark catalogue cases/native/full prototype complete without independent evidence.
- [ ] Step5: Update durable record with exact source/build/run hashes, results and unresolved blockers; revalidate main transfer against prior dirty baseline before any local application. No automatic merge/push/publish.
