# Prototype v1.3 Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Reach complete native minimal-prototype v1.3 acceptance, preserving every mandatory constraint and recording actual evidence.

**Architecture:** Repair the existing native implementation and its evidence chain. Keep protected mechanisms in EL1, align control/service roles with the specified EL0 boundaries, and admit acceptance results only through independent raw-event verification.

**Tech Stack:** Rust no_std, AArch64 assembly, Python tooling, pinned QEMU 10.2.2.

**Spec:** `CyxiaOS_Minimal_Prototype_Design_Final.docx`, 1.3 Rust revision, SHA-256 `01f8c315018d8117c0b43671add6527fe76d0b83caabe865b5d714a99fa135a0`.

## Global Constraints

- AArch64 virt, cortex-a53, 4 vCPU, 1 GiB RAM; per-node 512 MiB disks.
- Encoding/inference/decoding ≤2 ms; IPC/validation/publication ≤0.5 ms; wall deadline 50 ms.
- Mandatory control work 61 ms/100 ms, per-control-core ceiling 70 ms/100 ms.
- 16 domains, 18 action families; no host inference, protocol decisions or file recovery.
- At least 144 training and 72 validation samples, grouped disjointly; no synthetic replacement for execution evidence.
- A01–A16, T01–T20, E01–E15, all action families and filesystem fault cases require native evidence.
- Preserve prior local work. No threshold loosening, fabricated PASS, automatic destructive reset or shared-branch push.

## Review Focus

- Budget failure must retain fresh diagnostic evidence, never an older healthy snapshot.
- Missing, malformed or contradictory raw events must fail closed without promoting a scenario.
- Incomplete/UNKNOWN executions retain obligations and cannot become complete-cost labels.
- Service restart must not repeat a task or lose custody of its completion token.
- Core migration must preserve ownership, charged time, model generations and execution pins.

### Task 1: Native budget root cause and bounded execution

**Files:** `kernel/src/domain_control.rs`, relevant executor code identified by measurements; `tools/verify_domains.py`, `tools/test_verify_domains.py`.

**Interfaces:** Preserve native input ABI, paid-work witnesses and deadlines. Extend optional diagnostic symbols without changing acceptance criteria.

- [x] Add a failing parser regression for detailed preparation evidence surviving a budget fault.
- [x] Instrument target/observation/dependency/candidate/queue/construction stages and reproduce with the existing wallclock configuration.
- [x] Establish specific preparation costs before modifying production scheduling or algorithms.
- [ ] Add a behavior regression, apply the smallest justified correction, and run targeted plus integration checks.
- [ ] Rebuild both native images and verify wallclock execution without budget quarantine.

### Task 2: Learning replay and complete data

**Files:** `kernel/src/learning_*`, `crates/prototype/src/learning/*`, corresponding tests.

**Interfaces:** Existing capture archives, trial identity, protected cost intervals, FrozenData and independent validation roles.

- [x] Trace excluded native sides to concrete raw evidence and exact rejection conditions.
- [ ] Reproduce any defect in a meaningful failing regression, then repair without relaxing sampling criteria.
- [ ] Demonstrate accepted paired replay; extend to all action families and required group-disjoint data.
- [ ] Demonstrate qualified Shadow/Canary/APPLIED/model-hash transition and rejection/rollback scenarios.

### Task 3: Native full-case verifiers

**Files:** `tools/check_v13_evidence.py`, new scenario-specific verifier/test modules, later native runners.

**Interfaces:** Pinned specification definitions, immutable artifact hashes and independently decoded raw native events.

- [x] Select a scenario with a complete, reviewable event contract; document missing runner fields.
- [x] Write negative/tamper tests first, then implement strict event verification.
- [x] Bind source/build/guest/runtime identities; never accept a trusted success boolean.
- [ ] Run the actual scenario and register only fully proven results; extend to the remaining mandatory cases.

### Task 4: Architecture and crash-recovery conformance

**Files:** To be pinned by current-code audit: control coordinator, EL0 services, cluster driver and persistence.

- [x] Separate genuine placement/fixed-core gaps from legitimate EL1 validation mechanisms.
- [ ] Specify bounded service interfaces and restart/token-custody behavior before edits.
- [ ] Add failing isolation, migration, duplicate-request and same-epoch restart regressions.
- [ ] Implement coherent EL0 role and recovery changes, then validate native behavior.

### Task 5: Fault matrix and final acceptance

- [ ] Implement and execute the filesystem crash/reorder/recovery-interruption matrix.
- [ ] Run mandatory resource-pressure, ownership, member/contract/task and policy-generation fault scenarios.
- [ ] Run host/tool/Rust suites, native builds and full 1.3 release gate on the final source identity.
- [ ] Obtain independent code/evidence review and fix substantive findings.
- [ ] Mark complete only when all mandatory cases and filesystem matrix pass.

## Execution Ledger

- 2026-10-25: User explicitly authorized the full acceptance goal. Existing branch and prior uncommitted work retained; no fresh checkout that would strand fixes.
- Ruling: Start with known defects and independently useful verifier work while auditing architecture. The approved design supplies requirements; remaining implementation decisions are recorded here as evidence becomes available.
- Pre-flight: Tasks 1/2 share the final native build and evidence run; root owns those runs to avoid contention. Task 3 does not edit `verify_domains.py`. Architecture audit initially read-only.
- Baseline: 69 NOT_RUN and filesystem matrix incomplete; wallclock replay quarantines on real recorded overruns. No completion claim.

- Preparation detail parser RED→GREEN: `artifacts/v13-preparation-detail-{red,green}.log`; native stages now separate observation, legal candidates, queue estimate and CandidateSet construction.
- Detailed original build: wallclock/single and multi fail; `/artifacts/v13-preparation-*` retains stages. Instruction-clock diagnostic also timed out with 0 labels; correct Budget rejection and missing first adoption explained in `docs/implementation/v13-learning-replay-investigation.md`.
- Exact p99 computation for a 64-element ring now uses maximum; native observation stage fell from ~1.887 ms in one original run to ~0.278 ms in the integrated run. Ring zero/eviction/extreme-value tests pass; this does not prove total budget conformance.
- TCP idle egress regression failed with 9 NIC receives; no-progress exit reduces repeated work. Full transport tests, including multichain 65KB transfer/retransmission, pass. Model dot-product traverses bounded slices and native candidate evaluation avoids duplicate feature encoding; existing model/policy/native-control golden tests pass.
- Same-BootEpoch custody lookup/inventory and Driver reconciliation implemented; exact kernel handler host tests catch actual request/output-capacity ABI. This does not yet add native service supervision/restart to unified.rs.
- Native A02 capture/affinity syscall and reviewed raw runner integrated. All unified EL0 entry sites instrumented, source still awaits native run. Full-case catalogue remains unchanged pending real receipt.
- Interrupted earlier processes were confirmed absent after machine restart; old `/tmp` source and identities were gone. Restored exact source using build hashes; new development identities live outside checkout at `/Users/robin/.local/state/cyxia-v13-development/pair`.
- `artifacts/v13-integration-build` contains a successful two-node native build. Exact source preserved under ignored `artifacts/v13-integration-source`. Integrated wallclock replay remains FAIL: first control preparation ~6.989 ms versus 2.5 ms credit; observation ~0.278 ms, queue estimate ~2.133 ms, CandidateSet ~1.170 ms. Storage build overlapped briefly; no timing-fix claim.
- Root workspace verification: 1081 tests in 145 result groups passed (`artifacts/v13-workspace-tests.log`); additional cluster/capture/fault tests recorded by their subsystem workers. Final combined checks still required.
- Filesystem interrupted-recovery host matrix passes. Independent disk checker now distinguishes incomplete uncommitted tail from corrupt committed chains. NBD fault injector/runner pending native execution; full A10 matrix not complete.
- 2026-10-26: `artifacts/v13-storage-faults-20261026-point92/summary.json` independently verifies four native COMMIT-FLUSH cut cases (before/after backend reply, drop/reverse-half volatile writes). Before FLUSH, recovery retains BootEpoch 1 / LSN 6; after its reply, BootEpoch 2 / LSN 10. This covers one of 92 boot-journal mutation boundaries, not ordinary EL0 file-fsync acknowledgments or full A10. The old point-1 diagnostic is not release evidence because QMP stop introduced an extra backend FLUSH; the corrected runner captures the halted guest without that stop.
- A02 native attempt `artifacts/a02-native-20261026-preboot` correctly failed with one dropped event. Deferred syscall handling on CPU0 can follow another task's entry on the original CPU; capture eligibility now follows the returned task identity until that task re-enters. New state/decoder regression passes; a new native image is still required. Protected config injection uses a bounded, transcript-checked GDB write while QMP is paused, followed by exact QMP readback before the sole initial continue.
- Candidate registration now validates raw features without computing unused normalized vectors; inference retains the identical validation and encoding. Focused feature/policy/native-control tests: 27 passed (`artifacts/v13-feature-validation-green.log`). New source requires new model/schema/build evidence.
- Latest broad subsystem check: 1092 Rust tests in 148 result groups, 558 Python host tests (one environment skip), and 47 tooling tests passed (`artifacts/v13-storage-{workspace,host,tool}-tests.log`). These precede pending-debit and subsequent A10 work; they are not final-source checks.
- Grouped target collection now reads each of the five used owners once per preparation, retaining fresh target generations and all eligibility rules. Unavailable snapshots return a retry instead of a partial queue estimate. The same decision carries every failed attempt's CPU debit and original deadline. Review caught a liveness defect in the initial debit patch; explicit retirement now preserves a bounded rejection record, consumes the reserved sequence and restores other-family scheduling. Eighteen focused regressions pass, and the parser's rejection-bank retention test failed before its fix and now passes with all 41 domain-tool tests.
- `artifacts/v13-batched-build-20261026` successfully builds both native node images with the corrected A02 capture and preparation changes. Exact 899-file compiled source is preserved in `artifacts/v13-batched-source-20261026`. Native A02 and budget results are pending; successful compilation does not close either requirement.
- Architecture contracts recorded in `docs/implementation/v13-service-restart-contract.md` and `docs/implementation/v13-el0-governance-contract.md`. Actual unified service restart and EL0 governance-command placement remain unimplemented; fixed-CPU1 learning checks are still present and require a complete ownership/credit/context handoff, not just removal of guards.
- A02 native run and root-independent receipt replay PASS in `artifacts/a02-native-20261026-paused-status-v4`: 83 events, zero dropped/error events, one real business-to-C affinity request denied, no accepted forbidden binding. This is native execution evidence, not hardware attestation. The fixed A02 adapter is now enrolled; default catalogue stays 69 NOT_RUN while implementation source continues to change. Historical receipt remains bound to the exact 899-file source and reviewed tool hashes.
- Uncontended two-node `artifacts/v13-batched-wallclock-20261026` still FAILs the 2.5 ms control credit: first preparations 8.154 ms / 6.877 ms. Queue collection 2.872 ms / 1.872 ms; candidate construction 0.903 ms / 1.028 ms. No timing-conformance claim. Rejection banks were zero in this run.
- `artifacts/v13-batched-icount-20261026` is a separate instruction-clock diagnostic and FAILs on a native secondary fault. CPU1's fault address exactly matches its stack guard. ELF inspection found a feasible 75,856-byte nested preparation path before its candidate-constructor frame, exceeding the unchanged 64 KiB stack. Fix pending: keep normal and read-only preparation scratch in mutually exclusive sibling frames and check the actual ELF. Root added a sticky original-exception diagnostic bank because CPU0's later panic only preserved its own ELR; its retention regression observed RED then 42 domain-tool tests passed.
- Successful read-only preparation retries now include the outer prefix in their cumulative decision cost. The production-owner regression observed 1.3 ms instead of required 1.4 ms before the fix, and now also rejects 1.2 + 0.1 + 0.8 ms. Twenty focused tests pass; this source change awaits the next native build.
- Preparation stack regression is now checked from both actual built ELFs before a successful build manifest is emitted. Keeping normal/read-only scratch in sibling frames and passing one caller-owned input buffer reduced the selected peak from 83,104 to 50,384 bytes. Both `artifacts/v13-buffered2-build-20261026` images pass the unchanged 65,536-byte stack with a 4,096-byte exception reserve. This bounded direct-call check does not prove all indirect or interrupt stack paths. Exact compiled source is preserved in `artifacts/v13-buffered2-source-20261026` (902 files).
- Native instruction-clock regression `artifacts/v13-buffered2-icount-20261026` ran for 157.49 host seconds without the previous SMP fault, but remains FAIL: a task consumed 3,168,400 ns against its 2,500,000 ns credit. It produced zero accepted paired labels. Node 2 had already stopped optimization after sequence 16 consumed 517,136 ns in publication against 500,000 ns. Node 1's candidate capture was excluded with incomplete evidence; its missing proposals still need diagnosis. These failures are retained and are not acceptance passes.
- Protected preparation-rejection diagnostics now decode original identity, cumulative cost, retirement reason, bounded-ring order and warm/read-only work identity. Malformed/transient-only rows cannot become completed rejection evidence. Before this checkpoint, 73 focused Python tests passed (`artifacts/v13-checkpoint-python-tests.log`); no full-prototype completion is claimed.
- User requested committing and pushing this implementation checkpoint to `CyxiaOS-V0.1` before continuing. A10 ordinary-file clean native chain/full cut matrix, guest CPU-time semantics, complete learning data, EL0 governance, migration and native service supervision remain open.
- The patched translated-execution PMU in CI run `40277865579` localized the next failure to an actual 5.041 ms phase-5 EL0 turn (2.5 ms credit). The controller's redundant volatile copies of the protected 4 KiB input, 2,772-byte model and 4 KiB output were removed in favor of the existing immutable/precleared mappings. Host equivalence tests and both rebuilt node stack gates pass; exact Linux patched-QEMU replay remains required before this closes Task 1 or Task 2.
- CI run `40324229499` crossed the former EL0 overrun and exposed a later ordinary-task window-tail fault: three turns used only 0.190/0.209/0.290 ms of translated CPU time but began with less than the runtime's 10 ms wall envelope and completed after the aligned window. Unified builtin dispatch now defers that tail without reserving credit, matching the existing standalone contract while retaining crossed-window quarantine and all budget limits. The complete prototype/tool tests, configured kernel Clippy gate and a fresh two-node 51,520-byte selected-stack build pass; a new Linux patched-QEMU replay remains required.
