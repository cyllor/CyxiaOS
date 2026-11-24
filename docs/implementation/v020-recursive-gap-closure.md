# V0.20 recursive gap closure ledger — iteration 1–2

Baseline merged commit ed68dc8345da18217f17e23e8a1c47f4da7ccd48 (PR #83).
Source: docs/design/baselines/v0.19.9-implementation-spec.txt §2.2.3, §6.1, §8.0 and 安§7.4; V0.20 target design and draft immutable-snapshot amendment.

## Evidence-based re-audit

PR #83 exact head 888793136022b14ece3b4d8c6af04e4ba6bd5d2e, CI run 45435873736:
- Native 256 MiB three trials PASS, artifact 14941992285; maximum recorded conservative per-window upper 5,658,837 ns.
- Native 1 GiB three trials PASS, artifact 14940254716; maximum recorded conservative per-window upper 5,359,845 ns.
- Each trial eight diagnostic package reloads, 56 survivor progress pairs and four integer model probes. Not production model inference or service readiness.
- Native epoch disk PASS, artifact 14942330525, actual flush/restart generations in separate scratch disk fixture.
- Fixed-control run 45435873724 PASS; snapshot component run 45435874151 PASS.
Close only the prior diagnostic rerun blocker. Do not delete earlier failures or infer complete accounting/production service acceptance.

## New source changes

- Canonical ControlRPC v1 request parsing and bounded per-holder state machine: role whitelist, 10 ordinary / 6 recovery slots, exact copied bytes and SHA256, sequence/ACK, frozen replies, retained UNKNOWN, fenced old holder tombstones, independently verified next-generation replacement. Explicitly requires trusted registry, real cap preflight, copyout pin and completion credit. This is an internal EL1 component; does not create a new syscall.
- Connect op9 publisher read to actual retained DecisionRecord in the existing RegisteredDecisionGate, through 0x50 copied-wire bridge. The gate derives publisher epoch/role; read has no publication authority.
- Canonical ApplyWork v1 construction and parsing. Native gate requires exact registered/accepted plan, bound target and executor generation, protected desired/version/reservation verification and atomic acceptance before work is returned. Report-based terminal feedback settlement now requires matching previously accepted work and completion time, not only a well-formed report.
- Connect D04 role12 op11 to that claim and RPC frozen reply. Independent backend must provide the actual atomic admission/effect evidence. Rejected/unknown work never becomes a success through replay.
- Source-bound focused control-plane regression workflow. New tests exercise lost reply, conflict, duplicate claim, stale role, recovery retention and ordinary slot pressure.

## Remaining gaps (all OPEN unless separately proven)

G01 Production bootstrap: verified offline config, signatures, entropy/randomized address spaces, physical FrameMeta, native cap table, durable boot & all service IDs. Diagnostic roots/stacks/reloads do not suffice.
G02 Native role loops: actual 8 ELF services, scheduler/coordination, real bounded IPC, complete 19 syscall ABI and actual 12 ControlRPC endpoints; newly added RPC/claim components and op9/op11 bridges are not yet wired to actual EL1 trap + protected allocator. No fabricated capability, audit or work is issued.
G03 Models/observations: trained current-schema models, trusted model and schema registration, 15 real observations, protected candidate sets, security redaction and real findings.
G04 Decision/plan: independent rules and true controller/publisher programs, causal fallback, trial permits, 64 published nonterminal plans plus at most one unpublished, terminal query/idempotency, shared controller epoch reconciliation. Existing gate remains single-plan, not full contract.
G05 Effects: 15 native owners with actual accepted apply/version/reservation and effect proof, especially role12 file owner and kernel D10. New claim checks are necessary, not effect evidence.
G06 Feedback/learning: full protected replay sample collection (120/60 minimum, disjoint groups), true RewardSchema v2 CPU cost, bounded training, independent validation, model promotion/rollback.
G07 Persistence: real mounted baseline-v1 filesystem protected objects, arbitrary torn-write/FLUSH fault and recovery, full actual role generation and service restart. Scratch fixture remains separate.
G08 Snapshot: freeze new unified format/ABI and authority, real COW/retention/recovery/GC and failure injection; candidate G1 NOT_READY.
G09 Budget: early architecture init, last evidence seal/halt, exact cross-window splits, integrated all real control work, pools and long-lived loaded stress. Prior diagnostic PASS not full coverage.
G10 Acceptance: all 127 stable IDs / 262 G4 proof pairs, additional snapshot assertions, and 26 G5 physical A53 proofs. No physical device available in this chat environment. Formal verdicts are absent and remain NOT_RUN unless complete proof.
G11 Design freeze: reconcile formal V0.19.9 source and candidate snapshot amendment; no silent media migration or acceptance threshold changes.

## Closure discipline

For each gap require source-bound positive and negative proof, actual appropriate native evidence and independent verifier, not just compiler success. Keep failed/NOT_RUN evidence. New CI is required for this increment; don't mark its tests PASS until queried. Continue only from observed current source and test results. Merge is a separate development action; not release certification.
