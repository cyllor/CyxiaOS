# V0.20 native eight-role integrated candidate (WIP)

Base #73 (853306b16beb79dc7248f60862ee7e9044ecc43c) actual native eight-package bootstrap PASS: run 45417764253. All eight role package hashes, roots, private 32KiB stacks and PMU debits independently observed. This is a 256MiB mechanism guest, not the formal 1GiB full system.
Integrate independent #74, #75, #76 changes into one review tree; the parent heads are retained as actual Git parents. Combined regression is required, not inferred from individual tests.

| Workstream | Actual development evidence | Remaining blocking condition |
|---|---|---|
| Native programs | eight independently linked ABI3 bootstrap packages, role-specific startup calls and immutable catalog | complete production model/config, controller, publisher, validation, model manager, learner and supervisor behavior |
| Loader/cap table | actual PIE/guarded 32KiB stacks, private page tables, sealed code aliases, narrowly issued bootstrap capabilities | physical production allocator, complete cap/object registry, entropy and durable startup prerequisites |
| CPU0 scheduling | actual native preemption/entry and measured single-core prepaid role turns; independent class/recovery ledger | complete CPU accounting including production services, system coordination/recovery and actual workload stress |
| Advice to receipt | single-action assisted decision freeze with admitted advice and exact disposition, independent rule evaluation and distinct publisher; existing security finding review and terminal verifier | actual authorized snapshot/inference/IPC/native SVC dispatch for production work, real executor/apply receipts |
| Recovery | eight-package guard fault, root disconnection/TLBI, complete private backing scrub/reload under alternate root; SecurityStateStore v2 exact after-image and independent commit proof | native persistent security-state file owner and verified redo/FLUSH, persistent shared controller epoch and real outstanding device/file obligations |
| QEMU | combined candidate workflow | formal G0 eight complete applications, G1 complete ABI and media, G4 127 IDs, G5 hardware remain unaccepted |

All four PRs #73–76 are development changes; this candidate does not modify CyxiaOS-V0.20. Do not promote bootstrap test generation to durable BootEpoch or a capability, or synthesize APPLIED from adapter acceptance.
