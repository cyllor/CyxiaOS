# V0.20.2 full-system performance review ledger

Baseline: 89f87ec7d480cd2cfc5851cecc079da5b3786459 (tree 7728e3be29ddaf651a9fabdd69230644e9e55f63). Branch: work/v0202-full-system-perf.
2026-11-27 / round 2. No verified native performance gain or completed P-item yet.

| ID | Scope | State | Evidence / next |
| --- | --- | --- | --- |
| P01 | Per-core scheduler indices and incremental accounting | Pending | Locate dispatch/roll, preserve budget and fairness |
| P02 | Process/receipt/free-slot indices | Pending | Differential and generation tests |
| P03 | Physical frames, contiguous ranges, clean pool | Pending | 69-case host benchmark, N=4 and N<=30, native evidence |
| P04 | Page tables/TLB batching | Pending | Ownership, shootdown and failure safety |
| P05 | File blocks, directory, transactions, cache indices | Pending | Crash/consistency and native checks |
| P06 | Journal, COW, immutable snapshots | Pending | FLUSH, fault recovery, UNKNOWN reconciliation |
| P07 | IPC copies and replay indexing | Pending | Ownership, credits and replay |
| P08 | Per-core IRQ and accounting | Pending | Native SMP and race checks |
| P09 | Active timer index and event-driven delivery | Partial implementation, module regression passed on R01; R02 verification pending | crates/prototype/src/domains/platform/timer.rs: 4-word armed bitmap, circular poll skip, regression tests; native event integration and performance not done |
| P10 | Syscall dispatch/user memory | Pending | Access and bounds safety |
| P11 | Classified I/O queues and incremental accounting | Pending | Credit and budget invariants |
| P12 | VirtIO descriptor bitmap, batching, DMA | Pending | Device completion and ownership |
| P13 | Network/TLS and CPU0 busy-wait removal | Pending | Business-core event-driven path |
| P14 | Security verification, recovery, receipts | Pending | Fail-closed and replay checks |
| P15 | HAL serial batching and idle | Pending | Native IRQ/idle verification |
| P16 | Independent brain views, exact inference, 96 targets, policy index, generations, budgets, cross-domain | Pending | Preserve control-only recommendation semantics |
| P17 | POSIX/desktop, graphics copies, async scoring | Pending | Native and contract checks |
| P18 | ARM/x86 independent native performance | Pending | Production wiring and representative workload, not fixture-only |
| CI | Automatic work-branch trigger | Implemented; trigger confirmed, R02 verification pending | .github/workflows/v0202-full-system-perf.yml, pinned module/format/workspace, build and QEMU fixture lanes, 69-case host comparison; original branch unchanged |
| Joint | Native end-to-end workload and production wiring | Pending | No G4/G5 acceptance claim |

P09 change preserves slot/cursor order, budget-zero, wraparound, retry/fatal errors and backend-first arm/cancel. Adds 32 bytes to Timers on 64-bit; dense-workload overhead and sparse benefits are unmeasured. Tests compare original linear poll with indexed poll and verify arm/cancel failure and slot reuse. Need exact commit CI results and actual native profiling; not equivalent to full event-driven integration. Container has no Rust/QEMU and cannot resolve github.com; GitHub connector used for source edits. The CI host benchmark is not native acceptance. Keep architecture/ABI/security constraints intact; no deploy or release. User authorized validated batches to merge into CyxiaOS-V0.20 only; verify exact candidate CI, ancestry and authorized diff, never force or bypass checks. Inspect commit and CI before further edits.

## Round 2 (2026-11-27)

R01 head cd701fbabf9cbcb438f7570cea088c87bd623842: [CI 45857098164](https://github.com/cyllor/CyxiaOS/actions/runs/45857098164), 34 successful jobs / 35, one rustfmt failure; timer module regression (2 tests), workspace, cross-builds, pinned QEMU, ARM production skeleton and x86 SMP mechanism fixture all passed. Fixture scope excludes G4/G5. [69-workload host comparison](https://github.com/cyllor/CyxiaOS/actions/runs/45857098164/job/140038217167) checks match; N=4 dense 32 ns prior / 30 ns candidate; frame-clean-256 1620.5 / 1632 ns; IPC 64 7023 / 7161 ns; no new timer-poll speed evidence. Rustfmt diff fixed in 52d23cad1b6cd3819f010fab8f8896d0c36dadde; awaiting exact candidate checks. Added identical harness on exact prior and candidate, 12 no-due / Busy-retry cases, active counts 0,1,4,16,64,256, alternating side order, 14 samples per side, exact attempted-fire totals and no successful delivery. Host-only evidence; dense overhead and sparse gain must be reviewed, fix/investigate regressions before sync. Target CI trigger added for CyxiaOS-V0.20. Target head 4912423cf2bc26ddf5c38eeea0f64190ce07a085 is ancestor of R01 (18 commits ahead, 0 behind); includes inherited V0.20.1/.2 changes, review full target delta before merge. No synchronization yet. Native event-driven delivery and representative production timer measurements remain open. No local Rust/QEMU; CI required.
