# V0.20.2 full-system performance review ledger

Baseline: 89f87ec7d480cd2cfc5851cecc079da5b3786459 (tree 7728e3be29ddaf651a9fabdd69230644e9e55f63). Branch: work/v0202-full-system-perf.
2026-11-27 / round 1. No verified native performance gain or completed P-item yet.

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
| P09 | Active timer index and event-driven delivery | Partial implementation, unverified | crates/prototype/src/domains/platform/timer.rs: 4-word armed bitmap, circular poll skip, regression tests; native event integration and performance not done |
| P10 | Syscall dispatch/user memory | Pending | Access and bounds safety |
| P11 | Classified I/O queues and incremental accounting | Pending | Credit and budget invariants |
| P12 | VirtIO descriptor bitmap, batching, DMA | Pending | Device completion and ownership |
| P13 | Network/TLS and CPU0 busy-wait removal | Pending | Business-core event-driven path |
| P14 | Security verification, recovery, receipts | Pending | Fail-closed and replay checks |
| P15 | HAL serial batching and idle | Pending | Native IRQ/idle verification |
| P16 | Independent brain views, exact inference, 96 targets, policy index, generations, budgets, cross-domain | Pending | Preserve control-only recommendation semantics |
| P17 | POSIX/desktop, graphics copies, async scoring | Pending | Native and contract checks |
| P18 | ARM/x86 independent native performance | Pending | Production wiring and representative workload, not fixture-only |
| CI | Automatic work-branch trigger | Implemented, unverified | .github/workflows/v0202-full-system-perf.yml, pinned module/format/workspace, build and QEMU fixture lanes, 69-case host comparison; original branch unchanged |
| Joint | Native end-to-end workload and production wiring | Pending | No G4/G5 acceptance claim |

P09 change preserves slot/cursor order, budget-zero, wraparound, retry/fatal errors and backend-first arm/cancel. Adds 32 bytes to Timers on 64-bit; dense-workload overhead and sparse benefits are unmeasured. Tests compare original linear poll with indexed poll and verify arm/cancel failure and slot reuse. Need exact commit CI results and actual native profiling; not equivalent to full event-driven integration. Container has no Rust/QEMU and cannot resolve github.com; GitHub connector used for source edits. The CI host benchmark is not native acceptance. Keep architecture/ABI/security constraints intact; no automatic merge, deploy or release. Inspect commit and CI before further edits.
