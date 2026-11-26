# V0.20.1 kernel algorithms — wave 8

Parent e94879c4f5a2b7a3f3c6d58fedccccf8c7317545. Wave 6 corrected commit eac116e passed all 33 jobs (run 45837501414). Wave 7 run 45838007128: 33/34 jobs passed, all 25 module lanes, 715 kernel-core and 2210 workspace test executions (overlapping scopes), both cross-builds and QEMU mechanism runs, both benchmarks; format alone failed. Exact format diagnostic at native_v0199.rs:667 corrected here. No baseline ref modification.

## Measured regression and ruling

Wave 7 exact baseline benchmark, run 45838007128, artifact 15126417335 (ns/complete synthetic workload, median 14 samples per side):

| Workload | V0.20 baseline | Wave 7 | Baseline/wave 7 |
|---|---:|---:|---:|
| dense-8 | 90.5 | 248.5 | 0.3642 |
| fragmented-8 | 158.5 | 371.5 | 0.4266 |
| dense-64 | 7329 | 4507.5 | 1.6260 |
| fragmented-64 | 11773 | 6797 | 1.7321 |
| operations-d01 | 3262.5 | 1875 | 1.7400 |
| operations-d06 | 2512 | 1515 | 1.6581 |

T44: exact rustfmt correction. T45: actual performance RED at N=8, not a failed semantic test. Keep the original baseline small-table sparse-slot implementation at N<=8 (compile-time const generic decision); retain ordered compact table and binary lookup at N>8. No persistent metadata or wire layout change; no runtime adaptation, no new resource authority. Small table scratch at most 128 bytes explicit interval array; large table does not enter this branch. Preserve first-fit, capacity-before-exhaustion, exact base/pages/owner and release preconditions. Alignment bounds ensure a saturated end comparison in the original small-table path cannot accept an overflowing request: representable aligned pool endpoint is strictly below u64::MAX. The original small-table algorithm is intentionally restored instead of claiming a new improvement. Cutoff at 8 is provisional: only N=8 and 64 had measured evidence; N=9/16/32 must be measured before choosing a different cutoff. Large-table correctness does not imply performance at every size.

T46: new boundary regression covers N=4/8/9/16/64, near-u64 address ceiling, fragmented exhaustion, wrong owner/length and full reuse. Executed independent occupancy-model checks: 144000 state transitions across N=1/2/4/8/9/16/32/64, including 25937 owner, 35342 stale, 4532 capacity, 18767 exhausted, 8326 invalid responses, all matched. These are JS reference results, not compiled Rust execution. Existing Rust regressions retained. Local Rust RED/GREEN not run; timing RED is actual wave 7 benchmark, candidate performance GREEN pending.

T47: expand same-runner source benchmark to V0.20 exact baseline, wave 7 exact parent and current code. Check both immutable tree hashes, use identical harness in separate worktrees/target directories. Six runs base/prior/new/new/prior/base, 7 samples/run, 4096 rounds/sample. Sweep N=4/8/9/16/32/64 with dense and fragmented workloads; keep D01 and D06 actual score_operations. Fourteen workload outputs must match across all six runs. Report each median and both speedup ratios. No arbitrary timing threshold on a shared runner; compare evidence and recursively correct regressions. Host-only, no physical page clearing, native CPU0 timing, or energy claim.

T48: retain all 34 planned jobs and independent format/host/cross-build/QEMU/benchmark gates. No weakening of runtime verifier or authorization. Record known trade-offs, no new joint optimization policy or authority. Same-agent review only. Formal hardware acceptance remains NOT_RUN; actual candidate test and benchmark results pending CI.
