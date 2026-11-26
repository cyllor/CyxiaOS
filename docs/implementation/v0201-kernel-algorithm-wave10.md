# V0.20.1 kernel algorithms — wave 10

Parent: 88d1fc966374396d67e5b3cd7cf8537fe4867ecb. Wave 8 run 45839915538 completed 34/34 jobs successfully. Wave 9 run 45840530489: at last pre-edit query 30/34 planned jobs passed, zero failures, remaining integration and pinned-QEMU build/guest runs. Wave 9 baseline benchmark passed all 57 exact-output comparisons (artifact 15128300920).

## Evidence-driven rulings

The wave 9 same-runner medians show the N=9 and N=16 sparse restoration is near baseline, while 17..27 remain slower for both workloads and 28..30 show small mixed gains. At N=4 the dense case was slower (42.5 -> 61 ns), despite near-baseline fragmentation; this is not a universally eliminated regression. Preserve the result and remeasure.

| N | Dense baseline/current (ns) | Fragmented baseline/current (ns) |
|---:|---:|---:|
| 4 | 42.5 / 61 | 66.5 / 69.5 |
| 8 | 127.5 / 134.5 | 187.5 / 195 |
| 9 | 158 / 162 | 228.5 / 233.5 |
| 16 | 420 / 437 | 661.5 / 678 |
| 17 | 450.5 / 701 | 681 / 1057.5 |
| 24 | 1007.5 / 1065.5 | 1595 / 1653 |
| 27 | 1184.5 / 1241 | 1863.5 / 1886 |
| 28 | 1302.5 / 1357 | 2100.5 / 2058 |
| 30 | 1463.5 / 1475 | 2355.5 / 2269 |
| 31 | 1931 / 1521.5 | 2857.5 / 2335.5 |
| 32 | 1629.5 / 1594 | 2641 / 2468.5 |
| 64 | 6295 / 4362.5 | 9855 / 6609.5 |

All fifteen operations-domain scoring workloads matched their original baseline outputs and showed 1.7753..1.9175x median acceleration on the wave 9 runner. Neither this range nor synthetic 32-candidate inference measures entire domain execution or native control-core latency.

- T53: move the compile-time sparse fallback cutoff 16 -> 30. Prefer the original bounded sparse algorithm for 17..30 rather than trade small dense regressions for small fragmentation gains. Keep the ordered algorithm at >=31, where measured medians were favorable. The cutoff is provisional, not universal, and no runtime switching or new authority. Explicit interval scratch grows to at most 480 bytes plus sorting call stack; never exceeds the historical original array at the same capacity. Target stack margin still unverified.
- T54: add actual Rust public-API deterministic differential regression, 14 capacities, two address origins including near u64 ceiling, 2048 state transitions each = 57344 potential transitions. Independent bitmap first-fit and exact live-run identity model, snapshot checks after each transition, cleanup. Extend existing boundary checks at 28/30. Test is scheduled in existing module lane; not executed locally.
- T55: pure FeatureSchema arithmetic only. For positive scale h, v>=h produces 256 exactly; else if h<=u64::MAX/513 the numerator 512*v+h and denominator 2*h fit u64. Preserve original u128 calculation on other scales, clipping only when v>h and None remains no-op. Both brains use this scalar normalization, their schemas, scope validation, independent score paths and authority remain unchanged. New Rust arithmetic oracle compares 25 scales including overflow boundary and maximum, 263 values/scale plus absent-field case. No timing benefit assumed until measured.
- T56: extend three immutable revision comparison (V0.20, wave 9, current) from 57 to 69 workloads. Add two FramePool metadata clean-allocation workloads, two IPC FIFO/replay/copy/ACK workloads, two console wrapped streams, one 32-input soft timer rounding workload and five security scoring kinds. Preserve all 42 capacity and 15 operations scoring workloads. Same harness; 14 samples/side, 4096 rounds/sample except FramePool and IPC 512 rounds/sample. Synthetic PageZeroer does not touch real pages, console sink is not MMIO, IPC is serialized metadata, timer is arithmetic, no hardware claim. Verify exact addresses, bytes, output scores and state, and compare checksums/returned values; timings diagnostic only.
- T57: preserve 34 planned CI jobs, pinned QEMU provenance and existing format, module, cross-build, workspace and positive/negative native fixture gates.

Executed independent JS differential models: 57344 allocator transitions (10536 successful releases), 51375 normalization inputs (23644 u64, 3082 wide, 24649 saturated). All matched. These checks are not Rust execution. Local Rust RED/GREEN and independent-agent review unavailable; same-agent source review only. Actual candidate CI, host performance, native target stack size/latency and formal G4/G5 remain open. No change to V0.20 ref, CPU0 topology, authorization, budgets, or production release scope.
