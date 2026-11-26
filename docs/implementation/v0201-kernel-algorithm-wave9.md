# V0.20.1 kernel algorithms — wave 9

Parent: 60cd9583342931eaed7ca099b99713a7150ad75c. Wave 8 CI run 45839915538 was still running at start of this wave: format, all 25 module lanes, both cross-builds and both benchmark jobs passed; full integration and QEMU build/captures not yet complete at the last pre-edit query. Do not transfer parent results to this commit.

## Measured evidence and ruling

Wave 8 three-revision benchmark, artifact 15126863864; median ns per synthetic complete workload, 14 samples per revision, 4096 rounds per sample:

| Workload | Original V0.20 | Wave 7 | Wave 8 | Baseline / wave 8 |
|---|---:|---:|---:|---:|
| dense-4 | 52 | 93.5 | 53 | 0.9811 |
| fragmented-4 | 75.5 | 141 | 76 | 0.9934 |
| dense-8 | 150 | 247.5 | 147.5 | 1.0169 |
| fragmented-8 | 229 | 373 | 224 | 1.0223 |
| dense-9 | 183.5 | 318.5 | 311 | 0.5900 |
| fragmented-9 | 263.5 | 483 | 474 | 0.5559 |
| dense-16 | 554.5 | 621 | 674 | 0.8227 |
| fragmented-16 | 904 | 969 | 1013 | 0.8924 |
| dense-32 | 2190 | 1727 | 1695 | 1.2920 |
| fragmented-32 | 3547 | 2601 | 2605.5 | 1.3614 |
| dense-64 | 7509.5 | 4901.5 | 4924.5 | 1.5249 |
| fragmented-64 | 12144.5 | 7456 | 7462.5 | 1.6274 |
| operations-d01 | 3945 | 2375.5 | 2371.5 | 1.6635 |
| operations-d06 | 2964 | 1908.5 | 1918 | 1.5454 |

T49: extend the compile-time sparse-table cutoff from 8 to 16. This preserves the original algorithm for the additional measured regressing sizes; retain the wave 7 ordered-table algorithm above 16. No changes to allocation identity, error precedence, public interfaces, wire layout, resource grants or runtime policy. One authoritative ownership table; the maximum explicit sparse interval scratch grows from 128 to 256 bytes, plus existing sorting call stack. Target stack headroom is still an open verification item. The original 9/16 timings motivate the change but do not prove the new implementation's speed. Do not move the cutoff again without comparative measurements.

T50: extend the existing public Rust boundary test to 17, 24, 31 and 32, retaining prior 4/8/9/16/64 cases. The independent JS occupancy model ran 168000 transitions across 14 capacities (1,2,4,8,9,15,16,17,20,24,28,31,32,64), including near-u64 ceiling; 31177 successful releases, 6501 invalid, 3926 capacity, 24172 exhausted, 37507 stale, 32098 owner errors, all matched. This is reference evidence, not actual Rust test execution.

T51: same-runner benchmark now compares exact V0.20 baseline, wave 8 parent and wave 9 candidate. The identical harness sweeps 21 sizes (4,8,9,16..32,64) for both dense and fragmented workloads; every integer size 17..31 is included. Keep 14 samples/side/workload and 4096 rounds/sample, record median and sample min/max. No claim that all 17..31 benefit until measured. Test outputs must match exactly. Timing remains diagnostic on a shared runner, not a hard real-time or statistical guarantee.

T52: expand actual score_operations measurement from two domains to all 15 equally situated domains, using the current ActionSchema v2 legal values (three or four per domain; D06 includes CPU metadata). All scores and selected indices must match across revisions. These are synthetic snapshot/model workloads, not native authority, real model deployment or cross-resource optimization. No security-brain code changed. Total 57 distinct workload names (42 allocation + 15 scoring). Retain all 34 planned CI jobs, existing QEMU provenance, positive and negative checks.

## Completion gates and limitations

Wave 9 actual Rust compilation, full regression, format, both QEMU mechanism tests and three-way benchmark pending. No local Rust toolchain or separate agent reviewer; reference-state checks and same-agent source/spec review only. No full local RED/GREEN claim. Performance acceptance requires actual same-runner measurements and eventually target-hardware evidence; no energy, G4/G5 or release claim. No baseline ref modification or merge.
