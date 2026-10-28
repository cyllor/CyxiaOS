# V0.12 continuation — 2026-10-28

The complete prototype remains **incomplete**. The fixed configuration-1.3 catalogue reports 69 `NOT_RUN` entries, an incomplete filesystem fault matrix, and `functional_acceptance_complete: false`. Passing host checks and individual native startup observations do not close those requirements.

## Implemented checkpoint

| Commit | Change |
| --- | --- |
| `44afad4` | Unified `build`, `run-single`, `run-pair`, `test`, and `report` commands in `tools/prototype.py`; retain independent check failures and refuse to overwrite evidence. |
| `73ee833` | Retry transient governance acquisition failures; settle retained physical credit before request selection; finish the bounded startup self-test before new model admission while preserving already-owned work. |
| `d61faa3` | Retain a fixed 512-byte native file admission/ABI diagnostic bank, including failed grants, current request and previous completed request. |
| `7c0e6e1` | Keep known no-effect file retries in the kernel owner queue with the original stopped syscall; distinguish executed EAGAIN and retained result delivery. |

The normal governance entry quantum is 2 ms. Its work/credit limits, deliberate timer probe, 50 ms snapshot deadline and all acceptance thresholds remain unchanged. File retries receive and settle actual CPU0/caller credit on each turn.

## Evidence retained locally

Paths below are relative to `artifacts/v012-continuation/`, which is ignored and contains provisioned native artifacts. Do not publish private identity material.

| Evidence | Result and limit |
| --- | --- |
| `delivery-checks-v5/summary.json` | All nine host-validation commands pass: 1,159 Rust tests across 155 result groups, TLS checks, 671 host tests (two environment skips), 83 tooling tests, formatting and both configured Clippy checks. |
| `build-retained-file-retry/build-manifest.json` | Both native images built; selected preparation stack checks pass. Build status remains `BUILT_NOT_RUN`. Code source SHA-256: `4755836255f249cf6b2a3ddca97e59710d95e62faf4fbae14a81d5fbf58cd600`. |
| `native-single-governance-startup/result.json` | Governance startup reaches phase 8 with fault 0, 19 turns, protection/timer probes and settled credit. Snapshot-to-validation is 3.570 ms within the unchanged 50 ms deadline. The overall run fails the ordinary file client; this is not A16 acceptance. |
| `native-single-retained-file-retry/result.json` | Overall **FAIL**, client stage 134 after 64.329 host seconds. Ordinary CRUD/fsync/stat/reopen advances to successful request 19, a 32 KiB workload write; the client's unchanged 45 s whole-run deadline expires at the following yield. No full workload or model adoption is proven. |
| `catalogue-checkpoint.json` | Catalogue valid; all 69 entries `NOT_RUN`; filesystem matrix incomplete. `prototype.py report` correctly exits 2. |

File diagnostic timestamps are generic timer ticks, not nanoseconds. This run reports a 62,500,000 Hz timer; convert ticks using that recorded frequency. Admission diagnostics are explanatory data, not acceptance receipts.

The native verifier retains failure status even when useful diagnostics are present. In the latest failed run it does not assert source/build attestation or release acceptance.

## Native filesystem progress

The same source was rebuilt with the existing `--selftest --storage-fault` profile in `build-a10-retained-retry/`. Both image and preparation stack checks pass. Three standalone ordinary EL0 modes now have independently verified native results:

| Evidence directory | Actual verified behavior |
| --- | --- |
| `a10-preparation-retained-retry/` | Mode 1 PASS in 120.830 s: writer consumes fsync sequences 1 and 2; the other endpoint reads and checks all 4,096 bytes of version 2. Protected exits, receipt consumption and independent disk oracle agree. |
| `a10-overwrite-retained-retry/` | Mode 2 PASS in 90.783 s: the device trace confirms actual reordered replies; the original object `[5, 2]` remains and fsync sequence 3 becomes durable. The concurrent reader observes the valid prior version before the writer commits. |
| `a10-recovery-retained-retry/` | Mode 3 PASS in 60.880 s: a fresh boot replays four blocks from three committed transactions; the new reader verifies all 4,096 bytes of version 3 and the original object identity. |

Each uses the source-attested patched QEMU, wall clock, multiple TCG threads, and the frozen 30 s observation interval. These standalone runs use a shorter 180 s diagnostic capture cap; they cannot automatically satisfy the full matrix's exact input contract. Their reports correctly retain `native_acceptance_status: NOT_RUN` and `A10_complete: false`. Cache-pressure mode, every required power-cut boundary, recovery interruption, and full matrix review remain open.

Mode 1 also retains a performance concern: its first cache-only WRITE and reader READ follow their preceding successful OPEN by 15.190 s and 24.259 s respectively, with no intervening device reads/writes in the protected counters. This requires further attribution of caller, owner and memory-copy scheduling; it does not justify increasing deadlines.

## Independent review

Fresh-context source reviews found no Critical or Important defect in this checkpoint. The production-body scheduling harness covers retained credit settlement, startup priority, and already-owned job priority with independent failing mutations. The file harness covers no-effect retry custody, executed-EAGAIN non-replay and retained receipts using the production Scheduler.

Deferred minor: extend file retry coverage to deferred completion settlement and cleanup barriers. The current harness exercises immediate settlement; reviewed production barriers are not a substitute for executing that case in the final fault matrix.

## Next native gate

The reviewed source commit `7c0e6e1` is on the independent validation branch `codex/v012-native-retry-20261028`. The existing Linux workflow is running the exact patched QEMU build, first protected replay pair, and all five same-boot service restart profiles:

[Native run 40731506555](https://github.com/cyllor/CyxiaOS/actions/runs/40731506555)

No result is assumed while it runs. Compare its raw evidence with the Mac failure before changing scheduling or deadlines. Then complete accepted paired replay, native training/validation data, model transitions, all mandatory scenario verifiers and the filesystem fault matrix under the existing acceptance plan.
