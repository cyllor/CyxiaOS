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

## Independent review

Fresh-context source reviews found no Critical or Important defect in this checkpoint. The production-body scheduling harness covers retained credit settlement, startup priority, and already-owned job priority with independent failing mutations. The file harness covers no-effect retry custody, executed-EAGAIN non-replay and retained receipts using the production Scheduler.

Deferred minor: extend file retry coverage to deferred completion settlement and cleanup barriers. The current harness exercises immediate settlement; reviewed production barriers are not a substitute for executing that case in the final fault matrix.

## Next native gate

The reviewed source commit `7c0e6e1` is on the independent validation branch `codex/v012-native-retry-20261028`. The existing Linux workflow is running the exact patched QEMU build, first protected replay pair, and all five same-boot service restart profiles:

[Native run 40731506555](https://github.com/cyllor/CyxiaOS/actions/runs/40731506555)

No result is assumed while it runs. Compare its raw evidence with the Mac failure before changing scheduling or deadlines. Then complete accepted paired replay, native training/validation data, model transitions, all mandatory scenario verifiers and the filesystem fault matrix under the existing acceptance plan.
