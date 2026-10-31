# A01 settled self-test and cold-boot evidence — 2026-10-31

## Scope and tested source

This increment fixes actual boot-worker result/accounting defects and closes the normal-boot four-CPU observation gap. It is not a declaration of complete formal A01 acceptance. The formal catalogue remains unchanged and `native_acceptance_status` remains `NOT_RUN`.

The latest code and verifier tested here are commit `acab773e25495485fd800fa7a2a14a9cdb6f9b4a`, tree `a4a5f60cb5bfe7d11a0f9740e480c7f9636d3489`. A later documentation-only commit does not change the identity of these native executions. Relevant design clauses are 2.1, 14.1/A01 and 14.4; host tests and native receipts are deliberately separate.

## Defects fixed

The exact original worker is retained as Git blob `c26d59b15fb84ed9317eaa57e083a9019c8efec1` in `tests/fixtures/a01-boot-worker-before-settlement.rs.txt`. The test checks its Git object identity before compiling it. These defects are independently reproducible in the actual worker under explicit host-only interleavings:

| Before | Now |
| --- | --- |
| Any non-preemption trap or malformed completion became `Some(false)`, indistinguishable from a completed model rejection. | A model result requires the exact EL0 SVC, output magic, Boolean result and case count. An unrelated fault or malformed reply closes boot authority but does not certify corrupted-model detection. |
| The completed result was written into the evidence checkpoint before the physical CPU bill settled. | Intermediate checkpoints always remain pending. Only a valid result whose exact bill successfully settles can publish a completed model-test receipt. |
| A cancelled or unsuccessfully settled turn could leave a completed-looking model checkpoint. | Pending-state compare/exchange prevents cancellation from resurrecting a result. Budget/settlement errors and cancelled work retain no completed model receipt. |
| A Busy settlement could later publish without checking the original wall deadline again. | Terminal settlement rechecks the original deadline; retries never reset it or rerun the model body. |
| The reported CPU amount was the earlier checkpoint, not the final enclosing bill. | A completed receipt contains the cumulative actual CPU used by the settled worker bills, including checkpoint serialization within the measured span. |
| Only SAFE_EXEC copied the actual registered CPU mask; normal activation left that field zero. | Normal activation copies the guest SMP observations before release-publishing its terminal state. Both stopped normal snapshots must contain exactly mask 15. |

The existing recovery credit and cumulative self-test CPU limit remain 8,000,000 ns. The existing one-second self-test wall deadline is unchanged. No control ceiling, ownership grant, runtime timeout, failure mode or acceptance threshold has been relaxed. Generic self-test failure still keeps SAFE_EXEC closed to new AI and cluster authority.

## Implementation and diagnostics

`kernel/src/prototype_runtime/boot_model.rs` distinguishes a validated rejection from a generic failure. CPU1 retains the exact pending bill across Busy retries; CPU0 publishes the final settled model receipt only after observing the successful result publication. Preemption resumes the saved context rather than creating a fresh model test or extending the deadline.

A separate 512-byte `A01_BOOT_MODEL_DEBUG` bank records admissions, final actual/cumulative CPU, exact credit identity, settlement status, entry/return PC, terminal cause and cancellation. It is explicitly a diagnostic, not an authority or a substitute acceptance receipt. Failure capture independently retains this bank, `CONTROL_SETTLEMENT_EVIDENCE` and the original SMP fault bank as well as the existing boot/control/runtime/unified buffers. A missing or torn buffer cannot suppress the other buffers or mask the original run error. Successful QMP capture ordering remains unchanged.

`kernel/src/boot_recovery.rs::active()` now records `smp::boot_progress()` before sealing normal activation. `tools/verify_v13_boot_recovery.py` requires `online_mask == 15` separately in each stopped normal sample and reports the observed mask. The launch command alone is not accepted as evidence that the secondary CPUs started.

The substantive commits are:

| Commit | Change |
| --- | --- |
| `0eb379d2834caa70268950598e67a67aaa1a124b` | Final-settlement diagnostics, independent stopped failure captures, four added capture tests and a five-matrix native workflow. |
| `383d071814e0218991e8153979383977ef4e1b8a` | Validated-and-settled model result publication; actual-source interleaving harness and historical comparator. |
| `e1452421a402e517a6f724579ba71cf9a39c149a` | Exact Rust 1.95 rustfmt corrections only; no behavior changes. |
| `acab773e25495485fd800fa7a2a14a9cdb6f9b4a` | Normal-boot observed four-CPU assertion and decoder mutation tests. |

## Host verification: actual source, not a substitute implementation

`tools/test_a01_boot_worker.py` compiles the real kernel worker with explicitly mocked architecture, clocks and scheduler. Fourteen independent scenario processes cover valid pass/rejection, exact final CPU, pending settlement, cancellation, delayed settlement, unexpected traps, wrong magic/count/Boolean, settlement failure, per-turn/aggregate overrun, preemption resume and no-credit deadline expiry.

All fourteen pass on the fixed source. The same harness reproduces six expected failures against the exact historical worker: final CPU, premature pending-settlement receipt, cancelled return, late settlement, unexpected trap and settlement failure. A historical no-credit/deadline control scenario still passes. These are deterministic host reproductions of the result-ordering defects, not a reproduction of the unexplained historical native stall.

Run `41218697547` passed both host test methods but failed its formatting step. That failed run is preserved, not relabelled. After the formatting correction, the latest-source worker run `41219593286`, job `124591175720`, completed successfully, including formatting.

Four additional capture tests exercise independent stopped buffers, partial buffer failure, size bounds and separation of final bills from checkpoints. Two additional CPU decoder tests mutate either normal snapshot to missing/partial/extra CPU masks and check the reported registration. The diagnostic discovery command reports 20 test invocations because the imported eight-test base class is discovered twice; this is not 20 unique diagnostic tests. The latest boot-verifier discovery command reports 25 test methods.

For tested source `acab773`, engineering run `41219593282` has verified successful static, Rust and tools lanes. The separate host engineering lane was still running when this note was prepared; it is not included in that PASS claim. The narrower exact-worker host run above is complete.

## Native repetitions: keep source identities separate

Each matrix runs `normal`, `epoch-write`, `epoch-flush` and `model-corrupt` against the pinned PMU-patched native emulator. Every trial is retained. A failed profile or separate-process replay fails the aggregate instead of being replaced by a later successful trial.

| Tested source | Run | Four-profile executions | Separate-process matrix replays |
| --- | --- | --- | --- |
| `0eb379d2834caa70268950598e67a67aaa1a124b` | `41217259312` | 20/20 PASS | 5/5 PASS |
| `383d071814e0218991e8153979383977ef4e1b8a` | `41218697385` | 20/20 PASS | 5/5 PASS |
| `acab773e25495485fd800fa7a2a14a9cdb6f9b4a` | `41219593299` | 20/20 PASS | 5/5 PASS |

Only the last row includes the new normal-boot four-CPU assertion. Earlier results do not certify later source or stronger assertions. These are boot regression passes, not formal catalogue passes or hardware-isolation proofs.

The last run's job `124591175669` checked out `acab773`, built both native node images and completed all five matrices with `returncode=0` and `replay_returncode=0`. Its artifact contains 944 files including the exact source archive, build log, per-trial raw evidence, receipts and replay logs.

| Run | Artifact | Artifact ZIP SHA-256 |
| --- | --- | --- |
| `41217259312` | `13048178306` | `88a40cc26d7e83c4353f85bd48af47cb2f831f4a7501e2af8c70dc03e14022aa` |
| `41218697385` | `13049172773` | `eba799a937c5971d75147052d36369cfc60e02f34e6b863a5b692b8f4a893603` |
| `41219593299` | `13049627199` | `dca852f557b6468df2a65910caed1dbb635bcd379f96167b5bb47b0d2570f77a` |

The latest artifact is named `v13-a01-stress-acab773e25495485fd800fa7a2a14a9cdb6f9b4a-1`, is 62,879,954 bytes, and expires on 2026-11-30 under the 30-day retention policy. These are retained CI artifacts, not permanent archival.

## Pinned emulator and reproduction

The repeated-boot workflow verifies and reuses the byte-identical emulator from previously successful provenance run `41189912033`, artifact `13038781976`. It verifies the entire ZIP hash `0505b2597c127246eab4a1b774efade2423c2560768c48c9061b5988edcdad07`, reads only the three explicitly named emulator metadata/binary entries, and never imports archived Python or shell code. Exact source checkout plus the repository patch is independently attested:

```
QEMU source: f8ed81651e61d9c2166df6121ce2af0f44f06b3e
QEMU binary SHA-256: c66d0d610d82aa80c83244953390fc3c241cefe6dbefd5d7edcd1d84ddff5395
PMU patch SHA-256: b92d2ce14bca13cae43338729de3226c1ad9f469dc9947e1bd5c465d753876fd
Rust: 1.95.0, aarch64-unknown-none and aarch64-unknown-none-softfloat
```

The cache artifact also has finite retention. If unavailable, rebuild the exact pinned patched emulator using the existing provenance workflow; do not substitute an unpatched system QEMU or skip attestation.

Host checks:

```
python3 -B -m unittest discover -s tools -p 'test_a01_boot_worker.py' -v
python3 -B -m unittest discover -s tools -p 'test_run_v13_boot*.py' -v
python3 -B -m unittest discover -s tools -p 'test_verify_v13_boot*.py' -v
```

Native execution uses `.github/workflows/v13-a01-stress.yml`, `build_unified.py --selftest`, `run_v13_boot_evidence.py`, and `verify_v13_boot_receipt.py`. Use a distinct output directory for every matrix and retain failed output. Verification uses the exact source/verifier corresponding to each run, not an older producer's PASS flag.

## What is still open before formal A01 admission

The earlier Mount failure and the earlier one-turn/preempted model-corruption failure described in `v13-a01-focused-debug.md` remain historical failures. They did not recur in the repetitions listed here. That observation is not a root-cause proof that either intermittent failure is repaired; the result-ordering fixes above address separately demonstrated defects. Diagnostic final bills and terminal causes now make a recurrence distinguishable from the old checkpoint-only record.

The complete A01 adapter still needs a reviewed, run-specific assertion/receipt mapping for actual EL0/EL1 setup and authorization ordering. In particular, correlate the first actual new DecisionKey/publication with the durable BootEpoch rather than treating an activation timestamp alone as the complete decision-key proof. Exercise persistent-epoch continuity across reboot with the same node identity and disk; the matrices here deliberately use newly formatted independent disks and do not establish that reboot property. Preserve the existing failed-boot no-new-AI/cluster-authority and deterministic local-progress checks while extending the evidence.

Only after these coverage and provenance gates are met should a reviewed formal adapter/catalogue entry be added. No catalogue status is promoted by this note, the host harness, a regression producer, or a successful CI badge.
