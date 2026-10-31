# A01 focused debugging — 2026-10-31

This increment repairs failure diagnostics and preservation. It does not repair every observed boot failure, admit A01 to the formal catalogue, or change runtime authority, CPU budgets or deadlines.

## Historical normal-boot failure isolated

The failed `12e07b5102c3d557f4399d32f1d2733d0d28a524` run was `41172744146`. Its artifact `13032017145` has ZIP SHA-256 `1febcc75dd047e282086fc4d2c2070b95eead43a7c9d130ebf2649d5214294db`.

The read-only forensics job in run `41188138908` checked that digest and decoded the recorded bytes, without executing code from the archive. The normal profile's last `pending-boot.bin` contains state 2 (SAFE_EXEC), reason 3 (Mount), epoch 0, model turns 0, model CPU checkpoint 0, and online mask 15. Its serial stream contains `BOOT_SAFE_EXEC new_ai=closed cluster=closed`. The pending sample was read while running, not a stopped/sealed acceptance sample. It is diagnostic corroboration, not a substitute for a complete native A01 receipt.

`try_boot()` maps reason 3 to `journal.mount()` failure, before BootEpoch allocation and before the EL0 model self-test. The old `Err(_)` discarded the underlying journal/device error, so the precise I/O/format cause cannot be recovered from this archive. In particular, this failure does not demonstrate a model CPU overrun.

Forensic output artifact: `13037512732`; ZIP SHA-256 `d1d7ee3f52bf24e8d737135f3502f4f612ec237e1f22c8e71702ca24056285ea`.

## Changes integrated

* After a mount failure, a bounded 256-byte formatter records the underlying error and successful read/write/FLUSH counts. It does not retry I/O, release retained DMA ownership, invent an epoch or grant authority.
* The boot runner recognizes an unexpected terminal state only after stopping the guest, checking paused status and reading an even-sequence, identity-bound snapshot. A normal boot that has already failed no longer waits for a generic outer timeout.
* Failure cleanup records stopped boot/control/runtime/unified buffers and drains bounded raw serial. A torn boot snapshot or one failed buffer does not suppress the other independent captures. Failure collection neither resumes the guest nor rewrites its memory and cannot mask the original run error.
* The wrapper seals available raw results and adds source/tool/build/model inventory before rejecting a failed producer. Failed output never reaches the PASS verifier; successful evidence still uses the unchanged independent verifier.
* Eight persistent host tests cover mount classification, torn/mixed captures, stop-before-read, independent buffer failures, serial bounds and preserve-before-reject behavior.

Reviewed source blobs:

| Path | Git blob |
| --- | --- |
| `kernel/src/prototype_storage.rs` | `a48396fbab35571d8ad664e1e7262294497bb7e5` |
| `kernel/src/prototype_storage/boot_diagnostics.rs` | `62369eaf505e7f39cc1aae11785523b65e07a398` |
| `tools/run_v13_boot_recovery.py` | `a38f7ff482b3f3f52dcf41d3db9456254c08d8e7` |
| `tools/run_v13_boot_evidence.py` | `b9df370d32dbab65beb99a5fc6a82be9f91718f7` |
| `tools/test_run_v13_boot_diagnostics.py` | `fe490d9daed1fb636386b425f4b155f808161a72` |

## Native results: retain every trial

Run `41188549012` tested candidate `bc41155236434d94326fe465627ded28fe5b18b8`, not its workflow trigger commit. It built the pinned Rust 1.95.0 guest pair, formatter and PMU-patched QEMU 10.2.2, then ran three complete matrices. The frozen emulator source was `f8ed81651e61d9c2166df6121ce2af0f44f06b3e` with the repository's exact PMU patch.

| Trial | normal | epoch-write | epoch-flush | model-corrupt |
| --- | --- | --- | --- | --- |
| 0 | PASS | PASS | PASS | FAIL |
| 1 | PASS | PASS | PASS | PASS |
| 2 | PASS | PASS | PASS | PASS |

There were 11 successful profile executions out of 12; the job correctly returned failure. Trials 1 and 2 also passed separate-process matrix replay. They do not erase trial 0, and the absence of another Mount failure in these three trials does not prove that issue fixed.

Trial 0's failed model-corrupt profile supplied a stopped failure snapshot with:

```
state=2, reason=5 (model-selftest), mode=3, epoch=1
online_mask=15, model_turns=1, model_exit_kind=9 (preempted)
model_checkpoint_cpu_ns=1800, model_checkpoint_result=0 (pending)
model_passed_ticks=0, active_ticks=0
```

Thus the failed injection did not establish completion of the actual corruption check. SAFE_EXEC remained closed, but the regression must not count a generic timeout or preemption as a demonstrated corrupted-model result. The checkpoint CPU is not the final settled CPU bill; these bytes alone cannot distinguish wall deadline, settlement failure, scheduling delay or another cause. No claim of repaired preemption progress is made.

Native artifact `13037807555`, ZIP SHA-256 `8bbcb07f1917e325de744cf57a2e4e0fd81eb27a0f9391b192a28c9003efbbd96`, retains all three matrices and the exact source/emulator. Retention is 30 days, not permanent archival.

## Host validation and limits

The first candidate's Rust and tools lanes passed, and 23 existing boot/provenance tests plus focused inline diagnostic checks passed. Its static lane failed; its cross-toolchain setup was incomplete and must be diagnosed rather than reclassified as PASS.

Refinement `87eabfe7fa664104ce3627d995f300b13e614d9a` preserves partial failure captures independently and adds the eight persistent tests. Run `41189111330` successfully checked out that exact candidate and passed the complete tools lane, which discovers all `tools/test_*.py`. Its static and Rust jobs failed before testing because Git upload-pack did not resolve the candidate on those runners. Such infrastructure failures are not test passes. Integration into the existing branch makes the reviewed source reachable normally; post-integration results remain separate.

The focused debug workflow now checks the pushed source, never an old frozen candidate, and has read-only permissions. Existing engineering and native boot workflows remain required. No job edits the acceptance catalogue or promotes its own result.

## Reproduce and next hard gates

```
python3 -B -m unittest discover -s tools -p 'test_run_v13_boot_diagnostics.py' -v
python3 -B -m unittest discover -s tools -p 'test_verify_v13_boot*.py' -v
```

Native execution continues to use `build_unified.py --selftest`, the exact patched emulator, and `run_v13_boot_evidence.py` / `verify_v13_boot_receipt.py`; do not replace it with host fixtures or an unpatched emulator. Repeat matrices in different output directories and retain all failed trials.

Remaining A01 work is explicit: obtain the actual Mount error on recurrence; establish why the preempted self-test failed to complete, including its final settlement/deadline evidence; rerun the full boot matrix; cover and audit the four-vCPU/EL0-EL1 and no-new-authority assertions; only then add a reviewed formal A01 adapter and run-specific catalogue entry. A01 formal status remains NOT_RUN and the observed native regression set is not wholly passing.
