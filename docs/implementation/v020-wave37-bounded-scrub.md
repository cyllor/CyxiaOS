# V0.20 wave 37 — bounded retired-page scrub and cloud replay

Preparation evidence, 2026-11-26. Parent `8aceebd462a6a40683b7c5c4e013c37aa6703da8`, target `4912423cf2bc26ddf5c38eeea0f64190ce07a085`; refreshed comparison ahead 170 / behind 0. Only the existing `work/v020-integrated-eleven-gate-custody` branch and PR #97 are used. No target-branch write, merge, production authorization or deployment.

The requested issues 3/4/5 are respectively incomplete production callers, CPU0 accounting overruns and intermittent VirtIO-blk timeout. They do not all have one established software root cause.

## Exact-parent CI and retained failure evidence

The REST query includes both `push` and `pull_request`, rather than the connector convenience method which returns only PR runs. All 11 returned runs completed on attempt 1: nine success, two failure. The six PR workflow families succeeded; the push production and eight-role workflows failed. No current run was cancelled for this increment.

- [Push eight-role run 45847107148](https://github.com/cyllor/CyxiaOS/actions/runs/45847107148), job `140006019609`, artifact `15131289044`: 1 GiB captures 1–3 failed at `V0199_RECOVERY_OVERRUN_PHASE a=5 b=32`, actual **2193384 / 2043315 / 2127727 ns**, each against the unchanged **2000000 ns** recovery reservation. Original ZIP SHA-256 `41e0ded5e460629c52510f50a26657a3845d7cc4bb760c06740009fd0482667b`.
- [Push production run 45847107313](https://github.com/cyllor/CyxiaOS/actions/runs/45847107313), job `140006120679`, artifact `15130564891`: initial format step 1 failed with `V020_W11_MEDIA_IO_ERROR a=6 b=2040 c=23`. This is **WRITE / POLL / Timeout**, at the batch beginning with sector 2040; it is not the older read/reopen diagnosis. Completed I/O maxima were 3439 / 149000 / 519 microseconds for READ / WRITE / FLUSH. Original ZIP SHA-256 `ac8f2351daf41d8ce496d4ff83716260e86b1a5692b4f42abef1c0c215d83b4e`.
- Successful PR comparators: eight-role run `45847111795`, artifact `15132058872`; production run `45847111600`, artifact `15132637185`. Both pairs have identical guest ELF bytes and source manifests. Eight-role guest SHA-256 `a771b5031d8c3cf6a5e0a6f15586f6145007a3c7a6f72a30e0384c3f59c54b6e`; media-staging guest SHA-256 `5a4e77fd7bcce132cb0c65c2c25a33bc4240d14fdfc3fc8663e8be4dd26744f8`. QEMU binaries differ, including media QEMU `.text` and `.rodata`, so whole-file metadata alone does not explain the difference.
- Media host pre-run I/O pressure `some avg10` was 25.52 in the failed job and 14.11 in the successful job. These are snapshots, not per-request causal evidence. No claim that pressure or QEMU code differences caused the timeout.

## Issue 4: repair the actual retired-image scrub

The failing call is `restart_each -> retire_root_checkpointed`, phase 5. Its real linked ARM instructions perform a generic page fill followed by a **4096-iteration byte-load verification loop**, then reach the accounting callback. The check is after the entire page. Old root revocation, non-global leaves and architectural TLBI already precede this operation.

`cyxia_arch_aarch64::memory::scrub_retired_page` now clears and reads back every byte using aligned volatile `u64` accesses, with byte handling for an unaligned prefix/tail. It calls the existing accounting checkpoint after each **256-byte** piece. The native caller still retires the same 64 KiB image plus 32 KiB stack, and never republishes an unfinished backing. Actual work, callback/settlement overhead and gaps retain their existing accounting. No 2 ms reservation, 8 ms recovery budget, 70 ms/100 ms limit, role quota, deadline or overrun verdict is relaxed.

The low-level helper resides in the architecture crate. An initial development placement was rejected by `kernel-core::control_plane`'s `forbid(unsafe_code)`; that change was removed, and the prohibition remains unchanged. This is a real architecture boundary, not a reason to suppress the lint.

Behavior regression covers all eight alignment offsets, all 4096 bytes, adjacent canaries and the maximum 256-byte work between callbacks. Actual RED was observed before the helper existed; the component tests establish scrub semantics, **not** a timing guarantee. The original native CI failures above are the performance RED. Linked ARM disassembly confirms ordinary 64-bit stores and loads in the candidate, without replacing verification with a constant.

## Cloud verification blocker repaired

The existing runner could not start its Unix-socket QMP channel in this cloud executor (`Operation not permitted`), before guest execution. Rust 1.95.0 and the pinned QEMU CI artifacts were available after verified downloads; lack of local Codex or independent agents was not a blocker.

The optional `--qmp-stdio` transport uses only the owned QEMU child's stdin/stdout. It preserves the existing QMP framing/IDs, UART decoder, stopped-memory capture, source/ELF binding, budgets, failure predicates and cleanup. The default CI Unix transport is unchanged. The report records which transport was used. Both the SMP/eight-role and production runners support it, including all production reopen subprocesses. Three real-child transport tests cover command/argument/ID delivery with an intervening event, bounded silent-read timeout, and EOF. They are transport tests, not guest evidence.

## Actual local verification before push

| Check | Observed result | Limit |
|---|---|---|
| Rust 1.95.0 AArch64 crate tests | 6 passed, including the new scrub behavior test | Host functional tests |
| Driver VirtIO tests | 104 unit + 5 integration passed | Existing driver unchanged |
| Production verifier / TLS / signed scratch / envelopes / QMP transport tests | 111 passed | Synthetic verifier inputs are not native proof |
| Native security source guards | 49 passed | Structural checks only |
| Architecture crate Clippy with `-D warnings`, touched Rust formatting, diff whitespace | Passed | Scoped author checks |
| ARM 256 MiB, 1 GiB and epoch-disk kernel builds | Passed | Builds are not runtime acceptance |
| Exact parent eight-role guest, failing push QEMU, stdio transport | 3 failures before recovery: Role 2 286067 ns, Role 8 256881 / 272779 ns, each versus 250000 ns | Exposes an additional earlier local-host entry/exit overrun |
| Same parent guest, successful PR QEMU, stdio transport | Role 8 273476 ns versus 250000 ns | A different QEMU binary did not remove the local failure |
| Candidate 1 GiB kernel, failing push QEMU, stdio transport | Role 8 355871 ns versus 250000 ns, before recovery | Candidate recovery timing not reached locally; no native GREEN claim |
| Exact parent media guest and failing push QEMU, stdio transport | PASS, 33.156 seconds; real VirtIO/network, UART and stopped-memory checks | One replay, not a timeout fix or production certification |

The candidate therefore requires the existing exact-new-SHA CI, including all three native captures at both memory sizes. A local earlier overrun is not turned into a skip or success. Timing variability and original CI failure artifacts remain relevant even if later runs succeed.

## Issues 3 and 5: current boundary, no manufactured closure

Issue 3: `production::pie_dispatch` authenticates the actual CPU, registered caller and TTBR0. `observations::snapshot` has live Operations/Controller views for one D01 installed target, age field only; missing native data remains `None`/`EAGAIN`. Bootstrap role loops explicitly wait for real plan keys, candidate inputs, authenticated audit state and models. These are incomplete production integrations, not errors that can be fixed by returning success. All 15 domains retain equal architectural status; there is no claim of 15 live capture/execution loops or two authentic trained brains. No authority is invented to enable a missing path.

Issue 5: `media_staging::Disk -> scratch_blk -> BatchedBlock::poll` retains the 250 ms request deadline, live device-status checks and pinned-buffer custody. The actual failed write was not reproduced in the one exact-artifact cloud replay. Current driver regressions pass. The available evidence does not justify a driver change, timeout increase, retry that hides failed writes, backend/cache substitution, or a root-cause-closure claim. Next evidence must distinguish host/device delay from a missed completion on the same authenticated artifact and request.

## Two-axis author review and gate ledger

Superpowers (using, executing, systematic debugging, TDD, verification), Ask-matt routing/diagnosis/TDD/code review and CyxDiag routing/service/performance/hardware/root-cause/repro skills were actually loaded. Work was performed by one cloud agent as requested. **Standards review and specification review are separate author self-review passes; there is no independent reviewer or approval.**

- Standards: retain the core's unsafe prohibition; keep volatile pointer access in the architecture layer with exclusive-slice/alignment reasoning; no new allocations or ABI layout; default runner behavior and existing failure checks preserved. Review scope is this delta from the exact parent, not certification of the entire cumulative PR.
- Specification: CPU0 remains the sole control CPU, CPU1–3 remain business CPUs, both brains remain advisory, all budgets and 15-domain standing remain unchanged. New tests and native replay are honestly scoped. No formal Verdict v4 is issued and no signing/device/model input is fabricated.

| Gate | Current remaining production obligation | Status |
|---|---|---|
| G01 | Authentic signed catalog, production identity/cap issuance and boot custody | OPEN |
| G02 | Eight complete native service/IPC/trap/lifecycle loops | OPEN |
| G03 | All 15 actual observation producers and genuine model inputs | OPEN |
| G04 | Independent deterministic authorization, publication and epoch/recovery closure | OPEN |
| G05 | All 15 real execution owners and terminal effect proofs | OPEN |
| G06 | Authentic paired training/validation data, complete costs and model promotion | OPEN |
| G07 | Mounted production file service and arbitrary crash-tail recovery | OPEN |
| G08 | Immutable snapshot COW/GC/restore with actual media custody | OPEN |
| G09 | This bounded scrub plus entry/exit/gap timing, full-path accounting and loaded measurement | OPEN |
| G10 | 127 stable IDs, 262 G4 + 26 G5 mandatory proof pairs and physical A53 evidence | OPEN / formal verdicts NOT_RUN |
| G11 | Approved ABI/media/sub-schema byte freeze and independent golden vectors | OPEN |

Production signing authorization, authentic training data and physical A53 access require real external inputs. They are not the only outstanding work: the software integrations and timing/timeout investigations above also remain open. No completion or automation shutdown is warranted.
