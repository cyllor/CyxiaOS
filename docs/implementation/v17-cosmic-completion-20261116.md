# COSMIC notification build and runtime reliability, 2026-11-16

This slice starts at `8842e8e0e397fc5150c7f324f1dd6de257eb4bb5` on
`CyxiaOS-V0.17`. It continues the genuine COSMIC session work and repairs the
eight findings from the latest review. Complete OS, rendered notifications and
complete COSMIC session acceptance remain false. A03 remains cancelled.

## Process exits and runtime profiles

`Supervisor::publish_child_exits` is the original receipt-publication half of
`collect_children`, separated from waiter delivery. Every actual Runner reuse
passes through the single `launch_accounted` call to `Runner::start`; publication
now happens before that call can replace the old PID/status. Spawn also publishes
before counting free receipt slots, reclaiming completed auto-reap/orphan entries
before admission. The waiter/usercopy half and status encoding are unchanged.

`None -> Some` publishes an exit and raises SIGCHLD once. Successful wait,
auto-reap or orphan disposal clears the receipt and releases its one accounting
charge. Failed usercopy retains the receipt for retry even after Runner reuse.
There is no new usercopy, scheduling or synchronous model evaluation in the
publication step. Existing admission decisions and resource reserves remain.

The pipe accounting diagnostic now has the same `ported` feature condition as
the pipe module. A real default `os-runtime` build, without `ported`, completed
with Rust 1.95.0 and Clang 19.1.7. The output was `BUILT_NOT_RUN`; the ordinary
build still reported its existing unused-code warnings, so this is not a claim
that every runtime profile is warning-free.

The host regression extracts the production launch/spawn/finish/publication/wait
methods and uses the real POSIX signal types, memory admission policy and AI
accounting module. Its 12 semantic scenarios, two feature compilations and two
negative controls cover reuse, signal outcomes, parent death, auto-reap,
usercopy retry, parked waiters, pair rollback and failed ELF loading. Hardware,
MMU and resource-release facades are explicitly test substitutes.

## Clock and final capture truth

The PC wall clock no longer permanently latches an unsuccessful boot probe.
Every CPU0 request samples the real CMOS decoder again. Busy hardware returns
`Again`, unavailable hardware returns `Nodev`, and invalid calendar data returns
`Io`; a later valid sample can recover. Non-CPU0 requests return before CMOS I/O.
Tests compile the actual kernel clock and RTC decoder with simulated hardware
ports and exercise recovery without reinitializing or returning guessed time.

`os_smoke.capture` keeps its result at FAIL until normal process exit and both
final serial drains have completed. Failure markers or read errors arriving
after the last display check, or during QEMU shutdown, are preserved as errors
and cannot be turned into PASS. The second drain permits the expected process
exit while retaining serial/content checks. Source/input revalidation remains
required before assigning PASS. Five new finalization tests and the four
existing smoke tests pass. The old producer fails four of the five new cases.

## Existing gates and probe production

The pinned x86 selftest Clippy command now passes with `-D warnings`. Changes
preserve the ABI and runtime behavior: equivalent range/alignment expressions,
`Default` forwarding to `Handoff::new`, runtime-only code under its actual
feature, and three local lint explanations for intentional ABI/publication
signatures and the existing PlanView count contract.

The active prototype catalogue had 12 distinct stale paths in 73 references.
Those paths now follow the exact checked-in kernel migration map. No historical
status or evidence was promoted: its checker returns 80 BLOCKED and one NOT_RUN,
with zero PASS and both release-completeness/runtime-attestation flags false.

`tools/build_pipe_capacity_probe.py` provides the missing reproducible producer
for the existing public-syscall probe. It reuses the frozen Builder, target
profile and ELF checks, but compiles and links with this host's actual Clang/LLD
against the selected read-only SDK. It neither mutates the generic PROBES table
nor rewrites old SDK compiler wrappers. Its receipt binds the source/producers,
SDK report, headers, CRT, libc, builtins, actual tools, commands and static ELF.

```sh
RUSTUP_TOOLCHAIN=1.95.0 python3 -B tools/build_pipe_capacity_probe.py \
  --sysroot artifacts/v017-cosmic-completion-20261116/sdk-x86_64 \
  --output artifacts/v017-cosmic-completion-20261116/pipe-capacity-build \
  --arch x86_64 \
  --native-lock artifacts/v017-cosmic-completion-20261116/native-session.lock
```

The host needs the real compiler/Rust installation on PATH. A successful result
is `BUILT_NOT_RUN`, with guest execution and native acceptance false. Failed
production retains its FAILED receipt and logs without publishing a final ELF.

This producer subsequently built the real x86 probe against the rebuilt SDK:
45,840 bytes, SHA256
`d40b31b30d1f1bddef128b18e8509126417ea3efc159c5a072a0ceb4d0507a07`.
It was copied with three actual SDK probes into a separate catalog prefix. The
formal OS builder embedded those exact ELFs with `os-runtime`, `graphics`,
`ported` and `full-os`; the kernel build completed in 28.25 seconds. Its existing
35 warnings are preserved in the compiler log.

### Actual native execution

The standard `os_smoke` native capture failed before boot because this execution
environment rejects Unix-domain sockets. A separate one-session capture used
QEMU's real FIFO chardev for UART and QMP. Its first attempt received a genuine
QMP greeting but lacked the private QEMU GPU module search path; that failure
also remains preserved. Supplying the actual installed `QEMU_MODULE_DIR`, with
module hashes bound before and after execution, enabled the unchanged VirtIO
GPU and machine configuration. No guest output or device was substituted.

The earlier FIFO capture returned `OS_NATIVE_PIPE_CAPACITY_FIFO_PASS` in
14.306 seconds, with QEMU exit 0 after QMP quit and no forced termination. It
used QEMU 11.1.2, `pc-i440fx-10.2`, four CPUs and 1 GiB RAM. The capture bound
the real firmware, kernel manifest, embedded probe, producer and SDK identities,
all capture helpers and its own exact producer bytes. Both final serial drains
and post-run identity checks completed before the successful result.

The run exercised the existing native process/preemption/fault/FPU/heap/IPC
checks. The pipe probe produced its exact nine-line sequence: three rounds of
30 admitted pairs, bounded EAGAIN refusal, endpoint identity/data isolation,
dup/close/reuse semantics and EMFILE descriptor-installation rollback, followed
by the same PID's exit 0. The final pipe pool was 32 free / zero unavailable;
the process, heap/image pages, threads and global open descriptions were
reclaimed. The actual musl, Wayland and xkbcommon probes also exited 0.
QMP reported four CPUs, the register checks passed, and both actual 1024x768
scanouts matched the expected boot pixels byte for byte.

An independent review recomputed the nine markers, PID 12's exit and cleanup,
all current occupancy counters, pixels and source/tool identities from the raw
files. Pipe admission increased by 115 requests/proposals, 100 approvals and
commits, and 15 policy denials; 100 individual committed admission records
match those totals. The four FD-installation failures are included in committed
pool admissions because the pool allocation succeeds before FD rollback.
These cumulative counters are not used as a substitute for actual reclamation:
PIPE_POOL, OFD and ANON_POOL snapshots separately confirm zero current use.

This is functional OS/probe evidence with the declared FIFO transport. It does
not replace the failed standard socket capture, the separately pinned CPU
accounting backend, or full OS/COSMIC acceptance. In particular, the Wayland
probe explicitly reports `render=0 fd_passing=0`; its success does not establish
notification layer content or SHM/SCM_RIGHTS behavior.

## Genuine notification source, tools and installation

The component remains upstream `cosmic-notifications` 1.10.0 at
`1e4c1f11fdcae273d6954fd0bfc54749a6145267`. Its source/effective lock is
`448b38cb6bff1447d0b4fcd3b2f5bafa0b0c72d5200174f2932887eea831953b`.
The exact reviewed Cargo config removal and explicit `tokio_unstable` flags
remain the only source transformation. GUI, accessibility, Wayland, D-Bus and
the inherited panel socket protocol are retained.

The dedicated winit dependency validator now reads all Git objects with
`--no-replace-objects`. A real Git replacement regression proves that changed
blobs cannot pass by retaining original commit/tree IDs. The frozen generic
`build_cosmic.py`, `build_sysroot.py` and target profiles remain unchanged.

Explicit `--rust-root` and `--host-cc` select and record installed tools without
assuming the previous host's rustup/Clang paths. Source acquisition alone accepts
standard proxy transport settings and records their names rather than values.
Arbitrary compiler/Cargo environment injection remains excluded; target builds
remain locked and offline. Default distribution Clang links are resolved to a
recorded real executable; explicitly supplied paths remain strict.

The current environment rebuilt genuine musl/compiler-rt, libffi, Wayland and
xkbcommon, and produced their static x86 probe ELFs. The new Linux recipe binds
all eight native inputs, of which six hashes differ from the previous SDK.
The original recipe, source selection, lock and resource profile are preserved.
The first xkbcommon host-tool attempt lacked M4; its failed report/logs were
saved before supplying M4 and completing the real build.

The first acquisition lacked the required proxy transport and failed during
Git resolution. The corrected explicit acquisition completed in 153.249 seconds
with 493 target packages, including 446 registry packages, and 1,181,083,571
bytes of private-cache growth. Source and all 19 transitive producer identities
were unchanged during that run. Its exact producer bytes were also snapshotted.

The notification installer's default path requires a verified `cross-built`
report with both link flags. It rechecks canonical upstream blobs, source
normalization, full preserved export, Cargo metadata/dependencies, recipe/profile,
producers, tools/SDK and both linked and published ELF bytes. Local metadata paths
may be relocated only from the recorded, already deleted temporary stage into
the verified build/source copy. An independent check exercised that relocation
on all 493 actual dependencies. The explicit Full OS post-link admission below
retains all of these source and input checks while reading the original linked
ELF from a narrowly defined failed-build state.

Installation publishes one complete directory by rename after rechecking its
staged files and original inputs. It contains the unchanged executable, upstream
license and origin receipt. The kernel catalog now recognizes
`cosmic-notifications.elf` as `/bin/cosmic-notifications`; no substitute launcher
or duplicate rootfs/bin file is introduced. `INSTALLED_NOT_RUN` and
`VALIDATED_NOT_RUN` never imply service or session success.

### Native build outcome

The actual unmodified-source target build uses the Linux SDK recipe, two jobs,
Rust 1.95.0, locked/offline Cargo and the existing 3 GiB growth / 1 GiB reserve /
1,200-second command bounds. It failed with `build deadline exceeded`, after
447 compilation-start lines and before any final ELF. The stopped target
directory contained 1,508,288,128 bytes; that is not a successful peak or a
completion percentage. All producer identities were preserved. Its report is
`artifacts/v017-cosmic-completion-20261116/notifications-build-linux/build-report.json`.

A separate `native-linux-x86_64-extended-recipe.json` selects the versioned
`native-linux-x86_64-resource-v2.json`. The recipe differs only in its profile
name; the profile changes only its purpose and the per-command deadline from
1,200 to 3,600 seconds. Jobs, growth/free-space bounds, source/SDK identities,
features, image/stack bounds and every runtime-false flag remain unchanged.
The original recipe/profile and failed evidence are untouched. The follow-up
used a fresh target directory, since the interrupted target cache lacks a
completed provenance contract.

The genuine v2 Cargo build completed its release link in 23 minutes 45 seconds,
as recorded in `notifications-build-linux-v2/cargo.log`. The linked x86_64 ELF
contains 29,604,216 bytes with SHA256
`709ad360f05956909fb494a1c9053410d9f7010608941d9b51c2df0f761a40f1`.
Source, dependency, SDK and all 20 transitive producer postchecks completed
before the frozen inspector rejected the image with
`Invalid LOAD bounds, alignment or W^X permissions`. The subsequent independent
checks identify the legacy 16 MiB LOAD window as the rejecting condition.
The original `notifications-build-linux-v2/build-report.json` remains `failed`,
with `link_completed=true` and `target_linked=false`; the builder did not publish
its final ELF or an image-page count. The report SHA256 remains
`4d0cfb8a5533b9e6a538bb1a971fd5a5bc7f3a19ea6b64a59d44af3ea7d28644`.

### Full OS admission and actual installation

The separate `tools/cosmic_notifications_elf.py` helper checked this exact ELF
against a fixed, reviewed `full-os-v3` contract. Its four LOAD segments occupy
5,893 pages; adding the 512-page stack requires 6,405 of the 16,384 available
private image-pool pages. The helper preserves the original ELF guards and adds
the production loader's header, permission, PHDR, TLS, note, unwind and RELRO
checks. It binds the four reviewed loader/layout source hashes and refuses
contract drift or enlarged image/stack limits. The frozen builder and its
transitive producer closure were not changed to obtain this result.

An independently built Rust host witness called the actual
`cyxia_posix::executable::parse_for_profile` on the same ELF with Rust 1.95.0.
It returned `HOST_PARSER_WITNESS_PASS` for FullOsV3 and `Bounds` for Legacy.
Its four LOADs, entry, mapped PHDR, TLS and page budget agree with the Python
inspection. The witness preserved the ELF, failed build report and source
identities. Its result is recorded in
`cosmic-work/kernel/notification-loader-witness/witness.json`; the helper result
is in `cosmic-work/x86/notifications-elf-v2-helper-inspection.json`. These checks
establish parsing and the static page budget. They do not allocate physical
memory, obtain an AI grant, install TLS, publish page permissions or execute the
notification service.

After independent combined review, the real installer ran successfully with
`--full-os-linked-elf` and the unchanged extended recipe/v2 profile. The resulting
`notifications-install-full-os/cosmic-notifications-origin.json` has status
`INSTALLED_NOT_RUN` and records admission schema 1, mode
`full-os-linked-elf-v1`, the original `failed` report identity and the actual
FullOsV3 inspection. Its installed `cosmic-notifications.elf` has the exact
29,604,216-byte size and SHA256 above. The directory also contains the genuine
upstream license. The installer rechecked its staged bytes and every original
input before the atomic directory rename; it did not rewrite the failed report
or create a published ELF inside the failed build directory.

The default installer still rejects that failed report. The explicit mode only
accepts the exact legacy LOAD failure after preserved, completed linking,
requires a real legacy-window exceedance and repeats the full bounded parser
during installation revalidation. Guest execution remains `not performed`,
with `notifications_verified=false` and `cosmic_session_verified=false`. The
original build outcome, static admission, installation and eventual service
execution remain separately recorded facts.

### Final catalog image and actual native capture

The installed package was revalidated and copied with the four actual probe
ELFs into `runtime-catalog-notifications`. Its curation record binds each original
file, the unchanged failed build report and the complete installation validation.
The formal `os-full-notifications` build completed in 31.266 seconds with
`os-runtime`, `graphics`, `ported` and `full-os`. Its source identity is
`10b016cbc4ae678fb1c84ce487e80b3d0822a521d987103285b93e23c3d72a51`.
The 56,299,056-byte kernel has SHA256
`98edc7f5e5b035e6316176a48833db550831e34cf4d1f668bb5bae727e58a7fa`;
the 47,087,616-byte boot image has SHA256
`89d65bc220d8c61fef234c2f346c8e4a5dc4b54ca78fcca58de24a212bec694f`.
The build remains `BUILT_NOT_RUN`; its existing compiler warnings are retained.

The first capture of this image, `notifications-catalog-capture`, booted but
failed when its temporary harness requested `ls /bin` before the first ported
program. The full FAIL record, raw serial and normal QEMU exit remain preserved.
Source review confirmed that ported launch creates the parent directories
lazily, while shell `ls` reads RAMFS entries and does not merge the immutable
`ROOT_FILES` catalog. The POSIX stat/getdents adapters expose that catalog.
Consequently this shell command cannot prove that a ROM executable is absent
or present. No runtime code was changed to accommodate the unsuitable check.

The separate `notifications-catalog-capture-embedded` used the same built image
and returned `OS_NATIVE_PIPE_CAPACITY_NOTIFICATIONS_EMBEDDED_FIFO_PASS` in
16.237 seconds. QEMU exited 0 after QMP quit, without forced termination or a
capture error. The actual native checks, exact nine pipe-probe markers and
same-PID exit 0 passed again. The pipe pool returned to 32 free / zero
unavailable; live/open-description references, thread count and heap/image
allocations returned to zero. The musl, Wayland and xkbcommon probes exited 0.
Both 1024x768 scanouts again matched all 786,432 expected boot pixels.

Before and after that run, the capture checked the complete installed-package
inputs. The actual notification and pipe ELFs occur exactly once in read-only
kernel LOAD bytes. The captured generated `ported_catalog.rs` maps the genuine
notification ELF to `/bin/cosmic-notifications` in both `PORTED` and `ROOT_FILES`;
the corresponding compiler-output ELF matches the installed and embedded hash.
The generated catalog itself has SHA256
`a33ed61e2aa781a39b59fb2865556afc595d641e0987454dfc32221eb7d7968f`.
Final serial drains, source/tool/catalog revalidation and QEMU exit checks
preceded the successful status.

This proves static catalog integration plus actual OS/probe execution with that
larger image. The capture explicitly records `notification_catalog_embedded=true`,
`notification_catalog_listed=false`, `notification_guest_filesystem_accessed=false`
and `notifications_executed=false`. Guest reading or executing the notification
file, notification display and complete-session acceptance are not established.
The earlier successful FIFO run remains evidence for its own image and probes.

### Source-identified runtime follow-ups

The resolved renderer is `iced_tiny_skia`, whose ordinary Wayland surface uses
softbuffer and `wl_shm`. The presence of WGPU/DRM/DMA packages in metadata does
not establish that these paths are required for the notification's first frame.

Two genuine dynamic function tables still need explicit static bindings before
runtime readiness can be claimed. The selected `wayland-sys` 0.31.11 dlopen path
loads libwayland-client before creating the connection. The selected
`xkbcommon-dl` 0.4.2 loads the core/compose tables when the compositor advertises
keyboard capability. Merely adding the static archives to the linker does not
populate either table. Existing settings and compositor ports contain real
static-symbol binding patterns for these exact versions. The existing XKB patch
also requires libxkbcommon-x11 when x11 is selected; that additional library
cannot be silently treated as present in this notification SDK.

These are source-derived follow-ups, not observed notification guest failures.
Actual D-Bus delivery, visible Wayland layer content, close/expiry behavior,
panel integration, SHM/SCM_RIGHTS ownership and final resource reclamation remain
required. A complete COSMIC session must also exercise the other real services.

### Remaining complete-session boundary

The repository already integrates genuine compositor, session/launch-pad,
settings daemon, session D-Bus and configuration/theme sources. Their older
source-bound execution records are not replayed by this slice. The successful
current native run exercises the OS and listed probes, not that complete
service combination.

Beyond notification static binding, panel, applets, launcher and workspaces
still need actual package production and catalog/session integration. The
current `Supervisor::spawn_image_accounted` resolves programs from the explicit
`PORTED` catalog. The full-os configuration currently has eight process slots,
64 descriptors per process and 32 pipe slots with 4096 bytes per pipe. The
measured pipe result does not establish that the whole desktop fits its process
and descriptor limits; capacity changes need the real combined workload.

Service lifecycle also has remaining syscall boundaries. `Action::validate_for`
in `crates/posix/src/signal.rs` rejects SA_RESTART for an actual signal handler,
and the current x86 ABI decoder does not implement general execve. The existing
settings port reports signal-registration failure explicitly, and its SIGHUP
restart path still attempts real exec. The receipt fix in this slice preserves
exit custody; it does not implement those missing signal/exec semantics.
TERM/SIGHUP, crash restart, notification/panel disconnect and final service
cleanup must be exercised together before complete-session acceptance.

## Verification scope and evidence

The focused host suites cover 124 test entries: 100 Python and 24 Rust. The
Python total comprises notification dependencies/source/toolchain/ELF admission/
installation (62), smoke/finalization (9), pipe producer (8), existing catalogue
contracts (19), and child custody orchestration (2). The Rust total comprises
RTC/signal/architecture/prototype checks (24). Inner semantic cases, the actual
ELF parser witness and repeated independent reviews are not added to this count.
The notification ELF helper passes 24 tests and the installer passes 18;
synthetic ELF fixtures remain parser/identity tests, not compiler or guest
evidence.

Separate reviewers inspected receipt reuse/accounting, RTC, serial finalization,
the installer and toolchain isolation. The smoke suite was compared with the
previous producer; real metadata was checked with its temporary source absent.
No reviewer promoted source analysis or host fixtures into native acceptance.

The V0.17 workflow previously selected only two Python suites. Its new explicit
`COSMIC and POSIX host regressions` step now selects the 100 Python cases in
this slice plus the exact `cyxia-posix` integration targets `pc_clock` and
`x86_signal`. Existing shared-component gates cover the other targeted Rust
checks. The final exact module-loading check resolves 62 notification cases and
38 other Python cases, with no failed imports; it does not rerun test bodies.
Workflow shell syntax was verified, and removing the new step restores the
original workflow exactly. Triggers, native-execution boundaries and
source-evidence retention are unchanged. The final command review is recorded
in `cosmic-work/root/final-ci-step-review.json`. Remote CI has not been run;
these are the existing local regression results and verified future CI commands.

Native records live under `artifacts/v017-cosmic-completion-20261116`:

- `notifications-source.json` and `notifications-linux-sdk-inputs.json`.
- Both notification acquisition attempts, including the successful producer
  snapshot and original metadata/logs.
- `sdk-x86_64` reports and `sdk-failures/xkb-missing-m4`.
- `os-default/build-manifest.json` and its compiler log.
- `pipe-capacity-build`, `runtime-catalog` and `os-full`, binding the actual
  target probe and its embedded runtime image.
- `os-native-capture` (socket rejection), `pipe-capacity-capture` (module-search
  failure), and `pipe-capacity-capture-modules` (successful real FIFO run).
- Both real notification builds' metadata, Cargo logs and final reports.
- `notifications-install-full-os`, containing the exact admitted ELF, upstream
  license and `INSTALLED_NOT_RUN` receipt; its original v2 build report remains
  failed.
- `runtime-catalog-notifications` and `os-full-notifications`, binding the
  installed notification, license, actual probes and final image identities.
- `notifications-catalog-capture` retains the unsuitable shell-listing failure;
  `notifications-catalog-capture-embedded` retains the successful real native
  run and the explicitly static notification catalog proof.

Independent host-test and review logs are retained in the accompanying
`cosmic-work/kernel`, `cosmic-work/x86` and `cosmic-work/desktop` evidence folders.
The combined admission review is
`cosmic-work/kernel/notification-full-os-admission-review.json`; it compares the
actual helper inspection and Rust witness and reports no findings. Installer
and helper regression logs remain in the desktop and x86 evidence folders.
Remote CI and full COSMIC runtime results are not implied by these local checks.
