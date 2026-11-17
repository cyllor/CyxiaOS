# Genuine COSMIC runtime integration, 2026-11-16

This continuation starts at `fb763e7e9a76b1f146544d9c40e1a3d34acf79b8`
on `work/cosmic-completion-20261116`. The earlier notification build,
embedded-image capture and their failed intermediate reports remain in
`artifacts/v017-cosmic-completion-20261116`. New work uses
`artifacts/v017-cosmic-runtime-20261116` and the same native-session lease.

The current work joins the genuine upstream compositor, D-Bus and notification
service on CyxiaOS. Static linking, an embedded ELF, a successful D-Bus exchange
and a visible notification are separate claims. Complete COSMIC session and
complete OS acceptance require additional services and workloads beyond this
first runtime gate. A03 remains cancelled; x86 is primary and ARM remains a
compatibility target.

## Source and build boundaries

`tools/build_cosmic_notifications_static_v1.py` preserves the pinned upstream
`cosmic-notifications` commit
`1e4c1f11fdcae273d6954fd0bfc54749a6145267`. The new source policy exports the
complete checksum-verified `wayland-sys` and `xkbcommon-dl` registry packages
and applies explicit static-client features. The original GUI, accessibility
and X11 feature graph remains present. Actual locked, offline Cargo metadata
contains 493 packages, three workspace members and five local packages.

`tools/build_cosmic_comp_linux.py` uses the existing three-layer compositor
patch series for commit `41497b42d9744d9963c4c6d17e8add49489b45ee`, with
`--no-default-features --features backend-cyxia`. It selects the actual Linux
host compiler and Rust installation explicitly. Canonical export reads verified
Git blobs, file modes and links; it does not let replacement refs change the
exported commit. Recursive Git dependencies include their initialized submodules
and parent gitlinks. Git dependency query normalization accepts equivalent
percent encoding while retaining the repository and complete commit identity.

The successful v3 compositor preparation verifies 468 actual Cargo packages.
Its status is `CARGO_SOURCES_AVAILABLE`, not a linked or running compositor.
`tools/cosmic_comp_inputs_v1.py` independently checks source, dependency,
toolchain, generated wrapper, native input, log and ELF evidence before a
runtime capture can consume a successful build.

The subsequent real compositor build completed in 1,317.669 seconds with
`status=cross-built`, `link_completed=true` and `target_linked=true`. Its
actual ELF is 42,222,296 bytes, SHA256
`c4b35e727bb587a042fae928249ca5551bd08f5999fae70c3c183c4027df3538`.
Independent consumer validation and program-header calculation agree on
8,557 LOAD pages plus the 512-page stack, for 9,069 total pages. Raw and
published binaries are identical; there is no interpreter, dynamic segment
or writable/executable LOAD segment. All twelve actual native inputs and the
retained source, dependency, toolchain, log and producer evidence revalidate.
The log retains four config warnings and 45 compositor library warnings.
This is a linked compositor; guest behavior remains a separate claim.

The original Cargo cache was independently compared with the identities saved
before acquisition. All 32,098 registry entries and 2,918 Git entries match;
there are no added, removed or changed entries in those two trees. The old
notification report remains `failed`, and all 20 of its recorded producers
remain unchanged. The full comparison is
`artifacts/v017-cosmic-runtime-20261116/previous-cargo-cache-preservation.json`.

## Actual target dependencies and assets

The new runtime SDK is assembled separately from the earlier foundation SDK.
The target C library and compiler builtins retain their existing inputs. Real
XOrg libraries, zlib, pixman and xkbcommon core/X11 archives are built and their
actual hashes are bound to subsequent recipes. The xkbcommon X11 archive is
not replaced with an empty library or a successful-return shim.

The official zlib 1.3.2 release archive was recovered from its upstream release
URL after the old URL returned 404. Its bytes match the original manifest pin;
the original failed foundation report and manifest URL were not rewritten.
The new SDK assembly receipt records the independently regenerated compiler
drivers instead of altering the copied foundation report.

The genuine D-Bus 1.16.4 daemon, command-line clients and development archives
were built against this SDK. The actual daemon is 469,224 bytes with SHA256
`9e6b7f635bd4d0f1f14425a08b28f3125a36b356bde1092065a33f55d511ab13`.
The new real libdbus notification client is 946,192 bytes with SHA256
`ba549cd2a052837fbed319e9990b6e18c8be66100b7074aebd71cbb7b17cddce`.
These builds alone do not establish guest execution.

The font installer binds seven Open Sans/Noto Sans Mono TTF files and their two
complete upstream license files to the canonical libcosmic commit
`5a8bd9482a35ae94c1e54edf77b331c6b970f170`. The nine installed files total
2,150,905 bytes. Five genuine compositor/settings configuration files and
licenses are staged separately. Guest font discovery, text rendering and
configuration behavior still require the actual runtime.

The fixed xkeyboard-config 2.42 archive was also acquired and verified. The
upstream rules generators produced identical output in two separate passes;
30 real evdev/pc105/us assets totaling 353,200 bytes passed the independent
asset consumer. This is the bounded default keyboard closure, not support for
every upstream keyboard layout.

Mesa's missing host Flex and m4 were supplied from verified official Debian
packages in a separate prefix. The actual Flex 2.6.4/m4 1.4.19 pair generated a
scanner, which was compiled with the host compiler and executed with the exact
expected output. The SDK and failed Mesa inputs were unchanged. Mesa's new
attempt binds this tool prefix and its provisioning receipt before and after
the build.

Mesa coordinator v4 subsequently completed all 946 genuine build steps in
985.850 seconds. The frozen producer reports `libraries-compiled`; the
coordinator reports `MESA_LIBRARIES_BUILT_NOT_RUN`, with the SDK and earlier
failed attempt preserved. The stripped real EGL probe is 13,813,792 bytes,
SHA256 `8b14b22a82158cae16a8484d0d8339a5f582cbd82fed639b17955ea0b6c5056f`.
The new `native-comp/native-linux-recipe-v1.json` binds the actual twelve native
inputs, including the seven static link archives. Its source pin, lock and
backend patch series are unchanged. Mesa and the probe have not been executed
in the guest at this point.

## Kernel launch and runtime evidence

The shell and embedded catalog can launch the actual `cosmic-notifications`
and the new `notification-probe`. The notification service receives the real
session bus and Wayland environment; the client receives the session bus.
The semantic host regression compiles production launch code and exercises six
positive cases plus four negative controls. It does not emulate the entire
guest or substitute a fake notification service.

The C client checks the notification bus owner, resolves its process ID through
the real broker, requests server information, sends `Notify`, checks the
nonzero notification ID, sends `CloseNotification`, and waits for the matching
`NotificationClosed` signal with reason 3. It checks reply signatures, signal
sender, owner stability and that the owner is not its own process. A bounded
five-second window permits capturing the actual displayed notification.

`tools/os_cosmic_notifications_runtime.py` uses real QEMU FIFO UART/QMP
channels because host Unix-domain sockets are unavailable in this environment.
It requires actual original build receipts, exact embedded catalog bytes,
configuration, fonts and XKB assets. Its protocol success requires the real
bus, compositor, service and client; a live compositor with a completed
display transfer; successful client exit; and observed release of the started
services' grants and global resource occupancy. QEMU must acknowledge quit and
exit normally, with final UART drain and input revalidation complete.

A completed display transfer is evidence of a bounded rectangle transfer and
flush fence. It is not independent proof of correct notification content or
text. Protocol-only success keeps rendered-notification, text, full-session,
full-OS and filesystem-namespace cleanup acceptance false. Actual frames must
be inspected separately.

The assembled runtime catalog contains 56 actual images/assets totaling
76,460,035 bytes. After the receipt representation fix, original and installed
inputs revalidated and the assembly completed in 81.408 seconds.

The prior successful OS manifests use the same root `Cargo.lock` SHA256
`e6f44c0bd2c1a0d4912dda3f63a3ea2ff2f19e8cdee4ae46c8e5aee12ec7eb71`.
Their actual dependency files identify the original `toolchains/cargo`
registry source paths. That existing cache contains all 52 locked sparse-index
records and the sixteen verified package archives, including the nine
packages used by the prior OS target. A fresh offline copy retains all 519
files, 9,169,480 bytes and original modes/hashes; the original cache is
unchanged. No network acquisition is claimed for this recovery.

Using that separate cache and the same explicitly selected Rust/Clang tools,
formal OS v2 built successfully in 61.268 seconds. Its source identity is
`d9dad46f887efd58e43a7ba0c6cb160edb927a01cd29453a13980734101f47b0`.
The actual kernel ELF SHA256 is
`be6281d18d063d079d18ce030af404fa86893d0c9498050c56d52810249096ef`;
the boot image SHA256 is
`5e6507fb90a61057c2e31ca399dcc68e2d97f75c1b499a32baf033c6deec03a0`.
The selected features are `os-runtime`, `graphics`, `ported`,
`cosmic-desktop` and `full-os`. The first genuine FIFO runtime attempt booted
this image and observed the initial resource baseline, then failed while
parsing an empty initial process list. It ran no D-Bus or COSMIC component.
The complete 39.922-second failed capture remains separate from build success.

The dedicated capture parser now accepts the exact completed empty `posix list`
response while rejecting errors, truncated responses and missing required live
processes. Three focused host tests include the original 21-byte UART response.
The next genuine guest capture ran for 41.120 seconds. The real D-Bus daemon
started as PID 1; the real `dbus-send` client queried `ListNames`, received
`org.freedesktop.DBus` and its unique connection name, and exited zero as PID 2.
This is observed guest D-Bus execution, before either COSMIC executable starts.

That second capture exposed a separate consumer accounting error: it required
the global native arena to have all 64 pages free immediately after the client
exited, although the daemon still owned eight pages. The observed 56 free pages
are consistent with the running daemon. The client's image, heap and thread
ownership had returned to zero. The kernel refreshes the global ledger value
in every process status on each poll; this value must be checked against the
whole active process set and, after all services stop, against the fully free
arena. The failed capture and its exact producer remain preserved; no completed
COSMIC protocol or rendered-notification result is inferred from this failure.

The corrected consumer checks one fresh process list against the actual global
ledger invariant: 64 native arena pages, with eight held per active Runner.
Every reported row must agree on the free count. Individual terminal processes
must still have released their image, heap and threads. Final recovery requires
a new nonempty list containing all launched service/client PIDs, no active
processes and all 64 native pages free, together with the existing global pool
and display checks. Eight focused host tests pass, including the actual v2
UART snapshot and inconsistent, incomplete and leaked-grant counterexamples.
No kernel code, generic parser, image admission limit or AI policy was changed
for this correction.

Capture v3 passed the corrected D-Bus and arena checks and started the real
`cosmic-comp` as PID 3. Its last observed process row was Running, with four
threads and the expected 9,069 image/stack pages. The 42.651-second attempt
then stopped because the inherited generic Console command check matched the
substring `error:` inside a concurrent upstream shortcuts-configuration log.
The `posix list` command itself completed and returned the live bus and
compositor rows. No completed compositor scanout had yet been observed.
The original UART, producer and failure summary are retained before separating
shell/kernel command-error lines from background application log messages.

The actual compiled `cosmic-settings-config` pin is `e37160f`. Its shortcuts
reader logs a missing user `custom` entry and returns an empty custom map, then
extends the already loaded system defaults and returns normally. Both actual
default assets in this catalog match the pinned sources and generated install
output byte for byte. The upstream installers install those defaults, not a
fabricated user `custom` file. Thus this specific diagnostic is a supported
fallback; its presence is retained in the capture instead of changing config
or suppressing application logging to pass the harness.

The dedicated Console now requires this command's complete echo and following
prompt, and searches expected asynchronous markers only after that echo. It
recognizes actual standalone shell errors and the kernel's ELF/USER/EL0
start, pair and kill failure lines, while retaining the inherited fatal-guest
checks. Five focused host tests pass. The original v3 ANSI log and process-list
bytes are replayed unchanged; genuine command failures, stale markers and
incomplete responses still fail. The generic Console and the formal OS inputs
are unchanged.

Capture v4 reached a genuine kernel failure: immediately after compositor
PID 3's launch, the x86 kernel trapped with vector 14 at
`ffff8000001a6f69`. QEMU exited with status 35 without a host force-kill; a
normal QMP quit was not acknowledged. The 46.402-second failed capture is
retained. Its OS, catalog, binaries, QEMU and initial resource identities
match v3 exactly; the bus's scheduling state differed, but that observation
does not identify the cause.

Symbolization against that exact unstripped kernel resolves the faulting
instruction to `memset`'s `rep stosq`. The existing panic handler formats into
only 96 bytes; the UART panic is exactly 96 bytes and truncates the already
supplied CR2 field. Boot-time registers cannot recover the fault address.
An explicit diagnostic capture option therefore retains QEMU's actual
interrupt/exception log without changing the kernel image. This option is off
by default and has a child-process, kernel-enforced 24 MiB file limit; reaching
the limit prevents acceptance. The existing 240-second guest and 96 MiB total
capture budgets are unchanged. The trace may perturb scheduling, so absence
of a fault in a diagnostic attempt cannot invalidate the v4 failure.

Diagnostic capture v5 ran the unchanged OS for 45.212 seconds and retained
14,390,374 bytes of QEMU exception/interrupt output, below the 24 MiB hard
limit. It recorded no page-fault block. Instead the kernel stopped at the
executable-clear path's `make_writable(...).expect(...)`; its error text was
again truncated by the old panic buffer. This is a separate observed failure,
not a recovered CR2 for v4.

The subsequent kernel change expands only bounded fatal diagnostics: a
512-byte panic buffer and complete trap registers. It changes no permission
operation, deadline, model or resource limit. Formal OS v3 built in 63.514
seconds with source SHA256
`baa650fb6256ca969d98d07bf44d6201c9c9042c8f459f2d164e9358b99789f9`.
Capture v6 used this image without heavy QEMU tracing. It ran for 83.165 seconds
and failed the unchanged 45-second first-scanout gate. The compositor remained
Running with five threads and 1,622 syscalls, but display submissions and
completions remained zero. No kernel panic was observed; QMP quit was
acknowledged and QEMU exited zero without force. This does not invalidate the
earlier kernel failures or establish a working renderer.

Two independent source reviews identify a definite permission-transition
failure path. Sealing changes direct-map pages to read-only before TLB
synchronization and records the sealed bit only after that synchronization
succeeds. A failed synchronization can therefore leave a protected page
unrecorded; the former writable-restoration path skips unrecorded pages.
Unsealing also clears the stable bit before completing its synchronization.
The source defect is established; its causal relationship to the particular
v4 fault remains unproven without that fault's CR2.

The applied fix uses `StableWritable`, `Transition`, and `StableSealed` for
each physical page. It marks the complete range pending before changing PTEs;
pending pages reject new aliases but allow removal. Sealing commits its stable
state only after the actual fence succeeds. Unsealing preserves both original
fences and commits writable state only after both complete. Retrying a pending
range repeats the complete protocol. `publish_code` checks every page before
its stable fast path, and `make_writable` restores pending as well as sealed
pages. Existing alias locking, PTE operations, IPI/ACK handling and the 100 ms
deadline remain unchanged. The additional phase bit occupies 32 KiB of boot
metadata; no user or AI resource bound is changed.

Nine helper failure-injection cases and four cases extracting the actual
production wrappers and unchanged `ExecMemory::clear` passed under Rust 1.95.
The portable `tests/host/test_code_permissions.py` subsequently compiled the
current checkout and reran its four actual-method cases successfully in 1.464
seconds. Hardware and ledger objects in these host tests are explicit fixtures,
not guest TLB or production-ledger proof. On a restoration failure, production
cleanup still terminates before zeroing or release; its already-taken lease
Option is empty, and backing remains charged. The frozen `ExecMemory` and all
four reviewed loader-contract source hashes remain unchanged.

Formal OS v4 contains the reviewed permission fix and saved-context observation
fields. It built in 56.837 seconds with source SHA256
`aa3b5f5b9d213959ff2aabb9221c3d5f55e1e8ee1fb71cd1697d6cbefdc3b97c`.
Capture v7 ran for 85.598 seconds and still failed the original first-scanout
gate. QMP quit was acknowledged, QEMU exited zero without force, and no kernel
panic was observed. This one run does not prove the historical fault's cause
or establish notification execution.

Its 126 process snapshots contain 25 different saved PCs. Matching their
addresses against the exact real compositor ELF identifies regex AST teardown,
literal-trie construction, dense DFA construction and determinization, as well
as `__mmap` and `__munmap`. These are saved contexts after all worker CPUs return,
not live stack samples. The ELF has a symbol table but no DWARF line information;
the evidence establishes function intervals and offsets, not exact source
lines or the particular rule being processed. The saved syscall operation
number may persist during later computation, so snapshot frequencies are not
syscall counts.

The retained upstream `TilingExceptions` implementation compiles each appid
and title separately for validation, discards those compiled objects, and then
compiles two RegexSets. The actual default asset expands to 38 paired rules,
requiring 76 individual constructions plus two set constructions if all rules
validate. The 76 strings contain 49 distinct values. This identifies duplicate
work but does not measure its share of guest startup time. The x86 runtime also
rebuilds and retires the full address space at every user entry, including
syscall returns. A separate diagnostic records cumulative HPET wall time for
both BSP and real SMP preparation/retirement paths, without changing scheduling,
fences, billing, resource limits or the first-frame gate. Formal OS v5 built in
75.132 seconds with source SHA256
`6df0d77531323cfc752a5d63e1ef8eacf2e9c8b13a71f8aa24db6b2bfb2cef55`;
capture v8 subsequently ran for 104.251 seconds and failed the unchanged
first-scanout gate. QMP quit was acknowledged and QEMU exited zero without
force. The 124 compositor snapshots start after the first construction, which
took 2.408 seconds, and end at 2,010 construction attempts. Between the first
and last snapshots, 2,009 more attempts accumulated 23.922 seconds of preparation
and 5.937 seconds of retirement wall time. The last compositor status remained
Running with five threads; display submissions and completions were zero.
These measured publication costs support optimizing the page-table mechanism
before changing upstream window-rule behavior. Counts include cancelled and
failed publication attempts, not only successful user entries. Preparation is
inclusive of `begin` retirement if a previous root remains, so these fields
must not be described as universally disjoint CPU-time billing.

The next tested change batches page-table publication while preserving the
complete retirement boundary. A batch reuses a leaf-table lookup only within
the same 2 MiB region, retains every page's address, permission, phase, conflict
and alias-count checks, and publishes the original epoch increment for exactly
the successful prefix. A non-Send guard holds the existing alias lock for the
batch, with actual CPU ownership checked by the runtime. RX sealing finishes
before the batch acquires that lock. Retirement still visits every mapping;
invalid tables or failed alias decrements now terminate before backing can be
cleared or released. Actual PTE fences, AI policy and all resource limits are
unchanged.

Twelve focused host cases passed using the actual runtime-enabled architecture
code and exact production runtime/staging functions. The only platform switch
in the generated architecture source is the documented `none` to `linux` cfg
adaptation; CPU identity, physical backing and RX/TLB operations are explicit
fixtures. The portable `tests/host/test_page_map_batch.py` reran those same
twelve cases from the current checkout successfully in 1.488 seconds. These
are twelve cases exercised twice, not twenty-four distinct cases. Two
independent source reviews and an independent compiled-witness review found
no remaining material defect in those tested boundaries.

Formal OS v6 built in 66.114 seconds with source SHA256
`19dccf7324ecbb12e941429748692c9ccb4ed6eeb479810f11a7acaa4acc880a`.
Capture v9 then ran for 90.671 seconds and still failed the original first-frame
gate. Normal QMP quit and zero exit succeeded. The compositor remained Running,
with 1,764 syscalls, five threads and 2,144 construction attempts; display
submissions remained zero. Its final cumulative preparation/retirement fields
were 23.406 and 9.765 seconds. This run does not establish an overall performance
improvement: preparation decreased while retirement increased, and the two
runs reached different amounts of application work. The preserved v8/v9
timing and compiled kernels are used to inspect the actual hot call paths
before making a further change.

The existing formal builder also supports an explicit `release` profile.
OS v7 used that profile with the exact same source SHA, component inputs,
features, compiler, CPU count and RAM as OS v6, and built in 68.153 seconds.
Its manifest records the actual `--release` command. This is a distinct
compiler-profile observation, not a controlled continuation of the dev
timing comparison. Actual disassembly confirms that release inlines the GS
CPU-slot read and phase checks while retaining owner validation; it does not
by itself prove runtime performance or graphics initialization.

Capture v10 stopped before starting QEMU after 33.050 seconds: the consumer
searched the entire source cache and found both genuine debug and release
generated catalogs. Both were identical, but each belonged to a different
build profile. The corrected selector now uses the verified target/profile
and requires exactly one kernel catalog inside that profile's build directory.
Missing, duplicate or linked paths still fail; there is no fallback to another
profile. All later catalog bytes, assets and actual read-only kernel embedding
checks remain unchanged. Five focused host cases pass, and the old function
still reproduces its original failure against the unchanged real cache.

Capture v11 then genuinely booted the release OS and launched D-Bus and the
compositor. It stopped after 72.147 seconds because an incomplete upstream
configuration log directly preceded the complete `posix list` echo. The
response contains both genuine process rows and the following prompt, but the
consumer incorrectly required the echo to begin a line. Its final command
span, starting at UART byte 151827, is preserved byte for byte. During the
30-second command wait the compositor continued into actual EGL initialization
and emitted DRI2 initialization errors followed by a Smithay display warning.
Those later messages are not evidence of a completed scanout. No final display
snapshot was requested during that wait, so this run does not establish a
first-frame latency or successful rendering. Normal QMP quit and zero exit
succeeded; the failed command recognition and original capture remain intact.

The retained Smithay and Mesa sources narrow the meaning of those messages.
In Smithay's `src/backend/egl/display.rs`, `eglInitialize` must return success
and display-extension discovery must succeed before `get_dmabuf_formats` can
emit the observed warning. Its missing-import-extension branch returns two
empty format sets successfully. Mesa's `eglInitialize` permits an initial
driver attempt, an optional Zink retry and then software fallback inside one
call; failed intermediate surfaceless attempts emit the observed DRI2 error.
Thus v11 reached successful EGL initialization and extension discovery. The
later OpenGL ES API binding, context, renderer, shaders, buffer and scanout
remain unverified by this log sequence.

The fresh-echo correction removes only the line-start requirement from the
complete literal command plus newline. It still starts at this command's fresh
UART offset, requires the later anchored shell prompt, and checks expected
results and errors within the resulting response. Replaying the complete
2,543-byte original command span now recognizes both real process rows; the
five existing command-boundary fixtures also pass. The portable suite now
retains that complete, checksum-bound span and rejects the same response when
its echo is changed to a different command. All six command-boundary tests
passed in 0.141 seconds. The live runtime producer
used next has SHA-256
`2bc81de5c5d8f458e721679b7ea9bf845a04bb20b22e995ec4efe5a80466ed00`.

Capture v12 used the unchanged release OS and corrected command reader. It
stopped after 43.246 seconds because the required compositor had exited with
normalized `Fault`/139 before any recorded syscall, preemption or successful
user slice. Its saved PC still equaled the ELF entry, `0x1de4000`. One address
space preparation attempt took 920,672,860 ns; retirement accumulated
8,960,380 ns. Image, heap and thread ownership returned to zero, while the
still-running real bus retained its eight native pages (56 globally free).
Normal QMP quit was acknowledged and QEMU exited zero without force.

That result is neither a hardware page-fault diagnosis nor proof of a TLB
timeout. The runner also maps preparation and entry-mechanism errors to
`Fault`/139, and currently discards their original architectural error variants.
The next diagnostic must distinguish those paths, keep AP errors in the owned
context until all workers drain, and retain the actual permission fences and
execution policy. No notification service or non-boot compositor frame was
observed in v12.

The diagnostic change preserves original architectural error variants at
address-space creation, mapping and code publication failures. A resume error
is stored in its exclusively owned `Context`; CPU0 consumes it only after the
existing drain and root-retirement boundary. The normalized error, exit and AI
accounting remain unchanged. The fixed-size log is formatted only on failure;
the mapping loop does not track a diagnostic value on every successful page.
The portable permission integration suite still passes all four actual-method
Rust cases through its Python driver (0.878 seconds).

OS v8, with only those additional diagnostics, built in 87.636 seconds from
source SHA `11b40d4ade91127578583726112d3e9492da2bcc8a1bc1320301cd39ab86449e`.
Capture v13 then ran for 96.170 seconds and failed the unchanged first-frame
gate. No entry-mechanism or hardware-fault diagnostic was emitted. The final
compositor snapshot remained Running with 2,943 syscalls, seven threads
(peak eight), 4,030 address-space preparations and 6,051 heap pages. Its
cumulative preparation and retirement times were 19.096 and 5.516 seconds.
QMP quit was acknowledged and QEMU exited zero without force.

The final saved PC, `0x2fc5bfd`, lies uniquely inside the genuine compositor
ELF's `nir_legacy_trivialize` symbol at offset `+0x68d`. Retained Mesa sources
place that routine in shader IR/register conversion on the `nir_to_tgsi` path
used by softpipe shader creation. Recent samples also reached GLES renderer
and shader-linking functions. This is evidence of actual Mesa shader
initialization work, not a completed renderer, specific shader identity or
proof of an infinite loop. No buffer submission or notification launch was
observed. The intermittent v12 entry failure was not reproduced or assigned a
cause by this run.

The next change groups only adjacent executable staging entries whose physical
frames are consecutive. A hole, non-executable entry, physical discontinuity
or 512-entry table boundary ends the group. Each group calls the existing
whole-range permission transaction before the mapping batch acquires its
alias gate. Per-page alias checks, Transition states, actual PTE writes, real
TLB synchronization, its 100 ms limit and all recovery/retirement checks stay
in place. The original comparator and all failed captures are retained.

Seventeen portable Rust integration cases passed in 1.704 seconds. They
extract the real staging publication, wrappers, runtime permission backend
and transaction helper, using explicit CPU/PTE/TLB fixtures. The compositor's
4,931-page contiguous RX layout exercises eleven groups and 4,931 PTE writes;
other cases cover mixed ranges, physical gaps, writable aliases, failures in
later groups, partial PTE changes, failed fences and failed recovery before
zero eligibility. These fixtures do not claim real AP synchronization or
actual guest reclamation.

OS v9 built in 55.632 seconds from source SHA
`d73336cbfce69621a8392cbc8936e4b96fae023e96ed84786dfd863dab64cf1e`.
Capture v14 ran for 92.520 seconds and still failed the original first-frame
gate, with normal QMP quit/zero exit and no entry or hardware-fault diagnostic.
Its first preparation attempt recorded 18,419,300 ns, compared with
851,846,830 ns in v13. These are single-run observations, not a controlled
latency benchmark or a proven cause/fix for v12. At the final snapshot the
compositor remained Running with 2,242 syscalls, seven threads and 3,079
preparations; cumulative preparation/retirement were 19.034/6.015 seconds.
No overall performance gain or completed compositor frame is claimed.

Three compiler inline attributes were then added to the remaining measured
mapping call boundaries. Removing those three attributes restores both source
files byte for byte; no function body, guard, fence, timeout or AI policy
changed. OS v10 built in 70.825 seconds from source SHA
`caebe804a1ef3e3b28e7f7782b2935760f85611a45f945b032ec67389c55d2d8`.
Actual v9/v10 disassembly verifies the intended code generation: the two
private validation/wrapper calls disappear from `PageTable::publish`, and the
runtime batch entry contains the checked alias core instead of tail-jumping
to it. CPU owner, phase and the three checked counters remain. The containing
functions grow from 1,996 to 2,393 bytes and 64 to 374 bytes respectively;
code-size effects are retained rather than assuming an automatic speedup.

All seventeen integration cases passed again against the exact current
checkout (2.102 seconds inside the test driver). Capture v15 still failed the
original first-frame gate after 87.771 seconds, with normal QMP quit/zero exit
and no entry or hardware-fault diagnostic. The compositor remained Running:
3,701 syscalls, 4,874 preparations, 6,391 heap pages and cumulative
preparation/retirement of 18.263/5.880 seconds. These different workloads and
wall-time samples do not constitute a controlled speedup measurement.
Its last PC, `0x2d6fe16`, is the entry of the actual Mesa
`_mesa_printed_blake3_equal` helper. No call stack was captured, so neither a
particular caller/shader nor renderer completion follows from that sample.

The next diagnostic will preserve the failed 45-second acceptance result
while explicitly observing later startup under the original global bounds.
A later real frame or protocol observation must not upgrade that acceptance
result to PASS. The purpose is to expose any remaining functional failure
beyond expensive initialization, using the same genuine OS and components.

## Preserved failures and corrections

| Attempt | Actual result | Treatment |
| --- | --- | --- |
| New SDK foundation | XOrg built; old zlib URL returned 404 | Preserve the failed report; recover the identical pinned archive separately. |
| Compositor preparation v1 | Genuine dependencies acquired; old dependency checker rejected a Git submodule | Preserve the exact producer snapshot; add recursive canonical verification. |
| Compositor preparation v2 | The same locked Git branch used different percent encoding in metadata | Preserve the exact producer snapshot; normalize only the documented query encoding. |
| Compositor preparation v3 | 468 packages verified offline | Preparation only; no ELF or runtime claim. |
| Mesa coordinators v1/v2 | Fixed Linux UAPI downloads were rate limited | Preserve reports and partial verified sources; honor retry delays. |
| Mesa coordinator v3 | Remaining fixed sources recovered; configuration found missing host Flex | Preserve its failed report and setup log; acquire a genuine host tool separately. |
| Mesa coordinator v4 | All 946 steps and the real EGL probe link completed | Libraries built; no guest claim. |
| Notification static build v1 | `xkbcommon-dl` could not find native static `xkbcommon` while producing its Rust library | Preserve its report, Cargo log, source, target and all 13 producer plus six policy/patch/recipe/profile snapshots before repair. |
| Catalog assembly attempt v1 | Client receipt consumer compared a JSON array with the target profile's Python tuple | Preserve the failed log and exact consumer/coordinator sources; correct JSON representation in the consumer without rewriting the original client receipt or ELF. |
| Formal OS build v1 | Default Cargo home lacked the `sha2` index; build stopped before target compilation | Preserve the 3.232-second failure and use a separately recovered existing OS cache. |
| OS dependency acquisition v1 | Proxy CONNECT returned 403 and the execution transport disconnected | Preserve actual logs and the 177-byte incomplete cache; Cargo exit status and group termination were not observed, so no completed acquisition is claimed. |
| Notification runtime capture v1 | OS booted; the nonempty-only process parser rejected the genuinely empty initial process table | Preserve the actual UART/QMP/frame evidence; QMP quit was acknowledged and QEMU exited zero without force. No component process had launched. |
| Notification runtime capture v2 | Real daemon and `dbus-send` completed `ListNames`; the consumer incorrectly required all 64 global native pages free while the daemon still owned eight | Preserve the complete 41.120-second failed capture and exact producer. QMP quit was acknowledged and QEMU exited zero without force. Per-process release and final global release require separate checks. |
| Notification runtime capture v3 | Real compositor PID 3 was Running with four threads; a background upstream configuration log containing `error:` triggered the inherited shell-command check | Preserve the complete 42.651-second failure and exact producer. The observed shell command completed, but no scanout had yet completed. QMP quit was acknowledged and QEMU exited zero without force. |
| Notification runtime capture v4 | Genuine x86 kernel page fault in `memset` immediately after real compositor launch | Preserve the complete 46.402-second failed capture and exact OS/producer. QEMU exited 35 without force; normal quit was not acknowledged. Obtain actual fault registers before changing kernel behavior. |
| Notification runtime capture v5 diagnostic | Same OS; executable-clear restoration assertion failed; no page-fault block in 14.39 MB of actual exception trace | Preserve the distinct 45.212-second failure. QEMU exited 35; the diagnostic file limit was not reached. Do not assign this run's register values to v4. |
| Notification runtime capture v6 diagnostic kernel | Compositor remained alive but completed no display submission within 45 seconds | Preserve the 83.165-second capture and diagnostic-only OS. Normal QMP quit/exit succeeded; no rendering or notification protocol acceptance. |
| Notification runtime capture v7 permission transaction | Real compositor executed regex construction but completed no display submission within 45 seconds | Preserve the 85.598-second capture, tested fix, exact OS and saved-PC symbolization. Normal QMP quit/exit succeeded; no notification or complete-session claim. |
| Notification runtime capture v8 page-table timing | Compositor preparation and retirement accumulated 23.922 s and 5.937 s between the first and last snapshots; no first scanout | Preserve the 104.251-second failure, read-only timing source and 124 snapshots. QMP quit/exit succeeded; optimize measured publication overhead without widening acceptance. |
| Notification runtime capture v9 page batching | No first scanout; final cumulative preparation 23.406 s and retirement 9.765 s across 2,144 attempts | Preserve the 90.671-second failure and actual compiled kernel. QMP quit/exit succeeded; no overall speedup, rendering or full-session acceptance is claimed. |
| Notification runtime capture v10 release preflight | Two genuine profile catalogs were mistaken for an ambiguous catalog within one build | Preserve the 33.050-second failure and zero-byte UART; QEMU was not started. Select the exact verified target/profile without changing later byte checks. |
| Notification runtime capture v11 release | A fresh, complete command echo followed a partial application log instead of starting a line | Preserve the 72.147-second failure and exact 2,543-byte command span. Actual command response and later EGL logs exist; rendering during the parser wait was not observed. |
| Notification runtime capture v12 release | The compositor exited with normalized `Fault`/139 before any recorded syscall or successful user slice | Preserve the 43.246-second failure. Image, heap and threads were reclaimed; QMP quit and zero exit succeeded. Preserve the original preparation/entry error before assigning a cause. |
| Notification runtime capture v13 entry diagnostics | Compositor reached real Mesa shader IR conversion but completed no display submission within the original gate | Preserve the 96.170-second failure and final saved-PC source analysis. No entry or hardware-fault diagnostic was emitted; normal QMP quit/zero exit succeeded. |
| Notification runtime capture v14 RX ranges | First preparation recorded 18.419 ms, but the compositor still completed no display submission within the original gate | Preserve the 92.520-second failure and all original limits. No entry/fault diagnostic; normal QMP quit/zero exit. The first-attempt observation does not establish overall performance or explain v12. |
| Notification runtime capture v15 inline boundaries | Actual code generation removed the reviewed call boundaries, but no display submission completed within the original gate | Preserve the 87.771-second failure. All 17 integration cases passed on the current checkout; normal QMP quit/zero exit and no entry/fault diagnostic. No first frame or notification acceptance. |

The notification failure occurred before final ELF linking. Passing absolute
archive names to the final linker does not make them discoverable when rustc
bundles a static archive into an intermediate Rust library. The correction
stages only the seven already hash-bound native archives alongside the existing
`libunwind.a` in the generated native search directory, and verifies that exact
set at production and consumption boundaries. It does not change the original
source patches, target SDK or retained upstream feature graph.

A subsequent actual Rust 1.95 precheck reproduced the missing-static-library
failure with an empty native search directory. With the corrected staging,
rustc produced a real target rlib; LLVM ar and object-byte comparison confirmed
that all 88 native ELF objects from the eight bound archives were included.
The precheck completed in 2.895 seconds, with original and generated inputs
unchanged. Its report remains a compiler precheck rather than a notification
executable or a guest result. Its exact producer and script snapshots are
retained separately before the additional publication cleanup repair.

The publication repair uses a verified temporary candidate and atomic rename.
Late archive, source, producer, evidence, inspection or report-write failure
withdraws the published ELF and clears `target_linked`, while retaining raw
target output and diagnostics. A successful full build requires all three
logs; metadata-only requires both metadata logs. Twenty focused host lifecycle
fixtures pass, including partial copy, missing logs and interruption cases;
independent review found no remaining material issue in this boundary.

The real notification rebuild v2 then completed successfully in 1,526.9
seconds. Cargo compiled 462 packages and finished the release target; the
producer revalidated its original sources, all generated native inputs and
the complete producer closure before publishing. The actual x86_64 musl ELF
is 29,912,232 bytes, with SHA256
`b3ba8dfecd8f8b0f4a07e58afdc908768d7702c3560d7c959d448b08125caec7`.
Its FullOs parser result contains 5,948 image-load pages; with the 512-page
stack the request is 6,460 pages. The successful receipt is
`artifacts/v017-cosmic-runtime-20261116/notifications-static-build-v2/build-report.json`.
This is a genuinely linked service, with `notifications_verified=false`
until its separate guest protocol test succeeds. The original v1 failure and
all compiler warnings remain available.

An independent invocation of the formal installer consumer revalidated that
successful build. The raw and published files have identical bytes, and an
independent program-header calculation confirms the same 6,460-page total.
There is no interpreter, dynamic segment or writable/executable LOAD segment.
All 493 dependency records, the actual SDK and Rust archives, three logs and
eight generated native archives match their build identities. This check did
not execute the target program.

## Full-session resource and source boundary

The FullOs pipe pool has 32 pairs, with 30 admitted under the current policy.
The ordinary profile still has eight pairs. A native session child initially
uses three pairs; actual occupancy depends on endpoint closure and reaping.
The eight physical Runner slots currently admit seven simultaneous processes.
The manager, compositor, bus, settings daemon, notifications and panel already
form a six-process lower bound before helper processes or other desktop apps.
The exact full-session peak must be measured before changing admission policy.

Likewise, the structural ELF bound of 16,384 pages includes a 512-page stack;
the current model admits at most 16,256 pages from a completely free image
backing. Static parser acceptance alone does not establish a runtime grant.
No model weights, business hot paths, CPU-domain relationships or admission
reserves are changed merely to turn a failed workload into an accepted one.

The first cached settings daemon and panel were real full source trees, but
their commits differed from the old native recipes. Subsequent bounded source
acquisition recovered and canonically verified the exact session `8093b59`,
settings-daemon `9e4ae69`, panel `3ce6ce1` and launch-pad `5b516ee` commits.
Their full identities and file inventories are recorded in
`artifacts/v017-cosmic-runtime-20261116/session-source-acquisition-v1`.
Source recovery does not establish that their feature-selected Cargo dependency
closures are available, built or running. Full session integration still
requires actual manager supervision and FD handoff, the real settings daemon
and panel, further application images, and runtime accounting.

## Next genuine services

The independent session Linux-host entry fixes the recovered session and
launch-pad commits, applies the original NativeChild patch byte for byte, and
uses this SDK's actual five core inputs. A real local source export produces
the expected 46-file tree. The producer and read-only consumer have 25 passing
host fixtures; the shared registry source verifier has 13. These results cover
canonical sources, checksum-bound registry extraction, metadata relocation and
publication rollback. Actual offline Cargo metadata was attempted below;
target compilation and session execution remain pending. A read-only inventory of the
effective session lock contains 176 packages: 173 registry, one Git and two
local packages. The current cache has 157 of the checksum-pinned registry
archives; 16 are missing. This inventory is not feature-selected Cargo
resolution. A separate bounded acquisition step will use a fresh cache and
preserve the currently used runtime cache.

The first actual session metadata attempt ran for 18.813 seconds and exited
with Cargo status 101: the offline index had no matching
`freedesktop-desktop-entry`. Its complete source export, stderr and `FAILED`
receipt remain in `session-linux-v1-metadata-offline-v1`; no target ELF was
published. This is the concrete input for the separate bounded acquisition
step, not an inferred success from the inventory.

The settings-daemon Linux entry is also implemented against its exact
recovered pin and the original native patch. Its canonical export contains
97 files. All eight real SDK inputs are bound, and static archives are staged
for rustc as well as final linking. Seventeen focused host fixtures pass,
including source/cache drift, evidence omissions and publication rollback;
independent review found no unresolved material defect. Actual Cargo metadata
was attempted below; compilation and guest execution remain pending. The existing explicit
`NotSupported` boundary for volume and backlight operations remains present;
no substitute audio or system service is introduced. Both new service paths
leave the frozen notification and compositor producers unchanged.

The settings effective lock contains 734 packages across all retained
workspace/platform capabilities: 689 registry, 34 Git packages from ten
fixed source/commit identities, and eleven local packages. Read-only checking
verified 535 checksum-bound registry archives and their full extracted trees;
153 archives are missing. One further archive, `windows` 0.62.2, has the
correct checksum but exceeds the verifier's existing extraction byte limit,
so its extracted contents are not claimed as verified. All ten fixed Git
sources are available and canonical. These whole-lock observations do not
identify the feature-selected Linux dependency gap; actual target-filtered
metadata is still required.

The first real settings metadata attempt subsequently ran for 12.589 seconds
and failed with Cargo status 101 because the offline index lacked `zlink`,
required while resolving the retained `cosmic-settings-audio-client`
workspace member. The failure is preserved in `settings-native-metadata-v1`.
This does not establish that the native daemon enables its audio service;
the workspace is retained and its missing dependency must be recovered rather
than omitted to make metadata appear successful.

## Exact panel integration gap

Read-only inspection of the recovered panel commit verifies all 144 original
files. Its sole binary is `cosmic-panel`, built from package
`cosmic-panel-bin` 1.10.0. The panel is itself a nested Wayland compositor;
its first layer configure creates a Wayland EGL window surface. The current
genuine Mesa build explicitly provides only surfaceless EGL, so adding an ELF
to the catalog cannot supply that missing presentation path. A separate real
Wayland EGL platform or a GLES renderbuffer/readback-to-`wl_shm` adapter must
preserve layout, popup, scale, input and buffer-release behavior.

Panel also needs its own static client/server/EGL bindings and native child
launcher integration. Its launch-pad pin matches the reviewed session pin,
but patching one executable does not alter the library inside another. Its
Smithay commit is `0ff00983b6007257a7a161a4fe8b14a778e2ac8f`, distinct from the
successfully built compositor's dependency. Exact panel metadata and linking
remain pending.

The real startup chain passes session-owned `PANEL_NOTIFICATIONS_FD` and
`DAEMON_NOTIFICATIONS_FD` sockets, then passes a notification FD and nested
`WAYLAND_SOCKET` to the notification applet. The simple notification protocol
test does not establish that three-level handoff. The default Panel and Dock
configure thirteen and five applet instances respectively. Eighteen applet
processes exceed the current eight physical process slots even before the
other services; their three initial stdio pipes each also exceed the current
32-pair FullOs pool. Full default-desktop delivery therefore requires genuine
applet binaries/assets and a separate measured capacity and reclamation
change. No pool, model or limit is enlarged in this continuation solely on
the basis of that static inventory.
