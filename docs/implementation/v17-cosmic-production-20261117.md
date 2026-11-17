# Genuine COSMIC production-profile continuation, 2026-11-17

**Current outcome: complete COSMIC is not accepted.** The retained production
Mesa v2 preserves libc++ FAST hardening. The reviewed alias-retirement change
and a complete upstream Compose data installation are applied and built, but
the latest genuine runtime capture, v21, still fails the original first-frame
deadline and notification registration window. Its partial scanout is not a
desktop/session success. This document separates those results from the
successful native builds and focused host validation.

This work starts at local commit
`3dc273742215a9a932f79c1b6da50414b7a0ad70`. The previous sixteen runtime
captures, ten OS coordinators and the old successful component closures remain
under `artifacts/v017-cosmic-runtime-20261116`. New outputs use the separate
`artifacts/v017-cosmic-runtime-20261117` directory and the existing shared native
lease. No remote publication is included.

The target remains genuine upstream COSMIC execution on CyxiaOS. A03 remains
cancelled, x86 is the primary target, and ARM remains a compatibility target.
The attached prototype document describes the older AArch64 configuration;
it does not supersede these later project decisions. Compilation, executable
admission, display completion, notification protocol, visible content and full
session acceptance remain separate claims.

The current production candidate is **v2**, which explicitly preserves the
original libc++ FAST hardening. Production-profile v1 and capture v17 are
retained diagnostic evidence: actual command review found that v1 also lost
that C++ hardening. The v1 results below must be read with that qualification.

## Concrete production configuration finding

The retained Mesa 26.2.3 build uses `buildtype=minsize`, `debug=false`,
`optimization=s` and `b_ndebug=if-release`. Its actual compilation database has
889 commands: 821 C, 64 C++ and four assembly inputs. All use `-Oz` and
`-DMESA_DEBUG=0`; none defines `NDEBUG`.

The actual Mesa build logic and installed Meson 1.8.3 implementation do not
treat `minsize` as release for `if-release`. The `debug` option and `MESA_DEBUG`
do not substitute for the `NDEBUG` preprocessor definition. The retained
`nir_validate.c` implements internal compiler-IR validation under
`#ifndef NDEBUG`; successful NIR passes can allocate validation structures and
traverse the shader again. This is a concrete additional-work finding, not a
measurement of its share of startup time. Capture v16's last saved PC in
`nir_algebraic_impl` does not by itself identify a particular shader, caller,
validation cost or infinite loop.

The new versioned producer `tools/build_mesa_production_v1.py` preserves the
original `tools/build_mesa.py` byte for byte and explicitly adds
`-Db_ndebug=true` to the existing options. It retains `minsize/-Oz`, all existing
platform and feature selections, source pins, patches, genuine shader variants
and ordinary optimizer passes. It changes Mesa's internal assertions and debug
logic globally, not only one NIR validator. Ordinary checked GLSL compilation
errors and compile/link status handling remain present in the reviewed source.
Kernel/Rust checks, AI policy, resource grants and runtime acceptance limits are
unchanged by this profile selection.

Some private layouts, including ralloc metadata, depend on `NDEBUG`. Therefore
the implementation requires a complete independent Mesa compilation and a new
compositor link; old and new Mesa objects cannot be mixed. The old diagnostic
build and its failed guest observations remain reproducible.

## Actual configuration checks and host validation

After genuine Meson setup, the producer reads the generated build-options and
compile-command files. Before compilation it requires the exact typed feature
options, `minsize/-Oz`, explicit `b_ndebug=true`, real target compiler paths,
source/output correspondence and unambiguous `-DNDEBUG`/`-DMESA_DEBUG=0` flags.
Conflicting macros, hidden response-file overrides, unexpected optimizations,
missing commands, malformed metadata and linked metadata paths are rejected.
The same configuration and file identities are rechecked after compilation.
A later failure retains the actual successful precompile configuration record.

Six focused pure-host tests passed on the applied repository files in 0.037
seconds. They exercise actual validation/build orchestration with explicit
host fixtures and mocked native boundaries; no target execution is implied.
A separate labelled replay of the old real metadata rejects its `if-release`
configuration. Only a temporary fixture with relocated paths and explicit
production flags is accepted. That replay demonstrates parser compatibility,
not a successful new compilation.

The applied producer SHA is
`6561e39d22e2c629b0bf94ce325962ed5bf77e108fc116353a683331896ab783`;
the unchanged original builder SHA is
`29c7bf29500b053df3e4a3f33ccf25caef8ddea413d3d1e5f30bdcff219fab3f`.

## Separate SDK and preserved first failure

A fresh SDK was assembled in 4.911 seconds. Its non-Mesa sysroot, licenses and
cached UAPI inputs were copied and checked against the original identities;
actual compiler drivers were regenerated for the new prefix. The genuine
pinned host Python generator environment was copied and its files, links and
base interpreter were checked. No original SDK or successful Mesa output was
rewritten.

Production coordinator v1 failed before target compilation because the copied
top-level UAPI cache was incomplete: `include/uapi/linux/types.h` was the first
missing file. Its failed producer report, timestamped logs and coordinator
report are preserved. The complete pinned source set still existed in the
old Mesa work directory. A separate local recovery checked all 25 manifest
files/provenance inputs and copied six missing files with their required
SHA-256 identities; no network fetch or source substitution was used.

Coordinator v2 uses `--resume` only for the already verified prepared source.
It checks that no Mesa build directory or target object exists before starting
the complete build. The same jobs=2, 3600-second deadline, 3 GiB work budget
and 1 GiB free-space reserve remain enforced. Actual source/UAPI trees,
new SDK drivers/generators, native tools and the Meson/Ninja environment are
checked against recorded identities. Old producers, old SDK contents, original
Mesa outputs and the first failed report remain bound separately.

## Actual production Mesa completion

Coordinator v2 completed all 946 build steps in 416.461 seconds and returned
`MESA_PRODUCTION_LIBRARIES_BUILT_NOT_RUN`. The actual generated configuration
contains 889 compile commands (821 C, 64 C++, four assembly), each with the
required unambiguous production flags. Its precompile and postcompile
configuration records agree. The coordinator independently confirmed the
source/UAPI identities, original inputs and fresh target object set.

The completion report SHA is
`fb905025d16e76602068ec3be6e355ac9f6b8dcd06e0c8ccdc356b18edaf1475`;
the immutable/latest producer report SHA is
`2b64d558e5c6ff8463675ab4e9518e8e0e956fff2a8e84ced8ffdc84988d4170`.
The resulting EGL probe has SHA
`846a5bd6aa52641134cbed9042a2485f91e9404098a1fb75f8262de33a06a1fb`.
The probe has not been executed in a guest. These are compilation and identity
results; neither their elapsed time nor the smaller executable establishes a
guest startup improvement.

A new compositor recipe is recorded under the artifact directory
`compositor-production-recipe-v1`, preserving the original recipe in `ports`.
Only the four declared Mesa archive identities may change; all eight other
native inputs and every source, feature, patch, link-order and resource field
must remain identical. The actual C++ runtime archive is unchanged, while
the EGL, Gallium and GLES archives differ. The unchanged genuine compositor
producer uses a separately cloned Cargo cache and a fresh build output; its
original static consumer will validate the resulting executable. The copied
cache's growth remains part of the original 3 GiB build budget.

## Actual genuine compositor completion

The unchanged producer compiled all 422 packages offline and completed the
release target in 10 minutes 28 seconds. The coordinator, including cache
preservation and the original independent consumer, completed in 752.487
seconds with status
`GENUINE_PRODUCTION_COMPOSITOR_COMPILED_REVALIDATED_NOT_RUN`.

The real executable is 41,136,216 bytes, SHA
`c10f8c5bebacafa34ce9e2c1be8eeba22401fd91b0c5f1c4bf0adf337437a3e5`.
The actual build occupies 1,448,196,732 bytes; the independent cache has zero
measured growth. All original source, patch, dependency, host tool and resource
contracts passed the coordinator checks. Both the old successful compositor
closure and the new genuine executable passed the unchanged consumer. Original
cache contents and the completed production Mesa closure remained unchanged.

The actual build report SHA is
`d82ac1e0cf37bbebff2c6e62966fbcdff9eb6243950b4ac5b103db6840f47866`;
the completed coordinator report SHA is
`81263b580068032cffced4646d1daa2fcc368272b6df0187e23a5f9d7455fd9b`.
These results establish a real new compositor binary, not a guest frame.

## Hardening finding and production v2 correction

Independent review of the actual 889 old/new compile commands found a second
effect of Meson's `b_ndebug=true`: its Clang C++ assertion helper returns
`-DNDEBUG` before adding the former libc++ FAST definition. All 64 original
Mesa C++ commands defined
`_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST`; none of the 64 production-v1
C++ commands did. The actual libc++ configuration defaults to 2 (`NONE`),
while `FAST` is 4. Actual headers show that FAST retains input-range and
element-access checks independently of `NDEBUG`. Therefore v1 changed runtime
hardening as well as Mesa internal debug validation. Its guest observations
cannot isolate NIR validation overhead, and v1 is not the retained production
recommendation.

`tools/build_mesa_production_v2.py` is a separate complete producer. It adds
the original symbolic FAST definition only to Mesa `cpp_args`; the C and
assembly arguments and the separate C++ support-runtime build remain unchanged.
Before and after real compilation, the actual configuration requires all 64
native x86 C++ commands to contain exactly one unambiguous FAST definition.
Missing, duplicate, cancelled, NONE/numeric/default or legacy assertion-mode
overrides are rejected; C/assembly must not receive the C++ macro. The two
upstream NDEBUG-related unused-warning suppressions are recorded separately.

The applied v2 producer SHA is
`affbfc9aada1cb0a63ebb043843bbee6d7dc5aeb9b966f5b61112148ef538acd`.
Eleven focused host cases passed in 0.319 seconds, including the real build
orchestration's precompile rejection and postcompile recheck with mocked native
boundaries. They do not establish native compilation or guest execution.
The old producer, production v1 and every completed output remain unchanged.
An independent SDK v2 was assembled in 4.815 seconds from the original SDK,
with all 25 pinned UAPI inputs checked and the six previously missing files
copied from the preserved original source cache.

The corrected Mesa completed all 946 build steps in 431.396 seconds. Its
actual 889 commands retain `NDEBUG/-Oz`; all 64 C++ commands have the original
FAST definition, and the 821 C/four assembly commands have no C++ override.
Both expected upstream unused-warning suppressions occur in 889 commands.
Source/UAPI identities, original inputs and the v1 diagnostic artifacts were
rechecked unchanged. Coordinator v3 report SHA is
`177c9c56aadbab9bd55cb17d9290eaed2223f86a39ee0d044c8e6f343a24b54d`;
the actual Mesa producer report SHA is
`aace2acd2d6928cc6b788a61c587f5c28f8b8dd89fde04b4e30e099470fda316`.

The genuine compositor was then rebuilt from all 422 packages and admitted by
the original consumer. Cargo reported 11 minutes 06 seconds; the complete
coordinator, including preservation and revalidation, took 822.419 seconds.
The corrected executable is 41,136,280 bytes, SHA
`3c2edd38067fe98803d95bceb110a174a2e7066d0dc199c8a3fafa0e1375d87c`.
Actual output is 1,448,195,166 bytes with zero cache growth. The success report
SHA is `5e6ff47f87ef828541ffe1e17f781512374715a318ee8d4c5ac867e308391892`.
This completes the corrected native compilation path, without establishing
guest startup or protocol acceptance.

## Actual v17 diagnostic runtime boundary

The first new catalog contains 56 entries totalling 75,373,955 bytes. Only
`cosmic-comp.elf` changed; the other 55 guest entries and four installer
receipts remain byte/mode identical. Assembly completed in 64.695 seconds.
Formal OS v11 completed in 35.703 seconds and retained source SHA
`caebe804a1ef3e3b28e7f7782b2935760f85611a45f945b032ec67389c55d2d8`.
The new compositor was embedded through the unchanged formal producer.

Capture v17 is **FAIL**, with 145.444 seconds recorded elapsed time. Its
original 45-second gate latched failure at 45.068 seconds. Later, PID 3 owned
16 completed bounded rectangle transfers, and `compositor.ppm` showed 65,478
changed pixels restricted to the top 64 rows. This is a partial display
observation: most of the screenshot still contains the boot color bars. It is
not a completed semantic desktop frame, notification rendering or a gate pass.

The genuine notification process was launched as PID 4 and exchanged Wayland
registry/input initialization messages. Eight subsequent genuine broker
queries exited successfully but did not list `org.freedesktop.Notifications`
within the existing 30-second registration window. The capture terminated
with `Real broker did not list the notification service`. No notification
probe was launched and no owned-service reclamation sequence was completed.
The VM exited with code zero without forced termination; VM termination does
not establish guest process/resource reclamation. The capture retains
`late_observation_evidence_verified=false` and all protocol, render, text,
session and FullOs acceptance flags remain false.

Capture v17 summary SHA is
`95abe9a7d3754ea58f3c48a050e09bd7aba2b81bcbeece887c68225d9e88e26e`;
the partial compositor PPM SHA is
`2e0745eb007cc3a5f96fb410d6858f74c6edc24f2665b19d6910b485a54c6eae`.

## Corrected baseline, user pause and resumed capture v19

Catalog v3 contains the corrected FAST compositor and preserves the other 55
guest entries and four installer receipts. Its 56 inputs total 75,374,019 bytes.
Formal OS v12 completed in 31.206 seconds, retaining the original 1,250-entry
source map and its `caebe804...` digest. Its six genuine program images and 50
assets were checked in the actual generated kernel.

The user paused capture v18. Its controller returned 130 and the native lease
was subsequently observed free. The nine files left in its output directory
were frozen by an independent size/SHA inventory; no terminal summary,
commands receipt or QMP transcript exists. The controller interruption does
not establish a QEMU exit code, guest cleanup or acceptance. The partial
45-second failure and image remain historical evidence. Resuming used a fresh
v19 directory with the identical OS12/compositor2 inputs; v18 was not overwritten
and no synthetic completion summary was added.

Actual capture v19 completed with **FAIL** in 129.948 seconds. The original
first-frame gate latched failure at 45.062 seconds. Its 16 later PID3-owned
completed rectangles produced the same partial PPM bytes as v17: 65,478
changed pixels confined to the top 64 rows. Seven broker queries after the
notification launch exited zero but did not list the notification name. The
protocol probe and owned-service reclamation sequence were not reached.
QMP quit was acknowledged and QEMU exited zero without forced termination;
that remains separate from guest resource reclamation.

The last notification process observation was Running, with three threads,
564 syscalls and 1,850 address-space rebuilds. Its sampled PC resolves inside
the genuine `zbus::message::header::Header::serialize`; the compositor sample
resolves inside `polling::epoll::Poller::wait_deadline`. These are single-point
function/instruction observations, not stack traces, CPU-time measurements,
proof of deadlock, or a demonstrated registration failure cause. The missing
Compose file is a separate concrete packaging defect.

The v19 summary SHA is
`4a44a8aaef6367a5fdf28463e4a0baf7bbbd6b5d9afe17c415bf5290e55e8190`.
All protocol, notification render/text, full session and FullOs acceptance
flags remain false. V17's missing FAST checks also preclude treating v17/v19
as a qualified single-variable performance comparison.

## Exact-zero alias retirement optimization

After the corrected baseline failed, two reviewed source replacements were
applied. `PhaseTable::contains_page` checks the actual phase-table coverage
without loading its state. The locked mapping core uses this only for exactly
`new == 0`. All nonzero requests retain the original phase and permission
checks. Physical bounds/alignment, owner authentication, all three checked
20-bit alias counts and their final Release store remain unchanged.

This is valid because `permits_mapping(0)` already accepts every phase, while
all production phase writers and both mapping entry paths hold the same alias
gate. The gate's Release/Acquire synchronization retains the ordering required
for phase writes and permission transactions. This argument depends on the
existing writer/reader discipline; a future writer outside that gate or a
phase-dependent removal policy would require a new review. The change does
not remove local/remote TLB fences, quarantine, owned drain, retirement, W^X,
or the existing AI/resource admission policy.

The actual production-extracting host harness passed all 24 mapping cases and
the existing nine phase transaction cases in 1.705 seconds, with warnings
denied. The former 17 mapping cases were retained. Added cases cover real
table coverage at zero/one/two words, physical bounds, all removal phases,
per-component underflow/overflow, wrong/inactive ownership and single-page
guard release. Hardware PTE/TLB effects and CPU identity remain explicit host
fixtures; these tests do not establish guest execution or real cross-core
fence completion. An earlier private launcher import-path failure occurred
before compiler/test execution and is retained separately.

Formal OS13 completed in 34.042 seconds with exact source digest
`c9ef4b07fad00a63679a4dc0f49a3f4d247e4fbdb59987a0247385d13ac5e541`.
Its source contract derives from the original full map and permits only the
two fixed replacements; the other 1,248 source entries and the original
policy/producer/tool fields must match. It preserves both the original v10
and same-catalog OS12 manifests and explicitly records
`original_os_source_preserved=false`. Catalog3 and compositor2 are unchanged.

Actual OS12/OS13 machine code was examined under the shared native lease.
OS13 tests the exact zero value before the phase load and branches directly
to the alias-count segment. Owner/CPU/physical guards, all count rejection
branches and the sole final counter store remain present. The begin/end
instructions retain gate acquisition and owner/gate release. This establishes
the intended emitted-code change, without establishing a guest speedup.
OS13 coordinator SHA is
`310bdf408674a4aca3c19250116024659658f39b1ee7e5b17a0cc1d6d6a4a118`;
the actual 24+9 host report SHA is
`1f8b172972c171b724de320cf19cb8f0f91cf86492c8e8aaef3ccf512b6a080f`.

Capture v20 completed **FAIL** in 137.429 seconds. Its original gate failed at
45.129 seconds; later scanout remained the same 16 completed rectangles and
partial PPM bytes as v19. Seven post-launch broker queries did not list the
notification name. The phase change therefore does not resolve the current
runtime gates. Different syscall/rebuild counts and one observation per build
do not establish a reliable speedup or regression. The capture summary SHA is
`e66a529d46c5aa08a16036646513515bcb353ce050791c8fbb23185d1cc361f4`.

## Complete upstream Compose data and actual locale experiment

The new reusable `tools/install_cosmic_locale_v1.py` copies four complete
files from the preserved original runtime SDK: `en_US.UTF-8/Compose`,
`compose.dir`, `locale.alias` and the entire libX11 `COPYING` file. It binds
their exact bytes and 0644 modes to the SDK origin, existing X.Org manifest,
actual X.Org bootstrap report, libX11 1.8.12 archive and provenance. The
archive is already present and checksum-verified; no source is fetched or
substituted. All 5,145 generated Compose rules must match the upstream rule
bytes. The fixed table has no additional include dependencies, and the UTF-8
mapping/alias entries are checked. No shortened or synthesized table is used.

The installer refuses linked/overlapping paths and existing output, bounds
regular reads, validates the source again during copying, preserves the full
license and atomically publishes only a completely validated directory. Its
receipt says `ASSETS_INSTALLED_NOT_RUN`; installation is separate from input
method behavior. Installer SHA is
`36e72cf9e28781ff534082c119f437de392d742c501fcef0677bfb8cdba3c6bf`.

Actual catalog4 assembly completed in 24.713 seconds. Every original guest
entry and installer receipt remains byte/mode-identical; the original catalog
origin is preserved separately. Exactly four new guest paths add 610,900
bytes, producing 60 inputs and 75,984,919 bytes within the original 256-file,
96 MiB and 95-byte path limits. Catalog origin SHA is
`951351caba4fba144cd164c9a8f747c5e00386508f549c54053d9ac0b0a328be`.

Formal OS14 completed in 38.556 seconds. It derives its accepted source map
from the original v10 manifest, the two exact phase replacements and actual
successful OS13 evidence, rather than accepting an arbitrary current checkout.
The source digest remains `c9ef4b07...`; no further compiled source, producer,
feature, AI or resource policy changed. The actual kernel consumer verified
all six unchanged executable images and 54 assets, including the four new
files. Its coordinator SHA is
`aaff180a83760377389d0e8a66c0d97f557b7a4e21b5c572f495021454fe9e7d`.

Capture v21 completed **FAIL** in 128.517 seconds. The original first-frame
gate failed at 45.094 seconds, and seven post-launch broker queries still did
not list `org.freedesktop.Notifications`. The retained image contains 36,806
changed pixels in the top 36 rows, a cursor and the remaining boot color bars.
It is an early partial scanout observation, not proof of a completed semantic
frame or a performance regression relative to a differently timed capture.

The complete 2,025,644-byte UART capture has no Compose/locale/xkbcommon error
message, and later Wayland text-input, tablet, pointer and touch initialization
messages are present. Thus the previously observed missing-file error is
absent in this run after embedding the genuine data. Successful loading of
every locale rule, keyboard composition, notification rendering and complete
session behavior were not separately established. The last notification
process observation is Running with three threads and no recorded thread
admission denial; this is not service readiness or a diagnosis of the delay.

V21 summary SHA is
`661852bed219cc2d68aa73e2bc8dc377bed3b7c884a81b6be4723f24c33818fc`;
partial PPM SHA is
`bfa18c33c822889c9e6dc0c741ef421322209c24894268a7e07b6a0cef54a529`.
QMP quit was acknowledged and QEMU exited zero without force. The notification
protocol probe, text verification and owned-service reclamation sequence were
not reached; all corresponding acceptance flags remain false.

## Remaining complete-session blockers

The observed first-frame deadline and notification registration failures remain
open. No larger deadline, reduced feature set, relaxed memory check, changed
AI model or enlarged resource pool was used to turn these observations into a
pass. The complete Mesa/compositor build and the local kernel/data fixes do
not satisfy the full-session target.

The retained actual offline metadata attempts for `cosmic-session` and
`cosmic-settings` fail first on `freedesktop-desktop-entry 0.8.3` and
`zlink 0.5.0`, respectively. A read-only investigation of 2,532 existing crate
archives, 3,415 package manifests and six outer containers did not find those
pinned inputs. It found one checksum-matching settings archive,
`byteorder 1.5.0`, which has not been copied or counted as a resolution success.
The whole-lock inventories still lack 16 session archives and 152 settings
archives; these include optional/other-platform entries and must not be
presented as a proven selected-target dependency requirement. The separate
`windows 0.62.2` extraction gap also remains unresolved. No new metadata or
build success is claimed for these components.

The real panel requires a genuine presentation path beyond the current
surfaceless Mesa setup. Complete-session work also needs the real default
applets, FD handoffs, measured process/pipe capacity and end-to-end resource
reclamation. The earlier 18-default-applet versus seven-admitted-native-slot
and initial-stdio versus 30-admitted-pipe-pair findings remain design and
measurement work, not permission to remove applets or raise caps blindly.

Final source review found no critical blocker in the eight scoped retained
source/test files and requested no repairs. That code-review result is
distinct from the still-failing runtime acceptance. All failed and interrupted
experiments, source/tool identities and original receipts are retained. The
changes are intended for a local commit only; no remote publication is part
of this continuation.
