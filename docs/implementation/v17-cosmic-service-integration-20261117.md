# Genuine COSMIC service and Wayland integration, 2026-11-17

**Complete COSMIC has not passed acceptance.** This continuation starts from
published commit `a8a2795a09a7c1c11804e131398c68320b3616a9`. It advances the real
session manager, settings service and native Wayland EGL dependency chain.
Build, installation, guest execution, service protocol, complete scanout and
session acceptance remain distinct results.

New build and capture evidence is isolated under
`artifacts/v017-cosmic-runtime-20261117-next`. The existing native lease at
`artifacts/v017-cosmic-completion-20261116/native-session.lock` serializes native
compilers, Cargo, symbol inspection and QEMU. Older producers, successful
closures and failed attempts remain unchanged.

The design remains CyxiaOS-native, with x86 as the primary target and ARM
compatibility retained. A03 is cancelled. AI control and execution planes remain
separate; this work does not introduce fixed AI core counts, preferred resource
domains, host-OS cluster agents or simulated COSMIC services.

## Page-table staging and actual runtime result

The x86 staging representation in `kernel/src/desktop/address_space.rs` now
stores packed page values and separate present/executable bitmaps. The
representation remains 8,192 bytes with 4,096-byte alignment; its original
73-table pool is unchanged. Present pages are visited in ascending index order.
Executable alias runs additionally require both virtual adjacency and checked
physical adjacency, and never cross the 512-entry table boundary.

Set, overwrite, remove and clear update all indexes. Original validation/error
precedence, executable sealing before alias admission, full PTE retirement and
ownership accounting remain. The ARM-specific blocks and `ProcessSpace`
implementation are unchanged. The actual applied source passed 32 mapping and
staging cases plus nine phase-order cases with warnings denied. These checks
establish the scoped behavior, not a measured guest startup improvement.

Formal OS v15 completed in 30.644 seconds using exactly one changed file in the
previous 1,250-file source map. Its compiled-source digest is
`16de7449f3618ca8ec7070088f617a08780c9a74a3465534d7bcdccac7ab0b49`.
The same six real executables and 54 assets, totalling 75,984,919 bytes, were
embedded. The original formal-build features, compiler identities, 1 GiB guest
RAM and four guest CPUs remain unchanged.

Capture v22 failed the original first-frame gate and later stopped on a
console echo timeout. The raw UART shows that the corresponding real
`dbus-send` process had started, replied and exited successfully. Concurrent
background output had followed the exact echoed command before the shell's
own CRLF, so the old controller did not recognize the command boundary.

The new `tools/os_cosmic_notifications_runtime_v2.py` changes only that echo
boundary. The exact contiguous command, fresh receive offset, shell line
boundary, prompt and later business/process checks are still required. The
other 49 functions remain byte-identical to the original producer. The old
producer and tests are retained. Its 53 installed host tests pass, including a
fixture containing the exact retained v22 bytes and rejection cases for wrong
commands, missing shell boundaries and missing real process completion.

Capture v23 completed the observation sequence but still **failed**:

| Observation | Actual result |
| --- | --- |
| Overall capture | FAIL, 134.783 seconds |
| Original first-frame gate | Failure latched at 45.3269 seconds |
| Post-start D-Bus name queries | Eight real replies, exit code zero and complete per-process reclamation |
| Notification service name | Absent in all eight replies |
| Scanout | 16 completed rectangle transfers, 65,478 changed pixels in the top 64 rows |
| Full frame, notification protocol, text, session | Not verified |

The v23 compositor PPM is byte-identical to v22, with SHA-256
`2e0745eb007cc3a5f96fb410d6858f74c6edc24f2665b19d6910b485a54c6eae`.
The remaining 704 rows retain the boot image. A rectangle transfer is not a
semantic full frame. This was one saved compositor snapshot; it does not prove
that later rendering remained at 16 rectangles or that a frame timer stopped.
Read-only symbol mapping of 235 actual instruction-pointer samples shows later
presentation and event-loop activity, without establishing a cause for the
missed frame deadline. All 470 command spans in v23 matched the old and new echo
regex at the same boundary; the new suffix branch did not occur in that run.
The concrete concurrency repair is therefore evidenced by the v22 fixture,
not by claiming that v23 reproduced it.

The last saved notification process sample had 660 syscalls, three threads and
1,676 heap pages. No observed fault or thread-admission denial establishes a
capacity failure. No performance ratio is inferred from cumulative prepare or
retire time across different progress points.

## Genuine session and settings compilation

Missing dependencies were recovered as their original pinned registry archives
and exact index entries. Archive/member/extraction limits were retained. The
session selected graph contains 125 packages. Settings metadata retains all
11 workspace members and 502 selected packages, including the audio and
varlink workspace sources; no member was deleted to resolve metadata.

Both original Linux-v1 producers completed real offline release builds and
their separate original consumers revalidated the results:

| Component | ELF bytes | LOAD pages + stack pages | Original build limits |
| --- | ---: | ---: | --- |
| `cosmic-session` | 5,332,352 | 1,000 + 512 | One Cargo job, 900 seconds, 512 MiB |
| `cosmic-settings-daemon` | 7,339,984 | 1,371 + 512 | Two Cargo jobs, 1,200 seconds, 1.5 GiB |

The session producer completed in 332.558 seconds. Its executable SHA-256 is
`786fe6ac3c4922d19409959202d88619010fa4de0c3b27497fd18c709bbd3f20`.
The settings producer completed in 591.365 seconds. Its executable SHA-256 is
`277cc8dca56472061493e5db4614afe6c3b7f9d50248d448746d0f870083b104`.
These binaries have not acquired a runtime claim merely by compiling.

## Separate verified installations

`tools/install_cosmic_session_linux_v1.py` binds the original session consumer's
complete build identity and receipt. It installs the admitted executable and
both full upstream licenses. `tools/install_cosmic_settings_linux_v2.py` uses
the original settings Linux-v1 consumer and preserves the earlier settings
installer. Its new receipt binds the complete consumer proof, original build
report, exact ELF, three full licenses and explicit unsupported-service
boundaries.

Both installers check source and copied bytes and exact file modes, revalidate
the original build before publication, protect source/SDK/Cargo/Rust/native
tool directories and retain legitimate verified tool symlinks. Optional tools
recorded unavailable are not mistaken for required existing files. Publication
uses Linux `renameat2(RENAME_NOREPLACE)` so a concurrently created empty output
directory is preserved. Unsupported atomic publication fails closed.

The receipt does not bind the installation prefix: an exact installation can
be copied into a combined catalog and revalidated there. It still binds its
original build and complete installed file set. Execution, service readiness
and complete-COSMIC claims remain false.

The actual installed host suites pass nine session and 17 settings cases,
including atomic publication races, tampering and failure cleanup. Their
consumers are explicit fixtures; these host tests do not substitute for the
subsequent real installation checks. The real session installation completed
in 16.615 seconds, and settings in 30.511 seconds, each replaying its original
consumer. Their receipt identities are:

- Session: `c3b771be2bd368de34937022b565fa2a0da42e20115630751420e5b946060a29`.
- Settings: `9aa5a43700d7e2371677325dcb5743b0e0c4e5a300f4fd028af1aeee6782dc35`.

The previous catalog already contains the same 35,158-byte settings main
license. A new combined catalog must reuse that exact byte/mode-identical
entry, without overwriting it. Before adding a protocol probe, the unique
guest inventory is expected to be 66 entries and 88,743,916 bytes. This
arithmetic is a preparation constraint; actual catalog assembly and embedding
must independently verify the result.

## Genuine settings protocol client and theme inputs

The separate `user/ported/settings_probe_v1.c` retains the original
configuration/state mutation, subscription, change-signal, theme-export and
explicit unsupported-operation checks. It adds a bounded connection to the
real Wayland socket and resolves the settings service's unique D-Bus owner
and process ID. The client also resolves its own process ID, verifies the
returned watcher owners and message senders, and checks that the service owner
remains stable. A successful socket connection is only transport readiness;
the probe does not label it a completed Wayland protocol exchange.

`tools/build_settings_probe_v1.py` binds the genuine native SDK, D-Bus archive,
source policy and original probe source. Its separate
`tools/settings_probe_inputs_v1.py` consumer reconstructs the actual compile
and link commands and validates the producer closure, object, logs, static
ELF permissions and page admission. The original 120-second build limit,
64 MiB output limit and single compiler job remain unchanged. Sixteen focused
installed host checks pass without launching an external process.

The real build and independent consumer completed in 5.920 seconds. The new
probe is 950,704 bytes, with 58 LOAD pages and the original 512-page stack
allowance. Its ELF SHA-256 is
`fb43ec31733c1f7566dc9ebad4046eeabe1a6c74df17c3b3dd1fda7cc866d0e7`;
the build-receipt SHA-256 is
`03f2e0b6677a8bc5e165b8c291d8e03afcc377016c5eb9e32d4d4eb782187ce5`.
This establishes a genuine admitted client, not a guest service result.

The previous runtime catalog lacks the complete CosmicTheme Light and Dark
defaults. Inspection of the exact settings/libcosmic sources shows that, with
those defaults absent, the fallback can supply the dark theme for both
entries and leave the expected light CSS export missing. The protocol test
will retain both theme checks. The same pinned libcosmic revision provides
39 configuration keys per mode plus its full MPL license: 79 unique files,
34,654 bytes. Their actual bytes, modes and schema match the retained asset
reference. The original exporter build and guest capture provenance is not
available in the current evidence set, including the two recovered November
16 evidence archives, so the old generation consumer has not passed.

A new, separately versioned generation path uses the current verified settings
build's actual libraries and the unchanged theme export client. The installed
v1 chain passed 31 pure host tests, then its first real invocation failed after
35.250 seconds during host-tool input validation, before linking or either
theme export. The failed coordinator report is retained at
`theme-linux-native-v1/report.json` in the continuation's work evidence.

The failure is concrete: the active Python ELF's dynamic string table occupies
virtual addresses `[4191704, 4233970)`, crossing two adjacent file-backed load
segments. Both segments have the same file-to-virtual-address offset and
together cover the whole table. The v1 parser incorrectly requires one segment
to enclose the complete table. The new v2 producer and separate receipt accept
complete, unambiguous piecewise coverage while rejecting
gaps, conflicting mappings, BSS overlap and out-of-file reads. The v1 sources
and failed attempt remain unchanged; no generation success is credited to them.

The v2 chain passed 47 actual installed host tests. An independent numerical
review rejected all four retained BSS-overlap counterexamples and accepted all
56 previously captured real dynamic-table layouts, without executing an ELF.
The subsequent real v2 invocation successfully linked and ran the unchanged
exporter in both modes. The native link and two exports took 1.736 seconds;
the complete coordinator, including repeated source validation, independent
consumption and atomic installation, completed in 132.830 seconds. All
79 generated and installed files match their pinned source-equivalence
reference, with the original inputs preserved.

The generated executable is 6,322,144 bytes, with SHA-256
`08866244cdb61305719288c5b17075814f99173823949399122e2b97f4e0f257`.
The completed build receipt is
`c60471984db4a72a428fe48dc621fbed9d8af30b100279ac6261f9b17263265c`;
the distinct `cosmic-theme-linux-v2-assets.json` installation receipt is
`f05713d72ad5f57580112d7ea7425d7785d73dc34f455a1356912cc71bf82246`.
This proves Linux-host generation and installation. CyxiaOS theme behavior
still requires the real guest service probe.

The subsequent real catalog assembly passed. It contains 146 guest files:
nine executables and 137 assets, totalling 89,729,274 bytes. The producer took
175.070 seconds; the outer invocation and final checks took 178.442 seconds.
All 60 original guest inputs and their receipts remain identical. The actual
catalog origin SHA-256 is
`ef37d989fc52bd1929c1550e0c1fa68e623594b8c3fa4a570c421ae473dc0032`.

## Formal service image

The fresh `service-runtime-os-v1` build completed in 39.033 seconds. The actual
compiled map preserves all 1,250 OS-v15 source entries and adds only the
reviewed `user/ported/settings_probe_v1.c`, for 1,251 entries and source digest
`53da2e0922bdefec85966edd4da33fa346bc0a166be1cd4b43ae39d581e0abfb`.
All 18 original formal-build policy fields, including compiler identities,
features, 1 GiB RAM and four guest CPUs, remain unchanged.

The independent embedding validator confirms all nine exact executables in
the generated catalog, installed inputs and read-only kernel load, together
with all 137 exact resource files. This is an actual embedding result. The
completed OS coordinator receipt is
`de64dda9d06da0e70d23f4293882825dcb81f583631f594354eced0b76d3842a`;
the build manifest is
`138edb36deda84a92948926ef8c587de913388d878d4a27ded40b86923f49ebe`.
Runtime protocol, visible content and complete session acceptance still need
their separate guest evidence.

## Service lifecycle validation

`tools/os_cosmic_services_runtime_v2.py` implements a bounded manual integration
capture for the real session version command, broker, compositor, settings
daemon and protocol client. It checks actual process identities, exit codes,
per-process reclamation and final global resource accounting. The original
45-second first-frame gate remains latched on failure, with separate later
frame observations and the unchanged 240-second guest bound. These checks do
not establish normal session-owned startup or notification descriptor handoff.

The complete theme proof is consumed while holding the original native lease,
before creating any capture output. All verified source, build and generation
directories are protected from nested output paths. A selected host-generation
receipt cannot be interpreted as the earlier guest-generation proof.

The actual installed repository suite passed 43 tests with one explicitly
unselected retained-UART fixture. Selecting the exact saved v23 UART by its
full SHA-256 passed all 44 tests. All 74 loaded local modules came from the
repository's tools directory, their sources were preserved, and neither run
started an external process. These are controller and rejection-path checks;
their separate guest result is recorded below.

The separately versioned `tools/os_cosmic_services_runtime_v3.py` adds the
fixed `linux-host-v2` consumer and its distinct receipt. Its capture, timing
and lifecycle functions remain byte-identical to v2. The actual installed v3
suite passed 48 tests with the optional UART fixture unselected, and all
49 tests when that exact retained fixture was selected. These runs likewise
loaded all 74 local modules from the repository and started no external process.

### First actual service capture

The first `service-runtime-capture-v1` invocation records **FAIL**. Its final
summary SHA-256 is
`5a203bdacbf3eb7b2ebf063e59233bc2e1d6fe46c6059bf6044c52cae899c006`.
The complete 993,462-byte raw UART is
`983de36db1f8caaaaf9fcca0a7ab38bc3dc19534d5ff59217532aecd66944693`.
Original inputs passed the final independent identity checks. QMP acknowledged
quit and QEMU exited with code zero without a forced kill; that host cleanup
does not establish guest service completion or resource reclamation.

| Stage | Actual retained evidence |
| --- | --- |
| Session version | PID 1 printed `cosmic-session 1.10.0`, exited zero, released its image/heap/threads and restored the 64-page global arena; this component passed |
| Probe preparation | PID 2 printed `PREPARED`, exited zero and completed the same resource checks |
| Real broker | PID 3 served a real ListNames query; its client PID 4 replied, exited zero and was reclaimed |
| Wayland transport | Client PID 6 successfully connected to `/run/user/0/wayland-1`; protocol and rendering remain unverified |
| Settings owner | The broker bound `com.system76.CosmicSettingsDaemon` to unique owner `:1.3`, actual daemon PID 7, distinct from client PID 6 |
| First settings request | `WatchConfig` to `:1.3` at `/com/system76/CosmicSettingsDaemon` returned `org.freedesktop.DBus.Error.NoReply` under the unchanged 10-second method limit |
| Remaining protocol and cleanup | Configuration/state change signals, theme exports, unsupported-operation replies, final client exit and service/global reclamation were not reached |
| Display | Only the boot image was saved, with zero submitted/completed compositor transfers; no compositor-frame acceptance |

The summary's 117.052-second interval begins before its input validation; it
is not pure QEMU execution time. The outer launcher took 253.152 seconds,
including additional validation. The original 45-second frame failure flag
was still false when the earlier protocol failure stopped the run. This does
not constitute a first-frame pass.

Read-only symbol inspection of the exact retained daemon ELF maps all sampled
PCs. After the owner marker, the main thread continues through theme/config
deserialization and real GTK/Qt export functions. The pinned daemon runs a
current-thread Tokio runtime, and its initial dark/light theme export performs
synchronous work before its next await. These observations support executor
starvation as a concrete cause candidate; a corrected real build and guest
run are still required to establish the fix. The original timeout is retained.

A separate definite client-contract defect was also found before its code path
could be reached: upstream `WatchConfig` and `WatchState` create separate D-Bus
connections for the returned watcher names. The v1 client incorrectly requires
those names and signals to use the main service's unique owner. The next client
must independently resolve each watcher's owner, bind its Unix PID to the real
daemon, and verify that owner and signal sender remain stable. This later
defect does not explain the first request's observed NoReply. The original v1
source, executable and failed capture remain preserved.

## Genuine Wayland EGL build path

The real panel creates a Wayland EGL window surface. The previous retained
Mesa configuration supplies surfaceless EGL only. The new separate
`tools/build_mesa_production_v3.py` enables the upstream Wayland platform while
retaining surfaceless, softpipe, explicit `NDEBUG`, `-Oz`, and the original FAST
hardening for all 64 C++ translation units. It does not fabricate a renderer,
libdrm implementation or display response.

`tools/install_wayland_protocols_v1.py` validates the complete genuine
wayland-protocols 1.41 archive, retaining all 125 source files and 53 XML files.
The installed data includes the full XML/README/license inventory and the
upstream pkg-config template substitution. It does not replace a native
release with the differently packaged Rust crate. The archive SHA-256 is
`2786b6b1b79965e313f2c289c12075b9ed700d41844810c51afda10ee329576b`.

The Wayland producer binds the original genuine host scanner, target Wayland
and libffi archives, headers, pkg-config metadata and protocol source data.
The parent SDK coordinator binds headers and metadata to the complete old SDK
manifest. Actual Meson configuration must contain both Wayland and surfaceless
platform sources and all 14 scanner targets for the seven required protocol
inputs. Configuration alone does not establish generation or compilation.

The actual installed producer modules passed 27 pure Python input and
configuration cases. A fresh SDK was assembled in 25.068 seconds, preserving
all old non-Mesa SDK bytes and adding exactly 105 protocol data files. The first
Mesa coordinator then failed at toolchain discovery before setup or
compilation: its launch environment lacked the pinned Clang/Rust directories.
That failed attempt is retained separately; native compilation and runtime
acceptance are not credited to it.

The second coordinator restored the original pinned toolchain environment
and completed all 955 genuine Ninja compile/link steps. The actual
configuration contains 894 compiler commands: 826 C, 64 C++ and four assembly
commands, plus all 14 protocol scanner targets. The producer records
`libraries-compiled`; its receipt SHA-256 is
`0e8ea89167188b799da66c895706bc0580b84179e86570f7f0208d47d2d95347`.
All required production flags and both platform source files remain present.

The second coordinator nevertheless records **FAILED**, after 471.902
seconds. Its final validator incorrectly expected a standalone
`libloader_wayland_helper.a` argument. The generated Ninja graph instead
places the helper and generated presentation-protocol objects directly in
`libEGL.a`. The failure receipt remains unchanged, with SHA-256
`49d1c1f9d0c4df8da60079bafab059a15aa0eaeba8c6e0bf9805ed685ea11352`.
A separate read-only consumer subsequently passed in 29.669 seconds. All
126 actual `libEGL.a` members match the 126 Ninja object inputs by name, size
and SHA-256, including the real helper and generated presentation-protocol
objects. It reconstructs the actual final linker arguments and verifies five
Wayland/helper/surfaceless functions in executable ELF segments, including
their unchanged bytes after stripping. The archive is 4,938,074 bytes, with
SHA-256 `5d5296054b18b6d0e2ad358203cccc321255528b5be8f2dc9f731a0107ed09bd`.

All nine original preservation categories match the fixed before-build
snapshots, including both SDKs, source archives, toolchain/scanner inputs and
the retained first failure. The independent consumption receipt is
`e7817eaf044b63693a0b1e93a8c447cd8b9695fcb04eeca70d6f900162bc1647`.
The final genuine EGL probe is 12,885,176 bytes, with SHA-256
`b7f8e7e2a02dea7e05d2a9bd79817d64cb95e5beb54b5320ec50afc0a47d13ad`.
This accepts the actual build and static-link closure. Runtime Wayland
presentation, panel execution and session acceptance remain unverified.

## Exact panel dependency sources

The original panel revision is
`3ce6ce1cec97669f91e809962d9446aaefe8a06e`. Its complete lock file contains
555 packages, including three workspace-local packages. This whole-lock
inventory is not a selected feature graph. All three workspace members and
the original default features remain required for the forthcoming metadata
resolution and build.

Three missing Git identities were acquired through the original HTTPS Git
transport in one bounded source-only run:

| Source | Exact commit | Canonical files | Source bytes |
| --- | --- | ---: | ---: |
| cosmic-protocols | `32283d76a8d0342da74c4cc022a533c52dcf378f` | 37 | 251,588 |
| cosmic-notifications | `41d722cdef7bfe49030e72f61784a49902dbbc63` | 43 | 300,710 |
| Smithay | `0ff00983b6007257a7a161a4fe8b14a778e2ac8f` | 343 | 4,491,978 |

The original double slash in the locked cosmic-protocols URL was preserved.
Each checkout passed full canonical Git verification. The coordinator completed
in 28.948 seconds under its unchanged 240-second and combined 128 MiB bounds;
the original panel, launch-pad and protected inputs matched before and after.
Its receipt SHA-256 is
`520200c46a6c61c88f369ba4a91b7cb5659a68ac436496b5380f8ad367807c3a`.
No Cargo metadata, compilation or guest execution occurred in this source run.

## Settings v2: preserve theme work while yielding the service executor

The retained first service capture remains **FAIL**. The subsequent bounded PC
analysis found the genuine settings main thread progressing through theme,
configuration and GTK/Qt export work while the first WatchConfig call timed
out. This supports executor starvation as a concrete candidate; it does not
establish causality or a successful fix before a new guest run.

The v2 source keeps the real current-thread Tokio runtime and LocalSet. It
moves the original synchronous theme work into sequentially awaited
`spawn_blocking` closures. All initial and later theme branches retain their
original operations and ordering. The pinned Tokio blocking worker enters the
runtime context, preserving the context used by existing upstream asynchronous
helpers. No `spawn_local` operation is moved. The original release
`panic=abort` profile remains; an end marker means that the synchronous closure
returned, not that detached upstream helper tasks finished.

The complete 11-member workspace and 502-package selected graph remain
unchanged. Its normalized graph SHA-256 is
`3a05c8c691eb9a7120aaaa99dc355788b2848116199da1646be3a653e5ad2734`.
The actual installed build/consumer/installer suite passed all 44 cases, with
no external processes. A preceding test coordinator had failed its own module
origin lookup after those cases passed; that failed coordinator result is
retained, and the corrected result explicitly binds the detached installer
subject to the installed repository source.

The genuine v2 producer completed in 715.830 seconds within the original
1,200-second, two-job and 1.5 GiB build bounds. Its independent build consumer,
installation and installation consumer also completed successfully. The new
ELF is 7,424,856 bytes, SHA-256
`e8472d9bdf74971f8c8f7cf8852cfaa010c4cd90f86b13128765fb702583d07a`.
It requires 1,384 load pages plus the original 512 stack pages: 1,896 pages in
total. No resource capacity or timeout was raised.

| Actual settings v2 evidence | SHA-256 |
| --- | --- |
| Producer build report | `936a4698cbd440f2512caebd419d0328d809f3a6b0c4bc3d0675a8c627adea5b` |
| Root build/install execution | `d4487924db4d4ad7a0a4fe6658c5b37c8baac6c315e02ef78fa1ef6ad4a174e4` |
| Independent build consumer | `ea89bfa719916bb59ab395ccf3ec2ef85d0e4c8d29d44d11e08d21ab933d8d49` |
| Installation receipt | `3b8f87b61f257070703ae06aa22934384c667c979508d8a24d857f0a56ec7f6e` |
| Installation consumer | `0378ff8bde8a49104bbdd3cbefa7ae7c460113fd052808123242e3d50cebb3bb` |

## Probe v2 and the actual upstream watcher ownership contract

The genuine upstream service creates separate D-Bus connections for its
configuration and state watchers. Consequently, the watcher's unique sender
can differ from the main service owner while belonging to the same daemon
process. Probe v2 authenticates each returned watch name through the actual
broker, obtains its unique owner and Unix PID, and requires that PID to match
the daemon and exclude the client. It matches Changed signals to that unique
watcher connection and rechecks the returned name's owner/PID afterward. Main
service ownership stability remains an independent requirement.

The actual native build and independent consumer completed in 6.188 seconds.
The probe ELF is 954,880 bytes, SHA-256
`26cd8fc3fa992a67b37182cd0300ae0d2fe2d151dc8033074b32bebf05d64c45`,
requiring 59 load pages plus 512 stack pages. Its build receipt SHA-256 is
`e2999e3f9340fb3c5085f0314f6fa481e78e06a2413889f9f2de4e397f1420a3`.
All 20 installed consumer cases passed without external processes.

The new runtime controller accepts only the explicit v2 watcher marker
contract. All 49 prior lifecycle tests are preserved, with 12 additional
cases. The actual installed portable run reports 60 passes and one explicit
UART-fixture skip; the separate run with the retained real UART reports all
61 passes. The latter receipt is
`0cdc4b235ff5bf4baa11c716f682f0c0bb98951a8b88448bcfdbf6491008daf6`.
These are host parser/controller checks, not new guest protocol success.
The original method, changed-signal, theme, first-frame and guest budgets
remain unchanged.

## Panel source cache, archive-reader correction and real metadata

A fresh panel cache was prepared from the preserved genuine source caches.
One bounded locked Cargo fetch acquired the remaining exact dependencies;
there was no automatic retry. The preparation completed in 89.772 seconds,
with 33,181,781 bytes of growth under the original 240-second/128 MiB bounds.
All 516 exported source files were verified. The preparation receipt is
`4648357af5d45b5b09a1f6dbdf9a57969d866d5bdb862f267d60b65d863a18b7`.
Copy-size preservation is recorded separately from full source-byte checks;
no whole-seed byte-hash claim is inferred from a reflink/copy.

The first real metadata attempt failed before Cargo resolution. The genuine
Gallium archive is 29,779,478 bytes. Its initial validation correctly used the
existing 64 MiB native-archive bound, but two later archive reads omitted that
argument and inherited the unrelated 16 MiB general-source default. A new
contract version supplies the existing native bound at those two calls.
The old failed producer report and original source versions remain unchanged;
no resource bound was enlarged.

All 20 installed cases passed, including the original 17 cases and three
new archive-size/integrity cases. The new metadata producer then completed
in 46.997 seconds, with no postcheck errors and the original workspace,
default features, native libraries and budgets preserved. Its receipt is
10,127,164 bytes, SHA-256
`f7ebc183a635768336de41b91fb7a5325efc98fd11e770c1c52b94eaec877971`.
The independently recomputed selected graph contains 473 nodes; all three
workspace and default members remain present. The original panel/dock
configuration retains its 18 applet instances, comprising 16 distinct IDs.
This is actual offline metadata evidence; it does not establish a linked
panel binary, applet startup or Wayland presentation.

## Service catalog v2

A fresh catalog was assembled from the completed genuine settings v2 and
probe v2 results. The actual coordinator completed in 175.495 seconds; the
outer execution and final receipt check completed in 178.497 seconds.
Independent consumers were replayed against the real installations and their
relocated catalog copies under the original native lease.

The catalog contains 146 entries: nine ELFs and 137 assets, totaling
89,818,322 bytes. Exactly the settings daemon and protocol probe changed;
the other 144 guest inputs retain their prior identities and modes. The
complete base, session and host-generated theme proof dictionaries remain
equal, and the three installation receipts are exact byte copies. The original
96 MiB, 256-entry and 95-byte guest-path limits remain in force. Panel has not
been added to this catalog.

The catalog origin is 310,494 bytes, SHA-256
`71c3b9c715447fca8a60bcfc7714b606ea75ff4efcf739be8c7ca16dc40fb833`.
The separate actual-result JSON review is
`e94b9553c37d075fee4b7fcd39b28e9f51de243ed0692840fe034e70b1dcf079`.
Assembly and static provenance remain distinct from formal OS embedding and
actual guest protocol/lifecycle acceptance.

## Formal service OS v2

The formal OS coordinator completed in 35.073 seconds; its outer supervisor
completed in 38.585 seconds. The actual source map contains exactly the prior
1,251 entries plus ten reviewed source/policy additions, with SHA-256
`8d9bffd5e25cf339bd9562a9ba6aae16cd25b81ae2dd4af65b24aea1743436e7`.
All 18 original OS policy fields remain equal, including the original two-job,
900-second, four-CPU and 1 GiB machine configuration. The generated catalog
proves all nine exact ELFs embedded in read-only kernel segments and all
137 assets, totaling 89,818,322 bytes.

The actual coordinator receipt SHA-256 is
`d097ade9f5afaf0119cf32cd1b8117aa8f1ed207ea1112adceef04b1b2a6415a`;
the build manifest is
`3757af0176bd518d4de00f72be9dad2d1b893df7723183a42ae00e600e900fc7`.
The independent JSON association review is
`a2c3a550b9c29c4cdcf28f87174c42f2c4709c19b045d5b50a62c0cec666e05c`.
The actual outer supervisor observed the leader reaped and its process group
gone, with no cleanup signals needed. A pre-execution source review had
corrected the case where a failed leader could leave compiler descendants;
that unexecuted earlier wrapper remains retained.

## Actual service capture v2: protocol progress and retained failures

The second real service capture used the new settings ELF and probe with the
original protocol and runtime limits. Its nine strict protocol markers all
completed. The broker authenticated main owner `:1.3` as daemon PID 7 and the
client as PID 6. Config watcher `:1.4` and State watcher `:1.5` each belonged
to the same genuine daemon PID 7, and their Changed signals matched their
separate authenticated watcher identities. Light/dark theme behavior,
unsupported capability responses and stable main ownership also passed the
probe. The client subsequently exited with code 0 and released its own image,
heap and thread ownership.

This run crosses the previous WatchConfig NoReply barrier under the same
timeout. The later capture v4, using the exact same settings ELF, reproduces
that timeout. The single protocol success therefore does not establish a
stable startup fix or a unique cause for the earlier delays. Wayland socket
connection remains distinct from a verified Wayland client protocol or
rendered pixels.

The complete capture still records **FAIL**. Its first-frame failure was
latched at 45.043961 seconds from compositor launch, and the late observation
closed at 120.000137 seconds. All 339 recorded display snapshots have zero
proposals, submissions and completions. Only the boot image was captured.
The genuine service processes were then terminated by the explicit commands
for PID 7, PID 5 and PID 3; each was observed as Killed/137 with zero image,
heap and thread ownership. This is targeted test cleanup, not a graceful
normal-session shutdown.

The controller failed at the subsequent final arena check with
`Missing process from final arena snapshot`. The last two complete process
lists contain the four terminal PIDs `{3, 5, 6, 7}`, each reporting all 64
Runner pages free. The kernel deliberately reuses an inactive Runner slot on
later starts; earlier PID 1 was replaced by PID 2, then PID 3, and the
short-lived query PID 4 was replaced by PID 5. The process list is a current
slot inventory. The old controller incorrectly required historical PIDs 1
and 2 to remain in that final inventory despite their separately completed
phase checks.

The old run never reached the final `ai system` after killing the broker.
Consequently its final global OFD, shared-memory, anonymous-memory and pipe
baseline is **unverified**. Its settings component remains
`OBSERVED_NOT_FINALIZED`; resource/lifecycle completion flags remain false.
The retained failure is not retrospectively relabeled using later parser
logic.

QMP quit was acknowledged, QEMU exited with code 0, no watchdog termination
was forced, and the complete launch input identities were preserved. The
producer's 220.670-second interval includes input validation; the outer
344.247-second interval also includes surrounding proof checks. Neither is
reported as pure guest execution time.

| Actual capture v2 evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| `summary.json` | 1,263,634 | `e0dc03f6da6e1be3b70c8a752f68a24b87ec9c0f3ddd8796d4945e17b682b861` |
| `serial.raw` | 3,780,285 | `c5bc67ae603b3f9a1df1f1a3de4fd6f1038175c0d09c3a96e61945261866bcb9` |
| Host launch receipt | 27,332 | `57239ab8fcc04e6a2d2a421a4b96bae080895eacbb95e8f155cc825a0fcc42f9` |
| Independent result review | 17,192 | `7cea1b9fb3adbf719d17af45ffea8bea03f50d94322a21692b2616459c5e7599` |

## Runtime v5: current slots and separately proved earlier phases

A new version adds `final_service_arena` and changes only the two final arena
calls plus an explicit completed-version-phase prerequisite. The six launch
identities remain a closed set of positive, distinct PIDs. The final snapshot
must contain the four service-stage identities, and every fresh process row
still participates in the original global arena check. All rows must be
terminal, no process may remain active, and all 64 pages must be free. The
client must be Exited/0; the three services must be Killed/137, with no image,
heap or thread ownership remaining.

Earlier version and preparation UART, PID, terminal-state, arena and global
resource proofs remain mandatory in their own completed phases. The final
real `ai system` and complete baseline comparison are still required. This
corrects the historical-PID assumption while preserving the missing-evidence
and resource-leak failures.

All 14 other original function/class bodies and all 61 old test methods are
byte-identical. Eight new cases include the actual old driver's failing
slot-reuse case, the new driver's complete final resource read, missing early
proofs, wrong PIDs, live rows, inconsistent free-page accounting and global
resource leaks. Actual installed repository validation reports 67 passes plus
two explicit optional-UART skips, and 69 passes when both complete fixed UART
fixtures are selected. All 82 local module origins are the real repository,
all source identities are preserved, and external-process calls are zero.
The two installed receipts are
`a0c712394caced2e41d9a17cb8bf1e38858e62b74339057d10108027458ba045`
and `53ab321b30b016a9b2e9be1188aed9d459511b83a2ebc2e67e794bba4392bbbe`.
The subsequent genuine guest run is recorded separately below; it failed
before reaching this final arena path. The two new tool paths are outside the panel producer's
31-file source closure and all 54 of its fixed inputs; those inputs matched
before and after application.

## Compositor initialization evidence

One bounded, read-only symbol-mapping operation matched the actual capture v2
PCs against the unchanged genuine compositor ELF. It completed in 1.637
seconds under the original native lease and 30-second tool bound, preserving
both inputs. The mapping report is
`4204c303728bdc0000e65d56a59ed19faf89d01771c336a9c5ddeb5acb756f2c`;
the independent timeline interpretation is
`90b778b52a3f017763ec4902641ca4c3712aaf7ccb164344fb9c03c0be1b4554`.

There are 339 running-process contexts and three killed-process residual
contexts. The latter are excluded from continued-execution interpretations.
Running samples progress through language/configuration/theme handling,
regular-expression construction, EGL/context setup, then real GLSL/NIR shader
work. The first sampled EGL function occurs after the first-frame gate's raw
serial anchor; a sampled appearance is not the precise function-entry time.
No sample establishes first-frame presentation, and the actual display
counters remain zero throughout. Syscall-boundary samples and aggregate HPET
prepare/retire spans are not converted into CPU percentages or wall-time shares.

The earlier notification capture's saved top-64-row image also cannot prove a
permanent rendering stall. The genuine backend submits 16 four-row tiles per
tick, and the existing capture saves the first completed bounded rectangle
candidate only. Source inspection finds full initial damage and continued
pending-tile advancement, not a zero-canvas pixel-difference shortcut. That
first-batch screenshot and this run's zero-submission initialization failure
are separate observations.

## Actual genuine panel build and independent consumption

The corrected producer completed the real offline release build with the
original full workspace, default features, exact native libraries and selected
graph. The Cargo release compilation reported 10 minutes 18 seconds. The full
producer interval was 693.798 seconds; the outer build-and-consumer interval
was 711.461 seconds. These are separate intervals, not alternative measurements
of the same compiler phase. The original 3,600-second shared build/consumer
budget, two Cargo jobs, 3 GiB resource bound and 64 MiB ELF bound remain.

The genuine `cosmic-panel.elf` is 33,718,544 bytes, SHA-256
`4da6dab25872e0cdb9444fa6507f15b58c08b0726ed462dd772b407186b5d7f1`.
The independent consumer accepted the exact ELF, provenance, dependencies and
resource contract. It requires 6,920 load pages plus the original 512 stack
pages, for 7,432 pages. Producer postcheck errors are empty. The outer owner
observed both build and consumer exit zero, all owned process groups gone,
unchanged fixed inputs, and no cleanup signals or errors.

| Actual panel evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Producer report | 10,137,170 | `870a8d35c59bf9d3cf21db2c26cb67d9824efd11d45d7dc2fbb02c62002152b5` |
| Independent consumer | 37,147 | `10777abff77e0664f2794bbf2fa8d0f3b03336a1b943c145a343ae375671570c` |
| Native ownership and execution report | 31,039 | `f1b15b62c463904a3ebc3990aa36137ad158728852174744cb7c92f3afeac3ef` |

This build result is **built and revalidated, not guest-run**. The subsequent
installation result is recorded separately below. Catalog admission, applet
execution and actual presentation have not passed.
Adding the unchanged 33,718,544-byte panel to the existing 89,818,322-byte
catalog exceeds the original 96 MiB common catalog bound before its additional
licenses. That packaging constraint needs an explicit solution. The executable
grant ledger is separately constructed for each process slot; adding the
compositor's and panel's page totals is not a valid test of one process's
16,256-page model limit. No capacity is raised from that incorrect aggregate
interpretation.

## Actual service capture v3: retained transport failure

The next actual run uses runtime v5 with the exact same OS v2, catalog v2,
settings v2, probe v2, machine configuration and runtime deadlines. A preceding
root invocation mistakenly supplied the literal review-hash placeholder. The
immutable launcher's input check rejected it before creating output, changing
native state or starting a child. That caller error is retained in a separate
preflight receipt (`3fcfc5136553c7e43605e8a5956f0024729061828e71793cb01f2a8b7cf506f6`);
only the caller's hash argument was corrected for the actual launch.

The actual capture records **FAIL** at
`Wayland socket readiness is not bound to the launched real client`.
Session-version and preparation phases passed their original reclamation
checks, and the actual launched client is PID 6. Its UART readiness line was
interrupted by the controller's own complete `posix list` response:
the prefix ends in `client_p`, followed by the command echo, three real status
rows and the shell prompt, then the suffix `id=6 protocol_verified=false`.
The command was issued at raw offset 54,102. Its echoed response block occupies
offsets 54,166 through 56,663; the continued marker's actual LF ends at 56,692.
The existing wide wait accepted the truncated first line, and the subsequent
strict marker parser correctly refused it. This is concrete transport
interleaving evidence; it is not proof of a wrong guest PID or permission to
relax the PID, path or full marker contract.

The daemon was not launched. No configuration/state/theme success or final
service arena/global resource proof was reached. `first_frame_deadline_failed`
is false because this run ended before that observation gate; it does not mean
the first-frame gate passed. Only the boot frame is present. QMP quit was
acknowledged, QEMU exited zero without forced termination, and all launch
inputs were preserved. Runtime and outer intervals are 87.208 and 213.233
seconds respectively, both including their documented validation work.

| Actual capture v3 evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| `summary.json` | 1,247,355 | `5a39e04326ba67276a244ac5de7a759a28e996dffeb117cd9beea70e6c8a4863` |
| `serial.raw` | 64,357 | `caff73b9ab1689c1fc3fb371307ef95c4ced458a10dad0f806376cf600df98e4` |
| Host launch receipt | 33,908 | `dc63e3f973c9bcdcb68dc959de1ab1754942bfd222f9ba186cdab727a60a351f` |

A separate controller repair was subsequently tested against these exact
retained raw bytes and command receipts. No later parser can retrospectively
finalize this run or fill its missing daemon, protocol and resource observations.

## Runtime v6: authenticated command-response projection

`tools/os_cosmic_services_runtime_v6.py` adds a narrowly bounded observation
view for an already-started `SETTINGS_PROBE` line interrupted by the
controller's own `posix list`. The raw UART and command ledger remain intact.
Only the exact authored command echo, one through eight strictly parsed full
status rows and the literal shell prompt can be projected out, before the
next issued command boundary. Unknown commands, malformed fields, ambiguous
or multiple interruptions, missing prompts and missing continuation LFs fail.

Every accepted projection carries the command index, issued offset, actual
echo-to-prompt span and its SHA-256, original marker-prefix hash, real
continuation LF and reconstructed-line hash. Finalization reconstructs the
view from the original raw bytes and requires the same receipts. The existing
nine protocol markers, owner/PID/path checks, current-slot final arena and
global resource baseline remain mandatory. The original monotonic deadline
is checked after the real LF; an incomplete final buffer is not a marker.

The 69 existing test methods and 13 unaffected controller bodies are preserved.
Fourteen new cases include the real capture-v3 interruption and rejection
boundaries. Actual installed validation reports 80 passes and three explicit
retained-fixture skips in the portable run, and all 83 passes with the exact
retained raw/command fixtures selected. All 83 local module origins are in the
repository, inputs remain unchanged and external-process events are empty.
The installed retained-suite receipt SHA-256 is
`2733fe691088151e4817328174ce80e0de0b7b4f3ad5049aac3bf2cf511ef75c`.

## Actual service capture v4: recurring genuine WatchConfig timeout

The actual run of runtime v6 again records **FAIL**. The OS, build manifest,
catalog, session installation, settings installation and probe input proofs
are exactly equal to capture v2. Session-version and preparation phases pass;
the real client PID 6 connects to the expected socket, and the broker binds
the main settings owner `:1.3` to daemon PID 7. These two observed markers
needed no transport projection in this run, so capture v4 does not itself
exercise the repaired interruption branch.

The first `WatchConfig` request, serial 43 to `:1.3`, receives
`org.freedesktop.DBus.Error.NoReply` after 10,249 ms with the original 10,000 ms
method limit. The real probe prints `SETTINGS_PROBE FAIL method-call` and
exits with code 1. The longer diagnostic line is itself interrupted by a
status response, but the method failure and Exited/1 evidence are unambiguous.
Configuration/state/theme markers, client success, targeted service cleanup
and the final global resource proof are not reached.

The last display snapshot still has zero proposals, submissions and
completions; only `boot.ppm` is saved. The unset first-frame failure latch
reflects the earlier protocol failure, not a successful frame gate. QMP quit
is acknowledged, QEMU exits zero without a forced kill, and launch inputs
remain unchanged. The producer interval is 121.043 seconds and the outer
interval is 234.975 seconds; both retain their documented validation work.

| Actual capture v4 evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| `summary.json` | 1,263,845 | `fc36f06918349c6122a163b0215c32c742d9a67cb04f07c7fb1c469594fd449c` |
| `serial.raw` | 981,651 | `3cc20ccabaef4a62c4ac9cda0765e35b9103066c49bdf403cea3bdbc53c41e3b` |
| `commands.json` | 12,471 | `f663ecf61da0c5d5dd65f3eabd65855bdea1065a1d16dae6da229e36bee80d76` |
| Host launch receipt | 40,552 | `9be5a28cd0ca7bd4721250e62b951202c4a795468fff03b700dea4a90099675c` |
| Independent result review | 13,998 | `229c5a056239417a9b94eac621b7df83b252d70a8c6d5a2dcbe3960ac427a33f` |

One actual read-only `nm` invocation maps the retained daemon samples in both
runs to the same exact settings-v2 ELF. It completes in 0.481 seconds under
the original 30-second symbol-tool limit and native lease, preserving both
failed captures and all input bytes. Its report is 331,610 bytes, SHA-256
`b31010792f91351e09b07e133a75bd6c8efc8185690d74ba22817b58304b9947`.
All 39 owner-to-first-outcome samples in capture v2 and all 33 in capture v4
map to code symbols. The main thread, worker threads and broker continue
making progress; whole-dispatcher or whole-scheduler stoppage is not proved.
Symbol aliases at one address are not separate execution samples.

The successful run's first configuration result occurs before its initial
theme-export end marker. Therefore an unfinished initial export alone does
not explain the failed run. The exact request, interface-lock and channel
backpressure interaction needs separate source and execution evidence; no
longer timeout or automatic retry is credited as a fix.

## Actual panel installation and bootstrap catalog capacity

The new panel installer consumes the real build proof, installs the exact
33,718,544-byte ELF and all five full upstream licenses, revalidates the
pending prefix and publishes it atomically without replacing an existing
destination. Its independent installation consumer replays the original
build and complete installed-byte/mode checks. The six installed files total
33,772,227 bytes; no ELF stripping, feature removal or license omission occurs.

The actual installed host suite passes 27 cases: 19 installer and eight
capacity cases. These use explicitly synthetic fixtures and do not stand in
for the subsequent native installation. The real install plus independent
consumer completes in 55.516 seconds under a separate 300-second operation
limit. Both exit zero, all owned groups are gone, no cleanup signals are
needed and all fixed inputs remain unchanged.

| Actual panel installation evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Installation receipt | 5,896 | `e8ecfc22fa1c9a1bf52bf31f49d87df1a2d8da6e30cbedd604aed4b245863268` |
| Independent installation consumer | 6,265 | `b0ed2cf7b0f39b1d546965f053ce1e86da1178243131c6a0113c1c9cd698de7c` |
| Native execution and ownership report | 23,615 | `fd40e009acf703f04f996e8bbf1a54ca39fe4a40277b4194c824c3254a205d88` |
| Installed host-test report | 19,311 | `26b8708a85d3c6c50dea5161499edd8bf562d2798679cace1c32bf2c9b643824` |

Panel is **installed and independently revalidated, not guest-run**. Adding
its original files to catalog v2 would produce 152 entries and 123,590,549
bytes, exceeding the existing 96 MiB bound by 22,927,253 bytes. That bound
belongs to the kernel's bootstrap `include_bytes` catalog, not to a generic
filesystem volume. It is not raised. Header-only ELF tail/gap analysis also
does not establish a faithful fit: even the bounded optimistic layout remains
38,102 bytes above the catalog limit before derived metadata.

Native storage work is being scoped against the existing CyxiaOS block
service and its original AI admission, ownership, DMA and request budgets.
A small real disk-to-original-probe loading milestone must be distinguished
from a full-size COSMIC object loader. A host-mounted filesystem or an enlarged
bootstrap catalog is not claimed as native storage completion.

The private format/transfer candidate now passes 17 actual host cases in
5.061 seconds, including authenticated chunks, the complete original checksum,
stale owner/sector rejection, cancellation custody, the shared original I/O
window and two mutations of already transferred bytes. The first attempt
failed before compilation because its fixture lock included a transitive
dependency's development-only graph; the retained correction removes only
that edge and three unreachable local packages. Registry versions/checksums
and `--locked --offline` remain unchanged. The successful receipt SHA-256 is
`28deedc06cb5d92b876a8945fd70b3d8ed78315ffbf1f47105deed0adf5931e4`.
These synthetic host cases do not exercise a real disk, kernel grants or ELF
launch. The private provider is not applied to the kernel; actual Service,
Runner and OS-producer integration still needs its own build and guest proof.

## Applied compositor phase observation

A separately versioned producer and consumer retain the original three
patches and add a fourth patch touching four compositor source paths. The
observations cover `State::new`, EGL display/context setup, renderer and shader
setup, first render/readback, first real tile submission and completion of all
tiles belonging to that first render cursor. Black scanout is excluded.
Each of the 19 events is claimed at most once, with a 160-byte stack record
and at most 3,040 bytes of output. Failed writes are not promoted to evidence.
The timestamp is relative to an actual compositor-side `Instant`, not the
host launch clock or an input to any acceptance deadline.

The seven repository source/policy files are applied. Their actual installed
24-case pure suite passes with zero skips or external events and unchanged
sources; the report SHA-256 is
`fb8116768dabeaa91b27ba29435bfefdf4686001b29e183523eb5ba9db633793`.
The repository now also contains `tools/test_cosmic_comp_phase_v1.py`, with no
dependency on a private work directory. Its portable run passes 18 cases and
explicitly skips six canonical-source cases. Selecting
`CYXIA_COMP_PHASE_CANONICAL` with the original unpatched pinned source directory
passes all 24 cases. The suite reads only the 24 hash-bound preimages needed
to replay the three original patches and the new phase patch in memory; it
does not invoke Git, Cargo, a compiler or a native consumer. Its actual
installed retained-source receipt is
`b3d06c271b9c70026f97b4876c5174af4c413fc8d31eff17f004d8a7c50e75f8`.
All 29 loaded project modules come from the repository and the sources remain
unchanged. This source-window replay does not substitute for complete
upstream source-tree validation in the real producer and consumer.

The genuine new compositor has now compiled and passed its independent
consumer. The outer operation completed in 700.887 seconds, including a
670.833-second producer, under the original 3,600-second shared deadline,
two Cargo jobs and a 3 GiB build-directory byte limit. This byte limit is
enforced against files on disk; it is not a host-RAM limit. The private cache copy was
verified separately before compilation, with the original cache preserved.
All 65 fixed build inputs remained unchanged and the owned process groups
were confirmed gone without cleanup signals.

The preserved graph has 468 metadata nodes, two workspace members and the
original `backend-cyxia` feature; this is not a compiled-unit count. Complete
source verification covers 297 files, with the expected four-path phase
patch delta. The new ELF is 41,149,848 bytes and requires 8,330 load pages
plus the unchanged 512 stack pages: 8,842 pages in total. Relative to the
previous compositor, this adds 13,568 file bytes and three load pages within
the existing admission bound.

| Actual phase compositor evidence | SHA-256 |
| --- | --- |
| New genuine ELF | `9775e44263f6e76501741de55a9ef5b47792ed8b504f0e8e298004b681324517` |
| Producer report | `d5e4741df72eca97ce844c9ad94116f9bdc5dbba8dfa3e8e49a38ed0daf27e5f` |
| Independent consumer | `6e3eb14f2871d9a3009df8f991e48cf817cd707676cffb986c8dc898c576fe0e` |
| Build coordinator | `331eeb2cf6699e03d6de6954d8426bd2a8905bb65b32e2d878f5a25f2b0176db` |

This ELF has not yet run in the guest. The added policy files require a
fresh formal OS source-map build before another capture. A phase marker
records actual execution only when its complete write is observed; missing
output alone does not prove that the function was never entered. Completing
the first render cursor's scanout does not by itself establish a vblank or
a complete session.

## Settings v3: release the interface guard before bounded sends

Inspection of the exact settings v2 source and its pinned zbus dependency
found a concrete lock-lifetime hazard. The change-processing future keeps an
interface read guard while awaiting sends to the existing capacity-ten theme
channel. The mutable `WatchConfig` and `WatchState` methods require the
corresponding interface write lock. A blocked send can therefore delay
method dispatch while retaining the read guard.

The separately versioned v3 patch clones the existing watched-config and
watched-state `Arc`s in a short scope, drops the interface guard, then
processes the same change batch. It retains the existing map locks, bounded
channel, sequential awaits and signal order. Both previous source patches,
the complete upstream policy, all 11 workspace members, the 502-node
metadata graph and original resource limits are preserved. Only
`src/main.rs` changes in the new upstream source delta.

All 12 v3 source, producer, consumer, installer and test files have been
applied. Their actual installed suite passes 48 cases with no skips, errors
or external process events. All 39 loaded project modules came from the
repository, and the checked source inputs were unchanged. The installed
test receipt SHA-256 is
`7fd8c6f7451503948ac4da9616fdb399a364727c79c80431d2bc734ef0ea394b`.

A separate native host harness embeds the old and new production
`main_fut` bodies verbatim. Its first compilation failed with an E0282 type
inference error in the fixture adapter; that failed attempt is retained.
The v2 harness changes only that closure's explicit argument type. Its six
actual cases now pass: the old-source blocked-writer negative control, the
new-source released-writer case, shared watcher-map visibility, failed lookup
handling, mixed effect order, and capacity-ten backpressure preserving all
13 updates and signals. Compilation and execution completed in 1.030 seconds
under the original native lease, with all inputs and the runner unchanged
and both process groups fully cleaned up. The report SHA-256 is
`2b6e35b03e1a2d38a1f8aadf19d669b973e66274653e23a3702a5645cfeb7f62`.

The harness uses real standard-library read/write guards with deterministic
future adapters, not the real Tokio/zbus executor or the guest. It proves
the constructible lock interaction and the source correction's behavior;
it does not establish the cause of capture v4. In particular, the initial
theme export writes GTK/Qt paths outside the observed COSMIC configuration
watch prefix, so that export alone cannot be assumed to fill the channel.
The new genuine settings build started with the original two-job,
1,200-second and 1.5 GiB build-directory byte budgets. Its execution session
became unavailable before any producer or coordinator report was written.
The retained Cargo log ends during dependency compilation; no compiler
failure, timeout, OOM or successful build can be inferred from that fact.
The new installation and guest behavior remain unverified. All earlier
failed captures retain their original classification.

The repository includes the unchanged Rust fixture template and
`tools/generate_settings_guard_harness_v1.py`. It selects complete pinned
v2/v3 `src/main.rs` exports through explicit arguments, keeps all production
bodies verbatim, and rejects a different template, source hash, channel
capacity or six-case set. An actual installed generation using the new v3
producer's exported source reproduced the previously executed 28,944-byte
harness byte for byte, with SHA-256
`cbdbca97a9a581a678f0e57ff0e07dc777676dbdbd3398d3dbf89d04bb9779a0`.
Generation itself invokes no compiler or external process and does not count
as another execution of the six cases. From the repository root, with both
source exports available and a fresh output path:

```sh
python3 tools/generate_settings_guard_harness_v1.py \
  --baseline-main artifacts/v017-cosmic-runtime-20261117-next/settings-linux-v2-build-v1/source/src/main.rs \
  --candidate-main artifacts/v017-cosmic-runtime-20261117-next/settings-linux-v3-build-v1/source/src/main.rs \
  --output artifacts/settings-guard-regression-v1
```

## Runtime v7: fixed consumers for the next integration capture

The new runtime selects the exact phase-compositor consumer and settings3
installer. A local copy of the original six-image input validator changes
only the fixed compositor import, explicit references to the original helper
objects and a strict phase-proof check. It retains the original OS features,
broker identity, notification provenance, runtime assets and image admissions.
Its six-image catalog gate still uses the original base helper; the separate
service gate subsequently verifies all nine images. An old compositor proof,
settings2 receipt, failed independent consumer or observer-only success claim
cannot identify the new inputs.

The other 18 existing functions and classes are byte-identical to runtime v6,
including the protocol reconstruction, actual process-owner checks, final
resource baseline, capture driver and frame observer. The original 45-second
first-frame deadline, 120-second late observation, 240-second guest budget and
248-second outer watchdog remain unchanged.

Both new repository files are applied. The actual installed suite passes all
89 cases with zero skips and zero external process events in 1.480 seconds.
All 90 loaded project modules come from the repository; their sources and the
selected retained UART/command fixtures are unchanged. The suite retains all
83 previous test semantics and adds six cases for the new consumer boundary.
Its receipt SHA-256 is
`5c32d206336ad3ad81127fabe4d835111a6ae2a95ef9ace5a431c013377ffeb7`.
These are host regression results. No fresh runtime-v7 guest capture has run,
and the settings3 build, new catalog and new formal OS still need actual
terminal receipts before that capture can begin.

## Interrupted native execution and recovery boundary

The settings3 execution interface reports that its prior session is unknown.
The original native lease, cache build lock, SDK build lock, two Cargo cache
locks and target Cargo lock were all observed available. However, no final
owned-process cleanup receipt exists. The former process identities and
ancestry were held in that execution context's memory, so a process list or
the same numeric PID in a new context cannot prove their termination.

The incomplete build output and logs are retained. Its status is
`INTERRUPTED_NO_FINAL_REPORT`, with cleanup unverified; the unresolved native
owner remains recorded. The interruption observation SHA-256 is
`dbd02ef25d9ee001fceebb23e40e2487871f772c438f45c6afcadf9fb37fe2a7`,
and the independent recovery review SHA-256 is
`586e0104d952ec9418ffcaa2ea95a10a3e89bd0c2550c936865165f15218ec59`.
Subsequent work is limited to source review, pure tests and source publication.
A new native operation requires the original execution service's terminal
state or a supported confirmation that the exact old execution context and
all its tasks have ended. Such recovery would be recorded separately; it
would not turn this missing cleanup result into a successful build or test.

## Remaining acceptance work

The real session version path, successful exit and stage reclamation have
passed. The actual new settings probe has completed configuration/state
subscriptions and Changed signals, theme behavior, unsupported operations,
main/watcher ownership checks and client exit in capture v2. The same settings
ELF times out again in capture v4. Stable service progress and a fresh final
global resource baseline are still required to finalize the complete manual
service lifecycle. All four service captures remain failed records.
A manual component test does not establish the normal session-owned startup
and notification FD handoff chain.

Full delivery additionally needs native loading of the installed panel,
actual applet binaries and their native Wayland EGL presentation, complete rendering within the original first-frame
gate, notification registration and protocol behavior, visible content, input
behavior, session supervision and resource reclamation. The default panel and
dock contain 18 applet instances; this static inventory does not justify
silently increasing process, pipe or model capacities. No original runtime
deadline, image/catalog bound or resource pool is enlarged in this work.
