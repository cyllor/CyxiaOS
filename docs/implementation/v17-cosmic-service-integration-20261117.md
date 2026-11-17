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

## Remaining acceptance work

The real session version path, successful exit and reclamation have passed.
Settings has reached its real owner/PID binding; the first WatchConfig response
and the corrected per-watcher ownership contract remain the immediate work.
Configuration/state subscriptions and signals, theme data, unsupported
operations and complete lifecycle reclamation still need actual guest proof.
A manual component test does not establish the normal session-owned startup
and notification FD handoff chain.

Full delivery additionally needs actual panel/applet binaries and their native
Wayland EGL presentation, complete rendering within the original first-frame
gate, notification registration and protocol behavior, visible content, input
behavior, session supervision and resource reclamation. The default panel and
dock contain 18 applet instances; this static inventory does not justify
silently increasing process, pipe or model capacities. No original runtime
deadline, image/catalog bound or resource pool is enlarged in this work.
