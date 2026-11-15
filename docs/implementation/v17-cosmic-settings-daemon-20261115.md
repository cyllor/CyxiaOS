# Genuine COSMIC settings daemon

This stage continues `1d62412` on `CyxiaOS-V0.17`. The selected daemon is
upstream 1.10.0 at `9e4ae69fc175191f15789d35423806ea0f093c9d`.
A03 remains cancelled. Complete OS and complete COSMIC session acceptance
remain false.

## Build and platform boundaries

The original builder could not select the root package by name: the dependency
graph also contains a Git library named cosmic-settings-daemon 0.1.0. The new
bounded component entry selects the actual root package ID from Cargo metadata
and preserves the complete exported source. The unmodified exact-package build
then failed in libspa-sys because target libpipewire-0.3 is unavailable. Both
failures are preserved; no stub native library replaces that dependency.

Ordinary upstream defaults keep audio and backlight features. The explicit
Cyxia profile omits currently unavailable PipeWire/Varlink and udev/DDC paths.
Exposed unavailable volume/brightness mutations return real D-Bus NotSupported
errors; unavailable brightness getters retain upstream's -1 sentinel. No audio
service is fabricated. Configuration/state interfaces, notifications, theme
logic and the Wayland client use the real upstream implementation.

The full pinned cosmic-comp-config package is exported with its license and
libinput enums separated from device integration, following the existing
compositor port. Geonames library types and embedded data remain real; its
ordinary default generator keeps its network/archive dependencies. Optional
randr resolution uses the exact revision in the compositor lock. Two actual
isolated offline lock resolutions and their deltas are retained.

The genuine wayland-sys 0.31.11 registry archive is verified against the original
Cargo.lock checksum, then every archive/extraction file is bound. An explicit,
default-off static-client feature fills the upstream function table with real
libwayland-client symbols, including C variadic and conditional entries. Other
modules and ordinary dynamic loading remain unchanged. The selected native
profile uses the actual static Wayland, ffi and xkbcommon libraries.

Missing system time services warn and leave the local theme watcher active.
A closed system event stream becomes pending; cancellation remains selectable
while theme setup backs off. Original SA_RESTART signal registrations remain
unsupported and now report their errors. Default TERM can terminate a process;
graceful signal-driven theme cleanup and SIGHUP restart are not qualified.

## Source integrity and retained failures

The generator validates both original Git trees and all tracked blobs, registry
archive/extraction hashes, and support inputs. The origin validator independently
checks complete original-plus-patch file contents, actual metadata package
selection, dependency sources, SDK, tool identities, Rust archives, ELF and logs.
Existing compositor, session and sysroot builder files remain unchanged.

An intermediate native compile exposed a misplaced brace in feature gating; its
failed source and log are retained. A later linked artifact was rejected before
publication because difflib omitted the missing-final-newline marker: a following
diff header became part of .cargo_vcs_info.json. The generator now emits the
marker, and a real git-apply regression checks added/changed files and the next
file boundary byte-for-byte. The corrected actual export matches all 97 files;
validation was not weakened to accept the damaged export.

The component build uses two jobs, a 1 GiB reserve, a 1.5 GiB growth bound and
1,200 seconds per bounded invocation. The existing legacy ELF admission check
still runs alongside the explicit 64 MiB image budget including a 2 MiB stack.
Compilation and all guests hold the shared native lease. Cache cleanup removes
only regenerable compilation output; original source, receipts, raw diagnostics
and retained executable evidence remain intact.

## Measured filesystem prerequisites

Actual direct03 and direct04 reached genuine Wayland exchange, then failed the
first configuration client call. The trace identifies exhausted namespace
capacity: `df` reports 64/64 nodes with only 546 data bytes; AI admission has zero
denials and nine capacity refusals. Increasing elapsed-time limits would not
address this. The pinned GTK CSS template also has a source-derived minimum of
4,104 bytes, above the original 4 KiB file bound, and uses real symbolic links.

The full-OS filesystem now provides 128 nodes and 8 KiB per file with a separate
256 KiB retained-data cap. Unlinked but pinned file content still consumes that
cap until its last handle closes. Growth rejection precedes mutation. Default
profiles retain 64 nodes and 4 KiB files. The maximum full-OS snapshot is 276,512
bytes, inside the existing 392,704-byte disk slots and 128-page staging buffer;
disk geometry is unchanged. Snapshots without links retain schema v1; v2 carries
real link records. Both schemas validate topology, targets, identities and total
payload before publishing recovered nodes.

Link expansion is component-by-component, bounded to 40 traversals, and preserves
relative targets, permissions, directory-FD ancestry and `..` order. Stat follows;
lstat/readlink/unlink/rename operate on the link. Open honors exclusive creation,
nofollow and dangling targets. Directory entries and inotify identify link nodes.
The x86 legacy and x86/ARM at-syscalls use the same policy. Immutable boot assets
remain protected. Binding a socket at a dangling link is rejected; unlinking a
link to a socket preserves the socket's actual name.

Independent review caught unwired directory-FD mutations and cross-namespace
link hazards; real guest coverage now exercises both. The first filesystem
probe also exposed an incorrect test assumption: musl readlinkat deliberately
uses a one-byte dummy for zero-size buffers and returns zero. The raw syscall
case now checks kernel EINVAL directly. Its original failure is preserved.

Actual filesystem-write-02 verifies absolute/relative links, truncating readlink,
EFAULT/ELOOP/exclusive creation, cycles, directory FDs, immutable assets and socket
boundaries, 8 KiB content, aggregate exhaustion without partial mutation, pinned
unlinked retention, 8 KiB reuse, node exhaustion/reuse and 70 retained test files.
After temporary capacity files are removed, the guest reports 106/128 nodes and
8,217 data bytes. Fsync commits a 20,121-byte snapshot with two device FLUSHes.
The subsequent filesystem-recovery-01 recovers the same link/content/70-file
state: generation 1, 42 reads, zero writes/flushes and unchanged disk bytes.
Both captures reclaim all process/open-description resources. There is no shell
checkpoint command; the existing storage trace calls the explicit fsync trigger
OPERATOR, which must not be confused with a manually injected checkpoint.

Existing AI weights remain unchanged. The enlarged metadata inputs extend beyond
the earlier training range; an exhaustive synthetic-rule comparison passes,
but this is not new empirical model training or performance qualification.

## Complete upstream theme defaults

After filesystem repair, the first call immediately after bus-name ownership
still timed out. A separate observation waited for the real theme startup marker
inside the unchanged 90-second startup budget; both WatchConfig and WatchState
then passed their unchanged ten-second RPC deadlines. The light-theme check
still failed: the mode file contained false, but only dark CSS existed. The
pinned library's empty Light configuration starts from its preferred dark
default. This is a missing system-data dependency, not a successful light export.

The explicit `theme-defaults` generator links the actual cosmic-theme and
cosmic-config libraries from the independently validated daemon build. Separate
fresh guests call the pinned upstream light/dark constructors, write all 39 keys,
read them through the genuine configuration library, write again and compare
every canonical byte. This deliberately accounts for upstream color conversion
from floating point to eight-bit hex. Directory sync and temporary-directory
cleanup precede the successful export. Both processes exit zero and reclaim all
objects: light 48.549 seconds / 8,966 bytes, dark 49.684 seconds / 8,963 bytes.

The installer verifies source Git blobs, library/SDK/tool provenance, generator,
successful raw captures and all generated bytes. The committed assets contain
78 keys plus the pinned MPL-2.0 license, totaling 34,654 bytes. They are installed
only under `/usr/share/cosmic` and `/usr/share/doc/libcosmic`; existing user keys
keep precedence. A review caught and fixed an output-path overlap that could
modify preserved build inputs before a failed post-copy check. The installer
now rejects that path before creating its output.

The full-OS immutable catalog permits 256 entries; the default profile retains
128. The actual final catalog has 143 entries (26 executables and 117 data files).
This does not increase mutable file-node, retained-data, path or disk budgets.
The daemon ELF remains unchanged throughout the filesystem/default-data fixes.

## Runtime verification

`settings-final-03` passes on the actual final image in 162.629 seconds including
startup, observation, cleanup and input revalidation. Genuine D-Bus ownership,
WatchConfig/WatchState replies, Changed signals after fsync/readback, GTK3/GTK4
symlinks switching from real light CSS to real dark CSS, and NotSupported replies
for VolumeUp/VolumeDown/IncreaseDisplayBrightness all pass. Watch names disappear
after the client disconnects while the daemon remains alive. The real Wayland
registry exchange includes the keyboard-layout manager and callback completion.
Local theme watching stays active despite the absent system time service.

Independent review found that an earlier observer could accept an already
buffered readiness marker after its deadline. The separate bounded observer now
checks monotonic time after every ownership query and after readiness. The final
run records compositor startup 55.215 seconds (limit 120), settings startup
46.012 seconds (limit 90); the real client keeps its ten-second RPC timeout.
Earlier functional captures and the review finding remain preserved.

The final guest reports 90/128 RAMFS nodes and 12,932 retained bytes. The settings
daemon has four live threads (peak five) and 2,173 heap pages (peak 2,738) after the
client. Operator termination then reclaims all process image/heap/thread resources
and restores the all-zero open-description/inotify/epoll object baseline. This
does not qualify graceful signal shutdown. Waiting for theme startup also does
not qualify RPC responsiveness immediately after bus-name ownership.

Final compiled source identity after the profile-aware probe correction is
`6b80ebe9b93818d40a357f66031b77a521850266dca5373780c5170c27a39b8a`
(1,218 files). Genuine settings ELF is
`48514109ba52208169ee4d04dc3002c6dda50d5d59cbcaaa445a679d9b2cd189`;
the separate defaults generator is
`06bd18712c13186acb4983186d2691765269694be4c02c6e46b1e56d6378e046`.
The generator is an explicit data-production tool, never a replacement service.

## Final regression and session boundary

The final native regression first exposed an outdated C test: its hardcoded
4 KiB short-write assertion returned source line 89 under the new 8 KiB full-OS
profile. A dedicated negative capture confirms that exact exit and complete
reclamation. The C build now supplies the selected filesystem bound on both
architectures. The test still requires a four-byte short write at limit-minus-four
and EFBIG on the next byte; neither assertion was weakened. Actual x86 full-OS
and legacy-profile native runs both pass, and the updated ARM build passes.

On the final source, native syscalls, inotify, D-Bus, fsync and the genuine
configuration library pass separate guest regressions. The filesystem write and
same-disk recovery repeat also passes: 111/128 nodes, 8,217 retained bytes,
20,681-byte generation-1 checkpoint, two FLUSHes; recovery performs 43 reads,
zero writes/flushes and leaves the disk byte-identical. The additional five
directory nodes come from the installed theme-data directories.

Host verification after filesystem repair passes 1,492 workspace tests,
319 full POSIX/AI tests, 265 legacy-large POSIX tests and 26 x86 runtime tests.
These groups overlap and must not be added as distinct coverage. Full filesystem
tests require `RUST_MIN_STACK=16777216` for their large stack-resident test objects.
The earlier direct filesystem suites pass 32 default / 35 full-profile tests.
All 36 final Python build/provenance/install contract tests pass; kernel layout
checks 201 Rust files and 183 recorded moves. The final ARM graphics/large-memory
build includes the corrected native C boundary.

The original `session-final-01` receives the real compositor environment and
spawns settings as PID 7, then aborts with 134 when notifications launch returns
EAGAIN. Its observer initially reports FAIL because its error classifier did
not include that actual resource error. That report is preserved, with a separate
read-only classification receipt; it is not rewritten as a successful session.
The pipe ledger records seven requests, six approvals, one model denial, zero
mechanical-capacity failures and errno 11. The pinned admission policy requires
three free slots for a one-pipe request; with eight total slots and six live
pairs this leaves a two-slot reserve. This free-slot count is a source/ledger
deduction, not a directly logged free-count snapshot. Notifications fails before
its native spawn request, so its executable availability was not tested.

The final same-source `session-final-02` records the identical boundary with a
strict observer: 107.147 seconds from the session command to exit (limit 180),
132.569 seconds for the entire capture including cleanup and revalidation. It
verifies the live session-parented settings child, the exact pipe-denial ledger,
exit 134 and zero remaining resources. Its status is
SESSION_NEXT_BOUNDARY_OBSERVED, never complete-session PASS. The independently
observed direct service functionality and session launch boundary are separate
claims.

Local evidence root: `artifacts/v017-cosmic-settings-20261115-r1/`. The final
`final-evidence.json` binds 2,428 retained files / 1,716,189,457 bytes, including
negative captures and build failures, with SHA-256
`ab8d1e048febc928b7523ff13e21278be5a0870fa83bac1a17e08944f2bf692e`.
Its capture receipts bind current source, producers, actual ELF bytes, raw serial,
QMP, object accounting and disks. Regenerable target caches and the index/audit
itself are excluded. Five cleanup receipts retain the original executable/source
identities; only superseded compiler caches were removed. Standards/Spec reviews,
their resolved findings and the final independent hash audit are retained there.

Standards review found no documented-rule breaches. One nonblocking maintainability
observation remains: shared POSIX open and the immutable-asset syscall adapter
compute the same final-link flag policy separately. Spec correctness findings
(directory-FD wiring, socket/link collisions, immutable assets, capacity coverage,
installer output overlap and timing acceptance) were corrected and verified.

Complete OS/session acceptance remains false. Next work is the multi-service
pipe budget and genuine notifications, followed by panel/applications and
remaining OS services.
