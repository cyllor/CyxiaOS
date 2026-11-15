# Genuine COSMIC session and native process supervision

This stage continues `6fe8597` on `CyxiaOS-V0.17`. A03 remains cancelled.
Complete OS and COSMIC session acceptance remain false. The port uses the real
pinned session, launch-pad manager and compositor; no mandatory service is
replaced with a test process.

## Measured baseline and process boundary

The unmodified cosmic-session 1.10.0 at
`8093b59bb1262b0612d814e6540ba936303f735a` builds with 125 selected target
dependencies and no optional systemd/logind/autostart. Its real guest version
command succeeds, but startup aborts at `src/comp.rs:154`: launching the
compositor returns ENOSYS. Version output is not session acceptance.

The explicit `cyxia-native` feature adapts launch-pad 1.0.1 at
`5b516ee6a012b5ad4a5acc0cf51b4472fc6733af` to Cyxia's existing 64-byte isolated
static-image spawn request. The original manager retains callbacks, delayed and
exponential restart backoff, restart limits and TERM/cancellation timeout logic.
Failed spawn returns before publishing a manager entry. This does not implement
general fork/exec or arbitrary pre-exec callbacks.

Three real pipes provide stdin/stdout/stderr. Only new parent pipe ends become
nonblocking; AsyncFd uses the real reactor. Ambient non-CLOEXEC and explicit
callback descriptors retain their numbers and shared open descriptions without
changing parent descriptor flags. The adapter merges environment overrides,
passes argv, inherits cwd, bounds all ABI input, searches PATH in order, waits on
real kernel receipts, and kills/reaps a live child on Drop. General concurrent
parent FD-table mutation is not a fork-equivalent snapshot.

The actual public-API guest probe covers 12,000-byte partial I/O and EOF,
FD/environment/argv/PATH/cwd inheritance, failed-spawn rollback, cancelled waits,
repeated status retrieval, KILL/Drop reclamation, closed-stdio collisions and the
real manager's callbacks, restart PID changes/limits, TERM timeout followed by
KILL, descriptor/environment refresh on restart, and reuse after failed starts.

## Cross-process signals and review regressions

The original positive-PID kill path returned ESRCH even for a live native child.
Requests now cross the Supervisor boundary after all AP user roots drain, and
carry the originating TID rather than borrowed target references. A cancelled
origin cannot send a deferred signal. The current real/effective/saved UID0
domain permits same-UID peers; parent identity remains the wait/reap authority.
The existing pending-signal machinery supplies real SI_USER sender identity and
handler/default delivery. Native non-Linux runners reject nonzero delivery.

The actual C probe verifies signal-zero existence without side effects, TERM
handler/sender identity, default TERM status, ignored TERM then KILL, same-UID
sibling delivery with non-parent ECHILD, invalid/unknown/dead targets, one reap,
pipe EOF and resource reclamation. No SA_RESTART semantics are silently enabled.

Independent source reviews caught two additional defects, both reproduced in
real guests before repair. `kill(0, 0)` falsely reported self success; unsupported
zero/negative process-group targets now return EOPNOTSUPP after signal-number
validation. Eager PATH validation rejected a valid executable when an unrelated
entry was too long; candidate bounds are now checked during ordered lookup.
Both valid-before-long and valid-after-long cases pass; an oversized explicit
path still fails with ENAMETOOLONG. Both review axes accepted the corrections.

## Cancellation callback status

A proposed 35 ms graceful-exit / 50 ms cancellation-timeout race did not reproduce:
that baseline run returned the real code 23 and passed. It is retained as a
successful boundary check, not claimed as a demonstrated timing defect.

A separate deterministic default-TERM case did expose the manager fallback:
the kernel recorded child PID 2 exiting with status 143, while the callback
reported 137. The native fallback now obtains the real cached wait receipt after
kill/reap and returns the code or `128 + signal`; errors are logged and reported
as unknown. Restart/backoff and cancellation timing remain in the upstream
manager. The ordinary backend keeps its original implementation. On the final image,
the actual manager reports TERM143, graceful23 and forced-KILL137; the complete
public-API lifecycle probe passes in 21.488 seconds with resource reclamation.

## Observed startup cost and actual handshake

The first adapted session retained a 10 ms waitpid poll. Its 180-second capture
expired while the compositor continued allocating and executing: 6,126 heap
pages, 28,730 preemptions and no thread admission denials. The parent issued
32,382 syscalls and entered 4,022 timed waits. All resources were reclaimed after
the diagnostic timeout; this failed capture is preserved.

The parallel dispatcher stops and drains peer APs after the first AP completes,
so frequent parent polling can repeatedly interrupt the compositor. A read-only
source/timeline audit identified this concrete mechanism. Waiting now checks
immediately, then backs off from 10 to at most 100 ms while retaining real kernel
receipts and cancellation-safe cached status. This remains polling, not a
synthetic process notification.

Under the same 180-second bound, the next real session received
`WAYLAND_DISPLAY=wayland-1` from the actual compositor and subsequently aborted
with the explicit missing `cosmic-settings-daemon` ENOENT. The observation,
expected failure and cleanup completed in 128.104 seconds. This is functional
startup evidence, not a performance qualification or completed desktop.
The panic uses abort; orphaned compositor cleanup in this integration capture
is performed by the observer. NativeChild Drop cleanup is separately verified
by the public-API probe and must not be confused with panic-abort cleanup.

## Reproducible source and limits

The generator checks both pinned commits, Git trees and every tracked blob,
exports the complete launch-pad tree including license/tests, applies the
adapter to that export, then rechecks original and support bytes before writing
its manifest. The ordinary build recipe selects the exact patch and effective
lock hash. Original cached sources are unchanged. Existing compositor/sysroot
builders and source-series tooling are unchanged.

The selected experiment uses one build job, a 512 MiB growth bound, 1 GiB free
reserve and 900-second invocation limit. The unchanged legacy ELF inspector
still runs before the declared 64 MiB image budget. The final session fits at
996 LOAD pages; SHA256 is
`94c0949ffab24f59c00aba4e4caaa71472dd1c9870a08daf083906762c896eb8`.
The original builder records wrapper hashes but not every underlying host tool
at build time; later validation does not retroactively establish those hashes.

The read-only origin validator binds the current recipe/profile, report, logs,
source export, original source/patch/support bytes, selected dependency trees,
SDK and recorded tool identities, Rust archives and curated ELF. Its result is
`VALIDATED_NOT_RUN`; actual guest evidence remains a separate requirement.

Eight global pipes and eight process slots remain bounded capacity limits.
Three pipes per managed child require measured capacity work before a complete
multi-service session. Late upstream signal-hook handlers still request
SA_RESTART, which remains unsupported. Real settings daemon, notifications,
panel, remaining applications, optional service integrations and full OS
facilities still require implementation and validation.

## Final verification and evidence

The final OS binds 1,121 source files to
`68c68cafae6331665b027391dd1b74f430c043120221547514ca8c836aaf2ce0`.
Ten final captures pass their stated scopes: native services, thread exit,
thread capacity, real D-Bus, configuration write/reboot, actual compositor
render/input/steady operation, native manager lifecycle, spawn/signals and real
session readiness. Final session observation/cleanup takes 126.359 seconds;
its explicit mandatory-service failure remains ENOENT / 134.

The unchanged compositor ELF
`de9c94b47387439414a410bf1a529d8e0a62047af614185889d47d7445b13ab2`
responds to actual mouse input with 751 changed scanout pixels and a cleared old
cursor. It stays active for 60.049681 seconds with ten threads and 12,225 heap
pages. Display completions advance 192 to 384; these count tile operations,
not frames. Broker names, image/heap pages, threads, open descriptions, shared
objects and anonymous grants are reclaimed. The configuration reboot uses the
same unchanged disk bytes and verifies recovered values.

The full workspace passes 1,475 tests; full-OS POSIX/AI passes 308, legacy large
POSIX passes 254, and x86 runtime passes 26. These groups overlap. Twelve origin
validator tests, exact patch reproduction/application, kernel layout validation
and the AArch64 graphics/large-memory kernel compile also pass. ARM is a compile
result, not a new guest replay.

The initial D-Bus regression caught an observer race: it recorded eight objects
while a prior client disconnect was still pending, then compared that against
seven after actual cleanup. The corrected observer records the sole broker's
baseline before any client and requires exact restoration with a bounded drain.
It retains leak detection and the genuine authentication/routing/name/cleanup
checks. The direct-display observer's first replay used the old helper signature;
that API error is also retained and is not classified as a compositor defect.
All ten selected final captures bind the corrected producer sources.

Six superseded kernel compilation caches were removed after verifying the
retained images against their receipts, freeing 1,019,183,104 bytes. Original
sources, build receipts, executable evidence and failed captures are retained.

[final-evidence.json](../../artifacts/v017-cosmic-session-20261115-r1/final-evidence.json)
binds 569 artifact files, final source identities, raw results, historical
failures, resource accounting and host logs. Its SHA256 is
`ab6ad442c8b67d1b6511f8ddb5bc1584eb7ad2883b4ad583e11c4a90c87c6e24`.
Independent Standards and Spec source reviews have no outstanding findings;
complete OS and COSMIC session acceptance remain false.
