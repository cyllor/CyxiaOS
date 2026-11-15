# Nested epoll and actual COSMIC configuration startup

This continues the complete OS / COSMIC plan from `4355cc5` and specification
`docs/superpowers/specs/2026-11-15-cosmic-nested-epoll.md`. The same real source08
COSMIC ELF now advances beyond Wayland Display event-source registration to
configuration watching. Complete compositor rendering/input and desktop session
operation remain unverified.

## Mechanism

The shared POSIX OFD table owns the nested graph. Parent readiness reflects
deliverable child events without consuming them, advancing child fairness or
disarming child ONESHOT. Actual backend notifications propagate through the
graph even when the child was already readable. Sampling or collecting a
still-ready LEVEL child does not create another parent EDGE notification.
Drain, ONESHOT delivery, DEL and final OFD release update ancestor readiness.
Aliases and inherited descriptors preserve the original weak watch until its
last reference closes; reused numeric descriptors and slots do not inherit it.

`epoll/nesting.rs` validates the entire bounded graph, including disarmed
watches. Self-monitoring returns EINVAL; cycles and paths above five epoll
instances return ELOOP. Checking the whole graph includes existing ancestors
when adding an edge. No new allocation policy or capacity expansion is hidden
in this mechanism. The depth contract follows [epoll_ctl](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html).

`Process::epoll_sample` visits only the requested epoll's reachable subgraph,
children first. Backend callbacks run outside the OFD borrow, because the
kernel's socket/pipe/PTY wrappers publish notifications back into that table.
Returned samples update the current watch rather than overwriting callbacks'
pending state with an older copied watch. The kernel adapter uses this shared
path for epoll waits and poll of epoll descriptors on both ISAs.

The notification distinction was checked against Linux's `ep_done_scan`:
LEVEL reinsertion wakes direct waiters, not nested poll waiters. See the
[fixed Linux v6.12 implementation](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/eventpoll.c).

## Verification

Evidence root: `artifacts/v017-cosmic-nested-epoll-20261115-r1/`.
The final formal build is `os-build-01`, compiled source SHA256
`de61ea64f490eec7a57050c59097172d912395b9118f0375596c98b507565907`.
The actual musl syscall probe is 45,280 bytes, SHA256
`5010578e3ba5fc63ee795b65b680382de610cfc5f733a906eb3f04c881c0f68a`.
Its source, SDK libc/driver, ELF layout and exact read-only embedding are bound
and rechecked; modified source receipts and ELF bytes are rejected.

- Public Process tests first reproduced the rejected nested registration, then
  passed nonconsuming readiness and cycle rejection. A second RED reproduced
  acceptance of a six-instance path; the five-instance bound then passed.
  Five focused tests cover edges, ONESHOT, cross-owner depth, real pipe callbacks,
  unrelated-source exclusion, inheritance and generation reuse. A compile-time
  array-copy correction is retained separately from behavioral RED evidence.
- All 212 POSIX tests and 14 shell tests passed with the default layout; all
  212 POSIX tests passed with full-os. All 14 Python OS tests passed.
- `nested-epoll-01`: `OS_NESTED-EPOLL_PASS` in the actual four-CPU/1-GiB guest.
  Two complete executions pass LEVEL, INNER_ONESHOT, OUTER_EDGE, CYCLE_REJECTION,
  OFD_REUSE and SOCKET_TIMER. Each performs 183 syscalls and records one actual
  kernel wait. Real socketpair bytes and a 20-ms timer expiration are read back.
  Both runs reclaim every OFD/watch/epoll and all image, heap and thread resources.
- `native-01`: `OS_NATIVE_PASS`; preemption, expected user faults, FP/TLS, heap
  isolation/recycling and IPC. `cosmic-version-01`: two real version executions
  and the ported C probe pass.
- `flock-01` and `flock-reboot-01`: cold and same-disk recovery pass, including
  prior runtime sentinel expiry, ordinary durable data and two syscall-probe runs
  per capture. The shared capture refactor retains predecessor/disk provenance.
- `arm-legacy-check.log`: legacy ARM large-memory kernel compiles. This is not
  an ARM guest boot result. All native commands used the shared lease serially.

Standards review: no hard violation; one optional suggestion to centralize
future probe scenario metadata. Spec review: no confirmed code defect or scope
expansion. Actual guest evidence above completes this stage's runtime checks.
`progress.json` binds the final summaries and preserves both complete-OS and
complete-COSMIC flags as false.

## New observed boundary

`cosmic-startup-01` runs the unchanged 42,173,224-byte COSMIC image, SHA256
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
The earlier `Failed to init the wayland event source.` error is gone. The actual
process now panics at source08 `src/config/mod.rs:176`, where
`ConfigWatchSource::new(&config).unwrap()` receives `Notify` with OS error 38
(`Function not implemented`), then exits 134. Raw UART, registers, QMP and display
remain preserved; capture status stays FAIL and source identity is preserved.

The linked `notify 8.2.0` first calls `inotify 0.11.0`'s `Inotify::init`, which
invokes `inotify_init1(IN_CLOEXEC | IN_NONBLOCK)`. This path and the unsupported
syscall establish real configuration notifications as the next missing
capability. The logged syscall 89 is readlink and is not itself proof of the
inotify error. A locale warning also appears before the fatal notification
failure; it has not been substituted for that failure's cause.

Next implement actual inotify object/watch/event lifetimes and filesystem
mutation notifications, then verify the unchanged configuration watcher. Audit
the associated FD/epoll/thread requirements against the explicit full-OS profile:
the current two-epoll/16-FD limits are still unchanged. Socket pathname lifecycle,
actual session services and complete desktop interaction remain open.

## Reproduce

Use fresh output directories with the existing receipt-bound isolated catalog:

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-cosmic-nested-epoll-20261115-r1/sysroot \
  --output artifacts/nested-epoll-new-build
python3 tools/os_smoke.py --build artifacts/nested-epoll-new-build \
  --scenario nested-epoll --output artifacts/nested-epoll-new-run
```

The preserved `capture-startup.py` accepts a build directory and fresh output
directory for actual COSMIC startup. It retains genuine failures and never
certifies a session from version output or merely completing its capture.
