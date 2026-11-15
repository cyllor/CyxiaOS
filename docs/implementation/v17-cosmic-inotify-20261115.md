# Real filesystem notifications for COSMIC

This continues the complete CyxiaOS / COSMIC plan from `508da71`, against
`docs/superpowers/specs/2026-11-15-cosmic-inotify.md`. The prior unchanged
compositor stopped at `ConfigWatchSource::new` with Notify/ENOSYS. This stage
implements real committed filesystem observations and Linux inotify objects.
Complete OS and complete desktop-session verification remain separate claims.

## Shared mechanisms

The filesystem owns a runtime-only 128-record journal. Each record binds stable
inode and parent identities, actual names, object kind and committed action.
Rename emits paired nonzero cookies; unlink keeps an orphan's identity until its
final pin is released. Failed mutations publish no changes. Recovery rebuilds
parent identities while preserving the existing checkpoint format. Journal
loss is observable, and watches never pin filesystem nodes.

Each inotify OFD owns up to 64 watches and 64 ordinary queued events, with an
additional reserved overflow record. Independent masks, MASK_ADD/MASK_CREATE,
ONLYDIR, DONT_FOLLOW within the existing no-symlink VFS, EXCL_UNLINK, ONESHOT,
IGNORED, adjacent event coalescing and Q_OVERFLOW are implemented. Watch IDs are
not reused within an instance. Lost journal history emits overflow and removes
dead watches. Duplicate, inherited and SCM_RIGHTS references share the same
queue; last close reclaims watches, events and weak epoll registrations.

Events have the Linux 16-byte header and name padding; short buffers never split
a record. FIONREAD reports queued bytes without consuming events. Empty blocking
reads use the existing interruptible, generation-bound syscall retry path.
New records wake nested EDGE epolls even while the queue remains readable.
Filesystem synchronization occurs before/after Linux syscalls and before the
supervisor checks waits, including mutations made through the OS shell.

The syscall adapters map both x86-64 and ARM to the same mechanism. Legacy x86
inotify_init normalizes flags to zero. inotify readv follows the legacy Linux
read operation per iovec, rather than combining short buffers into a record.
The compatibility baseline is [Linux v6.12 inotify](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/notify/inotify/inotify_user.c).

Creation installs permissions atomically with the new inode, preserving all
0o7777 mode bits without generating a spurious chmod event. Directory enumeration
publishes ACCESS, including successful EOF. These paths use the same journal as
ordinary open/read/write/chmod/final-close operations.

## Explicit object capacity

Source08 configuration and theme initialization require at least seven notify
watchers: 35 retained FDs, nine epolls and eight threads including the main
thread, before later service dependencies. The selected full-OS metadata profile
is explicit and logged at boot:

| Resource | Legacy | full-os-objects-v1 |
|---|---:|---:|
| FDs per process | 16 | 64 |
| Shared OFDs | 128 | 256 |
| Epolls per owner / global | 2 / 16 | 16 / 64 |
| Inotify instances per owner / global | 2 / 8 | 8 / 32 |

Global pools are shared bounds, not reserved per-process allocations. OFD
identity width and bounded epoll bitsets remain checked. The existing eight-thread
scheduler/model limit remains unchanged; more threads require a separately
validated capacity change. Boot metadata is not represented as an AI admission.

## Host verification and review

Evidence root: `artifacts/v017-cosmic-inotify-20261115-r1/`. Real behavioral RED
logs cover filesystem emission/order/recovery, initial inotify ENOSYS, descriptor
capacity, both ISA mappings, directory deletion flags, SCM_RIGHTS lifetime,
creation events, directory ACCESS and preservation of special mode bits.

The final host checks pass 25 filesystem tests, 229 legacy POSIX tests, 230
full-OS POSIX tests, 14 shell tests and 10 Python OS checks. The focused mode-bit
regression was rerun after its review fix. The inotify suite contains 16 public
behavior tests. No native command overlaps another native command: all use the
shared lease.

Standards review found no remaining hard violation. Spec review found creation
ATTRIB and directory ACCESS gaps, then a mode-bit regression in the fix; each was
reproduced and corrected, and the final review closed all three findings.

## Actual x86 execution

Formal `os-build-01` uses source SHA256
`e17b4473d4ad1865fd8eca1937bfe2b3ab18e0f7785ef7cbb6f1f96716974c52`.
The 67,256-byte musl inotify probe has SHA256
`ea2a70ea52639476f60552f49a5c0c7b0222e9c065117a76164087de1607f3d7`.
Its receipt binds source, SDK libc/driver and ELF layout; the capture verifies
exact embedding once in a read-only kernel LOAD and rechecks all inputs.

- `inotify-01`: OS_INOTIFY_PASS. Two actual executions each pass FLAGS_MASKS,
  FILE_EVENTS, RENAME, WATCH_LIFETIME, UNLINK_POLICY, RECORDS_DUP, VECTORED_READ,
  READINESS and OVERFLOW. Each then passes BLOCKING_READ, INTERRUPT and
  RETRY_REUSE. Host gates wait for the real kernel wait counter to increase
  before allowing the parent to modify, signal or replace the descriptor.
  Both runs record 24 waits; syscall totals are 1,368 and 1,369. Every OFD,
  epoll, inotify instance/watch/event and image/heap/thread resource is reclaimed.
- `native-01`, `cosmic-version-01` and `nested-epoll-01` pass the existing native,
  real compositor version and nested epoll guest regressions.
- `flock-01` and `flock-reboot-01` pass cold and same-disk recovery, including
  expiry of the previously durable runtime sentinel and preserved ordinary data.
- `arm-legacy-check.log` compiles the legacy ARM large-memory kernel. This is
  compilation evidence, not an ARM guest boot result.

## New observed startup boundary

`cosmic-startup-01` runs the unchanged 42,173,224-byte COSMIC ELF, SHA256
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
The ConfigWatchSource Notify/ENOSYS panic is gone. Actual startup now continues
through configuration to the Cyxia EGL backend, logs DRI2 driver-initialization
errors and then the Smithay dmabuf-extension warning. It ends as `Fault code=139`
with signal 11, `esr=0`, `far=0`, after 532 syscalls. The capture's
OBSERVED_PROCESS_END status only records that outcome; it is not a successful
compositor session. The fault's exact cause is not established by these logs.

The process reached six threads with no thread-admission denial, and teardown
reclaimed all observed object/image/heap/thread resources. This does not prove
that the complete later desktop workload fits the unchanged eight-thread limit.
NoConfigDirectory warnings also remain: successful inotify mechanics do not
supply the missing session configuration and assets. The next work is to locate
the first EGL/context fault, supply real configuration/runtime inputs, and then
validate compositor rendering/input and the remaining session services. Socket
pathname lifecycle remains a separate open item. Full OS and COSMIC-session
flags remain false in `progress.json`.

## Reproduce

Use a fresh build/output path and the preserved isolated catalog:

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-cosmic-inotify-20261115-r1/sysroot \
  --output artifacts/inotify-new-build
python3 tools/os_smoke.py --build artifacts/inotify-new-build \
  --scenario inotify --output artifacts/inotify-new-run
```

The evidence root's `capture-startup.py` accepts the build directory and a fresh
output directory. Raw UART, QMP, registers, display and process/object snapshots
are retained even when the actual compositor fails.
