# V0.17 real session D-Bus and COSMIC startup dependencies

Implementation record for the approved complete CyxiaOS/COSMIC plan.
Evidence root: `artifacts/v017-dbus-20261115-r1/`. The session broker, socket
namespace, durability lifecycle and same-disk reboot captures pass on the
identified kernels below. Rebuilt COSMIC also passes real bus registration,
rendering, mouse input and 60-second observation. Historical results identify
their own captures; they are not
automatically evidence for a later combined source tree. A03 remains cancelled.

## Real upstream broker and authentication

[`ports/dbus/manifest.json`](../../ports/dbus/manifest.json) pins upstream
D-Bus 1.16.4, archive SHA-256
`d08b05526c2cb7966a5fb79210d6112b1aca3d135f315c1b302e14b4b0297dac`.
[`tools/build_dbus.py`](../../tools/build_dbus.py) builds the real static
`dbus-daemon`, `dbus-send`, `dbus-uuidgen`, libdbus client probe and Expat dependency
in a fresh output directory. It preserves the input SDK, retains source/build
provenance, and uses the shared native execution lease. Its build result alone
does not establish guest execution.

The foreground daemon listens at `unix:path=/run/user/0/bus` using the checked
session configuration. The runtime validates the existing private UID 0 runtime
directory and provides `DBUS_SESSION_BUS_ADDRESS` to the relevant catalog
programs. Authentication remains upstream EXTERNAL against actual socket peer
credentials. The policy admits the implemented UID 0 domain; it does not accept
an arbitrary claimed identity. There is no replacement protocol server or
authentication-success shortcut.

The recipe disables traditional activation, systemd integration, X11 autolaunch,
launchd, and daemon inotify configuration watching. The session configuration
has no service directories, activation helper, includes or system policy. Its
limits include 16 completed connections, 8 incomplete connections, 1 MiB
messages, 8 FDs per message, and 16 pending incoming/outgoing FDs. These limits
sit above the separately bounded kernel socket and descriptor mechanisms.

Pinned zbus 5.16.0's Unix transport treats `SO_PEERPIDFD` as optional only when
the kernel returns `ENOPROTOOPT`. Unknown socket options and wrong levels now
return the real errno 92 rather than `ENOSYS`; actual `SO_PEERCRED` snapshots,
`SO_TYPE`, buffer sizes and `SO_ERROR` retain their implemented behavior. This
was a source-derived prerequisite checked by a real target-musl ABI probe; it
must not be presented as a captured original COSMIC authentication failure.

## Durable fsync and fdatasync

The Linux ABI decodes x86-64 syscall numbers 74/75 and AArch64 82/83 into
`Fsync`/`Fdatasync`. [`user/files.rs`](../../kernel/src/desktop/user/files.rs)
validates the real descriptor and accepts persistent regular files or
directories. Both calls request the stronger existing whole-RAMFS checkpoint.
They do not acknowledge success merely because a write reached memory.

[`storage.rs`](../../kernel/src/desktop/storage.rs) stages a coherent snapshot
synchronously on CPU0, then executes the existing durable transaction through
the actual VirtIO block device: payload writes, payload FLUSH, header write,
header FLUSH. Only successful completion of the second FLUSH advances the
active durable generation. `Wait::Checkpoint(generation)` blocks the calling
thread until `checkpoint_complete` reports that generation durable or returns
an actual error. Filesystem staging, storage admission, operation pacing and
grant release retain their existing mechanisms and models.

If another commit is active, the caller waits using the existing syscall retry
path. The retry binds the descriptor number to its open-description generation;
after wake it must obtain admission and stage a fresh snapshot. Finishing the
older transaction cannot acknowledge this caller's later writes. A closed or
reused descriptor cannot silently retarget the retry. Once staging is admitted,
the wait owns the generation and no longer needs to look up that descriptor.
Signal interruption or process termination drops the caller's wait while the
already admitted global storage transaction continues.

Immutable boot files and anonymous memfd storage have no persistent backing
to flush and use explicit no-dirty-state handling. Pipes and sockets return
`EINVAL`; invalid descriptors return `EBADF`. Absent, failed and read-only
storage produce real errors. A directory fsync snapshots the whole RAMFS;
this implementation does not provide per-inode writeback or automatic saving.

Upstream `dbus/dbus-file-unix.c` writes and fsyncs a temporary machine-ID file,
closes it, then renames it to `/etc/machine-id`. Its successful temporary-file
fsync alone does not make the subsequent rename durable. The probe's explicit
final root-directory fsync includes that rename in a later snapshot. Same-disk
reboot evidence must observe the final generation and recovered contents;
machine-ID generation succeeding is insufficient on its own.

## Shared null-device and socket pathname semantics

[`crates/posix/src/lib.rs`](../../crates/posix/src/lib.rs) exposes the existing
Null EOF/discard backend through `open_null` and the shared `/dev/null` path.
Native Process operations and Linux adapters use the same character-device
metadata and flag checks. Real `/dev` traversal permissions remain effective;
the reserved boot child prevents removal of its parent. No regular RAMFS file
stands in for the device.

The bounded device entry is immutable: mkdir reports `EEXIST`, bind reports
`EADDRINUSE`, connect reports `ECONNREFUSED`, and unlink/chmod/rename involving
the device report `EROFS`. Using it as an intermediate path or directory reports
`ENOTDIR`. This is an explicit one-device namespace, not mutable devtmpfs.

[`crates/posix/src/unix.rs`](../../crates/posix/src/unix.rs) retains pathname
binding metadata separately from endpoint lifetime. Each pathname gets a
stable inode derived from its original generation-checked handle in a tagged
high-bit namespace, plus the mode captured from the binding process's umask.
Kernel stat and chmod consult this metadata after real path resolution.
Abstract addresses have no pathname metadata. Socket mode changes are real;
new connections check the implemented UID 0 owner-write policy.

Closing a listener preserves its directory entry, inode and mode. Connection
then fails with `ECONNREFUSED` until a listener is rebound after explicit unlink.
Unlink removes the entry while preserving existing stream lifetimes. Rebinding
the same name allocates a different identity. This allows upstream dbus-daemon's
existing `stat`/`S_ISSOCK`/`unlink` startup sequence to clear a stale socket;
the kernel does not automatically unlink on close.

The Linux adapters also prevent RAMFS overlays on socket entries. Opening a
socket pathname returns `ENXIO`, exclusive creation returns `EEXIST`, and
directory opening returns `ENOTDIR`. mkdir returns `EEXIST`, including its
allowed trailing-slash spelling. Rename with either endpoint in the socket
namespace returns `EOPNOTSUPP` (95) before mutating either name. Cross-namespace
atomic rename is not implemented; ordinary regular-file rename still uses its
existing implementation. Legacy x86-64 chmod syscall 90 is normalized to the
same real chmod adapter used by fchmodat.

## Sixteen full-OS threads without changing admission models

The full-OS profile now reserves sixteen 4 KiB context slots per Runner; legacy
builds retain eight. The shared signal page and spare page make the actual
reserved envelope eighteen pages for full OS and ten for legacy. Thread
admission still requests one context credit from memory model 8193 and preserves
its two-credit floor. User stacks and anonymous pages remain independently
backed and admitted through their existing memory mechanisms.

The new `full_os_thread_dispatch_policy` admits at most sixteen candidates and
uses the same per-candidate CPU ranking and starvation guard. The process
selector remains bounded to eight. Candidate count is not a new model feature;
the existing weights and model identities are reused. This slice does not
retrain the CPU/memory policies or enlarge the shared anonymous physical pool.
Thread-group reset clears records in place rather than constructing a 68 KiB
temporary on the 64 KiB kernel stack.

## Presentation watchdog after real tile progress

The native COSMIC backend retains bounded, resumable tile submission. The new
five-second watchdog measures absence of a completed tile, rather than total
elapsed time for an entire frame. Only a successful native tile completion
renews the deadline. `EAGAIN`, `EINTR`, event-loop dispatch and retry attempts
do not renew it. A stalled or permanently failed presentation remains failed;
partial frames cannot emit frame/presentation completion. Normal scanout and
the session-lock black frame use the same cursor and watchdog.

The source-clock tests exercise a frame whose tiles genuinely complete every
four seconds over twenty seconds, continuous busy/interrupted attempts until
timeout, and terminal failure. `presentation-watchdog-red.log` preserves one
failure with 13 other tests passing; `presentation-watchdog-green.log` records
14 passing tests. `presentation-patch-tests.log` additionally records 27
generated-backend tests, four selection tests in each of four feature builds,
and three Python patch tests passing. These host results do not substitute for
rebuilding the actual COSMIC ELF and observing it with the live guest broker.

## Retained failures and observations

All paths in this table are relative to the evidence root above.

| Capture/log | Observed result and scope |
| --- | --- |
| `socket-red-full/serial.raw` | Optional `SO_PEERPIDFD` returned errno 38 instead of 92. This is the exact real ABI RED, separately from daemon startup. |
| `dbus-run-01/serial.raw` | Unchanged upstream uuidgen exited 1: temporary machine-ID file synchronization returned “Function not implemented”. |
| `dbus-run-02/serial.raw` | After real fsync, the daemon failed to open `/dev/null` while preparing standard FDs. |
| `dbus-run-05/serial.raw` | After a successful first broker run, restart failed with address in use. Retained socket bindings were invisible to stat, so upstream did not unlink them. |
| `null-namespace-red.log` | Public Process tests recorded 5 passes and 4 behavioral failures: missing native path behavior, hidden directory creation, rename collision and incorrect traversal errors. |
| `socket-namespace-red/serial.raw` | Real bind/listen/stat passed, then mkdir over the socket returned 0/errno 0 instead of `EEXIST` (17). |
| `dbus-final/summary.json` | Historical `OS_DBUS_PASS` on `os-build-04`: two broker runs, upstream ListNames, rejected false EXTERNAL identity, actual PID/UID queries, ownership conflict, method routing and release/disconnect checks. Both runs were subsequently terminated and accounted for. It is not the final combined-tree replay. |
| `thread-capacity-final/summary.json` | `os-build-05` runs two cycles at 16 live threads, rejects thread 17 with `EAGAIN`, joins/reuses 15 worker slots, and reclaims resources. |
| `cosmic-bus-01/summary.json` | Historical FAIL with unchanged COSMIC ELF: notify SendError panic and exit 134; UART records peak 8 threads and one thread denial. No live render progress was accepted. |
| `cosmic-bus-02/summary.json` | Historical FAIL after thread expansion: peak 10 threads, no thread denials, then the old whole-frame presentation deadline stopped the backend after 170 completed tile submissions. Tiles are not complete frames. |
| `fd-share-verified/summary.json` | Retained FAIL at the retry-gate timeout, despite earlier individual FD-sharing checks passing. The directory name does not make this a passing capture; `fd-share-verified02` is the subsequent passing run. |

The two historical COSMIC-plus-bus captures preserve their input identity and
use the original compositor ELF
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
The watchdog change requires a new ELF and separate identity evidence.
`cosmic-bus-02` still reports a missing system D-Bus endpoint. The upstream
broker also reports that raising its FD limit to 65536 is denied; successful
bounded broker protocol checks do not mean that resource limit was granted.

## Verified kernel replay and durability recovery

The following summaries identify `os-build-08` and compiled source digest
`ef6cfc0851b2a631959106fc3fca8a3033c5a933e206ce004f1a0cf666804d1e`.
Each reports PASS and QEMU return code 0, and retains producer/input hashes,
UART and command transcripts. These are the final kernel/service replays for
this record; the compositor binary with the watchdog change is separate.

| Capture | Verified behavior |
| --- | --- |
| `socket-options-verified` | Two complete guest executions pass socket options, real peer credentials, pathname mkdir/rename/open errors, preserved regular-file data, chmod, closed-binding metadata, unlink and rebind with a new inode. Both exit 0 and return object tables to empty. |
| `fd-share-verified02` | Descriptor sharing, unlink lifetime, event/epoll/socket descriptions, peer credentials, creator exit, atomic reuse and all six pipe/event/PTY read/write retry gates pass. |
| `fsync-verified02` | Real file fsync/fdatasync, rename and directory fsync, bad/closed/non-file descriptor cases, explicit volatile/immutable behavior and final root fsync pass. |
| `fsync-concurrent-verified02` | Killed admitted caller, concurrent fresh snapshots, interrupted busy retry, descriptor reuse and interrupted admitted wait pass. Later saves succeed after cancellation. UART reaches durable generation 10 with 20 actual FLUSH completions. |
| `dbus-verified02` | Two real upstream daemon cycles pass ListNames, rejected false EXTERNAL identity, PID/UID queries, ownership conflict, method routing and release/disconnect, with final machine-ID namespace checkpoint. |
| `fsync-concurrent-reboot` | The same disk recovers generation 10 and the concurrent probe verifies retained file contents. |
| `dbus-reboot` | The same disk recovers generation 5 with the identical machine ID and committed rename contents; two further daemon/protocol cycles also pass. |
| `fsync-reboot` | The same disk recovers generation 4 and the ordinary fsync probe verifies committed file contents and the absent temporary name. |

For all three reboot pairs, the producing run's `disk_after_sha256` equals the
reboot run's `disk_before_sha256`. The D-Bus pair's recorded machine IDs also
match. This ties recovery to the actual previous guest disk rather than a new
disk or host-created stand-in. The earlier `thread-capacity-final` result uses
`os-build-05` as explicitly recorded above and is not silently relabelled as
an os-build-08 thread-capacity execution.

## Rebuilt COSMIC with the real session bus

`cosmic-build` completed the actual offline release compile/link in 4m53s.
Its linked ELF is 42,169,384 bytes, SHA256
`de9c94b47387439414a410bf1a529d8e0a62047af614185889d47d7445b13ab2`;
patched source-tree SHA256 is
`0b37b315a3150dec5921aee1845a698e62bafed67d533bc4175fc82d0059d595`.
The receipt binds the exact current presentation module and patch series.
The generic build tool still rejects its old 16-MiB LOAD profile after linking;
that report remains `failed`, `link_completed=true`, `target_linked=false`.
`cosmic-link-measurement.json` separately records the static x86 image's
8,546 LOAD pages and full-OS range. No legacy admission check was weakened.

`os-build-09` embeds these exact bytes and runs the existing full-OS loader.
Its compiled source digest equals os-build-08; only the curated compositor
ELF/catalog input differs. `cosmic-bus-03` reports
`OBSERVED_RENDER_INPUT_STEADY`, identity preserved and QEMU exit 0:

- Genuine upstream D-Bus owns the socket; actual COSMIC registers
  `com.system76.CosmicComp` and `org.freedesktop.a11y.Manager`.
- The observer waits for all 192 initial display tiles. Real `(320,240)` mouse
  input moves the cursor bounds from `(0,0)-(19,28)` to `(319,239)-(339,268)`.
  Exact PPM comparison finds 751 changed pixels, clears the old cursor, and
  shows no changes outside the old/new cursor regions.
- COSMIC stays active for 60.046953 seconds after input, with ten threads and
  12,199 anonymous heap pages. Display operations reach 384, not 384 frames.
  No thread or anonymous-memory admission is refused in this capture.
- Killing COSMIC removes both service names. Killing the broker leaves all
  OFDs, epoll/inotify objects, shared objects and user memory reclaimed.
  All 3,826 anonymous grants/34,778 page units balance their releases; the
  physical pool returns to all 65,536 pages free.

The retained earlier failures are not relabelled PASS. This replay establishes
startup service integration and bounded compositor liveness, not a complete
session or performance qualification.

## Shared-code regression results

Final host checks pass: 1,475 default workspace tests; 308 tests across full-OS
POSIX and AI runtime; 254 legacy large-memory POSIX tests; and 26 x86 runtime
tests. The generated native backend patch tests include all 14 actual ABI/
presentation tests, lock/delivery/scheduling behavior and selector profiles.
Python build/tool checks run 60 cases with one explicitly optional skip.
Kernel layout validation and AArch64 large-memory shared-kernel compilation pass.

The final os-build-09 guest regression also passes native services, sixteen-thread
capacity/reuse, normal and bad-stack thread exit, inotify, nested epoll, flock
and XKB rules. `thread-capacity-os09-final` supersedes the earlier os05 capacity
observation for final-source replay without altering that historical evidence.
The aggregate [final-evidence.json](../../artifacts/v017-dbus-20261115-r1/final-evidence.json)
binds all 16 successful guest captures/177 files, both kernel images, upstream
build reports and host logs to 1,108 compiled-source files. Its SHA256 is
`9de787e906ef8965f4e3c6ebb5e877f6a317151253962d97f5d92d4979c99656`.
Two independent standards/spec reviews found no remaining blocking issue.

The initial ARM command also requested `ported`, but the cached AArch64 probe
ELF is absent; its failed build log remains. The successful ARM check establishes
shared-kernel compilation, not an ARM ported-program execution. The first combined
Python invocation omitted the repository's `tools` import path; its import
failures are retained, and the corrected `PYTHONPATH=tools:.` run passes.

## Current boundary

There is no system bus, service activation, multi-user policy or complete
COSMIC session in this slice. Session manager, panel, launcher, applications,
persistent settings, and broader desktop service integration remain separate
work. Existing default-configuration/locale diagnostics and unsupported APIs
must be evaluated from the next real guest trace. A working session broker or
background and cursor does not certify a full desktop. `full_os_verified` and
`cosmic_session_verified` remain false.
