# Real COSMIC configuration notifications

Continue the approved complete OS / COSMIC plan from `508da71`. The unchanged
compositor reaches ConfigWatchSource construction and fails with Notify/ENOSYS.
Implement actual inotify, not successful empty descriptors or callbacks.

The filesystem records committed create/modify/metadata/delete/rename and
open/access/close observations with stable inode and parent identities, paired
nonzero rename cookies and detectable bounded-journal loss. Failed operations
must not publish changes. Deleted open inodes retain their identity until final
release; watches do not pin files. Journal state is runtime-only, separate from
the existing persistent checkpoint format. Shell and POSIX mutations share it.

Inotify instances are OFD-owned, with independent masks, monotonic watch IDs,
bounded event queues, aligned Linux event records, duplicate-descriptor lifetime
and real read/poll/epoll readiness. Implement mask update/add/create, ONLYDIR,
DONT_FOLLOW within the existing no-symlink filesystem, EXCL_UNLINK, ONESHOT,
IGNORED and explicit Q_OVERFLOW. Watch queue overflow and missed journal records
must never appear as an empty successful stream. Preserve complete record
boundaries, EINVAL for a nonempty record too large for the buffer, EAGAIN for
empty nonblocking reads, and the existing interruptible/generation-safe blocking
read mechanism. Expose unread-byte accounting. No references leak on failure,
descriptor transfer, last close or process teardown. Both Linux ISAs map to the
same shared mechanism; no architecture-specific policy.

The real pinned configuration/theme chain has at least seven notify watchers:
35 retained descriptors, nine epolls and eight threads including the main
thread, before later session/backend dependencies. Introduce an explicit
full-os object profile: 64 FDs/process, 256 shared OFDs, 16 epolls/owner from a
shared 64-instance pool, eight inotify instances/owner from 32 shared instances,
64 watches and 64 ordinary queued events per instance plus one overflow record.
Legacy capacities stay unchanged. Shared pools are global bounds, not reserved
per-process allotments. Keep existing OFD identity width and bounded epoll
bitsets by decoupling per-owner quotas from shared pool size. The existing
eight-thread scheduler/model limit is not silently increased; later thread
needs require a separately validated capacity/model change.

Use the already approved public FileSystem and Process/OFD seams with
behavioral RED/GREEN, actual musl guest syscalls, and unchanged COSMIC startup.
Validate the capacity boundary, notification contents/order/filtering, unlink
and rename lifecycle, partial reads, overflow, readiness, reuse and teardown.
Preserve source/ELF receipts and raw failures. All native work uses the shared
lease serially; independent ownership and review follow the main plan. Preserve
`.qwen/`. Routine steps need no further confirmation. Full OS and complete
desktop-session flags remain false until actual interaction/services pass.
