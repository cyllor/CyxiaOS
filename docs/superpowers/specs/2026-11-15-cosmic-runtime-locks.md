# COSMIC runtime directory and advisory file locks

Continuation of the approved complete OS / COSMIC plan, based on the exact
source08 ELF's observed `RuntimeDirNotSet` panic. Preserve that ELF and the
full-os-v1 loader configuration; this stage must advance actual startup rather
than change the compositor into a probe.

The current single-user OS runs UID/GID 0. Provide `/run/user/0` as a real,
writable directory with mode 0700 and pass `XDG_RUNTIME_DIR=/run/user/0` to
COSMIC. Prepare it through the shared filesystem, validate existing nodes,
and preserve ordinary filesystem errors. Runtime state must be reset at boot
after persistent recovery, before user processes can hold files/sockets there;
repeated compositor launches in one boot must not reset another live listener.
Legacy application's environment remains unchanged.

Implement actual advisory flock on supported filesystem objects. Locks belong
to shared open file descriptions and identify the actual inode, not a pathname
or reusable descriptor number. Independent opens conflict; dup and inherited
descriptions share a lock; explicit unlock and the last OFD reference release
it. Shared/exclusive locks, nonblocking conflict, conversion and invalid inputs
must have finite, explicit results. Unlink/recreate, rename and descriptor reuse
must not transfer a lock to a different file. Lock state fits in the existing
bounded OFD metadata allocation. Blocking syscall retries must validate the OFD
generation, yield instead of spin, and remain interruptible. O_NONBLOCK does
not replace the flock operation's LOCK_NB flag. Both Linux ISA decoders must
select the same shared mechanism.

Agreed test seams for this routine implementation are Process/OFD lifetime and
filesystem APIs, Linux syscall decoding, and real four-CPU/1-GiB guest syscall
and COSMIC startup paths. Use behavioral RED then GREEN for new mechanisms.
Exercise lock contention and final-release reuse, and retain existing tests.
Freeze source before native compilation/capture. Native work uses the shared
lease serially; implementation ownership can run independently as required by
the approved plan. Preserve `.qwen/` and previous evidence.

Capture the exact COSMIC startup again and retain the next genuine failure.
Full OS and complete COSMIC session flags stay false until actual session,
display/input and application lifecycle requirements have been verified.
Inotify, session services and assets follow as separately proven capabilities;
none may be replaced by empty-success stubs.
