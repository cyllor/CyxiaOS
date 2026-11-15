# Real COSMIC session bus

Continuation of the approved V0.17 full OS plan at `b7a63d6`. The user has
authorized direct implementation and routine verification without repeated
confirmation. This stage uses the existing actual guest syscall, upstream
application, and source-bound QEMU capture seams.

## Required behavior

Build genuine upstream D-Bus 1.16.4 (official archive SHA256
`d08b05526c2cb7966a5fb79210d6112b1aca3d135f315c1b302e14b4b0297dac`) and
target Expat 2.7.5 for x86_64 musl. Keep host libraries out of the target link;
retain source, license, command, tool, configuration and executable receipts.
The build is offline unless fetching is explicitly requested.

Run the actual daemon in the foreground on `/run/user/0/bus`, using EXTERNAL
authentication and the implemented single UID/GID 0 domain. Validate actual
client method replies, name ownership and disconnect behavior, then measure
unchanged COSMIC with the bus present. Unsupported optional socket options must
return ENOPROTOOPT so applications can use their documented fallback. Existing
SO_PEERCRED must retain the actual peer PID across descriptor duplication and
peer exit. Invalid descriptors and valid options must preserve their semantics.

## Evidence and boundaries

First run the socket option regression against the old behavior, then fix it.
Preserve every real daemon startup failure before correcting the measured
runtime gap. Guest tests cover actual static executables, authentication and
message traffic; host tests cover build input validation. They do not establish
a complete session, panel, applications, system bus, user isolation, activation,
or all Linux ABI support. Do not substitute a mock broker or bypass credentials.
Machine IDs, if needed, must derive from persistent guest state rather than a
shared baked-in constant. Full OS and COSMIC session flags remain false until
their wider acceptance criteria are met.

The root agent owns all native jobs under the shared native lease. Independent
agents may edit explicitly assigned files and review, but never run competing
compilers or guests. Final review checks standards and this specification.

## Measured dependency: durable file synchronization

The first actual `dbus-uuidgen --ensure=/etc/machine-id` run failed with
`Could not synchronize file ...: Function not implemented`. Add Linux fsync
and fdatasync at their existing file-descriptor and blocking-syscall seams.
Persistent RAMFS files and directories must wait for the real checkpoint's
second successful device FLUSH; busy checkpoints must yield and retry without
claiming durability for a snapshot taken before this call. Invalid descriptors
and unsupported objects retain meaningful errors. Interruption and process
exit must not cancel the shared storage service or leak wait state. Verify a
renamed file after syncing its parent directory and rebooting the same disk.
This is a bounded whole-filesystem snapshot implementation of synchronization,
not a claim of a journaled filesystem or per-file writeback.

After synchronization passed, the actual daemon next failed opening `/dev/null`
while preparing standard descriptors. Connect that device path to the existing
Null open-description backend (EOF on read, discard and count on write), with
real access-mode/CLOEXEC/dup lifetime rules and character-device metadata.
Never replace it with an empty regular boot file.

The next real run completed authentication and routing but could not restart
after operator kill: the retained Unix socket binding was invisible to stat,
so upstream's stat/S_ISSOCK/unlink cleanup never ran. Expose real pathname
binding metadata, retain it after listener close, apply bind umask and chmod,
and remove it only through unlink. Abstract sockets remain outside the file
namespace. Rebinding after explicit unlink must have a distinct identity.

## Measured dependency: full OS thread capacity

With the real broker present, unchanged COSMIC hit the existing eight-thread
capacity and exited with notify SendError before rendering. The capture records
one thread capacity refusal (`EAGAIN`) and zero anonymous-memory refusals.
Use 16 context slots only in `full-os`, retaining eight in legacy profiles.
Each process must actually reserve 18 pages (16 contexts, one shared signal
page, one spare), adding 256 KiB across eight process slots. Model 8193 admits
from those real free context credits with its existing two-credit floor;
weights and stack/heap admission remain unchanged. Compile-time size assertions
and native tests must verify 15 concurrent workers plus the main thread, reject
a seventeenth thread, then join and reuse every slot. Re-run unchanged COSMIC
with the real broker; the expanded limit alone does not prove startup success.

## Measured dependency: presentation progress watchdog

The next real capture reached ten threads with no resource refusals, then
exited after 170 of 192 successful display tiles: the backend's five-second
absolute frame deadline expired despite ongoing successful submissions.
Retain the five-second timeout as a stall watchdog, refreshed only by an actual
successful tile completion. EAGAIN, EINTR and timer dispatch do not refresh it.
Keep the bounded per-dispatch syscall budget and terminal failure behavior.
Neither normal presentation nor session-lock blanking may acknowledge an
incomplete frame. Deterministic clock tests must distinguish sustained progress
past five seconds from a stalled tile; rebuild and measure the real compositor.
