# COSMIC runtime files and real advisory locks

This continues from `8c4cfe3` and the actual `RuntimeDirNotSet` panic in
`v017-full-os-capacity-20261115-r1/cosmic-startup-04`. The application remains
the same real source08 x86 COSMIC ELF, SHA256
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
The specification is `docs/superpowers/specs/2026-11-15-cosmic-runtime-locks.md`.

## Runtime lifecycle

The single-UID session uses `/run/user/0`, mode 0700. The full-OS entry prepares
it after storage recovery and before accepting process launches. Runtime
descendants from a previous checkpoint are removed at that boundary. Ordinary
launches validate the directory without removing any live lock or socket.
Only COSMIC and its syscall regression probe receive the new runtime-directory
environment; existing application environment entries retain their behavior.

## File-lock mechanism

Lock mode resides in the existing bounded open-description entry. A stable
file identity determines conflict; lock ownership follows the OFD's actual
references, including duplicates and transferred descriptors. Unsupported
object kinds return an explicit error. The Linux ISA tables select the same
mechanism (x86 syscall 73, AArch64 syscall 32, from pinned musl 1.2.6 headers).

A nonblocking conflict returns EAGAIN. A blocking call yields through the
existing interruptible restart mechanism, rechecking the descriptor's OFD
generation before replay. A replaced descriptor cannot silently acquire a lock
on its new target. LOCK_NB governs this behavior independently of O_NONBLOCK.
The contract follows the documented [flock semantics](https://man7.org/linux/man-pages/man2/flock.2.html).

## Evidence boundary

New artifacts are under `artifacts/v017-cosmic-runtime-locks-20261115-r1/`.
The guest probe exercises the actual musl syscall path, pthread blocking,
signal delivery and descriptor replacement. Host gates wait for observed kernel
wait-counter progress while the leader only checks the gate and yields.
Resource snapshots and exited-process fields verify descriptor, image, heap
and thread reclamation. A separate disk-recovery capture checks runtime expiry
while preserving ordinary durable data.

Full OS and complete COSMIC session flags remain false. Runtime directories and
file locks do not establish actual compositor output, input, application
lifecycle or desktop session services. Subsequent capabilities must follow
genuine startup observations, with the raw failures preserved.

## Verified result

The final image is `os-build-01`, with compiled source SHA256
`e9d62752dd96e0dba9ae290cbf9b7f6095be850f16f3bd239cd3321b1dd6d769`.
All native work used the shared exclusion lease, serially, with four guest CPUs
and 1 GiB RAM. The real syscall probe is 58,200 bytes, SHA256
`ffb24fb55af713467625ed72453e3845e68bac506e223c3767d19091f5ec811c`;
its source, musl archive, compiler driver and actual ELF layout are bound in the
build receipt and rechecked after execution. Changed source receipts and changed
ELF bytes are rejected. The exact probe occurs once in a read-only kernel LOAD.

| Capture | Actual result |
|---|---|
| `flock-run-03` | `OS_FLOCK_PASS`; two complete runs, including blocked unlock, caught signal/EINTR and descriptor-generation reuse; all OFDs, image/heap pages and threads reclaimed |
| `flock-reboot-01` | `OS_REBOOT_FLOCK_PASS`; restores the same generation-1 disk, removes the previously persisted runtime sentinel, retains `/v17/hello`, then passes both complete probe runs again |
| `native-01` | `OS_NATIVE_PASS`; preemption, expected user faults, FP/TLS, heap isolation/recycle and IPC |
| `cosmic-version-01` | `OS_COSMIC-VERSION_PASS`; unchanged real compositor executes twice and exits 0, followed by the ported C probe |
| `cosmic-startup-01` | Real normal startup passes runtime-directory/listener creation, then exits 1: `Failed to init the wayland event source.`; identity preserved, no session PASS |

The recovery validator accepts only the unchanged disk of a successful cold
capture with matching source/build/producer/helper identities. The captured
command sequence must end in sentinel write, exact readback, then a durable
checkpoint with at least two flushes. Serial/command/disk hashes and checkpoint
generation are bound to the recovery capture. The guest must report that same
generation and preserve the ordinary file before runtime expiry is accepted.
Four Python regression tests reject missing readback, incomplete flushes and
changed evidence. The initial `flock-run-02` exposed a capture-parser error:
the actual durable record includes `slot=0`. Its failed result is retained;
the parser and protocol fixture were corrected before fresh cold/recovery runs.

Host results: 207 POSIX tests and 14 shell tests passed with the default layout;
207 POSIX tests passed with full-os. These include 13 focused flock cases,
runtime-directory creation/expiry/live-file preservation and both ISA decoders.
All 14 Python OS build/Smithay/recovery tests passed. The legacy ARM large-memory
kernel compiles; that result does not establish an ARM guest boot. RED/GREEN logs
for lock behavior are in `artifacts/cosmic-runtime-flock-20261115/`; runtime,
ABI and recovery validation logs are in this stage's evidence root.

Independent Standards and Spec reviews found no remaining confirmed functional
defect. The Spec review's initial signal-restart finding was withdrawn after
tracing the existing architecture encoder: both ISAs save the post-syscall PC
and `-EINTR` in a caught signal frame. No redundant signal-code change was made.
The confirmed recovery-provenance gap was fixed and re-reviewed. Optional style
suggestions about repeated embedding checks and numeric probe case selectors
remain outside the functional fixes.

## Next actual startup boundary

The unchanged pinned source08 `init_wayland_display()` first installs the socket
source, then wraps its `Display` in calloop `Generic` at `src/lib.rs:335–351`.
The linked Rust `wayland-backend 0.3.15` exposes an epoll descriptor for this
display. `crates/posix/src/epoll.rs` currently rejects every `Object::Epoll`
registration with EINVAL. The observed event-source error therefore matches
the missing nested-epoll capability; directory/flock startup is no longer the
first failure. Implement readiness propagation, self/cycle rejection and
OFD-generation cleanup with actual syscall and compositor verification next.

Later source-audited gaps remain independently unverified: socket pathname stat
visibility after abrupt listener exit, real inotify configuration notifications,
measured descriptor/epoll capacity, and actual COSMIC session services. No
complete compositor rendering/input or desktop session is claimed here.

## Reproduce

With the existing x86 SDK and isolated input catalog, all native commands below
acquire the shared lease. Use fresh output directories.

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-cosmic-runtime-locks-20261115-r1/sysroot \
  --output artifacts/runtime-locks-new-build
python3 tools/os_smoke.py --build artifacts/runtime-locks-new-build \
  --scenario flock --output artifacts/runtime-locks-new-cold
python3 tools/os_smoke.py --build artifacts/runtime-locks-new-build \
  --scenario flock --recover-disk artifacts/runtime-locks-new-cold/data.raw \
  --output artifacts/runtime-locks-new-reboot
```

The isolated catalog already contains the receipt-matched probe and unchanged
COSMIC image. If rebuilding the probe, copy both its ELF and layout receipt from
the SDK to that catalog before the kernel build. Normal COSMIC startup uses
the preserved `capture-startup.py` beside the evidence, taking build and fresh
output paths; it records the genuine process outcome without certifying a session.
