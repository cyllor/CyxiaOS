# Wayland transport foundation for COSMIC

The genuine upstream Wayland 1.24.0 client and server libraries now cross-build
as static AArch64 musl archives and complete registry/bind/events/sync roundtrips
inside CyxiaOS. This is a transport milestone, not a COSMIC desktop, compositor,
surface rendering, or shared-memory-buffer implementation.

## Sources and build

`ports/cosmic/wayland-source.json` pins the [official Wayland release archive](https://gitlab.freedesktop.org/wayland/wayland/-/releases/1.24.0/downloads/wayland-1.24.0.tar.xz)
to SHA-256 `82892487a01ad67b334eca83b54317a7c86a03a89cfadacfef5211f11a5d0536`.
The unmodified upstream source declares MIT licensing; its installed `COPYING`
has SHA-256 `6eefcb023622a463168a5c20add95fd24a38c7482622a9254a23b99b7c153061`.
Archive integrity is verified. Signature verification is not claimed.

```sh
python3 tools/build_wayland.py inventory
python3 tools/build_wayland.py build --fetch --jobs 4
# Subsequent builds use verified cached archives without network retrieval:
python3 tools/build_wayland.py build --jobs 4
```

The builder holds the existing sysroot build lock. It builds native Expat 2.7.5
from the existing pinned source manifest and native `wayland-scanner` from the
same Wayland release in `artifacts/sysroot/aarch64-musl/wayland-host-tools`.
Separate native and cross Meson files keep native scanner dependencies out of
the target link. Target pkg-config searches only the AArch64 sysroot; the target
reuses its existing libffi and musl archives. Meson fallback downloads, upstream
tests, documentation, and scanner DTD validation are disabled. The upstream
source itself has no CyxiaOS patch.

`artifacts/sysroot/aarch64-musl/wayland-build-report.json` records sources,
licenses, compiler paths, commands, options, native scanner identity, target
dependency hashes, every archive's AArch64 object count, and probe ELF layout.
It deliberately reports compilation separately from guest execution. It does
not establish bit-for-bit reproducibility across different native compilers or
SDKs.

| Target artifact | Bytes | AArch64 objects |
| --- | ---: | ---: |
| `libwayland-client.a` | 122668 | 5 |
| `libwayland-server.a` | 165442 | 7 |
| `libwayland-cursor.a` | 34454 | 3 |
| `libwayland-egl.a` | 1996 | 1 |

Compiling the cursor and EGL window-helper archives is not evidence that cursor
shared-memory allocation or an EGL renderer works. The executed probe links
the client/server libraries. Its 141696-byte static ELF passes the existing
fixed-address, W^X, no-dynamic-interpreter and unresolved-symbol checks.

## Guest evidence

```sh
python3 tools/verify_wayland.py \
  --elf artifacts/cosmic-bootstrap-r3/cyxia-kernel.elf \
  --output artifacts/cosmic-bootstrap-r3/wayland --runs 3
```

Frozen kernel SHA-256:
`0d31c3fcb2668b67b31a9e1388c62579f32025aefc47babbb121560c595e2b5d`.
Embedded probe SHA-256:
`5fb2335f663ebd5ec207af1a54be0d0d504590d110e15c874aada828be2ad5b9`.
Evidence is `artifacts/cosmic-bootstrap-r3/wayland/summary.json` and its saved
guest console. Three consecutive executions in one guest passed:

- A real AF_UNIX socketpair connects upstream client and server code. A real
  EL0 pthread drives `wl_event_loop_dispatch()` through kernel epoll.
- `wl_registry` advertises one `wl_output` version 2. The client binds it and
  checks geometry, manufacturer/model strings, 640×480 mode at 60000 mHz,
  scale 1 and the output's done event, after two real sync roundtrips.
- An attempted SCM_RIGHTS transfer fails with ENOSYS before any payload is
  transmitted. Receiving on the other endpoint confirms that it stayed empty.
- Each execution exits with code 0, uses two thread contexts at peak, records
  one AI-admitted additional thread and real UNIX-object AI admissions, then
  returns all native, anonymous, executable-image and thread allocations.
  Each final process has 64 free native pages, zero heap/image pages in use,
  4096 free heap pages, 4096 free image pages, and zero live threads.

The probe's `wl_output` is a protocol test global. It does not represent a
physical output, draw a window, or substitute for a real COSMIC compositor.
Repeated successful creation exercises socket/epoll reuse, while the explicit
page and thread assertions establish the corresponding allocation reclamation.
There is not yet a separate exported epoll-pool occupancy counter.

The retained r0 run failed before launching the ELF because the shell command
allowlist omitted `wayland-probe`. Its report remains under
`artifacts/cosmic-bootstrap-r0/wayland`; r1 includes the corrected dispatch and
its original three-run PASS remains under `artifacts/cosmic-bootstrap-r1/wayland`.
The r3 gate repeats the same tests with the unchanged probe inside the unified
kernel that also carries the Rust and libxkbcommon foundations.

## Remaining integration

The historical transport gate above exercised bounded level-triggered epoll and
one-shot rearming. Subsequent [edge-triggered epoll](epoll-edge.md) and
[genuine Mio](rust-reactor.md) have separate guest evidence; exclusive and nested
epoll remain explicit errors.
sendmsg/recvmsg perform checked stream iovec transfers, with bounded short
results, and never silently discard unsupported outgoing ancillary descriptors.
The probe does not need timerfd or signalfd: upstream creates its timerfd lazily
when an actual timer source is added.

Subsequent [descriptor transfer](scm-rights.md), [shared buffers](wayland-shm.md)
and [Smithay rendering](smithay-static-renderer.md) have bounded independent
tests. COSMIC still needs their combined compositor integration, actual
presentation, Rust dependency closure, session services and measured resource
profiles. This historical transport result does not certify those capabilities.
