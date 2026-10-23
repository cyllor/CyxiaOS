# AArch64 musl bootstrap for CyxiaOS

This directory fixes the sources for a **real target libc**, not a host libc or
Linux virtual machine. The target interface is the deliberately limited Linux
AArch64 syscall persona implemented by CyxiaOS's own kernel. A successful cross
build does not prove those syscall semantics work in the guest.

## Build and inspect

From the project root:

```sh
python3 tools/build_sysroot.py                     # read-only inventory
python3 tools/build_sysroot.py build --fetch       # explicit source retrieval + build
python3 tools/build_sysroot.py build               # repeat using verified local archives
python3 tools/build_sysroot.py inspect             # validate/report the final ELF
python3 tools/build_sysroot.py xorg-bootstrap --fetch # target Xau/XCB/X11 and headers
python3 -m venv artifacts/sysroot/build-tools
artifacts/sysroot/build-tools/bin/python -m pip install --disable-pip-version-check --no-cache-dir --only-binary=:all: --require-hashes -r ports/libc/build-tools.lock
python3 tools/build_sysroot.py server-bootstrap --fetch # real upstream X.Org + native DDX
python3 tools/build_twm.py build --fetch           # TWM plus target ICE/SM/Xt/Xext/Xmu
python3 tools/build_openbox.py foundation --fetch  # target libffi, PCRE2 and GLib
python3 tools/build_openbox_fonts.py build --fetch # target font/XML closure
python3 tools/build_openbox.py build --fetch       # Openbox ELF and read-only assets
python3 tools/build_sysroot.py probes              # all local runtime probes, no retrieval
python3 tools/build_sysroot.py probes --probe signal-probe # select/repeat individual probes
python3 -m unittest tests.host.test_build_sysroot -v
```

The project-local output root is `artifacts/sysroot/aarch64-musl/`:

- `probe.elf`: ELF64 AArch64 static ET_EXEC, no interpreter, no PIE.
- `sysroot/usr/include`, `sysroot/usr/lib`: musl headers, startup objects, static libraries.
- `sysroot/usr/lib/libclang_rt.builtins-aarch64.a`: target compiler-rt generic integer,
  floating and quad-precision helpers. These are rebuilt from C source with the
  normal AArch64 floating-point ABI. The existing Rust soft-float builtins and
  macOS runtime libraries are **not used**.
- `bin/aarch64-linux-musl-cc`, `aarch64-linux-musl-ar`, `aarch64-linux-musl-ranlib`:
  reusable static target tool drivers. Shared objects/PIE are outside this stage.
- `licenses/`, `build-report.json`, `probe-layout.json`, `logs/`: source identities,
  licenses, commands, source/output digests, load layout and build diagnostics.
- `openbox.elf`, `openbox-build-report.json`, `openbox-foundation-report.json`,
  `openbox-fonts-*-report.json`: the static window manager and its dependency
  build records. Runtime verification is recorded separately by the guest tools.

The explicit `build`, `xorg-bootstrap`, `server-bootstrap` and window-manager commands execute
upstream build scripts. Omit `--fetch` to use verified offline archives. The
`probes` command uses the existing target sysroot and never downloads. The default mode never downloads
or executes package scripts. The builder verifies sources before extraction,
rejects devices and escaping archive paths/links, regenerates source/build directories,
reserves 512 MiB of disk space, excludes host header/library search environment,
and publishes `probe.elf` only after validating its static ELF contract. A failed
build removes `build-report.json`; an earlier ELF may remain, and must not be
mistaken for a successful new build. Logs identify the failing stage.

The initial build used Apple Clang 17 and LLVM tools bundled with Rust 1.95.0.
No compiler or dependency was installed globally. GNU make and Python 3.11+
are needed on the build host; LLVM tools must be installed in its Rust toolchain.
Paths are resolved locally, not embedded as portable assumptions in the manifest.

Run the dependency stages in order. The current Openbox link also uses X libraries
installed by `build_twm.py`; that stage is a prerequisite even when selecting
Openbox for the guest. Builders use a shared target-sysroot lock. Do not replace
the kernel or embedded ELFs while a guest acceptance run is in progress.

## Source integrity and licenses

musl 1.2.6 comes from its [official release archive](https://musl.libc.org/releases/musl-1.2.6.tar.gz).
Its SHA256 and COPYRIGHT digest are pinned from the
[Buildroot maintainer hash record](https://gitlab.com/buildroot.org/buildroot/-/raw/6f8f031cef37ac39a39241bd7871caf542f549be/package/musl/musl.hash),
whose maintainer states that they checked musl's PGP signature. This project
checks the fixed SHA256; it does **not** claim to have verified that PGP signature.
The full upstream MIT notice and bundled notices are copied to `licenses/musl.txt`.

compiler-rt 20.1.8 comes from the
[official LLVM release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-20.1.8).
The fixed SHA256 is the digest published on that release's GitHub API asset.
The complete Apache-2.0 WITH LLVM-exception notice is retained in
`licenses/compiler-rt.txt`. The build selects the upstream `GENERIC_SOURCES` and
`GENERIC_TF_SOURCES` groups, substitutes AArch64's `fp_mode.c` for the generic
one, and includes the target `clear_cache.c` helper required by libffi. This is a
bootstrap builtins subset: no outlined atomics, CPU dispatch, SME,
emulated TLS, sanitizer or C++ standard-library implementation is supplied.

musl 1.2.6 is not claimed production ready: the
[GB18030 iconv DoS advisory](https://www.openwall.com/lists/oss-security/2026/04/09/19)
applies and has not yet been patched here. The probe does not exercise iconv.
The [qsort advisory](https://www.openwall.com/lists/musl/2026/04/10/3) affects
32-bit builds, while this target is AArch64. Patch/upgrade work is required before
accepting untrusted text conversions as part of a desktop.

## Native loader contract

The current probe is linked at image base `0x01000000`, within the reserved
`0x01000000..0x02000000` window. LLD uses 4096-byte pages and separates code from
writable data. The loader must read the generated program headers rather than
hard-code current addresses. Each slot has a 4096-page image grant, including
the separate 256 KiB / 64-page stack at `0x03000000`; the preceding stack page
is unmapped. Kernel boot assets have a combined 40 MiB catalog limit. These
limits are distinct from the per-process 8 MiB anonymous heap.
The initial inspected output below is historical; current layout reports and
ELF digests are authoritative:

| Field | Value |
|---|---|
| Entry | `0x01002000` |
| AT_PHDR / AT_PHENT / AT_PHNUM | `0x01000040` / 56 / 9 |
| PT_TLS | VA `0x0100a000`, filesz 4, memsz 4, align 4 |
| LOAD R | VA `0x01000000`, file/memory size 4196 |
| LOAD RX | VA `0x01002000`, file/memory size 30352 |
| LOAD RW | VA `0x0100a000`, file size 120, memory size 4096 |
| LOAD RW | VA `0x0100b078`, file size 248, memory size 2816 |

Copy each LOAD's file bytes and zero its memory tail. Honor unaligned-within-page
LOAD offsets such as `0x...b078`, map complete pages, and enforce W^X. Static musl
uses the mapped PHDR and PT_TLS to create its initial TLS block and writes
`TPIDR_EL0` itself; the kernel must preserve this register and FP/SIMD state across
exceptions and scheduling. There are no dynamic relocations to apply.

Initial SP is 16-byte aligned and points to 64-bit words in Linux order:

```
argc, argv[0] ... argv[argc-1], NULL,
envp[0] ... envp[n-1], NULL,
AT_PHDR, mapped_phdr_address, AT_PHENT, 56, AT_PHNUM, phnum,
AT_PAGESZ, 4096,
AT_UID, uid, AT_EUID, uid, AT_GID, gid, AT_EGID, gid,
AT_SECURE, 0, AT_RANDOM, pointer_to_16_random_bytes,
AT_EXECFN, pointer_to_exec_path, AT_NULL, 0
```

All pointers target readable user memory with NUL-terminated strings. At least
`argv[0]` is present. AT_RANDOM contains actual entropy supplied by the kernel.
UID/EUID and GID/EGID match; a secure launch would additionally activate musl's
stdio descriptor checks and is not the baseline. HWCAP/HWCAP2 may be omitted
(zero) unless actual enabled hardware capability bits are provided. Do not
advertise vDSO/AT_SYSINFO when there is none.

## Required syscall behavior and probe evidence

The ABI is `svc #0`, number in X8, arguments X0..X5, signed result in X0 with
negative Linux errno values. This persona must be explicitly selected for these
images and cannot reinterpret the kernel's different private syscall numbers.

| Linux AArch64 number | Call | Probe path |
|---|---|---|
| 96 | set_tid_address | libc startup; stable positive task ID and valid clear-tid registration |
| 56 | openat | AT_FDCWD and directory-FD relative paths, missing file ENOENT, create/read/write |
| 66 | writev | unbuffered printf; validate both iovecs and total bytes |
| 214 | brk | returning current brk 0 consistently forces mallocng's mmap fallback |
| 222 | mmap | anonymous private PROT_NONE metadata reserve and RW large allocations |
| 226 | mprotect | change second page of metadata reserve from NONE to RW |
| 215 | munmap | whole large malloc mapping on free |
| 64 / 63 | write / read | regular-file IO and short/EOF return behavior |
| 62 | lseek | SEEK_SET reset before readback |
| 57 | close | invalidate descriptor and return status |
| 113 | clock_gettime | monotonic time for a bounded, at least 50 ms live-FP interruption test |
| 94 / 93 | exit_group / exit | normal termination / fallback |

The desktop ABI probe adds syscall 19 `eventfd2`, 61 `getdents64`, 17 `getcwd`,
49 `chdir`, and directory-relative `openat`/`fstatat` coverage. Directory FDs retain
their opened inode identity and stable iteration offsets, including duplicated
descriptors; read-only boot files participate in directory enumeration. The
RAMFS rejects removal of directories containing boot assets. Eventfd uses a
shared 64-bit counter, supports semaphore/dup/poll semantics and validates exact
write lengths, overflow and user buffers before consuming events. Readv scatters
one eight-byte event; writev processes each eight-byte entry as a separate write
and preserves partial-write behavior. These are bounded implementations, not a
claim of a complete Linux filesystem or event API.

Futex support is limited to valid WAKE requests returning zero waiters in the
single-thread process model. WAIT and general clone/pthread execution remain
unsupported. The signal subset accepts SA_NOCLDSTOP, but does not implement
job-control notifications, SA_NOCLDWAIT, SA_RESTART or full cross-process signals.

musl adds O_LARGEFILE to `open` (`0400000` octal, `0x20000` in this AArch64 ABI); this harmless flag must be
accepted. Initial descriptors 0/1/2 are valid. The program calls `setvbuf` to avoid
stdout's usual ioctl(TIOCGWINSZ). Unused generic libc error/cancellation paths can
contain more syscalls, so this table describes the intended normal execution,
not all capabilities of the library. Unsupported calls must return ENOSYS.

The first mallocng metadata allocation tries brk and then reserves 8192 bytes
with PROT_NONE, enables only the second 4096-byte page with mprotect, and retains
the first guard page. Mapping both pages RW while reporting success would violate
the allocator contract. Each explicit allocation requests 256 KiB, above
mallocng's direct-mmap threshold, and frees that complete allocation. The test
does not require a partially unmapped malloc allocation or mremap.

`user/ported/probe.c` performs initialized `_Thread_local` access, verifies ENOENT
through TLS errno, checks three 256 KiB allocation/write/read/free cycles, writes
and reads `/musl-probe.txt`, performs volatile double arithmetic, and formats
`3.625` through real musl printf plus compiler-rt quad helpers. It then repeatedly
keeps a double live in an FP register across a timed loop for at least 50 ms,
checking its value after each chunk. This permits the guest verifier to require
actual timer IRQs rather than relying on a fast probe happening to be interrupted.
`/musl-probe-missing`
must not exist. Every stage prints a `PORTED_PROBE` marker; only a final
`PORTED_PROBE PASS` and exit status 0 from CyxiaOS count as a runtime pass.

The parent kernel integration ran the initial version in CyxiaOS, reporting
all stages PASS (TLS/errno, three allocation cycles, file readback, floating
output `3.625`) and 28 syscalls. The raw guest evidence is in
`artifacts/ported-initial/`; that evidence predates the added timed IRQ stage.
The builder still reports cross-build status only. Read current guest reports
for the exact ELF digest tested.

## Native X.Org and additional probes

`server-bootstrap` now cross-builds real X.Org 21.1.25 core and Kdrive, with the
native [CyxiaOS DDX](../../user/ported/xorg/cyxia_ddx.c). It publishes
`Xcyxia.elf`, `xcyxia-layout.json` and `xserver-build-report.json`. The renderer is
upstream software fb/Pixman, with neither a host X server nor GL/DRM. Compiled
target dependencies and their official source/hash records are in
`xorg-bootstrap.json`, `xserver-dependencies.json`, `pixman-source.json` and
`xserver-source.json`. Source licenses are retained under the output's `licenses/`.

The DDX uses four explicitly private CyxiaOS persona extensions documented in
[cyxia_abi.h](../../user/ported/xorg/cyxia_abi.h). They provide display info,
fenced bounded pixel uploads, raw evdev events, and overflow key-state resync.
Dirty rectangles are split into at most 64 KiB transfers. EAGAIN retains a full
frame retry. Input is checked every 10 ms using the real X server timer loop;
relative mouse movement and buttons are supported. Raw absolute tablet axes
are ignored because ABI v1 provides no axis range. RandR exposes the actual
single fixed mode; mode switching and acceleration are not implemented.

The keyboard uses a real precompiled XKM file at
`/usr/share/X11/xkb/cyxia-us.xkm`, generated by upstream xkbcomp from the fixed
evdev/pc105/US map. See [the asset build](../xkb/README.md). The local patch
`patches/xorg-cyxia-precompiled-xkm.patch` calls upstream `XkmReadFile` rather
than executing a compiler in the guest. Other layouts require additional
compiled assets and selection support. TCP, IPv6 and MIT-SHM are compiled out.
Do not pass `-nolisten tcp` when this transport does not exist. Suggested initial
native arguments are `Xcyxia :0 -fp built-ins -noreset -retro`; this shows the
real X server root background, not a completed desktop.

The `probes` command produces individually validated static executables:

- `probe.elf`: libc, TLS/errno, allocator, files, formatted FP and IRQ preservation.
- `xau-probe.elf`: upstream Xau authorization-file write/read/free through musl.
- `socket-probe.elf`: Unix socketpair backpressure/EOF and pathname listen/connect/accept/poll.
- `signal-probe.elf`: real musl signal handlers, masks/pending state, FP/TLS context and fault recovery.
- `desktop-api-probe.elf`: eventfd/dup/readv/writev and error atomicity;
  directory-FD open/stat, chdir/getcwd, readdir/rewind and boot-font enumeration.
- `x11-probe.elf`: upstream Xlib/XCB connection, window creation, drawing and server pixel readback;
  `--interactive` reads real key/button events for 15 seconds, while `--demo`
  remains open until closed. This is a
  diagnostic client, not a desktop shell. X.Org must run concurrently.

Builds never run these executables on the host. A PASS requires execution on
CyxiaOS and a guest report tied to the artifact SHA256. Real X.Org, Openbox and
the Xlib client now execute concurrently in separate guest EL0 processes;
TWM remains an additional verified integration path. See the
[X11 integration record](../../docs/implementation/x11-desktop-integration.md)
for actual rendering, input and resource-reclamation evidence. Cross-linking
alone does not establish functioning guest behavior.

## Openbox font and XML port

`openbox-foundation.json` pins libffi 3.4.8, PCRE2 10.47, GLib 2.86.5 and
Openbox 3.6.1. `openbox-fonts.json` pins Expat 2.7.5, fontconfig 2.17.1,
FriBidi 1.0.16, HarfBuzz 12.3.2, libXrender 0.9.12, libXft 2.3.9,
libxml2 2.15.2 and Pango 1.56.4; FreeType comes from the existing X server
dependency closure. Verified source identities, commands and licenses remain
in the build output. Openbox's old platform-recognition helpers are replaced
with those from the pinned xorgproto 2024.1 source so the host can configure it.

HarfBuzz uses compiler-supplied libc++ template headers with a recorded target
configuration for musl; no macOS binary libc++ is linked. This is not a general
C++ runtime implementation. The current Openbox font closure uses Pango Xft,
FreeType and fontconfig with Cairo disabled; GTK requires a separate Cairo-enabled
dependency configuration and guest validation.

The explicit [Pango port patch](patches/pango-cyxia-synchronous-fontconfig.patch)
is enabled by `__CYXIA_SINGLE_THREAD_FONTCONFIG__`. It runs fontconfig
initialization, matching and sorting synchronously on the calling guest thread,
using the real upstream functions and results. It neither returns fake pthread
handles nor claims background work was scheduled. The process remains
preemptible by CyxiaOS's local AI scheduler. Other library paths requiring
general threads still need implementation and validation.

`build_openbox.py build` installs Openbox configuration, a Cyxia theme,
fontconfig configuration, passwd/group and Roboto Regular as read-only boot
assets. The unmodified font is taken from the verified HarfBuzz archive;
its Apache 2.0 license and provenance are retained under `licenses/Roboto/`.
The current Openbox build disables startup notification, Xcursor, Imlib2 and
librsvg; guest launch uses `--sm-disable` and the explicit rc.xml path. It does
not launch a session manager or application menu service.

See the parent implementation's
[memory/display progress](../../docs/implementation/desktop-memory-display.md)
and [remaining desktop inventory](../../docs/implementation/desktop-port-inventory.md)
for the wider context. GTK/LXDE components, general pthread scheduling, session
process management, PTYs and complete Unix compatibility remain separate work;
the X.Org/Openbox integration and probes do not establish a complete LXDE desktop.

## GTK target build

`tools/build_gtk_foundation.py build --fetch` builds the pinned static GTK
closure from `gtk-foundation.json`; omit `--fetch` to use verified cached archives.
`tools/build_gtk_foundation.py probe` links the real GTK client after those
libraries exist. The existing musl/X.Org/Openbox dependency stages remain
prerequisites. The builder uses separate `gtk-source` and build directories and
the shared sysroot lock; it records archive object architectures, source hashes,
licenses and local patches in `gtk-foundation-*-report.json`.

GTK 3.24.52 and `gtk-probe.elf` have cross-built. The probe report records its
exact static ELF layout; these build reports explicitly do not claim guest
execution. Current options select X11 and built-in input/image modules, disable
printing backends and AT-SPI integration, and retain the synchronous Pango
fontconfig adaptation. Compiled GLX dispatch does not supply an OpenGL provider.
The kernel `gtk` feature includes `openbox` and the probe; it enlarges the boot
asset budget, not the per-process image/heap grants. LXDE components still need
their own runtime evidence.
