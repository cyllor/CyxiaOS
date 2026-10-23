# libxkbcommon foundation for COSMIC

The genuine upstream libxkbcommon 1.13.2 core library cross-builds as a static
AArch64 musl archive. The accompanying CyxiaOS probe exercises the real keymap
parser and keyboard-state engine using an embedded four-key fixture. It does
not establish a complete keyboard layout database, physical input routing, an
input method, or COSMIC compositor integration.

## Source and build identity

`ports/cosmic/xkbcommon-source.json` pins the [official release-tag archive](https://github.com/xkbcommon/libxkbcommon/releases/tag/xkbcommon-1.13.2):

- Tag: `xkbcommon-1.13.2`.
- Annotated tag object: `322bf223710e9d3a646dd345896eb4e7a83f8c41`.
- Upstream commit: `d1442aaa6b635551182e83c3b55037f4c118c962`.
- Archive SHA-256: `acc4d5f7c3cbba5f9f8d08d8bdbeede84ecede46792f47929aa9321873385528`.

The archive hash was calculated from the official GitHub release-tag download
and is checked on every extraction. It is not an independently published
upstream checksum or a verified signature. Upstream's full
[LICENSE](https://github.com/xkbcommon/libxkbcommon/blob/xkbcommon-1.13.2/LICENSE)
contains the MIT/X11-derived license variants and per-file attribution scheme;
the builder preserves it intact rather than replacing it with a single MIT
label. Its SHA-256 is
`967e97b28658f0037bbe164a237bdfb0c3ec790e67f6c29372ea5b09306f61f3`.

```sh
python3 tools/build_xkbcommon.py inventory
python3 tools/build_xkbcommon.py build --fetch --jobs 4
# Cached sources, full native tool rebuild:
python3 tools/build_xkbcommon.py build --jobs 4
# Reuse the already built native Bison only after provenance/hash checks:
python3 tools/build_xkbcommon.py build --reuse-host-tools --jobs 4
```

Upstream needs Bison 3.6 or newer. The builder compiles pinned GNU Bison 3.8.2
from its official archive into
`artifacts/sysroot/aarch64-musl/xkbcommon-host-tools`; it installs no system
package. Bison's archive hash is
`9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2`, and its
license is retained separately. Reuse verifies the original build manifest,
source identity, version and binary hash and preserves the original build
record. Native Bison generates parser source; no native library enters the
target link.

The existing sysroot lock, verified archive extraction, isolated target
pkg-config, Clang/musl driver, and ELF validator are reused. Upstream source
code is unmodified. X11 support, Wayland command-line tools, xkbregistry,
documentation, other tools and shell completion are disabled. Upstream has no
`enable-tests` option: the build selects only the actual `xkbcommon` library
target and installs with `--no-rebuild`. It does not compile or execute the
upstream test suite. The initial unsupported-option failure is retained in the
native Bison provenance record; the corrected target build succeeded.

`artifacts/sysroot/aarch64-musl/xkbcommon-build-report.json` records the exact
sources, commands, compiler paths, options, native generator, target libc and
archive identity, and probe layout. Compilation and guest execution remain
separate results. Cross-host bit-for-bit reproducibility is not claimed.

| Artifact | Identity |
| --- | --- |
| `libxkbcommon.a` | 634130 bytes, 37 AArch64 objects |
| Archive SHA-256 | `a9430ee30901c802e2100be6893ddc5f6e91b4a1da62689bacbad98df2f8642a` |
| `xkbcommon-probe.elf` | 333304 bytes, static AArch64 ET_EXEC |
| Probe SHA-256 | `a708f5a154423a4014c15e0e3706fe67ff6824caf3511f4e31911e7197c8184d` |

## Probe and guest gate

`user/ported/xkbcommon_probe.c` creates a context with default include paths and
environment-provided layout names disabled. Its complete embedded keymap
defines `a`, left Shift, Caps Lock and left Ctrl; no host layout files or host
keyboard evaluation supply the results. Twenty-four assertions cover:

- Parsing key names and repeat metadata, with ordinary `a` text and keysym.
- Shift producing `A` and key release restoring `a`.
- Caps Lock remaining active after release, Shift reversing capitalization
  while locked, and a second Caps press unlocking.
- Ctrl becoming effective and translating `a` to UTF-8 byte `01`, followed by
  correct release behavior.
- Serializing the keymap, reparsing it into an independent keymap/state,
  retaining Shift behavior, and rejecting malformed input.

`tools/verify_xkbcommon.py` requires an exact embedded probe ELF, all result
markers, exit code zero, real AI scheduling and complete native/heap/image and
thread reclamation. It repeats the probe in one guest so a reboot cannot hide
per-run leakage. A library-only PASS is not full desktop-layout acceptance.

```sh
python3 tools/verify_xkbcommon.py \
  --elf artifacts/cosmic-bootstrap-r3/cyxia-kernel.elf \
  --output artifacts/cosmic-bootstrap-r3/xkbcommon --runs 3
```

The unified frozen kernel has SHA-256
`0d31c3fcb2668b67b31a9e1388c62579f32025aefc47babbb121560c595e2b5d`.
`artifacts/cosmic-bootstrap-r3/xkbcommon/summary.json` and its saved guest
console record three consecutive PASS executions in the same guest. Every run
completed all 24 assertions with 45 syscalls, real AI scheduling, and exit code
zero. The malformed-keymap test intentionally emits upstream parser errors
before the probe confirms rejection.

Each final process has 64 free native pages, no live threads, zero heap/image
pages in use, 4096 free heap pages and 4096 free image pages. The peak thread
count is one: this particular dependency is exercised synchronously. The exact
333304-byte probe ELF above is verified against the kernel catalog before
execution. These results establish the real parser/state fixture in EL0; they
do not expand the result to complete desktop layout or compositor acceptance.
