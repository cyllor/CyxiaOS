# CyxiaOS initial US keyboard data

This port builds **host tools only**, then produces a real XKM keymap for the
CyxiaOS X server. It does not add a Linux runtime, host display connection, or
target-side `xkbcomp` execution. The target loads the data through upstream
`XkmReadFile`.

The manifest fixes xkbcomp 1.4.7, xkeyboard-config 2.42, and the complete host
X11/XCB/libxkbfile source closure by SHA-256. The source archive URL is official
upstream for every package. The xkeyboard-config checksum is independently
recorded in the linked immutable OpenEmbedded recipe; the manifest records that
distinction. Archive signatures are not claimed as verified.

From the project root:

```sh
python3 tools/build_xkb.py inventory
python3 tools/build_xkb.py build --fetch   # retrieve missing pinned sources once
python3 tools/build_xkb.py build           # subsequent fully offline rebuild
python3 -m unittest tests.host.test_build_xkb -v
```

Required host tools are clang, make, pkg-config, patch, and Python 3.12+ (the shared
archive verifier uses the safe tar extraction filter). The current verified
host is macOS arm64. XKM uses native-endian fields; this initial build requires a
little-endian host matching the AArch64 guest. Each build gets a fresh directory below
`artifacts/xkb-host/runs`; it never reuses target libraries or a previous build's
objects. `PKG_CONFIG_LIBDIR` selects only the freshly built host prefix. All
source files, licenses, commands, and build logs remain available there.

The host-only libxkbfile patch initializes serialized wire structures to zero.
Upstream 1.1.3 left explicit padding uninitialized: the first comparison found
72 differing padding bytes across otherwise identical 12,052-byte keymaps.
This small source correction prevents stack contents entering the generated
asset; it does not change key symbols, types, or geometry. Both the patch and
the pristine source file have fixed checksums in the manifest. Target libxkbfile
is not modified by this build.

`cyxia-us.xkb` selects evdev keycodes, complete types/compatibility, standard PC
US symbols, and pc105 geometry. An explicit empty `-I` clears the compiler's
implicit include path before adding the verified xkeyboard-config source root.
No host-installed keyboard layouts can supply missing inputs. The complete
upstream source database remains in the build's `source` directory; generated
rules for dynamic layout selection are outside this initial fixed-map scope.

Successful builds atomically publish:

```text
artifacts/sysroot/aarch64-musl/rootfs/usr/share/X11/xkb/cyxia-us.xkm
artifacts/xkb-host/report.json
```

The report gives the exact asset hash and size, source provenance, host compiler
path, and verification results. Before publication the script:

1. Compiles the same verified inputs twice and compares every output byte.
2. Decompiles the XKM with the upstream compiler.
3. Loads it with upstream libxkbfile `XkmReadFile`, requiring key names, types,
   compatibility, symbols, virtual modifiers, and geometry.
4. Verifies evdev keycode range 8–255, q/Q, a/A, 2/@, Return, and the Shift
   modifier. Evdev event codes need the X11 `+8` conversion at the DDX boundary.
5. Confirms the reader rejects a truncated file.

These host checks validate the keyboard data. They do not establish guest input
delivery or completion of a desktop session. The guest must expose the complete
read-only asset (larger than the small writable AI filesystem's per-file limit),
load it successfully, and exercise actual VirtIO keyboard events through XKB.
