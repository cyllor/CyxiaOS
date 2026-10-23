# GTK 3 static cross-build

## Scope and result

On 2026-10-16, the existing isolated AArch64 musl sysroot successfully built
the eleven packages below and linked a real GTK 3 widget program. The package reports establish cross-compilation. A separate real guest
widget gate subsequently passed; its scope and image identities are recorded
below. The package build reports themselves remain build-only evidence.

| Package | Version | Verified output objects |
| --- | --- | --- |
| libpng | 1.6.56 | `libpng16.a`: 20 |
| libjpeg-turbo | 3.1.2 | `libjpeg.a`: 101 |
| Cairo | 1.18.4 | `libcairo.a`: 147; `libcairo-gobject.a`: 2 |
| GdkPixbuf | 2.42.12 | `libgdk_pixbuf-2.0.a`: 18 |
| ATK | 2.38.0 | `libatk-1.0.a`: 34 |
| Pango | 1.56.4 | `libpango-1.0.a`: 33; `libpangocairo-1.0.a`: 6 |
| libXfixes | 6.0.2 | `libXfixes.a`: 6 |
| libXrandr | 1.5.4 | `libXrandr.a`: 10 |
| libXi | 1.8.2 | `libXi.a`: 57 |
| libepoxy | 1.5.10 | `libepoxy.a`: 4 |
| GTK | 3.24.52 | `libgtk-3.a`: 539; `libgdk-3.a`: 69 |

The builder checks every ordinary archive member for ELF64 little-endian,
AArch64, and relocatable-object type. Existing musl, GLib/GObject/GIO, Xlib/XCB,
Pixman, font and text libraries come from the referenced sysroot manifests.
The list above is the additional build stage, not a claim that it is a
standalone dependency graph or an LXDE installation.

## Reproduction and evidence

`ports/libc/gtk-foundation.json` pins the official source archives and their
SHA-256 values. Hash provenance is included in that manifest, using upstream
checksum files where available and fixed Buildroot source references otherwise.
Archive bytes are verified before extraction; this is not signature verification.
Existing cached archives in `artifacts/desktop-sources` are reused.

The host needs the existing `tools/build_sysroot.py` toolchain, isolated build
tools, and native GLib resource/schema/marshal/enum/D-Bus code generators.
The tested CMake version for libjpeg-turbo was 3.31.10, installed in
`artifacts/sysroot/build-tools`; Meson and Ninja use that same host tool directory.
Target binaries are never run during configuration or compilation. Native code
generators are explicitly passed to Meson, avoiding accidental execution of a
cross-compiled GLib tool.

```sh
# Inspect pins without modifying the sysroot.
python3 tools/build_gtk_foundation.py inventory

# Build in manifest order; --fetch permits fetching missing pinned archives.
python3 tools/build_gtk_foundation.py build --fetch

# Rebuild one package after its prerequisites have been installed.
python3 tools/build_gtk_foundation.py build --only gtk

# Relink only the real GTK test program using the installed libraries.
python3 tools/build_gtk_foundation.py probe
```

Every modifying command holds
`artifacts/sysroot/aarch64-musl/.build.lock` for its full duration and fails if
another builder owns that lock. Source extraction/build directories are named
`gtk-source` and `gtk-<package>-build`, separate from the Openbox build trees.

Actual outputs, commands, licenses, source verification records, and hashes are
in `artifacts/sysroot/aarch64-musl/gtk-foundation-<package>-report.json`.
Each selected package was actually built; the reports have `status: cross-built`.
Compiler/configure/install logs are retained in the sysroot `logs` directory.
License texts are copied to the sysroot `licenses/<package>` directories;
Cairo's alternative license texts and the JPEG IJG notice are preserved as well.

## Explicit port choices

- Cairo enables software image rendering, PNG, Fontconfig, FreeType, Xlib, XCB,
  zlib and GObject integration.
- GdkPixbuf has real built-in PNG, JPEG and GIF decoders. Other loaders, TIFF
  and GIO MIME sniffing are disabled. `gdk-pixbuf-static-loaders.patch` forwards
  the actual decoder dependencies with the built-in loader archive, fixing
  the upstream static link of GdkPixbuf's tools.
- Pango enables Cairo and retains the existing synchronous Fontconfig port
  used for Openbox. This does not provide general background threads.
- GTK uses X11 and built-in input modules. Wayland, Broadway, Quartz and Win32
  are disabled. Introspection, tests, demos and examples are not built.
- `gtk-cyxia-static-single-thread.patch` adds the opt-in
  `cyxia_single_thread_compose` build option. It loads the original Compose
  tables synchronously during input-context class initialization, on the actual
  AI-scheduled caller. It does not emulate a worker or change general GTask
  semantics. The same patch checks an unavailable module handle before GTK's
  optional GTK 2/3 symbol-mixing inspection; static musl cannot open the main
  executable through `dlopen(NULL)`.
- The real ATK library is present. `gtk-optional-atspi-bridge.patch` adds an
  explicit build option to omit the AT-SPI bridge, its dependency and its
  initialization call. No bridge or D-Bus accessibility service is emulated.
- `gtk-allow-no-print-backends.patch` permits an explicitly empty backend list;
  GTK printing backends are disabled because they otherwise require dynamic
  shared modules. Printing is not provided by this build.
- Epoxy's real GLX dispatch is compiled, but no OpenGL provider is installed.
  GL widgets and GPU acceleration have not been demonstrated.

There is no dynamic loader or general guest pthread support established by
this work. Linking against musl's pthread entry points is not evidence that
the guest kernel supports creating a thread. The widget runtime gate below exercised initialization, rendering, input and
exit; it does not establish asynchronous GIO or general thread compatibility.
Unsupported calls must remain explicit errors rather than successful no-ops.

For the single-thread desktop profile, the upstream environment choices
`GSETTINGS_BACKEND=memory`, `GIO_USE_VFS=local`, `GTK_USE_PORTAL=0` and
`GTK_IM_MODULE=simple` select local implementations without a settings/session
bus or XIM service. The probe uses a plain `GtkWindow`, not a `GtkApplication`.
This does not make general asynchronous file search, icon loading, D-Bus,
portals or file monitors work without threads.

The first guest attempt (`artifacts/gtk-start-r1/console.txt`) connected to X11
but failed a real allocation while free heap pages remained. That failure is
handled by the separate kernel mapping-capacity work. The log's syscall `0x94`
was `getresuid`; GTK fell back to the existing identity queries. The kernel now
also exposes `getresuid`/`getresgid` (AArch64 syscall 148/150) for its existing
single-root identity domain. `desktop_api_probe.c` checks both libc queries,
the 32-bit result width, and ordered partial writes when any result pointer
faults. Source semantics were checked against
[Linux v6.18 kernel/sys.c](https://raw.githubusercontent.com/torvalds/linux/v6.18/kernel/sys.c)
and the
[AArch64-compatible generic syscall table](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/uapi/asm-generic/unistd.h).

## Real widget probe

`user/ported/gtk_probe.c` constructs a GTK window containing a label, editable
entry, button, and click counter. The default process remains open for manual
input. `--smoke` closes it after three seconds; `--timeout-ms N` accepts
1 through 600000 milliseconds. The timeout runs through GLib's real main loop.

The probe flushes these acceptance markers:

- `GTK_PROBE INIT_FAILED`: initialization failed; this is not a passing run.
- `GTK_PROBE READY`: widgets were created and shown.
- `GTK_PROBE WINDOW`, `ENTRY`, `BUTTON`: actual mapped window/widget geometry.
- `GTK_PROBE DRAW`: the first completed GTK draw signal.
- `GTK_PROBE CLICK count=N`: the actual button signal ran and updated its label.
- `GTK_PROBE TEXT text=...`: the entry's actual contents changed.
- `GTK_PROBE EXIT`: the main loop returned after the window was destroyed.

Build output is `artifacts/sysroot/aarch64-musl/gtk-probe.elf`, with a separate
`gtk-probe.symbols.elf` for address-to-symbol diagnosis. GTK uses function/data
sections and the executable uses linker garbage collection. The boot image is
stripped only after the symbol-bearing image passes the static ELF checks.

The completed optimized build produced:

- File size: **14,635,704 bytes**.
- SHA-256: `37d3becd3f6dc329ce30ed6e6abc586fad0ce4c271833d1576027fe01162b9c9`.
- Four load segments; page-rounded address span `0x01000000..0x01e03000`.
- No interpreter or dynamic segment; no unresolved strong symbols in the
  preserved symbol image; no segment writable and executable at the same time.

These values correspond to the probe embedded in
`gtk-foundation-gtk-report.json`. A later `probe` command writes a standalone
`gtk-probe-build-report.json`; consult the ELF hash in the applicable report
when diagnosing a particular guest image.

## Verified guest widget workflow

[The runtime report](../../artifacts/gtk-verified-release-r4/summary.json) records
**PASS** for the actual X.Org/Openbox/GTK guest. Kernel SHA-256 is
`2c1b21eb05a5ed7b43b27ed762f4ecdbbade6736f72353002c6fd4dfd4193e33`;
the GTK ELF hash matches the probe above. The test observed a mapped and drawn
GTK window, clicked its real button through the virtual input device, edited
the entry to `aA`, and closed the window with Openbox Alt+F4. GTK exited with
code 0, all three processes released their image and heap grants, and the
serial shell remained responsive. The report retains every target ELF hash,
AI dispatch counters, widget geometry, QMP input transcript, console output
and the actual framebuffer capture.

```sh
python3 tools/desktop.py --app gtk
# Verify a graphics,gtk kernel without rebuilding it during the gate.
python3 tools/verify_gtk.py \
  --elf target/aarch64-unknown-none-softfloat/release/cyxia-kernel \
  --output artifacts/gtk-verified
```

The successful image includes 512 anonymous-allocation records per process,
eight process slots and a 64-page process admission pool. X.Org had 232 of
2048 anonymous pages free at the recorded interaction point; adding windows
requires a fresh capacity test. This is a GTK widget workflow, not PCManFM,
LXPanel, terminal, persistent storage or a completed LXDE session. Subsequent
kernel changes, including threads and filesystem expansion, require new guest
reports instead of inheriting this PASS.
