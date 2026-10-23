# LXPanel GTK3 static port

The real upstream LXPanel 0.11.1 executable cross-built successfully on
2026-10-18 against the existing AArch64 musl/GTK3/libfm sysroot. This document
records compilation, deployed resources and real guest acceptance. The combined
spawn/menu/clock profile passed the physical menu and durable-recovery gate.

## Source and output identities

`ports/desktop/manifest.json` pins LXPanel to commit
`b90d169002d4ac9c8b24a577c8be8f2e654409a8`. The two additional dependencies in
`ports/libc/lxpanel-foundation.json` are libwnck 43.3 and keybinder 0.3.2. The
builder verifies cached source hashes/commits, checks license files, and never
executes an ARM target program on the host.

| Artifact | Result |
| --- | --- |
| `artifacts/sysroot/aarch64-musl/lxpanel.elf` | 15,030,576 bytes, with explicit CyxiaOS spawn libraries |
| Executable SHA-256 | `33bbf2344256b98322ee7478f6c65b1fd8774bd1ba10cbe353347c528eff5a09` |
| Symbol-image SHA-256 | `23d6ae7906456dc4ecabb2276c62bc9ee247a7e6ca60a48cbcf7cf705dd89cf4` |
| ELF contract | AArch64 ET_EXEC, no interpreter/dynamic segment, four non-overlapping W^X load segments below `0x02000000` |
| Link validation | No unresolved strong symbols in retained `lxpanel.symbols.elf` |

The build uses upstream built-in plugins. Dynamic plugin loading, optional
network/device/volume plugins, indicators, and ALSA are disabled through real
upstream configure options. No OS calls are replaced with successful stubs.

Three LXPanel/dependency build patches are retained:

- libwnck honors Meson's static-library selection, exports its Xi static dependency,
  and retains the real generated GResource object/constructor for its PNG fallback icon.
- keybinder permits explicitly disabled introspection without host introspection macros;
  enabling introspection without those macros still fails.
- LXPanel's out-of-tree build finds generated `panel.h` and creates the generated UI directory.

GdkPixbuf additionally enables upstream built-in XPM decoding for window icons.
This is separate from libwnck's default PNG icon, which is an embedded GResource.
The real rename-dialog test exposed the dropped resource object in static
links. A reference to its generated getter retains its registration constructor;
the builder checks the symbol before stripping to prevent that regression. Missing
menu-cached reports an explicit connection failure through a narrow menu-cache
error-handling patch; dynamic application scanning remains unavailable.

## Reproduction

The existing musl, X11, GTK3, PCManFM/libfm foundations and pinned native build
tools must already be built. Fetching is opt-in; normal builds use verified cache.
For desktop application launching, first build the opt-in GLib/libfm profile
described in [glib-catalog-spawn.md](glib-catalog-spawn.md).

```sh
python3 tools/build_lxpanel.py build
python3 tools/build_lxpanel.py verify
python3 tools/build_pcmanfm.py install-assets
python3 tools/build_lxpanel.py install-assets
```

Use `--only libwnck`, `--only keybinder`, or `--only lxpanel` for an isolated
rebuild. Every mutation holds the shared sysroot `.build.lock`; a concurrent
builder fails rather than altering another build's files. The source is freshly
extracted and verified for each rebuild.

Reports are written under `artifacts/sysroot/aarch64-musl/`:
`lxpanel-{libwnck,keybinder,lxpanel}-report.json`, per-stage build reports,
`lxpanel-verified-report.json`, and `lxpanel-assets-report.json`. Earlier failed
logs remain in `artifacts/lxpanel-*-r*.txt` for diagnosis; the successful LXPanel
compile/install log is `artifacts/lxpanel-panel-build-r3.txt`.

## Runtime profile and resources

`ports/desktop/lxpanel-rootfs.json` pins eight resources, including actual
upstream preference UI files and images, plus the CyxiaOS panel/config files.
`install-assets` validates all source sizes, hashes, target paths and XML before
writing any asset. Individual replacements are atomic. It preserves unrelated
rootfs resources. Host tests cover hash failure before writes, duplicate/escaping
paths, destination symlink escape, and repeatable installation.

The default profile requests a bottom 1024-wide, 32-high panel, an icon-only
application menu, show-desktop button, one-workspace pager, taskbar and UTC clock.
The static menu contains Files, Terminal and Save Files commands and does not
start the system application-menu daemon. These are the actual upstream
Menu plugin's explicit `item { action=... }` entries, not generated menu-cache
application scanning. The same three commands are deployed in the genuine
Openbox root menu for blank-desktop right-click. Run `posix exec lxpanel` in a kernel
built with the `graphics,lxpanel` features after Xorg and Openbox are ready.
The `lxpanel` feature includes `pcmanfm` and Openbox, while keeping the standalone
GTK probe out of the combined desktop catalog.

Both LXPanel and PCManFM initialize real libfm workers and require working
pthread/clone/futex support. Menu actions use the explicit real catalog-process
spawn/wait API through the opt-in GLib/libfm profile. The UTC clock is enabled
only after the PL031 clock/gettimeofday probe passed in
`artifacts/desktop-background-r2/console.txt`; the initial environment must set
`TZ=UTC`. Save Files uses the guest checkpoint service and its durable result;
closing a window does not imply that unsaved filesystem changes reached disk.

```sh
python3 tools/verify_panel.py --elf /path/to/cyxia-kernel \
  --output artifacts/panel-verified
```

This gate checks the exact embedded executable identities, guest X11 window
geometry, physical QMP mouse interactions with taskbar/show-desktop, and full
image/heap reclamation when all application groups stop. Its JSON and guest
console are the authority for runtime status.

The initial taskbar/show-desktop gate passed in
`artifacts/panel-verified-r1/summary.json`, using kernel SHA-256
`90325ac73b6ab44d61bfab5f60edcb7794853dcd5f4e7dab5569412ab6049726`
and the pre-spawn LXPanel image
`80133e70036ea6f95379a9e87316a941b386b4b936459034047463840ab27225`.
It observed the actual upstream panel and PCManFM window, physically minimized
and restored that same X window, exercised show-desktop in both directions, and
reclaimed all four process groups. The screenshot is
`artifacts/panel-verified-r1/desktop.png`.

`tools/verify_desktop_menu.py` passed for the current menu profile in
`artifacts/desktop-integrated-r4/menu/summary.json`, kernel SHA-256
`f432d168507faf0276f97dd4689401314d91d9b90c5b08c67ca054b990a929ee`.
The gate verifies the actual parent/child admissions, GUI file rename, the
missing application-service error without a process abort, and a newly opened
PCManFM window from the real Openbox root menu. Save Files completed two actual
VirtIO flushes; storage returned all 128 staging pages before the dialog
reported success. The save child exited with status 0, and all application
threads, floor pages, image grants and heap grants were reclaimed. A fresh VM
recovered the saved file and excluded subsequent unsaved changes.

A separate `menu/exact-saved-file.json` fresh-VM check confirms the saved value
and its exact 21-byte size. This supplements the physical run, which started
before that last content-length assertion was added to the reusable script.
The actual screenshots are `menu/desktop-saved.png` and
`menu/desktop-root-menu.png` beneath the same r4 artifact directory.

The deployed Openbox profile also binds Alt+right-button drag and all four
window corners to its real Resize action. Reinstall those resources with
`python3 tools/build_openbox.py install-assets`; rebuilding Openbox is unnecessary
for a configuration-only change.

## Seven-process desktop peak

The same r4 kernel passed `tools/verify_desktop_peak.py` in
`artifacts/desktop-integrated-r4/peak-seven-r3/summary.json`. Xorg, Openbox,
PCManFM desktop and LXPanel remained resident while the actual menu launched
Cyxia Terminal and its EL0 PTY shell. Physical keyboard input wrote a 17-byte
file. Save Files then became the seventh live process and completed two
VirtIO flushes, with eight floor pages still free and all 128 storage staging
pages returned. The test did not create an eighth X11 inspector during this
peak. It located the actual painted save window in the framebuffer and clicked
Close; the save, shell and terminal exited with status 0. All thread, image,
heap and floor grants were reclaimed after cleanup, and a fresh VM recovered
the exact terminal-written file.

`seven-processes-saved.png` in that evidence directory shows the real terminal
and save dialog together. A zero-heap shell correctly has no heap allocation
model decision; every process that allocated heap had model 8194, and all seven
used CPU model 12290. This is a measured seven-process profile, not a claim of
unbounded process capacity or a full Linux/LXDE system.
