# PCManFM GTK 3 port

This stage uses the actual LXDE file manager and its libraries. It adds no
replacement desktop shell, GTK widget wrapper, fake worker, or fake filesystem.
Cross-compilation and guest acceptance remain separate gates.

## Fixed inputs and build procedure

The package identities are the existing pins in `ports/desktop/manifest.json`:

| Source | Version | Git commit |
| --- | --- | --- |
| libfm / libfm-extra | 1.3.2 | `695d3e863440b50c50c53ff7287b24b42a624a9e` |
| menu-cache | 1.1.0 | `3a44b8179009eb212fd762d5b1ce0153f00ec09e` |
| PCManFM | 1.3.2 | `94e7f39699014e1661ce2402de8e965722beee99` |
| lxmenu-data | 0.1.5 | `3b14415ff9862e6b79577fd4b9a097965001b270` |

`desktop_ports` fetches the exact commit, verifies its Git objects, and verifies
the resulting source tar against the recorded SHA-256. These checks do not
claim signed commits. The build uses each package's real Autotools scripts and
the isolated AArch64 musl sysroot, including the existing GTK 3 port.

`ports/libc/pcmanfm-foundation.json` defines the staged bootstrap order and
fixed native build-tool archives. Intltool 0.51.0 comes from Debian's unchanged
upstream archive mirror because the original Launchpad transfer failed; its
hash is checked against the recorded upstream-archive hash. GTK-doc 1.34.0
comes from GNOME's archive and published checksum. Host-only Pygments is
pinned with a wheel SHA-256 in `pcmanfm-host-tools.lock`. Host and target tools
are installed separately. Source COPYING files and their hashes are preserved.

```sh
python3 tools/build_pcmanfm.py inventory
python3 tools/build_pcmanfm.py host-tools --fetch
python3 tools/build_pcmanfm.py build --fetch

# Rebuild just one stage after its prerequisites are installed.
python3 tools/build_pcmanfm.py build --only pcmanfm
python3 tools/build_pcmanfm.py verify
```

Every modifying command acquires the shared sysroot `.build.lock`. The default
inventory command is read-only. Stage source/build directories are separate
from the GTK and Openbox trees. No target program is run on the host.

## Source adaptations

- `libfm-vpath-generated-headers.patch` adds build-directory include paths for
  the real generated marshal/version headers when source and build trees are
  separate.
- `libfm-optional-modules.patch` adds an explicit `--disable-modules` option,
  leaving upstream's default enabled. This static target omits optional
  dynamically loaded modules. It retains the core local-directory/file code.
  Applications virtual folders, search modules and plugin property/menu
  extensions are not provided by this profile.
- `libfm-static-pkgconfig.patch` records the real private menu-cache dependency
  in libfm's pkg-config metadata so static consumers link its implementation.
- menu-cache 1.1.0 is compiled with `-fcommon`: that release has tentative
  definitions in shared headers. This preserves its original C compilation
  semantics under modern Clang.
- The target explicitly disables UDisks, EXIF acceleration, old Vala actions,
  the libfm demo and documentation. It enables GTK 3. Native code generators
  and translation tools remain real upstream programs.

All installed static archive members are checked for AArch64 ELF64 relocatable
objects. Build commands, source/archive hashes, output hashes, options and
licenses are recorded under
`artifacts/sysroot/aarch64-musl/pcmanfm-*-build-report.json` and per-stage
`pcmanfm-*-report.json`. The final executable is checked before symbols are
removed; `pcmanfm.symbols.elf` preserves its symbol table for fault diagnosis.
The compact artifact is `pcmanfm.elf`.

The initial build completed on 2026-10-16; the current build also includes the
explicit catalog-spawn profile described in [glib-catalog-spawn.md](glib-catalog-spawn.md).
The authoritative current executable bytes, SHA-256 and segment layout are
recorded in `artifacts/sysroot/aarch64-musl/pcmanfm-verified-report.json`.
Its four load segments occupy the page-rounded range
`0x01000000..0x01e80000`, within the current 16 MiB image window. The static ELF
checks pass: no interpreter/dynamic segment, no unresolved strong symbol in
the retained symbol image, valid entry point and W^X permissions.

`libfm-extra.a`, `libmenu-cache.a`, `libfm.a` and `libfm-gtk3.a` contain
1, 1, 35 and 37 verified AArch64 objects respectively. The actual `menu-cached`
and `menu-cache-gen` helper executables were also built and statically checked.
Thirteen installed libfm/PCManFM UI XML files parse successfully. The current
installed file hashes, ELF layouts, helper outputs and resource inventory are
in `pcmanfm-verified-report.json`; per-stage reports preserve their own build
snapshots, including the extra library before the full libfm stage reinstalls it.
These static reports alone do not establish guest behavior. Separate real guest
gates are recorded below.

## Real runtime requirements

Reading the pinned sources establishes that **a normal local-directory window
requires working threads**. No upstream configuration flag removes this
requirement. The existing synchronous GTK Compose/Pango paths do not replace
libfm's asynchronous jobs.

| Requirement | Actual call path / configuration boundary |
| --- | --- |
| GThreadPool | PCManFM `src/pcmanfm.c:491` → `main-win.c:1706` → `tab-page.c:1004,1048` → libfm `fm-folder.c:1192,1200` → `fm-job.c:232,269`. Every directory reload schedules a real listing job. |
| GTask workers | libfm `fm-folder.c:1481` queries filesystem space asynchronously; GLib `gfile.c:6221–6225` dispatches a worker. `fm-path-entry.c:578–581` also performs asynchronous completion. |
| Thread lifecycle | GLib 2.86.5 starts `pool-spawner` in `gthreadpool.c:633`, and GTask starts `gmain` through `gmain.c:6791`. `gthread-posix.c:762` invokes real `pthread_create`. TLS, scheduling, waits, wakeups, mutex/condition and exit/join semantics are required. |
| File monitoring | libfm `fm-folder.c:1176` requests a monitor. Failure can allow the first listing to proceed, but does not establish live updates. Polling fallback also uses GTask workers. |
| Optional work | Existing template directories trigger jobs; `[ui] show_thumbnail=0` suppresses thumbnail generation. Neither setting removes directory workers. |
| Module loading | `fm-module.c:392` calls `dlopen` before testing its blacklist at line 403. An empty module directory and no deployed `.so` avoid the load; a blacklist alone does not. |
| menu-cache daemon | Application menus/selectors use loader and I/O threads. If no daemon is running, `menu-cache.c:1563–1575` forks, executes and waits for `menu-cached`; the daemon launches the actual `menu-cache-gen`. The basic local-directory listing does not itself require this daemon. |
| D-Bus | PCManFM single-instance IPC uses UNIX sockets (`single-inst.c:187–237`). UDisks is disabled; local GIO and no GVfs modules can avoid a session bus for a local window. Turning off automount does not suppress the volume-monitor API call. |

Minimal guest configuration can use `GIO_USE_VFS=local`,
`GSETTINGS_BACKEND=memory`, `GTK_USE_PORTAL=0`, `GTK_IM_MODULE=simple`, disabled
thumbnail generation, disabled automount, and empty dynamic module directories.
That narrows optional behavior; the guest now supplies actual pthread/clone,
mutex, condition, worker and exit/join behavior. No `pthread_create`, GTask or
file-operation success is faked.

Further guest acceptance also requires appropriate MIME/icon/menu/UI assets,
actual writable directory operations, and persistent storage for the desktop's
reboot-survival criterion. A linked ELF alone satisfies none of those runtime
criteria.

## Deployed desktop profile and failure handling

`ports/desktop/pcmanfm-rootfs.json` pins the 19 required configuration, UI and
image resources. `python3 tools/build_pcmanfm.py install-assets` validates all
hashes, paths and XML before installing them; no unrelated rootfs file is removed.
The desktop background is `#1b2738`. Blank-desktop right-click is forwarded by
upstream `show_wm_menu=1` to the actual Openbox root menu. This menu and LXPanel's
menu use explicit Files, Terminal and Save Files items, with real command
execution. They do not scan installed applications through menu-cache.

GdkPixbuf's upstream built-in XPM loader is enabled for XPM window icons.
A separate static-link defect omitted libwnck's embedded PNG fallback icon
resource: the rename dialog exposed it when the panel requested a fallback.
The libwnck static-build patch now references the real generated resource
getter so the linker retains its object and registration constructor.
The LXPanel builder verifies that symbol survives before stripping.
`artifacts/desktop-menu-r2/session/console.txt` and `desktop-menu-r3` retain
the distinct XPM warning and missing-GResource failure for diagnosis.

`menu-cache-missing-service-error.patch` converts the missing menu-cached
executable from a fatal process abort into an explicit warning and connection
failure, preserving upstream's existing failed-load completion. The daemon and
application scanning are not deployed. An application chooser can therefore
have an empty application list; this is not evidence of menu-cache support.
Dynamic modules, automount, thumbnails, arbitrary Linux execution and a full
LXDE installation remain outside this profile.

## Guest acceptance

`artifacts/filemanager-large-r3/summary.json` records the actual GTK file-manager
window, physical keyboard directory creation and rename, byte preservation,
window close and reclamation. The desktop plus directory window share the real
PCManFM UNIX-socket single-instance IPC. Files actions create a real temporary
catalog child which sends its directory request to the resident PCManFM.

`tools/verify_desktop_menu.py` separately checks physical panel launch, GUI
rename, root-menu execution, the X11 Save Files dialog, actual VirtIO flush,
and file recovery in a fresh VM. It passed in
`artifacts/desktop-integrated-r4/menu/summary.json`, using kernel SHA-256
`f432d168507faf0276f97dd4689401314d91d9b90c5b08c67ca054b990a929ee`.
The current PCManFM SHA-256 is
`401d01cbcaa853dde747511577546dc6848222d51a5303bed6f703e904d9ee7d`.
The missing application service completed with an explicit warning while the
file manager survived; cancelling the chooser restored normal operation.
The root-menu test closed the old directory first and required a new window ID
and a child whose parent was Openbox. Saving required two completed VirtIO
flushes and staging-grant reclamation before success. All application resource
ledgers returned to their capacities afterward. The independent fresh-VM
`menu/exact-saved-file.json` additionally confirms the exact 21-byte value;
uncheckpointed changes did not survive reboot.

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
