# Real GLib process launching on CyxiaOS

The opt-in `cyxia_spawn` GLib build profile uses CyxiaOS's private catalog-process
creation ABI. It creates a new isolated ELF process with actual inherited pipe
references, then uses real `wait4` and SIGCHLD for child completion. It does not
provide `fork`, `vfork`, `execve`, or arbitrary child-setup callback emulation.

## Verified GLib behavior

`user/ported/glib_spawn_probe.c` passed inside the ARM guest on 2026-10-18:

- `g_spawn_sync`: PATH selected from the supplied environment, copied argv/envp,
  `/tmp` working directory, captured stdout/stderr and actual child exit code 7.
- `g_spawn_async_with_pipes`: parent wrote the child's stdin pipe; child output
  was read from its stdout pipe after exit code 9.
- `g_child_watch_add`: the real GLib worker/main context observed SIGCHLD and
  collected the child through the kernel's wait mechanism.
- A missing executable reported `G_SPAWN_ERROR_NOENT` and released temporary
  pipe descriptors. An arbitrary child-setup callback was explicitly rejected.
- Child and parent executable/heap grants were reclaimed after termination.

Evidence: `artifacts/glib-spawn-runtime-r1/session/console.txt` and its immutable
`cyxia-kernel.elf`, SHA-256
`45e19b301379658b2517e7bbcf673408e521d5fe028ca7f2f42fc0299efda65c`.
The tested probe SHA-256 is
`cf2ecb163a9020e32d83d811d75b7d1d40bfaa399f60f04933afe3db675fdc54`.
These results establish the enumerated GLib process APIs, not general Linux
program execution or all GIO launch semantics.

## Explicit platform adaptations

`ports/libc/patches/glib-cyxia-spawn.patch` adds a Meson option which defaults to
false. When enabled for AArch64, `gspawn-posix.c` routes the already-created real
pipes to the private spawn request. It preserves standard stream redirection,
explicit descriptor remapping, close-on-exec behavior, environment/PATH search,
working directory and automatic-reap selection. General callbacks are rejected
with an error. Unsupported descriptor types fail in the kernel rather than
silently becoming a different endpoint.

The same profile disables only the unsupported SA_RESTART/SA_ONSTACK flags in
GLib's signal-source installation; SA_NOCLDSTOP remains. GDesktopAppInfo launches
the selected executable directly instead of starting `gio-launch-desktop`,
whose final step requires `execve`. The helper's optional journald redirection
and child-specific `GIO_LAUNCHED_DESKTOP_FILE_PID` environment setup are not
implemented by this direct-launch profile.

`ports/libc/patches/libfm-cyxia-spawn.patch` is activated by the explicit
`__CYXIA_CATALOG_SPAWN__` build define. libfm prepares DESKTOP_STARTUP_ID in a
copied child environment instead of invoking a fork-time callback. Process-group
relocation through `setpgid` is unsupported and omitted in this profile. This
does not claim process-group/session compatibility.

## Request boundary

Syscall `0x43595810` accepts a 64-byte request. The fields are, in order:
`u32 size`, `u32 flags`, five `u64` user pointers for path/argv/envp/cwd/mappings,
`u32 mapping_count`, `u32 reserved`, `u64 reserved2`. Reserved fields are zero.
Flag bit 0 requests automatic reaping. A mapping is `{i32 source, i32 target}`:
nonnegative sources refer to parent descriptors, -2 requests a real `/dev/null`
endpoint, and -1 leaves the target closed. Targets are unique and below 16.

The kernel copies and validates the request before publishing a child, enforces
its catalog/path/argv/environment limits, obtains real AI-governed process and
memory grants, and owns the resulting process lifetime. `wait4` supports an exact
child PID or -1 and WNOHANG; unsupported resource-usage output is rejected.

## Reproduction

```sh
python3 tools/build_openbox.py foundation --only glib --cyxia-spawn
python3 tools/build_glib_spawn_probe.py
python3 tools/build_pcmanfm.py build --only libfm --cyxia-spawn
python3 tools/build_pcmanfm.py build --only pcmanfm --cyxia-spawn
python3 tools/build_lxpanel.py build --only lxpanel
python3 tools/build_openbox.py build
python3 tools/build_gtk_foundation.py probe
```

Build a kernel with `ported,spawn-test` (and the desired memory profile) to embed
the optional GLib probe, then run `posix exec glib-spawn-probe`. Production
desktop builds omit this probe to preserve the boot-catalog budget. The source
patches are applied from freshly verified archives; all build tools share the
sysroot lock. Rebuild every statically linked application after changing GLib
or libfm. Older accepted executables are retained in
`artifacts/desktop-before-spawn-elfs/` with their hashes.

## Desktop consumers

The real upstream LXPanel Menu plugin runs explicit Files, Terminal and Save
Files `action` commands through libfm and this GLib backend. No `system {}`
menu-cache application scan is configured. Openbox's genuine static root menu
uses `Execute`, which calls `g_spawn_async` with no arbitrary child callback.
PCManFM's resident desktop receives additional directory windows through its
real UNIX-socket single-instance protocol; the temporary catalog child exits
after forwarding that request.

Save Files launches the small X11 `cyxia-save` utility, which submits the real
checkpoint service and reports completion only after guest VirtIO disk flush.
Process creation alone is not storage durability: the combined physical-menu
and fresh-VM recovery gate is `tools/verify_desktop_menu.py`. It passed independently of the GLib API probe in
`artifacts/desktop-integrated-r4/menu/summary.json`, kernel SHA-256
`f432d168507faf0276f97dd4689401314d91d9b90c5b08c67ca054b990a929ee`.
The observed Files child was 21 (parent LXPanel 14); the root-menu child was
30 (parent Openbox 2), and the Save Files child was 37 (parent LXPanel 14).
The latter reported success only after the kernel's durable-generation marker
and two VirtIO flushes, then exited with status 0. A fresh VM recovered the
saved file; `menu/exact-saved-file.json` separately verifies its exact size.
Those PID numbers identify this captured run, not fixed runtime identities.

The menu-cache daemon is not installed. Missing daemon launch now returns an
actual library connection failure and warning rather than aborting the entire
file manager. That failure handling does not implement daemon scanning or
Linux `fork`/`execve`. An empty application list remains a visible limitation.

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
