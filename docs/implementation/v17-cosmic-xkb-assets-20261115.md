# Installed COSMIC keyboard rules and immutable mappings

This stage continues the approved complete CyxiaOS/COSMIC plan from `6b3461d`.
It implements `docs/superpowers/specs/2026-11-15-cosmic-xkb-assets.md`.
Evidence is in `artifacts/v017-cosmic-xkb-20261115-r1/`.
Complete OS and COSMIC session verification remain false.

## Real failure and implementation

`baseline-01` replays the unchanged compositor and exits 134 at
`Failed to load xkb configuration files: BadKeymap`. The selected rootfs lacked
`/usr/share/X11/xkb/rules/evdev`. Source inspection also establishes that the
actual SDK library has `HAVE_MMAP=1`: its rules/component reader calls fstat
and `mmap(PROT_READ, MAP_SHARED)` with no read fallback. Boot resources could
already be opened/read/stat'ed, but file mappings accepted only memfds.

`tools/install_xkb_data.py` verifies the existing xkeyboard-config 2.42 pin,
extracts a fresh source tree, and runs the upstream rule generators with isolated
Python. Its recipe matches upstream's compatibility-enabled evdev target.
All fourteen generated outputs are produced twice and compared byte for byte.
It copies 27 complete include files, geometry/pc, COPYING and generated evdev;
it never substitutes libxkbcommon's altered test keyboard database.

`xkb-assets-01` contains 30 assets totaling 353,200 bytes, using 13 directory
nodes and a maximum 39-byte path. With eight actual executables, the final
catalog has 38 entries, within the existing 128-file limit. The generated
evdev file is 36,104 bytes. Every source, script, interpreter and installed file
has a recorded identity. Existing outputs are refused; failed generation does
not publish a rootfs or success receipt. Initial support is explicitly
`evdev/pc105/us` with empty variant/options; other layouts are not claimed.

Bootfile mappings now use admitted, zeroed heap pages and actual PTE protection.
Since the backing bytes are immutable, read-only MAP_SHARED snapshots remain
coherent without introducing a second mutable backing owner. A per-page write
ceiling prevents later shared mprotect write upgrades, including from PROT_NONE;
rejected changes are atomic. MAP_PRIVATE copies may become writable without
altering another mapping or original bytes. Mapping does not move the OFD offset,
and mapped bytes remain valid after close. Invalid offsets, empty ranges,
unsupported protections and whole pages beyond EOF are rejected before allocation.
The final partial file page is zero-padded. General mutable-file mmap, lazy COW,
SIGBUS beyond EOF and partial-allocation munmap are outside this change.

## Verification

`vm-red.log` and `ofd-red.log` preserve failing behavior assertions before the
implementation: write upgrades succeeded, the snapshot validator was absent,
and the typed source accessor returned no bootfile. `host-green.log` passes all
238 full-os POSIX unit/integration tests. `python-final.log` passes 24 tests,
including changed/missing/duplicate/foreign asset receipts and nondeterministic
generation refusal. Both fresh independent Standards and Spec reviews are clean.

The first native `xkb-rules-01` capture fails before program entry because its
new name was missing from the shell's explicit launch list. The entry was added;
the failed capture is retained. The first successful keyboard build `os-build-02` has compiled source SHA256
`f5fb9bda5aaf3fa1f8065ba512ca882f10ed91664a2c772b36060829d34fdc09`.

`xkb-rules-02` is `OS_XKB-RULES_PASS`. It runs the actual x86 musl/libxkbcommon
probe twice, each execution passing all 73 assertions and exiting zero:
installed by-names compilation; a/A, production 6/^, Shift/Caps/Ctrl/Return;
independent serialization/reparse; missing-rule, absent-include and malformed
rejection; mapping byte equality, offset/lifetime/EOF, shared write denial and
private isolation. Each run reaches 174 heap pages and 83 allocation records;
all heap/image pages, threads and open descriptions return to their initial
state. Capture binds the probe, actual library build receipt, assets, kernel
embedding, raw UART, four CPUs and final source identities.

Probe ELF SHA256:
`af80e09a7ce4bf720e5fdff413e8989fee5d3d488c4f3cdfb920b781e165f89f`.
The unchanged compositor SHA256 remains
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.

Final review also required a real probe failure at the unsupported mmap seam.
`old-mmap-build` / `old-mmap-red` perform a **controlled regression replay** after
implementation: keep the exact same probe and installed resources, remove only
the bootfile dispatch branch to restore the former memfd-only path. The real
program opens, stats and reads the rules, then fails at
`XKBRULES_PROBE FAIL stage=rules-mmap-shared ... errno=22`.
`old-mmap-replay.json` records both source hashes and confirms byte-identical
restoration of the final source in a finally block. This is not described as a
chronologically earlier native test. The final build/source binding is rechecked
after restoration; final successful captures remain bound to os-build-03.

## Mapping-record capacity measured in the compositor

`cosmic-observe-01` no longer reports missing rules, but the real process reaches
all 512 allocation records. A one-page mmap is refused with 590 free pages;
peak usage is 7,615 pages. A NULL write follows (vector14/error6, instruction
0x2d02a78), ending139 with all pages/objects reclaimed. This run does not prove
completed keyboard initialization or a desktop frame.

`records-red-01` isolates the bound using one-page allocations. It fails at
512 mappings/512 pages with 7,680 pages still free. Full-os allocation and grant
metadata are now bounded at 1,024 records; legacy remains512. Physical heap
capacity, the model8198 reserve and 2,048-page per-request cap are unchanged.
The extended heap probe in `heap-capacity-final` passes twice: it reaches1,024
live records, rejects the next allocation, preserves all live payloads, frees
alternating slots, verifies zeroed nonaliasing replacements, then reclaims all.
The existing8,160-page capacity and32-page reserve checks still pass.

Final build is `os-build-03` with `sysroot-records`; its compiled source SHA256 is
`2e528f72615d8bca10a7e1924bd3c51310bd79113876ea9b2ece4dc05064df9b`.
The identical extended heap probe ELF in RED and GREEN has SHA256
`4461bf6ba37da59a86f41727dffb8f7be584f94985ab93f5b803737447b12901`.
Both independent reviewers also reviewed this measured follow-up and found no
concrete Standards or Spec issues.

## Unchanged compositor replay and next boundary

`cosmic-observe-02` advances beyond keyboard-file loading and the old mapping
record ceiling, but reaches a new notify panic. Its general panic guard aborts
the capture; that FAIL remains retained. A separate observer permits only the
exact identified notify user panic through termination, retaining all fatal
kernel guards and raw bytes. `cosmic-observe-03` is OBSERVED_PROCESS_END,
Exited134, identity preserved and QEMU return0. It is not a session PASS.

The capture first shows one 8-page shared object at this new boundary. In the
pinned Smithay source, `KeyboardHandle::new` (keyboard/mod.rs:761) calls
`KeymapFile::new` only after keymap compilation succeeds; keymap_file.rs:33–36
serializes it into a sealed `smithay-keymap` memfd. This supports keymap
serialization having completed, as an inference from source order and the
observed shared object, rather than a captured keyboard-ready log message.

Peak heap is 8,144 pages with 531 records; a 515-page request is refused with
49 pages free. Upstream notify 8.2.0 `EventLoop::run` ignores thread-spawn failure
at src/inotify.rs:122–125; its subsequent `watch_inner` channel send panics at558.
The request size is consistent with a musl thread stack plus guard/TLS overhead,
and the ignored spawn failure explains the later closed channel. No original
BadKeymap or Mesa allocation assertion is present. Unsupported syscall 89
(readlink on x86-64) is also observed; its separate compatibility gap is not
claimed fixed or established as the allocation failure cause. Display completions
remain zero.

All 4,270 successful anonymous grants are released, with 32,222 cumulative
pages granted/released. Final heap/image capacity is 8,192/16,384; live pages,
threads, open descriptions, shared objects/mappings and shared grants are zero.
`heap-capacity-final`, `xkb-rules-final`, `native-final`, `thread-exit-final`,
`inotify-final`, `nested-epoll-final` and `flock-final` all pass on os-build-03.
Default workspace 1,444 tests, legacy large-memory POSIX 236 tests and ARM legacy
compilation pass. The progress checker rejects the original baseline and accepts
only this verified dependency/metadata advance and complete reclamation;
full-OS/session verification remains false.

Next work is a measured production heap/thread-memory capacity change that
respects the 1 GiB firmware reservations. This stage does not bypass the model,
shrink upstream stacks, or claim a completed desktop.

## Replay and workflow follow-up

Use `tools/install_xkb_data.py --output NEW_DIRECTORY` under the shared native
lease, copy its rootfs and report.json (as xkb-assets.json) into a fresh curated
OS sysroot, and add the genuine `xkb-rules-probe` ELF/layout built by
`tools/build_sysroot.py probes --arch x86_64 --probe xkb-rules-probe`.
Build with os_x86.py full-os/cosmic-desktop and run os_smoke.py `--scenario
xkb-rules` plus `--scenario heap-capacity`. The installer is offline; an absent
archive is fetched separately using desktop_ports.py's pinned manifest.

A probe has three launch registrations: build_sysroot PROBES, kernel/build/os.rs,
and crates/shell's explicit command list. The actual native scenario catches
missing wiring; keep it in the stage's required replay set. Existing
validate-current and desktop-port CI discover the new Python tests automatically;
complete native XKB/COSMIC replay still requires the prepared real SDK/assets.
