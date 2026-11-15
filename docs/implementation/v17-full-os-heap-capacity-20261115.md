# Full-OS v2 anonymous memory

This continues the complete CyxiaOS/COSMIC plan from `4d22e83`, against
`docs/superpowers/specs/2026-11-15-full-os-heap-capacity.md`.
The unchanged compositor has advanced past its Mesa allocation assertion to
keyboard configuration loading. Complete OS and COSMIC session verification
remain false.

## Reproduction and capacity decision

Evidence root: `artifacts/v017-cosmic-memory-20261115-r1/`.
`baseline-01` reproduces the real compositor's exit 134: a 16-page anonymous
request is refused with 40 pages free in the 4,096-page heap. Model 8194 correctly
retains its reserve; relaxing that boundary would not provide desktop capacity.
The anonymous accounting records one policy denial, no capacity/commit failure,
and balanced grants/releases after process teardown.

`heap-red-01` minimizes the capacity problem to real musl mmap calls. Three
4 MiB mappings succeed; the fourth is refused because it would consume all
remaining capacity. `vm-red.log` independently records the public VM interface
refusing allocation beyond the old 4,096-page boundary.

The new explicit `full-os-v2` layout selects a 32 MiB private heap at
`0x0c000000..0x0e000000`. Image, shared and initial-stack windows are unchanged.
Moving the heap preserves unmapped space around the stack at
`0x0a000000..0x0a200000`. FullOsV1 and Legacy definitions remain available to
the explicit layout inspector; default/non-full-os large-memory capacities stay
2,048/4,096 pages. The executable model remains 8197.

The real boot reserves four nonoverlapping physical pools after the kernel:

| Pool | Bytes | Actual physical range |
|---|---:|---|
| Private page tables | 4 MiB | `0x03ab4000..0x03eb4000` |
| Eight anonymous heaps | 256 MiB | `0x03eb4000..0x13eb4000` |
| Eight executable arenas | 512 MiB | `0x13eb4000..0x33eb4000` |
| Shared backing | 16 MiB | `0x33eb4000..0x34eb4000` |

These are successful firmware-aware reservations, not assumed free ranges.
The guest remains four CPUs and 1 GiB. The existing 128-frame per-process page
table arena maps all complete image/shared/stack/heap windows in a real table
test, including permissions and unmapped guards. No frame limit was increased.

## Admission and observability

Anonymous heap admission now selects separate model 8198 only for full-os.
It accepts 0..8,192 free pages and 1..2,048 requested pages. Free capacity rounds
down and requests round up in 16-page units; every admission leaves at least
32 pages. Authenticated grants, actual capacity, zeroing, page permissions,
revocation and release accounting remain authoritative.

`tools/train_resource_models.py` appends a synthetic teacher dataset after all
eight historical models. Generated weights are `[-454, 444, -444, 0]`;
52,531 training and 13,133 held-out pairs are recorded, with all held-out pairs
matching the teacher. All 65,664 quantized input cells pass the reserve check.
Previous weights and report entries are unchanged. This is synthetic policy
distillation, not application training, performance validation or an Active
learning claim. Shared-memory/storage continue using model 8194.

Process status now retains peak heap pages and peak allocation-record use after
exit, alongside live allocation records and the largest contiguous free virtual
run. These distinguish total capacity from fragmentation and record exhaustion.
The 512-record limit and whole-allocation munmap behavior are unchanged.

## Actual guest regression

The same probe ELF is bound in RED and GREEN:
`1e2f8a80b38bd76856733dc4d2df5fd783e67699be163c91dedc1e171a93da1f`.
`heap-capacity-01` runs it twice. Each execution holds/touches five concurrent
4 MiB mappings, checks all words for zeroing and distinct payloads, rejects a
request above the retained 8 MiB per-request domain, then fills with 64 KiB
allocations until refusal. Both reach 8,160 pages and 195 mapping records,
preserving 32 pages. Whole-allocation replacement, NONE/R/RW transitions,
another 20 MiB cycle and final process/object/page reclamation all pass.

Formal `os-build-01` compiled source SHA256:
`676b1fd66d8b4a5efe9a1f21e7979ead64658eed05044e29ed651e948a688592`.
The captures bind source, SDK, probe ELF and exact read-only embedding, and
recheck inputs at completion. Native activity is serialized under the shared
lease. Full-os host verification passes 315 tests; the default workspace passes
1,438 tests, and non-full-os large-memory POSIX passes 230. ARM legacy compilation
and deterministic model regeneration pass. Native process/protection, COSMIC
version, detached-thread/invalid-stack, inotify, nested epoll, flock and same-disk
reboot regressions all pass on the same final build. Both independent Standards
and Spec reviews found no implementation defect.

## Real compositor outcome

The compositor remains byte-identical:
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.
`cosmic-startup-01` records Running after 30 seconds and a 6,587-page heap peak;
its terminal-state-only capture times out and remains FAIL. It is not presented
as a passed desktop. The longer `cosmic-observe-01` reaches the next real error:
missing `/usr/share/X11/xkb/rules/evdev`, followed by COSMIC's `BadKeymap` panic.
The generic smoke panic guard stops that first observation, also retained as
FAIL. A separate observer permits only this exact identified userspace panic
through process termination so reclamation can be checked without relaxing
kernel or unrelated program failure checks.

`cosmic-observe-02` captures complete reclamation but still reports FAIL when
the known panic arrives as a partial UART line. The corrected streaming observer
retains that failure and produces fresh `cosmic-observe-03` evidence:
`OBSERVED_PROCESS_END`, Exited134 after 8,302 syscalls, heap peak 7,536 pages
(29.4375 MiB), and allocation-record peak 492. All 4,170 anonymous requests are
approved; all 31,414 cumulative granted pages are released. Final heap/image
capacity is 8,192/16,384 pages, with zero live threads, mappings and objects.
There is no `MMAP_DENIED` or original Mesa allocation assertion.
`check-progress.py` rejects the original baseline and accepts only this measured
heap-boundary advance and complete reclamation. It leaves both full-OS and
COSMIC-session verification false.

The pinned source orders `EGLContext::new`, `GlowRenderer::new`, `init_shaders`
and output-buffer creation in `src/backend/cyxia/mod.rs:484–491`, all with error
propagation. `src/backend/mod.rs:55–64` creates the keyboard seat only after that
backend succeeds. The event loop/render timer has not started at the keyboard
failure, so this is initialization progress without a completed-frame claim.

The selected sysroot has no rootfs. Existing `build_xkb.py` installs a fixed
X.Org `cyxia-us.xkm`, explicitly skipping generated xkeyboard-config rules;
that file cannot satisfy COSMIC's evdev/pc105/us rules lookup. The next asset
installation must use the pinned xkeyboard-config 2.42 input in
`ports/xkb/manifest.json`, include the real rules/include closure, and bind it
through the existing rootfs catalog. The current self-contained xkbcommon probe
supplies its own keymap text and therefore does not verify this missing path.

Next work is to install and expose the actual keyboard configuration/assets,
then continue session rendering/input/services. The larger heap does not
implement mremap, partial munmap, more simultaneous records or lazy/shared
physical backing. If later workloads exceed this profile, measure their demand
before another capacity change; 64 MiB eagerly reserved for each of eight heaps
would exceed the current guest's physical budget.

Coverage lesson: use the real `heap-capacity` scenario when changing a capacity
profile; a host VM test cannot prove physical reservation, zeroing or guest
page-table publication. Current V0.17 CI's host/build checks do not run this
scenario. For an application expected to stay alive, preserve timeout results
and use explicit state/stage observations; absence of an old panic alone is
insufficient progress evidence.

## Reproduce

```sh
python3 tools/os_x86.py build --profile release --graphics --ported \
  --feature full-os --feature cosmic-desktop \
  --sysroot artifacts/v017-cosmic-memory-20261115-r1/sysroot \
  --output artifacts/heap-v2-new-build
python3 tools/os_smoke.py --build artifacts/heap-v2-new-build \
  --scenario heap-capacity --output artifacts/heap-v2-new-run
```
