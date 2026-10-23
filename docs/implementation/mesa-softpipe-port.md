# Mesa softpipe EGL/GLES foundation

This is the P5 software-rendering foundation for the COSMIC port. Real Mesa
EGL/GLES now executes in the AArch64 CyxiaOS guest, including a real X11 EGL
window whose pixels were checked in QEMU scanout. The real Smithay EGL
context and GLES renderer also pass the bounded rendering checks described
below. The complete COSMIC runtime and G-EGL gate remain unverified.

## Source and implementation boundary

`ports/cosmic/mesa-source.json` pins Mesa 26.2.3, release SHA256
`1628058a8d2c0615975de5a15ab7bbb9638c50000b5bed9456ff423ea034a81f` and upstream
commit `31e9a6b2e95e30d84bf3177d1f497d063e59b6b2`. The archive hash is published
in the [official release notes](https://docs.mesa3d.org/relnotes/26.2.3.html).
The opt-in `cyxia-static-softpipe` patch changes library packaging and platform
selection. It keeps Mesa's actual EGL entry points, GL dispatch, GLSL compiler,
Gallium frontend, softpipe renderer and X11 software presentation code.

The target uses the Linux musl userspace ABI, but has no KMS/DRM device ABI. The
profile therefore disables KMS/DRM, GBM, Vulkan, GLX, LLVM, JIT and shader disk
cache. Internal DRI software interfaces are retained: in Mesa 26.2.3,
`dri2.c` also contains image/drawable functions needed by the software path.
Compiling that file does not implement a DRM device or advertise DRI3 support.

Mesa's bundled DRM format declarations require Linux UAPI types even in this
software profile. Eighteen headers are pinned to Linux v6.12 commit
`adc218676eef25575469234709c2d87185ca223a`. They are exported in the isolated
work directory using the pinned upstream `unifdef.c` and `headers_install.sh`.
Two equivalent sed spellings make the export script usable on macOS. Generated
`asm` forwarding headers follow the pinned arm64/asm-generic Kbuild lists.
These headers supply types and constants, not syscall implementations.

Mesa's real C++ objects require allocation, mutex, hash-table and static-object
initialization functions. The builder compiles eleven unchanged implementation
files from official libc++/libc++abi 20.1.8 archives, using their matching C++
headers and a musl/pthread configuration. Archive hashes are pinned from the
official GitHub release asset digests. This is the runtime subset needed by
Mesa, not a complete general-purpose C++ library. Exceptions, RTTI and unwinding
remain disabled. Allocation failure and mutex errors retain upstream failure
behavior; no fake allocation, lock, driver or loading success functions exist.

All target compilation uses the AArch64 musl compiler and isolated target
pkg-config metadata. Native Python generators and native `unifdef` are kept
separate. The builder never executes a target program on macOS. It uses its
own work-directory lock and does not install into or rewrite the shared
sysroot. Full source, patch and runtime tree identities are recorded; edited
source is rejected on resume. Each failed attempt retains its report and logs.

## Reproduction

```sh
python3 tools/build_mesa.py inventory
python3 tools/build_mesa.py build --fetch \
  --work artifacts/sysroot/aarch64-musl/mesa-static-r10 --jobs 6
python3 tools/build_mesa.py build --resume \
  --work artifacts/sysroot/aarch64-musl/mesa-static-r10 --jobs 6
python3 -m unittest tests.host.test_mesa_port -v
```

`--fetch` explicitly permits the pinned sources/native Python dependencies to
be acquired. A resumed build validates source identity before compilation.
The target output and reports remain under the selected work directory.

## Guest evidence required

`user/ported/egl_probe.c` calls real EGL and GLES3. Offscreen mode creates a
surfaceless EGL display, a GLES3 context and a 64×64 pbuffer. It compiles ESSL
3.00 vertex/fragment shaders, draws four exact-color quadrants into both an
RGBA8 FBO and the default surface, and checks every one of the 4096 pixels in
each readback. It also checks BGRA capability, procedure lookup, swap and
teardown. Any failed check produces a nonzero exit.

The current probe also samples two real textures, compares all pixels after
rebind, checks nonzero bilinear weights across 32-pixel tile boundaries,
updates an unbound texture and samples its retained view again, and uses a
real GLES 3.1 compute shader to write an unbound sampled texture. The latter
checks the image-store/barrier/rebind invalidation boundary. A texture-cache
pressure loop must return `GL_OUT_OF_MEMORY`; after deleting those textures,
both existing views and an entirely new view must render correctly.

After the root integrator embeds that exact ELF in a frozen kernel, run:

```sh
python3 tools/verify_egl.py --elf <frozen-kernel.elf> \
  --probe <exact-egl-probe.elf> --output <evidence-directory> --runs 3
```

The verifier requires the selected probe to occur exactly once in the kernel,
the checked build report and ELF segment layout, matching current source,
patch and build-tool hashes, all checks in order, the actual softpipe GLES3
renderer, successful exit, full process heap/image/thread reclamation,
balanced AI grants and zero remaining OFD/ancillary/shared-memory objects.
Missing, duplicated, interleaved
or failed markers cannot pass. It records `g_egl_pass=false` even if this
foundation passes.

The optional `--mode x11` verifier uses the `egl-x11-probe` catalog alias,
which runs the same ELF with argument `x11`. It starts real guest Xorg, creates
an actual X window, calls EGL's real window-surface/swap path and compares all
4096 window pixels in the QEMU scanout, including GL-to-X vertical orientation.
The verifier then stops Xorg and checks complete resource reclamation. Linking
libxcb-shm does not mean the X server supports MIT-SHM. Mesa's software
fallback and actual xcb PutImage path must be observed on CyxiaOS's Xorg.

## Remaining boundary

Smithay now has an explicit static EGL adapter that fills its generated
entry table through real Mesa `eglGetProcAddress`, with unavailable symbols
remaining null. Its actual EGL context and GLES renderer run against r10;
see [the Smithay renderer evidence](smithay-static-renderer.md). This does
not establish a general dynamic loader for `libEGL.so.1`. The Wayland EGL
helper and Pixman remain distinct components. The COSMIC shader corpus,
BGRA operation tests, full surface resize/recreate, compositor event-loop
integration, presentation failure/recovery, memory limits and desktop-scale
timing remain separate gates in the COSMIC plan.

Compute allocation failure was a concrete issue in r8. Upstream
softpipe's `softpipe_launch_grid` dereferences an unchecked result from
`tgsi_exec_machine_create`; its local shared-memory allocation also lacks a
failure check. The cache-allocation fix alone does not repair these paths.
A 64-invocation local group exhausted the fixed guest heap and caused SIGSEGV,
with kernel isolation and resource reclamation intact. Thus this port must
not be described as generally OOM-safe or as passing the complete G-EGL gate.
The bounded image-store regression uses a four-invocation local group and
1024 workgroups to cover all 4096 pixels with one reused interpreter machine.
The r9 dispatch-preparation fix and its stronger regression are described
below. Shader compilation, compute-state creation and other frontend
allocation failures remain separate work.

The 64×64 probe is a functional foundation, not a desktop capacity claim.
CPU, memory, IPC and final display submission remain subject to CyxiaOS's AI
resource policies. Mesa does not reinterpret user input or bypass those
kernel admission/completion contracts.

## Current build evidence

The `mesa-static-r3` attempt compiled all 940 library/probe object and archive
targets, then failed the final link because the target had no C++ runtime and
the no-DRM profile omitted software-shared DRI functions. Those failure logs
remain under `artifacts/sysroot/aarch64-musl/mesa-static-r3/reports`.
The `mesa-static-r4` attempt includes the real runtime and corrected frontend
closure. All 942 targets compiled/linked. The final checked and stripped ELF is
`artifacts/sysroot/aarch64-musl/mesa-static-r4/egl-probe.elf`, SHA256
`a3fa97765fa800f742a1d1a81cf86984aa5aee12953442e4dca703abb365641b`.
It is 14,511,304 bytes, with 14,721,024 bytes of mapped LOAD pages and highest
mapped byte below `0x01e09cd7`, inside the existing 16 MiB image window.
It has nine program headers, a real TLS segment (8 initialized/80 total bytes),
and no dynamic/interpreter segment or unresolved strong symbols. LOAD pages
have separate write/execute permissions.

The durable build report is
`artifacts/sysroot/aarch64-musl/mesa-static-r4/reports/20261018T133413-77545.json`.
It records source/configuration hashes, all commands, the final link recipe,
static input hashes, unstripped/stripped ELF identities and program headers.
The real C++ runtime archive is 65,802 bytes. No library was installed into the
shared sysroot.

The first actual guest run of r4 failed to create the GLES3 context.
`artifacts/cosmic-mesa-r0/egl/summary.json` preserves that failure; the separate
`egl-failure-cleanup/summary.json` proves process and grant reclamation after
the expected failure. Target C layout measurement showed that eager softpipe
allocation required `6 × 128 × 262,368 = 201,498,624` bytes of texture caches
per context, before any texture was bound. The existing 16 MiB per-process
heap limit and local AI admission were retained.

The demand-cache patch allocates the unchanged real 16-entry cache when a
sampler view is created. Each bound slot retains a normal view reference and
borrows its cache; the final view destruction releases the cache and resource
reference. Allocation failure returns a real Gallium failure and the state
tracker reports `GL_OUT_OF_MEMORY`. Cache size, advertised GLES capabilities
and AI policy limits are unchanged.

The r5 ELF (`aa74a5db320b434d4768ef02f305950ec80fb1c45ad4d49f3e778a08f3de0f37`)
passed 30 original offscreen checks in three sequential guest process
launches: `artifacts/cosmic-mesa-r1/egl/summary.json`. The frozen kernel hash is
`ffd09e6e31a15e48dbc68c530e71ba7db1ef5242dc91498e4e387f6813e7761f`.
That is historical functional evidence, not acceptance of the later expanded
probe or all resource-accounting checks.

Independent source review identified a retained-cache invalidation gap:
barriers only flush bound caches, while image stores need not advance the
CPU-transfer timestamp. The r6 patch explicitly invalidates a view cache on
rebind after `draw_flush`, restoring the original invalidation boundary.
The r6 probe adds regression coverage, exact bilinear filtering and a new
cache allocation after OOM. It is built as
`artifacts/sysroot/aarch64-musl/mesa-static-r6/egl-probe.elf`, SHA256
`fd41913332af0bbbc7ed2a0f1258911851b9f3e2ffa7f25a41a28b3b9a196d1b`,
with 14,725,120 mapped LOAD bytes. The checked build report is
`mesa-static-r6/reports/20261020T140224-12685.json`.
That revision's guest run exposed a probe error: GLES image binding requires
immutable texture storage. The test incorrectly used `glTexImage2D`, which
raised `GL_INVALID_OPERATION`; subsequent compute setup under memory pressure
faulted. This failure is retained at
`artifacts/cosmic-mesa-r2/egl-accounting/summary.json` and is not acceptance.

The r7 probe uses `glTexStorage2D` plus real sub-image uploads, and performs
compute setup before the deliberate cache-exhaustion phase. Its ELF is
`artifacts/sysroot/aarch64-musl/mesa-static-r7/egl-probe.elf`, SHA256
`d72ad048f2d85af6d955b81b99f3432708fdd36f228f79365fdaabf45d9bc586`,
with the same 14,725,120 mapped LOAD bytes. The build report is
`mesa-static-r7/reports/20261020T140645-18483.json`.
That revision confirmed the compute-allocation issue described above, without
the r6 invalid-image-binding error. Its preserved report is
`artifacts/cosmic-mesa-r3/egl-accounting/summary.json`; the faulting process
exited with SIGSEGV, and its heap, image, threads and grants were reclaimed.
The r8 probe reduces its local workgroup to four invocations while keeping
total work and all per-pixel checks unchanged.

## Verified r8 foundation, 2026-10-20

The final probe is
`artifacts/sysroot/aarch64-musl/mesa-static-r8/egl-probe.elf`, SHA256
`67ece171b5ba14bde975a38c7b4de62038aedf33516fdeb474146ac95d82d820`;
its checked build report is `mesa-static-r8/reports/20261020T141053-23717.json`.
The frozen kernel is `artifacts/cosmic-mesa-r4/cyxia-kernel.elf`, SHA256
`9fe65b2bcef73e0680ddd7f1cbcc35533ddfe65b3c1cfd01af8906c7db41007d`,
built with `graphics,openbox,large-memory,mesa-probe`. The X11 test starts only
Xorg; it does not depend on a window manager or a host X server.

| Evidence | Observed result |
| --- | --- |
| `artifacts/cosmic-mesa-r4/egl-accounting/summary.json` | PASS: three sequential process launches, all 34 offscreen checks each |
| `artifacts/cosmic-mesa-r4/egl-x11-accounting/summary.json` | PASS: three X11 process launches, all 36 checks each, all 4096 actual window pixels match |
| `artifacts/cosmic-mesa-negative-r1/retained-cache-regression/summary.json` | Expected stale-cache failure reproduced with the same r8 probe linked against r5 Mesa archives |
| `artifacts/mesa-r8-host-tests-final.txt` | Six host verifier/source-containment tests pass |

Each offscreen process reclaimed its heap, mapped image, threads and all
resource grants. After the X11 runs, stopping Xorg returned the global process
page pool to 64 free pages and all per-process image/heap pools to capacity.
OFD, ancillary-message and shared-memory object/reference counts were zero.
AI grant units equalled release units for all observed resource domains.
Both positive test sessions recorded three actual model denials during the
deliberate texture-cache pressure cases; each GL client recovered and created
a new cache successfully.

All three X11 scanout files have pixel SHA256
`a591b24295087ea3d15acde9a7aa1b4522e786972d1820192072d51aa63b5633`.
The initial X11 report at `egl-x11/summary.json` is retained as a verifier
failure: it incorrectly required 64 global free process pages while the
running Xorg server still owned eight. The corrected test compares client
exit against the live-server baseline and requires all 64 pages after server
termination.

The negative-control kernel hash is
`0c42c2838944aba8e65f3821349d450884fbc70135b08f82ce631ba1252a3d1b`.
With the unchanged older r5 cache code, the new image-store/rebind test reads
the wrong pixel at `(0, 0)` and exits with one ordinary test failure. It has
no invalid GL operation, allocation rejection or CPU fault; all resources are
reclaimed. The corrected r8 code passes that same test. Link command, probe
object and static-library identities are retained under
`artifacts/mesa-cache-negative-control-r2/identity.json`.

These r8 results accepted the enumerated bounded rendering foundation. At
that stage, they did not close the compute-OOM defect or Smithay's EGL loading
contract addressed in later sections. The actual COSMIC shader corpus,
desktop-scale capacity/timing, full surface resize/recreate and session
recovery remain open. Every positive report deliberately keeps
`g_egl_pass=false` and `cosmic_runtime_verified=false`.

## Compute dispatch allocation handling

The opt-in `cyxia-compute-oom` patch keeps the existing 16 MiB process heap,
AI admission policy, advertised workgroup limits and actual TGSI interpreter.
For already compiled valid shaders, it allocates the shared scratch memory,
machine pointer array, every interpreter machine and every parsed shader
array before executing the first workgroup. Failed preparation releases all
initialized objects and scratch allocations before recording the error.
An indirect-dispatch mapping failure follows the same error path.

The compute-only checked shader binder counts declarations, instructions and
immediates before allocating exact-sized arrays. It commits those arrays to
the machine only after successful parsing and validation; other callers keep
the upstream binder. Fixed workgroup dimensions and shared memory are checked
against the driver's existing advertised limits, with checked arithmetic.
This does not add variable-workgroup support or reduce shader capabilities.

A synchronous profile-only driver callback records `GL_OUT_OF_MEMORY` in the
owning Mesa context. It does not depend on KHR_debug, reset-notification flags
or current-context TLS. The state tracker installs the callback after context
initialization and clears it before context data is freed, including failed
construction. Invalid internal dispatch input is reported separately as
`GL_INVALID_OPERATION`.

The strengthened probe compiles its shaders before the pressure case. In
each of three cycles in one process, it dispatches the original 8×8 local
workgroup over an 8×8 grid, requires exactly one `GL_OUT_OF_MEMORY`, and checks
that every one of 4096 SSBO words is unchanged. A following 4×1 local
workgroup writes a new seed to all 4096 words. Changing the expected seed on
every recovery prevents unchanged data from passing as successful execution.
The verifier requires all fourteen new check markers and all three exact
64-invocation attempt markers. These checks supplement all r8 texture,
image-store, rendering, presentation and reclamation observations.

The unpatched control is the same strengthened probe linked against
unchanged r8 static libraries:
`artifacts/mesa-compute-oom-negative-r0/egl-probe-unfixed.elf`, SHA256
`76ca7eff9b0821ef7aec4cbeae91279896606b46e61d2c5948bb5f26741b2f9c`.
The separate `identity.json` records its object, library and link identities.
Seven host source-containment/verifier tests pass in
`artifacts/mesa-r9-host-tests.txt`.

All 942 r9 build targets succeeded. The checked AArch64 ELF is
`artifacts/sysroot/aarch64-musl/mesa-static-r9/egl-probe.elf`, SHA256
`d0120a52e7c0c143e7d1538383a862e5a087701f9d655009aed6a2aed963a87e`.
Its 14,741,504 mapped LOAD bytes fit the existing image window. The durable
build report is `mesa-static-r9/reports/20261020T145209-34089.json`, SHA256
`a2cd0bedc249b1dfc4bd66666f06a5920af64a39005dd9e17f9c3c13596ff10c`.
The report binds the source patches, compiler/runtime inputs, probe source,
link recipe and final segment layout.

## Verified r9 dispatch recovery, 2026-10-20

The frozen kernel is `artifacts/cosmic-mesa-r5/cyxia-kernel.elf`, SHA256
`846d8ed966d41b12b53aea141297d792dbeafc227dded1c97691b4aee1642b19`.
It contains the exact r9 ELF above and uses the existing
`graphics,openbox,large-memory,mesa-probe` feature set.

| Evidence | Observed result |
| --- | --- |
| `artifacts/cosmic-mesa-r5/egl-accounting/summary.json` | PASS: three sequential launches, all 48 offscreen checks each |
| `artifacts/cosmic-mesa-r5/egl-x11-accounting/summary.json` | PASS: three X11 launches, all 50 checks each, all 4096 actual window pixels match |
| `artifacts/cosmic-mesa-compute-control-r0/runtime/summary.json` | Expected original compute-OOM fault reproduced with the same probe linked against r8 libraries; subsequent independent native process passes |

The report SHA256 values are respectively
`d3ea35d7500a8f9b4bd390fc43638be78fe3903a423eb056592b9fffdbac345b`
and `c3d35e565c5fd7ed49630f73ada7ce0701923a0f645085a979eafffbed9d724e`.
Every launch completed three compute-OOM/unchanged-SSBO/recovery cycles,
followed by the original texture-pressure/recovery and rendering checks.
Thus eighteen original 64-invocation dispatch attempts returned the expected
GL error without modifying their SSBO, and all eighteen small dispatches
produced their new exact values within the same processes.

The control kernel SHA256 is
`ed608b0dc6aa46f64ed3ce528d2e06e37acc9dcd76c942a53f8b18854df00beb`.
Its report, SHA256
`dbbce90ca470802a2728d91c71f8987aa90b0acccfbf0bdbb87dfcb591593351`,
records `PASS_EXPECTED_ORIGINAL_COMPUTE_OOM_FAULT`. The unchanged r8
libraries pass every preceding probe check, then fault at the first original
8×8 dispatch with exit code 139, SIGSEGV, ESR `0x92000046` and FAR `0x40618`.
The kernel reclaims all of that process's resources. A separately launched
native libc/memory/file/floating-point probe then passes with normal exit
and complete reclamation. `tools/verify_mesa_compute_control.py` checks the
exact fault boundary, source/object/library/kernel identities, grant
accounting and subsequent process isolation. This control establishes the
behavioral difference between the original libraries and the patched r9
libraries using the same strengthened probe source.

All six r9 processes exited with code, signal, ESR and FAR equal to zero, with
their heaps, images and threads reclaimed. All observed grant units matched
release units; OFD, ancillary and shared-memory objects/references returned
to zero. The offscreen session recorded three anonymous-memory AI denials
and nine capacity rejections; the X11 session recorded nine AI denials and
three capacity rejections. The reports preserve these distinct admission
outcomes. Xorg teardown restored the global process
page pool to all 64 free pages.

All three X11 scanouts retain pixel SHA256
`a591b24295087ea3d15acde9a7aa1b4522e786972d1820192072d51aa63b5633`.
This accepts the tested dispatch-preparation error and rollback path. It
does not claim shader-compiler/context-creation allocation safety, general
compute conformance, full G-EGL or a running COSMIC compositor. Both reports
retain `g_egl_pass=false` and `cosmic_runtime_verified=false`.

## Smaller NIR slabs for the real Smithay renderer

With r9, the actual upstream Smithay renderer successfully created its EGL
display and context, then compiled and linked six texture programs. Its
seventh solid-color program link exhausted the fixed process heap inside NIR
`lower_vars_to_ssa`. The preserved original guest is
`artifacts/smithay-kernel-slot-r0/runtime/summary.json`; the diagnostic stack
is `artifacts/smithay-diagnosis-stack-r0/lldb.txt`.
`nir_instr_create` dereferences a failed allocation at offset `0x18`.
This is a shader-compiler allocation failure, separate from the repaired
compute-dispatch preparation path.

At that failure, the process owns 3947 of 4096 heap pages. A 256-page
allocation cannot fit the remaining 149 pages. The shortfall for that
single reservation is 107 pages, or 428 KiB. This is a lower bound for that
allocation, not a measured complete-renderer capacity requirement.
NIR uses 32 KiB GC slabs across its allocation buckets; musl's allocation
groups can request 1 MiB to serve these slabs. The compiler's unrelated
linear allocator has a 2048-byte default minimum.

The r10 opt-in `cyxia-nir-small-slabs` profile uses 4 KiB GC slabs.
Object sizes, the 512-byte maximum freelist allocation, bucket selection,
alignment, linked-list ownership, collection and shader capabilities remain
unchanged. Compile-time assertions require every bucket to fit at least
one object and all slab offsets to fit their `uint16_t` field. Independent
review found no ownership/alignment blocker. More slabs and allocator/list
operations are the expected performance tradeoff. The 16 MiB heap and
AI admission policy are unchanged.

The exact patch is
`ports/cosmic/patches/mesa-26.2.3-cyxia-nir-small-slabs.patch`, SHA256
`0f97a775fc3912be963515c812e4ec6cd6b9bb1ba49632c2f18e3f86f4dcf0d0`.
All 942 build targets succeeded. The isolated report is
`artifacts/sysroot/aarch64-musl/mesa-static-r10/reports/20261020T155154-51965.json`,
SHA256 `032a9f5d90db2a7f6d3beb3b59674fdc89b22098b5e1a75c7c4cc93a45a9846f`.
Its `egl-probe.elf` has SHA256
`d14c039153bd22e2ccfd47814e31a5d16e0c866ca2a3e230f3aecab8e44366e7`.
Seven host tests pass in `artifacts/mesa-r10-host-tests.txt`.

Calling real `glReleaseShaderCompiler` before each program link did not
resolve the observed peak: the next link immediately recreates the compiler
builtin cache. That failed experiment is retained in
`artifacts/smithay-kernel-r2/runtime/summary.json`. The accepted Smithay r3
build contains no such cache-release change.

## Verified r10 rendering and regression, 2026-10-20

The isolated Mesa regression kernel is
`artifacts/cosmic-mesa-r6/cyxia-kernel.elf`, SHA256
`2156db172b9a16ffd84d8918ff70064216c22de5020ffc616e0293b2c62a14c1`.
It embeds the exact r10 ELF and uses
`graphics,openbox,large-memory,mesa-probe`. Before/after manifests in that
directory bind 118 kernel source files, 64 catalog inputs and 13 bootstrap
inputs; none changed during the build.

| Evidence | Observed result |
| --- | --- |
| `artifacts/cosmic-mesa-r6/egl-accounting/summary.json` | PASS: three launches, all 48 offscreen checks each |
| `artifacts/cosmic-mesa-r6/egl-x11-accounting/summary.json` | PASS: three launches, all 50 checks each and all 4096 actual window pixels match |
| `artifacts/smithay-kernel-r3/runtime/summary.json` | PASS: three launches, real seven-program renderer construction and 1087 exact RGBA pixel readbacks each |

The offscreen and X11 report SHA256 values are respectively
`1fdd81ab6a1fb119c3cb10d58bb886c913deb0068b79e28a20ed17df56d165f3`
and `676ee0dd06861eef62451ac237683f7481e54cc07cf90c316806d2bca6875175`.
All eighteen original 8×8 compute dispatch attempts still return the expected
`GL_OUT_OF_MEMORY`, leave all 4096 SSBO words unchanged and recover with an
exact small dispatch in the same process. Texture cache pressure, fresh
allocation after recovery, filtering across tile boundaries, view rebinding
and image-store invalidation also pass unchanged.

All six Mesa clients exit normally with zero signal, ESR and FAR. Heap,
image, thread, OFD, ancillary and shared-memory resources are reclaimed;
observed resource grant units equal their releases. Xorg teardown restores
all 64 global process pages. All three actual X11 scanouts retain pixel
SHA256 `a591b24295087ea3d15acde9a7aa1b4522e786972d1820192072d51aa63b5633`.

The Smithay report SHA256 is
`1098684bba928b6e90271ec63b80918c3915248b00abb2927561e8fd2fefa47f`.
Its exact upstream renderer completes all seven eager programs and checks
clear, solid color, texture sampling, texture update and replacement-target
rendering. Every launch exits normally and reclaims its resources under the
unchanged 16 MiB heap and AI admission policy, with no memory rejection in
this workload. The associated build and static-adapter identities are
recorded in [the Smithay renderer evidence](smithay-static-renderer.md).

These observations accept the smaller-slab configuration for the tested
Mesa and Smithay workloads. Smaller slabs reduce retained allocation slack;
they do not make arbitrary NIR/compiler allocation failure safe. Full
COSMIC execution, the complete G-EGL gate, general shader compilation under
memory pressure and desktop-scale capacity remain unverified.
