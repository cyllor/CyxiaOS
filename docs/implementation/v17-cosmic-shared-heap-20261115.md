# V0.17 shared anonymous pool and actual COSMIC output

Continues `27fd80a` under the approved complete CyxiaOS/COSMIC plan. A03 stays
cancelled. The real compositor binary is unchanged:
`f7eb5c8a16aa498785929ec3499f00a954553c8ba4210251ed1efbe6d2e1af96`.

## Change and physical budget

FullOsV3 gives each process a 64 MiB anonymous virtual window at
`0x0c000000..0x10000000`. Its physical pages come from one 256 MiB pool at mmap
commit. Idle processes no longer own an eager 32 MiB anonymous partition.
Capacity is shared; each allocated page remains private to one owner. This is
not page-fault demand allocation or shared writable user memory.

Legacy, large-memory, FullOsV1/V2 layout definitions, 1,024 full-OS allocation
records (512 legacy), and the 2,048-page individual request limit are retained.
Executable backing remains eight eager 64 MiB partitions. The guest is still
four CPUs with 1 GiB RAM. The actual boot reserves 4 MiB page tables, 256 MiB
anonymous backing, 512 MiB executable backing and 16 MiB shared backing: 788 MiB
total. Kernel load ends at 70,946,816 bytes; the final reservation ends at
`0x357a9000` (855.66015625 MiB), within the firmware-validated RAM map.

The existing FramePool now supplies indexed, generation-checked handles,
constant-time free/used counters and bounded cursor allocation. The old
first-fit clean allocator keeps its selection order. A local VM slot is not a
physical-frame index; in particular physical index 65,535 is valid. CPU0 remains
the sole metadata owner after every AP has returned and retired its root.

Heap admission uses model 8199 with `min(virtual_free, physical_free)`. The new
synthetic dataset covers 0..16,384 free pages and 1..2,048 requested pages, with
16-page conservative quantization and a 32-page reserve. All 131,200 cells were
checked: zero unsafe grants or teacher disagreements. Its 26,240 held-out cells
all match. The previous nine weight constants are byte-identical and their
report entries JSON-identical. This is policy distillation, not workload training.

Allocation records are published only after redemption, VM reservation,
physical clearing and desired-PTE staging. The production transaction is tested
directly through a source inclusion, using real VM, grant ledger and FramePool
APIs. Partial zeroing, PTE staging, physical exhaustion and fragmented VM failures
restore capacity and preserve existing mappings/bytes; retries succeed. All new
PTEs are removed before any backing is released. Unmap preflights ownership,
revokes mappings, clears frames and balances grants. Internal reclamation errors
retain charges rather than fabricate completed-revocation receipts.

## Evidence

Evidence root: `artifacts/v017-cosmic-heap-pool-20261115-r1/`.
Final kernel build: `os-build-03`, source digest
`5d8795e28b1c4940325adeb95331dce843cd626080cd31e420f7f7c04781ca60`.
The initial successful pool/COSMIC captures below use `os-build-02`, digest
`8bed992310ff587b8569796b5565082709e224151e73a22e30094d2763877bc6`;
the final-source replays are recorded separately.
The curated `sysroot-final` retains the same real COSMIC ELF and official XKB
assets, with rebuilt capacity and pool probes.

- `baseline-01`: unchanged COSMIC on the previous kernel again rejects 515
  pages with 49 free, then exits 134 with notify SendError. `reproduce.py` is RED.
- `probe-red-01`: the new real musl workload fails its 40 MiB allocation on the
  previous 32 MiB profile. That earlier probe revision predates the additional
  every-word zero assertion; it is retained as capacity RED, not final-binary
  parity evidence.
- Host RED logs retain the missing pool/model/layout APIs and actual VM Nomem.
  FramePool 10 integration plus 2 internal cases, model, layout, VM and actual
  x86 page-table tests pass. `transaction-red.log` and `transaction-green.log`
  preserve the extraction's missing-module RED and both production-helper tests.
- `os-build-01` preserves an explicit-module-path compilation error; it is not
  a verified image. The path is fixed in `os-build-02`.
- `native-final` preserves a regression-test failure: the built-in Rust heap
  workload still selected FullOsV2's 8,192-page limit, so it expected EINVAL for
  8,193 pages. In V3 this lies inside the virtual window but exceeds the unchanged
  2,048-page per-request bound, correctly returning ENOMEM. Its two profile
  references now select FullOsV3. `os-build-03` differs from build02 only in
  `user/rust/services.rs`; external ELFs/assets and physical load end are unchanged.
- `heap-pool-01` passes: two 40 MiB cycles with three concurrent 2 MiB pthread
  stacks, TLS/payload checks, peak 11,782 pages and four live threads. Four
  independent holders retain 60 MiB each; the fifth obtains 4,064 pages and is
  refused at global free=32/used=65,504. Normal release/replacement and live-owner
  kill reclaim all pages, objects and grants. The stronger pressure-preserving
  killed-owner reuse check is tracked separately below.
- `heap-pool-02` passes the stronger scenario. With other holders kept alive and
  only 32 pages free, replacing a killed 15,360-page holder necessarily reuses
  at least 15,328 of its physical pages. The replacement checks every word for
  zero before writing; surviving owners verify their distinct payloads. All
  6,030 grants/119,788 page units balance, and all 65,536 physical pages return.
- `cosmic-observe-01`: at 50.41 seconds, the real compositor is Running with
  eight threads and 11,124 anonymous pages (43.453125 MiB), with zero anonymous
  denial/capacity/failure and zero thread denials. Display reports 192 completed
  submissions, zero failures. These are tile submissions, not 192 desktop frames.
  The captured 1024×768 scanout shows the actual dark background and cursor,
  replacing the boot color bars. After explicit operator termination, all 4,333
  anonymous grants/35,217 pages, eight shared pages, image pages, threads and
  open descriptions are reclaimed. QEMU exits 0; source/input identity is retained.
- `cosmic-live-01` independently observes the same output, injects relative
  mouse movement `(320,240)`, and keeps the compositor active for another
  60.031 seconds. Untouched QMP PPMs show the cursor bounds move from
  `[0,0,19,28]` to `[319,239,339,268]`. Exactly 751 pixels change, confined to
  the old and new cursor regions; the old region is cleared. The 10-second and
  60-second post-input images are byte-identical. Display completions rise from
  192 to 384; all six live polls retain 11,128 heap pages (43.46875 MiB), eight
  threads and continued syscalls. Operator termination then reclaims all 4,335
  anonymous grants/35,990 page units and all objects/shared/image/thread state.
  QEMU exits 0 and identities match. This is real initial output, input and
  bounded liveness evidence, not application/session acceptance or a startup SLA.

`capture-file-audit.json` inventories the completed captures, including raw QMP
and command transcripts not individually hashed by every original summary.
It is a separate post-capture audit; original producer-bound summaries remain
unchanged. PNGs are viewing conversions of the untouched QMP PPMs.

### Final-source replay

All final native outputs use `os-build-03` and the final source digest above:

- `native-v3-final`, `thread-exit-v3-final`, `inotify-v3-final`,
  `nested-epoll-v3-final`, `flock-v3-final`, `xkb-rules-v3-final`: PASS.
- `heap-capacity-v3-final`: two real executions reach 16,352 pages and 1,024
  mapping records, then fully reclaim them. The 32-page reserve is retained.
- `heap-pool-v3-final`: the full pressure/kill/zeroed-reuse sequence passes again,
  including the minimum 15,328 killed-owner frame reuse and full grant balance.
- `cosmic-live-final`: `OBSERVED_RENDER_INPUT_STEADY`, 60.035992 seconds after
  input, the same exact 751-pixel cursor movement, stable 11,128 pages/eight
  threads and 384 completed display operations. Full cleanup balances the same
  4,335 grants/35,990 page units. QEMU exits 0 with source and input identity intact.
- `host-default.log`: 1,457 default workspace tests pass.
  `host-full.log`: 241 full-OS POSIX tests pass.
  `host-large.log`: 238 legacy large-memory POSIX tests pass.
  The explicit x86 runtime suite passes 26 tests; Python build/asset/OS tests
  pass 31 tests. `arm-legacy.log` passes the AArch64 large-memory compile check
  (this is not an ARM guest execution).

`final-evidence.json` inventories all nine final-source native captures, raw
QMP/commands/serial/image files and host results. It rechecks all 1,099 compiled
source entries and applies the original 515-page/49-free failure assertion to
the retained baseline (RED) and final real COSMIC capture (GREEN). Render/input
and reclamation checks supply the stronger positive evidence.

## Current boundary

The old 32 MiB denial and notify panic are absent in the new observed startup.
The first actual COSMIC output and mouse response are now visible. Its log still reports missing
session/system D-Bus endpoints, default configuration directories and a locale
parse error. Syscall 89 (`readlink`) remains unsupported. A background and cursor do not certify a complete desktop session:
session/panel/launcher/application services, Wayland client interaction,
persistent settings and the broader OS services remain work to do.
`full_os_verified` and `cosmic_session_verified` remain false.

## Review and lessons

Independent Standards review found no documented-standard or unsafe-boundary
violation; one nonblocking duplicated ownership-transition heuristic remains in
the two FramePool allocation selectors. Independent Spec review led to two
concrete improvements: direct production rollback tests and forced physical
reuse after killing a holder under pool pressure. Free capacity alone cannot
prove the next allocation reused a killed owner's bytes. Keep complete UART
line matching when a probe marker is immediately followed by another command.
Versioned layout migrations must include embedded user diagnostics as consumers,
in addition to kernel/crate definitions; the retained native RED caught that omission.
