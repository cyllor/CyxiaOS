# Full-OS v3 shared physical anonymous memory

Continue the approved complete CyxiaOS/COSMIC plan from 27fd80a. Fresh baseline
again refuses 515 pages with 49 pages free, ending in notify SendError. Mapping
records peak near 531 of1024; largest free run equals free capacity. This is a
per-process physical partition limit, not record pressure or fragmentation.

## Contract and ownership

- Add explicit FullOsV3 with a64MiB anonymous virtual window at
  0x0c000000..0x10000000. Retain Legacy/V1/V2 definitions, default/large-memory
  behavior, image/shared/stack windows,1024records and2048-page request limit.
- Keep the four-CPU/1GiB guest and exactly256MiB anonymous physical reservation.
  Full-os processes take physical frames from that common pool at mmap commit;
  no anonymous RAM is statically assigned to an idle process. Pages stay private
  to their owner; this is not shared writable user memory or demand paging.
- Reuse the kernel-core FramePool ownership/revocation/zeroing state machine.
  Add indexed generation-checked handles and bounded cursor allocation so full
  pool operations avoid repeated scans from index0. Retain prior API contracts.
- Each Heap translates existing private Vm local slots to owned frame handles.
  An allocation is published only after actual AI admission, grant redemption,
  virtual allocation, physical allocation/zeroing and PTE staging succeed.
  Any failure unwinds all newly staged pages, handles and grant accounting.
- CPU0 foreground remains the sole metadata owner. All AP execution and roots
  must already be drained/retired before syscall mutation, clear or reuse.
  Validate the full released batch first; revoke every mapping, clear pages,
  finish frame revocation and balance grants before reuse. Preserve W^X and
  immutable-map write ceilings. Stale/foreign handles cannot release pages.
- New model8199 accepts min(process virtual free, physical pool free), bounded
  to0..16384 free and1..2048 request pages. Conservative16-page rounding retains
  at least32pages in both domains. Append training after all previous models;
  preserve prior weights/provenance and8194shared/storage policy. Synthetic
  teacher distillation is not workload training or a fullOS acceptance claim.
- Expose actual global pool capacity/free/used/peak separately from virtual
  per-process capacity, making oversubscription and reclamation observable.

## Approved verification seams

Use the existing public FramePool, VM/layout/model APIs and real musl guest
syscalls plus source-bound QEMU capture. Routine execution under the approved
plan needs no repeated confirmation. All native jobs remain serialized.

1. Preserve real COSMIC baseline RED; run a real guest probe RED on old32MiB.
2. Host tests cover frame ownership, zero failure, stale/wrong-owner release,
   complete65,536-frame capacity, revocation, reuse and transactional failure.
   Policy/layout tests cover reserve/input bounds, >32MiB, guards and real PTEs.
3. Guest probe holds40MiB and starts real concurrent2MiB-stack threads, touches
   payloads and proves teardown. Five independent holders exercise aggregate
   pool pressure, capacity refusal, no aliasing, owner exit and zeroed reuse.
   Prove free/used and grants return to baseline; do not rely on model-only tests.
4. Replay the unchanged COSMIC SHA, record its actual next outcome and all
   cleanup. No old failure does not by itself prove rendering or full desktop.
5. Run relevant native/legacy/ARM regressions, two independent reviews, document
   limits and commit/push a coherent stage. Preserve .qwen and all evidence.
