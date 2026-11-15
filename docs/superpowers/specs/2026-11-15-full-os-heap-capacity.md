# Full-OS anonymous-memory capacity

Continue the approved complete CyxiaOS/COSMIC plan from `4d22e83`. The unchanged
real compositor reproducibly exits 134 at Mesa GLSL allocation after a 16-page
request is refused with 40 pages free in its 4,096-page heap. Its completed
grant/release receipts balance. The existing reserve decision is valid; the
desktop needs a larger explicit capacity profile.

Add `full-os-v2`, retaining the historical Legacy and FullOsV1 layouts. Keep the
64 MiB executable arena and 2 MiB initial stack, but provide an 8,192-page
(32 MiB) private heap at `0x0c000000..0x0e000000`. Preserve gaps around the stack
at `0x0a000000..0x0a200000`, shared mappings, and the image. Select this profile
only for full-os; default and non-full-os large-memory behavior stay unchanged.
Actual firmware-aware reservations must fit the existing four-CPU/1-GiB guest.
Do not increase the guest RAM or bypass reserve_pool failure.

Add a separate anonymous policy/model 8198, bounded to 0..8192 free pages and
1..2048 requested pages, with conservative 16-page floor/ceil features. Generate
weights by appending a dataset to the existing synthetic teacher distillation
workflow, retaining every previous model and its provenance. Reject unsafe
generated grants; every admission must retain at least 32 pages. This is
synthetic policy training, not desktop workload training or an Active claim.
Keep shared-memory/storage on the old anonymous policy. Keep authenticated
grants, accounting, zeroing, revocation, W^X and actual capacity enforcement.

Use the existing approved public seams: real musl mmap/mprotect/munmap in the
guest, the policy/layout/VM APIs, and the source-bound capture interface. A real
probe must first fail on the old 16 MiB runtime, then hold and touch more than
16 MiB, test bounded exhaustion/refusal, verify no aliasing, reclaim/reuse with
zeroing and retain the per-request limit. Verify process/object/page reclamation.
Expose live/peak heap pages and allocation records plus largest free virtual run
so later failures can distinguish capacity, fragmentation and leaks.

Run the unchanged compositor again. Passing this stage means eliminating its
original Mesa allocation failure with the new profile, not declaring a complete
desktop. Record any subsequent boundary honestly; if 32 MiB is insufficient,
measure before designing shared/lazy physical backing. Preserve prior evidence,
the original compositor ELF and `.qwen/`. Complete relevant host/native/legacy
checks, independent Standards/Spec review, and a coherent V0.17 commit/push.
