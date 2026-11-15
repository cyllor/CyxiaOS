# Full OS image capacity v1

This implements the already approved full-OS capacity work in the V0.17 runtime
plan. The measured, actually linked x86 cosmic-comp has 8,548 LOAD pages and a
42,173,224-byte ELF. Its text overlaps the legacy stack at 0x03000000.
Changing a host-side size check alone cannot make this image runnable.

## Selected layout

`contracts::user_layout::ImageProfile` explicitly selects `legacy` or
`full-os-v1`. Legacy parsing and stack APIs remain legacy by default, with the
existing ARM and Smithay evidence unchanged. The new kernel `full-os` feature
is x86-only and opt-in; it selects the same profile in parsing, mapping,
initial-stack construction, anonymous-memory placement and boot reporting.

| Resource | Legacy | Full OS v1 |
| --- | --- | --- |
| Image VA | 0x01000000–0x02000000 | 0x01000000–0x05000000 |
| Initial stack VA | 0x03000000, 64 pages | 0x0a000000, 512 pages |
| Private executable backing per process | 4,096 pages | 16,384 pages |
| Anonymous VA, existing large-memory heap | 0x04000000, 4,096 pages | 0x08000000, 4,096 pages |
| Shared VA | 0x06000000, 4,096 pages | unchanged |

Eight executable arenas reserve 512 MiB of actual discovered boot RAM. The
existing heap, shared and page-table pools retain their sizes; all reservations
must fit in the real four-CPU/1-GiB boot map without crossing firmware/kernel or
other allocations. The 128 page-table frames per process must suffice for the
selected mapped regions; exhaustion remains an error. A u16 slot can represent
all 16,384 image backing slots. Every mapping retains W^X, ownership, zeroing and
revocation-before-reuse. The ELF still must fit backing plus its actual stack;
the 64-MiB image window is not an unconditional grant for 64 MiB of image data.

The executable admission model has a separate ID and domain: full OS uses
model 8197, 0..16,384 free pages and 1..16,384 requested pages, quantized in
64-page units. Legacy model 8195 and its 16-page domain do not change. New
weights use the existing explicitly synthetic policy-distillation procedure;
this is not A03 training or a production-performance result. Inputs outside
the domain are rejected, never clamped. Actual pool capacity remains a hard
mechanism check after model admission.

## Verification and scope

The test seams are the real ELF plan/stack interface, executable-admission
interface, host image inspection and actual QEMU process loading. First show
that the unchanged real ELF fails legacy admission. Verify the new explicit
profile accepts its real segment layout while wrong ISA, W+X, overlap,
overflow and out-of-profile segments continue to fail. Verify stack/heap/shared
regions are disjoint, quantized admission never overcommits, and all old API
behavior remains unchanged. Then embed that same actual ELF in the OS catalog
and capture actual user execution and the first runtime failure, if any.

Existing catalog and kernel bounds are separately checked, with a 96-MiB
catalog budget only for the explicit full-OS build. Passing loader checks or
running `--version` is not a complete compositor/session result. Writable
runtime directories, flock, inotify, session services and application assets
remain subsequent requirements, driven by actual startup observations.
