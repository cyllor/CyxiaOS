# V0.20.1 kernel algorithms — wave 4

Baseline: 4b5716f5992d7ac5893e4fb95759d599bdf5217f. Wave 2 full host CI at a198013 passed (706 kernel-core and 2190 workspace tests; overlapping scopes). Wave 3 at 4b5716f: 11 module lanes (84 tests), independent rustfmt and kernel-core suite passed; workspace regression still running when this wave began. Do not attribute those results to this new commit.

## Scope and engineering decisions

- T20 CPU scheduler dispatch: one pass over the bounded thread table, preserving strict minimum > overdue > weighted priority, exact rational weight comparison, tie ordering, reservations and completion/clock gates. Worst case O(N) as before, fewer scans; weighted comparisons before discovery of a higher tier may offset the saving. No hard-budget or scheduling policy change. Existing prototype scheduler path, not a claim of complete native D01 integration.
- T21 VM backing commitment: short-circuit preflight after finding the exact quota; stop committing at that quota. Preserve all-or-nothing admission, first-fit selection, retired generations and separate progress backing. Worst-case O(P) with two bounded passes; no new allocator metadata, no change to fault/unmap/TLB interfaces.
- T22 I/O admission: count ordinary pages and descriptors together in one traversal. Reserved/queued/inflight/unknown/completed slots remain included; existing recovery pools, credit, escrow and byte policy unchanged. No new persistent counters or format.
- T23 VirtIO telemetry: compute published, retained descriptors, and max pending policy version in one scan. Completed descriptors remain charged until release. No change to DMA ownership, memory barriers, notification or device transport.
- T24 local TLS source admission: locate existing IP and remember first vacancy in one pass; existing IP takes precedence even after an earlier hole. Full-table LRU, debt, generation and pending/active rules unchanged. No reintroduction of cluster discovery.
- T25 snapshot capture: record exact registered slots during complete preflight and detect duplicate slots; no second per-observation registry lookup at publication. 192 bytes of local scratch for 96 slots (one u8 index and bool per slot), not a second authority ledger. Preserve verification ordering, exact identity/owner, all-or-nothing publication, previous batch invalidation and snapshot schema. Lookup remains O(M*N); do not claim O(M+N) for entire capture.
- T26 CI: add six independent jobs (17 module lanes total) and nonempty test filter gate, retain full default workspace and format checks. TLS explicitly enabled in its job; no changes to production feature defaults. Commit-SHA isolation retained.

## Verification and review ledger

Independent deterministic JavaScript reference comparisons: scheduler selection 30,000, VM commitment 25,000, I/O count 25,000, VirtIO stats 25,000, source selection 30,000, snapshot slot resolution 15,000 = 150,000; PASS. Models compare old and proposed algorithms, not compiled Rust or actual hardware. Added public-interface regression cases for tier precedence, VM rollback and progress partitions, I/O completion custody, VirtIO retained descriptors, source table holes, and atomic snapshot publication. Local Rust RED/GREEN not executed; real compile/regression evidence pending GitHub Actions. Self-review only, no independent reviewer. Native AArch64/x86 and performance measurements NOT_RUN.

Ruling: prefer bounded low-intrusion implementations over changing scheduler policy, virtual memory mappings, DMA or security-authority mechanisms; all domains retain equal architecture status. Fixed CPU0, advisory brain isolation and native single-device scope unchanged. No merge or release claim.
