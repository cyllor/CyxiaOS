# V0.20.1 kernel algorithm optimization — wave 1

Base: `4912423cf2bc26ddf5c38eeea0f64190ce07a085` (CyxiaOS-V0.20). Target: V0.20.1.

## Scope and decisions

- T02 contiguous-frame pool: maintain sorted occupied prefix instead of building/sorting a scratch array on each allocation; preserve first-fit, owner checks, error precedence, and the existing serialized caller contract. Allocation/release O(N), O(1) explicit auxiliary storage; release now shifts the occupied suffix. No pool layout or persistent format change.
- T05 console output: retain the CPU-owned FIFO, admission and short-write semantics; one tail computation and at most two slice copies per enqueue. O(k) byte copy work, O(1) auxiliary storage. No locking/IRQ/MMIO protocol change.
- Existing SPSC control IPC and FramePool dirty cursor are not replaced. General FrameMeta, scheduler and protected control authority changes are deferred until the native toolchain and baseline are available. No changes to fixed CPU0, the isolated advisory brains, or the single-device scope.
- The two modules have no shared mutable interface; integration is atomic on the requested branch. No merge to the base branch.

## Evidence ledger

Local environment: git remote DNS failed, Rust/Cargo/QEMU unavailable. Independent Python algorithm models were verified using two concurrent processes: 35 deterministic allocation traces / 105,000 state transitions (69,894 allocation attempts, 25,823 release attempts) against a page occupancy oracle; 2,390,960 exhaustive ring combinations across capacities 1..64 comparing old per-byte placement and two-copy placement. These are algorithm-level reference checks, not compiled Rust execution; the trace does not independently prove wrong-owner rejection. Existing Rust behavior tests retained, and additional public-interface regression tests added for all 8-page occupancy masks and request lengths, near-limit addresses, non-power-of-two ring states and single-byte rings.

Status at authoring: reference models PASS; Rust RED/GREEN NOT_RUN; full workspace and native ARM/x86 NOT_RUN. Performance results not measured. No release/G1/G4/G5 acceptance claim. Review must check sorted-prefix preservation, first-fit/error semantics, zeroing/revocation prerequisites, FIFO/atomic admission, and resource budgets. Any Rust or CI failure remains open until reproduced, repaired, and rerun.

## Verification commands (pinned repository toolchain)

```sh
cargo +1.95.0 test --locked -p cyxia-kernel-core contig_frames::tests
cargo +1.95.0 test --locked -p cyxia-kernel-core console::tests
cargo +1.95.0 test --locked -p cyxia-kernel-core
cargo +1.95.0 fmt --all --check
```

Follow existing V0.20 native and source gates before integration beyond this development branch.
