# V0.20 native owner integration: paired startup and baseline recovery

## Scope and predecessor evidence

This increment descends from PR #87 corrected head `93eb083edac23ded98106228d10342867845295c`. It keeps the eight independent roles, CPU0 control / CPU1–3 business assignment and all V0.19.9 mandatory acceptance IDs. It is not production acceptance. No training data, board evidence, signed deployment catalogue or formal PASS verdict is manufactured.

Observed predecessor CI (not evidence for the new head):
- 45446230872: 104 control-plane tests, 7 syscall tests, ordinary IPC and filesystem structure regressions passed.
- 45446230850: exact-source, ARM, x86 and security host checks passed.
- 45446230582: 22 historical filesystem format/protocol tests passed; the background maintenance joint host job failed with E0463 (macro dependency path). The omitted maintenance harness search flags are fixed here; new evidence is required.
- 45446230787: ARM 256/1024 MiB builds passed. Native 1 GiB diagnostics 3/3 passed (artifact 14944279884); 256 MiB 2/3 passed (artifact 14943924963). Failed capture: V0199_BOOTSTRAP_OVERRUN a=2 b=250798 c=250000. Keep the failed run. Earlier dedicated role7 durable diagnostic passed (artifact 14946446416), but it was single-state-store only.

## Changes

- G01/G07: canonical BootEpochStore v1 (4 KiB, 40-byte header, CRC32C, reserved bytes zero). Atomic boot allocation writes both SecurityStateStore and independent BootEpochStore afterimages in the same redo transaction, with ordered FLUSH, COMMIT, FLUSH and readback. Production startup capability issuance requires independently verified signed config and paired boot confirmation. Service-generation restart remains a separate transaction. Legacy single-state diagnostic cannot grant startup capabilities.
- G07: bounded baseline-v1 journal scan and recovery under an exclusive owner. Verify the complete committed chain and current log epoch, retain the latest committed afterimage per home block, write homes, FLUSH, read back, verify post-replay structure/system state, then update the noncurrent superblock and FLUSH/readback. Unknown completion remains closed. The implementation conservatively refuses ambiguous/corrupt log headers, and is not a general arbitrary torn-tail recovery proof.
- G07/G10: existing actual native VirtIO scratch-disk role7 fixture now uses paired startup transactions and full redo-area scan; on the second independent QEMU process it replays both latest home blocks, FLUSHes them and checks their bytes before continuing. The independent host verifier checks exact redo bytes, generations, two recovered homes, extra FLUSH and disk state. The scratch volume does not contain a complete mounted production filesystem; the fixture does not advance a superblock or issue actual production credentials.
- G02/G09: validated immutable manifest borrow removes repeated full eight-member overlap scans inside each role turn and service preflight. Check the complete manifest on construction and replacement, retain per-call actor/generation, endpoint, capability and CPU checks, and preserve all existing charges and time limits. This is a proposed fix to the observed role2 798 ns overrun, not a demonstrated WCET.
- G10: add host regressions for highest-commit merge, incomplete suffix, discontinuity, failed FLUSH, blocked checkpoint, paired store mismatch, unknown boot transaction, and single-store startup rejection. CI must verify the new commits. Fix the omitted background maintenance test dependency search.

## Remaining production gates

G01 still needs authentic signed startup catalogue, protected system inode registry and actual cap issuance. G02 still needs complete native role service loops and real dispatch integration; immutable manifest validation does not establish a running service. G03 needs actual workloads, observations and trained/validated models. G04 needs complete production trial/plan/epoch wiring, not component-only admission. G05 needs measured effects for every domain. G06 needs authentic training and validation provenance and real promotion. G07 needs mounted FS owner integration, full ACL/system-object scan, live service recovery, and independent torn-write/FLUSH fault evidence. G08 needs unified immutable snapshot media contract, production COW/GC and safe reopen. G09 still lacks exact production-wide timing and physical counter verification. G10 retains 127 IDs and all required proof pairs including physical Cortex-A53. G11 still needs final versioned media/design freeze. No G01–G11 production gate is closed by this increment alone.

New implementation choices: use the existing scratch fixture for paired-store and replay evidence; conservatively fail closed on ambiguous media; use immutable manifest borrow rather than raise the role turn allowance. These are bounded integration choices, not user-approved changes to normative semantics.
