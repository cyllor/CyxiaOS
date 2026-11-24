# V0.20 eight-role native adapter increment

Baseline: PR #80, corrected head e00f55cbcf2ba5b16a7b57dfebf5f4be6557c368. No change to the eight-role architecture or V0.19.9 acceptance criteria.

## Verified baseline results (not results of this branch)

- Run 45428678428: fixed-control hardening builds and security host checks succeeded.
- Run 45428678731: snapshot/media component checks succeeded.
- Run 45428678180: both ARM package builds and pinned QEMU build succeeded; both native matrix jobs failed. The 1024 MiB guest exceeded the 2,000,000 ns coordination sub-budget on all three attempts (2,009,402, 2,001,662 and 2,006,719 ns). Preserve these failures.

## This increment

- Current SnapshotReply v3 and FeatureSchema v3, with all 15 local domains, and separate security feature semantics. Reuse only the existing integer MLP arithmetic, not the historical input schema. Two native brain binaries perform fixed-vector, untrained-seed arithmetic diagnostics before their first clock call. Independent host comparison and per-generation private memory evidence are required. These are not trained models, live observations, learning feedback, or production service completion. The operations codec conservatively requires all four domain fields.
- Budget: no-admission diagnostic retries wait for the next aligned replenishment window rather than repeatedly polling. Keep all quotas unchanged and retain overrun failures. Initialization/final evidence output accounting, exact window splits, and complete production-path scheduling remain outstanding.
- Durable state: exact single-block protected-state redo append, ordered write/FLUSH/commit/FLUSH/readback and UNKNOWN on ambiguous I/O. Separate 1 GiB native scratch-disk fixture checks two fresh QEMU processes against a single newly created test disk and independently constructed canonical log records. The fixture intentionally does not mount a full filesystem, install production capabilities, persist service restarts, or demonstrate crash recovery from arbitrary torn writes. It has no production full-path budget claim. Native evidence remains pending until CI actually runs.
- Existing executor binding and terminal report verification are retained. Actual domain-specific state effects across all 15 domains, with independently verified reports, remain outstanding.
- The required proof inventory stays at 127 IDs / 262 G4 proof-class pairs; no acceptance item is promoted based on a diagnostic or host check.

## Validation

Use the parallel jobs in .github/workflows/v20-native-eight-role-bringup.yml. Preserve exact source SHA, ELF/package hashes, UART capture, memory evidence, and disk image hashes. New branch results must be obtained from the corresponding CI run, not inherited from PR #80.

This is an incremental implementation, not formal G4 acceptance or a claim that all eight production services are complete.
