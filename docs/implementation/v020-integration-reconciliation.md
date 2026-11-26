# V0.20 integration convergence (2026-11-26)

The sole continuing integration head is `work/v020-integrated-eleven-gate-custody`, PR #97. The former topic `work/v020-wave22-native-entry-guards` remains a historical reference; do not independently advance it.

## Reconciliation bases

- Common ancestor: 21c0e986f80d9bc0c830f57f864ee2096ef72e5f.
- Target: 1f94d1d6326ea0fb904beec0a10e6edb916886c4.
- Previous PR #97 head: e58850aba0b7a8333841984d43d443eee5799514 (156 commits after common ancestor).
- Remediation topic: c7a2e60e8881a8b98bb7291d8bc65c1c9fcf84fa (34 commits after common ancestor; five commits after target).

The release record's wave 17 explicitly identifies e58850a as integrated into the newer work. All 54 paths changed by the old PR exist in the topic tree; 9 blob-identical, 45 differing, none still equal to the common ancestor, and no file-mode differences. Reviewed content differences, including normalized Rust token comparisons (review aids, not formal equivalence), workflow and Python differences, and subsequent release history. Retain the newer topic tree as the resolved basis: it includes later fixed-CPU0 migration, opt-in legacy fixtures, native role/receipt/media and snapshot protections, formatters and subsequent regressions. Specific observed differences include a new BootEpoch authority and file-index encoding, generation-exhaustion refusal for snapshot GC, fixed-CPU0 default verification with legacy tests retained, and stricter recovery phase evidence. The repeated identical restore-prepare test assertion is deduplicated; one exact replay assertion remains. No old branch files are blindly copied over the newer target. Both complete histories are retained by an explicit two-parent merge commit; the branch advances without force.

## Narrow validation changes

- Route the existing six CI push lanes to the canonical integration branch, retaining all other existing triggers, scope labels, permissions and pinned toolchains.
- Correct the reserved-tail regression: 183–187 now carry the signed receipt-view proof, while 188–191 remain reserved. Explicitly test rejection of each of 183–187 in the unsigned lane. Do not change verifier acceptance rules to make a stale test pass.

## Evidence and limits

Prior topic CI c7a2e60: 4/6 workflows passed; production scope failed a stale reserved-word assertion (103/104 tests); eight-package 1 GiB native fixture failed 3/3 with controller/recovery overruns, while 256 MiB passed 3/3 and the native epoch disk passed both boots. Retain the original logs and artifacts. These are historical results, not the merged head's results. Reconciliation does not change budgets, issue formal verdicts, or claim production readiness. New exact-head CI and independent review required. All eleven production gates and formal acceptance remain open. No main-branch push or deployment is performed by this convergence.
