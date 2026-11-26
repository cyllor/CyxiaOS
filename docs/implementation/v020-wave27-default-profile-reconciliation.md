# V0.20 wave 27 — canonical default profile reconciliation (2026-11-26)

Prior integrated head c90cf0406c586097414c7389a4ad66fc80fe47e3; actual target 4912423cf2bc26ddf5c38eeea0f64190ce07a085; common ancestor 1f94d1d6326ea0fb904beec0a10e6edb916886c4. Target advanced one commit; compare diverged, ahead 163 / behind 1. PR #97 only. No production push or force.

Wave 26 exact head finished 11/12 workflows. Both production-wiring runs succeeded (45765232999, 45765225045); both media-staging jobs (139726143994, 139726638832) report ten PASS summaries. Signed receipt regression passed, new-media component 126/126 (139724425950). Diagnostic/fixture results, not formal G4/G5.

Remaining native eight-role PR run 45765232957/job 139726227976: 1 GiB 0/3, Role 6 retire_scrub phase 5 checkpoint 32 actual 2216361 ns / 2000000 ns; Role 0 actual 2091622 / 2000000 and 1994083 / 1764297 ns. Push succeeded; 256 MiB passed both. No timing waiver.

Integrate all 15 target changes: 12 nonoverlapping blobs; three workflow overlaps retain cumulative push routes and add four no-default-features flags. Exact text comparison confirmed no other overlap changes; three source comparisons failed before and passed on the candidate. New structural regression pins eight workflows (15 invocations), default manifest and three push routes; Python/Rust/native execution pending. Canonical default remains a production skeleton.

Ruling: reconcile target before timing edits to avoid verifying against obsolete defaults. All G01–G11 OPEN; 127 formal IDs NOT_RUN. Fixed CPU0, original budgets, authority and 70ms/100ms unchanged. Production signing, authentic training corpus and physical A53 evidence missing. Skills not exposed during this execution; use previously agreed inline verification rules, author self-review only. Complete new exact-head CI before further pushes. Next: root cause Role 6 scrub and Role 0 accounting.
