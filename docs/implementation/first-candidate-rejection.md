# Retired first-candidate rejection

A captured candidate trial owns its original first snapshot. Previously, a first numerical job could complete with a definite unpublished error, retire, and leave Root Running with `initial=None`. The next sequence then used a fresh snapshot inside that same already-open scope. Native jobs 409–418 followed this path before publication 419 arrived after the original observation window.

`finish_job` now forwards the **original completion error** to Root after any retained core-replay delivery succeeds. Only ordinary, non-read-only, non-core jobs qualify. Root requires the current token's boot, Running Candidate phase, exact original snapshot and sequence, matching family and full target, and no committed initial publication. It retains the original fault and prevents successor admission. No new clock read, receipt, snapshot, job, policy or deadline is created.

A transient failure to deliver a completion retains the original Job without rejecting its scope. A successful receipt, an actual published initial latch, other trials, other targets and later snapshots cannot take the unpublished rejection path. Abort preserves an existing completion and only synthesizes the existing Expired result when none exists. The existing owner error handler recognizes retained Busy as a trial fault and advances the original scope to Drain.

The existing unactivated close path remains responsible for proving no publication, unresolved work or actual owner custody before excluded export/release. The change does not directly publish a closing baseline, synthesize those proofs or release owners.

`tests/host/test_first_candidate_rejection.py` executes the actual `finish_job`, abort, Root admission/first/rejection, owner error handler and CloseGate bodies. Six Rust scenarios cover exact rejection, foreign/success/published cases, retained delivery, owner Drain, publication/activation barriers and abort behavior. Seven independent mutations must fail. Initial behavioral RED fails because the retired Busy leaves its original scope open; positive and negative tests pass after the fix.

Reply authentication, actual Registry commit, capture and resource-owner proofs remain explicit host boundaries. The owner fixture supplies a protected fault lookup and the CloseGate fixture supplies custody facts; neither is an end-to-end unactivated export/release test. These tests establish no native deadline, pair label or complete-prototype acceptance. All nine v47 engineering checks pass: 702 host tests (two environment skips), 84 tooling tests, workspace Rust/TLS, formats and configured Clippy checks. Both native images are being built from frozen source; native validation remains pending.

## Native checkpoint

`native-single-first-candidate-rejection/` ends **FAIL after 600.720324 s**. The ordinary client exits 0, task overrun/quarantine counts are zero, and compiled source remains `47a9ece5c0faa425eecf72fce2bf77799782aa2bd6226d18ba062f2097ff2d47`. Both images and selected preparation stacks pass at 33,104/65,536 bytes. No heavy tests, builds or CRC parsing run alongside QEMU.

The real retirement case is trial 4: first job **411**, original snapshot **235000012000 ns**, completes Failed(Stale), version zero, before publication. The exact ordinary row, input-only CRC history and owner Activate-fault record agree. Its archived scope has **one input-only row, no adoption and no closing publication**; it is explicitly excluded as DataIncomplete. The next trial progresses. No new first sequence is admitted into this failed captured scope. This demonstrates the native retirement/closure path for this case; it does not make the excluded trial a valid label.

The frozen run's remaining candidates fail other boundaries:

| Trial | First Applied, from original snapshot | Later evidence |
| --- | --- | --- |
| 2 | 378: 11.209008 ms | Renewal 379 takes 81.397008 ms from snapshot; Applied 26.560 ms after its publication-based deadline. Kernel result Evidence. |
| 6 | 443: 11.316992 ms | Renewal 445 takes 80.383008 ms; Applied 25.627008 ms after its publication-based deadline. Kernel result Evidence. |
| 8 | 478: 11.269008 ms | Renewals 479–481 reject Busy; actual renewal 482 later fails Expired. Capture reaches the unchanged 8,192-interval cap. |

The explicit late renewals are sufficient violations, not proof of the verifier's first Evidence branch. The initial-priority cache covers only the original candidate publication; actual candidate renewal custody and the original workload demand must be investigated separately. No new arrivals, clock refresh or receipt retiming has been introduced.

Four baseline sides are kernel-verified and three sides excluded at the final observation; pair labels and training/validation remain zero. **Phase 10 means Archive.** Its cached Root `pending_baseline` field does not establish a current drain blockage. Kernel durable count is seven while CRC-committed disk bytes contain eight complete records; disk presence alone is not a kernel archive-completion receipt.

The single committed archive is 879,424 bytes, SHA-256 `628a989299b99662fe72e750350ebd91c86f09d4d966de943b1bc6017281d551`. CRC redo, inode extents, complete length-delimited record boundaries, whole-file hash and truncated-append refusal pass. All eight records contain 100 requests and zero missing events. Capture handoff loss is zero, retained = drained = 82,610, pending zero. Network diagnostics agree across raw/report/final watcher with 1,476,261 pieces and settlements, no binding/context/identity failures and no physical overrun. This does not explain the earlier separate physical overrun.

Admission observes 6,156 candidate visits and no denials; the prior optimizer-stopped stall is not reproduced or explained. Latest recipe 1/2 recoveries are Applied, without reproducing or explaining the old Recovery 443 stall. Neither empty first-stop evidence nor latest healthy recovery rows certify global health. Formal acceptance remains 69 NOT_RUN with the filesystem matrix incomplete.
