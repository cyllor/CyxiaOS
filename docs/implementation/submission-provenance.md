# Original submission provenance

The original acceptance path now records passive facts in the existing Control record tail, words 612–638. Input hash words 608–611 and record seqlock 639 retain their existing meanings. No evidence bank or workspace allocation is added. Facts are written once, after the original completion is formed and before queue-result delivery. Delivery Busy, retry and abort of an already completed job preserve them. A new abort records Expired with unknown generation context.

The diagnostic separates the outer accept stage, the original Registry submission stage/result, and the last native callback stage/result. A successful callback followed by Registry CPU rejection is therefore represented as two distinct facts. Cleanup counts cancellation separately. Native callback wrappers preserve the original checks, operation order, clocks, results and budget enforcement. Baseline/replay/governance Executor constructions explicitly disable this ordinary-job diagnostic. This does not attribute the latest native Busy outcomes until a fresh matching run records them.

## Record layout

| Relative word | Meaning |
| --- | --- |
| 0–5 | magic `0x43595355424d0001`, schema 1, accept stage, read-only flag, completion result (1 Ok / 2 Err), error enum + 1 |
| 6–13 | Registry observed flag, stage, result tag, error + 1, version, preparation-started flag, committed flag (version != 0), published wall ns |
| 14–19 | native callback, native stage, return tag (0 absent / 1 entered / 2 Ok / 3 Err), error + 1, callback count, cancellation count |
| 20–22 | sequence echo, flags (bit 0 enabled / bit 1 generation context known), aborted flag |
| 23–26 | expected/current core generation, expected/current ledger generation |

Accept stages: 1 Start, 2 Context, 3 Verify, 4 DecodeBudget, 5 ReadOnlyModel, 6 ReadOnlyLegal, 7 Executor, 8 Submit, 9 Receipt, 10 ReadOnlyComplete, 11 Aborted.

Native callbacks: 1 AuthorizeModel, 2 AuthorizeBaseline, 3 AuthorizeRecovery, 4 Check, 5 Prepare, 6 Revalidate, 7 Publish. Native stages: 1 Enter, 2 ModelBinding, 3 ScopeAuthority, 4 Context, 5 Family, 6 Legal, 7 Dependencies, 8 OldDesired, 9 Selection, 10 PrepareIndex, 11 PreparedCount, 12 Stamp, 13 CommitTime, 14 CommitDeadline, 15 CommitCpu, 16 ModelHash, 17 ScopeCommit, 18 RootPublish, 19 DesiredWrites. Selection internals and mapped model-gate errors remain unsplit.

Registry stages are defined by `SubmissionStage` in `crates/prototype/src/policy.rs`. The observer runs after the retained record and original optimization-stop rule; original failure phase is saved before cleanup. Cached receipts and early Registry returns do not emit an observation. Their absence is explicit, and callback facts are copied back before propagating an early return.

## Verification boundary

The native harness executes actual callbacks with the actual Registry and controlled role/resource/model-gate boundaries. Post-scope-commit Root/Desired/history writes are a counted facade, not custody evidence. Tests cover legal/selection/unfinished-Desired/dependency/model-authorization/commit refusal; native precommit CPU rejection; Registry CPU rejection following a successful native callback; actual accept submit/read-only blocks; actual completion/retry/abort bodies; and the full evidence writer. Nine isolated negative mutations detect observer loss, cleanup/error conflation, record identity/overwrite failures, missing completion/abort facts and copy-back ordering. Generic Registry tests independently cover retained post-publication effects and default observers. Host debug accept fixtures use a larger libtest thread stack; target stack remains subject to the image build gate.

Empty or absent rows are not proof of a healthy publication path. These facts do not change deadlines, create execution requests, substitute for nonzero Scheduler receipts or establish physical WCET. The full prototype still requires valid paired labels, catalogue execution and the filesystem fault matrix.
