# V0.20 cloud inline remediation ledger — wave 26

Base: `12ddd3b3e273bf65c4248fbb100cfc2e0adf1268`. Only PR #97 and its existing cumulative branch are writable. The user selected cloud-only inline execution with Superpowers and Ask Matt. No independent subagents, local Codex, new MCP or physical proof claimed. Parallel independent reads and CI; dependent edits serialized.

## Exact-base observed results

- 12 workflow runs (six push and six pull_request): 9 success, 3 failure.
- Production scope: 105/105 host verifier tests; ARM build and native skeleton completed in both runs. Media staging failed in push 45761819657/job 139715036323 and PR 45761823255/job 139715442676. Preserve artifacts 15091185529 and 15091135583.
- Push eight-role 45761819762 passed both 256 MiB and 1024 MiB lanes and native epoch disk. PR 45761823242 passed 1024 MiB and epoch disk; 256 MiB job 139715276775 failed all three runs, measured Role 6 recovery phase 5 checkpoint 32 at 2176502, 2160437, 2099751 ns against unchanged 2000000 ns reservation. Artifact 15091045036. These repeated failures remain visible, not cleared by the successful push lane.
- Protected gates, fixed-control, snapshot components and two-architecture native mechanism workflows all passed on both events. This is not a formal G4/G5 verdict.

## W26-A — mounted signed receipt custody

RED: downloaded push artifact 15091185529, inspected run-media-unified/boot-1/serial.txt and summary.json. Fresh signed unified boot reports V020_W11_MEDIA_STEP 1,2,3,4 success; then V020_W11_MEDIA_STAGING_INCOMPLETE step=5, with no step-5 admission report. The signed/envelopes predecessor lane completed. Trace the pre-admission signed receipt digest through media_staging.rs, volume.rs, and file_mount_v1.rs: validate_unified read the valid index into Workspace.index, then reused it for snapshot envelopes and zero continuation blocks. confirmed_receipt_query_digest subsequently consumes that overwritten buffer. The paired boot transaction does not change receipts or index. This is a concrete custody defect, not a rejected signature to bypass.

Test-first regression added to file_mount_v1.rs: an actual Ed25519-signed host-only configuration bound to the fixture, unified mount, next confirmed epoch, digest compared with the seven original disk blocks, and rejection of the unchanged epoch. Existing native CI is the observed RED; the additional Rust unit test has not independently been run red because this chat executor has no cargo/rustc/QEMU. Its execution and the full native lane must be verified on the new exact commit in CI; no GREEN claim yet.

Ruling: scan the snapshot objects before reading baseline protected payloads, so the existing scratch buffer is reused only before the index is captured. No new allocation, disk read, relaxed validation, format change, or authority expansion. This changes error precedence when both snapshot and baseline homes are simultaneously invalid; both remain fail-closed before ACL policy or mount publication. Verify existing corruption/denial tests, signed receipt regression, then signed unified and subsequent file/snapshot lanes. Author self-review only, not a fresh independent reviewer.

## W26-B — recovery scrub and CPU accounting

The current failure is at retire_root_checkpointed phase 5, not a proven general role execution or memory capacity regression. The quiescent role root has been disconnected and TLBI completed; the scrub loops through IMAGE + ROLE_STACK_BYTES, verifies zero bytes and checkpoints per page. Need measure/trace the charged work around checkpoint 32 and assess smaller bounded verified scrub units or a verified equivalent; do not expand 2ms/8ms/70ms budgets, discard execution time or reinterpret an overrun as a pass. No timing fix asserted in W26-A. Compare new exact-head native artifacts across both memory sizes and both triggers.

## Gate status and continuation

G01–G11 remain OPEN. All fifteen local domains retain equal standing; no model authority, business hot-path synchronization, or deployment change. Use existing acceptance-coverage and gate documents as authoritative. No formal acceptance IDs or proof pairs closed. No production merge. Actual production signed configuration, genuine paired training data, physical A53 and formal evidence still require external inputs. New head CI must be completed before another unverified push.
