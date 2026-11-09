# V0.16: native learning-pair capture and strict A10 composition

Continue the user's existing unPASS implementation request. Scope and Rust/AArch64/QEMU constraints come from the pinned v1.3 DOCX; implementation choices below are the controller's engineering decisions, not a claim of separate user approval.

## Findings and approach

The present boot model is explicitly UNTRAINED_SEED0 and has a positive CoreSet count/capacity preference. The current A03 runner only observes normal startup; no quiet-after-drain workload is established. Rewriting the seed or treating synthetic packets as training data is excluded. First obtain an actual completed local learning pair through the existing guest producer, before adding a demand profile which cannot repair an unsuitable model.

The old A10 gate enumerates every overwrite cut multiplied by every recovery cut, phase and loss. Observed O=216 and one R=84 imply a conditional 582339 native children. Do not launch that plan or reduce its completion conditions. New strict WRITE evidence is nonreordered and cannot fill old mandatory reordered slots.

Alternatives considered: (a) continue generic 60/120-second captures, which cannot establish the missing learning prerequisite; (b) change seed/budgets, which violates the task; (c) build complete new kernel demand/raw-ABI profiles immediately, which adds kernel risk while the model prerequisite is unmet. Choose existing native learning capture plus independent chain composition first.

## Deliverables

1. A fixed external-seed → strict v2 WRITE cut → original v1 recovery composition verifier with explicit caller trust, temporal and identity edges, and conservative old-matrix scale preflight. It grants selected_chain_verified only, always complete A10 NOT_RUN.
2. A standalone native local D01 pair runner, using unchanged C4 images, fixed patched QEMU, original guest budgets, existing preboot identity injection and a bounded 600-second HOST observation window. It captures progress and raw fsynced archives only after both sides have been released. A capture-complete result is not AcceptedSample/Reward verification, a trained package, A03 or A16 PASS.
Task2 alone grants released_pair_observed, never capture_complete. Grant capture_complete only after Task3 has validated both committed side ranges and identities. Baseline records legitimately omit model fields: expected model/schema/node identity comes from explicit trusted capture context, not invented baseline fields.

3. Extract the matching raw archive ranges from the committed filesystem with strict structural validation and fresh artifact provenance. Preserve complete raw files for subsequent independent reward/MLP re-execution. Do not fabricate EvidenceAuthority or AcceptedSample.

## Pair stopping boundary

Use REPLAY_V13_EVIDENCE (64 u64 LE): even publication; phase[2] Prepare0 or Complete17; paired[19]>=1, verified[10]>=2, archived[17]>=2, pending_baseline[20]=0, root_phase[13]=0, capture_generation[9]=first[14]=observation[15]=closing[16]=0, current_archive[63]=0. The first pair must be local D01 weight, seed/group mapping from actual archive headers. word8 may be0 between preparations; boot identity comes from the boot bank and filesystem. A live candidate is only a hint: stop, confirm paused, reread and validate all evidence. Resume if a torn or moved candidate fails. Stop attempts <=64. Poll0.1s; serial drain1s; max600s. Positive original optimization-stop/fault evidence or timeout is FAIL with raw stopped evidence retained; no automatic retries to select a passing run.

## Native custody and archives

Accept only normal selftest, no A09/A10/service/runtime fault profile. Explicit trusted source/build/formatter/QEMU arguments; match source map, actual ELF/model and fixed boot symbols. Preserve nonce/config/input/source hashes, exact launch/platform/DTB, raw QMP/serial, stopped boot/replay/control/runtime and final disk, exact tool context and normal quit/wait0. No writes after existing preboot config, no result or mask injection.

Read committed files through existing filesystem oracle. Archives are /lr-<boot16hex>-<segment4hex>, can contain several sides. Regular side layout derives from kernel/src/learning_replay/archive.rs: header2048, peer padding, records6144 each, CPU64 each, requests128 each, prewarm64 each. First implementation supports only local D01(1,1), no peer/late/preparation/excluded/multi-action sharedPolicy. Reject unsupported or truncated records rather than silently skipping them. Save exact raw ranges/digests and matching side/group/model/schema identifiers. Capture/structure validation must explicitly report reward_replay_verified=false until an actual trusted numeric verifier is implemented.

## Trust and non-goals

Do not modify kernel, initial model, policy quotas, 500000ns publication cap, source-bound A10 budgets, old v1/v2 checkers, default catalogue or historical captures. Do not register any new full PASS. No commits/pushes of ELF/disks/identities. Native runs are serialized and heavy compilation pauses during timed native windows. Preserve the nine pre-existing uncommitted files.
