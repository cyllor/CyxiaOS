# V0.16 UnPASS Native Prerequisites Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox syntax. This continues the authorized existing task in an isolated worktree, with independent task and final reviews.

**Goal:** Deliver strict A10 chain composition and the first honest, bounded native learning-pair capture on unchanged C4 code.

**Architecture:** Keep all existing trusted verifiers immutable. Compose fixed native children using an explicit caller plan; independently capture the existing guest learning pipeline and extract its actual committed side archives. Never turn a selected chain or capture into full acceptance.

**Tech Stack:** Python standard library, existing Rust/AArch64 source and C4 builds, pinned QEMU.

**Spec:** `docs/superpowers/specs/2026-11-09-v016-unpassed-next-design.md`; pinned `CyxiaOS_Minimal_Prototype_Design_Final.docx` A03/A08/A10/A16 and §§6.3/9/14.4.

## Global Constraints

- Native compiled map remains957 / 60c336577974f21545bf29f6babccc0575376cb070abb8157ba2be83f6357f93.
- Do not modify kernel, model seed, quotas,500000ns publication cap, old A10 modules or catalogue.
- Keep selected_chain_verified/capture_complete separate from full acceptance; NOT_RUN for full A03/A08/A10/A16.
- Explicit caller-selected source/build/QEMU/formatter/seed disk; no receipt-selected checker, code, command or executable.
- Preserve historical raw artifacts and nine baseline working files. Use new ignored artifact directories, permissions0700.
- No overlapping VMs; pause heavy builds during native capture. Guest deadlines unchanged;600s is host observation only.
- No auto push or merge. Preserve exact code/test/evidence hashes and RED→GREEN logs in this plan's ledger.

## Review Focus

- Same bytes from a different parent or earlier run cannot satisfy chain ancestry; test path plus timestamp edges.
- Paired counter can precede archive fsync/close/release; test the real released boundary rather than paired alone.
- Unpublished/torn banks and a partial final archive must never become complete captures; test explicit rejection.
- Unknown recovery branch counts cannot produce an exact resource approval; budget checks must remain conservative.
- A completed raw capture does not prove Reward/AcceptedSample; reports must keep the numeric-proof flag false.

### Task 1: Fixed A10 chain composition and scale preflight

**Files:** Create `tools/v16_a10_composition.py`, `tools/verify_v16_a10_composition.py`, `tools/test_v16_a10_composition.py`.

**Interfaces:** `verify_chain(trusted_plan, *, source_root, build_manifest, qemu_binary, qemu_source, initial_disk)` calls only fixed original `verify_native_child` and strict `verify_native_write_child`. Core pure link validation consumes their derived records. `legacy_preflight(overwrite_count, recovery_point_counts, *, assumed_recovery_count, observed_costs, resource_budget)` has no VM execution path.

- [x] Write behavior tests with literal expectations: supported chain stays NOT_RUN; same-byte/wrong-path ancestor rejected; temporal inversion; reused identities; changed selector/summary; untrusted checker field. Budget O2 and eight R3 branches yields211 children; O216 with assumedR84 yields conditional582339, never an exact measured branch count.
- [x] Run the new tests; Expected: failing missing functionality, not syntax/import errors. Save the RED log.
- [x] Implement exact trusted-plan schema from design: schema1/test_idA10/profile strict-write-cut-recovery-v1, external_seed sha256, cut directory/summary_sha256/expected_write, recovery directory/summary_sha256. Reject extra keys; resolve caller paths without copying/rewriting captures.
- [x] Validate seed hash/input/source path; parent final disk equals child initial; parent final-disk+identity-after < child identity-before+backend-open+spawn; same source/build/images/UUID; fresh nonce/backend/endpoint/backing. Recovery mode3/cut0/nonreordered and actual original v1 clean completion. Always full-A10 false and mandatory_matrix_slots_closed0.
- [x] Implement preflight formula P=4O, S=sum(R_i), N=3+2P+8S, exact/conditional distinction, actual runtime/storage inputs and refusal above any explicit cap. Unknown branches => INDETERMINATE_UNMEASURED_BRANCHES. Never claim to intercept the legacy CLI.
- [x] Run targeted and complete Python tools suites. Expected: no failures. Generate task report and diff package for independent review.
- [x] Independently run the new verifier on the actual R6 chain with explicit trusted plan/context. Expected: selected_chain_verified true, complete A10 NOT_RUN; reject a caller plan selecting the earlier R5 recovery despite equal disk bytes.

### Task 2: Standalone real local-pair native capture

**Files:** Create `tools/run_v16_learning_pair.py`, `tools/v16_learning_pair.py`, `tools/test_v16_learning_pair.py`. Keep old boot and acceptance runners unchanged.

**Interfaces:** `released_pair_candidate(raw_replay: bytes) -> dict | None` checks the exact boundary in the spec. CLI requires explicit source/build/output/formatter/QEMU/QEMU-source; host timeout5..600 default600. New outputs have their own scope/version, never an A01/A03 receipt.

- [x] Write tests for paired-only early state, Archive/readback state, pending baseline, wrong phase, odd publication, valid released first-pair boundary with word8zero, and caller/source/profile mismatch. Name the missing retirement/identity behavior each catches.
- [x] Run tests first; Expected: RED because the standalone capture/boundary is absent. Do not force native masks or scoring results.
- [x] Implement the fixed native custody and stopping loop from design, reusing only reviewed static helper functions. Poll0.1s, serial1s, max64 stopped retries. Preserve all exact commands, raw serial, images/model, source/input/config and hashes, final stopped banks/disk and normal process exit. Keep fatal/timeout records; do not retry for GREEN.
- [x] Add owned-socket/process tests for stop-confirm-before-save, moved/torn boundary resume, failure cleanup and exact provenance. Validate executable references and tool closure before any native start.
- [x] Run targeted and complete Python tools suites. Expected: all pass, with normal-profile guest inputs and quotas unchanged. Review independently before a VM.
- [x] Hand off native execution to Task4 after Task3 integration freezes the producer dependency closure. Task2 reports released_pair_observed only; never grant capture_complete from counters alone.

### Task 3: Strict committed-archive extraction

**Files:** Create `tools/v16_learning_archive.py`, `tools/test_v16_learning_archive.py`; integrate only the new learning runner.

**Interfaces:** `extract_local_pair(disk_path, *, trusted_capture_context, boot_epoch, family=(1,1), minimum_pairs=1) -> list[dict]` uses existing committed filesystem replay/validation. trusted_capture_context binds actual source/build/model bytes, schema/node identity, input/boot/volume and stopped released boundary. Baseline records may omit model fields. Return exact raw side ranges/hashes and identities, never AcceptedSample. No cfg(test) authority or fabricated attest.

- [x] Derive literal boundary fixtures from the actual archive writer and write tests first for concatenated sides, truncated headers/rows/tails, unsupported peer/preparation/excluded records, mismatched group/schema/model/node/arrival schedule, and wrong boot/path.
- [x] Run RED; implement a bounded parser with checked arithmetic and exact supported local layout; use existing filesystem oracle rather than an alternate disk parser.
- [x] Require Baseline and Candidate of the same actual group and distinct trial/generation, preserve complete raw bytes and matching source/model/schema hashes. Reject missing or contradictory side pairs.
- [x] Grant capture_complete only after both committed ranges and all trusted identities validate. Reports explicitly keep reward_replay_verified=false, accepted_training_sample_verified=false, model_trained=false and native_acceptance_status NOT_RUN. Do not infer numeric replay from producer hashes.
- [x] Run targeted/full tools tests; independently review. If Task2 captured native data, extract and validate actual committed sides; otherwise preserve the native blocker and do not invent a pair fixture as native success.

### Task 4: Review, native execution, integrate and hand back

- [x] After Tasks2/3 code is frozen, run one original-C4 native pair capture bounded600s with exact source/build/FMT/QEMU and no concurrent heavy jobs. Recheck released boundary after stopping, extract the committed pair, and independently revalidate. On failure retain specific diagnostics and investigate; do not invent data or retry for GREEN.
- [x] Independent whole-change review against spec and baseline inventory; fix Important/Critical through observed RED→GREEN.
- [x] Run full Python tools suite and relevant project checks; preserve named failures without relabeling old runs.
- [x] Copy only verified new changes back to the user's workspace with unchanged baseline preimages; keep prior uncommitted files intact. Do not merge/push branches or overwrite captures.
- [x] Update progress with actual results, remaining model/demand/coverage prerequisites and exact source/evidence identity. No full-case PASS without its complete adapter.

### Task 5: Native-derived closing receipt correction and independent offline replay

**Trigger:** The single native run completed first pair267.299s, verified2/archived2/paired1 and normal quit/EOF/wait0. Frozen raw custody independently passes. Original producer/parser FAIL is preserved: invalid closing restoration receipt. Both real terminal Applied closing receipts started before deadline and were polled~0.2s later, lawful under the native writer/poll contract.

**Workspace:** isolated fix-worktree from2e7a069; original worktree/source and1064 native capture files remain immutable.

**Files:** tools/v16_learning_archive.py, tools/test_v16_learning_archive.py, tools/v16_learning_pair.py, tools/test_v16_learning_pair.py. No runner/kernel/model/old A10 changes.

- [x] Add literal native-derived closing receipt RED: terminal Applied observed after approved deadline but before seal is lawful; keep actual execution/adoption deadline checks unchanged. Correct only the overstrict closing observation bound.
- [x] Add native-derived request/ABI regressions: scheduled requests are queued before release (`0<queued<=first<=arrival`), and actual ordinary Candidate input uses runtime ABI `0x4359585254494e31`, not engineering-fixture magic. Preserve Probe magic and all ordinary adoption deadlines.
- [x] Add explicit caller-only `producer_tools_root=None` to raw checker/context and composed wrapper. Default remains current trusted tool source. Supplied trusted root is hashed/AST-inspected to derive the actual producer closure; no code from it or capture artifacts is imported/executed, no receipt selects it. Preserve the original native-context path schema and all old42 tool hashes. Current independent checker identity must be recorded separately from producer identity.
- [x] Add explicit caller-only `exports_directory=None` to composed wrapper (default existing native learning-archives path). Explicit save mode exclusively creates a fresh separate derived export directory; default independent mode validates exact bytes/ranges/manifest against original disk. Never alter original native summary/context/raw files to report a new execution.
- [x] Use tests for absent/wrong frozen producer source, no archived authority, default compatibility, late closing accepted, actual execution deadline violations still rejected, separate exports roundtrip/tamper/alias/refuse-overwrite. Actual retained raw data is the tight offline feedback loop; never rerun VM for GREEN.
- [x] Targeted RED→GREEN then one final full tool suite, independent scoped fix review over2e7a069..fixHEAD. Update current checker/version/producer-root/export-root proof fields, leaving event/reward/initial-image/training/fullcase limits false/NOT_RUN.
- [x] Independently replay the SAME captured disk under corrected checker with explicit frozen producer root and new derived export directory, preserve original FAIL and all1064 hashes, and integrate verified changes only after review.
