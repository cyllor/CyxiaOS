# Control preparation: bounded target projections

The original wallclock evidence in `artifacts/v13-integration-wallclock/result.json` records a 6.989 ms first control turn against a 2.5 ms reservation: 2.133 ms in queued-control WCET collection and 1.170 ms in `CandidateSet::new`. These are observations from the earlier image, not performance claims for the changes below. Native timing must be measured after rebuilding.

## Integrated target collection

`domain_services/target_projection.rs` projects only target identities through the existing `ReadSnapshot::inspect` gate. It preserves the timestamp, strict 50 ms freshness boundary, future-clock rejection, ordinal holes, fallback and actual object generations. The live service `read()` remains unchanged: observation, legality and target-feature callbacks can call task-owner operations and must not execute under a service publication gate.

Each registered family now has an explicit `TargetSource` (Tasks, Services, Network, Storage or Platform). Registration verifies the family/source mapping; there is no function-pointer grouping. The invocation-local `domain_control/target_batch.rs` collector accepts at most eighteen released families, excludes the active family and future due times, groups queries by source, and reads each used source exactly once. It then applies the existing replay, Canary, model-publication and blocked-desired predicates in original family order. The active evaluation contributes one job; every accepted queued evaluation contributes exactly 2,500 microseconds. CoreSet still uses the ceiling of this WCET divided by candidate control cores.

Owner adapters resolve cursor ordinal, otherwise ordinal zero, against one bounded captured view. They never advance a cursor or retain targets across invocations. Task targets share one scheduler/IPC owner gate; service and network targets use one fresh immutable publication; storage captures the boot filesystem/device identities once; platform captures live IRQ identities and projects timer availability once. None calls an executor while holding a publication gate.

`Busy`, `Again` and `NotReady` invalidate the entire queue estimate. No eligibility callback sees a partial owner batch and no partial `CandidateSet` is published. True target absence remains `None`. All four collector callers propagate the result: ordinary preparation, read-only CoreSet work, replay preparation and governance preparation.

## Retry decision debit

A queued-target failure retains a pending preparation keyed by boot, controller, decision sequence, domain/kind, exact target generation, complete model binding, core/ledger generations and (for read-only work) exact WorkId. It retains the first snapshot and cursor. Subsequent attempts retry that same family, recheck the current identity and retain the original 50 ms deadline. The retry's target lookup uses the error-preserving owner batch API, so scalar callback contention cannot masquerade as object deletion and erase the debit.

Every unsuccessful retry adds its measured preparation span using checked arithmetic. The successful job receives prior spans exactly once in `encode_ns`; existing paid Measurement scopes continue recording actual physical/reward CPU and receive no additional synthetic charge. The pre-bind check rejects accumulated preparation beyond 2 ms. Final binding/bookkeeping remains included in the later accept-time bound. The first unavailable queue reserves its unique decision sequence. Terminal Budget, Expired, Overflow and Stale results retain an explicit preparation rejection, retire the attempt, restore its original family period and let other families run. Retirement and successful encoding never lower the global sequence watermark, including when governance or replay consumed a larger sequence while preparation waited. Actual identity changes follow the same recorded retirement path; prior global CPU charges remain recorded. An exact failed first replay snapshot faults the original replay root so a new sequence cannot revive that captured trial; a failed read-only WorkId is terminated only while still never-admitted Queued.

The bounded protected rejection journal retains sixteen full identities, original snapshots, accumulated CPU spans and terminal reasons, with total and overwritten-record counters. The exported `DOMAIN_PREPARATION_REJECTIONS` bank is 648 little-endian u64 words (5,184 bytes): an eight-word seqlocked header followed by sixteen forty-word records. Header words are magic `0x4359505245503133`, total, overwritten, seqlock, version 1, row width 40, capacity 16, zero. Rows retain identity, model hashes, original snapshot, cost/overflow, terminal reason, retirement time, cursor, WorkId and monotonic record ordinal. Empty evidence is all zero. This is a negative preparation record, never a proposal or APPLIED receipt. No deadline, reservation, clock claim or warm-up classification changed.

## Verification and remaining evidence

Eighteen focused host regressions pass: six bounded-collector cases, five tests using the actual ReadSnapshot publication implementation, and seven decision-debit/retirement cases. The collector tests compare scalar due/cursor/absence/eligibility behavior, assert eighteen families produce 45,000 microseconds, count one read per used source, reject incomplete owner batches before eligibility callbacks, verify all source registrations and reject unbounded/mismatched output buffers. Projection tests cover live generation updates, exact freshness boundaries, publication contention, holes, fallback and one projection serving all service families. Debit tests reject 1.2 ms plus 0.9 ms, preserve the original deadline while adding only CPU spans, reject every identity-field mismatch, latch checked overflow, retire Budget/Expired/Overflow/Stale while leaving other released families schedulable, reject old-identity reuse, preserve a larger sequence watermark and retain bounded rejection history with explicit overwrite counts.

The test-first runs observed the expected missing collector/count failures and the prior missing-debit behavior before implementation. Rust formatting and `git diff --check` pass. The root agent owns native compilation and the next cold wallclock comparison. Host tests do not establish native execution-time compliance.

## Native result and follow-up accounting correction

The next wallclock run, `artifacts/v13-batched-wallclock-20261026`, still fails the preparation bound: node A first preparation is 8.154 ms and node B is 6.877 ms, with one candidate. Queued-target collection is approximately 2.872/1.872 ms; candidate construction is 0.903/1.028 ms. No pending rejection was recorded. This run does not establish a successful timing optimization.

An independent review then found that successful read-only retry preparation used an inner start timestamp after queue selection and Measurement creation, while failed attempts used the outer timestamp. Both CoreReplay callers now pass the outer start through to its snapshot and encoding. The actual production CoreReplay host regression first observed 1.3 ms instead of 1.4 ms, then passed after correction. It also rejects 1.2 ms prior CPU plus 0.1 ms current prefix plus 0.8 ms encoding. Twenty focused tests now pass, including the existing 100-work CoreReplay lifecycle regression; this correction still requires the next native rebuild.

## Native stack regression and bounded frame separation

The batched instruction-count run (`artifacts/v13-batched-icount-20261026`) failed with a CPU1 data abort whose FAR is its stack guard. Its original faulting ELR was not retained, so the exact fault instruction cannot be established from that capture. The compiled ELF nevertheless exposes a concrete excessive preparation chain: `secondary_entry` (7,264 bytes), `run_turn` (10,176), `next_input` (30,688), the newly outlined `core_replay::next` (27,728), and `CandidateSet::new` (7,248). Those simultaneously retained frames sum to 83,104 bytes before any exception frame, against the unchanged 65,536-byte usable stack. A normal family can finish without a candidate, then fall through to read-only preparation while its scratch frame remains allocated. In the prior preparation ELF, replay was inlined into the shared frame, and the same selected-call check peaks at 58,048 bytes.

The first correction placed the entire ordinary family loop in non-inlined `next_normal`, with normal and read-only preparation called as siblings. Its actual ELF (`artifacts/v13-stack-build-20261026`) still failed: `next_input` retained 12,672 bytes of large result buffers and `next_normal` needed 29,120, giving a 66,480-byte peak. This image was retained as a failed static regression and was not used for another unsafe native run.

The follow-up gave internal preparation helpers one invocation-owned `[u64; 512]` output buffer and small boolean/unit results. Normal and read-only preparation both have explicit non-inlining boundaries. The resulting `artifacts/v13-buffered-build-20261026` ELF peaks at 62,256 bytes; `encode_job` fell to 752 bytes, but the outer value-return interface leaves `next_input` at 8,592. Its remaining 3,280 bytes do not meet the required 4,096-byte reserve, so this second intermediate image also remains a failed static regression.

The remaining correction passes that same output buffer through the sole `next_paid` caller in native `run_turn`, eliminating its large value-return intermediates. `encode_job` zeroes the complete buffer before encoding and hashing; it never mutates the buffer after binding the WorkId hash. Only success consumes the buffer, so partial failed buffers expose no execution authority. The native private input page, copy measurement and hash lifecycle are unchanged. The outer start is taken in `run_turn` before caller-buffer initialization so its actual cost remains in the decision debit. Eligibility order, original pending snapshots, sequence reservation, paid Measurement scopes, error propagation and retirement remain unchanged. No stack or CPU bound increases.

`tools/check_v13_preparation_stack.py` reads actual disassembly, accounts for LLVM page-probe loops and selected direct preparation calls, and requires a 4,096-byte reserve within the fixed stack. It fails closed on missing selected paths and unknown prologues, including register-based stack pointer rewrites. The real batched ELF produced RED (`artifacts/v13-batched-preparation-stack-red.json`); five parser/path tests and all twenty focused Rust regressions pass. The final `artifacts/v13-buffered2-build-20261026` node A and B ELFs both pass the actual-disassembly check: peak 50,384 bytes, comprising `secondary_entry` 7,264, `run_turn` 6,288, `next_input` 608, `next_normal` 28,976 and `CandidateSet::new` 7,248. The 15,152-byte remaining space exceeds the fixed 4,096-byte reserve. Both SHA-bound results are retained as `node-a-stack.json` and `node-b-stack.json` in that build directory. The checker is a regression for these known sizeable frames, not a complete proof of every indirect callback or interrupt path. A native rerun is still required.

The unified builder now requires `llvm-tools-preview` from the selected Rust toolchain (`rustup component add llvm-tools-preview`). It locates objdump under the `rustc --print sysroot` and reported host, without a PATH fallback. Before emitting a successful build manifest it disassembles both copied node ELFs and recomputes the selected paths. Missing/unrecognized paths, changed image/tool bytes, or an excessive peak block the build; both per-node diagnostic reports remain available. The reports and manifest retain ELF, checker and objdump SHA-256 values, objdump version and its Rust sysroot/host origin. Existing report booleans are never inputs to this gate. The native replay CI installs that component and independently reruns the checker on both images before QEMU; failed stack reports are retained without uploading private-key-bearing ELFs. This gate establishes only the selected preparation stack condition, not native execution, physical timing, or full stack safety.

## Read-only assessment: fused construction and registration

A proposed `Registry::create_and_register(publisher, snapshot, target, model, choices, current)` can safely authorize publisher and Active model, construct a local `CandidateSet::new`, immediately store `registered_set` using its newly computed private digest, and return the set. No mutable set escapes before that registration, so the second full SHA is redundant in this method. The existing `register` must retain its recomputation for externally supplied sets, whose snapshot/target/model fields are public, and Canary registration must retain its existing permit-scoped verification.

The normal root constructor is in `domain_control::next_normal`; its second hash currently occurs in `encode_job` through `Registry::register`. Only ordinary root and read-only CoreReplay call that encoder; read-only already skips registration. Governance scoring/Canary and replay validation have separate constructors and should remain on their current paths.

The direct substitution moves registration earlier than `core_replay::primary`, evidence-slot availability and pending-budget validation. Registration only changes the bounded 64-entry registration cache, not publication authority, model, version, quota, physical reservations or execution. Nevertheless, failed subsequent preparation can now insert or evict a cache entry where it previously did not. This must be explicitly accepted/documented, or preserved using a narrowly scoped fresh-set proof/commit design; a general public skip-integrity flag is inappropriate. A returned set mutated after registration cannot alter the independent registered binding, and normal publication must still reject mismatched target/snapshot/model envelopes.

## Protected EL0 hot-path follow-up

GitHub Actions run `40277865579` on source `fb6f1fde2023c5849aab0746ed0a4fdfcc0bccdb` used the patched translated-execution PMU and reached a later, more precise failure: CPU1 sequence 247 spent 5,040,697 ns in a 2,500,000 ns control turn, with phase 5 (EL0 evaluation) active and one real preemption. The same run passed formatting, the configured native Clippy gate, Rust workspace tests, host tests, tool tests, the native pair build and both preparation-stack checks. Its artifact upload failed separately because the repository artifact quota was full. Neither failure is recorded as acceptance evidence.

The ABI3 controller previously copied the complete 4 KiB input page with volatile loads, copied all 2,772 model bytes with volatile loads, initialized another 4 KiB output array, and copied all 4 KiB back with volatile stores on every invocation. EL1 already owns the exact lifetime of these disjoint mappings: input and the pinned model are read-only for the invocation, while the output page is cleared before it is exposed writable to EL0. The controller now borrows those protected pages in place and writes the formal plan directly into the precleared output page. The ordinary host API still clears all 512 output words; a separate protected-boundary entry point preserves canonical zero padding without a second clear. A new equivalence regression compares both APIs and checks the untouched tail.

Both locally rebuilt node images pass the unchanged selected-call stack gate with a 51,520-byte peak in the 65,536-byte stack and the fixed 4,096-byte exception reserve. Disassembly confirms the ABI3 entry passes the mapped addresses directly and no longer constructs the former page-sized input/output temporaries. This is a build and structural result only. The Linux patched-QEMU native replay must still demonstrate that the actual EL0 charge, total encode/infer/decode cost, wall deadline and paired-label path pass on this exact source before the timing or learning requirement can close.

The measured registration segment is approximately 0.314 ms on A and 0.273 ms on B. Fusion is a reasonable small follow-up, but it cannot resolve the several-millisecond cold overrun by itself. It must preserve canonical hashes and candidate ordering, validate failure-side cache behavior, retain external-set mutation regressions and be evaluated by another complete cold native timing run. No fused registration code has been applied.

## Native business-window tail admission

GitHub Actions run `40324229499` on source `a0209db` passed the prior protected-EL0 control turn, then failed later because three ordinary task credits began with only 2.437, 5.850 and 7.747 ms left in their aligned 100 ms windows. Their measured translated execution was only 0.190, 0.209 and 0.290 ms, respectively, and remained below every reserved CPU-time credit. MTTCG descheduling nevertheless moved their completion timestamps beyond the original window, correctly triggering the existing fail-closed crossed-window quarantine. The artifact upload failed independently because the repository artifact quota was full.

The standalone runtime already requires a complete 10 ms wall-time envelope before entering its bounded 1 ms user slice. The unified builtin path reserved at most the same 10 ms but admitted partial window tails. `Scheduler::dispatch_with_window_headroom` now separates this wall-time admission condition from CPU-time reservation: insufficient headroom returns no dispatch and consumes no thread or CPU credit, while the existing `dispatch` behavior and crossed-window quarantine remain unchanged. Unified builtin turns require the same 10 ms envelope before selection. Thread budgets, the 90 ms business CPU ceiling, per-turn reservation limits, timer slice, completion checks and quarantine criteria are unchanged.

The new regression proves a tail deferral leaves zero credit and that the next aligned window can dispatch and settle normally. The complete `cyxia-prototype` test suite, all 66 tool tests, formatting and the configured AArch64 kernel Clippy gate pass. A fresh two-node native build at `/tmp/cyxia-prototype.d74jke` passes both selected preparation-stack gates at 51,520 bytes of the fixed 65,536-byte stack with the 4,096-byte exception reserve. Its manifest status is `BUILT_NOT_RUN`; only the Linux patched-QEMU replay can establish that the tail quarantine is gone without a later regression.

Run `40326728813` on that source removed the CPU0/CPU2 tail faults but retained one CPU3 fault. Its builtin credit was selected with 14.663 ms remaining, then settled 22.35 ms later after only 0.797 ms of translated execution; the projected actual interval (`finished - actual`) begins in the next aligned window. This identifies a second boundary: the vCPU can be descheduled after selection but before entering the selected builtin task. Merely increasing the admission margin would guess at host scheduling latency and would not repair that credit lifetime.

The builtin path now revalidates the exact untouched credit immediately before generic EL0 entry. If MTTCG delay consumed its window or 10 ms envelope, a dedicated `cancel_unstarted` operation refunds the exact thread, physical-CPU and optional-budget reservations without recording execution, changing readiness age or weakening the existing crossed-window completion quarantine. The associated owner captures are discarded rather than converted into zero-cost work. A regression advances past the credit's window, proves the complete reservation is refunded with zero actual time and no quarantine, then dispatches normally in the new window. The complete prototype suite (now 48 task-domain tests), formatting, configured kernel Clippy and a fresh exact-source two-node build at `/tmp/cyxia-prototype.GSNcol` pass. This source is again `BUILT_NOT_RUN` pending Linux replay.

Run `40329384076` removed the CPU3 fault and next exposed the analogous CPU0 service path. A `0x101` service segment reserved the unchanged 2.5 ms, used 0.537 ms of translated execution, and crossed its window after selection with 14.210 ms initially remaining; the failure snapshot retained service stage 4. Exact service segments now use the same initial 10 ms window-headroom admission and revalidate immediately before network, owner and I/O bodies, including every resumed segment. The ordinary CPU0 EL0 service turn also revalidates after refreshing its input and reconstructs that input on a refund. No already-started segment can use this path. All 48 task-domain tests, formatting, configured kernel Clippy and a fresh exact-source two-node build at `/tmp/cyxia-prototype.S6FEdy` pass; the manifest remains `BUILT_NOT_RUN` pending another Linux replay.

## Native control-preparation admission

Run `40345901704` cleared the preceding CPU0/CPU2/CPU3 service and builtin faults, then reached a distinct CPU1 control-preparation overrun. Sequence 130 began at 27,809,488,784 ns in aligned window 278, completed at 27,953,556,736 ns, and used 4,880,863 ns of translated CPU time against a 2,500,000 ns reservation. Runtime phases 3 and 4 identify fresh candidate preparation plus protected-input copy; no EL0 slice or runtime preemption was recorded. The initial credit was also admitted with only 9.511 ms remaining in its aligned window. The substantive validation job, exact native pair build and both stack gates passed; artifact retention failed independently because the GitHub Actions artifact quota remained full.

An intermediate correction on `ef564e7` gave fresh preparation an 8 ms credit. Its complete host/static gates and two-node build passed, but this was not a conforming resolution: v1.3 §5.3 fixes encoding, inference and decoding at at most 2 ms plus at most 0.5 ms for proposal IPC/validation/publication, and explicitly forbids silently enlarging that budget. Run `40348782905` did clear the phase-3/4 quarantine and completed three proposals, but later quarantined CPU1 phase 6 after only 0.673 ms of translated execution: the credit began with 12.137 ms left and host descheduling moved completion 1.516 ms into the next aligned window. That run is diagnostic evidence only, not an acceptance pass.

The implementation therefore restores the ordinary 2.5 ms credit. `next_normal` may skip unregistered or not-yet-due slots as bounded bookkeeping, but one prepaid invocation now performs observation/candidate construction for at most one registered due action family. Every no-target, blocked, transient-unavailable or no-candidate outcome ends that evaluation turn instead of falling through into another family's complete evaluation. This matches the specification's per-family slots and prevents several nominal 2 ms evaluations from being hidden inside one 2.5 ms scheduler credit.

Control admission now requires 20 ms of aligned-window wall headroom. This leaves all 70 ms of specified control CPU capacity usable in a 100 ms window, does not enlarge any CPU credit and covers the measured 13.65 ms host pause that crossed the previous 10 ms envelope. Actual settlement, the 70 ms control and 90 ms physical ceilings, the 50 ms proposal deadline and crossed-window quarantine remain unchanged. The scheduler regression proves a 19,999,999 ns tail defers without reserving CPU and the next window settles an ordinary 2.5 ms credit to its measured actual cost. Control-credit failures now print the raw preparation phase banks even when artifact upload is unavailable. The complete prototype suite, 66 tool tests, formatting and configured AArch64 Clippy pass. A compiler-generated `next_normal` closure exposed an overbroad stack-checker symbol match; a negative regression now distinguishes the exact function/hash from nested closures. A fresh exact-source two-node build at `/tmp/cyxia-prototype.dg4Jqk` passes both stack gates with a 50,944-byte selected peak. Its manifest is `BUILT_NOT_RUN`; Linux replay remains required.

Run `40351167637` passed all host/static/build/stack gates and moved the first native failure to CPU2 ordinary thread `2:1`. Its 10 ms credit used only 0.163 ms of translated CPU, but began with 12.577 ms left and finished 1.012 ms into the following aligned window after another host pause. The same 20 ms admission envelope is therefore applied to builtin and exact service dispatches. This does not reduce the 90 ms business capacity: nine consecutive 10 ms credits can still begin at 0 through 80 ms and settle by 90 ms. A regression exercises that exact schedule. CPU-time reservations, actual-time settlement, service budgets, revalidation/refund and crossed-window quarantine are unchanged. The complete prototype suite, configured AArch64 Clippy and fresh exact-source build `/tmp/cyxia-prototype.mXWlCS` pass; both selected stack peaks remain 50,944 bytes. A new Linux replay is required.

## Conservative completion-window carry

Run `40352953711` passed every substantive host, static, build and stack gate and ran longer, then failed on CPU0 service thread `257:1`. The segment began with 30.219 ms left in aligned window 306 and used 1.037 ms of translated guest CPU against its unchanged 2.5 ms credit, but its wall completion arrived 32.235 ms later and 2.015 ms into window 307. This exceeds both previously observed host pauses and demonstrates that a larger fixed admission margin would be a host-scheduling guess rather than a guest CPU bound. It would also begin to reduce the specified 90 ms business envelope. Artifact upload again failed independently because the repository quota was full.

Scheduler settlement now separates a real CPU overrun from a wall-late receipt. `actual_ns > reserved_ns` still consumes the receipt, increments the overrun counter and quarantines the physical CPU. When actual CPU remains within its prepaid credit but the host-delayed completion crosses the aligned boundary, settlement succeeds and retains the actual cost in both windows: the original window replaces the reservation with actual usage, and a window-tagged carry conservatively charges the same actual usage to the completion window before any new admission. Control work carries both its 70 ms control ledger and shared 90 ms physical ledger. Ordinary and delegated service work carry the executing CPU/group ledger plus the caller thread ledger; delegated work does not falsely charge the caller's source CPU. A pending old-window service receipt blocks rolling, so tagged carries survive until they can be applied instead of being erased by another core's completion. Read-only usage reports expose a pending carry.

This is deliberately conservative: host descheduling is not reported as guest CPU execution, while no completion-window capacity is released by the delay. Guest wall deadlines, the 50 ms proposal deadline, the 20 ms start/revalidation envelope, per-thread limits, 70/90 ms ceilings and actual-over-reservation quarantine remain independent and unchanged. Three regressions cover ordinary, control and delegated-service late receipts, including concurrent old-window work on the caller's source CPU; they prove the next window loses the exact carried amount and that true CPU overruns still quarantine. The task-domain suite now has 52 passing tests. The complete prototype suite, 608 host tests (two environment-specific skips), 67 evidence-tool tests, the full non-kernel Rust workspace, formatting and configured AArch64 kernel Clippy pass locally. The exact-source two-node build at `/tmp/cyxia-prototype.f27Xvm` has status `BUILT_NOT_RUN`; both selected preparation paths peak at 50,944 of 65,536 bytes with the fixed 4,096-byte exception reserve. Patched-QEMU replay remains required.

Run `40356644036` confirms that change: no crossed-window quarantine occurred. It instead reached a real CPU overrun on CPU1 sequence 118, where one domain-1/kind-1 candidate preparation used 3.738 ms of translated execution against the unchanged 2.5 ms credit. Phases 3 and 4 were active, the protected EL0 evaluation itself used only 0.013 ms, and no runtime preemption was recorded. All substantive validation, exact-build and stack gates passed; both artifact uploads failed only on the existing quota. Because the detailed preparation timestamps were still wall-clock values, MTTCG pauses make their deltas unsuitable for CPU attribution. `DOMAIN_PREPARATION_DETAIL` now records absolute patched per-vCPU execution ticks while the coarse bank retains wall-clock timestamps. The next failure snapshot can therefore partition actual CPU across target/current/observation, legality/features, candidate construction, registration, input encoding, page hashing and evidence publication without changing a guest budget or acceptance rule.

## CPU-attributed candidate preparation

CI run `40359127789` on source `9db754bcb1eb9ae3e0db5db19eecd5b23540ac3d`
reproduced a genuine single-candidate overrun on CPU1: sequence 149 used
2,985,985 ns against the unchanged 2,500,000 ns reservation, with no
preemption. The absolute per-vCPU detail ticks partition the pre-encoding path
as follows: target/replay prefix 155,011 ns, current/observation 358,151 ns,
stability/dependencies 37,858 ns, legal candidates 254,394 ns, queued WCET
239,982 ns, candidate feature assembly 424,359 ns, CandidateSet construction
and canonical hash 459,907 ns, and CoreReplay selection 41,004 ns. The remaining
1,015,319 ns covers registration, input encoding/page hash, evidence/history
publication and the final retained-job copy. Protected EL0 evaluation was only
41,576 ns. This run passed every substantive validation, exact-build and stack
gate; both artifact uploads failed independently on the existing repository
quota.

The measured correction does not increase any budget. Invocation scratch now
uses `MaybeUninit<Candidate>` and exposes only the prefix written before its
count is advanced, eliminating unconditional initialization of 32 complete
feature records when the family emits one. `CandidateSet` now stores the
common/domain feature fields once and retains only action-specific target and
capacity fields per bounded entry; `get` and `iter` reconstruct the same public
`Candidate` values, so ordering, duplicate/conflict checks and canonical hashes
are unchanged. A compile-time bound requires the complete 32-entry set to fit
within one 4 KiB page, reducing construction and each later retained copy. The
full prototype test suite and strict AArch64 Clippy pass locally. Exact-source
build `/tmp/cyxia-prototype.dUwVeu` is `BUILT_NOT_RUN`; both selected native
stack paths pass at 37,968 of 65,536 bytes with the unchanged 4,096-byte
exception reserve (down from 50,944 bytes on the diagnostic source).
Patched-QEMU timing is still required on this source before the preparation
budget can be accepted.

Run `40362192077` shows the structural change is beneficial but insufficient:
the scratch/feature segment fell from 424,359 ns to 265,438 ns and both native
stack peaks remained 37,968 bytes, but the complete preparation still used
3,242,836 ns. CandidateSet construction/hash measured 762,495 ns in this run
and the segment after CoreReplay selection measured 1,252,579 ns; neither can
be treated as fixed overhead from the earlier single sample. Validation,
build and stack gates all passed, with only the known artifact-quota failures.
The detailed CPU bank now uses its remaining five per-CPU slots to mark
registration/prechecks, completed input encoding, completed input-page hash,
completed WorkId/evidence binding, and completed history/final Job retention.
This adds attribution only and changes no execution path, budget or acceptance
condition.

Run `40364424158` on the instrumented source crossed the complete control
preparation path without a C-credit fault and instead stopped later with native
learning worker fault `1294` (`0x50e`). The code is `0x500 + Error::Budget`
from `ExtraBudget::settle`: the physical control credit had already accepted an
in-reservation guest-CPU span, but the learning ledger still rejected its
host-delayed wall completion against `start + 2.5 ms`. This run therefore
establishes that the candidate compaction closes the observed preparation
failure, while exposing a separate learning-ledger clock mismatch.

`ExtraBudget` settlement now matches the physical control ledger's clock
semantics. A real `actual_ns > limit_ns`, impossible interval, 9 ms extra-role
ceiling or 70 ms combined ceiling remains a sticky Budget fault. An in-credit
turn whose wall receipt arrives in a later aligned window succeeds, remains
charged in its grant window and carries the same actual CPU into the completion
window before any new extra-role admission. The carry is window-tagged and
checked against the unchanged 9 ms ceiling. A regression uses a 1 ms actual
turn whose wall receipt arrives 15 ms after a 90 ms start, proves both ledgers
settle, and proves only 8 ms of extra-role capacity remains in the next window;
the existing 2.6 ms actual-overrun regression still faults both ledgers.
The complete prototype suite and strict AArch64 Clippy pass. Exact-source build
`/tmp/cyxia-prototype.b9yAHp` is `BUILT_NOT_RUN`; both selected stack paths pass
at 37,984/65,536 bytes with the unchanged 4,096-byte exception reserve.

Run `40369025168` confirms learning fault `0x50e` is gone, but another sample
used 2,962,778 ns of actual preparation CPU. The complete detail timeline
attributes 700,368 ns to CandidateSet construction/canonical hashing, 313,736
ns to registration/prechecks, 69,171 ns to input encoding, 171,426 ns to the
4 KiB input hash, 236,020 ns to WorkId/evidence binding, 129,286 ns to history
and final Job retention, and about 154 µs after the last marker. This leaves a
real 462,778 ns gap to the unchanged 2.5 ms credit; the learning carry is not a
substitute for closing it.

The canonical candidate hash still consumes the identical byte stream and
keeps the `CYXIA_CANDIDATES_V1.3` format. Its fixed header, each candidate and
optional Canary scope are now assembled into small bounded buffers and passed
to SHA-256 once per component, instead of invoking the generic digest update
for every two-byte, one-byte and eight-byte field. A golden regression records
the pre-change four-candidate digest and all policy/Canary/native-control and
bounded-replay tests pass unchanged. Strict AArch64 Clippy passes. Exact-source
build `/tmp/cyxia-prototype.Z5Nrx0` is `BUILT_NOT_RUN`; both selected stack
paths remain 37,984/65,536 bytes and `CandidateSet::new` remains a 4,032-byte
frame. Linux patched-QEMU timing is required to establish whether the measured
hash overhead is reduced enough.

Run `40372166147` shows that batching generic digest updates did not close the
native bound. CPU1 sequence 137 used 3.768 ms against its unchanged 2.5 ms
credit. The per-vCPU detail bank attributes approximately 0.786 ms to legality,
0.799 ms to CandidateSet construction/hash and 0.460 ms to registration; the
remaining stages and unmarked edges account for the balance. This is a real CPU
overrun, not a wall-clock carry or artifact-upload failure.

The AArch64 kernel build now hashes the same single bounded canonical byte
stream with the existing Armv8 SHA2 implementation used for protected page
hashes. The maximum representation is fixed at 5,519 bytes (150-byte header,
32 164-byte candidates and an optional 121-byte Canary scope). Other targets
and AArch64 machines without SHA2 retain the `sha2` software fallback. The
pre-change four-candidate golden digest remains
`9e0f74e396ebe50cbb1047727cbc4cbc0cf11c5e891bfea495d8bfade103ccda`;
the complete prototype suite and configured AArch64 strict Clippy pass. Exact
local build `/tmp/cyxia-prototype.6Acj71` is `BUILT_NOT_RUN`; both independently
checked node paths remain 37,984/65,536 bytes with the 4,096-byte exception
reserve. Disassembly of the actual node image shows CandidateSet hashing calls
`cyxia_sha256_compress_hw` and retains the software digest branch. Patched-QEMU
timing is still required; no preparation or catalogue requirement is closed by
the local build.

Run `40375412966` no longer reached the former fresh-preparation failure. It
instead failed during the earlier boot mapping probe: CPU1 sequence 6 spent
9.024 ms against the separate 8 ms recovery/setup credit, with phase 2, one
timer preemption, no active job and zero preparation markers. The first A02
capture entry proved a new task identity by scanning all 512 protected task
slots even though the table is append-only and never develops holes. That
evidence work is inside the paid EL0 boundary and was therefore part of the
real overrun.

The A02 task count already retained in counter 27 now bounds lookup to the
dense initialized prefix. New identities append at exactly that prefix; a
count beyond capacity, a hole, a full table or a missing exit identity still
fails closed. Exit and affinity binding use the same prefix, and binding reuses
the resolved slot rather than scanning a second time. The standalone protected
capture tests include exact two-slot exhaustion and pass, as do formatting and
configured AArch64 strict Clippy. Exact local build
`/tmp/cyxia-prototype.PbxIPh` is `BUILT_NOT_RUN`; both selected preparation
paths pass at 37,984/65,536 bytes with the 4,096-byte exception reserve. Native
timing remains required.

Run `40376975641` confirms the dense-prefix change removed the boot-probe
failure and the hardware-hashed ordinary preparation was no longer the first
fault. It instead exposed simultaneous cold EL0 overruns on CPU0 and CPU3:
3.903/2.5 ms and 12.718/10 ms. Both entries share the optional A02 capture
lock. Its prior unbounded spin converted time spent waiting for a descheduled
lock owner into paid translated execution on every contender.

A02 capture contention now uses strong compare-exchange followed by AArch64
`WFE`; release publishes the protected state with release ordering, `DSB
ISHST`, then broadcasts `SEV`. Strong CAS prevents a spurious failure from
sleeping when no owner exists, while the event-register rule prevents an
unlock between failed CAS and WFE from being lost. Capture records remain
serialized and none are skipped. A host structural regression pins the strong
CAS/WFE/release/DSB/SEV protocol; all thirteen A02 host tests (one historical
artifact skip), formatting and configured AArch64 strict Clippy pass. Native
build `/tmp/cyxia-prototype.sNuH59` is `BUILT_NOT_RUN`; both selected paths pass
at 37,984/65,536 bytes with the 4,096-byte exception reserve. Native timing is
still required.

Run `40378384224` confirms the event-sleep lock removed both competing task
overruns. The next failure is again the mapping probe, now 8.287/8 ms on CPU1
sequence 42 after three timer preemptions; it has no job or preparation
markers. The remaining hot entry path wrote the same slice-evidence magic and
version from every CPU on every entry, used an exclusive atomic increment for
a per-CPU single-writer row, and read the architectural timer twice with no
intervening work. The immutable header is now initialized in the static bank,
the row count uses single-writer atomic load/store, and the adjacent evidence
fields share one observed timestamp. Layout, ordering fields, credit sizes and
timer deadlines are unchanged. Configured AArch64 strict Clippy passes. Exact
local build `/tmp/cyxia-prototype.8XqGmq` is `BUILT_NOT_RUN`; both selected
stack paths remain 37,984/65,536 bytes. Linux timing remains required.

Run `40380893390` confirms the probe-counter sharding removed that control
failure and again passed beyond ordinary preparation, but the first CPU0/2/3
task segments concurrently exceeded 2.5/10/10 ms. The A02 lock's first WFE
correction broadcast `SEV` on every unlock, even with no sleeping contender.
Under TCG that architectural broadcast is a synchronous helper inside the
charged translated block. The lock now publishes a waiter flag after failed
strong CAS, rechecks the lock before WFE, and performs `DSB ISHST; SEV` only
when release atomically consumes a real waiter flag. This preserves the
unlock-before-WFE event-register proof and wakes all multiple waiters, while
uncontended capture does no broadcast. All thirteen A02 host tests (one
historical-artifact skip), formatting and configured AArch64 strict Clippy
pass. Exact local build `/tmp/cyxia-prototype.u002qv` is `BUILT_NOT_RUN`; both
selected stack paths remain 37,984/65,536 bytes. Native timing remains
required.

Run `40421014889` remains in phase 2 at sequence 583 with
8,773,658/8,000,000 ns. The previously attempted index optimization paid for
three additional atomic handoffs. The verified registration index is now kept
in the CPU-private native `WorkerState` and passed as an ordinary argument
through the same `enter_service` stack frame. Exact entry and return directly
recheck `tasks[index] == task`; no atomic handoff or capture-layout field is
added. Fixed builtin callers pass `None` and retain the original lookup path.
The full 615 host tests (two environment skips), 141 v1.3 tests (one
historical-evidence skip), formatting and configured strict AArch64 Clippy
pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-capture-direct-index-2`
passes both selected stack paths at 33,920/65,536 bytes. Linux timing remains
required.

Run `40419400094` crosses registration and all C-worker gates, then the global
task bank reports CPU0 service `257:1` at 4,806,874/2,500,000 ns in network
stage 4 and CPU2 builtin `2:1` at 10,957,969/10,000,000 ns. Halving the builtin
loop did not materially change its cold boundary; the auxiliary slice row is
therefore disabled for this fixed fixture while A02 authoritative boundaries
and task-credit receipts remain unconditional. TCP polling now checkpoints
after preflight and before the first NIC service, where no device/socket borrow
is live. Network segments publish substage 40 and increment after every safe
checkpoint so any remaining overrun is attributable to one bounded piece.
No credit changes. The full 615 host tests (two environment skips), 141 v1.3
tests (one historical-evidence skip), all 14 cluster-transport network tests,
formatting and configured strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-network-preflight` passes both selected
stack paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40420213955` again reaches phase 2 and uses 8,559,843/8,000,000 ns at
sequence 599. Inside the exact capture boundary, one-word entry/return payloads
still used a dynamically sized loop, and every uncontended unlock executed a
`WAITERS.swap` RMW. Capture append is now const-generic over payload length so
the one/two/six-word cases compile as fixed work. Unlock first acquire-loads
the waiter flag and performs the RMW/`SEV` only when published contention may
exist; a waiter racing after a false load observes the released lock in its
mandatory recheck and cannot sleep. Capture bytes and synchronization semantics
are unchanged. The full 615 host tests (two environment skips), 141 v1.3 tests
(one historical-evidence skip), formatting and configured strict AArch64
Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-capture-fixed-payload` passes both selected
stack paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40418568412` crosses the mapping-probe exception boundary; the next
failure is phase 0 at sequence 601, where the separately paid task registration
uses 9,784,972/8,000,000 ns. Registration constructs one capture event, but
`append` used `copy_from_slice` for its seven-word fixed header and dynamic
payload, retaining a generic copy path similar to the earlier clear failure.
The event writer now emits seven explicit scalar header stores and a bounded
payload loop. Event bytes, ordering, counters, capacity and failure behavior
are unchanged. The full 615 host tests (two environment skips), 141 v1.3 tests
(one historical-evidence skip), formatting and configured strict AArch64
Clippy pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-capture-scalar`
passes both selected stack paths at 33,904/65,536 bytes. Linux timing remains
required.

Run `40417713681` shows the atomic index handoff is counterproductive under
TCG: phase 2 rises to 10,973,090/8,000,000 ns at sequence 625, so that change
is removed. Inspection also finds that `record_slice_evidence=false` skipped
the entry-side auxiliary row but the exception handler still unconditionally
wrote five atomic `TASK_SLICE_EVIDENCE` fields. A per-CPU flag now enables those
exception fields only for entries that requested auxiliary timing. Mapping
probes therefore skip the complete auxiliary row as intended, while their A02
authoritative enter/return capture and all normal task slice evidence remain
unchanged. The full 615 host tests (two environment skips), 141 v1.3 tests
(one historical-evidence skip), formatting and configured strict AArch64
Clippy pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-probe-no-aux`
passes both selected stack paths at 33,904/65,536 bytes. Linux timing remains
required.

Run `40381922994` confirms conditional `SEV` removed the three task-credit
faults and progressed to normal preparation. CPU1 sequence 73 then used
13.057/2.5 ms before candidate construction: the current-action callback took
approximately 4.840 ms and dependency preparation approximately 2.630 ms.
The dependency admission view scanned all 512 entries for every lookup even
though publication slots are stable and almost all rows are unused. It now
publishes a seqlock-covered monotonic high watermark and scans only that prefix;
a sparse-slot regression proves later entries remain visible across retirement.
The service current-action reader also projects under its immutable snapshot
gate rather than copying the complete view. Error semantics, exact object and
generation matching, seqlock recheck and dependency authorization are
unchanged. Focused dependency/service tests and configured AArch64 strict
Clippy pass. Exact local build `/tmp/cyxia-prototype.dMmVh7` is `BUILT_NOT_RUN`;
both selected stack paths remain 37,984/65,536 bytes. Native timing remains
required.

Run `40379550634` moved the next probe fault to the separate phase-8 return
bookkeeping: CPU1 sequence 8 used 10.007/8 ms, with no active job or
preparation markers. The only cross-core exclusive operation in that path was
the shared protected-probe counter, updated by both C workers at synchronous
returns. It is now four per-CPU single-writer atomics; evidence readers
saturating-sum the same exact counts. The external total and release/acquire
publication semantics are unchanged. Configured AArch64 strict Clippy passes.
Exact local build `/tmp/cyxia-prototype.wu12S3` is `BUILT_NOT_RUN`; both selected
stack paths remain 37,984/65,536 bytes. Linux timing remains required.

Run `40383183823` did not validate the dependency source. Its first attempt
stopped in an early 8 ms mapping probe, while an exact rerun progressed to
normal preparation and recorded a 23.516 ms CPU overrun between detailed
markers 5 and 6. The preceding optimization was nevertheless visible:
current-action lookup fell from approximately 4.840 ms to 2.595 ms and
dependency preparation from 2.630 ms to 0.845 ms. The uncompleted interval is
legal-tier enumeration. That path previously reacquired the same domain owner
snapshot independently for every one of up to four tier values; the task Cache
family also repeated identical physical partition and backing validation four
times.

Each registered family now supplies a bulk legality projection. Normal
preparation and publication revalidation collect a tier from one immutable
owner view, retaining the scalar callback for final apply checks. Hard action
rejections still remove only that action, while Busy/Again/NotReady/Stale/
NotFound abort the complete tier and retain the original preparation identity.
The task Cache projection additionally reads its common partition identity and
physical spans once, varying only the candidate page grant. Three direct
behavior regressions pin order, transient short-circuiting and capacity failure.
A new per-CPU diagnostic row records family, target and current action without
changing an acceptance condition. The complete prototype suite, 47 domain-tool
tests and exact two-node build `/tmp/cyxia-prototype.BxOJpS` pass locally; both
selected stack peaks are 37,968/65,536 bytes. Patched-QEMU timing is required.

Run `40386657172` did not reach legality preparation. CPU1 sequence 20 spent
11.612 ms against the unchanged 8 ms mapping-probe credit, phase 2 after five
earlier timer returns; all preparation rows were empty. Each mapping probe's
first EL0 instruction is the deliberate fault under test, but it inherited the
normal model's 100 us wall timer. Serialized protected capture before the
architectural entry can consume that wall interval, so an already-expired timer
repeatedly returned before the faulting instruction ran. Mapping probes now use
a separate 20 ms wall escape deadline. This grants no CPU: their actual debit
still settles against `PROBE_PREPAY_NS = 8 ms`, and a missing immediate fault
therefore still quarantines. Normal model slices remain 100 us and the probe's
overall wall deadline remains one second. A source regression pins all three
bounds. Exact two-node build `/tmp/cyxia-prototype.aiYaXT` passes with both
selected stack peaks unchanged at 37,968/65,536 bytes; Linux timing is pending.

Run `40387650339` confirms the separate wall deadline removed the repeated
timer returns (`preemptions=0`), but the first direct mapping fault still used
8.900 ms of its 8 ms CPU credit. The high-granularity
`TASK_SLICE_EVIDENCE` row is an auxiliary timing diagnostic, not the A02
authoritative schedule trace; its many timer/control reads and atomic stores
were therefore perturbing the cold probe being measured. Mapping probes now
skip only that auxiliary row. `a02_capture::enter/returned` remain unconditional
around the actual architectural entry, while normal model, learning, service
and business entries retain the slice bank. A regression pins both facts.
Exact two-node build `/tmp/cyxia-prototype.n8RbyI` passes and both selected
stack peaks remain 37,968/65,536 bytes. Patched-QEMU timing is required.

Run `40388709995` passed the exact build and both stack gates, crossed the
mapping probes, and then found a different empty preparation turn: CPU1
sequence 22 used 2.964 ms against the unchanged 2.5 ms credit. Phase 3 was set,
but only preparation marker 0 was present and the family context remained
empty. Marker 0 arrived about 2.023 ms after the turn body began. The native
caller was eagerly constructing a zeroed 4 KiB stack array before entering the
domain owner; a successful encoder later zeroed the complete array again and
copied it to the already isolated per-CPU input page. The stopped C worker now
encodes directly into that private page. `encode_job` still clears every word
before publishing a job, empty/retry turns never expose old contents to EL0,
and `DSB ISH` still publishes all writes before a later entry. A structural
regression pins those properties. The complete prototype suite, 137 v1.3 host
tests (one historical-evidence skip), configured AArch64 strict Clippy and
exact two-node build `/tmp/cyxia-prototype.4ohiQN` pass locally. Removing the
redundant stack page reduces both selected preparation peaks from 37,968 to
33,872 bytes out of 65,536, with the unchanged 4,096-byte exception reserve.
Patched-QEMU timing is still required.

Run `40390634770` crossed the prior empty-preparation failure but stopped in a
separate first private-clear turn: CPU1 sequence 2 used 13.273 ms against the
unchanged 8 ms setup credit, phase 1 with no preparation or active job. The
clear loop attempted to yield after 0.5 ms by sampling the patched guest CPU
counter inside a translated loop. That is not a static work bound: a translated
block may retire before the counter observation exposes the limit. Each paid
clear turn is now capped at exactly one 4 KiB private page, independent of any
in-loop clock refresh. The full nine-page clear still completes incrementally;
each page retains its final `DSB ISH`, actual CPU settlement and next-offset
publication. The focused source regressions, configured AArch64 strict Clippy
and exact two-node build `/tmp/cyxia-prototype.RwELJY` pass; both selected
preparation peaks remain 33,872/65,536 bytes. Patched-QEMU timing is required.

Run `40391681911` crossed the bounded private clears and localized the next
ordinary family-0 preparation to two earlier intervals. CPU1 sequence 57 used
23.140/2.5 ms for domain 1, kind 1, target 1:1: target discovery consumed about
6.815 ms and the replay/measurement prefix another 11.364 ms. Target discovery
previously acquired the task owner separately for current ordinal, fallback
ordinal zero and exact lookahead. It now submits current/fallback plus exact
lookahead as one batch against one immutable owner view; a direct regression
proves lookahead cannot accidentally reuse fallback zero. Measurement setup
also scanned all 16 completed-attempt handoff slots with exclusive CAS even
before any attempt had ever been retained. A release/acquire monotonic flag now
proves that virgin state and skips the scan; after the first retention attempt,
the full conservative scan remains enabled permanently. The custody regression
proves zero virgin scans and still exercises cross-CPU retained completion.
Configured AArch64 strict Clippy, 138 v1.3 host tests (one historical-evidence
skip), focused native-control tests and exact two-node build
`/tmp/cyxia-prototype.NWCKfy` pass. Both selected preparation peaks are
34,080/65,536 bytes with the unchanged exception reserve. Linux timing remains
required.

Run `40392949565` attempt 1 stopped in the known cold mapping probe at
8.348/8 ms. Its exact-source attempt 2 crossed all C-worker preparation without
a C-credit failure, confirming the batched target and virgin-handoff paths,
then exposed a CPU0 service segment at 5.003/2.5 ms (`0x101`, unified service
stage 4). The initial native TCP segment combined device completion service and
its port flush before the first scheduler callback. Those are separately
bounded operations and no device/socket borrow or protocol update crosses the
boundary. Native polling now checkpoints after completion service, after its
flush, after one ingress attempt, after each egress attempt, and after the final
flush. The transport regression observed only three checkpoints before the
change and now requires at least five. All 14 transport tests, 138 v1.3 host
tests (one historical-evidence skip), configured AArch64 strict Clippy and
exact two-node build `/tmp/cyxia-prototype.PCoLCe` pass; both selected
preparation peaks remain 34,080/65,536 bytes. Native replay is pending.

Run `40394645785` crossed preparation again, but the broader checkpoint alone
still left two genuine task-credit faults. CPU0 service thread `0x101` used
9.548/2.5 ms in unified network stage 4, and CPU2 builtin thread `2:1` used
6.333/2.696 ms. The network device's apparently bounded TX/RX checks each
synchronized an entire 4 KiB used-ring page merely to acquire `used.idx`, so
one empty service call retained 8 KiB of cache maintenance inside a segment.
The batch queue now synchronizes only the exact index, returned record,
descriptor, availability, request and response byte ranges participating in
each DMA ownership transition. Publication/acquisition barriers and a second
post-index record synchronization remain intact. TX and RX device checks also
have a scheduler-safe boundary with no live port call or DMA token. A recording
platform regression rejects any steady-state synchronization larger than one
cache line and verifies the actual 3/7/8-byte fields; the transport regression
now requires at least seven safe points. The CPU2 receipt was a distinct
window-tail grant: the translated-execution PMU can charge more than 2.696 ms
before the architectural timer PPI returns, so builtin workers now require the
existing complete 10 ms turn and defer an undersized tail to the next budget
window. No budget or overrun threshold is enlarged. The full non-kernel Rust
workspace, 613 host tests (two environment skips), 67 tool tests, 139 v1.3
host tests (one historical-evidence skip), strict AArch64 Clippy and exact
two-node build `/tmp/cyxia-prototype.fdQQtL` pass. Both independently recomputed
selected stack peaks remain 34,080/65,536 bytes. Patched-QEMU replay is pending.

Run `40396666561` confirms both preceding task-credit corrections: neither the
network service nor the builtin worker faulted, and the first failure returned
to a single CPU1 CoreSet preparation. Sequence 114 used 3,692,619 ns of its
unchanged 2,500,000 ns reservation with no preemption. Per-vCPU detail markers
attribute about 0.629 ms to one-candidate construction/hash and 0.375 ms to
registration; repeated service projection, held-tier alternate validation and
diagnostic release stores also remained in the charged prefix. Every
substantive static, exact-build and stack gate passed; artifact upload failed
independently on the existing repository quota.

The follow-up keeps all v1.3 budgets and candidate bytes unchanged. CoreSet
current action and observation now come from one immutable service snapshot.
A frozen or not-yet-held numerical tier validates only its current action,
because the alternate is unconditionally discarded later in the same turn.
Per-CPU detail markers use relaxed stores; their stopped failure snapshot and
the credit record remain the publication boundary. Canonical hashing selects
the smallest fixed scratch tier that contains the exact stream, so the common
single candidate no longer clears 5.5 KiB to hash about 314 bytes. Retained
actions use a private lossless 64-bit representation, and registration hashes
have a contiguous bounded index instead of scanning one cache line from each
large retained set. All eighteen action shapes round-trip exactly; a 65-entry
regression proves the index follows the existing 64-slot eviction order and is
cleared with model or publisher authority changes. The full non-kernel Rust
workspace, 613 host tests (two environment skips), 67 tool tests, 139 v1.3
host tests (one historical-evidence skip), formatting and strict AArch64
Clippy pass. Exact local build `/tmp/cyxia-prototype.In9GVv` is
`BUILT_NOT_RUN`; both independently checked selected stack paths peak at
33,888/65,536 bytes with the unchanged 4,096-byte exception reserve. Patched
Linux QEMU timing remains required.

Run `40400153990` validates the preparation correction over a substantially
longer native interval: it passed exact build and stack gates and ran for
466.6 seconds without another C-credit failure. It then exposed an independent
CPU2 builtin-fixture overrun at sequence 149,797. A complete 10 ms credit used
12,740,208 ns of translated CPU. This was not the earlier undersized tail: the
credit was exactly 10 ms, thread identity was the fixed `2:1` worker, and the
run had already completed roughly 150 thousand dispatches. Both validation and
native artifact uploads again failed separately on the repository quota.

The fixed builtin is a deliberately non-yielding EL0 loop whose private timer
was its only return path. Although each entry armed a 250 us slice, patched
MTTCG can retire a longer translated chain before delivering the PPI; reserving
the full 10 ms turn therefore cannot make an asynchronous interrupt a static
execution bound. The unified fixture now selects a dedicated worker mode that
performs exactly 256 cookie-checked increments and voluntarily returns through
SVC 4. EL1 accepts only that exact SVC or the existing timer return, then
rechecks the unchanged cookie, TLS and SIMD state. The timer remains the hard
backstop, while a finite instruction batch ends the ordinary path without
increasing its 10 ms credit, 30 ms thread budget or 90 ms business ceiling. The
non-unified SMP fixture retains its timer-only loop, preserving the independent
requirement that every completed dispatch has timer-preemption evidence. A
source regression pins the mode separation, batch and exact return
classification. The full non-kernel workspace, 614 host tests (two environment
skips), 67 tool tests, 140 v1.3 host tests (one historical-evidence skip),
formatting and strict AArch64 Clippy pass. Exact local build
`/tmp/cyxia-prototype.lcqCJ7` is `BUILT_NOT_RUN`; both selected stack paths pass
at 33,904/65,536 bytes with the unchanged 4,096-byte exception reserve. A new
patched-QEMU replay is required.

Run `40404300372` validates the unified builtin mode far enough to start the
native control worker, then exposes the remaining cold private-clear mechanism:
CPU1 sequence 6 spent 9,722,780 ns against its unchanged 8 ms recovery credit,
in phase 1 with no active job and no timer preemption. The fixed one-page slice
still issued 64 `DC ZVA` instructions. Patched TCG handles each as a synchronous
helper, so the helpers rather than the 4 KiB range defeated the static bound.
The clear keeps one page per paid turn and the final `DSB ISH`, but now emits an
ordinary fixed-size zero store sequence. This preserves the exact bytes, turn
count and accounting while removing the per-cache-line helper. The full 614
host tests pass with two environment skips, including all 140 v1.3 tests with
one historical-evidence skip; formatting, the focused regressions and configured
AArch64 strict Clippy also pass. Exact local build
`/tmp/cyxia-prototype.lcqCJ7/build-clear` is `BUILT_NOT_RUN`, contains no
`DC ZVA`, and passes both selected stack paths at 33,888/65,536 bytes with the
unchanged 4,096-byte reserve. Linux replay remains required.

Run `40405800984` confirms the ordinary-store clear crosses all phase-1 work,
then fails later at CPU1 sequence 137 in normal preparation: phase 3 consumes
8,993,958 ns against 2.5 ms, reaches only coarse marker 0, and has no active
record or target context. The existing context was published only after target
resolution, leaving this precise lookup failure unattributed. The lookup now
publishes its family, domain, kind, source, ordinal and before/after per-vCPU
counter into the existing stopped-failure evidence bank; a successful lookup
is still overwritten by the established target context. This is diagnostic
only and does not change control work or authority. Linux replay is required.
The full 615 host tests pass with two environment skips, including 141 v1.3
tests with one historical-evidence skip; formatting, configured strict AArch64
Clippy and exact build `/tmp/cyxia-prototype.lcqCJ7/build-lookup` pass. Both
selected stack paths remain 33,888/65,536 bytes with the fixed reserve.

Run `40407063795` attributes the same pre-target failure precisely: family 0,
domain 1, kind 1, Tasks source, ordinal 0. Its before/after per-vCPU counters
show 291,108 ticks (approximately 4.66 ms) inside target lookup alone, while the
whole turn uses 6,117,578 ns. Tasks resolved current and exact lookahead with
two separate iterator walks over the scheduler's sparse `Group` policy array.
Groups are append-only, so Scheduler now retains a contiguous identity index
and count at registration. Exact group lookup and ordinal projection touch only
that compact index, preserving duplicate-ID rejection, capacity, generations,
policy records and all scheduling/accounting state. The existing sixteen-group
test now also pins first, last and out-of-range ordinal results. Native Linux
timing remains required. The full non-kernel workspace, 615 host tests (two
environment skips), 141 v1.3 host tests (one historical-evidence skip),
formatting and configured strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-compact-groups` is `BUILT_NOT_RUN`; both
selected stack paths pass at 33,904/65,536 bytes with the fixed reserve.

Run `40408468486` confirms compact target lookup succeeds and reaches detailed
marker 2 for domain-1 group `1:1`, then the combined prefix/current path uses
17,063,616 ns. During two-node replay, `Measurement::new` tried the remote
ledger for every ordinary policy owner before the ledger itself rejected an
unrelated identity. The immutable active ledger family, kind and target are now
release-published beside its existing family gate. Policy/action attempts first
apply the exact same relevance predicate without borrowing the live ledger;
only relevant identities enter its lock and open-credit bookkeeping.
Executor-work still resolves its mutable remote-token table under the ledger
gate. The now-resolved target diagnostic keeps family/source attribution but
drops its two per-turn counter reads. No capture, credit or authority is
created by the projection. Local validation and Linux timing remain required.
All seven peer-ledger tests, 141 v1.3 host tests (one historical-evidence skip),
formatting and configured strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-peer-filter` is `BUILT_NOT_RUN`; both selected
stack paths remain 33,904/65,536 bytes with the fixed reserve.

Run `40410681654` fails before preparation and therefore does not evaluate the
peer relevance correction: CPU1 sequence 2 spends 12,892,894 ns against the
unchanged 8 ms recovery credit in the first phase-1 private clear. Removing
`DC ZVA` eliminated helper amplification, but the complete-page `memset` still
compiled to 512 ordinary 64-bit stores in one translated loop. The existing
continuation now clears a fixed 512 bytes per paid turn instead of 4 KiB. All
nine pages, final `DSB ISH`, exact actual accounting and credits are unchanged;
the smaller ordinary loop also applies to the stricter 2.5 ms job-clear turns.
The full 615 host tests (two environment skips), 141 v1.3 tests (one
historical-evidence skip), formatting and configured strict AArch64 Clippy
pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-clear-512` passes both
selected stack paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40414762247` confirms the four fixed stores cross phase 1. The next
failure is CPU1 sequence 594 in phase 2 at 8,683,018/8,000,000 ns, exactly
after the 576 clear pieces and setup turns. The first protected capture entry
was both registering immutable task identity (one 128-byte event) and recording
the actual entry (another event) before the architectural transition. Task
registration now occurs in the paid context-creation turn. The following turn
retains the unconditional `a02_capture::enter`, `user::enter`, and
`a02_capture::returned` boundary; the capture rechecks the prepared identity
and fails closed on any mismatch. The full 615 host tests (two environment
skips), 141 v1.3 tests (one historical-evidence skip), formatting and configured
strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-capture-prepare` passes both selected stack
paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40416748290` reaches phase 2 at sequence 580 but the first exact capture
boundary still uses 8,683,689/8,000,000 ns. Registration is already separate;
entry and return were each scanning the same protected task prefix to recover
the index just validated by `prepare`. The protected state now returns that
index to a per-CPU atomic handoff. Exact entry and return each recheck
`tasks[index] == task` before updating the unchanged capture structure and
event format, failing closed on any stale or mismatched handoff. This removes
both repeated searches from the architectural boundary without weakening its
identity checks. The full 615 host tests (two environment skips), 141 v1.3
tests (one historical-evidence skip), formatting and configured strict AArch64
Clippy pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-capture-index`
passes both selected stack paths at 33,904/65,536 bytes. Linux timing remains
required.

Run `40415656116` crosses all native C-worker phase-1/phase-2 gates. The next
failure is the global task-credit bank: CPU0 service thread `257:1` uses
2,904,603/2,500,000 ns while diagnostic stage 1 installs learning storage, and
CPU3 builtin `3:1` uses 10,912,938/10,000,000 ns. Learning startup had combined
capture storage, history storage, peer replay and learning replay under one
service segment. It is now a four-stage state machine, one exact 2.5 ms service
credit per operation, retaining its stage on transient failure. The bounded
EL0 builtin batch is 128 rather than 256 iterations under the same 10 ms credit
and timer backstop. No budget or authority changes. The full 615 host tests
(two environment skips), 141 v1.3 tests (one historical-evidence skip),
formatting and configured strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-install-stages` passes both selected stack
paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40411712557` crosses the exact build and stack gates, then fails before
preparation on CPU1 sequence 3: a 512-byte phase-1 clear consumes 10,302,577 ns
against the unchanged 8 ms recovery credit. Its empty preparation context
confirms peer relevance is still not exercised. The fixed slice is therefore
64 bytes, bounding the translated memset at eight 64-bit stores. The total
nine-page clear, continuation, barrier, accounting and credits remain intact.
The full 615 host tests (two environment skips), formatting and configured
strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-clear-64` passes both selected stack paths
at 33,904/65,536 bytes. Linux timing remains required.

Run `40412622069` advances phase-1 clearing from sequence 3 to sequence 1101,
then one 64-byte turn consumes 9,061,316 ns against the unchanged 8 ms credit.
The continuation currently executes `DSB ISH` after every 64-byte range, even
though no consumer can use the private pages before the complete clear. The
same completion barrier is now retained as its own final continuation turn:
all zero stores finish first, then the barrier, then (on another paid turn)
EL0 entry. This preserves ordering while removing 575 redundant barriers per
nine-page clear and prevents store and barrier costs from sharing one envelope.
The full 615 host tests (two environment skips), formatting and configured
strict AArch64 Clippy pass. Exact build
`/tmp/cyxia-prototype.lcqCJ7/build-clear-barrier-turn` passes both selected
stack paths at 33,904/65,536 bytes. Linux timing remains required.

Run `40413776197` fails on CPU1 sequence 2 before the independent barrier: the
first 64-byte phase-1 turn consumes 8,635,911 ns against 8 ms. Although the
range is fixed, `write_bytes` receives its length at runtime and retains the
generic memset call/loop path. The 64-byte operation now emits four ordinary
AArch64 `STP` instructions directly (eight 64-bit zero stores), with no DC ZVA
helper and no generic loop. The separate final `DSB ISH`, exact nine-page
range, accounting and credits remain unchanged. The full 615 host tests (two
environment skips), 141 v1.3 tests (one
historical-evidence skip), formatting and configured strict AArch64 Clippy
pass. Exact build `/tmp/cyxia-prototype.lcqCJ7/build-clear-stp` passes both
selected stack paths at 33,904/65,536 bytes. Linux timing remains required.
