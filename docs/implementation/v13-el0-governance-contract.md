# Proposed EL0 learning-governance contract

**Status: bounded coordinator wire v1 and the independent EL0 image are
implemented. The unified kernel now builds, embeds, hashes and installs a
separate bounded governance address space, but it is not yet dispatched or
native-accepted.** This increment does not claim A16 completion or move the
remaining learning coordination choices out of EL1. The governing requirements
are v1.3 §2.1, §5 control budgets, §6.3, and A16.

## 2026-10-28 implementation checkpoint

`crates/prototype/src/learning/coordinator_wire.rs` and its `snapshot`,
`command`, `receipt`, and `codec` modules now implement the contract's fixed
512-byte observation, 256-byte command, and 256-byte receipt formats. Canonical
zero-filled encoding binds the actual registered role context, session and
model/core/ledger generations, snapshot digest, command sequence, protected
score/permit/registration handles, effect handle, and paid credit evidence.
Malformed encodings, stale generations, skipped or wrapped sequences, expired
snapshots, handle substitution, receipt tampering, and excess credit are covered
by negative tests in `crates/prototype/tests/learning_coordinator_wire.rs`.

The exact transport source passed Rust 1.95 formatting, configured AArch64
kernel Clippy with `-D warnings`, the complete non-kernel Rust workspace, 630
host tests (two environment skips), and 77 evidence-tool tests in public Actions
run `40625220174`.

The next integration slice builds `prototype-governance.elf` inside the exact
unified kernel build, retains the exact embedded bytes as a separately hashed
build artifact, validates an RX/RO-only AArch64 ELF plan, copies it into the real
8 MiB control pool, and installs distinct read-only observation, writable
command, private stack and sealed page-table mappings. The stopped-snapshot
`GOVERNANCE_V13_EVIDENCE` bank binds the image hash, role context, entry, root
and page counts and explicitly reports a mapped-not-scheduled state. This does
not grant command authority or create another 9 ms budget. Actual prepaid EL0
dispatch, trap-derived authority, shared-surplus accounting, command application
refactor, migration ownership handoff, and native A16 execution evidence remain
open.

## Observed deployment gap

`kernel/src/learning_session.rs::manage` currently makes coordination choices
in EL1: when to score Shadow, close a Shadow window, start Canary, schedule a
Canary score, and request promotion. `prepare_score` chooses another action
family after incomplete data. `maintenance` initiates rollback of an Active
session. `Phase::Consume` automatically proceeds from a Canary score to a
publication. These choices require an actual independently scheduled EL0
control role, not a renamed EL1 helper or a host command producer.

The protected operations called by those choices are not themselves deployment
violations. EL1 must retain role authorization, accounting, capability and
permission checks, generation checks, and atomic commit. In particular,
`domain_control/learning.rs::{promote,rollback}` prepares and commits model-bank,
Registry and CommitGate state under the publication critical section. That
final commit belongs in EL1.

The current native reply/publication path needs a separate, concrete review
before assigning any additional unique-publisher responsibility. This document
does **not** infer that an EL1 final commit is an EL1 policy decision, and does
not authorize a second competing publisher.

## Minimum change

An independent EL0 GovernanceCoordinator receives an immutable observation and
returns one bounded command. EL1 checks and executes that command, advances
only its deterministic execution/cleanup phases, and returns a receipt. It
does not choose the following command on the role's behalf.

| Choice made in EL0 | Checks/effects retained in EL1 |
| --- | --- |
| Choose Shadow/Canary scoring opportunity and action family | Validate actual role, current C ownership, registered candidate/data, immutable inputs and budget; run the separately mapped numerical worker |
| Request closing a Shadow window | Verify real score receipts, coverage, window continuity and elapsed time |
| Request baseline preparation and Canary start | Resolve the registered noncritical D15 object; verify baseline readiness; mint only the bounded permit |
| Request publication of a verified Canary score | Revalidate exact score capability, target/object generation, current model generation, one submission/window, quota, prior terminal receipt, freshness, legality and publication ownership |
| Request freeze, promotion or rollback | Recheck all evidence and generations; atomically update CommitGate, Registry and model bank; preserve old obligations/pins |
| Request session rejection/release | Revoke permitted future work and release only resources whose stopped/terminal state is proven |

`record_shadow` may still validate and register an actual receipt in EL1.
Canary scoring must stop at a protected verified-score handle until a command
requests publication; EL1 must not invent that request in `Phase::Consume`.

Mandatory safety actions remain independent of the coordinator's liveness:
timer/deadline enforcement, quota exhaustion, invalid evidence rejection,
permit revocation, receipt reconciliation, fixed baseline restoration, and
retention of UNKNOWN work. These actions do not select a new optimization.
If an Active model requires intervention while the coordinator is unavailable,
the mechanism may stop new unsafe publishing and preserve safe execution; a
voluntary model choice/rollback still needs its authorized coordination command.

## Bounded transport and state

Use a new `learning/coordinator_wire.rs`, separate from the numerical
`worker_wire` Training/Validation/Score protocol. Proposed wire bounds are a
512-byte snapshot, 256-byte command and 256-byte receipt. They are explicit
little-endian structures, with magic/version/length, fixed enum ranges and
zero reserved fields. No pointers or variable-length lists cross this boundary.

The snapshot contains facts: request ID; session key and revision;
boot/controller/core/ledger/model/data and role-context generations; monotonic
time/deadline; current protected stage; original/candidate/registration hashes;
verified Shadow coverage and closed windows; permit identity, target, start,
expiry and quota; the exact pending apply/version/status; baseline readiness;
last command status; and the available verified-score handle. Its digest binds
the entire canonical snapshot. It must not contain a kernel-selected “next
command” disguised as an observation.

The command echoes the request, session, revision, role-context identity,
snapshot digest and relevant generations. It carries exactly one of:

- `Wait`.
- `Score(Shadow|Canary, domain, kind)`.
- `CloseShadowWindow(window)`.
- `PrepareBaseline(target)` or `BeginCanary(target)`.
- `PublishCanary(verified_score_handle)`.
- `Freeze(permit)` or `Promote(candidate_registration)`.
- `Rollback(expected_active_generation)`.
- `Reject(reason)` or `Release(session)`.

Any extension remains contingent on a separately registered independent
validator's extension evidence; the coordinator cannot increase its own quota
or supply a trusted validation boolean. EL1 computes the permitted duration
and quota. A promotion request is also not a declaration of successful Canary.

The receipt echoes the command/session, result and resulting state revision,
the actual model binding and protected effect/receipt handle, and measured
credit identity/cost. Detailed apply/executor evidence remains in the protected
receipt store and raw acceptance trace, referenced by that handle.

EL0 needs only bounded private coordination state, such as a family cursor and
last acknowledged command. EL1 keeps existing candidate/model pins, Governance
safety state, immutable evidence, one pending-command slot, and fixed execution
phases. The existing 35-page Governance value is not copied or mapped writable
to EL0. A command may complete across several prepaid turns. Completion writes
a receipt and waits for another EL0 command.

Use `(boot, role_generation, session_generation, command_sequence)` for
idempotency. Same key and bytes return the same result without a second debit
or effect; different bytes conflict. Stale revisions, old model/core/role
generations, expired snapshots and counter wrap fail closed. Recheck at final
commit, so A→B→A cannot revive an old request. Settle the exact credit before
publishing a consumable completion; restart or timeout cannot erase an unpaid
debit or unknown worker loan.

## Actual role and publication authority

The coordinator must have its own registered context, stack/address space and
immutable image identity. A training worker cannot acquire that role by
changing a mode or opcode. Its commands are authenticated from the real trap's
registered context; echoed role fields alone do not authorize anything.

Learning-governance coordination shares the existing learning/validation/
Shadow/Canary surplus. It must not create a new 9 ms budget, reduce the
mandatory 61 ms reservation, or increase the 70 ms physical control ceiling.
Code, stack, pages and page-table ownership must fit the real 8 MiB control
pool, with their actual allocations and charged execution recorded.

The implementation must connect requests to the one authorized publication
identity and the existing atomic publication gate. Whether the new role sends
through an existing EL0 publication agent or assumes an explicitly transferred
publication role depends on review of the current native reply path. An EL1
authorization/atomic-commit implementation is expected in either case.

## Fixed-CPU ownership is a separate migration task

`domain_control/learning.rs::control`,
`prototype_runtime/learning.rs::require_extra_caller`, `step`, and recovery paths
currently require CPU1. Removing those guards alone would allow the wrong
context to borrow global authority or concurrently access the single worker
address space.

That task must change all of the following together:

1. Replace global `EXTRA_ACTIVE` as sufficient authority with an actual
   dispatch-derived per-CPU owner ticket carrying context/role generation, job,
   CPU, core generation and credit identity.
2. Retain one exclusive owner for each logical worker/context and its mailbox,
   page tables, input loans and recovery state. Scheduling on another C CPU
   must not create a second simultaneous owner.
3. Close new admission, observe actual return, settle the old physical CPU's
   credit, and retain pending debits/UNKNOWN loans before transferring the
   context. Complete required TLB, mapping and reference handoff before entry
   on a healthy, non-draining C CPU under its new owner ticket.
4. Preserve spending on the original physical CPU. Migration cannot reconstruct
   `ExtraBudget`, reset a window, or move previously incurred cost to a fresh
   ledger. Numerical and coordination roles may each have one logical instance
   while being scheduled on any currently authorized C member.

This migration includes singleton ROOTS/POOL ownership, role registration,
recovery scheduling and authoritative context checks. It must not be mixed
into the current debit/A02 measurement build without its own tests and source
freeze.

## Proposed implementation files

- New `crates/prototype/src/learning/coordinator_wire.rs` and independent decoder
  and command-state tests.
- New `user/prototype-governance/{main.rs,decision.rs,linker.ld}` for a small
  no_std command-producing role, and `kernel/build.rs`/build manifest support.
- New `kernel/src/prototype_runtime/governance.rs` for bounded mappings,
  registration, prepaid execution, actual EL0 entry/trap, and receipt custody.
- Refactor `kernel/src/learning_session.rs` into snapshot export, checked
  command application, deterministic command execution and safety maintenance.
- Adapt `kernel/src/domain_control/{learning,governance}.rs` to accept authority
  constructed from the actual registered caller; keep their trusted validators
  and atomic commits.
- Update `prototype_runtime/{native,learning}.rs`, control-pool allocation and
  shared surplus accounting for the new role. Perform the fixed-CPU ownership
  migration as the separate task above.
- Register the role in native scheduling evidence and add A16 command,
  generation, cost and commit receipts. Existing SGD/MLP/MSE arithmetic remains
  outside this refactor.

## Evidence required before claiming the gap closed

An A16 native run must link the actual EL0 coordinator context/image and command
to its trap, authorization, budget settlement, permit/effect and atomic model
commit. It must retain candidate/hash and all relevant generations. Existing
host Governance tests or a producer-written success field cannot establish
deployment.

Required negative cases include a numerical worker impersonating the role;
snapshot write protection; stale role/core/model generations; duplicate or
conflicting commands; zero-APPLIED/UNKNOWN Canary promotion; expired/excessive
Canary requests; A→B→A stale proposals; and a hung/restarted coordinator with
timely permit revocation and baseline recovery while retaining obligations.
Migration tests must additionally prove no concurrent context ownership and no
loss or resetting of old-CPU credit.
