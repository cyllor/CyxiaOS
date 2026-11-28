//! V0.19.9 EL1 AuthContext identity + admission-ledger contract layer.
//!
//! Baseline derivations (v0.19.9-implementation-spec.txt):
//! * §8.5 (~line 3285): EL1 verifies the real sender and the x3 selector
//!   against holder/object/generation and THEN generates a protected
//!   AuthContext; endpoint receipts must bind `service_generation`.
//! * §9.6.1 (~line 4096): the FileServiceRequest v4 user frame carries
//!   `auth_context_id:u64=0` — the real id is encapsulated internally by
//!   EL1, never self-reported by the service.
//! * §9.6.1 ADMIT v3 (~lines 4276-4345): internal 0x50, FILE_AUTH op1,
//!   role12 only. EL1 reads the original request digest, real holder,
//!   endpoint, parent/file cap and generations from the protected original
//!   AuthContext. Step ② atomically registers `admission_id`, the frozen
//!   binding digest and an in-flight reference under the exact
//!   (AuthContext, request_seq) key. Same key + same proposal digest returns
//!   the original ADMIT; a different digest is E_CONFLICT; STALE/RETRY/
//!   REVOKED register no in-flight reference.
//! * §9.6.1 three-step linearization: ① trusted role12 freezes target/ACL
//!   generations, object-local monotonic non-wrapping `prepared_version`,
//!   data/snapshot digest and resource descriptors locally, releases the
//!   local lock, NO user-visible side effects; ② EL1 authoritative register;
//!   ③ the service re-verifies its local `prepared_version` against the
//!   frozen object and executes per the original admission — mismatch with
//!   provable zero effect completes NO_EFFECT, otherwise UNKNOWN keeps the
//!   gate/reference. A frozen local version is NOT an admission and no
//!   irreversible user effect may be written before ADMITTED.
//! * §9.6.1 COMPLETE state machine: ADMITTED→UNKNOWN (evidence updatable)
//!   →DONE/PARTIAL/NO_EFFECT, or ADMITTED directly terminal; any terminal is
//!   irreversible, identical (state, evidence) repeats are idempotent,
//!   anything else E_CONFLICT; UNKNOWN never releases gate/reference/credit.
//! * BootEpoch (~line 358): persistent u64 boot generation, confirmed after
//!   file recovery, fixed within the boot; service restarts do NOT change
//!   it — each role uses its own runtime generation.
//! * Principal identity (~lines 4229, 6547): persistent `principal_id` +
//!   identity version registered in the offline/volume manifest; 16 fixed
//!   principal records / 16 group slots permanently bound to unique
//!   principals. The persistent identity version changes only by offline
//!   rebuild and is DISTINCT from the runtime generation modeled here.
//!
//! Contract-only scope: this module models the EL1-internal AuthContext and
//! the admission ledger as bounded, pure in-memory state rules for host
//! tests. It deliberately does NOT wire into `kernel/`, does NOT invent any
//! wire bytes for the AuthContext (the baseline fixes no public schema for
//! it — it is protected and unforgeable), and does NOT perform the native
//! authoritative cross-checks. The following details are UNSPECIFIED by the
//! baseline and are documented contract choices, not invented wire facts:
//! 1. AuthContext internal layout: no encode/decode exists; the struct is
//!    EL1-internal memory only.
//! 2. `auth_context_id` allocation policy: unspecified; modeled as strictly
//!    monotonic non-zero per boot. Uniqueness scope is per boot because
//!    `boot_epoch` is bound into `operation_digest` and the ledger.
//! 3. `generation` source: the baseline binds `service_generation` to
//!    receipts and `holder_gen`/`service_gen` to volatile keys but does not
//!    fix the exact AuthContext generation source. Modeled as an opaque
//!    EL1-verified runtime generation, monotonic per principal, never
//!    wrapping; NOT the offline principal identity version.
//! 4. Zero reservations: the baseline rejects zero key components in the
//!    idempotency gate; `principal_id == 0` / `generation == 0` are not
//!    explicitly reserved, so this contract rejects them as unidentifiable.
//! 5. Non-ADMITTED stickiness: replay is defined only for ADMIT and
//!    STALE/RETRY/REVOKED register no in-flight; the baseline does not make
//!    DENY sticky, so no non-ADMITTED verdict is cached.
//! 6. Ledger capacity: the baseline fixes 8 tickets/result slots per group
//!    and ≤8 staging slots but not the admission-ledger size; 16 is a
//!    contract bound, native sizing is a later gate. No record is ever
//!    evicted (in-flight/UNKNOWN obligations must not drop; terminal records
//!    stay for idempotency/irreversibility). Retirement/compaction policy is
//!    unspecified here (the receipt store has its own watermarks).
//! 7. Gate-closed errno: unspecified; `Error::Busy` at this layer. The gate
//!    is modeled ledger-wide; per-object gating for affected
//!    CREATE/MKDIR/UNLINK targets is a native detail.
//! 8. `accepted_local_ns` is an EL1 clock fact supplied by the caller; this
//!    layer does not model time.
//! 9. Authority checks (authoritative cap/ACL versions, ancestor revocation,
//!    object health, resource/completion credits, binding recomputation) are
//!    the native EL1 gate. [`AuthorityFacts`] carries their EL1-supplied
//!    outcome; nothing here derives authorization from a frame body.
//! 10. Durable ordering (receipt terminal state persisted before EL1
//!     publishes generations / releases the reference) and the volatile vs
//!     durable split are native; only the state rules are modeled via
//!     [`Completion`].
//!
//! Nothing in this module authorizes a file operation by itself.

use super::Error;
use super::file_auth_v3::{
    AdmitDecision, AdmitRequestV3, CompleteOutcome, CompleteRequestV1, Completion,
    RegisteredAdmission, StepThree, Verdict, admit_idempotency, admit_role_gate,
    complete_role_gate, complete_transition, frozen_data_digest, next_prepared_version,
    operation_digest, reverify_execution,
};

/// Baseline: 16 fixed principal records / 16 group slots permanently bound
/// to unique principals (§9.6.1 ACL, OfflineConfigEnvelope payload).
pub const MAX_AUTH_PRINCIPALS: usize = 16;

/// Contract bound for the admission ledger; native sizing is a later gate
/// (see module doc note 6). Records retire only on a verified terminal ACK.
pub const ADMISSION_LEDGER_CAPACITY: usize = 16;

/// EL1-internal protected AuthContext identity (§8.5, §9.6.1). No wire
/// schema exists for this struct; it is never decoded from a service frame.
/// `role` and `generation` are EL1-verified facts, not body self-report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthContextV1 {
    /// Non-zero; encapsulated internally by EL1 (the user frame carries 0).
    pub auth_context_id: u64,
    /// Persistent manifest principal_id; non-zero (module doc note 4).
    pub principal: u64,
    /// EL1-verified caller role. FILE_AUTH ADMIT requires role12.
    pub role: u64,
    /// EL1-verified runtime generation, monotonic per principal, non-zero.
    pub generation: u64,
    /// Confirmed current boot epoch; non-zero (fixed within the boot).
    pub boot_epoch: u64,
}

impl AuthContextV1 {
    /// Validity rules: every identity component must be non-zero. A zero
    /// `auth_context_id` means "not encapsulated"; a zero `boot_epoch` means
    /// "not confirmed"; zero principal/generation cannot identify a holder.
    pub const fn new(
        auth_context_id: u64,
        principal: u64,
        role: u64,
        generation: u64,
        boot_epoch: u64,
    ) -> Result<Self, Error> {
        if auth_context_id == 0 || principal == 0 || generation == 0 || boot_epoch == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            auth_context_id,
            principal,
            role,
            generation,
            boot_epoch,
        })
    }

    pub const fn validate(&self) -> Result<(), Error> {
        if self.auth_context_id == 0
            || self.principal == 0
            || self.generation == 0
            || self.boot_epoch == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// FILE_AUTH ADMIT is role12-only; the role is an EL1-verified fact.
    pub const fn file_auth_gate(&self) -> Result<(), Error> {
        admit_role_gate(self.role)
    }

    /// Receipt / volatile-key binding check (§8.5 receipts bind
    /// service_generation; §9.6.1 volatile key binds boot_epoch + holder +
    /// generations). A reply must bind the context it was issued under.
    pub const fn binds(&self, boot_epoch: u64, principal: u64, generation: u64) -> bool {
        self.boot_epoch == boot_epoch
            && self.principal == principal
            && self.generation == generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PrincipalGeneration {
    principal: u64,
    generation: u64,
}

/// Bounded per-principal runtime-generation tracker that issues protected
/// AuthContexts. Generations advance strictly monotonically per principal
/// and never wrap (overflow permanently stops that principal, matching the
/// baseline overflow-stop pattern). `boot_epoch` is fixed for the boot.
pub struct AuthContextIssuerV1 {
    boot_epoch: u64,
    slots: [Option<PrincipalGeneration>; MAX_AUTH_PRINCIPALS],
    next_context_id: u64,
}

impl AuthContextIssuerV1 {
    /// Fresh issuer for a confirmed boot epoch.
    pub const fn new(boot_epoch: u64) -> Result<Self, Error> {
        if boot_epoch == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot_epoch,
            slots: [None; MAX_AUTH_PRINCIPALS],
            next_context_id: 0,
        })
    }

    /// Rebuild the generation floor from EL1's authoritative durable record
    /// at boot (recovery verifies existing state, it does not reset it).
    /// Each entry is (principal_id, last_generation); both non-zero, unique,
    /// at most [`MAX_AUTH_PRINCIPALS`]. The context-id stream restarts per
    /// boot (ids are boot-local; `boot_epoch` binds them into the digest).
    pub fn recover(boot_epoch: u64, principals: &[(u64, u64)]) -> Result<Self, Error> {
        let mut issuer = Self::new(boot_epoch)?;
        if principals.len() > MAX_AUTH_PRINCIPALS {
            return Err(Error::Capacity);
        }
        for (i, &(principal, generation)) in principals.iter().enumerate() {
            if principal == 0 || generation == 0 {
                return Err(Error::Invalid);
            }
            if principals[..i].iter().any(|&(p, _)| p == principal) {
                return Err(Error::Conflict);
            }
            issuer.slots[i] = Some(PrincipalGeneration {
                principal,
                generation,
            });
        }
        Ok(issuer)
    }

    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    /// Current runtime generation for a principal, if registered.
    pub fn current_generation(&self, principal: u64) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .find(|p| p.principal == principal)
            .map(|p| p.generation)
    }

    /// Issue a protected AuthContext. The first issuance for a principal
    /// gets generation 1; every re-issuance advances it strictly. `role` is
    /// stored as the EL1-verified fact (FILE_AUTH qualification is checked
    /// at admission, not here). Capacity is bounded; generation/id overflow
    /// permanently stops (Exhausted), never wraps.
    pub fn issue(&mut self, principal: u64, role: u64) -> Result<AuthContextV1, Error> {
        if principal == 0 {
            return Err(Error::Invalid);
        }
        let idx = match self
            .slots
            .iter()
            .position(|s| matches!(s, Some(p) if p.principal == principal))
        {
            Some(i) => i,
            None => self
                .slots
                .iter()
                .position(|s| s.is_none())
                .ok_or(Error::Capacity)?,
        };
        let current = self.slots[idx].map(|p| p.generation).unwrap_or(0);
        let generation = current.checked_add(1).ok_or(Error::Exhausted)?;
        let auth_context_id = self
            .next_context_id
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.next_context_id = auth_context_id;
        self.slots[idx] = Some(PrincipalGeneration {
            principal,
            generation,
        });
        Ok(AuthContextV1 {
            auth_context_id,
            principal,
            role,
            generation,
            boot_epoch: self.boot_epoch,
        })
    }
}

/// Exact admission-ledger key (§9.6.1 step ②). Both components non-zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerKey {
    pub auth_context_id: u64,
    pub request_seq: u64,
}

/// One registered step-② admission. The in-flight reference is the retained
/// (admission_id, frozen proposal digest) obligation while `completion` is
/// non-terminal; only a verified terminal publication releases it. The
/// verdict invariant is `Admitted`: non-ADMITTED outcomes register nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub key: LedgerKey,
    /// Frozen binding digest (`operation_digest`) recorded atomically.
    pub proposal_digest: [u8; 32],
    pub admission_id: u64,
    pub verdict: Verdict,
    pub accepted_local_ns: u64,
    /// In-flight / UNKNOWN / terminal completion state of the reference.
    pub completion: Completion,
}

impl LedgerEntry {
    /// In-flight reference held iff not terminally published. UNKNOWN and
    /// in-flight both retain the gate/reference/credit.
    pub const fn inflight_held(&self) -> bool {
        !self.completion.is_terminal()
    }

    /// Projection into the v3 idempotency record (exact-key lookup).
    pub const fn registered(&self) -> RegisteredAdmission {
        RegisteredAdmission {
            auth_context_id: self.key.auth_context_id,
            request_seq: self.key.request_seq,
            operation_digest: self.proposal_digest,
            admission_id: self.admission_id,
            accepted_local_ns: self.accepted_local_ns,
        }
    }
}

/// EL1-supplied authoritative facts for step ②. The contract never derives
/// these from the frame body; native EL1 computes them from the protected
/// original AuthContext, authoritative cap/ACL versions, ancestor revocation,
/// object health and resource/completion credits (module doc note 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityFacts {
    /// Authoritative current runtime generation for `ctx.principal`.
    pub current_generation: u64,
    /// Outcome of the native authority checks.
    pub verdict: Verdict,
    /// Meaningful on non-ADMITTED replies (deny_generation).
    pub deny_generation: u64,
    /// EL1 clock fact for an ADMITTED registration.
    pub accepted_local_ns: u64,
}

/// Result of a step-② registration attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// Fresh ADMITTED: admission_id, frozen digest and in-flight reference
    /// atomically registered.
    Admitted {
        admission_id: u64,
        accepted_local_ns: u64,
    },
    /// Same key + same proposal digest: the original ADMIT is returned; no
    /// new registration and no new in-flight reference.
    Replay {
        admission_id: u64,
        accepted_local_ns: u64,
    },
    /// Non-ADMITTED verdict: nothing registered, no in-flight reference.
    NotAdmitted {
        verdict: Verdict,
        deny_generation: u64,
    },
}

/// Bounded admission ledger keyed by (auth_context_id, request_seq), bound
/// to one confirmed boot epoch, with a single admission gate. Enforces the
/// §9.6.1 idempotency/conflict matrix, in-flight lifecycle, terminal
/// irreversibility and UNKNOWN retention. No record is implicitly evicted.
pub struct AdmissionLedgerV1 {
    boot_epoch: u64,
    entries: [Option<LedgerEntry>; ADMISSION_LEDGER_CAPACITY],
    next_admission_id: u64,
    gate_open: bool,
}

impl AdmissionLedgerV1 {
    pub const fn new(boot_epoch: u64) -> Result<Self, Error> {
        if boot_epoch == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot_epoch,
            entries: [None; ADMISSION_LEDGER_CAPACITY],
            next_admission_id: 0,
            gate_open: true,
        })
    }

    pub const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub const fn gate_open(&self) -> bool {
        self.gate_open
    }

    /// EL1 closes the same admission gate against NEW authorizations for
    /// affected CREATE/MKDIR/UNLINK objects when an authoritative version
    /// changes; admitted obligations still complete per their frozen digest.
    pub const fn close_gate(&mut self) {
        self.gate_open = false;
    }

    /// Reopen only after admitted obligations are handled / frozen versions
    /// retained and the authoritative version updated (§9.6.1).
    pub const fn open_gate(&mut self) {
        self.gate_open = true;
    }

    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of retained in-flight references (in-flight + UNKNOWN).
    pub fn inflight_count(&self) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|e| e.inflight_held())
            .count()
    }

    pub fn entry(&self, key: LedgerKey) -> Option<&LedgerEntry> {
        self.entries.iter().flatten().find(|e| e.key == key)
    }

    pub fn entry_by_admission(&self, admission_id: u64) -> Option<&LedgerEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.admission_id == admission_id)
    }

    /// The native volatile owner has separately checked the original holder,
    /// exact result digest and contiguous retirement order. Only that owner
    /// can retire a verified terminal admission and release its ledger slot.
    pub fn retire_terminal(
        &mut self,
        admission_id: u64,
        key: LedgerKey,
        evidence_digest: [u8; 32],
    ) -> Result<(), Error> {
        let slot = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_some_and(|entry| entry.admission_id == admission_id))
            .ok_or(Error::Stale)?;
        let entry = slot.ok_or(Error::Stale)?;
        if entry.key != key {
            return Err(Error::Conflict);
        }
        match entry.completion {
            Completion::Terminal {
                evidence_digest: digest,
                ..
            } if digest == evidence_digest => {
                *slot = None;
                Ok(())
            }
            Completion::Terminal { .. } => Err(Error::Conflict),
            _ => Err(Error::Busy),
        }
    }

    fn entry_by_admission_mut(&mut self, admission_id: u64) -> Option<&mut LedgerEntry> {
        self.entries
            .iter_mut()
            .flatten()
            .find(|e| e.admission_id == admission_id)
    }

    /// Step ② authoritative register. Pure state rules over EL1-supplied
    /// facts; the native authority cross-checks themselves are a later gate.
    ///
    /// Order: identity validity → role12 gate → boot-epoch binding →
    /// generation freshness → exact-key idempotency/conflict → gate →
    /// verdict → atomic registration. A generation mismatch maps to STALE
    /// ("失配 STALE"); a cross-boot context is STALE; a non-role12 caller is
    /// Unauthorized; a closed gate rejects only NEW authorizations (Busy).
    pub fn register(
        &mut self,
        ctx: &AuthContextV1,
        request: &AdmitRequestV3,
        facts: &AuthorityFacts,
    ) -> Result<RegisterOutcome, Error> {
        ctx.validate()?;
        // The carried id must be the encapsulated context id, never a
        // self-reported different identity.
        if request.auth_context_id != ctx.auth_context_id {
            return Err(Error::Invalid);
        }
        ctx.file_auth_gate()?;
        if ctx.boot_epoch != self.boot_epoch {
            return Err(Error::Stale);
        }
        if ctx.generation != facts.current_generation {
            return Err(Error::Stale);
        }
        let key = LedgerKey {
            auth_context_id: request.auth_context_id,
            request_seq: request.request_seq,
        };
        let prior = self.entry(key).map(|e| e.registered());
        match admit_idempotency(request, prior.as_ref())? {
            AdmitDecision::Replay {
                admission_id,
                accepted_local_ns,
            } => {
                // Returning an existing ADMIT is not a new authorization:
                // it works even while the gate is closed and even after the
                // admission reached a terminal state (idempotent query).
                return Ok(RegisterOutcome::Replay {
                    admission_id,
                    accepted_local_ns,
                });
            }
            AdmitDecision::Fresh => {}
        }
        if !self.gate_open {
            return Err(Error::Busy);
        }
        if facts.verdict != Verdict::Admitted {
            // STALE/RETRY/REVOKED/DENY register no in-flight reference and
            // no ledger record (module doc note 5).
            return Ok(RegisterOutcome::NotAdmitted {
                verdict: facts.verdict,
                deny_generation: facts.deny_generation,
            });
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .ok_or(Error::Capacity)?;
        let admission_id = self
            .next_admission_id
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        self.next_admission_id = admission_id;
        *slot = Some(LedgerEntry {
            key,
            proposal_digest: request.operation_digest,
            admission_id,
            verdict: Verdict::Admitted,
            accepted_local_ns: facts.accepted_local_ns,
            completion: Completion::InFlight,
        });
        Ok(RegisterOutcome::Admitted {
            admission_id,
            accepted_local_ns: facts.accepted_local_ns,
        })
    }

    /// COMPLETE v1 state rules over a real registered admission. The caller
    /// must already have passed [`complete_role_gate`] natively (role12 or a
    /// verified protected recovery successor); a successor may only
    /// reconcile old obligations, never issue new work. Terminal publication
    /// releases the in-flight reference; UNKNOWN retains it. The native
    /// durable ordering (receipt persisted first) is a later gate.
    pub fn complete(
        &mut self,
        caller_role: u64,
        protected_recovery_successor: bool,
        report: &CompleteRequestV1,
    ) -> Result<CompleteOutcome, Error> {
        complete_role_gate(caller_role, protected_recovery_successor)?;
        if report.admission_id == 0 {
            return Err(Error::Invalid);
        }
        let entry = self
            .entry_by_admission_mut(report.admission_id)
            .ok_or(Error::Invalid)?;
        let outcome = complete_transition(entry.completion, report)?;
        match outcome {
            CompleteOutcome::UnknownRetained { evidence_digest } => {
                entry.completion = Completion::Unknown { evidence_digest };
            }
            CompleteOutcome::Terminal {
                state,
                evidence_digest,
            } => {
                entry.completion = Completion::Terminal {
                    state,
                    evidence_digest,
                };
            }
            CompleteOutcome::Idempotent => {}
        }
        Ok(outcome)
    }

    /// Step ③ re-verification bound to a real, non-terminal admission. A
    /// terminal admission can never be re-executed (recovery only reconciles
    /// old obligations; no new work through an old admission). The service
    /// supplies its local and originally frozen `prepared_version`; the
    /// match/mismatch rules are [`reverify_execution`].
    pub fn reverify(
        &self,
        admission_id: u64,
        local_prepared_version: u64,
        frozen_prepared_version: u64,
        provable_no_effect: bool,
    ) -> Result<StepThree, Error> {
        let entry = self
            .entry_by_admission(admission_id)
            .ok_or(Error::Invalid)?;
        if entry.completion.is_terminal() {
            return Err(Error::Conflict);
        }
        Ok(reverify_execution(
            local_prepared_version,
            frozen_prepared_version,
            provable_no_effect,
        ))
    }
}

/// Step ① local freeze (pure). Advances the object-local `prepared_version`
/// to its strict non-wrapping successor, freezes the actual data/snapshot
/// digest and recomputes the binding `operation_digest`. Produces NO
/// user-visible side effect and is NOT an admission. The caller supplies the
/// identity/target/rights/seq/acl_generation fields; this function owns the
/// version advance and the two digests. Overflow permanently stops the
/// object (Exhausted), never wraps.
pub fn freeze_local(
    mut proposal: AdmitRequestV3,
    current_prepared_version: u64,
    boot_epoch: u64,
    original_user_frame: &[u8],
    data: &[u8],
) -> Result<AdmitRequestV3, Error> {
    if proposal.auth_context_id == 0 || proposal.request_seq == 0 || boot_epoch == 0 {
        return Err(Error::Invalid);
    }
    let next = next_prepared_version(current_prepared_version).ok_or(Error::Exhausted)?;
    proposal.prepared_version = next;
    proposal.frozen_data_digest = frozen_data_digest(data);
    proposal.operation_digest = operation_digest(boot_epoch, original_user_frame, &proposal)?;
    Ok(proposal)
}

/// Pure three-step linearization state (§9.6.1). `FrozenLocal` is NOT
/// admitted; irreversible user effects are permitted only once EL1 has
/// registered an ADMITTED admission (`Admitted`/`Execute`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linearization {
    /// ① frozen locally; no admission, no user-visible side effects.
    FrozenLocal,
    /// ② returned a non-ADMITTED verdict; nothing registered; request ends.
    NotAdmitted { verdict: Verdict },
    /// ② EL1 atomically registered the admission; effects now permitted.
    Admitted,
    /// ③ local version matches the frozen admission: execute per admission.
    Execute,
    /// ③ mismatch with provable zero request effect: COMPLETE NO_EFFECT.
    CompleteNoEffect,
    /// ③ mismatch without proof: UNKNOWN keeps the gate/reference.
    KeepUnknown,
}

impl Linearization {
    /// State after a successful step-① freeze.
    pub const fn frozen_local() -> Self {
        Self::FrozenLocal
    }

    /// Step ② transition driven by the EL1 authoritative verdict.
    pub const fn register(self, verdict: Verdict) -> Result<Self, Error> {
        match self {
            Self::FrozenLocal => Ok(match verdict {
                Verdict::Admitted => Self::Admitted,
                v => Self::NotAdmitted { verdict: v },
            }),
            _ => Err(Error::Conflict),
        }
    }

    /// Step ③ transition driven by the local re-verification.
    pub const fn reverify(
        self,
        local_prepared_version: u64,
        frozen_prepared_version: u64,
        provable_no_effect: bool,
    ) -> Result<Self, Error> {
        match self {
            Self::Admitted => Ok(
                match reverify_execution(
                    local_prepared_version,
                    frozen_prepared_version,
                    provable_no_effect,
                ) {
                    StepThree::Execute => Self::Execute,
                    StepThree::CompleteNoEffect => Self::CompleteNoEffect,
                    StepThree::KeepUnknown => Self::KeepUnknown,
                },
            ),
            _ => Err(Error::Conflict),
        }
    }

    /// Whether an admission has been registered (steps ②/③ states).
    pub const fn is_admitted(self) -> bool {
        matches!(
            self,
            Self::Admitted | Self::Execute | Self::CompleteNoEffect | Self::KeepUnknown
        )
    }

    /// No irreversible user effect before ADMITTED. Only `Admitted` and
    /// `Execute` may write irreversible effects; `CompleteNoEffect` is
    /// provably zero-effect and `KeepUnknown` is unproven.
    pub const fn irreversible_effects_allowed(self) -> bool {
        matches!(self, Self::Admitted | Self::Execute)
    }

    /// Guard to call before any irreversible user effect.
    pub const fn effect_gate(self) -> Result<(), Error> {
        if self.irreversible_effects_allowed() {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::file_auth_v3::{FILE_SERVICE_ROLE, TerminalState};
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const BOOT: u64 = 7;

    fn user_frame() -> Vec<u8> {
        let header = super::super::file_service_v4::REQUEST_HEADER;
        let mut b = vec![0u8; header + 4];
        b[0..4].copy_from_slice(&super::super::file_service_v4::REQUEST_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&super::super::file_service_v4::REQUEST_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(header as u16).to_le_bytes());
        b[8..10].copy_from_slice(&6u16.to_le_bytes());
        b[12..16].copy_from_slice(&4u32.to_le_bytes());
        b[16..24].copy_from_slice(&4u64.to_le_bytes());
        b
    }

    fn proposal(ctx: u64, seq: u64) -> AdmitRequestV3 {
        AdmitRequestV3 {
            auth_context_id: ctx,
            target_id: 42,
            target_generation: 7,
            required_rights: 0b1011,
            request_seq: seq,
            prepared_version: 3,
            acl_generation: 5,
            frozen_data_digest: [0xa5; 32],
            operation_digest: [0x5a; 32],
        }
    }

    fn frozen(ctx: u64, seq: u64) -> AdmitRequestV3 {
        freeze_local(proposal(ctx, seq), 2, BOOT, &user_frame(), b"data").unwrap()
    }

    fn facts(generation: u64, verdict: Verdict) -> AuthorityFacts {
        AuthorityFacts {
            current_generation: generation,
            verdict,
            deny_generation: 12,
            accepted_local_ns: 1_000,
        }
    }

    fn issuer() -> AuthContextIssuerV1 {
        AuthContextIssuerV1::new(BOOT).unwrap()
    }

    fn ledger() -> AdmissionLedgerV1 {
        AdmissionLedgerV1::new(BOOT).unwrap()
    }

    fn report(id: u64, state: TerminalState, evidence: [u8; 32]) -> CompleteRequestV1 {
        CompleteRequestV1 {
            admission_id: id,
            terminal_state: state,
            evidence_digest: evidence,
        }
    }

    #[test]
    fn auth_context_identity_validity_role_gate_and_binding() {
        // Every zero identity component is rejected.
        assert!(AuthContextV1::new(0, 1, 12, 1, BOOT).is_err());
        assert!(AuthContextV1::new(1, 0, 12, 1, BOOT).is_err());
        assert!(AuthContextV1::new(1, 1, 12, 0, BOOT).is_err());
        assert!(AuthContextV1::new(1, 1, 12, 1, 0).is_err());
        let ctx = AuthContextV1::new(1, 9, FILE_SERVICE_ROLE, 3, BOOT).unwrap();
        assert_eq!(ctx.validate(), Ok(()));
        assert_eq!(ctx.file_auth_gate(), Ok(()));
        // role12-only FILE_AUTH gate; other verified roles are Unauthorized.
        for role in [0u64, 1, 9, 11, 13, 15] {
            let c = AuthContextV1::new(1, 9, role, 3, BOOT).unwrap();
            assert_eq!(c.file_auth_gate(), Err(Error::Unauthorized));
        }
        // Receipt binding must match boot/principal/generation exactly.
        assert!(ctx.binds(BOOT, 9, 3));
        assert!(!ctx.binds(BOOT + 1, 9, 3));
        assert!(!ctx.binds(BOOT, 8, 3));
        assert!(!ctx.binds(BOOT, 9, 4));
    }

    #[test]
    fn issuer_generation_monotonic_bounded_and_overflow_stops() {
        let mut iss = issuer();
        let a1 = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let a2 = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let b1 = iss.issue(10, FILE_SERVICE_ROLE).unwrap();
        assert_eq!(a1.generation, 1);
        assert_eq!(a2.generation, 2);
        assert_eq!(b1.generation, 1); // independent per principal
        assert!(a2.auth_context_id > a1.auth_context_id);
        assert_eq!(iss.current_generation(9), Some(2));
        assert_eq!(iss.current_generation(10), Some(1));
        assert_eq!(iss.current_generation(11), None);
        assert_eq!(iss.boot_epoch(), BOOT);
        // Zero principal rejected; zero boot epoch rejected.
        assert!(iss.issue(0, FILE_SERVICE_ROLE).is_err());
        assert!(AuthContextIssuerV1::new(0).is_err());
        // Bounded 16 principals; the 17th is Capacity, never evicts.
        let mut full = issuer();
        for p in 1u64..=16 {
            full.issue(p, FILE_SERVICE_ROLE).unwrap();
        }
        assert_eq!(full.issue(17, FILE_SERVICE_ROLE), Err(Error::Capacity));
        // Existing principal still advances when full.
        assert_eq!(full.issue(1, FILE_SERVICE_ROLE).unwrap().generation, 2);
        // Recovery restores the generation floor; overflow permanently stops.
        let mut rec = AuthContextIssuerV1::recover(BOOT, &[(9, u64::MAX)]).unwrap();
        assert_eq!(rec.issue(9, FILE_SERVICE_ROLE), Err(Error::Exhausted));
        assert_eq!(rec.current_generation(9), Some(u64::MAX));
        // Recovery validation: non-zero, unique, bounded.
        assert!(AuthContextIssuerV1::recover(BOOT, &[(0, 1)]).is_err());
        assert!(AuthContextIssuerV1::recover(BOOT, &[(9, 0)]).is_err());
        assert!(AuthContextIssuerV1::recover(BOOT, &[(9, 1), (9, 2)]).is_err());
        let many: Vec<(u64, u64)> = (1u64..=17).map(|p| (p, 1)).collect();
        assert!(AuthContextIssuerV1::recover(BOOT, &many).is_err());
    }

    #[test]
    fn ledger_idempotency_and_conflict_matrix() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let out = led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap();
        let id = match out {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!("expected fresh admit"),
        };
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 1);
        // Same key + same digest: original ADMIT, no new record/in-flight.
        let replay = led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap();
        assert_eq!(
            replay,
            RegisterOutcome::Replay {
                admission_id: id,
                accepted_local_ns: 1_000
            }
        );
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 1);
        // Same key, different digest: E_CONFLICT.
        let mut changed = req;
        changed.operation_digest[0] ^= 1;
        assert_eq!(
            led.register(&ctx, &changed, &facts(1, Verdict::Admitted)),
            Err(Error::Conflict)
        );
        // A genuinely changed proposal recomputes to a different digest.
        let mut changed = proposal(ctx.auth_context_id, 9);
        changed.prepared_version = 4;
        changed.operation_digest = operation_digest(BOOT, &user_frame(), &changed).unwrap();
        assert_ne!(changed.operation_digest, req.operation_digest);
        assert_eq!(
            led.register(&ctx, &changed, &facts(1, Verdict::Admitted)),
            Err(Error::Conflict)
        );
        // Different request_seq is a different key: fresh, not conflict.
        let next = frozen(ctx.auth_context_id, 10);
        assert!(matches!(
            led.register(&ctx, &next, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
        assert_eq!(led.len(), 2);
        // Different AuthContext is a different key.
        let ctx2 = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let other = frozen(ctx2.auth_context_id, 9);
        assert!(matches!(
            led.register(&ctx2, &other, &facts(2, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
        // Zero key components cannot identify a request.
        let mut zero = req;
        zero.request_seq = 0;
        assert_eq!(
            led.register(&ctx, &zero, &facts(1, Verdict::Admitted)),
            Err(Error::Invalid)
        );
        // Carried id must equal the encapsulated context id.
        let mut mismatch = req;
        mismatch.auth_context_id = ctx.auth_context_id + 999;
        assert_eq!(
            led.register(&ctx, &mismatch, &facts(1, Verdict::Admitted)),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn non_admitted_verdicts_register_no_inflight_and_are_not_sticky() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        for verdict in [
            Verdict::Deny,
            Verdict::Revoked,
            Verdict::Stale,
            Verdict::Retry,
        ] {
            let out = led.register(&ctx, &req, &facts(1, verdict)).unwrap();
            assert_eq!(
                out,
                RegisterOutcome::NotAdmitted {
                    verdict,
                    deny_generation: 12
                }
            );
            assert!(!verdict.registers_inflight());
        }
        assert_eq!(led.len(), 0);
        assert_eq!(led.inflight_count(), 0);
        // No sticky denial: a later authoritative ADMIT under the same key
        // registers normally (baseline defines replay only for ADMIT).
        assert!(matches!(
            led.register(&ctx, &req, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
        assert_eq!(led.inflight_count(), 1);
    }

    #[test]
    fn role_generation_and_boot_epoch_rejection() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        // Non-role12 caller: Unauthorized.
        let bad_role = AuthContextV1::new(ctx.auth_context_id, 9, 9, 1, BOOT).unwrap();
        assert_eq!(
            led.register(&bad_role, &req, &facts(1, Verdict::Admitted)),
            Err(Error::Unauthorized)
        );
        // Generation mismatch: STALE.
        assert_eq!(
            led.register(&ctx, &req, &facts(2, Verdict::Admitted)),
            Err(Error::Stale)
        );
        // Cross-boot context: STALE.
        let cross =
            AuthContextV1::new(ctx.auth_context_id, 9, FILE_SERVICE_ROLE, 1, BOOT + 1).unwrap();
        assert_eq!(
            led.register(&cross, &req, &facts(1, Verdict::Admitted)),
            Err(Error::Stale)
        );
        // Invalid identity: Invalid.
        let zero = AuthContextV1 {
            auth_context_id: 0,
            principal: 9,
            role: FILE_SERVICE_ROLE,
            generation: 1,
            boot_epoch: BOOT,
        };
        assert_eq!(
            led.register(&zero, &req, &facts(1, Verdict::Admitted)),
            Err(Error::Invalid)
        );
        assert_eq!(led.len(), 0);
        // Current generation admits.
        assert!(matches!(
            led.register(&ctx, &req, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
    }

    #[test]
    fn inflight_lifecycle_unknown_retention_and_terminal_release() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let id = match led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        let key = LedgerKey {
            auth_context_id: ctx.auth_context_id,
            request_seq: 9,
        };
        assert!(led.entry(key).unwrap().inflight_held());
        assert_eq!(led.entry(key).unwrap().completion, Completion::InFlight);
        // UNKNOWN retains gate/reference/credit; evidence may be updated.
        let out = led
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Unknown, [0x77; 32]),
            )
            .unwrap();
        assert_eq!(
            out,
            CompleteOutcome::UnknownRetained {
                evidence_digest: [0x77; 32]
            }
        );
        assert_eq!(led.inflight_count(), 1);
        assert!(led.entry(key).unwrap().inflight_held());
        // Repeated UNKNOWN only reconciles; updated evidence still retains.
        let out = led
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Unknown, [0x88; 32]),
            )
            .unwrap();
        assert_eq!(
            out,
            CompleteOutcome::UnknownRetained {
                evidence_digest: [0x88; 32]
            }
        );
        assert_eq!(led.inflight_count(), 1);
        // Authoritative terminal evidence releases the reference.
        let out = led
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Done, [0x3c; 32]),
            )
            .unwrap();
        assert_eq!(
            out,
            CompleteOutcome::Terminal {
                state: TerminalState::Done,
                evidence_digest: [0x3c; 32]
            }
        );
        assert_eq!(led.inflight_count(), 0);
        assert!(!led.entry(key).unwrap().inflight_held());
        // Record retained for idempotency/irreversibility, never evicted.
        assert_eq!(led.len(), 1);
    }

    #[test]
    fn terminal_irreversibility_and_complete_idempotency() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let id = match led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        let done = report(id, TerminalState::Done, [0x3c; 32]);
        led.complete(FILE_SERVICE_ROLE, false, &done).unwrap();
        // Identical repeat: idempotent original result, no state change.
        assert_eq!(
            led.complete(FILE_SERVICE_ROLE, false, &done),
            Ok(CompleteOutcome::Idempotent)
        );
        // Different evidence digest: Conflict.
        let mut other = done;
        other.evidence_digest[0] ^= 1;
        assert_eq!(
            led.complete(FILE_SERVICE_ROLE, false, &other),
            Err(Error::Conflict)
        );
        // Different terminal state: Conflict.
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Partial, [0x3c; 32])
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::NoEffect, [0x3c; 32])
            ),
            Err(Error::Conflict)
        );
        // Terminal never regresses to UNKNOWN.
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Unknown, [0x3c; 32])
            ),
            Err(Error::Conflict)
        );
        // No new work through a terminal admission.
        assert_eq!(led.reverify(id, 3, 3, false), Err(Error::Conflict));
        // ADMIT replay still returns the original admission (idempotent query).
        assert_eq!(
            led.register(&ctx, &req, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Replay {
                admission_id: id,
                accepted_local_ns: 1_000
            })
        );
        assert_eq!(led.inflight_count(), 0);
    }

    #[test]
    fn terminal_claim_without_evidence_keeps_unknown() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let id = match led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        // Zero-evidence terminal claim rejected; admission stays in-flight.
        for state in [
            TerminalState::Done,
            TerminalState::Partial,
            TerminalState::NoEffect,
        ] {
            assert_eq!(
                led.complete(FILE_SERVICE_ROLE, false, &report(id, state, [0; 32])),
                Err(Error::Invalid)
            );
        }
        assert_eq!(
            led.entry_by_admission(id).unwrap().completion,
            Completion::InFlight
        );
        assert_eq!(led.inflight_count(), 1);
        // After UNKNOWN, an unproven terminal claim still keeps UNKNOWN.
        led.complete(
            FILE_SERVICE_ROLE,
            false,
            &report(id, TerminalState::Unknown, [0x77; 32]),
        )
        .unwrap();
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Done, [0; 32])
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            led.entry_by_admission(id).unwrap().completion,
            Completion::Unknown {
                evidence_digest: [0x77; 32]
            }
        );
        assert_eq!(led.inflight_count(), 1);
    }

    #[test]
    fn gate_close_rejects_new_authorization_not_obligations() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let id = match led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        led.close_gate();
        assert!(!led.gate_open());
        // New authorization while closed: Busy.
        let new_req = frozen(ctx.auth_context_id, 10);
        assert_eq!(
            led.register(&ctx, &new_req, &facts(1, Verdict::Admitted)),
            Err(Error::Busy)
        );
        // Existing admitted obligation: replay + complete still work.
        assert!(matches!(
            led.register(&ctx, &req, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Replay { .. })
        ));
        assert!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id, TerminalState::Done, [0x3c; 32])
            )
            .is_ok()
        );
        // Reopen after obligations handled; new authorization admits again.
        led.open_gate();
        assert!(led.gate_open());
        assert!(matches!(
            led.register(&ctx, &new_req, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
    }

    #[test]
    fn capacity_bounded_and_admission_ids_monotonic() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let mut last_id = 0u64;
        for seq in 1u64..=ADMISSION_LEDGER_CAPACITY as u64 {
            let req = frozen(ctx.auth_context_id, seq);
            let id = match led
                .register(&ctx, &req, &facts(1, Verdict::Admitted))
                .unwrap()
            {
                RegisterOutcome::Admitted { admission_id, .. } => admission_id,
                _ => panic!(),
            };
            assert!(id > last_id);
            last_id = id;
        }
        assert_eq!(led.len(), ADMISSION_LEDGER_CAPACITY);
        assert_eq!(led.inflight_count(), ADMISSION_LEDGER_CAPACITY);
        // Full: a fresh admission is Capacity, never evicts an obligation.
        let extra = frozen(ctx.auth_context_id, 999);
        assert_eq!(
            led.register(&ctx, &extra, &facts(1, Verdict::Admitted)),
            Err(Error::Capacity)
        );
        assert_eq!(led.len(), ADMISSION_LEDGER_CAPACITY);
        // Replay does not consume capacity or a new id.
        let first = frozen(ctx.auth_context_id, 1);
        assert!(matches!(
            led.register(&ctx, &first, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Replay { .. })
        ));
    }

    #[test]
    fn volatile_retirement_requires_original_key_and_terminal_evidence() {
        let ctx = issuer().issue(9, FILE_SERVICE_ROLE).unwrap();
        let request = frozen(ctx.auth_context_id, 19);
        let key = LedgerKey {
            auth_context_id: ctx.auth_context_id,
            request_seq: 19,
        };
        let mut ledger = ledger();
        let RegisterOutcome::Admitted { admission_id, .. } = ledger
            .register(&ctx, &request, &facts(1, Verdict::Admitted))
            .unwrap()
        else {
            panic!()
        };
        let evidence = [0x52; 32];
        assert_eq!(
            ledger.retire_terminal(admission_id, key, evidence),
            Err(Error::Busy)
        );
        ledger
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &report(admission_id, TerminalState::Unknown, [0; 32]),
            )
            .unwrap();
        assert_eq!(
            ledger.retire_terminal(admission_id, key, evidence),
            Err(Error::Busy)
        );
        ledger
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &report(admission_id, TerminalState::Done, evidence),
            )
            .unwrap();
        assert_eq!(
            ledger.retire_terminal(
                admission_id,
                LedgerKey {
                    request_seq: 20,
                    ..key
                },
                evidence
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            ledger.retire_terminal(admission_id, key, [1; 32]),
            Err(Error::Conflict)
        );
        assert_eq!(ledger.retire_terminal(admission_id, key, evidence), Ok(()));
        assert!(ledger.is_empty());
        assert_eq!(
            ledger.retire_terminal(admission_id, key, evidence),
            Err(Error::Stale)
        );
    }

    #[test]
    fn complete_role_gate_recovery_successor_and_unknown_admission() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        let req = frozen(ctx.auth_context_id, 9);
        let id = match led
            .register(&ctx, &req, &facts(1, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        // Non-role12 without successor qualification: Unauthorized.
        assert_eq!(
            led.complete(9, false, &report(id, TerminalState::Done, [0x3c; 32])),
            Err(Error::Unauthorized)
        );
        // Verified protected recovery successor may reconcile old obligations.
        assert!(
            led.complete(9, true, &report(id, TerminalState::Unknown, [0x77; 32]))
                .is_ok()
        );
        assert_eq!(led.inflight_count(), 1);
        // Unknown / zero admission id can never bind a real admission.
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(id + 999, TerminalState::Done, [0x3c; 32])
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            led.complete(
                FILE_SERVICE_ROLE,
                false,
                &report(0, TerminalState::Done, [0x3c; 32])
            ),
            Err(Error::Invalid)
        );
        // Successor still cannot register new work (ADMIT stays role12-only).
        let successor_ctx = AuthContextV1::new(50, 9, 9, 1, BOOT).unwrap();
        let new_req = frozen(50, 1);
        assert_eq!(
            led.register(&successor_ctx, &new_req, &facts(1, Verdict::Admitted)),
            Err(Error::Unauthorized)
        );
    }

    #[test]
    fn freeze_local_advances_version_binds_digests_and_never_wraps() {
        let req = proposal(1, 9);
        let out = freeze_local(req, 2, BOOT, &user_frame(), b"data").unwrap();
        assert_eq!(out.prepared_version, 3);
        assert_eq!(out.frozen_data_digest, frozen_data_digest(b"data"));
        // Binding digest matches the v3 formula recomputation.
        assert_eq!(
            out.operation_digest,
            operation_digest(BOOT, &user_frame(), &out).unwrap()
        );
        // Empty data freezes to all-zero digest.
        let empty = freeze_local(req, 2, BOOT, &user_frame(), &[]).unwrap();
        assert_eq!(empty.frozen_data_digest, [0; 32]);
        // Overflow permanently stops; never wraps.
        assert_eq!(
            freeze_local(req, u64::MAX, BOOT, &user_frame(), b"data"),
            Err(Error::Exhausted)
        );
        // Zero identity / boot rejected.
        let mut zero = req;
        zero.auth_context_id = 0;
        assert!(freeze_local(zero, 2, BOOT, &user_frame(), b"data").is_err());
        assert!(freeze_local(req, 2, 0, &user_frame(), b"data").is_err());
    }

    #[test]
    fn three_step_linearization_frozen_not_admitted_and_effect_gate() {
        // ① frozen local is NOT admitted; no irreversible effects.
        let step = Linearization::frozen_local();
        assert!(!step.is_admitted());
        assert!(!step.irreversible_effects_allowed());
        assert_eq!(step.effect_gate(), Err(Error::Unauthorized));
        // ② non-ADMITTED verdict ends the request; still no effects.
        for verdict in [
            Verdict::Deny,
            Verdict::Revoked,
            Verdict::Stale,
            Verdict::Retry,
        ] {
            let s = step.register(verdict).unwrap();
            assert_eq!(s, Linearization::NotAdmitted { verdict });
            assert!(!s.is_admitted());
            assert!(!s.irreversible_effects_allowed());
            assert_eq!(s.effect_gate(), Err(Error::Unauthorized));
            // Cannot re-verify or re-register a non-admitted request.
            assert!(s.reverify(3, 3, false).is_err());
            assert!(s.register(Verdict::Admitted).is_err());
        }
        // ② ADMITTED permits effects.
        let admitted = step.register(Verdict::Admitted).unwrap();
        assert_eq!(admitted, Linearization::Admitted);
        assert!(admitted.is_admitted());
        assert!(admitted.irreversible_effects_allowed());
        assert_eq!(admitted.effect_gate(), Ok(()));
        // ③ match executes per admission (effects allowed).
        let exec = admitted.reverify(3, 3, false).unwrap();
        assert_eq!(exec, Linearization::Execute);
        assert!(exec.irreversible_effects_allowed());
        // ③ mismatch provable zero effect: NO_EFFECT, no irreversible effect.
        let no_eff = admitted.reverify(4, 3, true).unwrap();
        assert_eq!(no_eff, Linearization::CompleteNoEffect);
        assert!(no_eff.is_admitted());
        assert!(!no_eff.irreversible_effects_allowed());
        // ③ mismatch unproven: UNKNOWN keeps gate/reference, no new effects.
        let unknown = admitted.reverify(4, 3, false).unwrap();
        assert_eq!(unknown, Linearization::KeepUnknown);
        assert!(unknown.is_admitted());
        assert!(!unknown.irreversible_effects_allowed());
        // Illegal phase ordering is Conflict.
        assert!(step.reverify(3, 3, false).is_err());
        assert!(admitted.register(Verdict::Admitted).is_err());
        assert!(exec.reverify(3, 3, false).is_err());
    }

    #[test]
    fn end_to_end_three_step_with_ledger_match_and_mismatch_paths() {
        let mut iss = issuer();
        let ctx = iss.issue(9, FILE_SERVICE_ROLE).unwrap();
        let mut led = ledger();
        // ① freeze locally (no admission, no effects).
        let req = freeze_local(
            proposal(ctx.auth_context_id, 9),
            2,
            BOOT,
            &user_frame(),
            b"payload",
        )
        .unwrap();
        let step = Linearization::frozen_local();
        assert_eq!(step.effect_gate(), Err(Error::Unauthorized));
        // ② EL1 authoritative register.
        let id = match led
            .register(&ctx, &req, &facts(ctx.generation, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        let step = step.register(Verdict::Admitted).unwrap();
        assert_eq!(step.effect_gate(), Ok(()));
        // ③ match: execute per admission, then authoritative DONE.
        assert_eq!(
            led.reverify(id, req.prepared_version, req.prepared_version, false),
            Ok(StepThree::Execute)
        );
        let step = step
            .reverify(req.prepared_version, req.prepared_version, false)
            .unwrap();
        assert_eq!(step, Linearization::Execute);
        led.complete(
            FILE_SERVICE_ROLE,
            false,
            &report(id, TerminalState::Done, [0x3c; 32]),
        )
        .unwrap();
        assert_eq!(led.inflight_count(), 0);

        // Mismatch path on a second admission: UNKNOWN retains, then resolves.
        let req2 = freeze_local(
            proposal(ctx.auth_context_id, 10),
            5,
            BOOT,
            &user_frame(),
            b"other",
        )
        .unwrap();
        let id2 = match led
            .register(&ctx, &req2, &facts(ctx.generation, Verdict::Admitted))
            .unwrap()
        {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        // Local version drifted; no proof of zero effect → KeepUnknown.
        assert_eq!(
            led.reverify(id2, req2.prepared_version + 1, req2.prepared_version, false),
            Ok(StepThree::KeepUnknown)
        );
        led.complete(
            FILE_SERVICE_ROLE,
            false,
            &report(id2, TerminalState::Unknown, [0x77; 32]),
        )
        .unwrap();
        assert_eq!(led.inflight_count(), 1); // reference retained
        // Authoritative evidence later resolves to NO_EFFECT (proven zero).
        assert_eq!(
            led.reverify(id2, req2.prepared_version + 1, req2.prepared_version, true),
            Ok(StepThree::CompleteNoEffect)
        );
        led.complete(
            FILE_SERVICE_ROLE,
            false,
            &report(id2, TerminalState::NoEffect, [0x4d; 32]),
        )
        .unwrap();
        assert_eq!(led.inflight_count(), 0);
        assert_eq!(led.len(), 2);
    }
}
