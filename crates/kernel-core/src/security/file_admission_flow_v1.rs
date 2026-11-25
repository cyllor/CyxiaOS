//! V0.19.9 integrated end-to-end FILE_AUTH admission flow (contract layer).
//!
//! The three contract layers already exist separately:
//! * [`super::file_service_v4`] — the FileServiceRequest v4 user frame
//!   (`auth_context_id:u64=0`, encapsulated internally by EL1).
//! * [`super::file_auth_v3`] — ADMIT v3 / COMPLETE v1 frames, the
//!   `operation_digest` binding formula and the completion state machine.
//! * [`super::file_auth_context_v1`] — the protected EL1 AuthContext issuer
//!   and the bounded admission ledger with the three-step linearization.
//!
//! This module BINDS them into one pure admission flow; it adds no new wire
//! bytes and performs no native EL1 wiring (a later release gate). Nothing
//! here authorizes a file operation by itself.
//!
//! Baseline derivations (v0.19.9-implementation-spec.txt §9.6.1, ~4067-4385):
//! * v4 user frame (~4096): header 32B, `auth_context_id:u64=0` at offset 24
//!   ("由 EL1 内部封装"). The real id is never self-reported by the service;
//!   [`FileAdmissionFlowV1::begin`] stamps the encapsulated context id into
//!   the proposal. [`super::file_service_v4::Request::decode`] enforces the
//!   zero field, op range, exact payload schema and the x3 cap-selector rule.
//! * EL1 AuthContext (~4283): EL1 reads the original request digest, real
//!   holder, endpoint, parent/file cap and generations from the protected
//!   original AuthContext. Modeled by [`AuthContextIssuerV1::issue`].
//! * operation_digest (~4288): SHA256(ASCII "CYX/FILE-ADMIT/v3" ||
//!   LE64(boot_epoch) || LE64(auth_context_id) || SHA256(original full user
//!   frame with its auth_context_id field zeroed) || request[16..96)).
//!   Computed by [`super::file_auth_v3::operation_digest`] inside
//!   [`super::file_auth_context_v1::freeze_local`]; the v4 frame's 8-byte
//!   auth_context_id field at offset 24 is hashed as zero.
//! * Three-step linearization (~4297): ① trusted role12 freezes target/ACL
//!   generations, object-local monotonic non-wrapping `prepared_version`,
//!   data/snapshot digest locally, releases the local lock, NO user-visible
//!   side effect; ② EL1 atomically registers `admission_id`, the frozen
//!   binding digest and an in-flight reference under the exact
//!   (AuthContext, request_seq) key — same key + same proposal digest returns
//!   the original ADMIT, a different digest is E_CONFLICT, STALE/RETRY/
//!   REVOKED register no in-flight; ③ the service re-verifies its local
//!   `prepared_version` against the frozen object and executes per the
//!   original admission — mismatch with provable zero effect completes
//!   NO_EFFECT, otherwise UNKNOWN keeps the gate/reference. A frozen local
//!   version is NOT an admission and no irreversible user effect may be
//!   written before ADMITTED.
//! * COMPLETE state machine (~4360): ADMITTED→UNKNOWN (evidence updatable)
//!   →DONE/PARTIAL/NO_EFFECT, or ADMITTED directly terminal; any terminal is
//!   irreversible, identical (state, evidence) repeats are idempotent,
//!   anything else E_CONFLICT; UNKNOWN never releases gate/reference/credit.
//!   Reused via [`AdmissionLedgerV1::complete`], which calls
//!   [`super::file_auth_v3::complete_transition`].
//!
//! Contract-only scope and UNSPECIFIED details (documented choices, not
//! invented wire facts):
//! 1. Native authoritative cross-checks (authoritative cap/ACL versions,
//!    ancestor revocation, object health, resource/completion credits,
//!    per-op target resolution CREATE/MKDIR→parent vs OPEN/UNLINK→resolved
//!    target) are the later EL1 gate. [`AuthorityFacts`] carries their
//!    EL1-supplied outcome; nothing here derives authorization from a body.
//! 2. `request_seq` vs the v4 header `request_id`: the baseline embeds
//!    `request_seq` in the receipt key
//!    (`request_id=((group_id+1)<<56)|(stream_slot<<53)|request_seq`, ~4393)
//!    but does not fix a body-only extraction. The caller supplies
//!    `request_seq` independently; the native binding extracts it from the
//!    real receipt key. No extraction is invented here.
//! 3. Which v4 ops require ADMIT and their per-op target semantics are
//!    native; the flow accepts any frame [`file_service_v4::Request::decode`]
//!    accepts and does not restrict the op.
//! 4. Completion semantic truth belongs to the file-service TCB. The flow
//!    records the step-③ re-verification outcome and publishes the supplied
//!    authoritative evidence claim. The baseline mandates NO_EFFECT/UNKNOWN
//!    on a mismatch path; the native TCB must report accordingly — the
//!    contract does not second-guess authoritative evidence (consistent with
//!    [`super::file_auth_v3::complete_transition`]).
//! 5. `accepted_local_ns` is an EL1 clock fact supplied by the caller; this
//!    layer does not model time.
//! 6. Durable ordering (receipt terminal state persisted before EL1
//!    publishes generations / releases the reference) and the volatile vs
//!    durable split are native; only the state rules are modeled.
//! 7. AuthContext encapsulation happens on syscall arrival (§8.5), before
//!    service-side frame validation; a malformed frame therefore still
//!    consumes an encapsulated context id but registers no admission.

use super::Error;
use super::file_auth_context_v1::{
    AdmissionLedgerV1, AuthContextIssuerV1, AuthContextV1, AuthorityFacts, Linearization,
    RegisterOutcome, freeze_local,
};
use super::file_auth_v3::{
    AdmitRequestV3, CompleteOutcome, CompleteRequestV1, StepThree, TerminalState, Verdict,
    admit_role_gate,
};
use super::file_service_v4;

/// One integrated admission flow binding the three contract layers. It holds
/// the encapsulated EL1 AuthContext, the frozen step-① proposal, the
/// three-step [`Linearization`] state and the registered admission binding.
///
/// The flow is pure in-memory state for host tests; it never touches
/// `kernel/`, never invents wire bytes and never performs native authority
/// cross-checks. Step ordering is enforced: ① freeze → ② admit → effect gate
/// → ③ execute/reverify → COMPLETE.
pub struct FileAdmissionFlowV1 {
    ctx: AuthContextV1,
    request: AdmitRequestV3,
    state: Linearization,
    /// 0 until step ② registers (or replays) a real admission.
    admission_id: u64,
    accepted_local_ns: u64,
}

impl FileAdmissionFlowV1 {
    /// Step ① under an ALREADY encapsulated AuthContext: validate the v4 user
    /// frame, stamp the encapsulated context id into the proposal and freeze
    /// locally (advance `prepared_version`, bind the data and operation
    /// digests). Produces NO user-visible side effect and is NOT an admission.
    ///
    /// This models a service retry freezing under the same protected context
    /// (the conflict/replay key is (auth_context_id, request_seq)). The role
    /// must be role12 — step ① is performed by the trusted file service.
    pub fn freeze(
        ctx: AuthContextV1,
        user_frame: &[u8],
        cap_selector: u64,
        mut proposal: AdmitRequestV3,
        current_prepared_version: u64,
        data: &[u8],
    ) -> Result<Self, Error> {
        ctx.validate()?;
        // Step ① is trusted role12 only (baseline ~4297).
        ctx.file_auth_gate()?;
        // Layer 1: strict v4 decode enforces auth_context_id=0, op range,
        // exact payload schema and the x3 cap-selector rule.
        file_service_v4::Request::decode(user_frame, cap_selector)?;
        // EL1 encapsulation: the user frame carried 0; the real id is stamped
        // here, never self-reported by the service.
        proposal.auth_context_id = ctx.auth_context_id;
        // Step ① freeze owns prepared_version + the two digests (v3 formula).
        let request = freeze_local(
            proposal,
            current_prepared_version,
            ctx.boot_epoch,
            user_frame,
            data,
        )?;
        Ok(Self {
            ctx,
            request,
            state: Linearization::frozen_local(),
            admission_id: 0,
            accepted_local_ns: 0,
        })
    }

    /// Full step ① entry: EL1 wraps a protected AuthContext via the issuer
    /// (the v4 user frame carried `auth_context_id=0`), then freezes locally.
    /// The role12 gate is checked BEFORE any identity is consumed, so a
    /// non-role12 caller never advances a generation or allocates a context id.
    // Each argument is a distinct EL1-supplied admission fact (issuer, principal,
    // role, frame, cap selector, proposal, version, data); bundling them into a
    // struct would obscure the baseline §9.6.1 step-① input contract.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        issuer: &mut AuthContextIssuerV1,
        principal: u64,
        role: u64,
        user_frame: &[u8],
        cap_selector: u64,
        proposal: AdmitRequestV3,
        current_prepared_version: u64,
        data: &[u8],
    ) -> Result<Self, Error> {
        admit_role_gate(role)?;
        let ctx = issuer.issue(principal, role)?;
        Self::freeze(
            ctx,
            user_frame,
            cap_selector,
            proposal,
            current_prepared_version,
            data,
        )
    }

    pub const fn ctx(&self) -> AuthContextV1 {
        self.ctx
    }
    pub const fn request(&self) -> AdmitRequestV3 {
        self.request
    }
    pub const fn state(&self) -> Linearization {
        self.state
    }
    /// The registered admission id, or 0 before step ② succeeds.
    pub const fn admission_id(&self) -> u64 {
        self.admission_id
    }
    pub const fn accepted_local_ns(&self) -> u64 {
        self.accepted_local_ns
    }

    /// Step ② authoritative register via the admission ledger. Drives the
    /// linearization state and binds the admission on a fresh ADMITTED;
    /// a replay returns the original ADMIT without a new registration or a
    /// new linearization step. A non-ADMITTED verdict ends this flow instance
    /// (nothing registered, no in-flight reference). Errors leave the flow
    /// frozen and register nothing.
    pub fn admit(
        &mut self,
        ledger: &mut AdmissionLedgerV1,
        facts: &AuthorityFacts,
    ) -> Result<RegisterOutcome, Error> {
        match self.state {
            // A non-ADMITTED flow instance is ended; new work needs a new
            // freeze. Do not touch the ledger (no sticky denial is cached,
            // but this instance may not re-register).
            Linearization::NotAdmitted { .. } => Err(Error::Conflict),
            Linearization::FrozenLocal => {
                let outcome = ledger.register(&self.ctx, &self.request, facts)?;
                let verdict = match outcome {
                    RegisterOutcome::Admitted {
                        admission_id,
                        accepted_local_ns,
                    } => {
                        self.admission_id = admission_id;
                        self.accepted_local_ns = accepted_local_ns;
                        Verdict::Admitted
                    }
                    RegisterOutcome::NotAdmitted { verdict, .. } => verdict,
                    // A fresh context id cannot already be registered; an
                    // external pre-registration under the same key is a
                    // caller bug. Replay registers nothing, so this is safe.
                    RegisterOutcome::Replay { .. } => return Err(Error::Conflict),
                };
                self.state = self.state.register(verdict)?;
                Ok(outcome)
            }
            // Already admitted (or later): a retry must replay the original
            // admission. No new registration and no new linearization step.
            _ => {
                let outcome = ledger.register(&self.ctx, &self.request, facts)?;
                match outcome {
                    RegisterOutcome::Replay { admission_id, .. } => {
                        if admission_id != self.admission_id {
                            return Err(Error::Conflict);
                        }
                        Ok(outcome)
                    }
                    _ => Err(Error::Conflict),
                }
            }
        }
    }

    /// Guard to call before ANY irreversible user effect. Only an ADMITTED
    /// admission (states `Admitted`/`Execute`) permits effects; a frozen or
    /// non-admitted flow never does (baseline ~4302).
    pub const fn effect_gate(&self) -> Result<(), Error> {
        self.state.effect_gate()
    }

    /// Step ③ re-verification bound to this flow's real, non-terminal
    /// admission: compare the service's local `prepared_version` against the
    /// originally frozen one and execute per the original admission. Match →
    /// Execute; mismatch with provable zero effect → CompleteNoEffect;
    /// mismatch without proof → KeepUnknown. The effect gate is enforced
    /// first; illegal phase ordering (e.g. re-execution) is Conflict.
    pub fn execute(
        &mut self,
        ledger: &mut AdmissionLedgerV1,
        local_prepared_version: u64,
        provable_no_effect: bool,
    ) -> Result<StepThree, Error> {
        // No irreversible effect before ADMITTED.
        self.effect_gate()?;
        let frozen = self.request.prepared_version;
        // Phase check first (rejects anything but `Admitted`), so a wrong
        // phase never touches the ledger.
        let next = self
            .state
            .reverify(local_prepared_version, frozen, provable_no_effect)?;
        let step = ledger.reverify(
            self.admission_id,
            local_prepared_version,
            frozen,
            provable_no_effect,
        )?;
        self.state = next;
        Ok(step)
    }

    /// COMPLETE transition bound to THIS flow's registered admission. Builds
    /// the COMPLETE v1 report with the real `admission_id` (the service never
    /// completes a different admission through this flow) and reuses
    /// [`AdmissionLedgerV1::complete`] → [`super::file_auth_v3::complete_transition`].
    /// A terminal claim requires authoritative evidence; UNKNOWN retains the
    /// gate/reference/credit. Fails Conflict if no admission is bound yet.
    pub fn complete(
        &mut self,
        ledger: &mut AdmissionLedgerV1,
        caller_role: u64,
        protected_recovery_successor: bool,
        terminal_state: TerminalState,
        evidence_digest: [u8; 32],
    ) -> Result<CompleteOutcome, Error> {
        if self.admission_id == 0 {
            return Err(Error::Conflict);
        }
        let report = CompleteRequestV1 {
            admission_id: self.admission_id,
            terminal_state,
            evidence_digest,
        };
        ledger.complete(caller_role, protected_recovery_successor, &report)
    }
}

/// Bundled EL1-supplied inputs for the pure end-to-end driver
/// [`run_admission_flow`]. Every authority/identity/clock fact is supplied by
/// the verified EL1 caller, never derived from a frame body.
pub struct AdmissionFlowInput<'a> {
    /// EL1-verified real holder principal (§8.5 x3 lookup).
    pub principal: u64,
    /// EL1-verified caller role; FILE_AUTH ADMIT requires role12.
    pub role: u64,
    /// Original FileServiceRequest v4 user frame (`auth_context_id=0`).
    pub user_frame: &'a [u8],
    /// Independently checked syscall x3 cap selector.
    pub cap_selector: u64,
    /// Step-① proposal fields. `auth_context_id` is stamped by encapsulation;
    /// `prepared_version`, `frozen_data_digest` and `operation_digest` are
    /// owned by the freeze. The caller supplies target/rights/seq/acl fields.
    pub proposal: AdmitRequestV3,
    /// Object-local `prepared_version` before the freeze advance.
    pub current_prepared_version: u64,
    /// Actual frozen data / FSYNC snapshot bytes (empty → all-zero digest).
    pub data: &'a [u8],
    /// Step-② EL1 authoritative facts (generation freshness + verdict).
    pub facts: AuthorityFacts,
    /// Step-③ service-local `prepared_version` to re-verify.
    pub local_prepared_version: u64,
    /// Whether a step-③ mismatch has provable zero request effect.
    pub provable_no_effect: bool,
    /// COMPLETE terminal claim (admission id bound by the flow).
    pub terminal_state: TerminalState,
    /// Authoritative completion evidence digest.
    pub evidence_digest: [u8; 32],
}

/// Outcome of the pure end-to-end driver. `Err` propagates schema/identity/
/// authority/gate rejections (nothing registered, no irreversible effect); a
/// failed COMPLETE after a real admission leaves that admission in-flight /
/// UNKNOWN (it is a retained obligation, never released).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowOutcome {
    /// Step ② returned a non-ADMITTED verdict; nothing registered, no effect.
    NotAdmitted {
        verdict: Verdict,
        deny_generation: u64,
    },
    /// The full pipeline ran: ② fresh ADMITTED, effect gate, ③ reverify and a
    /// COMPLETE transition. `completion` distinguishes a terminal publication
    /// from UNKNOWN retention; `step_three` records the re-verification.
    Completed {
        admission_id: u64,
        accepted_local_ns: u64,
        step_three: StepThree,
        completion: CompleteOutcome,
    },
}

/// Pure end-to-end admission flow binding all three contract layers:
/// v4 user frame (`auth_context_id=0`) → EL1 wraps AuthContext (issuer) →
/// freeze computes `operation_digest` (v3 formula, zeroing the v4 frame's
/// auth_context_id field) → ADMIT register via the ledger (idempotent /
/// conflict) → effect gate (no irreversible effect before ADMITTED) →
/// execute/reverify → COMPLETE transition (reuses `complete_transition`).
///
/// This drives the FRESH path. Replay and conflict (a retry under the same
/// (auth_context_id, request_seq) key) are modeled by reusing a
/// [`FileAdmissionFlowV1`] instance's [`FileAdmissionFlowV1::admit`] or by
/// freezing a second proposal under the same context with
/// [`FileAdmissionFlowV1::freeze`].
pub fn run_admission_flow(
    issuer: &mut AuthContextIssuerV1,
    ledger: &mut AdmissionLedgerV1,
    input: &AdmissionFlowInput<'_>,
) -> Result<FlowOutcome, Error> {
    let mut flow = FileAdmissionFlowV1::begin(
        issuer,
        input.principal,
        input.role,
        input.user_frame,
        input.cap_selector,
        input.proposal,
        input.current_prepared_version,
        input.data,
    )?;
    match flow.admit(ledger, &input.facts)? {
        RegisterOutcome::NotAdmitted {
            verdict,
            deny_generation,
        } => Ok(FlowOutcome::NotAdmitted {
            verdict,
            deny_generation,
        }),
        // Unreachable for a fresh context id; treated as a caller bug.
        RegisterOutcome::Replay { .. } => Err(Error::Conflict),
        RegisterOutcome::Admitted {
            admission_id,
            accepted_local_ns,
        } => {
            // No irreversible user effect before ADMITTED.
            flow.effect_gate()?;
            let step_three = flow.execute(
                ledger,
                input.local_prepared_version,
                input.provable_no_effect,
            )?;
            let completion = flow.complete(
                ledger,
                input.role,
                false,
                input.terminal_state,
                input.evidence_digest,
            )?;
            Ok(FlowOutcome::Completed {
                admission_id,
                accepted_local_ns,
                step_three,
                completion,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::file_auth_v3::{FILE_SERVICE_ROLE, operation_digest};
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const BOOT: u64 = 7;
    const PRINCIPAL: u64 = 9;
    const CAP_SELECTOR: u64 = 1;

    /// Minimal valid FileServiceRequest v4 user frame (op6 CLOSE, 4B payload,
    /// auth_context_id=0). Mirrors the sibling contract layers' test frame.
    fn user_frame() -> Vec<u8> {
        let header = file_service_v4::REQUEST_HEADER;
        let mut b = vec![0u8; header + 4];
        b[0..4].copy_from_slice(&file_service_v4::REQUEST_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&file_service_v4::REQUEST_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(header as u16).to_le_bytes());
        b[8..10].copy_from_slice(&6u16.to_le_bytes());
        b[12..16].copy_from_slice(&4u32.to_le_bytes());
        b[16..24].copy_from_slice(&4u64.to_le_bytes());
        b
    }

    fn proposal(seq: u64) -> AdmitRequestV3 {
        AdmitRequestV3 {
            auth_context_id: 0, // stamped by encapsulation
            target_id: 42,
            target_generation: 7,
            required_rights: 0b1011,
            request_seq: seq,
            prepared_version: 0, // owned by freeze
            acl_generation: 5,
            frozen_data_digest: [0; 32], // owned by freeze
            operation_digest: [0; 32],   // owned by freeze
        }
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

    fn begin(seq: u64, data: &[u8]) -> (AuthContextIssuerV1, FileAdmissionFlowV1) {
        let mut iss = issuer();
        let flow = FileAdmissionFlowV1::begin(
            &mut iss,
            PRINCIPAL,
            FILE_SERVICE_ROLE,
            &user_frame(),
            CAP_SELECTOR,
            proposal(seq),
            2,
            data,
        )
        .unwrap();
        (iss, flow)
    }

    fn input<'a>(seq: u64, frame: &'a [u8]) -> AdmissionFlowInput<'a> {
        AdmissionFlowInput {
            principal: PRINCIPAL,
            role: FILE_SERVICE_ROLE,
            user_frame: frame,
            cap_selector: CAP_SELECTOR,
            proposal: proposal(seq),
            current_prepared_version: 2,
            data: b"payload",
            facts: facts(1, Verdict::Admitted),
            local_prepared_version: 3, // freeze advances 2 → 3
            provable_no_effect: false,
            terminal_state: TerminalState::Done,
            evidence_digest: [0x3c; 32],
        }
    }

    #[test]
    fn happy_path_end_to_end_binds_all_three_layers() {
        let mut iss = issuer();
        let mut led = ledger();
        let frame = user_frame();
        let out = run_admission_flow(&mut iss, &mut led, &input(9, &frame)).unwrap();
        let (admission_id, step_three, completion) = match out {
            FlowOutcome::Completed {
                admission_id,
                step_three,
                completion,
                ..
            } => (admission_id, step_three, completion),
            _ => panic!("expected completed flow"),
        };
        assert_eq!(step_three, StepThree::Execute);
        assert_eq!(
            completion,
            CompleteOutcome::Terminal {
                state: TerminalState::Done,
                evidence_digest: [0x3c; 32]
            }
        );
        // One admission registered, terminally published, reference released.
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 0);
        let entry = led.entry_by_admission(admission_id).unwrap();
        assert_eq!(entry.key.auth_context_id, 1); // first encapsulated id
        assert_eq!(entry.key.request_seq, 9);
        assert!(!entry.inflight_held());
        // The issuer advanced exactly one generation for the holder.
        assert_eq!(iss.current_generation(PRINCIPAL), Some(1));
    }

    #[test]
    fn operation_digest_uses_v3_formula_and_encapsulates_context_id() {
        let (_iss, flow) = begin(9, b"payload");
        let req = flow.request();
        let ctx = flow.ctx();
        // The real id is encapsulated, never the user frame's 0.
        assert_ne!(ctx.auth_context_id, 0);
        assert_eq!(req.auth_context_id, ctx.auth_context_id);
        assert_eq!(&user_frame()[24..32], &[0; 8]);
        // Freeze advanced the object-local version and bound the data digest.
        assert_eq!(req.prepared_version, 3);
        assert_ne!(req.frozen_data_digest, [0; 32]);
        // Binding digest equals the v3 formula recomputation over the original
        // v4 frame (whose auth_context_id field is hashed as zero).
        assert_eq!(
            req.operation_digest,
            operation_digest(BOOT, &user_frame(), &req).unwrap()
        );
        // Changing the frozen data changes the binding digest.
        let (_iss2, other) = begin(9, b"different");
        assert_ne!(other.request().operation_digest, req.operation_digest);
        // Step ① is frozen, NOT admitted: no effects yet.
        assert_eq!(flow.state(), Linearization::FrozenLocal);
        assert!(!flow.state().is_admitted());
        assert_eq!(flow.admission_id(), 0);
    }

    #[test]
    fn v4_frame_nonzero_auth_context_or_bad_schema_rejected() {
        let mut iss = issuer();
        // A self-reported non-zero auth_context_id is rejected by v4 decode.
        let mut bad = user_frame();
        bad[24..32].copy_from_slice(&0xdead_beefu64.to_le_bytes());
        assert!(
            FileAdmissionFlowV1::begin(
                &mut iss,
                PRINCIPAL,
                FILE_SERVICE_ROLE,
                &bad,
                CAP_SELECTOR,
                proposal(9),
                2,
                b"data",
            )
            .is_err()
        );
        // Bad magic is rejected; no admission is registered.
        let mut bad = user_frame();
        bad[0] ^= 1;
        assert!(
            FileAdmissionFlowV1::begin(
                &mut iss,
                PRINCIPAL,
                FILE_SERVICE_ROLE,
                &bad,
                CAP_SELECTOR,
                proposal(9),
                2,
                b"data",
            )
            .is_err()
        );
        let led = ledger();
        assert_eq!(led.len(), 0);
    }

    #[test]
    fn replay_returns_original_admit_without_new_record() {
        let mut iss = issuer();
        let mut led = ledger();
        let mut flow = FileAdmissionFlowV1::begin(
            &mut iss,
            PRINCIPAL,
            FILE_SERVICE_ROLE,
            &user_frame(),
            CAP_SELECTOR,
            proposal(9),
            2,
            b"payload",
        )
        .unwrap();
        let id = match flow.admit(&mut led, &facts(1, Verdict::Admitted)).unwrap() {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!("expected fresh admit"),
        };
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 1);
        // Same context + same proposal: the original ADMIT is returned, no new
        // registration and no new in-flight reference.
        let replay = flow.admit(&mut led, &facts(1, Verdict::Admitted)).unwrap();
        assert_eq!(
            replay,
            RegisterOutcome::Replay {
                admission_id: id,
                accepted_local_ns: 1_000
            }
        );
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 1);
        assert_eq!(flow.admission_id(), id);
        // Replay still works after a terminal publication (idempotent query).
        flow.complete(
            &mut led,
            FILE_SERVICE_ROLE,
            false,
            TerminalState::Done,
            [0x3c; 32],
        )
        .unwrap();
        assert_eq!(led.inflight_count(), 0);
        assert!(matches!(
            flow.admit(&mut led, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Replay { admission_id, .. }) if admission_id == id
        ));
    }

    #[test]
    fn conflict_same_key_different_proposal_digest() {
        let (_iss, mut flow) = begin(9, b"payload");
        let mut led = ledger();
        flow.admit(&mut led, &facts(1, Verdict::Admitted)).unwrap();
        assert_eq!(led.len(), 1);
        // A second freeze under the SAME encapsulated context and request_seq
        // but different frozen data → different binding digest → E_CONFLICT.
        let mut retry = FileAdmissionFlowV1::freeze(
            flow.ctx(),
            &user_frame(),
            CAP_SELECTOR,
            proposal(9),
            2,
            b"changed",
        )
        .unwrap();
        assert_ne!(
            retry.request().operation_digest,
            flow.request().operation_digest
        );
        assert_eq!(
            retry.admit(&mut led, &facts(1, Verdict::Admitted)),
            Err(Error::Conflict)
        );
        // Nothing new registered; the original obligation is retained.
        assert_eq!(led.len(), 1);
        assert_eq!(led.inflight_count(), 1);
        assert_eq!(retry.admission_id(), 0);
        assert_eq!(retry.state(), Linearization::FrozenLocal);
    }

    #[test]
    fn stale_generation_registers_no_inflight() {
        let (_iss, mut flow) = begin(9, b"payload");
        let mut led = ledger();
        // Authoritative generation drifted: STALE, nothing registered.
        assert_eq!(
            flow.admit(&mut led, &facts(2, Verdict::Admitted)),
            Err(Error::Stale)
        );
        assert_eq!(led.len(), 0);
        assert_eq!(led.inflight_count(), 0);
        assert_eq!(flow.state(), Linearization::FrozenLocal);
        assert_eq!(flow.admission_id(), 0);
        // No irreversible effect is permitted on a stale (unadmitted) flow.
        assert_eq!(flow.effect_gate(), Err(Error::Unauthorized));
        // The current generation admits normally afterwards.
        assert!(matches!(
            flow.admit(&mut led, &facts(1, Verdict::Admitted)),
            Ok(RegisterOutcome::Admitted { .. })
        ));
        assert_eq!(led.inflight_count(), 1);
    }

    #[test]
    fn role12_gate_rejects_other_roles_without_consuming_identity() {
        let mut iss = issuer();
        for role in [0u64, 1, 9, 11, 13, 15] {
            assert!(
                FileAdmissionFlowV1::begin(
                    &mut iss,
                    PRINCIPAL,
                    role,
                    &user_frame(),
                    CAP_SELECTOR,
                    proposal(9),
                    2,
                    b"data",
                )
                .is_err()
            );
        }
        // Rejected callers consumed no generation and no context id: the first
        // valid role12 issuance still gets generation 1.
        assert_eq!(iss.current_generation(PRINCIPAL), None);
        let ctx = iss.issue(PRINCIPAL, FILE_SERVICE_ROLE).unwrap();
        assert_eq!(ctx.generation, 1);
        assert_eq!(ctx.auth_context_id, 1);
        // freeze under a non-role12 context is also rejected.
        let bad_ctx = AuthContextV1::new(50, PRINCIPAL, 9, 1, BOOT).unwrap();
        assert!(
            FileAdmissionFlowV1::freeze(
                bad_ctx,
                &user_frame(),
                CAP_SELECTOR,
                proposal(9),
                2,
                b"data",
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_keeps_reference_then_resolves() {
        let mut iss = issuer();
        let mut led = ledger();
        let frame = user_frame();
        let mut inp = input(9, &frame);
        // Local version drifted, no proof of zero effect → KeepUnknown.
        inp.local_prepared_version = 4;
        inp.provable_no_effect = false;
        inp.terminal_state = TerminalState::Unknown;
        inp.evidence_digest = [0x77; 32];
        let out = run_admission_flow(&mut iss, &mut led, &inp).unwrap();
        let (id, step_three, completion) = match out {
            FlowOutcome::Completed {
                admission_id,
                step_three,
                completion,
                ..
            } => (admission_id, step_three, completion),
            _ => panic!("expected completed flow"),
        };
        assert_eq!(step_three, StepThree::KeepUnknown);
        assert_eq!(
            completion,
            CompleteOutcome::UnknownRetained {
                evidence_digest: [0x77; 32]
            }
        );
        // UNKNOWN retains the gate/reference/in-flight credit.
        assert_eq!(led.inflight_count(), 1);
        assert!(led.entry_by_admission(id).unwrap().inflight_held());
        // Repeated UNKNOWN only reconciles; updated evidence still retains.
        let reconcile = CompleteRequestV1 {
            admission_id: id,
            terminal_state: TerminalState::Unknown,
            evidence_digest: [0x88; 32],
        };
        assert_eq!(
            led.complete(FILE_SERVICE_ROLE, false, &reconcile),
            Ok(CompleteOutcome::UnknownRetained {
                evidence_digest: [0x88; 32]
            })
        );
        assert_eq!(led.inflight_count(), 1);
        // Resolve later with authoritative NO_EFFECT evidence via the ledger.
        let report = CompleteRequestV1 {
            admission_id: id,
            terminal_state: TerminalState::NoEffect,
            evidence_digest: [0x4d; 32],
        };
        led.complete(FILE_SERVICE_ROLE, false, &report).unwrap();
        assert_eq!(led.inflight_count(), 0);
    }

    #[test]
    fn no_irreversible_effect_before_admitted() {
        let (_iss, mut flow) = begin(9, b"payload");
        let mut led = ledger();
        // ① frozen local: no admission, no effects.
        assert_eq!(flow.effect_gate(), Err(Error::Unauthorized));
        assert!(flow.execute(&mut led, 3, false).is_err());
        assert!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0x3c; 32]
            )
            .is_err()
        );
        // ② non-ADMITTED verdict: still no effects, nothing registered.
        let out = flow.admit(&mut led, &facts(1, Verdict::Deny)).unwrap();
        assert!(matches!(
            out,
            RegisterOutcome::NotAdmitted {
                verdict: Verdict::Deny,
                ..
            }
        ));
        assert_eq!(
            flow.state(),
            Linearization::NotAdmitted {
                verdict: Verdict::Deny
            }
        );
        assert_eq!(flow.effect_gate(), Err(Error::Unauthorized));
        assert!(flow.execute(&mut led, 3, false).is_err());
        assert_eq!(led.len(), 0);
        assert_eq!(led.inflight_count(), 0);
        // A ended (non-admitted) instance cannot re-register or complete.
        assert_eq!(
            flow.admit(&mut led, &facts(1, Verdict::Admitted)),
            Err(Error::Conflict)
        );
        // The driver's NotAdmitted path likewise produces no effect/reference.
        let mut iss = issuer();
        let mut led2 = ledger();
        let frame2 = user_frame();
        let mut inp = input(10, &frame2);
        inp.facts = facts(1, Verdict::Revoked);
        let out = run_admission_flow(&mut iss, &mut led2, &inp).unwrap();
        assert!(matches!(
            out,
            FlowOutcome::NotAdmitted {
                verdict: Verdict::Revoked,
                ..
            }
        ));
        assert_eq!(led2.len(), 0);
        assert_eq!(led2.inflight_count(), 0);
    }

    #[test]
    fn mismatch_provable_zero_effect_completes_no_effect() {
        let mut iss = issuer();
        let mut led = ledger();
        let frame = user_frame();
        let mut inp = input(9, &frame);
        inp.local_prepared_version = 4; // drifted
        inp.provable_no_effect = true; // provable zero request effect
        inp.terminal_state = TerminalState::NoEffect;
        inp.evidence_digest = [0x4d; 32];
        let out = run_admission_flow(&mut iss, &mut led, &inp).unwrap();
        match out {
            FlowOutcome::Completed {
                step_three,
                completion,
                admission_id,
                ..
            } => {
                assert_eq!(step_three, StepThree::CompleteNoEffect);
                assert_eq!(
                    completion,
                    CompleteOutcome::Terminal {
                        state: TerminalState::NoEffect,
                        evidence_digest: [0x4d; 32]
                    }
                );
                // NO_EFFECT maps to CANCELLED receipt status; reference released.
                assert_eq!(TerminalState::NoEffect.receipt_status(true), 6);
                assert_eq!(led.inflight_count(), 0);
                assert!(
                    !led.entry_by_admission(admission_id)
                        .unwrap()
                        .inflight_held()
                );
            }
            _ => panic!("expected completed flow"),
        }
    }

    #[test]
    fn complete_binds_admission_idempotent_and_irreversible() {
        let (_iss, mut flow) = begin(9, b"payload");
        let mut led = ledger();
        let id = match flow.admit(&mut led, &facts(1, Verdict::Admitted)).unwrap() {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        flow.execute(&mut led, 3, false).unwrap();
        // Terminal claim without evidence is rejected; admission stays in-flight.
        assert_eq!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0; 32]
            ),
            Err(Error::Invalid)
        );
        assert_eq!(led.inflight_count(), 1);
        // Authoritative DONE publishes and releases.
        let done = flow
            .complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0x3c; 32],
            )
            .unwrap();
        assert_eq!(
            done,
            CompleteOutcome::Terminal {
                state: TerminalState::Done,
                evidence_digest: [0x3c; 32]
            }
        );
        assert_eq!(led.inflight_count(), 0);
        // Identical repeat: idempotent. Different evidence/state: Conflict.
        assert_eq!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0x3c; 32]
            ),
            Ok(CompleteOutcome::Idempotent)
        );
        assert_eq!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0x3d; 32]
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Partial,
                [0x3c; 32]
            ),
            Err(Error::Conflict)
        );
        // Terminal never regresses to UNKNOWN; no re-execution.
        assert_eq!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Unknown,
                [0x3c; 32]
            ),
            Err(Error::Conflict)
        );
        assert_eq!(flow.execute(&mut led, 3, false), Err(Error::Conflict));
        assert_eq!(
            led.entry_by_admission(id).unwrap().completion.is_terminal(),
            true
        );
    }

    #[test]
    fn step_ordering_enforced_and_admission_id_monotonic() {
        let mut iss = issuer();
        let mut led = ledger();
        // Execute/complete before admit are rejected.
        let mut flow = FileAdmissionFlowV1::begin(
            &mut iss,
            PRINCIPAL,
            FILE_SERVICE_ROLE,
            &user_frame(),
            CAP_SELECTOR,
            proposal(1),
            2,
            b"a",
        )
        .unwrap();
        assert!(flow.execute(&mut led, 3, false).is_err());
        assert!(
            flow.complete(
                &mut led,
                FILE_SERVICE_ROLE,
                false,
                TerminalState::Done,
                [0x3c; 32]
            )
            .is_err()
        );
        let id1 = match flow.admit(&mut led, &facts(1, Verdict::Admitted)).unwrap() {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        // Double execute is rejected (no re-execution through one admission).
        flow.execute(&mut led, 3, false).unwrap();
        assert_eq!(flow.execute(&mut led, 3, false), Err(Error::Conflict));
        // A second request gets a strictly larger admission id.
        let mut flow2 = FileAdmissionFlowV1::begin(
            &mut iss,
            PRINCIPAL,
            FILE_SERVICE_ROLE,
            &user_frame(),
            CAP_SELECTOR,
            proposal(2),
            2,
            b"b",
        )
        .unwrap();
        let id2 = match flow2.admit(&mut led, &facts(2, Verdict::Admitted)).unwrap() {
            RegisterOutcome::Admitted { admission_id, .. } => admission_id,
            _ => panic!(),
        };
        assert!(id2 > id1);
        assert_eq!(led.len(), 2);
    }
}
