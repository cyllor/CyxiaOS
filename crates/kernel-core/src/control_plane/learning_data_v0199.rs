//! Evidence-bound local learning data. Internal EL1 custody only.
//! A trace verifier must authenticate both replay branches, all executed work,
//! renewals/restoration and the complete CPU intervals. Neither an APPLIED
//! wire field nor a model's estimate is evidence by itself.
use super::{
    Error, Identity,
    action_schema_v2::ActionV2,
    advice_disposition_v1::AdviceDispositionV1,
    apply_report_v1::{ActionStatus, ApplyReportV1},
    candidate_registry_v0199::FrozenCandidates,
    decision_record_v3::{DecisionRecordV3, DecisionSource},
    feedback_v0199::{CausalLabel, FeedbackRecord},
};
use cyxia_control_model::{
    native_v0199::{
        Candidate,
        integer_model::{MODEL_BYTES, Model},
        operations_features,
    },
    reward_v2::{self, Reward, Trace, Workspace, softfloat::F64},
    sgd_v2::{self, LastLayer},
};
use sha2::{Digest, Sha256};

pub const MAX_SAMPLES: usize = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayGroup {
    pub seed: u64,
    pub workload: [u8; 32],
    pub initial_image: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaBinding {
    pub feature: [u8; 32],
    pub action: [u8; 32],
    pub reward: [u8; 32],
    pub learning: [u8; 32],
}
impl SchemaBinding {
    fn valid(self) -> bool {
        [self.feature, self.action, self.reward, self.learning]
            .iter()
            .all(|h| *h != [0; 32])
    }
}
#[derive(Clone, Copy)]
pub struct Sample {
    group: ReplayGroup,
    schemas: SchemaBinding,
    domain: u16,
    input: [i16; 64],
    reward: Reward,
    candidate_receipt: [u8; 32],
    baseline_receipt: [u8; 32],
    pair: [u8; 32],
}
impl Sample {
    #[allow(clippy::too_many_arguments)]
    pub fn capture(
        group: ReplayGroup,
        schemas: SchemaBinding,
        candidates: &FrozenCandidates,
        baseline_candidates: &FrozenCandidates,
        feedback: &FeedbackRecord,
        baseline: &FeedbackRecord,
        actual: Trace<'_>,
        reference: Trace<'_>,
        cpu: [Option<u64>; 4],
        workspace: &mut Workspace,
        verify_archived_pair: impl FnOnce(
            &ReplayGroup,
            &SchemaBinding,
            &FrozenCandidates,
            &FrozenCandidates,
            &FeedbackRecord,
            &FeedbackRecord,
            &Trace<'_>,
            &Trace<'_>,
            [Option<u64>; 4],
        ) -> Result<[u8; 32], Error>,
    ) -> Result<Self, Error> {
        if !schemas.valid() || group.workload == [0; 32] || group.initial_image == [0; 32] {
            return Err(Error::Invalid);
        }
        let (decision, report) = checked_feedback(feedback, candidates)?;
        let (base, base_report) = checked_feedback(baseline, baseline_candidates)?;
        let snap = candidates.snapshot();
        if base.domain_id!=decision.domain_id||base.rules_hash!=decision.rules_hash
            ||base.rules_generation!=decision.rules_generation
            // For an assisted comparison the no-advice side must actually
            // follow its own frozen rule fallback, not a second assisted
            // or trial-selected action. Authorized trial pairs still
            // require their independent archive/permit verifier.
            ||decision.source==DecisionSource::AiAssisted
                &&(base.source!=DecisionSource::RuleOnly||baseline.advice.is_some())
            ||actual.domain!=snap.domain||reference.domain!=snap.domain
            ||report.completed_ns<actual.first_ns||report.completed_ns>actual.closing_ns
            ||base_report.completed_ns<reference.first_ns||base_report.completed_ns>reference.closing_ns
        {
            return Err(Error::Denied);
        }
        let action = ActionV2::decode(snap.domain, 1, report.action)?;
        let mut bytes = [0; 6];
        let n = action.encode(snap.domain, &mut bytes)?;
        // Current ActionSchema v2 canonical payload lengths, not historical features.
        let (a1, a2) = match snap.domain {
            3 => (
                u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Invalid)?) as u64,
                Some(u16::from_le_bytes([bytes[4], bytes[5]]) as u64),
            ),
            4 => (
                u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
                Some(u16::from_le_bytes([bytes[2], bytes[3]]) as u64),
            ),
            5 => (
                u16::from_le_bytes([bytes[0], bytes[1]]) as u64,
                Some(bytes[2] as u64),
            ),
            _ if n == 1 => (bytes[0] as u64, None),
            _ if n == 2 => (u16::from_le_bytes([bytes[0], bytes[1]]) as u64, None),
            _ => return Err(Error::Invalid),
        };
        let input = operations_features(&snap, Candidate { a1, a2, cpu })
            .map_err(|_| Error::Invalid)?
            .values;
        let candidate_receipt = feedback.evidence_digest();
        let baseline_receipt = baseline.evidence_digest();
        if candidate_receipt == baseline_receipt {
            return Err(Error::Denied);
        }
        let pair = verify_archived_pair(
            &group,
            &schemas,
            candidates,
            baseline_candidates,
            feedback,
            baseline,
            &actual,
            &reference,
            cpu,
        )?;
        if pair == [0; 32] {
            return Err(Error::Denied);
        }
        let reward = reward_v2::compute(actual, reference, workspace).map_err(|_| Error::Denied)?;
        Ok(Self {
            group,
            schemas,
            domain: snap.domain,
            input,
            reward,
            candidate_receipt,
            baseline_receipt,
            pair,
        })
    }
    pub fn reward(&self) -> Reward {
        self.reward
    }
}
/// Both sides of a paired replay must be checked against their own
/// immutable candidate table and exact causal envelope, before asking the
/// independent archive verifier to authenticate the native trace.
fn checked_feedback<'a>(
    f: &'a FeedbackRecord,
    candidates: &FrozenCandidates,
) -> Result<(DecisionRecordV3, ApplyReportV1<'a>), Error> {
    let n = usize::from(f.report_len);
    if n > super::apply_report_v1::MAX_APPLY_REPORT_BYTES || f.report[n..].iter().any(|&v| v != 0) {
        return Err(Error::Invalid);
    }
    let d = DecisionRecordV3::decode(&f.decision)?;
    let r = ApplyReportV1::decode(f.report_bytes())?;
    if r.state != ActionStatus::Applied
        || r.key.boot_epoch != d.boot_epoch
        || r.key.controller_epoch != d.controller_epoch
        || r.key.plan_seq != d.plan_seq
        || r.action_index != d.action_index
        || r.domain_id != d.domain_id
        || r.target
            != (Identity {
                id: d.target_id,
                generation: d.target_generation,
            })
    {
        return Err(Error::Denied);
    }
    let snap = candidates.snapshot();
    if d.boot_epoch != snap.boot_epoch
        || d.snapshot_seq != snap.snapshot_seq
        || d.target_id != snap.target_id
        || d.target_generation != snap.target_generation
        || d.ledger_generation != snap.ledger_generation
        || d.core_generation != snap.core_generation
        || d.domain_id != snap.domain
        || d.candidate_set_hash != candidates.digest()
        || !d.matches_candidate_count(candidates.ordinals().len())
    {
        return Err(Error::Denied);
    }
    let view = candidates.view();
    if view.selected(d.selected_index)?.action_payload != r.action {
        return Err(Error::Denied);
    }
    let needs_pair = d.source == DecisionSource::AiAssisted || d.reason_code == 7;
    match &f.advice {
        Some((a, disp)) if needs_pair => {
            AdviceDispositionV1::decode(disp)?.matches_decision_pair(
                d.boot_epoch,
                a,
                &f.decision,
            )?;
        }
        None if !needs_pair => {}
        _ => return Err(Error::Denied),
    }
    let label = if d.source == DecisionSource::AiAssisted {
        if d.selected_index == d.fallback_index {
            CausalLabel::AdoptedSameFallback
        } else {
            CausalLabel::AdoptedDifferentFallback
        }
    } else {
        CausalLabel::NoAdoption
    };
    if f.causal_label != label {
        return Err(Error::Denied);
    }
    Ok((d, r))
}
fn split_ok(samples: &[Sample], schemas: SchemaBinding, minimum: usize) -> Result<(), Error> {
    if !schemas.valid() || samples.len() > MAX_SAMPLES {
        return Err(Error::Invalid);
    }
    let mut count = [0usize; 15];
    for (i, s) in samples.iter().enumerate() {
        if s.schemas != schemas
            || !(1..=15).contains(&s.domain)
            || s.pair == [0; 32]
            || samples[..i].iter().any(|p| duplicates(p, s))
        {
            return Err(Error::Denied);
        }
        count[usize::from(s.domain - 1)] += 1;
    }
    if count.iter().any(|n| *n < minimum) {
        return Err(Error::NotReady);
    }
    Ok(())
}
fn duplicates(a: &Sample, b: &Sample) -> bool {
    a.pair == b.pair
        || [a.candidate_receipt, a.baseline_receipt]
            .iter()
            .any(|h| *h == b.candidate_receipt || *h == b.baseline_receipt)
}
fn digest(samples: &[Sample], schemas: SchemaBinding) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYX/LEARNING-DATA/v0199");
    for v in [
        schemas.feature,
        schemas.action,
        schemas.reward,
        schemas.learning,
    ] {
        h.update(v);
    }
    h.update((samples.len() as u32).to_le_bytes());
    for s in samples {
        h.update(s.group.seed.to_le_bytes());
        h.update(s.group.workload);
        h.update(s.group.initial_image);
        h.update(s.domain.to_le_bytes());
        for x in s.input {
            h.update(x.to_le_bytes());
        }
        h.update(s.reward.value.to_bits().to_le_bytes());
        h.update(s.pair);
        h.update(s.candidate_receipt);
        h.update(s.baseline_receipt);
    }
    h.finalize().into()
}
pub struct TrainingData<'a> {
    rows: &'a [Sample],
    schemas: SchemaBinding,
    hash: [u8; 32],
}
impl<'a> TrainingData<'a> {
    pub fn freeze(rows: &'a [Sample], schemas: SchemaBinding) -> Result<Self, Error> {
        split_ok(rows, schemas, 8)?;
        Ok(Self {
            rows,
            schemas,
            hash: digest(rows, schemas),
        })
    }
}
pub struct Trainer<'a> {
    data: TrainingData<'a>,
    layer: LastLayer<'a>,
    parent: [u8; 32],
    learner: Identity,
}
pub struct CandidateModel {
    bytes: [u8; MODEL_BYTES],
    parent: [u8; 32],
    data: [u8; 32],
    schemas: SchemaBinding,
    learner: Identity,
}
impl CandidateModel {
    pub fn bytes(&self) -> &[u8; MODEL_BYTES] {
        &self.bytes
    }
    pub fn learner(&self) -> Identity {
        self.learner
    }
}
impl<'a> Trainer<'a> {
    pub fn start(
        data: TrainingData<'a>,
        active: &'a [u8; MODEL_BYTES],
        learner: Identity,
        verify_active: impl FnOnce(Identity, &[u8; MODEL_BYTES], SchemaBinding) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if !learner.valid() {
            return Err(Error::Denied);
        }
        verify_active(learner, active, data.schemas)?;
        let layer = LastLayer::start(active, data.rows.len()).map_err(|_| Error::Invalid)?;
        Ok(Self {
            data,
            layer,
            parent: Sha256::digest(active).into(),
            learner,
        })
    }
    /// Exactly one ordered arithmetic step. The native owner must charge
    /// actual elapsed CPU including the invocation, never just the grant.
    pub fn step(
        &mut self,
        actor: Identity,
        verify_credit: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if actor != self.learner {
            return Err(Error::Denied);
        }
        let s = self
            .data
            .rows
            .get(self.layer.completed())
            .ok_or(Error::Stale)?;
        verify_credit()?;
        self.layer
            .step(&s.input, s.reward.value)
            .map_err(|_| Error::Invalid)
    }
    pub fn finish(self) -> Result<CandidateModel, Error> {
        Ok(CandidateModel {
            bytes: self.layer.finish().map_err(|_| Error::NotReady)?,
            parent: self.parent,
            data: self.data.hash,
            schemas: self.data.schemas,
            learner: self.learner,
        })
    }
}
/// Bounded consumed experiment groups. The protected storage owner must
/// authenticate the entire recovered history before validation opens.
/// An ambiguous consume write blocks the ledger until independently restored.
/// This is internal custody, NOT a new on-disk ABI or a FLUSH implementation.
pub struct Holdouts {
    used: [Option<ReplayGroup>; MAX_SAMPLES],
    len: usize,
    blocked: bool,
    history_digest: [u8; 32],
    claims: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationEvidence {
    pub candidate: [u8; 32],
    pub parent: [u8; 32],
    pub training: [u8; 32],
    pub holdout: [u8; 32],
}
/// Unforgeable in safe Rust outside this module. This proves the current
/// independent integer-model MSE check, not Shadow/Canary or promotion.
/// Production adapter must retain this exact binding and authenticate
/// the actual validator, learner and model manager before evaluation.
#[derive(Debug)]
pub struct ValidatedCandidate {
    binding: ValidationEvidence,
    learner: Identity,
    validator: Identity,
    manager: Identity,
    claim_sequence: u64,
    claim_head: [u8; 32],
}
impl ValidatedCandidate {
    pub fn binding(&self) -> ValidationEvidence {
        self.binding
    }
    pub fn authorize_shadow(
        &self,
        manager: Identity,
        current_active: [u8; 32],
        candidate: &CandidateModel,
        verify_current: impl FnOnce(
            Identity,
            Identity,
            u64,
            [u8; 32],
            ValidationEvidence,
        ) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if manager != self.manager
            || candidate.learner != self.learner
            || current_active != self.binding.parent
            || <[u8; 32]>::from(Sha256::digest(candidate.bytes)) != self.binding.candidate
            || candidate.data != self.binding.training
        {
            return Err(Error::Denied);
        }
        // Read-only preflight, not a state transition. Must independently
        // prove retained validation, current schema and manager capability.
        verify_current(
            self.learner,
            self.validator,
            self.claim_sequence,
            self.claim_head,
            self.binding,
        )
    }
}
/// Independent Shadow observation of one complete aligned 100ms
/// window. The protected metering/evidence owner must authenticate every
/// scoring trace and prove that Shadow never published any action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShadowWindow {
    pub window: u64,
    pub domains: u16,
    pub optional_cpu_ns: u64,
    pub evidence: [u8; 32],
}
pub struct ShadowGate {
    manager: Identity,
    boot: u64,
    active_generation: u64,
    binding: ValidationEvidence,
    claim_head: [u8; 32],
    next_window: u64,
    windows: u64,
    domains: u16,
    head: [u8; 32],
    closed: bool,
}
/// Preflight evidence for the manager's separate D15 TrialPermit grant.
/// This is not an action authorization or an Active model transition.
#[derive(Debug)]
pub struct ShadowReady {
    boot: u64,
    active_generation: u64,
    binding: ValidationEvidence,
    claim_head: [u8; 32],
    evidence: [u8; 32],
    target: Identity,
}
impl ShadowReady {
    /// Read-only evidence projection; only the independent gate can
    /// construct this token. A manager still needs a real trial permit.
    pub fn scope(&self) -> (u64, u64, ValidationEvidence, [u8; 32], [u8; 32], Identity) {
        (
            self.boot,
            self.active_generation,
            self.binding,
            self.claim_head,
            self.evidence,
            self.target,
        )
    }
}
impl ShadowGate {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        proof: ValidatedCandidate,
        manager: Identity,
        boot: u64,
        active_generation: u64,
        active: [u8; 32],
        candidate: &CandidateModel,
        first_window: u64,
        verify_current: impl FnOnce(
            Identity,
            Identity,
            u64,
            [u8; 32],
            ValidationEvidence,
        ) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if boot == 0 || active_generation == 0 || first_window.checked_add(10).is_none() {
            return Err(Error::Invalid);
        }
        proof.authorize_shadow(manager, active, candidate, verify_current)?;
        let mut h = Sha256::new();
        h.update(b"CYX/SHADOW/v0199");
        h.update(boot.to_le_bytes());
        h.update(active_generation.to_le_bytes());
        h.update(proof.binding.candidate);
        h.update(proof.claim_head);
        h.update(first_window.to_le_bytes());
        Ok(Self {
            manager,
            boot,
            active_generation,
            binding: proof.binding,
            claim_head: proof.claim_head,
            next_window: first_window,
            windows: 0,
            domains: 0,
            head: h.finalize().into(),
            closed: false,
        })
    }
    pub fn abort(&mut self) {
        self.closed = true;
    }
    #[allow(clippy::too_many_arguments)]
    pub fn record_window(
        &mut self,
        manager: Identity,
        boot: u64,
        active_generation: u64,
        active: [u8; 32],
        candidate: [u8; 32],
        now: u64,
        e: ShadowWindow,
        verify_native: impl FnOnce(&ShadowWindow) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if manager != self.manager {
            return Err(Error::Denied);
        }
        if self.closed {
            return Err(Error::NotReady);
        }
        if boot != self.boot
            || active_generation != self.active_generation
            || active != self.binding.parent
            || candidate != self.binding.candidate
        {
            return Err(Error::Stale);
        }
        let end = e
            .window
            .checked_add(1)
            .and_then(|w| w.checked_mul(100_000_000))
            .ok_or(Error::Clock)?;
        if e.window != self.next_window
            || now < end
            || e.domains == 0
            || e.domains & !0x7fff != 0
            || e.optional_cpu_ns == 0
            || e.optional_cpu_ns > 8_500_000
            || e.evidence == [0; 32]
        {
            return Err(Error::Denied);
        }
        // Must check actual optional-class shared ledger and that every
        // scoring operation was read-only. A claimed scalar is not proof.
        verify_native(&e)?;
        let mut h = Sha256::new();
        h.update(self.head);
        h.update(e.window.to_le_bytes());
        h.update(e.domains.to_le_bytes());
        h.update(e.optional_cpu_ns.to_le_bytes());
        h.update(e.evidence);
        self.head = h.finalize().into();
        self.domains |= e.domains;
        self.windows += 1;
        self.next_window += 1;
        Ok(())
    }
    pub fn seal_canary_preflight(
        self,
        manager: Identity,
        boot: u64,
        generation: u64,
        active: [u8; 32],
        target: Identity,
        verify_target_and_history: impl FnOnce(Identity, [u8; 32]) -> Result<(), Error>,
    ) -> Result<ShadowReady, Error> {
        if manager != self.manager
            || boot != self.boot
            || generation != self.active_generation
            || active != self.binding.parent
            || !target.valid()
        {
            return Err(Error::Denied);
        }
        if self.closed || self.windows < 10 || self.domains != 0x7fff {
            return Err(Error::NotReady);
        }
        // Must be the one actual offline-registered noncritical D15
        // target. This does not create or spend a TrialPermit.
        verify_target_and_history(target, self.head)?;
        Ok(ShadowReady {
            boot: self.boot,
            active_generation: self.active_generation,
            binding: self.binding,
            claim_head: self.claim_head,
            evidence: self.head,
            target,
        })
    }
}
pub struct HoldoutClaim<'a> {
    pub sequence: u64,
    pub prior_history: [u8; 32],
    pub next_history: [u8; 32],
    pub binding: ValidationEvidence,
    pub learner: Identity,
    pub validator: Identity,
    pub groups: &'a [Option<ReplayGroup>],
}
/// An authenticated archive supplies ordered claim metadata and its
/// complete group ranges. This is an internal projection, not a new media
/// encoding. Each claim consumes its groups even when evaluation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredClaim {
    pub sequence: u64,
    pub binding: ValidationEvidence,
    pub learner: Identity,
    pub validator: Identity,
    pub first: usize,
    pub count: usize,
    pub history_digest: [u8; 32],
}
fn genesis() -> [u8; 32] {
    Sha256::digest(b"CYX/HOLDOUT-HISTORY/v0199").into()
}
fn claim_digest(
    prior: [u8; 32],
    sequence: u64,
    binding: ValidationEvidence,
    learner: Identity,
    validator: Identity,
    count: usize,
    groups: impl Iterator<Item = ReplayGroup>,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYX/HOLDOUT-CLAIM/v0199");
    h.update(prior);
    h.update(sequence.to_le_bytes());
    for b in [
        binding.candidate,
        binding.parent,
        binding.training,
        binding.holdout,
    ] {
        h.update(b);
    }
    for a in [learner, validator] {
        h.update(a.id.to_le_bytes());
        h.update(a.generation.to_le_bytes());
    }
    h.update((count as u64).to_le_bytes());
    for g in groups {
        h.update(g.seed.to_le_bytes());
        h.update(g.workload);
        h.update(g.initial_image);
    }
    h.finalize().into()
}
impl Holdouts {
    /// Verify the complete append-only recovered group history, including
    /// a legitimate empty genesis. Caller must authenticate recovery and
    /// prove no consumed group was omitted; a bare empty slice is not proof.
    #[cfg(test)]
    fn restore(
        groups: &[ReplayGroup],
        verify_history: impl FnOnce(&[ReplayGroup]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if groups.len() > MAX_SAMPLES {
            return Err(Error::Exhausted);
        }
        for (i, g) in groups.iter().enumerate() {
            if g.workload == [0; 32] || g.initial_image == [0; 32] || groups[..i].contains(g) {
                return Err(Error::Denied);
            }
        }
        verify_history(groups)?;
        let mut out = Self {
            used: [None; MAX_SAMPLES],
            len: groups.len(),
            blocked: false,
            history_digest: genesis(),
            claims: 0,
        };
        for (i, g) in groups.iter().enumerate() {
            out.used[i] = Some(*g);
        }
        Ok(out)
    }
    /// Recover the complete claim chain, not just spent group IDs. Refuse
    /// gaps, overlaps, altered ordering, same-principal validation, or a
    /// claimed suffix without its authenticated prefix. The native callback
    /// must verify actual persistent archive custody and terminal head.
    pub fn restore_claims(
        groups: &[ReplayGroup],
        claims: &[RecoveredClaim],
        expected_head: [u8; 32],
        verify_history: impl FnOnce(&[ReplayGroup], &[RecoveredClaim], [u8; 32]) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if groups.len() > MAX_SAMPLES || claims.len() > groups.len() {
            return Err(Error::Exhausted);
        }
        for (i, g) in groups.iter().enumerate() {
            if g.workload == [0; 32] || g.initial_image == [0; 32] || groups[..i].contains(g) {
                return Err(Error::Denied);
            }
        }
        let mut cursor = 0usize;
        let mut head = genesis();
        for (i, c) in claims.iter().enumerate() {
            if c.sequence != i as u64 + 1
                || c.first != cursor
                || c.count == 0
                || !c.learner.valid()
                || !c.validator.valid()
                || c.learner.id == c.validator.id
                || [
                    c.binding.candidate,
                    c.binding.parent,
                    c.binding.training,
                    c.binding.holdout,
                ]
                .contains(&[0; 32])
            {
                return Err(Error::Denied);
            }
            let end = cursor.checked_add(c.count).ok_or(Error::Exhausted)?;
            let range = groups.get(cursor..end).ok_or(Error::Denied)?;
            head = claim_digest(
                head,
                c.sequence,
                c.binding,
                c.learner,
                c.validator,
                c.count,
                range.iter().copied(),
            );
            if head != c.history_digest {
                return Err(Error::Denied);
            }
            cursor = end;
        }
        if cursor != groups.len() || head != expected_head {
            return Err(Error::Denied);
        }
        verify_history(groups, claims, head)?;
        let mut out = Self {
            used: [None; MAX_SAMPLES],
            len: groups.len(),
            blocked: false,
            history_digest: head,
            claims: claims.len() as u64,
        };
        for (i, g) in groups.iter().enumerate() {
            out.used[i] = Some(*g);
        }
        Ok(out)
    }
    pub fn history(&self) -> (u64, [u8; 32]) {
        (self.claims, self.history_digest)
    }
    #[cfg(test)]
    fn new() -> Self {
        Self::restore_claims(&[], &[], genesis(), |_, _, _| Ok(())).unwrap()
    }
    /// Role-specific entry: unauthorized callers cannot burn a valid
    /// holdout before the independent preflight. No validation result
    /// can be converted into a manager grant by a learner.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_registered(
        &mut self,
        manifest: &super::role_manifest_v0199::NativeRoleManifest,
        manager: Identity,
        validator: Identity,
        active: &[u8; MODEL_BYTES],
        model: &CandidateModel,
        training: &TrainingData<'_>,
        holdout: &[Sample],
        authenticate: impl FnOnce(Identity, Identity, Identity) -> Result<(), Error>,
        commit_consumption: impl FnOnce(&HoldoutClaim<'_>) -> Result<(), Error>,
        verify_native: impl FnOnce(
            Identity,
            &[u8; MODEL_BYTES],
            &CandidateModel,
            &[Sample],
        ) -> Result<(), Error>,
    ) -> Result<ValidatedCandidate, Error> {
        use super::role_manifest_v0199::{
            CANDIDATE_SUBMIT, MODEL_MANAGE, Role, VALIDATION_REGISTER,
        };
        manifest.can_act(Role::ModelManager, manager, MODEL_MANAGE, 0)?;
        manifest.can_act(Role::Validator, validator, VALIDATION_REGISTER, 0)?;
        manifest.can_act(Role::Learner, model.learner, CANDIDATE_SUBMIT, 0)?;
        authenticate(manager, validator, model.learner)?;
        let binding = self.validate(
            validator,
            active,
            model,
            training,
            holdout,
            commit_consumption,
            verify_native,
        )?;
        Ok(ValidatedCandidate {
            binding,
            learner: model.learner,
            validator,
            manager,
            claim_sequence: self.claims,
            claim_head: self.history_digest,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn validate(
        &mut self,
        validator: Identity,
        active: &[u8; MODEL_BYTES],
        model: &CandidateModel,
        training: &TrainingData<'_>,
        holdout: &[Sample],
        commit_consumption: impl FnOnce(&HoldoutClaim<'_>) -> Result<(), Error>,
        verify_native: impl FnOnce(
            Identity,
            &[u8; MODEL_BYTES],
            &CandidateModel,
            &[Sample],
        ) -> Result<(), Error>,
    ) -> Result<ValidationEvidence, Error> {
        if self.blocked {
            return Err(Error::NotReady);
        }
        // Independent validation must not be performed by the training
        // identity, including a restart with a new generation. The native
        // verifier still authenticates both registered role capabilities.
        if !validator.valid()
            || validator.id == model.learner.id
            || model.schemas != training.schemas
            || model.data != training.hash
            || model.parent != <[u8; 32]>::from(Sha256::digest(active))
            || !sgd_v2::frozen_equal(active, &model.bytes)
        {
            return Err(Error::Denied);
        }
        split_ok(holdout, training.schemas, 4)?;
        let mut n = 0;
        for (i, s) in holdout.iter().enumerate() {
            if training
                .rows
                .iter()
                .any(|t| t.group == s.group || duplicates(t, s))
                || self.used[..self.len].contains(&Some(s.group))
            {
                return Err(Error::Denied);
            }
            if !holdout[..i].iter().any(|t| t.group == s.group) {
                n += 1;
            }
        }
        if n > MAX_SAMPLES - self.len {
            return Err(Error::Exhausted);
        }
        let sequence = self.claims.checked_add(1).ok_or(Error::Exhausted)?;
        let first = self.len;
        let binding = ValidationEvidence {
            candidate: Sha256::digest(model.bytes).into(),
            parent: model.parent,
            training: model.data,
            holdout: digest(holdout, training.schemas),
        };
        for (i, s) in holdout.iter().enumerate() {
            if !holdout[..i].iter().any(|t| t.group == s.group) {
                self.used[self.len] = Some(s.group);
                self.len += 1;
            }
        }
        // Consume BEFORE exposing the holdout to evaluation. The native
        // owner must commit the exact candidate/group binding and verify
        // durable completion. Any error is conservatively ambiguous.
        let prior_history = self.history_digest;
        let next_history = claim_digest(
            prior_history,
            sequence,
            binding,
            model.learner,
            validator,
            n,
            self.used[first..self.len].iter().flatten().copied(),
        );
        self.blocked = true;
        commit_consumption(&HoldoutClaim {
            sequence,
            prior_history,
            next_history,
            binding,
            learner: model.learner,
            validator,
            groups: &self.used[first..self.len],
        })?;
        self.claims = sequence;
        self.history_digest = next_history;
        self.blocked = false;
        verify_native(validator, active, model, holdout)?;
        sgd_v2::operator_selftest().map_err(|_| Error::Denied)?;
        let old = Model::parse(active).map_err(|_| Error::Invalid)?;
        let new = Model::parse(&model.bytes).map_err(|_| Error::Invalid)?;
        let mut totals = [[F64::ZERO; 16]; 2];
        let mut counts = [0u64; 16];
        for s in holdout {
            let i = usize::from(s.domain - 1);
            counts[i] += 1;
            counts[15] += 1;
            for (k, score) in [old.score(&s.input), new.score(&s.input)]
                .into_iter()
                .enumerate()
            {
                let prediction = F64::from_i64(i64::from(score))
                    .div(F64::from_u64(256))
                    .map_err(|_| Error::Invalid)?;
                let e = prediction.sub(s.reward.value).map_err(|_| Error::Invalid)?;
                let square = e.mul(e).map_err(|_| Error::Invalid)?;
                totals[k][i] = totals[k][i].add(square).map_err(|_| Error::Invalid)?;
                totals[k][15] = totals[k][15].add(square).map_err(|_| Error::Invalid)?;
            }
        }
        let tolerance = F64::ONE
            .div(F64::from_u64(65536))
            .map_err(|_| Error::Invalid)?;
        for i in 0..16 {
            let divisor = F64::from_u64(counts[i]);
            let a = totals[0][i].div(divisor).map_err(|_| Error::Invalid)?;
            let b = totals[1][i].div(divisor).map_err(|_| Error::Invalid)?;
            let bound = if i == 15 {
                a
            } else {
                a.add(tolerance).map_err(|_| Error::Invalid)?
            };
            if b.compare(bound).is_gt() {
                return Err(Error::Denied);
            }
        }
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyxia_control_model::reward_v2::{Cost, Metrics, Performance};
    // Synthetic component fixtures exercise custody arithmetic only.
    // They cannot enter Sample::capture or supply native verdict evidence.
    const SCHEMAS: SchemaBinding = SchemaBinding {
        feature: [1; 32],
        action: [2; 32],
        reward: [3; 32],
        learning: [4; 32],
    };
    fn id(n: u64) -> [u8; 32] {
        let mut b = [0; 32];
        b[..8].copy_from_slice(&n.to_le_bytes());
        b
    }
    fn sample(i: usize, per_domain: usize, offset: u64) -> Sample {
        let metrics = Metrics {
            performance: Performance {
                emitted: 100,
                completed: 100,
                rejected: 0,
                timed_out: 0,
                pending: 0,
                penalty_p99_ns: 1,
                actual_p99_ns: Some(1),
            },
            cost: Cost {
                union_ns: 0,
                by_class: [0; 3],
                raw_tagged: [0; 3],
            },
        };
        let key = offset + i as u64;
        Sample {
            group: ReplayGroup {
                seed: key,
                workload: [1; 32],
                initial_image: [2; 32],
            },
            schemas: SCHEMAS,
            domain: (i / per_domain + 1) as u16,
            input: [0; 64],
            reward: Reward {
                candidate: metrics,
                baseline: metrics,
                delta_x: F64::ZERO,
                delta_l: F64::ZERO,
                raw_cost: F64::ZERO,
                clipped_cost: F64::ZERO,
                value: F64::ZERO,
            },
            candidate_receipt: id(key * 3),
            baseline_receipt: id(key * 3 + 1),
            pair: id(key * 3 + 2),
        }
    }
    #[test]
    fn both_replay_sides_require_exact_frozen_action_and_causal_evidence() {
        use crate::control_plane::{
            apply_report_v1::{MAX_APPLY_REPORT_BYTES, PlanKey},
            candidate_registry_v0199::CatalogEntry,
        };
        use cyxia_control_model::native_v0199::SnapshotReplyV3;
        let snapshot = SnapshotReplyV3 {
            snapshot_seq: 1,
            boot_epoch: 1,
            ledger_generation: 2,
            core_generation: 3,
            target_id: 15,
            target_generation: 1,
            sampled_ns: 10,
            domain: 15,
            fields: [
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(20),
                Some(0),
                Some(1),
                Some(1),
            ],
        };
        let values = ActionV2::values(15).unwrap();
        let catalog: [CatalogEntry; 4] = core::array::from_fn(|i| CatalogEntry {
            ordinal: i as u16,
            value: values[i],
        });
        let capture = |snap| {
            FrozenCandidates::capture(
                snap,
                &catalog,
                [1; 32],
                values[1],
                Some(20),
                Some(true),
                false,
                |_, _| Ok(()),
                |_| Ok(true),
            )
            .unwrap()
        };
        let cand = capture(snapshot);
        let baseline = capture(SnapshotReplyV3 {
            boot_epoch: 2,
            ..snapshot
        });
        let make = |c: &FrozenCandidates| {
            let snap = c.snapshot();
            let mut d = [0u8; 256];
            d[..4].copy_from_slice(&0x43594431u32.to_le_bytes());
            d[4..6].copy_from_slice(&3u16.to_le_bytes());
            d[6..8].copy_from_slice(&256u16.to_le_bytes());
            for (at, v) in [
                (8, snap.boot_epoch),
                (16, 1),
                (24, 1),
                (32, 1),
                (40, 1),
                (48, 15),
                (56, 1),
                (64, 2),
                (72, 3),
                (80, 1),
                (144, 100),
            ] {
                d[at..at + 8].copy_from_slice(&v.to_le_bytes());
            }
            d[88..92].copy_from_slice(&1u32.to_le_bytes());
            d[94..96].copy_from_slice(&15u16.to_le_bytes());
            d[96..98].copy_from_slice(&1u16.to_le_bytes());
            d[102..104].copy_from_slice(&1u16.to_le_bytes());
            d[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
            d[108..112].copy_from_slice(&2u32.to_le_bytes());
            d[152..156].copy_from_slice(&2u32.to_le_bytes());
            d[156..158].copy_from_slice(&1u16.to_le_bytes());
            d[160..192].fill(2);
            d[192..224].fill(3);
            d[224..].copy_from_slice(&c.digest());
            let mut report = [0; MAX_APPLY_REPORT_BYTES];
            let n = ApplyReportV1 {
                key: PlanKey {
                    boot_epoch: snap.boot_epoch,
                    controller_epoch: 1,
                    plan_seq: 1,
                },
                action_index: 0,
                domain_id: 15,
                state: ActionStatus::Applied,
                target: Identity {
                    id: 15,
                    generation: 1,
                },
                executor_generation: 1,
                plan_version: 1,
                result: 0,
                completed_ns: 50,
                action: &[8, 0],
            }
            .encode(&mut report)
            .unwrap();
            FeedbackRecord {
                decision: d,
                report,
                report_len: n as u16,
                causal_label: CausalLabel::NoAdoption,
                advice: None,
            }
        };
        let good = make(&cand);
        let base = make(&baseline);
        assert!(checked_feedback(&good, &cand).is_ok());
        assert!(checked_feedback(&base, &baseline).is_ok());
        assert!(matches!(checked_feedback(&base, &cand), Err(Error::Denied)));
        let mut bad = base;
        bad.report[96] = 32;
        assert!(matches!(
            checked_feedback(&bad, &baseline),
            Err(Error::Denied)
        ));
        let mut bad = base;
        bad.causal_label = CausalLabel::AdoptedDifferentFallback;
        assert!(matches!(
            checked_feedback(&bad, &baseline),
            Err(Error::Denied)
        ));
        let mut bad = base;
        bad.report[351] = 1;
        assert!(matches!(
            checked_feedback(&bad, &baseline),
            Err(Error::Invalid)
        ));
        let mut bad = base;
        bad.decision[108..112].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            checked_feedback(&bad, &baseline),
            Err(Error::Denied)
        ));
    }
    #[test]
    fn shadow_requires_complete_windows_and_all_families_before_canary_preflight() {
        let learner = Identity {
            id: 10,
            generation: 1,
        };
        let validator = Identity {
            id: 9,
            generation: 1,
        };
        let manager = Identity {
            id: 3,
            generation: 1,
        };
        let target = Identity {
            id: 15,
            generation: 1,
        };
        let model = CandidateModel {
            bytes: [0; MODEL_BYTES],
            parent: [2; 32],
            data: [3; 32],
            schemas: SCHEMAS,
            learner,
        };
        let binding = ValidationEvidence {
            candidate: Sha256::digest(model.bytes).into(),
            parent: model.parent,
            training: model.data,
            holdout: [4; 32],
        };
        let proof = || ValidatedCandidate {
            binding,
            learner,
            validator,
            manager,
            claim_sequence: 1,
            claim_head: [5; 32],
        };
        let new = || {
            ShadowGate::start(
                proof(),
                manager,
                1,
                7,
                model.parent,
                &model,
                2,
                |_, _, _, _, _| Ok(()),
            )
            .unwrap()
        };
        assert!(matches!(
            new().seal_canary_preflight(manager, 1, 7, model.parent, target, |_, _| panic!()),
            Err(Error::NotReady)
        ));
        let mut g = new();
        let e = ShadowWindow {
            window: 2,
            domains: 1,
            optional_cpu_ns: 100,
            evidence: [6; 32],
        };
        assert_eq!(
            g.record_window(
                manager,
                1,
                7,
                model.parent,
                binding.candidate,
                299_999_999,
                e,
                |_| panic!()
            ),
            Err(Error::Denied)
        );
        assert_eq!(
            g.record_window(
                manager,
                1,
                8,
                model.parent,
                binding.candidate,
                300_000_000,
                e,
                |_| panic!()
            ),
            Err(Error::Stale)
        );
        assert_eq!(
            g.record_window(
                manager,
                1,
                7,
                model.parent,
                binding.candidate,
                300_000_000,
                ShadowWindow {
                    optional_cpu_ns: 8_500_001,
                    ..e
                },
                |_| panic!()
            ),
            Err(Error::Denied)
        );
        for w in 2..12 {
            let e = ShadowWindow {
                window: w,
                domains: if w == 11 { 0x7fff } else { 1 },
                ..e
            };
            g.record_window(
                manager,
                1,
                7,
                model.parent,
                binding.candidate,
                (w + 1) * 100_000_000,
                e,
                |_| Ok(()),
            )
            .unwrap();
        }
        let ready = g
            .seal_canary_preflight(manager, 1, 7, model.parent, target, |t, h| {
                assert_eq!(t, target);
                assert_ne!(h, [0; 32]);
                Ok(())
            })
            .unwrap();
        assert_eq!(ready.binding, binding);
    }
    #[test]
    fn shadow_preflight_binds_exact_candidate_and_independent_manager() {
        let learner = Identity {
            id: 10,
            generation: 1,
        };
        let validator = Identity {
            id: 9,
            generation: 1,
        };
        let manager = Identity {
            id: 3,
            generation: 1,
        };
        let model = CandidateModel {
            bytes: [0; MODEL_BYTES],
            parent: [2; 32],
            data: [3; 32],
            schemas: SCHEMAS,
            learner,
        };
        let binding = ValidationEvidence {
            candidate: Sha256::digest(model.bytes).into(),
            parent: model.parent,
            training: model.data,
            holdout: [4; 32],
        };
        let proof = ValidatedCandidate {
            binding,
            learner,
            validator,
            manager,
            claim_sequence: 1,
            claim_head: [5; 32],
        };
        assert_eq!(
            proof.authorize_shadow(learner, model.parent, &model, |_, _, _, _, _| panic!()),
            Err(Error::Denied)
        );
        assert_eq!(
            proof.authorize_shadow(manager, [9; 32], &model, |_, _, _, _, _| panic!()),
            Err(Error::Denied)
        );
        assert_eq!(
            proof.authorize_shadow(manager, model.parent, &model, |_, _, _, _, _| Err(
                Error::NotReady
            )),
            Err(Error::NotReady)
        );
        proof
            .authorize_shadow(manager, model.parent, &model, |l, v, seq, head, b| {
                assert_eq!(
                    (l, v, seq, head, b),
                    (learner, validator, 1, [5; 32], binding)
                );
                Ok(())
            })
            .unwrap();
    }
    #[test]
    fn complete_claim_history_cannot_lose_identity_or_consumed_prefix() {
        let groups: [ReplayGroup; 2] = core::array::from_fn(|i| sample(i, 1, 1000).group);
        let learner = Identity {
            id: 10,
            generation: 1,
        };
        let validator = Identity {
            id: 9,
            generation: 1,
        };
        let binding = ValidationEvidence {
            candidate: [1; 32],
            parent: [2; 32],
            training: [3; 32],
            holdout: [4; 32],
        };
        let head = claim_digest(
            genesis(),
            1,
            binding,
            learner,
            validator,
            2,
            groups.iter().copied(),
        );
        let claim = RecoveredClaim {
            sequence: 1,
            binding,
            learner,
            validator,
            first: 0,
            count: 2,
            history_digest: head,
        };
        let ledger = Holdouts::restore_claims(&groups, &[claim], head, |g, c, h| {
            assert_eq!(g, &groups);
            assert_eq!(c, &[claim]);
            assert_eq!(h, head);
            Ok(())
        })
        .unwrap();
        assert_eq!(ledger.history(), (1, head));
        assert_eq!(ledger.len, 2);
        assert!(matches!(
            Holdouts::restore_claims(&groups, &[], head, |_, _, _| panic!()),
            Err(Error::Denied)
        ));
        assert!(matches!(
            Holdouts::restore_claims(
                &groups,
                &[RecoveredClaim {
                    validator: Identity {
                        generation: 2,
                        ..learner
                    },
                    ..claim
                }],
                head,
                |_, _, _| panic!()
            ),
            Err(Error::Denied)
        ));
        assert!(matches!(
            Holdouts::restore_claims(&[groups[1], groups[0]], &[claim], head, |_, _, _| panic!()),
            Err(Error::Denied)
        ));
        assert!(matches!(
            Holdouts::restore_claims(&groups, &[claim], head, |_, _, _| Err(Error::NotReady)),
            Err(Error::NotReady)
        ));
    }
    #[test]
    fn per_domain_minimum_and_duplicate_evidence() {
        let mut rows: [Sample; 120] = core::array::from_fn(|i| sample(i, 8, 100));
        assert!(TrainingData::freeze(&rows, SCHEMAS).is_ok());
        assert!(matches!(
            TrainingData::freeze(&rows[..119], SCHEMAS),
            Err(Error::NotReady)
        ));
        rows[119].baseline_receipt = rows[0].candidate_receipt;
        assert!(matches!(
            TrainingData::freeze(&rows, SCHEMAS),
            Err(Error::Denied)
        ));
    }
    #[test]
    fn ordered_training_and_holdout_consumed_even_on_failed_verifier() {
        let rows: [Sample; 120] = core::array::from_fn(|i| sample(i, 8, 100));
        let mut holdout: [Sample; 60] = core::array::from_fn(|i| sample(i, 4, 1000));
        let active = [0u8; MODEL_BYTES];
        let actor = Identity {
            id: 10,
            generation: 1,
        };
        let validator = Identity {
            id: 11,
            generation: 1,
        };
        let mut trainer = Trainer::start(
            TrainingData::freeze(&rows, SCHEMAS).unwrap(),
            &active,
            actor,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(trainer.step(validator, || panic!()), Err(Error::Denied));
        for _ in 0..120 {
            trainer.step(actor, || Ok(())).unwrap();
        }
        assert_eq!(trainer.step(actor, || panic!()), Err(Error::Stale));
        let model = trainer.finish().unwrap();
        let training = TrainingData::freeze(&rows, SCHEMAS).unwrap();
        let mut ledger = Holdouts::new();
        let group = holdout[0].group;
        assert_eq!(model.learner(), actor);
        // Deny self-validation before calling the native verifier or
        // consuming independent holdouts; a generation change is no bypass.
        for identity in [
            actor,
            Identity {
                id: actor.id,
                generation: actor.generation + 1,
            },
        ] {
            assert!(matches!(
                ledger.validate(
                    identity,
                    &active,
                    &model,
                    &training,
                    &holdout,
                    |_| panic!(),
                    |_, _, _, _| panic!()
                ),
                Err(Error::Denied)
            ));
        }
        assert_eq!(ledger.len, 0);
        holdout[0].group = rows[0].group;
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &holdout,
                |_| panic!(),
                |_, _, _, _| panic!()
            ),
            Err(Error::Denied)
        ));
        holdout[0].group = group;
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &holdout,
                |claim| {
                    assert_eq!(claim.groups.len(), 60);
                    Ok(())
                },
                |_, _, _, _| Err(Error::NotReady)
            ),
            Err(Error::NotReady)
        ));
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &holdout,
                |_| panic!(),
                |_, _, _, _| panic!()
            ),
            Err(Error::Denied)
        ));
        let fresh: [Sample; 60] = core::array::from_fn(|i| sample(i, 4, 2000));
        assert!(
            ledger
                .validate(
                    validator,
                    &active,
                    &model,
                    &training,
                    &fresh,
                    |_| Ok(()),
                    |_, _, _, _| Ok(())
                )
                .is_ok()
        );
        // Crash/ambiguous commit cannot open another holdout or run MSE.
        let next: [Sample; 60] = core::array::from_fn(|i| sample(i, 4, 3000));
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &next,
                |claim| {
                    assert_eq!(claim.learner, actor);
                    assert_eq!(claim.validator, validator);
                    assert_eq!(claim.groups.len(), 60);
                    Err(Error::NotReady)
                },
                |_, _, _, _| panic!()
            ),
            Err(Error::NotReady)
        ));
        assert!(ledger.blocked);
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &next,
                |_| panic!(),
                |_, _, _, _| panic!()
            ),
            Err(Error::NotReady)
        ));
        // Only authenticated recovery may reopen, preserving spent groups.
        let recovered: [ReplayGroup; 180] = core::array::from_fn(|i| ledger.used[i].unwrap());
        assert!(matches!(
            Holdouts::restore(&recovered, |_| Err(Error::NotReady)),
            Err(Error::NotReady)
        ));
        let mut ledger = Holdouts::restore(&recovered, |g| {
            assert_eq!(g.len(), 180);
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            ledger.validate(
                validator,
                &active,
                &model,
                &training,
                &next,
                |_| panic!(),
                |_, _, _, _| panic!()
            ),
            Err(Error::Denied)
        ));
        assert!(matches!(
            Holdouts::restore(&[group, group], |_| panic!()),
            Err(Error::Denied)
        ));
    }
}
