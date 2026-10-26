//! Sealed-candidate Shadow/Canary governance. The native integration must keep
//! one CommitGate in the same protected critical section used by Plan PUBLISH.
//! Pure operators and host fixtures do not constitute a running learning role.
use super::{
    Error, FAMILIES, Family,
    reward::{self, Performance, RewardWorkspace, WorkRequest},
    validate::{ValidatedCandidate, integer_reference},
};
use crate::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    features,
    model::{MODEL_BYTES, Model},
    policy::{CandidateSet, ExecutionState, ModelBinding},
};
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};
mod init;
pub use init::{GovernanceInit, InitComplete, InitPiece, InitValue};

// Credits are capabilities of one live ledger, not merely a serial number.
// Exhaustion never wraps to an earlier identity; that instance starts faulted.
static NEXT_LEDGER: AtomicU64 = AtomicU64::new(1);

pub const WINDOW_NS: u64 = 100_000_000;
pub const EXTRA_NS: u64 = 9_000_000;
pub const MANDATORY_NS: u64 = 61_000_000;
pub const CONTROL_NS: u64 = 70_000_000;
pub const MAX_SUBMISSIONS: usize = 300;
/// Final receipts/last-window verification after observation stops. This is
/// not an execution lease, another publication window or a TTL extension.
pub const CLOSING_NS: u64 = 50_000_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Training,
    Validation,
    Shadow,
    Canary,
}

/// Registered EL1 control-pool ownership and current C membership. A future
/// native adapter must implement this using the actual allocator/CPU ledger.
pub trait ControlAuthority {
    fn authorize(
        &self,
        role: Role,
        cpu: u16,
        core_generation: u64,
        workspace_bytes: u32,
    ) -> Result<(), Error>;
}
#[derive(Debug)]
pub struct ExtraCredit {
    ledger_id: u64,
    serial: u64,
    role: Role,
    window: u64,
    start_ns: u64,
    limit_ns: u64,
    cpu: u16,
    core_generation: u64,
}
#[derive(Debug)]
pub struct WorkReceipt {
    ledger_id: u64,
    serial: u64,
    role: Role,
    window: u64,
    actual_ns: u64,
    cpu: u16,
    core_generation: u64,
}
/// Read-only identifying facts, not a constructor for a settled receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkIdentity {
    pub ledger_id: u64,
    pub serial: u64,
    pub role: Role,
    pub window: u64,
    pub actual_ns: u64,
    pub cpu: u16,
    pub core_generation: u64,
}
impl WorkReceipt {
    pub fn identity(&self) -> WorkIdentity {
        WorkIdentity {
            ledger_id: self.ledger_id,
            serial: self.serial,
            role: self.role,
            window: self.window,
            actual_ns: self.actual_ns,
            cpu: self.cpu,
            core_generation: self.core_generation,
        }
    }
}
/// All four extra roles share this single ledger. Losing a credit reply cannot
/// reset a window or obtain another credit. Overruns remain sticky and billed.
pub struct ExtraBudget {
    ledger_id: u64,
    window: Option<u64>,
    carry_window: Option<u64>,
    carry_spent: u64,
    serial: u64,
    spent: u64,
    mandatory: u64,
    pending: Option<(u64, u64)>,
    fault: bool,
}
impl Default for ExtraBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl ExtraBudget {
    pub fn new() -> Self {
        let ledger_id = NEXT_LEDGER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .unwrap_or(0);
        Self {
            ledger_id,
            window: None,
            carry_window: None,
            carry_spent: 0,
            serial: 0,
            spent: 0,
            mandatory: 0,
            pending: None,
            fault: ledger_id == 0,
        }
    }
    fn at(&mut self, now: u64) -> Result<u64, Error> {
        if self.fault {
            return Err(Error::Budget);
        }
        let window = now / WINDOW_NS;
        if self.window.is_some_and(|old| window < old) {
            return Err(Error::Stale);
        }
        if self.window != Some(window) {
            if self.pending.is_some() {
                return Err(Error::Unknown);
            }
            self.window = Some(window);
            self.spent = if self.carry_window == Some(window) {
                self.carry_spent
            } else {
                0
            };
            self.mandatory = 0;
            if self.carry_window.is_some_and(|carried| carried <= window) {
                self.carry_window = None;
                self.carry_spent = 0;
            }
        }
        Ok(window)
    }
    pub fn record_mandatory(&mut self, now: u64, actual_ns: u64) -> Result<(), Error> {
        self.at(now)?;
        self.mandatory = self
            .mandatory
            .checked_add(actual_ns)
            .ok_or(Error::Numeric)?;
        if self.mandatory > MANDATORY_NS || self.mandatory.saturating_add(self.spent) > CONTROL_NS {
            self.fault = true;
            return Err(Error::Budget);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        role: Role,
        cpu: u16,
        core_generation: u64,
        workspace_bytes: u32,
        now: u64,
        limit_ns: u64,
        authority: &impl ControlAuthority,
    ) -> Result<ExtraCredit, Error> {
        if workspace_bytes == 0 || workspace_bytes > 1024 * 1024 || core_generation == 0 {
            return Err(Error::Capacity);
        }
        authority.authorize(role, cpu, core_generation, workspace_bytes)?;
        let window = self.at(now)?;
        if self.pending.is_some() {
            return Err(Error::Unknown);
        }
        let end = (window + 1).checked_mul(WINDOW_NS).ok_or(Error::Numeric)?;
        if limit_ns == 0
            || limit_ns > EXTRA_NS.saturating_sub(self.spent)
            || limit_ns > CONTROL_NS.saturating_sub(self.mandatory + self.spent)
            || limit_ns > end - now
        {
            return Err(Error::Budget);
        }
        self.serial = self.serial.checked_add(1).ok_or(Error::Numeric)?;
        self.pending = Some((self.serial, limit_ns));
        Ok(ExtraCredit {
            ledger_id: self.ledger_id,
            serial: self.serial,
            role,
            window,
            start_ns: now,
            limit_ns,
            cpu,
            core_generation,
        })
    }
    pub fn settle(
        &mut self,
        credit: ExtraCredit,
        actual_ns: u64,
        finished_ns: u64,
    ) -> Result<WorkReceipt, Error> {
        if credit.ledger_id != self.ledger_id
            || self.pending != Some((credit.serial, credit.limit_ns))
            || self.window != Some(credit.window)
        {
            return Err(Error::Stale);
        }
        // Record even invalid execution before closing the credit. A budget
        // violation does not disappear by reporting failure or advancing time.
        self.spent = self.spent.checked_add(actual_ns).ok_or(Error::Numeric)?;
        self.pending = None;
        if self.fault
            || actual_ns > credit.limit_ns
            || finished_ns < credit.start_ns
            || actual_ns > finished_ns.saturating_sub(credit.start_ns)
            || self.spent > EXTRA_NS
            || self.spent.saturating_add(self.mandatory) > CONTROL_NS
        {
            self.fault = true;
            return Err(Error::Budget);
        }
        let finished_window = finished_ns / WINDOW_NS;
        if finished_window > credit.window {
            if self.carry_window != Some(finished_window) {
                self.carry_window = Some(finished_window);
                self.carry_spent = 0;
            }
            self.carry_spent = self
                .carry_spent
                .checked_add(actual_ns)
                .ok_or(Error::Numeric)?;
            if self.carry_spent > EXTRA_NS {
                self.fault = true;
                return Err(Error::Budget);
            }
        }
        Ok(WorkReceipt {
            ledger_id: credit.ledger_id,
            serial: credit.serial,
            role: credit.role,
            window: credit.window,
            actual_ns,
            cpu: credit.cpu,
            core_generation: credit.core_generation,
        })
    }
    pub fn spent_ns(&self) -> u64 {
        self.spent
    }
    pub fn faulted(&self) -> bool {
        self.fault
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetRegistration {
    pub key: ObjectKey,
    pub baseline: Action,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestorationRequest {
    pub boot_epoch: u64,
    pub id: u64,
    pub target: TargetRegistration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanaryPermit {
    pub id: u64,
    pub active_generation: u64,
    pub candidate_hash: [u8; 32],
    pub target: ObjectKey,
    pub start_ns: u64,
    pub expires_ns: u64,
    pub windows: u16,
    pub quota: u16,
}
/// This gate owns model generation and the exclusive D15 optimization lease.
/// No method cancels pre-existing plans, task custody or I/O obligations.
pub struct CommitGate {
    boot_epoch: u64,
    active: ModelBinding,
    permit: Option<CanaryPermit>,
    closing: Option<CanaryPermit>,
    restore: Option<RestorationRequest>,
    next_permit: u64,
    next_restore: u64,
}
impl CommitGate {
    pub fn new(boot_epoch: u64, active: ModelBinding) -> Result<Self, Error> {
        if boot_epoch == 0
            || active.generation == 0
            || active.model_hash == [0; 32]
            || active.schema_hash == [0; 32]
        {
            return Err(Error::Manifest);
        }
        Ok(Self {
            boot_epoch,
            active,
            permit: None,
            closing: None,
            restore: None,
            next_permit: 0,
            next_restore: 0,
        })
    }
    pub fn active(&self) -> ModelBinding {
        self.active
    }
    pub fn permit(&self) -> Option<CanaryPermit> {
        self.permit
    }
    pub fn closing(&self) -> Option<CanaryPermit> {
        self.closing
    }
    pub fn restoration_pending(&self) -> Option<ObjectKey> {
        self.restore.map(|request| request.target.key)
    }
    pub fn restoration_request(&self) -> Option<RestorationRequest> {
        self.restore
    }
    /// Apply this only to new publication. Accepted old-generation obligations
    /// continue to use their original apply_id/model binding and are reconciled.
    pub fn check_active_publication(
        &self,
        binding: ModelBinding,
        target: ObjectKey,
    ) -> Result<(), Error> {
        if binding != self.active {
            return Err(Error::Stale);
        }
        if self.permit.is_some_and(|p| p.target == target)
            || self.closing.is_some_and(|p| p.target == target)
            || self.restore.is_some_and(|r| r.target.key == target)
        {
            return Err(Error::State);
        }
        Ok(())
    }
    fn next_restoration(&self, target: TargetRegistration) -> Result<RestorationRequest, Error> {
        Ok(RestorationRequest {
            boot_epoch: self.boot_epoch,
            id: self.next_restore.checked_add(1).ok_or(Error::Numeric)?,
            target,
        })
    }
    fn freeze_permit(&mut self, permit: CanaryPermit) -> Result<(), Error> {
        if self.closing == Some(permit) && self.permit.is_none() {
            return Ok(());
        }
        if self.permit != Some(permit) || self.closing.is_some() || self.restore.is_some() {
            return Err(Error::Stale);
        }
        self.permit = None;
        self.closing = Some(permit);
        Ok(())
    }
    fn revoke_and_restore(
        &mut self,
        permit: CanaryPermit,
        target: TargetRegistration,
    ) -> Result<RestorationRequest, Error> {
        if (self.permit != Some(permit) && self.closing != Some(permit)) || self.restore.is_some() {
            return Err(Error::Stale);
        }
        let request = self.next_restoration(target)?;
        self.permit = None;
        self.closing = None;
        self.next_restore = request.id;
        self.restore = Some(request);
        Ok(request)
    }
    fn change(
        &mut self,
        expected: ModelBinding,
        hash: [u8; 32],
        permit: Option<CanaryPermit>,
    ) -> Result<ModelBinding, Error> {
        let exact = match permit {
            Some(p) => self.permit == Some(p) || (self.permit.is_none() && self.closing == Some(p)),
            None => self.permit.is_none() && self.closing.is_none(),
        };
        if self.active != expected || !exact || self.restore.is_some() {
            return Err(Error::Stale);
        }
        if hash == expected.model_hash {
            return Err(Error::NoChange);
        }
        let generation = expected.generation.checked_add(1).ok_or(Error::Numeric)?;
        self.active = ModelBinding {
            generation,
            model_hash: hash,
            schema_hash: expected.schema_hash,
        };
        self.permit = None;
        self.closing = None;
        Ok(self.active)
    }
}

/// Protected independent validator and execution owners, not model-authored
/// booleans. These callbacks must authenticate their full records natively.
pub trait GovernanceAuthority {
    fn registered_noncritical_console(&self, target: TargetRegistration) -> Result<(), Error>;
    fn legal_console(&self, target: ObjectKey, action: Action, now_ns: u64) -> Result<(), Error>;
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), Error>;
    fn verify_measurement(
        &self,
        permit: CanaryPermit,
        second: u16,
        baseline: &[WorkRequest],
        candidate: &[WorkRequest],
        digest: [u8; 32],
    ) -> Result<(), Error>;
    fn authorize_extension(
        &self,
        registration_hash: [u8; 32],
        permit: CanaryPermit,
        now_ns: u64,
        new_windows: u16,
    ) -> Result<(), Error>;
    fn verify_restoration(
        &self,
        request: RestorationRequest,
        receipt: &RestorationReceipt,
    ) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Shadow,
    Ready,
    Canary,
    Frozen,
    Restoring,
    Active,
    Rejected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    New,
    Existing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanaryReceipt {
    pub apply: ApplyId,
    pub plan_version: u64,
    pub executor_generation: u64,
    pub model: ModelBinding,
    pub state: ExecutionState,
    pub actual: Option<Action>,
    pub started_ns: u64,
    pub finished_ns: u64,
    pub installed_until_ns: u64,
    pub evidence_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestorationReceipt {
    pub boot_epoch: u64,
    pub restoration_id: u64,
    pub target: ObjectKey,
    pub actual: Action,
    /// The actual baseline installation version, authenticated for this request.
    pub actual_version: u64,
    pub executor_generation: u64,
    pub state: ExecutionState,
    pub evidence_hash: [u8; 32],
}
pub struct ScoreProof {
    ledger_id: u64,
    registration_hash: [u8; 32],
    credit_serial: u64,
    window: u64,
    role: Role,
    cpu: u16,
    core_generation: u64,
    family: Family,
    target: ObjectKey,
    snapshot_ns: u64,
    model: ModelBinding,
    candidate_set_hash: [u8; 32],
    selected_index: u16,
    selected: Action,
    score_count: u16,
    scores: [i16; 32],
    hash: [u8; 32],
}
impl ScoreProof {
    /// Complete scores authenticated with this exact set/model/scope. Root
    /// history must retain these values rather than inventing another vector
    /// which happens to have the same selected index.
    pub fn scores(&self) -> &[i16] {
        &self.scores[..usize::from(self.score_count)]
    }
    pub fn selected_index(&self) -> u16 {
        self.selected_index
    }
    /// Bind the exact registered/scoped decision before the root commits a
    /// Canary publication. A credit for one score cannot authorize another
    /// legal action from the same target or a different permit's candidate set.
    pub fn verify_selection(
        &self,
        candidate_set_hash: [u8; 32],
        model: ModelBinding,
        target: ObjectKey,
        snapshot_ns: u64,
        selected_index: u16,
        action: Action,
    ) -> Result<(), Error> {
        if self.role != Role::Canary {
            return Err(Error::State);
        }
        if self.candidate_set_hash != candidate_set_hash
            || self.model != model
            || self.target != target
            || self.snapshot_ns != snapshot_ns
            || self.selected_index != selected_index
            || self.selected != action
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub apply: ApplyId,
    pub action: Action,
    pub stamp: PolicyStamp,
    pub model: ModelBinding,
    pub score_hash: [u8; 32],
    pub published_ns: u64,
    pub apply_deadline_ns: u64,
    pub state: ExecutionState,
    pub receipt: Option<CanaryReceipt>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondResult {
    pub baseline: Performance,
    pub candidate: Performance,
    pub degraded: bool,
    pub evidence_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncompleteSecond {
    /// None means zero issued requests; no percentile was measured.
    pub baseline: Option<Performance>,
    pub candidate: Option<Performance>,
    pub evidence_hash: [u8; 32],
}

pub struct Governance<'a, 'model> {
    candidate: &'a ValidatedCandidate<'model>,
    old: &'a [u8; MODEL_BYTES],
    original: ModelBinding,
    promoted_binding: Option<ModelBinding>,
    stage: Stage,
    shadow_next: u64,
    shadow_closed: u16,
    shadow_seen: bool,
    shadow_families: u32,
    target: Option<TargetRegistration>,
    permit: Option<CanaryPermit>,
    closing_deadline_ns: Option<u64>,
    restoration: Option<RestorationRequest>,
    last_submit_window: Option<u64>,
    history: [Option<Submission>; MAX_SUBMISSIONS],
    submitted: usize,
    pending: Option<usize>,
    applied: u16,
    seconds: [Option<SecondResult>; 30],
    incomplete_seconds: [Option<IncompleteSecond>; 30],
    seconds_seen: u16,
    valid_seconds: u16,
    degraded_run: u8,
    reason: Option<Error>,
}
impl<'a, 'model> Governance<'a, 'model> {
    fn validate_new(
        gate: &CommitGate,
        candidate: &ValidatedCandidate<'_>,
        old: &[u8; MODEL_BYTES],
        start_window: u64,
    ) -> Result<(), Error> {
        start_window
            .checked_add(10)
            .and_then(|window| window.checked_mul(WINDOW_NS))
            .ok_or(Error::Numeric)?;
        if gate.active.model_hash != candidate.parent_hash()
            || gate.active.schema_hash != candidate.model().manifest().schemas.feature.hash
            || Sha256::digest(old).as_slice() != gate.active.model_hash
            || gate.permit.is_some()
            || gate.closing.is_some()
            || gate.restore.is_some()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn new(
        gate: &CommitGate,
        candidate: &'a ValidatedCandidate<'model>,
        old: &'a [u8; MODEL_BYTES],
        start_window: u64,
    ) -> Result<Self, Error> {
        Self::validate_new(gate, candidate, old, start_window)?;
        Ok(Self {
            candidate,
            old,
            original: gate.active,
            promoted_binding: None,
            stage: Stage::Shadow,
            shadow_next: start_window,
            shadow_closed: 0,
            shadow_seen: false,
            shadow_families: 0,
            target: None,
            permit: None,
            closing_deadline_ns: None,
            restoration: None,
            last_submit_window: None,
            history: [None; MAX_SUBMISSIONS],
            submitted: 0,
            pending: None,
            applied: 0,
            seconds: [None; 30],
            incomplete_seconds: [None; 30],
            seconds_seen: 0,
            valid_seconds: 0,
            degraded_run: 0,
            reason: None,
        })
    }
    pub fn original_binding(&self) -> ModelBinding {
        self.original
    }
    pub fn candidate_hash(&self) -> [u8; 32] {
        self.candidate.model().manifest().parameters_hash
    }
    pub fn registration_hash(&self) -> [u8; 32] {
        self.candidate.registration_hash()
    }
    pub fn validation_data(&self) -> super::data::DataManifest {
        match self.candidate.model().manifest().origin {
            super::manifest::Origin::Learned(record) => record.data,
            // ValidatedCandidate has no public unchecked constructor; its
            // independent registration always rejects an untrained origin.
            super::manifest::Origin::Untrained { .. } => unreachable!("validated candidate origin"),
        }
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn reason(&self) -> Option<Error> {
        self.reason
    }
    pub fn submissions(&self) -> impl Iterator<Item = Submission> + '_ {
        self.history[..self.submitted].iter().flatten().copied()
    }
    pub fn second(&self, index: usize) -> Option<SecondResult> {
        self.seconds.get(index).copied().flatten()
    }
    pub fn incomplete_second(&self, index: usize) -> Option<IncompleteSecond> {
        self.incomplete_seconds.get(index).copied().flatten()
    }
    /// Preparation performs bounded encoding and identity checks only. The
    /// complete old/new MLP executes in a separately scheduled EL0 Score role.
    pub fn prepare_score<'s>(
        &'s self,
        set: &'s CandidateSet,
        role: Role,
        binding: super::worker_wire::JobBinding,
        workspace_bytes: u32,
        now_ns: u64,
    ) -> Result<super::score::EncoderState<'s>, Error> {
        let role = match role {
            Role::Shadow => super::worker_wire::Role::ShadowScore,
            Role::Canary => super::worker_wire::Role::CanaryScore,
            _ => return Err(Error::State),
        };
        let encoder = super::score::EncoderState::new(
            self.candidate,
            self.old,
            set,
            role,
            binding,
            workspace_bytes,
            now_ns,
        )?;
        self.score_context(encoder.header(), now_ns)?;
        Ok(encoder)
    }
    fn score_context(&self, h: super::score_wire::Header, now_ns: u64) -> Result<(), Error> {
        if h.registration_hash != self.candidate.registration_hash()
            || h.manifest_hash != self.candidate.model().hash()
            || h.parent_hash != self.original.model_hash
            || h.candidate_hash != self.candidate_hash()
            || h.model.generation != self.original.generation
            || h.model.schema_hash != self.original.schema_hash
            || now_ns < h.prepared_ns
            || now_ns < h.snapshot.taken_ns
            || now_ns - h.snapshot.taken_ns > 50_000_000
        {
            return Err(Error::Stale);
        }
        match h.role {
            super::worker_wire::Role::ShadowScore
                if self.stage == Stage::Shadow
                    && now_ns / WINDOW_NS == self.shadow_next
                    && h.model == self.original
                    && h.permit.is_none() =>
            {
                Ok(())
            }
            super::worker_wire::Role::CanaryScore if self.stage == Stage::Canary => {
                let p = self.permit.ok_or(Error::State)?;
                if h.permit != Some(p)
                    || h.target != p.target
                    || h.model.model_hash != p.candidate_hash
                    || h.family
                        != (Family {
                            domain: 15,
                            kind: 1,
                        })
                    || now_ns < p.start_ns
                    || now_ns >= p.expires_ns
                {
                    return Err(Error::Stale);
                }
                if self.pending.is_some() {
                    return Err(Error::Unknown);
                }
                if self.last_submit_window == Some((now_ns - p.start_ns) / WINDOW_NS)
                    || self.submitted >= usize::from(p.quota)
                {
                    return Err(Error::Budget);
                }
                Ok(())
            }
            _ => Err(Error::State),
        }
    }
    /// Import is bounded identity/output checking; it never replays an MLP in
    /// EL1. The runtime authenticates exact stopped-job custody and this same
    /// settled receipt, which record_shadow/PUBLISH must subsequently consume.
    pub fn accept_score(
        &self,
        job: &mut super::score::PreparedScore,
        output: &[u8],
        cost: &WorkReceipt,
        authority: &impl super::worker::CompletionAuthority,
        now_ns: u64,
    ) -> Result<super::score::Scored, Error> {
        let h = job.header();
        self.score_context(h, now_ns)?;
        let report = job.authenticate(output, cost, authority, now_ns)?;
        let receipt = cost.identity();
        let role = match h.role {
            super::worker_wire::Role::ShadowScore => Role::Shadow,
            super::worker_wire::Role::CanaryScore => Role::Canary,
            _ => return Err(Error::State),
        };
        let selected = job.action(report.selected)?;
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_PROTECTED_SCORE_PROOF_1.3\0");
        hash.update(report.identity.input_hash);
        hash.update(report.transcript_hash);
        hash.update(h.set_hash);
        hash.update(h.registration_hash);
        hash.update(report.selected.to_le_bytes());
        for v in &report.scores[..usize::from(report.count)] {
            hash.update(v.to_le_bytes());
        }
        let proof = ScoreProof {
            ledger_id: receipt.ledger_id,
            registration_hash: h.registration_hash,
            credit_serial: receipt.serial,
            window: receipt.window,
            role,
            cpu: receipt.cpu,
            core_generation: receipt.core_generation,
            family: h.family,
            target: h.target,
            snapshot_ns: h.snapshot.taken_ns,
            model: h.model,
            candidate_set_hash: h.set_hash,
            selected_index: report.selected,
            selected,
            score_count: report.count,
            scores: report.scores,
            hash: hash.finalize().into(),
        };
        Ok(super::score::Scored::new(proof, report))
    }
    fn score(
        &self,
        set: &CandidateSet,
        credit: &ExtraCredit,
        role: Role,
    ) -> Result<ScoreProof, Error> {
        if credit.role != role {
            return Err(Error::State);
        }
        if set.snapshot.core_generation != credit.core_generation
            || set.snapshot.taken_ns > credit.start_ns
            || credit.start_ns - set.snapshot.taken_ns > 50_000_000
        {
            return Err(Error::Stale);
        }
        let expected = if role == Role::Shadow {
            self.original
        } else {
            ModelBinding {
                model_hash: self.candidate.model().manifest().parameters_hash,
                ..self.original
            }
        };
        if set.model != expected {
            return Err(Error::Stale);
        }
        let first = set.get(0).ok_or(Error::Evidence)?;
        let family = Family {
            domain: first.action.domain(),
            kind: first.action.kind(),
        };
        family.index()?;
        let runtime = Model::parse(self.candidate.model().bytes()).map_err(|_| Error::Model)?;
        let old = Model::parse(self.old).map_err(|_| Error::Model)?;
        let mut best = 0;
        let mut score = i16::MIN;
        let mut all_scores = [0; 32];
        let mut hash = Sha256::new();
        hash.update(set.hash());
        hash.update(self.candidate.registration_hash());
        let mut choices = [first; 32];
        for (index, candidate) in set.iter().enumerate() {
            choices[index] = candidate;
            let input = features::encode(candidate.action, candidate.features)
                .map_err(|_| Error::Evidence)?
                .values;
            let trace = runtime.trace(&input);
            all_scores[index] = trace.output;
            if trace != integer_reference(self.candidate.model().bytes(), &input) {
                return Err(Error::Validation);
            }
            let prior = old.score(&input);
            if role == Role::Shadow && old.trace(&input) != integer_reference(self.old, &input) {
                return Err(Error::Validation);
            }
            if index == 0 || trace.output > score {
                best = index;
                score = trace.output;
            }
            for x in input {
                hash.update(x.to_le_bytes());
            }
            hash.update(prior.to_le_bytes());
            hash.update(trace.output.to_le_bytes());
        }
        let rebuilt = CandidateSet::new(
            set.snapshot,
            set.target,
            set.model,
            &choices[..set.len()],
            Some(first.action),
        )
        .map_err(|_| Error::Evidence)?;
        let rebuilt_hash = match set.canary_permit() {
            Some(permit) if role == Role::Canary && self.permit == Some(permit) => rebuilt
                .hash_for_canary(permit)
                .map_err(|_| Error::Evidence)?,
            Some(_) => return Err(Error::Stale),
            None => rebuilt.hash(),
        };
        if rebuilt_hash != set.hash() {
            return Err(Error::Evidence);
        }
        hash.update((best as u16).to_le_bytes());
        Ok(ScoreProof {
            ledger_id: credit.ledger_id,
            registration_hash: self.candidate.registration_hash(),
            credit_serial: credit.serial,
            window: credit.window,
            role,
            cpu: credit.cpu,
            core_generation: credit.core_generation,
            family,
            target: set.target,
            snapshot_ns: set.snapshot.taken_ns,
            model: expected,
            candidate_set_hash: set.hash(),
            selected_index: best as u16,
            selected: set.get(best).ok_or(Error::Evidence)?.action,
            score_count: set.len() as u16,
            scores: all_scores,
            hash: hash.finalize().into(),
        })
    }
    pub fn score_shadow(
        &self,
        set: &CandidateSet,
        credit: &ExtraCredit,
    ) -> Result<ScoreProof, Error> {
        if self.stage != Stage::Shadow || credit.window != self.shadow_next {
            return Err(Error::State);
        }
        self.score(set, credit, Role::Shadow)
    }
    fn cost(proof: &ScoreProof, receipt: WorkReceipt) -> Result<(), Error> {
        if (
            proof.ledger_id,
            proof.credit_serial,
            proof.window,
            proof.role,
            proof.cpu,
            proof.core_generation,
        ) != (
            receipt.ledger_id,
            receipt.serial,
            receipt.window,
            receipt.role,
            receipt.cpu,
            receipt.core_generation,
        ) || receipt.actual_ns == 0
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }
    pub fn record_shadow(&mut self, proof: ScoreProof, receipt: WorkReceipt) -> Result<(), Error> {
        if self.stage != Stage::Shadow
            || proof.window != self.shadow_next
            || proof.role != Role::Shadow
            || proof.registration_hash != self.candidate.registration_hash()
        {
            return Err(Error::State);
        }
        Self::cost(&proof, receipt)?;
        self.shadow_families |= 1 << proof.family.index()?;
        self.shadow_seen = true;
        Ok(())
    }
    pub fn close_shadow_window(&mut self, now_ns: u64) -> Result<(), Error> {
        let next = self.shadow_next.checked_add(1).ok_or(Error::Numeric)?;
        if self.stage != Stage::Shadow || now_ns / WINDOW_NS != next || !self.shadow_seen {
            return Err(Error::DataIncomplete);
        }
        self.shadow_closed = self.shadow_closed.checked_add(1).ok_or(Error::Numeric)?;
        self.shadow_next = next;
        self.shadow_seen = false;
        if self.shadow_closed >= 10 && self.shadow_families == (1 << FAMILIES) - 1 {
            self.stage = Stage::Ready;
        }
        Ok(())
    }
    pub fn begin_canary(
        &mut self,
        gate: &mut CommitGate,
        target: TargetRegistration,
        now_ns: u64,
        authority: &impl GovernanceAuthority,
    ) -> Result<CanaryPermit, Error> {
        let shadow_finished = self
            .shadow_next
            .checked_mul(WINDOW_NS)
            .ok_or(Error::Numeric)?;
        if self.stage != Stage::Ready
            || gate.active != self.original
            || gate.permit.is_some()
            || gate.closing.is_some()
            || gate.restore.is_some()
            || now_ns < shadow_finished
        {
            return Err(Error::State);
        }
        if target.key.id == 0
            || target.key.generation == 0
            || !matches!(target.baseline, Action::ConsoleBatch(_))
        {
            return Err(Error::Schema);
        }
        target.baseline.validate().map_err(|_| Error::Schema)?;
        authority.registered_noncritical_console(target)?;
        authority.legal_console(target.key, target.baseline, now_ns)?;
        let remainder = now_ns % WINDOW_NS;
        let start_ns = if remainder == 0 {
            now_ns
        } else {
            now_ns
                .checked_add(WINDOW_NS - remainder)
                .ok_or(Error::Numeric)?
        };
        let expires_ns = start_ns.checked_add(10_000_000_000).ok_or(Error::Numeric)?;
        let next_permit = gate.next_permit.checked_add(1).ok_or(Error::Numeric)?;
        let permit = CanaryPermit {
            id: next_permit,
            active_generation: self.original.generation,
            candidate_hash: self.candidate.model().manifest().parameters_hash,
            target: target.key,
            start_ns,
            expires_ns,
            windows: 100,
            quota: 100,
        };
        gate.next_permit = next_permit;
        gate.permit = Some(permit);
        self.permit = Some(permit);
        self.target = Some(target);
        self.stage = Stage::Canary;
        Ok(permit)
    }
    pub fn score_canary(
        &self,
        set: &CandidateSet,
        credit: &ExtraCredit,
    ) -> Result<ScoreProof, Error> {
        if self.stage != Stage::Canary
            || set.target != self.target.ok_or(Error::State)?.key
            || set
                .get(0)
                .is_none_or(|c| c.action.domain() != 15 || c.action.kind() != 1)
        {
            return Err(Error::State);
        }
        let permit = self.permit.ok_or(Error::State)?;
        if credit.start_ns < permit.start_ns || credit.start_ns >= permit.expires_ns {
            return Err(Error::Deadline);
        }
        self.score(set, credit, Role::Canary)
    }
    /// Called at the actual protected Plan PUBLISH commit point, after its hard
    /// constraint checks. Reserving a score or writing desired is not APPLIED.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        &mut self,
        gate: &mut CommitGate,
        now_ns: u64,
        proof: ScoreProof,
        cost: WorkReceipt,
        apply: ApplyId,
        stamp: PolicyStamp,
        authority: &impl GovernanceAuthority,
    ) -> Result<Publication, Error> {
        let permit = self.permit.ok_or(Error::State)?;
        Self::cost(&proof, cost)?;
        if self.stage != Stage::Canary
            || gate.permit != Some(permit)
            || gate.active != self.original
        {
            return Err(Error::Stale);
        }
        if now_ns < permit.start_ns || now_ns >= permit.expires_ns {
            self.abort(gate, Error::Deadline);
            return Err(Error::Deadline);
        }
        if proof.role != Role::Canary
            || proof.registration_hash != self.candidate.registration_hash()
            || proof.family
                != (Family {
                    domain: 15,
                    kind: 1,
                })
            || proof.target != permit.target
            || apply.target != permit.target
            || apply.boot_epoch != gate.boot_epoch
            || apply.controller_epoch == 0
            || apply.plan_seq == 0
            || apply.action_index != 0
            || proof.model.generation != permit.active_generation
            || proof.model.model_hash != permit.candidate_hash
            || proof.window != now_ns / WINDOW_NS
            || stamp.snapshot_ns != proof.snapshot_ns
            || stamp.version == 0
            || !stamp.live(now_ns)
            || stamp.installed_until_ns
                != stamp
                    .snapshot_ns
                    .checked_add(10_000_000_000)
                    .ok_or(Error::Numeric)?
            || now_ns < stamp.snapshot_ns
            || now_ns - stamp.snapshot_ns > 50_000_000
        {
            self.abort(gate, Error::Evidence);
            return Err(Error::Evidence);
        }
        authority
            .legal_console(permit.target, proof.selected, now_ns)
            .inspect_err(|_| self.abort(gate, Error::Safety))?;
        if let Some(previous) = self.history[..self.submitted]
            .iter()
            .flatten()
            .find(|old| old.apply == apply)
        {
            if previous.action != proof.selected
                || previous.stamp != stamp
                || previous.score_hash != proof.hash
            {
                return Err(Error::Conflict);
            }
            return Ok(Publication::Existing);
        }
        if self.pending.is_some() {
            return Err(Error::Unknown);
        }
        let window = (now_ns - permit.start_ns) / WINDOW_NS;
        if self.last_submit_window == Some(window)
            || self.submitted >= usize::from(permit.quota)
            || self.submitted == MAX_SUBMISSIONS
        {
            self.abort(gate, Error::Budget);
            return Err(Error::Budget);
        }
        self.history[self.submitted] = Some(Submission {
            apply,
            action: proof.selected,
            stamp,
            model: proof.model,
            score_hash: proof.hash,
            published_ns: now_ns,
            apply_deadline_ns: now_ns.checked_add(50_000_000).ok_or(Error::Numeric)?,
            state: ExecutionState::Pending,
            receipt: None,
        });
        self.pending = Some(self.submitted);
        self.submitted += 1;
        self.last_submit_window = Some(window);
        Ok(Publication::New)
    }
    pub fn reconcile(
        &mut self,
        gate: &mut CommitGate,
        receipt: CanaryReceipt,
        authority: &impl GovernanceAuthority,
    ) -> Result<(), Error> {
        let index = self.history[..self.submitted]
            .iter()
            .position(|v| v.is_some_and(|s| s.apply == receipt.apply))
            .ok_or(Error::Stale)?;
        let mut submission = self.history[index].ok_or(Error::State)?;
        if receipt.plan_version != submission.stamp.version
            || receipt.model != submission.model
            || receipt.executor_generation == 0
            || receipt.evidence_hash == [0; 32]
        {
            return Err(Error::Evidence);
        }
        authority.verify_receipt(&receipt)?;
        if submission.state.terminal() {
            return if submission.receipt == Some(receipt) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let late = receipt.state.terminal() && receipt.finished_ns > submission.apply_deadline_ns;
        if receipt.state == ExecutionState::Applied {
            if receipt.actual != Some(submission.action)
                || receipt.started_ns < submission.published_ns
                || receipt.finished_ns < receipt.started_ns
                || receipt.installed_until_ns != submission.stamp.installed_until_ns
            {
                return Err(Error::Evidence);
            }
            self.applied = self.applied.checked_add(1).ok_or(Error::Numeric)?;
        }
        submission.state = receipt.state;
        submission.receipt = Some(receipt);
        self.history[index] = Some(submission);
        if receipt.state.terminal() && self.pending == Some(index) {
            self.pending = None;
        }
        // A genuine late terminal receipt still closes the unique obligation.
        // It can never rehabilitate this Canary or conceal the deadline fault.
        if late {
            self.abort(gate, Error::Deadline);
            return Err(Error::Deadline);
        }
        if matches!(receipt.state, ExecutionState::Failed(_)) {
            self.abort(gate, Error::Safety);
        }
        Ok(())
    }
    pub fn observe_second(
        &mut self,
        gate: &mut CommitGate,
        second: u16,
        baseline: &[WorkRequest],
        candidate: &[WorkRequest],
        work: &mut RewardWorkspace,
        authority: &impl GovernanceAuthority,
    ) -> Result<(), Error> {
        self.observe_second_bounded(
            gate,
            second,
            baseline,
            candidate,
            work.latency_scratch(),
            authority,
        )
    }
    /// A one-second comparison needs only one latency per request. The native
    /// owner uses its real 100-entry scratch instead of allocating CPU-union
    /// workspace while the independent numerical worker retains its banks.
    pub fn observe_second_bounded(
        &mut self,
        gate: &mut CommitGate,
        second: u16,
        baseline: &[WorkRequest],
        candidate: &[WorkRequest],
        latencies: &mut [u64],
        authority: &impl GovernanceAuthority,
    ) -> Result<(), Error> {
        let permit = self.permit.ok_or(Error::State)?;
        if !matches!(self.stage, Stage::Canary | Stage::Frozen)
            || second != self.seconds_seen
            || second >= 30
            || u64::from(second + 1) * 1_000_000_000 > permit.expires_ns - permit.start_ns
        {
            return Err(Error::Order);
        }
        let start = permit
            .start_ns
            .checked_add(u64::from(second) * 1_000_000_000)
            .ok_or(Error::Numeric)?;
        if baseline.len() != candidate.len() {
            self.abort(gate, Error::Evidence);
            return Err(Error::Evidence);
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_CANARY_SECOND_1.3\0");
        hash.update(permit.id.to_le_bytes());
        hash.update(second.to_le_bytes());
        hash.update((baseline.len() as u64).to_le_bytes());
        for (b, c) in baseline.iter().zip(candidate) {
            if b.id != c.id || b.arrived_ns != c.arrived_ns {
                self.abort(gate, Error::Evidence);
                return Err(Error::Evidence);
            }
            for r in [b, c] {
                hash.update(r.id.to_le_bytes());
                hash.update(r.arrived_ns.to_le_bytes());
                let (code, at) = match r.result {
                    reward::RequestResult::Completed { finished_ns } => (0u64, finished_ns),
                    reward::RequestResult::Rejected => (1, 0),
                    reward::RequestResult::TimedOut => (2, 0),
                    reward::RequestResult::Pending => (3, 0),
                };
                hash.update(code.to_le_bytes());
                hash.update(at.to_le_bytes());
            }
        }
        let digest = hash.finalize().into();
        authority.verify_measurement(permit, second, baseline, candidate, digest)?;
        let (baseline, candidate) = match (
            reward::inspect_one_second_with_latencies(baseline, start, latencies),
            reward::inspect_one_second_with_latencies(candidate, start, latencies),
        ) {
            (Ok(b), Ok(c)) => (b, c),
            _ => {
                self.abort(gate, Error::Evidence);
                return Err(Error::Evidence);
            }
        };
        self.seconds_seen += 1;
        let (b, c) = match (baseline, candidate) {
            (Some(b), Some(c)) if b.emitted >= 100 && c.emitted >= 100 => (b, c),
            _ => {
                self.incomplete_seconds[usize::from(second)] = Some(IncompleteSecond {
                    baseline,
                    candidate,
                    evidence_hash: digest,
                });
                self.degraded_run = 0;
                return Err(Error::DataIncomplete);
            }
        };
        let degraded = u128::from(c.completed) * 10 < u128::from(b.completed) * 9
            || u128::from(c.penalty_p99_ns) * 10 > u128::from(b.penalty_p99_ns) * 11;
        self.seconds[usize::from(second)] = Some(SecondResult {
            baseline: b,
            candidate: c,
            degraded,
            evidence_hash: digest,
        });
        self.valid_seconds += 1;
        self.degraded_run = if degraded { self.degraded_run + 1 } else { 0 };
        if self.degraded_run >= 3 {
            self.abort(gate, Error::Validation);
            return Err(Error::Validation);
        }
        Ok(())
    }
    pub fn extend(
        &mut self,
        gate: &mut CommitGate,
        now_ns: u64,
        new_windows: u16,
        authority: &impl GovernanceAuthority,
    ) -> Result<(), Error> {
        let mut permit = self.permit.ok_or(Error::State)?;
        if self.stage != Stage::Canary
            || gate.permit != Some(permit)
            || now_ns < permit.start_ns
            || now_ns >= permit.expires_ns
            || new_windows <= permit.windows
            || new_windows > 300
        {
            return Err(Error::Deadline);
        }
        let expires_ns = permit
            .start_ns
            .checked_add(u64::from(new_windows) * WINDOW_NS)
            .ok_or(Error::Numeric)?;
        authority.authorize_extension(
            self.candidate.registration_hash(),
            permit,
            now_ns,
            new_windows,
        )?;
        permit.windows = new_windows;
        permit.quota = new_windows;
        permit.expires_ns = expires_ns;
        gate.permit = Some(permit);
        self.permit = Some(permit);
        Ok(())
    }
    pub fn freeze(&mut self) -> Result<(), Error> {
        if self.stage != Stage::Canary {
            return Err(Error::State);
        }
        self.stage = Stage::Frozen;
        Ok(())
    }
    /// Native end-of-observation transition, in the root commit critical
    /// section. It revokes all new Canary publication while retaining a
    /// distinct exact token for bounded, already-owned finalization only.
    pub fn freeze_at(&mut self, gate: &mut CommitGate, now_ns: u64) -> Result<(), Error> {
        if !matches!(self.stage, Stage::Canary | Stage::Frozen) {
            return Err(Error::State);
        }
        let permit = self.permit.ok_or(Error::State)?;
        if now_ns < permit.start_ns {
            return Err(Error::Deadline);
        }
        let deadline = match self.closing_deadline_ns {
            Some(deadline) => deadline,
            None => now_ns
                .min(permit.expires_ns)
                .checked_add(CLOSING_NS)
                .ok_or(Error::Numeric)?,
        };
        gate.freeze_permit(permit)?;
        self.closing_deadline_ns = Some(deadline);
        self.stage = Stage::Frozen;
        if now_ns > deadline {
            self.abort(gate, Error::Deadline);
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub fn closing_deadline_ns(&self) -> Option<u64> {
        self.closing_deadline_ns
    }
    pub fn promote(&mut self, gate: &mut CommitGate, now_ns: u64) -> Result<ModelBinding, Error> {
        let permit = self.permit.ok_or(Error::State)?;
        if self.stage != Stage::Frozen {
            return Err(Error::State);
        }
        if now_ns
            < permit
                .start_ns
                .checked_add(10_000_000_000)
                .ok_or(Error::Numeric)?
        {
            return Err(Error::Deadline);
        }
        self.freeze_at(gate, now_ns)?;
        if self.pending.is_some()
            || self.history[..self.submitted]
                .iter()
                .flatten()
                .any(|s| !s.state.terminal())
        {
            return Err(Error::Unknown);
        }
        if self.valid_seconds < 10 || self.applied == 0 || self.reason.is_some() {
            return Err(Error::DataIncomplete);
        }
        let binding = gate.change(self.original, permit.candidate_hash, Some(permit))?;
        self.promoted_binding = Some(binding);
        self.stage = Stage::Active;
        self.permit = None;
        Ok(binding)
    }
    pub fn abort(&mut self, gate: &mut CommitGate, reason: Error) {
        self.reason.get_or_insert(reason);
        if let Some(request) = self.restoration {
            // A repeated abort never replaces a pending restoration identity.
            if gate.restore == Some(request) {
                self.stage = Stage::Restoring;
            }
            return;
        }
        if let (Some(permit), Some(target)) = (self.permit, self.target) {
            match gate.revoke_and_restore(permit, target) {
                Ok(request) => {
                    self.restoration = Some(request);
                    self.stage = Stage::Restoring;
                }
                Err(error) => {
                    self.reason = Some(error);
                    // Leave the gate untouched: stale owners cannot revoke or
                    // replace another owner's lease/restoration obligation.
                    self.stage = Stage::Rejected;
                }
            }
        } else {
            self.stage = Stage::Rejected;
        }
    }
    pub fn tick(&mut self, gate: &mut CommitGate, now_ns: u64) {
        if matches!(self.stage, Stage::Canary | Stage::Frozen)
            && let Some(index) = self.pending
            && let Some(submission) = self.history[index].as_mut()
            && now_ns > submission.apply_deadline_ns
        {
            submission.state = ExecutionState::Unknown;
            self.abort(gate, Error::Deadline);
            return;
        }
        if self.stage == Stage::Frozen
            || (self.stage == Stage::Canary && self.permit.is_some_and(|p| now_ns >= p.expires_ns))
        {
            // Late polling never restarts the closing interval at `now`.
            let _ = self.freeze_at(gate, now_ns);
        }
    }
    pub fn restored(
        &mut self,
        gate: &mut CommitGate,
        receipt: RestorationReceipt,
        authority: &impl GovernanceAuthority,
    ) -> Result<(), Error> {
        let target = self.target.ok_or(Error::State)?;
        let request = self.restoration.ok_or(Error::State)?;
        if self.stage != Stage::Restoring || gate.restore != Some(request) {
            return Err(Error::State);
        }
        if self.pending.is_some() {
            return Err(Error::Unknown);
        }
        if receipt.state != ExecutionState::Applied
            || receipt.boot_epoch != request.boot_epoch
            || receipt.restoration_id != request.id
            || receipt.target != target.key
            || receipt.actual != target.baseline
            || receipt.executor_generation == 0
            || receipt.evidence_hash == [0; 32]
        {
            return Err(Error::Evidence);
        }
        authority.verify_restoration(request, &receipt)?;
        gate.restore = None;
        self.stage = Stage::Rejected;
        self.permit = None;
        Ok(())
    }
    pub fn rollback(&mut self, gate: &mut CommitGate) -> Result<ModelBinding, Error> {
        if self.stage != Stage::Active || Some(gate.active) != self.promoted_binding {
            return Err(Error::State);
        }
        let request = self
            .target
            .map(|target| gate.next_restoration(target))
            .transpose()?;
        let binding = gate.change(
            self.promoted_binding.ok_or(Error::State)?,
            self.original.model_hash,
            None,
        )?;
        // Existing operations retain their original TTL and receipt identities.
        if let Some(request) = request {
            gate.next_restore = request.id;
            gate.restore = Some(request);
            self.restoration = Some(request);
            self.stage = Stage::Restoring;
        } else {
            self.stage = Stage::Rejected;
        }
        self.reason = Some(Error::Validation);
        Ok(binding)
    }
}
const _: () = assert!(core::mem::size_of::<Governance<'_, '_>>() < 256 * 1024);
