//! Native Shadow/Canary admission under the ordinary Plan PUBLISH gate.
//! Owner observations define candidates; only the isolated extra role scores.
use super::learning_coordinator::{control, native_error};
use super::{
    Action, ApplyId, Candidate, CandidateSet, Error as DomainError, ExecutionState, Executor,
    Family, ModelBinding, NativeClock, ObjectKey, Owner, POLICY_NS, Plan, PlanHeader, PolicyStamp,
    PublicationScope, RawFeatures, Snapshot, State, WINDOW_NS, bind_dependencies, categorical,
    ensure_stability, execution_blocks_replacement, family_index, locate, now, policy, policy_wire,
    publisher, queued_control_wcet_us, submission, tiers, with,
};
use crate::{control_pool::Allocation, smp::prototype_runtime as runtime};
use core::mem::MaybeUninit;
use cyxia_prototype::learning::{
    Error,
    data::DataManifest,
    governance::{
        CanaryPermit, CanaryReceipt, CommitGate, Governance, GovernanceAuthority, Publication,
        RestorationReceipt, RestorationRequest, Role as ExtraRole, ScoreProof, TargetRegistration,
        WorkReceipt,
    },
    reward::{RewardWorkspace, WorkRequest},
    score::{PreparedScore, Scored},
    worker::{CompletionAuthority, CompletionClaim},
    worker_wire::{JobBinding, JobIdentity, Role},
};
use sha2::{Digest, Sha256};
#[path = "publication_clock.rs"]
mod publication_clock;
use publication_clock::PublicationClock;

// A failed numerical worker cannot own the only path which revokes its
// Canary and restores the exact baseline. CPU0 may perform only these typed
// maintenance operations, in a real prepaid service segment. No new score,
// numerical acknowledgement or model promotion uses this entry.
fn maintenance<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return control(f);
    }
    crate::domain_tasks::authorize_service_turn().map_err(native_error)?;
    with(|state| Ok(f(state))).map_err(native_error)?
}
fn safety_cpu() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::State);
    }
    crate::domain_tasks::authorize_service_turn().map_err(native_error)
}
pub fn safety_tick(governance: &mut Governance<'_, '_>) -> Result<(), Error> {
    safety_cpu()?;
    tick(governance)
}
pub fn safety_abort(governance: &mut Governance<'_, '_>, reason: Error) -> Result<(), Error> {
    safety_cpu()?;
    abort(governance, reason)
}
pub fn safety_reconcile(
    governance: &mut Governance<'_, '_>,
    apply: ApplyId,
    version: u64,
) -> Result<ExecutionState, Error> {
    safety_cpu()?;
    reconcile(governance, apply, version)
}
pub fn safety_restore(governance: &mut Governance<'_, '_>) -> Result<ExecutionState, Error> {
    safety_cpu()?;
    restore(governance)
}

#[derive(Clone, Copy)]
struct ScoreJob {
    binding: JobBinding,
    role: Role,
    original: ModelBinding,
    model: ModelBinding,
    registration: [u8; 32],
    data: DataManifest,
    snapshot: Snapshot,
    target: ObjectKey,
    set_hash: [u8; 32],
    count: usize,
    sequence: u64,
    base_version: u64,
    dependencies: [Option<super::BoundDependency>; 2],
    identity: Option<JobIdentity>,
    input: Option<Allocation>,
    consumed: bool,
}
impl ScoreJob {
    fn key(self) -> ObjectKey {
        ObjectKey {
            id: self.binding.job_id,
            generation: self.binding.boot_epoch,
        }
    }
}
#[derive(Clone, Copy)]
struct Restoration {
    request: RestorationRequest,
    apply: ApplyId,
    version: u64,
}
/// Protected independent validator callbacks authenticate retained immutable
/// replay data. An absent owner is DataIncomplete, never a successful result.
#[derive(Clone, Copy)]
pub struct EvidenceChecks {
    pub owner: ObjectKey,
    pub measurement:
        fn(CanaryPermit, u16, &[WorkRequest], &[WorkRequest], [u8; 32]) -> Result<(), Error>,
    pub extension: fn([u8; 32], CanaryPermit, u64, u16) -> Result<(), Error>,
}
impl EvidenceChecks {
    fn same(self, other: Self) -> bool {
        self.owner == other.owner
            && core::ptr::fn_addr_eq(self.measurement, other.measurement)
            && core::ptr::fn_addr_eq(self.extension, other.extension)
    }
}
pub(super) struct Jobs {
    score: Option<ScoreJob>,
    restoration: Option<Restoration>,
    checks: Option<EvidenceChecks>,
}
impl Jobs {
    pub(super) const fn new() -> Self {
        Self {
            score: None,
            restoration: None,
            checks: None,
        }
    }
    pub(super) fn busy(&self) -> bool {
        self.score.is_some()
    }
    pub(super) fn reserves_publication(&self, at: u64) -> bool {
        self.score.is_some_and(|job| {
            job.role == Role::CanaryScore && at.saturating_sub(job.snapshot.taken_ns) <= 50_000_000
        })
    }
}
pub fn register_evidence(checks: EvidenceChecks) -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 || checks.owner.id == 0 || checks.owner.generation == 0
    {
        return Err(DomainError::Auth);
    }
    with(|state| {
        if let Some(old) = state.governance_jobs.checks {
            return if old.same(checks) {
                Ok(())
            } else {
                Err(DomainError::Conflict)
            };
        }
        state.governance_jobs.checks = Some(checks);
        Ok(())
    })
}
fn consistent(state: &State, governance: &Governance<'_, '_>) -> Result<(), Error> {
    let original = governance.original_binding();
    if original != state.registry.model()
        || state.models.active().map_err(native_error)? != original
        || state.model_gate.as_ref().ok_or(Error::State)?.active() != original
    {
        return Err(Error::Stale);
    }
    let candidate = ModelBinding {
        model_hash: governance.candidate_hash(),
        ..original
    };
    if state.models.provenance(candidate).map_err(native_error)?
        != (crate::model_bank::Provenance::Validated {
            registration: governance.registration_hash(),
            parent: original.model_hash,
        })
    {
        return Err(Error::Evidence);
    }
    Ok(())
}
fn current(state: &State, governance: &Governance<'_, '_>, job: ScoreJob) -> Result<(), Error> {
    consistent(state, governance)?;
    let b = job.binding;
    let actual = runtime::learning_registration(job.role).map_err(native_error)?;
    if job.original != governance.original_binding()
        || job.registration != governance.registration_hash()
        || job.data != governance.validation_data()
        || b.boot_epoch != state.boot
        || b.controller_epoch != state.registry.publisher().controller_epoch
        || b.model_generation != job.original.generation
        || b.data_generation != state.learning_jobs.data_generation
        || state.learning_jobs.data != Some(job.data)
        || b.core_generation != state.owner.context.core_generation
        || b.ledger_generation != state.owner.context.ledger_generation
        || b.core_generation != actual.core_generation
        || b.ledger_generation != actual.ledger_generation
        || b.role_context != actual.role_context
        || b.image_hash != actual.image_hash
    {
        return Err(Error::Stale);
    }
    Ok(())
}
#[inline(never)]
fn candidates_into(
    output: &mut MaybeUninit<CandidateSet>,
    state: &mut State,
    f: Family,
    target: ObjectKey,
    model: ModelBinding,
    sequence: u64,
    at: u64,
) -> Result<[Option<super::BoundDependency>; 2], DomainError> {
    let current = (f.current)(f.domain, f.kind, target)?;
    let observed = (f.observe)(f.domain, target)?;
    if locate(&state.owner, current, target)
        .and_then(|i| state.owner.desired[i].as_ref())
        .is_some_and(execution_blocks_replacement)
    {
        return Err(DomainError::Busy);
    }
    let slot = ensure_stability(&mut state.owner, current, target, at)?;
    let guard = state.owner.stability[slot]
        .as_ref()
        .ok_or(DomainError::Stale)?;
    let dependencies = bind_dependencies(&state.owner, current, target, at)?;
    let (options, n) = tiers(current);
    let mut legal = [None; 32];
    let mut count = 0;
    for action in options[..n].iter().flatten().copied() {
        match (f.legal)(action, target, at) {
            Ok(()) => {
                legal[count] = Some(action);
                count += 1;
            }
            Err(
                e @ (DomainError::Busy
                | DomainError::Again
                | DomainError::NotReady
                | DomainError::Stale
                | DomainError::NotFound),
            ) => return Err(e),
            Err(_) => {}
        }
    }
    legal[..count].sort_unstable_by_key(|a| a.map(Action::order));
    if current != Action::OfferCpu(0) && !legal[..count].iter().any(|a| *a == Some(current)) {
        return Err(DomainError::Stale);
    }
    let hold = if matches!(current, Action::ControlSet(_) | Action::UnauthRate(_)) {
        1_000_000_000
    } else {
        WINDOW_NS
    };
    let held = at.saturating_sub(guard.last_change_ns()) >= hold;
    let queued = queued_control_wcet_us(state, family_index(f.domain, f.kind)?, at)?;
    let mut choices = [Candidate {
        action: current,
        features: RawFeatures::default(),
    }; 32];
    let mut used = 0;
    for action in legal[..count].iter().flatten().copied() {
        if action != current
            && (guard.frozen()
                || !categorical(action)
                    && (!held
                        || !cyxia_prototype::domains::stability::adjacent(
                            current,
                            action,
                            &legal[..count],
                        )?))
        {
            continue;
        }
        let mut target_features = (f.target_features)(action, target)?;
        if let Action::ControlSet(mask) = action {
            let cores = u64::from(mask.count_ones());
            if cores == 0 {
                return Err(DomainError::Range);
            }
            target_features.values[2] = Some(queued.div_ceil(cores));
        }
        let mut common = state.owner.context.common;
        common[2] = queued / 2_500;
        common[6] = 0;
        choices[used] = Candidate {
            action,
            features: RawFeatures {
                common,
                domain: observed.values,
                domain_present: observed.present,
                target: target_features,
                control_capacity: if let Action::ControlSet(mask) = action {
                    Some(u64::from(mask.count_ones()) * 1000)
                } else {
                    None
                },
            },
        };
        used += 1;
    }
    let snapshot = Snapshot {
        sequence,
        taken_ns: at,
        ledger_generation: state.owner.context.ledger_generation,
        core_generation: state.owner.context.core_generation,
    };
    output.write(CandidateSet::new(
        snapshot,
        target,
        model,
        &choices[..used],
        Some(current),
    )?);
    Ok(dependencies)
}
/// The encoder retains this immutable set in actual pool-backed storage. A
/// score reservation excludes other numerical input preparations until close.
pub fn prepare_score(
    governance: &Governance<'_, '_>,
    role: ExtraRole,
    domain: u16,
    kind: u16,
    ordinal: usize,
) -> Result<(CandidateSet, JobBinding), Error> {
    let mut output = MaybeUninit::uninit();
    let binding = prepare_score_into(&mut output, governance, role, domain, kind, ordinal)?;
    Ok((unsafe { output.assume_init() }, binding))
}
/// Native Session supplies its permanently pinned two-page set destination.
/// No CandidateSet value crosses the numerical driver's small kernel stack.
/// On error the destination must remain unborrowed and may be overwritten.
#[inline(never)]
pub fn prepare_score_into(
    output: &mut MaybeUninit<CandidateSet>,
    governance: &Governance<'_, '_>,
    role: ExtraRole,
    domain: u16,
    kind: u16,
    ordinal: usize,
) -> Result<JobBinding, Error> {
    control(|state| {
        consistent(state, governance)?;
        if state.governance_jobs.busy() || state.learning_jobs.busy() {
            return Err(Error::Unknown);
        }
        if state.registry.optimization_stopped() {
            return Err(Error::Budget);
        }
        let role = match role {
            ExtraRole::Shadow => Role::ShadowScore,
            ExtraRole::Canary => Role::CanaryScore,
            _ => return Err(Error::State),
        };
        if role == Role::CanaryScore && state.job.is_some() {
            return Err(Error::Unknown);
        }
        let at = now();
        let index = family_index(domain, kind).map_err(native_error)?;
        let f = state.owner.families[index].ok_or(Error::DataIncomplete)?;
        let target = (f.target)(domain, kind, ordinal).ok_or(Error::DataIncomplete)?;
        let original = state.registry.model();
        let gate = state.model_gate.as_ref().ok_or(Error::State)?;
        let model = if role == Role::CanaryScore {
            let permit = gate.permit().ok_or(Error::State)?;
            if (domain, kind) != (15, 1)
                || target != permit.target
                || permit.candidate_hash != governance.candidate_hash()
            {
                return Err(Error::Evidence);
            }
            ModelBinding {
                model_hash: permit.candidate_hash,
                ..original
            }
        } else {
            gate.check_active_publication(original, target)?;
            original
        };
        let data = governance.validation_data();
        if state.learning_jobs.data != Some(data) || state.learning_jobs.data_generation == 0 {
            return Err(Error::Stale);
        }
        let actual = runtime::learning_registration(role).map_err(native_error)?;
        if actual.core_generation != state.owner.context.core_generation
            || actual.ledger_generation != state.owner.context.ledger_generation
        {
            return Err(Error::Stale);
        }
        let sequence = state.sequence.checked_add(1).ok_or(Error::Numeric)?;
        let dependencies =
            candidates_into(output, state, f, target, model, sequence, at).map_err(native_error)?;
        let set = unsafe { output.assume_init_mut() };
        if role == Role::CanaryScore {
            let gate = state.model_gate.as_ref().ok_or(Error::State)?;
            state
                .registry
                .register_canary(
                    state.registry.publisher(),
                    set,
                    gate.permit().ok_or(Error::State)?,
                    gate,
                    now(),
                )
                .map_err(native_error)?;
        }
        let job_id = state.worker_sequence.checked_add(1).ok_or(Error::Numeric)?;
        let binding = JobBinding {
            boot_epoch: state.boot,
            job_id,
            controller_epoch: state.registry.publisher().controller_epoch,
            core_generation: actual.core_generation,
            model_generation: original.generation,
            data_generation: state.learning_jobs.data_generation,
            role_context: actual.role_context,
            image_hash: actual.image_hash,
            ledger_generation: actual.ledger_generation,
        };
        binding.validate()?;
        state.sequence = sequence;
        state.worker_sequence = job_id;
        state.governance_jobs.score = Some(ScoreJob {
            binding,
            role,
            original,
            model,
            registration: governance.registration_hash(),
            data,
            snapshot: set.snapshot,
            target,
            set_hash: set.hash(),
            count: set.len(),
            sequence,
            base_version: state.registry.version(),
            dependencies,
            identity: None,
            input: None,
            consumed: false,
        });
        Ok(binding)
    })
}
pub fn submit_score(
    governance: &Governance<'_, '_>,
    prepared: &PreparedScore,
    input: Allocation,
) -> Result<ObjectKey, Error> {
    control(|state| {
        let mut job = state.governance_jobs.score.ok_or(Error::State)?;
        current(state, governance, job)?;
        let h = prepared.header();
        let identity = prepared.identity();
        if prepared.consumed()
            || h.role != job.role
            || h.binding != job.binding
            || h.registration_hash != job.registration
            || h.data_hash != job.data.hash
            || h.set_hash != job.set_hash
            || h.model != job.model
            || h.snapshot != job.snapshot
            || h.target != job.target
            || usize::from(h.count) != job.count
            || h.parent_hash != job.original.model_hash
            || h.candidate_hash != governance.candidate_hash()
            || job.identity.is_some_and(|old| old != identity)
            || job.input.is_some_and(|old| old != input)
        {
            return Err(Error::Evidence);
        }
        let key = runtime::submit_learning(runtime::LearningRequest {
            identity,
            input,
            input_len: prepared.input_len(),
        })
        .map_err(native_error)?;
        if key != job.key() {
            return Err(Error::Evidence);
        }
        job.identity = Some(identity);
        job.input = Some(input);
        state.governance_jobs.score = Some(job);
        Ok(key)
    })
}
struct NativeCompletion<'a, 'b, 'm> {
    state: &'a State,
    governance: &'a Governance<'b, 'm>,
    job: ScoreJob,
}
impl CompletionAuthority for NativeCompletion<'_, '_, '_> {
    fn verify_completion(&self, _: &CompletionClaim) -> Result<(), Error> {
        Err(Error::Evidence)
    }
    fn verify_score_completion(
        &self,
        claim: &CompletionClaim,
        cost: &WorkReceipt,
    ) -> Result<(), Error> {
        current(self.state, self.governance, self.job)?;
        if self.job.consumed
            || self.job.identity != Some(claim.identity)
            || self.job.input.is_none()
        {
            return Err(Error::Evidence);
        }
        runtime::verify_learning_score_completion(claim, cost)
    }
}
pub fn accept_score(
    governance: &Governance<'_, '_>,
    prepared: &mut PreparedScore,
    output: &[u8],
    cost: &WorkReceipt,
) -> Result<Scored, Error> {
    control(|state| {
        let mut job = state.governance_jobs.score.ok_or(Error::State)?;
        if job.identity != Some(prepared.identity()) {
            return Err(Error::Evidence);
        }
        let scored = governance.accept_score(
            prepared,
            output,
            cost,
            &NativeCompletion {
                state,
                governance,
                job,
            },
            now(),
        )?;
        job.consumed = true;
        state.governance_jobs.score = Some(job);
        Ok(scored)
    })
}
pub fn record_shadow(
    governance: &mut Governance<'_, '_>,
    scored: &mut Option<Scored>,
    cost: &mut Option<WorkReceipt>,
) -> Result<(), Error> {
    control(|state| {
        let job = state.governance_jobs.score.ok_or(Error::State)?;
        current(state, governance, job)?;
        if !job.consumed || job.role != Role::ShadowScore {
            return Err(Error::Evidence);
        }
        if scored.is_none() || cost.is_none() {
            return Err(Error::State);
        }
        governance.record_shadow(
            scored.take().ok_or(Error::State)?.into_proof(),
            cost.take().ok_or(Error::State)?,
        )
    })
}
pub fn close_shadow_window(governance: &mut Governance<'_, '_>) -> Result<(), Error> {
    control(|state| {
        consistent(state, governance)?;
        governance.close_shadow_window(now())
    })
}
/// Discard only known terminal results; stale generations do not strand an
/// input loan, and UNKNOWN/running work never becomes reusable memory.
pub fn close_score(key: ObjectKey) -> Result<(), Error> {
    control(|state| {
        let job = state.governance_jobs.score.ok_or(Error::State)?;
        if job.key() != key {
            return Err(Error::Stale);
        }
        if job.identity.is_some() {
            match runtime::query_learning(key).map_err(native_error)? {
                runtime::LearningStatus::Pending | runtime::LearningStatus::Running => {
                    return Err(Error::Unknown);
                }
                _ => {}
            }
            runtime::acknowledge_learning(key).map_err(native_error)?;
        }
        state.governance_jobs.score = None;
        Ok(())
    })
}
fn receipt_for(owner: &Owner, apply: ApplyId, version: u64) -> Result<CanaryReceipt, Error> {
    let d = owner
        .desired
        .iter()
        .flatten()
        .find(|d| d.apply == apply && d.stamp.version == version)
        .ok_or(Error::Stale)?;
    if !matches!(d.action, Action::ConsoleBatch(_)) {
        return Err(Error::Evidence);
    }
    if d.state == ExecutionState::Applied && d.first_entry_ns.is_none() {
        return Err(Error::Evidence);
    }
    let generation = owner.family_epochs[family_index(15, 1).map_err(native_error)?];
    if generation == 0 {
        return Err(Error::Evidence);
    }
    let mut receipt = CanaryReceipt {
        apply,
        plan_version: version,
        executor_generation: generation,
        model: d.model,
        state: d.state,
        actual: (d.state == ExecutionState::Applied).then_some(d.action),
        started_ns: d.first_entry_ns.unwrap_or(d.published),
        finished_ns: d.observed_ns,
        installed_until_ns: d.stamp.installed_until_ns,
        evidence_hash: [0; 32],
    };
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_NATIVE_CONSOLE_RECEIPT_1.3\0");
    for value in [
        apply.boot_epoch,
        apply.controller_epoch,
        apply.plan_seq,
        u64::from(apply.action_index),
        apply.target.id,
        apply.target.generation,
        version,
        generation,
        d.model.generation,
        receipt.started_ns,
        receipt.finished_ns,
        receipt.installed_until_ns,
    ] {
        hash.update(value.to_le_bytes());
    }
    hash.update(d.model.model_hash);
    hash.update(d.model.schema_hash);
    let mut bytes = [0; 16];
    let n = policy_wire::encode_payload(d.action, 0, &mut bytes).map_err(native_error)?;
    hash.update(&bytes[..n]);
    let (status, error) = match d.state {
        ExecutionState::Pending => (0u64, 0),
        ExecutionState::Applied => (1, 0),
        ExecutionState::Unknown => (2, 0),
        ExecutionState::Failed(e) => (3, e as u64),
    };
    hash.update(status.to_le_bytes());
    hash.update(error.to_le_bytes());
    receipt.evidence_hash = hash.finalize().into();
    Ok(receipt)
}
struct Authority<'a> {
    owner: &'a Owner,
    checks: Option<EvidenceChecks>,
    restoration: Option<Restoration>,
    publication: Option<PublicationClock>,
}
impl GovernanceAuthority for Authority<'_> {
    fn registered_noncritical_console(&self, target: TargetRegistration) -> Result<(), Error> {
        if crate::domain_services::canary_target().map_err(native_error)? != target {
            return Err(Error::Evidence);
        }
        Ok(())
    }
    fn legal_console(&self, target: ObjectKey, action: Action, at: u64) -> Result<(), Error> {
        if !matches!(action, Action::ConsoleBatch(_)) {
            return Err(Error::Safety);
        }
        let f = self.owner.families[family_index(15, 1).map_err(native_error)?]
            .ok_or(Error::DataIncomplete)?;
        (f.legal)(action, target, at).map_err(native_error)?;
        if let Some(publication) = self.publication {
            // No callback or clock reset follows this final permit/window
            // check before the protected Governance publication mutation.
            publication.check(at, policy::Clock::read(&mut NativeClock))?;
        }
        Ok(())
    }
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), Error> {
        if receipt_for(self.owner, receipt.apply, receipt.plan_version)? != *receipt {
            return Err(Error::Evidence);
        }
        Ok(())
    }
    fn verify_measurement(
        &self,
        permit: CanaryPermit,
        second: u16,
        baseline: &[WorkRequest],
        candidate: &[WorkRequest],
        digest: [u8; 32],
    ) -> Result<(), Error> {
        (self.checks.ok_or(Error::DataIncomplete)?.measurement)(
            permit, second, baseline, candidate, digest,
        )
    }
    fn authorize_extension(
        &self,
        registration: [u8; 32],
        permit: CanaryPermit,
        at: u64,
        windows: u16,
    ) -> Result<(), Error> {
        (self.checks.ok_or(Error::DataIncomplete)?.extension)(registration, permit, at, windows)
    }
    fn verify_restoration(
        &self,
        request: RestorationRequest,
        receipt: &RestorationReceipt,
    ) -> Result<(), Error> {
        let record = self.restoration.ok_or(Error::DataIncomplete)?;
        if record.request != request || restoration_receipt(self.owner, record)? != *receipt {
            return Err(Error::Evidence);
        }
        Ok(())
    }
}
pub fn begin_canary(governance: &mut Governance<'_, '_>) -> Result<CanaryPermit, Error> {
    control(|state| {
        if !super::replay::model_change_allowed() {
            return Err(Error::Unknown);
        }
        consistent(state, governance)?;
        let target = crate::domain_services::canary_target().map_err(native_error)?;
        let auth = Authority {
            owner: &state.owner,
            checks: state.governance_jobs.checks,
            restoration: state.governance_jobs.restoration,
            publication: None,
        };
        governance.begin_canary(
            state.model_gate.as_mut().ok_or(Error::State)?,
            target,
            now(),
            &auth,
        )
    })
}
struct CanaryScope<'a, 'b, 'm> {
    gate: &'a mut CommitGate,
    governance: &'a mut Governance<'b, 'm>,
    scored: &'a mut Option<Scored>,
    cost: &'a mut Option<WorkReceipt>,
    started: policy::PublicationTime,
    deadline: u64,
}
fn domain_error(error: Error) -> DomainError {
    match error {
        Error::Unknown | Error::State => DomainError::Busy,
        Error::Stale => DomainError::Stale,
        Error::Deadline => DomainError::Expired,
        Error::Budget => DomainError::Budget,
        Error::Capacity => DomainError::Capacity,
        _ => DomainError::Auth,
    }
}
impl PublicationScope for CanaryScope<'_, '_, '_> {
    fn authorize(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), DomainError> {
        if set.canary_permit().is_none() {
            return Err(DomainError::Auth);
        }
        set.authorize_with_gate(active, self.gate, at)
    }
    fn commit(
        &mut self,
        owner: &Owner,
        model: ModelBinding,
        plan: &Plan,
        stamps: &[PolicyStamp],
        boot: u64,
        at: u64,
    ) -> Result<(), DomainError> {
        if plan.len() != 1 || stamps.len() != 1 {
            return Err(DomainError::Conflict);
        }
        let d = plan.iter().next().ok_or(DomainError::Format)?;
        self.scored
            .as_ref()
            .ok_or(DomainError::Auth)?
            .proof()
            .verify_selection(
                d.envelope.candidate_set_hash,
                model,
                d.envelope.target,
                stamps[0].snapshot_ns,
                d.candidate_index,
                d.action,
            )
            .map_err(domain_error)?;
        let auth = Authority {
            owner,
            checks: None,
            restoration: None,
            publication: Some(PublicationClock {
                started: self.started,
                deadline_ns: self.deadline,
                permit: self.gate.permit().ok_or(DomainError::Auth)?,
            }),
        };
        let apply = ApplyId {
            boot_epoch: boot,
            controller_epoch: plan.header.controller_epoch,
            plan_seq: plan.header.plan_seq,
            action_index: 0,
            target: d.envelope.target,
        };
        match self
            .governance
            .publish(
                self.gate,
                at,
                self.scored.take().ok_or(DomainError::Auth)?.into_proof(),
                self.cost.take().ok_or(DomainError::Auth)?,
                apply,
                stamps[0],
                &auth,
            )
            .map_err(domain_error)?
        {
            Publication::New => Ok(()),
            Publication::Existing => Err(DomainError::Conflict),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanaryPublication {
    Published {
        apply: ApplyId,
        version: u64,
    },
    /// Registry has definitively refused this attempt. Its identity cannot be
    /// rebound, even when the numerical proof remains available for cleanup.
    Rejected(Error),
}
pub fn publish_canary(
    governance: &mut Governance<'_, '_>,
    scored: &mut Option<Scored>,
    cost: &mut Option<WorkReceipt>,
) -> Result<CanaryPublication, Error> {
    // The same publication clock includes native identity/model validation
    // and admission; it is never restarted after those fallible checks.
    let publication_started = policy::Clock::read(&mut NativeClock);
    let started = publication_started.wall_ns;
    control(|state| {
        let job = state.governance_jobs.score.ok_or(Error::State)?;
        current(state, governance, job)?;
        if !job.consumed || job.role != Role::CanaryScore {
            return Err(Error::Evidence);
        }
        let deadline = job
            .snapshot
            .taken_ns
            .checked_add(50_000_000)
            .ok_or(Error::Numeric)?;
        if started > deadline {
            return Err(Error::Deadline);
        }
        let prepared = scored.as_ref().ok_or(Error::State)?;
        if cost.is_none() {
            return Err(Error::State);
        }
        let index = prepared.selected();
        let mut scores = [0; 32];
        if prepared.scores().len() != job.count {
            return Err(Error::Evidence);
        }
        scores[..job.count].copy_from_slice(prepared.scores());
        let selected = state
            .registry
            .registered_action(job.set_hash, usize::from(index))
            .map_err(native_error)?;
        prepared.proof().verify_selection(
            job.set_hash,
            job.model,
            job.target,
            job.snapshot.taken_ns,
            index,
            selected,
        )?;
        let header = PlanHeader {
            plan_seq: job.sequence,
            base_plan_version: job.base_version,
            active_model_generation: job.model.generation,
            controller_epoch: job.binding.controller_epoch,
            snapshot_seq: job.snapshot.sequence,
            active_until_local_ns: job
                .snapshot
                .taken_ns
                .checked_add(POLICY_NS)
                .ok_or(Error::Numeric)?,
        };
        let decision = policy_wire::Decision {
            action: selected,
            candidate_index: index,
            envelope: policy_wire::Envelope {
                controller_epoch: job.binding.controller_epoch,
                decision_seq: job.sequence,
                snapshot_seq: job.snapshot.sequence,
                target: job.target,
                ledger_generation: job.snapshot.ledger_generation,
                core_generation: job.snapshot.core_generation,
                expires_local_ns: job
                    .snapshot
                    .taken_ns
                    .checked_add(WINDOW_NS)
                    .ok_or(Error::Numeric)?,
                model_hash: job.model.model_hash,
                candidate_set_hash: job.set_hash,
            },
        };
        let mut wire = [0; 384];
        let used =
            policy_wire::encode_plan(header, &[decision], &mut wire).map_err(native_error)?;
        // The scope borrows both non-clonable capabilities. Even a later owner
        // Busy leaves them retained unless the actual commit consumes them.
        let scope = CanaryScope {
            gate: state.model_gate.as_mut().ok_or(Error::State)?,
            governance,
            scored,
            cost,
            started: publication_started,
            deadline,
        };
        let mut executor = Executor {
            owner: &mut state.owner,
            scope,
            model: job.model,
            evidence: None,
            job: job.sequence,
            boot: state.boot,
            publication_started,
            wall_deadline: deadline,
            dependencies: job.dependencies,
            scores,
            score_count: job.count,
            provenance: submission::Facts::disabled(),
        };
        let receipt = match state.registry.submit_job(
            publisher(job.binding.controller_epoch),
            &wire[..used],
            publication_started,
            deadline,
            &mut NativeClock,
            &mut executor,
        ) {
            Ok(receipt) => receipt,
            Err(error) => return Ok(CanaryPublication::Rejected(native_error(error))),
        };
        if receipt.version == 0 {
            return Ok(CanaryPublication::Rejected(match receipt.state() {
                ExecutionState::Failed(e) => native_error(e),
                _ => Error::Evidence,
            }));
        }
        Ok(CanaryPublication::Published {
            apply: ApplyId {
                boot_epoch: state.boot,
                controller_epoch: job.binding.controller_epoch,
                plan_seq: job.sequence,
                action_index: 0,
                target: job.target,
            },
            version: receipt.version,
        })
    })
}
pub fn reconcile(
    governance: &mut Governance<'_, '_>,
    apply: ApplyId,
    version: u64,
) -> Result<ExecutionState, Error> {
    maintenance(|state| {
        let receipt = receipt_for(&state.owner, apply, version)?;
        let auth = Authority {
            owner: &state.owner,
            checks: state.governance_jobs.checks,
            restoration: state.governance_jobs.restoration,
            publication: None,
        };
        governance.reconcile(
            state.model_gate.as_mut().ok_or(Error::State)?,
            receipt,
            &auth,
        )?;
        Ok(receipt.state)
    })
}
pub fn observe_second(
    governance: &mut Governance<'_, '_>,
    second: u16,
    baseline: &[WorkRequest],
    candidate: &[WorkRequest],
    workspace: &mut RewardWorkspace,
) -> Result<(), Error> {
    control(|state| {
        let auth = Authority {
            owner: &state.owner,
            checks: state.governance_jobs.checks,
            restoration: state.governance_jobs.restoration,
            publication: None,
        };
        governance.observe_second(
            state.model_gate.as_mut().ok_or(Error::State)?,
            second,
            baseline,
            candidate,
            workspace,
            &auth,
        )
    })
}
pub fn observe_second_bounded(
    governance: &mut Governance<'_, '_>,
    second: u16,
    baseline: &[WorkRequest],
    candidate: &[WorkRequest],
    latencies: &mut [u64],
) -> Result<(), Error> {
    control(|state| {
        let auth = Authority {
            owner: &state.owner,
            checks: state.governance_jobs.checks,
            restoration: state.governance_jobs.restoration,
            publication: None,
        };
        governance.observe_second_bounded(
            state.model_gate.as_mut().ok_or(Error::State)?,
            second,
            baseline,
            candidate,
            latencies,
            &auth,
        )
    })
}
pub fn extend(governance: &mut Governance<'_, '_>, windows: u16) -> Result<(), Error> {
    control(|state| {
        let auth = Authority {
            owner: &state.owner,
            checks: state.governance_jobs.checks,
            restoration: state.governance_jobs.restoration,
            publication: None,
        };
        governance.extend(
            state.model_gate.as_mut().ok_or(Error::State)?,
            now(),
            windows,
            &auth,
        )
    })
}
pub fn tick(governance: &mut Governance<'_, '_>) -> Result<(), Error> {
    maintenance(|state| {
        governance.tick(state.model_gate.as_mut().ok_or(Error::State)?, now());
        Ok(())
    })
}
pub fn abort(governance: &mut Governance<'_, '_>, reason: Error) -> Result<(), Error> {
    maintenance(|state| {
        governance.abort(state.model_gate.as_mut().ok_or(Error::State)?, reason);
        Ok(())
    })
}
fn restoration_receipt(owner: &Owner, record: Restoration) -> Result<RestorationReceipt, Error> {
    let actual = receipt_for(owner, record.apply, record.version)?;
    if actual.state != ExecutionState::Applied
        || actual.actual != Some(record.request.target.baseline)
    {
        return Err(Error::Unknown);
    }
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_NATIVE_RESTORATION_1.3\0");
    hash.update(record.request.boot_epoch.to_le_bytes());
    hash.update(record.request.id.to_le_bytes());
    hash.update(actual.evidence_hash);
    Ok(RestorationReceipt {
        boot_epoch: record.request.boot_epoch,
        restoration_id: record.request.id,
        target: record.request.target.key,
        actual: record.request.target.baseline,
        actual_version: record.version,
        executor_generation: actual.executor_generation,
        state: actual.state,
        evidence_hash: hash.finalize().into(),
    })
}
struct RestoreScope<'a> {
    gate: &'a CommitGate,
    request: RestorationRequest,
}
impl RestoreScope<'_> {
    fn check(&self, model: ModelBinding, plan: &Plan) -> Result<(), DomainError> {
        if self.gate.active() != model
            || self.gate.restoration_request() != Some(self.request)
            || plan.len() != 1
        {
            return Err(DomainError::Stale);
        }
        let d = plan.iter().next().ok_or(DomainError::Format)?;
        if d.envelope.target != self.request.target.key
            || d.action != self.request.target.baseline
            || !matches!(d.action, Action::ConsoleBatch(_))
            || d.envelope.model_hash != model.model_hash
            || plan.header.active_model_generation != model.generation
        {
            return Err(DomainError::Auth);
        }
        Ok(())
    }
}
impl PublicationScope for RestoreScope<'_> {
    fn authorize_executor(&self, owner: &Owner) -> Result<(), DomainError> {
        if self.gate.restoration_request() != Some(self.request) {
            return Err(DomainError::Stale);
        }
        if cyxia_arch_aarch64::cpu::slot() == 0 {
            crate::domain_tasks::authorize_service_turn()
        } else {
            super::require_control(owner)
        }
    }
    fn authorize(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        _: u64,
    ) -> Result<(), DomainError> {
        if active != self.gate.active()
            || set.model != active
            || set.canary_permit().is_some()
            || set.target != self.request.target.key
            || self.gate.restoration_request() != Some(self.request)
        {
            return Err(DomainError::Stale);
        }
        Ok(())
    }
    fn authorize_recovery(
        &mut self,
        active: ModelBinding,
        plan: &Plan,
        _: u64,
    ) -> Result<(), DomainError> {
        self.check(active, plan)
    }
    fn selection(
        &self,
        _: &Owner,
        _: Family,
        action: Action,
        target: ObjectKey,
        _: u64,
    ) -> Result<(), DomainError> {
        // The exact frozen baseline is a restoration obligation, not another
        // optimization tier. Hard legality/dependencies still run every pass.
        if self.gate.restoration_request() == Some(self.request)
            && target == self.request.target.key
            && action == self.request.target.baseline
        {
            Ok(())
        } else {
            Err(DomainError::Auth)
        }
    }
    fn commit(
        &mut self,
        _: &Owner,
        model: ModelBinding,
        plan: &Plan,
        _: &[PolicyStamp],
        boot: u64,
        _: u64,
    ) -> Result<(), DomainError> {
        if boot != self.request.boot_epoch {
            return Err(DomainError::Stale);
        }
        self.check(model, plan)
    }
}
/// Keep the failed Canary's original obligation until a real terminal receipt.
/// Only then install the registered baseline and verify actual UART use under
/// its own fresh version. Publishing restoration never clears its gate.
pub fn restore(governance: &mut Governance<'_, '_>) -> Result<ExecutionState, Error> {
    maintenance(|state| {
        // The root executor may have learned a late terminal result while
        // Governance still owns UNKNOWN. Import that exact receipt before a
        // baseline publication can replace this object's desired record.
        let pending = governance
            .submissions()
            .find(|submission| !submission.state.terminal());
        if let Some(submission) = pending {
            let receipt = receipt_for(&state.owner, submission.apply, submission.stamp.version)?;
            let auth = Authority {
                owner: &state.owner,
                checks: state.governance_jobs.checks,
                restoration: state.governance_jobs.restoration,
                publication: None,
            };
            let result = governance.reconcile(
                state.model_gate.as_mut().ok_or(Error::State)?,
                receipt,
                &auth,
            );
            match result {
                Ok(()) => {}
                Err(Error::Deadline) if receipt.state.terminal() => {
                    // A genuine late completion closes custody but never
                    // rehabilitates the failed Canary's promotion eligibility.
                }
                Err(error) => return Err(error),
            }
            if !receipt.state.terminal() {
                return Ok(receipt.state);
            }
        }
        let gate = state.model_gate.as_ref().ok_or(Error::State)?;
        let request = gate.restoration_request().ok_or(Error::State)?;
        let active = state.registry.model();
        if gate.active() != active || state.models.active().map_err(native_error)? != active {
            return Err(Error::Stale);
        }
        if let Some(record) = state
            .governance_jobs
            .restoration
            .filter(|r| r.request == request)
        {
            let actual = receipt_for(&state.owner, record.apply, record.version)?;
            if actual.state == ExecutionState::Applied {
                let receipt = restoration_receipt(&state.owner, record)?;
                let auth = Authority {
                    owner: &state.owner,
                    checks: state.governance_jobs.checks,
                    restoration: Some(record),
                    publication: None,
                };
                governance.restored(
                    state.model_gate.as_mut().ok_or(Error::State)?,
                    receipt,
                    &auth,
                )?;
                return Ok(ExecutionState::Applied);
            }
            if !actual.state.terminal() {
                return Ok(actual.state);
            }
        }
        let publication_started = policy::Clock::read(&mut NativeClock);
        let started = publication_started.wall_ns;
        let target = request.target.key;
        let baseline = request.target.baseline;
        let f = state.owner.families[family_index(15, 1).map_err(native_error)?]
            .ok_or(Error::DataIncomplete)?;
        if locate(&state.owner, baseline, target)
            .and_then(|i| state.owner.desired[i].as_ref())
            .is_some_and(execution_blocks_replacement)
        {
            return Err(Error::Unknown);
        }
        let current = (f.current)(15, 1, target).map_err(native_error)?;
        let observed = (f.observe)(15, target).map_err(native_error)?;
        (f.legal)(baseline, target, started).map_err(native_error)?;
        ensure_stability(&mut state.owner, current, target, started).map_err(native_error)?;
        let dependencies =
            bind_dependencies(&state.owner, baseline, target, started).map_err(native_error)?;
        let choices = [current, baseline].map(|action| {
            (f.target_features)(action, target).map(|target| Candidate {
                action,
                features: RawFeatures {
                    common: state.owner.context.common,
                    domain: observed.values,
                    domain_present: observed.present,
                    target,
                    control_capacity: None,
                },
            })
        });
        let choices = [
            choices[0].map_err(native_error)?,
            choices[1].map_err(native_error)?,
        ];
        let sequence = state.sequence.checked_add(1).ok_or(Error::Numeric)?;
        let snapshot = Snapshot {
            sequence,
            taken_ns: started,
            core_generation: state.owner.context.core_generation,
            ledger_generation: state.owner.context.ledger_generation,
        };
        let set = CandidateSet::new(snapshot, target, active, &choices, Some(current))
            .map_err(native_error)?;
        state
            .registry
            .register(state.registry.publisher(), &set)
            .map_err(native_error)?;
        let selected = set
            .iter()
            .position(|c| c.action == baseline)
            .ok_or(Error::Evidence)? as u16;
        let controller = state.registry.publisher().controller_epoch;
        let header = PlanHeader {
            plan_seq: sequence,
            base_plan_version: state.registry.version(),
            active_model_generation: active.generation,
            controller_epoch: controller,
            snapshot_seq: sequence,
            active_until_local_ns: started.checked_add(POLICY_NS).ok_or(Error::Numeric)?,
        };
        let decision = policy_wire::Decision {
            action: baseline,
            candidate_index: selected,
            envelope: policy_wire::Envelope {
                controller_epoch: controller,
                decision_seq: sequence,
                snapshot_seq: sequence,
                target,
                ledger_generation: snapshot.ledger_generation,
                core_generation: snapshot.core_generation,
                expires_local_ns: started.checked_add(WINDOW_NS).ok_or(Error::Numeric)?,
                model_hash: active.model_hash,
                candidate_set_hash: set.hash(),
            },
        };
        let mut wire = [0; 384];
        let used =
            policy_wire::encode_plan(header, &[decision], &mut wire).map_err(native_error)?;
        state.sequence = sequence;
        let mut executor = Executor {
            owner: &mut state.owner,
            scope: RestoreScope {
                gate: state.model_gate.as_ref().ok_or(Error::State)?,
                request,
            },
            model: active,
            evidence: None,
            job: sequence,
            boot: state.boot,
            publication_started,
            wall_deadline: started.checked_add(50_000_000).ok_or(Error::Numeric)?,
            dependencies,
            scores: [0; 32],
            score_count: 0,
            provenance: submission::Facts::disabled(),
        };
        let receipt = state
            .registry
            .submit_job(
                publisher(controller),
                &wire[..used],
                publication_started,
                executor.wall_deadline,
                &mut NativeClock,
                &mut executor,
            )
            .map_err(native_error)?;
        if receipt.version == 0 {
            return Err(match receipt.state() {
                ExecutionState::Failed(e) => native_error(e),
                _ => Error::Evidence,
            });
        }
        let apply = ApplyId {
            boot_epoch: state.boot,
            controller_epoch: controller,
            plan_seq: sequence,
            action_index: 0,
            target,
        };
        state.governance_jobs.restoration = Some(Restoration {
            request,
            apply,
            version: receipt.version,
        });
        Ok(ExecutionState::Pending)
    })
}
