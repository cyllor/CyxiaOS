//! Protected admission for the separately budgeted numerical worker. Native
//! callers run these bounded steps through the C1 extra-work driver. This gate
//! cannot construct replay labels or replace an absent FrozenData with rows
//! received over the worker transport.
use super::{Error as DomainError, State, require_control, with};
use crate::{control_pool::Allocation, smp::prototype_runtime as runtime};
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error,
        data::{DataManifest, FrozenData},
        manifest::ModelManifest,
        governance::{Governance, GovernanceInit, InitComplete},
        train::TrainedModel,
        validate::ValidatedCandidate,
        worker::{CompletionAuthority, CompletionClaim, PreparedJob},
        worker_wire::{JobBinding, JobIdentity, Role},
    },
    model::MODEL_BYTES,
    policy::ModelBinding,
};

#[derive(Clone, Copy)]
struct Job {
    role: Role,
    binding: JobBinding,
    model: ModelBinding,
    data: DataManifest,
    identity: Option<JobIdentity>,
    input: Option<Allocation>,
    consumed: bool,
    registration: Option<[u8; 32]>,
    staged: Option<ModelBinding>,
}
pub(super) struct Jobs {
    pub(super) data_generation: u64,
    pub(super) data: Option<DataManifest>,
    job: Option<Job>,
}
impl Jobs {
    pub(super) const fn new() -> Self {
        Self { data_generation: 0, data: None, job: None }
    }
    pub(super) fn busy(&self) -> bool { self.job.is_some() }
}
pub(super) fn native_error(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Stale => Error::Stale,
        DomainError::Budget => Error::Budget,
        DomainError::Expired => Error::Deadline,
        DomainError::Capacity => Error::Capacity,
        DomainError::Overflow | DomainError::Range => Error::Numeric,
        DomainError::Schema => Error::Schema,
        DomainError::Conflict => Error::Conflict,
        _ => Error::Evidence,
    }
}
pub(super) fn control<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 1 { return Err(Error::State); }
    runtime::authorize_learning_turn().map_err(native_error)?;
    with(|state| {
        require_control(&state.owner)?;
        Ok(f(state))
    }).map_err(native_error)?
}
fn current(state: &State, job: Job) -> Result<(), Error> {
    let b = job.binding;
    if state.boot == 0 || b.boot_epoch != state.boot
        || b.controller_epoch != state.registry.publisher().controller_epoch
        || job.model != state.registry.model()
        || state.models.active().map_err(native_error)? != job.model
        || state.model_gate.as_ref().ok_or(Error::State)?.active() != job.model
        || b.core_generation != state.owner.context.core_generation
        || b.ledger_generation != state.owner.context.ledger_generation
        || b.model_generation != job.model.generation
        || b.data_generation != state.learning_jobs.data_generation
        || state.learning_jobs.data != Some(job.data) {
        return Err(Error::Stale);
    }
    let actual = runtime::learning_registration(job.role).map_err(native_error)?;
    if b.role_context != actual.role_context || b.image_hash != actual.image_hash
        || b.core_generation != actual.core_generation
        || b.ledger_generation != actual.ledger_generation {
        return Err(Error::Stale);
    }
    Ok(())
}
fn key(job: Job) -> ObjectKey {
    ObjectKey { id: job.binding.job_id, generation: job.binding.boot_epoch }
}

/// Called only after real protected replay labels have passed FrozenData's
/// grouped split/minimum coverage checks. Repeated preparation retains the
/// same identity; another dataset cannot replace an outstanding worker loan.
pub fn binding(role: Role, data: &FrozenData<'_>) -> Result<JobBinding, Error> {
    control(|state| {
        if state.governance_jobs.busy() { return Err(Error::Unknown); }
        let manifest = data.manifest();
        let schemas = state.models.schemas().map_err(native_error)?;
        if manifest.feature_schema != schemas.feature || manifest.action_schema != schemas.action
            || manifest.reward_schema != schemas.reward || manifest.learning_config != schemas.learning {
            return Err(Error::Schema);
        }
        if let Some(job) = state.learning_jobs.job {
            current(state, job)?;
            return if job.role == role && job.data == manifest && job.identity.is_none() {
                Ok(job.binding)
            } else { Err(Error::State) };
        }
        let actual = runtime::learning_registration(role).map_err(native_error)?;
        let model = state.models.active().map_err(native_error)?;
        if state.model_gate.as_ref().ok_or(Error::State)?.active() != model
            || state.registry.model() != model || state.boot == 0 {
            return Err(Error::Stale);
        }
        let generation = if state.learning_jobs.data == Some(manifest) {
            state.learning_jobs.data_generation
        } else { state.learning_jobs.data_generation.checked_add(1).ok_or(Error::Numeric)? };
        let job_id = state.worker_sequence.checked_add(1).ok_or(Error::Numeric)?;
        let binding = JobBinding {
            boot_epoch: state.boot, job_id,
            controller_epoch: state.registry.publisher().controller_epoch,
            core_generation: actual.core_generation,
            model_generation: model.generation, data_generation: generation,
            role_context: actual.role_context, image_hash: actual.image_hash,
            ledger_generation: actual.ledger_generation,
        };
        binding.validate()?;
        if binding.core_generation != state.owner.context.core_generation
            || binding.ledger_generation != state.owner.context.ledger_generation {
            return Err(Error::Stale);
        }
        state.worker_sequence = job_id;
        state.learning_jobs.data_generation = generation;
        state.learning_jobs.data = Some(manifest);
        state.learning_jobs.job = Some(Job { role, binding, model, data: manifest,
            identity: None, input: None, consumed: false, registration: None, staged: None });
        Ok(binding)
    })
}
pub fn pin_parent(binding: JobBinding) -> Result<super::NativeModelPin, Error> {
    control(|state| {
        let job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        current(state, job)?;
        if job.binding != binding || job.consumed { return Err(Error::Stale); }
        state.models.pin(job.model).map_err(native_error)
    })
}
pub fn pin_active() -> Result<super::NativeModelPin, Error> {
    control(|state| {
        let active = state.registry.model();
        if state.models.active().map_err(native_error)? != active
            || state.model_gate.as_ref().ok_or(Error::State)?.active() != active {
            return Err(Error::Stale);
        }
        state.models.pin(active).map_err(native_error)
    })
}
pub fn prepare_governance<'a, 'model>(candidate: &'a ValidatedCandidate<'model>,
    old: &'a [u8; MODEL_BYTES], start_window: u64) -> Result<GovernanceInit<'a, 'model>, Error> {
    control(|state| {
        let active = state.registry.model();
        if state.models.active().map_err(native_error)? != active {
            return Err(Error::Stale);
        }
        let binding = ModelBinding { model_hash: candidate.model().manifest().parameters_hash, ..active };
        if state.models.provenance(binding).map_err(native_error)?
            != (crate::model_bank::Provenance::Validated {
                registration: candidate.registration_hash(), parent: active.model_hash }) {
            return Err(Error::Evidence);
        }
        GovernanceInit::new(state.model_gate.as_ref().ok_or(Error::State)?, candidate, old, start_window)
    })
}
pub fn finish_governance<'a, 'model>(init: &mut Option<GovernanceInit<'a, 'model>>)
    -> Result<InitComplete<'a, 'model>, Error> {
    control(|state| {
        if state.models.active().map_err(native_error)? != state.registry.model() {
            return Err(Error::Stale);
        }
        let gate = state.model_gate.as_ref().ok_or(Error::State)?;
        init.as_ref().ok_or(Error::State)?.check_finish(gate)?;
        // No mutation/callback can change the gate between this check and
        // consuming the recipe. Busy/stale retries keep the original recipe.
        init.take().ok_or(Error::State)?.finish(gate)
    })
}

/// Encoder has finished incrementally before this call. The runtime pins and
/// hashes the actual sealed allocation, not an EL0-reported input digest.
pub fn submit(prepared: &PreparedJob, input: Allocation) -> Result<ObjectKey, Error> {
    control(|state| {
        let mut job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        current(state, job)?;
        let header = prepared.header();
        let identity = prepared.identity();
        if prepared.consumed() || header.binding != job.binding || header.role != job.role
            || header.data != job.data || header.parent_hash != job.model.model_hash
            || job.identity.is_some_and(|old| old != identity)
            || job.input.is_some_and(|old| old != input) {
            return Err(Error::Evidence);
        }
        let result = runtime::submit_learning(runtime::LearningRequest {
            identity, input, input_len: prepared.input_len(),
        }).map_err(native_error)?;
        if result != key(job) { return Err(Error::Evidence); }
        job.identity = Some(identity);
        job.input = Some(input);
        state.learning_jobs.job = Some(job);
        Ok(result)
    })
}

struct NativeCompletion<'a> { state: &'a State, job: Job }
impl CompletionAuthority for NativeCompletion<'_> {
    fn verify_completion(&self, claim: &CompletionClaim) -> Result<(), Error> {
        current(self.state, self.job)?;
        if self.job.consumed || self.job.identity != Some(claim.identity)
            || self.job.input.is_none() {
            return Err(Error::Evidence);
        }
        // This consumes the exact stopped context's authenticated completion
        // once. Current model/data/controller checks and native custody checks
        // remain in the same root critical section.
        runtime::verify_learning_completion(claim)
    }
}
pub fn accept_training(prepared: &mut PreparedJob, output: &[u8]) -> Result<TrainedModel, Error> {
    control(|state| {
        let mut job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        if job.role != Role::Training || job.identity != Some(prepared.identity()) {
            return Err(Error::Evidence);
        }
        let result = prepared.accept_training(output, &NativeCompletion { state, job })?;
        job.consumed = true;
        state.learning_jobs.job = Some(job);
        Ok(result)
    })
}
pub fn accept_validation<'a>(
    prepared: &mut PreparedJob, candidate: &'a [u8; MODEL_BYTES],
    manifest: ModelManifest, output: &[u8],
) -> Result<ValidatedCandidate<'a>, Error> {
    control(|state| {
        let mut job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        if job.role != Role::Validation || job.identity != Some(prepared.identity()) {
            return Err(Error::Evidence);
        }
        let result = prepared.accept_validation(candidate, manifest, output,
            &NativeCompletion { state, job })?;
        job.consumed = true;
        job.registration = Some(result.registration_hash());
        state.learning_jobs.job = Some(job);
        Ok(result)
    })
}
/// A typed host validation result alone is insufficient: the root must also
/// own this exact accepted native Validation receipt before writing the bank.
pub fn stage(candidate: &ValidatedCandidate<'_>) -> Result<ModelBinding, Error> {
    control(|state| {
        let mut job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        current(state, job)?;
        if job.role != Role::Validation || !job.consumed
            || job.registration != Some(candidate.registration_hash()) {
            return Err(Error::Evidence);
        }
        let binding = state.models.stage(candidate).map_err(native_error)?;
        job.staged = Some(binding);
        state.learning_jobs.job = Some(job);
        Ok(binding)
    })
}
/// Transfer independent validation custody to the immutable bank before the
/// numerical worker's input/output allocations are acknowledged and reused.
pub fn pin_staged(binding: ModelBinding) -> Result<super::NativeModelPin, Error> {
    control(|state| {
        let job = state.learning_jobs.job.ok_or(Error::DataIncomplete)?;
        current(state, job)?;
        if job.role != Role::Validation || !job.consumed || job.registration.is_none()
            || job.staged != Some(binding) {
            return Err(Error::Evidence);
        }
        state.models.pin(binding).map_err(native_error)
    })
}
/// Abandon a preparation before any runtime pin or effects exist. The consumed
/// sequence remains high so another preparation cannot revive its identity.
pub fn abandon_preparation(binding: JobBinding) -> Result<(), Error> {
    control(|state| {
        let job = state.learning_jobs.job.ok_or(Error::State)?;
        if job.binding != binding || job.identity.is_some() { return Err(Error::State); }
        state.learning_jobs.job = None;
        Ok(())
    })
}
/// UNKNOWN/running loans survive this call. An accepted validation must be
/// copied/sealed before its output can be acknowledged and reused.
pub fn close(job_key: ObjectKey) -> Result<(), Error> {
    control(|state| {
        let job = state.learning_jobs.job.ok_or(Error::State)?;
        if key(job) != job_key || job.identity.is_none() { return Err(Error::Stale); }
        match runtime::query_learning(job_key).map_err(native_error)? {
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running => return Err(Error::Unknown),
            runtime::LearningStatus::Complete { .. } => {
                if !job.consumed || job.role == Role::Validation && job.staged.is_none() {
                    return Err(Error::State);
                }
            }
            runtime::LearningStatus::DataIncomplete | runtime::LearningStatus::Failed(_)
                | runtime::LearningStatus::Cancelled => {}
        }
        runtime::acknowledge_learning(job_key).map_err(native_error)?;
        state.learning_jobs.job = None;
        Ok(())
    })
}
/// Explicitly discard a known terminal result without adopting its model. A
/// generation change may invalidate a perfectly completed numerical job; it
/// must not strand the unique runtime input loan. Pending/Running still own
/// their input, output and unsettled cost and cannot be released here.
pub fn discard(job_key: ObjectKey) -> Result<(), Error> {
    control(|state| {
        let job = state.learning_jobs.job.ok_or(Error::State)?;
        if key(job) != job_key || job.identity.is_none() { return Err(Error::Stale); }
        match runtime::query_learning(job_key).map_err(native_error)? {
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running => return Err(Error::Unknown),
            runtime::LearningStatus::Complete { .. } | runtime::LearningStatus::DataIncomplete
                | runtime::LearningStatus::Failed(_) | runtime::LearningStatus::Cancelled => {}
        }
        runtime::acknowledge_learning(job_key).map_err(native_error)?;
        state.learning_jobs.job = None;
        Ok(())
    })
}

/// Prepare both fallible owners before Governance changes its gate. The two
/// borrowed capabilities then commit metadata without a callback or allocation;
/// old execution pins and already published plans keep their exact identities.
pub fn promote(governance: &mut Governance<'_, '_>) -> Result<ModelBinding, Error> {
    control(|state| {
        if !super::replay::model_change_allowed() { return Err(Error::Unknown); }
        let active = state.registry.model();
        let gate = state.model_gate.as_mut().ok_or(Error::State)?;
        if gate.active() != active || state.models.active().map_err(native_error)? != active
            || governance.original_binding() != active
            || gate.permit().or(gate.closing()).is_none_or(|permit| permit.candidate_hash != governance.candidate_hash()) {
            return Err(Error::Stale);
        }
        let next = ModelBinding { generation: active.generation.checked_add(1).ok_or(Error::Numeric)?,
            model_hash: governance.candidate_hash(), schema_hash: active.schema_hash };
        let bank = state.models.prepare_change(next, crate::model_bank::ChangeKind::Promotion)
            .map_err(native_error)?;
        let publisher = state.registry.publisher();
        let registry = state.registry.prepare_model_change(publisher, next).map_err(native_error)?;
        // Any failure here drops both preparations without changing their owners.
        let admitted = governance.promote(gate, super::now())?;
        debug_assert_eq!(admitted, next);
        registry.commit();
        bank.commit();
        Ok(admitted)
    })
}
pub fn rollback(governance: &mut Governance<'_, '_>) -> Result<ModelBinding, Error> {
    control(|state| {
        if !super::replay::model_change_allowed() { return Err(Error::Unknown); }
        let active = state.registry.model();
        let gate = state.model_gate.as_mut().ok_or(Error::State)?;
        if gate.active() != active || state.models.active().map_err(native_error)? != active {
            return Err(Error::Stale);
        }
        let next = ModelBinding { generation: active.generation.checked_add(1).ok_or(Error::Numeric)?,
            model_hash: governance.original_binding().model_hash, schema_hash: active.schema_hash };
        let bank = state.models.prepare_change(next, crate::model_bank::ChangeKind::Rollback)
            .map_err(native_error)?;
        let publisher = state.registry.publisher();
        let registry = state.registry.prepare_model_change(publisher, next).map_err(native_error)?;
        let admitted = governance.rollback(gate)?;
        debug_assert_eq!(admitted, next);
        registry.commit();
        bank.commit();
        Ok(admitted)
    })
}
