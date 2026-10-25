//! The actual extra-turn producer/worker/consumer pump. Its persistent state
//! and all dataset/vector buffers live in the control pool. No producer means
//! DataIncomplete; it never substitutes wire rows or synthetic replay labels.
use super::{NativeModelPin, learning_coordinator as coordinator};
use crate::{control_pool as pool, smp::prototype_runtime as runtime};
use core::{
    cell::UnsafeCell,
    mem::{align_of, size_of},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    learning::{
        Error,
        data::FrozenData,
        manifest::ModelManifest,
        train::TrainedModel,
        validate::{ReferenceSuite, ValidatedCandidate},
        worker::{EncoderState, PreparedJob},
        worker_wire::{self as wire, JobBinding, Role},
    },
    model::MODEL_BYTES,
    policy::{CandidateSet, ModelBinding},
};

const OWNER: ObjectKey = ObjectKey {
    id: 0x4c45_4452_4956,
    generation: 1,
};
const SOURCE_BANKS: usize = 8;
const WORKSPACE: usize = 1024 * 1024;
const DRIVER_PAGES: usize = 4;
// Preparation uses the same input bank as EL0, plus its live source banks.
// Charge the runtime's exact four-page metadata loan, the whole bounded C1
// kernel stack, session metadata and both possible immutable model pages as
// overhead. Metadata loans replace EL0 scratch pages; they are not second
// allocations. The governance model itself is outside the numerical workspace.
const DRIVER_ALLOWANCE: usize = 64 * 1024
    + (DRIVER_PAGES + crate::learning_session::WORKSPACE_METADATA_PAGES) * 4096
    + 2 * 4096;
pub const MAX_SOURCE_BYTES: usize = WORKSPACE - wire::INPUT_LIMIT - DRIVER_ALLOWANCE;

/// The producer keeps this exact source frozen until returned(). Every
/// referenced object, including FrozenData/ReferenceSuite metadata, must lie
/// in one of these real, sealed, producer-owned control-pool allocations.
#[derive(Clone, Copy)]
pub struct Source {
    pub key: ObjectKey,
    pub data: &'static FrozenData<'static>,
    pub validation: Option<ValidationSource>,
    pub backing: [Option<pool::Allocation>; SOURCE_BANKS],
}
#[derive(Clone, Copy)]
pub struct ValidationSource {
    pub bytes: &'static [u8; MODEL_BYTES],
    pub manifest: &'static ModelManifest,
    pub vectors: &'static ReferenceSuite<'static>,
    pub probes: &'static [CandidateSet],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Trained {
        parameters: [u8; 32],
    },
    Validated {
        binding: ModelBinding,
        registration: [u8; 32],
    },
    Rejected(Error),
    Cancelled,
}

/// A validated capability relocated onto its exact sealed model-bank pin.
/// The consumer may retain this for Shadow/Canary after the worker input has
/// been acknowledged. It must keep the pin until every such borrow is ended.
pub struct ValidationDelivery {
    pub job: JobBinding,
    pub binding: ModelBinding,
    candidate: Option<ValidatedCandidate<'static>>,
    pin: Option<NativeModelPin>,
}
impl ValidationDelivery {
    pub fn candidate<'a>(&'a self) -> Result<&'a ValidatedCandidate<'a>, Error> {
        self.candidate.as_ref().ok_or(Error::State)
    }
    /// End all candidate borrows before calling this. A Busy reply preserves
    /// the exact pin for retry; Drop alone never makes its memory reusable.
    pub fn release(&mut self) -> Result<(), Error> {
        self.candidate = None;
        if let Some(pin) = self.pin.as_ref() {
            super::release_job_model(pin).map_err(native_error)?;
            self.pin = None;
        }
        Ok(())
    }
}

/// CPU0 registers protected kernel callbacks once. A rejected delivery returns
/// its non-clonable capability, so backpressure cannot silently lose custody.
/// Callbacks run on C1 only inside the runtime's prepaid extra turn and must
/// themselves perform bounded work. They never receive replay-construction
/// authority, a writable model bank, or an already-consumed completion ticket.
#[derive(Clone, Copy)]
pub struct Provider {
    pub owner: ObjectKey,
    pub next: fn() -> Result<Option<Source>, Error>,
    pub training: fn(JobBinding, TrainedModel) -> Result<(), (Error, TrainedModel)>,
    pub validation: fn(ValidationDelivery) -> Result<(), (Error, ValidationDelivery)>,
    pub returned: fn(ObjectKey, Outcome) -> Result<(), Error>,
}
impl Provider {
    fn same(self, other: Self) -> bool {
        self.owner == other.owner
            && core::ptr::fn_addr_eq(self.next, other.next)
            && core::ptr::fn_addr_eq(self.training, other.training)
            && core::ptr::fn_addr_eq(self.validation, other.validation)
            && core::ptr::fn_addr_eq(self.returned, other.returned)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    Idle,
    PinSource,
    CheckSource,
    Bind,
    BorrowInput,
    PinParent,
    StartEncoder,
    Encode,
    FinishEncoding,
    ReleaseSource,
    ReleaseParent,
    Seal,
    Submit,
    Wait,
    Read,
    Accept,
    Stage,
    PinStaged,
    Relocate,
    Close,
    Deliver,
    Cleanup,
    Notify,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub source: Option<ObjectKey>,
    pub job: Option<ObjectKey>,
    pub completed: u64,
    pub rejected: u64,
    pub steps: u64,
    pub source_bytes: usize,
    pub last_error: Option<Error>,
}
#[derive(Clone, Copy)]
struct Span {
    base: usize,
    bytes: usize,
}
struct State {
    provider: Option<Provider>,
    phase: Phase,
    source: Option<Source>,
    source_key: Option<ObjectKey>,
    spans: [Option<Span>; SOURCE_BANKS],
    source_pins: [Option<pool::Lease>; SOURCE_BANKS],
    cursor: usize,
    source_bytes: usize,
    role: Role,
    binding: Option<JobBinding>,
    bound: bool,
    submitted: bool,
    input: Option<runtime::LearningInputLoan>,
    input_base: usize,
    input_bytes: usize,
    allocation: Option<pool::Allocation>,
    parent: Option<NativeModelPin>,
    encoder: Option<EncoderState<'static, 'static>>,
    prepared: Option<PreparedJob>,
    report: [u8; wire::RESULT_BYTES],
    trained: Option<TrainedModel>,
    validated: Option<ValidatedCandidate<'static>>,
    staged: Option<ModelBinding>,
    staged_pin: Option<NativeModelPin>,
    delivery: Option<ValidationDelivery>,
    outcome: Option<Outcome>,
    cancel: bool,
    completed: u64,
    rejected: u64,
    steps: u64,
    last_error: Option<Error>,
}
impl State {
    const fn new() -> Self {
        Self {
            provider: None,
            phase: Phase::Idle,
            source: None,
            source_key: None,
            spans: [None; SOURCE_BANKS],
            source_pins: [const { None }; SOURCE_BANKS],
            cursor: 0,
            source_bytes: 0,
            role: Role::Training,
            binding: None,
            bound: false,
            submitted: false,
            input: None,
            input_base: 0,
            input_bytes: 0,
            allocation: None,
            parent: None,
            encoder: None,
            prepared: None,
            report: [0; wire::RESULT_BYTES],
            trained: None,
            validated: None,
            staged: None,
            staged_pin: None,
            delivery: None,
            outcome: None,
            cancel: false,
            completed: 0,
            rejected: 0,
            steps: 0,
            last_error: None,
        }
    }
    fn job(&self) -> Result<ObjectKey, Error> {
        let b = self.binding.ok_or(Error::State)?;
        Ok(ObjectKey {
            id: b.job_id,
            generation: b.boot_epoch,
        })
    }
    fn fail(&mut self, error: Error) {
        self.last_error = Some(error);
        self.outcome = Some(Outcome::Rejected(error));
        self.phase = Phase::Cleanup;
    }
    fn contains(&self, base: usize, bytes: usize) -> bool {
        bytes != 0
            && base.checked_add(bytes).is_some_and(|end| {
                self.spans.iter().flatten().any(|span| {
                    base >= span.base
                        && span
                            .base
                            .checked_add(span.bytes)
                            .is_some_and(|limit| end <= limit)
                })
            })
    }
    fn object<T>(&self, object: &T) -> Result<(), Error> {
        if self.contains(object as *const T as usize, size_of::<T>()) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn slice<T>(&self, slice: &[T]) -> Result<(), Error> {
        let bytes = slice
            .len()
            .checked_mul(size_of::<T>())
            .ok_or(Error::Numeric)?;
        if self.contains(slice.as_ptr() as usize, bytes) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn check_source(&self) -> Result<(), Error> {
        let source = self.source.ok_or(Error::State)?;
        self.object(source.data)?;
        self.slice(source.data.training())?;
        self.slice(source.data.validation())?;
        if let Some(validation) = source.validation {
            self.object(validation.bytes)?;
            self.object(validation.manifest)?;
            self.object(validation.vectors)?;
            self.slice(validation.vectors.cases)?;
            self.slice(validation.vectors.selections)?;
            self.slice(validation.probes)?;
        }
        Ok(())
    }
}
const STATE_PAGES: usize = size_of::<State>().div_ceil(4096);
const _: () = assert!(STATE_PAGES <= DRIVER_PAGES);

struct Setup {
    allocation: Option<pool::Allocation>,
    pin: Option<pool::Lease>,
}
struct SetupCell(UnsafeCell<Setup>);
unsafe impl Sync for SetupCell {}
static SETUP: SetupCell = SetupCell(UnsafeCell::new(Setup {
    allocation: None,
    pin: None,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn guard() -> Result<Guard, DomainError> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| DomainError::Busy)?;
    Ok(Guard)
}
fn with<R>(f: impl FnOnce(&mut State) -> Result<R, DomainError>) -> Result<R, DomainError> {
    let _guard = guard()?;
    let address = ADDRESS.load(Ordering::Acquire);
    if address == 0 {
        return Err(DomainError::NotReady);
    }
    // A permanent exclusive pool pin and this non-reentrant gate are the only
    // access path to the initialized metadata; no EL0 mapping includes it.
    f(unsafe { &mut *(address as *mut State) })
}
fn native_error(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Stale => Error::Stale,
        DomainError::Capacity => Error::Capacity,
        DomainError::Budget => Error::Budget,
        DomainError::Expired => Error::Deadline,
        DomainError::Overflow | DomainError::Range => Error::Numeric,
        DomainError::Conflict => Error::Conflict,
        DomainError::Schema => Error::Schema,
        _ => Error::Evidence,
    }
}

/// Startup is resumable: a Busy retry neither allocates another metadata bank
/// nor creates another permanent pin. No worker/data job is fabricated here.
#[inline(never)]
pub fn init() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    crate::learning_session::init()?;
    {
        let _guard = guard()?;
        if ADDRESS.load(Ordering::Acquire) == 0 {
            let setup = unsafe { &mut *SETUP.0.get() };
            if setup.allocation.is_none() {
                let allocation = runtime::learning_driver_workspace()?;
                if allocation.owner() != OWNER || allocation.pages() != DRIVER_PAGES {
                    return Err(DomainError::Range);
                }
                setup.allocation = Some(allocation);
            }
            let allocation = setup.allocation.ok_or(DomainError::NotReady)?;
            if setup.pin.is_none() {
                setup.pin = Some(pool::pin(allocation)?);
            }
            let (base, _, bytes) = pool::span(allocation)?;
            if bytes < size_of::<State>() || !base.is_multiple_of(align_of::<State>()) {
                return Err(DomainError::Range);
            }
            // Only small bounded control state is constructed here. Dataset,
            // input and candidate buffers are never allocated on the stack.
            unsafe {
                core::ptr::write(base as *mut State, State::new());
            }
            ADDRESS.store(base, Ordering::Release);
        }
    }
    runtime::register_learning_driver(driver_turn)
}
pub fn register(provider: Provider) -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0
        || provider.owner.id == 0
        || provider.owner.generation == 0
    {
        return Err(DomainError::Auth);
    }
    init()?;
    with(|state| {
        if let Some(old) = state.provider {
            return if old.same(provider) {
                Ok(())
            } else {
                Err(DomainError::Conflict)
            };
        }
        state.provider = Some(provider);
        Ok(())
    })
}
pub fn status() -> Result<Status, DomainError> {
    with(|s| {
        Ok(Status {
            phase: s.phase,
            source: s.source_key,
            job: s.binding.map(|b| ObjectKey {
                id: b.job_id,
                generation: b.boot_epoch,
            }),
            completed: s.completed,
            rejected: s.rejected,
            steps: s.steps,
            source_bytes: s.source_bytes,
            last_error: s.last_error,
        })
    })
}
pub fn cancel(source: ObjectKey) -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    with(|state| {
        if state.source_key != Some(source) || state.phase == Phase::Idle {
            return Err(DomainError::Stale);
        }
        state.cancel = true;
        Ok(())
    })
}

fn pin_source(s: &mut State, provider: Provider) -> Result<(), Error> {
    let source = s.source.ok_or(Error::State)?;
    if s.cursor == SOURCE_BANKS {
        s.phase = Phase::CheckSource;
        return Ok(());
    }
    let index = s.cursor;
    let Some(allocation) = source.backing[index] else {
        s.cursor += 1;
        return Ok(());
    };
    if source.backing[..index]
        .iter()
        .flatten()
        .any(|old| *old == allocation)
    {
        s.cursor += 1;
        return Ok(());
    }
    if allocation.owner() != provider.owner {
        return Err(Error::Evidence);
    }
    let bytes = s
        .source_bytes
        .checked_add(allocation.bytes())
        .ok_or(Error::Numeric)?;
    if bytes
        .checked_add(wire::INPUT_LIMIT + DRIVER_ALLOWANCE)
        .is_none_or(|n| n > WORKSPACE)
    {
        return Err(Error::Capacity);
    }
    // Acquire the real pin before publishing the span or advancing the cursor.
    // If span is Busy, the pin remains in its exact slot for retry.
    if s.source_pins[index].is_none() {
        s.source_pins[index] = Some(pool::pin_readonly(allocation).map_err(native_error)?);
    }
    let (base, _, actual) = pool::span(allocation).map_err(native_error)?;
    if actual != allocation.bytes() {
        return Err(Error::Evidence);
    }
    s.spans[index] = Some(Span {
        base,
        bytes: actual,
    });
    s.source_bytes = bytes;
    s.cursor += 1;
    Ok(())
}
fn release_source(s: &mut State) -> Result<bool, Error> {
    if let Some(index) = s.source_pins.iter().position(Option::is_some) {
        pool::unpin(s.source_pins[index].as_ref().ok_or(Error::State)?).map_err(native_error)?;
        s.source_pins[index] = None;
        s.spans[index] = None;
        return Ok(false);
    }
    Ok(true)
}
fn input(s: &mut State) -> Result<&mut [u8], Error> {
    let loan = s.input.as_ref().ok_or(Error::State)?;
    let (base, bytes) = runtime::learning_input_span(loan).map_err(native_error)?;
    if base != s.input_base || bytes != s.input_bytes || bytes != wire::INPUT_LIMIT {
        return Err(Error::Evidence);
    }
    // The unsealed exclusive input loan is not mapped into a running context.
    // EncoderState never retains this temporary writable borrow between turns.
    Ok(unsafe { core::slice::from_raw_parts_mut(base as *mut u8, bytes) })
}
fn model_bytes(pin: &NativeModelPin) -> Result<&'static [u8; MODEL_BYTES], Error> {
    let address = pin
        .physical_address()
        .checked_add(crate::HIGH)
        .ok_or(Error::Numeric)?;
    // The exact sealed model-bank pin lives until every returned capability is
    // dropped or relocated. This region is never writable by EL0 or the pool.
    Ok(unsafe { &*(address as *const [u8; MODEL_BYTES]) })
}

#[inline(never)]
fn step(s: &mut State, provider: Provider) -> Result<bool, Error> {
    if !matches!(s.role, Role::Training | Role::Validation) {
        return Err(Error::Schema);
    }
    match s.phase {
        Phase::Idle => {
            let source = match (provider.next)() {
                Ok(Some(source)) => source,
                Ok(None) | Err(Error::DataIncomplete) => return Ok(false),
                Err(error) => return Err(error),
            };
            if source.key.id == 0 || source.key.generation == 0 {
                return Err(Error::Evidence);
            }
            s.source_key = Some(source.key);
            s.source = Some(source);
            s.role = if source.validation.is_some() {
                Role::Validation
            } else {
                Role::Training
            };
            s.cursor = 0;
            s.source_bytes = 0;
            s.cancel = false;
            s.outcome = None;
            s.last_error = None;
            s.phase = Phase::PinSource;
        }
        Phase::PinSource => pin_source(s, provider)?,
        Phase::CheckSource => {
            s.check_source()?;
            s.phase = Phase::Bind;
        }
        Phase::Bind => {
            s.binding = Some(coordinator::binding(
                s.role,
                s.source.ok_or(Error::State)?.data,
            )?);
            s.bound = true;
            s.phase = Phase::BorrowInput;
        }
        Phase::BorrowInput => {
            if s.input.is_none() {
                s.input = Some(runtime::borrow_learning_input().map_err(native_error)?);
            }
            let (base, bytes) = runtime::learning_input_span(s.input.as_ref().ok_or(Error::State)?)
                .map_err(native_error)?;
            if bytes != wire::INPUT_LIMIT {
                return Err(Error::Capacity);
            }
            s.input_base = base;
            s.input_bytes = bytes;
            s.phase = Phase::PinParent;
        }
        Phase::PinParent => {
            s.parent = Some(coordinator::pin_parent(s.binding.ok_or(Error::State)?)?);
            s.phase = Phase::StartEncoder;
        }
        Phase::StartEncoder => return start_encoder(s),
        Phase::Encode => {
            // Borrow distinct fields: input() only validates the loan and
            // returns its separate physical buffer, never the metadata bank.
            let (base, bytes) = {
                let b = input(s)?;
                (b.as_mut_ptr(), b.len())
            };
            let progress = s
                .encoder
                .as_mut()
                .ok_or(Error::State)?
                .step(unsafe { core::slice::from_raw_parts_mut(base, bytes) })?;
            if progress.done {
                s.phase = Phase::FinishEncoding;
            }
        }
        Phase::FinishEncoding => return finish_encoding(s),
        Phase::ReleaseSource => {
            if release_source(s)? {
                s.phase = Phase::ReleaseParent;
            }
        }
        Phase::ReleaseParent => {
            if let Some(pin) = s.parent.as_ref() {
                super::release_job_model(pin).map_err(native_error)?;
                s.parent = None;
            }
            s.phase = Phase::Seal;
        }
        Phase::Seal => {
            s.allocation = Some(
                runtime::seal_learning_input(s.input.as_mut().ok_or(Error::State)?)
                    .map_err(native_error)?,
            );
            s.phase = Phase::Submit;
        }
        Phase::Submit => {
            let key = coordinator::submit(
                s.prepared.as_ref().ok_or(Error::State)?,
                s.allocation.ok_or(Error::State)?,
            )?;
            if key != s.job()? {
                return Err(Error::Evidence);
            }
            s.submitted = true;
            s.phase = Phase::Wait;
        }
        Phase::Wait => match runtime::query_learning(s.job()?).map_err(native_error)? {
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running => {
                return Ok(false);
            }
            runtime::LearningStatus::Complete { bytes } if bytes == wire::RESULT_BYTES => {
                s.phase = Phase::Read
            }
            runtime::LearningStatus::Complete { .. } => return Err(Error::Evidence),
            runtime::LearningStatus::DataIncomplete => return Err(Error::DataIncomplete),
            runtime::LearningStatus::Failed(_) => return Err(Error::Validation),
            runtime::LearningStatus::Cancelled => {
                s.outcome = Some(Outcome::Cancelled);
                s.phase = Phase::Cleanup;
            }
        },
        Phase::Read => {
            runtime::read_learning_result(s.job()?, 0, &mut s.report).map_err(native_error)?;
            s.phase = Phase::Accept;
        }
        Phase::Accept => return accept_result(s),
        Phase::Stage => {
            s.staged = Some(coordinator::stage(
                s.validated.as_ref().ok_or(Error::State)?,
            )?);
            s.phase = Phase::PinStaged;
        }
        Phase::PinStaged => {
            s.staged_pin = Some(coordinator::pin_staged(s.staged.ok_or(Error::State)?)?);
            s.phase = Phase::Relocate;
        }
        Phase::Relocate => return relocate_result(s),
        Phase::Close => {
            coordinator::close(s.job()?)?;
            s.bound = false;
            s.submitted = false;
            s.input = None;
            s.allocation = None;
            s.prepared = None;
            s.phase = Phase::Deliver;
        }
        Phase::Deliver => return deliver_result(s, provider),
        Phase::Cleanup => return cleanup(s),
        Phase::Notify => return notify_result(s, provider),
    }
    Ok(true)
}

// Keep disjoint phase temporaries out of the long-lived C1 loop frame.
#[inline(never)]
fn start_encoder(s: &mut State) -> Result<bool, Error> {
    let source = s.source.ok_or(Error::State)?;
    let parent = model_bytes(s.parent.as_ref().ok_or(Error::State)?)?;
    let binding = s.binding.ok_or(Error::State)?;
    let encoder = if let Some(v) = source.validation {
        EncoderState::validation(
            binding,
            parent,
            v.bytes,
            v.manifest,
            source.data,
            v.vectors,
            v.probes,
            WORKSPACE as u32,
        )?
    } else {
        EncoderState::training(binding, parent, source.data, WORKSPACE as u32)?
    };
    if encoder.input_len() > s.input_bytes {
        return Err(Error::Capacity);
    }
    s.encoder = Some(encoder);
    s.phase = Phase::Encode;
    Ok(true)
}

#[inline(never)]
fn finish_encoding(s: &mut State) -> Result<bool, Error> {
    let (base, bytes) = {
        let b = input(s)?;
        (b.as_ptr(), b.len())
    };
    let encoder = s.encoder.take().ok_or(Error::State)?;
    s.prepared = Some(encoder.finish(unsafe { core::slice::from_raw_parts(base, bytes) })?);
    // End all source references before returning their exact pins.
    s.source = None;
    s.phase = Phase::ReleaseSource;
    Ok(true)
}

#[inline(never)]
fn accept_result(s: &mut State) -> Result<bool, Error> {
    let prepared = s.prepared.as_mut().ok_or(Error::State)?;
    if s.role == Role::Training {
        let result = coordinator::accept_training(prepared, &s.report)?;
        s.outcome = Some(Outcome::Trained {
            parameters: result.record().result_hash,
        });
        s.trained = Some(result);
        s.phase = Phase::Close;
    } else {
        let manifest = prepared.header().candidate_manifest()?;
        let offset = wire::HEADER_BYTES + MODEL_BYTES;
        if offset + MODEL_BYTES > prepared.input_len() {
            return Err(Error::Evidence);
        }
        // Submitted input remains sealed and owned by the runtime's
        // exact source pin until close/discard. The known Complete
        // context cannot write it; no new input loan can reuse it.
        let bytes = unsafe { &*((s.input_base + offset) as *const [u8; MODEL_BYTES]) };
        s.validated = Some(coordinator::accept_validation(
            prepared, bytes, manifest, &s.report,
        )?);
        s.phase = Phase::Stage;
    }
    Ok(true)
}

#[inline(never)]
fn relocate_result(s: &mut State) -> Result<bool, Error> {
    let bytes = model_bytes(s.staged_pin.as_ref().ok_or(Error::State)?)?;
    let candidate = s.validated.as_ref().ok_or(Error::State)?.rebind(bytes)?;
    let binding = s.staged.ok_or(Error::State)?;
    s.outcome = Some(Outcome::Validated {
        binding,
        registration: candidate.registration_hash(),
    });
    s.delivery = Some(ValidationDelivery {
        job: s.binding.ok_or(Error::State)?,
        binding,
        candidate: Some(candidate),
        pin: s.staged_pin.take(),
    });
    s.validated = None;
    s.phase = Phase::Close;
    Ok(true)
}

#[inline(never)]
fn deliver_result(s: &mut State, provider: Provider) -> Result<bool, Error> {
    if s.role == Role::Training {
        let model = s.trained.take().ok_or(Error::State)?;
        if let Err((error, model)) = (provider.training)(s.binding.ok_or(Error::State)?, model) {
            s.trained = Some(model);
            return Err(error);
        }
    } else {
        let delivery = s.delivery.take().ok_or(Error::State)?;
        if let Err((error, delivery)) = (provider.validation)(delivery) {
            s.delivery = Some(delivery);
            return Err(error);
        }
    }
    s.phase = Phase::Notify;
    Ok(true)
}

#[inline(never)]
fn notify_result(s: &mut State, provider: Provider) -> Result<bool, Error> {
    let outcome = s.outcome.ok_or(Error::State)?;
    let successful = matches!(outcome, Outcome::Trained { .. } | Outcome::Validated { .. });
    let completed = s
        .completed
        .checked_add(u64::from(successful))
        .ok_or(Error::Numeric)?;
    let rejected = s
        .rejected
        .checked_add(u64::from(!successful))
        .ok_or(Error::Numeric)?;
    (provider.returned)(s.source_key.ok_or(Error::State)?, outcome)?;
    s.completed = completed;
    s.rejected = rejected;
    s.source_key = None;
    s.binding = None;
    s.outcome = None;
    s.cancel = false;
    s.staged = None;
    s.input_base = 0;
    s.input_bytes = 0;
    s.cursor = 0;
    s.source_bytes = 0;
    s.report.fill(0);
    s.phase = Phase::Idle;
    Ok(true)
}

#[inline(never)]
fn cleanup(s: &mut State) -> Result<bool, Error> {
    // Drop every reference into source/input memory before releasing its pin.
    s.encoder = None;
    s.source = None;
    s.validated = None;
    s.trained = None;
    if let Some(delivery) = s.delivery.as_mut() {
        delivery.release()?;
        s.delivery = None;
        return Ok(true);
    }
    if let Some(pin) = s.staged_pin.as_ref() {
        super::release_job_model(pin).map_err(native_error)?;
        s.staged_pin = None;
        return Ok(true);
    }
    if !release_source(s)? {
        return Ok(true);
    }
    if let Some(pin) = s.parent.as_ref() {
        super::release_job_model(pin).map_err(native_error)?;
        s.parent = None;
        return Ok(true);
    }
    if s.submitted {
        match runtime::query_learning(s.job()?).map_err(native_error)? {
            runtime::LearningStatus::Pending | runtime::LearningStatus::Running => {
                runtime::cancel_learning(s.job()?).map_err(native_error)?;
                return Ok(false);
            }
            _ => {
                coordinator::discard(s.job()?)?;
                s.submitted = false;
                s.bound = false;
                s.input = None;
                s.allocation = None;
                s.prepared = None;
                return Ok(true);
            }
        }
    }
    if s.bound {
        coordinator::abandon_preparation(s.binding.ok_or(Error::State)?)?;
        s.bound = false;
        return Ok(true);
    }
    if let Some(loan) = s.input.as_mut() {
        runtime::abandon_learning_input(loan).map_err(native_error)?;
        s.input = None;
        s.allocation = None;
        return Ok(true);
    }
    s.prepared = None;
    s.staged = None;
    s.phase = Phase::Notify;
    Ok(true)
}

/// The runtime calls this only with one actual ControlCredit+ExtraCredit on
/// healthy C1. Returning false while a worker is pending lets that same owner
/// enter/run the independently mapped EL0 context instead of busy-polling it.
pub fn driver_turn() -> Result<bool, DomainError> {
    runtime::authorize_learning_turn()?;
    if crate::learning_canary::control_step()? {
        return Ok(true);
    }
    match crate::learning_session::turn()? {
        crate::learning_session::Turn::Idle => (),
        crate::learning_session::Turn::Progress => return Ok(true),
        crate::learning_session::Turn::Waiting => return Ok(false),
        crate::learning_session::Turn::Retry => return Err(DomainError::Again),
    }
    // The producer borrows the same real scoring input only while the
    // numerical driver has no current job or loan. It returns the loan before
    // exposing its frozen source through Provider::next.
    if with(|s| Ok(s.phase == Phase::Idle && s.input.is_none() && s.binding.is_none()))?
        && crate::learning_replay::control_step()?
    {
        return Ok(true);
    }
    with(|s| {
        let Some(provider) = s.provider else {
            return Ok(false);
        };
        if s.cancel && !matches!(s.phase, Phase::Idle | Phase::Cleanup | Phase::Notify) {
            s.outcome = Some(Outcome::Cancelled);
            s.phase = Phase::Cleanup;
        }
        match step(s, provider) {
            Ok(progress) => {
                if progress {
                    s.steps = s.steps.checked_add(1).ok_or(DomainError::Overflow)?;
                }
                Ok(progress)
            }
            Err(Error::Unknown) => Ok(false),
            Err(error) => {
                s.last_error = Some(error);
                if s.phase == Phase::Idle {
                    return Ok(false);
                }
                // Cleanup/notification errors retain the current exact loan;
                // they never relabel an unknown exit as a completed job.
                if !matches!(s.phase, Phase::Cleanup | Phase::Notify) {
                    s.fail(error);
                }
                Ok(false)
            }
        }
    })
}
