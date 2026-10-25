//! The actual native driver and pool/model-bank sources, exercised with a
//! synthetic stopped-worker authority. These are custody/fault-injection
//! tests, never native CPU measurements or the real 144/72 replay corpus.
extern crate self as cyxia_arch_aarch64;
pub const HIGH: u64 = 0;
pub mod cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static SLOT: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        SLOT.load(Ordering::Acquire)
    }
    pub fn set(value: usize) {
        SLOT.store(value, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/control_pool.rs"]
mod actual_pool;
pub mod control_pool {
    pub use super::actual_pool::{
        Allocation, Lease, allocate, pin, pin_readonly, read, seal, unseal, usage, write,
    };
    use core::sync::atomic::{AtomicBool, Ordering};
    use cyxia_prototype::domains::Error;
    pub static SPAN_BUSY: AtomicBool = AtomicBool::new(false);
    pub static UNPIN_BUSY: AtomicBool = AtomicBool::new(false);
    pub fn span(a: Allocation) -> Result<(usize, u64, usize), Error> {
        if SPAN_BUSY.swap(false, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        super::actual_pool::span(a)
    }
    pub fn unpin(p: &Lease) -> Result<(), Error> {
        if UNPIN_BUSY.swap(false, Ordering::AcqRel) {
            return Err(Error::Busy);
        }
        super::actual_pool::unpin(p)
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/model_bank.rs"]
mod model_bank;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_control/learning_driver.rs"]
mod native_driver;
#[path = "support/learning.rs"]
mod support;
use control_pool as pool;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    features,
    learning::{
        Error,
        data::FrozenData,
        manifest::{ModelManifest, UntrainedSeed},
        train::TrainedModel,
        validate::{
            ReferenceCase, ReferenceSelection, ReferenceSuite, ValidatedCandidate,
            integer_reference,
        },
        worker::{CompletionAuthority, CompletionClaim, PreparedJob, Worker},
        worker_wire::{self as wire, JobBinding, JobIdentity, Report, Role},
    },
    model::MODEL_BYTES,
    policy::ModelBinding,
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    mem::{align_of, size_of},
    sync::Mutex,
};
const PRODUCER: ObjectKey = ObjectKey {
    id: 42,
    generation: 7,
};
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn learn(error: DomainError) -> Error {
    if matches!(
        error,
        DomainError::Busy | DomainError::Again | DomainError::NotReady
    ) {
        Error::Unknown
    } else if error == DomainError::Stale {
        Error::Stale
    } else {
        Error::Evidence
    }
}
// This shim tests only the actual driver's dispatch/ownership boundary. The
// native session's model governance is independently tested in its own suite.
pub mod learning_session {
    use super::DomainError;
    use core::sync::atomic::{AtomicU8, Ordering};
    pub const WORKSPACE_METADATA_PAGES: usize = 6;
    pub enum Turn {
        Idle,
        Progress,
        Waiting,
        Retry,
    }
    pub static NEXT: AtomicU8 = AtomicU8::new(0);
    pub fn init() -> Result<(), DomainError> {
        Ok(())
    }
    pub fn turn() -> Result<Turn, DomainError> {
        Ok(match NEXT.swap(0, Ordering::AcqRel) {
            1 => Turn::Progress,
            2 => Turn::Waiting,
            3 => Turn::Retry,
            _ => Turn::Idle,
        })
    }
}
pub type NativeModelPin = model_bank::ModelPin<pool::Lease>;
pub fn release_job_model(pin: &NativeModelPin) -> Result<(), DomainError> {
    COORDINATOR
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .models
        .release(pin)
}
struct PoolMemory;
impl model_bank::Memory for PoolMemory {
    type Allocation = pool::Allocation;
    type Pin = pool::Lease;
    fn allocate(&mut self, owner: ObjectKey) -> Result<Self::Allocation, DomainError> {
        pool::allocate(owner, 1)
    }
    fn unseal(&mut self, a: Self::Allocation) -> Result<(), DomainError> {
        pool::unseal(a)
    }
    fn write(&mut self, a: Self::Allocation, bytes: &[u8; MODEL_BYTES]) -> Result<(), DomainError> {
        pool::write(a, 0, bytes)
    }
    fn seal(&mut self, a: Self::Allocation) -> Result<(), DomainError> {
        pool::seal(a)
    }
    fn hash(&mut self, a: Self::Allocation) -> Result<[u8; 32], DomainError> {
        let mut bytes = [0; MODEL_BYTES];
        pool::read(a, 0, &mut bytes)?;
        Ok(Sha256::digest(bytes).into())
    }
    fn pin(&mut self, a: Self::Allocation) -> Result<(pool::Lease, u64), DomainError> {
        let (_, physical, _) = pool::span(a)?;
        Ok((pool::pin_readonly(a)?, physical))
    }
    fn release(&mut self, p: &pool::Lease) -> Result<(), DomainError> {
        pool::unpin(p)
    }
}
struct Job {
    binding: JobBinding,
    submitted: bool,
    consumed: bool,
    staged: Option<ModelBinding>,
}
struct Coordinator {
    models: model_bank::ModelBank<PoolMemory>,
    next: u64,
    job: Option<Job>,
}
static COORDINATOR: Mutex<Option<Coordinator>> = Mutex::new(None);
static STALE_ADOPTION: AtomicBool = AtomicBool::new(false);
static UNKNOWN_COMPLETION: AtomicBool = AtomicBool::new(false);
struct Authority;
impl CompletionAuthority for Authority {
    fn verify_completion(&self, claim: &CompletionClaim) -> Result<(), Error> {
        smp::prototype_runtime::verify(claim)
    }
}
pub mod learning_coordinator {
    use super::*;
    pub fn binding(role: Role, data: &FrozenData<'_>) -> Result<JobBinding, Error> {
        smp::prototype_runtime::authorize_learning_turn().map_err(learn)?;
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        if s.job.is_some() {
            return Err(Error::State);
        }
        assert_eq!(data.manifest().training_count, 144);
        assert!(matches!(role, Role::Training | Role::Validation));
        s.next += 1;
        let binding = JobBinding {
            boot_epoch: 2,
            job_id: s.next,
            controller_epoch: 3,
            core_generation: 4,
            model_generation: s.models.active().unwrap().generation,
            data_generation: 6,
            role_context: key(role as u64),
            image_hash: [9; 32],
            ledger_generation: 8,
        };
        s.job = Some(Job {
            binding,
            submitted: false,
            consumed: false,
            staged: None,
        });
        Ok(binding)
    }
    pub fn pin_parent(binding: JobBinding) -> Result<NativeModelPin, Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        assert_eq!(s.job.as_ref().unwrap().binding, binding);
        let active = s.models.active().unwrap();
        s.models.pin(active).map_err(learn)
    }
    pub fn submit(prepared: &PreparedJob, input: pool::Allocation) -> Result<ObjectKey, Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        let job = s.job.as_mut().unwrap();
        assert_eq!(job.binding, prepared.identity().binding);
        let key = smp::prototype_runtime::submit(prepared, input).map_err(learn)?;
        job.submitted = true;
        Ok(key)
    }
    pub fn accept_training(prepared: &mut PreparedJob, out: &[u8]) -> Result<TrainedModel, Error> {
        if STALE_ADOPTION.load(Ordering::Acquire) {
            return Err(Error::Stale);
        }
        let value = prepared.accept_training(out, &Authority)?;
        COORDINATOR
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .job
            .as_mut()
            .unwrap()
            .consumed = true;
        Ok(value)
    }
    pub fn accept_validation<'a>(
        prepared: &mut PreparedJob,
        bytes: &'a [u8; MODEL_BYTES],
        manifest: ModelManifest,
        out: &[u8],
    ) -> Result<ValidatedCandidate<'a>, Error> {
        if STALE_ADOPTION.load(Ordering::Acquire) {
            return Err(Error::Stale);
        }
        let value = prepared.accept_validation(bytes, manifest, out, &Authority)?;
        COORDINATOR
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .job
            .as_mut()
            .unwrap()
            .consumed = true;
        Ok(value)
    }
    pub fn stage(candidate: &ValidatedCandidate<'_>) -> Result<ModelBinding, Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        assert!(s.job.as_ref().unwrap().consumed);
        let binding = s.models.stage(candidate).map_err(learn)?;
        s.job.as_mut().unwrap().staged = Some(binding);
        Ok(binding)
    }
    pub fn pin_staged(binding: ModelBinding) -> Result<NativeModelPin, Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        assert_eq!(s.job.as_ref().unwrap().staged, Some(binding));
        s.models.pin(binding).map_err(learn)
    }
    pub fn abandon_preparation(binding: JobBinding) -> Result<(), Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        let job = s.job.as_ref().unwrap();
        assert_eq!(job.binding, binding);
        assert!(!job.submitted);
        s.job = None;
        Ok(())
    }
    pub fn close(key: ObjectKey) -> Result<(), Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        let job = s.job.as_ref().unwrap();
        assert!(job.submitted && job.consumed);
        smp::prototype_runtime::ack(key).map_err(learn)?;
        s.job = None;
        Ok(())
    }
    pub fn discard(key: ObjectKey) -> Result<(), Error> {
        let mut lock = COORDINATOR.lock().unwrap();
        let s = lock.as_mut().unwrap();
        assert!(s.job.as_ref().unwrap().submitted);
        smp::prototype_runtime::ack(key).map_err(learn)?;
        s.job = None;
        Ok(())
    }
}
pub mod smp {
    pub mod prototype_runtime {
        use super::super::*;
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum LearningStatus {
            Pending,
            Running,
            Complete { bytes: usize },
            DataIncomplete,
            Failed(u64),
            Cancelled,
        }
        pub struct LearningInputLoan {
            allocation: pool::Allocation,
            pin: Option<pool::Lease>,
            sealed: bool,
        }
        struct Runtime {
            input: pool::Allocation,
            token: bool,
            pin: Option<pool::Lease>,
            identity: Option<JobIdentity>,
            len: usize,
            status: Option<LearningStatus>,
            report: [u8; wire::RESULT_BYTES],
            consumed: bool,
            submissions: usize,
            acknowledgments: usize,
            cancellations: usize,
        }
        static STATE: Mutex<Option<Runtime>> = Mutex::new(None);
        static DRIVER: Mutex<Option<pool::Allocation>> = Mutex::new(None);
        static EXTRA: AtomicBool = AtomicBool::new(false);
        pub static ACK_BUSY: AtomicBool = AtomicBool::new(false);
        pub static WORKSPACE_BUSY: AtomicBool = AtomicBool::new(false);
        pub fn learning_driver_workspace() -> Result<pool::Allocation, DomainError> {
            if cpu::slot() != 0 {
                return Err(DomainError::Auth);
            }
            if WORKSPACE_BUSY.swap(false, Ordering::AcqRel) {
                return Err(DomainError::Busy);
            }
            let mut slot = DRIVER.lock().unwrap();
            if let Some(allocation) = *slot {
                return Ok(allocation);
            }
            let allocation = pool::allocate(key(0x4c45_4452_4956), 4)?;
            *slot = Some(allocation);
            Ok(allocation)
        }
        pub fn initialize() {
            let driver = learning_driver_workspace().unwrap();
            assert_eq!(driver.pages(), 4);
            let input = pool::allocate(key(900), 128).unwrap();
            *STATE.lock().unwrap() = Some(Runtime {
                input,
                token: false,
                pin: None,
                identity: None,
                len: 0,
                status: None,
                report: [0; wire::RESULT_BYTES],
                consumed: false,
                submissions: 0,
                acknowledgments: 0,
                cancellations: 0,
            });
        }
        pub fn extra(value: bool) {
            EXTRA.store(value, Ordering::Release);
        }
        pub fn authorize_learning_turn() -> Result<(), DomainError> {
            if cpu::slot() == 1 && EXTRA.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(DomainError::Auth)
            }
        }
        pub fn register_learning_driver(
            _: fn() -> Result<bool, DomainError>,
        ) -> Result<(), DomainError> {
            if cpu::slot() == 0 {
                Ok(())
            } else {
                Err(DomainError::Auth)
            }
        }
        pub fn borrow_learning_input() -> Result<LearningInputLoan, DomainError> {
            authorize_learning_turn()?;
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            if s.token || s.status.is_some() {
                return Err(DomainError::Busy);
            }
            pool::unseal(s.input)?;
            let pin = pool::pin(s.input)?;
            s.token = true;
            Ok(LearningInputLoan {
                allocation: s.input,
                pin: Some(pin),
                sealed: false,
            })
        }
        pub fn learning_input_span(
            loan: &LearningInputLoan,
        ) -> Result<(usize, usize), DomainError> {
            authorize_learning_turn()?;
            if loan.sealed || loan.pin.is_none() {
                return Err(DomainError::Auth);
            }
            let (base, _, len) = pool::span(loan.allocation)?;
            Ok((base, len))
        }
        pub fn seal_learning_input(
            loan: &mut LearningInputLoan,
        ) -> Result<pool::Allocation, DomainError> {
            authorize_learning_turn()?;
            if let Some(pin) = loan.pin.as_ref() {
                pool::unpin(pin)?;
                loan.pin = None;
            }
            pool::seal(loan.allocation)?;
            loan.sealed = true;
            Ok(loan.allocation)
        }
        pub fn abandon_learning_input(loan: &mut LearningInputLoan) -> Result<(), DomainError> {
            authorize_learning_turn()?;
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            if s.status.is_some() {
                return Err(DomainError::Busy);
            }
            if let Some(pin) = loan.pin.as_ref() {
                pool::unpin(pin)?;
                loan.pin = None;
            }
            pool::unseal(loan.allocation)?;
            s.token = false;
            Ok(())
        }
        pub fn submit(
            prepared: &PreparedJob,
            input: pool::Allocation,
        ) -> Result<ObjectKey, DomainError> {
            authorize_learning_turn()?;
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            assert!(s.token && s.status.is_none());
            assert_eq!(s.input, input);
            s.pin = Some(pool::pin_readonly(input)?);
            s.identity = Some(prepared.identity());
            s.len = prepared.input_len();
            s.status = Some(LearningStatus::Pending);
            s.submissions += 1;
            s.consumed = false;
            Ok(ObjectKey {
                id: prepared.identity().binding.job_id,
                generation: prepared.identity().binding.boot_epoch,
            })
        }
        fn check(s: &Runtime, key: ObjectKey) -> Result<(), DomainError> {
            let identity = s.identity.ok_or(DomainError::Stale)?;
            if key.id == identity.binding.job_id && key.generation == identity.binding.boot_epoch {
                Ok(())
            } else {
                Err(DomainError::Stale)
            }
        }
        pub fn query_learning(key: ObjectKey) -> Result<LearningStatus, DomainError> {
            let lock = STATE.lock().unwrap();
            let s = lock.as_ref().unwrap();
            check(s, key)?;
            s.status.ok_or(DomainError::Stale)
        }
        pub fn read_learning_result(
            key: ObjectKey,
            offset: usize,
            out: &mut [u8],
        ) -> Result<(), DomainError> {
            authorize_learning_turn()?;
            let lock = STATE.lock().unwrap();
            let s = lock.as_ref().unwrap();
            check(s, key)?;
            if !matches!(s.status, Some(LearningStatus::Complete { .. })) {
                return Err(DomainError::Busy);
            }
            out.copy_from_slice(&s.report[offset..offset + out.len()]);
            Ok(())
        }
        pub fn verify(claim: &CompletionClaim) -> Result<(), Error> {
            authorize_learning_turn().map_err(learn)?;
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            if UNKNOWN_COMPLETION.load(Ordering::Acquire) {
                return Err(Error::Unknown);
            }
            let report = Report::decode(&s.report)?;
            if s.consumed
                || s.status
                    != Some(LearningStatus::Complete {
                        bytes: wire::RESULT_BYTES,
                    })
                || s.identity != Some(claim.identity)
                || claim.output_bytes != wire::RESULT_BYTES as u32
                || claim.output_hash != <[u8; 32]>::from(Sha256::digest(s.report))
                || claim.completed_steps != report.counts.steps
            {
                return Err(Error::Evidence);
            }
            s.consumed = true;
            Ok(())
        }
        pub fn ack(key: ObjectKey) -> Result<(), DomainError> {
            authorize_learning_turn()?;
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            check(s, key)?;
            if matches!(
                s.status,
                Some(LearningStatus::Pending | LearningStatus::Running) | None
            ) {
                return Err(DomainError::Busy);
            }
            if ACK_BUSY.swap(false, Ordering::AcqRel) {
                return Err(DomainError::Busy);
            }
            pool::unpin(s.pin.as_ref().unwrap())?;
            s.pin = None;
            s.token = false;
            s.status = None;
            s.identity = None;
            s.acknowledgments += 1;
            Ok(())
        }
        pub fn cancel_learning(key: ObjectKey) -> Result<(), DomainError> {
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            check(s, key)?;
            s.cancellations += 1;
            Ok(()) // A request to stop is not proof of stopping.
        }
        pub fn confirm_cancel() {
            STATE.lock().unwrap().as_mut().unwrap().status = Some(LearningStatus::Cancelled);
        }
        pub fn run_numerical_worker() {
            let mut lock = STATE.lock().unwrap();
            let s = lock.as_mut().unwrap();
            assert_eq!(s.status, Some(LearningStatus::Pending));
            s.status = Some(LearningStatus::Running);
            let (base, _, _) = pool::span(s.input).unwrap();
            let input = unsafe { core::slice::from_raw_parts(base as *const u8, s.len) };
            let mut worker = Worker::start(input).unwrap();
            while !worker.step().unwrap().done {}
            assert_eq!(worker.finish(&mut s.report).unwrap(), wire::RESULT_BYTES);
            // Only this explicit synthetic stopped-and-settled transition permits import.
            s.status = Some(LearningStatus::Complete {
                bytes: wire::RESULT_BYTES,
            });
        }
        pub fn counters() -> (usize, usize, usize, bool) {
            let lock = STATE.lock().unwrap();
            let s = lock.as_ref().unwrap();
            (s.submissions, s.acknowledgments, s.cancellations, s.token)
        }
        pub fn allocation() -> pool::Allocation {
            STATE.lock().unwrap().as_ref().unwrap().input
        }
    }
}

static QUEUE: Mutex<VecDeque<native_driver::Source>> = Mutex::new(VecDeque::new());
static TRAINED: Mutex<Option<TrainedModel>> = Mutex::new(None);
static VALIDATED: Mutex<Option<native_driver::ValidationDelivery>> = Mutex::new(None);
static RETURNS: Mutex<Vec<(ObjectKey, native_driver::Outcome)>> = Mutex::new(Vec::new());
static DELIVERY_BUSY: AtomicBool = AtomicBool::new(false);
static RETURN_BUSY: AtomicBool = AtomicBool::new(false);
fn next() -> Result<Option<native_driver::Source>, Error> {
    Ok(QUEUE.lock().unwrap().pop_front())
}
fn training(_: JobBinding, model: TrainedModel) -> Result<(), (Error, TrainedModel)> {
    if DELIVERY_BUSY.swap(false, Ordering::AcqRel) {
        return Err((Error::Unknown, model));
    }
    assert!(TRAINED.lock().unwrap().replace(model).is_none());
    Ok(())
}
fn validation(
    value: native_driver::ValidationDelivery,
) -> Result<(), (Error, native_driver::ValidationDelivery)> {
    assert!(VALIDATED.lock().unwrap().replace(value).is_none());
    Ok(())
}
fn returned(key: ObjectKey, outcome: native_driver::Outcome) -> Result<(), Error> {
    if RETURN_BUSY.swap(false, Ordering::AcqRel) {
        return Err(Error::Unknown);
    }
    RETURNS.lock().unwrap().push((key, outcome));
    Ok(())
}
fn provider() -> native_driver::Provider {
    native_driver::Provider {
        owner: PRODUCER,
        next,
        training,
        validation,
        returned,
    }
}

/// Host producer fixture writes each typed value once into a real pool bank.
/// No wire deserializer or public forged AcceptedSample factory is used.
struct Arena {
    allocation: pool::Allocation,
    base: usize,
    cursor: usize,
}
impl Arena {
    fn new() -> Self {
        assert_eq!(cpu::slot(), 0);
        let allocation = pool::allocate(PRODUCER, 96).unwrap();
        Self {
            allocation,
            base: pool::span(allocation).unwrap().0,
            cursor: 0,
        }
    }
    fn region<T>(&mut self, n: usize) -> *mut T {
        self.cursor = self.cursor.next_multiple_of(align_of::<T>());
        let first = self.cursor;
        self.cursor += size_of::<T>() * n;
        assert!(self.cursor <= self.allocation.bytes());
        (self.base + first) as *mut T
    }
    fn object<T>(&mut self, value: T) -> &'static T {
        let ptr = self.region::<T>(1);
        unsafe {
            ptr.write(value);
            &*ptr
        }
    }
    fn slice<T>(&mut self, values: Vec<T>) -> &'static [T] {
        let n = values.len();
        let ptr = self.region::<T>(n);
        for (i, value) in values.into_iter().enumerate() {
            unsafe {
                ptr.add(i).write(value);
            }
        }
        unsafe { core::slice::from_raw_parts(ptr, n) }
    }
}
fn source(id: u64, model: Option<&TrainedModel>) -> native_driver::Source {
    cpu::set(0);
    let mut arena = Arena::new();
    let (training, validation) = support::dataset();
    let training = arena.slice(training);
    let validation = arena.slice(validation);
    let data =
        arena.object(FrozenData::freeze(training, validation, 7, support::schemas()).unwrap());
    let validation = model.map(|model| {
        let probes = support::probes(model.bytes());
        let mut cases = Vec::new();
        let mut selections = Vec::new();
        for set in &probes {
            let first = cases.len();
            let mut selected = 0;
            let mut score = i16::MIN;
            for (i, candidate) in set.iter().enumerate() {
                let input = features::encode(candidate.action, candidate.features)
                    .unwrap()
                    .values;
                let trace = integer_reference(model.bytes(), &input);
                if i == 0 || trace.output > score {
                    selected = i;
                    score = trace.output;
                }
                cases.push(ReferenceCase { input, trace });
            }
            selections.push(ReferenceSelection {
                first: first as u16,
                count: set.len() as u16,
                selected: selected as u16,
            });
        }
        let vectors = ReferenceSuite {
            parameters_hash: Sha256::digest(model.bytes()).into(),
            cases: arena.slice(cases),
            selections: arena.slice(selections),
        };
        let manifest =
            ModelManifest::learned(model, support::schemas(), &vectors, 1024 * 1024).unwrap();
        native_driver::ValidationSource {
            bytes: arena.object(*model.bytes()),
            manifest: arena.object(manifest),
            vectors: arena.object(vectors),
            probes: arena.slice(probes),
        }
    });
    pool::seal(arena.allocation).unwrap();
    let mut backing = [None; 8];
    backing[0] = Some(arena.allocation);
    backing[1] = backing[0];
    native_driver::Source {
        key: key(id),
        data,
        validation,
        backing,
    }
}
fn until(phase: native_driver::Phase) {
    cpu::set(1);
    for _ in 0..5000 {
        if native_driver::status().unwrap().phase == phase {
            return;
        }
        native_driver::driver_turn().unwrap();
    }
    panic!(
        "driver did not reach {phase:?}: {:?}",
        native_driver::status().unwrap()
    );
}

#[test]
fn real_driver_keeps_exact_pool_custody_across_unknown_busy_delivery_and_cancellation() {
    use native_driver::{Outcome, Phase};
    use smp::prototype_runtime as runtime;
    cpu::set(0);
    runtime::WORKSPACE_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::init(), Err(DomainError::Busy));
    assert_eq!(pool::usage().unwrap(), (0, 0, 0));
    pool::SPAN_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::init(), Err(DomainError::Busy));
    let partial = pool::usage().unwrap();
    assert_eq!(partial, (4, 1, 1));
    let workspace = runtime::learning_driver_workspace().unwrap();
    assert_eq!(workspace.pages(), 4);
    assert_eq!(pool::usage().unwrap(), partial);
    native_driver::init().unwrap();
    assert_eq!(pool::usage().unwrap(), partial);
    native_driver::init().unwrap();
    assert_eq!(pool::usage().unwrap(), partial);
    assert_eq!(
        native_driver::MAX_SOURCE_BYTES
            + wire::INPUT_LIMIT
            + 64 * 1024
            + partial.0 * 4096
            + learning_session::WORKSPACE_METADATA_PAGES * 4096
            + 2 * 4096,
        1024 * 1024,
    );
    let seed = UntrainedSeed::new(0);
    let active = ModelBinding {
        generation: 5,
        model_hash: Sha256::digest(seed.bytes()).into(),
        schema_hash: support::schemas().feature.hash,
    };
    let mut models = model_bank::ModelBank::new(PoolMemory);
    models
        .initialize(2, active, support::schemas(), seed.bytes())
        .unwrap();
    *COORDINATOR.lock().unwrap() = Some(Coordinator {
        models,
        next: 0,
        job: None,
    });
    let before_runtime = pool::usage().unwrap();
    runtime::initialize();
    assert_eq!(runtime::learning_driver_workspace().unwrap(), workspace);
    assert_eq!(pool::usage().unwrap().0, before_runtime.0 + 128);
    assert_eq!(pool::usage().unwrap().1, before_runtime.1 + 1);
    assert_eq!(native_driver::driver_turn(), Err(DomainError::Auth));
    cpu::set(1);
    runtime::extra(true);
    learning_session::NEXT.store(1, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(true));
    learning_session::NEXT.store(2, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(false));
    learning_session::NEXT.store(3, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Err(DomainError::Again));
    assert_eq!(native_driver::status().unwrap().phase, Phase::Idle);
    assert_eq!(runtime::counters(), (0, 0, 0, false));
    assert_eq!(native_driver::driver_turn(), Ok(false)); // No provider, no fabricated job.
    cpu::set(0);
    native_driver::register(provider()).unwrap();
    native_driver::register(provider()).unwrap();
    let mut other = provider();
    other.owner = key(43);
    assert_eq!(native_driver::register(other), Err(DomainError::Conflict));

    let first = source(1, None);
    QUEUE.lock().unwrap().push_back(first);
    until(Phase::PinSource);
    let pins = pool::usage().unwrap().2;
    pool::SPAN_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(false));
    assert_eq!(pool::usage().unwrap().2, pins + 1); // Pin survived a later Busy.
    native_driver::driver_turn().unwrap();
    assert_eq!(pool::usage().unwrap().2, pins + 1); // Exact retry did not repin.
    until(Phase::Wait);
    assert_eq!(runtime::counters(), (1, 0, 0, true));
    assert_eq!(pool::unseal(runtime::allocation()), Err(DomainError::Busy));
    for _ in 0..3 {
        assert_eq!(native_driver::driver_turn(), Ok(false));
    }
    assert_eq!(runtime::counters(), (1, 0, 0, true));
    runtime::run_numerical_worker();
    until(Phase::Accept);
    UNKNOWN_COMPLETION.store(true, Ordering::Release);
    for _ in 0..3 {
        assert_eq!(native_driver::driver_turn(), Ok(false));
    }
    assert_eq!(native_driver::status().unwrap().phase, Phase::Accept);
    assert_eq!(runtime::counters().1, 0);
    UNKNOWN_COMPLETION.store(false, Ordering::Release);
    until(Phase::Deliver);
    assert_eq!(runtime::counters().1, 1);
    DELIVERY_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(false));
    assert_eq!(native_driver::status().unwrap().phase, Phase::Deliver);
    until(Phase::Notify);
    RETURN_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(false));
    assert_eq!(native_driver::status().unwrap().completed, 0);
    until(Phase::Idle);
    assert_eq!(native_driver::status().unwrap().completed, 1);
    assert_eq!(RETURNS.lock().unwrap().len(), 1);
    let trained = TRAINED.lock().unwrap().take().unwrap();

    let second = source(2, Some(&trained));
    QUEUE.lock().unwrap().push_back(second);
    until(Phase::Wait);
    runtime::run_numerical_worker();
    until(Phase::Close);
    runtime::ACK_BUSY.store(true, Ordering::Release);
    assert_eq!(native_driver::driver_turn(), Ok(false));
    assert_eq!(runtime::counters().1, 1);
    assert!(runtime::counters().3);
    until(Phase::Idle);
    assert_eq!(runtime::counters().1, 2);
    let mut delivery = VALIDATED.lock().unwrap().take().unwrap();
    assert_eq!(
        delivery.candidate().unwrap().model().bytes(),
        trained.bytes()
    );
    let loan = &mut runtime::borrow_learning_input().unwrap();
    let (input, _) = runtime::learning_input_span(loan).unwrap();
    unsafe {
        core::ptr::write_bytes(input as *mut u8, 0xa5, 4096);
    }
    assert_eq!(
        delivery.candidate().unwrap().model().bytes(),
        trained.bytes()
    );
    runtime::abandon_learning_input(loan).unwrap();
    pool::UNPIN_BUSY.store(true, Ordering::Release);
    assert_eq!(delivery.release(), Err(Error::Unknown));
    assert!(delivery.candidate().is_err());
    delivery.release().unwrap();
    delivery.release().unwrap();

    let stale = source(3, None);
    QUEUE.lock().unwrap().push_back(stale);
    until(Phase::Wait);
    runtime::run_numerical_worker();
    STALE_ADOPTION.store(true, Ordering::Release);
    until(Phase::Idle);
    STALE_ADOPTION.store(false, Ordering::Release);
    assert_eq!(runtime::counters().1, 3);
    assert_eq!(
        RETURNS.lock().unwrap().last(),
        Some(&(key(3), Outcome::Rejected(Error::Stale)))
    );
    assert!(TRAINED.lock().unwrap().is_none());

    let cancel = source(4, None);
    QUEUE.lock().unwrap().push_back(cancel);
    until(Phase::Wait);
    cpu::set(0);
    native_driver::cancel(key(4)).unwrap();
    cpu::set(1);
    for _ in 0..3 {
        assert_eq!(native_driver::driver_turn(), Ok(false));
    }
    assert_eq!(native_driver::status().unwrap().phase, Phase::Cleanup);
    assert_eq!(runtime::counters().1, 3);
    assert!(runtime::counters().3);
    assert!(runtime::counters().2 >= 1);
    assert_eq!(pool::unseal(runtime::allocation()), Err(DomainError::Busy));
    runtime::confirm_cancel();
    until(Phase::Idle);
    assert_eq!(runtime::counters().1, 4);
    assert_eq!(
        RETURNS.lock().unwrap().last(),
        Some(&(key(4), Outcome::Cancelled))
    );

    let mut wrong = first;
    wrong.key = key(5);
    wrong.backing = second.backing;
    QUEUE.lock().unwrap().push_back(wrong);
    until(Phase::PinSource);
    until(Phase::Idle);
    assert_eq!(runtime::counters().0, 4);
    assert_eq!(
        RETURNS.lock().unwrap().last(),
        Some(&(key(5), Outcome::Rejected(Error::Evidence)))
    );
    cpu::set(0);
    let boundary_pages = native_driver::MAX_SOURCE_BYTES / 4096 - first.backing[0].unwrap().pages();
    let excess = pool::allocate(PRODUCER, boundary_pages + 1).unwrap();
    pool::seal(excess).unwrap();
    let mut too_large = first;
    too_large.key = key(6);
    too_large.backing[2] = Some(excess);
    QUEUE.lock().unwrap().push_back(too_large);
    until(Phase::PinSource);
    until(Phase::Idle);
    assert_eq!(runtime::counters().0, 4);
    assert_eq!(
        RETURNS.lock().unwrap().last(),
        Some(&(key(6), Outcome::Rejected(Error::Capacity)))
    );

    let mut preparation = first;
    preparation.key = key(7);
    QUEUE.lock().unwrap().push_back(preparation);
    until(Phase::Encode);
    cpu::set(0);
    native_driver::cancel(key(7)).unwrap();
    cpu::set(1);
    until(Phase::Idle);
    assert_eq!(runtime::counters().0, 4);
    assert_eq!(runtime::counters().1, 4);
    assert!(!runtime::counters().3);
    assert!(COORDINATOR.lock().unwrap().as_ref().unwrap().job.is_none());
    assert_eq!(
        RETURNS.lock().unwrap().last(),
        Some(&(key(7), Outcome::Cancelled))
    );
    cpu::set(0);
    let allowed = pool::allocate(PRODUCER, boundary_pages).unwrap();
    pool::seal(allowed).unwrap();
    let mut exact = first;
    exact.key = key(8);
    exact.backing[2] = Some(allowed);
    QUEUE.lock().unwrap().push_back(exact);
    until(Phase::Encode);
    assert_eq!(
        native_driver::status().unwrap().source_bytes,
        native_driver::MAX_SOURCE_BYTES
    );
    cpu::set(0);
    native_driver::cancel(key(8)).unwrap();
    cpu::set(1);
    until(Phase::Idle);
    assert_eq!(runtime::counters().0, 4);
    assert_eq!(runtime::counters().1, 4);
    assert!(!runtime::counters().3);
    assert_eq!(native_driver::status().unwrap().completed, 2);
    assert_eq!(native_driver::status().unwrap().rejected, 6);
    assert_eq!(pool::usage().unwrap().2, 1); // Only the driver's permanent metadata pin remains.
    runtime::extra(false);
    assert_eq!(native_driver::driver_turn(), Err(DomainError::Auth));
}
