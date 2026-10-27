//! Control CPUs own proposal publication. Isolated EL0 scores immutable candidates; executors
//! report real completion independently, with no inference in business paths.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use cyxia_arch_aarch64::timer;
use cyxia_prototype::{
    domains::stability::{Boundary, Guard as StabilityGuard, ServiceWindow, WindowOutcome},
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS},
    features::{DomainObservation, RawFeatures, TargetFeatures},
    learning::{self, SchemaBinding, Schemas, governance::CommitGate},
    policy::{
        self, Candidate, CandidateSet, ExecutionState, ModelBinding, PreparedCandidateSet,
        Publisher, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use sha2::{Digest, Sha256};
#[repr(transparent)]
struct DiagnosticRow<const N: usize>(UnsafeCell<[u64; N]>);
unsafe impl<const N: usize> Sync for DiagnosticRow<N> {}
impl<const N: usize> DiagnosticRow<N> {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }
    fn store(&self, offset: usize, value: u64) {
        // Each row has one CPU writer and is consumed only from a stopped
        // failure snapshot. Volatile preserves the external evidence writes
        // without introducing a translated atomic helper into the measured
        // preparation path.
        unsafe {
            self.0.get().cast::<u64>().add(offset).write_volatile(value);
        }
    }
}
#[repr(C, align(64))]
struct PreparationEvidence([DiagnosticRow<8>; 2]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_EVIDENCE: PreparationEvidence =
    PreparationEvidence([const { DiagnosticRow::new() }; 2]);
#[repr(C, align(64))]
struct PreparationDetail([DiagnosticRow<16>; 2]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_DETAIL: PreparationDetail =
    PreparationDetail([const { DiagnosticRow::new() }; 2]);
#[repr(C, align(64))]
struct PreparationPrefixDetail([DiagnosticRow<8>; 2]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_PREFIX_DETAIL: PreparationPrefixDetail =
    PreparationPrefixDetail([const { DiagnosticRow::new() }; 2]);
const _: () = assert!(core::mem::size_of::<PreparationEvidence>() == 128);
const _: () = assert!(core::mem::size_of::<PreparationDetail>() == 256);
const _: () = assert!(core::mem::size_of::<PreparationPrefixDetail>() == 128);
#[repr(C, align(64))]
struct PreparationContextRow {
    payload: UnsafeCell<[u64; 7]>,
    published: AtomicU64,
}
unsafe impl Sync for PreparationContextRow {}
impl PreparationContextRow {
    const fn new() -> Self {
        Self {
            payload: UnsafeCell::new([0; 7]),
            published: AtomicU64::new(0),
        }
    }
    fn store(&self, offset: usize, value: u64) {
        // This row has exactly one CPU writer and no live Rust reader. The
        // independent verifier reads it only from a stopped guest snapshot;
        // published is the release validity word for partial live updates.
        unsafe {
            self.payload
                .get()
                .cast::<u64>()
                .add(offset)
                .write_volatile(value);
        }
    }
}
#[repr(C, align(64))]
struct PreparationContext([PreparationContextRow; 2]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_CONTEXT: PreparationContext =
    PreparationContext([const { PreparationContextRow::new() }; 2]);
const _: () = assert!(core::mem::size_of::<PreparationContextRow>() == 64);
const _: () = assert!(core::mem::size_of::<PreparationContext>() == 128);
fn preparation_detail(phase: usize) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let row = &DOMAIN_PREPARATION_DETAIL.0[cpu - 1];
    if phase + 1 < 16 {
        // A zero terminator distinguishes this invocation from stale tail
        // slots without rewriting the complete diagnostic row on every paid
        // preparation turn. Markers are emitted in strict phase order.
        row.store(phase + 1, 0);
    }
    // The coarse preparation bank retains wall-clock ordering. This detailed
    // bank uses the patched per-vCPU execution counter so MTTCG descheduling
    // cannot hide which preparation substage consumed the prepaid CPU credit.
    // Each bank has one CPU writer and is consumed only from a stopped failure
    // snapshot whose credit record is the publication boundary.
    row.store(phase, timer::cpu_ticks());
}
fn preparation_prefix_detail(phase: usize) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let row = &DOMAIN_PREPARATION_PREFIX_DETAIL.0[cpu - 1];
    if phase + 1 < 8 {
        row.store(phase + 1, 0);
    }
    row.store(phase, timer::cpu_ticks());
}
fn preparation_phase(phase: usize) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let row = &DOMAIN_PREPARATION_EVIDENCE.0[cpu - 1];
    if phase + 1 < 8 {
        row.store(phase + 1, 0);
    }
    row.store(phase, now());
}
fn clear_preparation_context() {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    // Word 7 is the release-published validity/start field. Clearing it makes
    // the older payload in words 0..6 explicitly invalid until the next
    // preparation_lookup/preparation_context publication completes.
    DOMAIN_PREPARATION_CONTEXT.0[cpu - 1]
        .published
        .store(0, Ordering::Release);
}
fn preparation_lookup(family: usize, descriptor: Family, ordinal: usize, started: u64) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let source = match descriptor.target_source {
        TargetSource::Tasks => 1,
        TargetSource::Services => 2,
        TargetSource::Network => 3,
        TargetSource::Storage => 4,
        TargetSource::Platform => 5,
    };
    let row = &DOMAIN_PREPARATION_CONTEXT.0[cpu - 1];
    for (offset, value) in [
        family as u64 + 1,
        u64::from(descriptor.domain),
        u64::from(descriptor.kind),
        source,
        ordinal as u64,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        row.store(offset, value);
    }
    row.published.store(started, Ordering::Release);
}
fn preparation_context(family: usize, descriptor: Family, target: ObjectKey, started: u64) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let row = &DOMAIN_PREPARATION_CONTEXT.0[cpu - 1];
    for (offset, value) in [
        family as u64 + 1,
        u64::from(descriptor.domain),
        u64::from(descriptor.kind),
        target.id,
        target.generation,
        0,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        row.store(offset, value);
    }
    row.published.store(started, Ordering::Release);
}
fn preparation_current(current: Action) {
    let cpu = cyxia_arch_aarch64::cpu::slot();
    if !(1..=2).contains(&cpu) {
        return;
    }
    let (_, _, a, b) = current.order();
    let row = &DOMAIN_PREPARATION_CONTEXT.0[cpu - 1];
    row.store(5, a);
    row.store(6, b);
}
#[path = "domain_control/core_replay.rs"]
pub mod core_replay;
#[path = "domain_control/dependencies.rs"]
mod dependencies;
#[path = "domain_control/governance.rs"]
pub mod governance;
#[path = "domain_control/learning.rs"]
pub mod learning_coordinator;
#[path = "domain_control/learning_driver.rs"]
pub mod learning_driver;
#[path = "domain_control/replay.rs"]
pub mod replay;
#[path = "domain_control/reply.rs"]
mod reply;
#[path = "domain_control/target_batch.rs"]
pub(crate) mod target_batch;
pub use target_batch::Source as TargetSource;
#[path = "domain_control/preparation.rs"]
mod preparation;
// Serialized by the same protected control-owner gate as State. This is an
// explicit negative preparation record, never a proposal or execution receipt.
static mut PREPARATION_REJECTIONS: preparation::Rejections = preparation::Rejections::new();
/// Header: magic, count, overwritten, seqlock, version, row words, capacity, 0.
/// Sixteen 40-word explicit rejected preparations follow; no proposal is implied.
#[repr(C, align(64))]
struct PreparationRejections([core::sync::atomic::AtomicU64; 648]);
#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_REJECTIONS: PreparationRejections =
    PreparationRejections([const { core::sync::atomic::AtomicU64::new(0) }; 648]);
pub use cyxia_prototype::policy::{BoundDependency, Prerequisite};
type DependencyResolver = fn(ObjectKey) -> Result<[Option<Prerequisite>; 2], Error>;
type ExecutionObserver = fn(ObjectKey, u64) -> Result<(), Error>;
static ADMISSION: dependencies::AdmissionView = dependencies::AdmissionView::new();
static DEPENDENCY_RESOLVERS: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
#[path = "../../user/prototype-runtime/abi.rs"]
mod abi;

#[derive(Clone, Copy)]
pub struct Family {
    pub domain: u16,
    pub kind: u16,
    pub target_source: TargetSource,
    pub target: fn(u16, u16, usize) -> Option<ObjectKey>,
    pub observe: fn(u16, ObjectKey) -> Result<DomainObservation, Error>,
    pub current: fn(u16, u16, ObjectKey) -> Result<Action, Error>,
    pub legal: fn(Action, ObjectKey, u64) -> Result<(), Error>,
    pub legal_options:
        fn(&[Option<Action>], ObjectKey, u64, &mut [Option<Action>]) -> Result<usize, Error>,
    pub target_features: fn(Action, ObjectKey) -> Result<TargetFeatures, Error>,
    pub apply: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
    pub reconcile: fn(Action, ApplyId, PolicyStamp, u64) -> Result<ExecutionState, Error>,
}
#[derive(Clone, Copy, Default)]
pub struct Context {
    pub core_generation: u64,
    pub ledger_generation: u64,
    pub control_mask: u64,
    pub business_mask: u64,
    pub healthy_mask: u64,
    pub draining_mask: u64,
    pub common: [u64; 8],
}
#[derive(Clone, Copy)]
struct Desired {
    action: Action,
    apply: ApplyId,
    stamp: PolicyStamp,
    state: ExecutionState,
    execution_observed: bool,
    started: bool,
    first_entry_ns: Option<u64>,
    observed_ns: u64,
    published: u64,
    evidence: Option<usize>,
    job: u64,
    model: ModelBinding,
    dependencies: [Option<BoundDependency>; 2],
    core_generation: u64,
    ledger_generation: u64,
}
struct Owner {
    families: [Option<Family>; 18],
    family_epochs: [u64; 18],
    desired: [Option<Desired>; 512],
    stability: [Option<StabilityGuard>; 512],
    stability_high: usize,
    context: Context,
    prepared: [usize; 16],
    prepared_count: usize,
    poll_cursor: usize,
    dependencies: [Option<DependencyResolver>; 16],
    execution_observers: [Option<ExecutionObserver>; 16],
}
#[derive(Clone, Copy)]
struct Job {
    cpu: usize,
    set: CandidateSet,
    sequence: u64,
    controller: u64,
    base_version: u64,
    started: u64,
    encode_ns: u64,
    evidence: Option<usize>,
    dependencies: [Option<BoundDependency>; 2],
    work: Option<core_replay::WorkId>,
    read_only: bool,
    completion: Option<JobCompletion>,
}
#[derive(Clone, Copy)]
struct JobCompletion {
    result: Result<u64, Error>,
    selected: u64,
    decoded_ns: u64,
    elapsed_ns: u64,
    cpu_ns: u64,
    output_hash: [u8; 32],
    aborted: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct JobSource {
    pub owner: ObjectKey,
    pub class: learning::reward::CpuClass,
    pub work: Option<core_replay::WorkId>,
}
fn job_source(job: &Job) -> JobSource {
    JobSource {
        owner: if job.read_only {
            core_replay::CORE_OWNER
        } else {
            job.set.target
        },
        class: if job.read_only {
            learning::reward::CpuClass::ExecutorWork
        } else {
            learning::reward::CpuClass::Policy
        },
        work: job.work,
    }
}
struct State {
    registry: Registry,
    models: crate::model_bank::ModelBank<crate::model_bank::NativeMemory>,
    model_gate: Option<CommitGate>,
    learning_jobs: learning_coordinator::Jobs,
    governance_jobs: governance::Jobs,
    worker_sequence: u64,
    owner: Owner,
    boot: u64,
    sequence: u64,
    job: Option<Job>,
    preparation: Option<preparation::Pending>,
    due: [u64; 18],
    cursor: [usize; 18],
    family_cursor: usize,
    started: u64,
}
static CLAIMED: AtomicBool = AtomicBool::new(false);
static mut STATE: State = State {
    registry: Registry::empty(),
    models: crate::model_bank::ModelBank::new(crate::model_bank::NativeMemory),
    model_gate: None,
    learning_jobs: learning_coordinator::Jobs::new(),
    governance_jobs: governance::Jobs::new(),
    worker_sequence: 0,
    owner: Owner {
        families: [None; 18],
        family_epochs: [0; 18],
        desired: [None; 512],
        stability: [None; 512],
        stability_high: 0,
        context: Context {
            core_generation: 0,
            ledger_generation: 0,
            control_mask: 0,
            business_mask: 0,
            healthy_mask: 0,
            draining_mask: 0,
            common: [0; 8],
        },
        prepared: [0; 16],
        prepared_count: 0,
        poll_cursor: 0,
        dependencies: [None; 16],
        execution_observers: [None; 16],
    },
    boot: 0,
    sequence: 0,
    job: None,
    preparation: None,
    due: [0; 18],
    cursor: [0; 18],
    family_cursor: 0,
    started: 0,
};
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        CLAIMED.store(false, Ordering::Release);
    }
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    if cyxia_arch_aarch64::cpu::slot() >= 4 {
        return Err(Error::Auth);
    }
    if CLAIMED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(Error::Busy);
    }
    let _guard = Guard;
    f(unsafe { &mut *core::ptr::addr_of_mut!(STATE) })
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn require_control(owner: &Owner) -> Result<(), Error> {
    let bit = 1u64 << cyxia_arch_aarch64::cpu::slot();
    if owner.context.control_mask & owner.context.healthy_mask & !owner.context.draining_mask & bit
        == 0
    {
        Err(Error::Auth)
    } else {
        Ok(())
    }
}
fn family_index(domain: u16, kind: u16) -> Result<usize, Error> {
    match (domain, kind) {
        (1, 1) => Ok(0),
        (1, 2) => Ok(1),
        (2..=15, 1) => Ok(domain as usize),
        (16, 1) => Ok(16),
        (16, 2) => Ok(17),
        _ => Err(Error::Unsupported),
    }
}
fn publisher(epoch: u64) -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 0x43414350,
            generation: epoch,
        },
        controller_epoch: epoch,
    }
}
pub fn init(boot: u64) -> Result<(), Error> {
    if boot == 0 {
        return Err(Error::Auth);
    }
    if !cyxia_arch_aarch64::sha256::selftest() {
        return Err(Error::Schema);
    }
    // The actual driver remains idle without protected replay data. Do this
    // before publishing boot readiness so a Busy startup can retry its loan.
    learning_driver::init()?;
    crate::learning_canary::init()?;
    crate::service_windows::init()?;
    with(|s| {
        if s.boot != 0 {
            return if s.boot == boot {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let model = ModelBinding {
            generation: 1,
            model_hash: Sha256::digest(abi::domain_model_bytes()).into(),
            schema_hash: Sha256::digest(include_bytes!("../../crates/prototype/src/features.rs"))
                .into(),
        };
        let schemas = Schemas {
            feature: SchemaBinding {
                version: 13,
                hash: model.schema_hash,
            },
            action: SchemaBinding {
                version: 13,
                hash: Sha256::digest(include_bytes!("../../crates/prototype/src/policy_wire.rs"))
                    .into(),
            },
            reward: learning::reward_schema(),
            learning: learning::learning_config(),
        };
        // Provision the actual four-bank backing before exposing Registry. A
        // Busy retry retains every already allocated page and exact identity.
        s.models
            .initialize(boot, model, schemas, &abi::domain_model_bytes())?;
        let gate = CommitGate::new(boot, model).map_err(|_| Error::Schema)?;
        s.registry.initialize(boot, publisher(1), model)?;
        s.model_gate = Some(gate);
        s.boot = boot;
        s.started = now();
        crate::domain_evidence::initialize(boot, model);
        Ok(())
    })
}
pub type NativeModelPin = crate::model_bank::ModelPin<crate::control_pool::Lease>;
/// The immutable parameters are selected by the exact outstanding job, never
/// by an EL0 pointer, echoed model hash, or the newest Active after a restart.
pub fn pin_job_model(sequence: u64, controller: u64) -> Result<NativeModelPin, Error> {
    with(|s| {
        require_control(&s.owner)?;
        let job = s.job.as_ref().ok_or(Error::NotReady)?;
        if job.cpu != cyxia_arch_aarch64::cpu::slot()
            || job.sequence != sequence
            || job.controller != controller
        {
            return Err(Error::Auth);
        }
        let gate = s.model_gate.as_ref().ok_or(Error::NotReady)?;
        if gate.active() != s.registry.model() || s.models.active()? != s.registry.model() {
            return Err(Error::Stale);
        }
        gate.check_active_publication(job.set.model, job.set.target)
            .map_err(|_| Error::Stale)?;
        s.models.pin(job.set.model)
    })
}
/// Runtime calls this after the exact context has stopped, its model mapping
/// and TLB entry are revoked, and the final physical/control bill has settled.
/// Busy leaves the caller's original, non-clonable pin live for retry.
pub fn release_job_model(pin: &NativeModelPin) -> Result<(), Error> {
    with(|s| s.models.release(pin))
}
pub fn register(family: Family) -> Result<(), Error> {
    with(|s| {
        if s.boot == 0 {
            return Err(Error::NotReady);
        }
        let i = family_index(family.domain, family.kind)?;
        if TargetSource::for_family(family.domain, family.kind) != Some(family.target_source) {
            return Err(Error::Conflict);
        }
        if let Some(old) = s.owner.families[i] {
            return if old.domain == family.domain
                && old.kind == family.kind
                && old.target_source == family.target_source
                && core::ptr::fn_addr_eq(old.target, family.target)
                && core::ptr::fn_addr_eq(old.observe, family.observe)
                && core::ptr::fn_addr_eq(old.current, family.current)
                && core::ptr::fn_addr_eq(old.legal, family.legal)
                && core::ptr::fn_addr_eq(old.legal_options, family.legal_options)
                && core::ptr::fn_addr_eq(old.target_features, family.target_features)
                && core::ptr::fn_addr_eq(old.apply, family.apply)
                && core::ptr::fn_addr_eq(old.reconcile, family.reconcile)
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        s.owner.families[i] = Some(family);
        // Registered callbacks are fixed for this boot. This is the executor's
        // protected registration epoch, independent of each target's lifetime.
        s.owner.family_epochs[i] = s.boot;
        crate::domain_evidence::registered(i);
        Ok(())
    })
}

pub fn register_dependencies(consumer: u16, resolver: DependencyResolver) -> Result<(), Error> {
    if !matches!(consumer, 1 | 4 | 8 | 10) {
        return Err(Error::Unsupported);
    }
    with(|s| {
        let slot = &mut s.owner.dependencies[usize::from(consumer - 1)];
        if let Some(old) = *slot {
            return if core::ptr::fn_addr_eq(old, resolver) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        *slot = Some(resolver);
        DEPENDENCY_RESOLVERS[usize::from(consumer - 1)].store(resolver as usize, Ordering::Release);
        Ok(())
    })
}
/// Confirm the exact APPLIED version to the owner of real resource grants.
/// The callback must be idempotent and nonblocking. Busy/Again/NotReady retain
/// the receipt for retry; another policy for this object cannot replace it.
/// Existing grants keep their own confirmation across later policy versions.
pub fn register_execution_observer(domain: u16, observer: ExecutionObserver) -> Result<(), Error> {
    if !matches!(domain, 5 | 9) {
        return Err(Error::Unsupported);
    }
    with(|s| {
        let slot = &mut s.owner.execution_observers[usize::from(domain - 1)];
        if let Some(old) = *slot {
            return if core::ptr::fn_addr_eq(old, observer) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if s.owner
            .desired
            .iter()
            .flatten()
            .any(|d| d.action.domain() == domain)
        {
            return Err(Error::Conflict);
        }
        *slot = Some(observer);
        Ok(())
    })
}
fn execution_blocks_replacement(d: &Desired) -> bool {
    !d.state.terminal() || d.state == ExecutionState::Applied && !d.execution_observed
}
fn observe_execution(s: &mut State, d: &mut Desired) {
    if d.state != ExecutionState::Applied || d.execution_observed {
        return;
    }
    let result = s.owner.execution_observers[usize::from(d.action.domain() - 1)]
        .map_or(Ok(()), |observer| observer(d.apply.target, d.stamp.version));
    match result {
        Ok(()) => d.execution_observed = true,
        Err(Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound) => {}
        Err(error) => {
            // The resource already exists. Preserve its real APPLIED receipt
            // and obligations while stopping further optimization on a broken
            // owner-confirmation contract.
            s.registry.stop_optimization();
            crate::domain_evidence::observer_failed(d.action.domain(), d.stamp.version, error);
        }
    }
}
/// Call while holding the actual prerequisite owner's resource gate, after
/// checking its initialized baseline, ownership, current capacity and usage.
/// Existing in-flight completion/recovery must not pass through this new-work gate.
pub fn admit_dependency(prerequisite: Prerequisite, consumer: u16, at: u64) -> Result<u64, Error> {
    ADMISSION.admit(prerequisite, consumer, at)
}
/// Resolve before taking a consumer lock. Resolution validates initialized
/// baseline owners; this method never takes the coordinator/policy gate.
pub fn admit_dependencies(consumer: u16, target: ObjectKey) -> Result<(), Error> {
    let address = DEPENDENCY_RESOLVERS
        .get(usize::from(
            consumer.checked_sub(1).ok_or(Error::Unsupported)?,
        ))
        .ok_or(Error::Unsupported)?
        .load(Ordering::Acquire);
    if address == 0 {
        return Err(Error::NotReady);
    }
    // Only register_dependencies writes a statically typed function address;
    // release/acquire publication prevents observing a partially installed resolver.
    let resolver: DependencyResolver = unsafe { core::mem::transmute(address) };
    for prerequisite in resolver(target)?.into_iter().flatten() {
        admit_dependency(prerequisite, consumer, now())?;
    }
    Ok(())
}
fn bind_dependencies(
    owner: &Owner,
    action: Action,
    target: ObjectKey,
    at: u64,
) -> Result<[Option<BoundDependency>; 2], Error> {
    if !matches!(action.domain(), 1 | 4 | 8 | 10) || matches!(action, Action::ControlSet(_)) {
        return Ok([None; 2]);
    }
    let resolver = owner.dependencies[usize::from(action.domain() - 1)].ok_or(Error::NotReady)?;
    bind_dependency_list(
        owner,
        action,
        at,
        resolver(target)?,
        |f, key| (f.current)(f.domain, f.kind, key),
        |f, value, key| (f.legal)(value, key, at),
    )
}
fn bind_dependency_list(
    owner: &Owner,
    action: Action,
    at: u64,
    prerequisites: [Option<Prerequisite>; 2],
    mut current: impl FnMut(Family, ObjectKey) -> Result<Action, Error>,
    mut legal: impl FnMut(Family, Action, ObjectKey) -> Result<(), Error>,
) -> Result<[Option<BoundDependency>; 2], Error> {
    let mut bound = [None; 2];
    for (i, prerequisite) in prerequisites.into_iter().enumerate() {
        let Some(prerequisite) = prerequisite else {
            continue;
        };
        if !policy::dependency_allowed(prerequisite.domain, action.domain()) {
            return Err(Error::Unsupported);
        }
        let f = owner.families[family_index(prerequisite.domain, 1)?].ok_or(Error::NotReady)?;
        let value = current(f, prerequisite.target)?;
        legal(f, value, prerequisite.target)?;
        let version = admit_dependency(prerequisite, action.domain(), at)?;
        bound[i] = Some(BoundDependency {
            prerequisite,
            version,
        });
    }
    Ok(bound)
}
pub fn publish_context(context: Context) -> Result<(), Error> {
    with(|s| {
        if context.core_generation == 0
            || context.ledger_generation == 0
            || context.control_mask & context.business_mask != 0
        {
            return Err(Error::Conflict);
        }
        if context.core_generation < s.owner.context.core_generation
            || context.ledger_generation < s.owner.context.ledger_generation
        {
            return Err(Error::Stale);
        }
        s.owner.context = context;
        Ok(())
    })
}
fn locate(owner: &Owner, action: Action, key: ObjectKey) -> Option<usize> {
    locate_family(owner, action.domain(), action.kind(), key)
}
fn locate_family(owner: &Owner, domain: u16, kind: u16, key: ObjectKey) -> Option<usize> {
    owner.stability[..owner.stability_high]
        .iter()
        .position(|guard| {
            guard
                .as_ref()
                .is_some_and(|guard| guard.family() == (domain, kind) && guard.target() == key)
        })
}
fn ensure_stability(
    owner: &mut Owner,
    action: Action,
    key: ObjectKey,
    at: u64,
) -> Result<usize, Error> {
    if let Some(slot) = locate(owner, action, key) {
        if action == Action::OfferCpu(0) {
            owner.stability[slot]
                .as_mut()
                .ok_or(Error::Stale)?
                .observe_stopped_offer(at)?;
        }
        return Ok(slot);
    }
    let slot = owner.stability[..owner.stability_high]
        .iter()
        .enumerate()
        .position(|(i, guard)| guard.is_none() && owner.desired[i].is_none())
        .unwrap_or(owner.stability_high);
    if slot == owner.stability.len() {
        return Err(Error::Capacity);
    }
    owner.stability[slot] = Some(StabilityGuard::new(key, action, at)?);
    owner.stability_high = owner.stability_high.max(slot + 1);
    Ok(slot)
}
/// A protected service owner freezes its measurement bounds before the first
/// window. There are no synthetic default throughput or latency observations.
pub fn register_service_boundary(
    domain: u16,
    kind: u16,
    target: ObjectKey,
    boundary: Boundary,
    starts_at_ns: u64,
) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    with(|s| {
        let f = s.owner.families[family_index(domain, kind)?].ok_or(Error::NotReady)?;
        let current = (f.current)(domain, kind, target)?;
        let at = now();
        let slot = ensure_stability(&mut s.owner, current, target, at)?;
        s.owner.stability[slot]
            .as_mut()
            .ok_or(Error::Stale)?
            .register_boundary(boundary, starts_at_ns, at)
    })
}
/// A window registration may be recycled only after its exact owner generation
/// has disappeared. This is a read-only query: live generations retain their
/// sticky Guard, and unresolved execution or inference still pins the target.
pub fn service_target_retired(domain: u16, kind: u16, target: ObjectKey) -> Result<bool, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    with(|s| {
        let f = s.owner.families[family_index(domain, kind)?].ok_or(Error::NotReady)?;
        if s.job.as_ref().is_some_and(|job| {
            job.set.target == target
                && job.set.get(0).is_some_and(|candidate| {
                    candidate.action.domain() == domain && candidate.action.kind() == kind
                })
        }) {
            return Err(Error::Busy);
        }
        if let Some(slot) = locate_family(&s.owner, domain, kind, target)
            && (s.owner.prepared[..s.owner.prepared_count].contains(&slot)
                || s.owner.desired[slot]
                    .as_ref()
                    .is_some_and(|desired| !desired.state.terminal()))
        {
            return Err(Error::Busy);
        }
        // The same exact-owner predicate used by the service-step Guard
        // collector. Busy, unavailable ownership and UNKNOWN are not death.
        match (f.current)(domain, kind, target) {
            Err(Error::Stale | Error::NotFound) => Ok(true),
            Ok(_) => Ok(false),
            Err(error) => Err(error),
        }
    })
}
/// Consume owner-measured complete windows; partial and missing evidence never
/// becomes a successful service-boundary observation. Freeze preserves APPLY.
pub fn observe_service_window(window: ServiceWindow) -> Result<WindowOutcome, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    with(|s| {
        let f =
            s.owner.families[family_index(window.domain, window.kind)?].ok_or(Error::NotReady)?;
        let current = (f.current)(window.domain, window.kind, window.target)?;
        let slot = locate(&s.owner, current, window.target).ok_or(Error::NotReady)?;
        s.owner.stability[slot]
            .as_mut()
            .ok_or(Error::Stale)?
            .observe_service(window, now())
    })
}
fn tiers(current: Action) -> ([Option<Action>; 32], usize) {
    let mut out = [None; 32];
    let mut n = 0;
    let mut add = |a| {
        out[n] = Some(a);
        n += 1;
    };
    match current {
        Action::CpuWeight(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::CpuWeight(v));
            }
        }
        Action::ControlSet(mask) => {
            add(Action::ControlSet(mask));
            add(Action::ControlSet(mask ^ 4));
        }
        Action::SpawnTokens(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::SpawnTokens(v));
            }
        }
        Action::Cache { .. } => {
            for (pages, batch) in [(64, 4), (256, 16), (1024, 32), (4096, 64)] {
                add(Action::Cache { pages, batch });
            }
        }
        Action::Filesystem { .. } => {
            for (readahead, flush) in [(0, 4), (2, 8), (8, 16), (16, 32)] {
                add(Action::Filesystem { readahead, flush });
            }
        }
        Action::Ipc { .. } => {
            for (budget, batch) in [(8, 1), (32, 4), (64, 8), (128, 16)] {
                add(Action::Ipc { budget, batch });
            }
        }
        Action::IrqTarget(_) => {
            for v in 0..4 {
                add(Action::IrqTarget(v));
            }
        }
        Action::SoftCoalesce(_) => {
            for v in [0, 50, 200, 1000] {
                add(Action::SoftCoalesce(v));
            }
        }
        Action::ServiceBatch(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::ServiceBatch(v));
            }
        }
        Action::IoShare(_) => {
            for v in [100, 250, 500, 750] {
                add(Action::IoShare(v));
            }
        }
        Action::TxBatch(_) => {
            for v in [1, 4, 8, 16] {
                add(Action::TxBatch(v));
            }
        }
        Action::NotifyBatch(_) => {
            for v in [1, 2, 4, 8] {
                add(Action::NotifyBatch(v));
            }
        }
        Action::UnauthRate(_) => {
            for v in [4, 8, 16, 32] {
                add(Action::UnauthRate(v));
            }
        }
        Action::BackgroundBudget(_) => {
            for v in [50, 100, 200, 400] {
                add(Action::BackgroundBudget(v));
            }
        }
        Action::RecoveryRecipe(_) => {
            for v in 0..3 {
                add(Action::RecoveryRecipe(v));
            }
        }
        Action::ConsoleBatch(_) => {
            for v in [1, 8, 32, 64] {
                add(Action::ConsoleBatch(v));
            }
        }
        Action::OfferCpu(_) => {
            for v in [100, 250, 500, 1000] {
                add(Action::OfferCpu(v));
            }
        }
        Action::Placement(_) => {
            for v in 0..3 {
                add(Action::Placement(v));
            }
        }
    }
    (out, n)
}
fn categorical(action: Action) -> bool {
    matches!(
        action,
        Action::IrqTarget(_) | Action::RecoveryRecipe(_) | Action::Placement(_)
    )
}
fn validate_selection(
    owner: &Owner,
    f: Family,
    action: Action,
    target: ObjectKey,
    at: u64,
) -> Result<(), Error> {
    let slot = locate(owner, action, target).ok_or(Error::Stale)?;
    let guard = owner.stability[slot].as_ref().ok_or(Error::Stale)?;
    let current = (f.current)(action.domain(), action.kind(), target)?;
    if action == current {
        return Ok(());
    }
    if guard.frozen() {
        return Err(Error::Busy);
    }
    if categorical(action) {
        return Ok(());
    }
    let hold = if matches!(action, Action::ControlSet(_) | Action::UnauthRate(_)) {
        1_000_000_000
    } else {
        WINDOW_NS
    };
    if at.saturating_sub(guard.last_change_ns()) < hold {
        return Err(Error::Busy);
    }
    let (options, n) = tiers(current);
    let mut legal = [None; 32];
    let count = (f.legal_options)(&options[..n], target, at, &mut legal)?;
    legal[..count].sort_unstable_by_key(|a| a.map(Action::order));
    if !cyxia_prototype::domains::stability::adjacent(current, action, &legal[..count])? {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn read_target_batch(
    source: TargetSource,
    queries: &[target_batch::Query],
    output: &mut [Option<ObjectKey>],
) -> Result<(), Error> {
    match source {
        TargetSource::Tasks => crate::domain_tasks::queued_targets(queries, output),
        TargetSource::Services => crate::domain_services::queued_targets(queries, output),
        TargetSource::Network => crate::domain_network::queued_targets(queries, output),
        TargetSource::Storage => crate::domain_storage::queued_targets(queries, output),
        TargetSource::Platform => crate::domain_platform::queued_targets(queries, output),
    }
}
fn queued_control_wcet_us(s: &State, active_family: usize, at: u64) -> Result<u64, Error> {
    // A released family slot remains required work even if its object walk later
    // records EMPTY or its legal-candidate set is empty. Use the scheduler's own
    // due table for this deterministic WCET feature instead of synchronously
    // borrowing all five object owners. Actual targets, generations, replay/model
    // gates and replacement blockers are checked when each family starts.
    target_batch::queued_wcet_us(active_family, at, |index| {
        s.owner.families[index].map(|_| s.due[index])
    })
}
pub fn next(controller_epoch: u64) -> Result<Option<[u64; 512]>, Error> {
    let wall_started = now();
    let cpu_started = timer::cpu_ticks();
    let mut input = [0; 512];
    let ready = with(|s| {
        next_locked(
            s,
            controller_epoch,
            None,
            wall_started,
            cpu_started,
            &mut input,
        )
    })?;
    Ok(ready.then_some(input))
}
pub(crate) fn next_paid(
    controller_epoch: u64,
    witness: &core_replay::PaidWorkWitness,
    wall_started: u64,
    cpu_started: u64,
    input: &mut [u64; 512],
) -> Result<Option<JobSource>, Error> {
    // The sole native caller starts both clocks before initializing this
    // invocation-owned buffer and consumes its bytes only after Some(source).
    with(|s| {
        if !next_locked(
            s,
            controller_epoch,
            Some(witness),
            wall_started,
            cpu_started,
            input,
        )? {
            return Ok(None);
        }
        Ok(Some(job_source(s.job.as_ref().ok_or(Error::Stale)?)))
    })
}
fn next_locked(
    s: &mut State,
    controller_epoch: u64,
    witness: Option<&core_replay::PaidWorkWitness>,
    wall_started: u64,
    cpu_started: u64,
    input: &mut [u64; 512],
) -> Result<bool, Error> {
    let result = next_locked_inner(
        s,
        controller_epoch,
        witness,
        wall_started,
        cpu_started,
        input,
    );
    if let Some(pending) = s.preparation.as_mut() {
        // Every failed retry retains its actual CPU span. Reward/physical CPU
        // accounting remains with the original paid Measurement, exactly once.
        let at = now();
        let debit = pending.charge(timer::cpu_elapsed_ns(cpu_started));
        let terminal = debit.err().or_else(|| match &result {
            Err(error) if !matches!(error, Error::Busy | Error::Again | Error::NotReady) => {
                Some(*error)
            }
            _ => None,
        });
        if let Some(error) = terminal {
            retire_preparation(s, error, at)?;
            return Err(error);
        }
        s.due[pending.family] = pending.snapshot.taken_ns;
        s.cursor[pending.family] = pending.ordinal;
        s.family_cursor = pending.family;
    }
    result
}
fn retire_preparation(s: &mut State, reason: Error, at: u64) -> Result<(), Error> {
    let pending = s.preparation.ok_or(Error::Stale)?;
    if let Some(work) = pending.identity.work {
        // A changed WorkId is already outside this attempt's authority; the
        // rejected old identity is still retained without touching its successor.
        match core_replay::reject_preparation(work, pending.identity.sequence, reason, at) {
            Ok(()) | Err(Error::Stale) => (),
            Err(error) => return Err(error),
        }
    } else {
        replay::reject_preparation(pending.identity, pending.snapshot, reason);
    }
    let (retired, total, overwritten) = unsafe {
        let journal = &mut *core::ptr::addr_of_mut!(PREPARATION_REJECTIONS);
        (
            journal.retire(pending, reason, at, s.sequence)?,
            journal.total,
            journal.overwritten,
        )
    };
    let bank = &DOMAIN_PREPARATION_REJECTIONS.0;
    bank[3].fetch_add(1, Ordering::AcqRel);
    let row = preparation::Rejected {
        pending,
        reason,
        retired_ns: at,
    }
    .words(total);
    let base = 8 + ((total - 1) as usize % 16) * 40;
    for (destination, value) in bank[base..base + 40].iter().zip(row) {
        destination.store(value, Ordering::Relaxed);
    }
    for (index, value) in [0x4359_5052_4550_3133, total, overwritten]
        .into_iter()
        .enumerate()
    {
        bank[index].store(value, Ordering::Relaxed);
    }
    for (index, value) in [1, 40, 16, 0].into_iter().enumerate() {
        bank[4 + index].store(value, Ordering::Relaxed);
    }
    bank[3].fetch_add(1, Ordering::Release);
    s.sequence = s.sequence.max(retired.sequence);
    s.due[retired.family] = retired.due_ns;
    s.cursor[retired.family] = retired.ordinal;
    s.family_cursor = retired.next_family;
    s.preparation = None;
    Ok(())
}
fn preparation_identity(
    s: &State,
    controller: u64,
    domain: u16,
    kind: u16,
    target: ObjectKey,
    sequence: u64,
    work: Option<core_replay::WorkId>,
) -> preparation::Identity {
    preparation::Identity {
        boot: s.boot,
        controller,
        sequence,
        domain,
        kind,
        target,
        model: s.registry.model(),
        core_generation: s.owner.context.core_generation,
        ledger_generation: s.owner.context.ledger_generation,
        work: work.map(core_replay::WorkId::identity),
    }
}
fn preparation_snapshot(
    s: &mut State,
    identity: preparation::Identity,
    fresh: Snapshot,
) -> Result<Snapshot, Error> {
    let Some(pending) = s.preparation else {
        return Ok(fresh);
    };
    if pending.identity != identity {
        // An actual owner/model/context change abandons the old attempt. Its
        // paid CPU is retained globally; no old debit authorizes the new key.
        return Err(Error::Stale);
    }
    pending.check(identity, now())?;
    Ok(pending.snapshot)
}
fn next_locked_inner(
    s: &mut State,
    controller_epoch: u64,
    witness: Option<&core_replay::PaidWorkWitness>,
    wall_started: u64,
    cpu_started: u64,
    input: &mut [u64; 512],
) -> Result<bool, Error> {
    preparation_phase(0);
    preparation_detail(0);
    clear_preparation_context();
    require_control(&s.owner)?;
    if s.boot == 0
        || s.job.is_some()
        || s.registry.optimization_stopped()
        || s.governance_jobs.reserves_publication(now())
    {
        return Ok(false);
    }
    if s.registry.publisher() != publisher(controller_epoch) {
        s.registry
            .change_publisher(s.registry.publisher(), publisher(controller_epoch))?;
    }
    if s.preparation
        .is_some_and(|p| p.identity.sequence != s.sequence)
    {
        return Err(Error::Stale);
    }
    if s.preparation.is_some_and(|p| p.identity.work.is_some()) {
        return core_replay::next(
            s,
            controller_epoch,
            witness.ok_or(Error::Auth)?,
            wall_started,
            cpu_started,
            input,
        );
    }
    match next_normal(
        s,
        controller_epoch,
        witness,
        wall_started,
        cpu_started,
        input,
    ) {
        Ok(false) => (),
        result => return result,
    }
    if let Some(witness) = witness {
        return core_replay::next(
            s,
            controller_epoch,
            witness,
            wall_started,
            cpu_started,
            input,
        );
    }
    Ok(false)
}
// Normal and read-only preparation each own sizeable bounded candidate scratch.
// Keep them in sibling calls: retaining the normal frame while entering replay
// exceeds the fixed control stack even before an exception adds its frame.
#[inline(never)]
fn next_normal(
    s: &mut State,
    controller_epoch: u64,
    witness: Option<&core_replay::PaidWorkWitness>,
    wall_started: u64,
    cpu_started: u64,
    input: &mut [u64; 512],
) -> Result<bool, Error> {
    let start_cursor = s.family_cursor;
    let turns = if s.preparation.is_some() { 1 } else { 18 };
    // One prepaid control turn evaluates at most one registered, due family.
    // Skipping unavailable slots to find that family is bounded bookkeeping;
    // continuing into another family's observation/candidate construction
    // would silently combine multiple 2 ms evaluations in one 2.5 ms credit.
    'families: for turn in 0..turns {
        let index = (start_cursor + turn) % 18;
        if wall_started < s.due[index] {
            continue;
        }
        let Some(f) = s.owner.families[index] else {
            continue;
        };
        s.due[index] = wall_started.saturating_add(if index == 1 || index == 16 {
            1_000_000_000
        } else {
            WINDOW_NS
        });
        s.family_cursor = (index + 1) % 18;
        let ordinal = s.cursor[index];
        // Resolve current/fallback plus exact lookahead from one immutable
        // owner view. A retry must never turn owner contention into absence,
        // and the exact lookahead must not advance onto fallback ordinal zero.
        let mut targets = [None; 2];
        let target_result = read_target_batch(
            f.target_source,
            &[
                target_batch::Query::fallback(f.domain, f.kind, ordinal),
                target_batch::Query::exact(f.domain, f.kind, ordinal + 1),
            ],
            &mut targets,
        );
        if let Err(error) = target_result {
            preparation_lookup(index, f, ordinal, wall_started);
            return Err(error);
        }
        let target = targets[0];
        s.cursor[index] = if targets[1].is_some() { ordinal + 1 } else { 0 };
        let Some(target) = target else {
            preparation_lookup(index, f, ordinal, wall_started);
            if s.preparation.is_some() {
                return Err(Error::Stale);
            }
            break 'families;
        };
        preparation_context(index, f, target, wall_started);
        preparation_detail(1);
        preparation_prefix_detail(0);
        if f.domain == 15 && crate::learning_canary::blocks_active() {
            break 'families;
        }
        preparation_prefix_detail(1);
        if !replay::allows(f.domain, f.kind, target) {
            break 'families;
        }
        preparation_prefix_detail(2);
        let fresh_snapshot = Snapshot {
            sequence: match s.preparation {
                Some(pending) => pending.identity.sequence,
                None => s.sequence.checked_add(1).ok_or(Error::Overflow)?,
            },
            taken_ns: wall_started,
            ledger_generation: s.owner.context.ledger_generation,
            core_generation: s.owner.context.core_generation,
        };
        let preparation_identity = preparation_identity(
            s,
            controller_epoch,
            f.domain,
            f.kind,
            target,
            fresh_snapshot.sequence,
            None,
        );
        preparation_prefix_detail(3);
        let replay_snapshot = preparation_snapshot(s, preparation_identity, fresh_snapshot)?;
        preparation_prefix_detail(4);
        let (replay_snapshot, _replay_prefix) =
            match replay::first(replay_snapshot, f.domain, f.kind, target) {
                Ok(v) => v,
                Err(Error::Again | Error::Busy | Error::NotReady) => {
                    // Retry the same queued first generation within its real
                    // original deadline; no additional successful AI slot.
                    s.due[index] = wall_started;
                    break 'families;
                }
                Err(e) => return Err(e),
            };
        preparation_prefix_detail(5);
        let _encoding_measure = if _replay_prefix.is_none() {
            witness
                .map(|w| {
                    core_replay::Measurement::new(
                        JobSource {
                            owner: target,
                            class: learning::reward::CpuClass::Policy,
                            work: None,
                        },
                        w,
                    )
                })
                .transpose()?
        } else {
            None
        };
        preparation_prefix_detail(6);
        preparation_detail(2);
        // An exclusive Canary or restoration reservation suppresses new
        // Active proposals before encoding and inference spend their CPU.
        if s.model_gate.as_ref().is_none_or(|gate| {
            gate.check_active_publication(s.registry.model(), target)
                .is_err()
        }) {
            break 'families;
        }
        let core_preparation = if (f.domain, f.kind) == (1, 2) {
            match crate::domain_services::core_preparation(target) {
                Ok(v) => Some(v),
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound,
                ) => break 'families,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let current = match core_preparation {
            Some((current, _)) => current,
            None => match (f.current)(f.domain, f.kind, target) {
                Ok(v) => v,
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound,
                ) => break 'families,
                Err(e) => return Err(e),
            },
        };
        preparation_current(current);
        preparation_detail(3);
        let observed = match core_preparation {
            Some((_, observed)) => observed,
            None => match (f.observe)(f.domain, target) {
                Ok(v) => v,
                Err(Error::Busy | Error::Again | Error::NotReady) => break 'families,
                Err(e) => return Err(e),
            },
        };
        preparation_detail(4);
        let old = locate(&s.owner, current, target).and_then(|i| s.owner.desired[i].as_ref());
        if old.is_some_and(execution_blocks_replacement) {
            break 'families;
        }
        let stability_slot = ensure_stability(&mut s.owner, current, target, wall_started)?;
        let stability = s.owner.stability[stability_slot]
            .as_ref()
            .ok_or(Error::Stale)?;
        let dependencies = match bind_dependencies(&s.owner, current, target, wall_started) {
            Ok(v) => v,
            Err(Error::Busy | Error::Again | Error::NotReady | Error::Conflict | Error::Stale) => {
                break 'families;
            }
            Err(e) => return Err(e),
        };
        preparation_detail(5);
        let hold = if matches!(current, Action::ControlSet(_) | Action::UnauthRate(_)) {
            1_000_000_000
        } else {
            WINDOW_NS
        };
        let held = wall_started.saturating_sub(stability.last_change_ns()) >= hold;
        let (options, n) = tiers(current);
        let current_only = [Some(current)];
        // An adjacent numerical action cannot enter this candidate set before
        // the hold expires, and no alternate may enter a frozen tier. Do not
        // borrow its owner merely to validate an action that this same turn
        // must discard. The current action is still revalidated normally.
        let eligible = if stability.frozen() || !categorical(current) && !held {
            &current_only[..]
        } else {
            &options[..n]
        };
        let mut legal = [None; 32];
        let legal_count = match (f.legal_options)(eligible, target, wall_started, &mut legal) {
            Ok(count) => count,
            Err(Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound) => {
                break 'families;
            }
            Err(error) => return Err(error),
        };
        legal[..legal_count].sort_unstable_by_key(|a| a.map(Action::order));
        preparation_detail(6);
        if current != Action::OfferCpu(0)
            && !legal[..legal_count].iter().any(|a| *a == Some(current))
        {
            break 'families;
        }
        let queued_wcet_us = match queued_control_wcet_us(s, index, wall_started) {
            Ok(value) => value,
            Err(error @ (Error::Busy | Error::Again | Error::NotReady)) => {
                // Retry this same evaluation. replay::first retains its exact
                // snapshot/deadline; the paid measurement still owns this span.
                s.due[index] = wall_started;
                s.cursor[index] = ordinal;
                s.family_cursor = index;
                if s.preparation.is_none() {
                    preparation::next_sequence(s.sequence, preparation_identity)?;
                    s.sequence = preparation_identity.sequence;
                    s.preparation = Some(preparation::Pending::new(
                        preparation_identity,
                        replay_snapshot,
                        index,
                        ordinal,
                    ));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        preparation_detail(7);
        // A family usually emits one candidate. Do not initialize 32 complete
        // feature records merely to obtain bounded scratch; only the prefix
        // written below is ever exposed to CandidateSet::new.
        let mut choices = [const { core::mem::MaybeUninit::<Candidate>::uninit() }; 32];
        let mut count = 0;
        for action in legal[..legal_count].iter().flatten().copied() {
            if !replay::allows_action(action, target) {
                continue;
            }
            if action != current
                && (stability.frozen()
                    || (!categorical(action)
                        && (!held
                            || !cyxia_prototype::domains::stability::adjacent(
                                current,
                                action,
                                &legal[..legal_count],
                            )?)))
            {
                continue;
            }
            let mut target_features = match (f.target_features)(action, target) {
                Ok(v) => v,
                Err(
                    Error::Busy | Error::Again | Error::NotReady | Error::Stale | Error::NotFound,
                ) => break 'families,
                Err(e) => return Err(e),
            };
            if let Action::ControlSet(mask) = action {
                let cores = u64::from(mask.count_ones());
                if cores == 0 {
                    return Err(Error::Range);
                }
                target_features.values[2] = Some(queued_wcet_us.div_ceil(cores));
            }
            let mut common = s.owner.context.common;
            common[2] = queued_wcet_us / 2_500;
            common[6] = 0;
            choices[count].write(Candidate {
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
            });
            count += 1;
        }
        if count == 0 {
            break 'families;
        }
        preparation_detail(8);
        let sequence = match s.preparation {
            Some(pending) => pending.identity.sequence,
            None => s.sequence.checked_add(1).ok_or(Error::Overflow)?,
        };
        let snapshot = replay_snapshot;
        if snapshot.sequence != sequence
            || snapshot.ledger_generation != s.owner.context.ledger_generation
            || snapshot.core_generation != s.owner.context.core_generation
        {
            return Err(Error::Stale);
        }
        // SAFETY: count is incremented only after writing the corresponding
        // slot, never exceeds the 32 legal-action bound, and the slice cannot
        // outlive this scratch array.
        let initialized_choices =
            unsafe { core::slice::from_raw_parts(choices.as_ptr().cast::<Candidate>(), count) };
        let prepared = s.registry.prepare_candidates(
            publisher(controller_epoch),
            snapshot,
            target,
            s.registry.model(),
            initialized_choices,
            Some(current),
        )?;
        preparation_detail(9);
        let work = core_replay::primary(prepared.candidate_set())?;
        preparation_detail(10);
        return encode_prepared_job(
            s,
            controller_epoch,
            wall_started,
            cpu_started,
            snapshot,
            prepared,
            current,
            dependencies,
            work,
            input,
        )
        .map(|()| true);
    }
    if s.preparation.is_some() {
        return Err(Error::NotReady);
    }
    Ok(false)
}
enum JobCandidates<'a> {
    Prepared(PreparedCandidateSet),
    CandidateSet(&'a CandidateSet),
}
impl JobCandidates<'_> {
    fn candidate_set(&self) -> &CandidateSet {
        match self {
            Self::Prepared(prepared) => prepared.candidate_set(),
            Self::CandidateSet(set) => set,
        }
    }
}
#[inline(never)]
fn encode_prepared_job(
    s: &mut State,
    controller_epoch: u64,
    wall_started: u64,
    cpu_started: u64,
    snapshot: Snapshot,
    prepared: PreparedCandidateSet,
    current: Action,
    dependencies: [Option<BoundDependency>; 2],
    work: Option<core_replay::WorkId>,
    input: &mut [u64; 512],
) -> Result<(), Error> {
    encode_job_inner(
        s,
        controller_epoch,
        wall_started,
        cpu_started,
        snapshot,
        JobCandidates::Prepared(prepared),
        current,
        dependencies,
        work,
        false,
        input,
    )
}
#[inline(never)]
fn encode_job(
    s: &mut State,
    controller_epoch: u64,
    wall_started: u64,
    cpu_started: u64,
    snapshot: Snapshot,
    set: &CandidateSet,
    current: Action,
    dependencies: [Option<BoundDependency>; 2],
    work: Option<core_replay::WorkId>,
    read_only: bool,
    input: &mut [u64; 512],
) -> Result<(), Error> {
    encode_job_inner(
        s,
        controller_epoch,
        wall_started,
        cpu_started,
        snapshot,
        JobCandidates::CandidateSet(set),
        current,
        dependencies,
        work,
        read_only,
        input,
    )
}
#[inline(never)]
fn encode_job_inner(
    s: &mut State,
    controller_epoch: u64,
    _wall_started: u64,
    cpu_started: u64,
    snapshot: Snapshot,
    candidates: JobCandidates<'_>,
    current: Action,
    dependencies: [Option<BoundDependency>; 2],
    work: Option<core_replay::WorkId>,
    read_only: bool,
    input: &mut [u64; 512],
) -> Result<(), Error> {
    preparation_phase(1);
    let pending_set = candidates.candidate_set();
    let sequence = snapshot.sequence;
    let target = pending_set.target;
    let preparation_identity = preparation_identity(
        s,
        controller_epoch,
        current.domain(),
        current.kind(),
        target,
        sequence,
        if read_only { work } else { None },
    );
    if let Some(pending) = s.preparation {
        pending.total(
            preparation_identity,
            now(),
            timer::cpu_elapsed_ns(cpu_started),
        )?;
    }
    let evidence = if read_only {
        None
    } else {
        Some(
            crate::domain_evidence::available_slot(
                (sequence as usize - 1) % crate::domain_evidence::SLOTS,
            )
            .ok_or(Error::Busy)?,
        )
    };
    let set = match &candidates {
        JobCandidates::Prepared(prepared) => {
            s.registry
                .commit_candidates(publisher(controller_epoch), prepared)?;
            prepared.candidate_set()
        }
        JobCandidates::CandidateSet(set) => {
            if !read_only {
                s.registry.register(publisher(controller_epoch), set)?;
            }
            *set
        }
    };
    preparation_detail(11);
    preparation_phase(2);
    input.fill(0);
    input[..16].copy_from_slice(&[
        abi::INPUT_MAGIC,
        3,
        sequence,
        controller_epoch,
        snapshot.taken_ns,
        cyxia_arch_aarch64::timer::frequency(),
        snapshot.core_generation,
        snapshot.ledger_generation,
        u64::from(current.domain()),
        u64::from(current.kind()),
        target.id,
        target.generation,
        s.registry.version(),
        set.model.generation,
        s.boot,
        set.len() as u64,
    ]);
    for (at, hash) in [(16, set.model.model_hash), (20, set.hash())] {
        for i in 0..4 {
            input[at + i] = u64::from_le_bytes(hash[i * 8..i * 8 + 8].try_into().unwrap());
        }
    }
    let raw = set.get(0).ok_or(Error::NotReady)?.features;
    input[24..32].copy_from_slice(&raw.common);
    input[32..36].copy_from_slice(&raw.domain);
    input[40] = u64::from(raw.domain_present);
    input[36..40].copy_from_slice(&[
        sequence,
        sequence,
        sequence,
        if current.one_shot() {
            0
        } else {
            snapshot
                .taken_ns
                .checked_add(POLICY_NS)
                .ok_or(Error::Overflow)?
        },
    ]);
    for (i, c) in set.iter().enumerate() {
        let at = 64 + i * 10;
        let mut p = [0; 16];
        input[at] = policy_wire::encode_payload(c.action, i as u16, &mut p)? as u64;
        input[at + 1] = u64::from_le_bytes(p[..8].try_into().unwrap());
        input[at + 2] = u64::from_le_bytes(p[8..].try_into().unwrap());
        for j in 0..4 {
            if let Some(v) = c.features.target.values[j] {
                input[at + 3 + j] = v;
                input[at + 7] |= 1 << j;
            }
        }
        input[at + 8] = c.features.control_capacity.unwrap_or(0);
    }
    input[400..404].copy_from_slice(&[
        s.owner.context.control_mask,
        s.owner.context.business_mask,
        s.owner.context.healthy_mask,
        s.owner.context.draining_mask,
    ]);
    let mut prior = [0; 16];
    input[404] = cyxia_prototype::learning::baseline::encode(current, &mut prior)
        .map_err(|_| Error::Schema)? as u64;
    input[405] = u64::from_le_bytes(prior[..8].try_into().unwrap());
    input[406] = u64::from_le_bytes(prior[8..].try_into().unwrap());
    for (i, binding) in dependencies.into_iter().enumerate() {
        if let Some(binding) = binding {
            input[408 + i * 4..412 + i * 4].copy_from_slice(&[
                u64::from(binding.prerequisite.domain),
                binding.prerequisite.target.id,
                binding.prerequisite.target.generation,
                binding.version,
            ]);
        }
    }
    const _: () = assert!(cfg!(target_endian = "little"));
    preparation_detail(12);
    preparation_phase(3);
    let input_bytes = unsafe { &*((input as *const [u64; 512]).cast::<[u8; 4096]>()) };
    let input_hash = cyxia_arch_aarch64::sha256::digest_page(input_bytes)
        .unwrap_or_else(|| Sha256::digest(input_bytes).into());
    preparation_detail(13);
    preparation_phase(4);
    if let Some(pending) = s.preparation {
        pending.total(
            preparation_identity,
            now(),
            timer::cpu_elapsed_ns(cpu_started),
        )?;
    }
    if let Some(work) = work {
        core_replay::bind(work, sequence, cyxia_arch_aarch64::cpu::slot(), input_hash)?;
    }
    if let Some(evidence) = evidence {
        crate::domain_evidence::begin(evidence, input, input_hash);
        preparation_detail(14);
        preparation_phase(5);
        let _ = crate::learning_history::record_proposal(sequence, &set, input_bytes, input_hash);
    } else {
        preparation_detail(14);
    }
    preparation_phase(6);
    let elapsed = timer::cpu_elapsed_ns(cpu_started);
    let encode_ns = if let Some(pending) = s.preparation {
        // The admission check above precedes WorkId binding. Any final owner
        // bookkeeping is still included in the eventual accept-time bound.
        pending.carried(preparation_identity, elapsed)?
    } else {
        elapsed
    };
    s.sequence = s.sequence.max(sequence);
    s.job = Some(Job {
        cpu: cyxia_arch_aarch64::cpu::slot(),
        set: *set,
        sequence,
        controller: controller_epoch,
        base_version: s.registry.version(),
        started: snapshot.taken_ns,
        encode_ns,
        evidence,
        dependencies,
        work,
        read_only,
        completion: None,
    });
    s.preparation = None;
    preparation_detail(15);
    preparation_phase(7);
    Ok(())
}

struct NativeClock;
impl policy::Clock for NativeClock {
    fn now_ns(&mut self) -> u64 {
        now()
    }
}
trait PublicationScope {
    fn authorize_executor(&self, owner: &Owner) -> Result<(), Error> {
        require_control(owner)
    }
    fn authorize_recovery(&mut self, _: ModelBinding, _: &Plan, _: u64) -> Result<(), Error> {
        Err(Error::Budget)
    }
    fn legal(&self, f: Family, action: Action, target: ObjectKey, at: u64) -> Result<(), Error> {
        (f.legal)(action, target, at)
    }
    fn dependencies(
        &self,
        owner: &Owner,
        action: Action,
        target: ObjectKey,
        at: u64,
    ) -> Result<[Option<BoundDependency>; 2], Error> {
        bind_dependencies(owner, action, target, at)
    }
    fn authorize_baseline(
        &mut self,
        _: ModelBinding,
        _: &policy::RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        Err(Error::Auth)
    }
    fn authorize(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), Error>;
    fn selection(
        &self,
        owner: &Owner,
        f: Family,
        action: Action,
        target: ObjectKey,
        at: u64,
    ) -> Result<(), Error> {
        validate_selection(owner, f, action, target, at)
    }
    /// All fallible scope checks precede the common infallible desired-root
    /// writes. A Canary consumes its exact score receipt and quota here.
    fn commit(
        &mut self,
        owner: &Owner,
        model: ModelBinding,
        plan: &Plan,
        stamps: &[PolicyStamp],
        boot: u64,
        at: u64,
    ) -> Result<(), Error>;
}
struct ActiveScope<'a>(&'a CommitGate);
impl PublicationScope for ActiveScope<'_> {
    fn authorize(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), Error> {
        if set.canary_permit().is_some() || set.baseline_action().is_some() {
            return Err(Error::Auth);
        }
        set.authorize_with_gate(active, self.0, at)
    }
    fn commit(
        &mut self,
        _: &Owner,
        model: ModelBinding,
        plan: &Plan,
        _: &[PolicyStamp],
        _: u64,
        _: u64,
    ) -> Result<(), Error> {
        for d in plan.iter() {
            if d.action.domain() == 15 && crate::learning_canary::blocks_active() {
                return Err(Error::Busy);
            }
            if !replay::allows_action(d.action, d.envelope.target) {
                return Err(Error::Busy);
            }
            self.0
                .check_active_publication(model, d.envelope.target)
                .map_err(|_| Error::Busy)?;
        }
        Ok(())
    }
}
struct Executor<'a, S: PublicationScope> {
    owner: &'a mut Owner,
    scope: S,
    model: ModelBinding,
    evidence: Option<usize>,
    job: u64,
    boot: u64,
    publication_started: u64,
    wall_deadline: u64,
    dependencies: [Option<BoundDependency>; 2],
    scores: [i16; 32],
    score_count: usize,
}
impl<S: PublicationScope> policy::Executor for Executor<'_, S> {
    fn authorize_baseline(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), Error> {
        if set.model != self.model {
            return Err(Error::Stale);
        }
        self.scope.authorize_baseline(active, set, at)
    }
    fn authorize_recovery(
        &mut self,
        active: ModelBinding,
        plan: &Plan,
        at: u64,
    ) -> Result<(), Error> {
        self.scope.authorize_recovery(active, plan, at)
    }
    fn authorize_model(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        at: u64,
    ) -> Result<(), Error> {
        if set.model != self.model {
            return Err(Error::Stale);
        }
        self.scope.authorize(active, set, at)
    }
    fn check(&mut self, d: Decision, _: &policy::RegisteredSet, now: u64) -> Result<(), Error> {
        let c = self.owner.context;
        if d.envelope.core_generation != c.core_generation
            || d.envelope.ledger_generation != c.ledger_generation
        {
            return Err(Error::Stale);
        }
        let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
            .ok_or(Error::Unsupported)?;
        self.scope.legal(f, d.action, d.envelope.target, now)?;
        if self
            .scope
            .dependencies(self.owner, d.action, d.envelope.target, now)?
            != self.dependencies
        {
            return Err(Error::Stale);
        }
        if let Some(i) = locate(self.owner, d.action, d.envelope.target) {
            if self.owner.desired[i]
                .as_ref()
                .is_some_and(execution_blocks_replacement)
            {
                return Err(Error::Busy);
            }
        }
        self.scope
            .selection(self.owner, f, d.action, d.envelope.target, now)?;
        Ok(())
    }
    fn prepare(&mut self, plan: &Plan, _: u64) -> Result<(), Error> {
        self.owner.prepared_count = 0;
        for d in plan.iter() {
            let i = locate(self.owner, d.action, d.envelope.target).ok_or(Error::Stale)?;
            if self.owner.prepared[..self.owner.prepared_count].contains(&i) {
                return Err(Error::Conflict);
            }
            self.owner.prepared[self.owner.prepared_count] = i;
            self.owner.prepared_count += 1;
        }
        Ok(())
    }
    fn revalidate(&mut self, plan: &Plan, now: u64) -> Result<(), Error> {
        for d in plan.iter() {
            let c = self.owner.context;
            if d.envelope.core_generation != c.core_generation
                || d.envelope.ledger_generation != c.ledger_generation
            {
                return Err(Error::Stale);
            }
            let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
                .ok_or(Error::Unsupported)?;
            self.scope.legal(f, d.action, d.envelope.target, now)?;
            self.scope
                .selection(self.owner, f, d.action, d.envelope.target, now)?;
            if self
                .scope
                .dependencies(self.owner, d.action, d.envelope.target, now)?
                != self.dependencies
            {
                return Err(Error::Stale);
            }
        }
        Ok(())
    }
    fn publish(&mut self, plan: &Plan, version: u64, at: u64) -> Result<(), Error> {
        self.scope.authorize_executor(self.owner)?;
        if self.owner.prepared_count != plan.len() {
            return Err(Error::Conflict);
        }
        let mut stamps = [PolicyStamp::default(); 16];
        for (index, d) in plan.iter().enumerate() {
            stamps[index] = PolicyStamp::for_action(
                d.action,
                version,
                if d.action.one_shot() {
                    d.envelope
                        .expires_local_ns
                        .checked_sub(WINDOW_NS)
                        .ok_or(Error::Format)?
                } else {
                    plan.header
                        .active_until_local_ns
                        .checked_sub(POLICY_NS)
                        .ok_or(Error::Format)?
                },
                at,
            )?;
            let f = self.owner.families[family_index(d.action.domain(), d.action.kind())?]
                .ok_or(Error::Unsupported)?;
            self.scope
                .selection(self.owner, f, d.action, d.envelope.target, at)?;
        }
        let commit_ns = now();
        if commit_ns < at {
            return Err(Error::Range);
        }
        if commit_ns > self.wall_deadline
            || plan.iter().any(|d| commit_ns > d.envelope.expires_local_ns)
        {
            return Err(Error::Expired);
        }
        if commit_ns.saturating_sub(self.publication_started) > policy::PUBLICATION_BUDGET_NS {
            return Err(Error::Budget);
        }
        for d in plan.iter() {
            if d.envelope.model_hash != self.model.model_hash
                || plan.header.active_model_generation != self.model.generation
            {
                return Err(Error::Stale);
            }
        }
        self.scope.commit(
            self.owner,
            self.model,
            plan,
            &stamps[..plan.len()],
            self.boot,
            commit_ns,
        )?;
        replay::published(plan, self.boot)?;
        for (index, d) in plan.iter().enumerate() {
            let slot = self.owner.prepared[index];
            let stamp = stamps[index];
            self.owner.desired[slot] = Some(Desired {
                action: d.action,
                apply: ApplyId {
                    boot_epoch: self.boot,
                    controller_epoch: plan.header.controller_epoch,
                    plan_seq: plan.header.plan_seq,
                    action_index: index as u16,
                    target: d.envelope.target,
                },
                stamp,
                state: ExecutionState::Pending,
                execution_observed: false,
                started: false,
                first_entry_ns: None,
                observed_ns: commit_ns,
                published: commit_ns,
                evidence: self.evidence,
                job: self.job,
                model: self.model,
                dependencies: self.dependencies,
                core_generation: d.envelope.core_generation,
                ledger_generation: d.envelope.ledger_generation,
            });
            ADMISSION.publish(
                slot,
                Prerequisite {
                    domain: d.action.domain(),
                    target: d.envelope.target,
                },
                version,
                stamp.installed_until_ns,
                ExecutionState::Pending,
            );
        }
        let mut concurrent = [ApplyId::default(); 16];
        for (index, d) in plan.iter().enumerate() {
            concurrent[index] = ApplyId {
                boot_epoch: self.boot,
                controller_epoch: plan.header.controller_epoch,
                plan_seq: plan.header.plan_seq,
                action_index: index as u16,
                target: d.envelope.target,
            };
        }
        for (index, d) in plan.iter().enumerate() {
            let _ = crate::learning_history::record_publish(crate::learning_history::Publish {
                decision_seq: d.envelope.decision_seq,
                apply: concurrent[index],
                plan_version: version,
                stamp: stamps[index],
                model: self.model,
                selected: d.candidate_index,
                scores: &self.scores[..self.score_count],
                received_ns: self.publication_started,
                published_ns: commit_ns,
                expires_local_ns: d.envelope.expires_local_ns,
                active_until_local_ns: plan.header.active_until_local_ns,
                approved_deadline_ns: commit_ns.saturating_add(execution_limit(d.action)),
                concurrent: &concurrent[..plan.len()],
            });
        }
        self.owner.prepared_count = 0;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.owner.prepared_count = 0;
    }
}
pub fn accept(output: &[u64; 512], cpu_ns: u64) -> Result<u64, Error> {
    with(|s| {
        if s.job.as_ref().ok_or(Error::Stale)?.cpu != cyxia_arch_aarch64::cpu::slot() {
            return Err(Error::Auth);
        }
        if s.job.as_ref().is_some_and(|job| job.completion.is_some()) {
            let job = s.job.take().ok_or(Error::Stale)?;
            return finish_job(s, job, Some(output));
        }
        require_control(&s.owner)?;
        let mut job = s.job.take().ok_or(Error::Stale)?;
        let wall_begin = now();
        let decode_cpu_started = timer::cpu_ticks();
        const _: () = assert!(cfg!(target_endian = "little"));
        let bytes = unsafe { &*((output as *const [u64; 512]).cast::<[u8; 4096]>()) };
        let output_hash = cyxia_arch_aarch64::sha256::digest_page(bytes)
            .unwrap_or_else(|| Sha256::digest(bytes).into());
        let mut selected = u64::MAX;
        let mut decoded_ns = None;
        let mut publication_cpu_started = None;
        let result = (|| {
            if wall_begin < job.started
                || wall_begin - job.started > 50_000_000
                || cpu_ns.checked_add(job.encode_ns).ok_or(Error::Overflow)? > 2_000_000
            {
                return Err(Error::Expired);
            }
            if job.set.snapshot.core_generation != s.owner.context.core_generation
                || job.set.snapshot.ledger_generation != s.owner.context.ledger_generation
            {
                return Err(Error::Stale);
            }
            let reply = reply::verify(
                reply::Expected {
                    set: &job.set,
                    sequence: job.sequence,
                    controller: job.controller,
                    base_version: job.base_version,
                    started_ns: job.started,
                    boot_epoch: s.boot,
                    output_magic: abi::OUTPUT_MAGIC,
                },
                output,
            )?;
            selected = reply.selected as u64;
            let decoding = timer::cpu_elapsed_ns(decode_cpu_started);
            decoded_ns = Some(decoding);
            if cpu_ns
                .checked_add(job.encode_ns)
                .and_then(|v| v.checked_add(decoding))
                .ok_or(Error::Overflow)?
                > 2_000_000
            {
                return Err(Error::Budget);
            }
            publication_cpu_started = Some(timer::cpu_ticks());
            if job.read_only {
                // A read-only work ticket is root-owned. Even a byte-perfect
                // Plan is only checked here; it never reaches publication.
                if job.work.is_none() || s.registry.model() != job.set.model {
                    return Err(Error::Stale);
                }
                s.model_gate
                    .as_ref()
                    .ok_or(Error::NotReady)?
                    .check_active_publication(job.set.model, job.set.target)
                    .map_err(|_| Error::Stale)?;
                let f = s.owner.families[family_index(reply.action.domain(), reply.action.kind())?]
                    .ok_or(Error::NotReady)?;
                (f.legal)(reply.action, job.set.target, now())?;
                return Ok(0);
            }
            let mut executor = Executor {
                owner: &mut s.owner,
                scope: ActiveScope(s.model_gate.as_ref().ok_or(Error::NotReady)?),
                model: job.set.model,
                evidence: job.evidence,
                job: job.sequence,
                boot: s.boot,
                publication_started: wall_begin,
                wall_deadline: job.started.checked_add(50_000_000).ok_or(Error::Overflow)?,
                dependencies: job.dependencies,
                scores: reply.scores,
                score_count: job.set.len(),
            };
            let receipt = s.registry.submit_job(
                publisher(job.controller),
                &reply.bytes[..reply.len],
                wall_begin,
                job.started.checked_add(50_000_000).ok_or(Error::Overflow)?,
                &mut NativeClock,
                &mut executor,
            )?;
            if receipt.version == 0 {
                return Err(match receipt.state() {
                    ExecutionState::Failed(e) => e,
                    _ => Error::Conflict,
                });
            }
            Ok(receipt.version)
        })();
        let publication_ns = publication_cpu_started
            .map(timer::cpu_elapsed_ns)
            .unwrap_or(0);
        if !job.read_only && publication_ns > policy::PUBLICATION_BUDGET_NS {
            s.registry.stop_optimization();
        }
        let decoding = decoded_ns.unwrap_or_else(|| timer::cpu_elapsed_ns(decode_cpu_started));
        job.completion = Some(JobCompletion {
            result,
            selected,
            decoded_ns: decoding,
            elapsed_ns: publication_ns,
            cpu_ns,
            output_hash,
            aborted: false,
        });
        finish_job(s, job, Some(output))
    })
}
/// The real verified result survives owner-gate contention. A retry can finish
/// its exact queue receipt, but cannot resubmit a policy or replace its result.
fn finish_job(s: &mut State, job: Job, output: Option<&[u64; 512]>) -> Result<u64, Error> {
    let completion = job.completion.ok_or(Error::Stale)?;
    if let Some(work) = job.work {
        if let Err(error) = core_replay::evaluated(
            work,
            job.sequence,
            completion.result,
            completion.output_hash,
        ) {
            s.job = Some(job);
            return Err(error);
        }
    }
    if let Some(evidence) = job.evidence {
        let (version, state) = match completion.result {
            Ok(version) => (version, ExecutionState::Pending),
            Err(error) => (0, ExecutionState::Failed(error)),
        };
        crate::domain_evidence::finish(
            evidence,
            job.sequence,
            completion.cpu_ns,
            job.encode_ns,
            completion.decoded_ns,
            completion.elapsed_ns,
            version,
            state,
            completion.selected,
            if completion.aborted { None } else { output },
        );
        if completion.aborted {
            crate::domain_evidence::aborted();
        }
    }
    completion.result
}
pub fn pending_job() -> Result<bool, Error> {
    with(|s| Ok(s.job.is_some()))
}
pub fn abort(cpu_ns: u64) -> Result<(), Error> {
    with(|s| {
        if s.job
            .as_ref()
            .is_some_and(|job| job.cpu != cyxia_arch_aarch64::cpu::slot())
        {
            return Err(Error::Auth);
        }
        if let Some(mut job) = s.job.take() {
            if job.completion.is_none() {
                job.completion = Some(JobCompletion {
                    result: Err(Error::Expired),
                    selected: u64::MAX,
                    decoded_ns: 0,
                    elapsed_ns: 0,
                    cpu_ns,
                    output_hash: [0; 32],
                    aborted: true,
                });
            }
            let result = finish_job(s, job, None);
            // A failed actual evaluation is still a known retired root job.
            // Gate contention keeps the exact owned job for another paid turn.
            if s.job.is_some() {
                return result.map(|_| ());
            }
        }
        Ok(())
    })
}
fn execution_limit(action: Action) -> u64 {
    match action {
        Action::ControlSet(_) => 200_000_000,
        Action::RecoveryRecipe(_) => 1_000_000_000,
        Action::Placement(_) => 4_000_000_000,
        _ => 50_000_000,
    }
}
pub fn poll(_at: u64) -> Result<(), Error> {
    with(|s| {
        // A control CPU may have completed publication since CPU0 captured
        // its outer-loop timestamp. APPLY and stability use a fresh clock.
        let at = now();
        for scanned in 0..s.owner.stability_high {
            let i = (s.owner.poll_cursor + scanned) % s.owner.stability_high;
            let Some(mut d) = s.owner.desired[i] else {
                continue;
            };
            if d.state.terminal() && !execution_blocks_replacement(&d) {
                continue;
            }
            s.owner.poll_cursor = (i + 1) % s.owner.stability_high;
            if d.state == ExecutionState::Applied {
                observe_execution(s, &mut d);
                s.owner.desired[i] = Some(d);
                break;
            }
            let family_slot = family_index(d.action.domain(), d.action.kind())?;
            let f = s.owner.families[family_slot].ok_or(Error::Unsupported)?;
            let was_started = d.started;
            let dependency_status = if d.started {
                Ok(())
            } else if d.core_generation != s.owner.context.core_generation
                || d.ledger_generation != s.owner.context.ledger_generation
            {
                Err(Error::Stale)
            } else {
                bind_dependencies(&s.owner, d.action, d.apply.target, at).and_then(|actual| {
                    if actual == d.dependencies {
                        Ok(())
                    } else {
                        Err(Error::Stale)
                    }
                })
            };
            let mut actual_entry = None;
            let result = if let Err(error) = dependency_status {
                Err(error)
            } else {
                let cpu_started = timer::cpu_ticks();
                let mut cost = crate::learning_evidence::attempt(
                    d.apply.target,
                    learning::reward::CpuClass::ExecutorAction,
                )
                .ok()
                .flatten();
                let entered = now();
                let result = if d.started {
                    (f.reconcile)(d.action, d.apply, d.stamp, entered)
                } else {
                    actual_entry = Some(entered);
                    d.first_entry_ns.get_or_insert(entered);
                    d.started = true;
                    (f.apply)(d.action, d.apply, d.stamp, entered)
                };
                if let Some(cost) = cost.as_mut() {
                    let (first, last, _) = crate::domain_tasks::finish_cpu_interval(cpu_started);
                    let _ = crate::learning_evidence::finish_attempt(cost, first, last);
                }
                result
            };
            d.state = match result {
                Ok(state) => state,
                Err(Error::Busy | Error::Again) => {
                    d.started = was_started;
                    ExecutionState::Pending
                }
                Err(Error::Io | Error::NotReady) => ExecutionState::Unknown,
                Err(error) => ExecutionState::Failed(error),
            };
            let observed = now();
            d.observed_ns = observed;
            if !d.state.terminal()
                && observed.saturating_sub(d.published) >= execution_limit(d.action)
            {
                if d.started {
                    d.state = ExecutionState::Unknown;
                } else {
                    // Busy/Again before admission is an authoritative no-effect
                    // refusal. Do not invent an in-flight operation to reconcile.
                    d.state = ExecutionState::Failed(Error::Again);
                }
            }
            let _ = crate::learning_history::record_execution(crate::learning_history::Execution {
                apply: d.apply,
                stamp: d.stamp,
                state: d.state,
                observed_ns: observed,
                started_ns: actual_entry,
                executor_generation: actual_entry.map(|_| s.owner.family_epochs[family_slot]),
            });
            s.owner.desired[i] = Some(d);
            ADMISSION.publish(
                i,
                Prerequisite {
                    domain: d.action.domain(),
                    target: d.apply.target,
                },
                d.stamp.version,
                d.stamp.installed_until_ns,
                d.state,
            );
            s.registry.reconcile(d.apply, d.stamp.version, d.state)?;
            if let Some(evidence) = d.evidence {
                crate::domain_evidence::progress(
                    evidence,
                    d.job,
                    d.stamp.version,
                    d.state,
                    observed,
                );
            }
            let stability_result =
                s.owner.stability[i]
                    .as_mut()
                    .ok_or(Error::Stale)
                    .and_then(|guard| {
                        guard.observe_execution(d.stamp.version, d.action, d.state, observed)
                    });
            if let Err(error) = stability_result {
                s.registry.stop_optimization();
                crate::domain_evidence::stability_failed(d.action.domain(), d.stamp.version, error);
            }
            observe_execution(s, &mut d);
            s.owner.desired[i] = Some(d);
            break;
        }
        // Reclaim only an owner-proven dead, terminal object; unknown work is pinned.
        for i in 0..s.owner.stability_high {
            if let Some(guard) = s.owner.stability[i].as_ref()
                && s.owner.desired[i]
                    .as_ref()
                    .is_none_or(|d| d.state.terminal())
            {
                let (domain, kind) = guard.family();
                let f = s.owner.families[family_index(domain, kind)?].ok_or(Error::Unsupported)?;
                if matches!(
                    (f.current)(domain, kind, guard.target()),
                    Err(Error::Stale | Error::NotFound)
                ) {
                    s.owner.desired[i] = None;
                    s.owner.stability[i] = None;
                    ADMISSION.retire(i);
                    break;
                }
            }
        }
        Ok(())
    })
}
