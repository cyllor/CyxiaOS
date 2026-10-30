//! Protected local P/E/O and request-event ingress. The actual control-pool
//! owner must loan the storage and validate its allocation before installation.
//! A local trace seal is not a label, a partner attestation or a model verdict.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use cyxia_arch_aarch64::cpu;
#[cfg(not(test))]
use cyxia_arch_aarch64::timer;
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        self, Family,
        capture::{
            Capture, Config, FrozenRequest, RunKey, Seal, Source, SourceToken, SpanToken, Status,
        },
        reward::{CpuClass, CpuCoverage, CpuInterval, RequestResult, WorkRequest},
    },
};

pub type Storage = Capture<8192, 4096>;
pub const STORAGE_BYTES: usize = core::mem::size_of::<Storage>();
pub const EXPORT_CHUNK: usize = 16;
// Larger replay tables need a separately budgeted, incremental preparer. This
// synchronous native entry accepts enough real requests for one training trial.
pub const START_REQUESTS: usize = 128;
#[path = "learning_evidence/execution_trace.rs"]
#[cfg_attr(test, allow(dead_code))]
pub(crate) mod execution_trace;
#[path = "learning_evidence/handoff.rs"]
mod handoff;
#[path = "learning_evidence/provenance.rs"]
mod provenance;
pub use provenance::TaskIdentity;
/// Exact fixed storage for completed exits and first-loss diagnostics.
pub const HANDOFF_BYTES: usize = handoff::OWNED_BYTES
    + 2 * core::mem::size_of::<AtomicU64>()
    + execution_trace::OWNED_BYTES
    + provenance::OWNED_BYTES;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotReady,
    Busy,
    Owner,
    Stale,
    Capacity,
    Capture(learning::Error),
}
impl From<learning::Error> for Error {
    fn from(error: learning::Error) -> Self {
        Self::Capture(error)
    }
}

/// The callback verifies this exact live allocation in the real pool ledger.
/// The module supplies no permissive default or synthetic allocation receipt.
pub type PoolCheck = fn(ObjectKey, usize, usize) -> Result<(), Error>;
pub type ScheduleCheck = fn(RunKey, ObjectKey, u64, u64) -> Result<(), learning::Error>;
pub type ScheduleAtCheck = fn(RunKey, ObjectKey, u64, u64) -> Result<u64, learning::Error>;
pub type RecordedCoreCheck =
    fn(RunKey, ObjectKey, u64, u16, u64, u64) -> Result<(), learning::Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecordedCore {
    run: RunKey,
    event: u64,
    class: CpuClass,
    core: u16,
    first: u64,
    last: u64,
}
#[derive(Clone, Copy)]
struct RecordedOwner {
    owner: ObjectKey,
    check: RecordedCoreCheck,
    last: Option<RecordedCore>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceDisposition {
    Measure(ObjectKey),
    Outside,
}
pub type SourceClassifier =
    fn(RunKey, ObjectKey, CpuClass) -> Result<SourceDisposition, learning::Error>;
#[derive(Clone, Copy)]
enum ScheduleProof {
    Current(ScheduleCheck),
    Queued(ScheduleAtCheck),
}
#[derive(Clone, Copy)]
struct ScheduleOwner {
    owner: ObjectKey,
    check: ScheduleProof,
}
/// A CPU0-prepared start authorization for one exact trial/family. Only the
/// trusted root's first-generation callback borrows this capability on C1.
pub struct StartPermit {
    serial: u64,
    owner: ObjectKey,
    trial_id: u64,
    family: Family,
}
#[derive(Clone, Copy)]
struct StartBinding {
    serial: u64,
    owner: ObjectKey,
    trial_id: u64,
    family: Family,
    started: Option<RunKey>,
}
struct Owner {
    storage: *mut Storage,
    node: [u8; 32],
    boot_epoch: u64,
    generation: u64,
    merged_losses: [u64; 4],
    merged_ns: [u64; 4],
    merged_detached_losses: [u64; 4],
    merged_detached_ns: [u64; 4],
    detached_tainted: bool,
    schedules: [Option<ScheduleOwner>; 32],
    start_serial: u64,
    start: Option<StartBinding>,
    recorded: [Option<RecordedOwner>; 32],
    staged_intervals: usize,
}
struct Cell(UnsafeCell<Owner>);
// Every access, including installation, holds GATE; there are no borrowed
// references across the gate and no IRQ/device callback occurs inside it.
unsafe impl Sync for Cell {}
static OWNER: Cell = Cell(UnsafeCell::new(Owner {
    storage: core::ptr::null_mut(),
    node: [0; 32],
    boot_epoch: 0,
    generation: 0,
    merged_losses: [0; 4],
    merged_ns: [0; 4],
    merged_detached_losses: [0; 4],
    merged_detached_ns: [0; 4],
    detached_tainted: false,
    schedules: [None; 32],
    start_serial: 0,
    start: None,
    recorded: [None; 32],
    staged_intervals: 0,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static RUN: AtomicU64 = AtomicU64::new(0);
// Published only at the same count-zero boundary as RUN. An admitted
// producer lease prevents these identities from changing under its exit.
static RUN_BOOT: AtomicU64 = AtomicU64::new(0);
static RUN_TRIAL: AtomicU64 = AtomicU64::new(0);
static SERVICE_CONSUMER: AtomicUsize = AtomicUsize::new(0);
static SOURCE_CLASSIFIER: AtomicUsize = AtomicUsize::new(0);
static FAMILY: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DROPPED_CLASSES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static DROPPED_NS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
// A segment which observed an active run can lose admission to its final
// count-zero freeze. It still needs an exit record. These counters never reset
// with RUN, so its late exit cannot contaminate or disappear into a new replay.
// Without a retained handoff proving which side of that boundary owned it,
// this boot is conservatively ineligible to produce complete reward evidence.
static DETACHED_FAULT: AtomicBool = AtomicBool::new(false);
static DETACHED_PENDING: AtomicU64 = AtomicU64::new(0);
static DETACHED_FIRST: AtomicU64 = AtomicU64::new(0);
static DETACHED_LAST: AtomicU64 = AtomicU64::new(0);
static DETACHED_CLASSES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static DETACHED_NS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
// Admission and the producer count share one atomic word. A successful close
// cannot race a producer increment based on an earlier OPEN observation.
const CLOSING: u64 = 1 << 63;
const FROZEN: u64 = 1 << 62;
const PRODUCERS: u64 = FROZEN - 1;
static INGRESS: AtomicU64 = AtomicU64::new(CLOSING | FROZEN);
struct Producer;
impl Drop for Producer {
    fn drop(&mut self) {
        INGRESS.fetch_sub(1, Ordering::Release);
    }
}
fn enter(generation: u64, completing: bool) -> Result<Producer, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    if generation == 0 || generation != RUN.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    let mut state = INGRESS.load(Ordering::Acquire);
    loop {
        if state & FROZEN != 0 || (!completing && state & CLOSING != 0) {
            return Err(Error::Busy);
        }
        if state & PRODUCERS == PRODUCERS {
            return Err(Error::Capacity);
        }
        match INGRESS.compare_exchange_weak(state, state + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                let guard = Producer;
                if generation != RUN.load(Ordering::Acquire) {
                    drop(guard);
                    return Err(Error::Stale);
                }
                return Ok(guard);
            }
            Err(current) => state = current,
        }
    }
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn lock() -> Result<Guard, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    Ok(Guard)
}
fn cpu0() -> Result<(), Error> {
    if cpu::slot() == 0 {
        Ok(())
    } else {
        Err(Error::Owner)
    }
}
fn now_ns() -> u64 {
    crate::domain_platform::now_ns()
}

// Native builds charge the executing vCPU through PMCCNTR_EL0. Host contract
// tests include this module directly and intentionally provide only a synthetic
// monotonic clock; under cfg(test) that clock is also the explicit CPU fixture.
// This keeps the production accounting boundary free of host-only crate shims.
#[cfg(not(test))]
#[inline]
fn cpu_ticks() -> u64 {
    timer::cpu_ticks()
}
#[cfg(test)]
#[inline]
fn cpu_ticks() -> u64 {
    now_ns()
}
#[cfg(not(test))]
#[inline]
fn cpu_elapsed_ns(started: u64) -> u64 {
    timer::cpu_elapsed_ns(started)
}
#[cfg(test)]
#[inline]
fn cpu_elapsed_ns(started: u64) -> u64 {
    now_ns().saturating_sub(started)
}

#[inline]
fn finish_cpu_interval(started: u64) -> (u64, u64, u64) {
    let finished_ns = now_ns();
    let actual_ns = cpu_elapsed_ns(started);
    (
        finished_ns.saturating_sub(actual_ns),
        finished_ns,
        actual_ns,
    )
}
fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Release, Ordering::Relaxed, |old| {
        Some(old.saturating_add(value))
    });
}
fn lost(class: CpuClass, duration: u64) {
    add(&DROPPED_NS[class as usize], duration);
    add(&DROPPED_CLASSES[class as usize], 1);
    add(&DROPPED, 1);
}
fn detached_begin(generation: u64, class: CpuClass) {
    // Publish exclusion before the caller is allowed to perform real work.
    DETACHED_FAULT.store(true, Ordering::Release);
    add(&DETACHED_PENDING, 1);
    let _ = DETACHED_FIRST.compare_exchange(0, generation, Ordering::AcqRel, Ordering::Acquire);
    DETACHED_LAST.fetch_max(generation, Ordering::AcqRel);
    add(&DETACHED_CLASSES[class as usize], 1);
}
fn detached_end(class: CpuClass, duration: u64) {
    add(&DETACHED_NS[class as usize], duration);
    DETACHED_PENDING.fetch_sub(1, Ordering::Release);
}
/// Raw costs whose entry raced the replay's final freeze are retained for the
/// lifetime of the boot, separately from later runs. This is diagnostic and
/// exclusion evidence, never a complete CPU union or an accepted reward.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnrecordedStatus {
    pub first_generation: u64,
    pub last_generation: u64,
    pub pending: u64,
    pub counts: [u64; 4],
    pub raw_ns: [u64; 4],
}
pub fn unrecorded_status() -> UnrecordedStatus {
    UnrecordedStatus {
        first_generation: DETACHED_FIRST.load(Ordering::Acquire),
        last_generation: DETACHED_LAST.load(Ordering::Acquire),
        pending: DETACHED_PENDING.load(Ordering::Acquire),
        counts: core::array::from_fn(|i| DETACHED_CLASSES[i].load(Ordering::Acquire)),
        raw_ns: core::array::from_fn(|i| DETACHED_NS[i].load(Ordering::Acquire)),
    }
}
fn merge_losses(capture: &mut Storage, owner: &mut Owner) -> Result<(), Error> {
    if capture.config().is_none() {
        return Ok(());
    }
    if DETACHED_FAULT.load(Ordering::Acquire) && !owner.detached_tainted {
        capture.taint(learning::Error::DataIncomplete);
        owner.detached_tainted = true;
    }
    for (index, class) in [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
        CpuClass::Optional,
    ]
    .into_iter()
    .enumerate()
    {
        let count = DROPPED_CLASSES[index].load(Ordering::Acquire);
        let duration = DROPPED_NS[index].load(Ordering::Acquire);
        let new_count = count
            .checked_sub(owner.merged_losses[index])
            .ok_or(Error::Stale)?;
        let new_duration = duration
            .checked_sub(owner.merged_ns[index])
            .ok_or(Error::Stale)?;
        if new_count != 0 || new_duration != 0 {
            capture.missing_events(class, new_count, new_duration)?;
            owner.merged_losses[index] = count;
            owner.merged_ns[index] = duration;
        }
        // Only an unambiguous original generation gets these raw durations
        // in its trace hash. Never charge an old detached exit to a new run.
        if DETACHED_FIRST.load(Ordering::Acquire) == owner.generation
            && DETACHED_LAST.load(Ordering::Acquire) == owner.generation
        {
            let count = DETACHED_CLASSES[index].load(Ordering::Acquire);
            let duration = DETACHED_NS[index].load(Ordering::Acquire);
            let new_count = count
                .checked_sub(owner.merged_detached_losses[index])
                .ok_or(Error::Stale)?;
            let new_duration = duration
                .checked_sub(owner.merged_detached_ns[index])
                .ok_or(Error::Stale)?;
            if new_count != 0 || new_duration != 0 {
                capture.missing_events(class, new_count, new_duration)?;
                owner.merged_detached_losses[index] = count;
                owner.merged_detached_ns[index] = duration;
            }
        }
    }
    Ok(())
}
fn with<T>(f: impl FnOnce(&mut Storage, &mut Owner) -> Result<T, Error>) -> Result<T, Error> {
    if !READY.load(Ordering::Acquire) {
        return Err(Error::NotReady);
    }
    let _guard = lock()?;
    // The unique &'static mut loan is held here until boot ends. `Owner` only
    // retains its pointer; callers cannot obtain a second storage reference.
    let owner = unsafe { &mut *OWNER.0.get() };
    if owner.storage.is_null() {
        return Err(Error::NotReady);
    }
    let capture = unsafe { &mut *owner.storage };
    merge_losses(capture, owner)?;
    f(capture, owner)
}

/// On failure the original unique loan is returned, so startup can retry once
/// the real allocation becomes registered. No part of the pool is fabricated.
pub fn install(
    storage: &'static mut Storage,
    node: [u8; 32],
    boot_epoch: u64,
    allocation: ObjectKey,
    check: PoolCheck,
) -> Result<(), (Error, &'static mut Storage)> {
    if cpu0().is_err() {
        return Err((Error::Owner, storage));
    }
    if node == [0; 32] || boot_epoch == 0 || allocation.id == 0 || allocation.generation == 0 {
        return Err((Error::Owner, storage));
    }
    if READY.load(Ordering::Acquire) {
        return Err((Error::Stale, storage));
    }
    if let Err(error) = check(allocation, storage as *mut Storage as usize, STORAGE_BYTES) {
        return Err((error, storage));
    }
    let _guard = match lock() {
        Ok(guard) => guard,
        Err(error) => return Err((error, storage)),
    };
    if READY.load(Ordering::Relaxed) || storage.status().key.is_some() {
        return Err((Error::Stale, storage));
    }
    let owner = unsafe { &mut *OWNER.0.get() };
    owner.storage = storage as *mut Storage;
    owner.node = node;
    owner.boot_epoch = boot_epoch;
    owner.generation = 0;
    READY.store(true, Ordering::Release);
    Ok(())
}
#[derive(Clone, Copy)]
pub struct RegisteredSource {
    token: SourceToken,
    class: CpuClass,
    generation: u64,
}
/// Frozen logical request identity scoped to one capture generation. An old
/// workload still owns its resources after export, but cannot report into a
/// later replay which happens to reuse its local request number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredRequest {
    generation: u64,
    owner: ObjectKey,
    id: u64,
}
pub struct Span {
    token: Option<SpanToken>,
    generation: u64,
    class: CpuClass,
    core: u16,
    start_ns: u64,
    finished: Option<(u16, u64)>,
    reported_wrong_cpu: bool,
}
impl Span {
    pub fn pending(&self) -> bool {
        self.token.is_some()
    }
}

/// CPU0's protected replay owner supplies the frozen manifest and complete
/// local owner list. Partners have separate local clocks and separate logs.
pub fn start(
    trial_id: u64,
    family: Family,
    first_ns: u64,
    observation_ns: u64,
    scope_hash: [u8; 32],
    sources: &[Source],
    requests: &[FrozenRequest],
) -> Result<RunKey, Error> {
    cpu0()?;
    start_inner(
        trial_id,
        family,
        first_ns,
        observation_ns,
        scope_hash,
        sources,
        requests,
        None,
    )
}
pub fn prepare_start(
    owner: ObjectKey,
    trial_id: u64,
    family: Family,
) -> Result<StartPermit, Error> {
    cpu0()?;
    family.index()?;
    if owner.id == 0 || owner.generation == 0 || trial_id == 0 {
        return Err(Error::Owner);
    }
    with(|capture, state| {
        if capture.config().is_some() || state.start.is_some() {
            return Err(Error::Busy);
        }
        let serial = state.start_serial.checked_add(1).ok_or(Error::Capacity)?;
        state.start_serial = serial;
        state.start = Some(StartBinding {
            serial,
            owner,
            trial_id,
            family,
            started: None,
        });
        Ok(StartPermit {
            serial,
            owner,
            trial_id,
            family,
        })
    })
}
fn start_matches(binding: StartBinding, permit: &StartPermit) -> bool {
    binding.serial == permit.serial
        && binding.owner == permit.owner
        && binding.trial_id == permit.trial_id
        && binding.family == permit.family
}
/// No generic relaxation of CPU0's ingress authority: a control CPU needs the exact
/// pre-registered non-clonable permit and may only start its matching trial.
pub fn start_authorized(
    permit: &StartPermit,
    first_ns: u64,
    observation_ns: u64,
    scope_hash: [u8; 32],
    sources: &[Source],
    requests: &[FrozenRequest],
) -> Result<RunKey, Error> {
    if !matches!(cpu::slot(), 0 | 1 | 2) {
        return Err(Error::Owner);
    }
    start_inner(
        permit.trial_id,
        permit.family,
        first_ns,
        observation_ns,
        scope_hash,
        sources,
        requests,
        Some(permit),
    )
}
pub(crate) fn validate_start_permit(permit: &StartPermit, key: RunKey) -> Result<(), Error> {
    with(|_, state| {
        let binding = state.start.ok_or(Error::Owner)?;
        if start_matches(binding, permit) && binding.started == Some(key) {
            Ok(())
        } else {
            Err(Error::Owner)
        }
    })
}
pub fn release_start(permit: &StartPermit) -> Result<(), Error> {
    cpu0()?;
    with(|capture, state| {
        let binding = state.start.ok_or(Error::Owner)?;
        if !start_matches(binding, permit) {
            return Err(Error::Owner);
        }
        if capture.config().is_some() {
            return Err(Error::Busy);
        }
        state.start = None;
        Ok(())
    })
}
fn start_inner(
    trial_id: u64,
    family: Family,
    first_ns: u64,
    observation_ns: u64,
    scope_hash: [u8; 32],
    sources: &[Source],
    requests: &[FrozenRequest],
    permit: Option<&StartPermit>,
) -> Result<RunKey, Error> {
    if requests.len() > START_REQUESTS {
        return Err(Error::Capacity);
    }
    with(|capture, owner| {
        if let Some(permit) = permit {
            let binding = owner.start.ok_or(Error::Owner)?;
            if !start_matches(binding, permit) {
                return Err(Error::Owner);
            }
            if let Some(key) = binding.started {
                let config = capture.config().ok_or(Error::Stale)?;
                if config.key != key
                    || config.first_ns != first_ns
                    || config.observation_ns != observation_ns
                    || config.frozen_scope_hash != scope_hash
                {
                    return Err(Error::Stale);
                }
                return Ok(key);
            }
        } else if owner.start.is_some() {
            return Err(Error::Owner);
        }
        if INGRESS.load(Ordering::Acquire) != (CLOSING | FROZEN)
            || DETACHED_PENDING.load(Ordering::Acquire) != 0
        {
            return Err(Error::Busy);
        }
        let generation = owner.generation.checked_add(1).ok_or(Error::Capacity)?;
        let key = RunKey {
            boot_epoch: owner.boot_epoch,
            trial_id,
            generation,
        };
        capture.start(
            Config {
                key,
                family,
                node: owner.node,
                first_ns,
                observation_ns,
                frozen_scope_hash: scope_hash,
            },
            sources,
            requests,
        )?;
        owner.generation = generation;
        owner.staged_intervals = 0;
        if let Some(binding) = owner.start.as_mut() {
            binding.started = Some(key);
        }
        owner.merged_losses = [0; 4];
        owner.merged_ns = [0; 4];
        owner.merged_detached_losses = [0; 4];
        owner.merged_detached_ns = [0; 4];
        owner.detached_tainted = false;
        DROPPED.store(0, Ordering::Relaxed);
        for counter in &DROPPED_CLASSES {
            counter.store(0, Ordering::Relaxed);
        }
        for counter in &DROPPED_NS {
            counter.store(0, Ordering::Relaxed);
        }
        FAMILY.store(u64::from(family.domain), Ordering::Release);
        merge_losses(capture, owner)?;
        RUN_BOOT.store(owner.boot_epoch, Ordering::Release);
        RUN_TRIAL.store(trial_id, Ordering::Release);
        RUN.store(generation, Ordering::Release);
        INGRESS.store(0, Ordering::Release);
        ACTIVE.store(true, Ordering::Release);
        Ok(key)
    })
}
pub fn source(owner: ObjectKey, class: CpuClass) -> Result<RegisteredSource, Error> {
    with(|capture, state| {
        Ok(RegisteredSource {
            token: capture.source(owner, class)?,
            class,
            generation: state.generation,
        })
    })
}
/// A segment lease acquired before real owner work starts. Resolving the
/// immutable source table is deferred to its exit. Once an active replay was
/// observed this API always returns a token, including an excluded token if
/// closure won admission; callers must finish or drop that token.
#[derive(Clone, Copy)]
#[repr(u64)]
enum AttemptMode {
    Record,
    Excluded,
    Detached,
    PeerOnly,
}
#[derive(Clone, Copy)]
enum Retry {
    Collector,
    Classifier,
    Peer,
}
pub struct OwnerAttempt {
    lease: Option<Producer>,
    owner: ObjectKey,
    class: CpuClass,
    generation: u64,
    core: u16,
    measured: Option<(u64, u64)>,
    validated: bool,
    invalid: bool,
    retry: Option<Retry>,
    resolved: Option<ObjectKey>,
    outside: bool,
    source_checked: bool,
    mode: AttemptMode,
    pending: bool,
    #[cfg(not(test))]
    peer: Option<crate::peer_replay::Attempt>,
}
impl OwnerAttempt {
    pub fn pending(&self) -> bool {
        self.pending
    }
    fn lose_as(&mut self, reason: handoff::Loss) {
        if !self.pending {
            return;
        }
        handoff::loss(reason, self);
        let duration = self.measured.map_or(0, |(a, b)| b.saturating_sub(a));
        match self.mode {
            AttemptMode::Record => lost(self.class, duration),
            AttemptMode::Excluded => add(&DROPPED_NS[self.class as usize], duration),
            AttemptMode::Detached => detached_end(self.class, duration),
            AttemptMode::PeerOnly => {}
        }
        self.pending = false;
        self.lease.take();
    }
    fn lose(&mut self) {
        let reason = if self.invalid {
            handoff::Loss::InvalidCompletion
        } else {
            match self.mode {
                AttemptMode::Excluded => handoff::Loss::Excluded,
                AttemptMode::Detached => handoff::Loss::Detached,
                _ => match self.retry {
                    Some(Retry::Collector) => handoff::Loss::CollectorBusy,
                    Some(Retry::Classifier) => handoff::Loss::ClassifierUnknown,
                    Some(Retry::Peer) => handoff::Loss::PeerBusy,
                    None if self.measured.is_none() => handoff::Loss::Unfinished,
                    None => handoff::Loss::Other,
                },
            }
        };
        self.lose_as(reason);
    }
    fn blocked(&mut self, reason: Retry) -> Error {
        if matches!(reason, Retry::Peer) {
            // Peer ledger contention happens before the local lookup. Keep
            // the same exit-time identity proof before its task can retire.
            self.preserve_exit_hint();
        }
        self.retry = Some(reason);
        handoff::temporary(reason);
        Error::Busy
    }
    fn preserve_exit_hint(&mut self) {
        if !self.validated
            || self.invalid
            || self.source_checked
            || !matches!(self.mode, AttemptMode::Record)
        {
            return;
        }
        let run = RunKey {
            boot_epoch: RUN_BOOT.load(Ordering::Acquire),
            trial_id: RUN_TRIAL.load(Ordering::Acquire),
            generation: self.generation,
        };
        if run.boot_epoch != 0 && run.trial_id != 0 && RUN.load(Ordering::Acquire) == run.generation
        {
            let _ = self.source_hint(run);
        }
    }
    fn source_hint(&mut self, run: RunKey) -> Result<(), learning::Error> {
        if self.resolved.is_some() || self.outside {
            return Ok(());
        }
        let address = SOURCE_CLASSIFIER.load(Ordering::Acquire);
        if address == 0 {
            self.resolved = Some(self.owner);
            return Ok(());
        }
        let classify: SourceClassifier = unsafe { core::mem::transmute(address) };
        match classify(run, self.owner, self.class)? {
            SourceDisposition::Measure(owner) => self.resolved = Some(owner),
            SourceDisposition::Outside => self.outside = true,
        }
        Ok(())
    }
}
impl Drop for OwnerAttempt {
    fn drop(&mut self) {
        if self.retryable_completion() {
            if handoff::retain(self) {
                return;
            }
            // No allocation or overwrite when all original receipts remain
            // owned. The exact raw cost is excluded once, as before.
            self.lose_as(handoff::Loss::Full);
        } else {
            self.lose();
        }
    }
}
impl OwnerAttempt {
    /// A real validated completion whose exact token and times remain owned.
    /// This predicate supplies custody information, never execution authority.
    pub(crate) fn retryable_completion(&self) -> bool {
        self.pending && self.validated && !self.invalid && self.retry.is_some()
    }
}
pub fn attempt(owner: ObjectKey, class: CpuClass) -> Result<Option<OwnerAttempt>, Error> {
    attempt_class(owner, |_| class)
}
/// One synchronous owner segment, including an error/Busy body return. A
/// completed exit may retain its original token for collector contention;
/// asynchronous waiting never becomes part of this actual CPU interval.
#[inline(never)]
pub fn measure<R>(owner: ObjectKey, class: CpuClass, body: impl FnOnce() -> R) -> R {
    let Some(mut attempt) = attempt(owner, class).ok().flatten() else {
        return body();
    };
    let cpu_started = cpu_ticks();
    let result = body();
    let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);
    let _ = finish_attempt(&mut attempt, first_ns, last_ns);
    result
}
/// Compatibility wrapper. A generic call has no proved enclosing ledger
/// sample and therefore supplies no invocation observation.
#[allow(dead_code)] // Preserve the existing public diagnostic wrapper signature.
#[inline(never)]
pub fn measure_task<R>(
    owner: ObjectKey,
    class: CpuClass,
    _identity: TaskIdentity,
    body: impl FnOnce() -> R,
) -> R {
    measure(owner, class, body)
}
/// Diagnostic context borrowed only during an original measured body. Its
/// caller must prove the enclosing physical ledger sample independently.
pub(crate) struct PaidEntry<'a> {
    attempt: &'a OwnerAttempt,
    started: u64,
}
impl PaidEntry<'_> {
    pub fn observe(self, identity: impl FnOnce() -> TaskIdentity) {
        observe_paid_entry(self.attempt, self.started, || {
            let identity = identity();
            (identity.site, Some(identity))
        });
    }
}
/// Only TaskGuard service_segment bodies use this opt-in. Identity construction
/// occurs lazily inside the original capture sample and its enclosing service
/// ledger sample, never during credit setup or completion.
#[inline(never)]
pub(crate) fn measure_paid_task<R>(
    owner: ObjectKey,
    class: CpuClass,
    body: impl FnOnce(Option<PaidEntry<'_>>) -> R,
) -> R {
    let Some(mut attempt) = attempt(owner, class).ok().flatten() else {
        return body(None);
    };
    let cpu_started = cpu_ticks();
    let entry = if attempt.core == 0
        && matches!(attempt.mode, AttemptMode::Record)
        && attempt.lease.is_some()
    {
        Some(PaidEntry {
            attempt: &attempt,
            started: cpu_started,
        })
    } else {
        None
    };
    let result = body(entry);
    let (first_ns, last_ns, _) = finish_cpu_interval(cpu_started);
    let _ = finish_attempt(&mut attempt, first_ns, last_ns);
    result
}
/// service_io_piece starts its original capture and ledger PMCC timer before
/// acquiring the attempt and calling this probe. No caller identity is inferred.
pub(crate) fn observe_service_io(attempt: &OwnerAttempt, started: u64) {
    observe_paid_entry(attempt, started, || (5, None));
}
fn observe_paid_entry(
    attempt: &OwnerAttempt,
    started: u64,
    identity: impl FnOnce() -> (u64, Option<TaskIdentity>),
) {
    if attempt.core != 0
        || cpu::slot() != 0
        || !matches!(attempt.mode, AttemptMode::Record)
        || attempt.lease.is_none()
        || !attempt.pending
        || attempt.measured.is_some()
    {
        return;
    }
    // One existing nonblocking gate acquisition. Do not use with(): merging
    // losses would mutate capture state merely to collect a diagnostic.
    let Ok(_guard) = lock() else {
        return;
    };
    let owner = unsafe { &*OWNER.0.get() };
    if owner.storage.is_null() {
        return;
    }
    let capture = unsafe { &*owner.storage };
    let Some(config) = capture.config() else {
        return;
    };
    if config.key.generation != attempt.generation {
        return;
    }
    // A direct immutable roster match is known; alias/classifier resolution
    // is deliberately not attempted and can never grant execution authority.
    let direct = capture.source(attempt.owner, attempt.class).is_ok();
    let (site, identity) = identity();
    provenance::observed(provenance::Observation {
        run: config.key,
        offered: attempt.owner,
        direct: direct.then_some(attempt.owner),
        class: attempt.class,
        core: attempt.core,
        started,
        site,
        identity,
    });
}
pub fn attempt_work(owner: ObjectKey, optional: bool) -> Result<Option<OwnerAttempt>, Error> {
    attempt_class(owner, |family| {
        if optional && family == 13 {
            CpuClass::Optional
        } else {
            CpuClass::ExecutorWork
        }
    })
}
fn attempt_class(
    owner: ObjectKey,
    classify: impl FnOnce(u16) -> CpuClass,
) -> Result<Option<OwnerAttempt>, Error> {
    // Existing paid owner entries advance at most one completed receipt.
    handoff::drain(1);
    let local = ACTIVE.load(Ordering::Acquire);
    #[cfg(test)]
    if !local {
        return Ok(None);
    }
    #[cfg(not(test))]
    if !local {
        let Some(family) = crate::peer_replay::family() else {
            return Ok(None);
        };
        let class = classify(family);
        let core = cpu::slot() as u16;
        let peer = crate::peer_replay::attempt(owner, class, core);
        return Ok(peer.map(|peer| OwnerAttempt {
            lease: None,
            owner,
            class,
            generation: 0,
            core,
            measured: None,
            validated: false,
            invalid: false,
            retry: None,
            resolved: None,
            outside: false,
            source_checked: false,
            mode: AttemptMode::PeerOnly,
            pending: true,
            peer: Some(peer),
        }));
    }
    let generation = RUN.load(Ordering::Acquire);
    let first_family = FAMILY.load(Ordering::Acquire) as u16;
    let (lease, mode) = match enter(generation, false) {
        Ok(lease) => (Some(lease), AttemptMode::Record),
        Err(_) => match enter(generation, true) {
            Ok(lease) => (Some(lease), AttemptMode::Excluded),
            Err(_) => (None, AttemptMode::Detached),
        },
    };
    let family = if lease.is_some() {
        FAMILY.load(Ordering::Acquire) as u16
    } else {
        first_family
    };
    let class = classify(family);
    match mode {
        AttemptMode::Record => {}
        AttemptMode::Excluded => lost(class, 0),
        AttemptMode::Detached => detached_begin(generation, class),
        AttemptMode::PeerOnly => {}
    }
    #[cfg(not(test))]
    let peer = crate::peer_replay::attempt(
        owner,
        if class == CpuClass::Optional && crate::peer_replay::family() != Some(13) {
            CpuClass::ExecutorWork
        } else {
            class
        },
        cpu::slot() as u16,
    );
    Ok(Some(OwnerAttempt {
        lease,
        owner,
        class,
        generation,
        core: cpu::slot() as u16,
        measured: None,
        validated: false,
        invalid: false,
        retry: None,
        resolved: None,
        outside: false,
        source_checked: false,
        mode,
        pending: true,
        #[cfg(not(test))]
        peer,
    }))
}
/// Release an untouched producer only with its scheduler cancellation proof.
/// A busy peer ledger keeps both the proof and local producer in the CPU slot.
pub(crate) fn cancel_unstarted(
    attempt: &mut OwnerAttempt,
    proof: &crate::domain_tasks::Cancellation,
) -> Result<(), Error> {
    if !attempt.pending {
        return Err(Error::Stale);
    }
    if !proof.matches(attempt.owner, attempt.core)
        || attempt.measured.is_some()
        || attempt.validated
        || attempt.invalid
        || attempt.retry.is_some()
        || !matches!(attempt.mode, AttemptMode::Record | AttemptMode::PeerOnly)
    {
        return Err(Error::Owner);
    }
    #[cfg(not(test))]
    if let Some(peer) = attempt.peer.as_mut() {
        crate::peer_replay::cancel_unstarted(peer, proof).map_err(|error| {
            if error == learning::Error::Unknown {
                Error::Busy
            } else {
                Error::Capture(error)
            }
        })?;
        attempt.peer = None;
    }
    attempt.pending = false;
    attempt.lease.take();
    Ok(())
}
pub fn finish_attempt(
    attempt: &mut OwnerAttempt,
    first_ns: u64,
    last_ns: u64,
) -> Result<(), Error> {
    if !attempt.pending {
        return Err(Error::Stale);
    }
    if attempt.invalid {
        return Err(Error::Owner);
    }
    if let Some(prior) = attempt.measured {
        if prior != (first_ns, last_ns) {
            return Err(Error::Stale);
        }
    } else {
        attempt.measured = Some((first_ns, last_ns));
    }
    if !attempt.validated
        && (first_ns > last_ns || last_ns > now_ns() || cpu::slot() as u16 != attempt.core)
    {
        // A later clock tick or CPU change cannot turn this failed first
        // validation into a trusted completed interval.
        attempt.invalid = true;
        attempt.retry = None;
        return Err(Error::Owner);
    }
    attempt.validated = true;
    attempt.retry = None;
    // Host contention injection uses the same native temporary-reply branch;
    // it does not provide a peer trace or a completed peer receipt.
    #[cfg(test)]
    if test_support::peer_busy() {
        return Err(attempt.blocked(Retry::Peer));
    }
    #[cfg(not(test))]
    let peer_error = if let Some(peer) = attempt.peer.as_mut() {
        match crate::peer_replay::finish(peer, first_ns, last_ns) {
            Ok(()) => {
                attempt.peer = None;
                None
            }
            Err(learning::Error::Unknown) => return Err(attempt.blocked(Retry::Peer)),
            Err(error) => {
                attempt.peer = None;
                Some(error)
            }
        }
    } else {
        None
    };
    if matches!(attempt.mode, AttemptMode::PeerOnly) {
        attempt.pending = false;
        #[cfg(not(test))]
        if let Some(error) = peer_error {
            return Err(Error::Capture(error));
        }
        return Ok(());
    }
    if !matches!(attempt.mode, AttemptMode::Record) {
        attempt.lose();
        return Err(Error::Capture(learning::Error::DataIncomplete));
    }
    if attempt.generation != RUN.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    // Cache a genuine source hint at the first real exit, before its child
    // identity may retire. A hint never outranks the immutable actual roster.
    if !attempt.source_checked {
        let lookup = with(|capture, _| {
            Ok((
                capture.config().ok_or(Error::NotReady)?,
                capture.source(attempt.owner, attempt.class).is_ok(),
            ))
        });
        let (config, registered) = match lookup {
            Err(Error::Busy) => {
                attempt.preserve_exit_hint();
                return Err(attempt.blocked(Retry::Collector));
            }
            value => value?,
        };
        if config.key.generation != attempt.generation {
            return Err(Error::Stale);
        }
        if registered {
            attempt.resolved = Some(attempt.owner);
            attempt.outside = false;
        } else {
            match attempt.source_hint(config.key) {
                Err(learning::Error::Unknown) => return Err(attempt.blocked(Retry::Classifier)),
                Ok(()) => {}
                Err(_) => {}
            }
        }
        attempt.source_checked = true;
    }
    if attempt.outside {
        attempt.pending = false;
        attempt.lease.take();
        return Ok(());
    }
    let measured_owner = attempt.resolved.unwrap_or(attempt.owner);
    let mut entered = false;
    let result = with(|capture, _| {
        entered = true;
        match capture.source(measured_owner, attempt.class) {
            Ok(token) => capture
                .record(token, attempt.core, first_ns, last_ns)
                .map_err(Error::from),
            Err(error) => {
                capture.missing_events(attempt.class, 1, last_ns - first_ns)?;
                handoff::loss(handoff::Loss::UnknownSource, attempt);
                Err(Error::Capture(error))
            }
        }
    });
    if result == Err(Error::Busy) {
        attempt.blocked(Retry::Collector);
    } else {
        if !entered {
            handoff::loss(handoff::Loss::Other, attempt);
            lost(attempt.class, last_ns - first_ns);
        }
        attempt.pending = false;
        attempt.lease.take();
    }
    #[cfg(not(test))]
    if result.is_ok() {
        if let Some(error) = peer_error {
            return Err(Error::Capture(error));
        }
    }
    result
}
pub fn register_source_classifier(classifier: SourceClassifier) -> Result<(), Error> {
    cpu0()?;
    let address = classifier as usize;
    match SOURCE_CLASSIFIER.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(old) if old == address => Ok(()),
        Err(_) => Err(Error::Capture(learning::Error::Conflict)),
    }
}
pub fn current_config() -> Result<Option<Config>, Error> {
    with(|capture, _| Ok(capture.config()))
}
pub fn request(owner: ObjectKey, id: u64) -> Result<RegisteredRequest, Error> {
    with(|capture, state| {
        if capture.request_owner(id)? != owner {
            return Err(Error::Owner);
        }
        Ok(RegisteredRequest {
            generation: state.generation,
            owner,
            id,
        })
    })
}
pub fn begin(source: RegisteredSource) -> Result<Option<Span>, Error> {
    if !ACTIVE.load(Ordering::Acquire) {
        return Ok(None);
    }
    let _producer = enter(source.generation, false)?;
    let core = cpu::slot() as u16;
    let at = now_ns();
    let result = with(|capture, _| {
        Ok(Span {
            token: Some(capture.begin(source.token, core, at)?),
            generation: source.generation,
            class: source.class,
            core,
            start_ns: at,
            finished: None,
            reported_wrong_cpu: false,
        })
    });
    if result.is_err() {
        lost(source.class, 0);
    }
    result.map(Some)
}
/// At the first real exit, timestamp it before attempting the collector gate.
/// A Busy reply keeps the unique token and that exit time for a later retry.
pub fn end(span: &mut Span) -> Result<(), Error> {
    if span.token.is_none() {
        return Err(Error::Stale);
    }
    if span.generation != RUN.load(Ordering::Acquire) {
        return Err(Error::Stale);
    }
    let (core, at) = *span
        .finished
        .get_or_insert_with(|| (cpu::slot() as u16, now_ns()));
    let _producer = enter(span.generation, true)?;
    if core != span.core {
        if !span.reported_wrong_cpu {
            lost(span.class, at.saturating_sub(span.start_ns));
            span.reported_wrong_cpu = true;
        }
        return Err(Error::Owner);
    }
    with(|capture, _| {
        let token = span.token.take().ok_or(Error::Stale)?;
        let result = capture.end(token, core, at).map_err(Error::from);
        if result.is_err() {
            lost(span.class, 0);
        }
        result
    })
}
/// Used by existing native CPU-credit owners after measuring an actual slice.
/// It records the executing CPU, not the thread's preferred/assigned CPU.
/// Record before publishing the owned job/credit as quiescent. An owner cannot
/// queue unleased telemetry, acknowledge closure, then report it after sealing.
pub fn record(source: RegisteredSource, start_ns: u64, end_ns: u64) -> Result<bool, Error> {
    let _producer = enter(source.generation, true)?;
    if start_ns > end_ns || end_ns > now_ns() {
        lost(source.class, 0);
        return Err(Error::Capture(learning::Error::Evidence));
    }
    let core = cpu::slot() as u16;
    let result = with(|capture, _| {
        capture.record(source.token, core, start_ns, end_ns)?;
        Ok(true)
    });
    if result == Err(Error::Busy) {
        lost(source.class, end_ns - start_ns);
    }
    result
}
/// Only a real retained hardware event owner may import another CPU's measured
/// interval. The event check runs outside the collector gate and must not pop
/// its ring until this API returns success. Exact retries are idempotent.
pub fn register_recorded_core_owner(
    owner: ObjectKey,
    check: RecordedCoreCheck,
) -> Result<(), Error> {
    cpu0()?;
    if owner.id == 0 || owner.generation == 0 {
        return Err(Error::Owner);
    }
    with(|_, state| {
        if let Some(old) = state.recorded.iter().flatten().find(|r| r.owner == owner) {
            return if core::ptr::fn_addr_eq(old.check, check) {
                Ok(())
            } else {
                Err(Error::Capture(learning::Error::Conflict))
            };
        }
        let slot = state
            .recorded
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(RecordedOwner {
            owner,
            check,
            last: None,
        });
        Ok(())
    })
}
pub fn record_on_core(
    run: RunKey,
    owner: ObjectKey,
    class: CpuClass,
    event_id: u64,
    core: u16,
    first_ns: u64,
    last_ns: u64,
) -> Result<bool, Error> {
    cpu0()?;
    let _producer = enter(run.generation, true)?;
    if event_id == 0 || core >= 64 || first_ns > last_ns || last_ns > now_ns() {
        return Err(Error::Owner);
    }
    let event = RecordedCore {
        run,
        event: event_id,
        class,
        core,
        first: first_ns,
        last: last_ns,
    };
    let (check, previous) = with(|capture, state| {
        if capture.config().map(|c| c.key) != Some(run) {
            return Err(Error::Stale);
        }
        let record = state
            .recorded
            .iter()
            .flatten()
            .find(|r| r.owner == owner)
            .ok_or(Error::Owner)?;
        Ok((record.check, record.last))
    })?;
    if let Some(previous) = previous {
        if event == previous {
            return Ok(true);
        }
        if event_id <= previous.event {
            return Err(Error::Stale);
        }
    }
    (check)(run, owner, event_id, core, first_ns, last_ns)?;
    with(|capture, state| {
        let record = state
            .recorded
            .iter_mut()
            .flatten()
            .find(|r| r.owner == owner)
            .ok_or(Error::Owner)?;
        if record.last != previous {
            return Err(Error::Busy);
        }
        let token = capture.source(owner, class)?;
        capture.record(token, core, first_ns, last_ns)?;
        record.last = Some(event);
        Ok(true)
    })
}
pub fn issued(request: RegisteredRequest) -> Result<(), Error> {
    let _producer = enter(request.generation, false)?;
    let at = now_ns();
    let result = with(|capture, _| {
        capture.issued(request.owner, request.id, at)?;
        Ok(())
    });
    if result == Err(Error::Busy) {
        lost(CpuClass::ExecutorWork, 0);
    }
    result
}
/// Register the real protected workload queue. A check must find the exact
/// retained request in that queue; merely knowing the frozen id is insufficient.
pub fn register_schedule_owner(owner: ObjectKey, check: ScheduleCheck) -> Result<(), Error> {
    register_schedule(owner, ScheduleProof::Current(check))
}
/// The returned time must come from the retained real admission receipt. This
/// allows a pre-owned one-shot request to be bound when its first snapshot is
/// generated, without inventing a late request at a past arrival timestamp.
pub fn register_schedule_owner_at(owner: ObjectKey, check: ScheduleAtCheck) -> Result<(), Error> {
    register_schedule(owner, ScheduleProof::Queued(check))
}
fn register_schedule(owner: ObjectKey, check: ScheduleProof) -> Result<(), Error> {
    cpu0()?;
    if owner.id == 0 || owner.generation == 0 {
        return Err(Error::Owner);
    }
    with(|_, state| {
        if let Some(old) = state.schedules.iter().flatten().find(|v| v.owner == owner) {
            let same = match (old.check, check) {
                (ScheduleProof::Current(a), ScheduleProof::Current(b)) => {
                    core::ptr::fn_addr_eq(a, b)
                }
                (ScheduleProof::Queued(a), ScheduleProof::Queued(b)) => core::ptr::fn_addr_eq(a, b),
                _ => false,
            };
            return if same {
                Ok(())
            } else {
                Err(Error::Capture(learning::Error::Conflict))
            };
        }
        let slot = state
            .schedules
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(ScheduleOwner { owner, check });
        Ok(())
    })
}
pub fn arm_scheduled(request: RegisteredRequest) -> Result<(), Error> {
    cpu0()?;
    let _producer = enter(request.generation, false)?;
    let (config, timing, check) = with(|capture, state| {
        let config = capture.config().ok_or(Error::NotReady)?;
        let timing = (0..capture.requests().len())
            .filter_map(|i| capture.request_timing(i))
            .find(|v| v.frozen.owner == request.owner && v.frozen.id == request.id)
            .ok_or(Error::Owner)?;
        let check = state
            .schedules
            .iter()
            .flatten()
            .find(|v| v.owner == request.owner)
            .map(|v| v.check)
            .ok_or(Error::Owner)?;
        Ok((config, timing, check))
    })?;
    if config.key.generation != request.generation {
        return Err(Error::Stale);
    }
    let at = match check {
        ScheduleProof::Current(check) => {
            (check)(
                config.key,
                request.owner,
                request.id,
                timing.frozen.arrived_ns,
            )?;
            timing.issued_observed_ns.unwrap_or_else(now_ns)
        }
        ScheduleProof::Queued(check) => (check)(
            config.key,
            request.owner,
            request.id,
            timing.frozen.arrived_ns,
        )?,
    };
    if at > now_ns() || at > timing.frozen.arrived_ns {
        return Err(Error::Capture(learning::Error::Deadline));
    }
    if timing.issued_observed_ns.is_some() {
        return if timing.scheduled && timing.issued_observed_ns == Some(at) {
            Ok(())
        } else {
            Err(Error::Capture(learning::Error::Conflict))
        };
    }
    with(|capture, _| {
        capture.arm_scheduled(request.owner, request.id, at)?;
        Ok(())
    })
}
pub fn result(request: RegisteredRequest, outcome: RequestResult) -> Result<(), Error> {
    let _producer = enter(request.generation, true)?;
    if matches!(outcome, RequestResult::Completed { finished_ns } if finished_ns > now_ns()) {
        lost(CpuClass::ExecutorWork, 0);
        return Err(Error::Capture(learning::Error::Evidence));
    }
    let result = with(|capture, _| {
        capture.result(request.owner, request.id, outcome)?;
        Ok(())
    });
    if result == Err(Error::Busy) {
        lost(CpuClass::ExecutorWork, 0);
    }
    result
}
pub fn close_source(source: RegisteredSource) -> Result<(), Error> {
    if !handoff::drain(2) {
        return Err(Error::Busy);
    }
    let _producer = enter(source.generation, true)?;
    let at = now_ns();
    with(|capture, _| {
        capture.close_source(source.token, at)?;
        Ok(())
    })
}
pub fn seal(incomplete: bool) -> Result<Seal, Error> {
    cpu0()?;
    if !READY.load(Ordering::Acquire) || RUN.load(Ordering::Acquire) == 0 {
        return Err(Error::NotReady);
    }
    // Stop new span/request admission first. Existing span exits, measured
    // slices, request results and source-close acknowledgements can drain.
    INGRESS.fetch_or(CLOSING, Ordering::AcqRel);
    ACTIVE.store(false, Ordering::Release);
    if !handoff::drain(2) {
        return Err(Error::Busy);
    }
    let at = now_ns();
    with(|capture, owner| {
        let state = INGRESS.load(Ordering::Acquire);
        if state & PRODUCERS != 0 || DETACHED_PENDING.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy);
        }
        let was_frozen = state & FROZEN != 0;
        if !was_frozen {
            INGRESS
                .compare_exchange(
                    CLOSING,
                    CLOSING | FROZEN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| Error::Busy)?;
        }
        // All admitted producers published their loss counters before dropping
        // the lease. Merge again after the count-zero CAS, not just on entry.
        let result = merge_losses(capture, owner).and_then(|()| {
            if incomplete {
                capture.seal_incomplete(at).map_err(Error::from)
            } else {
                capture.seal(at).map_err(Error::from)
            }
        });
        if result.is_err() && !was_frozen {
            // UNKNOWN/open sources remain able to deliver their real exits.
            // This does not re-open admission for new work or new spans.
            INGRESS.store(CLOSING, Ordering::Release);
        };
        if let Ok(seal) = &result {
            execution_trace::close(seal.key, at);
        }
        result
    })
}
pub fn status() -> Result<(Status, u64, [u64; 4]), Error> {
    with(|capture, _| {
        Ok((
            capture.status(),
            DROPPED.load(Ordering::Relaxed),
            core::array::from_fn(|i| DROPPED_NS[i].load(Ordering::Relaxed)),
        ))
    })
}
pub fn coverage(seal: Seal) -> Result<CpuCoverage, Error> {
    with(|capture, _| Ok(capture.coverage(seal)?))
}
/// An immutable view exists only while the sealed capture gate is held. The
/// callback must not reenter this collector. Business admission is already
/// closed; an UNKNOWN/open producer cannot obtain this view in the first place.
pub struct SealedTrace<'a> {
    seal: Seal,
    status: Status,
    coverage: CpuCoverage,
    cpu: &'a [CpuInterval],
    staged: &'a [CpuInterval],
    requests: &'a [WorkRequest],
}
impl SealedTrace<'_> {
    pub fn seal(&self) -> Seal {
        self.seal
    }
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn coverage(&self) -> CpuCoverage {
        self.coverage
    }
    pub fn intervals(&self) -> &[CpuInterval] {
        self.cpu
    }
    pub fn staged_intervals(&self) -> &[CpuInterval] {
        self.staged
    }
    pub fn requests(&self) -> &[WorkRequest] {
        self.requests
    }
}
pub fn with_sealed_trace<T>(
    seal: Seal,
    f: impl FnOnce(SealedTrace<'_>) -> Result<T, learning::Error>,
) -> Result<T, Error> {
    with(|capture, owner| {
        if capture.sealed() != Some(seal) {
            return Err(Error::Stale);
        }
        let status = capture.status();
        if status.issued != status.requests {
            return Err(Error::Capture(learning::Error::DataIncomplete));
        }
        let coverage = capture.coverage(seal)?;
        f(SealedTrace {
            seal,
            status,
            coverage,
            cpu: capture.intervals(),
            staged: capture.staged_intervals(seal, owner.staged_intervals)?,
            requests: capture.requests(),
        })
        .map_err(Error::Capture)
    })
}
/// Bounded staging is deliberately separate from attestation. Arbitrary rows
/// here cannot create a valid partner proof; native history checks the exact
/// protected, signature-verified peer ledger before including this tail.
pub fn stage_intervals(seal: Seal, offset: usize, values: &[CpuInterval]) -> Result<(), Error> {
    if cpu::slot() != 1 || values.is_empty() || values.len() > EXPORT_CHUNK {
        return Err(Error::Owner);
    }
    with(|capture, owner| {
        if offset != owner.staged_intervals {
            return Err(Error::Stale);
        }
        capture.stage_intervals(seal, offset, values)?;
        owner.staged_intervals = offset.checked_add(values.len()).ok_or(Error::Capacity)?;
        Ok(())
    })
}
pub fn copy_intervals(seal: Seal, offset: usize, out: &mut [CpuInterval]) -> Result<usize, Error> {
    if out.len() > EXPORT_CHUNK {
        return Err(Error::Capacity);
    }
    with(|capture, _| {
        if capture.sealed() != Some(seal) {
            return Err(Error::Stale);
        }
        let input = capture.intervals().get(offset..).ok_or(Error::Stale)?;
        let count = input.len().min(out.len());
        out[..count].copy_from_slice(&input[..count]);
        Ok(count)
    })
}
pub fn copy_requests(
    seal: Seal,
    offset: usize,
    out: &mut [(WorkRequest, Option<RequestResult>)],
) -> Result<usize, Error> {
    if out.len() > EXPORT_CHUNK {
        return Err(Error::Capacity);
    }
    with(|capture, _| {
        if capture.sealed() != Some(seal) {
            return Err(Error::Stale);
        }
        let input = capture.requests().get(offset..).ok_or(Error::Stale)?;
        let count = input.len().min(out.len());
        for (index, dst) in out[..count].iter_mut().enumerate() {
            *dst = capture
                .request_evidence(offset + index)
                .ok_or(Error::Stale)?;
        }
        Ok(count)
    })
}
/// Raw admission provenance travels with an exported request table; a consumer
/// can distinguish an already owned future release from a later direct issue.
pub fn copy_request_timing(
    seal: Seal,
    offset: usize,
    out: &mut [learning::capture::RequestTiming],
) -> Result<usize, Error> {
    if out.len() > EXPORT_CHUNK {
        return Err(Error::Capacity);
    }
    with(|capture, _| {
        if capture.sealed() != Some(seal) || offset > capture.requests().len() {
            return Err(Error::Stale);
        }
        let count = (capture.requests().len() - offset).min(out.len());
        for (i, row) in out[..count].iter_mut().enumerate() {
            *row = capture.request_timing(offset + i).ok_or(Error::Stale)?;
        }
        Ok(count)
    })
}
#[derive(Clone, Copy)]
pub struct ServiceSnapshot {
    pub config: Config,
    pub count: usize,
    pub observed_ns: u64,
    pub fault: Option<learning::Error>,
}
/// Protected service-window consumer only: copy the complete frozen request
/// table and actual issue/result state under one capture gate. This grants no
/// replay-label or model-validation capability, and never accepts wire rows.
pub fn service_snapshot(
    out: &mut [(WorkRequest, Option<RequestResult>)],
) -> Result<ServiceSnapshot, Error> {
    cpu0()?;
    if out.len() > START_REQUESTS {
        return Err(Error::Capacity);
    }
    with(|capture, _| {
        let config = capture.config().ok_or(Error::NotReady)?;
        let count = capture.requests().len();
        if count > out.len() {
            return Err(Error::Capacity);
        }
        for (i, row) in out[..count].iter_mut().enumerate() {
            *row = capture.request_evidence(i).ok_or(Error::Stale)?;
        }
        Ok(ServiceSnapshot {
            config,
            count,
            observed_ns: now_ns(),
            fault: capture.status().fault,
        })
    })
}
/// One actual native consumer must finish its registered service windows
/// before this capture's immutable request table can be retired and reused.
pub fn register_service_consumer(check: fn(RunKey) -> Result<(), Error>) -> Result<(), Error> {
    cpu0()?;
    let address = check as usize;
    match SERVICE_CONSUMER.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(()),
        Err(old) if old == address => Ok(()),
        Err(_) => Err(Error::Capture(learning::Error::Conflict)),
    }
}
/// Only the protected trace-export owner calls this after persistent retention
/// or transfer into an immutable validated record. An EL0 acknowledgement alone
/// is not sufficient. Existing workload/contract resources are not released.
pub fn retire_exported(seal: Seal) -> Result<(), Error> {
    cpu0()?;
    let consumer = SERVICE_CONSUMER.load(Ordering::Acquire);
    if consumer != 0 {
        // Registered only from the statically typed protected CPU0 owner.
        let check: fn(RunKey) -> Result<(), Error> = unsafe { core::mem::transmute(consumer) };
        check(seal.key)?;
    }
    with(|capture, _| {
        if INGRESS.load(Ordering::Acquire) != (CLOSING | FROZEN)
            || DETACHED_PENDING.load(Ordering::Acquire) != 0
        {
            return Err(Error::Busy);
        }
        capture.retire_exported(seal)?;
        Ok(())
    })
}

const _: () = assert!(STORAGE_BYTES <= 1024 * 1024);

/// Host contract tests exercise the actual admission and gate code. These
/// hooks are absent from the native image and never manufacture a capture.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub fn source_snapshot() -> [u64; 128] {
        provenance::snapshot()
    }
    static PEER_BUSY: AtomicBool = AtomicBool::new(false);
    pub fn set_peer_busy(value: bool) {
        PEER_BUSY.store(value, Ordering::Release);
    }
    pub(super) fn peer_busy() -> bool {
        PEER_BUSY.load(Ordering::Acquire)
    }
    pub fn handoff_status() -> [u64; 32] {
        handoff::snapshot()
    }
    pub fn handoff_scans() -> usize {
        handoff::scan_count()
    }
    pub fn with_gate(f: impl FnOnce()) {
        let _guard = lock().expect("test owns collector gate");
        f();
    }
    pub fn with_producer(source: RegisteredSource, f: impl FnOnce()) {
        let _guard = enter(source.generation, true).expect("test owns producer lease");
        f();
    }
    // Reproduce the preemption point between seal's CLOSING publication and
    // its ACTIVE=false store; Frozen also exercises a stale ACTIVE reader.
    pub fn admission_closed(frozen: bool) {
        INGRESS.fetch_or(CLOSING | if frozen { FROZEN } else { 0 }, Ordering::AcqRel);
    }
}
