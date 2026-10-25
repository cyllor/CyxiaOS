//! Actual paired labels to immutable worker sources. No wire decoder or
//! engineering seed can insert an AcceptedSample into this owner.
use super::{Error, Split, native_error};
use crate::{control_pool as pool, domain_control::learning_driver as driver,
    smp::prototype_runtime as runtime};
use core::{cell::UnsafeCell, mem::{align_of, size_of, MaybeUninit},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering}};
use cyxia_prototype::{domains::{Error as DomainError, ObjectKey},
    learning::{FAMILIES, SchemaBinding, Schemas, data::FrozenData,
        manifest::ModelManifest, reward::{self, AcceptedSample, VerifiedReplay},
        train::TrainedModel, validate::{integer_reference, ReferenceCase, ReferenceSelection, ReferenceSuite},
        worker_wire::JobBinding}, features, model::MODEL_BYTES, policy::CandidateSet};
use sha2::{Digest, Sha256};

pub const OWNER: ObjectKey = ObjectKey { id: 0x4c45_5250_4c59, generation: 1 };
const TRAIN: usize = FAMILIES * 8;
const VALID: usize = FAMILIES * 4;
const CASES: usize = FAMILIES * 2;
const BANKS: usize = 4;
const PAGES: [usize; BANKS] = [
    ((TRAIN + VALID) * size_of::<AcceptedSample>()).div_ceil(4096),
    (FAMILIES * size_of::<CandidateSet>()).div_ceil(4096),
    size_of::<FrozenData<'static>>().div_ceil(4096),
    size_of::<ValidationBank>().div_ceil(4096),
];
pub const OWNED_BYTES: usize = (PAGES[0] + PAGES[1] + PAGES[2] + PAGES[3] + 1) * 4096;
struct ValidationBank {
    model: MaybeUninit<[u8; MODEL_BYTES]>,
    trained: MaybeUninit<TrainedModel>,
    manifest: MaybeUninit<ModelManifest>,
    suite: MaybeUninit<ReferenceSuite<'static>>,
    cases: [MaybeUninit<ReferenceCase>; CASES],
    selections: [MaybeUninit<ReferenceSelection>; FAMILIES],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase { Collecting, Freeze, SealData, TrainingReady, Training, References, Manifest,
    SealValidation, ValidationReady, Validating, Complete, Rejected }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub training: [u8; FAMILIES],
    pub validation: [u8; FAMILIES],
    pub paired: usize,
    pub pending_baseline: bool,
    pub last_error: Option<Error>,
}
struct State {
    banks: [pool::Allocation; BANKS],
    bases: [usize; BANKS],
    phase: Phase,
    counts: [[u8; FAMILIES]; 2],
    probes_ready: [bool; FAMILIES],
    baseline: Option<(VerifiedReplay, Split)>,
    source_key: ObjectKey,
    in_flight: bool,
    cursor: usize,
    last_error: Option<Error>,
}
struct Setup { state: Option<pool::Allocation>, pin: Option<pool::Lease>,
    banks: [Option<pool::Allocation>; BANKS], bases: [usize; BANKS] }
struct SetupCell(UnsafeCell<Setup>);
unsafe impl Sync for SetupCell {}
static SETUP: SetupCell = SetupCell(UnsafeCell::new(Setup { state: None, pin: None,
    banks: [None; BANKS], bases: [0; BANKS] }));
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static GATE: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard { fn drop(&mut self) { GATE.store(false, Ordering::Release); } }
fn lock() -> Result<Guard, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Unknown)?; Ok(Guard)
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    let _guard = lock()?; let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 { return Err(Error::DataIncomplete); }
    f(unsafe { &mut *(base as *mut State) })
}
#[cfg(test)]
pub mod test_support {
    pub fn with_gate<T>(body: impl FnOnce() -> T) -> T {
        let _guard = super::lock().expect("exclusive test data gate");
        body()
    }
}
fn control() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 1 { return Err(Error::State); }
    runtime::authorize_learning_turn().map_err(native_error)
}
fn schemas() -> Schemas {
    Schemas { feature: SchemaBinding { version: 13,
        hash: Sha256::digest(include_bytes!("../../../crates/prototype/src/features.rs")).into() },
        action: SchemaBinding { version: 13,
            hash: Sha256::digest(include_bytes!("../../../crates/prototype/src/policy_wire.rs")).into() },
        reward: cyxia_prototype::learning::reward_schema(), learning: cyxia_prototype::learning::learning_config() }
}
fn samples(state: &State, split: Split) -> &'static [AcceptedSample] {
    let offset = if split == Split::Training { 0 } else { TRAIN };
    let count = if split == Split::Training { TRAIN } else { VALID };
    // Used only after every counted slot has been initialized; immutable for
    // the lifetime of both worker jobs and the later governance session.
    unsafe { core::slice::from_raw_parts((state.bases[0] as *const AcceptedSample).add(offset), count) }
}
fn dataset(state: &State) -> &'static FrozenData<'static> {
    unsafe { &*(state.bases[2] as *const FrozenData<'static>) }
}
fn probes(state: &State) -> &'static [CandidateSet] {
    unsafe { core::slice::from_raw_parts(state.bases[1] as *const CandidateSet, FAMILIES) }
}
fn package(state: &State) -> *mut ValidationBank { state.bases[3] as *mut ValidationBank }

/// Small persistent bookkeeping and all referenced source bytes are backed by
/// the real control pool. Initialization never builds the arrays on EL1 stack.
pub fn init() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 { return Err(DomainError::Auth); }
    if ADDRESS.load(Ordering::Acquire) == 0 {
        let _guard = lock().map_err(|_| DomainError::Busy)?;
        let setup = unsafe { &mut *SETUP.0.get() };
        if setup.state.is_none() { setup.state = Some(pool::allocate(OWNER, 1)?); }
        for i in 0..BANKS {
            if setup.banks[i].is_none() { setup.banks[i] = Some(pool::allocate(OWNER, PAGES[i])?); }
            setup.bases[i] = pool::span(setup.banks[i].ok_or(DomainError::NotReady)?)?.0;
        }
        let allocation = setup.state.ok_or(DomainError::NotReady)?;
        if setup.pin.is_none() { setup.pin = Some(pool::pin(allocation)?); }
        let base = pool::span(allocation)?.0;
        if !base.is_multiple_of(align_of::<State>()) { return Err(DomainError::Range); }
        let banks = core::array::from_fn(|i| setup.banks[i].expect("allocated replay source"));
        unsafe { core::ptr::write(base as *mut State, State { banks, bases: setup.bases,
            phase: Phase::Collecting, counts: [[0; FAMILIES]; 2], probes_ready: [false; FAMILIES], baseline: None,
            source_key: OWNER, in_flight: false, cursor: 0, last_error: None }); }
        ADDRESS.store(base, Ordering::Release);
    }
    driver::register(driver::Provider { owner: OWNER, next, training,
        validation: crate::learning_session::accept, returned })
}

pub fn status() -> Result<Status, Error> {
    with(|s| Ok(Status { phase: s.phase, training: s.counts[0], validation: s.counts[1],
        paired: s.counts.iter().flatten().map(|n| *n as usize).sum(),
        pending_baseline: s.baseline.is_some(), last_error: s.last_error }))
}
fn collected(s: &State) -> bool {
    s.counts[0].iter().all(|n| *n == 8) && s.counts[1].iter().all(|n| *n == 4)
        && s.probes_ready.iter().all(|v| *v) && probes(s).iter().all(|probe| probe.len() >= 2)
}
pub(super) fn needs_probe(family: cyxia_prototype::learning::Family) -> Result<bool, Error> {
    control()?; let index = family.index()?;
    with(|s| {
        if s.phase != Phase::Collecting { return Ok(false); }
        Ok(!s.probes_ready[index] || unsafe { &*(s.bases[1] as *const CandidateSet).add(index) }.len() < 2)
    })
}
/// Only the root can construct this capability, from actual current state and
/// legal tiers. It authorizes a read-only validation probe, never an action or
/// an AcceptedSample; the paired execution provenance remains unchanged.
pub(super) fn retain_probe(proof: crate::domain_control::replay::ValidationProbe) -> Result<bool, Error> {
    control()?; let family = proof.family().index()?; let set = proof.candidates();
    set.verify_integrity().map_err(native_error)?;
    if set.model.schema_hash != schemas().feature.hash || set.len() < 2 { return Err(Error::DataIncomplete); }
    with(|s| {
        if s.phase != Phase::Collecting || s.in_flight { return Err(Error::State); }
        if s.probes_ready[family] && unsafe { &*(s.bases[1] as *const CandidateSet).add(family) }.len() >= set.len() {
            return Ok(false);
        }
        unsafe { core::ptr::write((s.bases[1] as *mut CandidateSet).add(family), *set); }
        s.probes_ready[family] = true;
        if collected(s) { s.phase = Phase::Freeze; s.cursor = 0; }
        Ok(true)
    })
}
/// Retiring an excluded raw pair does not turn it into a label. Its previous
/// accepted baseline capability may be discarded only before a genuine reset
/// and rerun of that same group; collected labels are untouched.
pub(super) fn retry_pair(family: cyxia_prototype::learning::Family, group: cyxia_prototype::learning::ReplayGroup) -> Result<(), Error> {
    control()?;
    with(|s| {
        if s.phase != Phase::Collecting || s.in_flight { return Err(Error::State); }
        // A failed comparison may be precisely an initial-image mismatch.
        // Authenticate the same workload attempt, then discard its old
        // capability before a real reset. Pairing itself still requires the
        // full image hash and no accepted sample is changed here.
        if s.baseline.as_ref().is_some_and(|(b, _)| b.family() != family
            || b.group().seed != group.seed || b.group().workload != group.workload) { return Err(Error::Conflict); }
        s.baseline = None; Ok(())
    })
}

/// A complete group is assigned before admitting either side. Reusing a seed
/// with a different action does not permit train/validation leakage.
pub(super) fn accept(replay: VerifiedReplay, split: Split, probe: Option<&CandidateSet>)
    -> Result<(), (Error, VerifiedReplay)> {
    if let Err(error) = control() { return Err((error, replay)); }
    let mut retained = Some(replay);
    let result = with(|s| accept_into(s, &mut retained, split, probe));
    match result { Ok(()) => Ok(()), Err(error) => Err((error, retained.expect("unaccepted replay retained"))) }
}

pub(super) enum AcceptFailure {
    Busy(VerifiedReplay),
    Rejected(Error, VerifiedReplay),
}
/// Retain the unique checked capability across a real owner-gate contention.
/// An actual collection-state Unknown is a rejection, never a retry hint.
#[inline(never)]
pub(super) fn accept_bounded(replay: VerifiedReplay, split: Split, probe: Option<&CandidateSet>)
    -> Result<(), AcceptFailure> {
    if cyxia_arch_aarch64::cpu::slot() != 1 {
        return Err(AcceptFailure::Rejected(Error::State, replay));
    }
    match runtime::authorize_learning_turn() {
        Ok(()) => (),
        Err(DomainError::Busy) => return Err(AcceptFailure::Busy(replay)),
        Err(error) => return Err(AcceptFailure::Rejected(native_error(error), replay)),
    }
    let _guard = match lock() {
        Ok(guard) => guard,
        // lock() has exactly this one error: its real compare_exchange failed.
        Err(_) => return Err(AcceptFailure::Busy(replay)),
    };
    let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 { return Err(AcceptFailure::Rejected(Error::DataIncomplete, replay)); }
    let mut retained = Some(replay);
    let result = accept_into(unsafe { &mut *(base as *mut State) }, &mut retained, split, probe);
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(AcceptFailure::Rejected(error, retained.expect("unaccepted replay retained"))),
    }
}
#[inline(never)]
fn accept_into(s: &mut State, retained: &mut Option<VerifiedReplay>, split: Split,
    probe: Option<&CandidateSet>) -> Result<(), Error> {
        if s.phase != Phase::Collecting || s.in_flight { return Err(Error::State); }
        let replay = retained.as_ref().ok_or(Error::State)?;
        let group = replay.group();
        let other = usize::from(split == Split::Training);
        let per_family = if other == 0 { 8 } else { 4 };
        let base = if other == 0 { 0 } else { TRAIN };
        for family in 0..FAMILIES {
            for index in 0..usize::from(s.counts[other][family]) {
                let sample = unsafe { &*(s.bases[0] as *const AcceptedSample).add(base + family * per_family + index) };
                if sample.group() == group { return Err(Error::GroupOverlap); }
            }
        }
        if replay.kind() == reward::ReplayKind::Baseline {
            if s.baseline.is_some() { return Err(Error::Unknown); }
            s.baseline = Some((retained.take().ok_or(Error::State)?, split)); return Ok(());
        }
        let (baseline, old_split) = s.baseline.as_ref().ok_or(Error::DataIncomplete)?;
        if *old_split != split { return Err(Error::GroupOverlap); }
        let family = replay.family().index()?;
        let split_index = usize::from(split == Split::Validation);
        let limit = if split == Split::Training { 8 } else { 4 };
        if usize::from(s.counts[split_index][family]) >= limit { return Err(Error::Capacity); }
        let probe = probe.ok_or(Error::DataIncomplete)?;
        if Some(probe.hash()) != replay.candidate_set_hash() { return Err(Error::Evidence); }
        probe.verify_integrity().map_err(native_error)?;
        let sample = reward::pair_verified(replay, baseline)?;
        // Only actual checked pairs reach this write. The fixed family slots
        // give a stable frozen order independent of completion scheduling.
        let index = if split == Split::Training { family * 8 + usize::from(s.counts[0][family]) }
            else { TRAIN + family * 4 + usize::from(s.counts[1][family]) };
        if !s.probes_ready[family] || unsafe { &*(s.bases[1] as *const CandidateSet).add(family) }.len() < probe.len() {
            unsafe { core::ptr::write((s.bases[1] as *mut CandidateSet).add(family), *probe); }
            s.probes_ready[family] = true;
        }
        unsafe { core::ptr::write((s.bases[0] as *mut AcceptedSample).add(index), sample); }
        s.counts[split_index][family] += 1; s.baseline = None; retained.take();
        if collected(s) {
            s.phase = Phase::Freeze; s.cursor = 0;
        }
        Ok(())
}

pub fn control_step() -> Result<bool, DomainError> {
    control().map_err(|_| DomainError::Auth)?;
    let result = with(|s| {
        if s.in_flight { return Ok(false); }
        match s.phase {
            Phase::Freeze => {
                let data = FrozenData::freeze(samples(s, Split::Training), samples(s, Split::Validation),
                    0x4359_5849_415f_3133, schemas())?;
                unsafe { core::ptr::write(s.bases[2] as *mut FrozenData<'static>, data); }
                s.phase = Phase::SealData; s.cursor = 0;
            }
            Phase::SealData => {
                pool::seal(s.banks[s.cursor]).map_err(native_error)?;
                s.cursor += 1; if s.cursor == 3 { s.phase = Phase::TrainingReady; }
            }
            Phase::References => {
                let i = s.cursor; let probe = &probes(s)[i / 2];
                if probe.len() < 2 { return Err(Error::Untrained); }
                let choice = probe.get(i % 2).ok_or(Error::Evidence)?;
                let input = features::encode(choice.action, choice.features).map_err(native_error)?.values;
                let p = package(s);
                let bytes = unsafe { (&*core::ptr::addr_of!((*p).model)).assume_init_ref() };
                let case = ReferenceCase { input, trace: integer_reference(bytes, &input) };
                unsafe { core::ptr::addr_of_mut!((*p).cases).cast::<MaybeUninit<ReferenceCase>>().add(i).write(MaybeUninit::new(case)); }
                if i % 2 == 1 {
                    let previous = unsafe { (&*core::ptr::addr_of!((*p).cases[i - 1])).assume_init_ref() };
                    let selection = ReferenceSelection { first: (i - 1) as u16, count: 2,
                        selected: u16::from(case.trace.output > previous.trace.output) };
                    unsafe { core::ptr::addr_of_mut!((*p).selections).cast::<MaybeUninit<ReferenceSelection>>().add(i / 2)
                        .write(MaybeUninit::new(selection)); }
                }
                s.cursor += 1; if s.cursor == CASES { s.phase = Phase::Manifest; }
            }
            Phase::Manifest => {
                let p = package(s);
                let model = unsafe { (&*core::ptr::addr_of!((*p).trained)).assume_init_ref() };
                let suite = ReferenceSuite { parameters_hash: Sha256::digest(model.bytes()).into(),
                    cases: unsafe { core::slice::from_raw_parts(core::ptr::addr_of!((*p).cases).cast(), CASES) },
                    selections: unsafe { core::slice::from_raw_parts(core::ptr::addr_of!((*p).selections).cast(), FAMILIES) } };
                let manifest = ModelManifest::learned(model, schemas(), &suite, 1024 * 1024)?;
                unsafe { core::ptr::addr_of_mut!((*p).suite).write(MaybeUninit::new(suite));
                    core::ptr::addr_of_mut!((*p).manifest).write(MaybeUninit::new(manifest)); }
                s.phase = Phase::SealValidation;
            }
            Phase::SealValidation => {
                pool::seal(s.banks[3]).map_err(native_error)?;
                s.source_key.generation = s.source_key.generation.checked_add(1).ok_or(Error::Capacity)?;
                s.phase = Phase::ValidationReady;
            }
            _ => return Ok(false),
        }
        Ok(true)
    });
    result.map_err(|error| { if !matches!(error, Error::Unknown) {
        let _ = with(|s| { s.last_error = Some(error); s.phase = Phase::Rejected; Ok(()) }); }
        super::domain_error(error) })
}
fn next() -> Result<Option<driver::Source>, Error> {
    control()?;
    with(|s| {
        if s.in_flight || !matches!(s.phase, Phase::TrainingReady | Phase::ValidationReady) { return Ok(None); }
        let validation = if s.phase == Phase::ValidationReady {
            let p = package(s);
            Some(driver::ValidationSource { bytes: unsafe { (&*core::ptr::addr_of!((*p).model)).assume_init_ref() },
                manifest: unsafe { (&*core::ptr::addr_of!((*p).manifest)).assume_init_ref() },
                vectors: unsafe { (&*core::ptr::addr_of!((*p).suite)).assume_init_ref() }, probes: probes(s) })
        } else { None };
        let mut backing = [None; 8];
        for i in 0..if validation.is_some() { 4 } else { 3 } { backing[i] = Some(s.banks[i]); }
        let source = driver::Source { key: s.source_key, data: dataset(s), validation, backing };
        s.in_flight = true;
        s.phase = if validation.is_some() { Phase::Validating } else { Phase::Training };
        Ok(Some(source))
    })
}
fn training(job: JobBinding, model: TrainedModel) -> Result<(), (Error, TrainedModel)> {
    if let Err(error) = control() { return Err((error, model)); }
    let mut retained = Some(model);
    let result = with(|s| {
        if s.phase != Phase::Training || !s.in_flight { return Err(Error::State); }
        let model = retained.as_ref().ok_or(Error::State)?;
        if model.record().data != dataset(s).manifest() || job.data_generation == 0 { return Err(Error::Manifest); }
        let p = package(s);
        unsafe { core::ptr::addr_of_mut!((*p).model).write(MaybeUninit::new(*model.bytes()));
            core::ptr::addr_of_mut!((*p).trained).write(MaybeUninit::new(retained.take().ok_or(Error::State)?)); }
        s.phase = Phase::References; s.cursor = 0; Ok(())
    });
    match result { Ok(()) => Ok(()), Err(error) => Err((error, retained.expect("undelivered model retained"))) }
}
fn returned(key: ObjectKey, outcome: driver::Outcome) -> Result<(), Error> {
    control()?;
    with(|s| {
        if key != s.source_key { return Err(Error::Stale); }
        if !s.in_flight { return Err(Error::State); }
        match outcome {
            driver::Outcome::Trained { parameters } => {
                if s.phase != Phase::References { return Err(Error::State); }
                let p = package(s); let model = unsafe { (&*core::ptr::addr_of!((*p).trained)).assume_init_ref() };
                if parameters != model.record().result_hash { return Err(Error::Manifest); }
            }
            driver::Outcome::Validated { .. } => s.phase = Phase::Complete,
            driver::Outcome::Rejected(error) => { s.last_error = Some(error); s.phase = Phase::Rejected; }
            driver::Outcome::Cancelled => { s.last_error = Some(Error::State); s.phase = Phase::Rejected; }
        }
        s.in_flight = false; Ok(())
    })
}
const _: () = assert!(size_of::<State>() <= 4096);
const _: () = assert!(OWNED_BYTES <= driver::MAX_SOURCE_BYTES);
