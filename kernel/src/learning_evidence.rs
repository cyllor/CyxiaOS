//! Protected local P/E/O and request-event ingress. The actual control-pool
//! owner must loan the storage and validate its allocation before installation.
//! A local trace seal is not a label, a partner attestation or a model verdict.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_arch_aarch64::cpu;
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
struct Owner {
    storage: *mut Storage,
    node: [u8; 32],
    boot_epoch: u64,
    generation: u64,
    merged_losses: [u64; 4],
    merged_ns: [u64; 4],
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
}));
static GATE: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static RUN: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DROPPED_CLASSES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static DROPPED_NS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
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
fn merge_losses(capture: &mut Storage, owner: &mut Owner) -> Result<(), Error> {
    if capture.config().is_none() {
        return Ok(());
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
    if requests.len() > START_REQUESTS {
        return Err(Error::Capacity);
    }
    with(|capture, owner| {
        if INGRESS.load(Ordering::Acquire) != (CLOSING | FROZEN) {
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
        owner.merged_losses = [0; 4];
        owner.merged_ns = [0; 4];
        DROPPED.store(0, Ordering::Relaxed);
        for counter in &DROPPED_CLASSES {
            counter.store(0, Ordering::Relaxed);
        }
        for counter in &DROPPED_NS {
            counter.store(0, Ordering::Relaxed);
        }
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
    let at = now_ns();
    with(|capture, owner| {
        let state = INGRESS.load(Ordering::Acquire);
        if state & PRODUCERS != 0 {
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
/// Only the protected trace-export owner calls this after persistent retention
/// or transfer into an immutable validated record. An EL0 acknowledgement alone
/// is not sufficient. Existing workload/contract resources are not released.
pub fn retire_exported(seal: Seal) -> Result<(), Error> {
    cpu0()?;
    with(|capture, _| {
        if INGRESS.load(Ordering::Acquire) != (CLOSING | FROZEN) {
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
    pub fn with_gate(f: impl FnOnce()) {
        let _guard = lock().expect("test owns collector gate");
        f();
    }
    pub fn with_producer(source: RegisteredSource, f: impl FnOnce()) {
        let _guard = enter(source.generation, true).expect("test owns producer lease");
        f();
    }
}
