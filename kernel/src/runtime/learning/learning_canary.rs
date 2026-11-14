//! Protected D15 measurement owner. CPU0 drives a predeclared workload through
//! the actual serial pump; C1 imports its closed windows under extra credit.
//! These observations cannot be supplied by the numerical worker or by EL0.
use crate::{control_pool as pool, smp::prototype_runtime as runtime};
use core::{
    cell::UnsafeCell,
    mem::{align_of, size_of},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey, maintenance::ConsolePump},
    learning::{
        Error,
        governance::CanaryPermit,
        reward::{RequestResult, WorkRequest},
    },
};
#[path = "learning_canary/collector.rs"]
pub mod collector;
use collector::{Collector, Observation, PER_SECOND, Phase, State};

const OWNER: ObjectKey = ObjectKey {
    id: 0x4341_4e41_5259,
    generation: 1,
};
const PAGE: usize = 4096;
const REPORT_OFFSET: usize = size_of::<Collector>().div_ceil(PAGE) * PAGE;
const EMPTY: WorkRequest = WorkRequest {
    id: 0,
    arrived_ns: 0,
    result: RequestResult::Pending,
};
struct Report {
    baseline: [WorkRequest; PER_SECOND],
    candidate: [WorkRequest; PER_SECOND],
    latencies: [u64; PER_SECOND],
}
const PAGES: usize = (REPORT_OFFSET + size_of::<Report>()).div_ceil(PAGE);
// The fixed observations are retained alongside the small scoring input, not
// a second copy of the large training/CPU-union scratch workspace.
const _: () = assert!(PAGES * PAGE <= 128 * 1024);
struct Setup {
    allocation: Option<pool::Allocation>,
    pin: Option<pool::Lease>,
}
struct Cell(UnsafeCell<Setup>);
unsafe impl Sync for Cell {}
static SETUP: Cell = Cell(UnsafeCell::new(Setup {
    allocation: None,
    pin: None,
}));
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static CLEAR: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static GATE: AtomicBool = AtomicBool::new(false);
static OWN_OUTPUT: AtomicBool = AtomicBool::new(false);
static BLOCK_ACTIVE: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
static ABORT: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn lock() -> Result<Guard, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Unknown)?;
    Ok(Guard)
}
fn native(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Capacity => Error::Capacity,
        DomainError::Stale => Error::Stale,
        DomainError::Budget => Error::Budget,
        _ => Error::Evidence,
    }
}
fn with<T>(f: impl FnOnce(&mut Collector) -> Result<T, Error>) -> Result<T, Error> {
    let _g = lock()?;
    let address = ADDRESS.load(Ordering::Acquire);
    if address == 0 || !READY.load(Ordering::Acquire) {
        return Err(Error::Unknown);
    }
    let c = unsafe { &mut *(address as *mut Collector) };
    let result = f(c);
    OWN_OUTPUT.store(c.owns_output(), Ordering::Release);
    BLOCK_ACTIVE.store(c.blocks_active(), Ordering::Release);
    result
}
fn control() -> Result<(), Error> {
    runtime::authorize_learning_turn().map_err(native)
}
pub fn owns_output() -> bool {
    OWN_OUTPUT.load(Ordering::Acquire)
}
pub fn blocks_active() -> bool {
    BLOCK_ACTIVE.load(Ordering::Acquire)
}

/// CPU0 allocates once; no large Rust value is constructed on an EL1 stack.
pub fn init() -> Result<(), DomainError> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(DomainError::Auth);
    }
    {
        let _g = lock().map_err(|_| DomainError::Busy)?;
        if ADDRESS.load(Ordering::Acquire) == 0 {
            let setup = unsafe { &mut *SETUP.0.get() };
            if setup.allocation.is_none() {
                setup.allocation = Some(pool::allocate(OWNER, PAGES)?);
            }
            let a = setup.allocation.ok_or(DomainError::NotReady)?;
            if setup.pin.is_none() {
                setup.pin = Some(pool::pin(a)?);
            }
            let (base, _, bytes) = pool::span(a)?;
            if bytes < PAGES * PAGE
                || base % align_of::<Collector>() != 0
                || (base + REPORT_OFFSET) % align_of::<Report>() != 0
            {
                return Err(DomainError::Range);
            }
            ADDRESS.store(base, Ordering::Release);
        }
    }
    crate::domain_control::governance::register_evidence(
        crate::domain_control::governance::EvidenceChecks {
            owner: OWNER,
            measurement: verify_measurement,
            extension: verify_extension,
        },
    )
}
/// One ordinary prepaid CPU0 service piece clears at most one real page.
fn initialize_piece() -> Result<bool, Error> {
    if READY.load(Ordering::Acquire) {
        return Ok(false);
    }
    let _g = lock()?;
    let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 {
        return Ok(false);
    }
    let first = CLEAR.load(Ordering::Acquire);
    let end = (first + PAGE).min(PAGES * PAGE);
    unsafe {
        core::ptr::write_bytes((base + first) as *mut u8, 0, end - first);
    }
    CLEAR.store(end, Ordering::Release);
    if end == PAGES * PAGE {
        // Sample contains only u64s, so the zeroed row banks are initialized.
        // Initialize enum-bearing metadata/report explicitly before publishing.
        unsafe {
            core::ptr::addr_of_mut!((*(base as *mut Collector)).state).write(State::new());
            let p = (base + REPORT_OFFSET) as *mut Report;
            for i in 0..PER_SECOND {
                core::ptr::addr_of_mut!((*p).baseline)
                    .cast::<WorkRequest>()
                    .add(i)
                    .write(EMPTY);
                core::ptr::addr_of_mut!((*p).candidate)
                    .cast::<WorkRequest>()
                    .add(i)
                    .write(EMPTY);
            }
        }
        READY.store(true, Ordering::Release);
    }
    Ok(true)
}
fn observation(console: &ConsolePump, now: u64, unresolved: bool) -> Observation {
    Observation {
        written: console.written,
        queued: console.queued(),
        batch: console.current(now),
        unresolved,
        poisoned: console.poisoned(),
    }
}
pub fn before_console(
    console: &mut ConsolePump,
    target: ObjectKey,
    now: u64,
    unresolved: bool,
) -> Result<(), DomainError> {
    crate::domain_tasks::authorize_service_turn()?;
    if ABORT.load(Ordering::Acquire)
        && crate::learning_session::request_abort(Error::Evidence).is_ok()
    {
        ABORT.store(false, Ordering::Release);
    }
    if initialize_piece().map_err(|_| DomainError::Busy)? {
        return Ok(());
    }
    if !owns_output() {
        return Ok(());
    }
    with(|c| {
        if c.state.target != target {
            return Err(Error::Stale);
        }
        let o = observation(console, now, unresolved);
        if let Some(due) = c.before(now, o)? {
            let result = console.enqueue(collector::PAYLOAD, now).and_then(|()| {
                console
                    .written
                    .checked_add(console.queued() as u64)
                    .ok_or(DomainError::Overflow)
            });
            c.admitted(due, now, result)?;
        }
        Ok(())
    })
    .map_err(collector_error)
}
pub fn after_console(
    console: &ConsolePump,
    target: ObjectKey,
    now: u64,
    unresolved: bool,
) -> Result<(), DomainError> {
    if !owns_output() {
        return Ok(());
    }
    with(|c| {
        if c.state.target != target {
            return Err(Error::Stale);
        }
        let o = observation(console, now, unresolved);
        let result = c.after(now, o);
        if RELEASE.load(Ordering::Acquire) && c.release(o).is_ok() {
            RELEASE.store(false, Ordering::Release);
        }
        result
    })
    .map_err(collector_error)
}
fn collector_error(error: Error) -> DomainError {
    if error == Error::Unknown {
        return DomainError::Busy;
    }
    ABORT.store(true, Ordering::Release);
    request_release();
    DomainError::Conflict
}
pub fn prepare_baseline(target: ObjectKey) -> Result<bool, Error> {
    control()?;
    with(|c| c.reserve(target))
}
pub fn begin(permit: CanaryPermit) -> Result<(), Error> {
    control()?;
    with(|c| c.bind(permit, crate::domain_platform::now_ns()))
}
pub fn changed_permit(permit: CanaryPermit) -> Result<(), Error> {
    control()?;
    with(|c| c.extend(permit))
}
pub fn request_release() {
    RELEASE.store(true, Ordering::Release);
}
fn verify_measurement(
    permit: CanaryPermit,
    second: u16,
    b: &[WorkRequest],
    c: &[WorkRequest],
    digest: [u8; 32],
) -> Result<(), Error> {
    with(|book| {
        book.verify(
            permit,
            second,
            crate::domain_platform::now_ns(),
            b,
            c,
            digest,
        )
    })
}
fn verify_extension(
    _registration: [u8; 32],
    permit: CanaryPermit,
    at: u64,
    windows: u16,
) -> Result<(), Error> {
    // Only a complete matching baseline can authorize additional observation;
    // this callback cannot forgive safety failures or a changed workload.
    with(|c| {
        if c.state.permit != Some(permit)
            || c.state.fault.is_some()
            || at >= permit.expires_ns
            || windows <= permit.windows
            || windows > 300
            || windows % 10 != 0
            || c.state.delivered == 0
        {
            return Err(Error::Evidence);
        }
        Ok(())
    })
}
/// The driver invokes this before taking another scoring/input loan. The
/// immutable report resides in a disjoint real pool region, so the protected
/// evidence callback may reenter the collector without aliasing mutable rows.
pub fn control_step() -> Result<bool, DomainError> {
    runtime::authorize_learning_turn()?;
    if !READY.load(Ordering::Acquire) || !owns_output() {
        return Ok(false);
    }
    let base = ADDRESS.load(Ordering::Acquire);
    let ready = with(|c| {
        if !matches!(c.state.phase, Phase::Canary | Phase::Closing) {
            return Ok(None);
        }
        let permit = c.state.permit.ok_or(Error::State)?;
        let second = c.state.delivered;
        if u64::from(second + 1) * collector::SECOND > permit.expires_ns - permit.start_ns {
            return Ok(None);
        }
        let now = crate::domain_platform::now_ns();
        if now < permit.start_ns + u64::from(second + 1) * collector::SECOND {
            return Ok(None);
        }
        let report = unsafe { &mut *((base + REPORT_OFFSET) as *mut Report) };
        c.second(
            permit,
            second,
            now,
            &mut report.baseline,
            &mut report.candidate,
        )?;
        Ok(Some((permit, second)))
    });
    let Some((permit, second)) = (match ready {
        Ok(v) => v,
        Err(Error::Unknown) => return Ok(false),
        Err(error) => {
            let _ = collector_error(error);
            return Ok(false);
        }
    }) else {
        return Ok(false);
    };
    let report = unsafe { &mut *((base + REPORT_OFFSET) as *mut Report) };
    match crate::learning_session::observe_second_bounded(
        second,
        &report.baseline,
        &report.candidate,
        &mut report.latencies,
    ) {
        Ok(()) | Err(Error::DataIncomplete) => {
            with(|c| c.acknowledge(permit, second)).map_err(|_| DomainError::Busy)?;
            Ok(true)
        }
        // A live encoder or root gate retains its normal progress priority.
        Err(Error::Unknown | Error::State) => Ok(false),
        Err(error) => {
            let _ = collector_error(error);
            Ok(false)
        }
    }
}
