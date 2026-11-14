//! Actual complete one-second service windows from the protected request
//! collector. Frozen limits are supplied before collection by the replay
//! owner; domain feature normalization constants are never used as SLOs.
use crate::{control_pool as pool, learning_evidence as evidence};
use core::{
    cell::UnsafeCell,
    mem::{align_of, size_of},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::{
        Error, ObjectKey,
        stability::{Boundary, ServiceWindow},
    },
    learning::{
        Family,
        capture::{Config, RunKey},
        reward::{OBSERVATION_NS, RequestResult, WorkRequest},
    },
};
#[path = "service_windows/aggregate.rs"]
mod aggregate;
pub use aggregate::{COMPLETED_P99_NS, COMPLETED_REQUESTS, PENALIZED_P99_NS};
const SECOND: u64 = aggregate::SECOND_NS;
const MAX_BINDINGS: usize = 32;
const ROWS: usize = evidence::START_REQUESTS;
const PAGES: usize = 4;
const OWNER: ObjectKey = ObjectKey {
    id: 0x534c_4f57_494e,
    generation: 1,
};
const EMPTY: (WorkRequest, Option<RequestResult>) = (
    WorkRequest {
        id: 0,
        arrived_ns: 0,
        result: RequestResult::Pending,
    },
    None,
);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub family: Family,
    pub target: ObjectKey,
    pub boundary: Boundary,
    pub origin_ns: u64,
}
#[derive(Clone, Copy)]
struct Scope {
    registration: usize,
    hash: [u8; 32],
    first: u64,
    observation: u64,
    end: u64,
    next: u64,
    run: Option<RunKey>,
}
impl Scope {
    fn matches(self, config: Config, registration: Registration) -> bool {
        config.family == registration.family
            && config.frozen_scope_hash == self.hash
            && config.first_ns == self.first
            && config.observation_ns == self.observation
            && self.run.is_none_or(|old| old == config.key)
    }
    fn done(self) -> bool {
        self.next
            .checked_add(SECOND)
            .is_none_or(|end| end > self.end)
    }
}
struct State {
    registrations: [Option<Registration>; MAX_BINDINGS],
    scope: Option<Scope>,
    rows: [(WorkRequest, Option<RequestResult>); ROWS],
    latencies: [u64; ROWS],
    emitted: u64,
    incomplete: u64,
    last_error: Option<Error>,
}
impl State {
    const fn new() -> Self {
        Self {
            registrations: [None; MAX_BINDINGS],
            scope: None,
            rows: [EMPTY; ROWS],
            latencies: [0; ROWS],
            emitted: 0,
            incomplete: 0,
            last_error: None,
        }
    }
}
const _: () = assert!(size_of::<State>() <= PAGES * 4096);
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
static GATE: AtomicBool = AtomicBool::new(false);
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static CONFIGURED: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn owner() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}
fn lock() -> Result<Guard, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    Ok(Guard)
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    owner()?;
    let _guard = lock()?;
    let address = ADDRESS.load(Ordering::Acquire);
    if address == 0 {
        return Err(Error::NotReady);
    }
    f(unsafe { &mut *(address as *mut State) })
}
#[inline(never)]
pub fn init() -> Result<(), Error> {
    owner()?;
    {
        let _guard = lock()?;
        if ADDRESS.load(Ordering::Acquire) == 0 {
            let setup = unsafe { &mut *SETUP.0.get() };
            if setup.allocation.is_none() {
                setup.allocation = Some(pool::allocate(OWNER, PAGES)?);
            }
            let allocation = setup.allocation.ok_or(Error::NotReady)?;
            if setup.pin.is_none() {
                setup.pin = Some(pool::pin(allocation)?);
            }
            let (base, _, bytes) = pool::span(allocation)?;
            if bytes < size_of::<State>() || base % align_of::<State>() != 0 {
                return Err(Error::Range);
            }
            // This fixed small state owns all its request/sort backing in the
            // real control pool. No EL0 mapping or borrowed slice escapes it.
            unsafe {
                core::ptr::write(base as *mut State, State::new());
            }
            ADDRESS.store(base, Ordering::Release);
        }
    }
    evidence::register_service_consumer(ready_to_retire).map_err(evidence_error)
}
fn evidence_error(error: evidence::Error) -> Error {
    match error {
        evidence::Error::Busy => Error::Busy,
        evidence::Error::NotReady => Error::NotReady,
        evidence::Error::Stale => Error::Stale,
        evidence::Error::Capacity => Error::Capacity,
        evidence::Error::Owner => Error::Auth,
        _ => Error::Conflict,
    }
}
fn registration_slot(state: &State) -> Result<usize, Error> {
    if let Some(slot) = state.registrations.iter().position(Option::is_none) {
        return Ok(slot);
    }
    // Even a sealed capture owns its immutable request table until retirement.
    // Reclaiming a registration must not detach that table from its consumer.
    if evidence::current_config()
        .map_err(evidence_error)?
        .is_some()
    {
        return Err(Error::Busy);
    }
    let mut blocked = None;
    for (slot, registration) in state.registrations.iter().enumerate() {
        if state
            .scope
            .is_some_and(|scope| scope.registration == slot && !scope.done())
        {
            blocked.get_or_insert(Error::Busy);
            continue;
        }
        let registration = registration.ok_or(Error::Stale)?;
        match crate::domain_control::service_target_retired(
            registration.family.domain,
            registration.family.kind,
            registration.target,
        ) {
            Ok(true) => return Ok(slot),
            Ok(false) => {}
            Err(error) => {
                blocked.get_or_insert(error);
            }
        }
    }
    Err(blocked.unwrap_or(Error::Capacity))
}
/// The actual protected baseline owner supplies exact units, minimum sample
/// count and limits. Renewal cannot alter any boundary on this generation.
pub fn register(registration: Registration) -> Result<(), Error> {
    owner()?;
    registration
        .family
        .index()
        .map_err(|_| Error::Unsupported)?;
    if !aggregate::valid_metric(registration.boundary.metric) {
        return Err(Error::Unsupported);
    }
    with(|state| {
        if let Some(old) = state
            .registrations
            .iter()
            .flatten()
            .find(|old| old.target == registration.target && old.family == registration.family)
        {
            return if *old == registration {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let slot = registration_slot(state)?;
        crate::domain_control::register_service_boundary(
            registration.family.domain,
            registration.family.kind,
            registration.target,
            registration.boundary,
            registration.origin_ns,
        )?;
        // Commit replacement only after the new owner accepted the boundary.
        // A consumed old scope must not alias the replacement slot.
        if state.scope.is_some_and(|scope| scope.registration == slot) {
            state.scope = None;
        }
        state.registrations[slot] = Some(registration);
        CONFIGURED.store(true, Ordering::Release);
        Ok(())
    })
}
/// A replay chooses a future whole-second origin on its first real
/// registration. Later trials reuse that exact immutable boundary and origin.
/// Passing the boot's zero timestamp after boot would be a stale registration.
pub fn register_replay(family: Family, target: ObjectKey, boundary: Boundary) -> Result<(), Error> {
    let registration = with(|state| {
        if let Some(old) = state
            .registrations
            .iter()
            .flatten()
            .find(|old| old.target == target && old.family == family)
        {
            if old.boundary != boundary {
                return Err(Error::Conflict);
            }
            return Ok(*old);
        }
        let at = crate::domain_platform::now_ns();
        let origin_ns = (at / SECOND)
            .checked_add(1)
            .and_then(|v| v.checked_mul(SECOND))
            .ok_or(Error::Overflow)?;
        Ok(Registration {
            family,
            target,
            boundary,
            origin_ns,
        })
    })?;
    register(registration)
}
/// Bind the predeclared replay scope before its first event. A later trial may
/// use a new scope while the exact object's thresholds and window origin stay
/// frozen. A still-unconsumed capture cannot be replaced.
pub fn prepare(
    family: Family,
    target: ObjectKey,
    scope_hash: [u8; 32],
    first_ns: u64,
    observation_ns: u64,
) -> Result<(), Error> {
    prepare_scope(family, target, scope_hash, first_ns, observation_ns, false)
}
/// The target and SLO were registered before root activation. C1's exact first
/// snapshot may precede this CPU0 binding, but no complete observation second
/// may have elapsed and the protected capture must already match every field.
pub fn prepare_started(
    family: Family,
    target: ObjectKey,
    scope_hash: [u8; 32],
    first_ns: u64,
    observation_ns: u64,
) -> Result<(), Error> {
    owner()?;
    let config = evidence::current_config()
        .map_err(evidence_error)?
        .ok_or(Error::NotReady)?;
    if config.family != family
        || config.frozen_scope_hash != scope_hash
        || config.first_ns != first_ns
        || config.observation_ns != observation_ns
    {
        return Err(Error::Stale);
    }
    prepare_scope(family, target, scope_hash, first_ns, observation_ns, true)
}
fn prepare_scope(
    family: Family,
    target: ObjectKey,
    scope_hash: [u8; 32],
    first_ns: u64,
    observation_ns: u64,
    started: bool,
) -> Result<(), Error> {
    with(|state| {
        let at = crate::domain_platform::now_ns();
        if scope_hash == [0; 32]
            || (!started && first_ns < at)
            || observation_ns < first_ns
            || (started
                && observation_ns
                    .checked_add(SECOND)
                    .is_none_or(|end| at >= end))
        {
            return Err(Error::Stale);
        }
        if let Some(old) = state.scope {
            let registration = state.registrations[old.registration].ok_or(Error::Stale)?;
            if old.hash == scope_hash
                && old.first == first_ns
                && old.observation == observation_ns
                && registration.family == family
                && registration.target == target
            {
                return Ok(());
            }
            if !old.done() {
                return Err(Error::Busy);
            }
        }
        let i = state
            .registrations
            .iter()
            .position(|r| r.is_some_and(|r| r.family == family && r.target == target))
            .ok_or(Error::NotReady)?;
        let registration = state.registrations[i].ok_or(Error::Stale)?;
        let offset = observation_ns
            .saturating_sub(registration.origin_ns)
            .div_ceil(SECOND);
        let next = registration
            .origin_ns
            .checked_add(offset.checked_mul(SECOND).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        let end = observation_ns
            .checked_add(OBSERVATION_NS)
            .ok_or(Error::Overflow)?;
        if next.checked_add(SECOND).is_none_or(|next| next > end) {
            return Err(Error::Range);
        }
        state.scope = Some(Scope {
            registration: i,
            hash: scope_hash,
            first: first_ns,
            observation: observation_ns,
            end,
            next,
            run: None,
        });
        Ok(())
    })
}
/// One bounded CPU0 service piece: a complete frozen table has at most 128
/// native rows. Pending requests keep their penalty; stale/missing events make
/// the full window incomplete. At most one window is published per turn.
pub fn poll() -> Result<bool, Error> {
    owner()?;
    if !CONFIGURED.load(Ordering::Acquire) {
        return Ok(false);
    }
    with(|state| {
        let Some(mut scope) = state.scope else {
            return Ok(false);
        };
        if scope.done() {
            return Ok(false);
        }
        let end = scope.next.checked_add(SECOND).ok_or(Error::Overflow)?;
        if crate::domain_platform::now_ns() < end {
            return Ok(false);
        }
        let snapshot = evidence::service_snapshot(&mut state.rows).map_err(evidence_error)?;
        let registration = state.registrations[scope.registration].ok_or(Error::Stale)?;
        if !scope.matches(snapshot.config, registration) {
            return Err(Error::Stale);
        }
        if snapshot.observed_ns < end {
            return Ok(false);
        }
        scope.run = Some(snapshot.config.key);
        let measured = aggregate::summarize(
            &state.rows[..snapshot.count],
            registration.boundary.metric,
            scope.next,
            &mut state.latencies,
        );
        let (samples, value, complete) = match measured {
            Ok(m) => (m.samples, m.value, m.complete && snapshot.fault.is_none()),
            Err(error) => {
                state.last_error = Some(error);
                (0, None, false)
            }
        };
        let window = ServiceWindow {
            target: registration.target,
            domain: registration.family.domain,
            kind: registration.family.kind,
            boundary_id: registration.boundary.id,
            metric: registration.boundary.metric,
            start_ns: scope.next,
            end_ns: end,
            covered_ns: if complete { SECOND } else { 0 },
            samples,
            value: if complete { value } else { None },
        };
        // Busy preserves this exact window for retry. A dead target generation
        // is an explicit missing observation, never a new object's success.
        match crate::domain_control::observe_service_window(window) {
            Ok(_) => {}
            Err(error @ (Error::NotFound | Error::Stale)) => {
                state.last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
        if !complete || value.is_none() {
            state.incomplete = state.incomplete.saturating_add(1);
        }
        state.emitted = state.emitted.saturating_add(1);
        scope.next = end;
        state.scope = Some(scope);
        Ok(true)
    })
}
fn ready_to_retire(key: RunKey) -> Result<(), evidence::Error> {
    if !CONFIGURED.load(Ordering::Acquire) {
        return Ok(());
    }
    with(|state| {
        let Some(scope) = state.scope else {
            return Ok(());
        };
        if scope.done() {
            return Ok(());
        }
        if scope.run == Some(key) {
            return Err(Error::Busy);
        }
        let snapshot = evidence::service_snapshot(&mut state.rows).map_err(evidence_error)?;
        let registration = state.registrations[scope.registration].ok_or(Error::Stale)?;
        if snapshot.config.key == key && scope.matches(snapshot.config, registration) {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    })
    .map_err(|error| match error {
        Error::Busy => evidence::Error::Busy,
        Error::NotReady => evidence::Error::NotReady,
        _ => evidence::Error::Stale,
    })
}
