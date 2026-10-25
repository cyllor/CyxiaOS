//! D15's actual paired-workload adapter. Fixed requests are queued before
//! release; UART write watermarks are the only completion evidence.
use crate::{
    domain_control::replay::{self, Token},
    learning_history::{FrozenScope, ReplayChecks, TrialKind},
    learning_workload::{
        EMPTY_REQUEST, EMPTY_SOURCE, Prepared, REQUESTS, RelativeRequest, SOURCES,
    },
};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey, stability::Boundary},
    learning::{
        self, Family, ReplayGroup,
        capture::{RunKey, Source},
        reward::{Adoption, BaselineAdoption, CpuClass, RequestResult, Trial},
    },
};
use sha2::{Digest, Sha256};
const FAMILY: Family = Family {
    domain: 15,
    kind: 1,
};
const PERIOD: u64 = 100_000_000;
const DURATION: u64 = 10_000_000_000;
const REJECTED: u64 = u64::MAX;
const ZERO: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
#[derive(Clone, Copy)]
struct Row {
    mark: u64,
    finished: u64,
    reported: bool,
    armed: bool,
}
const EMPTY: Row = Row {
    mark: 0,
    finished: 0,
    reported: false,
    armed: false,
};
struct State {
    preparation: Option<replay::Preparation>,
    released_preparation: Option<replay::Preparation>,
    released_unactivated: Option<FrozenScope>,
    aborting: bool,
    abort_drained_at: Option<u64>,
    activation_started: bool,
    prepared: Option<Prepared>,
    kind: TrialKind,
    token: Option<Token>,
    run: Option<RunKey>,
    scope: Option<FrozenScope>,
    queued_at: u64,
    origin: u64,
    next: usize,
    closed: bool,
    warm: bool,
    closing_probe: Option<(u64, u64)>,
    drained_at: Option<u64>,
    rows: [Row; REQUESTS],
    fault: Option<Error>,
}
struct Cell(UnsafeCell<State>);
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State {
    preparation: None,
    released_preparation: None,
    released_unactivated: None,
    aborting: false,
    abort_drained_at: None,
    activation_started: false,
    prepared: None,
    kind: TrialKind::Baseline,
    token: None,
    run: None,
    scope: None,
    queued_at: 0,
    origin: 0,
    next: 0,
    closed: false,
    warm: false,
    closing_probe: None,
    drained_at: None,
    rows: [EMPTY; REQUESTS],
    fault: None,
}));
static GATE: AtomicBool = AtomicBool::new(false);
static RESERVED: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn with<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _g = Guard;
    f(unsafe { &mut *STATE.0.get() })
}
pub fn reserved() -> bool {
    RESERVED.load(Ordering::Acquire)
}
pub fn init() -> Result<(), Error> {
    Ok(())
}
pub fn bind_preparation(prep: replay::Preparation) -> Result<(), Error> {
    crate::domain_tasks::authorize_service_turn()?;
    replay::verify_preparation(prep)?;
    if prep.family != FAMILY {
        return Err(Error::Auth);
    }
    with(|s| {
        if let Some(old) = s.preparation {
            return if old == prep {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        }
        if s.run.is_some() || s.scope.is_some() || s.prepared.is_some() {
            return Err(Error::Busy);
        }
        s.preparation = Some(prep);
        s.released_preparation = None;
        s.released_unactivated = None;
        s.aborting = false;
        s.abort_drained_at = None;
        s.activation_started = false;
        Ok(())
    })
}
/// A prepared table has not released any measurement requests. Existing UART
/// bytes remain owned until the real pump drains them; time is not a receipt.
pub fn abort_prepared(prep: replay::Preparation) -> Result<bool, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    with(|s| {
        if s.preparation != Some(prep) || s.run.is_some() || s.scope.is_some() {
            return Err(Error::Stale);
        }
        s.aborting = true;
        s.closed = true;
        Ok(())
    })?;
    let (_, _, queued, poisoned) = super::replay_console_state()?;
    if poisoned {
        return Err(Error::Io);
    }
    if queued != 0 {
        return Ok(false);
    }
    with(|s| {
        if s.preparation != Some(prep) {
            return Err(Error::Stale);
        }
        s.abort_drained_at.get_or_insert(now());
        Ok(true)
    })
}
pub fn settled_prepared(prep: replay::Preparation) -> Result<(), Error> {
    with(|s| {
        if s.preparation != Some(prep) || s.run.is_some() || s.scope.is_some() {
            return Err(Error::Stale);
        }
        if !s.aborting || s.abort_drained_at.is_none() {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn prepared_failure(
    prep: replay::Preparation,
) -> Result<crate::learning_workload::PreparedFailure, Error> {
    settled_prepared(prep)?;
    with(|s| {
        Ok(crate::learning_workload::PreparedFailure {
            target: s.prepared.map(|p| p.target),
            group: s.prepared.map(|p| p.group),
            queued_at: s.queued_at,
            fault: s.fault,
            drained_at: s.abort_drained_at.ok_or(Error::NotReady)?,
        })
    })
}
pub fn release_prepared(prep: replay::Preparation) -> Result<(), Error> {
    crate::domain_tasks::authorize_service_turn()?;
    if with(|s| {
        Ok(s.preparation.is_none()
            && s.released_preparation == Some(prep)
            && s.released_unactivated.is_none())
    })? {
        return Ok(());
    }
    if !replay::preparation_archived(prep) {
        return Err(Error::Busy);
    }
    with(|s| {
        if s.preparation.is_none()
            && s.released_preparation == Some(prep)
            && s.released_unactivated.is_none()
        {
            return Ok(());
        }
        if s.preparation != Some(prep) || s.run.is_some() || s.scope.is_some() {
            return Err(Error::Stale);
        }
        if !s.aborting || s.abort_drained_at.is_none() {
            return Err(Error::Busy);
        }
        s.prepared = None;
        s.preparation = None;
        s.released_preparation = Some(prep);
        s.token = None;
        s.rows = [EMPTY; REQUESTS];
        s.queued_at = 0;
        RESERVED.store(false, Ordering::Release);
        Ok(())
    })
}
fn unactivated(s: &State, prep: replay::Preparation, scope: &FrozenScope) -> Result<(), Error> {
    let p = s.prepared.ok_or(Error::NotReady)?;
    let token = s.token.ok_or(Error::NotReady)?;
    if s.preparation != Some(prep)
        || prep.family != FAMILY
        || prep.seed != p.group.seed
        || prep.kind != s.kind
        || scope.kind != s.kind
        || scope.family != p.family
        || scope.target != p.target
        || scope.group != p.group
        || scope.key.boot_epoch != prep.boot_epoch
        || scope.key.trial_id != prep.trial_id
        || token.boot_epoch != prep.boot_epoch
        || scope.first_ns < s.queued_at
        || s.scope.is_some_and(|old| old != *scope)
        || s.run.is_some_and(|old| old != scope.key)
    {
        return Err(Error::Stale);
    }
    if s.activation_started
        || s.next != 0
        || s.closing_probe.is_some()
        || s.rows
            .iter()
            .any(|r| r.mark != 0 || r.finished != 0 || r.reported || r.armed)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// The collector already owns this real RunKey, but CPU0 never activated the
/// workload. Stop its unreleased schedule without inventing request results;
/// any previously accepted UART bytes must still leave the actual queue.
pub fn abort_unactivated(prep: replay::Preparation, scope: &FrozenScope) -> Result<bool, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    replay::verify_preparation(prep)?;
    let config = crate::learning_evidence::current_config()
        .map_err(capture_error)?
        .ok_or(Error::Stale)?;
    if config.key != scope.key
        || config.family != scope.family
        || config.first_ns != scope.first_ns
        || config.observation_ns != scope.observation_ns
        || config.frozen_scope_hash != scope.frozen_scope_hash
    {
        return Err(Error::Stale);
    }
    with(|s| {
        unactivated(s, prep, scope)?;
        s.scope = Some(*scope);
        s.run = Some(scope.key);
        s.origin = scope.observation_ns;
        s.aborting = true;
        s.closed = true;
        s.warm = false;
        Ok(())
    })?;
    let (_, _, queued, poisoned) = super::replay_console_state()?;
    if poisoned {
        return Err(Error::Io);
    }
    if queued != 0 {
        return Ok(false);
    }
    with(|s| {
        unactivated(s, prep, scope)?;
        s.abort_drained_at.get_or_insert(now());
        Ok(true)
    })
}
pub fn settled_unactivated(prep: replay::Preparation, scope: &FrozenScope) -> Result<(), Error> {
    with(|s| {
        unactivated(s, prep, scope)?;
        if !s.aborting || s.abort_drained_at.is_none() || s.scope != Some(*scope) {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn release_unactivated(prep: replay::Preparation, scope: &FrozenScope) -> Result<(), Error> {
    crate::domain_tasks::authorize_service_turn()?;
    if with(|s| {
        Ok(s.preparation.is_none()
            && s.released_preparation == Some(prep)
            && s.released_unactivated == Some(*scope))
    })? {
        return Ok(());
    }
    if !replay::preparation_archived(prep) {
        return Err(Error::Busy);
    }
    with(|s| {
        unactivated(s, prep, scope)?;
        if !s.aborting || s.abort_drained_at.is_none() || s.scope != Some(*scope) {
            return Err(Error::Busy);
        }
        s.prepared = None;
        s.preparation = None;
        s.released_preparation = Some(prep);
        s.released_unactivated = Some(*scope);
        s.run = None;
        s.scope = None;
        s.token = None;
        s.rows = [EMPTY; REQUESTS];
        s.queued_at = 0;
        s.activation_started = false;
        RESERVED.store(false, Ordering::Release);
        Ok(())
    })
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn capture_error(error: crate::learning_evidence::Error) -> Error {
    use crate::learning_evidence::Error as E;
    match error {
        E::Busy | E::Capture(learning::Error::Unknown) => Error::Busy,
        E::NotReady => Error::NotReady,
        E::Stale => Error::Stale,
        E::Capacity => Error::Capacity,
        _ => Error::Conflict,
    }
}
fn learned(_: Error) -> learning::Error {
    learning::Error::Evidence
}
pub fn prepare(family: Family, seed: u64, kind: TrialKind) -> Result<Option<Prepared>, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    if family != FAMILY {
        return Err(Error::Unsupported);
    }
    with(|s| {
        let prep = s.preparation.ok_or(Error::Auth)?;
        if prep.family != family || prep.seed != seed || prep.kind != kind || s.aborting {
            return Err(Error::Conflict);
        }
        Ok(())
    })?;
    RESERVED.store(true, Ordering::Release);
    let (target, _, queued, poisoned) = super::replay_console_state()?;
    if poisoned {
        return Err(Error::Io);
    }
    if queued != 0 {
        return Ok(None);
    }
    let result = with(|s| {
        if let Some(p) = s.prepared {
            return if p.group.seed == seed && s.kind == kind {
                Ok(p)
            } else {
                Err(Error::Busy)
            };
        }
        // Readback above proves the workload's initial queue is empty. Bind
        // the immutable payload and schedule separately from policy state.
        let mut workload = Sha256::new();
        workload.update(b"CYXIA_D15_NATIVE_WORKLOAD_1.3\0");
        workload.update(PERIOD.to_le_bytes());
        workload.update((REQUESTS as u64).to_le_bytes());
        workload.update(b"serial replay payload v1");
        let mut image = Sha256::new();
        image.update(b"CYXIA_D15_EMPTY_QUEUE_IMAGE_1.3\0");
        image.update(0u64.to_le_bytes());
        image.update(Sha256::digest(include_bytes!("replay_serial.rs")));
        let mut sources = [EMPTY_SOURCE; SOURCES];
        for (i, class) in [
            CpuClass::Policy,
            CpuClass::ExecutorAction,
            CpuClass::ExecutorWork,
        ]
        .into_iter()
        .enumerate()
        {
            sources[i] = Source {
                owner: target,
                class,
                allowed_cores: if class == CpuClass::Policy { 15 } else { 1 },
            };
        }
        let mut requests = [EMPTY_REQUEST; REQUESTS];
        for (i, r) in requests.iter_mut().enumerate() {
            *r = RelativeRequest {
                id: i as u64 + 1,
                owner: target,
                offset_ns: i as u64 * PERIOD,
            };
        }
        let p = Prepared {
            family,
            target,
            baseline: Action::ConsoleBatch(8),
            boundary: Boundary {
                id: 0x4431_3501,
                metric: crate::service_windows::PENALIZED_P99_NS,
                minimum: 0,
                maximum: DURATION,
                min_samples: 10,
            },
            group: ReplayGroup {
                seed,
                workload: workload.finalize().into(),
                initial_image: image.finalize().into(),
            },
            sources,
            source_count: 3,
            requests,
            checks: ReplayChecks {
                frozen,
                issued,
                baseline,
                closing,
            },
        };
        s.prepared = Some(p);
        s.kind = kind;
        s.queued_at = now();
        s.rows = [EMPTY; REQUESTS];
        s.closed = false;
        s.next = 0;
        s.warm = false;
        s.closing_probe = None;
        s.drained_at = None;
        s.fault = None;
        Ok(p)
    })?;
    crate::learning_evidence::register_schedule_owner_at(target, scheduled_at)
        .map_err(capture_error)?;
    Ok(Some(result))
}
pub fn bind_root(token: Token) -> Result<(), Error> {
    with(|s| {
        if s.prepared.is_none() || s.token.is_some_and(|old| old != token) {
            return Err(Error::Stale);
        }
        s.token = Some(token);
        Ok(())
    })
}
pub fn activate(run: RunKey, observation_ns: u64) -> Result<(), Error> {
    crate::domain_tasks::authorize_service_turn()?;
    with(|s| {
        if s.aborting {
            return Err(Error::Conflict);
        }
        if s.run == Some(run) && s.origin == observation_ns {
            s.activation_started = true;
            return Ok(());
        }
        if s.prepared.is_none() || s.token.is_none() || s.run.is_some() {
            return Err(Error::Stale);
        }
        if observation_ns < s.queued_at {
            return Err(Error::Range);
        }
        s.run = Some(run);
        s.origin = observation_ns;
        s.warm = true;
        s.activation_started = true;
        Ok(())
    })
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), Error> {
    with(|s| {
        if s.aborting {
            return Err(Error::Conflict);
        }
        let p = s.prepared.ok_or(Error::NotReady)?;
        let token = s.token.ok_or(Error::NotReady)?;
        if !replay::activation(token)
            || scope.family != p.family
            || scope.target != p.target
            || scope.group != p.group
            || scope.kind != s.kind
            || scope.first_ns < s.queued_at
            || scope.key.boot_epoch != token.boot_epoch
            || s.scope.is_some_and(|old| old != *scope)
        {
            return Err(Error::Auth);
        }
        if s.scope == Some(*scope) {
            return Ok(());
        }
        s.scope = Some(*scope);
        s.run = Some(scope.key);
        s.origin = scope.observation_ns;
        s.warm = true;
        Ok(())
    })
}
fn scheduled_at(
    run: RunKey,
    owner: ObjectKey,
    id: u64,
    release: u64,
) -> Result<u64, learning::Error> {
    with(|s| {
        let p = s.prepared.ok_or(Error::NotReady)?;
        let i = id.checked_sub(1).ok_or(Error::Range)? as usize;
        if s.run != Some(run)
            || owner != p.target
            || i >= REQUESTS
            || release
                != s.origin
                    .checked_add(p.requests[i].offset_ns)
                    .ok_or(Error::Overflow)?
        {
            return Err(Error::Stale);
        }
        Ok(s.queued_at)
    })
    .map_err(learned)
}
fn payload(seed: u64, id: u64) -> [u8; 16] {
    let mut out = *b"replay.00000000\n";
    let v = seed.wrapping_mul(0x9e37_79b9) ^ id;
    for i in 0..8 {
        let d = ((v >> (i * 4)) & 15) as u8;
        out[7 + i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
    }
    out
}
pub fn poll(run: RunKey) -> Result<bool, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    let (target, written, _, poisoned) = super::replay_console_state()?;
    with(|s| {
        let p = s.prepared.ok_or(Error::NotReady)?;
        if s.run != Some(run) || p.target != target {
            return Err(Error::Stale);
        }
        if s.aborting || !s.activation_started {
            return Ok(false);
        }
        if poisoned {
            s.fault = Some(Error::Io);
            return Err(Error::Io);
        }
        let at = now();
        let mut progress = false;
        for i in 0..REQUESTS {
            let r = &mut s.rows[i];
            if r.mark != 0 && r.mark != REJECTED && r.finished == 0 && written >= r.mark {
                r.finished = at;
                progress = true;
            }
        }
        if s.warm && at < s.origin {
            match super::replay_console_enqueue(&payload(p.group.seed, 0)) {
                Ok(_) => {
                    s.warm = false;
                    progress = true;
                }
                Err(Error::Again) => (),
                Err(e) => return Err(e),
            }
        }
        // These requests already exist in the predeclared queue. A closed
        // observation stops adding requests, while their actual obligations
        // continue to drain and keep late completion evidence.
        if s.next < REQUESTS && at >= s.origin + p.requests[s.next].offset_ns {
            let i = s.next;
            match super::replay_console_enqueue(&payload(p.group.seed, i as u64 + 1)) {
                Ok(mark) => s.rows[i].mark = mark,
                Err(Error::Again | Error::Capacity) => s.rows[i].mark = REJECTED,
                Err(e) => {
                    s.fault = Some(e);
                    return Err(e);
                }
            }
            s.next += 1;
            progress = true;
        }
        Ok(progress)
    })
}
/// Called without the queue gate: the capture owner authenticates scheduled
/// admission by calling back into this protected queue's retained receipt.
pub fn service_io() -> Result<bool, Error> {
    let Some((run, target, arm, result)) = with(|s| {
        if s.aborting || !s.activation_started {
            return Ok(None);
        }
        let (Some(run), Some(p)) = (s.run, s.prepared) else {
            return Ok(None);
        };
        let arm = s.rows.iter().position(|r| !r.armed);
        let result = s.rows.iter().enumerate().find_map(|(i, r)| {
            (!r.reported && (r.mark == REJECTED || r.finished != 0)).then_some((i, *r))
        });
        Ok(Some((run, p.target, arm, result)))
    })?
    else {
        return Ok(false);
    };
    if let Some(i) = arm {
        let r = crate::learning_evidence::request(target, i as u64 + 1).map_err(capture_error)?;
        crate::learning_evidence::arm_scheduled(r).map_err(capture_error)?;
        // Keep an independent armed fact; reporting result is a later action.
        with(|s| {
            if s.run != Some(run) {
                return Err(Error::Stale);
            }
            s.rows[i].armed = true;
            Ok(())
        })?;
        return Ok(true);
    }
    if let Some((i, row)) = result {
        let r = crate::learning_evidence::request(target, i as u64 + 1).map_err(capture_error)?;
        crate::learning_evidence::result(
            r,
            if row.mark == REJECTED {
                RequestResult::Rejected
            } else {
                RequestResult::Completed {
                    finished_ns: row.finished,
                }
            },
        )
        .map_err(capture_error)?;
        with(|s| {
            if s.run != Some(run) {
                return Err(Error::Stale);
            }
            s.rows[i].reported = true;
            Ok(())
        })?;
        return Ok(true);
    }
    Ok(false)
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    crate::domain_tasks::authorize_service_turn()?;
    let token = with(|s| {
        if s.run != Some(run) {
            return Err(Error::Stale);
        }
        s.closed = true;
        s.token.ok_or(Error::NotReady)
    })?;
    let _ = poll(run)?;
    let _ = service_io()?;
    let status = replay::poll(token)?;
    let installation = super::replay_console_installation()?;
    let (_, written, queued, poisoned) = super::replay_console_state()?;
    with(|s| {
        if s.run != Some(run) {
            return Err(Error::Stale);
        }
        if poisoned {
            return Err(Error::Io);
        }
        let Some(closing) = status.closing else {
            return Ok(false);
        };
        if closing.state == cyxia_prototype::policy::ExecutionState::Pending
            && installation.is_some_and(|(stamp, _)| stamp == closing.stamp)
            && s.closing_probe
                .is_none_or(|(version, _)| version != closing.stamp.version)
        {
            let p = s.prepared.ok_or(Error::NotReady)?;
            match super::replay_console_enqueue(&payload(p.group.seed, u64::MAX)) {
                Ok(mark) => s.closing_probe = Some((closing.stamp.version, mark)),
                Err(Error::Again | Error::Capacity) => return Ok(false),
                Err(e) => return Err(e),
            }
            return Ok(false);
        }
        let done = closing.state == cyxia_prototype::policy::ExecutionState::Applied
            && s.next == REQUESTS
            && queued == 0
            && s.rows
                .iter()
                .all(|r| r.armed && r.reported && (r.mark == REJECTED || written >= r.mark))
            && s.closing_probe.is_none_or(|(_, mark)| written >= mark);
        if done {
            s.drained_at.get_or_insert(now());
        }
        Ok(done)
    })
}
/// Read-only witness for the registered root owner. No action is published.
pub fn settled(run: RunKey) -> Result<(), Error> {
    with(|s| {
        if s.run != Some(run) {
            return Err(Error::Stale);
        }
        if s.drained_at.is_none() || s.fault.is_some() {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn release(run: RunKey) -> Result<(), Error> {
    if !drain(run)? {
        return Err(Error::Busy);
    }
    with(|s| {
        s.prepared = None;
        s.preparation = None;
        s.released_preparation = None;
        s.released_unactivated = None;
        s.activation_started = false;
        s.run = None;
        s.token = None;
        s.scope = None;
        Ok(())
    })?;
    RESERVED.store(false, Ordering::Release);
    Ok(())
}
fn token_for_raw(run: RunKey) -> Result<Token, Error> {
    with(|s| {
        if s.run != Some(run) {
            return Err(Error::Stale);
        }
        s.token.ok_or(Error::NotReady)
    })
}
fn frozen_token(scope: &FrozenScope) -> Result<Token, Error> {
    with(|s| {
        let p = s.prepared.as_ref().ok_or(Error::NotReady)?;
        if s.scope != Some(*scope)
            || s.run != Some(scope.key)
            || scope.family != FAMILY
            || scope.target != p.target
            || scope.group != p.group
            || scope.kind != s.kind
            || s.fault.is_some()
        {
            return Err(Error::Conflict);
        }
        s.token.ok_or(Error::NotReady)
    })
}
fn token_for(run: RunKey) -> Result<Token, learning::Error> {
    token_for_raw(run).map_err(learned)
}
fn frozen(scope: &FrozenScope) -> Result<(), learning::Error> {
    replay::verify_scope(frozen_token(scope).map_err(learned)?, scope)
}
fn issued(run: RunKey, a: &Adoption<'_>) -> Result<(), learning::Error> {
    replay::verify_adoption(token_for(run)?, a)
}
fn baseline(run: RunKey, b: &BaselineAdoption) -> Result<(), learning::Error> {
    replay::verify_baseline(token_for(run)?, b)
}
fn closing_raw(trial: &Trial<'_>) -> Result<(), Error> {
    with(|s| {
        if !s.closed
            || s.drained_at.is_none_or(|at| trial.closing_ns < at)
            || s.fault.is_some()
            || trial.observation_ns != s.origin
        {
            return Err(Error::Conflict);
        }
        Ok(())
    })
}

fn closing(scope: &FrozenScope, trial: &Trial<'_>) -> Result<(), learning::Error> {
    frozen(scope)?;
    closing_raw(trial).map_err(learned)
}
fn bounded_read<T>(result: Result<T, Error>) -> Result<Option<T>, learning::Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Busy) => Ok(None),
        Err(error) => Err(learned(error)),
    }
}
pub(crate) fn check_frozen_bounded(scope: &FrozenScope) -> Result<bool, learning::Error> {
    let Some(token) = bounded_read(frozen_token(scope))? else {
        return Ok(false);
    };
    replay::verify_scope_bounded(token, scope)
}
pub(crate) fn check_issued_bounded(
    run: RunKey,
    adoption: &Adoption<'_>,
) -> Result<bool, learning::Error> {
    let Some(token) = bounded_read(token_for_raw(run))? else {
        return Ok(false);
    };
    replay::verify_adoption_bounded(token, adoption)
}
pub(crate) fn check_baseline_bounded(
    run: RunKey,
    baseline: &BaselineAdoption,
) -> Result<bool, learning::Error> {
    let Some(token) = bounded_read(token_for_raw(run))? else {
        return Ok(false);
    };
    replay::verify_baseline_bounded(token, baseline)
}
pub(crate) fn check_closing_bounded(
    scope: &FrozenScope,
    trial: &Trial<'_>,
) -> Result<bool, learning::Error> {
    if !check_frozen_bounded(scope)? {
        return Ok(false);
    }
    Ok(bounded_read(closing_raw(trial))?.is_some())
}
