use super::*;
use crate::{
    domain_control::{core_replay as core_work, replay as root},
    learning_evidence as evidence,
};
use cyxia_prototype::domains::stability::Boundary;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Active,
    Settled,
}
#[derive(Clone, Copy)]
struct Request {
    phase: Phase,
    outcome: RequestResult,
    reported: bool,
    armed: bool,
}
const EMPTY: Request = Request {
    phase: Phase::Queued,
    outcome: RequestResult::Pending,
    reported: false,
    armed: false,
};
#[derive(Clone, Copy)]
struct Warm {
    id: u64,
    deadline: u64,
    active: bool,
}
struct Building {
    target: ObjectKey,
    image: [u8; 32],
    prewarm_member: ObjectKey,
    sources: [Source; SOURCES],
    source_count: usize,
    workload: Sha256,
    requests: [RelativeRequest; REQUESTS],
    cursor: usize,
}
struct State {
    preparation: Option<root::Preparation>,
    aborting: bool,
    family: Option<Family>,
    seed: u64,
    kind: TrialKind,
    queued_at: u64,
    prepared: Option<Prepared>,
    building: Option<Building>,
    initial_core: Option<crate::domain_services::replay::CoreImage>,
    initial_irq: Option<crate::domain_platform::replay::IrqImage>,
    token: Option<root::Token>,
    scope: Option<FrozenScope>,
    run: Option<RunKey>,
    activated: bool,
    activation_started: bool,
    unactivated: Option<FrozenScope>,
    requests: [Request; REQUESTS],
    cursor: usize,
    warm: Option<Warm>,
    next_warm: u64,
    warm_at: u64,
    close_probe: Option<Warm>,
    closing_version: u64,
    next_close: u64,
    drained_at: Option<u64>,
    fault: Option<Error>,
    released: u8,
    background: super::background::Queue,
}
struct Cell(UnsafeCell<State>);
unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State {
    preparation: None,
    aborting: false,
    family: None,
    seed: 0,
    kind: TrialKind::Candidate,
    queued_at: 0,
    prepared: None,
    building: None,
    initial_core: None,
    initial_irq: None,
    token: None,
    scope: None,
    run: None,
    activated: false,
    activation_started: false,
    unactivated: None,
    requests: [EMPTY; REQUESTS],
    cursor: 0,
    warm: None,
    next_warm: 101,
    warm_at: 0,
    close_probe: None,
    closing_version: 0,
    next_close: 251,
    drained_at: None,
    fault: None,
    released: 0,
    background: super::background::Queue::new(),
}));
static GATE: AtomicBool = AtomicBool::new(false);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _g = Guard;
    f(unsafe { &mut *STATE.0.get() })
}
fn owner() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() == 0 {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}
fn now() -> u64 {
    crate::domain_platform::now_ns()
}
fn transient(e: Error) -> bool {
    matches!(
        e,
        Error::Busy | Error::Again | Error::NotReady | Error::Budget | Error::Capacity
    )
}
fn native(_: evidence::Error) -> Error {
    Error::NotReady
}
fn learn(e: Error) -> learning::Error {
    if matches!(e, Error::Busy | Error::Again | Error::NotReady) {
        learning::Error::Unknown
    } else {
        learning::Error::Evidence
    }
}
fn uses_file(f: Family) -> bool {
    matches!(f.domain, 3 | 4 | 6 | 8 | 9 | 11)
}
fn uses_echo(f: Family) -> bool {
    matches!((f.domain, f.kind), (13, 1) | (14, 1))
}
fn control_work(f: Family) -> bool {
    (f.domain, f.kind) == (1, 2)
}
fn one_shot(f: Family) -> bool {
    matches!((f.domain, f.kind), (1, 2) | (14, 1))
}
fn baseline(f: Family) -> Result<Action, Error> {
    Ok(match (f.domain, f.kind) {
        (1, 1) => Action::CpuWeight(1),
        (1, 2) => crate::domain_services::replay::core_image()?.baseline(),
        (2, 1) => Action::SpawnTokens(2),
        (3, 1) => Action::Cache {
            pages: 256,
            batch: 16,
        },
        (4, 1) => Action::Filesystem {
            readahead: 0,
            flush: 4,
        },
        (5, 1) => Action::Ipc {
            budget: 32,
            batch: 4,
        },
        (6, 1) => crate::domain_platform::replay::irq_image()?.baseline(),
        (7, 1) => Action::SoftCoalesce(0),
        (8, 1) => Action::ServiceBatch(1),
        (9, 1) => Action::IoShare(250),
        (11, 1) => Action::NotifyBatch(1),
        (13, 1) => Action::BackgroundBudget(100),
        (14, 1) => Action::RecoveryRecipe(0),
        _ => return Err(Error::Unsupported),
    })
}
pub fn init() -> Result<(), Error> {
    owner()
}
pub fn bind_preparation(preparation: root::Preparation) -> Result<(), Error> {
    owner()?;
    with(|s| {
        if s.preparation.is_some_and(|old| old != preparation)
            || s.run.is_some()
            || s.scope.is_some()
            || s.aborting
        {
            return Err(Error::Busy);
        }
        s.preparation = Some(preparation);
        Ok(())
    })?;
    if one_shot(preparation.family) {
        crate::learning_prewarm::bind_preparation(preparation)?;
    }
    Ok(())
}
pub fn prepare(family: Family, seed: u64, kind: TrialKind) -> Result<Option<Prepared>, Error> {
    owner()?;
    baseline(family)?;
    with(|s| {
        let preparation = s.preparation.ok_or(Error::Auth)?;
        if preparation.family != family
            || preparation.seed != seed
            || preparation.kind != kind
            || s.aborting
        {
            return Err(Error::Conflict);
        }
        if let Some(old) = s.family {
            if old != family || s.seed != seed || s.kind != kind {
                return Err(Error::Busy);
            }
            if s.prepared.is_some() {
                return Ok(s.prepared);
            }
        } else {
            s.family = Some(family);
            s.seed = seed;
            s.kind = kind;
            s.queued_at = now();
        }
        if s.building.is_none() {
            let file = if uses_file(family) {
                let Some(image) = crate::domain_storage::replay::prepare(seed)? else {
                    return Ok(None);
                };
                Some(image)
            } else {
                None
            };
            let echo = if uses_echo(family) {
                Some(crate::domain_services::replay::prepare()?)
            } else {
                None
            };
            let timers = if family.domain == 7 {
                let Some(image) = crate::domain_platform::replay::prepare()? else {
                    return Ok(None);
                };
                Some(image)
            } else {
                None
            };
            let core = if control_work(family) {
                Some(core_work::prepare(seed)?)
            } else {
                None
            };
            let tasks = if core.is_none() {
                Some(crate::domain_tasks::replay::prepare(
                    family,
                    seed,
                    file.map_or(ZERO, |v| v.object),
                )?)
            } else {
                None
            };
            let initial_core = if control_work(family) {
                Some(crate::domain_services::replay::core_image()?)
            } else {
                None
            };
            let initial_irq = if family.domain == 6 {
                Some(crate::domain_platform::replay::irq_image()?)
            } else {
                None
            };
            let target = match family.domain {
                1 if family.kind == 2 => {
                    let target = core.ok_or(Error::NotReady)?.target;
                    if initial_core.ok_or(Error::NotReady)?.target != target {
                        return Err(Error::Conflict);
                    }
                    target
                }
                4 | 9 | 11 => crate::domain_storage::enumerate_target(family.domain, 0)
                    .ok_or(Error::NotReady)?,
                6 => initial_irq.ok_or(Error::NotReady)?.target,
                7 => crate::domain_platform::replay::target()?,
                14 => echo.ok_or(Error::NotReady)?.target,
                _ => tasks.ok_or(Error::NotReady)?.target,
            };
            if target == ZERO {
                return Err(Error::NotReady);
            }
            let mut image = Sha256::new();
            image.update(b"CYXIA_REPLAY_RESTORED_WORKING_SET_1.3\0");
            if let Some(tasks) = tasks {
                image.update(tasks.digest);
            }
            if let Some(core) = core {
                image.update(core.digest);
            }
            if let Some(core) = initial_core {
                image.update(core.digest());
            }
            if let Some(irq) = initial_irq {
                image.update(irq.digest());
            }
            if let Some(v) = file {
                image.update(v.digest);
            }
            if let Some(v) = echo {
                image.update(v.digest);
            }
            if let Some(v) = timers {
                image.update(v);
            }
            let mut workload = Sha256::new();
            workload.update(b"CYXIA_ORDINARY_REPLAY_PAYLOADS_1.3\0");
            workload.update(family.domain.to_le_bytes());
            workload.update(family.kind.to_le_bytes());
            workload.update(seed.to_le_bytes());
            let mut sources = [EMPTY_SOURCE; SOURCES];
            let mut count = 0;
            let mut add = |key, class, cores| {
                sources[count] = Source {
                    owner: key,
                    class,
                    allowed_cores: cores,
                };
                count += 1;
            };
            add(target, CpuClass::Policy, 7);
            add(target, CpuClass::ExecutorAction, 15);
            add(OWNER, CpuClass::ExecutorWork, 1);
            if uses_file(family) {
                add(IO_OWNER, CpuClass::ExecutorWork, 1);
                add(
                    crate::domain_platform::irq_replay::source()?,
                    CpuClass::ExecutorWork,
                    9,
                );
            }
            if control_work(family) {
                add(core_work::CORE_OWNER, CpuClass::ExecutorWork, 6);
            } else if matches!(family.domain, 1 | 2 | 13 | 14) {
                add(TASK_OWNER, CpuClass::ExecutorWork, 9);
            }
            if family.domain == 13 {
                add(TASK_OWNER, CpuClass::Optional, 8);
            }
            if family.domain == 7 {
                add(target, CpuClass::ExecutorWork, 1);
            }
            s.building = Some(Building {
                target,
                image: image.finalize().into(),
                prewarm_member: if control_work(family) {
                    core_work::CORE_OWNER
                } else {
                    echo.map_or(ZERO, |v| v.target)
                },
                sources,
                source_count: count,
                workload,
                requests: [EMPTY_REQUEST; REQUESTS],
                cursor: 0,
            });
            s.initial_core = initial_core;
            s.initial_irq = initial_irq;
        }
        // Hash and take actual queue custody of at most eight immutable
        // arrivals per paid turn. All 100 must exist before first publication.
        let build = s.building.as_mut().ok_or(Error::NotReady)?;
        for i in build.cursor..(build.cursor + 8).min(REQUESTS) {
            let id = i as u64 + 1;
            let offset = (i as u64 / 10) * 1_000_000_000 + (i as u64 % 10) * 1000;
            build.requests[i] = RelativeRequest {
                id,
                owner: OWNER,
                offset_ns: offset,
            };
            for v in [id, offset, REQUEST_DEADLINE_NS] {
                build.workload.update(v.to_le_bytes());
            }
            if control_work(family) {
                build.workload.update(core_work::request_digest(seed, id));
            } else {
                for v in [seed ^ id, (id - 1) % 16, 32768] {
                    build.workload.update(v.to_le_bytes());
                }
                build
                    .workload
                    .update(crate::domain_tasks::replay::payload_digest(seed, id));
            }
            if family.domain == 13 {
                super::background::Queue::commit_request(&mut build.workload, seed, i)?;
            }
            build.cursor = i + 1;
        }
        if build.cursor != REQUESTS {
            return Ok(None);
        }
        let group = ReplayGroup {
            seed,
            workload: build.workload.clone().finalize().into(),
            initial_image: build.image,
        };
        let prepared = Prepared {
            family,
            target: build.target,
            baseline: if let Some(core) = s.initial_core {
                core.baseline()
            } else if let Some(irq) = s.initial_irq {
                irq.baseline()
            } else {
                baseline(family)?
            },
            group,
            sources: build.sources,
            source_count: build.source_count,
            requests: build.requests,
            boundary: Boundary {
                id: 0x5245_5000 + family.index().map_err(|_| Error::Schema)? as u64,
                metric: crate::service_windows::PENALIZED_P99_NS,
                minimum: 0,
                maximum: REQUEST_DEADLINE_NS,
                min_samples: 10,
            },
            checks: ReplayChecks {
                frozen: check_frozen,
                issued: check_issued,
                baseline: check_baseline,
                closing: check_closing,
            },
        };
        if one_shot(family) {
            crate::learning_prewarm::begin(family, build.prewarm_member)?;
        }
        // This is the real acceptance point of the now-complete frozen
        // queue, after every request and payload commitment is retained.
        s.queued_at = now();
        s.prepared = Some(prepared);
        s.building = None;
        Ok(Some(prepared))
    })
}
pub fn bind_root(token: root::Token) -> Result<(), Error> {
    owner()?;
    with(|s| {
        if s.prepared.is_none() || s.token.is_some_and(|old| old != token) {
            return Err(Error::Stale);
        }
        s.token = Some(token);
        if s.family.is_some_and(uses_echo) {
            crate::domain_services::replay::bind_control();
        }
        Ok(())
    })
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), Error> {
    with(|s| {
        if s.aborting || s.unactivated.is_some() {
            return Err(Error::Conflict);
        }
        let p = s.prepared.ok_or(Error::NotReady)?;
        let token = s.token.ok_or(Error::NotReady)?;
        if scope.family != p.family
            || scope.target != p.target
            || scope.group != p.group
            || scope.kind != s.kind
            || scope.key.boot_epoch != token.boot_epoch
            || s.queued_at > scope.first_ns
            || s.scope.is_some_and(|old| old != *scope)
        {
            return Err(Error::Conflict);
        }
        s.scope = Some(*scope);
        if control_work(p.family) {
            core_work::bind_scope(scope)?;
        }
        Ok(())
    })
}
pub fn activate(run: RunKey, observation_ns: u64) -> Result<(), Error> {
    owner()?;
    let (family, active) = with(|s| {
        let scope = s.scope.ok_or(Error::NotReady)?;
        if scope.key != run
            || scope.observation_ns != observation_ns
            || s.run.is_some_and(|old| old != run)
        {
            return Err(Error::Stale);
        }
        if s.aborting || s.unactivated.is_some() {
            return Err(Error::Conflict);
        }
        // A facade may already start real work before a later facade returns
        // Busy. Such a turn must finish idempotent activation and normal drain.
        s.activation_started = true;
        s.run = Some(run);
        Ok((scope.family, s.activated))
    })?;
    if active {
        return Ok(());
    }
    if control_work(family) {
        core_work::activate(run)?;
    } else {
        crate::domain_tasks::replay::activate(run)?;
    }
    if one_shot(family) {
        let first = with(|s| Ok(s.scope.ok_or(Error::NotReady)?.first_ns))?;
        crate::learning_prewarm::activate(run, first)?;
    }
    if uses_file(family) {
        crate::domain_platform::irq_replay::activate(run)?;
    }
    if uses_echo(family) {
        crate::domain_services::replay::activate(run)?;
    }
    if family.domain == 7 {
        crate::domain_platform::replay::activate(run)?;
    }
    with(|s| {
        s.activated = true;
        #[cfg(not(test))]
        evidence::execution_trace::work(
            run,
            evidence::execution_trace::WorkEvent::Activated,
            now(),
        );
        Ok(())
    })
}
fn submit(f: Family, seed: u64, id: u64, release: u64, deadline: u64) -> Result<(), Error> {
    match f.domain {
        1 if f.kind == 2 => core_work::submit(id, release, deadline),
        13 if id >= 251 => crate::domain_services::replay::submit(id, seed ^ id),
        1 | 2 | 13 => crate::domain_tasks::replay::spawn(id, deadline),
        3 | 4 | 6 | 9 | 11 => {
            crate::domain_storage::replay::submit(id, f.domain != 3 && id % 4 == 0)
        }
        5 => crate::domain_tasks::replay::ipc(id, deadline),
        7 => crate::domain_platform::replay::submit(
            id,
            release.checked_add(2_000_000).ok_or(Error::Overflow)?,
        ),
        8 => crate::domain_tasks::replay::vector(id, deadline),
        14 => crate::domain_services::replay::submit(id, seed ^ id),
        _ => Err(Error::Unsupported),
    }
}
fn outcome(f: Family, id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    match f.domain {
        1 if f.kind == 2 => core_work::result(id),
        13 if id >= 251 => {
            let result = crate::domain_services::replay::result(id)?;
            if result.is_some() {
                crate::domain_services::replay::acknowledge(id)?;
            }
            Ok(result)
        }
        1 | 2 | 13 => crate::domain_tasks::replay::spawn_result(id),
        3 | 4 | 6 | 9 | 11 => crate::domain_storage::replay::take(id),
        5 => crate::domain_tasks::replay::ipc_result(id),
        7 => crate::domain_platform::replay::result(id),
        8 => crate::domain_tasks::replay::vector_result(id),
        14 => {
            let result = crate::domain_services::replay::result(id)?;
            if result.is_some() {
                crate::domain_services::replay::acknowledge(id)?;
            }
            Ok(result)
        }
        _ => Err(Error::Unsupported),
    }
}
struct OptionalEcho;
impl super::background::Echo for OptionalEcho {
    fn submit(&mut self, id: u64, value: u64) -> Result<(), Error> {
        crate::domain_services::replay::submit(id, value)
    }
    fn result(&mut self, id: u64) -> Result<Option<Result<u64, Error>>, Error> {
        crate::domain_services::replay::result(id)
    }
    fn acknowledge(&mut self, id: u64) -> Result<(), Error> {
        crate::domain_services::replay::acknowledge(id)
    }
}
fn warm(s: &mut State, f: Family, observation: u64, at: u64) -> Result<(), Error> {
    if let Some(mut w) = s.warm {
        if !w.active {
            let reply = submit(f, s.seed, w.id, at, w.deadline);
            #[cfg(not(test))]
            if let Some(scope) = s.scope {
                evidence::execution_trace::work(
                    scope.key,
                    evidence::execution_trace::WorkEvent::WarmSubmit {
                        id: w.id,
                        entered_ns: at,
                        result: reply,
                    },
                    now(),
                );
            }
            match reply {
                Ok(()) => {
                    w.active = true;
                    s.warm = Some(w);
                }
                Err(e) if transient(e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        let reply = outcome(f, w.id);
        #[cfg(not(test))]
        if let (Some(scope), Ok(Some(result))) = (s.scope, reply) {
            evidence::execution_trace::work(
                scope.key,
                evidence::execution_trace::WorkEvent::WarmOutcome { id: w.id, result },
                now(),
            );
        }
        match reply {
            Ok(Some(Ok(_))) => {
                s.warm = None;
                s.warm_at = at.saturating_add(100_000_000);
            }
            Ok(Some(Err(Error::Io))) => return Err(Error::Io),
            Ok(Some(Err(_))) => {
                s.warm = None;
                s.warm_at = at.saturating_add(100_000_000);
            }
            Ok(None) => (),
            Err(e) if transient(e) => (),
            Err(e) => return Err(e),
        }
    } else if at < observation.saturating_sub(50_000_000) && at >= s.warm_at && s.next_warm < 240 {
        let id = s.next_warm;
        s.next_warm += 1;
        let deadline = at.checked_add(REQUEST_DEADLINE_NS).ok_or(Error::Overflow)?;
        s.warm = Some(Warm {
            id,
            deadline,
            active: false,
        });
        #[cfg(not(test))]
        if let Some(scope) = s.scope {
            evidence::execution_trace::work(
                scope.key,
                evidence::execution_trace::WorkEvent::WarmCreated { id, deadline },
                at,
            );
        }
    }
    Ok(())
}
pub fn poll(run: RunKey) -> Result<bool, Error> {
    owner()?;
    #[cfg(not(test))]
    evidence::execution_trace::work(run, evidence::execution_trace::WorkEvent::Poll, now());
    let family = with(|s| s.family.ok_or(Error::NotReady))?;
    if one_shot(family) {
        let _ = crate::learning_prewarm::poll(run)?;
    }
    if uses_file(family) {
        evidence::measure(OWNER, CpuClass::ExecutorWork, || {
            crate::domain_platform::irq_replay::poll(run)
        })?;
    }
    // Arm outside the queue gate: the capture owner reenters this exact
    // retained queue through schedule_check before accepting custody proof.
    let todo = with(|s| {
        if s.run != Some(run) || !s.activated {
            return Err(Error::Stale);
        }
        Ok(core::array::from_fn::<_, 8, _>(|n| {
            s.requests
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.armed)
                .nth(n)
                .map(|(i, _)| i)
        }))
    })?;
    for i in todo.into_iter().flatten() {
        let request = evidence::request(OWNER, i as u64 + 1).map_err(native)?;
        evidence::arm_scheduled(request).map_err(native)?;
        with(|s| {
            if s.run != Some(run) {
                return Err(Error::Stale);
            }
            s.requests[i].armed = true;
            Ok(())
        })?;
    }
    evidence::measure(OWNER, CpuClass::ExecutorWork, || {
        crate::domain_tasks::replay::within_work(|| {
            with(|s| {
                let scope = s.scope.ok_or(Error::NotReady)?;
                let f = scope.family;
                let at = now();
                if let Some(e) = s.fault {
                    return Err(e);
                }
                warm(s, f, scope.observation_ns, at)?;
                if f.domain == 13 {
                    match s
                        .background
                        .poll(at, scope.observation_ns, s.seed, &mut OptionalEcho)
                    {
                        Ok(()) => (),
                        Err(error) if transient(error) => (),
                        Err(error) => {
                            s.fault = Some(error);
                            return Err(error);
                        }
                    }
                }
                // Four independent arrivals may enter one actual IPC queue before
                // dequeue. Batch policies therefore act on real queued messages.
                let mut issued = 0;
                for i in 0..REQUESTS {
                    let row = s.requests[i];
                    let id = i as u64 + 1;
                    let release = scope.observation_ns
                        + (i as u64 / 10) * 1_000_000_000
                        + (i as u64 % 10) * 1000;
                    if !row.armed || row.phase != Phase::Queued || at < release {
                        continue;
                    }
                    let deadline = release
                        .checked_add(REQUEST_DEADLINE_NS)
                        .ok_or(Error::Overflow)?;
                    if at >= deadline {
                        s.requests[i].phase = Phase::Settled;
                        s.requests[i].outcome = RequestResult::TimedOut;
                        continue;
                    }
                    match submit(f, s.seed, id, release, deadline) {
                        Ok(()) => {
                            s.requests[i].phase = Phase::Active;
                            issued += 1;
                        }
                        Err(e) if transient(e) => (),
                        Err(e) => {
                            s.requests[i].phase = Phase::Settled;
                            s.requests[i].outcome = RequestResult::Rejected;
                            if e == Error::Io {
                                s.fault = Some(e);
                                return Err(e);
                            }
                        }
                    }
                    if issued == 4 {
                        break;
                    }
                }
                for _ in 0..4 {
                    let Some(i) = (0..REQUESTS)
                        .map(|n| (s.cursor + n) % REQUESTS)
                        .find(|i| s.requests[*i].phase == Phase::Active)
                    else {
                        break;
                    };
                    s.cursor = (i + 1) % REQUESTS;
                    match outcome(f, i as u64 + 1) {
                        Ok(Some(result)) => {
                            s.requests[i].phase = Phase::Settled;
                            if !s.requests[i].reported {
                                s.requests[i].outcome = match result {
                                    Ok(finished_ns) => RequestResult::Completed { finished_ns },
                                    Err(Error::Expired) => RequestResult::TimedOut,
                                    Err(Error::Io) => {
                                        s.fault = Some(Error::Io);
                                        return Err(Error::Io);
                                    }
                                    Err(_) => RequestResult::Rejected,
                                };
                            }
                        }
                        Ok(None) => (),
                        Err(e) if transient(e) => (),
                        Err(e) => {
                            s.fault = Some(e);
                            return Err(e);
                        }
                    }
                }
                Ok(())
            })
        })
    })?;
    for _ in 0..8 {
        let Some((i, outcome)) = with(|s| {
            Ok(s.requests
                .iter()
                .enumerate()
                .find(|(_, r)| !r.reported && r.outcome != RequestResult::Pending)
                .map(|(i, r)| (i, r.outcome)))
        })?
        else {
            break;
        };
        evidence::result(
            evidence::request(OWNER, i as u64 + 1).map_err(native)?,
            outcome,
        )
        .map_err(native)?;
        with(|s| {
            s.requests[i].reported = true;
            Ok(())
        })?;
    }
    with(|s| {
        Ok(s.requests
            .iter()
            .all(|r| r.phase == Phase::Settled && r.reported)
            && s.warm.is_none()
            && (family.domain != 13 || s.background.settled()))
    })
}
pub fn drain(run: RunKey) -> Result<bool, Error> {
    owner()?;
    if !poll(run)? {
        return Ok(false);
    }
    let (token, f) = with(|s| {
        Ok((
            s.token.ok_or(Error::NotReady)?,
            s.family.ok_or(Error::NotReady)?,
        ))
    })?;
    if f.domain != 14 {
        let status = root::poll(token)?;
        let closing = status.closing.ok_or(Error::NotReady)?;
        if closing.state != cyxia_prototype::policy::ExecutionState::Applied {
            if closing.state.terminal() {
                return Err(Error::Conflict);
            }
            // CoreSet's actual ownership transition settles through its
            // protected migration receipt. No extra model action or business
            // request can stand in for that completion.
            if control_work(f) {
                return Ok(false);
            }
            evidence::measure(OWNER, CpuClass::ExecutorWork, || {
                crate::domain_tasks::replay::within_work(|| {
                    with(|s| {
                        if s.closing_version != closing.stamp.version && s.close_probe.is_none() {
                            if s.next_close >= 255 {
                                return Err(Error::Capacity);
                            }
                            let id = s.next_close;
                            s.next_close += 1;
                            s.closing_version = closing.stamp.version;
                            s.close_probe = Some(Warm {
                                id,
                                deadline: now()
                                    .checked_add(REQUEST_DEADLINE_NS)
                                    .ok_or(Error::Overflow)?,
                                active: false,
                            });
                        }
                        if let Some(mut work) = s.close_probe {
                            if !work.active {
                                submit(f, s.seed, work.id, now(), work.deadline)?;
                                work.active = true;
                                s.close_probe = Some(work);
                            }
                            if let Some(result) = outcome(f, work.id)? {
                                result?;
                                s.close_probe = None;
                            }
                        }
                        Ok(())
                    })
                })
            })?;
            return Ok(false);
        }
    }
    // A publication may be acknowledged before its closing workload returns.
    // Consume that exact request before retiring any of its backing resources.
    let done = evidence::measure(OWNER, CpuClass::ExecutorWork, || {
        with(|s| {
            if let Some(work) = s.close_probe {
                if !work.active {
                    s.close_probe = None;
                } else if let Some(result) = outcome(f, work.id)? {
                    result?;
                    s.close_probe = None;
                } else {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    })?;
    if !done
        || if control_work(f) {
            !core_work::drain()?
        } else {
            !crate::domain_tasks::replay::drain(run)?
        }
    {
        return Ok(false);
    }
    if uses_file(f) && !crate::domain_storage::replay::drain()? {
        return Ok(false);
    }
    if uses_file(f) && !crate::domain_platform::irq_replay::drain(run)? {
        return Ok(false);
    }
    if uses_echo(f) && !crate::domain_services::replay::drain(run)? {
        return Ok(false);
    }
    if one_shot(f) && !crate::learning_prewarm::drain(run)? {
        return Ok(false);
    }
    if f.domain == 7 && !crate::domain_platform::replay::drain(run)? {
        return Ok(false);
    }
    with(|s| {
        s.drained_at.get_or_insert(now());
        Ok(true)
    })
}
pub fn release(run: RunKey) -> Result<(), Error> {
    owner()?;
    with(|s| {
        if s.run != Some(run) || s.drained_at.is_none() {
            return Err(Error::Busy);
        }
        let f = s.family.ok_or(Error::NotReady)?;
        // Each successful release is retained under this gate. A later Busy
        // resumes at the next real owner, without retiring a caller twice.
        if s.released & 1 == 0 {
            if control_work(f) {
                core_work::release(run)?;
            } else {
                crate::domain_tasks::replay::release(run)?;
            }
            s.released |= 1;
        }
        if uses_file(f) && s.released & 2 == 0 {
            crate::domain_platform::irq_replay::release(run)?;
            s.released |= 2;
        }
        if uses_echo(f) && s.released & 4 == 0 {
            crate::domain_services::replay::release(run)?;
            s.released |= 4;
        }
        if one_shot(f) && s.released & 8 == 0 {
            crate::learning_prewarm::release(run)?;
            s.released |= 8;
        }
        if f.domain == 7 && s.released & 16 == 0 {
            crate::domain_platform::replay::release(run)?;
            s.released |= 16;
        }
        s.family = None;
        s.preparation = None;
        s.aborting = false;
        s.prepared = None;
        s.building = None;
        s.initial_core = None;
        s.initial_irq = None;
        s.token = None;
        s.scope = None;
        s.run = None;
        s.activated = false;
        s.activation_started = false;
        s.unactivated = None;
        s.requests.fill(EMPTY);
        s.cursor = 0;
        s.warm = None;
        s.next_warm = 101;
        s.warm_at = 0;
        s.close_probe = None;
        s.closing_version = 0;
        s.next_close = 251;
        s.drained_at = None;
        s.fault = None;
        s.released = 0;
        s.background = super::background::Queue::new();
        Ok(())
    })
}
pub fn settled(run: RunKey) -> Result<(), Error> {
    with(|s| {
        if s.run != Some(run) {
            return Err(Error::Stale);
        }
        if s.drained_at.is_none()
            || s.warm.is_some()
            || s.close_probe.is_some()
            || s.fault.is_some()
            || s.family.is_some_and(|f| f.domain == 13) && !s.background.settled()
            || s.requests
                .iter()
                .any(|r| r.phase != Phase::Settled || !r.reported)
        {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn prewarm_step() -> Result<(), Error> {
    owner()?;
    let warm = with(|s| {
        if s.aborting {
            return Ok(None);
        }
        if let Some(error) = s.fault {
            return Err(error);
        }
        if let Some(expected) = s.initial_core {
            if s.scope.is_none() {
                let actual = crate::domain_services::replay::core_image()?;
                if let Err(error) = expected.matches(actual) {
                    s.fault = Some(error);
                    return Err(error);
                }
            }
        }
        if let Some(expected) = s.initial_irq {
            if s.scope.is_none() {
                let actual = crate::domain_platform::replay::irq_image()?;
                if let Err(error) = expected.matches(actual) {
                    s.fault = Some(error);
                    return Err(error);
                }
            }
        }
        Ok(s.family
            .filter(|f| one_shot(*f) && s.scope.is_none())
            .map(|family| (family, s.seed)))
    })?;
    if let Some((family, seed)) = warm {
        if control_work(family) {
            core_work::prewarm_step(seed)?;
        } else {
            crate::domain_services::replay::prewarm_step(seed)?;
        }
    }
    Ok(())
}
pub fn before_first(
    token: root::Token,
    snapshot: cyxia_prototype::policy::Snapshot,
) -> Result<(), Error> {
    let family = with(|s| {
        if s.token != Some(token) || s.scope.is_some() || s.prepared.is_none() {
            return Err(Error::Stale);
        }
        if let Some(error) = s.fault {
            return Err(error);
        }
        if let Some(expected) = s.initial_core {
            let actual = crate::domain_services::replay::core_image()?;
            if let Err(error) = expected.matches(actual) {
                s.fault = Some(error);
                return Err(error);
            }
        }
        if let Some(expected) = s.initial_irq {
            let actual = crate::domain_platform::replay::irq_image()?;
            if let Err(error) = expected.matches(actual) {
                s.fault = Some(error);
                return Err(error);
            }
        }
        s.family.ok_or(Error::NotReady)
    })?;
    if control_work(family) {
        core_work::freeze(snapshot.taken_ns)?;
    } else if one_shot(family) {
        crate::domain_services::replay::freeze_warm(snapshot.taken_ns)?;
    }
    Ok(())
}
pub fn quiescent() -> bool {
    with(|s| Ok(s.preparation.is_none() && s.family.is_none() && s.run.is_none())).unwrap_or(false)
}
pub fn abort_prepared(preparation: root::Preparation) -> Result<bool, Error> {
    owner()?;
    let done = with(|s| {
        if s.preparation != Some(preparation) || s.run.is_some() || s.scope.is_some() || s.activated
        {
            return Err(Error::Stale);
        }
        s.aborting = true;
        Ok(s.drained_at.is_some())
    })?;
    if done {
        return Ok(true);
    }
    let f = preparation.family;
    let mut done = true;
    if control_work(f) {
        done &= core_work::abort_prepared()?;
    } else {
        done &= crate::domain_tasks::replay::abort_prepared()?;
    }
    if uses_file(f) {
        done &= crate::domain_storage::replay::abort_prepared()?;
    }
    if uses_echo(f) {
        done &= crate::domain_services::replay::abort_prepared()?;
    }
    if f.domain == 7 {
        done &= crate::domain_platform::replay::abort_prepared()?;
    }
    if done && one_shot(f) {
        done &= crate::learning_prewarm::freeze_abort(preparation)?;
    }
    if done {
        with(|s| {
            s.drained_at.get_or_insert(now());
            Ok(())
        })?;
    }
    Ok(done)
}
pub fn settled_prepared(preparation: root::Preparation) -> Result<(), Error> {
    with(|s| {
        if s.preparation != Some(preparation) || s.run.is_some() || s.scope.is_some() {
            return Err(Error::Stale);
        }
        if !s.aborting || s.drained_at.is_none() || s.warm.is_some() || s.close_probe.is_some() {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn prepared_failure(preparation: root::Preparation) -> Result<PreparedFailure, Error> {
    settled_prepared(preparation)?;
    with(|s| {
        Ok(PreparedFailure {
            target: s
                .prepared
                .map(|p| p.target)
                .or_else(|| s.building.as_ref().map(|b| b.target)),
            group: s.prepared.map(|p| p.group),
            queued_at: if s.prepared.is_some() { s.queued_at } else { 0 },
            fault: s.fault,
            drained_at: s.drained_at.ok_or(Error::NotReady)?,
        })
    })
}
pub fn release_prepared(preparation: root::Preparation) -> Result<(), Error> {
    owner()?;
    settled_prepared(preparation)?;
    with(|s| release_inactive(s, preparation, None))
}
fn release_inactive(
    s: &mut State,
    preparation: root::Preparation,
    scope: Option<&FrozenScope>,
) -> Result<(), Error> {
    let f = preparation.family;
    if s.released & 1 == 0 {
        if control_work(f) {
            if let Some(scope) = scope {
                core_work::release_unactivated(scope.key)?;
            } else {
                core_work::release_prepared()?;
            }
        } else {
            crate::domain_tasks::replay::release_prepared()?;
        }
        s.released |= 1;
    }
    if uses_file(f) && s.released & 32 == 0 {
        crate::domain_storage::replay::release_prepared()?;
        s.released |= 32;
    }
    if uses_echo(f) && s.released & 4 == 0 {
        crate::domain_services::replay::release_prepared()?;
        s.released |= 4;
    }
    if f.domain == 7 && s.released & 16 == 0 {
        crate::domain_platform::replay::release_prepared()?;
        s.released |= 16;
    }
    if one_shot(f) && s.released & 8 == 0 {
        crate::learning_prewarm::release_prepared(preparation)?;
        s.released |= 8;
    }
    s.preparation = None;
    s.aborting = false;
    s.family = None;
    s.prepared = None;
    s.building = None;
    s.initial_core = None;
    s.initial_irq = None;
    s.token = None;
    s.scope = None;
    s.run = None;
    s.activated = false;
    s.activation_started = false;
    s.unactivated = None;
    s.requests.fill(EMPTY);
    s.cursor = 0;
    s.warm = None;
    s.next_warm = 101;
    s.warm_at = 0;
    s.close_probe = None;
    s.closing_version = 0;
    s.next_close = 251;
    s.drained_at = None;
    s.fault = None;
    s.released = 0;
    s.background = super::background::Queue::new();
    Ok(())
}
/// Capture is already open, but no facade was allowed to activate. Retain
/// that real key and scope as a negative window; do not start its 100 requests
/// merely to close it, and do not reclassify it as a pre-capture preparation.
pub fn abort_unactivated(
    preparation: root::Preparation,
    scope: &FrozenScope,
) -> Result<bool, Error> {
    owner()?;
    let done = with(|s| {
        let prepared = s.prepared.ok_or(Error::NotReady)?;
        if s.preparation != Some(preparation)
            || s.activation_started
            || s.activated
            || scope.family != prepared.family
            || scope.target != prepared.target
            || scope.group != prepared.group
            || scope.kind != s.kind
            || scope.key.boot_epoch != preparation.boot_epoch
            || scope.key.trial_id != preparation.trial_id
            || s.scope.is_some_and(|old| old != *scope)
            || s.run.is_some_and(|old| old != scope.key)
            || s.unactivated.is_some_and(|old| old != *scope)
            || s.requests
                .iter()
                .any(|r| r.phase != Phase::Queued || r.armed || r.reported)
            || s.warm.is_some()
            || s.close_probe.is_some()
        {
            return Err(Error::Conflict);
        }
        s.scope = Some(*scope);
        s.run = Some(scope.key);
        s.unactivated = Some(*scope);
        s.aborting = true;
        Ok(s.drained_at.is_some())
    })?;
    if done {
        return Ok(true);
    }
    let f = preparation.family;
    let mut done = if control_work(f) {
        core_work::abort_unactivated(scope)?
    } else {
        crate::domain_tasks::replay::abort_prepared()?
    };
    if uses_file(f) {
        done &= crate::domain_storage::replay::abort_prepared()?;
    }
    if uses_echo(f) {
        done &= crate::domain_services::replay::abort_prepared()?;
    }
    if f.domain == 7 {
        done &= crate::domain_platform::replay::abort_prepared()?;
    }
    // Its raw rows remain under Preparation with capture generation zero.
    // The full negative archive exports them alongside the real capture key.
    if done && one_shot(f) {
        done &= crate::learning_prewarm::freeze_abort(preparation)?;
    }
    if done {
        with(|s| {
            s.drained_at.get_or_insert(now());
            Ok(())
        })?;
    }
    Ok(done)
}
pub fn settled_unactivated(
    preparation: root::Preparation,
    scope: &FrozenScope,
) -> Result<(), Error> {
    with(|s| {
        if s.preparation != Some(preparation)
            || s.unactivated != Some(*scope)
            || s.scope != Some(*scope)
            || s.run != Some(scope.key)
        {
            return Err(Error::Stale);
        }
        if !s.aborting
            || s.drained_at.is_none()
            || s.activation_started
            || s.activated
            || s.requests
                .iter()
                .any(|r| r.phase != Phase::Queued || r.armed || r.reported)
            || s.warm.is_some()
            || s.close_probe.is_some()
        {
            return Err(Error::Busy);
        }
        Ok(())
    })
}
pub fn release_unactivated(
    preparation: root::Preparation,
    scope: &FrozenScope,
) -> Result<(), Error> {
    owner()?;
    if !root::preparation_archived(preparation) {
        return Err(Error::Busy);
    }
    settled_unactivated(preparation, scope)?;
    with(|s| release_inactive(s, preparation, Some(scope)))
}
pub fn current_run(run: RunKey) -> bool {
    with(|s| Ok(s.scope.is_some_and(|scope| scope.key == run))).unwrap_or(false)
}
pub(crate) fn schedule_check(
    run: RunKey,
    owner: ObjectKey,
    id: u64,
    release_ns: u64,
) -> Result<u64, learning::Error> {
    with(|s| {
        let scope = s.scope.ok_or(Error::NotReady)?;
        let p = s.prepared.ok_or(Error::NotReady)?;
        let i = id
            .checked_sub(1)
            .filter(|i| *i < REQUESTS as u64)
            .ok_or(Error::Range)? as usize;
        if owner != OWNER
            || scope.key != run
            || s.run != Some(run)
            || p.requests[i].owner != owner
            || scope.observation_ns.checked_add(p.requests[i].offset_ns) != Some(release_ns)
            || s.queued_at > release_ns
        {
            return Err(Error::Conflict);
        }
        Ok(s.queued_at)
    })
    .map_err(learn)
}
fn frozen_token(scope: &FrozenScope) -> Result<root::Token, Error> {
    with(|s| {
        let p = s.prepared.as_ref().ok_or(Error::NotReady)?;
        if s.scope != Some(*scope)
            || scope.group != p.group
            || scope.family != p.family
            || scope.target != p.target
            || s.queued_at > scope.first_ns
            || s.fault.is_some()
            || (s.activated && s.run != Some(scope.key))
        {
            return Err(Error::Conflict);
        }
        s.token.ok_or(Error::NotReady)
    })
}
fn check_context(run: RunKey, kind: TrialKind) -> Result<(root::Token, FrozenScope), Error> {
    with(|s| {
        let scope = s.scope.ok_or(Error::NotReady)?;
        if scope.key != run || scope.kind != kind || s.fault.is_some() {
            return Err(Error::Stale);
        }
        Ok((s.token.ok_or(Error::NotReady)?, scope))
    })
}
fn closing_token(scope: &FrozenScope, trial: &Trial<'_>) -> Result<root::Token, Error> {
    with(|s| {
        if s.drained_at.is_none_or(|at| at > trial.closing_ns)
            || s.fault.is_some()
            || s.warm.is_some()
            || s.close_probe.is_some()
            || scope.family.domain == 13 && !s.background.settled()
            || trial.requests.len() != REQUESTS
            || !trial.correct
            || trial.closing != cyxia_prototype::policy::ExecutionState::Applied
        {
            return Err(Error::Conflict);
        }
        let p = s.prepared.as_ref().ok_or(Error::NotReady)?;
        if let Some(initial) = s.initial_core {
            initial.matches(crate::domain_services::replay::core_image()?)?;
        }
        if let Some(initial) = s.initial_irq {
            initial
                .restored()
                .matches(crate::domain_platform::replay::irq_image()?)?;
        }
        for (i, request) in trial.requests.iter().enumerate() {
            let actual = s.requests[i];
            if actual.phase != Phase::Settled
                || !actual.reported
                || !actual.armed
                || request.id != p.requests[i].id
                || request.arrived_ns != scope.observation_ns + p.requests[i].offset_ns
                || request.result
                    != match actual.outcome {
                        RequestResult::Completed { finished_ns }
                            if finished_ns > scope.observation_ns + 10_000_000_000 =>
                        {
                            RequestResult::Pending
                        }
                        value => value,
                    }
            {
                return Err(Error::Conflict);
            }
        }
        s.token.ok_or(Error::NotReady)
    })
}
fn closing_applied(status: &root::Status, closing_ns: u64) -> Result<(), learning::Error> {
    if status.closing.is_none_or(|v| {
        v.state != cyxia_prototype::policy::ExecutionState::Applied || v.observed_ns > closing_ns
    }) || status.fault.is_some()
    {
        return Err(learning::Error::Unknown);
    }
    Ok(())
}
fn check_frozen(scope: &FrozenScope) -> Result<(), learning::Error> {
    root::verify_scope(frozen_token(scope).map_err(learn)?, scope)
}
fn check_issued(run: RunKey, adoption: &Adoption<'_>) -> Result<(), learning::Error> {
    let (token, scope) = check_context(run, TrialKind::Candidate).map_err(learn)?;
    check_frozen(&scope)?;
    root::verify_adoption(token, adoption)
}
fn check_baseline(run: RunKey, baseline: &BaselineAdoption) -> Result<(), learning::Error> {
    let (token, scope) = check_context(run, TrialKind::Baseline).map_err(learn)?;
    check_frozen(&scope)?;
    root::verify_baseline(token, baseline)
}
fn check_closing(scope: &FrozenScope, trial: &Trial<'_>) -> Result<(), learning::Error> {
    check_frozen(scope)?;
    let token = closing_token(scope, trial).map_err(learn)?;
    closing_applied(&root::poll(token).map_err(learn)?, trial.closing_ns)
}

// Only a rejected actual try-lock is a resumable read. A real unresolved
// closing receipt retains Error::Unknown and cannot become successful retry.
fn bounded_read<T>(result: Result<T, Error>) -> Result<Option<T>, learning::Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Busy) => Ok(None),
        Err(error) => Err(learn(error)),
    }
}
pub(crate) fn check_frozen_bounded(scope: &FrozenScope) -> Result<bool, learning::Error> {
    let Some(token) = bounded_read(frozen_token(scope))? else {
        return Ok(false);
    };
    root::verify_scope_bounded(token, scope)
}
pub(crate) fn check_issued_bounded(
    run: RunKey,
    adoption: &Adoption<'_>,
) -> Result<bool, learning::Error> {
    let Some((token, scope)) = bounded_read(check_context(run, TrialKind::Candidate))? else {
        return Ok(false);
    };
    if !check_frozen_bounded(&scope)? {
        return Ok(false);
    }
    root::verify_adoption_bounded(token, adoption)
}
pub(crate) fn check_baseline_bounded(
    run: RunKey,
    baseline: &BaselineAdoption,
) -> Result<bool, learning::Error> {
    let Some((token, scope)) = bounded_read(check_context(run, TrialKind::Baseline))? else {
        return Ok(false);
    };
    if !check_frozen_bounded(&scope)? {
        return Ok(false);
    }
    root::verify_baseline_bounded(token, baseline)
}
pub(crate) fn check_closing_bounded(
    scope: &FrozenScope,
    trial: &Trial<'_>,
) -> Result<bool, learning::Error> {
    if !check_frozen_bounded(scope)? {
        return Ok(false);
    }
    let Some(token) = bounded_read(closing_token(scope, trial))? else {
        return Ok(false);
    };
    let Some(status) = bounded_read(root::poll(token))? else {
        return Ok(false);
    };
    closing_applied(&status, trial.closing_ns)?;
    Ok(true)
}

/// Disk waits run outside their CPU reservation and capture interval. Each
/// resumed segment first obtains a new actual CPU0 service grant, exactly like
/// the ordinary file syscall pump. No wall wait is charged as executor CPU.
pub fn service_io(progress: &mut dyn FnMut()) {
    if !crate::domain_storage::replay::needs_io() {
        return;
    }
    let Ok(run) = with(|s| Ok(s.run.filter(|_| s.activated))) else {
        return;
    };
    let _ = crate::domain_tasks::service_io_piece(Some(IO_OWNER), progress, |resume| {
        let mut callback = || {
            resume();
            if let Some(run) = run {
                let _ = crate::domain_platform::irq_replay::poll(run);
            }
        };
        let result = crate::domain_storage::replay::step(&mut callback);
        if let Some(run) = run {
            let _ = crate::domain_platform::irq_replay::poll(run);
        }
        result
    });
}
