//! Protected network workload owner. The retained arrival table is established
//! before first capture; only actual protocol/task terminal replies settle it.
use core::{cell::UnsafeCell, sync::atomic::{AtomicBool, Ordering}};
use cyxia_prototype::{domains::{Action, Error, ObjectKey, stability::Boundary}, learning::{self, Family, ReplayGroup,
    capture::RunKey, reward::{Adoption, BaselineAdoption, CpuClass, RequestResult, Trial}}, policy::Snapshot};
use crate::{domain_control::replay as root, learning_evidence as evidence, learning_history::{FrozenScope, ReplayChecks, TrialKind},
    learning_workload::{Prepared, RelativeRequest, OWNER, TASK_OWNER, REQUESTS, SOURCES, EMPTY_REQUEST, EMPTY_SOURCE, REQUEST_DEADLINE_NS}, peer_replay as peer};
use sha2::{Digest, Sha256};
const ZERO: ObjectKey = ObjectKey { id: 0, generation: 0 };
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase { Queued, Active, Settled }
#[derive(Clone, Copy)]
struct Row { phase: Phase, outcome: RequestResult, armed: bool, reported: bool }
const EMPTY: Row = Row { phase: Phase::Queued, outcome: RequestResult::Pending, armed: false, reported: false };
#[derive(Clone, Copy)]
struct Warm { id: u64, submitted: bool }
struct State { prepared: Option<Prepared>, kind: TrialKind, queued_at: u64, serial: u64, ready: bool,
    preparation: Option<root::Preparation>, released_preparation: Option<root::Preparation>, aborting: bool, held_target: Option<ObjectKey>,
    token: Option<root::Token>, scope: Option<FrozenScope>, run: Option<RunKey>, activated: bool,
    activation_started: bool, unactivated: Option<FrozenScope>,
    tasks_active: bool, prewarm: bool, rows: [Row; REQUESTS], warm: Option<Warm>, next_warm: u64, warm_at: u64,
    closing: Option<Warm>, closing_version: u64, next_close: u64, drained_at: Option<u64>, fault: Option<Error>,
    tasks_released: bool, services_released: bool, prewarm_released: bool }
struct Cell(UnsafeCell<State>); unsafe impl Sync for Cell {}
static STATE: Cell = Cell(UnsafeCell::new(State { prepared: None, kind: TrialKind::Candidate, queued_at: 0,
    preparation: None, released_preparation: None, aborting: false, held_target: None,
    serial: 0, ready: false, token: None, scope: None, run: None, activated: false, activation_started: false,
    unactivated: None, tasks_active: false,
    prewarm: false, rows: [EMPTY; REQUESTS], warm: None, next_warm: 101, warm_at: 0,
    closing: None, closing_version: 0, next_close: 241, drained_at: None, fault: None,
    tasks_released: false, services_released: false, prewarm_released: false }));
static GATE: AtomicBool = AtomicBool::new(false);
struct Guard; impl Drop for Guard { fn drop(&mut self) { GATE.store(false, Ordering::Release); } }
fn with<T>(f: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).map_err(|_| Error::Busy)?;
    let _guard = Guard; f(unsafe { &mut *STATE.0.get() })
}
fn now() -> u64 { crate::domain_platform::now_ns() }
fn owner() -> Result<(), Error> { if cyxia_arch_aarch64::cpu::slot() == 0 { Ok(()) } else { Err(Error::Auth) } }
fn transient(e: Error) -> bool { matches!(e, Error::Busy | Error::Again | Error::NotReady | Error::Capacity | Error::Budget) }
fn native(_: evidence::Error) -> Error { Error::NotReady }
fn learn(e: Error) -> learning::Error { if transient(e) { learning::Error::Unknown } else { learning::Error::Evidence } }
fn placement(f: Family) -> bool { f == (Family { domain: 16, kind: 2 }) }
fn baseline(f: Family) -> Result<Action, Error> { Ok(match (f.domain, f.kind) {
    (10, 1) => Action::TxBatch(4), (12, 1) => Action::UnauthRate(16), (16, 1) => Action::OfferCpu(0),
    (16, 2) => Action::Placement(2), _ => return Err(Error::Unsupported),
}) }
pub fn init() -> Result<(), Error> { owner() }
pub fn bind_preparation(preparation: root::Preparation) -> Result<(), Error> {
    owner()?; root::verify_preparation(preparation)?;
    with(|s| {
        if s.preparation.is_some_and(|old| old != preparation) || s.run.is_some() || s.scope.is_some() { return Err(Error::Busy); }
        s.preparation = Some(preparation); Ok(())
    })?;
    if placement(preparation.family) { crate::learning_prewarm::bind_preparation(preparation)?; } Ok(())
}
pub fn prepare(family: Family, seed: u64, kind: TrialKind) -> Result<Option<Prepared>, Error> {
    owner()?; let action = baseline(family)?;
    let existing = with(|s| {
        if s.preparation.is_none_or(|p| p.family != family || p.seed != seed || p.kind != kind) || s.aborting { return Err(Error::Auth); }
        if let Some(p) = s.prepared {
        if p.family != family || p.group.seed != seed || s.kind != kind { return Err(Error::Busy); }
    } Ok((s.prepared, s.ready)) })?;
    if existing.1 { return Ok(existing.0); }
    if existing.0.is_none() {
        let (local, remote, _) = peer::local_ready()?;
        if !peer::local_idle()? { return Ok(None); }
        let tasks = if placement(family) { Some(crate::domain_tasks::replay::prepare(family, seed, ZERO)?) } else { None };
        let echo = if placement(family) { Some(crate::domain_services::replay::prepare()?) } else { None };
        let mut image = Sha256::new(); image.update(b"CYXIA_NETWORK_IDLE_WORKING_SET_1.3\0");
        image.update(crate::unified_task::package_digest()); image.update(local.node); image.update(remote.node);
        image.update(b"no-live-contract;no-pending-application;remote-executor-free\0");
        if let Some(v) = tasks { image.update(v.digest); }
        if let Some(v) = echo { image.update(v.digest); }
        let target = if placement(family) {
            let (payload, _) = crate::peer_replay::work_wire::payload(seed, 1);
            with(|s| {
                if let Some(target) = s.held_target { return Ok(target); }
                let sequence = s.serial.checked_add(1).ok_or(Error::Overflow)?;
                let target = super::requests::reserve(OWNER, sequence, &payload)?;
                s.serial = sequence; s.held_target = Some(target); Ok(target)
            })?
        } else { ObjectKey { id: match family.domain { 10 => super::abi::TX_SERVICE_ID,
            12 => super::abi::UNAUTH_SERVICE_ID, _ => super::abi::OFFER_SERVICE_ID }, generation: 1 } };
        let mut requests = [EMPTY_REQUEST; REQUESTS]; let mut workload = Sha256::new();
        workload.update(b"CYXIA_REAL_NETWORK_ARRIVALS_1.3\0"); workload.update(family.domain.to_le_bytes());
        workload.update(family.kind.to_le_bytes()); workload.update(seed.to_le_bytes());
        for (i, request) in requests.iter_mut().enumerate() {
            let id = i as u64 + 1; let offset_ns = (i as u64 / 10) * 1_000_000_000 + (i as u64 % 10) * 1000;
            *request = RelativeRequest { id, owner: OWNER, offset_ns };
            for v in [id, offset_ns, REQUEST_DEADLINE_NS] { workload.update(v.to_le_bytes()); }
            workload.update(crate::peer_replay::work_wire::payload(seed, id).0);
        }
        let mut sources = [EMPTY_SOURCE; SOURCES]; let mut count = 0;
        let mut add = |owner, class, allowed_cores| { sources[count] = learning::capture::Source { owner, class, allowed_cores }; count += 1; };
        add(target, CpuClass::Policy, 7); add(target, CpuClass::ExecutorAction, 15);
        add(OWNER, CpuClass::ExecutorWork, 1);
        add(ObjectKey { id: 0x101, generation: 1 }, CpuClass::ExecutorWork, 1);
        add(peer::REMOTE_WORK_OWNER, CpuClass::ExecutorWork, 8);
        if placement(family) { add(TASK_OWNER, CpuClass::ExecutorWork, 9); }
        let prepared = Prepared { family, target, baseline: action, group: ReplayGroup { seed,
            workload: workload.finalize().into(), initial_image: image.finalize().into() }, sources, source_count: count, requests,
            boundary: Boundary { id: 0x4e45_5400 + family.index().map_err(|_| Error::Schema)? as u64,
                metric: crate::service_windows::PENALIZED_P99_NS, minimum: 0, maximum: REQUEST_DEADLINE_NS, min_samples: 10 },
            checks: ReplayChecks { frozen: check_frozen, issued: check_issued, baseline: check_baseline, closing: check_closing } };
        with(|s| { s.prepared = Some(prepared); s.kind = kind; s.queued_at = now(); Ok(()) })?;
    }
    let p = with(|s| s.prepared.ok_or(Error::NotReady))?;
    if !peer::prepare(family, seed, kind, p.group, p.target)? { return Ok(None); }
    if placement(family) {
        let image = crate::domain_services::replay::prepare()?;
        crate::learning_prewarm::begin(family, image.target)?;
    }
    with(|s| { s.ready = true; s.prewarm = placement(family); Ok(Some(p)) })
}
pub fn bind_root(token: root::Token) -> Result<(), Error> { owner()?;
    let warm = with(|s| { if !s.ready || s.token.is_some_and(|old| old != token) { return Err(Error::Stale); }
        s.token = Some(token); Ok(s.prewarm) })?;
    if warm { crate::domain_services::replay::bind_control(); } Ok(())
}
pub fn prewarm_step() -> Result<(), Error> { owner()?;
    let seed = with(|s| Ok(s.prepared.filter(|_| s.prewarm && s.scope.is_none() && !s.aborting).map(|p| p.group.seed)))?;
    if let Some(seed) = seed { crate::domain_services::replay::prewarm_step(seed)?; } Ok(())
}
pub fn before_first(token: root::Token, snapshot: Snapshot) -> Result<(), Error> {
    let warm = with(|s| { if s.token != Some(token) || s.scope.is_some() { return Err(Error::Stale); } Ok(s.prewarm) })?;
    if warm { crate::domain_services::replay::freeze_warm(snapshot.taken_ns)?; } Ok(())
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), Error> {
    with(|s| { let p = s.prepared.ok_or(Error::NotReady)?; let token = s.token.ok_or(Error::NotReady)?;
        if p.family != scope.family || p.target != scope.target || p.group != scope.group || s.kind != scope.kind
            || scope.key.boot_epoch != token.boot_epoch || s.queued_at > scope.first_ns || s.scope.is_some_and(|old| old != *scope) {
            return Err(Error::Conflict);
        } s.scope = Some(*scope); Ok(()) })?;
    peer::bind_scope(scope)
}
fn activate_tasks(run: RunKey) -> Result<(), Error> {
    let (needed, active) = with(|s| {
        if s.aborting { return Err(Error::Conflict); }
        let needed = s.prepared.is_some_and(|p| placement(p.family));
        if needed { s.activation_started = true; }
        Ok((needed, s.tasks_active))
    })?;
    if needed && !active { crate::domain_tasks::replay::activate(run)?; with(|s| { s.tasks_active = true; Ok(()) })?; } Ok(())
}
pub fn activate(run: RunKey, observation_ns: u64) -> Result<(), Error> { owner()?;
    let (scope, active, warm) = with(|s| { let scope = s.scope.ok_or(Error::NotReady)?;
        if s.aborting { return Err(Error::Conflict); }
        if scope.key != run || scope.observation_ns != observation_ns || s.run.is_some_and(|old| old != run) { return Err(Error::Stale); }
        s.run = Some(run); s.activation_started = true; Ok((scope, s.activated, s.prewarm)) })?;
    if active { return Ok(()); }
    activate_tasks(run)?;
    if warm { crate::domain_services::replay::activate(run)?; crate::learning_prewarm::activate(run, scope.first_ns)?; }
    if !peer::start(run)? { return Err(Error::Again); }
    // The frozen business arrival exists even if the one-shot plan never
    // publishes. The ordinary queue then performs its real four-second
    // fallback from the original timestamp, retaining the same request key.
    if placement(scope.family) { super::requests::release(OWNER, scope.target, scope.observation_ns)?; }
    with(|s| { s.activated = true; Ok(()) })
}
/// The original retained request becomes visible before the already selected
/// one-shot policy reaches its service. Its logical arrival remains first_ns.
pub(super) fn release_target(target: ObjectKey) -> Result<(), Error> {
    let scope = with(|s| Ok(s.scope.filter(|scope| placement(scope.family) && scope.target == target)))?;
    let Some(scope) = scope else { return Ok(()); };
    activate_tasks(scope.key)?;
    if !peer::start(scope.key)? { return Err(Error::Again); }
    super::requests::release(OWNER, target, scope.observation_ns)
}
pub(crate) fn claim_local(target: ObjectKey, spawn_id: u64) -> Result<(), Error> {
    let run = with(|s| Ok(s.scope.filter(|scope| placement(scope.family) && scope.target == target).map(|scope| scope.key)))?;
    if let Some(run) = run { activate_tasks(run)?; crate::domain_tasks::replay::claim_local(run, spawn_id)?; } Ok(())
}
/// A reserved request already has real payload custody. It is exposed for
/// selection only after the root exclusively owns this family/target.
pub(super) fn advertised() -> Option<ObjectKey> { with(|s| Ok(s.prepared.filter(|p|
    placement(p.family) && s.token.is_some() && s.drained_at.is_none()).map(|p| p.target))).ok().flatten() }
fn business_result(run: RunKey, p: Prepared, id: u64) -> Result<Option<RequestResult>, Error> {
    if placement(p.family) {
        if id == 1 {
            return Ok(super::requests::completion(OWNER, p.target)?.map(|v| if v.outcome == 1 {
                RequestResult::Completed { finished_ns: v.finished_ns } } else { RequestResult::Rejected }));
        }
        return Ok(crate::domain_tasks::replay::spawn_result(id)?.map(|v| match v {
            Ok(finished_ns) => RequestResult::Completed { finished_ns }, Err(Error::Expired) => RequestResult::TimedOut,
            Err(_) => RequestResult::Rejected,
        }));
    }
    Ok(peer::work_result(run, id)?.map(|v| match v.outcome {
        1 => RequestResult::Completed { finished_ns: now() }, 3 => RequestResult::TimedOut, _ => RequestResult::Rejected,
    }))
}
fn warm(run: RunKey, observation: u64) -> Result<(), Error> {
    let at = now();
    let work = with(|s| {
        if s.warm.is_none() && at < observation.saturating_sub(50_000_000) && at >= s.warm_at && s.next_warm < 240 {
            let id = s.next_warm; s.next_warm += 1; s.warm = Some(Warm { id, submitted: false });
        } Ok(s.warm)
    })?;
    if let Some(w) = work {
        if !w.submitted {
            match peer::submit_work(run, w.id) { Ok(()) => with(|s| { s.warm.as_mut().ok_or(Error::Stale)?.submitted = true; Ok(()) })?,
                Err(e) if transient(e) => return Ok(()), Err(e) => return Err(e) }
        }
        if peer::work_result(run, w.id)?.is_some() { with(|s| { s.warm = None; s.warm_at = at.saturating_add(100_000_000); Ok(()) })?; }
    } Ok(())
}
pub fn poll(run: RunKey) -> Result<bool, Error> { owner()?;
    let (p, scope, activated) = with(|s| { if s.run != Some(run) { return Err(Error::Stale); }
        Ok((s.prepared.ok_or(Error::NotReady)?, s.scope.ok_or(Error::NotReady)?, s.activated)) })?;
    if !activated { activate(run, scope.observation_ns)?; }
    if placement(p.family) { let _ = crate::learning_prewarm::poll(run)?; }
    else { warm(run, scope.observation_ns)?; }
    for _ in 0..8 {
        let i = with(|s| Ok(s.rows.iter().position(|r| !r.armed)))?; let Some(i) = i else { break; };
        evidence::arm_scheduled(evidence::request(OWNER, i as u64 + 1).map_err(native)?).map_err(native)?;
        with(|s| { s.rows[i].armed = true; Ok(()) })?;
    }
    evidence::measure(OWNER, CpuClass::ExecutorWork, || -> Result<(), Error> {
        let mut issued = 0;
        for i in 0..REQUESTS {
            let row = with(|s| Ok(s.rows[i]))?; let id = i as u64 + 1;
            let release = scope.observation_ns.checked_add(p.requests[i].offset_ns).ok_or(Error::Overflow)?;
            let deadline = release.checked_add(REQUEST_DEADLINE_NS).ok_or(Error::Overflow)?;
            if row.armed && row.phase == Phase::Queued && now() >= release {
                if placement(p.family) && id == 1 {
                    // Admission can already have happened in the actual
                    // publication path. Always query this original key.
                    with(|s| { s.rows[i].phase = Phase::Active; Ok(()) })?;
                } else if now() >= deadline {
                    with(|s| { s.rows[i].phase = Phase::Settled; s.rows[i].outcome = RequestResult::TimedOut; Ok(()) })?;
                } else {
                    let result = if placement(p.family) { crate::domain_tasks::replay::spawn(id, deadline) } else { peer::submit_work(run, id) };
                    match result {
                        Ok(()) => { with(|s| { s.rows[i].phase = Phase::Active; Ok(()) })?; issued += 1; },
                        Err(e) if transient(e) => {}, Err(e) => return Err(e),
                    }
                }
            }
            if with(|s| Ok(s.rows[i].phase == Phase::Active))? {
                if let Some(outcome) = business_result(run, p, id)? { with(|s| { s.rows[i].phase = Phase::Settled; s.rows[i].outcome = outcome; Ok(()) })?; }
            }
            if issued >= 4 { break; }
        }
        Ok(())
    })?;
    for _ in 0..8 {
        let item = with(|s| Ok(s.rows.iter().enumerate().find(|(_, r)| r.phase == Phase::Settled && !r.reported).map(|(i, r)| (i, r.outcome))))?;
        let Some((i, outcome)) = item else { break; };
        evidence::result(evidence::request(OWNER, i as u64 + 1).map_err(native)?, outcome).map_err(native)?;
        with(|s| { s.rows[i].reported = true; Ok(()) })?;
    }
    with(|s| Ok(s.rows.iter().all(|r| r.phase == Phase::Settled && r.reported) && s.warm.is_none()))
}
pub fn drain(run: RunKey) -> Result<bool, Error> { owner()?;
    if !poll(run)? { return Ok(false); }
    let (p, token) = with(|s| Ok((s.prepared.ok_or(Error::NotReady)?, s.token.ok_or(Error::NotReady)?)))?;
    if !placement(p.family) {
        let status = root::poll(token)?; let closing = status.closing.ok_or(Error::NotReady)?;
        let work = with(|s| {
            if closing.state != cyxia_prototype::policy::ExecutionState::Applied && s.closing.is_none() && s.closing_version != closing.stamp.version {
                if s.next_close >= 255 { return Err(Error::Capacity); }
                let id = s.next_close; s.next_close += 1; s.closing_version = closing.stamp.version;
                s.closing = Some(Warm { id, submitted: false });
            } Ok(s.closing)
        })?;
        if let Some(w) = work {
            if !w.submitted { match peer::submit_work(run, w.id) {
                Ok(()) => with(|s| { s.closing.as_mut().ok_or(Error::Stale)?.submitted = true; Ok(()) })?,
                Err(e) if transient(e) => return Ok(false), Err(e) => return Err(e),
            } }
            if peer::work_result(run, w.id)?.is_some() { with(|s| { s.closing = None; Ok(()) })?; }
            else { return Ok(false); }
        }
        if closing.state != cyxia_prototype::policy::ExecutionState::Applied { return Ok(false); }
    } else {
        if !crate::domain_tasks::replay::drain(run)? || !crate::domain_services::replay::drain(run)?
            || !crate::learning_prewarm::drain(run)? { return Ok(false); }
    }
    if !peer::close(run)? { return Ok(false); }
    with(|s| { s.drained_at.get_or_insert(now()); Ok(true) })
}
pub fn settled(run: RunKey) -> Result<(), Error> { with(|s| {
    if s.run != Some(run) || s.drained_at.is_none() || s.fault.is_some() || s.warm.is_some() || s.closing.is_some()
        || s.rows.iter().any(|r| r.phase != Phase::Settled || !r.reported) { return Err(Error::Busy); } Ok(())
}) }
pub fn release(run: RunKey) -> Result<(), Error> { owner()?; settled(run)?;
    // Keep the successful resource release and its retry marker in one owner
    // turn. A contended metadata lock must never make us release the same
    // already-retired run again, including the final peer handshake.
    with(|s| {
        if s.run != Some(run) { return Err(Error::Stale); }
        let p = s.prepared.ok_or(Error::NotReady)?;
        if placement(p.family) {
            if !s.tasks_released { crate::domain_tasks::replay::release(run)?; s.tasks_released = true; }
            if !s.services_released { crate::domain_services::replay::release(run)?; s.services_released = true; }
            if !s.prewarm_released { crate::learning_prewarm::release(run)?; s.prewarm_released = true; }
        }
        if !peer::release(run)? { return Err(Error::Again); }
        s.prepared = None; s.preparation = None; s.aborting = false; s.held_target = None;
        s.ready = false; s.token = None; s.scope = None; s.run = None; s.activated = false;
        s.activation_started = false; s.unactivated = None;
        s.tasks_active = false; s.prewarm = false; s.rows.fill(EMPTY); s.warm = None; s.next_warm = 101; s.warm_at = 0;
        s.closing = None; s.closing_version = 0; s.next_close = 241; s.drained_at = None; s.fault = None;
        s.tasks_released = false; s.services_released = false; s.prewarm_released = false; Ok(()) })
}
pub fn abort_prepared(preparation: root::Preparation) -> Result<bool, Error> {
    owner()?;
    let target = with(|s| {
        if s.preparation != Some(preparation) || s.scope.is_some() || s.run.is_some()
            || s.activation_started || s.activated || s.tasks_active { return Err(Error::Stale); }
        s.aborting = true; Ok(s.held_target)
    })?;
    drain_inactive(preparation, target, None)
}
fn drain_inactive(preparation: root::Preparation, target: Option<ObjectKey>, scope: Option<&FrozenScope>) -> Result<bool, Error> {
    let mut drained = true;
    if placement(preparation.family) {
        drained &= crate::domain_tasks::replay::abort_prepared()?;
        drained &= crate::domain_services::replay::abort_prepared()?;
        if drained { drained &= crate::learning_prewarm::freeze_abort(preparation)?; }
        if let Some(target) = target { super::requests::cancel_reserved(OWNER, target)?; }
    }
    drained &= if let Some(scope) = scope { peer::abort_unactivated(preparation, scope)? }
        else { peer::abort_prepared(preparation)? };
    if drained { with(|s| { s.drained_at.get_or_insert(now()); Ok(()) })?; }
    Ok(drained)
}
pub fn settled_prepared(preparation: root::Preparation) -> Result<(), Error> {
    with(|s| {
        if s.preparation != Some(preparation) || s.scope.is_some() || s.run.is_some() { return Err(Error::Stale); }
        if !s.aborting || s.drained_at.is_none() || s.activation_started || s.tasks_active
            || s.warm.is_some() || s.closing.is_some() { return Err(Error::Busy); }
        Ok(())
    })
}
pub fn prepared_failure(preparation: root::Preparation) -> Result<crate::learning_workload::PreparedFailure, Error> {
    settled_prepared(preparation)?;
    with(|s| Ok(crate::learning_workload::PreparedFailure { target: s.prepared.map(|p| p.target).or(s.held_target),
        group: s.prepared.map(|p| p.group), queued_at: s.queued_at, fault: s.fault,
        drained_at: s.drained_at.ok_or(Error::NotReady)? }))
}
pub fn release_prepared(preparation: root::Preparation) -> Result<(), Error> {
    owner()?;
    if with(|s| Ok(s.preparation.is_none() && s.released_preparation == Some(preparation)))? { return Ok(()); }
    if !root::preparation_archived(preparation) { return Err(Error::Busy); }
    settled_prepared(preparation)?;
    with(|s| release_inactive(s, preparation))
}
fn release_inactive(s: &mut State, preparation: root::Preparation) -> Result<(), Error> {
        if placement(preparation.family) {
            if !s.tasks_released { crate::domain_tasks::replay::release_prepared()?; s.tasks_released = true; }
            if !s.services_released { crate::domain_services::replay::release_prepared()?; s.services_released = true; }
            if !s.prewarm_released { crate::learning_prewarm::release_prepared(preparation)?; s.prewarm_released = true; }
        }
        peer::release_prepared(preparation)?;
        s.prepared = None; s.preparation = None; s.released_preparation = Some(preparation); s.aborting = false; s.held_target = None;
        s.ready = false; s.token = None; s.scope = None; s.run = None; s.activated = false;
        s.activation_started = false; s.unactivated = None;
        s.tasks_active = false; s.prewarm = false; s.rows.fill(EMPTY); s.warm = None; s.next_warm = 101; s.warm_at = 0;
        s.closing = None; s.closing_version = 0; s.next_close = 241; s.drained_at = None; s.fault = None;
        s.tasks_released = false; s.services_released = false; s.prewarm_released = false; Ok(())
}
/// A real capture may exist even when its first callback never completed.
/// Keep that scope and its raw preparation history while draining only work
/// that was actually owned before activation; never synthesize a trial run.
pub fn abort_unactivated(preparation: root::Preparation, scope: &FrozenScope) -> Result<bool, Error> {
    owner()?;
    let target = with(|s| {
        let p = s.prepared.ok_or(Error::NotReady)?;
        if s.preparation != Some(preparation) || s.activation_started || s.activated || s.tasks_active
            || scope.family != p.family || scope.target != p.target || scope.group != p.group || scope.kind != s.kind
            || scope.key.boot_epoch != preparation.boot_epoch || scope.key.trial_id != preparation.trial_id
            || s.scope.is_some_and(|old| old != *scope) || s.run.is_some_and(|old| old != scope.key)
            || s.unactivated.is_some_and(|old| old != *scope)
            || s.rows.iter().any(|r| r.phase != Phase::Queued || r.armed || r.reported)
            || s.warm.is_some() || s.closing.is_some() { return Err(Error::Conflict); }
        s.scope = Some(*scope); s.run = Some(scope.key); s.unactivated = Some(*scope); s.aborting = true;
        Ok(s.held_target)
    })?;
    drain_inactive(preparation, target, Some(scope))
}
pub fn settled_unactivated(preparation: root::Preparation, scope: &FrozenScope) -> Result<(), Error> {
    with(|s| {
        if s.preparation != Some(preparation) || s.scope != Some(*scope) || s.unactivated != Some(*scope)
            || s.run != Some(scope.key) { return Err(Error::Stale); }
        if !s.aborting || s.drained_at.is_none() || s.activation_started || s.activated || s.tasks_active
            || s.rows.iter().any(|r| r.phase != Phase::Queued || r.armed || r.reported)
            || s.warm.is_some() || s.closing.is_some() { return Err(Error::Busy); }
        Ok(())
    })
}
pub fn release_unactivated(preparation: root::Preparation, scope: &FrozenScope) -> Result<(), Error> {
    owner()?;
    if !root::preparation_archived(preparation) { return Err(Error::Busy); }
    settled_unactivated(preparation, scope)?;
    with(|s| release_inactive(s, preparation))
}
pub fn quiescent() -> bool { with(|s| Ok(s.token.is_none() && s.scope.is_none() && !s.prewarm && !s.tasks_active)).unwrap_or(false) }
pub fn outside_source(run: RunKey, key: ObjectKey, class: CpuClass) -> Result<bool, learning::Error> {
    let valid = with(|s| Ok(s.scope.is_some_and(|scope| scope.key == run))).map_err(learn)?;
    if !valid { return Err(learning::Error::Stale); }
    if crate::domain_tasks::replay::outside_source(key, class).map_err(learn)? { return Ok(true); }
    crate::domain_services::replay::outside_source(key, class).map_err(learn)
}
pub(crate) fn schedule_check(run: RunKey, owner: ObjectKey, id: u64, release: u64) -> Result<u64, learning::Error> {
    with(|s| { let p = s.prepared.ok_or(Error::NotReady)?; let scope = s.scope.ok_or(Error::NotReady)?;
        let i = id.checked_sub(1).filter(|i| *i < REQUESTS as u64).ok_or(Error::Range)? as usize;
        if owner != OWNER || scope.key != run || s.run != Some(run) || scope.observation_ns.checked_add(p.requests[i].offset_ns) != Some(release)
            || s.queued_at > release { return Err(Error::Conflict); } Ok(s.queued_at)
    }).map_err(learn)
}
fn frozen_token(scope: &FrozenScope) -> Result<root::Token, Error> {
    with(|s| { let p = s.prepared.ok_or(Error::NotReady)?;
        if s.scope != Some(*scope) || scope.family != p.family || scope.target != p.target || scope.group != p.group
            || s.queued_at > scope.first_ns || s.fault.is_some() { return Err(Error::Conflict); }
        s.token.ok_or(Error::NotReady)
    })
}
fn kind_token(run: RunKey, kind: TrialKind) -> Result<(root::Token, FrozenScope), Error> {
    with(|s| { let scope = s.scope.ok_or(Error::NotReady)?;
        if scope.key != run || scope.kind != kind { return Err(Error::Stale); }
        Ok((s.token.ok_or(Error::NotReady)?, scope)) })
}
fn check_frozen(scope: &FrozenScope) -> Result<(), learning::Error> {
    root::verify_scope(frozen_token(scope).map_err(learn)?, scope)
}
fn check_issued(run: RunKey, adoption: &Adoption<'_>) -> Result<(), learning::Error> {
    let (token, scope) = kind_token(run, TrialKind::Candidate).map_err(learn)?;
    check_frozen(&scope)?; root::verify_adoption(token, adoption)
}
fn check_baseline(run: RunKey, baseline: &BaselineAdoption) -> Result<(), learning::Error> {
    let (token, scope) = kind_token(run, TrialKind::Baseline).map_err(learn)?;
    check_frozen(&scope)?; root::verify_baseline(token, baseline)
}
fn closing_token(scope: &FrozenScope, trial: &Trial<'_>) -> Result<root::Token, Error> {
    with(|s| { let p = s.prepared.ok_or(Error::NotReady)?;
        if s.drained_at.is_none_or(|at| at > trial.closing_ns) || s.fault.is_some() || trial.requests.len() != REQUESTS || !trial.correct
            || trial.closing != cyxia_prototype::policy::ExecutionState::Applied { return Err(Error::Conflict); }
        for (i, request) in trial.requests.iter().enumerate() { let row = s.rows[i];
            if row.phase != Phase::Settled || !row.armed || !row.reported || request.id != p.requests[i].id
                || request.arrived_ns != scope.observation_ns + p.requests[i].offset_ns || request.result != match row.outcome {
                    RequestResult::Completed { finished_ns } if finished_ns > scope.observation_ns + 10_000_000_000 => RequestResult::Pending,
                    value => value,
                } { return Err(Error::Conflict); }
        } s.token.ok_or(Error::NotReady)
    })
}
fn closing_status(status: root::Status, trial: &Trial<'_>) -> Result<(), learning::Error> {
    if status.fault.is_some() || status.closing.is_none_or(|r| r.state != cyxia_prototype::policy::ExecutionState::Applied || r.observed_ns > trial.closing_ns) {
        return Err(learning::Error::Unknown);
    } Ok(())
}
fn check_closing(scope: &FrozenScope, trial: &Trial<'_>) -> Result<(), learning::Error> {
    check_frozen(scope)?;
    let token = closing_token(scope, trial).map_err(learn)?;
    closing_status(root::poll(token).map_err(learn)?, trial)
}
fn bounded_owner<T>(result: Result<T, Error>) -> Result<Option<T>, learning::Error> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Error::Busy) => Ok(None),
        Err(error) => Err(learn(error)),
    }
}
pub(crate) fn check_frozen_bounded(scope: &FrozenScope) -> Result<bool, learning::Error> {
    let Some(token) = bounded_owner(frozen_token(scope))? else { return Ok(false); };
    root::verify_scope_bounded(token, scope)
}
pub(crate) fn check_issued_bounded(run: RunKey, adoption: &Adoption<'_>) -> Result<bool, learning::Error> {
    let Some((token, scope)) = bounded_owner(kind_token(run, TrialKind::Candidate))? else { return Ok(false); };
    if !check_frozen_bounded(&scope)? { return Ok(false); }
    root::verify_adoption_bounded(token, adoption)
}
pub(crate) fn check_baseline_bounded(run: RunKey, baseline: &BaselineAdoption) -> Result<bool, learning::Error> {
    let Some((token, scope)) = bounded_owner(kind_token(run, TrialKind::Baseline))? else { return Ok(false); };
    if !check_frozen_bounded(&scope)? { return Ok(false); }
    root::verify_baseline_bounded(token, baseline)
}
pub(crate) fn check_closing_bounded(scope: &FrozenScope, trial: &Trial<'_>) -> Result<bool, learning::Error> {
    if !check_frozen_bounded(scope)? { return Ok(false); }
    let Some(token) = bounded_owner(closing_token(scope, trial))? else { return Ok(false); };
    let Some(status) = bounded_owner(root::poll(token))? else { return Ok(false); };
    // An actual failed/Unknown closing remains an evidence error; only an
    // unavailable gate above yields, and no retained receipt is reclassified.
    closing_status(status, trial)?;
    Ok(true)
}
