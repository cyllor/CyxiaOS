//! Ordinary, read-only CACP work used to measure CoreSet. The same isolated
//! EL0 program scores actual protected candidates; only the trial's first
//! candidate may publish a CoreSet action. Queue custody is independent of
//! that publication and every completion waits for real runtime retirement.
use super::*;
use crate::{
    control_pool as pool, learning_evidence as evidence,
    learning_history::{FrozenScope, TrialKind},
};
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use cyxia_prototype::{
    domains::tasks::ControlCredit,
    learning::{capture::RunKey, reward::CpuClass},
};

pub const CORE_OWNER: ObjectKey = ObjectKey {
    id: 0x5245_504c_434f,
    generation: 1,
};
const REQUESTS: usize = 100;
const META_PAGES: usize = 3;
pub const OWNED_BYTES: usize = META_PAGES * 4096;
const SECOND: u64 = 1_000_000_000;
const DEADLINE: u64 = 5 * SECOND;
#[derive(Clone, Copy)]
pub struct Image {
    pub target: ObjectKey,
    pub digest: [u8; 32],
}
/// Constructed only after the exact scheduler credit was observed live.
pub struct PaidWorkWitness {
    credit: ControlCredit,
}
impl PaidWorkWitness {
    pub(crate) fn new(credit: ControlCredit) -> Result<Self, Error> {
        crate::domain_tasks::verify_control_credit(&credit)?;
        Ok(Self { credit })
    }
    pub fn core(&self) -> u16 {
        self.credit.cpu
    }
    pub fn credit(&self) -> &ControlCredit {
        &self.credit
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WorkId {
    serial: u64,
    slot: u16,
    warm: bool,
    primary: bool,
}
impl WorkId {
    pub(super) fn identity(self) -> [u64; 4] {
        [
            self.serial,
            u64::from(self.slot),
            u64::from(self.warm),
            u64::from(self.primary),
        ]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Queued,
    Running,
    Evaluated,
    Done,
}
#[derive(Clone, Copy)]
struct Row {
    phase: Phase,
    sequence: u64,
    cpu: u16,
    result: Option<Result<u64, Error>>,
    root_ns: u64,
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    completion_reported: bool,
}
impl Row {
    const EMPTY: Self = Self {
        phase: Phase::Queued,
        sequence: 0,
        cpu: 0,
        result: None,
        root_ns: 0,
        input_hash: [0; 32],
        output_hash: [0; 32],
        completion_reported: false,
    };
}
struct Queue {
    serial: u64,
    seed: u64,
    image: Option<Image>,
    model: ModelBinding,
    scope: Option<FrozenScope>,
    activated: bool,
    first: Option<u64>,
    stopped: bool,
    rows: [Row; REQUESTS],
    warm: Row,
    warm_serial: u16,
    warm_queued: bool,
    warm_at: u64,
    warm_release: u64,
    fault: Option<Error>,
}
impl Queue {
    const fn new() -> Self {
        Self {
            serial: 0,
            seed: 0,
            image: None,
            model: ModelBinding {
                generation: 0,
                model_hash: [0; 32],
                schema_hash: [0; 32],
            },
            scope: None,
            activated: false,
            first: None,
            stopped: false,
            rows: [Row::EMPTY; REQUESTS],
            warm: Row::EMPTY,
            warm_serial: 0,
            warm_queued: false,
            warm_at: 0,
            warm_release: 0,
            fault: None,
        }
    }
}
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
static QUEUE_GATE: AtomicBool = AtomicBool::new(false);
struct QueueGuard;
impl Drop for QueueGuard {
    fn drop(&mut self) {
        QUEUE_GATE.store(false, Ordering::Release);
    }
}
fn queue<T>(f: impl FnOnce(&mut Queue) -> Result<T, Error>) -> Result<T, Error> {
    QUEUE_GATE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = QueueGuard;
    let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 {
        return Err(Error::NotReady);
    }
    f(unsafe { &mut *(base as *mut Queue) })
}
fn cpu0() -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    crate::domain_tasks::authorize_service_turn()
}
fn relative(id: u64) -> Result<u64, Error> {
    if !(1..=REQUESTS as u64).contains(&id) {
        return Err(Error::Range);
    }
    Ok(((id - 1) / 10) * SECOND + ((id - 1) % 10) * 1000)
}
pub fn request_digest(seed: u64, id: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYXIA_CORESET_CACP_WORK_1.3\0");
    h.update(seed.to_le_bytes());
    h.update(id.to_le_bytes());
    h.update(relative(id).unwrap_or(u64::MAX).to_le_bytes());
    h.update(DEADLINE.to_le_bytes());
    h.update(
        b"actual-protected-candidates;isolated-full-mlp;root-checked-no-background-publication\0",
    );
    h.finalize().into()
}
pub fn prepare(seed: u64) -> Result<Image, Error> {
    cpu0()?;
    if ADDRESS.load(Ordering::Acquire) == 0 {
        QUEUE_GATE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        let _guard = QueueGuard;
        let setup = unsafe { &mut *SETUP.0.get() };
        if setup.allocation.is_none() {
            setup.allocation = Some(pool::allocate(CORE_OWNER, META_PAGES)?);
        }
        let allocation = setup.allocation.ok_or(Error::NotReady)?;
        if setup.pin.is_none() {
            setup.pin = Some(pool::pin(allocation)?);
        }
        let base = pool::span(allocation)?.0;
        unsafe {
            core::ptr::write(base as *mut Queue, Queue::new());
        }
        ADDRESS.store(base, Ordering::Release);
    }
    let (target, model) = super::with(|s| {
        let f = s.owner.families[1].ok_or(Error::NotReady)?;
        Ok((
            (f.target)(1, 2, 0).ok_or(Error::NotReady)?,
            s.registry.model(),
        ))
    })?;
    queue(|q| {
        if let Some(image) = q.image {
            return if q.seed == seed && image.target == target && q.model == model {
                Ok(image)
            } else {
                Err(Error::Conflict)
            };
        }
        q.serial = q.serial.checked_add(1).ok_or(Error::Overflow)?;
        q.seed = seed;
        q.model = model;
        let mut h = Sha256::new();
        h.update(b"CYXIA_EMPTY_REAL_CACP_QUEUE_1.3\0");
        h.update(target.id.to_le_bytes());
        h.update(target.generation.to_le_bytes());
        h.update(model.generation.to_le_bytes());
        h.update(model.model_hash);
        h.update(model.schema_hash);
        h.update(seed.to_le_bytes());
        h.update(b"100-owned-relative-arrivals;no-running-context;no-outstanding-output\0");
        let image = Image {
            target,
            digest: h.finalize().into(),
        };
        q.image = Some(image);
        Ok(image)
    })
}
pub fn bind_scope(scope: &FrozenScope) -> Result<(), Error> {
    queue(|q| {
        if q.image.is_none_or(|i| i.target != scope.target)
            || q.seed != scope.group.seed
            || scope.family != (learning::Family { domain: 1, kind: 2 })
            || q.first != Some(scope.first_ns)
            || scope.first_ns != scope.observation_ns
            || q.scope.is_some_and(|old| old != *scope)
        {
            return Err(Error::Stale);
        }
        q.scope = Some(*scope);
        Ok(())
    })
}
pub fn activate(run: RunKey) -> Result<(), Error> {
    cpu0()?;
    queue(|q| {
        if q.stopped {
            return Err(Error::Conflict);
        }
        if q.scope.is_none_or(|s| s.key != run) {
            return Err(Error::Stale);
        }
        q.activated = true;
        Ok(())
    })
}
pub fn prewarm_step(seed: u64) -> Result<(), Error> {
    cpu0()?;
    queue(|q| {
        if q.image.is_none() || q.seed != seed || q.scope.is_some() {
            return Err(Error::Stale);
        }
        if q.stopped || q.first.is_some() || !crate::learning_prewarm::active() {
            return Ok(());
        }
        let due =
            q.warm_queued && q.warm.phase == Phase::Done || !q.warm_queued && now() >= q.warm_at;
        if !due {
            return Ok(());
        }
        let Some(mut attempt) = crate::learning_prewarm::attempt_service() else {
            return Err(Error::Busy);
        };
        let first = now();
        if q.warm_queued && q.warm.phase == Phase::Done {
            q.warm_queued = false;
            q.warm_at = now().saturating_add(60_000_000);
        }
        if !q.warm_queued && now() >= q.warm_at {
            q.warm_serial = q.warm_serial.checked_add(1).ok_or(Error::Capacity)?;
            q.warm = Row::EMPTY;
            q.warm_queued = true;
            q.warm_release = now();
        }
        crate::learning_prewarm::finish(&mut attempt, first, now())
    })
}
pub fn freeze(first_ns: u64) -> Result<(), Error> {
    queue(|q| {
        if q.first == Some(first_ns) {
            return Ok(());
        }
        if q.first.is_some() || q.scope.is_some() || q.stopped {
            return Err(Error::Stale);
        }
        if q.warm_queued && q.warm.phase != Phase::Done {
            return Err(Error::Busy);
        }
        crate::learning_prewarm::freeze(first_ns)?;
        q.first = Some(first_ns);
        q.warm_queued = false;
        Ok(())
    })
}
pub fn submit(id: u64, release: u64, deadline: u64) -> Result<(), Error> {
    cpu0()?;
    queue(|q| {
        let scope = q.scope.ok_or(Error::NotReady)?;
        if !q.activated
            || release
                != scope
                    .observation_ns
                    .checked_add(relative(id)?)
                    .ok_or(Error::Overflow)?
            || deadline != release.checked_add(DEADLINE).ok_or(Error::Overflow)?
        {
            return Err(Error::Stale);
        }
        Ok(()) // The complete queue was already owned before its frozen release.
    })
}
pub fn result(id: u64) -> Result<Option<Result<u64, Error>>, Error> {
    relative(id)?;
    queue(|q| {
        let row = &q.rows[id as usize - 1];
        Ok((row.phase == Phase::Done).then_some(row.result).flatten())
    })
}
fn expire(q: &mut Queue) -> Result<(), Error> {
    let Some(scope) = q.scope else {
        return Ok(());
    };
    for (i, row) in q.rows.iter_mut().enumerate() {
        if row.phase == Phase::Queued
            && now() >= scope.observation_ns + relative(i as u64 + 1)? + DEADLINE
        {
            row.phase = Phase::Done;
            row.result = Some(Err(Error::Expired));
        }
    }
    Ok(())
}
pub fn drain() -> Result<bool, Error> {
    cpu0()?;
    queue(|q| {
        expire(q)?;
        Ok(q.rows.iter().all(|r| r.phase == Phase::Done)
            && (!q.warm_queued || q.warm.phase == Phase::Done))
    })
}
pub fn release(run: RunKey) -> Result<(), Error> {
    cpu0()?;
    queue(|q| {
        if q.scope.is_none_or(|s| s.key != run)
            || !q.rows.iter().all(|r| r.phase == Phase::Done)
            || q.warm_queued && q.warm.phase != Phase::Done
        {
            return Err(Error::Busy);
        }
        let serial = q.serial;
        *q = Queue::new();
        q.serial = serial;
        Ok(())
    })
}
pub fn abort_prepared() -> Result<bool, Error> {
    cpu0()?;
    if ADDRESS.load(Ordering::Acquire) == 0 {
        return Ok(true);
    }
    queue(|q| {
        if q.scope.is_some() {
            return Err(Error::Conflict);
        }
        q.stopped = true;
        if q.warm_queued && q.warm.phase == Phase::Queued {
            q.warm.phase = Phase::Done;
            q.warm.result = Some(Err(Error::Again));
        }
        Ok(!q.warm_queued || q.warm.phase == Phase::Done)
    })
}
pub fn release_prepared() -> Result<(), Error> {
    cpu0()?;
    if ADDRESS.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    queue(|q| {
        if q.scope.is_some() || !q.stopped || q.warm_queued && q.warm.phase != Phase::Done {
            return Err(Error::Busy);
        }
        let serial = q.serial;
        *q = Queue::new();
        q.serial = serial;
        Ok(())
    })
}
/// Negative closure after a real capture was opened but before the queue was
/// activated. Scope metadata is retained; no evaluated or running request can
/// be reclassified as an unstarted preparation.
pub fn abort_unactivated(scope: &FrozenScope) -> Result<bool, Error> {
    cpu0()?;
    queue(|q| {
        if q.activated
            || q.image.is_none_or(|i| i.target != scope.target)
            || q.seed != scope.group.seed
            || q.first != Some(scope.first_ns)
            || q.scope.is_some_and(|old| old != *scope)
            || scope.family != (learning::Family { domain: 1, kind: 2 })
            || q.rows
                .iter()
                .any(|row| row.phase != Phase::Queued || row.sequence != 0)
        {
            return Err(Error::Conflict);
        }
        q.scope = Some(*scope);
        q.stopped = true;
        Ok(!q.warm_queued || q.warm.phase == Phase::Done)
    })
}
pub fn release_unactivated(run: RunKey) -> Result<(), Error> {
    cpu0()?;
    queue(|q| {
        if q.activated
            || !q.stopped
            || q.scope.is_none_or(|scope| scope.key != run)
            || q.rows
                .iter()
                .any(|row| row.phase != Phase::Queued || row.sequence != 0)
            || q.warm_queued && q.warm.phase != Phase::Done
        {
            return Err(Error::Busy);
        }
        let serial = q.serial;
        *q = Queue::new();
        q.serial = serial;
        Ok(())
    })
}
fn row_mut(q: &mut Queue, id: WorkId) -> Result<&mut Row, Error> {
    if id.serial != q.serial || q.image.is_none() {
        return Err(Error::Stale);
    }
    if id.warm {
        if !q.warm_queued || id.slot != q.warm_serial {
            return Err(Error::Stale);
        }
        Ok(&mut q.warm)
    } else {
        q.rows.get_mut(usize::from(id.slot)).ok_or(Error::Range)
    }
}
pub(super) fn primary(set: &CandidateSet) -> Result<Option<WorkId>, Error> {
    if set
        .get(0)
        .is_none_or(|c| !matches!(c.action, Action::ControlSet(_)))
        || ADDRESS.load(Ordering::Acquire) == 0
    {
        return Ok(None);
    }
    queue(|q| {
        let Some(scope) = q.scope else {
            return Ok(None);
        };
        if scope.kind != TrialKind::Candidate
            || scope.target != set.target
            || scope.first_ns != set.snapshot.taken_ns
        {
            return Ok(None);
        }
        if q.rows[0].phase != Phase::Queued {
            return Err(Error::Busy);
        }
        Ok(Some(WorkId {
            serial: q.serial,
            slot: 0,
            warm: false,
            primary: true,
        }))
    })
}
fn selected() -> Result<Option<WorkId>, Error> {
    if ADDRESS.load(Ordering::Acquire) == 0 {
        return Ok(None);
    }
    queue(|q| {
        if q.image.is_none() || q.stopped || q.fault.is_some() {
            return Ok(None);
        }
        if q.scope.is_none() {
            return Ok(
                (q.first.is_none() && q.warm_queued && q.warm.phase == Phase::Queued).then_some(
                    WorkId {
                        serial: q.serial,
                        slot: q.warm_serial,
                        warm: true,
                        primary: false,
                    },
                ),
            );
        }
        if !q.activated {
            return Ok(None);
        }
        expire(q)?;
        let scope = q.scope.ok_or(Error::NotReady)?;
        if scope.kind == TrialKind::Candidate && q.rows[0].phase != Phase::Done {
            return Ok(None);
        }
        let start = usize::from(scope.kind == TrialKind::Candidate);
        for i in start..REQUESTS {
            if q.rows[i].phase == Phase::Queued
                && now() >= scope.observation_ns + relative(i as u64 + 1)?
            {
                return Ok(Some(WorkId {
                    serial: q.serial,
                    slot: i as u16,
                    warm: false,
                    primary: false,
                }));
            }
        }
        Ok(None)
    })
}
pub(super) fn bind(
    id: WorkId,
    sequence: u64,
    cpu: usize,
    input_hash: [u8; 32],
) -> Result<(), Error> {
    queue(|q| {
        let row = row_mut(q, id)?;
        if row.phase != Phase::Queued || !matches!(cpu, 1 | 2) {
            return Err(Error::Stale);
        }
        row.sequence = sequence;
        row.cpu = cpu as u16;
        row.input_hash = input_hash;
        row.phase = Phase::Running;
        Ok(())
    })
}
pub(super) fn reject_preparation(
    identity: [u64; 4],
    sequence: u64,
    error: Error,
    at: u64,
) -> Result<(), Error> {
    let id = WorkId {
        serial: identity[0],
        slot: u16::try_from(identity[1]).map_err(|_| Error::Range)?,
        warm: identity[2] != 0,
        primary: identity[3] != 0,
    };
    queue(|q| {
        let row = row_mut(q, id)?;
        if row.phase == Phase::Done {
            return Err(Error::Stale);
        }
        if row.phase != Phase::Queued {
            return Err(Error::Busy);
        }
        row.sequence = sequence;
        row.cpu = cyxia_arch_aarch64::cpu::slot() as u16;
        row.root_ns = at;
        row.result = Some(Err(error));
        row.phase = Phase::Done;
        Ok(())
    })
}
pub(super) fn evaluated(
    id: WorkId,
    sequence: u64,
    result: Result<u64, Error>,
    output_hash: [u8; 32],
) -> Result<(), Error> {
    queue(|q| {
        let row = row_mut(q, id)?;
        if row.sequence != sequence || row.cpu as usize != cyxia_arch_aarch64::cpu::slot() {
            return Err(Error::Auth);
        }
        if row.phase == Phase::Evaluated {
            return if row.output_hash == output_hash
                && row.result.map(|value| value.map(|_| ())) == Some(result.map(|_| ()))
            {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        if row.phase != Phase::Running {
            return Err(Error::Stale);
        }
        row.root_ns = now();
        row.output_hash = output_hash;
        row.result = Some(result.map(|_| row.root_ns));
        row.phase = Phase::Evaluated;
        Ok(())
    })
}
pub(crate) fn report_completed(id: WorkId, witness: &PaidWorkWitness) -> Result<(), Error> {
    queue(|q| {
        let row = row_mut(q, id)?;
        if row.phase != Phase::Evaluated || row.cpu != witness.core() {
            return Err(Error::Stale);
        }
        if !row.completion_reported && id.warm && row.result.is_some_and(|v| v.is_ok()) {
            crate::learning_prewarm::completed_control(witness)?;
        }
        row.completion_reported = true;
        Ok(())
    })
}
pub(crate) fn retired(id: WorkId) -> Result<(), Error> {
    queue(|q| {
        let row = row_mut(q, id)?;
        if row.phase != Phase::Evaluated
            || row.cpu as usize != cyxia_arch_aarch64::cpu::slot()
            || id.warm && row.result.is_some_and(|v| v.is_ok()) && !row.completion_reported
        {
            return Err(Error::Busy);
        }
        row.result = row.result.map(|value| value.map(|_| now()));
        row.phase = Phase::Done;
        Ok(())
    })
}
pub(crate) struct Measurement {
    first: u64,
    last: Option<u64>,
    captured: Option<evidence::OwnerAttempt>,
    warm: Option<crate::learning_prewarm::Attempt>,
}
impl Measurement {
    pub(crate) fn new(source: JobSource, witness: &PaidWorkWitness) -> Result<Self, Error> {
        if usize::from(witness.core()) != cyxia_arch_aarch64::cpu::slot() {
            return Err(Error::Auth);
        }
        let warm_work = source.work.is_some_and(|w| w.warm);
        let warm = if warm_work {
            Some(crate::learning_prewarm::attempt_control(witness).ok_or(Error::Busy)?)
        } else {
            None
        };
        let captured = if warm_work {
            None
        } else {
            evidence::attempt(source.owner, source.class).map_err(|_| Error::Busy)?
        };
        Ok(Self {
            first: now(),
            last: None,
            captured,
            warm,
        })
    }
    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        let last = *self.last.get_or_insert_with(now);
        if let Some(capture) = self.captured.as_mut() {
            if evidence::finish_attempt(capture, self.first, last) == Err(evidence::Error::Busy) {
                return Err(Error::Busy);
            }
            // A terminal collector error already retains a missing interval;
            // dropping its original token cannot turn it into valid evidence.
            self.captured = None;
        }
        if let Some(warm) = self.warm.as_mut() {
            let result = crate::learning_prewarm::finish(warm, self.first, last);
            if result == Err(Error::Busy) {
                return result;
            }
            self.warm = None;
            result?;
        }
        Ok(())
    }
}
impl Drop for Measurement {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

// Keep read-only scratch out of the dispatcher that also invokes next_normal.
#[inline(never)]
pub(super) fn next(
    s: &mut State,
    controller: u64,
    witness: &PaidWorkWitness,
    started: u64,
    input: &mut [u64; 512],
) -> Result<bool, Error> {
    let Some(id) = selected()? else {
        if s.preparation.is_some() {
            return Err(Error::Stale);
        }
        return Ok(false);
    };
    let source = JobSource {
        owner: CORE_OWNER,
        class: CpuClass::ExecutorWork,
        work: Some(id),
    };
    let _measurement = Measurement::new(source, witness)?;
    let f = s.owner.families[1].ok_or(Error::NotReady)?;
    let (target, model) = queue(|q| Ok((q.image.ok_or(Error::NotReady)?.target, q.model)))?;
    if s.registry.model() != model {
        return Err(Error::Stale);
    }
    let fresh_snapshot = Snapshot {
        sequence: match s.preparation {
            Some(pending) => pending.identity.sequence,
            None => s.sequence.checked_add(1).ok_or(Error::Overflow)?,
        },
        taken_ns: started,
        ledger_generation: s.owner.context.ledger_generation,
        core_generation: s.owner.context.core_generation,
    };
    let identity = preparation_identity(
        s,
        controller,
        1,
        2,
        target,
        fresh_snapshot.sequence,
        Some(id),
    );
    let snapshot = preparation_snapshot(s, identity, fresh_snapshot)?;
    let current = (f.current)(1, 2, target)?;
    let observed = (f.observe)(1, target)?;
    let (options, count) = tiers(current);
    let mut choices = [Candidate {
        action: current,
        features: RawFeatures::default(),
    }; 32];
    let mut n = 0;
    let queued = match queued_control_wcet_us(s, 1, started) {
        Ok(value) => value,
        Err(error @ (Error::Busy | Error::Again | Error::NotReady)) => {
            if s.preparation.is_none() {
                preparation::next_sequence(s.sequence, identity)?;
                s.sequence = identity.sequence;
                s.preparation = Some(preparation::Pending::new(
                    identity,
                    snapshot,
                    1,
                    s.cursor[1],
                ));
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    for action in options[..count].iter().flatten().copied() {
        match (f.legal)(action, target, started) {
            Ok(()) => {}
            Err(Error::Busy | Error::Again | Error::NotReady) => return Ok(false),
            Err(_) => continue,
        }
        let Action::ControlSet(mask) = action else {
            return Err(Error::Schema);
        };
        let cores = u64::from(mask.count_ones());
        if cores == 0 {
            return Err(Error::Range);
        }
        let mut target_features = (f.target_features)(action, target)?;
        target_features.values[2] = Some(queued.div_ceil(cores));
        let mut common = s.owner.context.common;
        common[2] = queued / 2500;
        common[6] = 0;
        choices[n] = Candidate {
            action,
            features: RawFeatures {
                common,
                domain: observed.values,
                domain_present: observed.present,
                target: target_features,
                control_capacity: Some(cores * 1000),
            },
        };
        n += 1;
    }
    if n == 0 {
        return Ok(false);
    }
    let set = CandidateSet::new(snapshot, target, model, &choices[..n], Some(current))?;
    encode_job(
        s,
        controller,
        started,
        snapshot,
        &set,
        current,
        [None; 2],
        Some(id),
        true,
        input,
    )
    .map(|()| true)
}
const _: () = assert!(core::mem::size_of::<Queue>() <= META_PAGES * 4096);
