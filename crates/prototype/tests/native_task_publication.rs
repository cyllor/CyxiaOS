//! The production task publication guard, actual Scheduler reservations and
//! the real Registry. The small native facade exposes only D01 plus CPU0's
//! mechanism thread; no scripted policy result or fake execution receipt is
//! used to reproduce the C-worker/Registry race.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{
        Action, Error, ObjectKey, POLICY_NS, WINDOW_NS,
        tasks::{ControlCredit, CpuLayout, Dispatch, Scheduler, ThreadSpec},
    },
    policy::{
        self, Clock, ExecutionState, Executor, ModelBinding, PlanId, Publisher, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use std::sync::{Mutex, mpsc};

#[path = "../../../kernel/src/domain_tasks/publication.rs"]
mod publication;
#[path = "../../../kernel/src/domain_tasks/service_authority.rs"]
mod service_authority;
mod domain_control {
    pub use cyxia_prototype::policy::Prerequisite;
}
mod cpu {
    std::thread_local! { static SLOT: core::cell::Cell<usize> = const { core::cell::Cell::new(0) }; }
    pub fn slot() -> usize {
        SLOT.with(core::cell::Cell::get)
    }
    pub fn set(value: usize) {
        SLOT.with(|v| v.set(value));
    }
}
const LAYOUT: CpuLayout = CpuLayout {
    business_mask: 9,
    healthy_mask: 15,
    generation: 1,
};
const TARGET: ObjectKey = ObjectKey {
    id: 12,
    generation: 1,
};
const SERVICE: ObjectKey = ObjectKey {
    id: 0x101,
    generation: 1,
};
static SERIAL: Mutex<()> = Mutex::new(());
static LOCK: AtomicBool = AtomicBool::new(false);
static NOW: AtomicU64 = AtomicU64::new(0);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.store(false, Ordering::Release);
    }
}
struct State {
    scheduler: Scheduler,
    service: Option<Dispatch>,
}
static mut STATE: State = State {
    scheduler: Scheduler::new(),
    service: None,
};
fn now_ns() -> u64 {
    NOW.load(Ordering::Acquire)
}
fn lock() -> Result<Guard, Error> {
    LOCK.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    Ok(Guard)
}
// This facade controls the Registry race with bare exclusion; the actual
// native handoff/guard and publication acquisition execute in the separate
// task_owner_handoff host harness.
fn acquire_guard() -> Result<Guard, Error> {
    lock()
}
fn reset(service_started: u64) {
    assert!(!LOCK.load(Ordering::Acquire));
    cpu::set(0);
    let _guard = lock().unwrap();
    let s = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    *s = State {
        scheduler: Scheduler::new(),
        service: None,
    };
    s.scheduler.register_group(TARGET).unwrap();
    s.scheduler
        .register_group(ObjectKey {
            id: 14,
            generation: 1,
        })
        .unwrap();
    s.scheduler
        .admit(
            ThreadSpec {
                key: SERVICE,
                group: ObjectKey {
                    id: 14,
                    generation: 1,
                },
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 20_000_000,
                budget_ns: 60_000_000,
            },
            LAYOUT,
            service_started,
        )
        .unwrap();
    s.service = s
        .scheduler
        .dispatch(0, LAYOUT, service_started, 2_500_000)
        .unwrap();
    assert_eq!(s.service.unwrap().reserved_ns, 2_500_000);
    NOW.store(service_started + 100, Ordering::Release);
}
fn service_witness_locked(s: &State) -> Result<(), Error> {
    service_authority::authorize(
        service_authority::View {
            cpu: cpu::slot(),
            held: s.service.ok_or(Error::NotReady)?,
            actual: s.scheduler.active(0),
            layout: LAYOUT,
            draining: 0,
            quarantine: s.scheduler.stats().quarantine_mask,
            kind: 5,
            published_credit_ns: s.service.unwrap().reserved_ns,
            settlement_pending: false,
        },
        now_ns(),
    )
}
fn validate_locked(s: &State, action: Action, target: ObjectKey, at: u64) -> Result<(), Error> {
    action.validate()?;
    if !matches!(action, Action::CpuWeight(_)) {
        return Err(Error::Unsupported);
    }
    s.scheduler.weight(target, at)?;
    Ok(())
}
fn current_locked(s: &State, domain: u16, target: ObjectKey, at: u64) -> Result<Action, Error> {
    if domain != 1 {
        return Err(Error::Unsupported);
    }
    Ok(Action::CpuWeight(s.scheduler.weight(target, at)?))
}
fn scheduling_dependencies_locked(
    _: &State,
    target: ObjectKey,
) -> Result<[Option<domain_control::Prerequisite>; 2], Error> {
    assert_eq!(target, TARGET);
    Ok([None; 2])
}
fn service_endpoints_locked(_: &State, _: ObjectKey) -> Result<[ObjectKey; 2], Error> {
    Err(Error::Unsupported)
}
fn legacy_validate(action: Action, target: ObjectKey, at: u64) -> Result<(), Error> {
    let _guard = lock()?;
    validate_locked(unsafe { &*core::ptr::addr_of!(STATE) }, action, target, at)
}
fn legacy_authorize() -> Result<(), Error> {
    let _guard = lock()?;
    service_witness_locked(unsafe { &*core::ptr::addr_of!(STATE) })
}

fn publisher() -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: 9,
    }
}
fn model() -> ModelBinding {
    ModelBinding {
        generation: 1,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    }
}
fn identity() -> PlanId {
    PlanId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: 3,
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        sequence: 3,
        taken_ns: now_ns(),
        ledger_generation: 244,
        core_generation: 1,
    }
}
fn wire(registry: &mut Registry, snapshot: Snapshot, target: ObjectKey) -> Vec<u8> {
    let hash = registry
        .register_baseline(publisher(), snapshot, target, model(), Action::CpuWeight(1))
        .unwrap();
    let decision = Decision {
        action: Action::CpuWeight(1),
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: 9,
            decision_seq: 3,
            snapshot_seq: 3,
            target,
            ledger_generation: snapshot.ledger_generation,
            core_generation: snapshot.core_generation,
            expires_local_ns: snapshot.taken_ns + WINDOW_NS,
            model_hash: model().model_hash,
            candidate_set_hash: hash,
        },
    };
    let header = PlanHeader {
        plan_seq: 3,
        base_plan_version: registry.version(),
        active_model_generation: 1,
        controller_epoch: 9,
        snapshot_seq: 3,
        active_until_local_ns: snapshot.taken_ns + POLICY_NS,
    };
    let mut bytes = vec![0; 384];
    let n = policy_wire::encode_plan(header, &[decision], &mut bytes).unwrap();
    bytes.truncate(n);
    bytes
}
struct Scope {
    gate: Option<publication::BaselinePublication>,
    snapshot: Snapshot,
    target: ObjectKey,
    checks: usize,
    published: usize,
}
impl Scope {
    fn check_owner(&self, at: u64) -> Result<(), Error> {
        if let Some(g) = self.gate.as_ref() {
            g.validate(Action::CpuWeight(1), self.target, at)
        } else {
            legacy_validate(Action::CpuWeight(1), self.target, at)
        }
    }
}
impl Executor for Scope {
    fn authorize_baseline(
        &mut self,
        active: ModelBinding,
        set: &policy::RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        if active != model()
            || set.model != active
            || set.snapshot != self.snapshot
            || set.target != self.target
            || set.baseline_action() != Some(Action::CpuWeight(1))
        {
            return Err(Error::Auth);
        }
        Ok(())
    }
    fn check(&mut self, _: Decision, _: &policy::RegisteredSet, at: u64) -> Result<(), Error> {
        self.checks += 1;
        self.check_owner(at)
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, at: u64) -> Result<(), Error> {
        self.check_owner(at)
    }
    fn publish(&mut self, plan: &Plan, _: u64, _: u64) -> Result<(), Error> {
        if let Some(g) = self.gate.as_ref() {
            g.authorize_service_turn()?;
        } else {
            legacy_authorize()?;
        }
        assert_eq!(
            plan.header.active_until_local_ns,
            self.snapshot.taken_ns + POLICY_NS
        );
        self.published += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {}
}
struct FixedClock(u64);
impl Clock for FixedClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        let wall_ns = {
            NOW.store(self.0, Ordering::Release);
            self.0
        };
        publication_time(wall_ns)
    }
}
struct ScriptClock(std::collections::VecDeque<u64>);
impl Clock for ScriptClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        let wall_ns = {
            let at = self.0.pop_front().expect("unexpected Registry clock read");
            NOW.store(at, Ordering::Release);
            at
        };
        publication_time(wall_ns)
    }
}
struct NoClock;
impl Clock for NoClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        panic!("a retained Failed identity must not execute again")
    }
}

/// A real second CPU tries to reserve CACP credit while holding the native
/// task gate. If admitted, it keeps both obligations until explicitly settled.
struct Contender {
    release: mpsc::Sender<()>,
    join: Option<std::thread::JoinHandle<()>>,
    result: Result<ControlCredit, Error>,
}
impl Contender {
    fn start(at: u64) -> Self {
        let (released, receive_release) = mpsc::channel();
        let (ready, receive_ready) = mpsc::channel();
        let join = std::thread::spawn(move || {
            cpu::set(1);
            let guard = match lock() {
                Ok(g) => g,
                Err(e) => {
                    ready.send(Err(e)).unwrap();
                    return;
                }
            };
            let s = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
            let credit = s
                .scheduler
                .reserve_control(1, LAYOUT, at, 100_000)
                .unwrap()
                .unwrap();
            ready.send(Ok(credit)).unwrap();
            receive_release.recv().unwrap();
            s.scheduler.complete_control(credit, 100, at + 100).unwrap();
            drop(guard);
        });
        let result = receive_ready.recv().unwrap();
        Self {
            release: released,
            join: Some(join),
            result,
        }
    }
}
impl Drop for Contender {
    fn drop(&mut self) {
        let _ = self.release.send(());
        self.join.take().unwrap().join().unwrap();
    }
}
struct RacingClock {
    at: u64,
    contender: Option<Contender>,
}
impl Clock for RacingClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        let wall_ns = {
            if self.contender.is_none() {
                self.contender = Some(Contender::start(self.at));
            }
            NOW.store(self.at, Ordering::Release);
            self.at
        };
        publication_time(wall_ns)
    }
}

#[test]
fn the_old_reacquisition_race_is_a_real_immutable_failed_busy() {
    let _serial = SERIAL.lock().unwrap();
    reset(1_000_000);
    let original = snapshot();
    let mut registry = Registry::new(11, publisher(), model()).unwrap();
    let bytes = wire(&mut registry, original, TARGET);
    let mut scope = Scope {
        gate: None,
        snapshot: original,
        target: TARGET,
        checks: 0,
        published: 0,
    };
    legacy_validate(Action::CpuWeight(1), TARGET, original.taken_ns).unwrap();
    let mut clock = RacingClock {
        at: original.taken_ns,
        contender: None,
    };
    let failed = registry
        .submit_job(
            publisher(),
            &bytes,
            publication_time(original.taken_ns),
            original.taken_ns + 50_000_000,
            &mut clock,
            &mut scope,
        )
        .unwrap();
    assert!(clock.contender.as_ref().unwrap().result.is_ok());
    assert_eq!(failed.version, 0);
    assert_eq!(failed.state(), ExecutionState::Failed(Error::Busy));
    assert_eq!(scope.published, 0);
    drop(clock);
    NOW.store(original.taken_ns + 100, Ordering::Release);
    scope.gate = publication::reserve_baseline_publication(Action::CpuWeight(1), TARGET).unwrap();
    assert_eq!(
        registry.submit_job(
            publisher(),
            &bytes,
            publication_time(original.taken_ns),
            original.taken_ns + 50_000_000,
            &mut NoClock,
            &mut scope
        ),
        Ok(failed)
    );
    assert_eq!(scope.checks, 1);
    assert_eq!(scope.published, 0);
}

#[test]
fn reserved_task_owner_prevents_the_after_registration_cacp_race() {
    let _serial = SERIAL.lock().unwrap();
    reset(1_000_000);
    let original = snapshot();
    let gate = publication::reserve_baseline_publication(Action::CpuWeight(1), TARGET).unwrap();
    let mut registry = Registry::new(11, publisher(), model()).unwrap();
    let bytes = wire(&mut registry, original, TARGET);
    let mut scope = Scope {
        gate,
        snapshot: original,
        target: TARGET,
        checks: 0,
        published: 0,
    };
    let mut clock = RacingClock {
        at: original.taken_ns,
        contender: None,
    };
    let receipt = registry
        .submit_job(
            publisher(),
            &bytes,
            publication_time(original.taken_ns),
            original.taken_ns + 50_000_000,
            &mut clock,
            &mut scope,
        )
        .unwrap();
    assert_eq!(
        receipt.version, 1,
        "the original valid baseline must actually PUBLISH"
    );
    assert_eq!(receipt.state(), ExecutionState::Pending);
    assert_eq!(clock.contender.as_ref().unwrap().result, Err(Error::Busy));
    assert_eq!(scope.published, 1);
    assert_eq!(
        scope.gate.as_ref().unwrap().current(1, TARGET),
        Ok(Action::CpuWeight(1))
    );
    assert_eq!(
        scope
            .gate
            .as_ref()
            .unwrap()
            .prerequisites(Action::CpuWeight(1), TARGET),
        Ok([None; 2])
    );
    drop(clock);
    drop(scope);
    // Releasing the gate does not invent a control bill: the other CPU now
    // obtains and settles its own actual Scheduler reservation.
    assert!(Contender::start(original.taken_ns + 100).result.is_ok());
}

#[test]
fn a_busy_prepublication_gate_allocates_no_plan_and_preserves_the_snapshot() {
    let _serial = SERIAL.lock().unwrap();
    reset(1_000_000);
    let original = snapshot();
    let mut registry = Registry::new(11, publisher(), model()).unwrap();
    let contender = Contender::start(original.taken_ns);
    assert!(contender.result.is_ok());
    assert!(matches!(
        publication::reserve_baseline_publication(Action::CpuWeight(1), TARGET),
        Err(Error::Busy)
    ));
    assert_eq!(registry.query(publisher(), identity()), Err(Error::Stale));
    assert_eq!(registry.version(), 0);
    drop(contender);
    NOW.store(original.taken_ns + 100, Ordering::Release);
    let gate = publication::reserve_baseline_publication(Action::CpuWeight(1), TARGET).unwrap();
    let bytes = wire(&mut registry, original, TARGET);
    let mut scope = Scope {
        gate,
        snapshot: original,
        target: TARGET,
        checks: 0,
        published: 0,
    };
    let receipt = registry
        .submit_job(
            publisher(),
            &bytes,
            publication_time(original.taken_ns + 100),
            original.taken_ns + 50_000_000,
            &mut FixedClock(original.taken_ns + 100),
            &mut scope,
        )
        .unwrap();
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.id, identity());
    assert_eq!(scope.snapshot, original);
    assert_eq!(scope.published, 1);
}

#[test]
fn reservation_preserves_live_credit_target_and_publication_deadlines() {
    let _serial = SERIAL.lock().unwrap();
    for case in 0..3 {
        reset(1_000_000);
        if case == 0 {
            NOW.store(3_400_000, Ordering::Release);
        }
        let original = snapshot();
        let target = if case == 1 {
            ObjectKey {
                generation: 2,
                ..TARGET
            }
        } else {
            TARGET
        };
        let gate = publication::reserve_baseline_publication(Action::CpuWeight(1), target).unwrap();
        let mut registry = Registry::new(11, publisher(), model()).unwrap();
        let bytes = wire(&mut registry, original, target);
        let mut scope = Scope {
            gate,
            snapshot: original,
            target,
            checks: 0,
            published: 0,
        };
        let late = if case == 0 {
            3_500_001
        } else {
            original.taken_ns + 500_001
        };
        let times = [original.taken_ns, original.taken_ns, late, late, late, late];
        let mut clock = ScriptClock(times.into());
        let receipt = registry
            .submit_job(
                publisher(),
                &bytes,
                publication_time(original.taken_ns),
                original.taken_ns + 50_000_000,
                &mut clock,
                &mut scope,
            )
            .unwrap();
        assert_eq!(receipt.version, 0);
        assert_eq!(
            receipt.state(),
            ExecutionState::Failed(match case {
                0 => Error::Expired,
                1 => Error::Stale,
                _ => Error::Budget,
            })
        );
        assert_eq!(scope.published, 0);
        assert_eq!(scope.snapshot, original);
        assert_eq!(
            registry.submit_job(
                publisher(),
                &bytes,
                publication_time(original.taken_ns),
                original.taken_ns + 50_000_000,
                &mut NoClock,
                &mut scope
            ),
            Ok(receipt)
        );
        drop(scope);
        assert!(!LOCK.load(Ordering::Acquire));
    }
}

#[test]
fn a_new_service_turn_cannot_refresh_the_original_snapshot_wall_deadline() {
    let _serial = SERIAL.lock().unwrap();
    let original = Snapshot {
        sequence: 3,
        taken_ns: 1_000_100,
        ledger_generation: 244,
        core_generation: 1,
    };
    reset(original.taken_ns + 50_000_001);
    let actual_start = now_ns();
    let gate = publication::reserve_baseline_publication(Action::CpuWeight(1), TARGET).unwrap();
    let mut registry = Registry::new(11, publisher(), model()).unwrap();
    let bytes = wire(&mut registry, original, TARGET);
    let mut scope = Scope {
        gate,
        snapshot: original,
        target: TARGET,
        checks: 0,
        published: 0,
    };
    let receipt = registry
        .submit_job(
            publisher(),
            &bytes,
            publication_time(actual_start),
            original.taken_ns + 50_000_000,
            &mut FixedClock(actual_start),
            &mut scope,
        )
        .unwrap();
    assert_eq!(receipt.state(), ExecutionState::Failed(Error::Expired));
    assert_eq!(receipt.version, 0);
    assert_eq!(scope.checks, 0);
    assert_eq!(scope.published, 0);
    assert_eq!(scope.snapshot, original);
}

// Legacy fixtures deliberately advance execution and wall time together.
fn publication_time(wall_ns: u64) -> cyxia_prototype::policy::PublicationTime {
    cyxia_prototype::policy::PublicationTime {
        wall_ns,
        cpu: cyxia_prototype::policy::CpuTime {
            cpu: 0,
            ns: wall_ns,
        },
    }
}
