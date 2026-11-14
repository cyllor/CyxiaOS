//! Production CoreSet reservation, task Gate, service-credit predicate,
//! legality and Registry; host fixtures supply native State/CPU/clock only.
//! This is not a native capture, authority token or accepted training sample.
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::{
    domains::{
        Action, Error, ObjectKey, WINDOW_NS,
        tasks::{CpuLayout, Dispatch, Scheduler, ThreadSpec},
    },
    policy::{
        self, Clock, ExecutionState, Executor, ModelBinding, PlanId, Publisher, Registry, Snapshot,
    },
    policy_wire::{self, Decision, Envelope, Plan, PlanHeader},
};
use std::sync::Mutex;
#[path = "../../../kernel/src/runtime/tasks/domain_tasks/baseline_service_authority.rs"]
mod authority;
#[path = "../../../kernel/src/runtime/services/domain_services/core_set_legality.rs"]
mod legality;
#[path = "../../../kernel/src/runtime/tasks/domain_tasks/owner_gate.rs"]
mod owner_gate;
#[path = "../../../kernel/src/runtime/tasks/domain_tasks/service_authority.rs"]
mod service_authority;
static SERIAL: Mutex<()> = Mutex::new(());
static GATE: owner_gate::Gate = owner_gate::Gate::new();
static NOW: AtomicU64 = AtomicU64::new(1_000_100);
static USED: AtomicU64 = AtomicU64::new(100);
static ACQUIRES: AtomicUsize = AtomicUsize::new(0);
mod cpu {
    std::thread_local! {static SLOT:core::cell::Cell<usize>=const{core::cell::Cell::new(0)};}
    pub fn slot() -> usize {
        SLOT.with(core::cell::Cell::get)
    }
    pub fn set(slot: usize) {
        SLOT.with(|s| s.set(slot));
    }
}
mod domain_control {
    use super::*;
    #[derive(Clone, Copy, PartialEq)]
    pub enum TargetSource {
        Services,
        Tasks,
    }
    pub struct Family {
        pub domain: u16,
        pub kind: u16,
        pub target_source: TargetSource,
        pub target: fn(u16, u16, usize) -> Option<ObjectKey>,
        pub current: fn(u16, u16, ObjectKey) -> Result<Action, Error>,
        pub legal: fn(Action, ObjectKey, u64) -> Result<(), Error>,
        pub legal_options:
            fn(&[Option<Action>], ObjectKey, u64, &mut [Option<Action>]) -> Result<usize, Error>,
        pub target_features:
            fn(Action, ObjectKey) -> Result<cyxia_prototype::features::TargetFeatures, Error>,
        pub apply: fn(
            Action,
            cyxia_prototype::domains::ApplyId,
            cyxia_prototype::domains::PolicyStamp,
            u64,
        ) -> Result<ExecutionState, Error>,
        pub reconcile: fn(
            Action,
            cyxia_prototype::domains::ApplyId,
            cyxia_prototype::domains::PolicyStamp,
            u64,
        ) -> Result<ExecutionState, Error>,
    }
}
const KEY: ObjectKey = ObjectKey {
    id: 0x434f5245,
    generation: 1,
};
const LAYOUT: CpuLayout = CpuLayout {
    business_mask: 13,
    healthy_mask: 15,
    generation: 1,
};
struct State {
    scheduler: Scheduler,
    service: Option<Dispatch>,
    occupied: bool,
}
static mut STATE: State = State {
    scheduler: Scheduler::new(),
    service: None,
    occupied: false,
};
struct Guard(Option<owner_gate::Permit<'static>>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.take().unwrap().release(now_ns());
    }
}
fn now_ns() -> u64 {
    NOW.load(Ordering::Acquire)
}
fn acquire_guard() -> Result<Guard, Error> {
    ACQUIRES.fetch_add(1, Ordering::AcqRel);
    GATE.try_acquire(0, now_ns(), 1_000_000)
        .map(|g| Guard(Some(g)))
        .ok_or(Error::Busy)
}
fn service_witness_locked(s: &State) -> Result<(), Error> {
    if cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    let d = s.service.ok_or(Error::NotReady)?;
    service_authority::authorize(
        service_authority::View {
            cpu: 0,
            held: d,
            actual: s.scheduler.active(0),
            layout: LAYOUT,
            draining: 0,
            quarantine: s.scheduler.stats().quarantine_mask,
            kind: 5,
            published_credit_ns: d.reserved_ns,
            settlement_pending: false,
            execution_ns: Some(USED.load(Ordering::Acquire)),
        },
        now_ns(),
    )
}
fn can_control_move_locked(s: &State, slot: usize) -> Result<(), Error> {
    assert_eq!(slot, 2);
    if s.occupied {
        Err(Error::Budget)
    } else {
        Ok(())
    }
}
fn reset() {
    cpu::set(0);
    NOW.store(1_000_100, Ordering::Release);
    USED.store(100, Ordering::Release);
    let _g = acquire_guard().unwrap();
    let s = unsafe { &mut *core::ptr::addr_of_mut!(STATE) };
    *s = State {
        scheduler: Scheduler::new(),
        service: None,
        occupied: false,
    };
    let group = ObjectKey {
        id: 14,
        generation: 1,
    };
    s.scheduler.register_group(group).unwrap();
    s.scheduler
        .admit(
            ThreadSpec {
                key: ObjectKey {
                    id: 0x101,
                    generation: 1,
                },
                group,
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 20_000_000,
                budget_ns: 60_000_000,
            },
            LAYOUT,
            1_000_000,
        )
        .unwrap();
    s.service = s
        .scheduler
        .dispatch(0, LAYOUT, 1_000_000, 2_500_000)
        .unwrap();
    ACQUIRES.store(0, Ordering::Release);
}
fn view() -> legality::View {
    legality::View {
        key: KEY,
        generation: 1,
        control: 6,
        healthy: 15,
        draining: 0,
        business: 9,
        pending: false,
    }
}
fn check(g: &authority::CoreSetServiceAuthority, v: legality::View) -> Result<(), Error> {
    legality::check(v, 2, KEY, |slot| g.can_control_move(slot), |_| {})
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
fn snapshot() -> Snapshot {
    Snapshot {
        sequence: 3,
        taken_ns: now_ns(),
        ledger_generation: 244,
        core_generation: 1,
    }
}
fn identity() -> PlanId {
    PlanId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: 3,
    }
}
fn wire(r: &mut Registry, s: Snapshot) -> Vec<u8> {
    let hash = r
        .register_baseline(publisher(), s, KEY, model(), Action::ControlSet(2))
        .unwrap();
    let d = Decision {
        action: Action::ControlSet(2),
        candidate_index: 0,
        envelope: Envelope {
            controller_epoch: 9,
            decision_seq: 3,
            snapshot_seq: 3,
            target: KEY,
            ledger_generation: s.ledger_generation,
            core_generation: s.core_generation,
            expires_local_ns: s.taken_ns + WINDOW_NS,
            model_hash: model().model_hash,
            candidate_set_hash: hash,
        },
    };
    let h = PlanHeader {
        plan_seq: 3,
        base_plan_version: r.version(),
        active_model_generation: 1,
        controller_epoch: 9,
        snapshot_seq: 3,
        active_until_local_ns: 0,
    };
    let mut b = vec![0; 384];
    let n = policy_wire::encode_plan(h, &[d], &mut b).unwrap();
    b.truncate(n);
    b
}
struct Scope {
    guard: authority::CoreSetServiceAuthority,
    original: Snapshot,
    checks: usize,
    published: usize,
}
impl Executor for Scope {
    fn authorize_baseline(
        &mut self,
        m: ModelBinding,
        set: &policy::RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        if m != model()
            || set.snapshot != self.original
            || set.target != KEY
            || set.baseline_action() != Some(Action::ControlSet(2))
        {
            return Err(Error::Auth);
        }
        self.guard.authorize_service_turn()
    }
    fn check(&mut self, _: Decision, _: &policy::RegisteredSet, _: u64) -> Result<(), Error> {
        self.checks += 1;
        check(&self.guard, view())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.guard.authorize_service_turn()
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        check(&self.guard, view())
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.guard.authorize_service_turn()?;
        self.published += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {}
}
struct TestClock {
    expire_at_read: Option<usize>,
    reads: usize,
}
impl Clock for TestClock {
    fn read(&mut self) -> policy::PublicationTime {
        self.reads += 1;
        if self.expire_at_read == Some(self.reads) {
            USED.store(2_500_000, Ordering::Release);
        }
        policy::PublicationTime {
            wall_ns: now_ns(),
            cpu: policy::CpuTime { cpu: 0, ns: 100 },
        }
    }
}
fn time() -> policy::PublicationTime {
    policy::PublicationTime {
        wall_ns: now_ns(),
        cpu: policy::CpuTime { cpu: 0, ns: 100 },
    }
}

#[test]
fn held_gate_defers_before_any_registry_identity() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let r = Registry::new(11, publisher(), model()).unwrap();
    let held = acquire_guard().unwrap();
    assert!(matches!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2)),
        Err(Error::Busy)
    ));
    assert_eq!(r.version(), 0);
    assert!(matches!(
        r.query(publisher(), identity()),
        Err(Error::Stale)
    ));
    drop(held);
    assert!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2))
            .unwrap()
            .is_some()
    );
}
#[test]
fn retained_guard_runs_registry_and_repeated_checks_without_reacquiring() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let guard = authority::reserve_core_set_service_authority(Action::ControlSet(2))
        .unwrap()
        .expect("CoreSet must retain service gate before Registry");
    let acquires = ACQUIRES.load(Ordering::Acquire);
    let original = snapshot();
    let mut r = Registry::new(11, publisher(), model()).unwrap();
    let b = wire(&mut r, original);
    let mut s = Scope {
        guard,
        original,
        checks: 0,
        published: 0,
    };
    assert!(GATE.try_acquire(1, now_ns(), 1_000_000).is_none());
    let result = r
        .submit_job(
            publisher(),
            &b,
            time(),
            now_ns() + 50_000_000,
            &mut TestClock {
                expire_at_read: None,
                reads: 0,
            },
            &mut s,
        )
        .unwrap();
    assert!(result.version > 0);
    assert_eq!(s.published, 1);
    assert!(s.checks > 0);
    for _ in 0..3 {
        s.guard.authorize_service_turn().unwrap();
        check(&s.guard, view()).unwrap();
    }
    assert_eq!(ACQUIRES.load(Ordering::Acquire), acquires);
    drop(s);
    // Release exclusion even when the fairness policy subsequently prefers CPU0.
    GATE.try_acquire(0, now_ns(), 1_000_000)
        .unwrap()
        .release(now_ns());
}
#[test]
fn publish_rechecks_live_cpu_credit_and_releases_error_path() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let guard = authority::reserve_core_set_service_authority(Action::ControlSet(2))
        .unwrap()
        .unwrap();
    let original = snapshot();
    let mut r = Registry::new(11, publisher(), model()).unwrap();
    let b = wire(&mut r, original);
    let mut s = Scope {
        guard,
        original,
        checks: 0,
        published: 0,
    };
    let result = r
        .submit_job(
            publisher(),
            &b,
            time(),
            now_ns() + 50_000_000,
            &mut TestClock {
                expire_at_read: Some(4),
                reads: 0,
            },
            &mut s,
        )
        .unwrap();
    assert_eq!(result.version, 0);
    assert_eq!(result.state(), ExecutionState::Failed(Error::Budget));
    assert_eq!(s.published, 0);
    drop(s);
    USED.store(100, Ordering::Release);
    assert!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2))
            .unwrap()
            .is_some()
    );
}
#[test]
fn initial_bad_witness_releases_gate_without_admission() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    USED.store(2_500_000, Ordering::Release);
    assert!(matches!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2)),
        Err(Error::Budget)
    ));
    USED.store(100, Ordering::Release);
    assert!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2))
            .unwrap()
            .is_some()
    );
}
#[test]
fn reservation_does_not_claim_other_actions_or_move_other_cpu() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    assert!(
        authority::reserve_core_set_service_authority(Action::CpuWeight(1))
            .unwrap()
            .is_none()
    );
    let g = authority::reserve_core_set_service_authority(Action::ControlSet(6))
        .unwrap()
        .unwrap();
    assert_eq!(g.can_control_move(1), Err(Error::Auth));
    drop(g);
    cpu::set(1);
    assert!(
        authority::reserve_core_set_service_authority(Action::ControlSet(2))
            .unwrap()
            .is_none()
    );
    cpu::set(0);
}
#[test]
fn stale_time_is_not_authorized_by_a_retained_borrow() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let g = authority::reserve_core_set_service_authority(Action::ControlSet(2))
        .unwrap()
        .unwrap();
    NOW.store(100_000_000, Ordering::Release);
    assert_eq!(g.authorize_service_turn(), Err(Error::Expired));
    drop(g);
    // An earlier contender may own the next bounded handoff; test exclusion
    // release without assuming that fairness must prefer CPU0 again.
    GATE.try_acquire(1, now_ns(), 1_000_000)
        .expect("expired authority must release its gate to the queued peer")
        .release(now_ns());
}
#[test]
fn legal_order_keeps_mask_pending_and_real_task_refusals() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let calls = core::cell::Cell::new(0);
    let reason = core::cell::Cell::new(0);
    let can = |slot| {
        assert_eq!(slot, 2);
        calls.set(calls.get() + 1);
        Err(Error::Budget)
    };
    let mut v = view();
    v.generation = 0;
    assert_eq!(
        legality::check(v, 2, KEY, can, |r| reason.set(r)),
        Err(Error::Stale)
    );
    v = view();
    v.healthy = 2;
    assert_eq!(
        legality::check(v, 6, KEY, can, |r| reason.set(r)),
        Err(Error::Budget)
    );
    v = view();
    v.pending = true;
    assert_eq!(
        legality::check(v, 2, KEY, can, |r| reason.set(r)),
        Err(Error::Busy)
    );
    assert_eq!(reason.get(), 5);
    assert_eq!(calls.get(), 0);
    v = view();
    assert_eq!(
        legality::check(v, 2, KEY, can, |r| reason.set(r)),
        Err(Error::Budget)
    );
    assert_eq!(calls.get(), 1);
    // Unchanged control mask does not ask the task gate to move CPU2.
    v = view();
    assert_eq!(legality::check(v, 6, KEY, can, |r| reason.set(r)), Ok(()));
    assert_eq!(calls.get(), 1);
    assert_eq!(
        legality::check(view(), 2, KEY, |_| Err(Error::Busy), |r| reason.set(r)),
        Err(Error::Busy)
    );
    assert_eq!(reason.get(), 6);
}

// Registration fixtures identify the exact named callbacks without invoking
// them. A replacement's behavior is immaterial: it must not be substituted.
fn native_target(_: u16, _: u16, _: usize) -> Option<ObjectKey> {
    Some(KEY)
}
fn native_current(_: u16, _: u16, _: ObjectKey) -> Result<Action, Error> {
    Ok(Action::ControlSet(6))
}
fn native_legal(_: Action, _: ObjectKey, _: u64) -> Result<(), Error> {
    Ok(())
}
fn custom_legal(_: Action, _: ObjectKey, _: u64) -> Result<(), Error> {
    Err(Error::Conflict)
}
fn native_options(
    _: &[Option<Action>],
    _: ObjectKey,
    _: u64,
    _: &mut [Option<Action>],
) -> Result<usize, Error> {
    Ok(0)
}
fn native_features(
    _: Action,
    _: ObjectKey,
) -> Result<cyxia_prototype::features::TargetFeatures, Error> {
    Err(Error::Unsupported)
}
fn native_apply(
    _: Action,
    _: cyxia_prototype::domains::ApplyId,
    _: cyxia_prototype::domains::PolicyStamp,
    _: u64,
) -> Result<ExecutionState, Error> {
    Ok(ExecutionState::Pending)
}
fn native_reconcile(
    _: Action,
    _: cyxia_prototype::domains::ApplyId,
    _: cyxia_prototype::domains::PolicyStamp,
    _: u64,
) -> Result<ExecutionState, Error> {
    Ok(ExecutionState::Applied)
}
fn callbacks() -> legality::NativeCallbacks {
    legality::NativeCallbacks {
        target: native_target,
        current: native_current,
        legal: native_legal,
        legal_options: native_options,
        target_features: native_features,
        apply: native_apply,
        reconcile: native_reconcile,
    }
}
#[test]
fn custom_registration_is_not_given_the_borrowed_native_legality_path() {
    let mut f = domain_control::Family {
        domain: 1,
        kind: 2,
        target_source: domain_control::TargetSource::Services,
        target: native_target,
        current: native_current,
        legal: native_legal,
        legal_options: native_options,
        target_features: native_features,
        apply: native_apply,
        reconcile: native_reconcile,
    };
    assert!(legality::native_family_matches(&f, callbacks()));
    f.legal = custom_legal;
    assert!(!legality::native_family_matches(&f, callbacks()));
    f.legal = native_legal;
    f.kind = 1;
    assert!(!legality::native_family_matches(&f, callbacks()));
    f.kind = 2;
    f.target_source = domain_control::TargetSource::Tasks;
    assert!(!legality::native_family_matches(&f, callbacks()));
}
