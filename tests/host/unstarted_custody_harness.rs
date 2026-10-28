//! Actual non-test collector, peer Attempt/Ledger, prewarm and task-owner
//! bodies. Host clocks/CPU/pool are fixtures, never accepted replay evidence.
#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS, tasks::*, maintenance::{BackgroundBudgets, CpuDebit}};
use cyxia_prototype::learning::{self, Family};
static CPU: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(1_000_000_000);
static WORK: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(true);
static FAIL_REFUND: AtomicBool = AtomicBool::new(false);
static CREDIT_KIND: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static CREDIT_NS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static COMPLETE_READY: [AtomicBool; 64] = [const { AtomicBool::new(false) }; 64];
static FILE_BUSY: [AtomicBool; 1] = [AtomicBool::new(false)];
const CLUSTER_CALLER: ObjectKey = ObjectKey { id: u64::MAX - 9, generation: 1 };
const REMOTE_ID: u64 = 0x100;
const MEMBER: ObjectKey = ObjectKey { id: REMOTE_ID, generation: 42 };
pub mod cpu { pub fn slot() -> usize { super::CPU.load(super::Ordering::Acquire) } }
pub mod timer {
    pub fn ticks() -> u64 { super::NOW.load(super::Ordering::Acquire) }
    pub fn frequency() -> u64 { 1_000_000_000 }
    pub fn cpu_ticks() -> u64 { super::WORK.load(super::Ordering::Acquire) }
    pub fn cpu_ns(ticks: u64) -> u64 { ticks }
    pub fn cpu_elapsed_ns(start: u64) -> u64 { cpu_ticks() - start }
}
mod domain_platform { pub fn now_ns() -> u64 { super::now_ns() } }
fn now_ns() -> u64 { timer::ticks() }
fn group(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
fn builtin(slot: usize) -> ObjectKey { group(slot as u64) }
#[derive(Clone, Copy, PartialEq, Eq)] enum Life { Ready, Waiting }
#[derive(Clone, Copy)] struct Task { key: ObjectKey, optional: bool, pending: bool, parent: ObjectKey, life: Life, blocked: bool }
const TASK: Task = Task { key: MEMBER, optional: false, pending: false, parent: MEMBER, life: Life::Ready, blocked: false };
#[derive(Clone, Copy)] struct Active { dispatch: Dispatch, state: RunState, optional: Option<CpuDebit>, cpu_started: Option<u64> }
struct Counter;
impl Counter { fn add(&mut self, _: u64) {} }
struct Facts { wait: [Counter; 16], node_wait: Counter }
struct Background { inner: BackgroundBudgets }
impl core::ops::Deref for Background { type Target = BackgroundBudgets; fn deref(&self) -> &Self::Target { &self.inner } }
impl core::ops::DerefMut for Background { fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner } }
impl Background {
    fn complete(&mut self, debit: CpuDebit, actual: u64, finished: u64) -> Result<(), Error> {
        if FAIL_REFUND.load(Ordering::Acquire) { return Err(Error::Busy); }
        self.inner.complete(debit, actual, finished)
    }
}
struct State {
    scheduler: Scheduler, active: [Option<Active>; 64], layout: CpuLayout,
    draining: u64, service_admitted: bool, background: Background,
    tasks: [Task; 1], throttled: [Option<(ObjectKey, u64)>; 64], probe_key: Option<ObjectKey>, facts: Facts,
}
static mut STATE: State = State { scheduler: Scheduler::new(), active: [None; 64],
    layout: CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 }, draining: 0,
    service_admitted: false, background: Background { inner: BackgroundBudgets::new() },
    tasks: [TASK], throttled: [None; 64], probe_key: None,
    facts: Facts { wait: [const { Counter }; 16], node_wait: Counter } };
fn task_index(tasks: &[Task; 1], key: ObjectKey) -> Result<usize, Error> {
    tasks.iter().position(|t| t.key == key).ok_or(Error::Stale)
}
fn group_index(_: &State, _: ObjectKey) -> Result<usize, Error> { Err(Error::NotReady) }
mod replay { pub fn service_admitted() {} }
mod baseline_diagnostics { pub fn failure(_: usize, _: u64) {} }
fn complete_locked(s: &mut State, slot: usize) -> Result<(), Error> {
    let active = s.active[slot].take().ok_or(Error::Stale)?;
    s.scheduler.complete(active.dispatch, 100_000, active.state, now_ns())?;
    if let Some(debit) = active.optional { s.background.complete(debit, 100_000, now_ns())?; }
    COMPLETE_READY[slot].store(false, Ordering::Release);
    CREDIT_KIND[slot].store(0, Ordering::Release);
    Ok(())
}
mod domain_tasks {
    pub(crate) use super::{Cancellation, PaidServiceWitness};
    pub fn authorize_service_turn() -> Result<(), super::Error> { super::authorize_service_turn() }
    pub fn verify_control_credit(_: &super::ControlCredit) -> Result<(), super::Error> { Err(super::Error::Auth) }
}
// PRODUCTION_BODIES
// WARM_PLATFORM_FIXTURES
// EVIDENCE_MODULES
// PEER_FIXTURE

fn complete(slot: usize, at: u64) {
    CPU.store(slot, Ordering::Release);
    NOW.store(at, Ordering::Release);
    finish_capture(slot, at - 100_000, at);
    COMPLETE_READY[slot].store(true, Ordering::Release);
    locked(|s| complete_locked(s, slot)).unwrap();
}
fn run() {
    use learning::capture::{FrozenRequest, Source};
    use learning::reward::CpuClass;
    let storage = Box::leak(Box::new(learning_evidence::Storage::empty()));
    learning_evidence::install(storage, [1; 32], 1, group(44), |_, _, _| Ok(()))
        .map_err(|(error, _)| error).unwrap();
    locked(|s| s.scheduler.register_group(group(14))).unwrap();
    begin_service_segment().unwrap();
    let family = Family { domain: 14, kind: 1 };
    let preparation = domain_control::replay::prepared(1, family);
    learning_prewarm::bind_preparation(preparation).unwrap();
    for _ in 0..5 { assert_eq!(learning_prewarm::begin(family, MEMBER), Err(Error::Again)); }
    learning_prewarm::begin(family, MEMBER).unwrap();
    complete(0, 1_000_100_000);
    NOW.store(1_100_000_000, Ordering::Release);
    learning_evidence::start(1, family, now_ns(), 7_100_000_000, [7; 32],
        &[Source { owner: MEMBER, class: CpuClass::Policy, allowed_cores: 8 },
          Source { owner: MEMBER, class: CpuClass::ExecutorAction, allowed_cores: 8 },
          Source { owner: MEMBER, class: CpuClass::ExecutorWork, allowed_cores: 9 },
          Source { owner: group(0x101), class: CpuClass::ExecutorWork, allowed_cores: 1 }],
        &core::array::from_fn::<_, 100, _>(|i| FrozenRequest {
            owner: group(20), id: i as u64 + 1, arrived_ns: 7_100_000_000 + i as u64 * 1_000_000,
        })).unwrap();
    peer_replay::reset();
    let service = begin_service_segment().unwrap();
    locked(|s| {
        s.scheduler.admit(ThreadSpec { key: MEMBER, group: group(14), cpu: 3,
            allowed_mask: 8, minimum_ns: 10_000_000, budget_ns: 20_000_000 }, s.layout, now_ns())
    }).unwrap();
    CPU.store(3, Ordering::Release);
    NOW.store(1_103_000_000, Ordering::Release);
    let task = begin_builtin(3, now_ns()).unwrap();
    assert_eq!(task.thread, MEMBER);
    locked(|s| {
        s.background.register(group(98), 100, 0, now_ns())?;
        let debit = s.background.reserve(group(98), 1_000_000, now_ns())?;
        s.active[0].as_mut().unwrap().optional = Some(debit);
        Ok(())
    }).unwrap();
    let gate = peer_replay::LEDGER.lock().unwrap();
    assert_eq!(gate.as_ref().unwrap().open, 2);
    NOW.store(1_180_000_001, Ordering::Release);
    assert!(!revalidate_unstarted(3, 2));
    assert!(!begin_builtin(3, now_ns()).is_some(), "busy peer replaced cancelled task custody");
    CPU.store(0, Ordering::Release);
    assert!(!learning_prewarm::freeze_abort(preparation).unwrap(), "prewarm token disappeared while peer was busy");
    assert!(!revalidate_service_segment());
    capture_credit::check_binding_corruption(0);
    assert_eq!(authorize_service_turn(), Err(Error::NotReady));
    assert!(!begin_builtin(0, now_ns()).is_some(), "builtin admitted over cancelled peer custody");
    assert!(!begin_service_segment().is_some(), "service admitted over cancelled peer custody");
    assert!(begin_file_credit(MEMBER).unwrap().is_none(), "file admitted over cancelled peer custody");
    locked(|s| {
        assert_eq!(s.background.status(group(98))?.reserved_ns, 0,
            "refund must finish even while peer retirement remains busy");
        Ok(())
    }).unwrap();
    assert!(matches!(track_credit(0, Ok(Some(service))), Err(Error::Conflict)),
        "tracking a new credit overwrote retained cancellation custody");
    assert_eq!(gate.as_ref().unwrap().open, 2);
    assert_eq!(learning_evidence::status().unwrap().0.missing_events, 0);
    drop(gate);
    NOW.store(1_200_000_000, Ordering::Release);
    let next = begin_service_segment().expect("service did not retire cancelled custody after peer release");
    assert_ne!(next.sequence, service.sequence);
    CPU.store(3, Ordering::Release);
    NOW.store(1_203_000_000, Ordering::Release);
    let next_task = begin_builtin(3, now_ns()).expect("builtin did not retire cancelled custody after peer release");
    assert_ne!(next_task.sequence, task.sequence);
    complete(3, 1_203_100_000);
    CPU.store(0, Ordering::Release);
    assert!(learning_prewarm::freeze_abort(preparation).unwrap());
    let summary = learning_prewarm::summary_prepared(preparation).unwrap().unwrap();
    assert!(!summary.lost, "unused task cancellation marked prewarm data lost");
    assert_eq!(summary.rows, 0);
    assert_eq!(learning_evidence::status().unwrap().0.missing_events, 0);
    // A fresh real grant and its bill remain usable after cancellation.
    complete(0, 1_203_200_000);
    peer_replay::ledger_with(|l| { assert_eq!((l.open, l.count, l.missing), (0, 0, 0)); Ok(()) }).unwrap();
    locked(|s| {
        assert_eq!(s.scheduler.thread_cpu_ns(MEMBER)?, 100_000);
        assert_eq!(s.scheduler.thread_cpu_ns(service.thread)?, 200_000);
        Ok(())
    }).unwrap();

    // An unexpected refund failure follows irreversible physical cancel.
    NOW.store(1_300_000_000, Ordering::Release);
    let refunded = begin_service_segment().unwrap();
    locked(|s| {
        s.background.register(group(99), 100, 0, now_ns())?;
        let debit = s.background.reserve(group(99), 1_000_000, now_ns())?;
        s.active[0].as_mut().unwrap().optional = Some(debit);
        Ok(())
    }).unwrap();
    FAIL_REFUND.store(true, Ordering::Release);
    NOW.store(1_380_000_001, Ordering::Release);
    assert!(!revalidate_service_segment(), "refund failure executed an already cancelled body");
    assert_eq!(CREDIT_KIND[0].load(Ordering::Acquire), 0);
    assert_eq!(authorize_service_turn(), Err(Error::NotReady));
    assert!(begin_service_segment().is_none());
    locked(|s| {
        assert!(s.active[0].is_none()); assert!(s.scheduler.active(0).is_none());
        assert_eq!(s.background.status(group(99))?.reserved_ns, 1_000_000);
        Ok(())
    }).unwrap();
    FAIL_REFUND.store(false, Ordering::Release);
    assert!(capture_credit::retire(0));
    assert!(capture_credit::retire(0));
    locked(|s| { assert_eq!(s.background.status(group(99))?.reserved_ns, 0); Ok(()) }).unwrap();
    NOW.store(1_400_000_000, Ordering::Release);
    let final_credit = begin_service_segment().unwrap();
    assert_ne!(final_credit.sequence, refunded.sequence);
    complete(0, 1_400_100_000);
    NOW.store(1_500_000_000, Ordering::Release);
    begin_service_segment().unwrap();
    let gate = peer_replay::LEDGER.lock().unwrap();
    NOW.store(1_580_000_001, Ordering::Release);
    assert!(!revalidate_service_segment());
    assert!(begin_file_credit(MEMBER).unwrap().is_none());
    drop(gate);
    NOW.store(1_600_000_000, Ordering::Release);
    locked(|s| { s.tasks[0].life = Life::Waiting; s.scheduler.set_runnable(MEMBER, false, now_ns()) }).unwrap();
    FILE_BUSY[0].store(true, Ordering::Release);
    begin_file_credit(MEMBER).unwrap().expect("file did not retire cancelled custody after peer release");
    complete(0, 1_600_100_000);
    assert_eq!(learning_evidence::status().unwrap().0.missing_events, 0);
    println!("all cancellation custodians passed");
}
fn main() { std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(run).unwrap().join().unwrap(); }
