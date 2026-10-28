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
static COMPLETE_ACTUAL: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static COMPLETE_AT: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static BILLS: Mutex<Vec<(u64,u64,u64)>> = Mutex::new(Vec::new());
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
#[derive(Clone, Copy, PartialEq, Eq)] enum Life { Free, Ready, Waiting }
#[derive(Clone, Copy)] struct Task { key: ObjectKey, optional: bool, pending: bool, parent: ObjectKey, life: Life, blocked: bool, cpu: u16 }
const TASK: Task = Task { key: MEMBER, optional: false, pending: false, parent: MEMBER, life: Life::Ready, blocked: false, cpu: 3 };
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
    remote: Option<()>,
}
static mut STATE: State = State { scheduler: Scheduler::new(), active: [None; 64],
    layout: CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 }, draining: 0,
    service_admitted: false, background: Background { inner: BackgroundBudgets::new() },
    tasks: [TASK], throttled: [None; 64], probe_key: None,
    facts: Facts { wait: [const { Counter }; 16], node_wait: Counter }, remote: None };
fn task_index(tasks: &[Task; 1], key: ObjectKey) -> Result<usize, Error> {
    tasks.iter().position(|t| t.key == key).ok_or(Error::Stale)
}
fn group_index(_: &State, _: ObjectKey) -> Result<usize, Error> { Err(Error::NotReady) }
mod replay { pub fn service_admitted() {} }
mod baseline_diagnostics { pub fn failure(_: usize, _: u64) {} }
fn complete_locked(s: &mut State, slot: usize) -> Result<(), Error> {
    let active = s.active[slot].take().ok_or(Error::Stale)?;
    let actual = COMPLETE_ACTUAL[slot].load(Ordering::Acquire);
    let finished = COMPLETE_AT[slot].load(Ordering::Acquire);
    s.scheduler.complete(active.dispatch, actual, active.state, finished)?;
    BILLS.lock().unwrap().push((active.dispatch.sequence, actual, finished));
    if let Some(debit) = active.optional { s.background.complete(debit, actual, finished)?; }
    COMPLETE_READY[slot].store(false, Ordering::Release);
    CREDIT_KIND[slot].store(0, Ordering::Release);
    Ok(())
}
mod domain_tasks {
    pub(crate) use super::{Cancellation, PaidServiceWitness};
    pub fn authorize_service_turn() -> Result<(), super::Error> { super::authorize_service_turn() }
    pub fn verify_control_credit(_: &super::ControlCredit) -> Result<(), super::Error> { Err(super::Error::Auth) }
    pub use super::{close_cpu,quiescent};
    // LOCAL_RETIRE_EXPORT
}
// PRODUCTION_BODIES
// WARM_PLATFORM_FIXTURES
// EVIDENCE_MODULES
// PEER_FIXTURE
static GATES: [cyxia_kernel_core::control_plane::dispatch::Gate;4] =
    [const {cyxia_kernel_core::control_plane::dispatch::Gate::new()};4];
static STOP_OPERATION: AtomicU64 = AtomicU64::new(17);
static STOP_ACK: AtomicU64 = AtomicU64::new(0);
static STOP_TASK_ACK: AtomicU64 = AtomicU64::new(0);
const FAULT_MODE: u64 = 0;
struct NativeStop { discards: usize }
impl NativeStop {fn discard(&mut self){self.discards+=1;}}
struct Worker {context:Option<u64>,native:NativeStop}
mod prototype_runtime {
    use super::*;
    mod native {
        pub fn stop_ready(_: &mut super::Worker)->bool {true}
        pub fn measure_stop_tail<R>(_:u64,f:impl FnOnce()->R)->R {f()}
    }
    pub(super) fn idle_worker() {}
    // STOP_BODIES
}
fn context(n:usize)->u64{n as u64}
fn disabled_step(worker:&mut Worker) {
    let slot=2;
    let mut runtime_worker=worker;
    let mut contexts=[0,0];
    let _=&mut contexts;
    for _ in 0..1 {
        let view=GATES[slot].view();
        // DISABLED_BRANCH
    }
}

fn complete(slot: usize, at: u64) {
    CPU.store(slot, Ordering::Release);
    NOW.store(at, Ordering::Release);
    finish_capture(slot, at - 100_000, at);
    COMPLETE_ACTUAL[slot].store(100_000, Ordering::Release);
    COMPLETE_AT[slot].store(at, Ordering::Release);
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
fn run_completed() {
    use learning::capture::{FrozenRequest, Source};
    use learning::reward::CpuClass;
    let storage = Box::leak(Box::new(learning_evidence::Storage::empty()));
    learning_evidence::install(storage, [1;32], 1, group(44), |_,_,_| Ok(()))
        .map_err(|(error,_)| error).unwrap();
    locked(|s| s.scheduler.register_group(group(14))).unwrap();
    begin_service_segment().unwrap();
    let family = Family { domain:14, kind:1 };
    let preparation = domain_control::replay::prepared(1, family);
    learning_prewarm::bind_preparation(preparation).unwrap();
    for _ in 0..5 { assert_eq!(learning_prewarm::begin(family, MEMBER), Err(Error::Again)); }
    learning_prewarm::begin(family, MEMBER).unwrap();
    complete(0,1_000_100_000);
    NOW.store(1_100_000_000,Ordering::Release);
    learning_evidence::start(1,family,now_ns(),7_100_000_000,[7;32],
        &[Source {owner:MEMBER,class:CpuClass::Policy,allowed_cores:8},
          Source {owner:MEMBER,class:CpuClass::ExecutorAction,allowed_cores:8},
          Source {owner:MEMBER,class:CpuClass::ExecutorWork,allowed_cores:8}],
        &core::array::from_fn::<_,100,_>(|i| FrozenRequest {owner:group(20),id:i as u64+1,
            arrived_ns:7_100_000_000+i as u64*1_000_000})).unwrap();
    peer_replay::reset();
    locked(|s| s.scheduler.admit(ThreadSpec {key:MEMBER,group:group(14),cpu:3,
        allowed_mask:8,minimum_ns:10_000_000,budget_ns:20_000_000},s.layout,now_ns())).unwrap();
    CPU.store(3,Ordering::Release);
    NOW.store(1_103_000_000,Ordering::Release);
    let credit=begin_builtin(3,now_ns()).unwrap();
    let original=locked(|s|Ok(s.active[3].unwrap().dispatch)).unwrap();
    assert!(capture_credit::has_warm(3),"fixture must exercise an actual warm token");
    let warm_before=learning_prewarm::host_counts();
    learning_evidence::host_with_collector(|| {
        // Fill the real shared bank with sixteen independently completed owner
        // intervals. The dispatch already owns its original producer token.
        for i in 0..16 {
            let mut a=learning_evidence::attempt(MEMBER,CpuClass::ExecutorWork).unwrap().unwrap();
            let first=1_103_000_000+i*100;
            NOW.store(first+50,Ordering::Release);
            assert_eq!(learning_evidence::finish_attempt(&mut a,first,first+50),Err(learning_evidence::Error::Busy));
            drop(a);
        }
        assert_eq!(learning_evidence::host_handoff()[28],16);
        CPU.store(0,Ordering::Release);let gate=acquire_guard().unwrap();
        CPU.store(3,Ordering::Release);NOW.store(1_104_000_000,Ordering::Release);
        assert_eq!(complete_builtin(3,100_000,now_ns()),Ok(()));
        assert_eq!(learning_evidence::host_handoff()[2],0,"full handoff dropped the physical completion");
        assert!(COMPLETE_READY[3].load(Ordering::Acquire));
        assert_eq!(capture_credit::completion_times(3),Some((1_103_900_000,1_104_000_000)));
        assert!(!capture_credit::available(3));assert!(!capture_credit::has_warm(3));
        let warm_after=learning_prewarm::host_counts();
        assert_eq!(warm_after.0+1,warm_before.0);assert_eq!(warm_after.1,warm_before.1+1);
        assert!(!warm_after.2);
        // No second finish can rewrite the original timestamps or warm row.
        finish_capture(3,1_103_999_000,1_104_001_000);
        assert_eq!(capture_credit::completion_times(3),Some((1_103_900_000,1_104_000_000)));
        assert_eq!(learning_prewarm::host_counts(),warm_after);
        capture_credit::cancelled(3,original,None);
        assert_eq!(capture_credit::completion_times(3),Some((1_103_900_000,1_104_000_000)),
            "unstarted cancellation erased real completed work");
        CPU.store(0,Ordering::Release);drop(gate);CPU.store(3,Ordering::Release);
        NOW.store(1_104_010_000,Ordering::Release);
        assert!(begin_builtin(3,now_ns()).is_none(),"completed token allowed a new grant while collector was busy");
        assert!(!COMPLETE_READY[3].load(Ordering::Acquire),"capture Busy prevented original Scheduler settlement");
        locked(|s| {assert!(s.active[3].is_none());assert_eq!(s.scheduler.thread_cpu_ns(MEMBER)?,100_000);Ok(())}).unwrap();
        assert_eq!(BILLS.lock().unwrap().iter().filter(|b|b.0==credit.sequence).count(),1);
        assert_eq!(learning_evidence::host_handoff()[2],0);
        assert_eq!(learning_prewarm::host_counts(),warm_after);
    });
    // The independent collector owner can restore progress; retry keeps the
    // exact completed lease and never asks the Scheduler to repeat that work.
    capture_credit::check_binding_corruption(3);
    assert!(capture_credit::retire(3));assert!(capture_credit::available(3));
    learning_evidence::host_drain();
    assert_eq!(learning_evidence::host_handoff()[28],0);
    assert_eq!(learning_evidence::status().unwrap().0.missing_events,0);
    NOW.store(1_105_000_000,Ordering::Release);
    let next=begin_builtin(3,now_ns()).unwrap();assert_ne!(next.sequence,credit.sequence);
    NOW.store(1_105_100_000,Ordering::Release);
    complete_builtin(3,100_000,now_ns()).unwrap();
    assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(MEMBER)),Ok(200_000));
    assert_eq!(learning_evidence::status().unwrap().0.missing_events,0);
    // Peer Busy is independent of collector Busy. Its original lease is held
    // locally, while warm settles once and the physical Scheduler bill settles.
    NOW.store(1_106_000_000,Ordering::Release);
    begin_builtin(3,now_ns()).unwrap();
    let gate=peer_replay::LEDGER.lock().unwrap();
    assert_eq!(gate.as_ref().unwrap().open,1);
    NOW.store(1_106_100_000,Ordering::Release);
    complete_builtin(3,100_000,now_ns()).unwrap();
    let warm_once=learning_prewarm::host_counts();
    assert!(!capture_credit::available(3),"peer Busy completion escaped original producer custody");
    assert!(!COMPLETE_READY[3].load(Ordering::Acquire));
    assert!(!capture_credit::retire(3));
    assert_eq!(learning_prewarm::host_counts(),warm_once);
    assert_eq!(gate.as_ref().unwrap().open,1);
    drop(gate);assert!(capture_credit::retire(3));
    peer_replay::ledger_with(|l|{assert_eq!((l.open,l.missing),(0,0));Ok(())}).unwrap();
    assert_eq!(learning_prewarm::host_counts(),warm_once);
    assert_eq!(learning_evidence::host_handoff()[2],0);
    assert_eq!(locked(|s|s.scheduler.thread_cpu_ns(MEMBER)),Ok(300_000));
    println!("completed dispatch custody passed");
}
fn run_completed_stop() {
    use learning::capture::{FrozenRequest,Source};
    use learning::reward::CpuClass;
    let storage=Box::leak(Box::new(learning_evidence::Storage::empty()));
    learning_evidence::install(storage,[1;32],1,group(44),|_,_,_|Ok(()))
        .map_err(|(error,_)|error).unwrap();
    learning_evidence::start(1,Family{domain:1,kind:1},now_ns(),7_000_000_000,[7;32],
        &[Source{owner:group(2),class:CpuClass::Policy,allowed_cores:4},
          Source{owner:group(2),class:CpuClass::ExecutorAction,allowed_cores:4},
          Source{owner:group(2),class:CpuClass::ExecutorWork,allowed_cores:4}],
        &core::array::from_fn::<_,100,_>(|i|FrozenRequest{owner:group(20),id:i as u64+1,
            arrived_ns:7_000_000_000+i as u64*1_000_000})).unwrap();
    peer_replay::reset();
    locked(|s| {s.scheduler.register_group(group(14))?;
        s.scheduler.admit(ThreadSpec{key:group(2),group:group(14),cpu:2,allowed_mask:4,
            minimum_ns:10_000_000,budget_ns:20_000_000},s.layout,now_ns())}).unwrap();
    let token=cyxia_kernel_core::control_plane::dispatch::Token {generation:1,
        plane:cyxia_kernel_core::control_plane::Plane::Business};
    GATES[2].open(token).unwrap();let permit=GATES[2].try_enter(token).unwrap();
    CPU.store(2,Ordering::Release);
    NOW.store(1_003_000_000,Ordering::Release);
    let credit=begin_builtin(2,now_ns()).unwrap();
    let mut worker=Worker{context:Some(123),native:NativeStop{discards:0}};
    learning_evidence::host_with_collector(|| {
        NOW.store(1_003_100_000,Ordering::Release);
        complete_builtin(2,100_000,now_ns()).unwrap();
        assert!(!capture_credit::available(2));assert!(!COMPLETE_READY[2].load(Ordering::Acquire));
        drop(permit);GATES[2].close(token).unwrap();
        assert!(!GATES[2].view().enabled && GATES[2].quiescent());
        disabled_step(&mut worker);
        assert_eq!(STOP_TASK_ACK.load(Ordering::Acquire),0,
            "disabled CPU2 acknowledged stop while its completion token was retained");
        assert_eq!(worker.context,Some(123));assert_eq!(worker.native.discards,0);
        assert!(!capture_credit::available(2));
    });
    disabled_step(&mut worker);
    assert_eq!(STOP_TASK_ACK.load(Ordering::Acquire),17);
    assert!(capture_credit::available(2));assert_eq!(worker.native.discards,1);
    disabled_step(&mut worker);assert_eq!(worker.native.discards,1);
    assert_eq!(BILLS.lock().unwrap().iter().filter(|b|b.0==credit.sequence).count(),1);
    assert_eq!(learning_evidence::status().unwrap().0.missing_events,0);
    println!("disabled CPU2 completion custody passed");
}
fn main() { std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(|| {
    match std::env::var("CYXIA_COMPLETED_TEST").ok().as_deref() {
        Some("stop")=>run_completed_stop(),Some(_)=>run_completed(),None=>run()
    }
}).unwrap().join().unwrap(); }
