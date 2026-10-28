#![allow(dead_code)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::domains::{Action, Error, ObjectKey, PolicyStamp};
use cyxia_prototype::domains::tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec,
    ServiceBackend, ServiceBatch, ServiceItem, SubmitVector, ResolvedItem, ItemStatus, FILE_STAT_BY_CAP};
const TASKS: usize = 3;
const KEY: ObjectKey = ObjectKey { id: 0x101, generation: 1 };
const GROUP: ObjectKey = ObjectKey { id: 14, generation: 1 };
const LAYOUT: CpuLayout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
static READY: AtomicBool = AtomicBool::new(true);
static DENY: AtomicBool = AtomicBool::new(false);
static NOW: AtomicU64 = AtomicU64::new(0);
fn now_ns()->u64 {NOW.load(Ordering::Acquire)}
static CPU_NS: AtomicU64 = AtomicU64::new(0);
static BASELINE_PENDING: AtomicBool = AtomicBool::new(false);
static BASELINE_CALLS: AtomicU64 = AtomicU64::new(0);
static BASELINE_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
static GATE_MODE: AtomicBool = AtomicBool::new(false);
static CREATE_BASELINE: AtomicBool = AtomicBool::new(false);
static BILL_CPU: AtomicU64 = AtomicU64::new(0);
static BILL_AT: AtomicU64 = AtomicU64::new(0);
#[path = "// OWNER_GATE_PATH"]
mod owner_gate;
static mut OWNER_GATE: owner_gate::Gate = owner_gate::Gate::new();
fn owner_gate() -> &'static owner_gate::Gate {
    unsafe { &*core::ptr::addr_of!(OWNER_GATE) }
}
mod cpu { pub fn slot() -> usize { 0 } }
mod timer {
    pub fn cpu_ticks() -> u64 { super::CPU_NS.load(super::Ordering::Acquire) }
    pub fn cpu_elapsed_ns(start: u64) -> u64 { cpu_ticks() - start }
}
static CREDIT_KIND: [AtomicU64; 1] = [AtomicU64::new(0)];
static CREDIT_NS: [AtomicU64; 1] = [AtomicU64::new(0)];
static COMPLETE_READY: [AtomicBool; 1] = [AtomicBool::new(false)];
mod baseline_diagnostics {
    pub fn opportunity(_: bool, _: u64, _: u64, _: bool) -> Option<u64> { None }
    pub fn body_start(_: Option<u64>, _: u64, _: u64) {}
    pub fn body_finish(_: Option<u64>, _: &Result<bool, super::Error>, _: u64) {}
    pub fn finish(_: Option<u64>, _: bool, _: u64, _: bool) {}
}
mod crate_stubs {
    pub fn service_io(_: &mut dyn FnMut()) {}
    pub fn baseline_activation_pending() -> bool { super::BASELINE_PENDING.load(super::Ordering::Acquire) }
    pub fn service_step() -> Result<bool, super::Error> {
        super::locked(|s| { assert!(s.active.is_some()); Ok(()) }).unwrap();
        super::physical_work();
        assert!(super::NOW.load(super::Ordering::Acquire) - super::BASELINE_SNAPSHOT.load(super::Ordering::Acquire) < 50_000_000);
        let calls = super::BASELINE_CALLS.fetch_add(1, super::Ordering::AcqRel);
        if calls == 0 { return Err(super::Error::Busy); }
        super::BASELINE_PENDING.store(false, super::Ordering::Release);
        Ok(true)
    }
}
use crate_stubs as learning_workload;
use crate_stubs as learning_replay;
// Closing diagnostics are outside this independent vector-pump fixture.
mod learning_evidence { pub mod execution_trace {
    pub fn admission_opportunity(_:bool,_:bool,_:bool,_:u64) {}
    pub fn admission_body(_:u64,_:u64) {}
    pub fn admission_result(_:bool,_:u64) {}
} }
#[derive(Clone, Copy)]
enum Life { Free, Ready, Exiting }
struct Task { life: Life, recipe: u64, pending: bool }
struct State {
    scheduler: Scheduler, active: Option<Dispatch>, vectors: [Option<SubmitVector>; TASKS],
    tasks: [Task; TASKS], vector_cursor: usize, wake: u64, services: ServiceBatch,
    general: usize, files: usize, opportunities: usize, phase: usize, bodies: usize,
}
static mut STATE: Option<State> = None;
// Queue admission has its own actual-source/real-SpawnAdmission harness. This
// vector fixture's replay callback clears its hint on success, so that branch
// must never run here rather than silently granting synthetic admission.
fn advance_admission_bounded(_: &mut State, _: usize, _: usize) -> Result<(), Error> {
    panic!("queue admission is outside the vector fixture")
}
fn locked<R>(body: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    let permit = if GATE_MODE.load(Ordering::Acquire) {
        Some(owner_gate().try_acquire(0, NOW.load(Ordering::Acquire), 1_000_000)
            .ok_or(Error::Busy)?)
    } else { None };
    let result = body(unsafe { (&mut *core::ptr::addr_of_mut!(STATE)).as_mut().unwrap() });
    if let Some(permit) = permit { permit.release(NOW.load(Ordering::Acquire)); }
    result
}
fn settle(s: &mut State) -> Result<(), Error> {
    s.scheduler.complete(s.active.take().unwrap(), BILL_CPU.load(Ordering::Acquire),
        RunState::Runnable, BILL_AT.load(Ordering::Acquire))?;
    COMPLETE_READY[0].store(false, Ordering::Release);
    Ok(())
}
fn begin_service_segment() -> Option<()> {
    if DENY.load(Ordering::Acquire) { return None; }
    locked(|s| {
        if COMPLETE_READY[0].load(Ordering::Acquire) { settle(s)?; }
        assert!(s.active.is_none(), "combined or abandoned physical reservation");
        let mut d = s.scheduler.dispatch_with_window_headroom(0, LAYOUT,
            NOW.load(Ordering::Acquire), 2_500_000, 20_000_000)?.ok_or(Error::Budget)?;
        if d.reserved_ns < 2_500_000 { d = s.scheduler.resize_dispatch(d, 2_500_000)?; }
        assert_eq!(d.thread, KEY);
        assert_eq!(d.reserved_ns, 2_500_000);
        s.active = Some(d); Ok(())
    }).ok()
}
fn revalidate_service_segment() -> bool { locked(|s| Ok(s.active.is_some())).unwrap() }
fn finish_cpu_interval(started: u64) -> (u64, u64, u64) {
    (NOW.load(Ordering::Acquire), NOW.load(Ordering::Acquire), timer::cpu_ticks() - started)
}
fn complete_service(actual: u64, at: u64) -> Result<(), Error> {
    BILL_CPU.store(actual, Ordering::Relaxed); BILL_AT.store(at, Ordering::Relaxed);
    COMPLETE_READY[0].store(true, Ordering::Release);
    locked(|s| { s.bodies += 1; settle(s) })
}
fn physical_work() {
    CPU_NS.fetch_add(100_000, Ordering::AcqRel);
    NOW.fetch_add(100_000, Ordering::AcqRel);
}
struct Backend;
impl ServiceBackend for Backend {
    fn validate_object(&mut self, _: ObjectKey, _: u16) -> Result<(), Error> { Ok(()) }
    fn call_batch(&mut self, _: ObjectKey, items: &[ResolvedItem], out: &mut [Option<Result<u64, Error>>]) -> Result<(), Error> {
        assert!(!items.is_empty());
        for value in out { *value = Some(Ok(42)); }
        Ok(())
    }
}
fn vector_piece(s: &mut State, i: usize) {
    assert!(s.active.is_some());
    s.opportunities += 1;
    if let Some(vector) = s.vectors[i].as_mut() {
        s.services.step(vector, NOW.load(Ordering::Acquire), &mut Backend).unwrap();
    }
    physical_work();
}
fn publish_evidence(_: &State) {}
fn general_turn() {
    locked(|s| {
        assert!(s.active.is_some()); s.general += 1;
        if // OLD_VECTOR_PHASE
            && s.phase == 2 {
            let i = s.vector_cursor; s.vector_cursor = (i + 1) % TASKS;
            vector_piece(s, i);
        }
        s.phase = (s.phase + 1) % 11; Ok(())
    }).unwrap();
    physical_work();
    if CREATE_BASELINE.swap(false, Ordering::AcqRel) {
        BASELINE_SNAPSHOT.store(NOW.load(Ordering::Acquire), Ordering::Release);
        BASELINE_PENDING.store(true, Ordering::Release);
    }
    if GATE_MODE.load(Ordering::Acquire) {
        // General work outlasts the remaining CPU0 metadata turn. The real
        // gate must hand off to the queued peer at its next acquisition.
        CPU_NS.fetch_add(1_000_000, Ordering::AcqRel);
        NOW.fetch_add(1_000_000, Ordering::AcqRel);
    }
}
fn service_file(_: &mut dyn FnMut()) {
    service_segment(|| { locked(|s| { s.files += 1; Ok(()) }).unwrap(); physical_work(); });
}
fn diagnostic_service_stage(_: u64) {}
// PUMP_BODIES
fn reset(batch: u8) {
    GATE_MODE.store(false, Ordering::Release); CREATE_BASELINE.store(false, Ordering::Release);
    COMPLETE_READY[0].store(false, Ordering::Release);
    unsafe { OWNER_GATE = owner_gate::Gate::new(); }
    DENY.store(false, Ordering::Release); NOW.store(100_000_000, Ordering::Release); CPU_NS.store(0, Ordering::Release);
    BASELINE_PENDING.store(false, Ordering::Release); BASELINE_CALLS.store(0, Ordering::Release);
    BASELINE_SNAPSHOT.store(100_000_000, Ordering::Release);
    let mut scheduler = Scheduler::new(); scheduler.register_group(GROUP).unwrap();
    scheduler.admit(ThreadSpec { key: KEY, group: GROUP, cpu: 0, allowed_mask: 1,
        minimum_ns: 20_000_000, budget_ns: 60_000_000 }, LAYOUT, 100_000_000).unwrap();
    let mut services = ServiceBatch::new();
    let cap = services.grant(KEY, ObjectKey { id: 5, generation: 1 }, ObjectKey { id: 6, generation: 1 }, 1).unwrap();
    if batch != 1 { services.install(batch, PolicyStamp::for_action(Action::ServiceBatch(batch),
        1, 100_000_000, 100_000_000).unwrap(), 100_000_000).unwrap(); }
    let items: Vec<_> = (0..16).map(|tag| ServiceItem { op: FILE_STAT_BY_CAP,
        cap, object_gen: 1, tag, ..Default::default() }).collect();
    let vector = services.submit(KEY, &items, 150_000_000, 100_000_000).unwrap();
    unsafe { STATE = Some(State { scheduler, active: None, vectors: [Some(vector), None, None],
        tasks: [Task { life: Life::Ready, recipe: 0, pending: false },
                Task { life: Life::Ready, recipe: 1, pending: false },
                Task { life: Life::Ready, recipe: 2, pending: false }], vector_cursor: 0, wake: 0,
        services, general: 0, files: 0, opportunities: 0, phase: 0, bodies: 0 }); }
}
#[test]
fn owned_baseline_gets_the_live_owner_turn_before_general_work() {
    reset(1); BASELINE_PENDING.store(true, Ordering::Release);
    let permit = owner_gate().try_acquire(0, 100_000_000, 1_000_000).unwrap();
    assert!(owner_gate().try_acquire(1, 100_000_000, 1_000_000).is_none());
    permit.release(100_000_000);
    GATE_MODE.store(true, Ordering::Release);
    service(0, &mut || {});
    assert_eq!(BASELINE_CALLS.load(Ordering::Acquire), 1,
        "general work consumed the owned baseline's live task-owner turn");
    assert_eq!(BASELINE_SNAPSHOT.load(Ordering::Acquire), 100_000_000);
    assert!(BASELINE_PENDING.load(Ordering::Acquire)); // first body Busy, retain identity
    assert!(COMPLETE_READY[0].load(Ordering::Acquire));
    let state = unsafe { (&*core::ptr::addr_of!(STATE)).as_ref().unwrap() };
    assert_eq!(state.general, 1);
    assert_eq!(state.active.unwrap().reserved_ns, 2_500_000);
    assert_eq!(BILL_CPU.load(Ordering::Acquire), 1_100_000);
    // Only the baseline was settled; general's exact bill survives gate denial.
    assert_eq!(state.scheduler.thread_cpu_ns(KEY), Ok(100_000));
}
#[test]
fn newly_owned_baseline_keeps_its_same_pass_opportunity() {
    reset(1); CREATE_BASELINE.store(true, Ordering::Release);
    service(0, &mut || {});
    assert_eq!(BASELINE_CALLS.load(Ordering::Acquire), 1,
        "new first snapshot lost its same-pass paid retry");
    assert_eq!(BASELINE_SNAPSHOT.load(Ordering::Acquire), 100_100_000);
    locked(|s| { assert_eq!((s.general, s.files, s.opportunities, s.bodies), (1, 1, 1, 4));
        assert_eq!(s.scheduler.thread_cpu_ns(KEY), Ok(400_000)); Ok(()) }).unwrap();
}
#[test]
fn queued_query_does_not_wait_for_eleven_unrelated_phases() {
    reset(1);
    // Keep the existing selector's two idle recipe opportunities: this change
    // does not silently reprioritize tasks or change the batch of one.
    for turn in 0..48 {
        NOW.store(100_000_000 + turn * 1_000_000, Ordering::Release);
        service(0, &mut || {});
    }
    locked(|s| {
        assert!(s.vectors[0].as_ref().unwrap().complete(), "queued query still waits behind general service rotation");
        assert_eq!(s.services.stats().ipc_calls, 16);
        assert_eq!((s.general, s.files, s.opportunities, s.bodies), (48, 48, 48, 144));
        assert_eq!(s.scheduler.thread_cpu_ns(KEY), Ok(14_400_000));
        assert!(s.active.is_none()); Ok(())
    }).unwrap();
}
#[test]
fn policy_batch_eight_is_still_applied_by_real_service_batch() {
    reset(8);
    for turn in 0..6 {
        NOW.store(100_000_000 + turn * 1_000_000, Ordering::Release);
        service(0, &mut || {});
    }
    locked(|s| { assert!(s.vectors[0].as_ref().unwrap().complete());
        assert_eq!(s.services.stats().ipc_calls, 2); assert_eq!(s.services.policy(102_000_000), 8); Ok(()) }).unwrap();
}
#[test]
fn unavailable_credit_cannot_dispatch_or_consume_queued_items() {
    reset(1); DENY.store(true, Ordering::Release);
    BASELINE_PENDING.store(true, Ordering::Release);
    service(0, &mut || {});
    assert_eq!(BASELINE_CALLS.load(Ordering::Acquire), 0);
    assert!(BASELINE_PENDING.load(Ordering::Acquire));
    locked(|s| { assert_eq!(s.services.stats().ipc_calls, 0); assert_eq!(s.bodies, 0);
        assert!(s.vectors[0].as_ref().unwrap().results().iter().all(|r| r.status == ItemStatus::Pending));
        assert_eq!(s.scheduler.thread_cpu_ns(KEY), Ok(0)); Ok(()) }).unwrap();
}
#[test]
fn owned_baseline_retries_on_the_next_paid_pass_with_unchanged_snapshot() {
    reset(1); BASELINE_PENDING.store(true, Ordering::Release);
    for turn in 0..2 {
        NOW.store(100_000_000 + turn * 1_000_000, Ordering::Release);
        service(0, &mut || {});
    }
    assert_eq!(BASELINE_CALLS.load(Ordering::Acquire), 2,
        "owned baseline missed the next prepaid service opportunity");
    assert_eq!(BASELINE_SNAPSHOT.load(Ordering::Acquire), 100_000_000);
    assert!(!BASELINE_PENDING.load(Ordering::Acquire));
    locked(|s| { assert_eq!((s.general, s.files, s.bodies), (2, 2, 8));
        assert_eq!(s.scheduler.thread_cpu_ns(KEY), Ok(800_000));
        assert!(s.active.is_none()); Ok(()) }).unwrap();
}
