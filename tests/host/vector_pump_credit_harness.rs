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
static CPU_NS: AtomicU64 = AtomicU64::new(0);
static BASELINE_PENDING: AtomicBool = AtomicBool::new(false);
static BASELINE_CALLS: AtomicU64 = AtomicU64::new(0);
static BASELINE_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
mod cpu { pub fn slot() -> usize { 0 } }
mod timer { pub fn cpu_ticks() -> u64 { super::CPU_NS.load(super::Ordering::Acquire) } }
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
#[derive(Clone, Copy)]
enum Life { Free, Ready, Exiting }
struct Task { life: Life, recipe: u64, pending: bool }
struct State {
    scheduler: Scheduler, active: Option<Dispatch>, vectors: [Option<SubmitVector>; TASKS],
    tasks: [Task; TASKS], vector_cursor: usize, wake: u64, services: ServiceBatch,
    general: usize, files: usize, opportunities: usize, phase: usize, bodies: usize,
}
static mut STATE: Option<State> = None;
fn locked<R>(body: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    // Single CPU harness. Native gate's contention/custody is tested separately.
    body(unsafe { (&mut *core::ptr::addr_of_mut!(STATE)).as_mut().unwrap() })
}
fn begin_service_segment() -> Option<()> {
    if DENY.load(Ordering::Acquire) { return None; }
    locked(|s| {
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
    locked(|s| { s.bodies += 1; s.scheduler.complete(s.active.take().unwrap(), actual, RunState::Runnable, at) })
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
}
fn service_file(_: &mut dyn FnMut()) {
    service_segment(|| { locked(|s| { s.files += 1; Ok(()) }).unwrap(); physical_work(); });
}
fn diagnostic_service_stage(_: u64) {}
// PUMP_BODIES
fn reset(batch: u8) {
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
