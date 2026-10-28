//! No scheduler or time is simulated implicitly: CPU identity and shared tick
//! are controlled, while the production mutex/guard bodies execute unchanged.
#![allow(dead_code, unused_imports)]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::domains::{Action, Error, ObjectKey};
use cyxia_prototype::domains::tasks::{Scheduler, Dispatch, ThreadSpec, CpuLayout, RunState};
static CPU: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(100);
mod cpu { pub fn slot() -> usize { super::CPU.load(super::Ordering::Acquire) } }
mod timer {
    pub fn ticks() -> u64 { super::NOW.load(super::Ordering::Acquire) }
    pub fn frequency() -> u64 { 1000 }
    pub fn cpu_ticks() -> u64 { 0 }
}
struct State { effects: u64, scheduler: Scheduler, active: Option<Dispatch> }
static mut STATE: State = State { effects: 0, scheduler: Scheduler::new(), active: None };
const SERVICE: ObjectKey = ObjectKey { id: 0x101, generation: 1 };
const GROUP: ObjectKey = ObjectKey { id: 14, generation: 1 };
const LAYOUT: CpuLayout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
fn begin_service_segment() -> Option<()> {
    locked(|state| {
        let mut dispatch = state.scheduler.dispatch_with_window_headroom(0, LAYOUT,
            NOW.load(Ordering::Acquire) * 1_000_000, 2_500_000, 20_000_000)?.ok_or(Error::Budget)?;
        if dispatch.reserved_ns < 2_500_000 {
            dispatch = state.scheduler.resize_dispatch(dispatch, 2_500_000)?;
        }
        assert_eq!(dispatch.thread, SERVICE);
        state.active = Some(dispatch);
        assert_eq!(effect(2), Err(Error::Busy));
        CPU.store(0, Ordering::Release);
        Ok(())
    }).ok()
}
fn revalidate_service_segment() -> bool {
    // Matches production revalidate_unstarted's deliberate Busy fallback:
    // the existing grant remains valid and may not be stranded on contention.
    locked(|state| Ok(state.active.is_some())).unwrap_or(true)
}
fn finish_cpu_interval(_: u64) -> (u64, u64, u64) {
    let at = NOW.load(Ordering::Acquire) * 1_000_000;
    (at, at + 1000, 1000)
}
fn complete_service(actual: u64, at: u64) -> Result<(), Error> {
    locked(|state| state.scheduler.complete(state.active.take().unwrap(), actual, RunState::Runnable, at))
}
// OWNER_GATE_MODULE
// OWNER_GATE_BODY
static LIVE: AtomicBool = AtomicBool::new(true);
fn service_witness_locked(_: &State) -> Result<(), Error> {
    if LIVE.load(Ordering::Acquire) { Ok(()) } else { Err(Error::Budget) }
}
// PUBLICATION_BODIES
fn effect(slot: usize) -> Result<u64, Error> {
    CPU.store(slot, Ordering::Release);
    locked(|state| { state.effects += 1; Ok(state.effects) })
}
fn hold_and_queue(owner: usize, waiter: usize) {
    CPU.store(owner, Ordering::Release);
    locked(|_| {
        CPU.store(waiter, Ordering::Release);
        assert_eq!(effect(waiter), Err(Error::Busy));
        CPU.store(owner, Ordering::Release);
        Ok(())
    }).unwrap();
}
#[test]
fn continuously_runnable_business_cpu_cannot_bypass_waiting_owner() {
    NOW.store(100, Ordering::Release);
    hold_and_queue(2, 0);
    NOW.store(101, Ordering::Release);
    assert_eq!(effect(2), Err(Error::Busy), "business CPU bypassed the waiting task owner");
    assert!(effect(0).is_ok());
    NOW.store(102, Ordering::Release);
    assert!(effect(2).is_ok());
}
#[test]
fn missing_waiter_expires_once_and_cannot_leave_a_sticky_global_reservation() {
    NOW.store(200, Ordering::Release);
    hold_and_queue(2, 1);
    NOW.store(201, Ordering::Release);
    assert_eq!(effect(2), Err(Error::Busy));
    assert_eq!(effect(0), Err(Error::Busy), "waiting CPU lost its bounded handoff");
    NOW.store(202, Ordering::Release);
    assert!(effect(0).is_ok());
    assert!(effect(0).is_ok(), "absent CPU repeatedly reserved the global task gate");
    NOW.store(203, Ordering::Release);
    assert!(effect(2).is_ok());
}
#[test]
fn result_error_releases_the_gate_and_preserves_a_real_waiter() {
    NOW.store(300, Ordering::Release);
    CPU.store(2, Ordering::Release);
    let result: Result<(), Error> = locked(|_| {
        assert_eq!(effect(1), Err(Error::Busy));
        CPU.store(2, Ordering::Release);
        Err(Error::Io)
    });
    assert_eq!(result, Err(Error::Io));
    NOW.store(301, Ordering::Release);
    assert!(effect(1).is_ok());
}
#[test]
fn invalid_cpu_does_not_execute_shared_state_body() {
    NOW.store(400, Ordering::Release);
    CPU.store(4, Ordering::Release);
    let mut called = false;
    assert_eq!(locked(|_| { called = true; Ok(()) }), Err(Error::Busy));
    assert!(!called);
}
#[test]
fn baseline_publication_uses_the_same_exclusion_and_handoff_guard() {
    NOW.store(500, Ordering::Release);
    CPU.store(0, Ordering::Release);
    LIVE.store(true, Ordering::Release);
    let publication = reserve_baseline_publication(Action::ServiceBatch(1),
        ObjectKey { id: 1, generation: 1 }).unwrap().unwrap();
    assert_eq!(effect(1), Err(Error::Busy));
    CPU.store(0, Ordering::Release);
    drop(publication);
    NOW.store(501, Ordering::Release);
    assert_eq!(effect(0), Err(Error::Busy));
    assert!(effect(1).is_ok());
    NOW.store(502, Ordering::Release);
    assert!(effect(0).is_ok());
}
#[test]
fn failed_service_witness_releases_publication_without_allocating_custody() {
    NOW.store(600, Ordering::Release);
    CPU.store(0, Ordering::Release);
    LIVE.store(false, Ordering::Release);
    assert!(matches!(reserve_baseline_publication(Action::ServiceBatch(1),
        ObjectKey { id: 1, generation: 1 }), Err(Error::Budget)));
    assert!(effect(0).is_ok());
    LIVE.store(true, Ordering::Release);
}
#[test]
fn paid_owner_must_reach_its_real_body_after_admission_and_revalidation() {
    NOW.store(700, Ordering::Release);
    unsafe {
        let state = &mut *core::ptr::addr_of_mut!(STATE);
        state.scheduler = Scheduler::new();
        state.active = None;
        state.scheduler.register_group(GROUP).unwrap();
        state.scheduler.admit(ThreadSpec { key: SERVICE, group: GROUP, cpu: 0,
            allowed_mask: 1, minimum_ns: 20_000_000, budget_ns: 60_000_000 }, LAYOUT, 700_000_000).unwrap();
    }
    hold_and_queue(2, 0);
    NOW.store(701, Ordering::Release);
    CPU.store(0, Ordering::Release);
    let outcome = service_segment(|| locked(|state| { state.effects += 1; Ok(()) }));
    assert!(matches!(outcome, Some(Ok(()))),
        "paid owner could not reach its body after admission: {outcome:?}");
    assert_eq!(unsafe { (&*core::ptr::addr_of!(STATE)).scheduler.thread_cpu_ns(SERVICE) }, Ok(1000));
    // Leave no synthetic contender pending between independently clocked cases.
    NOW.store(702, Ordering::Release);
    assert_eq!(effect(0), Err(Error::Busy));
    assert!(effect(2).is_ok());
    NOW.store(703, Ordering::Release);
    assert!(effect(0).is_ok());
}
