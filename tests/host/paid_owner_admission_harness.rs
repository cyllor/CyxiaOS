#![allow(dead_code)]
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS};
use cyxia_prototype::domains::tasks::*;
use cyxia_prototype::domains::maintenance::{BackgroundBudgets, CpuDebit};
static CPU: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(true);
static CREDIT_KIND: [AtomicU64; 1] = [AtomicU64::new(0)];
static CREDIT_NS: [AtomicU64; 1] = [AtomicU64::new(0)];
static COMPLETE_READY: [AtomicBool; 1] = [AtomicBool::new(false)];
const BUILTIN_WINDOW_HEADROOM_NS: u64 = 20_000_000;
mod cpu { pub fn slot() -> usize { super::CPU.load(super::Ordering::Acquire) } }
mod timer {
    pub fn ticks() -> u64 { super::NOW.load(super::Ordering::Acquire) }
    pub fn frequency() -> u64 { 1_000_000_000 }
}
fn now_ns() -> u64 { timer::ticks() }
fn group(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
#[derive(Clone, Copy)]
struct Active { dispatch: Dispatch, state: RunState, optional: Option<CpuDebit> }
struct State {
    scheduler: Scheduler, active: [Option<Active>; 1], layout: CpuLayout,
    draining: u64, service_admitted: bool, background: BackgroundBudgets,
}
static mut STATE: State = State { scheduler: Scheduler::new(), active: [None],
    layout: CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 },
    draining: 0, service_admitted: false, background: BackgroundBudgets::new() };
mod replay { pub fn service_admitted() {} }
mod baseline_diagnostics { pub fn failure(_: usize, _: u64) {} }
fn track_credit(_: usize, value: Result<Option<Credit>, Error>) -> Result<Option<Credit>, Error> { value }
fn discard_capture(_: usize) {}
fn complete_locked(s: &mut State, _: usize) -> Result<(), Error> {
    let active = s.active[0].unwrap();
    s.scheduler.complete(active.dispatch, 100_000, RunState::Runnable, now_ns())?;
    s.active[0] = None;
    COMPLETE_READY[0].store(false, Ordering::Release);
    CREDIT_KIND[0].store(0, Ordering::Release);
    Ok(())
}
// PRODUCTION_BODIES

fn prepare(base: u64, late_peer: bool) {
    CPU.store(0, Ordering::Release); NOW.store(base, Ordering::Release);
    CREDIT_KIND[0].store(0, Ordering::Release); COMPLETE_READY[0].store(false, Ordering::Release);
    unsafe {
        let s = &mut *core::ptr::addr_of_mut!(STATE);
        s.scheduler = Scheduler::new(); s.active = [None]; s.service_admitted = false;
        s.scheduler.register_group(group(14)).unwrap();
    }
    let guard = acquire_guard().unwrap();
    if !late_peer {
        CPU.store(2, Ordering::Release);
        assert!(matches!(acquire_guard(), Err(Error::Busy)));
        CPU.store(0, Ordering::Release);
    }
    drop(guard);
    NOW.store(base + 900_000, Ordering::Release);
    assert_eq!(begin_service_segment().unwrap().reserved_ns, 2_500_000);
    if late_peer {
        CPU.store(2, Ordering::Release);
        assert!(matches!(acquire_guard(), Err(Error::Busy)), "late peer stole the admitted service turn");
        CPU.store(0, Ordering::Release);
    }
}

#[test]
fn actual_admission_authorizes_after_old_turn_end_and_settles_exact_work() {
    prepare(100_000_000, false);
    NOW.store(101_100_000, Ordering::Release);
    assert!(revalidate_service_segment());
    assert_eq!(authorize_service_turn(), Ok(()), "fresh service grant lost its paid authorization turn");
    let held = locked(|s| Ok(s.active[0].unwrap().dispatch)).unwrap();
    assert_eq!((held.started_ns, held.reserved_ns), (100_900_000, 2_500_000));
    COMPLETE_READY[0].store(true, Ordering::Release);
    assert_eq!(authorize_service_turn(), Err(Error::Auth), "pending bill became authority");
    NOW.store(101_200_000, Ordering::Release);
    locked(|s| complete_locked(s, 0)).unwrap();
    assert_eq!(locked(|s| s.scheduler.thread_cpu_ns(group(0x101))), Ok(100_000));
    assert_eq!(authorize_service_turn(), Err(Error::NotReady));
    NOW.store(102_500_000, Ordering::Release);
    assert!(matches!(acquire_guard(), Err(Error::Busy)), "paid turn renewed past its original epoch cap");
    CPU.store(2, Ordering::Release);
    drop(acquire_guard().unwrap());
}

#[test]
fn late_peer_cannot_turn_a_new_credit_into_authority_after_its_original_expiry() {
    prepare(200_000_000, true);
    NOW.store(201_100_000, Ordering::Release);
    assert_eq!(authorize_service_turn(), Ok(()));
    // No peer was queued at the initial metadata release, so admission starts
    // a legitimate new epoch at 200.9 ms; it still ends at the dispatch bound.
    NOW.store(203_400_000, Ordering::Release);
    assert!(matches!(acquire_guard(), Err(Error::Busy)));
    CPU.store(2, Ordering::Release); drop(acquire_guard().unwrap());
    CPU.store(0, Ordering::Release); NOW.store(205_000_000, Ordering::Release);
    assert_eq!(authorize_service_turn(), Err(Error::Expired));
    // Retain exactly the same dispatch; preference never settles or refreshes it.
    let active = locked(|s| Ok(s.active[0].unwrap().dispatch)).unwrap();
    assert_eq!((active.started_ns, active.reserved_ns), (200_900_000, 2_500_000));
}
