#![allow(dead_code)]
extern crate self as cyxia_arch_aarch64;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use cyxia_prototype::domains::{Error, ObjectKey, WINDOW_NS};
use cyxia_prototype::domains::tasks::*;
use cyxia_prototype::domains::maintenance::{BackgroundBudgets, CpuDebit};
static CPU: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(100_000_000);
static WORK: AtomicU64 = AtomicU64::new(0);
static READY: AtomicBool = AtomicBool::new(true);
static HINT: AtomicBool = AtomicBool::new(false);
static REENTER: AtomicBool = AtomicBool::new(false);
static STEP_CALLS: AtomicU64 = AtomicU64::new(0);
static BODY_EFFECTS: AtomicU64 = AtomicU64::new(0);
static RECURSED: AtomicBool = AtomicBool::new(false);
static TICKETS: AtomicU64 = AtomicU64::new(0);
static CURRENT_TICKET: AtomicU64 = AtomicU64::new(0);
static CREDIT_KIND: [AtomicU64; 1] = [AtomicU64::new(0)];
static CREDIT_NS: [AtomicU64; 1] = [AtomicU64::new(0)];
static COMPLETE_READY: [AtomicBool; 1] = [AtomicBool::new(false)];
static COMPLETE_ACTUAL: [AtomicU64; 1] = [AtomicU64::new(0)];
static COMPLETE_AT: [AtomicU64; 1] = [AtomicU64::new(0)];
const BUILTIN_WINDOW_HEADROOM_NS: u64 = 20_000_000;
// Controlled boot reset between single-threaded tests; every actual acquire
// still executes the production Gate through this static dereference.
struct ResettableGate(core::cell::UnsafeCell<owner_gate::Gate>);
unsafe impl Sync for ResettableGate {}
impl core::ops::Deref for ResettableGate {
    type Target = owner_gate::Gate;
    fn deref(&self) -> &Self::Target { unsafe { &*self.0.get() } }
}
pub mod cpu { pub fn slot() -> usize { super::CPU.load(super::Ordering::Acquire) } }
mod timer {
    pub fn ticks() -> u64 { super::NOW.load(super::Ordering::Acquire) }
    pub fn frequency() -> u64 { 1_000_000_000 }
    pub fn cpu_ticks() -> u64 { super::WORK.load(super::Ordering::Acquire) }
    pub fn cpu_elapsed_ns(start: u64) -> u64 { cpu_ticks() - start }
    pub fn cpu_ns(ticks: u64) -> u64 { ticks }
}
fn now_ns() -> u64 { timer::ticks() }
fn work(ns: u64) { WORK.fetch_add(ns, Ordering::AcqRel); NOW.fetch_add(ns, Ordering::AcqRel); }
fn group(id: u64) -> ObjectKey { ObjectKey { id, generation: 1 } }
struct Board;
impl Board { fn now_ns(&self) -> u64 { now_ns() } }
#[derive(Clone, Copy)]
struct Active { dispatch: Dispatch, state: RunState, optional: Option<CpuDebit>, cpu_started: Option<u64> }
struct State {
    scheduler: Scheduler, active: [Option<Active>; 1], layout: CpuLayout, draining: u64,
    service_admitted: bool, background: BackgroundBudgets, bills: Vec<(u64, u64, u64)>,
}
static mut STATE: State = State { scheduler: Scheduler::new(), active: [None],
    layout: CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 }, draining: 0,
    service_admitted: false, background: BackgroundBudgets::new(), bills: Vec::new() };
mod replay { pub fn service_admitted() {} }
fn track_credit(_: usize, value: Result<Option<Credit>, Error>) -> Result<Option<Credit>, Error> { value }
fn discard_capture(_: usize) {}
mod capture_credit {
    pub fn retire(_: usize) -> bool { true }
    pub fn available(_: usize) -> bool { true }
    pub fn cancelled(_: usize, _: super::Dispatch, _: Option<super::CpuDebit>) {}
}
fn finish_capture(_: usize, _: u64, _: u64) {}
fn finish_cpu_interval(start: u64) -> (u64, u64, u64) {
    let at = now_ns(); let actual = timer::cpu_elapsed_ns(start); (at - actual, at, actual)
}
fn complete_locked(s: &mut State, _: usize) -> Result<(), Error> {
    let a = s.active[0].ok_or(Error::Stale)?;
    let cpu = COMPLETE_ACTUAL[0].load(Ordering::Acquire);
    let at = COMPLETE_AT[0].load(Ordering::Acquire);
    s.scheduler.complete(a.dispatch, cpu, RunState::Runnable, at)?;
    s.bills.push((a.dispatch.sequence, cpu, at));
    s.active[0] = None; COMPLETE_READY[0].store(false, Ordering::Release);
    CREDIT_KIND[0].store(0, Ordering::Release); Ok(())
}
mod baseline_diagnostics {
    pub fn failure(_: usize, _: u64) {}
    pub fn opportunity(hint: bool, site: u64, _: u64, _: bool) -> Option<u64> {
        if !hint { return None; }
        assert_eq!(site, 2);
        let ticket = super::TICKETS.fetch_add(1, super::Ordering::AcqRel) + 1;
        super::CURRENT_TICKET.store(ticket, super::Ordering::Release); Some(ticket)
    }
    pub fn body_start(_: Option<u64>, _: u64, _: u64) {}
    pub fn body_finish(ticket: Option<u64>, _: &Result<bool, super::Error>, _: u64) {
        assert_eq!(ticket, Some(super::CURRENT_TICKET.load(super::Ordering::Acquire)),
            "recursive progress replaced the outer diagnostic ticket");
    }
    pub fn finish(_: Option<u64>, _: bool, _: u64, _: bool) {}
}
pub mod domain_tasks {
    pub use super::{begin_service_segment, revalidate_service_segment, complete_service,
        authorize_service_turn, service_baseline_progress};
}
mod learning_evidence {
    pub fn attempt(_: super::ObjectKey, _: cyxia_prototype::learning::reward::CpuClass)
        -> Result<Option<()>, super::Error> { Ok(None) }
    pub fn finish_attempt(_: &mut (), _: u64, _: u64) -> Result<(), super::Error> { Ok(()) }
}
static mut ORDER: Vec<u8> = Vec::new();
fn order(n: u8) { unsafe { (&mut *core::ptr::addr_of_mut!(ORDER)).push(n); } }
static POLLING: AtomicBool = AtomicBool::new(false);
mod smp { pub mod prototype_runtime {
    #[derive(Default)] pub struct Coordinator;
    impl Coordinator { pub fn poll(&mut self) {
        assert!(!super::super::POLLING.swap(true, super::super::Ordering::AcqRel));
        super::super::order(1); super::super::work(17_000);
        super::super::POLLING.store(false, super::super::Ordering::Release);
    } }
} }
mod domain_platform {
    pub fn now_ns() -> u64 { super::now_ns() }
    pub fn poll(_: u64) -> Result<(), super::Error> {
        assert!(!super::POLLING.swap(true, super::Ordering::AcqRel));
        super::order(2); super::work(13_000);
        super::POLLING.store(false, super::Ordering::Release); Ok(())
    }
}
struct NativeTcp<'a>(core::marker::PhantomData<&'a mut [u8]>);
fn network_turn(_: &mut smp::prototype_runtime::Coordinator, _: &mut Option<NativeTcp<'_>>, _: u64) -> Result<(), Error> { Ok(()) }
fn fail(code: u64) -> ! { panic!("unexpected service failure {code}") }
mod learning_replay {
    use super::*;
    type DomainError = Error;
    static GATE: AtomicBool = AtomicBool::new(false);
    static ADDRESS: AtomicUsize = AtomicUsize::new(0);
    struct State { archive: u64, snapshot: u64 }
    static mut ARCHIVE: State = State { archive: 0, snapshot: 100_000_000 };
    pub fn reset() {
        GATE.store(false, Ordering::Release);
        unsafe { ARCHIVE = State { archive: 0, snapshot: 100_000_000 }; }
        ADDRESS.store(core::ptr::addr_of_mut!(ARCHIVE) as usize, Ordering::Release);
    }
    pub fn baseline_activation_pending() -> bool { HINT.load(Ordering::Acquire) }
    mod diagnostic {
        pub struct Attempt;
        impl Attempt { pub fn new(_: u64) -> Self { Self } }
    }
    fn service(_: &mut diagnostic::Attempt) -> Result<bool, Error> {
        STEP_CALLS.fetch_add(1, Ordering::AcqRel); order(3);
        assert!(!POLLING.load(Ordering::Acquire), "helper ran inside a poll borrow");
        work(100_000);
        with(|s| {
            if REENTER.swap(false, Ordering::AcqRel) {
                super::mechanism_progress(&mut smp::prototype_runtime::Coordinator);
                RECURSED.store(true, Ordering::Release);
            }
            if now_ns() > s.snapshot + 50_000_000 {
                HINT.store(false, Ordering::Release); return Err(Error::Expired);
            }
            BODY_EFFECTS.fetch_add(1, Ordering::AcqRel);
            s.archive += 1; HINT.store(false, Ordering::Release); Ok(true)
        })
    }
    fn retain_error(_: Error, _: Option<&mut diagnostic::Attempt>) { let _ = with(|_| Ok(())); }
    fn publish_evidence() { let _ = with(|_| Ok(())); }
    // REPLAY_BODIES
    pub fn with_archive(body: impl FnOnce(&mut u64)) { with(|s| { body(&mut s.archive); Ok(()) }).unwrap(); }
    pub fn snapshot() -> u64 { with(|s| Ok(s.snapshot)).unwrap() }
    pub fn first_at(at: u64) { with(|s| { s.snapshot = at; Ok(()) }).unwrap(); }
}
// PRODUCTION_BODIES
fn reset() {
    unsafe { *LOCK.0.get() = owner_gate::Gate::new(); }
    CPU.store(0, Ordering::Release); NOW.store(100_000_000, Ordering::Release); WORK.store(0, Ordering::Release);
    READY.store(true, Ordering::Release); HINT.store(true, Ordering::Release);
    REENTER.store(false, Ordering::Release); RECURSED.store(false, Ordering::Release);
    STEP_CALLS.store(0, Ordering::Release); BODY_EFFECTS.store(0, Ordering::Release);
    TICKETS.store(0, Ordering::Release); CURRENT_TICKET.store(0, Ordering::Release);
    COMPLETE_READY[0].store(false, Ordering::Release); CREDIT_KIND[0].store(0, Ordering::Release);
    POLLING.store(false, Ordering::Release); learning_replay::reset();
    unsafe { (&mut *core::ptr::addr_of_mut!(ORDER)).clear();
        let s = &mut *core::ptr::addr_of_mut!(STATE);
        s.scheduler = Scheduler::new(); s.active = [None]; s.service_admitted = false; s.bills.clear();
        s.scheduler.register_group(group(14)).unwrap(); }
}
fn bills() -> Vec<(u64, u64, u64)> { locked(|s| Ok(s.bills.clone())).unwrap() }
#[test]
fn progress_retries_before_returning_to_suspended_io() {
    reset(); let mut c = smp::prototype_runtime::Coordinator;
    mechanism_progress(&mut c);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 1, "owned baseline did not run at the actual progress boundary");
    assert_eq!(unsafe { &*core::ptr::addr_of!(ORDER) }, &[1, 2, 3]);
    assert_eq!(bills().iter().map(|b| b.1).sum::<u64>(), 100_000);
    assert_eq!(learning_replay::snapshot(), 100_000_000);
}
#[test]
fn unified_suspended_io_pays_old_helper_and_resumed_work_once() {
    reset(); let mut c = smp::prototype_runtime::Coordinator;
    let mut tcp = None;
    service_work(&mut c, &mut tcp, 1, |yield_io| { work(20_000); yield_io(); work(30_000); });
    let b = bills();
    assert_eq!(b.iter().map(|b| b.1).collect::<Vec<_>>(), [20_000, 100_000, 30_000]);
    assert!(b.windows(2).all(|b| b[0].0 != b[1].0));
    assert_eq!(locked(|s| s.scheduler.thread_cpu_ns(group(0x101))), Ok(150_000));
    assert_eq!(WORK.load(Ordering::Acquire), 180_000); // polls have their own work
}
#[test]
fn held_archive_gate_returns_busy_without_aliasing_the_suspended_buffer() {
    reset(); let mut c = smp::prototype_runtime::Coordinator;
    learning_replay::with_archive(|archive| {
        *archive = 41;
        let result = service_io_piece(None, &mut || mechanism_progress(&mut c), |yield_io| {
            work(20_000); yield_io(); assert_eq!(*archive, 41); work(30_000); *archive += 1;
        });
        assert!(result.is_some()); assert_eq!(*archive, 42);
    });
    assert_eq!(BODY_EFFECTS.load(Ordering::Acquire), 0);
    assert_eq!(bills().iter().map(|b| b.1).collect::<Vec<_>>(), [20_000, 100_000, 30_000]);
    assert!(HINT.load(Ordering::Acquire));
    mechanism_progress(&mut c); assert_eq!(BODY_EFFECTS.load(Ordering::Acquire), 1);
}
#[test]
fn recursive_progress_cannot_replace_a_live_diagnostic_ticket() {
    reset(); REENTER.store(true, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert!(RECURSED.load(Ordering::Acquire));
    assert_eq!(TICKETS.load(Ordering::Acquire), 1, "recursive progress replaced the outer diagnostic ticket");
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(bills().len(), 1);
}
#[test]
fn denied_gate_retains_the_exact_submitted_bill_until_real_handoff() {
    reset(); let original = begin_service_segment().unwrap(); work(60_000);
    CPU.store(2, Ordering::Release); assert!(acquire_guard().is_err());
    CPU.store(0, Ordering::Release); NOW.store(102_500_000, Ordering::Release);
    assert_eq!(complete_service(60_000, now_ns()), Ok(()));
    assert!(COMPLETE_READY[0].load(Ordering::Acquire));
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 0);
    assert_eq!(COMPLETE_ACTUAL[0].load(Ordering::Acquire), 60_000);
    assert!(COMPLETE_READY[0].load(Ordering::Acquire));
    assert_eq!(unsafe { (&*core::ptr::addr_of!(STATE)).active[0].unwrap().dispatch.sequence }, original.sequence);
    CPU.store(2, Ordering::Release); drop(acquire_guard().unwrap());
    CPU.store(0, Ordering::Release); NOW.store(104_000_000, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(BODY_EFFECTS.load(Ordering::Acquire), 1);
    assert_eq!(bills().iter().map(|b| b.1).collect::<Vec<_>>(), [60_000, 100_000]);
}
#[test]
fn no_hint_or_failed_authority_never_runs_a_helper_body() {
    reset(); HINT.store(false, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!((TICKETS.load(Ordering::Acquire), STEP_CALLS.load(Ordering::Acquire)), (0, 0));
    HINT.store(true, Ordering::Release); READY.store(false, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 0);
    READY.store(true, Ordering::Release); CPU.store(2, Ordering::Release);
    service_baseline_progress(); assert_eq!(STEP_CALLS.load(Ordering::Acquire), 0);
}
#[test]
fn exhausted_real_service_budget_defers_without_refreshing_the_first_snapshot() {
    reset(); HINT.store(false, Ordering::Release);
    for _ in 0..24 {
        assert!(service_segment(|| work(2_500_000)).is_some());
    }
    assert_eq!(bills().iter().map(|b| b.1).sum::<u64>(), 60_000_000);
    learning_replay::first_at(now_ns()); HINT.store(true, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 0);
    assert_eq!(learning_replay::snapshot(), 160_000_000);
    assert!(HINT.load(Ordering::Acquire));
    NOW.store(200_000_000, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(BODY_EFFECTS.load(Ordering::Acquire), 1);
    assert_eq!(learning_replay::snapshot(), 160_000_000);
    assert_eq!(bills().iter().map(|b| b.1).sum::<u64>(), 60_100_000);
}
#[test]
fn progress_cannot_refresh_an_expired_original_snapshot() {
    reset(); NOW.store(160_000_000, Ordering::Release);
    mechanism_progress(&mut smp::prototype_runtime::Coordinator);
    assert_eq!(STEP_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(BODY_EFFECTS.load(Ordering::Acquire), 0);
    assert_eq!(learning_replay::snapshot(), 100_000_000);
}
