//! Actual service_file body with a controllable file-ABI boundary and the real
//! physical/caller Scheduler. No host result is native filesystem evidence.
#![allow(dead_code)]
use cyxia_prototype::domains::{Error, ObjectKey, tasks::{CpuLayout, Dispatch, RunState, Scheduler, ThreadSpec}};
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
const TASKS: usize = 1;
const OWNER: ObjectKey = ObjectKey { id: 4096, generation: 4 };
const GROUP: ObjectKey = ObjectKey { id: 4, generation: 1 };
const LAYOUT: CpuLayout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
static NOW: AtomicU64 = AtomicU64::new(1_000_000);
static CASE: AtomicU64 = AtomicU64::new(0);
static FILE_PENDING: [AtomicBool; TASKS] = [AtomicBool::new(false)];
static FILE_BUSY: [AtomicBool; TASKS] = [AtomicBool::new(false)];
static FILE_DONE: [AtomicBool; TASKS] = [AtomicBool::new(false)];
#[derive(Clone, Copy, PartialEq, Eq)]
enum Life { Waiting }
#[derive(Clone, Copy)]
struct Task { key: ObjectKey, life: Life }
#[derive(Clone, Copy)]
struct Active { dispatch: Dispatch }
struct State { tasks: [Task; TASKS], active: [Option<Active>; 1], scheduler: Scheduler }
static STATE: Mutex<State> = Mutex::new(State {
    tasks: [Task { key: OWNER, life: Life::Waiting }], active: [None], scheduler: Scheduler::new(),
});
mod user {
    #[derive(Clone, Copy)]
    pub struct Context { pub regs: [u64; 31] }
}
static mut CONTEXTS: [user::Context; TASKS] = [user::Context { regs: [0; 31] }];
fn locked<R>(f: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> {
    f(&mut STATE.lock().unwrap())
}
fn service_segment<R>(body: impl FnOnce() -> R) -> Option<R> { Some(body()) }
fn begin_file_credit(owner: ObjectKey) -> Result<Option<Dispatch>, Error> {
    locked(|s| {
        let credit = s.scheduler.dispatch_service_exact(owner, 0, LAYOUT,
            NOW.load(Ordering::Acquire), 2_500_000)?;
        s.active[0] = credit.map(|dispatch| Active { dispatch });
        Ok(credit)
    })
}
mod timer {
    pub fn cpu_ticks() -> u64 { super::NOW.fetch_add(1000, super::Ordering::AcqRel) }
}
fn finish_cpu_interval(started: u64) -> (u64, u64, u64) {
    (started, NOW.fetch_add(1000, Ordering::AcqRel), 100)
}
fn complete_builtin(_: usize, actual: u64, finished: u64) -> Result<(), Error> {
    locked(|s| {
        let credit = s.active[0].take().unwrap().dispatch;
        s.scheduler.complete(credit, actual, RunState::Blocked, finished)
    })
}
fn error_word(_: Error) -> u64 { (-22i64) as u64 }
mod domain_file_abi {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    // DISPATCH_RESULT
    pub fn record_credit_attempt(_: ObjectKey, _: Result<bool, Error>) {}
    pub fn pending_delivery(_: ObjectKey) -> bool { CASE.load(Ordering::Acquire) == 3 }
    pub fn dispatch(_: ObjectKey, context: &mut user::Context, _: &mut dyn FnMut()) -> DispatchResult {
        match CASE.load(Ordering::Acquire) {
            0 => { context.regs[0] = (-11i64) as u64; DispatchResult::RetryBeforeEffect }
            1 => { context.regs[0] = 0; DispatchResult::Returned }
            // Delivered EAGAIN is an actual operation receipt; replaying it
            // because of its integer errno would consume the request twice.
            2 => { context.regs[0] = (-11i64) as u64; DispatchResult::Returned }
            3 => { context.regs[0] = (-11i64) as u64; DispatchResult::Returned }
            _ => DispatchResult::NotHandled,
        }
    }
}
// FILE_SERVICE_FUNCTION

fn reset(case: u64) {
    let mut s = STATE.lock().unwrap();
    s.scheduler = Scheduler::new();
    s.active = [None];
    s.scheduler.register_group(GROUP).unwrap();
    s.scheduler.admit(ThreadSpec { key: OWNER, group: GROUP, cpu: 3,
        allowed_mask: 12, minimum_ns: 0, budget_ns: 10_000_000 }, LAYOUT, 0).unwrap();
    s.scheduler.set_runnable(OWNER, false, 0).unwrap();
    NOW.store(1_000_000, Ordering::Release);
    CASE.store(case, Ordering::Release);
    FILE_PENDING[0].store(true, Ordering::Release);
    FILE_BUSY[0].store(false, Ordering::Release);
    FILE_DONE[0].store(false, Ordering::Release);
    unsafe { (*core::ptr::addr_of_mut!(CONTEXTS))[0].regs[8] = 0x40; }
}

#[test]
fn no_effect_retry_stays_with_kernel_and_settles_each_original_credit() {
    reset(0);
    service_file(&mut || {});
    assert!(FILE_PENDING[0].load(Ordering::Acquire), "no-effect retry lost its pending syscall");
    assert!(!FILE_BUSY[0].load(Ordering::Acquire));
    assert!(!FILE_DONE[0].load(Ordering::Acquire), "no-effect retry manufactured an EL0 completion");
    assert_eq!(STATE.lock().unwrap().scheduler.cpu_window_usage(0, NOW.load(Ordering::Acquire)), Ok((100, 0)));
    CASE.store(1, Ordering::Release);
    service_file(&mut || {});
    assert!(!FILE_PENDING[0].load(Ordering::Acquire));
    assert!(FILE_DONE[0].load(Ordering::Acquire));
    let s = STATE.lock().unwrap();
    assert_eq!(s.scheduler.cpu_window_usage(0, NOW.load(Ordering::Acquire)), Ok((200, 0)));
    assert_eq!(s.scheduler.thread_cpu_ns(OWNER), Ok(200));
}

#[test]
fn delivered_eagain_is_not_replayed_as_a_no_effect_retry() {
    reset(2);
    service_file(&mut || {});
    assert!(FILE_DONE[0].load(Ordering::Acquire));
    assert!(!FILE_PENDING[0].load(Ordering::Acquire));
}

#[test]
fn retained_result_stays_queued_for_its_existing_receipt() {
    reset(3);
    service_file(&mut || {});
    assert!(FILE_DONE[0].load(Ordering::Acquire));
    assert!(FILE_PENDING[0].load(Ordering::Acquire));
}
