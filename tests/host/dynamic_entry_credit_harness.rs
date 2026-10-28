//! Actual begin_builtin/throttle bodies, real scheduler and background ledger.
//! Captures and irrelevant metrics are substituted; no host timing is native
//! WCET evidence. Every successful grant is actually completed below.
#![allow(dead_code)]
use cyxia_prototype::domains::{Error, ObjectKey, tasks::{Scheduler, ThreadSpec, CpuLayout, Dispatch, RunState}, maintenance::{BackgroundBudgets, CpuDebit}};
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
const LAYOUT: CpuLayout = CpuLayout { business_mask: 13, healthy_mask: 15, generation: 1 };
const OWNER: ObjectKey = ObjectKey { id: 4096, generation: 4 };
const GROUP: ObjectKey = ObjectKey { id: 4, generation: 1 };
const CLUSTER_CALLER: ObjectKey = ObjectKey { id: u64::MAX - 9, generation: 1 };
const REMOTE_ID: u64 = u64::MAX - 10;
static READY: AtomicBool = AtomicBool::new(true);
static NOW: AtomicU64 = AtomicU64::new(1_000_000);
static COMPLETE_READY: [AtomicBool; 64] = [const { AtomicBool::new(false) }; 64];
static CREDIT_NS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
static CREDIT_KIND: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
mod cpu { pub fn slot() -> usize { 3 } }
// Capture timing is covered by the dedicated production-hook harness.
mod learning_evidence { pub mod execution_trace { pub fn selected(_: super::super::Dispatch) {} } }
mod domain_control {
    pub struct Prerequisite { pub domain: u16, pub target: super::ObjectKey }
    pub fn admit_dependency(_: Prerequisite, _: u64, _: u64) -> Result<(), super::Error> { Ok(()) }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Life { Ready }
#[derive(Clone, Copy)]
struct Task { key: ObjectKey, optional: bool, pending: bool, parent: ObjectKey, life: Life, blocked: bool }
const TASK: Task = Task { key: OWNER, optional: false, pending: false, parent: OWNER, life: Life::Ready, blocked: false };
#[derive(Clone, Copy)]
struct Active { dispatch: Dispatch, state: RunState, optional: Option<CpuDebit>, cpu_started: Option<u64> }
struct Counter;
impl Counter { fn add(&mut self, _: u64) {} }
struct Facts { wait: [Counter; 16], node_wait: Counter }
struct State {
    scheduler: Scheduler, layout: CpuLayout, active: [Option<Active>; 64], draining: u64,
    tasks: [Task; 1], throttled: [Option<(ObjectKey, u64)>; 64], probe_key: Option<ObjectKey>,
    background: BackgroundBudgets, facts: Facts,
}
static STATE: Mutex<State> = Mutex::new(State {
    scheduler: Scheduler::new(), layout: LAYOUT, active: [None; 64], draining: 0,
    tasks: [TASK], throttled: [None; 64], probe_key: None,
    background: BackgroundBudgets::new(), facts: Facts { wait: [const { Counter }; 16], node_wait: Counter },
});
pub struct Credit { sequence: u64, thread: ObjectKey, reserved_ns: u64, optional: bool }
fn locked<R>(body: impl FnOnce(&mut State) -> Result<R, Error>) -> Result<R, Error> { body(&mut STATE.lock().unwrap()) }
fn now_ns() -> u64 { NOW.load(Ordering::Acquire) }
fn builtin(slot: usize) -> ObjectKey { ObjectKey { id: slot as u64, generation: 1 } }
fn task_index(tasks: &[Task; 1], key: ObjectKey) -> Result<usize, Error> {
    tasks.iter().position(|task| task.key == key).ok_or(Error::Stale)
}
fn group_index(_: &State, _: ObjectKey) -> Result<usize, Error> { Err(Error::NotFound) }
fn complete_locked(_: &mut State, _: usize) -> Result<(), Error> { unreachable!("no retained completion in this fixture") }
fn admit_service(_: &mut State, _: u64) -> Result<(), Error> { unreachable!("CPU3 admission only") }
fn track_credit(_: usize, result: Result<Option<Credit>, Error>) -> Result<Option<Credit>, Error> { result }
mod capture_credit {
    pub fn retire(_: usize) -> bool { true }
    pub fn available(_: usize) -> bool { true }
}
// NATIVE_ADMISSION
fn reset(budget: u64, ordinary: bool) {
    reset_spec(budget, ordinary, 0);
}
fn reset_spec(budget: u64, ordinary: bool, minimum: u64) {
    let mut state = STATE.lock().unwrap();
    state.scheduler = Scheduler::new();
    state.active = [None; 64];
    state.throttled = [None; 64];
    state.tasks = [TASK];
    state.scheduler.register_group(GROUP).unwrap();
    state.scheduler.admit(ThreadSpec { key: if ordinary { OWNER } else { builtin(3) },
        group: GROUP, cpu: 3, allowed_mask: 8, minimum_ns: minimum, budget_ns: budget }, LAYOUT, 1_000_000).unwrap();
    NOW.store(1_000_000, Ordering::Release);
}
fn finish(credit: Credit, actual: u64) {
    let at = NOW.fetch_add(actual.max(1), Ordering::AcqRel) + actual.max(1);
    let mut state = STATE.lock().unwrap();
    let dispatch = state.active[3].take().unwrap().dispatch;
    assert_eq!(dispatch.sequence, credit.sequence);
    assert_eq!(dispatch.reserved_ns, credit.reserved_ns);
    state.scheduler.complete(dispatch, actual, RunState::Runnable, at).unwrap();
}
#[test]
fn short_syscalls_do_not_force_a_ten_ms_thread_to_wait_a_whole_window() {
    reset(10_000_000, true);
    for _ in 0..20 {
        let credit = begin_builtin(3, now_ns()).expect("short syscall return forced a whole-window stall");
        assert_eq!(credit.thread, OWNER);
        finish(credit, 100_000);
    }
    let state = STATE.lock().unwrap();
    assert_eq!(now_ns(), 3_000_000);
    assert_eq!(state.scheduler.thread_cpu_ns(OWNER), Ok(2_000_000));
    assert_eq!(state.scheduler.cpu_window_usage(3, now_ns()), Ok((2_000_000, 0)));
    assert_eq!(state.scheduler.stats().quarantine_mask, 0);
}
#[test]
fn admitted_one_ms_ordinary_task_can_actually_enter() {
    reset(1_000_000, true);
    let credit = begin_builtin(3, now_ns()).expect("admitted one-ms task could never enter EL0");
    assert_eq!(credit.reserved_ns, 1_000_000);
    finish(credit, 100_000);
}
#[test]
fn guaranteed_window_minimum_does_not_become_an_indivisible_entry_cost() {
    reset_spec(10_000_000, true, 10_000_000);
    for _ in 0..20 {
        finish(begin_builtin(3, now_ns()).expect("minimum guarantee became a per-entry wall stall"), 100_000);
    }
    assert_eq!(STATE.lock().unwrap().scheduler.thread_cpu_ns(OWNER), Ok(2_000_000));
}
#[test]
fn short_tail_is_not_executed_or_falsely_charged_and_rolls_only_next_window() {
    reset(10_000_000, true);
    finish(begin_builtin(3, now_ns()).unwrap(), 9_600_000);
    assert!(begin_builtin(3, now_ns()).is_none());
    {
        let state = STATE.lock().unwrap();
        assert_eq!(state.scheduler.thread_cpu_ns(OWNER), Ok(9_600_000));
        assert_eq!(state.scheduler.cpu_window_usage(3, now_ns()), Ok((9_600_000, 0)));
    }
    NOW.store(101_000_000, Ordering::Release);
    let credit = begin_builtin(3, now_ns()).unwrap();
    assert_eq!(credit.reserved_ns, 10_000_000);
    finish(credit, 100_000);
}
#[test]
fn builtin_full_ten_ms_envelope_and_hard_cap_remain_in_force() {
    reset(30_000_000, false);
    for cost in [9_000_000, 9_000_000, 2_100_000] {
        let credit = begin_builtin(3, now_ns()).unwrap();
        assert_eq!(credit.reserved_ns, 10_000_000);
        finish(credit, cost);
    }
    assert!(begin_builtin(3, now_ns()).is_none());
    assert_eq!(STATE.lock().unwrap().scheduler.cpu_window_usage(3, now_ns()), Ok((20_100_000, 0)));
}
