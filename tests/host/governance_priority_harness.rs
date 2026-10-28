//! Host wiring for the actual native step and governance settlement functions.
//! Only architectural entry and unrelated workers are substituted. Credit
//! allocation, settlement and window accounting use the production Scheduler.
#![allow(dead_code)]
use cyxia_prototype::domains::{
    Error,
    tasks::{ControlCredit, CpuLayout, Scheduler},
};
use std::sync::{Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};

const PREPAY_NS: u64 = 2_500_000;
const PROBE_PREPAY_NS: u64 = 8_000_000;
static READY: AtomicBool = AtomicBool::new(true);
static REQUEST: AtomicU64 = AtomicU64::new(1);
static TARGET: AtomicU64 = AtomicU64::new(1);
static CONTROL_MAX_DEBIT: AtomicU64 = AtomicU64::new(0);
static CONTROL_TOTAL_DEBIT: AtomicU64 = AtomicU64::new(0);
static NEW_WORK: AtomicBool = AtomicBool::new(false);
static GOVERNANCE_PENDING: AtomicBool = AtomicBool::new(false);
static BLOCK_SETTLEMENT: AtomicBool = AtomicBool::new(false);
static NOW: AtomicU64 = AtomicU64::new(1_000_000);
static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());
const LAYOUT: CpuLayout = CpuLayout {
    business_mask: 13, healthy_mask: 15, generation: 1,
};
mod cpu { pub fn slot() -> usize { 1 } }
mod timer {
    pub fn ticks() -> u64 { super::NOW.fetch_add(10_000, super::Ordering::AcqRel) }
}
fn ns(value: u64) -> u64 { value }

#[derive(Default)]
struct Extra;
#[derive(Default)]
struct Native {
    failed: bool, in_job: bool, completion: Option<()>, model: Option<()>,
    probing: bool, phase: u64, phase_mask: u64,
}
struct Worker { native: Native, extra: Extra, probed: bool, context: Option<()> }
#[derive(Clone, Copy)]
struct RuntimeBill { credit: ControlCredit, actual_ns: u64, finished_ns: u64 }
struct Runtime { bill: Option<RuntimeBill>, last_bill: [u64; 8], failed: u64 }
fn finish_measurement(_: &mut Worker) -> bool { true }
fn settle(_: &mut Worker) -> bool { true }
fn publish_completion(_: &mut Worker) {}
fn publish_runtime(_: &Runtime) {}
fn fail_runtime(runtime: &mut Runtime, code: u64) { runtime.failed = code; }
fn begin_measurement(_: &mut Worker, _: &domain_control::core_replay::PaidWorkWitness) -> bool { true }
#[derive(Clone, Copy)]
struct ChargeStart;
impl ChargeStart { fn begin() -> Self { Self } }
fn run_probe_turn(_: &mut Worker, _: ControlCredit, _: ChargeStart) {
    panic!("this is a post-probe mandatory request");
}
fn run_turn(_: &mut Worker, credit: ControlCredit, _: ChargeStart,
            _: &domain_control::core_replay::PaidWorkWitness) {
    assert_eq!(SCHEDULER.lock().unwrap().control_active(1), Some(credit));
    NEW_WORK.store(true, Ordering::Release);
}
fn charge_turn(_: &mut Worker, credit: ControlCredit, _: ChargeStart) {
    domain_tasks::complete_control(credit, 1000, 2_000_000).unwrap();
}
mod domain_control {
    pub mod core_replay {
        pub struct PaidWorkWitness;
        impl PaidWorkWitness {
            pub fn new(_: super::super::ControlCredit) -> Result<Self, super::super::Error> { Ok(Self) }
        }
    }
}
mod domain_tasks {
    use super::*;
    pub fn begin_control(required: u64, _: bool) -> Result<Option<ControlCredit>, Error> {
        SCHEDULER.lock().unwrap().reserve_control(1, LAYOUT, timer::ticks(), required)
    }
    pub fn complete_control(credit: ControlCredit, actual: u64, finished: u64) -> Result<(), Error> {
        if BLOCK_SETTLEMENT.load(Ordering::Acquire) { return Err(Error::Busy); }
        SCHEDULER.lock().unwrap().complete_control(credit, actual, finished)
    }
}
mod learning {
    use super::*;
    pub fn settle(_: &mut Extra) -> bool { true }
    pub fn allow_mandatory(_: &Extra, _: u64, _: u64) -> bool { true }
    pub fn step(_: &mut Extra) { panic!("mandatory request must precede idle learning"); }
}
mod governance {
    use super::*;
    static INITIALIZED: AtomicBool = AtomicBool::new(true);
    static mut RUNTIME: Runtime = Runtime { bill: None, last_bill: [0; 8], failed: 0 };
    pub(super) fn runtime_state() -> &'static mut Runtime {
        // The one harness test runs with one thread, like the real C1 owner.
        unsafe { &mut *core::ptr::addr_of_mut!(RUNTIME) }
    }
    pub(super) fn step(_: &mut Extra) -> bool {
        if !GOVERNANCE_PENDING.load(Ordering::Acquire) { return false; }
        // Substitute only the bounded role body, retaining real reservations
        // and settlement rather than manufacturing a mock credit receipt.
        let Some(credit) = domain_tasks::begin_control(PREPAY_NS, false).unwrap() else {
            return true;
        };
        domain_tasks::complete_control(credit, 750, 1_000_750).unwrap();
        GOVERNANCE_PENDING.store(false, Ordering::Release);
        true
    }
    // GOVERNANCE_BILL_FUNCTION
    // GOVERNANCE_SETTLE_FUNCTION
}
mod native {
    use super::*;
    // NATIVE_STEP_FUNCTION
}

fn reset() {
    *SCHEDULER.lock().unwrap() = Scheduler::new();
    NEW_WORK.store(false, Ordering::Release);
    GOVERNANCE_PENDING.store(false, Ordering::Release);
    BLOCK_SETTLEMENT.store(false, Ordering::Release);
    NOW.store(1_000_000, Ordering::Release);
    let runtime = governance::runtime_state();
    runtime.bill = None;
    runtime.last_bill = [0; 8];
    runtime.failed = 0;
}

#[test]
fn pending_mandatory_request_settles_original_governance_credit_before_dispatch() {
    reset();
    let old = SCHEDULER.lock().unwrap()
        .reserve_control(1, LAYOUT, 0, PREPAY_NS).unwrap().unwrap();
    governance::runtime_state().bill = Some(RuntimeBill {
        credit: old, actual_ns: 2250, finished_ns: 50_000,
    });
    let mut worker = Worker { native: Native::default(), extra: Extra,
                              probed: true, context: None };
    BLOCK_SETTLEMENT.store(true, Ordering::Release);
    native::step(&mut worker);
    assert!(!NEW_WORK.load(Ordering::Acquire));
    assert_eq!(governance::runtime_state().bill.unwrap().credit, old);
    assert_eq!(SCHEDULER.lock().unwrap().control_active(1), Some(old));
    BLOCK_SETTLEMENT.store(false, Ordering::Release);
    native::step(&mut worker);
    assert!(governance::runtime_state().bill.is_none(), "old governor bill was starved by mandatory REQUEST");
    assert_eq!(governance::runtime_state().last_bill[7], 1);
    assert!(NEW_WORK.load(Ordering::Acquire), "mandatory request never obtained a new credit");
    assert_eq!(SCHEDULER.lock().unwrap().control_active(1), None);
    assert_eq!(SCHEDULER.lock().unwrap().cpu_window_usage(1, 2_000_000), Ok((3250, 0)));
    assert_eq!(governance::runtime_state().failed, 0);
}

#[test]
fn startup_coordinator_finishes_before_a_new_mandatory_job_obtains_credit() {
    reset();
    GOVERNANCE_PENDING.store(true, Ordering::Release);
    let mut worker = Worker { native: Native::default(), extra: Extra,
                              probed: true, context: None };
    native::step(&mut worker);
    assert!(!GOVERNANCE_PENDING.load(Ordering::Acquire), "coordinator startup was bypassed by REQUEST");
    assert!(!NEW_WORK.load(Ordering::Acquire), "two roles ran in one scheduling opportunity");
    assert_eq!(SCHEDULER.lock().unwrap().cpu_window_usage(1, 1_000_750), Ok((750, 0)));
    native::step(&mut worker);
    assert!(NEW_WORK.load(Ordering::Acquire));
    assert_eq!(SCHEDULER.lock().unwrap().cpu_window_usage(1, 2_000_000), Ok((1750, 0)));
}

#[test]
fn an_already_owned_ordinary_job_keeps_its_dispatch_priority() {
    reset();
    GOVERNANCE_PENDING.store(true, Ordering::Release);
    let mut worker = Worker { native: Native { in_job: true, ..Native::default() },
                              extra: Extra, probed: true, context: None };
    native::step(&mut worker);
    assert!(NEW_WORK.load(Ordering::Acquire), "already owned ordinary job was displaced");
    assert!(GOVERNANCE_PENDING.load(Ordering::Acquire));
    assert_eq!(SCHEDULER.lock().unwrap().cpu_window_usage(1, 2_000_000), Ok((1000, 0)));
}
