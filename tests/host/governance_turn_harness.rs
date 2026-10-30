//! Executes the production bounded dispatcher with controlled phase boundaries.
//! This is a host state-machine regression, not an EL0/runtime timing claim.
#![allow(dead_code)]
use cyxia_prototype::domains::{
    Error,
    tasks::{ControlCredit, CpuLayout, Scheduler},
};
use std::sync::atomic::{AtomicU64, Ordering};
const PHASE_INPUT_PROBE: u64 = 1;
const PHASE_CODE_PROBE: u64 = 2;
const PHASE_UNMAPPED_PROBE: u64 = 3;
const PHASE_TIMER_PROBE: u64 = 4;
const PHASE_PREPARE: u64 = 5;
const PHASE_RUN: u64 = 6;
const PHASE_VALIDATE: u64 = 7;
const PHASE_COMPLETE: u64 = 8;
const PREPAY: u64 = 2_500_000;
const DEADLINE: u64 = 50_000_000;
static OWNER: AtomicU64 = AtomicU64::new(1);
mod domain_tasks {
    pub fn control_owner_context(_: usize) -> Result<(u64, u64), super::Error> {
        let generation = super::OWNER.load(super::Ordering::Acquire);
        if generation == 0 {
            return Err(super::Error::Busy);
        }
        Ok((generation, 1))
    }
}
struct Resources;
struct Runtime {
    phase: u64,
    last_credit_core: u64,
    now: u64,
    deadline: u64,
    cpu_ns: u64,
    calls: Vec<&'static str>,
    preempt: bool,
    pins_busy: bool,
    prepare_error: Option<Error>,
    run_error: Option<Error>,
    validate_error: Option<Error>,
    run_ns: u64,
    snapshot_count: u64,
}
impl Runtime {
    fn new(phase: u64) -> Self {
        Self {
            phase,
            last_credit_core: 0,
            now: 1_000_000,
            deadline: 51_000_000,
            cpu_ns: 0,
            calls: Vec::new(),
            preempt: false,
            pins_busy: false,
            prepare_error: None,
            run_error: None,
            validate_error: None,
            run_ns: 600_000,
            snapshot_count: 0,
        }
    }
}
fn prepare_runtime_snapshot(r: &mut Runtime, _: &Resources, _: ControlCredit) -> Result<(), Error> {
    r.calls.push("prepare");
    r.cpu_ns += 100_000;
    if let Some(e) = r.prepare_error {
        return Err(e);
    }
    r.deadline = r.now + DEADLINE;
    r.snapshot_count += 1;
    r.phase = PHASE_RUN;
    Ok(())
}
fn run_runtime_context(r: &mut Runtime, _: &Resources) -> Result<(), Error> {
    r.calls.push("run");
    r.cpu_ns += r.run_ns;
    r.now += 1_000_000;
    if let Some(e) = r.run_error {
        return Err(e);
    }
    if r.phase <= PHASE_TIMER_PROBE {
        r.phase += 1;
    } else if !r.preempt && !r.pins_busy {
        r.phase = PHASE_VALIDATE;
    }
    Ok(())
}
fn validate_runtime_command(r: &mut Runtime, _: &Resources) -> Result<(), Error> {
    r.calls.push("validate");
    r.cpu_ns += 200_000;
    if let Some(e) = r.validate_error {
        return Err(e);
    }
    if r.now >= r.deadline {
        return Err(Error::Expired);
    }
    r.phase = PHASE_COMPLETE;
    Ok(())
}
// PRODUCTION_TURN
fn credit() -> (Scheduler, ControlCredit) {
    OWNER.store(1, Ordering::Release);
    let mut scheduler = Scheduler::new();
    let c = scheduler
        .reserve_control(
            1,
            CpuLayout {
                business_mask: 13,
                healthy_mask: 15,
                generation: 1,
            },
            1_000_000,
            PREPAY,
        )
        .unwrap()
        .unwrap();
    (scheduler, c)
}
#[test]
fn ready_chain_uses_one_credit_without_two_artificial_scheduler_delays() {
    let (mut scheduler, c) = credit();
    let mut r = Runtime::new(PHASE_PREPARE);
    assert_eq!(perform_runtime_turn(&mut r, &Resources, c), Ok(()));
    assert_eq!(
        r.calls,
        ["prepare", "run", "validate"],
        "ready chain was split across scheduler turns"
    );
    assert_eq!(r.phase, PHASE_COMPLETE);
    assert_eq!(r.snapshot_count, 1);
    assert_eq!(scheduler.control_active(1), Some(c));
    scheduler.complete_control(c, r.cpu_ns, r.now).unwrap();
    assert_eq!(scheduler.control_active(1), None);
    assert_eq!(scheduler.cpu_window_usage(1, r.now).unwrap(), (900_000, 0));
}
#[test]
fn returned_command_is_validated_before_an_avoidable_yield() {
    let (_, c) = credit();
    let mut r = Runtime::new(PHASE_RUN);
    r.now = r.deadline - 2_000_000;
    perform_runtime_turn(&mut r, &Resources, c).unwrap();
    assert_eq!(
        r.calls,
        ["run", "validate"],
        "returned command unnecessarily yielded"
    );
    assert_eq!(r.phase, PHASE_COMPLETE);
    assert_eq!(r.snapshot_count, 0);
}
#[test]
fn timer_preemption_and_unreleased_pins_each_end_the_bounded_turn() {
    for pins_busy in [false, true] {
        let (_, c) = credit();
        let mut r = Runtime::new(PHASE_PREPARE);
        r.preempt = !pins_busy;
        r.pins_busy = pins_busy;
        perform_runtime_turn(&mut r, &Resources, c).unwrap();
        assert_eq!(r.calls, ["prepare", "run"]);
        assert_eq!(r.phase, PHASE_RUN);
        let deadline = r.deadline;
        r.preempt = false;
        r.pins_busy = false;
        r.calls.clear();
        perform_runtime_turn(&mut r, &Resources, c).unwrap();
        assert_eq!(r.calls, ["run", "validate"]);
        assert_eq!(r.snapshot_count, 1);
        assert_eq!(r.deadline, deadline);
    }
}
#[test]
fn probes_never_fall_through_into_snapshot_or_command_work() {
    for phase in PHASE_INPUT_PROBE..=PHASE_TIMER_PROBE {
        let (_, c) = credit();
        let mut r = Runtime::new(phase);
        perform_runtime_turn(&mut r, &Resources, c).unwrap();
        assert_eq!(r.calls, ["run"]);
        assert_eq!(r.phase, phase + 1);
    }
}
#[test]
fn failures_are_not_converted_to_ready_transitions() {
    for error in [
        Error::Busy,
        Error::NotReady,
        Error::Auth,
        Error::Budget,
        Error::Stale,
    ] {
        let (_, c) = credit();
        let mut r = Runtime::new(PHASE_PREPARE);
        r.prepare_error = Some(error);
        assert_eq!(perform_runtime_turn(&mut r, &Resources, c), Err(error));
        assert_eq!(r.calls, ["prepare"]);
        r.prepare_error = None;
        r.run_error = Some(error);
        r.calls.clear();
        assert_eq!(perform_runtime_turn(&mut r, &Resources, c), Err(error));
        assert_eq!(r.calls, ["prepare", "run"]);
        r.phase = PHASE_VALIDATE;
        r.validate_error = Some(error);
        r.calls.clear();
        assert_eq!(perform_runtime_turn(&mut r, &Resources, c), Err(error));
        assert_eq!(r.calls, ["validate"]);
    }
}
#[test]
fn expired_original_snapshot_is_not_retimed_or_accepted() {
    let (_, c) = credit();
    let mut r = Runtime::new(PHASE_RUN);
    r.now = r.deadline;
    let deadline = r.deadline;
    assert_eq!(
        perform_runtime_turn(&mut r, &Resources, c),
        Err(Error::Expired)
    );
    assert_eq!(r.deadline, deadline);
    assert_eq!(r.snapshot_count, 0);
    assert_ne!(r.phase, PHASE_COMPLETE);
}
#[test]
fn owner_and_generation_must_still_authorize_the_whole_turn() {
    let (_, c) = credit();
    let mut r = Runtime::new(PHASE_PREPARE);
    OWNER.store(2, Ordering::Release);
    assert_eq!(
        perform_runtime_turn(&mut r, &Resources, c),
        Err(Error::Stale)
    );
    assert!(r.calls.is_empty());
    OWNER.store(0, Ordering::Release);
    assert_eq!(
        perform_runtime_turn(&mut r, &Resources, c),
        Err(Error::Busy)
    );
    assert!(r.calls.is_empty());
    OWNER.store(1, Ordering::Release);
    let mut wrong_cpu = c;
    wrong_cpu.cpu = 2;
    assert_eq!(
        perform_runtime_turn(&mut r, &Resources, wrong_cpu),
        Err(Error::Stale)
    );
    assert!(r.calls.is_empty());
}
#[test]
fn combined_actual_cost_still_fails_the_original_physical_credit() {
    let (mut scheduler, c) = credit();
    let mut r = Runtime::new(PHASE_PREPARE);
    r.run_ns = 2_300_001;
    perform_runtime_turn(&mut r, &Resources, c).unwrap();
    assert_eq!(r.calls, ["prepare", "run", "validate"]);
    assert_eq!(
        scheduler.complete_control(c, r.cpu_ns, r.now),
        Err(Error::Budget)
    );
}
#[test]
fn completed_or_unknown_phase_cannot_repeat_the_command() {
    let (_, c) = credit();
    let mut r = Runtime::new(PHASE_COMPLETE);
    perform_runtime_turn(&mut r, &Resources, c).unwrap();
    assert!(r.calls.is_empty());
    r.phase = 99;
    assert_eq!(
        perform_runtime_turn(&mut r, &Resources, c),
        Err(Error::Conflict)
    );
    assert!(r.calls.is_empty());
}
