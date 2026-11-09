//! Production interval sampling with deterministic clock fixtures from the
//! actual stopped CoreSet failure. No native evidence or accepted labels.
#[path = "../../../kernel/src/domain_tasks/measured_interval.rs"]
mod measured_interval;
use core::cell::{Cell, RefCell};
const CREDIT_START: u64 = 67_624_394_000;
const CPU_ACTUAL: u64 = 10_875;
const EARLY_SHARED_END: u64 = 67_624_404_000;
const LATER_SHARED_END: u64 = 67_624_405_000;
#[test]
fn closes_cpu_before_shared_end_without_losing_the_actual_875_ns() {
    let cpu_closed = Cell::new(false);
    let calls = RefCell::new(Vec::new());
    let (first, last, actual) = measured_interval::finish(
        || {
            calls.borrow_mut().push("cpu");
            cpu_closed.set(true);
            CPU_ACTUAL
        },
        || {
            calls.borrow_mut().push("shared");
            if cpu_closed.get() {
                LATER_SHARED_END
            } else {
                EARLY_SHARED_END
            }
        },
    );
    assert_eq!(
        actual, CPU_ACTUAL,
        "retain all actual execution, including 875 ns"
    );
    assert!(
        first >= CREDIT_START,
        "interval begins before live protected credit: {first}"
    );
    assert_eq!(
        (first, last, actual),
        (67_624_394_125, LATER_SHARED_END, CPU_ACTUAL)
    );
    assert_eq!(*calls.borrow(), ["cpu", "shared"]);
}
#[test]
fn insufficient_shared_coverage_is_not_clamped_into_credit() {
    let (first, last, actual) = measured_interval::finish(|| CPU_ACTUAL, || EARLY_SHARED_END);
    assert_eq!(
        (first, last, actual),
        (67_624_393_125, EARLY_SHARED_END, CPU_ACTUAL)
    );
    assert!(
        first < CREDIT_START,
        "unchanged protected owner must still reject this interval"
    );
    assert_eq!(last - first, CPU_ACTUAL);
}
#[test]
fn cpu_debit_excludes_shared_clock_wait_without_truncation() {
    let interval = measured_interval::finish(|| 25_000, || 2_000_000_000);
    assert_eq!(interval, (1_999_975_000, 2_000_000_000, 25_000));
}

use cyxia_prototype::{
    domains::{
        Error as DomainError,
        tasks::{ControlCredit, CpuLayout, Scheduler},
    },
    learning::{
        Error,
        governance::{ControlAuthority, ExtraBudget, Role},
    },
};
struct PhysicalFixture(ControlCredit);
impl ControlAuthority for PhysicalFixture {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, workspace: u32) -> Result<(), Error> {
        if self.0.cpu == cpu && self.0.core_generation == generation && workspace == 1024 * 1024 {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
}
fn credit() -> (
    Scheduler,
    ControlCredit,
    ExtraBudget,
    cyxia_prototype::learning::governance::ExtraCredit,
) {
    let mut scheduler = Scheduler::new();
    let physical = scheduler
        .reserve_control(
            1,
            CpuLayout {
                business_mask: 13,
                healthy_mask: 15,
                generation: 7,
            },
            CREDIT_START,
            2_500_000,
        )
        .unwrap()
        .unwrap();
    let mut extra = ExtraBudget::new();
    let e = extra
        .reserve(
            Role::Validation,
            1,
            7,
            1024 * 1024,
            CREDIT_START,
            2_500_000,
            &PhysicalFixture(physical),
        )
        .unwrap();
    (scheduler, physical, extra, e)
}
#[test]
fn both_original_ledgers_charge_all_10875_ns_and_refund_only_unused_once() {
    let (mut scheduler, physical, mut extra, e) = credit();
    let (_, finished, actual) = measured_interval::finish(|| CPU_ACTUAL, || LATER_SHARED_END);
    assert_eq!(actual, 10_875);
    let mut wrong_cpu = physical;
    wrong_cpu.cpu = 2;
    assert_eq!(
        scheduler.complete_control(wrong_cpu, actual, finished),
        Err(DomainError::Stale)
    );
    let mut stale = physical;
    stale.sequence += 1;
    assert_eq!(
        scheduler.complete_control(stale, actual, finished),
        Err(DomainError::Stale)
    );
    assert_eq!(scheduler.control_active(1), Some(physical));
    scheduler
        .complete_control(physical, actual, finished)
        .unwrap();
    let receipt = extra.settle(e, actual, finished).unwrap();
    assert_eq!(receipt.identity().actual_ns, 10_875);
    assert_eq!(
        scheduler.cpu_window_usage(1, finished).unwrap(),
        (10_875, 0)
    );
    assert_eq!(extra.spent_ns(), 10_875);
    assert_eq!(
        scheduler.complete_control(physical, 0, finished),
        Err(DomainError::Stale)
    );
    assert_eq!(extra.spent_ns(), 10_875);
}
#[test]
fn insufficient_shared_span_faults_extra_ledger_without_losing_cpu_charge() {
    let (mut scheduler, physical, mut extra, e) = credit();
    let (first, finished, actual) = measured_interval::finish(|| CPU_ACTUAL, || EARLY_SHARED_END);
    assert!(first < CREDIT_START);
    scheduler
        .complete_control(physical, actual, finished)
        .unwrap();
    assert!(matches!(
        extra.settle(e, actual, finished),
        Err(Error::Budget)
    ));
    assert_eq!(
        scheduler.cpu_window_usage(1, finished).unwrap(),
        (10_875, 0)
    );
    assert_eq!(
        extra.spent_ns(),
        10_875,
        "a failed coverage check cannot refund CPU"
    );
}
