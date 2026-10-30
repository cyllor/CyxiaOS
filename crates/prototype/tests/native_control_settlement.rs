//! Exercise the same bounded diagnostic writer used after physical settlement.
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_tasks/control_diagnostics.rs"]
mod control_diagnostics;
use control_diagnostics::Evidence;
use cyxia_prototype::domains::Error;
use cyxia_prototype::domains::tasks::{CpuLayout, Scheduler};

fn layout() -> CpuLayout {
    CpuLayout {
        business_mask: 9,
        healthy_mask: 15,
        generation: 7,
    }
}

#[test]
fn every_control_cpu_retains_the_exact_consumed_budget_failure() {
    let log = Evidence::new();
    let mut scheduler = Scheduler::new();
    for (cpu, offset) in [(1, 2), (2, 26)] {
        let credit = scheduler
            .reserve_control(cpu, layout(), 10_000_000 * cpu as u64, 2_500_000)
            .unwrap()
            .unwrap();
        let actual = 2_500_001;
        let finish = credit.started_ns + actual;
        let result = scheduler.complete_control(credit, actual, finish);
        assert_eq!(result, Err(Error::Budget));
        log.settled(
            credit,
            actual,
            finish,
            result,
            scheduler.control_active(cpu).is_some(),
        );
        let words = log.snapshot();
        assert_eq!(words[0], control_diagnostics::MAGIC);
        assert_eq!(
            &words[offset..offset + 15],
            &[
                2,
                cpu as u64,
                credit.sequence,
                7,
                0,
                credit.started_ns,
                finish,
                credit.reserved_ns,
                actual,
                credit.control_total_ns,
                actual,
                credit.physical_total_ns,
                actual,
                1,
                Error::Budget as u64 + 1,
            ]
        );
        assert_eq!(scheduler.cpu_spent_ns(cpu), Ok(actual));
        assert!(scheduler.control_active(cpu).is_none());
        assert_ne!(scheduler.stats().quarantine_mask & (1 << cpu), 0);
        // A duplicate/stale settlement cannot create another fault record.
        let duplicate = scheduler.complete_control(credit, actual, finish);
        log.settled(credit, actual, finish, duplicate, false);
        assert_eq!(log.snapshot(), words);
    }
    assert_eq!(log.snapshot()[1], 2);
    assert_eq!(core::mem::size_of::<Evidence>(), 512);
}

#[test]
fn malformed_unconsumed_and_successful_bills_never_become_fault_evidence() {
    let log = Evidence::new();
    let mut scheduler = Scheduler::new();
    let credit = scheduler
        .reserve_control(1, layout(), 10_000_000, 2_500_000)
        .unwrap()
        .unwrap();
    let mut forged = credit;
    forged.sequence += 1;
    let result = scheduler.complete_control(forged, 3_000_000, 13_000_000);
    assert_eq!(result, Err(Error::Stale));
    log.settled(forged, 3_000_000, 13_000_000, result, true);
    let result = scheduler.complete_control(credit, 3_000_000, 9_000_000);
    assert_eq!(result, Err(Error::Range));
    log.settled(credit, 3_000_000, 9_000_000, result, true);
    // Even an incorrectly forwarded Budget result must not record an active bill.
    log.settled(credit, 3_000_000, 13_000_000, Err(Error::Budget), true);
    assert_eq!(log.snapshot(), [0; 64]);
    let result = scheduler.complete_control(credit, 1000, 10_001_000);
    assert_eq!(result, Ok(()));
    log.settled(credit, 1000, 10_001_000, result, false);
    assert_eq!(log.snapshot(), [0; 64]);
}

#[test]
fn first_failure_is_not_overwritten_by_a_later_generation() {
    let log = Evidence::new();
    for generation in [7, 8] {
        let mut scheduler = Scheduler::new();
        let context = CpuLayout {
            generation,
            ..layout()
        };
        let credit = scheduler
            .reserve_control(1, context, 10_000_000, 2_500_000)
            .unwrap()
            .unwrap();
        let actual = 2_500_000 + generation;
        let result = scheduler.complete_control(credit, actual, 10_000_000 + actual);
        log.settled(credit, actual, 10_000_000 + actual, result, false);
    }
    let words = log.snapshot();
    assert_eq!(words[1], 2);
    assert_eq!(words[5], 7);
    assert_eq!(words[10], 2_500_007);
    assert!(words[17..].iter().all(|word| *word == 0));
}
