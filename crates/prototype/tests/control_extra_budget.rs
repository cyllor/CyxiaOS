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
const LAYOUT: CpuLayout = CpuLayout {
    business_mask: 13,
    healthy_mask: 15,
    generation: 7,
};
struct Physical(ControlCredit);
impl ControlAuthority for Physical {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, bytes: u32) -> Result<(), Error> {
        if cpu != 1
            || self.0.cpu != cpu
            || self.0.core_generation != generation
            || bytes != 1024 * 1024
        {
            Err(Error::State)
        } else {
            Ok(())
        }
    }
}
#[test]
fn extra_work_uses_the_same_prepaid_physical_cpu_and_refunds_only_actual_unused_time() {
    let mut scheduler = Scheduler::new();
    let mut extra = ExtraBudget::new();
    let mut now = 1_000_000;
    for _ in 0..3 {
        let physical = scheduler
            .reserve_control(1, LAYOUT, now, 2_500_000)
            .unwrap()
            .unwrap();
        let credit = extra
            .reserve(
                Role::Validation,
                1,
                7,
                1024 * 1024,
                now,
                2_500_000,
                &Physical(physical),
            )
            .unwrap();
        assert!(
            scheduler
                .reserve_control(1, LAYOUT, now, 2_500_000)
                .is_err()
        );
        scheduler
            .complete_control(physical, 2_500_000, now + 2_500_000)
            .unwrap();
        extra.settle(credit, 2_500_000, now + 2_500_000).unwrap();
        now += 2_500_000;
    }
    assert_eq!(extra.spent_ns(), 7_500_000);
    let physical = scheduler
        .reserve_control(1, LAYOUT, now, 2_500_000)
        .unwrap()
        .unwrap();
    assert!(matches!(
        extra.reserve(
            Role::Training,
            1,
            7,
            1024 * 1024,
            now,
            2_500_000,
            &Physical(physical)
        ),
        Err(Error::Budget)
    ));
    // No arithmetic starts after the extra ledger denied the second grant.
    // The already-owned physical reservation is explicitly settled once.
    scheduler.complete_control(physical, 0, now).unwrap();
    assert_eq!(scheduler.cpu_window_usage(1, now).unwrap(), (7_500_000, 0));
    assert_eq!(scheduler.stats().actual_ns, 0);
    assert_eq!(
        scheduler.complete_control(physical, 0, now),
        Err(DomainError::Stale)
    );
}
#[test]
fn one_late_real_execution_is_retained_as_a_fault_by_both_ledgers() {
    let mut scheduler = Scheduler::new();
    let mut extra = ExtraBudget::new();
    let start = 97_000_000;
    let physical = scheduler
        .reserve_control(1, LAYOUT, start, 2_500_000)
        .unwrap()
        .unwrap();
    let credit = extra
        .reserve(
            Role::Shadow,
            1,
            7,
            1024 * 1024,
            start,
            2_500_000,
            &Physical(physical),
        )
        .unwrap();
    assert_eq!(
        scheduler.complete_control(physical, 2_600_000, start + 2_600_000),
        Err(DomainError::Budget)
    );
    assert!(matches!(
        extra.settle(credit, 2_600_000, start + 2_600_000),
        Err(Error::Budget)
    ));
    assert_eq!(scheduler.stats().quarantine_mask, 2);
    assert_eq!(extra.spent_ns(), 2_600_000);
    assert!(extra.faulted());
    assert!(
        scheduler
            .reserve_control(1, LAYOUT, 100_000_000, 2_500_000)
            .is_err()
    );
    assert!(
        extra
            .reserve(
                Role::Canary,
                1,
                7,
                1024 * 1024,
                100_000_000,
                2_500_000,
                &Physical(physical)
            )
            .is_err()
    );
}
