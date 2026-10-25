#[path = "../../../kernel/src/prototype_runtime/learning_receipt.rs"]
mod receipt_match;
use cyxia_prototype::{
    domains::tasks::{ControlCredit, CpuLayout, Scheduler},
    learning::{
        Error,
        governance::{ControlAuthority, ExtraBudget, Role, WorkReceipt},
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
        if cpu == 1
            && self.0.cpu == cpu
            && self.0.core_generation == generation
            && bytes == 1024 * 1024
        {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
}
fn settled(
    scheduler: &mut Scheduler,
    extra: &mut ExtraBudget,
    role: Role,
    now: u64,
) -> WorkReceipt {
    let physical = scheduler
        .reserve_control(1, LAYOUT, now, 2_500_000)
        .unwrap()
        .unwrap();
    let credit = extra
        .reserve(role, 1, 7, 1024 * 1024, now, 2_500_000, &Physical(physical))
        .unwrap();
    scheduler
        .complete_control(physical, 100_000, now + 100_000)
        .unwrap();
    extra.settle(credit, 100_000, now + 100_000).unwrap()
}

#[test]
fn native_score_match_requires_exact_actual_ledger_and_turn() {
    let (mut scheduler, mut extra) = (Scheduler::new(), ExtraBudget::new());
    let actual = settled(&mut scheduler, &mut extra, Role::Shadow, 1_000_000);
    let proof = Some(actual.identity());
    assert!(receipt_match::matches(proof, &actual, Role::Shadow, 7));
    let mut other_ledger = ExtraBudget::new();
    let same_fields = settled(&mut scheduler, &mut other_ledger, Role::Shadow, 2_000_000);
    assert_eq!(actual.identity().serial, same_fields.identity().serial);
    assert_eq!(
        actual.identity().actual_ns,
        same_fields.identity().actual_ns
    );
    assert_ne!(
        actual.identity().ledger_id,
        same_fields.identity().ledger_id
    );
    assert!(!receipt_match::matches(
        proof,
        &same_fields,
        Role::Shadow,
        7
    ));
    let next = settled(&mut scheduler, &mut extra, Role::Shadow, 3_000_000);
    assert!(!receipt_match::matches(proof, &next, Role::Shadow, 7));
}

#[test]
fn native_score_match_rejects_unknown_wrong_role_or_old_core() {
    let (mut scheduler, mut extra) = (Scheduler::new(), ExtraBudget::new());
    let actual = settled(&mut scheduler, &mut extra, Role::Canary, 1_000_000);
    assert!(!receipt_match::matches(None, &actual, Role::Canary, 7));
    assert!(!receipt_match::matches(
        Some(actual.identity()),
        &actual,
        Role::Training,
        7
    ));
    assert!(!receipt_match::matches(
        Some(actual.identity()),
        &actual,
        Role::Canary,
        8
    ));
    assert!(receipt_match::matches(
        Some(actual.identity()),
        &actual,
        Role::Canary,
        7
    ));
    assert_eq!(
        scheduler.cpu_window_usage(1, 1_100_000).unwrap(),
        (100_000, 0)
    );
    assert_eq!(extra.spent_ns(), 100_000);
}
