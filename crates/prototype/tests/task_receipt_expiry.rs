#[path = "../../../kernel/src/domain_tasks/receipts.rs"]
mod receipts;
use cyxia_prototype::{
    domains::{
        Error, ObjectKey, PolicyStamp,
        tasks::{CpuLayout, RunState, Scheduler, ThreadSpec},
    },
    policy::ExecutionState,
};
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
#[test]
fn a_late_reconciler_preserves_the_actual_dispatch_receipt_after_policy_expiry() {
    let mut scheduler = Scheduler::new();
    let layout = CpuLayout {
        business_mask: 1,
        healthy_mask: 1,
        generation: 1,
    };
    scheduler.register_group(key(1)).unwrap();
    scheduler
        .admit(
            ThreadSpec {
                key: key(10),
                group: key(1),
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 0,
                budget_ns: 10_000_000,
            },
            layout,
            0,
        )
        .unwrap();
    let stamp = PolicyStamp::new(1, 1_000_000, 1_000_000).unwrap();
    scheduler
        .install_weight(key(1), 2, stamp, 1_000_000)
        .unwrap();
    let start = stamp.installed_until_ns - 100_000;
    let dispatch = scheduler
        .dispatch(0, layout, start, 500_000)
        .unwrap()
        .unwrap();
    let finished = start + 200_000;
    assert_eq!(
        receipts::reconcile(
            scheduler.policy_receipt(key(1)).unwrap(),
            stamp,
            finished,
            true
        ),
        ExecutionState::Unknown
    );
    scheduler
        .complete(dispatch, 200_000, RunState::Runnable, finished)
        .unwrap();
    assert_eq!(scheduler.weight(key(1), finished), Ok(1));
    assert_eq!(
        receipts::reconcile(
            scheduler.policy_receipt(key(1)).unwrap(),
            stamp,
            finished,
            false
        ),
        ExecutionState::Applied
    );
}
#[test]
fn only_an_unexecuted_policy_without_retained_obligations_can_expire_terminally() {
    let stamp = PolicyStamp::new(4, 1, 1).unwrap();
    assert_eq!(
        receipts::reconcile(0, stamp, stamp.installed_until_ns - 1, false),
        ExecutionState::Pending
    );
    assert_eq!(
        receipts::reconcile(0, stamp, stamp.installed_until_ns, true),
        ExecutionState::Unknown
    );
    assert_eq!(
        receipts::reconcile(0, stamp, stamp.installed_until_ns, false),
        ExecutionState::Failed(Error::Expired)
    );
    assert_eq!(
        receipts::reconcile(4, stamp, stamp.installed_until_ns, true),
        ExecutionState::Applied
    );
}
