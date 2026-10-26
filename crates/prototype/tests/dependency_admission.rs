#[path = "../../../kernel/src/domain_control/dependencies.rs"]
mod dependencies;
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    policy::{ExecutionState, Prerequisite},
};
use dependencies::AdmissionView;
fn key(id: u64, generation: u64) -> Prerequisite {
    Prerequisite {
        domain: 5,
        target: ObjectKey { id, generation },
    }
}
#[test]
fn dependencies_hold_unknown_and_failed_obligations_until_real_terminal() {
    let table = AdmissionView::new();
    let p = key(1, 1);
    assert_eq!(table.admit(p, 8, 1), Ok(0));
    table.publish(0, p, 3, 100, ExecutionState::Pending);
    assert_eq!(table.admit(p, 8, 1), Err(Error::Busy));
    table.publish(0, p, 3, 100, ExecutionState::Unknown);
    assert_eq!(table.admit(p, 10, u64::MAX), Err(Error::NotReady));
    table.publish(0, p, 3, 100, ExecutionState::Applied);
    assert_eq!(table.admit(p, 10, 99), Ok(3));
    assert_eq!(table.admit(p, 10, 100), Ok(0));
    table.publish(0, p, 4, 200, ExecutionState::Failed(Error::Io));
    assert_eq!(table.admit(p, 8, 101), Err(Error::Conflict));
    table.publish(0, p, 5, 300, ExecutionState::Applied);
    assert_eq!(table.admit(p, 8, 201), Ok(5));
}
#[test]
fn references_bind_domain_object_and_generation_without_invented_edges() {
    let table = AdmissionView::new();
    table.publish(0, key(1, 1), 7, 100, ExecutionState::Unknown);
    assert_eq!(table.admit(key(2, 1), 8, 1), Ok(0));
    assert_eq!(table.admit(key(1, 2), 8, 1), Ok(0));
    assert_eq!(table.admit(key(1, 1), 4, 1), Err(Error::Unsupported));
    assert_eq!(table.admit(key(0, 1), 8, 1), Err(Error::Stale));
    table.retire(0);
    assert_eq!(table.admit(key(1, 1), 8, 1), Ok(0));
}

#[test]
fn sparse_publication_high_watermark_keeps_every_exact_slot_visible() {
    let table = AdmissionView::new();
    table.publish(7, key(8, 1), 11, 200, ExecutionState::Applied);
    table.publish(1, key(2, 3), 12, 300, ExecutionState::Applied);
    assert_eq!(table.admit(key(8, 1), 8, 199), Ok(11));
    assert_eq!(table.admit(key(2, 3), 10, 299), Ok(12));
    table.retire(1);
    assert_eq!(table.admit(key(2, 3), 8, 299), Ok(0));
    assert_eq!(table.admit(key(8, 1), 10, 199), Ok(11));
}
