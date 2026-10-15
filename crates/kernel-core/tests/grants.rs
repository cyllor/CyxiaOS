use cyxia_contracts::*;
use cyxia_kernel_core::grants::*;
fn owner() -> Owner {
    Owner {
        task: TaskId::new(1).unwrap(),
        generation: Generation::new(1).unwrap(),
    }
}
fn req(n: u32) -> AuthorizedGrantRequest {
    unsafe { AuthorizedGrantRequest::bootstrap(owner(), PageCount(n)) }
}
#[test]
fn reservation_redemption_cancellation_and_release_conserve_capacity() {
    let mut l = GrantLedger::new(PageCount(200));
    let g = l.commit(req(100)).unwrap();
    let r = l.redeem(g, owner(), PageCount(20)).unwrap();
    assert_eq!(
        l.snapshot(),
        LedgerSnapshot {
            capacity: 200,
            free: 100,
            reserved_unredeemed: 80,
            in_use: 20
        }
    );
    let r2 = l.redeem(g, owner(), PageCount(1)).unwrap();
    assert_eq!(l.snapshot().reserved_unredeemed, 79);
    assert_eq!(l.cancel_unused(g, owner()).unwrap(), PageCount(79));
    assert!(l.redeem(g, owner(), PageCount(1)).is_err());
    let receipt = unsafe { ReleaseReceipt::after_revoke(r, owner(), PageCount(20)) };
    l.release_completed(receipt).unwrap();
    let before = l.snapshot();
    assert!(l.release_completed(receipt).is_err());
    assert_eq!(before, l.snapshot());
    l.release_completed(unsafe { ReleaseReceipt::after_revoke(r2, owner(), PageCount(1)) })
        .unwrap();
    assert_eq!(l.snapshot().free, 200);
}
#[test]
fn failed_admission_and_wrong_owner_do_not_mutate() {
    let mut l = GrantLedger::new(PageCount(10));
    assert!(l.commit(req(11)).is_err());
    assert_eq!(l.snapshot().free, 10);
    let g = l.commit(req(5)).unwrap();
    let before = l.snapshot();
    let stale = Owner {
        generation: Generation::new(2).unwrap(),
        ..owner()
    };
    assert!(l.redeem(g, stale, PageCount(1)).is_err());
    assert!(l.redeem(g, owner(), PageCount(6)).is_err());
    assert_eq!(l.snapshot(), before);
    assert_eq!(AuthorizedGrantRequest::from_ai(), Err(GrantError::NotReady));
}
#[test]
fn metadata_is_reserved_at_commit() {
    let mut l = GrantLedger::new(PageCount(1000));
    assert_eq!(l.commit(req(129)), Err(GrantError::Metadata));
    assert_eq!(l.snapshot().free, 1000);
}
#[test]
fn release_wrong_amount_keeps_commitment() {
    let mut l = GrantLedger::new(PageCount(10));
    let g = l.commit(req(4)).unwrap();
    let r = l.redeem(g, owner(), PageCount(3)).unwrap();
    let before = l.snapshot();
    assert!(
        l.release_completed(unsafe { ReleaseReceipt::after_revoke(r, owner(), PageCount(2)) })
            .is_err()
    );
    assert_eq!(l.snapshot(), before);
}
