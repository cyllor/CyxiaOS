use cyxia_prototype_cluster::{abi::*, quote_stop::Owner};

#[test]
fn stopped_owner_rejects_rebinding_and_only_a_newer_installed_offer_reopens() {
    let mut owner = Owner::new();
    let command = QuoteStopWire { boot_epoch: 7, replay_id: 81, owner_id: 9,
        owner_generation: 2, sequence: 1, issued_ns: 100 };
    owner.apply(command, 7, 15, 101);
    let receipt = owner.receipt();
    assert!(owner.stopped());
    assert_eq!((receipt.outcome, receipt.offer_version), (DOMAIN_APPLIED, 15));
    owner.apply(command, 7, 15, 100_000_000);
    assert_eq!(owner.receipt(), receipt);
    owner.apply(QuoteStopWire { replay_id: 82, ..command }, 7, 15, 102);
    assert_eq!(owner.receipt().outcome, DOMAIN_REJECTED);
    assert!(owner.stopped());
    owner.apply(command, 7, 15, 103);
    assert_eq!(owner.receipt(), receipt);
    owner.installed(15);
    assert!(owner.stopped());
    owner.installed(16);
    assert!(!owner.stopped());
    owner.apply(command, 7, 16, 104);
    assert!(!owner.stopped(), "old command retry cannot reapply a historical stop");
    owner.apply(QuoteStopWire { sequence: 2, boot_epoch: 6, ..command }, 7, 16, 105);
    assert_eq!(owner.receipt().outcome, DOMAIN_REJECTED);
    assert!(!owner.stopped());
    owner.apply(QuoteStopWire { sequence: 3, issued_ns: 200, ..command }, 7, 16, 106);
    assert_eq!(owner.receipt().outcome, DOMAIN_REJECTED);
    assert!(!owner.stopped());
}
