use cyxia_contracts::*;
#[test]
fn zero_identity_rejected() {
    assert!(TaskId::new(0).is_err());
    assert!(Generation::new(0).is_err());
    assert!(PlanId::new(0).is_err());
    assert!(GrantId::new(0).is_err());
    assert_eq!(CpuId(0).0, 0);
}
#[test]
fn generation_exhaustion_never_wraps() {
    assert_eq!(
        Generation::new(u64::MAX).unwrap().next_checked(),
        Err(ContractError::Exhausted)
    );
    assert_eq!(Generation::new(1).unwrap().next_checked().unwrap().get(), 2);
}
