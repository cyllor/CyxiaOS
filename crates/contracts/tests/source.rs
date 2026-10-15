use cyxia_contracts::*;
#[test]
fn ai_origin_requires_model() {
    assert!(DecisionOrigin::new(DecisionSource::AiDirect, None, None, None).is_err());
}
#[test]
fn plan_origin_requires_plan() {
    assert!(DecisionOrigin::new(DecisionSource::AiPlan, Some(1), None, None).is_err());
}
#[test]
fn mechanism_receipt_keeps_parent_grant() {
    let id = GrantId::new(7).unwrap();
    let o = DecisionOrigin::new(DecisionSource::Mechanism, None, None, Some(id)).unwrap();
    assert_eq!(o.parent(), Some(id));
}
#[test]
fn writable_executable_rejected() {
    assert!(PagePermissions::new(true, true).is_err());
    assert!(PagePermissions::new(false, true).is_ok());
}
#[test]
fn zero_model_and_ambiguous_origin_rejected() {
    assert!(DecisionOrigin::new(DecisionSource::AiDirect, Some(0), None, None).is_err());
    assert!(DecisionOrigin::new(DecisionSource::Bootstrap, Some(1), None, None).is_err());
}
