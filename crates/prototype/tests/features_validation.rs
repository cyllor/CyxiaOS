use cyxia_prototype::{
    domains::{Action, Error},
    features::{self, RawFeatures},
};

#[test]
fn candidate_validation_preserves_all_eighteen_action_families() {
    let actions = [
        Action::CpuWeight(1), Action::ControlSet(2), Action::SpawnTokens(1),
        Action::Cache { pages: 256, batch: 16 },
        Action::Filesystem { readahead: 2, flush: 8 },
        Action::Ipc { budget: 8, batch: 1 }, Action::IrqTarget(0),
        Action::SoftCoalesce(0), Action::ServiceBatch(1), Action::IoShare(250),
        Action::TxBatch(1), Action::NotifyBatch(1), Action::UnauthRate(4),
        Action::BackgroundBudget(100), Action::RecoveryRecipe(0),
        Action::ConsoleBatch(8), Action::OfferCpu(100), Action::Placement(2),
    ];
    for action in actions {
        let mut raw = RawFeatures::default();
        if matches!(action, Action::ControlSet(_)) { raw.control_capacity = Some(1000); }
        assert_eq!(features::validate(action, &raw), Ok(()), "{action:?}");
        assert!(features::encode(action, raw).is_ok());
        raw.common[0] = u64::MAX;
        raw.domain[0] = u64::MAX;
        raw.target.values[0] = Some(u64::MAX);
        // Measurement clipping is valid, and cannot be confused with permission
        // or boolean validation. The real encoder still performs normalization.
        assert_eq!(features::validate(action, &raw), Ok(()), "{action:?}");
        assert_ne!(features::encode(action, raw).unwrap().clipped, 0);
    }
}

#[test]
fn candidate_validation_rejects_missing_or_noncanonical_measurements() {
    let raw = RawFeatures::default();
    assert_eq!(features::validate(Action::ControlSet(2), &raw), Err(Error::NotReady));
    let mut raw = raw;
    raw.domain_present = 0x80;
    assert_eq!(features::validate(Action::CpuWeight(1), &raw), Err(Error::Format));
    raw.domain_present = 0b1000;
    raw.domain[0] = 1;
    assert_eq!(features::validate(Action::Placement(2), &raw), Err(Error::Format));
    raw.domain[0] = 0;
    assert_eq!(features::validate(Action::Placement(0), &raw), Ok(()));
    assert_eq!(features::validate(Action::Placement(2), &raw), Ok(()));
    assert_eq!(features::validate(Action::Placement(1), &raw), Err(Error::NotReady));
    assert_eq!(features::validate(Action::CpuWeight(1), &raw), Err(Error::NotReady));
    for field in 0..3 {
        let mut raw = RawFeatures::default();
        match field {
            0 => raw.common[7] = 2,
            1 => raw.domain[3] = 2,
            _ => raw.target.values[3] = Some(2),
        }
        assert_eq!(features::validate(Action::IrqTarget(0), &raw), Err(Error::Range));
    }
}
