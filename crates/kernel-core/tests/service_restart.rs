use cyxia_kernel_core::control_plane::{
    Error,
    service_restart::{Lifecycle, Phase, RestartDecision},
};

#[test]
fn same_boot_restart_advances_generation_and_rejects_the_old_service() {
    let mut lifecycle = Lifecycle::new(7, 1).unwrap();
    assert!(lifecycle.accepts(7, 1));
    assert_eq!(
        lifecycle.fault(7, 1).unwrap(),
        RestartDecision::Restart { generation: 2 }
    );
    assert_eq!(lifecycle.phase(), Phase::Resetting);
    assert!(!lifecycle.accepts(7, 1));
    assert!(!lifecycle.accepts(7, 2));

    lifecycle.reset_complete(7, 2).unwrap();
    assert_eq!(lifecycle.phase(), Phase::Recovering);
    assert!(lifecycle.accepts(7, 2));
    assert!(!lifecycle.ready());
    lifecycle.peer_ready(7, 2).unwrap();
    assert_eq!(lifecycle.phase(), Phase::Ready);
    assert!(lifecycle.ready());
}

#[test]
fn two_consecutive_pre_ready_faults_isolate_without_a_third_generation() {
    let mut lifecycle = Lifecycle::new(9, 1).unwrap();
    assert_eq!(
        lifecycle.fault(9, 1).unwrap(),
        RestartDecision::Restart { generation: 2 }
    );
    lifecycle.reset_complete(9, 2).unwrap();
    assert_eq!(lifecycle.fault(9, 2).unwrap(), RestartDecision::Isolate);
    assert_eq!(lifecycle.phase(), Phase::Isolated);
    assert_eq!(lifecycle.generation(), 2);
    assert!(!lifecycle.accepts(9, 2));
    assert_eq!(lifecycle.reset_complete(9, 2), Err(Error::Busy));
}

#[test]
fn completed_peer_reconciliation_starts_a_new_consecutive_failure_window() {
    let mut lifecycle = Lifecycle::new(11, 4).unwrap();
    assert_eq!(
        lifecycle.fault(11, 4).unwrap(),
        RestartDecision::Restart { generation: 5 }
    );
    lifecycle.reset_complete(11, 5).unwrap();
    lifecycle.peer_ready(11, 5).unwrap();
    assert_eq!(
        lifecycle.fault(11, 5).unwrap(),
        RestartDecision::Restart { generation: 6 }
    );
}

#[test]
fn stale_identity_and_generation_overflow_fail_closed() {
    let mut lifecycle = Lifecycle::new(13, u64::MAX).unwrap();
    assert_eq!(lifecycle.fault(12, u64::MAX), Err(Error::Stale));
    assert_eq!(lifecycle.fault(13, u64::MAX - 1), Err(Error::Stale));
    assert_eq!(lifecycle.fault(13, u64::MAX), Err(Error::Exhausted));
    assert_eq!(lifecycle.phase(), Phase::Isolated);
    assert!(!lifecycle.accepts(13, u64::MAX));
    assert!(Lifecycle::new(0, 1).is_err());
    assert!(Lifecycle::new(1, 0).is_err());
}
