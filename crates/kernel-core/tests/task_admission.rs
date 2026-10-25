use cyxia_kernel_core::control_plane::task_admission::{Authority, StartRequest, Terms};
fn terms() -> Terms {
    Terms {
        cpu_milli: 100,
        memory_pages: 16,
        runtime_ms: 50,
        contract: [1; 16],
        input_hash: [2; 32],
        package_hash: [3; 32],
    }
}
fn start(token: u64, deadline: u64, session: u64, input_hash: [u8; 32]) -> StartRequest {
    StartRequest {
        token,
        contract: [1; 16],
        grant: 1,
        deadline,
        session,
        input_hash,
    }
}
#[test]
fn freezes_contract_lease_and_content_before_unique_start() {
    let mut a = Authority::new();
    assert!(a.reserve(terms(), [3; 32], 1).is_err());
    a.session(7, 1, 1).unwrap();
    assert!(a.reserve(terms(), [3; 32], 2).is_err());
    a.session(7, 2, 3).unwrap();
    let token = a.reserve(terms(), [3; 32], 4).unwrap();
    assert!(a.grant(token, [1; 16], 1, 100, 5).is_err());
    a.grant(token, [1; 16], 1, 54, 5).unwrap();
    assert!(a.start(start(token, 55, 7, [2; 32]), 6).is_err());
    assert!(a.start(start(token, 54, 7, [9; 32]), 6).is_err());
    a.start(start(token, 54, 7, [2; 32]), 6).unwrap();
    assert!(a.start(start(token, 54, 7, [2; 32]), 7).is_err());
}
#[test]
fn disconnect_reconnect_and_missed_heartbeat_never_restore_old_authority() {
    let mut a = Authority::new();
    a.session(7, 1, 0).unwrap();
    a.session(7, 2, 0).unwrap();
    let t = a.reserve(terms(), [3; 32], 0).unwrap();
    a.grant(t, [1; 16], 1, 50, 0).unwrap();
    a.disconnect();
    a.session(8, 1, 1).unwrap();
    a.session(8, 2, 1).unwrap();
    assert!(a.start(start(t, 50, 8, [2; 32]), 2).is_err());
    a.release(t).unwrap();
    let mut long = terms();
    long.runtime_ms = 60000;
    let t = a.reserve(long, [3; 32], 3).unwrap();
    a.grant(t, [1; 16], 1, 60003, 3).unwrap();
    assert!(a.start(start(t, 60003, 8, [2; 32]), 1501).is_err());
}
#[test]
fn rejects_underreserved_memory_expired_prepare_and_unknown_package() {
    let mut a = Authority::new();
    a.session(1, 1, 0).unwrap();
    a.session(1, 2, 0).unwrap();
    let mut t = terms();
    t.memory_pages = 11;
    assert!(a.reserve(t, [3; 32], 0).is_err());
    assert!(a.reserve(terms(), [4; 32], 0).is_err());
    let token = a.reserve(terms(), [3; 32], 0).unwrap();
    a.session(1, 2, 1000).unwrap();
    a.session(1, 2, 1999).unwrap();
    assert!(a.grant(token, [1; 16], 1, 2050, 2000).is_err());
}

#[test]
fn queued_and_suspended_work_reaches_failure_without_an_execution_credit() {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use cyxia_kernel_core::control_plane::task_admission::expire_quiescent;
    for initial in [2, 3] {
        let state = AtomicU64::new(initial);
        assert!(!expire_quiescent(
            &state,
            &AtomicBool::new(false),
            49,
            &AtomicU64::new(50)
        ));
        assert_eq!(state.load(Ordering::Acquire), initial);
        assert!(expire_quiescent(
            &state,
            &AtomicBool::new(false),
            50,
            &AtomicU64::new(50)
        ));
        assert_eq!(state.load(Ordering::Acquire), 5);
    }
    for initial in [0, 1, 4, 5] {
        let state = AtomicU64::new(initial);
        assert!(!expire_quiescent(
            &state,
            &AtomicBool::new(true),
            100,
            &AtomicU64::new(50)
        ));
        assert_eq!(state.load(Ordering::Acquire), initial);
    }
    let state = AtomicU64::new(3);
    assert!(expire_quiescent(
        &state,
        &AtomicBool::new(true),
        1,
        &AtomicU64::new(50)
    ));
    assert_eq!(state.load(Ordering::Acquire), 5);
}

#[test]
fn idle_expiry_acquires_metadata_from_the_new_task_publication() {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use cyxia_kernel_core::control_plane::task_admission::expire_quiescent;
    for _ in 0..256 {
        let state = AtomicU64::new(0);
        let cancel = AtomicBool::new(true);
        let deadline = AtomicU64::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                deadline.store(500, Ordering::Relaxed);
                cancel.store(false, Ordering::Relaxed);
                state.store(2, Ordering::Release);
            });
            loop {
                assert!(!expire_quiescent(&state, &cancel, 100, &deadline));
                if state.load(Ordering::Relaxed) == 2 {
                    break;
                }
                std::thread::yield_now();
            }
        });
        assert_eq!(state.load(Ordering::Acquire), 2);
    }
}
