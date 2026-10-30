use cyxia_kernel_core::control_plane::task_admission::CustodyKey;
use cyxia_kernel_core::control_plane::task_admission::{Authority, StartRequest, Terms};

fn custody_key() -> CustodyKey {
    CustodyKey {
        owner_boot: 1,
        cluster: [4; 32],
        requester: [5; 32],
        contract: [1; 16],
        request_hash: [6; 32],
    }
}

#[test]
fn custody_lookup_survives_service_disconnect_without_restoring_start_authority() {
    let mut a = Authority::new();
    a.session(7, 1, 0).unwrap();
    a.session(7, 2, 0).unwrap();
    let key = custody_key();
    let token = a.reserve_with_custody(terms(), [3; 32], key, 0).unwrap();
    a.grant(token, [1; 16], 1, 50, 0).unwrap();
    assert!(!a.custody(key).unwrap().started);
    a.start(start(token, 50, 7, [2; 32]), 1).unwrap();
    a.disconnect();
    assert_eq!(a.custody(key).unwrap().token, token);
    assert!(a.custody(key).unwrap().started);
    assert!(a.start(start(token, 50, 7, [2; 32]), 2).is_err());
    for field in 0..5 {
        let mut wrong = key;
        match field {
            0 => wrong.owner_boot += 1,
            1 => wrong.cluster[0] ^= 1,
            2 => wrong.requester[0] ^= 1,
            3 => wrong.contract[0] ^= 1,
            _ => wrong.request_hash[0] ^= 1,
        }
        assert!(a.custody(wrong).is_err());
    }
    assert!(a.inventory(2, key.requester).is_err());
    assert!(a.inventory(1, [7; 32]).is_err());
    assert_eq!(a.inventory(1, key.requester).unwrap().key, key);
    a.release(token).unwrap();
    assert!(a.custody(key).is_err());
}

#[test]
fn custody_query_of_unstarted_work_cannot_refresh_expired_session_or_rebind_contract() {
    let mut a = Authority::new();
    a.session(7, 1, 0).unwrap();
    a.session(7, 2, 0).unwrap();
    let mut wrong = custody_key();
    wrong.contract = [9; 16];
    assert!(a.reserve_with_custody(terms(), [3; 32], wrong, 0).is_err());
    let token = a
        .reserve_with_custody(terms(), [3; 32], custody_key(), 0)
        .unwrap();
    a.grant(token, [1; 16], 1, 50, 0).unwrap();
    a.disconnect();
    assert!(!a.custody(custody_key()).unwrap().started);
    assert!(a.start(start(token, 50, 7, [2; 32]), 1).is_err());
    a.session(8, 1, 1).unwrap();
    a.session(8, 2, 1).unwrap();
    assert!(a.start(start(token, 50, 8, [2; 32]), 2).is_err());
}
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
fn live_activity_preserves_custody_generation_and_level_without_granting_ready() {
    let mut a = Authority::new();
    a.session(7, 1, 0).unwrap();
    for now in [1000, 2000, 3000] {
        a.activity(7, now).unwrap();
        assert!(a.reserve(terms(), [3; 32], now).is_err());
    }
    a.session(7, 2, 3000).unwrap();
    let token = a
        .reserve_with_custody(terms(), [3; 32], custody_key(), 3000)
        .unwrap();
    a.grant(token, [1; 16], 1, 3050, 3000).unwrap();
    for now in [3001, 3002, 3003] {
        a.activity(7, now).unwrap();
    }
    assert_eq!(a.custody(custody_key()).unwrap().token, token);
    a.start(start(token, 3050, 7, [2; 32]), 3004).unwrap();
    assert!(a.custody(custody_key()).unwrap().started);
}

#[test]
fn invalid_activity_never_revives_or_rebinds_old_reservation() {
    for (epoch, now) in [(0, 101), (8, 101), (7, 99), (7, 1600), (7, 1601)] {
        let mut a = Authority::new();
        a.session(7, 1, 100).unwrap();
        a.session(7, 2, 100).unwrap();
        let token = a
            .reserve_with_custody(terms(), [3; 32], custody_key(), 100)
            .unwrap();
        a.grant(token, [1; 16], 1, 150, 100).unwrap();
        assert!(a.activity(epoch, now).is_err());
        assert!(a.activity(7, 101).is_err(), "invalid activity must isolate");
        assert!(a.session(7, 2, 101).is_err());
        assert_eq!(a.custody(custody_key()).unwrap().token, token);
        a.session(7, 1, 101).unwrap();
        a.session(7, 2, 101).unwrap();
        assert!(
            a.start(start(token, 150, 7, [2; 32]), 102).is_err(),
            "reconnect reused old generation"
        );
    }
}

#[test]
fn activity_at_exact_deadline_is_stale_and_does_not_change_last_rx() {
    let mut a = Authority::new();
    assert!(a.activity(7, 0).is_err());
    a.session(7, 1, 10).unwrap();
    a.activity(7, 1509).unwrap();
    assert!(a.activity(7, 3009).is_err());
    // Explicit establishment at the previous accepted time still succeeds:
    // failed activity did not advance the monotonic last_rx watermark.
    a.session(7, 1, 1509).unwrap();
    a.disconnect();
    assert!(a.activity(7, 1510).is_err());
    assert!(a.session(7, 2, 1510).is_err());
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
