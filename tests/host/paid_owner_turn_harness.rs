#![allow(dead_code)]
// OWNER_GATE_MODULE
// BEFORE_API_ADAPTER

#[test]
fn paid_turn_survives_old_end_with_an_already_queued_peer() {
    let gate = owner_gate::Gate::new();
    let permit = gate.try_acquire(0, 100, 10).unwrap();
    assert!(gate.try_acquire(2, 101, 10).is_none());
    permit.release(101);
    let permit = gate.try_acquire(0, 109, 10).unwrap();
    permit.protect_service_until(134, 109);
    permit.release(109);
    assert!(gate.try_acquire(2, 111, 10).is_none(), "peer took a still-paid protected owner turn");
    gate.try_acquire(0, 111, 10).expect("paid owner lost authorization after the old turn end").release(111);
    assert!(gate.try_acquire(0, 125, 10).is_none());
    gate.try_acquire(2, 125, 10).unwrap().release(125);
}

#[test]
fn paid_turn_also_excludes_a_peer_arriving_after_release() {
    let gate = owner_gate::Gate::new();
    let permit = gate.try_acquire(0, 100, 10).unwrap();
    permit.protect_service_until(125, 100);
    permit.release(100); // nobody was queued at release
    assert!(gate.try_acquire(2, 105, 10).is_none(), "late peer stole the paid turn after a no-waiter release");
    gate.try_acquire(0, 111, 10).unwrap().release(111);
    assert!(gate.try_acquire(0, 125, 10).is_none());
    gate.try_acquire(2, 125, 10).unwrap().release(125);
}

#[test]
fn repeated_credits_and_reborrows_cannot_refresh_the_epoch_cap() {
    let gate = owner_gate::Gate::new();
    let permit = gate.try_acquire(0, 100, 10).unwrap();
    permit.protect_service_until(120, 100);
    assert!(gate.try_acquire(2, 101, 10).is_none());
    permit.release(101);
    let permit = gate.try_acquire(0, 119, 10).unwrap();
    permit.protect_service_until(144, 119);
    permit.release(119);
    let permit = gate.try_acquire(0, 124, 10).unwrap();
    permit.protect_service_until(149, 124);
    permit.release(124);
    assert!(gate.try_acquire(0, 125, 10).is_none(), "another credit renewed ahead of an existing peer");
    gate.try_acquire(2, 125, 10).unwrap().release(125);
}

#[test]
fn protection_stops_at_dispatch_end_and_absent_owner_expires() {
    for deadline in [108, 125] {
        let gate = owner_gate::Gate::new();
        let permit = gate.try_acquire(0, 100, 10).unwrap();
        permit.protect_service_until(deadline, 100);
        permit.release(100);
        assert!(gate.try_acquire(2, deadline - 1, 10).is_none());
        gate.try_acquire(2, deadline, 10).expect("absent protected CPU retained ownership past its deadline").release(deadline);
    }
}

#[test]
fn unprotected_release_and_other_cpu_turns_keep_their_existing_rules() {
    let gate = owner_gate::Gate::new();
    gate.try_acquire(0, 100, 10).unwrap().release(100);
    gate.try_acquire(2, 101, 10).unwrap().release(101);
    let permit = gate.try_acquire(2, 110, 10).unwrap();
    assert!(!permit.protect_service_until(999, 110));
    assert!(gate.try_acquire(0, 111, 10).is_none());
    permit.release(111);
    assert!(gate.try_acquire(2, 120, 10).is_none());
    gate.try_acquire(0, 120, 10).unwrap().release(120);
}

#[test]
fn saturated_clock_cannot_wrap_or_revive_an_expired_cap() {
    let gate = owner_gate::Gate::new();
    let permit = gate.try_acquire(0, u64::MAX - 20, 10).unwrap();
    permit.protect_service_until(u64::MAX, u64::MAX - 20);
    assert!(gate.try_acquire(2, u64::MAX - 19, 10).is_none());
    permit.release(u64::MAX - 19);
    let permit = gate.try_acquire(0, u64::MAX - 1, 10).unwrap();
    assert!(!permit.protect_service_until(u64::MAX, u64::MAX));
    permit.release(u64::MAX);
    // There is no representable future preference at MAX; the peer can
    // nevertheless acquire immediately, without a wrapped/sticky deadline.
    gate.try_acquire(2, u64::MAX, 10).unwrap().release(u64::MAX);
}
