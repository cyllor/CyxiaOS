use cyxia_cluster_transport::discovery::{Discovery, Error, Message, WIRE_BYTES};

fn state() -> Discovery {
    Discovery::new([1; 32], [2; 32], [10, 42, 0, 1], 24, 40001, 0).unwrap()
}

#[test]
fn canonical_discovery_payload_is_exact_bounded_and_contains_no_authority() {
    let m = Message {
        node: [2; 32],
        port: 8443,
        nonce: [7; 16],
    };
    let raw = m.encode().unwrap();
    assert_eq!(raw.len(), WIRE_BYTES);
    assert!(raw.len() <= 256);
    assert_eq!(&raw[..8], b"CXD1\x01\0\x3c\0");
    assert_eq!(Message::decode(&raw), Ok(m));
    for offset in [0, 4, 6, 42] {
        let mut bad = raw;
        bad[offset] ^= 0x80;
        assert!(Message::decode(&bad).is_err());
    }
    assert!(Message::decode(&raw[..59]).is_err());
    let mut extra = raw.to_vec();
    extra.push(0);
    assert!(Message::decode(&extra).is_err());
    assert!(Message { node: [0; 32], ..m }.encode().is_err());
    assert!(Message { port: 0, ..m }.encode().is_err());
    assert!(
        Message {
            nonce: [0; 16],
            ..m
        }
        .encode()
        .is_err()
    );
}

#[test]
fn announcements_require_fresh_guest_nonce_and_two_second_bounded_jitter() {
    let mut d = state();
    assert!(d.due(0).unwrap());
    assert_eq!(d.announce(0, [7; 16]).unwrap().port, 40001);
    let due = d.next_announcement_ms();
    assert!((1800..=2200).contains(&due));
    assert!(!d.due(due - 1).unwrap());
    assert_eq!(d.announce(due - 1, [8; 16]), Err(Error::NotDue));
    assert_eq!(d.announce(due, [7; 16]), Err(Error::Nonce));
    d.announce(due, [8; 16]).unwrap();
    assert!(
        d.due(due - 1).is_err(),
        "regressing local clock must fail closed"
    );
}

#[test]
fn untrusted_hint_does_not_authorize_and_tcp_target_comes_from_received_source() {
    let mut d = state();
    assert_eq!(d.begin_auth(0), Err(Error::NotFound));
    let msg = Message {
        node: [2; 32],
        port: 8443,
        nonce: [9; 16],
    }
    .encode()
    .unwrap();
    d.receive([10, 42, 0, 77], &msg, 10).unwrap();
    let attempt = d.begin_auth(11).unwrap();
    assert_eq!((attempt.ipv4, attempt.port), ([10, 42, 0, 77], 8443));
    assert_eq!(attempt.node, [2; 32]);
    assert_eq!(d.pending_auth(), 1);
    assert_eq!(d.begin_auth(12), Err(Error::Busy));
    let mut forged = attempt;
    forged.generation += 1;
    assert_eq!(d.finish_auth(forged), Err(Error::Stale));
    assert_eq!(d.pending_auth(), 1);
    d.finish_auth(attempt).unwrap();
    assert_eq!(d.pending_auth(), 0);
    // This API returns connection candidates only; no member, READY, grant or
    // resource authority can be produced by a datagram or successful attempt.
}

#[test]
fn cache_and_auth_bounds_survive_spoofed_nodes_and_peer_has_reserved_space() {
    let mut d = state();
    for node in 3..32 {
        let msg = Message {
            node: [node; 32],
            port: 8443,
            nonce: [node; 16],
        }
        .encode()
        .unwrap();
        let _ = d.receive([10, 42, 0, node], &msg, 1);
        assert!(d.candidates() <= 8);
        assert!(d.pending_auth() <= 4);
        assert_eq!(d.begin_auth(1), Err(Error::NotFound));
    }
    let msg = Message {
        node: [2; 32],
        port: 8443,
        nonce: [77; 16],
    }
    .encode()
    .unwrap();
    d.receive([10, 42, 0, 2], &msg, 2).unwrap();
    assert_eq!(d.candidates(), 8);
    assert_eq!(d.begin_auth(2).unwrap().node, [2; 32]);
}

#[test]
fn repeated_nonce_cannot_refresh_an_expired_candidate_and_bad_sources_are_rejected() {
    let mut d = state();
    let msg = Message {
        node: [2; 32],
        port: 8443,
        nonce: [7; 16],
    }
    .encode()
    .unwrap();
    for source in [
        [0; 4],
        [127, 0, 0, 1],
        [10, 43, 0, 2],
        [10, 42, 0, 0],
        [10, 42, 0, 255],
        [10, 42, 0, 1],
    ] {
        assert!(d.receive(source, &msg, 0).is_err());
    }
    d.receive([10, 42, 0, 2], &msg, 1).unwrap();
    assert_eq!(d.receive([10, 42, 0, 2], &msg, 6000), Err(Error::Nonce));
    assert_eq!(d.begin_auth(7000), Err(Error::Expired));
}

#[test]
fn announcement_handoff_is_configuration_bound_and_cannot_rewind_an_active_sender() {
    let mut old = state();
    old.announce(100, [7; 16]).unwrap();
    let schedule = old.announcement_schedule();
    let mut fresh = state();
    assert_eq!(fresh.resume_announcements(schedule, 99), Err(Error::Clock));
    let mut wrong = Discovery::new([3; 32], [2; 32], [10, 42, 0, 1], 24, 40001, 100).unwrap();
    assert_eq!(
        wrong.resume_announcements(schedule, 100),
        Err(Error::Configuration)
    );
    fresh.resume_announcements(schedule, 100).unwrap();
    assert!(!fresh.due(1000).unwrap());
    assert_eq!(fresh.begin_auth(1000), Err(Error::NotFound));
    let next = fresh.next_announcement_ms();
    fresh.announce(next, [9; 16]).unwrap();
    assert_eq!(
        fresh.resume_announcements(schedule, next),
        Err(Error::Configuration)
    );
}
