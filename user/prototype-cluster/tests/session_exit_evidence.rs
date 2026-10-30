#[path = "../../../kernel/src/unified_session_exit.rs"]
mod evidence;

fn record(generation: u64, connection: u64, auth: bool, now: u64) -> [u64; 24] {
    let mut r = [0; 24];
    r[..12].copy_from_slice(&[1, 7, generation, connection, now, 12, 0x4001, 5, 2,
        if auth { 15 } else { 0 }, now - 1500, if auth { 4 } else { 0 }]);
    r
}

#[test]
fn bounded_provenance_keeps_original_and_latest_across_service_restarts() {
    let mut bank = [0; 80];
    for (generation, connection, auth, now) in [(1, 1, false, 2000), (1, 2, true, 4000), (2, 3, true, 6000), (2, 4, false, 8000)] {
        let r = record(generation, connection, auth, now);
        assert!(evidence::retain(&mut bank, &r, 7, generation, connection));
    }
    assert_eq!(&bank[..8], &[8, 0x4359584558495431, 1, 2, 2, 1, 2, 0]);
    assert_eq!(&bank[8..32], &record(1, 1, false, 2000));
    assert_eq!(&bank[32..56], &record(1, 2, true, 4000));
    assert_eq!(&bank[56..80], &record(2, 3, true, 6000));
}

#[test]
fn malformed_or_cross_generation_payload_cannot_mutate_reserved_provenance() {
    let original = [0; 80];
    for field in [0, 1, 2, 3, 5, 7, 8, 9, 16, 23] {
        let mut bank = original;
        let mut r = record(2, 3, true, 4000);
        r[field] = u64::MAX;
        assert!(!evidence::retain(&mut bank, &r, 7, 2, 3), "field {field}");
        assert_eq!(bank, original);
    }
}
