use cyxia_prototype_cluster::{abi::*, arena::Arena};
#[test]
fn broker_accepts_only_bounded_known_requests() {
    assert!(valid_request(1, 32, 0));
    assert!(!valid_request(1, (PAYLOAD + 1) as u64, 0));
    assert!(!valid_request(99, 0, 0));
    assert!(!valid_request(7, 4096, u64::MAX));
}
#[test]
fn allocator_reuses_freed_storage_without_overlap() {
    let mut a = Arena::new(0x100000, 1024);
    let first = a.allocate(128, 64).unwrap();
    let second = a.allocate(128, 64).unwrap();
    assert_ne!(first, second);
    a.release(first, 128);
    assert_eq!(a.allocate(128, 64), Some(first));
    assert!(a.allocate(2048, 64).is_none());
    assert_eq!(second & 63, 0);
}
#[test]
fn repeated_disconnect_allocation_cycles_restore_entire_quota() {
    let mut arena = Arena::new(0x200000, 16384);
    for _ in 0..100 {
        let a = arena.allocate(4097, 4096).unwrap();
        let b = arena.allocate(8192, 64).unwrap();
        assert!(a + 4097 <= b || b + 8192 <= a);
        assert!(arena.allocate(16384, 64).is_none());
        arena.release(a, 4097);
        arena.release(b, 8192);
        let whole = arena.allocate(16384, 4096).unwrap();
        assert_eq!(whole, 0x200000);
        arena.release(whole, 16384);
    }
    assert!(arena.allocate(1, 3).is_none());
}

#[test]
fn advertised_result_and_tombstone_capacity_fits_bounded_eight_mib_quota() {
    let mut arena = Arena::new(0x4000000, 8 * 1024 * 1024);
    let placements = arena
        .allocate(PLACEMENT_STORAGE_BYTES, 4096)
        .expect("placement history is part of the same 8MiB quota");
    // 128 retained maximum-size results plus bounded tombstones and TLS work.
    let mut held = Vec::new();
    for _ in 0..128 {
        held.push(arena.allocate(32768, 64).unwrap());
    }
    let tombstones = arena.allocate(4096 * 256, 64).unwrap();
    let tls_and_protocol = arena.allocate(2 * 1024 * 1024, 4096).unwrap();
    for address in held {
        arena.release(address, 32768);
    }
    arena.release(tombstones, 4096 * 256);
    arena.release(tls_and_protocol, 2 * 1024 * 1024);
    arena.release(placements, PLACEMENT_STORAGE_BYTES);
    assert_eq!(arena.allocate(8 * 1024 * 1024, 4096), Some(0x4000000));
    assert!(arena.allocate(1, 64).is_none());
}
