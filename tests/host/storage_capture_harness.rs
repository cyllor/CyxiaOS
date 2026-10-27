#[path = "../../kernel/src/storage_fault_capture/state.rs"]
mod state;
use core::sync::atomic::Ordering;

fn config() -> [u64; 64] {
    let mut value = [0; 64];
    value[..4].copy_from_slice(&[0x4359584131304346, 1, 1, 9]);
    value[4..20].fill(7);
    value
}
#[test]
fn rejects_wrong_boot_uuid_or_reserved_configuration() {
    let s = Box::new(state::Capture::new());
    let c = config();
    assert!(!s.begin(&c, 8, [7; 16]));
    let uuid = [7u64.to_le_bytes(); 2].concat().try_into().unwrap();
    assert!(s.begin(&c, 9, uuid));
    let mut bad = c;
    bad[20] = 1;
    assert!(!state::Capture::new().begin(&bad, 9, uuid));
}

#[test]
fn cache_eviction_mode_accepts_only_the_reader_owner() {
    let s = Box::new(state::Capture::new());
    let mut c = config();
    c[2] = 4;
    assert!(s.begin(
        &c,
        9,
        [7u64.to_le_bytes(); 2].concat().try_into().unwrap()
    ));
    assert!(!s.owner(1, [100, 3]));
    assert!(s.owner(2, [101, 3]));
}

#[test]
fn consumed_reply_boundary_is_single_publish_and_fail_closed() {
    let s = state::Consumption::new();
    let progress = [0x5a; 104];
    assert!(s.publish([100, 3, 200, 7, 9, 10, 6], &progress));
    assert_eq!(s.words[0].load(Ordering::Acquire), 0x4359584131304350);
    assert_eq!(s.words[4].load(Ordering::Acquire), 7);
    assert_eq!(s.words[8].load(Ordering::Acquire), 0x5a5a5a5a5a5a5a5a);
    assert!(!s.publish([100, 3, 201, 7, 9, 10, 6], &progress));
    assert!(!state::Consumption::new().publish([100, 3, 0, 7, 9, 10, 6], &progress));
}

#[test]
fn only_registered_owner_is_published_and_overflow_fails_closed() {
    let s = Box::new(state::Capture::new());
    assert!(s.begin(
        &config(),
        9,
        [7u64.to_le_bytes(); 2].concat().try_into().unwrap()
    ));
    assert!(s.owner(1, [100, 3]));
    assert!(s.owner(2, [101, 3]));
    assert!(!s.selected([100, 4]));
    for index in 0..384 {
        let _ = s.record(
            [index + 1, 9, 100, 3, 24, 80, 16, 4, 0, 0],
            [0xab; 32],
            &[0x5a; 640],
        );
        assert_eq!(s.words[3].load(Ordering::Acquire), index + 1);
    }
    assert_eq!(s.words[64].load(Ordering::Acquire), 0x4359584131304556);
    assert_eq!(s.words[80].load(Ordering::Acquire), 0x5a5a5a5a5a5a5a5a);
    let _ = s.record([385, 9, 100, 3, 24, 80, 16, 4, 0, 0], [0; 32], &[0; 640]);
    assert_eq!(s.words[3].load(Ordering::Acquire), 384);
    assert_ne!(s.words[4].load(Ordering::Acquire), 0);
}
