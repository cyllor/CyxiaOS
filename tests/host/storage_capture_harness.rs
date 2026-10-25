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
    for index in 0..256 {
        s.record(
            [index + 1, 9, 100, 3, 24, 80, 16, 4, 0, 0],
            [0xab; 32],
            &[0x5a; 640],
        );
        assert_eq!(s.words[3].load(Ordering::Acquire), index + 1);
    }
    assert_eq!(s.words[64].load(Ordering::Acquire), 0x4359584131304556);
    assert_eq!(s.words[80].load(Ordering::Acquire), 0x5a5a5a5a5a5a5a5a);
    s.record([257, 9, 100, 3, 24, 80, 16, 4, 0, 0], [0; 32], &[0; 640]);
    assert_eq!(s.words[3].load(Ordering::Acquire), 256);
    assert_ne!(s.words[4].load(Ordering::Acquire), 0);
}
