// This is a child of the actual extracted production staging module, so it
// can observe the private range iterator without altering its implementation.
// Real publication tests remain in cases.rs; this case exercises impossible
// guest physical values before the existing HIGH+PA boundary rejects them.
#[test]
fn runtime_batch_staging_rx_ranges_do_not_wrap_or_join_across_bitmap_holes() {
    let mut table = super::PageTable::empty();
    for (index, physical) in [(0, 0x400000), (1, 0x401000),
            (63, u64::MAX - 4095), (64, 0), (65, 4096),
            (127, 0x500000), (129, 0x501000), (510, 0x600000), (511, 0x601000)] {
        table.set(index, physical, 5).unwrap();
    }
    assert_eq!(table.executable_runs().collect::<Vec<_>>(), vec![
        (0x400000, 8192), (u64::MAX - 4095, 4096), (0, 8192),
        (0x500000, 4096), (0x501000, 4096), (0x600000, 8192),
    ]);
}
