// This is a child of the actual extracted production staging module, so it
// can observe the private range iterator without altering its implementation.
// Real publication tests remain in cases.rs; this case exercises impossible
// guest physical values before the existing HIGH+PA boundary rejects them.
#[test]
fn runtime_batch_process_capacity_uses_the_production_feature_gate() {
    let slots = crate::usermem::MAX_PROCESSES;
    assert_eq!(slots, if cfg!(feature = "cosmic-session") { 40 } else { 8 });
    assert_eq!(super::TABLE_POOL_BYTES,
        (slots * super::TABLE_PAGES_PER_PROCESS * 4096) as u64);
}

#[test]
fn runtime_batch_process_owner_checks_first_last_and_out_of_range_slots() {
    let _lock = crate::runtime_fixture::TEST.lock().unwrap();
    crate::runtime_fixture::reset();
    // A deliberately unaligned nonzero physical pool cannot be dereferenced.
    // Valid slots must reach the REAL arena validator; invalid slots must stop
    // at the REAL owner guard before arena arithmetic or access. No HIGH+PA
    // translation is substituted, and no successful guest allocation is claimed.
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) { super::TABLE_POOL.store(self.0, core::sync::atomic::Ordering::Release); }
    }
    let pool = 0x200001;
    let _restore = Restore(super::TABLE_POOL.swap(pool, core::sync::atomic::Ordering::AcqRel));
    let slots = crate::usermem::MAX_PROCESSES;
    for slot in [0, slots - 1, slots, slots + 1, usize::MAX] {
        crate::HOST_DIAGNOSTICS.with(|bytes| bytes.borrow_mut().clear());
        let mut owner = super::ProcessSpace::new();
        owner.bind(slot, 123);
        let valid = slot < slots;
        assert_eq!(owner.begin(), Err(if valid { crate::Errno::Nomem } else { crate::Errno::Nodev }));
        assert!(owner.current.is_none());
        let text = crate::HOST_DIAGNOSTICS.with(|bytes| String::from_utf8(bytes.borrow().clone()).unwrap());
        if valid {
            let physical = pool + (slot * super::TABLE_PAGES_PER_PROCESS * 4096) as u64;
            assert!(text.contains("stage=begin.arena"), "{text}");
            assert!(text.contains(&format!("pa={physical:#x}")), "{text}");
        } else {
            assert!(text.contains("stage=begin.owner"), "{text}");
            assert!(text.contains(&format!("slot={slot} ")), "{text}");
        }
    }
}

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
