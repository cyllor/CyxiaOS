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
    struct Restore {
        pool: u64,
        #[cfg(boot_pool_plan)]
        slots: usize,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            super::TABLE_POOL.store(self.pool, core::sync::atomic::Ordering::Release);
            #[cfg(boot_pool_plan)]
            super::TABLE_SLOTS.store(self.slots, core::sync::atomic::Ordering::Release);
        }
    }
    let pool = 0x200001;
    let slots = crate::usermem::MAX_PROCESSES;
    #[cfg(boot_pool_plan)]
    let slots = slots - 1;
    let _restore = Restore {
        pool: super::TABLE_POOL.swap(pool, core::sync::atomic::Ordering::AcqRel),
        #[cfg(boot_pool_plan)]
        slots: super::TABLE_SLOTS.swap(slots, core::sync::atomic::Ordering::AcqRel),
    };
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

/// synchronize seals the changed subset, not the whole executable index: a
/// changed RW page must never be sealed, and consecutive RX pages share one
/// range instead of one shootdown per page.
#[test]
fn changed_subset_seals_only_executable_pages_in_consecutive_runs() {
    let mut table = super::PageTable::empty();
    for (index, physical, protection) in [
        (0usize, 0x400000u64, 5u8), (1, 0x401000, 5), (2, 0x402000, 3),
        (3, 0x403000, 5), (4, 0x404000, 5),
    ] {
        table.set(index, physical, protection).unwrap();
    }
    let sealable = core::array::from_fn::<_, 8, _>(|word| table.dirty[word] & table.executable[word]);
    assert_eq!(sealable[0] & 0b11111, 0b11011, "the changed RW page stayed sealable");
    assert_eq!(table.executable_runs_in(&sealable).collect::<Vec<_>>(), vec![
        (0x400000, 8192), (0x403000, 8192),
    ]);
}
