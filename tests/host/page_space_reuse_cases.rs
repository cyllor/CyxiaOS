#[test]
fn runtime_batch_owned_root_survives_repeated_dispatch_preparation() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map(VA, PA, UserPermissions::RW).unwrap();
    let root = space.root_phys();
    let epoch = space.epoch();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    runtime::clear_observations();
    for _ in 0..1000 {
        assert!(owner.begin().is_ok(), "preparing an owned root must preserve stable mappings");
        assert_eq!(owner.root().unwrap().root_phys(), root);
        assert_eq!(owner.root().unwrap().epoch(), epoch);
        assert_eq!(owner.root().unwrap().translate(VA).unwrap().physical, PA);
    }
    assert_eq!(runtime::locks(), (0, 0));
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    owner.retire();
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_reused_root_rejects_resident_cpu_without_losing_aliases() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map(VA, PA, UserPermissions::RW).unwrap();
    space.enter_cpu(2).unwrap();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    assert_eq!(owner.begin(), Err(crate::Errno::Busy));
    assert_eq!(owner.revoke_range(VA, 1), Err(crate::Errno::Busy));
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    owner.root().unwrap().leave_cpu(2);
    assert_eq!(owner.begin(), Ok(false));
}

#[test]
fn runtime_batch_dense_revoke_takes_one_lease_and_publishes_one_epoch() {
    let lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map_table_run(VA, PA, UserPermissions::RW, 512).unwrap();
    let epoch = space.epoch();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    runtime::clear_observations();
    runtime::take_epoch_publications();
    owner.revoke_range(VA, 512).unwrap();
    let publications = (runtime::locks(), runtime::take_epoch_publications());
    assert_eq!(owner.root().unwrap().epoch(), epoch + 512);
    for index in 0..512 {
        assert!(owner.root().unwrap().translate(VA + index * 4096).is_none());
        assert_eq!(runtime::count(PA + index * 4096), 0);
    }
    runtime::force_gate(true);
    owner.revoke_range(VA, 512).unwrap();
    assert!(runtime::gate());
    assert_eq!(runtime::take_epoch_publications(), 0);
    runtime::force_gate(false);
    drop(owner);
    drop(lock);
    assert_eq!(publications, ((1, 1), 1));
}

#[test]
fn runtime_batch_revoke_keeps_holes_permissions_and_peer_aliases_correct() {
    let lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = new_space(8);
    let start = VA + 0x1fb000;
    let mappings = [
        (0, 0, UserPermissions::RW),
        (1, 1, UserPermissions::RW),
        (3, 3, UserPermissions::RW),
        (4, 4, UserPermissions::RO),
        (5, 3, UserPermissions::RO),
        (6, 6, UserPermissions::RX),
        (7, 7, UserPermissions::RX),
        (8, 9, UserPermissions::RX),
        (9, 12, UserPermissions::RW),
    ];
    for (index, physical, permissions) in mappings {
        let physical = PA + physical * 4096;
        if permissions.executable { runtime::phase(physical, Phase::StableSealed); }
        let address = start + index * 4096;
        space.map(address, physical, permissions).unwrap();
        let leaf = space.leaf(address).unwrap();
        let hardware_flags = (index % 8) << 5;
        unsafe { leaf.write_volatile(leaf.read_volatile() | hardware_flags) };
    }
    let (_peer_memory, mut peer) = new_space(8);
    peer.map(VA, PA, UserPermissions::RO).unwrap();
    let epoch = space.epoch();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    runtime::clear_observations();
    runtime::take_epoch_publications();
    // Leave both the mapping just past the requested range and the other root's alias.
    owner.revoke_range(start, 9).unwrap();
    assert_eq!(owner.root().unwrap().epoch(), epoch + 8);
    for index in 0..9 {
        assert!(owner.root().unwrap().translate(start + index * 4096).is_none());
    }
    for frame in [1, 2, 3, 4, 6, 7, 9] { assert_eq!(runtime::count(PA + frame * 4096), 0); }
    assert_eq!(runtime::count(PA), 1);
    assert_eq!(peer.translate(VA).unwrap().permissions, UserPermissions::RO);
    assert_eq!(runtime::count(PA + 12 * 4096), 1 | 1 << 20);
    assert_eq!(owner.root().unwrap().translate(start + 9 * 4096).unwrap().physical, PA + 12 * 4096);
    let publications = (runtime::locks(), runtime::take_epoch_publications());
    drop(owner);
    drop(peer);
    drop(lock);
    assert_eq!(publications, ((2, 2), 2));
}

#[test]
fn runtime_batch_revoke_preflights_entire_range_before_changing_a_leaf() {
    let _lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = new_space(8);
    let last = 0x8000_0000_0000 - 4096;
    space.map(last, PA, UserPermissions::RW).unwrap();
    let epoch = space.epoch();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    runtime::clear_observations();
    runtime::take_epoch_publications();
    for (address, pages) in [(last + 1, 1), (last, 2), (last, usize::MAX)] {
        assert_eq!(owner.revoke_range(address, pages), Err(crate::Errno::Inval));
    }
    assert_eq!(owner.revoke_range(last, 0), Ok(()));
    assert_eq!(owner.root().unwrap().epoch(), epoch);
    assert_eq!(owner.root().unwrap().translate(last).unwrap().physical, PA);
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    assert_eq!((runtime::locks(), runtime::take_epoch_publications()), ((0, 0), 0));
}

#[test]
fn runtime_batch_persistent_staging_skips_unchanged_pages_and_rx_seals() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    let mut table = crate::staging::PageTable::empty();
    for index in 0..512 { table.set(index, PA + index as u64 * 4096, 5).unwrap(); }
    table.synchronize(&mut owner, VA, true).unwrap();
    let epoch = owner.root().unwrap().epoch();
    let root = owner.root().unwrap().root_phys();
    runtime::clear_observations();
    for _ in 0..1000 {
        assert_eq!(owner.begin(), Ok(false));
        table.synchronize(&mut owner, VA, false).unwrap();
    }
    assert_eq!(owner.root().unwrap().root_phys(), root);
    assert_eq!(owner.root().unwrap().epoch(), epoch);
    assert_eq!(runtime::locks(), (0, 0));
    assert_eq!(runtime::seal_calls(), 0);
    for index in 0..512 { assert_eq!(runtime::count(PA + index * 4096), 1 | 1 << 40); }
    owner.retire();
    for index in 0..512 { assert_eq!(runtime::count(PA + index * 4096), 0); }
}

#[test]
fn runtime_batch_persistent_delta_protect_none_replace_remove_and_reallocate() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    let mut table = crate::staging::PageTable::empty();
    for index in 0..4 { table.set(index, PA + index as u64 * 4096, 3).unwrap(); }
    table.synchronize(&mut owner, VA, true).unwrap();
    let untouched_epoch = owner.root().unwrap().epoch();
    table.set(0, PA, 3).unwrap();
    table.synchronize(&mut owner, VA, false).unwrap();
    assert_eq!(owner.root().unwrap().epoch(), untouched_epoch);
    table.set(0, PA, 1).unwrap();
    table.set(1, PA + 4096, 0).unwrap();
    table.set(2, PA + 10 * 4096, 3).unwrap();
    table.remove(3);
    table.synchronize(&mut owner, VA, false).unwrap();
    assert_eq!(owner.root().unwrap().translate(VA).unwrap().permissions, UserPermissions::RO);
    assert!(owner.root().unwrap().translate(VA + 4096).is_none());
    assert_eq!(owner.root().unwrap().translate(VA + 8192).unwrap().physical, PA + 10 * 4096);
    assert!(owner.root().unwrap().translate(VA + 12288).is_none());
    assert_eq!(runtime::count(PA), 1);
    for index in 1..4 { assert_eq!(runtime::count(PA + index * 4096), 0); }
    owner.revoke_range(VA + 8192, 1).unwrap();
    assert_eq!(runtime::count(PA + 10 * 4096), 0); // Eligible for backing release NOW.
    table.remove(2);
    table.set(2, PA + 11 * 4096, 3).unwrap();
    table.synchronize(&mut owner, VA, false).unwrap();
    assert_eq!(owner.root().unwrap().translate(VA + 8192).unwrap().physical, PA + 11 * 4096);
    table.clear();
    table.synchronize(&mut owner, VA, false).unwrap();
    assert!(owner.root().unwrap().translate(VA).is_none());
    assert_eq!(runtime::count(PA), 0);
    assert_eq!(runtime::count(PA + 11 * 4096), 0);
}

#[test]
fn runtime_batch_persistent_delta_failure_keeps_dirty_prefix_for_recovery() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    let mut table = crate::staging::PageTable::empty();
    table.set(0, PA, 3).unwrap();
    table.synchronize(&mut owner, VA, true).unwrap();
    table.set(1, PA + 4096, 3).unwrap();
    table.set(2, PA + 8192, 3).unwrap();
    runtime::phase(PA + 8192, Phase::StableSealed);
    assert_eq!(table.synchronize(&mut owner, VA, false), Err(crate::Errno::Io));
    assert_eq!(runtime::count(PA + 4096), 1 | 1 << 20);
    assert_eq!(runtime::count(PA + 8192), 0);
    runtime::phase(PA + 8192, Phase::StableWritable);
    table.synchronize(&mut owner, VA, false).unwrap();
    for index in 0..3 { assert_eq!(runtime::count(PA + index * 4096), 1 | 1 << 20); }
}

#[test]
fn runtime_batch_persistent_delta_cannot_seal_while_foreign_writable_alias_exists() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let (_peer_memory, mut peer) = new_space(8);
    peer.map(VA, PA, UserPermissions::RW).unwrap();
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    let mut table = crate::staging::PageTable::empty();
    table.set(0, PA, 3).unwrap();
    table.synchronize(&mut owner, VA, true).unwrap();
    table.set(0, PA, 5).unwrap();
    assert_eq!(table.synchronize(&mut owner, VA, false), Err(crate::Errno::Io));
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    assert!(owner.root().unwrap().translate(VA).is_none());
    drop(peer);
    table.synchronize(&mut owner, VA, false).unwrap();
    assert_eq!(runtime::count(PA), 1 | 1 << 40);
}

#[test]
fn runtime_batch_fresh_root_republishes_previously_clean_staging_and_active_delta_is_rejected() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    let mut table = crate::staging::PageTable::empty();
    table.set(63, PA, 3).unwrap();
    table.synchronize(&mut owner, VA, true).unwrap();
    owner.retire();
    let (_second_memory, second) = new_space(8);
    owner.current = Some(second);
    table.synchronize(&mut owner, VA, true).unwrap();
    owner.root().unwrap().enter_cpu(1).unwrap();
    table.remove(63);
    table.set(64, PA + 4096, 3).unwrap();
    assert_eq!(table.synchronize(&mut owner, VA, false), Err(crate::Errno::Busy));
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    owner.root().unwrap().leave_cpu(1);
    table.synchronize(&mut owner, VA, false).unwrap();
    assert_eq!(runtime::count(PA), 0);
    assert_eq!(runtime::count(PA + 4096), 1 | 1 << 20);
}

#[test]
fn runtime_batch_persistent_table_capacity_is_bounded_by_all_admitted_virtual_windows() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    #[repr(C, align(4096))]
    struct Pool([u8; 128 * 4096]);
    let mut memory = Box::new(Pool([0; 128 * 4096]));
    let arena = unsafe { TableArena::from_raw(memory.0.as_mut_ptr(), 0x200000, 128) }.unwrap();
    let kernel = KernelMappings::new([0; 256], runtime::RAM).unwrap();
    let mut space = unsafe { AddressSpace::new(arena, &kernel, SpaceId { id: 1, generation: 1 }) }.unwrap();
    let layout = crate::user_layout::ImageProfile::FullOsV3.layout();
    let windows = [(layout.image_base, layout.image_end),
        (layout.heap_base, layout.heap_base + layout.heap_pages as u64 * 4096),
        (layout.stack_base, layout.stack_base + layout.stack_pages as u64 * 4096),
        (0x6000000, 0x7000000), (0x100000, 0x109000)];
    let mut high_water = 0;
    for pass in 0..100 {
        for (start, end) in windows {
            for address in (start..end).step_by(0x200000) {
                space.map(address, PA, UserPermissions::RW).unwrap();
                space.unmap(address).unwrap();
            }
        }
        if pass == 0 { high_water = space.arena.used; }
        assert_eq!(space.arena.used, high_water);
        assert!(space.arena.used < 128);
    }
    drop(space);
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_revoked_table_frames_can_be_reused_across_all_user_levels() {
    let lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = new_space(4);
    let root = space.root_phys();
    let supervisor = 0x7777_0001;
    let upper = unsafe { space.arena.table(root).unwrap().add(256) };
    unsafe { upper.write_volatile(supervisor) };
    let mut result = Ok(());
    for index in 0..8 {
        let address = VA + (index << 39);
        result = space.map(address, PA, UserPermissions::RW);
        if result.is_err() { break; }
        assert_eq!(space.root_phys(), root);
        assert_eq!(unsafe { upper.read_volatile() }, supervisor);
        assert_eq!(space.translate(address).unwrap().physical, PA);
        assert!(space.translate(address + 4096).is_none());
        assert_eq!(space.unmap(address).unwrap().physical, PA);
        assert!(space.translate(address).is_none());
        assert_eq!(runtime::count(PA), 0);
        let epoch = space.epoch();
        space.enter_cpu(2).unwrap();
        assert_eq!(space.map(address + (1 << 39), PA, UserPermissions::RW), Err(Error::Active));
        space.leave_cpu(2);
        assert_eq!(space.epoch(), epoch);
    }
    drop(space);
    drop(lock);
    assert_eq!(result, Ok(()));
}

#[test]
fn runtime_batch_pressure_reclaims_empty_leaf_only_and_preserves_live_siblings() {
    let lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = new_space(5);
    let sibling = VA + 0x200000;
    let next = VA + 0x400000;
    let frame = PA + 64 * PAGE_BYTES;
    space.map_table_run(VA, PA, UserPermissions::RW, 12).unwrap();
    space.map(sibling, frame, UserPermissions::RO).unwrap();
    space.unmap_table_run(VA, 11).unwrap();
    let epoch = space.epoch();
    assert_eq!(space.map_table_run(next, PA, UserPermissions::RW, 2), Err(Error::Capacity));
    assert_eq!(space.epoch(), epoch);
    assert_eq!(space.translate(VA + 11 * PAGE_BYTES).unwrap().physical, PA + 11 * PAGE_BYTES);
    assert!(space.unmap_present(VA + 11 * PAGE_BYTES).unwrap());
    let vacant = space.leaf(VA + 12 * PAGE_BYTES).unwrap();
    unsafe { vacant.write_volatile(PA | W | NX) };
    // A walk needing all three levels must not consume the one recovered leaf.
    assert_eq!(space.map(VA + (1 << 39), PA, UserPermissions::RW), Err(Error::Capacity));
    let result = space.map_table_run(next, PA, UserPermissions::RW, 2);
    assert_eq!(space.translate(sibling).unwrap().permissions, UserPermissions::RO);
    assert_eq!(runtime::count(frame), 1);
    assert!(space.translate(next + 11 * PAGE_BYTES).is_none());
    if result.is_ok() {
        let recycled = space.leaf(next + 12 * PAGE_BYTES).unwrap();
        assert_eq!(recycled, vacant);
        assert_eq!(unsafe { recycled.read_volatile() }, 0);
    }
    assert_eq!(space.epoch(), epoch + 1 + 2 * u64::from(result.is_ok()));
    drop(space);
    assert_eq!(runtime::count(frame), 0);
    drop(lock);
    assert_eq!(result, Ok(()));
}

#[test]
fn runtime_batch_pressure_reclaims_paths_left_empty_by_failed_publication() {
    for run in [false, true] {
        let lock = runtime::TEST.lock().unwrap();
        runtime::reset();
        let (_memory, mut space) = new_space(4);
        runtime::set_count(PA, 0xfffff);
        let result = if run {
            space.map_table_run(VA, PA, UserPermissions::RW, 1)
        } else {
            space.map(VA, PA, UserPermissions::RW)
        };
        assert_eq!(result, Err(Error::Permissions));
        assert_eq!(runtime::count(PA), 0xfffff);
        assert!(space.translate(VA).is_none());
        let epoch = space.epoch();
        let other = VA + (1 << 39);
        let result = space.map(other, PA + PAGE_BYTES, UserPermissions::RW);
        let published = space.epoch() - epoch;
        let physical = space.translate(other).map(|page| page.physical);
        drop(space);
        drop(lock);
        assert_eq!(result, Ok(()));
        assert_eq!(published, 1);
        assert_eq!(physical, Some(PA + PAGE_BYTES));
    }
}

#[test]
fn runtime_batch_table_reclaim_leaves_foreign_and_shared_table_links_untouched() {
    let _lock = runtime::TEST.lock().unwrap();
    for duplicate in [false, true] {
        runtime::reset();
        let (_memory, mut space) = new_space(4);
        space.map(VA, PA, UserPermissions::RW).unwrap();
        space.unmap(VA).unwrap();
        let root = space.arena.table(space.root_phys()).unwrap();
        let original = unsafe { root.read_volatile() };
        let foreign = if duplicate { original } else { 0x7777_0000 | P | W | U };
        unsafe { root.add(1).write_volatile(foreign) };
        let result = space.map(VA + (2 << 39), PA, UserPermissions::RW);
        let links = unsafe { (root.read_volatile(), root.add(1).read_volatile()) };
        unsafe { root.add(1).write_volatile(0) };
        assert_eq!(result, Err(Error::Capacity));
        assert_eq!(links, (original, foreign));
        assert_eq!(runtime::count(PA), 0);
    }
}
