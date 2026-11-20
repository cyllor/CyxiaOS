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
