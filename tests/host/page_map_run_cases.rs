#[test]
fn runtime_batch_run_matches_scalar_dense_permissions_and_retirement() {
    let _lock = runtime::TEST.lock().unwrap();
    for permissions in [UserPermissions::RW, UserPermissions::RO, UserPermissions::RX] {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        if permissions.executable {
            for i in 0..512 { runtime::phase(PA + i * 4096, Phase::StableSealed); }
        }
        space.map_table_run(VA, PA, permissions, 512).unwrap();
        assert_eq!(space.epoch(), 513);
        for i in 0..512 {
            let actual = space.translate(VA + i * 4096 + 31).unwrap();
            assert_eq!(actual.physical, PA + i * 4096 + 31);
            assert_eq!(actual.permissions, permissions);
        }
        drop(space);
        for i in 0..512 { assert_eq!(runtime::count(PA + i * 4096), 0); }
        assert_eq!(runtime::locks(), (2, 2));
    }
}

#[test]
fn runtime_batch_run_partial_errors_match_scalar_tables_aliases_and_epochs() {
    let _lock = runtime::TEST.lock().unwrap();
    for scenario in 0..8 {
        let mut reference = None;
        for fast in [false, true] {
            runtime::reset();
            let (_memory, mut space) = new_space(8);
            let address = if scenario == 6 { VA + 1 } else { VA };
            let physical = if scenario == 5 { runtime::RAM - 3 * 4096 }
                else if scenario == 7 { PA + 1 } else { PA };
            let permissions = if scenario == 4 { UserPermissions::RX } else { UserPermissions::RW };
            if permissions.executable {
                for i in 0..16 { runtime::phase(PA + i * 4096, Phase::StableSealed); }
                runtime::phase(PA + 4 * 4096, Phase::StableWritable);
            }
            match scenario {
                1 => runtime::phase(PA + 4 * 4096, Phase::Transition),
                2 => runtime::phase(PA + 4 * 4096, Phase::StableSealed),
                3 => runtime::set_count(PA + 4 * 4096, 0xfffff),
                0 => { space.map(VA + 4 * 4096, PA + 20 * 4096, UserPermissions::RW).unwrap(); }
                _ => {}
            }
            let result = if fast { space.map_table_run(address, physical, permissions, 16) }
                else { space.map_pages((0..16).map(|i| (address + i * 4096, physical + i * 4096, permissions))) };
            let translations: Vec<_> = (0..16).map(|i| space.translate(VA + i * 4096)
                .map(|t| (t.physical, t.permissions.writable, t.permissions.executable))).collect();
            let aliases: Vec<_> = (0..16).map(|i| {
                let page = physical + i * 4096;
                if page < runtime::RAM && page % 4096 == 0 { runtime::count(page) } else { u64::MAX }
            }).collect();
            let snapshot = (result, space.epoch(), space.arena.used, translations, aliases);
            if fast { assert_eq!(Some(snapshot), reference, "scenario {scenario}"); }
            else { reference = Some(snapshot); }
            drop(space);
            assert!(!runtime::gate());
        }
    }
}

#[test]
fn runtime_batch_run_bounds_and_active_roots_do_not_publish() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map_table_run(0, 1, UserPermissions::RW, 0).unwrap();
    assert_eq!(space.map_table_run(VA, PA, UserPermissions::RW, 513), Err(Error::Address));
    assert_eq!(space.map_table_run(VA + 0x1ff000, PA, UserPermissions::RW, 2), Err(Error::Address));
    assert_eq!(space.epoch(), 1);
    assert_eq!(runtime::locks(), (0, 0));
    space.enter_cpu(1).unwrap();
    assert_eq!(space.map_table_run(VA, PA, UserPermissions::RW, 4), Err(Error::Active));
    space.leave_cpu(1);
    assert_eq!(space.epoch(), 1);
    drop(space);
}

#[test]
fn runtime_batch_run_capacity_failure_retains_the_existing_mapping() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(4);
    space.map(VA, PA, UserPermissions::RW).unwrap();
    assert_eq!(space.map_table_run(VA + 0x200000, PA + 4096, UserPermissions::RW, 8), Err(Error::Capacity));
    assert_eq!(space.epoch(), 2);
    assert_eq!(space.translate(VA).unwrap().physical, PA);
    assert!(space.translate(VA + 0x200000).is_none());
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    drop(space);
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_run_foreign_owners_and_bad_lengths_cannot_release_custody() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let owner = runtime::begin();
    for (who, physical, pages) in [(owner + 1, PA, 8), (owner, PA, 0),
            (owner, PA, 513), (owner, PA + 1, 8), (owner, u64::MAX - 4095, 8)] {
        assert_eq!(runtime::run(who, physical, pages, 0, 3), 0);
    }
    runtime::set_cpu(1);
    assert_eq!(runtime::run(owner, PA, 8, 0, 3), 0);
    assert!(!runtime::end(owner));
    assert!(runtime::gate());
    runtime::set_cpu(0);
    assert!(runtime::end(owner));
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_staging_dense_metadata_changes_and_policy_are_rechecked() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    for i in 0..3 { table.set(i, PA + i as u64 * 4096, 3).unwrap(); }
    for change in 0..6 {
        match change {
            1 => { table.set(1, PA + 8 * 4096, 3).unwrap(); }
            2 => table.remove(1),
            3 => { table.set(1, PA + 4096, 3).unwrap(); }
            4 => runtime::phase(PA + 4096, Phase::Transition),
            5 => table.clear(),
            _ => {}
        }
        let (_memory, space) = new_space(8);
        let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
        let result = table.publish(&mut owner, VA);
        let space = owner.current.as_ref().unwrap();
        if change == 4 {
            assert_eq!(result, Err(crate::Errno::Io));
            assert!(space.translate(VA).is_some());
            assert!(space.translate(VA + 4096).is_none());
            assert!(space.translate(VA + 8192).is_none());
        } else {
            result.unwrap();
            assert_eq!(space.translate(VA + 4096).map(|t| t.physical),
                match change { 1 => Some(PA + 8 * 4096), 2 | 5 => None, _ => Some(PA + 4096) });
        }
        drop(owner);
    }
}

#[test]
fn runtime_batch_staging_cross_leaf_dense_range_keeps_the_scalar_path() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    for i in 0..512 { table.set(i, PA + i as u64 * 4096, 3).unwrap(); }
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    table.publish(&mut owner, VA + 4096).unwrap();
    for i in 0..512 {
        assert_eq!(owner.current.as_ref().unwrap().translate(VA + (i + 1) * 4096).unwrap().physical, PA + i * 4096);
    }
    drop(owner);
}

#[test]
fn runtime_batch_staging_cached_shape_tracks_permission_overwrites() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    for protection in [3, 1, 5, 1, 3] {
        let phase = if protection == 5 { Phase::StableSealed } else { Phase::StableWritable };
        for i in 0..3 {
            runtime::phase(PA + i * 4096, phase);
            table.set(i as usize, PA + i * 4096, protection).unwrap();
        }
        // The second publication uses the populated shape cache. Runtime
        // phases and all per-page permissions must still be checked.
        for _ in 0..2 {
            let (_memory, space) = new_space(8);
            let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
            table.publish(&mut owner, VA).unwrap();
            for i in 0..3 {
                let actual = owner.current.as_ref().unwrap().translate(VA + i * 4096).unwrap();
                assert_eq!(actual.permissions.writable, protection & 2 != 0);
                assert_eq!(actual.permissions.executable, protection & 4 != 0);
            }
            drop(owner);
        }
    }
}
