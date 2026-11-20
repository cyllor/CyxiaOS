// These cases execute the production destructor and runtime alias core.
// A shortened prefix, wrong permission, skipped hole or premature bounds
// failure must leave observable counts different from the literal expectations.

#[test]
fn runtime_batch_retire_crosses_leaf_tables_with_mixed_permissions_and_phases() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(16);
    for i in 0..1025 {
        let permissions = if i < 512 { UserPermissions::RX }
            else if i < 768 { UserPermissions::RO } else { UserPermissions::RW };
        if permissions.executable { runtime::phase(PA + i * 4096, Phase::StableSealed); }
        space.map(VA + i * 4096, PA + i * 4096, permissions).unwrap();
    }
    // Retirement must accept an existing alias even after its phase changes.
    for i in 0..1025 { runtime::phase(PA + i * 4096, Phase::Transition); }
    drop(space);
    for i in 0..1025 { assert_eq!(runtime::count(PA + i * 4096), 0, "page {i}"); }
    assert!(!runtime::gate());
}

#[test]
fn runtime_batch_retire_respects_holes_noncontiguous_frames_and_shared_aliases() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(16);
    space.map_pages([
        (VA, PA, UserPermissions::RW),
        (VA + 8192, PA + 4096, UserPermissions::RW),
        (VA + 12288, PA + 24576, UserPermissions::RW),
        (VA + 16384, PA + 28672, UserPermissions::RO),
        (VA + 0x200000, PA, UserPermissions::RO),
        (VA + 0x201000, PA + 36864, UserPermissions::RO),
    ]).unwrap();
    assert_eq!(runtime::count(PA), 2 | 1 << 20);
    drop(space);
    for physical in [PA, PA + 4096, PA + 24576, PA + 28672, PA + 36864] {
        assert_eq!(runtime::count(physical), 0);
    }
}

#[test]
fn runtime_batch_retire_ignores_hardware_accessed_dirty_and_pat_flags() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map_table_run(VA, PA, UserPermissions::RW, 512).unwrap();
    for i in 0..512 {
        let leaf = space.leaf(VA + i * 4096).unwrap();
        let hardware_flags = match i % 4 { 0 => 0, 1 => 1 << 5, 2 => 1 << 6, _ => (1 << 5) | (1 << 6) | (1 << 7) };
        unsafe { leaf.write_volatile(leaf.read_volatile() | hardware_flags) };
    }
    drop(space);
    for i in 0..512 { assert_eq!(runtime::count(PA + i * 4096), 0); }
}

#[test]
fn runtime_batch_retire_counter_failure_preserves_the_exact_successful_prefix() {
    let _lock = runtime::TEST.lock().unwrap();
    for poison in [0, 1, 255, 511, 512, 519] {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        space.map_pages((0..520).map(|i| (VA + i * 4096, PA + i * 4096, UserPermissions::RW))).unwrap();
        runtime::set_count(PA + poison * 4096, 0);
        assert!(catch_unwind(AssertUnwindSafe(|| drop(space))).is_err());
        for i in 0..520 {
            assert_eq!(runtime::count(PA + i * 4096),
                if i <= poison { 0 } else { 1 | 1 << 20 }, "poison {poison}, page {i}");
        }
        assert!(!runtime::gate());
    }
}

#[test]
fn runtime_batch_retire_invalid_later_frame_does_not_preempt_valid_prefix_removal() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map_table_run(VA, PA, UserPermissions::RW, 8).unwrap();
    let leaf = space.leaf(VA + 3 * 4096).unwrap();
    unsafe { leaf.write_volatile(runtime::RAM | P | W | U | NX) };
    assert!(catch_unwind(AssertUnwindSafe(|| drop(space))).is_err());
    for i in 0..8 {
        assert_eq!(runtime::count(PA + i * 4096), if i < 3 { 0 } else { 1 | 1 << 20 });
    }
    assert!(!runtime::gate());
}

#[test]
fn runtime_batch_retire_permission_corruption_stops_before_later_aliases() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map_table_run(VA, PA, UserPermissions::RW, 8).unwrap();
    let leaf = space.leaf(VA + 3 * 4096).unwrap();
    unsafe { leaf.write_volatile((leaf.read_volatile() & !(W | NX)) | P | U) };
    assert!(catch_unwind(AssertUnwindSafe(|| drop(space))).is_err());
    for i in 0..8 {
        assert_eq!(runtime::count(PA + i * 4096), if i < 3 { 0 } else { 1 | 1 << 20 });
    }
    assert!(!runtime::gate());
}
