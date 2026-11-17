use super::*;
use crate::{code_permissions::Phase, runtime_fixture as runtime};
use std::{panic::{AssertUnwindSafe, catch_unwind}, sync::atomic::Ordering};

const VA: u64 = 0x01000000;
const PA: u64 = 0x00400000;
#[repr(C, align(4096))]
struct Tables([u8; 32 * 4096]);
fn new_space(pages: usize) -> (Box<Tables>, AddressSpace<'static>) {
    let mut memory = Box::new(Tables([0; 32 * 4096]));
    let kernel = KernelMappings::new([0; 256], runtime::RAM).unwrap();
    // Each test retains the Box until after AddressSpace has been dropped.
    let arena = unsafe { TableArena::from_raw(memory.0.as_mut_ptr(), 0x00200000, pages) }.unwrap();
    let space = unsafe { AddressSpace::new(arena, &kernel, SpaceId { id: 1, generation: 1 }) }.unwrap();
    (memory, space)
}

#[test]
fn runtime_batch_maps_same_region_crosses_and_returns_without_losing_permissions() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    runtime::phase(PA + 4096, Phase::StableSealed);
    let pages = [
        (VA, PA, UserPermissions::RO),
        (VA + 4096, PA + 4096, UserPermissions::RX),
        (VA + 0x200000, PA + 8192, UserPermissions::RW),
        (VA + 8192, PA + 12288, UserPermissions::RW),
    ];
    space.map_pages(pages).unwrap();
    assert_eq!(runtime::locks(), (1, 1));
    assert_eq!(space.epoch(), 5);
    for (va, pa, permissions) in pages {
        let actual = space.translate(va + 17).unwrap();
        assert_eq!(actual.physical, pa + 17);
        assert_eq!(actual.permissions, permissions);
        assert_eq!(runtime::count(pa), 1 | (u64::from(permissions.writable) << 20) | (u64::from(permissions.executable) << 40));
    }
    assert_eq!(space.arena.used, 5);
    drop(space);
    assert_eq!(runtime::locks(), (2, 2));
    for (_, pa, _) in pages { assert_eq!(runtime::count(pa), 0); }
}

#[test]
fn runtime_batch_empty_and_gate_failure_do_not_touch_tables_or_epoch() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    runtime::force_gate(true);
    space.map_pages(core::iter::empty()).unwrap();
    assert_eq!(space.map_pages([(VA, PA, UserPermissions::RW)]), Err(Error::Active));
    assert_eq!(space.epoch(), 1);
    assert_eq!(space.arena.used, 1);
    assert_eq!(runtime::locks(), (0, 0));
    assert_eq!(runtime::count(PA), 0);
    runtime::force_gate(false);
    drop(space);
}

#[test]
fn runtime_batch_active_root_is_unchanged() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.enter_cpu(1).unwrap();
    assert_eq!(space.map_pages([(VA, PA, UserPermissions::RW)]), Err(Error::Active));
    assert_eq!(space.epoch(), 1);
    assert_eq!(runtime::locks(), (0, 0));
    space.leave_cpu(1);
    drop(space);
}

#[test]
fn runtime_batch_all_per_page_guards_preserve_only_successful_prefix() {
    let _lock = runtime::TEST.lock().unwrap();
    let bad = [
        ((0, PA + 4096, UserPermissions::RW), Error::Address),
        ((0x800000000000, PA + 4096, UserPermissions::RW), Error::Address),
        ((VA + 4097, PA + 4096, UserPermissions::RW), Error::Address),
        ((VA + 4096, runtime::RAM, UserPermissions::RW), Error::Address),
        ((VA + 4096, PA + 4097, UserPermissions::RW), Error::Address),
        ((VA + 4096, PA + 4096, UserPermissions { writable: true, executable: true }), Error::Permissions),
        ((VA + 4096, PA + 4096, UserPermissions::RX), Error::Permissions),
        ((VA, PA + 4096, UserPermissions::RW), Error::Conflict),
    ];
    for (second, error) in bad {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        assert_eq!(space.map_pages([(VA, PA, UserPermissions::RW), second]), Err(error));
        assert_eq!(space.epoch(), 2);
        assert_eq!(space.translate(VA).unwrap().physical, PA);
        assert!(space.translate(VA + 4096).is_none());
        assert_eq!(runtime::count(PA), 1 | 1 << 20);
        assert_eq!(runtime::count(PA + 4096), 0);
        assert_eq!(runtime::locks(), (1, 1));
        drop(space);
        assert_eq!(runtime::count(PA), 0);
    }
}

#[test]
fn runtime_batch_transition_sealed_rw_and_count_overflow_reject_without_ghost_leaf() {
    let _lock = runtime::TEST.lock().unwrap();
    for (phase, perms, count) in [
        (Phase::Transition, UserPermissions::RO, 0),
        (Phase::Transition, UserPermissions::RW, 0),
        (Phase::StableSealed, UserPermissions::RW, 0),
        (Phase::StableWritable, UserPermissions::RO, 0xfffff),
    ] {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        runtime::phase(PA + 4096, phase);
        runtime::set_count(PA + 4096, count);
        assert_eq!(space.map_pages([(VA, PA, UserPermissions::RW), (VA + 4096, PA + 4096, perms)]), Err(Error::Permissions));
        assert_eq!(space.epoch(), 2);
        assert!(space.translate(VA + 4096).is_none());
        assert_eq!(runtime::count(PA + 4096), count);
        drop(space);
        assert_eq!(runtime::count(PA), 0);
        assert_eq!(runtime::count(PA + 4096), count);
    }
}

#[test]
fn runtime_batch_capacity_error_commits_epoch_for_only_mapped_prefix() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(4);
    assert_eq!(space.map_pages([(VA, PA, UserPermissions::RW), (VA + 0x200000, PA + 4096, UserPermissions::RO)]), Err(Error::Capacity));
    assert_eq!(space.epoch(), 2);
    assert_eq!(space.arena.used, 4);
    assert!(space.translate(VA + 0x200000).is_none());
    assert_eq!(runtime::count(PA + 4096), 0);
    assert_eq!(runtime::locks(), (1, 1));
    drop(space);
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_epoch_wrap_and_adversarial_iterator_unwind_publish_exact_prefix() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.epoch.store(u64::MAX - 1, Ordering::Release);
    space.map_pages((0..3).map(|n| (VA + n * 4096, PA + n * 4096, UserPermissions::RW))).unwrap();
    assert_eq!(space.epoch(), 1);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pages = core::iter::once((VA + 12288, PA + 12288, UserPermissions::RW))
            .chain(core::iter::from_fn(|| panic!("adversarial metadata iterator")));
        let _ = space.map_pages(pages);
    }));
    assert!(result.is_err());
    assert_eq!(space.epoch(), 2);
    assert!(!runtime::gate());
    assert_eq!(runtime::owner(), 0);
    assert_eq!(runtime::locks(), (2, 2));
    drop(space);
    for page in 0..4 { assert_eq!(runtime::count(PA + page * 4096), 0); }
}

#[test]
fn runtime_batch_drop_can_remove_transition_aliases_after_other_existing_maps() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    runtime::phase(PA, Phase::StableSealed);
    space.map(VA, PA, UserPermissions::RX).unwrap();
    space.map_pages([(VA + 4096, PA + 4096, UserPermissions::RW)]).unwrap();
    runtime::phase(PA, Phase::Transition);
    drop(space);
    assert_eq!(runtime::locks(), (3, 3));
    assert_eq!(runtime::count(PA), 0);
    assert_eq!(runtime::count(PA + 4096), 0);
}

#[test]
fn runtime_batch_runtime_owner_cannot_be_forged_or_transferred_to_another_cpu() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let owner = runtime::begin();
    assert_eq!(owner, 1);
    assert_eq!(runtime::begin(), 0);
    assert!(!runtime::change(2, PA, 0, 3));
    assert!(!runtime::end(2));
    runtime::set_cpu(1);
    assert!(!runtime::change(owner, PA, 0, 3));
    assert!(!runtime::end(owner));
    assert!(runtime::gate());
    assert_eq!(runtime::count(PA), 0);
    runtime::set_cpu(0);
    assert!(runtime::change(owner, PA, 0, 3));
    assert!(runtime::change(owner, PA, 3, 0));
    assert!(runtime::end(owner));
    assert!(!runtime::end(owner));
    assert_eq!(runtime::locks(), (1, 1));
}

#[test]
fn runtime_batch_drop_failures_never_report_completed_retirement() {
    let _lock = runtime::TEST.lock().unwrap();
    for kind in 0..4 {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        space.map(VA, PA, UserPermissions::RW).unwrap();
        match kind {
            0 => runtime::force_gate(true),
            1 => runtime::set_count(PA, 0),
            2 => {
                let root = space.arena.table(space.root).unwrap();
                unsafe { root.write_volatile(0x08000000 | P | W | U) };
            }
            3 => {
                let root = space.arena.table(space.root).unwrap();
                unsafe { root.write_volatile(root.read_volatile() | (1 << 7)) };
            }
            _ => unreachable!(),
        }
        let result = catch_unwind(AssertUnwindSafe(|| drop(space)));
        assert!(result.is_err(), "retirement defect {kind} returned normally");
        if kind != 1 { assert_eq!(runtime::count(PA), 1 | 1 << 20); }
        if kind != 0 { assert!(!runtime::gate()); }
        runtime::force_gate(false);
    }
}

#[test]
fn runtime_batch_actual_page_table_publishes_rx_before_gate_and_skips_empty() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    let mut table = crate::staging::PageTable::empty();
    runtime::force_gate(true);
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::locks(), (0, 0));
    runtime::force_gate(false);
    table.set(0, PA, 5).unwrap();
    table.set(1, PA + 4096, 3).unwrap();
    table.set(2, PA + 8192, 5).unwrap();
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::seal_calls(), 2);
    assert_eq!(runtime::locks(), (3, 3)); // Two actual seal guards, then one map batch.
    assert_eq!(owner.current.as_ref().unwrap().epoch(), 4);
    drop(owner);
    for page in 0..3 { assert_eq!(runtime::count(PA + page * 4096), 0); }
}

#[test]
fn runtime_batch_actual_rx_prepass_failure_does_not_publish_that_table() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    let mut table = crate::staging::PageTable::empty();
    table.set(0, PA, 5).unwrap();
    table.set(1, PA + 4096, 5).unwrap();
    table.set(2, PA + 8192, 3).unwrap(); // Genuine non-RX run boundary.
    table.set(3, PA + 12288, 5).unwrap();
    table.set(4, PA + 16384, 5).unwrap();
    runtime::fail_fence_at(2); // First range seals; second full range stays pending.
    assert_eq!(table.publish(&mut owner, VA), Err(crate::Errno::Io));
    assert_eq!(runtime::ranges(), vec![(PA, 8192), (PA + 12288, 8192)]);
    assert_eq!(runtime::locks(), (2, 2));
    assert_eq!(owner.current.as_ref().unwrap().epoch(), 1);
    assert!(owner.current.as_ref().unwrap().translate(VA).is_none());
    for page in 0..5 { assert_eq!(runtime::count(PA + page * 4096), 0); }
    for page in 0..2 { assert_eq!(runtime::current_phase(PA + page * 4096), Phase::StableSealed); }
    assert_eq!(runtime::current_phase(PA + 8192), Phase::StableWritable);
    for page in 3..5 { assert_eq!(runtime::current_phase(PA + page * 4096), Phase::Transition); }
    assert!(!runtime::zero_eligible(PA, 5 * 4096));
    drop(owner);
    runtime::fail_fence_at(u64::MAX);
    crate::production_process_arch::make_writable(crate::HIGH + PA, 5 * 4096).unwrap();
    assert!(runtime::zero_eligible(PA, 5 * 4096));
}

#[test]
fn runtime_batch_rx_actual_compositor_shape_stops_at_every_staging_boundary() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(32);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    // Actual ELF's 4931 RX pages begin at 0x1de4000, index 484 in its first table.
    // These literal expected lengths come from the retained program headers,
    // not from another copy of the candidate's run scanner.
    let runs: [usize; 11] = [28, 512, 512, 512, 512, 512, 512, 512, 512, 512, 295];
    let mut completed = 0u64;
    let mut expected = Vec::new();
    for (table_index, count) in runs.into_iter().enumerate() {
        let mut table = crate::staging::PageTable::empty();
        let first = if table_index == 0 { 484 } else { 0 };
        expected.push((PA + completed * 4096, count * 4096));
        for offset in 0..count {
            table.set(first + offset, PA + (completed + offset as u64) * 4096, 5).unwrap();
        }
        table.publish(&mut owner, 0x01c00000 + table_index as u64 * 0x200000).unwrap();
        completed += count as u64;
    }
    assert_eq!(completed, 4931);
    assert_eq!(runtime::ranges(), expected);
    assert_eq!(runtime::operations(), (4931, 11));
    assert_eq!(owner.current.as_ref().unwrap().epoch(), 4932);
    for page in 0..4931 {
        let translated = owner.current.as_ref().unwrap().translate(0x01de4000 + page * 4096).unwrap();
        assert_eq!(translated.physical, PA + page * 4096);
        assert_eq!(translated.permissions, UserPermissions::RX);
        assert_eq!(runtime::current_phase(PA + page * 4096), Phase::StableSealed);
        assert_eq!(runtime::count(PA + page * 4096), 1 | (1 << 40));
    }
    drop(owner);
    for page in 0..4931 { assert_eq!(runtime::count(PA + page * 4096), 0); }
}

#[test]
fn runtime_batch_rx_holes_non_rx_and_noncontiguous_physical_frames_split_ranges() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    let mut table = crate::staging::PageTable::empty();
    let pages = [(0, 0, 5), (1, 1, 5), (2, 2, 3), (3, 3, 5),
                 (4, 6, 5), (5, 7, 5), (7, 8, 5), (8, 9, 1), (9, 10, 5), (10, 8, 5)];
    for (index, physical_page, protection) in pages {
        table.set(index, PA + physical_page * 4096, protection).unwrap();
    }
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::ranges(), vec![
        (PA, 8192), (PA + 3 * 4096, 4096), (PA + 6 * 4096, 8192),
        (PA + 8 * 4096, 4096), (PA + 10 * 4096, 4096), (PA + 8 * 4096, 4096),
    ]);
    assert!(owner.current.as_ref().unwrap().translate(VA + 6 * 4096).is_none());
    assert_eq!(runtime::count(PA + 8 * 4096), 2 | (2 << 40));
    for (index, physical_page, protection) in pages {
        let actual = owner.current.as_ref().unwrap().translate(VA + index as u64 * 4096).unwrap();
        assert_eq!(actual.physical, PA + physical_page * 4096);
        assert_eq!(actual.permissions.writable, protection & 2 != 0);
        assert_eq!(actual.permissions.executable, protection & 4 != 0);
    }
    drop(owner);
    for (_, physical_page, _) in pages { assert_eq!(runtime::count(PA + physical_page * 4096), 0); }
}

#[test]
fn runtime_batch_rx_whole_range_cache_checks_mixed_stable_and_pending_pages() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    crate::production_process_arch::publish_code(crate::HIGH + PA, 4096).unwrap();
    crate::production_process_arch::publish_code(crate::HIGH + PA + 8192, 4096).unwrap();
    runtime::phase(PA + 4096, Phase::Transition);
    runtime::clear_observations();
    let mut table = crate::staging::PageTable::empty();
    for page in 0..3 { table.set(page, PA + page as u64 * 4096, 5).unwrap(); }
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::ranges(), vec![(PA, 12288)]);
    assert_eq!(runtime::operations(), (3, 1));
    for page in 0..3 {
        assert_eq!(runtime::current_phase(PA + page * 4096), Phase::StableSealed);
        assert_eq!(runtime::writable_views(PA + page * 4096), (false, false, false));
    }
    drop(owner);
    runtime::clear_observations();
    let (_memory2, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::ranges(), vec![(PA, 12288)]);
    assert_eq!(runtime::operations(), (0, 0)); // Entire range was already stable RX.
    assert_eq!(runtime::locks(), (1, 1)); // Only the actual map batch.
    drop(owner);
}

#[test]
fn runtime_batch_rx_partial_hardware_failures_keep_whole_range_pending_until_recovery() {
    let _lock = runtime::TEST.lock().unwrap();
    for fail_pte in [true, false] {
        runtime::reset();
        let (_memory, mut space) = new_space(8);
        space.map(VA + 0x200000, PA + 10 * 4096, UserPermissions::RW).unwrap();
        let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
        let mut table = crate::staging::PageTable::empty();
        for page in 0..3 { table.set(page, PA + page as u64 * 4096, 5).unwrap(); }
        runtime::clear_observations();
        if fail_pte { runtime::fail_pte_at(2); } else { runtime::fail_fence_at(1); }
        assert_eq!(table.publish(&mut owner, VA), Err(crate::Errno::Io));
        assert_eq!(runtime::ranges(), vec![(PA, 12288)]);
        assert_eq!(owner.current.as_ref().unwrap().epoch(), 2); // Only old mapping.
        assert!(owner.current.as_ref().unwrap().translate(VA).is_none());
        for page in 0..3 {
            assert_eq!(runtime::current_phase(PA + page * 4096), Phase::Transition);
            assert_eq!(runtime::count(PA + page * 4096), 0);
        }
        assert_eq!(runtime::count(PA + 10 * 4096), 1 | (1 << 20));
        assert!(!runtime::zero_eligible(PA, 12288));
        if !fail_pte {
            for page in 0..3 {
                assert_eq!(runtime::writable_views(PA + page * 4096), (false, false, true));
            }
        }
        drop(owner); // Existing aliases still pass through real AddressSpace Drop.
        assert_eq!(runtime::count(PA + 10 * 4096), 0);
        runtime::clear_observations();
        runtime::fail_fence_at(1);
        assert_eq!(crate::production_process_arch::make_writable(crate::HIGH + PA, 12288), Err(crate::Errno::Io));
        assert_eq!(runtime::operations(), (0, 1));
        assert!(!runtime::zero_eligible(PA, 12288));
        runtime::clear_observations();
        crate::production_process_arch::make_writable(crate::HIGH + PA, 12288).unwrap();
        assert_eq!(runtime::operations(), (3, 6)); // Both real protocol fences per page.
        assert!(runtime::zero_eligible(PA, 12288));
        // This fixture observes zero eligibility, not a real GrantLedger/free.
        // The separate actual-clear harness verifies fatal-before-zero/release.
    }
}

#[test]
fn runtime_batch_rx_tail_writable_alias_rejects_before_any_range_transition() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = new_space(8);
    space.map(VA + 0x200000, PA + 8192, UserPermissions::RW).unwrap();
    let mut owner = crate::staging::ProcessSpace { current: Some(space), pid: 1 };
    let mut table = crate::staging::PageTable::empty();
    for page in 0..3 { table.set(page, PA + page as u64 * 4096, 5).unwrap(); }
    runtime::clear_observations();
    assert_eq!(table.publish(&mut owner, VA), Err(crate::Errno::Io));
    assert_eq!(runtime::ranges(), vec![(PA, 12288)]);
    assert_eq!(runtime::operations(), (0, 0));
    assert_eq!(owner.current.as_ref().unwrap().epoch(), 2);
    for page in 0..3 { assert_eq!(runtime::current_phase(PA + page * 4096), Phase::StableWritable); }
    assert_eq!(runtime::count(PA + 8192), 1 | (1 << 20));
    assert!(!runtime::zero_eligible(PA, 12288));
    drop(owner);
    assert!(runtime::zero_eligible(PA, 12288));
}
