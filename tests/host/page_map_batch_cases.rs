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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
        let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
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

// These cases exercise the extracted production core. Only the fixture state
// setup below is synthetic; no mapping/count/phase algorithm is reimplemented.
#[test]
fn runtime_batch_zero_new_removals_keep_phase_and_match_checked_count_changes() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let before = 9 | (4 << 20) | (3 << 40);
    for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
        for (old, initial, expected) in [
            (0, before, before),
            (1, before, 8 | (4 << 20) | (3 << 40)),
            (3, before, 8 | (3 << 20) | (3 << 40)),
            (5, before, 8 | (4 << 20) | (2 << 40)),
            // The original core interprets the three old bits independently;
            // old high bits do not introduce a new rejection policy here.
            (7, before, 8 | (3 << 20) | (2 << 40)),
            (8, before, before),
            (11, before, 8 | (3 << 20) | (3 << 40)),
            (13, before, 8 | (4 << 20) | (2 << 40)),
            (u64::MAX, before, 8 | (3 << 20) | (2 << 40)),
            (1, 1, 0),
            (3, 1 | (1 << 20), 0),
            (5, 1 | (1 << 40), 0),
        ] {
            runtime::phase(PA, phase);
            runtime::set_count(PA, initial);
            let owner = runtime::begin();
            assert_eq!(owner, 1);
            assert!(runtime::change(owner, PA, old, 0));
            assert_eq!(runtime::count(PA), expected, "phase {phase:?}, old {old:#x}");
            assert_eq!(runtime::current_phase(PA), phase);
            assert_eq!(runtime::operations(), (0, 0));
            assert!(runtime::gate());
            assert_eq!(runtime::owner(), owner);
            assert!(runtime::end(owner));
        }
    }
}

#[test]
fn runtime_batch_zero_new_underflow_preserves_the_entire_packed_counter() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
        // Fault-injected component deficits isolate the first, second and
        // third checked_sub. Upper bits also expose any premature store.
        for (old, before) in [
            (1, (0x9u64 << 60) | (2 << 20) | (3 << 40)),
            (3, (0x9u64 << 60) | 2 | (3 << 40)),
            (5, (0x9u64 << 60) | 2 | (3 << 20)),
        ] {
            runtime::phase(PA, phase);
            runtime::set_count(PA, before);
            let owner = runtime::begin();
            assert_eq!(owner, 1);
            assert!(!runtime::change(owner, PA, old, 0));
            assert_eq!(runtime::count(PA), before, "phase {phase:?}, old {old:#x}");
            assert_eq!(runtime::current_phase(PA), phase);
            assert_eq!(runtime::operations(), (0, 0));
            assert!(runtime::gate());
            assert_eq!(runtime::owner(), owner);
            assert!(runtime::end(owner));
        }
    }
}

#[test]
fn runtime_batch_zero_new_physical_boundaries_preserve_the_original_core_contract() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    // Physical zero remains valid for this core, independently of any
    // higher-level range policy. The last RAM page has real phase/count storage.
    for physical in [0, runtime::RAM - 4096] {
        let saved_phase = runtime::current_phase(physical);
        runtime::phase(physical, Phase::Transition);
        runtime::set_count(physical, 1 | (1 << 40));
        let owner = runtime::begin();
        assert_eq!(owner, 1);
        assert!(runtime::change(owner, physical, 5, 0));
        assert_eq!(runtime::count(physical), 0);
        assert_eq!(runtime::current_phase(physical), Phase::Transition);
        assert!(runtime::end(owner));
        // reset() models the first 8192 pages; restore the tail explicitly.
        runtime::phase(physical, saved_phase);
    }
    runtime::phase(PA, Phase::Transition);
    let before = 1 | (1 << 20);
    runtime::set_count(PA, before);
    let owner = runtime::begin();
    assert_eq!(owner, 1);
    for physical in [1, 4095, PA + 1, runtime::RAM - 1, runtime::RAM,
                     runtime::RAM + 4096, u64::MAX - 4095, u64::MAX] {
        assert!(!runtime::change(owner, physical, 3, 0), "physical {physical:#x}");
        assert_eq!(runtime::count(PA), before);
        assert_eq!(runtime::count(0), 0);
        assert_eq!(runtime::count(runtime::RAM - 4096), 0);
        assert!(runtime::gate());
        assert_eq!(runtime::owner(), owner);
    }
    assert_eq!(runtime::operations(), (0, 0));
    assert!(runtime::end(owner));
}

#[test]
fn runtime_batch_zero_new_wrong_or_inactive_owner_cannot_mutate_or_release() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    runtime::phase(PA, Phase::Transition);
    let before = 1 | (1 << 20);
    runtime::set_count(PA, before);
    for token in [0, 1, 2, 5, u64::MAX] {
        assert!(!runtime::change(token, PA, 3, 0));
        assert!(!runtime::end(token));
        assert_eq!(runtime::count(PA), before);
        assert!(!runtime::gate());
        assert_eq!(runtime::owner(), 0);
    }
    let owner = runtime::begin();
    assert_eq!(owner, 1);
    for token in [0, 2, 5, u64::MAX] {
        assert!(!runtime::change(token, PA, 3, 0));
        assert!(!runtime::end(token));
        assert_eq!(runtime::count(PA), before);
        assert!(runtime::gate());
        assert_eq!(runtime::owner(), owner);
    }
    for cpu in [1, 3, 4] {
        runtime::set_cpu(cpu);
        assert!(!runtime::change(owner, PA, 3, 0));
        assert!(!runtime::end(owner));
        assert_eq!(runtime::begin(), 0);
        assert_eq!(runtime::count(PA), before);
        assert!(runtime::gate());
        assert_eq!(runtime::owner(), owner);
    }
    runtime::set_cpu(0);
    assert!(runtime::end(owner));
    assert!(!runtime::change(owner, PA, 3, 0));
    assert!(!runtime::end(owner));
    assert_eq!(runtime::count(PA), before);
    assert!(!runtime::gate());
    assert_eq!(runtime::owner(), 0);
    // CPU owner values are not nonces. This tests stale calls with no live
    // lease, and does not assert replay rejection across a later same-CPU lease.
    let successor = runtime::begin();
    assert_eq!(successor, owner);
    assert!(runtime::change(successor, PA, 3, 0));
    assert_eq!(runtime::count(PA), 0);
    assert!(runtime::end(successor));
    assert_eq!(runtime::locks(), (2, 2));
}

#[test]
fn runtime_batch_nonzero_flags_and_each_overflow_keep_the_original_rejection_path() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let before = 9 | (4 << 20) | (3 << 40);
    for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
        runtime::phase(PA, phase);
        runtime::set_count(PA, before);
        let owner = runtime::begin();
        assert_eq!(owner, 1);
        for new in [2, 4, 6, 7, 8, 9, 11, 13, u64::MAX] {
            assert!(!runtime::change(owner, PA, 0, new), "phase {phase:?}, new {new:#x}");
            assert_eq!(runtime::count(PA), before);
            assert_eq!(runtime::current_phase(PA), phase);
        }
        assert!(runtime::end(owner));
    }
    // Synthetic inconsistent counters isolate overflow after each preceding
    // component has succeeded. No partial packed value may be committed.
    for (phase, new, before) in [
        (Phase::StableWritable, 1, 0xfffff | (3 << 20) | (2 << 40)),
        (Phase::StableWritable, 3, 7 | (0xfffff << 20) | (2 << 40)),
        (Phase::StableSealed, 5, 7 | (2 << 20) | (0xfffff << 40)),
    ] {
        runtime::phase(PA, phase);
        runtime::set_count(PA, before);
        let owner = runtime::begin();
        assert_eq!(owner, 1);
        assert!(!runtime::change(owner, PA, 0, new));
        assert_eq!(runtime::count(PA), before);
        assert_eq!(runtime::current_phase(PA), phase);
        assert!(runtime::gate());
        assert_eq!(runtime::owner(), owner);
        assert!(runtime::end(owner));
    }
    assert_eq!(runtime::operations(), (0, 0));
}

#[test]
fn runtime_batch_phase_coverage_matches_get_for_zero_one_and_two_words() {
    use crate::code_permissions::PhaseTable;
    fn check<const WORDS: usize>(table: PhaseTable<WORDS>, cases: &[(usize, bool)]) {
        for &(page, covered) in cases {
            assert_eq!(table.contains_page(page), covered, "words {WORDS}, page {page}");
            assert_eq!(table.get(page).is_some(), covered);
            if covered {
                for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
                    table.set(page, phase).unwrap();
                    assert!(table.contains_page(page));
                    assert_eq!(table.get(page), Some(phase));
                }
            } else {
                assert_eq!(table.set(page, Phase::StableSealed), Err(Error::Address));
                assert_eq!(table.get(page), None);
            }
        }
    }
    check(PhaseTable::<0>::new(), &[
        (0, false), (1, false), (31, false), (32, false),
        (63, false), (64, false), (usize::MAX, false),
    ]);
    check(PhaseTable::<1>::new(), &[
        (0, true), (1, true), (30, true), (31, true),
        (32, false), (33, false), (usize::MAX, false),
    ]);
    check(PhaseTable::<2>::new(), &[
        (0, true), (31, true), (32, true), (63, true),
        (64, false), (65, false), (usize::MAX, false),
    ]);
}

#[test]
fn runtime_batch_single_removal_releases_its_guard_without_clearing_a_batch_owner() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
        runtime::phase(PA, phase);
        runtime::set_count(PA, 1 | (1 << 20));
        let (acquires, releases) = runtime::locks();
        assert!(runtime::single_change(PA, 3, 0));
        assert_eq!(runtime::count(PA), 0);
        assert_eq!(runtime::current_phase(PA), phase);
        assert_eq!(runtime::locks(), (acquires + 1, releases + 1));
        assert!(!runtime::gate());
        assert_eq!(runtime::owner(), 0);
    }
    for (physical, old, new, before) in [
        (PA, 3, 0, 0),
        (PA + 1, 3, 0, 1 | (1 << 20)),
        (runtime::RAM, 3, 0, 1 | (1 << 20)),
        (PA, 3, 8, 1 | (1 << 20)),
    ] {
        runtime::set_count(PA, before);
        let (acquires, releases) = runtime::locks();
        assert!(!runtime::single_change(physical, old, new));
        assert_eq!(runtime::count(PA), before);
        assert_eq!(runtime::locks(), (acquires + 1, releases + 1));
        assert!(!runtime::gate());
        assert_eq!(runtime::owner(), 0);
    }
    let before = 1 | (1 << 20);
    runtime::set_count(PA, before);
    let owner = runtime::begin();
    assert_eq!(owner, 1);
    let locks = runtime::locks();
    assert!(!runtime::single_change(PA, 3, 0));
    assert_eq!(runtime::locks(), locks);
    assert_eq!(runtime::count(PA), before);
    assert!(runtime::gate());
    assert_eq!(runtime::owner(), owner);
    assert!(runtime::change(owner, PA, 3, 0));
    assert_eq!(runtime::count(PA), 0);
    assert!(runtime::end(owner));
    assert_eq!(runtime::operations(), (0, 0));
}


// Dense, external observations of the real PageTable publisher are the oracle.
// No test reconstructs its private bitmaps, packed fields or range algorithm.
fn assert_staging_snapshot(
    table: &crate::staging::PageTable,
    expected: &[(usize, u64, u8)],
    ranges: &[(u64, usize)],
) {
    runtime::clear_observations();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    table.publish(&mut owner, VA).unwrap();
    let space = owner.current.as_ref().unwrap();
    assert_eq!(space.epoch(), expected.len() as u64 + 1);
    assert_eq!(runtime::ranges(), ranges);
    for index in 0..512 {
        let actual = space.translate(VA + index as u64 * 4096 + 17);
        if let Some(&(_, physical, protection)) = expected.iter().find(|&&(i, _, _)| i == index) {
            let actual = actual.unwrap();
            assert_eq!(actual.physical, physical + 17, "staged index {index}");
            assert_eq!(actual.permissions.writable, protection & 2 != 0);
            assert_eq!(actual.permissions.executable, protection & 4 != 0);
            let aliases = expected.iter().filter(|&&(_, pa, _)| pa == physical)
                .fold(0, |counts, &(_, _, prot)| {
                    counts + 1 + (u64::from(prot & 2 != 0) << 20)
                        + (u64::from(prot & 4 != 0) << 40)
                });
            assert_eq!(runtime::count(physical), aliases);
        } else {
            assert!(actual.is_none(), "unexpected mapping at staged index {index}");
        }
    }
    drop(owner); // Actual complete PTE walk removes every published alias.
    for &(_, physical, _) in expected { assert_eq!(runtime::count(physical), 0); }
}

#[test]
fn runtime_batch_staging_layout_and_sparse_word_boundaries_keep_all_translations() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    assert_eq!(core::mem::size_of::<crate::staging::PageTable>(), 8192);
    assert_eq!(core::mem::align_of::<crate::staging::PageTable>(), 4096);
    let mut table = crate::staging::PageTable::empty();
    // Reverse insertion must not change publish order or join across holes.
    let expected = [
        (0, 0, 1), (63, PA, 5), (64, PA + 4096, 5),
        (127, PA + 8192, 3), (128, PA + 12288, 1), (511, PA + 16384, 5),
    ];
    for &(index, physical, protection) in expected.iter().rev() {
        table.set(index, physical, protection).unwrap();
    }
    assert_staging_snapshot(&table, &expected, &[(PA, 8192), (PA + 16384, 4096)]);
}

#[test]
fn runtime_batch_staging_failed_mutations_leave_every_previous_mapping_unchanged() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    let expected = [(0, PA, 3), (63, PA + 4096, 5),
                    (64, PA + 8192, 5), (511, PA + 12288, 1)];
    for &(index, physical, protection) in &expected {
        table.set(index, physical, protection).unwrap();
    }
    for (index, physical, protection) in [
        (512, PA, 3), (usize::MAX, PA, 0),
        (0, PA + 1, 0), (63, PA + 4097, 5),
        (63, PA, 6), (64, PA, 7), (511, PA, 8), (511, PA, 255),
    ] {
        assert_eq!(table.set(index, physical, protection), Err(crate::Errno::Inval));
    }
    for index in [512, usize::MAX] {
        assert!(catch_unwind(AssertUnwindSafe(|| table.remove(index))).is_err());
    }
    assert_staging_snapshot(&table, &expected, &[(PA + 4096, 8192)]);
}

#[test]
fn runtime_batch_staging_repeated_permission_changes_use_real_seals_and_recovery() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    table.set(63, PA, 3).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 3)], &[]);
    table.set(63, PA, 5).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 5)], &[(PA, 4096)]);
    assert_eq!(runtime::current_phase(PA), Phase::StableSealed);
    table.set(63, PA, 1).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 1)], &[]);
    // Production requires actual retirement and writable recovery before reuse;
    // metadata itself never unseals a physical frame.
    crate::production_process_arch::make_writable(crate::HIGH + PA, 4096).unwrap();
    assert!(runtime::zero_eligible(PA, 4096));
    table.set(63, PA, 3).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 3)], &[]);
    table.set(64, PA + 4096, 5).unwrap();
    table.set(64, PA + 8192, 3).unwrap(); // Clear stale RX bit on physical overwrite.
    table.set(511, PA + 12288, 5).unwrap();
    table.set(511, PA + 16384, 0).unwrap(); // Zero protection removes old RX.
    table.remove(63);
    assert_staging_snapshot(&table, &[(64, PA + 8192, 3)], &[]);
    assert_eq!(runtime::current_phase(PA + 4096), Phase::StableWritable);
    assert_eq!(runtime::current_phase(PA + 12288), Phase::StableWritable);
}

#[test]
fn runtime_batch_staging_clear_removes_all_bits_and_reuse_keeps_only_new_pages() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    for index in 0..512 {
        table.set(index, PA + index as u64 * 4096, if index % 2 == 0 { 5 } else { 3 }).unwrap();
    }
    table.clear();
    // An empty table must remain a no-op even without an owner and with a held
    // alias gate. This catches stale present or executable entries after clear.
    let mut owner = crate::staging::ProcessSpace::test_owner(None);
    runtime::force_gate(true);
    table.publish(&mut owner, VA).unwrap();
    assert_eq!(runtime::seal_calls(), 0);
    assert_eq!(runtime::locks(), (0, 0));
    runtime::force_gate(false);
    table.set(0, PA, 3).unwrap();
    table.set(64, PA + 4096, 5).unwrap();
    table.set(511, PA + 8192, 1).unwrap();
    assert_staging_snapshot(&table, &[(0, PA, 3), (64, PA + 4096, 5), (511, PA + 8192, 1)],
                            &[(PA + 4096, 4096)]);
}

#[test]
fn runtime_batch_staging_sparse_failure_retains_exact_ascending_successful_prefix() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    for (index, physical, protection) in [
        (511, PA + 12288, 3), (200, runtime::RAM, 1),
        (64, PA + 8192, 3), (63, PA + 4096, 1), (0, PA, 3),
    ] { table.set(index, physical, protection).unwrap(); }
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    assert_eq!(table.publish(&mut owner, VA), Err(crate::Errno::Io));
    let space = owner.current.as_ref().unwrap();
    assert_eq!(space.epoch(), 4);
    for (index, physical) in [(0, PA), (63, PA + 4096), (64, PA + 8192)] {
        assert_eq!(space.translate(VA + index * 4096).unwrap().physical, physical);
    }
    assert!(space.translate(VA + 200 * 4096).is_none());
    assert!(space.translate(VA + 511 * 4096).is_none());
    assert_eq!(runtime::count(PA + 12288), 0);
    assert_eq!(runtime::seal_calls(), 0);
    drop(owner);
    for physical in [PA, PA + 4096, PA + 8192] { assert_eq!(runtime::count(physical), 0); }
}

#[test]
fn runtime_batch_staging_packed_high_physical_bits_are_never_truncated_into_ram() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    table.set(63, PA, 3).unwrap();
    table.set(64, u64::MAX - 4095, 1).unwrap(); // Original staging contract accepts aligned metadata.
    table.set(65, 0, 1).unwrap();
    let (_memory, space) = new_space(8);
    let mut owner = crate::staging::ProcessSpace::test_owner(Some(space));
    assert_eq!(table.publish(&mut owner, VA), Err(crate::Errno::Io));
    let space = owner.current.as_ref().unwrap();
    assert_eq!(space.epoch(), 2);
    assert_eq!(space.translate(VA + 63 * 4096).unwrap().physical, PA);
    assert!(space.translate(VA + 64 * 4096).is_none());
    assert!(space.translate(VA + 65 * 4096).is_none());
    drop(owner);
    assert_eq!(runtime::count(PA), 0);
    table.set(64, PA + 4096, 1).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 3), (64, PA + 4096, 1), (65, 0, 1)], &[]);
}

#[test]
fn runtime_batch_staging_nonread_protection_bits_preserve_original_x86_semantics() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let mut table = crate::staging::PageTable::empty();
    table.set(63, PA, 2).unwrap(); // Original x86 staging does not require bit0.
    table.set(64, PA + 4096, 4).unwrap();
    assert_staging_snapshot(&table, &[(63, PA, 2), (64, PA + 4096, 4)], &[(PA + 4096, 4096)]);
    table.set(63, PA + 8192, 0).unwrap();
    table.remove(64);
    assert_staging_snapshot(&table, &[], &[]);
}
