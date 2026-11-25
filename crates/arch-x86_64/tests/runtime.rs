use cyxia_arch_x86_64::{
    space::*,
    user::{Context, UserAbi},
};

// Catch confusing the native service ABI with the Linux x86_64 register ABI.
#[test]
fn native_and_linux_context_results_target_their_own_argument_banks() {
    let mut native = Context::empty();
    native
        .initialize(0x10000, 0x40000, UserAbi::CyxiaNative)
        .unwrap();
    native.set_argument(0, 41).unwrap();
    native.set_result(73);
    assert_eq!(native.argument(0), Some(73));
    assert_eq!(native.pc(), 0x10000);
    assert_eq!(native.sp(), 0x40000);
    let mut linux = Context::empty();
    linux
        .initialize(0x1000000, 0x3040000, UserAbi::Linux64)
        .unwrap();
    linux.set_argument(0, 41).unwrap();
    linux.set_result(73);
    assert_eq!(linux.argument(0), Some(41));
    assert_eq!(linux.result(), 73);
    assert!(linux.set_tls(0xffff800000001000).is_err());
    let mut os = Context::empty();
    os.initialize(0x100000, 0x109000, UserAbi::NativeOs)
        .unwrap();
    os.set_argument(5, 91).unwrap();
    os.set_argument(0, 41).unwrap();
    os.set_result(73);
    assert_eq!(os.result(), 73);
    assert_eq!(os.argument(0), Some(41));
    assert_eq!(os.argument(5), Some(91));
}

#[repr(C, align(4096))]
struct Tables([u8; 8 * 4096]);
// Catch shared lower-half entries and missing fourth-level allocation.
#[test]
fn private_roots_map_disjoint_frames_and_enforce_permissions() {
    let mut a = Box::new(Tables([0; 8 * 4096]));
    let mut b = Box::new(Tables([0; 8 * 4096]));
    let kernel = KernelMappings::new([0; 256], 0x40000000).unwrap();
    let mut a = unsafe {
        AddressSpace::new(
            TableArena::from_raw(a.0.as_mut_ptr(), 0x200000, 8).unwrap(),
            &kernel,
            SpaceId {
                id: 1,
                generation: 1,
            },
        )
    }
    .unwrap();
    let mut b = unsafe {
        AddressSpace::new(
            TableArena::from_raw(b.0.as_mut_ptr(), 0x300000, 8).unwrap(),
            &kernel,
            SpaceId {
                id: 2,
                generation: 1,
            },
        )
    }
    .unwrap();
    a.map(0x1000000, 0x400000, UserPermissions::RX).unwrap();
    b.map(0x1000000, 0x500000, UserPermissions::RW).unwrap();
    assert_eq!(a.translate(0x1000011).unwrap().physical, 0x400011);
    assert_eq!(b.translate(0x1000011).unwrap().physical, 0x500011);
    assert_eq!(
        a.translate(0x1000011).unwrap().permissions,
        UserPermissions::RX
    );
    assert_eq!(
        b.translate(0x1000011).unwrap().permissions,
        UserPermissions::RW
    );
    assert!(
        a.map(0xffff800000000000, 0x600000, UserPermissions::RW)
            .is_err()
    );
    assert!(a.map(0x1000000, 0x600000, UserPermissions::RW).is_err());
    let retired = a.unmap(0x1000000).unwrap();
    assert_eq!(retired.physical, 0x400000);
    assert!(a.translate(0x1000000).is_none());
    assert_eq!(b.translate(0x1000000).unwrap().physical, 0x500000);
}

/// Revocation walks the table once. An absent page must stay a no-op exactly as
/// the translate-then-unmap pair behaved, and a present page must retire while
/// leaving neighbouring translations intact.
#[test]
fn unmap_present_matches_translate_then_unmap() {
    let mut tables = Box::new(Tables([0; 8 * 4096]));
    let kernel = KernelMappings::new([0; 256], 0x40000000).unwrap();
    let mut space = unsafe {
        AddressSpace::new(
            TableArena::from_raw(tables.0.as_mut_ptr(), 0x200000, 8).unwrap(),
            &kernel,
            SpaceId {
                id: 1,
                generation: 1,
            },
        )
    }
    .unwrap();
    assert!(!space.unmap_present(0x1000000).unwrap());
    assert!(space.translate(0x1000000).is_none());
    // translate() reports None above the user half, so revocation skips it.
    assert!(!space.unmap_present(0xffff800000000000).unwrap());
    space.map(0x1000000, 0x400000, UserPermissions::RX).unwrap();
    space.map(0x1001000, 0x401000, UserPermissions::RW).unwrap();
    assert!(space.unmap_present(0x1000000).unwrap());
    assert!(space.translate(0x1000000).is_none());
    assert_eq!(space.translate(0x1001000).unwrap().physical, 0x401000);
    // Revoking twice is a no-op the second time, not an error.
    assert!(!space.unmap_present(0x1000000).unwrap());
    assert!(space.unmap_present(0x1001000).unwrap());
    assert!(space.translate(0x1001000).is_none());
}

#[test]
fn full_os_v3_complete_windows_fit_private_tables_and_preserve_stack_guard() {
    full_os_windows_fit_private_tables(
        cyxia_contracts::user_layout::ImageProfile::FullOsV3,
        64 * 1024 * 1024,
    );
}

#[test]
fn full_os_v2_complete_windows_fit_private_tables_and_preserve_stack_guard() {
    full_os_windows_fit_private_tables(
        cyxia_contracts::user_layout::ImageProfile::FullOsV2,
        32 * 1024 * 1024,
    );
}

fn full_os_windows_fit_private_tables(
    profile: cyxia_contracts::user_layout::ImageProfile,
    heap_bytes: u64,
) {
    #[derive(Clone)]
    #[repr(C, align(4096))]
    struct TableFrame([u8; 4096]);

    // Allocate directly on the host heap rather than putting a 512 KiB arena
    // through the test thread's stack. These frames stay pinned until space drops.
    let mut tables = vec![TableFrame([0; 4096]); 128];
    let kernel = KernelMappings::new([0; 256], 1 << 30).unwrap();
    let mut space = unsafe {
        AddressSpace::new(
            TableArena::from_raw(tables.as_mut_ptr().cast(), 0x200000, 128).unwrap(),
            &kernel,
            SpaceId {
                id: 1,
                generation: 1,
            },
        )
    }
    .unwrap();
    let layout = profile.layout();
    let stack_end = layout.stack_base + layout.stack_pages as u64 * PAGE_BYTES;
    let heap_end = layout.heap_base + layout.heap_pages as u64 * PAGE_BYTES;
    assert_eq!(heap_end - layout.heap_base, heap_bytes);
    let windows = [
        (layout.image_base, layout.image_end, UserPermissions::RX),
        // The existing shared-memory ABI window is independent of image profiles.
        (0x0600_0000, 0x0700_0000, UserPermissions::RW),
        (layout.stack_base, stack_end, UserPermissions::RW),
        (layout.heap_base, heap_end, UserPermissions::RW),
    ];
    let backing_start = 0x1000_0000;
    let mut physical = backing_start;
    for (start, end, permissions) in windows {
        for address in (start..end).step_by(PAGE_BYTES as usize) {
            // Every user page has distinct backing below 1 GiB, disjoint from
            // the table arena. No allocation beyond its 128 frames is possible.
            space.map(address, physical, permissions).unwrap();
            physical += PAGE_BYTES;
        }
    }
    assert!(physical <= kernel.ram_bytes());
    physical = backing_start;
    for (start, end, permissions) in windows {
        for address in (start..end).step_by(PAGE_BYTES as usize) {
            for offset in [0, PAGE_BYTES - 1] {
                let mapping = space.translate(address + offset).unwrap();
                assert_eq!(mapping.physical, physical + offset);
                assert_eq!(mapping.permissions, permissions);
            }
            physical += PAGE_BYTES;
        }
    }
    assert!(space.translate(layout.stack_base - PAGE_BYTES).is_none());
    assert!(space.translate(layout.stack_base - 1).is_none());
    assert!(space.translate(stack_end).is_none());
    assert!(space.translate(layout.heap_base - 1).is_none());
    assert!(space.translate(heap_end).is_none());
}

// A user frame's MXCSR_MASK is not authority for the next signal restore.
// Without preserving the original hardware mask, the second restore admits
// bit31 and the next kernel FXRSTOR raises #GP instead of isolating the process.
#[test]
fn consecutive_signal_restores_cannot_expand_the_trusted_mxcsr_mask() {
    let mut context = Context::empty();
    context
        .initialize(0x100000, 0x109000, UserAbi::Linux64)
        .unwrap();
    let mut first = context.signal_state();
    first.fxsave[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    context.restore_signal_state(first).unwrap();
    let before = context.signal_state();
    let mut second = before.clone();
    second.pc = 0x101000;
    second.fxsave[24..28].copy_from_slice(&0x8000_1f80u32.to_le_bytes());
    assert!(context.restore_signal_state(second).is_err());
    let after = context.signal_state();
    assert_eq!(after.pc, before.pc);
    assert_eq!(after.fxsave, before.fxsave);
}

#[test]
fn cloned_threads_keep_fp_values_and_cannot_inherit_a_forged_mxcsr_mask() {
    let mut parent = Context::empty();
    parent
        .initialize(0x100000, 0x109000, UserAbi::Linux64)
        .unwrap();
    let mut state = parent.signal_state();
    state.fxsave[160..176].copy_from_slice(&[0xa5; 16]); // real XMM0 slot.
    state.fxsave[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
    parent.restore_signal_state(state).unwrap();
    let mut child = parent.clone_for_thread(0x209000, 0x200000).unwrap();
    assert_eq!(&child.signal_state().fxsave[160..176], &[0xa5; 16]);
    assert_eq!(child.tls(), 0x200000);
    assert_eq!(child.sp(), 0x209000);
    assert_eq!(child.result(), 0);
    let mut bad = child.signal_state();
    bad.fxsave[24..28].copy_from_slice(&0x8000_1f80u32.to_le_bytes());
    assert!(child.restore_signal_state(bad).is_err());
    assert_eq!(&parent.signal_state().fxsave[160..176], &[0xa5; 16]);
}
