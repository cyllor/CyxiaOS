use cyxia_arch_x86_64::{
    code_permissions::{Phase, PhaseTable},
    space::{AddressSpace, Error, KernelMappings, RUNTIME_RAM_BYTES, SpaceId, TableArena, UserPermissions},
};

#[repr(C, align(4096))]
struct Tables([u8; 8 * 4096]);

#[test]
fn one_gib_window_covers_its_last_page_and_rejects_the_next() {
    assert_eq!(RUNTIME_RAM_BYTES, 1 << 30);
    let mut tables = Box::new(Tables([0; 8 * 4096]));
    let kernel = KernelMappings::new([0; 256], RUNTIME_RAM_BYTES).unwrap();
    let mut space = unsafe {
        AddressSpace::new(
            TableArena::from_raw(tables.0.as_mut_ptr(), 0x200000, 8).unwrap(),
            &kernel, SpaceId { id: 1, generation: 1 },
        )
    }.unwrap();
    let last = RUNTIME_RAM_BYTES - 4096;
    space.map(0x1000000, last, UserPermissions::RW).unwrap();
    assert_eq!(space.translate(0x1000017).unwrap().physical, last + 0x17);
    assert_eq!(space.map(0x1001000, RUNTIME_RAM_BYTES, UserPermissions::RW), Err(Error::Address));
    let upper = space.map(0x1002000, (1 << 30) + 4096, UserPermissions::RW);
    assert_eq!(upper, Err(Error::Address));
}

#[test]
fn phase_storage_covers_every_page_in_the_selected_profile() {
    const PAGES: usize = (RUNTIME_RAM_BYTES / 4096) as usize;
    let phases = Box::new(PhaseTable::<{ PAGES / 32 }>::new());
    assert!(phases.contains_page(PAGES - 1));
    assert!(!phases.contains_page(PAGES));
    phases.set(PAGES - 1, Phase::StableSealed).unwrap();
    assert_eq!(phases.get(PAGES - 1), Some(Phase::StableSealed));
    assert_eq!(phases.get(0), Some(Phase::StableWritable));
}
