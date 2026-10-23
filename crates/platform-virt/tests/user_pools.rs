use cyxia_contracts::{BootInfo, MemoryRegion, PhysAddr, PlatformError, RegionKind};
use cyxia_platform_virt::{KERNEL_POOL_END, RAM_BASE, reserve_user_pool};

fn boot() -> BootInfo {
    let mut info =
        cyxia_platform_virt::fdt::parse_fdt(include_bytes!("../../../tests/fixtures/fdt/virt.dtb"))
            .unwrap();
    info.reserved[info.reserved_count] = MemoryRegion {
        start: PhysAddr(RAM_BASE),
        len: KERNEL_POOL_END - RAM_BASE,
        kind: RegionKind::Reserved,
    };
    info.reserved_count += 1;
    info
}

#[test]
fn eight_desktop_slots_fit_exactly_without_overlapping_boot_or_each_other() {
    let mut info = boot();
    let prior = info;
    let heap = reserve_user_pool(&mut info, 8 * 8 * 1024 * 1024).unwrap();
    let images = reserve_user_pool(&mut info, 8 * 16 * 1024 * 1024).unwrap();
    assert_eq!(heap.start.0, 0x44000000);
    assert_eq!(heap.end().unwrap(), 0x48000000);
    assert_eq!(images.start.0, 0x48000000);
    assert_eq!(images.end().unwrap(), 0x50000000);
    assert!(!heap.overlaps(images));
    assert!(
        prior.reserved[..prior.reserved_count]
            .iter()
            .all(|r| !r.overlaps(heap) && !r.overlaps(images))
    );
    assert_eq!(info.reserved_count, prior.reserved_count + 2);
    let full = info;
    assert_eq!(
        reserve_user_pool(&mut info, 4096),
        Err(PlatformError::Again)
    );
    assert_eq!(info, full);
}

#[test]
fn firmware_reservation_or_smaller_ram_cannot_be_overcommitted() {
    for last_page_reserved in [true, false] {
        let mut info = boot();
        if last_page_reserved {
            info.reserved[info.reserved_count] = MemoryRegion {
                start: PhysAddr(0x50000000 - 4096),
                len: 4096,
                kind: RegionKind::Reserved,
            };
            info.reserved_count += 1;
        } else {
            info.ram[0].len -= 4096;
        }
        reserve_user_pool(&mut info, 64 * 1024 * 1024).unwrap();
        let prior = info;
        assert_eq!(
            reserve_user_pool(&mut info, 128 * 1024 * 1024),
            Err(PlatformError::Again)
        );
        assert_eq!(info, prior);
    }
}

#[cfg(feature = "large-memory")]
#[test]
fn desktop_512m_reserves_real_larger_heaps_and_images_without_aliasing() {
    let mut info = boot();
    info.ram[0].len = 512 * 1024 * 1024;
    let heap = reserve_user_pool(&mut info, 128 * 1024 * 1024).unwrap();
    let images = reserve_user_pool(&mut info, 128 * 1024 * 1024).unwrap();
    assert_eq!(heap.start.0, KERNEL_POOL_END);
    assert_eq!(heap.end().unwrap(), images.start.0);
    assert!(images.end().unwrap() <= cyxia_platform_virt::USER_RAM_END);
    assert_eq!(images.end().unwrap(), 0x54000000);
    assert!(!heap.overlaps(images));
}

#[test]
fn invalid_or_unrecordable_pool_request_does_not_mutate_boot_info() {
    for len in [0, 4097, u64::MAX - 4095] {
        let mut info = boot();
        let prior = info;
        assert!(reserve_user_pool(&mut info, len).is_err());
        assert_eq!(info, prior);
    }
    let mut info = boot();
    info.reserved_count = info.reserved.len();
    let prior = info;
    assert_eq!(
        reserve_user_pool(&mut info, 4096),
        Err(PlatformError::Again)
    );
    assert_eq!(info, prior);
}
