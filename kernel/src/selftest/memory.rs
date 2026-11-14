use cyxia_contracts::*;
use cyxia_kernel_core::frames::*;
static mut META: [FrameMeta; 65536] = [FrameMeta::EMPTY; 65536];
#[cfg(target_arch = "aarch64")]
pub fn pages(info: &BootInfo, offset: u64, kernel_end: u64) -> bool {
    let reserved = [MemoryRegion {
        start: PhysAddr(cyxia_platform_virt::RAM_BASE),
        len: kernel_end - cyxia_platform_virt::RAM_BASE,
        kind: RegionKind::Reserved,
    }];
    let pool = FramePool::from_regions(info, &reserved, unsafe {
        &mut *core::ptr::addr_of_mut!(META)
    })
    .unwrap();
    check_pages(pool, offset)
}

#[cfg(target_arch = "x86_64")]
pub fn pages_from_memory(ram: &[MemoryRegion], reserved: &[MemoryRegion], offset: u64) -> bool {
    let pool = FramePool::from_memory(ram, reserved, unsafe {
        &mut *core::ptr::addr_of_mut!(META)
    })
    .unwrap();
    check_pages(pool, offset)
}

// Both architectures exercise the same ownership/clearing/generation logic.
// Each boot adapter supplies a reserved RAM map and its direct-map offset.
fn check_pages(mut pool: FramePool<'_>, offset: u64) -> bool {
    struct Zero(u64);
    impl PageZeroer for Zero {
        fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
            unsafe { core::ptr::write_bytes((page.0 + self.0) as *mut u8, 0, 4096) }
            Ok(())
        }
    }
    let mut zero = Zero(offset);
    let owner = TaskId::new(1).unwrap();
    assert!(pool.alloc_clean(owner).is_err());
    pool.clean_one(&mut zero).unwrap();
    let h = pool.alloc_clean(owner).unwrap();
    let p = (h.address().0 + offset) as *mut u8;
    unsafe { core::ptr::write_bytes(p, 0xa5, 4096) };
    pool.begin_revoke(h, owner).unwrap();
    // This private boot-test page was never published to a task or DMA. Only
    // the allocator's supervisor direct map remains; this checks ownership and
    // clearing, while architecture tests independently check hardware access.
    pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
        .unwrap();
    assert!(pool.alloc_clean(owner).is_err());
    pool.clean_one(&mut zero).unwrap();
    let h2 = pool.alloc_clean(owner).unwrap();
    h2 != h
        && h2.address() == h.address()
        && (0..4096).all(|i| unsafe { p.add(i).read_volatile() == 0 })
}
