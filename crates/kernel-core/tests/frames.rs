use cyxia_contracts::*;
use cyxia_kernel_core::frames::*;
fn owner() -> TaskId {
    TaskId::new(1).unwrap()
}
fn info() -> BootInfo {
    let mut i = BootInfo::EMPTY;
    i.ram[0] = MemoryRegion {
        start: PhysAddr(0x1000),
        len: 3 * 4096,
        kind: RegionKind::Ram,
    };
    i.ram_count = 1;
    i
}
struct Zero {
    bytes: [u8; 12288],
}
impl PageZeroer for Zero {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
        let offset = (page.0 - 0x1000) as usize;
        self.bytes[offset..offset + 4096].fill(0);
        Ok(())
    }
}
#[test]
fn dirty_pages_not_reissued_and_reserved_never_allocated() {
    let mut meta = [FrameMeta::EMPTY; 3];
    let reserved = [MemoryRegion {
        start: PhysAddr(0x1000),
        len: 8192,
        kind: RegionKind::Reserved,
    }];
    let mut pool = FramePool::from_regions(&info(), &reserved, &mut meta).unwrap();
    let mut z = Zero {
        bytes: [0xa5; 12288],
    };
    assert_eq!(pool.alloc_clean(owner()), Err(FrameError::Again));
    pool.clean_one(&mut z).unwrap();
    let h = pool.alloc_clean(owner()).unwrap();
    assert_eq!(h.address().0, 0x3000);
    assert!(z.bytes[8192..].iter().all(|x| *x == 0));
    z.bytes[8192..].fill(0x7f);
    pool.begin_revoke(h, owner()).unwrap();
    assert!(pool.alloc_clean(owner()).is_err());
    pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
        .unwrap();
    assert_eq!(pool.alloc_clean(owner()), Err(FrameError::Again));
    pool.clean_one(&mut z).unwrap();
    let next = pool.alloc_clean(owner()).unwrap();
    assert_ne!(next, h);
    assert!(z.bytes[8192..].iter().all(|x| *x == 0));
    assert!(pool.begin_revoke(h, owner()).is_err());
}
#[test]
fn wrong_owner_and_duplicate_revoke_leave_state_unchanged() {
    let mut m = [FrameMeta::EMPTY; 3];
    let mut p = FramePool::from_regions(&info(), &[], &mut m).unwrap();
    let mut z = Zero { bytes: [1; 12288] };
    p.clean_one(&mut z).unwrap();
    let h = p.alloc_clean(owner()).unwrap();
    assert!(p.begin_revoke(h, TaskId::new(2).unwrap()).is_err());
    p.begin_revoke(h, owner()).unwrap();
    assert!(p.begin_revoke(h, owner()).is_err());
}
#[test]
fn failed_zero_does_not_publish_page() {
    struct Bad;
    impl PageZeroer for Bad {
        fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
            Err(FrameError::ZeroFailed)
        }
    }
    let mut m = [FrameMeta::EMPTY; 3];
    let mut p = FramePool::from_regions(&info(), &[], &mut m).unwrap();
    assert!(p.clean_one(&mut Bad).is_err());
    assert_eq!(p.alloc_clean(owner()), Err(FrameError::Again));
}

#[test]
fn firmware_independent_map_preserves_reservation_and_revoke_contract() {
    let info = info();
    let reserved = [MemoryRegion {
        start: PhysAddr(0x1000),
        len: 4096,
        kind: RegionKind::Reserved,
    }];
    let mut meta = [FrameMeta::EMPTY; 3];
    let mut p = FramePool::from_memory(&info.ram[..1], &reserved, &mut meta).unwrap();
    let mut z = Zero {
        bytes: [0xa5; 12288],
    };
    p.clean_one(&mut z).unwrap();
    let first = p.alloc_clean(owner()).unwrap();
    assert_eq!(first.address(), PhysAddr(0x2000));
    p.begin_revoke(first, owner()).unwrap();
    p.finish_revoke(first, unsafe { RevokeComplete::after_unmap(first) })
        .unwrap();
    p.clean_one(&mut z).unwrap();
    let second = p.alloc_clean(owner()).unwrap();
    assert_eq!(second.address(), first.address());
    assert_ne!(first, second);
    assert!(p.begin_revoke(first, owner()).is_err());
    assert!(z.bytes[4096..8192].iter().all(|&x| x == 0));
}

#[test]
fn firmware_independent_map_rejects_device_memory_and_overlap() {
    let mut regions = [info().ram[0]; 2];
    let mut meta = [FrameMeta::EMPTY; 6];
    assert!(FramePool::from_memory(&regions, &[], &mut meta).is_err());
    regions[0].kind = RegionKind::Reserved;
    assert!(FramePool::from_memory(&regions[..1], &[], &mut meta).is_err());
}

struct TrackedZero {
    base: u64,
    contents: Vec<u8>,
    calls: usize,
    fail: bool,
}

impl PageZeroer for TrackedZero {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
        self.calls += 1;
        if self.fail {
            return Err(FrameError::ZeroFailed);
        }
        let offset = page.0.checked_sub(self.base).ok_or(FrameError::Invalid)?;
        if offset % 4096 != 0 {
            return Err(FrameError::Invalid);
        }
        *self.contents.get_mut(offset as usize / 4096).ok_or(FrameError::Invalid)? = 0;
        Ok(())
    }
}

fn region(base: u64, pages: usize) -> MemoryRegion {
    MemoryRegion {
        start: PhysAddr(base),
        len: pages as u64 * 4096,
        kind: RegionKind::Ram,
    }
}

#[test]
fn complete_256_mib_shared_pool_preserves_owners_and_reuses_every_frame() {
    const PAGES: usize = 65_536;
    const BASE: u64 = 0x1000_0000;
    let mut metadata = vec![FrameMeta::EMPTY; PAGES];
    let mut pool = FramePool::from_memory(&[region(BASE, PAGES)], &[], &mut metadata).unwrap();
    let mut zero = TrackedZero {
        base: BASE,
        contents: vec![0xa5; PAGES],
        calls: 0,
        fail: false,
    };
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: PAGES, free: PAGES, used: 0 });
    let mut frames = Vec::with_capacity(PAGES);
    let mut seen = vec![false; PAGES];
    for index in 0..PAGES {
        let actor = TaskId::new(1 + (index % 8) as u32).unwrap();
        let frame = pool.alloc_zeroed(actor, &mut zero).unwrap();
        assert_eq!(frame.index(), index);
        assert_eq!(frame.address(), PhysAddr(BASE + index as u64 * 4096));
        assert!(!seen[frame.index()], "live owners must never alias");
        seen[frame.index()] = true;
        assert_eq!(zero.contents[frame.index()], 0);
        zero.contents[frame.index()] = actor.get() as u8;
        frames.push((actor, frame));
    }
    assert!(seen.into_iter().all(|seen| seen));
    assert_eq!(frames.last().unwrap().1.index(), 65_535);
    assert_eq!(zero.calls, PAGES);
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: PAGES, free: 0, used: PAGES });
    assert_eq!(pool.alloc_zeroed(owner(), &mut zero), Err(FrameError::Exhausted));
    assert_eq!(pool.check_owned(frames[0].1, frames[0].0), Ok(()));
    assert_eq!(pool.check_owned(frames[0].1, TaskId::new(99).unwrap()), Err(FrameError::Owner));
    assert_eq!(pool.begin_revoke(frames[0].1, TaskId::new(99).unwrap()), Err(FrameError::Owner));
    for &(actor, frame) in &frames {
        pool.begin_revoke(frame, actor).unwrap();
    }
    assert_eq!(pool.snapshot().free, 0, "revocation is not completed reuse");
    assert_eq!(pool.check_owned(frames[0].1, frames[0].0), Err(FrameError::Stale));
    assert_eq!(pool.alloc_zeroed(owner(), &mut zero), Err(FrameError::Again));
    for &(_, frame) in &frames {
        pool.finish_revoke(frame, unsafe { RevokeComplete::after_unmap(frame) }).unwrap();
    }
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: PAGES, free: PAGES, used: 0 });
    for (index, &(_, stale)) in frames.iter().enumerate() {
        let actor = TaskId::new(101 + (index % 8) as u32).unwrap();
        let frame = pool.alloc_zeroed(actor, &mut zero).unwrap();
        assert_eq!(frame.index(), index);
        assert_eq!(frame.address(), stale.address());
        assert_ne!(frame, stale);
        assert_eq!(zero.contents[index], 0, "old owner's bytes must be cleared");
        let before = pool.snapshot();
        assert_eq!(pool.check_owned(stale, actor), Err(FrameError::Stale));
        assert_eq!(pool.begin_revoke(stale, actor), Err(FrameError::Stale));
        assert_eq!(pool.snapshot(), before);
        pool.begin_revoke(frame, actor).unwrap();
        pool.finish_revoke(frame, unsafe { RevokeComplete::after_unmap(frame) }).unwrap();
    }
    assert_eq!(zero.calls, 2 * PAGES);
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: PAGES, free: PAGES, used: 0 });
}

#[test]
fn allocation_zero_failure_retains_free_dirty_frame_without_ownership() {
    let mut metadata = [FrameMeta::EMPTY; 1];
    let mut pool = FramePool::from_memory(&[region(0x1000, 1)], &[], &mut metadata).unwrap();
    let mut zero = TrackedZero { base: 0x1000, contents: vec![0xa5], calls: 0, fail: true };
    let before = pool.snapshot();
    assert_eq!(pool.alloc_zeroed(owner(), &mut zero), Err(FrameError::ZeroFailed));
    assert_eq!(pool.snapshot(), before);
    assert_eq!(pool.alloc_clean(owner()), Err(FrameError::Again));
    assert_eq!(zero.contents, [0xa5]);
    zero.fail = false;
    let frame = pool.alloc_zeroed(owner(), &mut zero).unwrap();
    assert_eq!(frame.index(), 0);
    assert_eq!(zero.contents, [0]);
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 1, free: 0, used: 1 });
}

#[test]
fn zeroed_allocation_reuses_clean_pages_without_rezeroing_and_excludes_reservations() {
    let mut metadata = [FrameMeta::EMPTY; 3];
    let reserved = [region(0x1000, 1)];
    let mut pool = FramePool::from_memory(&[region(0x1000, 3)], &reserved, &mut metadata).unwrap();
    let mut zero = TrackedZero { base: 0x1000, contents: vec![0xa5; 3], calls: 0, fail: false };
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 2, free: 2, used: 0 });
    assert!(pool.clean_one(&mut zero).unwrap());
    zero.fail = true;
    let clean = pool.alloc_zeroed(owner(), &mut zero).unwrap();
    assert_eq!(clean.index(), 1);
    assert_eq!(zero.calls, 1, "clean page needs no second zero");
    assert_eq!(zero.contents[0], 0xa5, "reserved memory is never cleared");
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 2, free: 1, used: 1 });
}

#[test]
fn indexed_handles_reject_foreign_pool_and_mismatched_completion() {
    let mut first_meta = [FrameMeta::EMPTY; 1];
    let mut second_meta = [FrameMeta::EMPTY; 1];
    let mut first = FramePool::from_memory(&[region(0x1000, 1)], &[], &mut first_meta).unwrap();
    let mut second = FramePool::from_memory(&[region(0x2000, 1)], &[], &mut second_meta).unwrap();
    let mut zero = TrackedZero { base: 0x1000, contents: vec![0xa5; 2], calls: 0, fail: false };
    let a = first.alloc_zeroed(owner(), &mut zero).unwrap();
    let b = second.alloc_zeroed(owner(), &mut zero).unwrap();
    assert_eq!(a.index(), b.index());
    assert_eq!(first.check_owned(b, owner()), Err(FrameError::Stale));
    assert_eq!(first.begin_revoke(b, owner()), Err(FrameError::Stale));
    first.begin_revoke(a, owner()).unwrap();
    let before = first.snapshot();
    assert_eq!(first.finish_revoke(a, unsafe { RevokeComplete::after_unmap(b) }), Err(FrameError::Stale));
    assert_eq!(first.snapshot(), before);
    first.finish_revoke(a, unsafe { RevokeComplete::after_unmap(a) }).unwrap();
    assert_eq!(first.finish_revoke(a, unsafe { RevokeComplete::after_unmap(a) }), Err(FrameError::Stale));
    assert_eq!(first.snapshot(), FrameSnapshot { capacity: 1, free: 1, used: 0 });
}

#[test]
fn legacy_and_zeroed_allocations_share_capacity_and_preserve_first_fit() {
    let mut metadata = [FrameMeta::EMPTY; 3];
    let mut pool = FramePool::from_memory(&[region(0x1000, 3)], &[], &mut metadata).unwrap();
    let mut zero = TrackedZero {
        base: 0x1000,
        contents: vec![0xa5; 3],
        calls: 0,
        fail: false,
    };
    pool.clean_one(&mut zero).unwrap();
    assert_eq!(pool.snapshot().free, 3);
    let first = pool.alloc_clean(owner()).unwrap();
    let second = pool.alloc_zeroed(owner(), &mut zero).unwrap();
    assert_eq!((first.index(), second.index()), (0, 1));
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 3, free: 1, used: 2 });
    pool.begin_revoke(first, owner()).unwrap();
    assert_eq!(pool.snapshot().free, 1);
    pool.finish_revoke(first, unsafe { RevokeComplete::after_unmap(first) }).unwrap();
    assert_eq!(pool.snapshot().free, 2);
    pool.clean_one(&mut zero).unwrap();
    let reused = pool.alloc_clean(owner()).unwrap();
    assert_eq!(reused.address(), first.address());
    assert_ne!(reused, first);
    assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 3, free: 1, used: 2 });
}
