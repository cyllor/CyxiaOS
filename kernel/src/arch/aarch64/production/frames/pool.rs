//! Bounded CPU0 frame lifecycle proof. The board reservation stays in BootInfo
//! for later boot consumers. Only the fixture admits those pages to its pool.

use super::super::role_loader::high_leaf;
use super::{evidence, report};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_contracts::{BootInfo, MemoryRegion, PhysAddr, RegionKind, TaskId};
use cyxia_kernel_core::frame_meta_v0199::{FrameMeta as LedgerRow, Ledger, PAGE, PoolBridge};
use cyxia_kernel_core::frames::{
    FrameError, FrameHandle, FrameMeta, FramePool, FrameSnapshot, PageZeroer, RevokeComplete,
};
use cyxia_platform_virt::{KERNEL_POOL_END, USER_RAM_END, reserve_user_pool};

const PAGES: usize = 4;
const PAGE_BYTES: usize = PAGE as usize;
const WORD_BYTES: usize = core::mem::size_of::<u64>();
const WORDS_PER_PAGE: usize = PAGE_BYTES / WORD_BYTES;
const BYTES: u64 = PAGES as u64 * PAGE;
// Entry's writable, non-executable normal-memory leaf, accessible at EL1 only.
const EL1_RAM_LEAF: u64 = 0x0060_0000_0000_0703;
static FREE_PAGES: AtomicU64 = AtomicU64::new(0);

struct MappedPool {
    reservation: MemoryRegion,
}

impl MappedPool {
    fn reserve(info: &mut BootInfo) -> Self {
        let range = reserve_user_pool(info, BYTES).expect("reserve production frame pool");
        let start = range.start.0;
        let end = range.end().expect("production frame pool range");
        assert!(
            range.kind == RegionKind::Reserved
                && range.len == BYTES
                && start.is_multiple_of(PAGE)
                && start >= KERNEL_POOL_END
                && end <= USER_RAM_END,
            "production frame pool outside the mapped reservation window"
        );
        for pa in (start..end).step_by(PAGE_BYTES) {
            // SAFETY: high_leaf addresses the mapped bootstrap table. This
            // CPU0 hook runs before secondaries or any code changing its leaves.
            let leaf = unsafe { high_leaf(pa).read_volatile() };
            assert_eq!(leaf, pa | EL1_RAM_LEAF, "production frame pool mapping");
        }
        Self { reservation: range }
    }

    fn page_ptr(&self, page: PhysAddr) -> Result<*mut u64, FrameError> {
        let offset = page
            .0
            .checked_sub(self.reservation.start.0)
            .ok_or(FrameError::Invalid)?;
        if offset >= self.reservation.len || !offset.is_multiple_of(PAGE) {
            return Err(FrameError::Invalid);
        }
        Ok(core::ptr::without_provenance_mut(
            (crate::HIGH + page.0) as usize,
        ))
    }

    fn fill(&mut self, page: PhysAddr, byte: u8) -> Result<(), FrameError> {
        let ptr = self.page_ptr(page)?;
        let pattern = u64::from_ne_bytes([byte; WORD_BYTES]);
        // SAFETY: the complete page lies in the verified EL1 mapping of the
        // exclusive board reservation, outside all Rust allocations. Only this
        // CPU0 fixture accesses it, using aligned volatile stores.
        for index in 0..WORDS_PER_PAGE {
            unsafe { ptr.wrapping_add(index).write_volatile(pattern) };
        }
        Ok(())
    }

    fn is_filled(&self, page: PhysAddr, byte: u8) -> bool {
        let ptr = self.page_ptr(page).expect("readback within the frame pool");
        let pattern = u64::from_ne_bytes([byte; WORD_BYTES]);
        // SAFETY: same verified reservation as fill. The fixture writes the
        // complete page before each aligned volatile readback.
        (0..WORDS_PER_PAGE)
            .all(|index| unsafe { ptr.wrapping_add(index).read_volatile() == pattern })
    }
}

impl PageZeroer for MappedPool {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
        self.fill(page, 0)?;
        if !self.is_filled(page, 0) {
            return Err(FrameError::ZeroFailed);
        }
        Ok(())
    }
}

fn check_state(
    pool: &FramePool<'_>,
    bridge: &PoolBridge<'_>,
    used: usize,
    allocated: u32,
    quarantined: u32,
) -> u64 {
    let snapshot = pool.snapshot();
    bridge
        .conservation(snapshot)
        .expect("frame pool conservation");
    assert_eq!(
        snapshot,
        FrameSnapshot {
            capacity: PAGES,
            free: PAGES - used,
            used
        }
    );
    let inv = bridge.inventory().expect("frame pool inventory");
    assert_eq!((inv.reserved, inv.permanent), (0, 0));
    assert_eq!(
        (inv.free, inv.allocated, inv.quarantined),
        (
            PAGES as u32 - allocated - quarantined,
            allocated,
            quarantined
        )
    );
    u64::from(inv.free)
}

fn finish_revoke(pool: &mut FramePool<'_>, handle: FrameHandle) {
    // SAFETY: the fixture runs before secondary startup. The reserved pages
    // are accessed through the verified EL1 mapping and are never mapped to
    // either fixture owner or admitted to DMA. No owner mapping needs a TLBI.
    let complete = unsafe { RevokeComplete::after_unmap(handle) };
    pool.finish_revoke(handle, complete)
        .expect("complete frame revoke");
}

pub(super) fn prove_or_fatal(info: &mut BootInfo) {
    let mut memory = MappedPool::reserve(info);
    let ram = MemoryRegion {
        kind: RegionKind::Ram,
        ..memory.reservation
    };

    let mut rows = [LedgerRow::ZERO; PAGES];
    let ledger = Ledger::initialize_pool(&mut rows, ram.start.0, &[ram], &[])
        .expect("initialize production pool ledger");
    let bridge = PoolBridge::new(ledger).expect("production pool bridge");
    let mut metadata = [FrameMeta::EMPTY; PAGES];
    let mut pool =
        FramePool::from_memory(&[ram], &[], &mut metadata).expect("production frame pool");
    pool.attach_recorder(&bridge);
    check_state(&pool, &bridge, 0, 0, 0);

    for index in 0..PAGES {
        let page = PhysAddr(ram.start.0 + index as u64 * PAGE);
        memory.fill(page, 0xa5).expect("dirty initial pool page");
        assert!(memory.is_filled(page, 0xa5));
    }
    let owner = TaskId::new(1).unwrap();
    let successor = TaskId::new(2).unwrap();
    let handles: [FrameHandle; PAGES] = core::array::from_fn(|_| {
        let handle = pool
            .alloc_zeroed(owner, &mut memory)
            .expect("allocate from frame pool");
        assert!(memory.is_filled(handle.address(), 0));
        handle
    });
    check_state(&pool, &bridge, PAGES, PAGES as u32, 0);
    assert_eq!(
        pool.alloc_zeroed(owner, &mut memory),
        Err(FrameError::Exhausted)
    );

    let first = handles[0];
    memory
        .fill(first.address(), 0x5a)
        .expect("dirty owned frame");
    assert!(memory.is_filled(first.address(), 0x5a));
    pool.begin_revoke(first, owner).expect("begin frame revoke");
    check_state(&pool, &bridge, PAGES, PAGES as u32 - 1, 1);
    assert_eq!(pool.check_owned(first, owner), Err(FrameError::Stale));
    assert_eq!(
        pool.alloc_zeroed(successor, &mut memory),
        Err(FrameError::Again)
    );
    finish_revoke(&mut pool, first);
    check_state(&pool, &bridge, PAGES - 1, PAGES as u32 - 1, 1);

    let reissued = pool
        .alloc_zeroed(successor, &mut memory)
        .expect("reissue revoked frame");
    assert_eq!(reissued.address(), first.address());
    assert_eq!(reissued.index(), first.index());
    // With the address and index identical, handle inequality proves the
    // generation changed. The attached ledger also requires each increment.
    assert_ne!(reissued, first);
    assert!(memory.is_filled(reissued.address(), 0));
    assert_eq!(pool.check_owned(first, successor), Err(FrameError::Stale));
    assert_eq!(pool.begin_revoke(first, successor), Err(FrameError::Stale));
    pool.check_owned(reissued, successor)
        .expect("successor owns the reissued frame");
    check_state(&pool, &bridge, PAGES, PAGES as u32, 0);

    pool.begin_revoke(reissued, successor)
        .expect("revoke reissued frame");
    finish_revoke(&mut pool, reissued);
    for handle in handles.into_iter().skip(1) {
        pool.begin_revoke(handle, owner)
            .expect("revoke remaining frame");
        finish_revoke(&mut pool, handle);
    }
    check_state(&pool, &bridge, 0, 0, PAGES as u32);
    for _ in 0..PAGES {
        assert!(pool.clean_one(&mut memory).expect("clear revoked frame"));
    }
    FREE_PAGES.store(check_state(&pool, &bridge, 0, 0, 0), Ordering::Release);
}

pub(super) fn publish() {
    let free = FREE_PAGES.load(Ordering::Acquire);
    assert_eq!(free, PAGES as u64, "missing production frame pool proof");
    evidence::put(evidence::W14_FRAME_POOL_LIFECYCLE, 1);
    evidence::put(evidence::W14_FRAME_POOL_PAGES, PAGES as u64);
    evidence::put(evidence::W14_FRAME_POOL_FREE, free);
    report("V020_W14_FRAME_POOL", 1, PAGES as u64, free);
}
