//! Bounded ownership state machine. Clearing and revocation must succeed before reuse.
use cyxia_contracts::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Invalid,
    Capacity,
    Again,
    Exhausted,
    Owner,
    Stale,
    ZeroFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Reserved,
    Dirty,
    Clean,
    Owned,
    Revoking,
    Retired,
}
#[derive(Debug, Clone, Copy)]
pub struct FrameMeta {
    address: PhysAddr,
    generation: u64,
    owner: Option<TaskId>,
    state: State,
}
impl FrameMeta {
    pub const EMPTY: Self = Self {
        address: PhysAddr(0),
        generation: 0,
        owner: None,
        state: State::Reserved,
    };
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHandle {
    index: usize,
    address: PhysAddr,
    generation: u64,
}
impl FrameHandle {
    /// Index in this pool's metadata, including excluded reserved entries.
    pub fn index(self) -> usize {
        self.index
    }
    pub fn address(self) -> PhysAddr {
        self.address
    }
}
pub struct RevokeComplete(FrameHandle);
impl RevokeComplete {
    /// # Safety
    /// Caller must remove all CPU/DMA mappings granted to the former owner of
    /// this exact handle and complete synchronization. Only an exclusively
    /// controlled supervisor mapping used by the allocator to clear/reassign
    /// the page may remain; no former owner or DMA agent may access it.
    pub unsafe fn after_unmap(handle: FrameHandle) -> Self {
        Self(handle)
    }
}
pub trait PageZeroer {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError>;
}
/// Available capacity excludes reserved and permanently retired frames.
/// Dirty pages are free capacity because `alloc_zeroed` clears them before use;
/// revoking pages remain used until the matching completion is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSnapshot {
    pub capacity: usize,
    pub free: usize,
    pub used: usize,
}

pub struct FramePool<'a> {
    meta: &'a mut [FrameMeta],
    capacity: usize,
    free: usize,
    next_zeroed: usize,
    // Conservative lower bound on the first dirty frame. Revocation may
    // lower it; cleaning advances it without changing first-fit ordering.
    next_dirty: usize,
}
impl<'a> FramePool<'a> {
    pub fn from_regions(
        info: &BootInfo,
        reserved: &[MemoryRegion],
        metadata: &'a mut [FrameMeta],
    ) -> Result<Self, FrameError> {
        if info.ram_count > 8 || info.reserved_count > 32 {
            return Err(FrameError::Invalid);
        }
        Self::from_memory_parts(
            &info.ram[..info.ram_count],
            reserved,
            &info.reserved[..info.reserved_count],
            metadata,
        )
    }
    /// Firmware-independent admission. Architecture adapters supply validated
    /// RAM and reservations; no DTB, PSCI or interrupt-controller ABI is needed.
    pub fn from_memory(
        ram: &[MemoryRegion],
        reserved: &[MemoryRegion],
        metadata: &'a mut [FrameMeta],
    ) -> Result<Self, FrameError> {
        Self::from_memory_parts(ram, reserved, &[], metadata)
    }
    fn from_memory_parts(
        ram: &[MemoryRegion],
        reserved: &[MemoryRegion],
        firmware_reserved: &[MemoryRegion],
        metadata: &'a mut [FrameMeta],
    ) -> Result<Self, FrameError> {
        if ram.len() > 8 {
            return Err(FrameError::Invalid);
        }
        let mut total = 0usize;
        for (i, r) in ram.iter().enumerate() {
            if r.kind != RegionKind::Ram
                || r.len == 0
                || !r.start.0.is_multiple_of(4096)
                || !r.len.is_multiple_of(4096)
                || r.end().is_err()
            {
                return Err(FrameError::Invalid);
            }
            if ram[..i].iter().any(|x| x.overlaps(*r)) {
                return Err(FrameError::Invalid);
            }
            total = total
                .checked_add(usize::try_from(r.len / 4096).map_err(|_| FrameError::Capacity)?)
                .ok_or(FrameError::Capacity)?;
        }
        if total > 65536 || total > metadata.len() {
            return Err(FrameError::Capacity);
        }
        for r in reserved.iter().chain(firmware_reserved.iter()) {
            if r.end().is_err() {
                return Err(FrameError::Invalid);
            }
        }
        let mut i = 0;
        let mut free = 0;
        for r in ram {
            for offset in (0..r.len).step_by(4096) {
                let page = MemoryRegion {
                    start: PhysAddr(r.start.0 + offset),
                    len: 4096,
                    kind: RegionKind::Ram,
                };
                let excluded = reserved
                    .iter()
                    .chain(firmware_reserved.iter())
                    .any(|x| x.overlaps(page));
                if !excluded {
                    free += 1;
                }
                metadata[i] = FrameMeta {
                    address: page.start,
                    state: if excluded {
                        State::Reserved
                    } else {
                        State::Dirty
                    },
                    ..FrameMeta::EMPTY
                };
                i += 1;
            }
        }
        Ok(Self {
            meta: &mut metadata[..total],
            capacity: free,
            free,
            next_zeroed: 0,
            next_dirty: 0,
        })
    }
    pub fn snapshot(&self) -> FrameSnapshot {
        FrameSnapshot {
            capacity: self.capacity,
            free: self.free,
            used: self.capacity - self.free,
        }
    }

    /// First-fit clean-page allocation retains the historical selection order.
    pub fn alloc_clean(&mut self, owner: TaskId) -> Result<FrameHandle, FrameError> {
        for (index, m) in self.meta.iter_mut().enumerate() {
            if m.state == State::Clean {
                let Some(g) = m.generation.checked_add(1) else {
                    m.state = State::Retired;
                    self.capacity -= 1;
                    self.free -= 1;
                    continue;
                };
                m.generation = g;
                m.owner = Some(owner);
                m.state = State::Owned;
                self.free -= 1;
                return Ok(FrameHandle {
                    index,
                    address: m.address,
                    generation: g,
                });
            }
        }
        if self
            .meta
            .iter()
            .any(|x| matches!(x.state, State::Dirty | State::Revoking))
        {
            Err(FrameError::Again)
        } else {
            Err(FrameError::Exhausted)
        }
    }
    /// Allocate a free page, clearing dirty contents before issuing ownership.
    /// Scanning starts after the previous successful allocation and examines at
    /// most one full pool. A zero failure leaves its page dirty and unowned;
    /// exhausted generations permanently retire capacity instead of wrapping.
    pub fn alloc_zeroed(
        &mut self,
        owner: TaskId,
        zeroer: &mut impl PageZeroer,
    ) -> Result<FrameHandle, FrameError> {
        let count = self.meta.len();
        let mut revoking = false;
        for offset in 0..count {
            let index = (self.next_zeroed + offset) % count;
            let m = &mut self.meta[index];
            if m.state == State::Revoking {
                revoking = true;
            }
            if !matches!(m.state, State::Dirty | State::Clean) {
                continue;
            }
            let Some(generation) = m.generation.checked_add(1) else {
                m.state = State::Retired;
                self.capacity -= 1;
                self.free -= 1;
                continue;
            };
            if m.state == State::Dirty {
                zeroer.zero(m.address)?;
            }
            m.generation = generation;
            m.owner = Some(owner);
            m.state = State::Owned;
            self.free -= 1;
            self.next_zeroed = (index + 1) % count;
            return Ok(FrameHandle {
                index,
                address: m.address,
                generation,
            });
        }
        Err(if revoking { FrameError::Again } else { FrameError::Exhausted })
    }

    fn find(&mut self, h: FrameHandle) -> Result<&mut FrameMeta, FrameError> {
        let m = self.meta.get_mut(h.index).ok_or(FrameError::Stale)?;
        if m.address != h.address || m.generation != h.generation {
            return Err(FrameError::Stale);
        }
        Ok(m)
    }

    /// Read-only preflight for a complete release batch before any VM mutation.
    pub fn check_owned(&self, h: FrameHandle, owner: TaskId) -> Result<(), FrameError> {
        let m = self.meta.get(h.index).ok_or(FrameError::Stale)?;
        if m.address != h.address || m.generation != h.generation {
            return Err(FrameError::Stale);
        }
        if m.owner != Some(owner) {
            return Err(FrameError::Owner);
        }
        if m.state != State::Owned {
            return Err(FrameError::Stale);
        }
        Ok(())
    }
    pub fn begin_revoke(&mut self, h: FrameHandle, owner: TaskId) -> Result<(), FrameError> {
        let m = self.find(h)?;
        if m.owner != Some(owner) {
            return Err(FrameError::Owner);
        }
        if m.state != State::Owned {
            return Err(FrameError::Stale);
        }
        m.state = State::Revoking;
        Ok(())
    }
    pub fn finish_revoke(
        &mut self,
        h: FrameHandle,
        completion: RevokeComplete,
    ) -> Result<(), FrameError> {
        if completion.0 != h {
            return Err(FrameError::Stale);
        }
        let m = self.find(h)?;
        if m.state != State::Revoking {
            return Err(FrameError::Stale);
        }
        m.owner = None;
        m.state = State::Dirty;
        self.next_dirty = self.next_dirty.min(h.index);
        self.free += 1;
        Ok(())
    }
    pub fn clean_one(&mut self, zeroer: &mut impl PageZeroer) -> Result<bool, FrameError> {
        // Avoid rescanning the same already-clean/reserved prefix for every
        // page of a sequential clear. Preserve the historical lowest-index
        // dirty choice and lower the cursor whenever a revoke returns a page.
        while self.next_dirty < self.meta.len() {
            let m = &mut self.meta[self.next_dirty];
            if m.state == State::Dirty {
                // On failure this page remains dirty and the cursor stays here.
                zeroer.zero(m.address)?;
                m.state = State::Clean;
                self.next_dirty += 1;
                return Ok(true);
            }
            self.next_dirty += 1;
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoZero;
    impl PageZeroer for NoZero {
        fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
            panic!("retired or clean pages must not invoke the zeroer");
        }
    }

    #[test]
    fn dirty_scan_advances_linearly_and_revoke_lowers_cursor() {
        struct Zero(bool);
        impl PageZeroer for Zero {
            fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
                if self.0 { Err(FrameError::ZeroFailed) } else { Ok(()) }
            }
        }
        let ram = [MemoryRegion { start: PhysAddr(0x1000), len: 4 * 4096, kind: RegionKind::Ram }];
        let mut metadata = [FrameMeta::EMPTY; 4];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mut zero = Zero(false);
        for expected in 1..=4 {
            assert!(pool.clean_one(&mut zero).unwrap());
            assert_eq!(pool.next_dirty, expected);
        }
        assert!(!pool.clean_one(&mut zero).unwrap());
        let owner = TaskId::new(1).unwrap();
        let frame = pool.alloc_clean(owner).unwrap();
        assert_eq!(frame.index(), 0);
        pool.begin_revoke(frame, owner).unwrap();
        assert!(!pool.clean_one(&mut zero).unwrap());
        pool.finish_revoke(frame, unsafe { RevokeComplete::after_unmap(frame) }).unwrap();
        assert_eq!(pool.next_dirty, 0);
        zero.0 = true;
        assert_eq!(pool.clean_one(&mut zero), Err(FrameError::ZeroFailed));
        assert_eq!(pool.next_dirty, 0);
        zero.0 = false;
        assert!(pool.clean_one(&mut zero).unwrap());
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 0);
    }

    #[test]
    fn exhausted_generations_retire_capacity_in_both_allocation_paths() {
        for zeroed in [false, true] {
            let mut metadata = [FrameMeta {
                address: PhysAddr(0x1000),
                generation: u64::MAX,
                owner: None,
                state: if zeroed { State::Dirty } else { State::Clean },
            }];
            let mut pool = FramePool {
                meta: &mut metadata,
                capacity: 1,
                free: 1,
                next_zeroed: 0,
                next_dirty: 0,
            };
            let owner = TaskId::new(1).unwrap();
            let result = if zeroed {
                pool.alloc_zeroed(owner, &mut NoZero)
            } else {
                pool.alloc_clean(owner)
            };
            assert_eq!(result, Err(FrameError::Exhausted));
            assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 0, free: 0, used: 0 });
            assert_eq!(pool.meta[0].state, State::Retired);
            assert_eq!(pool.alloc_zeroed(owner, &mut NoZero), Err(FrameError::Exhausted));
            assert_eq!(pool.snapshot().free, 0);
        }
    }

    #[test]
    fn forged_index_does_not_authorize_another_frame() {
        let owner = TaskId::new(1).unwrap();
        let mut metadata = [FrameMeta {
            address: PhysAddr(0x1000),
            generation: 1,
            owner: Some(owner),
            state: State::Owned,
        }, FrameMeta {
            address: PhysAddr(0x2000),
            generation: 1,
            owner: Some(owner),
            state: State::Owned,
        }];
        let mut pool = FramePool {
            meta: &mut metadata,
            capacity: 2,
            free: 0,
            next_zeroed: 0,
            next_dirty: 0,
        };
        for index in [1, usize::MAX] {
            let forged = FrameHandle { index, address: PhysAddr(0x1000), generation: 1 };
            assert_eq!(pool.check_owned(forged, owner), Err(FrameError::Stale));
            assert_eq!(pool.begin_revoke(forged, owner), Err(FrameError::Stale));
            assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 2, free: 0, used: 2 });
        }
    }
}
