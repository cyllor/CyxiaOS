//! Bounded ownership state machine. Clearing and revocation must succeed before reuse.
//!
//! An optional [`FrameRecorder`] hook mirrors pool transitions into an
//! external frame-accounting ledger (the V0.19.9 FrameMeta bridge in
//! [`crate::frame_meta_v0199`]). With no recorder attached every operation
//! behaves exactly as it historically has. The desktop full-OS pool
//! attaches the bridge under its own `full-os` gate (the former
//! `full-os + v0199-local-native` conjunction was never satisfiable in any
//! build); default, host and non-full-os builds stay unattached to the ledger.
//! Optional derived availability storage is independent of the recorder. The general-allocator native cutover to the V0.19.9
//! ledger (and native boot verification of the desktop attachment)
//! remains a later gate.
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
    /// The attached external frame ledger rejected an accounting transition.
    /// The pool operation aborted fail-closed before publishing any change.
    Ledger,
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
/// Optional external frame-accounting hook (V0.19.9 FrameMeta ledger bridge).
///
/// Every ownership transition consults the attached recorder before the pool
/// publishes the matching state change; a recorder error aborts the operation
/// fail-closed and leaves the pool untouched. `generation` is always the
/// pool's next generation for the frame, so a faithful recorder keeps its
/// frame generations in lockstep with the pool. With no recorder attached
/// the pool behaves exactly as it historically has.
///
/// The pool holds a shared borrow of the recorder for its lifetime, so
/// implementations account through interior mutability (single-core CPU0
/// context: `RefCell`); the ledger stays inspectable while attached.
///
/// This is a bounded accounting mirror only: the general-allocator native
/// cutover to the V0.19.9 ledger remains a later gate.
pub trait FrameRecorder {
    /// A clean or freshly zeroed page is about to become owned at
    /// `generation`. Reject to abort the allocation before ownership.
    fn alloc(&self, address: PhysAddr, owner: TaskId, generation: u64) -> Result<(), FrameError>;
    /// Zeroing of a dirty allocation candidate failed. The page stays dirty
    /// and unowned in the pool; the recorder must quarantine it, never
    /// account it as free.
    fn zero_failed(&self, address: PhysAddr) -> Result<(), FrameError>;
    /// Revocation begins: fence the recorded owner before unmap work.
    fn begin_revoke(
        &self,
        address: PhysAddr,
        owner: TaskId,
        generation: u64,
    ) -> Result<(), FrameError>;
    /// Revocation completed (unmap synchronized). The page returns dirty;
    /// the recorder may only account it free after an explicit zero proof.
    fn finish_revoke(&self, address: PhysAddr) -> Result<(), FrameError>;
    /// A dirty page was just successfully zeroed by `clean_one`: the zero
    /// proof that lets the recorder account the page as free.
    fn cleaned(&self, address: PhysAddr) -> Result<(), FrameError>;
    /// A frame's generation space is exhausted; it is permanently retired.
    fn retired(&self, address: PhysAddr) -> Result<(), FrameError>;
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

/// Derived availability index for up to 65536 metadata rows. Caller-owned
/// storage keeps the fixed 8336-byte cost out of small pools and kernel stacks.
/// This is a search accelerator, never an ownership or zeroing authority.
pub struct FreeFrameIndex {
    leaves: [u64; 1024],
    groups: [u64; 16],
    top: u64,
    revoking: usize,
}

impl FreeFrameIndex {
    pub const EMPTY: Self = Self {
        leaves: [0; 1024],
        groups: [0; 16],
        top: 0,
        revoking: 0,
    };

    fn set(&mut self, index: usize, available: bool) {
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        let group = word / 64;
        let group_bit = 1u64 << (word % 64);
        if available {
            self.leaves[word] |= bit;
        } else {
            self.leaves[word] &= !bit;
        }
        if self.leaves[word] != 0 {
            self.groups[group] |= group_bit;
        } else {
            self.groups[group] &= !group_bit;
        }
        if self.groups[group] != 0 {
            self.top |= 1u64 << group;
        } else {
            self.top &= !(1u64 << group);
        }
    }

    // Bits strictly above bit, without shifting by 64.
    fn after(bit: usize) -> u64 {
        if bit == 63 {
            0
        } else {
            u64::MAX << (bit + 1)
        }
    }

    /// Lowest available index >= start. At most one current leaf, one
    /// current summary, the top word and one selected summary/leaf pair.
    fn next_at_or_after(&self, start: usize) -> Option<usize> {
        if start >= 65536 {
            return None;
        }
        let word = start / 64;
        let group = word / 64;
        let leaf = self.leaves[word] & (u64::MAX << (start % 64));
        if leaf != 0 {
            return Some(word * 64 + leaf.trailing_zeros() as usize);
        }
        let later_words = self.groups[group] & Self::after(word % 64);
        let next_word = if later_words != 0 {
            group * 64 + later_words.trailing_zeros() as usize
        } else {
            let later_groups = self.top & Self::after(group);
            if later_groups == 0 {
                return None;
            }
            let next_group = later_groups.trailing_zeros() as usize;
            next_group * 64 + self.groups[next_group].trailing_zeros() as usize
        };
        Some(next_word * 64 + self.leaves[next_word].trailing_zeros() as usize)
    }
}

pub struct FramePool<'a> {
    meta: &'a mut [FrameMeta],
    capacity: usize,
    free: usize,
    next_zeroed: usize,
    // Conservative lower bound on the first clean frame; only successful
    // cleaning can create a new clean page below this cursor.
    next_clean: usize,
    // Conservative lower bound on the first dirty frame. Revocation may
    // lower it; cleaning advances it without changing first-fit ordering.
    next_dirty: usize,
    // Optional accounting mirror. None preserves the historical accounting
    // behavior; the desktop pool attaches it behind its own
    // full-os gate.
    recorder: Option<&'a dyn FrameRecorder>,
    free_index: Option<&'a mut FreeFrameIndex>,
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
            next_clean: 0,
            next_dirty: 0,
            recorder: None,
            free_index: None,
        })
    }
    /// Install exclusive caller-provided search storage. Rebuild from the
    /// authoritative metadata, including reserved and in-progress revokes.
    /// The same single-owner discipline as all pool transitions applies.
    pub fn attach_free_index(&mut self, storage: &'a mut FreeFrameIndex) -> Result<(), FrameError> {
        if self.free_index.is_some() {
            return Err(FrameError::Invalid);
        }
        storage.leaves.fill(0);
        storage.groups.fill(0);
        storage.top = 0;
        storage.revoking = 0;
        for (index, m) in self.meta.iter().enumerate() {
            match m.state {
                State::Dirty | State::Clean => storage.set(index, true),
                State::Revoking => storage.revoking += 1,
                _ => {}
            }
        }
        self.free_index = Some(storage);
        Ok(())
    }

    /// Attach an external accounting recorder (e.g. the V0.19.9
    /// `frame_meta_v0199::PoolBridge`). Replaces any previously attached
    /// recorder. Until attached, pool behavior is unchanged.
    pub fn attach_recorder(&mut self, recorder: &'a dyn FrameRecorder) {
        self.recorder = Some(recorder);
    }
    /// Detach and return the recorder.
    pub fn detach_recorder(&mut self) -> Option<&'a dyn FrameRecorder> {
        self.recorder.take()
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
        while self.next_clean < self.meta.len() {
            let index = self.next_clean;
            let m = &mut self.meta[index];
            if m.state == State::Clean {
                let Some(g) = m.generation.checked_add(1) else {
                    if let Some(r) = self.recorder {
                        r.retired(m.address)?;
                    }
                    m.state = State::Retired;
                    if let Some(free_index) = self.free_index.as_deref_mut() {
                        free_index.set(index, false);
                    }
                    self.capacity -= 1;
                    self.free -= 1;
                    self.next_clean += 1;
                    continue;
                };
                if let Some(r) = self.recorder {
                    r.alloc(m.address, owner, g)?;
                }
                m.generation = g;
                m.owner = Some(owner);
                m.state = State::Owned;
                if let Some(free_index) = self.free_index.as_deref_mut() {
                    free_index.set(index, false);
                }
                self.free -= 1;
                self.next_clean += 1;
                return Ok(FrameHandle {
                    index,
                    address: m.address,
                    generation: g,
                });
            }
            self.next_clean += 1;
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
    /// Selection starts after the previous successful allocation. With an
    /// index attached it skips unavailable rows; otherwise it examines at
    /// most one full pool. A zero failure leaves its page dirty and unowned;
    /// exhausted generations permanently retire capacity instead of wrapping.
    pub fn alloc_zeroed(
        &mut self,
        owner: TaskId,
        zeroer: &mut impl PageZeroer,
    ) -> Result<FrameHandle, FrameError> {
        let count = self.meta.len();
        let mut revoking = false;
        let mut offset = 0;
        loop {
            let index = if let Some(free_index) = self.free_index.as_deref() {
                // Retirement clears a candidate before the next search, so
                // each extra iteration corresponds to a real retired page.
                let Some(index) = free_index
                    .next_at_or_after(self.next_zeroed)
                    .or_else(|| free_index.next_at_or_after(0))
                else {
                    break;
                };
                index
            } else {
                if offset == count {
                    break;
                }
                let index = (self.next_zeroed + offset) % count;
                offset += 1;
                index
            };
            let m = self.meta.get_mut(index).ok_or(FrameError::Ledger)?;
            if m.state == State::Revoking {
                revoking = true;
            }
            if !matches!(m.state, State::Dirty | State::Clean) {
                if self.free_index.is_some() {
                    // A divergent derived index cannot authorize reuse.
                    return Err(FrameError::Ledger);
                }
                continue;
            }
            let Some(generation) = m.generation.checked_add(1) else {
                if let Some(r) = self.recorder {
                    r.retired(m.address)?;
                }
                m.state = State::Retired;
                if let Some(free_index) = self.free_index.as_deref_mut() {
                    free_index.set(index, false);
                }
                self.capacity -= 1;
                self.free -= 1;
                continue;
            };
            if m.state == State::Dirty
                && let Err(e) = zeroer.zero(m.address)
            {
                if let Some(r) = self.recorder {
                    r.zero_failed(m.address)?;
                }
                return Err(e);
            }
            if let Some(r) = self.recorder {
                r.alloc(m.address, owner, generation)?;
            }
            m.generation = generation;
            m.owner = Some(owner);
            m.state = State::Owned;
            if let Some(free_index) = self.free_index.as_deref_mut() {
                free_index.set(index, false);
            }
            self.free -= 1;
            self.next_zeroed = (index + 1) % count;
            return Ok(FrameHandle {
                index,
                address: m.address,
                generation,
            });
        }
        let revoking = self
            .free_index
            .as_deref()
            .map_or(revoking, |index| index.revoking != 0);
        Err(if revoking {
            FrameError::Again
        } else {
            FrameError::Exhausted
        })
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
        let recorder = self.recorder;
        let m = self.find(h)?;
        if m.owner != Some(owner) {
            return Err(FrameError::Owner);
        }
        if m.state != State::Owned {
            return Err(FrameError::Stale);
        }
        if let Some(r) = recorder {
            r.begin_revoke(m.address, owner, m.generation)?;
        }
        m.state = State::Revoking;
        if let Some(free_index) = self.free_index.as_deref_mut() {
            free_index.revoking += 1;
        }
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
        let recorder = self.recorder;
        let m = self.find(h)?;
        if m.state != State::Revoking {
            return Err(FrameError::Stale);
        }
        if let Some(r) = recorder {
            r.finish_revoke(m.address)?;
        }
        m.owner = None;
        m.state = State::Dirty;
        if let Some(free_index) = self.free_index.as_deref_mut() {
            free_index.revoking -= 1;
            free_index.set(h.index, true);
        }
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
                if let Some(r) = self.recorder {
                    r.cleaned(m.address)?;
                }
                m.state = State::Clean;
                self.next_clean = self.next_clean.min(self.next_dirty);
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
                if self.0 {
                    Err(FrameError::ZeroFailed)
                } else {
                    Ok(())
                }
            }
        }
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 4 * 4096,
            kind: RegionKind::Ram,
        }];
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
        pool.finish_revoke(frame, unsafe { RevokeComplete::after_unmap(frame) })
            .unwrap();
        assert_eq!(pool.next_dirty, 0);
        zero.0 = true;
        assert_eq!(pool.clean_one(&mut zero), Err(FrameError::ZeroFailed));
        assert_eq!(pool.next_dirty, 0);
        zero.0 = false;
        assert!(pool.clean_one(&mut zero).unwrap());
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 0);
    }

    #[test]
    fn clean_first_fit_revisits_reclaimed_lower_pages() {
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 4 * 4096,
            kind: RegionKind::Ram,
        }];
        let mut metadata = [FrameMeta::EMPTY; 4];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let owner = TaskId::new(1).unwrap();
        let mut zero = ToggleZero(false);
        for _ in 0..4 {
            assert!(pool.clean_one(&mut zero).unwrap());
        }
        let a = pool.alloc_clean(owner).unwrap();
        let b = pool.alloc_clean(owner).unwrap();
        assert_eq!((a.index(), b.index()), (0, 1));
        pool.begin_revoke(a, owner).unwrap();
        pool.finish_revoke(a, unsafe { RevokeComplete::after_unmap(a) })
            .unwrap();
        assert!(pool.clean_one(&mut zero).unwrap());
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 0);
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 2);
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 3);
        assert_eq!(pool.alloc_clean(owner), Err(FrameError::Exhausted));
        assert_eq!(pool.snapshot().free, 0);
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
                next_clean: 0,
                next_dirty: 0,
                recorder: None,
                free_index: None,
            };
            let owner = TaskId::new(1).unwrap();
            let result = if zeroed {
                pool.alloc_zeroed(owner, &mut NoZero)
            } else {
                pool.alloc_clean(owner)
            };
            assert_eq!(result, Err(FrameError::Exhausted));
            assert_eq!(
                pool.snapshot(),
                FrameSnapshot {
                    capacity: 0,
                    free: 0,
                    used: 0
                }
            );
            assert_eq!(pool.meta[0].state, State::Retired);
            assert_eq!(
                pool.alloc_zeroed(owner, &mut NoZero),
                Err(FrameError::Exhausted)
            );
            assert_eq!(pool.snapshot().free, 0);
        }
    }

    #[test]
    fn forged_index_does_not_authorize_another_frame() {
        let owner = TaskId::new(1).unwrap();
        let mut metadata = [
            FrameMeta {
                address: PhysAddr(0x1000),
                generation: 1,
                owner: Some(owner),
                state: State::Owned,
            },
            FrameMeta {
                address: PhysAddr(0x2000),
                generation: 1,
                owner: Some(owner),
                state: State::Owned,
            },
        ];
        let mut pool = FramePool {
            meta: &mut metadata,
            capacity: 2,
            free: 0,
            next_zeroed: 0,
            next_clean: 0,
            next_dirty: 0,
            recorder: None,
            free_index: None,
        };
        for index in [1, usize::MAX] {
            let forged = FrameHandle {
                index,
                address: PhysAddr(0x1000),
                generation: 1,
            };
            assert_eq!(pool.check_owned(forged, owner), Err(FrameError::Stale));
            assert_eq!(pool.begin_revoke(forged, owner), Err(FrameError::Stale));
            assert_eq!(
                pool.snapshot(),
                FrameSnapshot {
                    capacity: 2,
                    free: 0,
                    used: 2
                }
            );
        }
    }

    extern crate std;
    use std::vec::Vec;

    struct ToggleZero(bool);
    impl PageZeroer for ToggleZero {
        fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
            if self.0 {
                Err(FrameError::ZeroFailed)
            } else {
                Ok(())
            }
        }
    }

    struct MockRecorder {
        log: core::cell::RefCell<Vec<(&'static str, u64, u64)>>,
        fail_on: core::cell::Cell<Option<&'static str>>,
    }
    impl MockRecorder {
        fn new() -> Self {
            Self {
                log: core::cell::RefCell::new(Vec::new()),
                fail_on: core::cell::Cell::new(None),
            }
        }
        fn note(
            &self,
            op: &'static str,
            address: PhysAddr,
            generation: u64,
        ) -> Result<(), FrameError> {
            if self.fail_on.get() == Some(op) {
                return Err(FrameError::Ledger);
            }
            self.log.borrow_mut().push((op, address.0, generation));
            Ok(())
        }
    }
    impl FrameRecorder for MockRecorder {
        fn alloc(
            &self,
            address: PhysAddr,
            _owner: TaskId,
            generation: u64,
        ) -> Result<(), FrameError> {
            self.note("alloc", address, generation)
        }
        fn zero_failed(&self, address: PhysAddr) -> Result<(), FrameError> {
            self.note("zero_failed", address, 0)
        }
        fn begin_revoke(
            &self,
            address: PhysAddr,
            _owner: TaskId,
            generation: u64,
        ) -> Result<(), FrameError> {
            self.note("begin_revoke", address, generation)
        }
        fn finish_revoke(&self, address: PhysAddr) -> Result<(), FrameError> {
            self.note("finish_revoke", address, 0)
        }
        fn cleaned(&self, address: PhysAddr) -> Result<(), FrameError> {
            self.note("cleaned", address, 0)
        }
        fn retired(&self, address: PhysAddr) -> Result<(), FrameError> {
            self.note("retired", address, 0)
        }
    }

    #[test]
    fn recorder_mirrors_pool_transitions_in_order() {
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 2 * 4096,
            kind: RegionKind::Ram,
        }];
        let mut metadata = [FrameMeta::EMPTY; 2];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mock = MockRecorder::new();
        pool.attach_recorder(&mock);
        let owner = TaskId::new(1).unwrap();
        let mut zero = ToggleZero(false);
        let h = pool.alloc_zeroed(owner, &mut zero).unwrap();
        pool.begin_revoke(h, owner).unwrap();
        pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        assert!(pool.clean_one(&mut zero).unwrap());
        let h2 = pool.alloc_clean(owner).unwrap();
        assert_eq!(h2.index(), h.index());
        pool.detach_recorder();
        assert_eq!(
            *mock.log.borrow(),
            std::vec![
                ("alloc", 0x1000, 1),
                ("begin_revoke", 0x1000, 1),
                ("finish_revoke", 0x1000, 0),
                ("cleaned", 0x1000, 0),
                ("alloc", 0x1000, 2),
            ]
        );
    }

    #[test]
    fn recorder_zero_failure_quarantines_and_keeps_dirty_capacity() {
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 4096,
            kind: RegionKind::Ram,
        }];
        let mut metadata = [FrameMeta::EMPTY; 1];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mock = MockRecorder::new();
        pool.attach_recorder(&mock);
        let owner = TaskId::new(1).unwrap();
        let mut fail = ToggleZero(true);
        assert_eq!(
            pool.alloc_zeroed(owner, &mut fail),
            Err(FrameError::ZeroFailed)
        );
        // The page stays dirty and unowned: dirty capacity is unchanged and
        // the recorder saw a quarantine, never a free accounting.
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 1,
                free: 1,
                used: 0
            }
        );
        assert_eq!(*mock.log.borrow(), std::vec![("zero_failed", 0x1000, 0)]);
        let mut ok = ToggleZero(false);
        assert!(pool.clean_one(&mut ok).unwrap());
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 0);
        pool.detach_recorder();
        assert_eq!(mock.log.borrow()[1], ("cleaned", 0x1000, 0));
        assert_eq!(mock.log.borrow()[2], ("alloc", 0x1000, 1));
    }

    #[test]
    fn recorder_rejection_fails_closed_without_pool_mutation() {
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 4096,
            kind: RegionKind::Ram,
        }];
        let mut metadata = [FrameMeta::EMPTY; 1];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mock = MockRecorder::new();
        pool.attach_recorder(&mock);
        let owner = TaskId::new(1).unwrap();
        let mut zero = ToggleZero(false);
        // Allocation rejection leaves the page dirty and capacity untouched.
        mock.fail_on.set(Some("alloc"));
        assert_eq!(pool.alloc_zeroed(owner, &mut zero), Err(FrameError::Ledger));
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 1,
                free: 1,
                used: 0
            }
        );
        mock.fail_on.set(None);
        let h = pool.alloc_zeroed(owner, &mut zero).unwrap();
        // Begin-revoke rejection keeps the frame owned; finish stays stale.
        mock.fail_on.set(Some("begin_revoke"));
        assert_eq!(pool.begin_revoke(h, owner), Err(FrameError::Ledger));
        pool.check_owned(h, owner).unwrap();
        assert_eq!(
            pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) }),
            Err(FrameError::Stale)
        );
        mock.fail_on.set(None);
        pool.begin_revoke(h, owner).unwrap();
        // Finish-revoke rejection keeps the frame revoking: no free capacity.
        mock.fail_on.set(Some("finish_revoke"));
        assert_eq!(
            pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) }),
            Err(FrameError::Ledger)
        );
        assert_eq!(pool.snapshot().free, 0);
        mock.fail_on.set(None);
        pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        // Cleaned rejection keeps the page dirty and the cursor in place.
        mock.fail_on.set(Some("cleaned"));
        assert_eq!(pool.clean_one(&mut zero), Err(FrameError::Ledger));
        assert_eq!(pool.next_dirty, 0);
        assert_eq!(pool.meta[0].state, State::Dirty);
        mock.fail_on.set(None);
        assert!(pool.clean_one(&mut zero).unwrap());
        assert_eq!(pool.alloc_clean(owner).unwrap().index(), 0);
    }

    #[test]
    fn recorder_retirement_mirrors_and_fails_closed() {
        let mut metadata = [FrameMeta {
            address: PhysAddr(0x1000),
            generation: u64::MAX,
            owner: None,
            state: State::Clean,
        }];
        let mut pool = FramePool {
            meta: &mut metadata,
            capacity: 1,
            free: 1,
            next_zeroed: 0,
            next_clean: 0,
            next_dirty: 0,
            recorder: None,
            free_index: None,
        };
        let mock = MockRecorder::new();
        pool.attach_recorder(&mock);
        let owner = TaskId::new(1).unwrap();
        mock.fail_on.set(Some("retired"));
        assert_eq!(pool.alloc_clean(owner), Err(FrameError::Ledger));
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 1,
                free: 1,
                used: 0
            }
        );
        assert_eq!(pool.meta[0].state, State::Clean);
        mock.fail_on.set(None);
        assert_eq!(pool.alloc_clean(owner), Err(FrameError::Exhausted));
        assert_eq!(pool.meta[0].state, State::Retired);
        pool.detach_recorder();
        assert_eq!(*mock.log.borrow(), std::vec![("retired", 0x1000, 0)]);
    }

    #[test]
    fn indexed_tail_reuse_and_pressure_match_linear_selection() {
        const PAGES: usize = 65536;
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: PAGES as u64 * 4096,
            kind: RegionKind::Ram,
        }];
        let mut meta_a = std::vec![FrameMeta::EMPTY; PAGES];
        let mut meta_b = std::vec![FrameMeta::EMPTY; PAGES];
        let mut storage = FreeFrameIndex::EMPTY;
        let mut plain = FramePool::from_memory(&ram, &[], &mut meta_a).unwrap();
        let mut indexed = FramePool::from_memory(&ram, &[], &mut meta_b).unwrap();
        indexed.attach_free_index(&mut storage).unwrap();
        let owner = TaskId::new(1).unwrap();
        let mut zero = ToggleZero(false);
        let mut handles = Vec::with_capacity(PAGES);
        for _ in 0..PAGES {
            let a = plain.alloc_zeroed(owner, &mut zero).unwrap();
            let b = indexed.alloc_zeroed(owner, &mut zero).unwrap();
            assert_eq!(a, b);
            handles.push(a);
        }
        assert_eq!(indexed.alloc_zeroed(owner, &mut zero), Err(FrameError::Exhausted));
        for _ in 0..8 {
            let h = handles[PAGES - 1];
            for pool in [&mut plain, &mut indexed] {
                pool.begin_revoke(h, owner).unwrap();
                assert_eq!(pool.alloc_zeroed(owner, &mut zero), Err(FrameError::Again));
                pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
                    .unwrap();
            }
            let a = plain.alloc_zeroed(owner, &mut zero).unwrap();
            let b = indexed.alloc_zeroed(owner, &mut zero).unwrap();
            assert_eq!(a, b);
            assert_eq!(a.index(), PAGES - 1);
            handles[PAGES - 1] = a;
        }
        // Odd multiplier is a permutation mod 65536. Exercise dispersed
        // holes and wrap at approximately 99% and 95% occupancy.
        for holes in [PAGES / 100, PAGES / 20] {
            for i in 0..holes {
                let h = handles[(i * 40503 + 63) % PAGES];
                for pool in [&mut plain, &mut indexed] {
                    pool.begin_revoke(h, owner).unwrap();
                    pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
                        .unwrap();
                }
            }
            assert_eq!(plain.snapshot(), indexed.snapshot());
            for _ in 0..holes {
                let a = plain.alloc_zeroed(owner, &mut zero).unwrap();
                let b = indexed.alloc_zeroed(owner, &mut zero).unwrap();
                assert_eq!(a, b);
                handles[a.index()] = a;
            }
            assert_eq!(plain.snapshot(), indexed.snapshot());
        }
    }

    #[test]
    fn indexed_word_group_and_wrap_boundaries() {
        let mut index = FreeFrameIndex::EMPTY;
        for i in [0, 63, 64, 4095, 4096, 65535] {
            index.set(i, true);
        }
        for (start, expected) in [
            (0, Some(0)),
            (1, Some(63)),
            (63, Some(63)),
            (64, Some(64)),
            (65, Some(4095)),
            (4096, Some(4096)),
            (4097, Some(65535)),
            (65535, Some(65535)),
            (65536, None),
        ] {
            assert_eq!(index.next_at_or_after(start), expected);
        }
        for i in [63, 64, 4095, 4096, 65535, 0] {
            index.set(i, false);
        }
        assert_eq!(index.next_at_or_after(0), None);
        assert_eq!(index.top, 0);
    }

    #[test]
    fn indexed_failures_retirement_and_clean_path_keep_exact_availability() {
        let owner = TaskId::new(1).unwrap();
        let mut metadata = [
            FrameMeta {
                address: PhysAddr(0x1000),
                generation: u64::MAX,
                owner: None,
                state: State::Dirty,
            },
            FrameMeta {
                address: PhysAddr(0x2000),
                generation: 0,
                owner: None,
                state: State::Dirty,
            },
            FrameMeta {
                address: PhysAddr(0x3000),
                generation: 0,
                owner: None,
                state: State::Reserved,
            },
        ];
        let mut storage = FreeFrameIndex::EMPTY;
        let mock = MockRecorder::new();
        let mut pool = FramePool {
            meta: &mut metadata,
            capacity: 2,
            free: 2,
            next_zeroed: 0,
            next_clean: 0,
            next_dirty: 0,
            recorder: None,
            free_index: None,
        };
        pool.attach_free_index(&mut storage).unwrap();
        pool.attach_recorder(&mock);
        mock.fail_on.set(Some("retired"));
        assert_eq!(pool.alloc_zeroed(owner, &mut NoZero), Err(FrameError::Ledger));
        assert_eq!(pool.snapshot().free, 2);
        mock.fail_on.set(None);
        assert_eq!(pool.alloc_zeroed(owner, &mut ToggleZero(true)), Err(FrameError::ZeroFailed));
        assert_eq!(pool.snapshot().free, 1);
        mock.fail_on.set(Some("alloc"));
        assert_eq!(pool.alloc_zeroed(owner, &mut ToggleZero(false)), Err(FrameError::Ledger));
        assert_eq!(pool.snapshot().free, 1);
        mock.fail_on.set(None);
        assert!(pool.clean_one(&mut ToggleZero(false)).unwrap());
        let h = pool.alloc_clean(owner).unwrap();
        assert_eq!(h.index(), 1);
        assert_eq!(pool.alloc_zeroed(owner, &mut NoZero), Err(FrameError::Exhausted));
        mock.fail_on.set(Some("begin_revoke"));
        assert_eq!(pool.begin_revoke(h, owner), Err(FrameError::Ledger));
        assert_eq!(pool.alloc_zeroed(owner, &mut NoZero), Err(FrameError::Exhausted));
        mock.fail_on.set(None);
        pool.begin_revoke(h, owner).unwrap();
        mock.fail_on.set(Some("finish_revoke"));
        assert_eq!(
            pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) }),
            Err(FrameError::Ledger)
        );
        assert_eq!(pool.alloc_zeroed(owner, &mut NoZero), Err(FrameError::Again));
        mock.fail_on.set(None);
        pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        let reused = pool.alloc_zeroed(owner, &mut ToggleZero(false)).unwrap();
        assert_eq!(reused.index(), 1);
        assert_eq!(reused.generation, h.generation + 1);
        assert_eq!(pool.snapshot().capacity, 1);
        assert_eq!(pool.snapshot().free, 0);
    }

    #[test]
    fn attached_recorder_preserves_default_selection_and_accounting() {
        let ram = [MemoryRegion {
            start: PhysAddr(0x1000),
            len: 3 * 4096,
            kind: RegionKind::Ram,
        }];
        let mut meta_a = [FrameMeta::EMPTY; 3];
        let mut meta_b = [FrameMeta::EMPTY; 3];
        let mut plain = FramePool::from_memory(&ram, &[], &mut meta_a).unwrap();
        let mut mirrored = FramePool::from_memory(&ram, &[], &mut meta_b).unwrap();
        let mock = MockRecorder::new();
        mirrored.attach_recorder(&mock);
        let owner = TaskId::new(1).unwrap();
        let mut zero = ToggleZero(false);
        let mut handles = Vec::new();
        for _ in 0..3 {
            let a = plain.alloc_zeroed(owner, &mut zero).unwrap();
            let b = mirrored.alloc_zeroed(owner, &mut zero).unwrap();
            assert_eq!((a.index(), a.address()), (b.index(), b.address()));
            assert_eq!(plain.snapshot(), mirrored.snapshot());
            handles.push(b);
        }
        assert_eq!(
            plain.alloc_zeroed(owner, &mut zero),
            mirrored.alloc_zeroed(owner, &mut zero)
        );
        // Revoke the middle frame on both pools; selection and accounting
        // must stay identical with a faithfully mirroring recorder attached.
        let h = handles[1];
        plain.begin_revoke(h, owner).unwrap();
        mirrored.begin_revoke(h, owner).unwrap();
        plain
            .finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        mirrored
            .finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        assert_eq!(plain.snapshot(), mirrored.snapshot());
        assert!(plain.clean_one(&mut zero).unwrap());
        assert!(mirrored.clean_one(&mut zero).unwrap());
        let a = plain.alloc_clean(owner).unwrap();
        let b = mirrored.alloc_clean(owner).unwrap();
        assert_eq!((a.index(), a.address()), (b.index(), b.address()));
        assert_eq!(plain.snapshot(), mirrored.snapshot());
    }
}
