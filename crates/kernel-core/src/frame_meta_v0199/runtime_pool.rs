//! Exact-address accounting for a runtime whose allocator chooses the frame.
//! The task owner gate serializes both the allocator and this FrameMeta view.

use super::{
    ALLOCATED, DIRTY, Error, FREE, FrameMeta, Handle, Ledger, MemoryRegion, NONE, Owner, PAGE,
    PhysAddr, QUARANTINED, RegionKind,
};

pub struct RuntimePool<'a>(Ledger<'a>);

#[must_use = "the copy window must be revoked before returning this pin"]
pub struct Pin {
    base: u64,
    handle: Handle,
}

impl<'a> RuntimePool<'a> {
    pub fn initialize(
        rows: &'a mut [FrameMeta],
        base: u64,
        permanent_pages: usize,
    ) -> Result<Self, Error> {
        if permanent_pages == 0 || permanent_pages >= rows.len() {
            return Err(Error::Invalid);
        }
        let region = |pages: usize, kind: RegionKind| -> Result<MemoryRegion, Error> {
            let len = u64::try_from(pages)
                .ok()
                .and_then(|pages| pages.checked_mul(PAGE))
                .ok_or(Error::Invalid)?;
            Ok(MemoryRegion {
                start: PhysAddr(base),
                len,
                kind,
            })
        };
        let ram = region(rows.len(), RegionKind::Ram)?;
        let reserved = region(permanent_pages, RegionKind::Reserved)?;
        Ledger::initialize_pool(rows, base, &[ram], &[reserved]).map(Self)
    }

    /// Record one mapping of an exact frame cleared by the runtime. The
    /// caller checks the PTE and its permissions before entering this call.
    /// `publish` installs that PTE and completes its architecture barriers.
    pub fn map_zeroed(
        &mut self,
        address: u64,
        owner: Owner,
        publish: impl FnOnce(),
    ) -> Result<(), Error> {
        let generation = self
            .0
            .pool_row(address)?
            .frame_generation
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        self.0.record_alloc(address, owner, generation)?.refcnt = 1;
        publish();
        Ok(())
    }

    /// Pin an already checked live mapping. The returned handle carries both
    /// the task generation and the frame generation, even across slot reuse.
    pub fn pin(&mut self, address: u64, owner: Owner) -> Result<Pin, Error> {
        let base = self.0.base;
        let row = self.0.pool_row(address)?;
        if !owner.valid() {
            return Err(Error::Unauthorized);
        }
        if row.owner_slot != owner.slot || row.owner_generation != owner.generation {
            return Err(Error::Stale);
        }
        if row.flags != ALLOCATED || row.refcnt != 1 {
            return Err(Error::Busy);
        }
        row.pin_count = row.pin_count.checked_add(1).ok_or(Error::Capacity)?;
        Ok(Pin {
            base,
            handle: Handle {
                index: ((address - base) / PAGE) as u32,
                generation: row.frame_generation,
                owner,
            },
        })
    }

    /// The copy window owner must finish its local invalidation first.
    pub fn unpin(&mut self, pin: Pin) -> Result<(), Error> {
        if pin.base != self.0.base {
            return Err(Error::Stale);
        }
        let row = self.0.row(pin.handle)?;
        if row.flags != ALLOCATED || row.refcnt != 1 {
            return Err(Error::Busy);
        }
        row.pin_count = row.pin_count.checked_sub(1).ok_or(Error::Conflict)?;
        Ok(())
    }

    /// Fence the exact page while the runtime removes the PTE and completes
    /// TLBI. A failed teardown retains the mapping reference and owner for
    /// a later retry. `unmap(false)` may only verify an already absent
    /// mapping. Completed revocation leaves the row dirty until a later
    /// allocation supplies a cleared page.
    pub fn revoke(
        &mut self,
        address: u64,
        owner: Owner,
        unmap: impl FnOnce(bool) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let row = self.0.pool_row(address)?;
        if !owner.valid() {
            return Err(Error::Unauthorized);
        }
        if row.owner_slot == NONE
            && row.owner_generation == 0
            && row.empty_refs()
            && (row.flags == FREE || row.flags == FREE | DIRTY || row.flags == QUARANTINED | DIRTY)
        {
            return unmap(false);
        }
        if row.owner_slot != owner.slot || row.owner_generation != owner.generation {
            return Err(Error::Stale);
        }
        if !matches!(row.flags, ALLOCATED | QUARANTINED) || !row.only_mapping_refs(1) {
            return Err(Error::Busy);
        }
        row.flags = QUARANTINED;
        unmap(true)?;
        row.refcnt = 0;
        self.0.record_finish_revoke(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pin_blocks_revoke_and_cannot_release_a_reused_page() {
        let base = 0x4400_0000;
        let address = base + PAGE;
        let mut rows = [FrameMeta::ZERO; 3];
        let mut pool = RuntimePool::initialize(&mut rows, base, 1).unwrap();
        let owner = Owner {
            slot: 7,
            generation: 1,
        };
        let successor = Owner {
            slot: 7,
            generation: 2,
        };
        assert_eq!(pool.map_zeroed(base, owner, || panic!()), Err(Error::Busy));
        let mut published = false;
        pool.map_zeroed(address, owner, || published = true)
            .unwrap();
        assert!(published);
        assert_eq!(
            pool.map_zeroed(address, owner, || panic!()),
            Err(Error::Busy)
        );
        assert_eq!(pool.0.pool_row(address).unwrap().refcnt, 1);
        assert_eq!(pool.pin(address, successor).err(), Some(Error::Stale));
        let old = pool.pin(address, owner).unwrap();
        let simultaneous = pool.pin(address, owner).unwrap();
        let old_identity = old.handle;
        assert_eq!(pool.revoke(address, owner, |_| panic!()), Err(Error::Busy));
        pool.unpin(old).unwrap();
        assert_eq!(pool.revoke(address, owner, |_| panic!()), Err(Error::Busy));
        pool.unpin(simultaneous).unwrap();
        pool.revoke(address, owner, |owned| {
            assert!(owned);
            Ok(())
        })
        .unwrap();
        pool.map_zeroed(address, owner, || {}).unwrap();
        let next = pool.pin(address, owner).unwrap();
        assert_ne!(old_identity.generation(), next.handle.generation());
        assert_eq!(
            pool.unpin(Pin {
                base,
                handle: old_identity,
            }),
            Err(Error::Stale)
        );
        pool.unpin(next).unwrap();
    }

    #[test]
    fn a_pin_cannot_release_a_different_physical_pool() {
        let base = 0x4400_0000;
        let other_base = base + 2 * PAGE;
        let mut rows = [FrameMeta::ZERO; 2];
        let mut other_rows = [FrameMeta::ZERO; 2];
        let mut pool = RuntimePool::initialize(&mut rows, base, 1).unwrap();
        let mut other = RuntimePool::initialize(&mut other_rows, other_base, 1).unwrap();
        let owner = Owner {
            slot: 7,
            generation: 1,
        };
        pool.map_zeroed(base + PAGE, owner, || {}).unwrap();
        other.map_zeroed(other_base + PAGE, owner, || {}).unwrap();
        let pin = pool.pin(base + PAGE, owner).unwrap();
        let other_pin = other.pin(other_base + PAGE, owner).unwrap();
        assert_eq!(pin.handle, other_pin.handle);
        assert_eq!(
            pool.unpin(Pin {
                base: other_pin.base,
                handle: other_pin.handle,
            }),
            Err(Error::Stale)
        );
        pool.unpin(pin).unwrap();
        other.unpin(other_pin).unwrap();
    }

    #[test]
    fn uncertain_unmap_retains_custody_until_a_retry_proves_absence() {
        let base = 0x4400_0000;
        let address = base + PAGE;
        let mut rows = [FrameMeta::ZERO; 2];
        let mut pool = RuntimePool::initialize(&mut rows, base, 1).unwrap();
        let owner = Owner {
            slot: 7,
            generation: 1,
        };
        pool.map_zeroed(address, owner, || {}).unwrap();
        assert_eq!(
            pool.revoke(address, owner, |_| Err(Error::Unknown)),
            Err(Error::Unknown)
        );
        let blocked = *pool.0.pool_row(address).unwrap();
        assert_eq!(blocked.refcnt, 1);
        assert_eq!(blocked.flags, QUARANTINED);
        assert_eq!(blocked.owner_generation, owner.generation);
        assert_eq!(pool.pin(address, owner).err(), Some(Error::Busy));
        assert_eq!(
            pool.map_zeroed(address, owner, || panic!()),
            Err(Error::Busy)
        );
        pool.revoke(address, owner, |owned| {
            assert!(owned);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            *pool.0.pool_row(address).unwrap(),
            FrameMeta::unowned(QUARANTINED | DIRTY, blocked.frame_generation)
        );
        assert_eq!(
            pool.revoke(address, owner, |owned| {
                assert!(!owned);
                Err(Error::Conflict)
            }),
            Err(Error::Conflict)
        );
    }
}
