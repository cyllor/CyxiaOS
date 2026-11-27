use super::{Error, FrameMeta, Ledger, NONE, Owner, PAGE, PERMANENT, StaticClass};
use core::ops::Range;

impl FrameMeta {
    pub(super) fn is_static_dma(&self) -> bool {
        self.flags == PERMANENT
            && self.owner_slot != NONE
            && self.owner_generation != 0
            && self.frame_generation == 1
            && self.pin_count == 1
            && self.dma_inflight == 1
            && self.refcnt == 0
            && self.share_count == 0
    }
}

impl Ledger<'_> {
    /// Assign the exact, permanently reserved queue pages to one device
    /// generation before it can observe their addresses. The DMA reference
    /// accounts for the queue's permanently assigned aperture. The queue
    /// separately accounts for descriptors and reuses them after completion.
    pub fn claim_static_dma(&mut self, span: Range<u64>, owner: Owner) -> Result<(), Error> {
        if !owner.valid() {
            return Err(Error::Unauthorized);
        }
        if !span.start.is_multiple_of(PAGE)
            || !span.end.is_multiple_of(PAGE)
            || span.start >= span.end
        {
            return Err(Error::Invalid);
        }
        if !self.statically_pinned(span.clone(), StaticClass::Arena) {
            return Err(Error::Conflict);
        }
        let first = ((span.start - self.base) / PAGE) as usize;
        let last = ((span.end - self.base) / PAGE) as usize;
        let rows = &mut self.rows[first..last];
        if rows
            .iter()
            .any(|row| *row != FrameMeta::unowned(PERMANENT, 0))
        {
            return Err(Error::Conflict);
        }
        rows.fill(FrameMeta {
            owner_slot: owner.slot,
            flags: PERMANENT,
            owner_generation: owner.generation,
            frame_generation: 1,
            pin_count: 1,
            dma_inflight: 1,
            ..FrameMeta::ZERO
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_meta_v0199::{Handle, Reference, StaticRegion};
    use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};

    const BASE: u64 = 0x4000_0000;
    const NET_RX: Owner = Owner {
        slot: 0x8000_0000,
        generation: 1,
    };
    const NET_TX: Owner = Owner {
        slot: 0x8000_0001,
        generation: 1,
    };

    #[test]
    fn reserved_dma_ownership_excludes_overlap_and_survives_release_attempt() {
        let mut rows = [FrameMeta::ZERO; 6];
        let regions = [
            StaticRegion {
                region: MemoryRegion {
                    start: PhysAddr(BASE),
                    len: 4 * PAGE,
                    kind: RegionKind::Reserved,
                },
                class: StaticClass::Arena,
            },
            StaticRegion {
                region: MemoryRegion {
                    start: PhysAddr(BASE + 5 * PAGE),
                    len: PAGE,
                    kind: RegionKind::Reserved,
                },
                class: StaticClass::Metadata,
            },
        ];
        let mut ledger = Ledger::initialize_static_sparse(&mut rows, BASE, &regions).unwrap();
        let before = ledger.inventory().unwrap();
        let rx = BASE..BASE + 2 * PAGE;
        assert_eq!(ledger.claim_static_dma(rx.clone(), NET_RX), Ok(()));
        assert!(ledger.statically_pinned(rx.clone(), StaticClass::Arena));
        assert_eq!(ledger.claim_static_dma(rx, NET_RX), Err(Error::Conflict));
        assert_eq!(
            ledger.claim_static_dma(BASE + PAGE..BASE + 3 * PAGE, NET_TX),
            Err(Error::Conflict)
        );
        assert_eq!(
            ledger.claim_static_dma(BASE + 2 * PAGE..BASE + 4 * PAGE, NET_TX),
            Ok(())
        );
        for span in [
            BASE + 4 * PAGE..BASE + 5 * PAGE,
            BASE + 5 * PAGE..BASE + 6 * PAGE,
        ] {
            assert_eq!(ledger.claim_static_dma(span, NET_TX), Err(Error::Conflict));
        }
        let first = Handle {
            index: 0,
            generation: 1,
            owner: NET_RX,
        };
        assert_eq!(
            ledger.release_ref(first, Reference::Dma, |_| Ok(())),
            Err(Error::Busy)
        );
        assert_eq!(ledger.quarantine(first), Err(Error::Busy));
        assert_eq!(ledger.reclaim(first, |_| Ok(())), Err(Error::Busy));
        assert_eq!(ledger.inventory().unwrap(), before);
        for (row, owner) in ledger.rows[..4]
            .iter()
            .zip([NET_RX, NET_RX, NET_TX, NET_TX])
        {
            assert!(row.is_static_dma());
            assert_eq!(
                (row.owner_slot, row.owner_generation),
                (owner.slot, owner.generation)
            );
        }
    }
}
