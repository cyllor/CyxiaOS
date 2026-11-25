//! V0.19.9 1GiB RAM total ledger: exactly 262144 x 40-byte FrameMeta.
//! This is separate from the historical <=256MiB FramePool. All ranges
//! are physical, fixed and checked before initialization; the table itself
//! is a separately reserved 10MiB object. Pool suballocations and actual
//! mappings remain independently protected owner responsibilities.
use crate::security::Error;
use cyxia_contracts::{MemoryRegion, RegionKind};
pub const PAGE: u64 = 4096;
pub const COUNT: usize = 262144;
pub const RAM_BYTES: u64 = COUNT as u64 * PAGE;
pub const TABLE_BYTES: usize = COUNT * 40;
pub const POOL_BYTES: u64 = 8 * 1024 * 1024;
const NONE: u32 = u32::MAX;
const STATE: u32 = 7;
const FREE: u32 = 0;
const RESERVED: u32 = 1;
const ALLOCATED: u32 = 2;
const QUARANTINED: u32 = 3;
const PERMANENT: u32 = 4;
const DIRTY: u32 = 8;
const SECRET: u32 = 16;
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMeta {
    owner_slot: u32,
    flags: u32,
    owner_generation: u64,
    frame_generation: u64,
    refcnt: u32,
    pin_count: u32,
    dma_inflight: u32,
    share_count: u32,
}
const _: () =
    assert!(core::mem::size_of::<FrameMeta>() == 40 && core::mem::align_of::<FrameMeta>() == 8);
const _: () = assert!(TABLE_BYTES == 10 * 1024 * 1024);
impl FrameMeta {
    // Initialized backing, NOT a published frame state.
    pub const ZERO: Self = Self {
        owner_slot: 0,
        flags: 0,
        owner_generation: 0,
        frame_generation: 0,
        refcnt: 0,
        pin_count: 0,
        dma_inflight: 0,
        share_count: 0,
    };
    const fn unowned(state: u32, generation: u64) -> Self {
        Self {
            owner_slot: NONE,
            flags: state,
            owner_generation: 0,
            frame_generation: generation,
            refcnt: 0,
            pin_count: 0,
            dma_inflight: 0,
            share_count: 0,
        }
    }
    fn empty_refs(self) -> bool {
        self.refcnt == 0 && self.pin_count == 0 && self.dma_inflight == 0 && self.share_count == 0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Owner {
    pub slot: u32,
    pub generation: u64,
}
impl Owner {
    fn valid(self) -> bool {
        self.slot != NONE && self.generation != 0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    index: u32,
    generation: u64,
    owner: Owner,
}
impl Handle {
    pub fn index(self) -> u32 {
        self.index
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reference {
    Mapping,
    Pin,
    Dma,
    Share,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inventory {
    pub free: u32,
    pub reserved: u32,
    pub allocated: u32,
    pub quarantined: u32,
    pub permanent: u32,
    pub arena: u32,
    pub firmware_extra: u32,
    pub metadata: u32,
    pub control: u32,
    pub progress: u32,
}
pub struct Ledger<'a> {
    base: u64,
    rows: &'a mut [FrameMeta],
    arena: u32,
    firmware_extra: u32,
    fixed: [MemoryRegion; 4],
    fixed_total: u32,
}
fn span(r: MemoryRegion, base: u64) -> Result<(usize, usize), Error> {
    let end = r.end().map_err(|_| Error::Invalid)?;
    if r.len == 0
        || !r.start.0.is_multiple_of(PAGE)
        || !r.len.is_multiple_of(PAGE)
        || r.start.0 < base
        || end > base.checked_add(RAM_BYTES).ok_or(Error::Invalid)?
    {
        return Err(Error::Invalid);
    }
    Ok((
        ((r.start.0 - base) / PAGE) as usize,
        ((end - base) / PAGE) as usize,
    ))
}
impl<'a> Ledger<'a> {
    /// fixed = actual pinned boot/kernel/DMA arena, FrameMeta table,
    /// control pool, progress pool. Ranges must be disjoint. Firmware
    /// reservations are rounded outward and counted as a union; they
    /// must not overlap any separately reserved pool/table.
    pub fn initialize(
        rows: &'a mut [FrameMeta],
        ram: MemoryRegion,
        fixed: [MemoryRegion; 4],
        firmware: &[MemoryRegion],
    ) -> Result<Self, Error> {
        let base = ram.start.0;
        if rows.len() != COUNT
            || ram.kind != RegionKind::Ram
            || ram.len != RAM_BYTES
            || !base.is_multiple_of(PAGE)
            || base.checked_add(RAM_BYTES).is_none()
            || firmware.len() > 32
            || fixed[1].len != TABLE_BYTES as u64
            || fixed[2].len != POOL_BYTES
            || fixed[3].len != POOL_BYTES
        {
            return Err(Error::Invalid);
        }
        for (i, r) in fixed.iter().enumerate() {
            span(*r, base)?;
            if r.kind != RegionKind::Reserved || fixed[..i].iter().any(|p| p.overlaps(*r)) {
                return Err(Error::Conflict);
            }
        }
        for r in firmware {
            let end = r.end().map_err(|_| Error::Invalid)?;
            if r.len == 0 || end.checked_add(PAGE - 1).is_none() {
                return Err(Error::Invalid);
            }
            let aligned = MemoryRegion {
                start: cyxia_contracts::PhysAddr(r.start.0 & !(PAGE - 1)),
                len: ((end + PAGE - 1) & !(PAGE - 1)) - (r.start.0 & !(PAGE - 1)),
                kind: RegionKind::Reserved,
            };
            if fixed[1..].iter().any(|p| p.overlaps(aligned)) {
                return Err(Error::Conflict);
            }
        }
        if rows.iter().any(|r| *r != FrameMeta::ZERO) {
            return Err(Error::Busy);
        }
        rows.fill(FrameMeta::unowned(FREE | DIRTY, 0));
        let mut total = 0u32;
        for r in fixed {
            let (a, b) = span(r, base)?;
            rows[a..b].fill(FrameMeta::unowned(PERMANENT, 0));
            total = total.checked_add((b - a) as u32).ok_or(Error::Capacity)?;
        }
        let mut firmware_extra = 0u32;
        for r in firmware {
            let end = r.end().map_err(|_| Error::Invalid)?;
            let a = (r.start.0 & !(PAGE - 1)).max(base);
            let b = ((end + PAGE - 1) & !(PAGE - 1)).min(base + RAM_BYTES);
            if a >= b {
                continue;
            }
            for row in &mut rows[((a - base) / PAGE) as usize..((b - base) / PAGE) as usize] {
                if row.flags != PERMANENT {
                    *row = FrameMeta::unowned(PERMANENT, 0);
                    firmware_extra += 1;
                }
            }
        }
        let arena = (fixed[0].len / PAGE) as u32;
        let l = Self {
            base,
            rows,
            arena,
            firmware_extra,
            fixed,
            fixed_total: total + firmware_extra,
        };
        l.inventory()?;
        Ok(l)
    }
    pub fn inventory(&self) -> Result<Inventory, Error> {
        let mut counts = [0u32; 5];
        for r in self.rows.iter() {
            let state = r.flags & STATE;
            if r.flags & !(STATE | DIRTY | SECRET) != 0 || state > PERMANENT {
                return Err(Error::Conflict);
            }
            if state == FREE || state == PERMANENT {
                if r.owner_slot != NONE
                    || r.owner_generation != 0
                    || !r.empty_refs()
                    || r.flags & SECRET != 0
                    || state == PERMANENT && r.flags != PERMANENT
                {
                    return Err(Error::Conflict);
                }
            } else if r.owner_slot == NONE || r.owner_generation == 0 || r.frame_generation == 0 {
                return Err(Error::Conflict);
            }
            counts[state as usize] += 1;
        }
        for r in self.fixed {
            let (a, b) = span(r, self.base)?;
            if self.rows[a..b].iter().any(|r| r.flags != PERMANENT) {
                return Err(Error::Conflict);
            }
        }
        if counts.iter().sum::<u32>() != COUNT as u32 || counts[4] < self.fixed_total {
            return Err(Error::Conflict);
        }
        Ok(Inventory {
            free: counts[0],
            reserved: counts[1],
            allocated: counts[2],
            quarantined: counts[3],
            permanent: counts[4],
            arena: self.arena,
            firmware_extra: self.firmware_extra,
            metadata: (TABLE_BYTES as u64 / PAGE) as u32,
            control: (POOL_BYTES / PAGE) as u32,
            progress: (POOL_BYTES / PAGE) as u32,
        })
    }
    fn row(&mut self, h: Handle) -> Result<&mut FrameMeta, Error> {
        let r = self.rows.get_mut(h.index as usize).ok_or(Error::Invalid)?;
        if r.owner_slot != h.owner.slot
            || r.owner_generation != h.owner.generation
            || r.frame_generation != h.generation
        {
            return Err(Error::Stale);
        }
        Ok(r)
    }
    pub fn address(&self, h: Handle) -> u64 {
        self.base + u64::from(h.index) * PAGE
    }
    /// COMMIT_RESERVE: reserve one actual free physical frame. A generation
    /// that cannot advance is retired permanently, never wrapped.
    pub fn reserve(&mut self, owner: Owner) -> Result<Handle, Error> {
        if !owner.valid() {
            return Err(Error::Unauthorized);
        }
        for (i, r) in self.rows.iter_mut().enumerate() {
            if r.flags & STATE != FREE {
                continue;
            }
            let Some(next) = r.frame_generation.checked_add(1) else {
                *r = FrameMeta::unowned(PERMANENT, r.frame_generation);
                continue;
            };
            *r = FrameMeta {
                owner_slot: owner.slot,
                owner_generation: owner.generation,
                frame_generation: next,
                flags: RESERVED | DIRTY,
                ..FrameMeta::ZERO
            };
            return Ok(Handle {
                index: i as u32,
                generation: next,
                owner,
            });
        }
        Err(Error::Capacity)
    }
    /// The native owner zeroes the exclusive actual page before it can
    /// become mapped. Failed clearing is quarantined, not returned free.
    pub fn commit(
        &mut self,
        h: Handle,
        secret: bool,
        zero: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pa = self.address(h);
        let r = self.row(h)?;
        if r.flags & STATE != RESERVED || !r.empty_refs() {
            return Err(Error::Busy);
        }
        if let Err(e) = zero(pa) {
            r.flags = QUARANTINED | DIRTY | if secret { SECRET } else { 0 };
            return Err(e);
        }
        r.flags = ALLOCATED | if secret { SECRET } else { 0 };
        Ok(())
    }
    fn counter(r: &mut FrameMeta, kind: Reference) -> &mut u32 {
        match kind {
            Reference::Mapping => &mut r.refcnt,
            Reference::Pin => &mut r.pin_count,
            Reference::Dma => &mut r.dma_inflight,
            Reference::Share => &mut r.share_count,
        }
    }
    pub fn retain(
        &mut self,
        h: Handle,
        kind: Reference,
        verify: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pa = self.address(h);
        let r = self.row(h)?;
        if r.flags & STATE != ALLOCATED {
            return Err(Error::Busy);
        }
        let c = Self::counter(r, kind);
        let n = c.checked_add(1).ok_or(Error::Capacity)?;
        verify(pa)?;
        *c = n;
        Ok(())
    }
    pub fn release_ref(
        &mut self,
        h: Handle,
        kind: Reference,
        verify: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pa = self.address(h);
        let r = self.row(h)?;
        if !matches!(r.flags & STATE, ALLOCATED | QUARANTINED) {
            return Err(Error::Busy);
        }
        let c = Self::counter(r, kind);
        let n = c.checked_sub(1).ok_or(Error::Conflict)?;
        verify(pa)?;
        *c = n;
        Ok(())
    }
    pub fn quarantine(&mut self, h: Handle) -> Result<(), Error> {
        let r = self.row(h)?;
        if !matches!(r.flags & STATE, ALLOCATED | RESERVED) {
            return Err(Error::Busy);
        }
        r.flags = (r.flags & SECRET) | DIRTY | QUARANTINED;
        Ok(())
    }
    /// Independent unmap/TLBI/DMA drain and explicit zero proof. Any
    /// unresolved reference or error leaves the old owner fenced.
    pub fn reclaim(
        &mut self,
        h: Handle,
        verify_and_zero: impl FnOnce(u64) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let pa = self.address(h);
        let r = self.row(h)?;
        if r.flags & STATE != QUARANTINED || !r.empty_refs() {
            return Err(Error::Busy);
        }
        verify_and_zero(pa)?;
        *r = FrameMeta::unowned(FREE, h.generation);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use cyxia_contracts::PhysAddr;
    fn region(offset: u64, len: u64) -> MemoryRegion {
        MemoryRegion {
            start: PhysAddr(0x40000000 + offset),
            len,
            kind: RegionKind::Reserved,
        }
    }
    #[test]
    fn exact_layout_and_full_1g_conservation_with_retained_dma() {
        let mut rows = std::vec![FrameMeta::ZERO;COUNT];
        let ram = MemoryRegion {
            kind: RegionKind::Ram,
            ..region(0, RAM_BYTES)
        };
        let fixed = [
            region(0, 64 * 1024 * 1024),
            region(64 * 1024 * 1024, TABLE_BYTES as u64),
            region(74 * 1024 * 1024, POOL_BYTES),
            region(82 * 1024 * 1024, POOL_BYTES),
        ];
        let fw = [
            region(96 * 1024 * 1024, 4096),
            region(96 * 1024 * 1024, 4096),
        ];
        let mut l = Ledger::initialize(&mut rows, ram, fixed, &fw).unwrap();
        let before = l.inventory().unwrap();
        assert_eq!(before.permanent, 16384 + 2560 + 2048 + 2048 + 1);
        let h = l
            .reserve(Owner {
                slot: 1,
                generation: 1,
            })
            .unwrap();
        l.commit(h, true, |_| Ok(())).unwrap();
        l.retain(h, Reference::Dma, |_| Ok(())).unwrap();
        l.quarantine(h).unwrap();
        assert_eq!(l.reclaim(h, |_| panic!()), Err(Error::Busy));
        assert_eq!(
            l.release_ref(h, Reference::Dma, |_| Err(Error::Unknown)),
            Err(Error::Unknown)
        );
        assert_eq!(l.inventory().unwrap().quarantined, 1);
        l.release_ref(h, Reference::Dma, |_| Ok(())).unwrap();
        assert_eq!(l.reclaim(h, |_| Err(Error::Unknown)), Err(Error::Unknown));
        l.reclaim(h, |_| Ok(())).unwrap();
        assert_eq!(l.inventory().unwrap(), before);
        let n = l
            .reserve(Owner {
                slot: 1,
                generation: 2,
            })
            .unwrap();
        assert_eq!(n.index(), h.index());
        assert_eq!(n.generation(), h.generation() + 1);
        assert_eq!(l.commit(h, false, |_| panic!()), Err(Error::Stale));
    }
}
