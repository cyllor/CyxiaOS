//! V0.19.9 1GiB RAM total ledger: exactly 262144 x 40-byte FrameMeta.
//! This is separate from the historical <=256MiB FramePool. All ranges
//! are physical, fixed and checked before initialization; the table itself
//! is a separately reserved 10MiB object. Pool suballocations and actual
//! mappings remain independently protected owner responsibilities.
//!
//! Bounded static path: `initialize_static` registers statically backed,
//! physically contiguous permanent regions (e.g. the native control pool
//! backing) into an existing caller-provided FrameMeta table. Registered
//! pages become unowned PERMANENT rows, so ordinary reservation can never
//! hand them out and no lifecycle operation can reclaim them. The static
//! table must stay within the design's 10MiB global FrameMeta reservation
//! (at most COUNT rows); it is an additional authoritative record, not a
//! replacement for the full-RAM ledger or for pool suballocation ledgers.
//!
//! Bounded pool-accounting path: `initialize_pool` mirrors a historical
//! `frames::FramePool` geometry into a table, and `PoolBridge` implements
//! `frames::FrameRecorder` so pool allocations/frees are RECORDED here with
//! owner/generation (alloc -> ALLOCATED, revoke -> QUARANTINED, free -> FREE
//! only after an explicit zero proof, failed zeroing -> QUARANTINED|DIRTY,
//! generation exhaustion -> PERMANENT). This is an accounting mirror, not a
//! replacement allocator: the general-allocator native cutover remains a
//! later gate, and unattached pools (including desktop boot paths) keep
//! their historical behavior bit-identically.
use crate::frames::{FrameError, FrameRecorder};
use crate::security::Error;
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind, TaskId};
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
/// Owner class of a statically registered permanent region. The class is
/// recorded on the region record, never on the row: PERMANENT rows stay
/// unowned with empty reference counters, exactly like the fixed regions
/// of the full-RAM ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticClass {
    Arena,
    Metadata,
    Control,
    Progress,
    Firmware,
}
/// A statically backed, physically contiguous permanent region registered
/// into a bounded static FrameMeta table at initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticRegion {
    pub region: MemoryRegion,
    pub class: StaticClass,
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
    // Bounded static mode: the table covers exactly `fixed_count` registered
    // permanent regions tiling the whole row window; there is no ordinary
    // free pool. Full-RAM mode keeps fixed_count == 4 and static_mode false.
    static_mode: bool,
    // Bounded pool-accounting mode: rows mirror a frames::FramePool geometry
    // and transition only through the PoolBridge recording helpers; the
    // ordinary reserve/handle lifecycle is refused.
    pool_mode: bool,
    fixed_count: usize,
    classes: [StaticClass; 4],
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
            static_mode: false,
            pool_mode: false,
            fixed_count: 4,
            classes: [StaticClass::Arena; 4],
        };
        l.inventory()?;
        Ok(l)
    }
    /// Bounded static initialization: register physically contiguous
    /// permanent regions into an existing caller-provided FrameMeta table
    /// (static backing, no heap). The regions must be disjoint, Reserved,
    /// page-aligned, inside the table window, and must exactly tile it:
    /// a static ledger accounts only registered permanent pages and never
    /// exposes an ordinary free pool. Every covered row becomes unowned
    /// PERMANENT, so `reserve` can never hand these pages out and no
    /// lifecycle operation can transition or reclaim them. The table may
    /// not exceed the design's 10MiB global FrameMeta reservation (COUNT
    /// rows). Overlaps reject with Conflict; any other violation rejects
    /// before a row is published.
    pub fn initialize_static(
        rows: &'a mut [FrameMeta],
        base: u64,
        regions: &[StaticRegion],
    ) -> Result<Self, Error> {
        let window = (rows.len() as u64)
            .checked_mul(PAGE)
            .ok_or(Error::Invalid)?;
        if rows.is_empty()
            || rows.len() > COUNT
            || !base.is_multiple_of(PAGE)
            || base.checked_add(window).is_none()
            || regions.is_empty()
            || regions.len() > 4
        {
            return Err(Error::Invalid);
        }
        let mut fixed = [MemoryRegion::EMPTY; 4];
        let mut classes = [StaticClass::Arena; 4];
        let mut total = 0u32;
        for (i, sr) in regions.iter().enumerate() {
            let r = sr.region;
            let end = r.end().map_err(|_| Error::Invalid)?;
            if r.len == 0
                || !r.start.0.is_multiple_of(PAGE)
                || !r.len.is_multiple_of(PAGE)
                || r.start.0 < base
                || end > base + window
                || r.kind != RegionKind::Reserved
            {
                return Err(Error::Invalid);
            }
            if fixed[..i].iter().any(|p| p.overlaps(r)) {
                return Err(Error::Conflict);
            }
            fixed[i] = r;
            classes[i] = sr.class;
            total = total
                .checked_add((r.len / PAGE) as u32)
                .ok_or(Error::Capacity)?;
        }
        if total as usize != rows.len() {
            return Err(Error::Invalid);
        }
        if rows.iter().any(|r| *r != FrameMeta::ZERO) {
            return Err(Error::Busy);
        }
        for r in fixed[..regions.len()].iter() {
            let a = ((r.start.0 - base) / PAGE) as usize;
            let b = ((r.end().map_err(|_| Error::Invalid)? - base) / PAGE) as usize;
            rows[a..b].fill(FrameMeta::unowned(PERMANENT, 0));
        }
        let l = Self {
            base,
            rows,
            arena: 0,
            firmware_extra: 0,
            fixed,
            fixed_total: total,
            static_mode: true,
            pool_mode: false,
            fixed_count: regions.len(),
            classes,
        };
        l.inventory()?;
        Ok(l)
    }
    /// Bounded pool-accounting initialization: mirror a historical
    /// [`crate::frames::FramePool`] geometry into a FrameMeta table so pool
    /// transitions can be recorded through [`PoolBridge`]. RAM pages the
    /// pool would admit become unowned FREE|DIRTY rows; reserved exclusions
    /// and window gaps become unowned PERMANENT rows. Admission limits
    /// mirror the pool (<=8 RAM regions, <=32 reservations, <=65536 RAM
    /// pages, at most COUNT rows). Ordinary reserve/handle lifecycle is
    /// refused in this mode: rows transition only through the bridge, and
    /// FREE is only ever published after an explicit zero proof. This is an
    /// accounting mirror, not the general-allocator native cutover (a later
    /// gate). Any violation rejects before a row is published.
    pub fn initialize_pool(
        rows: &'a mut [FrameMeta],
        base: u64,
        ram: &[MemoryRegion],
        reserved: &[MemoryRegion],
    ) -> Result<Self, Error> {
        let window = (rows.len() as u64)
            .checked_mul(PAGE)
            .ok_or(Error::Invalid)?;
        if rows.is_empty()
            || rows.len() > COUNT
            || !base.is_multiple_of(PAGE)
            || base.checked_add(window).is_none()
            || ram.len() > 8
            || reserved.len() > 32
        {
            return Err(Error::Invalid);
        }
        let mut total = 0u32;
        for (i, r) in ram.iter().enumerate() {
            let end = r.end().map_err(|_| Error::Invalid)?;
            if r.kind != RegionKind::Ram
                || r.len == 0
                || !r.start.0.is_multiple_of(PAGE)
                || !r.len.is_multiple_of(PAGE)
                || r.start.0 < base
                || end > base + window
            {
                return Err(Error::Invalid);
            }
            if ram[..i].iter().any(|x| x.overlaps(*r)) {
                return Err(Error::Invalid);
            }
            total = total
                .checked_add((r.len / PAGE) as u32)
                .ok_or(Error::Capacity)?;
        }
        if total > 65536 {
            return Err(Error::Capacity);
        }
        for r in reserved {
            r.end().map_err(|_| Error::Invalid)?;
        }
        if rows.iter().any(|r| *r != FrameMeta::ZERO) {
            return Err(Error::Busy);
        }
        for (i, row) in rows.iter_mut().enumerate() {
            let pa = base + (i as u64) * PAGE;
            let page = MemoryRegion {
                start: PhysAddr(pa),
                len: PAGE,
                kind: RegionKind::Ram,
            };
            let in_ram = ram
                .iter()
                .any(|r| r.start.0 <= pa && pa < r.start.0 + r.len);
            let excluded = reserved.iter().any(|x| x.overlaps(page));
            *row = if in_ram && !excluded {
                FrameMeta::unowned(FREE | DIRTY, 0)
            } else {
                FrameMeta::unowned(PERMANENT, 0)
            };
        }
        let l = Self {
            base,
            rows,
            arena: 0,
            firmware_extra: 0,
            fixed: [MemoryRegion::EMPTY; 4],
            fixed_total: 0,
            static_mode: false,
            pool_mode: true,
            fixed_count: 0,
            classes: [StaticClass::Arena; 4],
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
            // Pool-mode quarantine mirrors the pool's unowned dirty pages
            // (failed zeroing or completed revocation): fenced from reuse
            // until a zero proof, with no owner and possibly generation 0.
            if state == FREE
                || state == PERMANENT
                || (self.pool_mode && state == QUARANTINED && r.owner_slot == NONE)
            {
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
        for r in self.fixed[..self.fixed_count].iter().copied() {
            let (a, b) = span(r, self.base)?;
            if self.rows[a..b].iter().any(|r| r.flags != PERMANENT) {
                return Err(Error::Conflict);
            }
        }
        if counts.iter().sum::<u32>() != self.rows.len() as u32 || counts[4] < self.fixed_total {
            return Err(Error::Conflict);
        }
        let (arena, firmware_extra, metadata, control, progress) = if self.pool_mode {
            // A pool mirror has no static class breakdown; permanent rows
            // are reserved exclusions, window gaps and retired frames.
            (0, 0, 0, 0, 0)
        } else if self.static_mode {
            let mut class_pages = [0u32; 5];
            for (i, r) in self.fixed[..self.fixed_count].iter().enumerate() {
                class_pages[self.classes[i] as usize] += (r.len / PAGE) as u32;
            }
            (
                class_pages[StaticClass::Arena as usize],
                class_pages[StaticClass::Firmware as usize],
                class_pages[StaticClass::Metadata as usize],
                class_pages[StaticClass::Control as usize],
                class_pages[StaticClass::Progress as usize],
            )
        } else {
            (
                self.arena,
                self.firmware_extra,
                (TABLE_BYTES as u64 / PAGE) as u32,
                (POOL_BYTES / PAGE) as u32,
                (POOL_BYTES / PAGE) as u32,
            )
        };
        Ok(Inventory {
            free: counts[0],
            reserved: counts[1],
            allocated: counts[2],
            quarantined: counts[3],
            permanent: counts[4],
            arena,
            firmware_extra,
            metadata,
            control,
            progress,
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
    /// that cannot advance is retired permanently, never wrapped. Bounded
    /// static and pool-accounting ledgers have no ordinary pool: registered
    /// permanent pages are never reservable, and pool-mirror rows transition
    /// only through the bridge, so reservation fails closed even before
    /// scanning.
    pub fn reserve(&mut self, owner: Owner) -> Result<Handle, Error> {
        if self.static_mode || self.pool_mode {
            return Err(Error::Capacity);
        }
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
        if self.pool_mode {
            return Err(Error::Busy);
        }
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
        if self.pool_mode {
            return Err(Error::Busy);
        }
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
        if self.pool_mode {
            return Err(Error::Busy);
        }
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
        if self.pool_mode {
            return Err(Error::Busy);
        }
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
        if self.pool_mode {
            return Err(Error::Busy);
        }
        let pa = self.address(h);
        let r = self.row(h)?;
        if r.flags & STATE != QUARANTINED || !r.empty_refs() {
            return Err(Error::Busy);
        }
        verify_and_zero(pa)?;
        *r = FrameMeta::unowned(FREE, h.generation);
        Ok(())
    }

    /// Address-indexed row access for the bounded pool-accounting bridge.
    fn pool_row(&mut self, address: u64) -> Result<&mut FrameMeta, Error> {
        if !self.pool_mode {
            return Err(Error::Busy);
        }
        if !address.is_multiple_of(PAGE) || address < self.base {
            return Err(Error::Invalid);
        }
        let index = ((address - self.base) / PAGE) as usize;
        self.rows.get_mut(index).ok_or(Error::Invalid)
    }
    /// Record a pool ownership grant: a clean (FREE) or freshly zeroed dirty
    /// (FREE|DIRTY / unowned QUARANTINED|DIRTY) row becomes ALLOCATED under
    /// the pool's next generation. Generations must stay in lockstep with
    /// the pool; a divergent or already-owned row rejects fail-closed.
    fn record_alloc(&mut self, address: u64, owner: Owner, generation: u64) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if !owner.valid() {
            return Err(Error::Unauthorized);
        }
        let reusable = r.flags == FREE
            || r.flags == (FREE | DIRTY)
            || (r.flags == (QUARANTINED | DIRTY) && r.owner_slot == NONE);
        if !reusable || !r.empty_refs() {
            return Err(Error::Busy);
        }
        let next = r.frame_generation.checked_add(1).ok_or(Error::Capacity)?;
        if generation != next {
            return Err(Error::Conflict);
        }
        *r = FrameMeta {
            owner_slot: owner.slot,
            owner_generation: owner.generation,
            frame_generation: generation,
            flags: ALLOCATED,
            ..FrameMeta::ZERO
        };
        Ok(())
    }
    /// Record a failed zeroing of a dirty pool candidate: the row stays
    /// unowned at the same generation but is quarantined, never free.
    fn record_zero_failed(&mut self, address: u64) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if !(r.flags == (FREE | DIRTY) || r.flags == (QUARANTINED | DIRTY))
            || r.owner_slot != NONE
            || !r.empty_refs()
        {
            return Err(Error::Busy);
        }
        r.flags = QUARANTINED | DIRTY;
        Ok(())
    }
    /// Record revocation start: fence the exact recorded owner/generation.
    fn record_begin_revoke(
        &mut self,
        address: u64,
        owner: Owner,
        generation: u64,
    ) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if r.flags != ALLOCATED || !r.empty_refs() {
            return Err(Error::Busy);
        }
        if r.owner_slot != owner.slot
            || r.owner_generation != owner.generation
            || r.frame_generation != generation
        {
            return Err(Error::Stale);
        }
        r.flags = QUARANTINED;
        Ok(())
    }
    /// Record completed revocation: ownership is released but the row stays
    /// quarantined and dirty. FREE requires a later explicit zero proof;
    /// a second completion rejects (double-free).
    fn record_finish_revoke(&mut self, address: u64) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if r.flags != QUARANTINED || r.owner_slot == NONE || !r.empty_refs() {
            return Err(Error::Busy);
        }
        *r = FrameMeta::unowned(QUARANTINED | DIRTY, r.frame_generation);
        Ok(())
    }
    /// Record a successful `clean_one` zeroing: the zero proof that returns
    /// an unowned dirty row (initial or quarantined) to FREE, keeping the
    /// generation history.
    fn record_cleaned(&mut self, address: u64) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if !(r.flags == (FREE | DIRTY) || r.flags == (QUARANTINED | DIRTY))
            || r.owner_slot != NONE
            || !r.empty_refs()
        {
            return Err(Error::Busy);
        }
        *r = FrameMeta::unowned(FREE, r.frame_generation);
        Ok(())
    }
    /// Record permanent retirement of an unowned pool row (generation
    /// exhaustion in the pool). Retirement is monotone and keeps history.
    fn record_retired(&mut self, address: u64) -> Result<(), Error> {
        let r = self.pool_row(address)?;
        if !matches!(r.flags & STATE, FREE | QUARANTINED) || r.owner_slot != NONE || !r.empty_refs()
        {
            return Err(Error::Busy);
        }
        *r = FrameMeta::unowned(PERMANENT, r.frame_generation);
        Ok(())
    }
}
/// Bounded accounting bridge recording [`crate::frames::FramePool`]
/// transitions into a pool-mode V0.19.9 FrameMeta ledger.
///
/// Attach with `FramePool::attach_recorder`; every pool ownership transition
/// is then mirrored fail-closed into ledger states with owner/generation:
/// alloc -> ALLOCATED, revoke -> QUARANTINED, free -> FREE only after an
/// explicit zero proof, failed zeroing -> QUARANTINED|DIRTY, generation
/// exhaustion -> PERMANENT. Conservation: the pool's capacity always equals
/// the ledger's free + reserved + allocated + quarantined rows; permanent
/// rows mirror reserved exclusions, window gaps and retired frames.
///
/// Pool owners are bare TaskIds without a generation; the bridge pins
/// owner_generation = 1 and rejects the NONE sentinel slot (u32::MAX).
/// The pool holds a shared borrow of the bridge, so accounting uses interior
/// mutability (single-core CPU0 context); the ledger stays inspectable while
/// attached.
///
/// Scope: this is an accounting mirror for the historical <=256MiB pool,
/// not a replacement allocator. The general-allocator native cutover to the
/// V0.19.9 ledger remains a later gate; desktop boot paths keep the
/// unattached pool and are bit-identical to before.
pub struct PoolBridge<'a> {
    ledger: core::cell::RefCell<Ledger<'a>>,
}
impl<'a> PoolBridge<'a> {
    /// Wrap a pool-mode ledger (from [`Ledger::initialize_pool`]). Full-RAM
    /// and static ledgers are refused: their rows must not be driven by a
    /// historical pool mirror.
    pub fn new(ledger: Ledger<'a>) -> Result<Self, Error> {
        if !ledger.pool_mode {
            return Err(Error::Busy);
        }
        Ok(Self {
            ledger: core::cell::RefCell::new(ledger),
        })
    }
    pub fn inventory(&self) -> Result<Inventory, Error> {
        self.ledger.borrow().inventory()
    }
}
fn pool_owner(owner: TaskId) -> Result<Owner, FrameError> {
    let slot = owner.get();
    if slot == NONE {
        return Err(FrameError::Ledger);
    }
    Ok(Owner {
        slot,
        generation: 1,
    })
}
impl FrameRecorder for PoolBridge<'_> {
    fn alloc(&self, address: PhysAddr, owner: TaskId, generation: u64) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_alloc(address.0, pool_owner(owner)?, generation)
            .map_err(|_| FrameError::Ledger)
    }
    fn zero_failed(&self, address: PhysAddr) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_zero_failed(address.0)
            .map_err(|_| FrameError::Ledger)
    }
    fn begin_revoke(
        &self,
        address: PhysAddr,
        owner: TaskId,
        generation: u64,
    ) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_begin_revoke(address.0, pool_owner(owner)?, generation)
            .map_err(|_| FrameError::Ledger)
    }
    fn finish_revoke(&self, address: PhysAddr) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_finish_revoke(address.0)
            .map_err(|_| FrameError::Ledger)
    }
    fn cleaned(&self, address: PhysAddr) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_cleaned(address.0)
            .map_err(|_| FrameError::Ledger)
    }
    fn retired(&self, address: PhysAddr) -> Result<(), FrameError> {
        self.ledger
            .borrow_mut()
            .record_retired(address.0)
            .map_err(|_| FrameError::Ledger)
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
    fn static_region(offset: u64, len: u64, class: StaticClass) -> StaticRegion {
        StaticRegion {
            region: region(offset, len),
            class,
        }
    }
    #[test]
    fn static_registration_golden_control_pool_shape() {
        // Exact native control-pool shape: one 8MiB physically contiguous
        // static backing registered as Control permanent pages.
        let pages = (POOL_BYTES / PAGE) as usize;
        let mut rows = std::vec![FrameMeta::ZERO;pages];
        let mut l = Ledger::initialize_static(
            &mut rows,
            0x40000000,
            &[static_region(0, POOL_BYTES, StaticClass::Control)],
        )
        .unwrap();
        let inv = l.inventory().unwrap();
        assert_eq!(inv.free, 0);
        assert_eq!(inv.reserved, 0);
        assert_eq!(inv.allocated, 0);
        assert_eq!(inv.quarantined, 0);
        assert_eq!(inv.permanent, pages as u32);
        assert_eq!(inv.arena, 0);
        assert_eq!(inv.firmware_extra, 0);
        assert_eq!(inv.metadata, 0);
        assert_eq!(inv.control, pages as u32);
        assert_eq!(inv.progress, 0);
        // Ordinary allocation can never hand out registered static pages.
        assert_eq!(
            l.reserve(Owner {
                slot: 1,
                generation: 1,
            }),
            Err(Error::Capacity)
        );
        assert_eq!(l.inventory().unwrap(), inv);
        // Re-initialization over published rows fails closed.
        assert!(matches!(
            Ledger::initialize_static(
                &mut rows,
                0x40000000,
                &[static_region(0, POOL_BYTES, StaticClass::Control)],
            ),
            Err(Error::Busy)
        ));
    }
    #[test]
    fn static_registration_multi_region_tiling_and_classes() {
        let mut rows = std::vec![FrameMeta::ZERO;6];
        let l = Ledger::initialize_static(
            &mut rows,
            0x40000000,
            &[
                static_region(3 * 4096, 3 * 4096, StaticClass::Progress),
                static_region(0, 4096, StaticClass::Metadata),
                static_region(4096, 2 * 4096, StaticClass::Control),
            ],
        )
        .unwrap();
        let inv = l.inventory().unwrap();
        assert_eq!(inv.permanent, 6);
        assert_eq!(inv.free, 0);
        assert_eq!(inv.metadata, 1);
        assert_eq!(inv.control, 2);
        assert_eq!(inv.progress, 3);
        assert_eq!(inv.arena, 0);
        assert_eq!(inv.firmware_extra, 0);
    }
    #[test]
    fn static_registration_rejects_overlap() {
        let mut rows = std::vec![FrameMeta::ZERO;4];
        assert!(matches!(
            Ledger::initialize_static(
                &mut rows,
                0x40000000,
                &[
                    static_region(0, 3 * 4096, StaticClass::Control),
                    static_region(2 * 4096, 2 * 4096, StaticClass::Progress),
                ],
            ),
            Err(Error::Conflict)
        ));
        // Rejected registration must not publish any row.
        assert!(rows.iter().all(|r| *r == FrameMeta::ZERO));
    }
    #[test]
    fn static_registration_rejects_invalid_geometry() {
        let mut rows = std::vec![FrameMeta::ZERO;4];
        let base = 0x40000000;
        let good = static_region(0, 4 * 4096, StaticClass::Control);
        // Misaligned base, start and length; zero length; wrong kind.
        for bad in [
            Ledger::initialize_static(&mut rows, base + 1, &[good]).err(),
            Ledger::initialize_static(
                &mut rows,
                base,
                &[static_region(1, 4 * 4096, StaticClass::Control)],
            )
            .err(),
            Ledger::initialize_static(
                &mut rows,
                base,
                &[static_region(0, 4097, StaticClass::Control)],
            )
            .err(),
            Ledger::initialize_static(
                &mut rows,
                base,
                &[static_region(0, 0, StaticClass::Control)],
            )
            .err(),
            Ledger::initialize_static(
                &mut rows,
                base,
                &[StaticRegion {
                    region: MemoryRegion {
                        kind: RegionKind::Ram,
                        ..region(0, 4 * 4096)
                    },
                    class: StaticClass::Control,
                }],
            )
            .err(),
        ] {
            assert_eq!(bad, Some(Error::Invalid));
        }
        // Outside the table window (below base and beyond the window).
        assert!(matches!(
            Ledger::initialize_static(
                &mut rows,
                base,
                &[static_region(0, 5 * 4096, StaticClass::Control)],
            ),
            Err(Error::Invalid)
        ));
        let mut low = std::vec![FrameMeta::ZERO;4];
        assert!(matches!(
            Ledger::initialize_static(
                &mut low,
                base + 4 * 4096,
                &[static_region(0, 4 * 4096, StaticClass::Control)],
            ),
            Err(Error::Invalid)
        ));
        // Incomplete coverage: a static ledger never leaves unaccounted rows.
        assert!(matches!(
            Ledger::initialize_static(
                &mut rows,
                base,
                &[static_region(0, 3 * 4096, StaticClass::Control)],
            ),
            Err(Error::Invalid)
        ));
        // Empty region list and more regions than the fixed record capacity.
        assert!(matches!(
            Ledger::initialize_static(&mut rows, base, &[]),
            Err(Error::Invalid)
        ));
        let mut five = std::vec![FrameMeta::ZERO;5];
        assert!(matches!(
            Ledger::initialize_static(
                &mut five,
                base,
                &[
                    static_region(0, 4096, StaticClass::Control),
                    static_region(4096, 4096, StaticClass::Control),
                    static_region(2 * 4096, 4096, StaticClass::Control),
                    static_region(3 * 4096, 4096, StaticClass::Control),
                    static_region(4 * 4096, 4096, StaticClass::Control),
                ],
            ),
            Err(Error::Invalid)
        ));
        // The static table must stay inside the 10MiB global reservation.
        let mut oversized = std::vec![FrameMeta::ZERO;COUNT + 1];
        assert!(matches!(
            Ledger::initialize_static(
                &mut oversized,
                base,
                &[static_region(
                    0,
                    (COUNT as u64 + 1) * 4096,
                    StaticClass::Control
                )],
            ),
            Err(Error::Invalid)
        ));
        assert!(rows.iter().all(|r| *r == FrameMeta::ZERO));
    }
    #[test]
    fn static_pages_refuse_lifecycle_and_reclaim() {
        let mut rows = std::vec![FrameMeta::ZERO;2];
        let mut l = Ledger::initialize_static(
            &mut rows,
            0x40000000,
            &[static_region(0, 2 * 4096, StaticClass::Control)],
        )
        .unwrap();
        let before = l.inventory().unwrap();
        // A handle forged to match the unowned PERMANENT row exactly, and a
        // handle claiming a real owner: neither may transition or reclaim.
        for h in [
            Handle {
                index: 0,
                generation: 0,
                owner: Owner {
                    slot: NONE,
                    generation: 0,
                },
            },
            Handle {
                index: 0,
                generation: 1,
                owner: Owner {
                    slot: 1,
                    generation: 1,
                },
            },
        ] {
            let expected = if h.owner.slot == NONE {
                Error::Busy
            } else {
                Error::Stale
            };
            assert_eq!(l.commit(h, false, |_| panic!()), Err(expected));
            assert_eq!(l.retain(h, Reference::Mapping, |_| panic!()), Err(expected));
            assert_eq!(
                l.release_ref(h, Reference::Dma, |_| panic!()),
                Err(expected)
            );
            assert_eq!(l.quarantine(h), Err(expected));
            assert_eq!(l.reclaim(h, |_| panic!()), Err(expected));
        }
        assert_eq!(
            l.reserve(Owner {
                slot: 1,
                generation: 1,
            }),
            Err(Error::Capacity)
        );
        // Refcount/quarantine conservation is untouched by refused attempts.
        assert_eq!(l.inventory().unwrap(), before);
    }
    #[test]
    fn static_inventory_rejects_tampered_rows() {
        let mut rows = std::vec![FrameMeta::ZERO;2];
        let l = Ledger::initialize_static(
            &mut rows,
            0x40000000,
            &[static_region(0, 2 * 4096, StaticClass::Control)],
        )
        .unwrap();
        // A permanent row may not carry an owner or any reference.
        l.rows[0].refcnt = 1;
        assert_eq!(l.inventory(), Err(Error::Conflict));
        l.rows[0].refcnt = 0;
        l.rows[0].flags = ALLOCATED;
        l.rows[0].owner_slot = 1;
        l.rows[0].owner_generation = 1;
        l.rows[0].frame_generation = 1;
        assert_eq!(l.inventory(), Err(Error::Conflict));
    }

    use crate::frames::{FramePool, FrameSnapshot, PageZeroer, RevokeComplete};
    fn pool_ram(base: u64, pages: u64) -> MemoryRegion {
        MemoryRegion {
            start: PhysAddr(base),
            len: pages * PAGE,
            kind: RegionKind::Ram,
        }
    }
    struct OkZero;
    impl PageZeroer for OkZero {
        fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
            Ok(())
        }
    }
    struct FailZero;
    impl PageZeroer for FailZero {
        fn zero(&mut self, _: PhysAddr) -> Result<(), FrameError> {
            Err(FrameError::ZeroFailed)
        }
    }
    #[test]
    fn pool_bridge_alloc_records_allocated_with_owner_and_generation() {
        let ram = [pool_ram(0x40000000, 4)];
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 4];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mut rows = std::vec![FrameMeta::ZERO; 4];
        let bridge =
            PoolBridge::new(Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap())
                .unwrap();
        pool.attach_recorder(&bridge);
        let owner = TaskId::new(7).unwrap();
        let h = pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        assert_eq!(h.address(), PhysAddr(0x40000000));
        let h2 = pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        assert_eq!(h2.address(), PhysAddr(0x40001000));
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        assert_eq!(
            (
                inv.free,
                inv.reserved,
                inv.allocated,
                inv.quarantined,
                inv.permanent
            ),
            (2, 0, 2, 0, 0)
        );
        // Conservation: pool capacity equals the ledger's non-permanent rows.
        assert_eq!(
            pool.snapshot().capacity as u32,
            inv.free + inv.reserved + inv.allocated + inv.quarantined
        );
        assert_eq!(pool.snapshot().used as u32, inv.allocated);
        let r = bridge.ledger.borrow().rows[0];
        assert_eq!(r.flags, ALLOCATED);
        assert_eq!(r.owner_slot, 7);
        assert_eq!(r.owner_generation, 1);
        assert_eq!(r.frame_generation, 1);
        assert_eq!(bridge.ledger.borrow().rows[1].frame_generation, 1);
    }
    #[test]
    fn pool_bridge_free_requires_zero_proof_and_rejects_double_free() {
        let ram = [pool_ram(0x40000000, 2)];
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 2];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mut rows = std::vec![FrameMeta::ZERO; 2];
        let bridge =
            PoolBridge::new(Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap())
                .unwrap();
        pool.attach_recorder(&bridge);
        let owner = TaskId::new(7).unwrap();
        let h = pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        pool.begin_revoke(h, owner).unwrap();
        pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        // Double free is rejected at the pool level; inventory is untouched.
        assert_eq!(
            pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) }),
            Err(FrameError::Stale)
        );
        assert_eq!(pool.begin_revoke(h, owner), Err(FrameError::Owner));
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        assert_eq!((inv.free, inv.allocated, inv.quarantined), (1, 0, 1));
        assert_eq!(bridge.ledger.borrow().rows[0].flags, QUARANTINED | DIRTY);
        assert_eq!(bridge.ledger.borrow().rows[0].owner_slot, NONE);
        // A second ledger-level completion also rejects (double-free).
        assert_eq!(
            bridge.ledger.borrow_mut().record_finish_revoke(0x40000000),
            Err(Error::Busy)
        );
        // The pool counts the returned dirty page as free capacity, but the
        // ledger keeps it quarantined until zero proof; capacity conserves.
        assert_eq!(pool.snapshot().free, 2);
        assert_eq!(
            pool.snapshot().capacity as u32,
            inv.free + inv.reserved + inv.allocated + inv.quarantined
        );
        // The clean_one zero proof returns the row to FREE, keeping history.
        pool.attach_recorder(&bridge);
        assert!(pool.clean_one(&mut OkZero).unwrap());
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        assert_eq!((inv.free, inv.quarantined), (2, 0));
        assert_eq!(bridge.ledger.borrow().rows[0].flags, FREE);
        assert_eq!(bridge.ledger.borrow().rows[0].frame_generation, 1);
    }
    #[test]
    fn pool_bridge_quarantines_failed_zeroing_and_recovers() {
        let ram = [pool_ram(0x40000000, 2)];
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 2];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mut rows = std::vec![FrameMeta::ZERO; 2];
        let bridge =
            PoolBridge::new(Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap())
                .unwrap();
        pool.attach_recorder(&bridge);
        let owner = TaskId::new(7).unwrap();
        assert_eq!(
            pool.alloc_zeroed(owner, &mut FailZero),
            Err(FrameError::ZeroFailed)
        );
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        assert_eq!((inv.free, inv.allocated, inv.quarantined), (1, 0, 1));
        assert_eq!(bridge.ledger.borrow().rows[0].flags, QUARANTINED | DIRTY);
        assert_eq!(bridge.ledger.borrow().rows[0].frame_generation, 0);
        // The pool page stays dirty and unowned: free capacity is unchanged.
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 2,
                free: 2,
                used: 0
            }
        );
        // A retried allocation re-zeroes and records ALLOCATED at generation 1.
        pool.attach_recorder(&bridge);
        let h = pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        assert_eq!(h.index(), 0);
        pool.begin_revoke(h, owner).unwrap();
        pool.finish_revoke(h, unsafe { RevokeComplete::after_unmap(h) })
            .unwrap();
        // Failed clearing during cleaning keeps the quarantine.
        assert_eq!(pool.clean_one(&mut FailZero), Err(FrameError::ZeroFailed));
        pool.detach_recorder();
        assert_eq!(bridge.inventory().unwrap().quarantined, 1);
        assert_eq!(bridge.ledger.borrow().rows[0].flags, QUARANTINED | DIRTY);
        // Successful clearing is the zero proof; the next alloc stays in
        // generation lockstep with the pool.
        pool.attach_recorder(&bridge);
        assert!(pool.clean_one(&mut OkZero).unwrap());
        let h2 = pool.alloc_clean(owner).unwrap();
        assert_eq!(h2.index(), 0);
        pool.detach_recorder();
        assert_eq!(bridge.ledger.borrow().rows[0].flags, ALLOCATED);
        assert_eq!(bridge.ledger.borrow().rows[0].frame_generation, 2);
        assert_eq!(bridge.inventory().unwrap().allocated, 1);
    }
    #[test]
    fn pool_bridge_conservation_across_mixed_lifecycle() {
        let ram = [pool_ram(0x40000000, 4)];
        let reserved = [region(4096, 4096)];
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 4];
        let mut pool = FramePool::from_memory(&ram, &reserved, &mut metadata).unwrap();
        let mut rows = std::vec![FrameMeta::ZERO; 4];
        let bridge = PoolBridge::new(
            Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &reserved).unwrap(),
        )
        .unwrap();
        assert_eq!(pool.snapshot().capacity, 3);
        pool.attach_recorder(&bridge);
        let owner = TaskId::new(7).unwrap();
        let mut handles = std::vec::Vec::new();
        for _ in 0..3 {
            handles.push(pool.alloc_zeroed(owner, &mut OkZero).unwrap());
        }
        assert_eq!(
            pool.alloc_zeroed(owner, &mut OkZero),
            Err(FrameError::Exhausted)
        );
        pool.begin_revoke(handles[0], owner).unwrap();
        pool.finish_revoke(handles[0], unsafe {
            RevokeComplete::after_unmap(handles[0])
        })
        .unwrap();
        assert!(pool.clean_one(&mut OkZero).unwrap());
        let again = pool.alloc_clean(owner).unwrap();
        assert_eq!(again.index(), handles[0].index());
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        assert_eq!(inv.permanent, 1);
        assert_eq!(
            (inv.free, inv.reserved, inv.allocated, inv.quarantined),
            (0, 0, 3, 0)
        );
        assert_eq!(
            pool.snapshot().capacity as u32,
            inv.free + inv.reserved + inv.allocated + inv.quarantined
        );
        assert_eq!(pool.snapshot().used as u32, inv.allocated);
        // The excluded page can never be recorded as a pool allocation.
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40001000,
                Owner {
                    slot: 7,
                    generation: 1
                },
                1
            ),
            Err(Error::Busy)
        );
        assert_eq!(bridge.inventory().unwrap(), inv);
    }
    #[test]
    fn pool_bridge_rejects_invalid_owner_and_divergent_rows() {
        let ram = [pool_ram(0x40000000, 2)];
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 2];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let mut rows = std::vec![FrameMeta::ZERO; 2];
        let bridge =
            PoolBridge::new(Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap())
                .unwrap();
        pool.attach_recorder(&bridge);
        // The NONE sentinel slot can never become a ledger owner; the pool
        // allocation aborts fail-closed before publishing ownership.
        let sentinel = TaskId::new(NONE).unwrap();
        assert_eq!(
            pool.alloc_zeroed(sentinel, &mut OkZero),
            Err(FrameError::Ledger)
        );
        assert_eq!(pool.snapshot().used, 0);
        let owner = TaskId::new(7).unwrap();
        pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        pool.detach_recorder();
        let inv = bridge.inventory().unwrap();
        // Double recording, divergent generation and forged geometry all
        // fail closed without publishing anything.
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40000000,
                Owner {
                    slot: 7,
                    generation: 1
                },
                2
            ),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40001000,
                Owner {
                    slot: 7,
                    generation: 1
                },
                2
            ),
            Err(Error::Conflict)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40000001,
                Owner {
                    slot: 7,
                    generation: 1
                },
                1
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x50000000,
                Owner {
                    slot: 7,
                    generation: 1
                },
                1
            ),
            Err(Error::Invalid)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40001000,
                Owner {
                    slot: NONE,
                    generation: 1
                },
                1
            ),
            Err(Error::Unauthorized)
        );
        assert_eq!(bridge.inventory().unwrap(), inv);
    }
    #[test]
    fn pool_ledger_geometry_mirrors_pool_and_fails_closed() {
        // Two RAM regions with a gap; a reserved exclusion inside the first.
        let ram = [pool_ram(0x40000000, 2), pool_ram(0x40004000, 2)];
        let reserved = [region(4096, 4096)];
        let mut rows = std::vec![FrameMeta::ZERO; 6];
        let l = Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &reserved).unwrap();
        let inv = l.inventory().unwrap();
        assert_eq!((inv.free, inv.permanent), (3, 3));
        assert_eq!(l.rows[0].flags, FREE | DIRTY);
        assert_eq!(l.rows[1].flags, PERMANENT);
        assert_eq!(l.rows[2].flags, PERMANENT);
        assert_eq!(l.rows[3].flags, PERMANENT);
        assert_eq!(l.rows[4].flags, FREE | DIRTY);
        assert_eq!(l.rows[5].flags, FREE | DIRTY);
        drop(l);
        // Rejected initialization publishes nothing.
        let mut fresh = std::vec![FrameMeta::ZERO; 4];
        let good = pool_ram(0x40000000, 4);
        let overlap = [good, pool_ram(0x40001000, 4096)];
        let nine = [good; 9];
        let mut many_reserved = std::vec::Vec::new();
        for i in 0..33u64 {
            many_reserved.push(region(i * 4096, 4096));
        }
        let mut empty: [FrameMeta; 0] = [];
        for bad in [
            Ledger::initialize_pool(&mut fresh, 0x40000001, &[good], &[]).err(),
            Ledger::initialize_pool(&mut fresh, 0x40000000, &overlap, &[]).err(),
            Ledger::initialize_pool(&mut fresh, 0x40000000, &nine, &[]).err(),
            Ledger::initialize_pool(&mut fresh, 0x40000000, &[good], &many_reserved).err(),
            Ledger::initialize_pool(&mut fresh, 0x40000000, &[pool_ram(0x40000000, 5)], &[]).err(),
            Ledger::initialize_pool(&mut empty, 0x40000000, &[good], &[]).err(),
        ] {
            assert_eq!(bad, Some(Error::Invalid));
        }
        // The pool's 65536-page admission cap is mirrored.
        let mut big = std::vec![FrameMeta::ZERO; 65537];
        assert_eq!(
            Ledger::initialize_pool(&mut big, 0x40000000, &[pool_ram(0x40000000, 65537)], &[])
                .err(),
            Some(Error::Capacity)
        );
        // Published rows refuse re-initialization.
        assert_eq!(
            Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &reserved).err(),
            Some(Error::Busy)
        );
        assert!(fresh.iter().all(|r| *r == FrameMeta::ZERO));
    }
    #[test]
    fn pool_ledger_refuses_ordinary_handle_lifecycle() {
        let ram = [pool_ram(0x40000000, 2)];
        let mut rows = std::vec![FrameMeta::ZERO; 2];
        let mut l = Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap();
        assert_eq!(
            l.reserve(Owner {
                slot: 1,
                generation: 1
            }),
            Err(Error::Capacity)
        );
        // Drive one row through the bridge, then forge its exact handle: the
        // ordinary lifecycle must still refuse to bypass the pool mirror.
        let mut metadata = std::vec![crate::frames::FrameMeta::EMPTY; 2];
        let mut pool = FramePool::from_memory(&ram, &[], &mut metadata).unwrap();
        let bridge = PoolBridge::new(l).unwrap();
        pool.attach_recorder(&bridge);
        let owner = TaskId::new(7).unwrap();
        pool.alloc_zeroed(owner, &mut OkZero).unwrap();
        pool.detach_recorder();
        let forged = Handle {
            index: 0,
            generation: 1,
            owner: Owner {
                slot: 7,
                generation: 1,
            },
        };
        assert_eq!(
            bridge
                .ledger
                .borrow_mut()
                .commit(forged, false, |_| panic!()),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge
                .ledger
                .borrow_mut()
                .retain(forged, Reference::Mapping, |_| panic!()),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge
                .ledger
                .borrow_mut()
                .release_ref(forged, Reference::Dma, |_| panic!()),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().quarantine(forged),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().reclaim(forged, |_| panic!()),
            Err(Error::Busy)
        );
        assert_eq!(bridge.inventory().unwrap().allocated, 1);
        // Only pool-mode ledgers may be wrapped by the bridge.
        let mut static_rows = std::vec![FrameMeta::ZERO; 1];
        let sl = Ledger::initialize_static(
            &mut static_rows,
            0x40000000,
            &[static_region(0, 4096, StaticClass::Control)],
        )
        .unwrap();
        assert_eq!(PoolBridge::new(sl).err(), Some(Error::Busy));
    }
    #[test]
    fn pool_bridge_retirement_mirrors_permanent() {
        let ram = [pool_ram(0x40000000, 2)];
        let mut rows = std::vec![FrameMeta::ZERO; 2];
        let bridge =
            PoolBridge::new(Ledger::initialize_pool(&mut rows, 0x40000000, &ram, &[]).unwrap())
                .unwrap();
        let before = bridge.inventory().unwrap();
        assert_eq!(
            bridge.ledger.borrow_mut().record_retired(0x40000000),
            Ok(())
        );
        let inv = bridge.inventory().unwrap();
        assert_eq!(inv.free, before.free - 1);
        assert_eq!(inv.permanent, 1);
        assert_eq!(bridge.ledger.borrow().rows[0].flags, PERMANENT);
        // Retirement is monotone; owned or already-permanent rows reject.
        assert_eq!(
            bridge.ledger.borrow_mut().record_retired(0x40000000),
            Err(Error::Busy)
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_alloc(
                0x40001000,
                Owner {
                    slot: 7,
                    generation: 1
                },
                1
            ),
            Ok(())
        );
        assert_eq!(
            bridge.ledger.borrow_mut().record_retired(0x40001000),
            Err(Error::Busy)
        );
        assert_eq!(bridge.inventory().unwrap().allocated, 1);
    }
}
