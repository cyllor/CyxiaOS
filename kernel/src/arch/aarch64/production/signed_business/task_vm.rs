//! Anonymous mappings and an explicitly registered owned page set. The same
//! native foreground owns the TTBR0, VA ranges, side-effect keys and exact
//! FrameMeta handles. The RAM alias is disconnected before any EL0 mapping.
use super::super::super::frames::with_business_ledger;
use super::*;
use cyxia_kernel_core::frame_meta_v0199::{Handle, Ledger, Owner, Reference};
use zeroize::Zeroize;

pub(super) const MAX_PAGES: usize = 8;
const VM_BASE: u64 = 0x0000_0040_0000_0000;
const VM_END: u64 = VM_BASE + SLOT_BYTES;
const REGION_SLOTS: usize = 16;
const REGION_CAP: u32 = 0x410;
const RECEIPTS: usize = 64;
const REPLY_BYTES: usize = 32;
const VM_PAGES: usize = (SLOT_BYTES as usize) / PAGE;
const DIRECT_FLAGS: u64 = 0x0060_0000_0000_0703;

#[unsafe(link_section = ".bss.sec_n")]
static mut VM_MIDDLE: Page = Page::ZERO;
#[unsafe(link_section = ".bss.sec_n")]
static mut VM_LEAF: Page = Page::ZERO;

#[derive(Clone, Copy)]
struct Frame {
    handle: Handle,
    address: u64,
}

#[derive(Clone, Copy)]
struct Mapping {
    frame: Frame,
    owned: bool,
    write: bool,
}

#[derive(Clone, Copy, Default)]
struct PageState {
    reserved: Option<Frame>,
    mapping: Option<Mapping>,
}

#[derive(Clone, Copy)]
struct Region {
    start: usize,
    pages: usize,
    present: u16,
    state: [PageState; MAX_PAGES],
}

impl Region {
    fn owns(&self, page: usize) -> bool {
        page.checked_sub(self.start)
            .is_some_and(|n| n < self.pages && self.present & (1 << n) != 0)
    }

    fn range(&self, offset: u64, pages: usize) -> Result<core::ops::Range<usize>, Errno> {
        let first = usize::try_from(offset / PAGE as u64).map_err(|_| Errno::Format)?;
        let end = first.checked_add(pages).ok_or(Errno::Format)?;
        if pages > self.pages || end > self.pages {
            return Err(Errno::Format);
        }
        if (first..end).any(|index| self.present & (1 << index) == 0) {
            return Err(Errno::Stale);
        }
        Ok(first..end)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Operation {
    Reserve {
        hint: u64,
        length: u64,
        flags: u64,
    },
    Map {
        region: u64,
        page_set: u64,
        offset: u64,
        flags: u64,
    },
    Unmap {
        region: u64,
        offset: u64,
        length: u64,
    },
}

#[derive(Clone, Copy)]
struct Receipt {
    id: u64,
    operation: Operation,
    region: usize,
}

pub(super) struct Vm {
    owner: Owner,
    quota: usize,
    page_count: usize,
    owned: [Option<Frame>; MAX_PAGES],
    owned_mapped: bool,
    regions: [Option<Region>; REGION_SLOTS],
    receipts: [Option<Receipt>; RECEIPTS],
    used: usize,
}

pub(super) fn contains(address: u64) -> bool {
    (VM_BASE..VM_END).contains(&address)
}

fn managed<E>(result: Result<E, SvcError>) -> Result<E, Errno> {
    result.map_err(|error| match error {
        SvcError::Invalid => Errno::Format,
        SvcError::Unauthorized => Errno::Auth,
        SvcError::Stale => Errno::Stale,
        SvcError::Capacity | SvcError::Exhausted => Errno::NoMemory,
        SvcError::Busy => Errno::Again,
        SvcError::Conflict => Errno::Conflict,
        SvcError::Unknown => Errno::Io,
    })
}

fn reserve_frame(ledger: &mut Ledger<'_>, owner: Owner) -> Result<Frame, SvcError> {
    let handle = ledger.reserve(owner)?;
    Ok(Frame {
        address: ledger.address(handle),
        handle,
    })
}

fn direct_leaf(address: u64) -> Result<*mut u64, SvcError> {
    if !(cyxia_platform_virt::KERNEL_POOL_END..cyxia_platform_virt::USER_RAM_END).contains(&address)
        || !address.is_multiple_of(PAGE as u64)
    {
        return Err(SvcError::Unauthorized);
    }
    Ok(high_leaf(address))
}

fn zero(address: u64) -> Result<(), SvcError> {
    let leaf = direct_leaf(address)?;
    if unsafe { leaf.read_volatile() } != (address | DIRECT_FLAGS) {
        return Err(SvcError::Unauthorized);
    }
    // SAFETY: FrameMeta reserved/quarantined the frame exclusively. The
    // checked actual high leaf is kernel-only RW and no user/DMA pins remain.
    unsafe { core::slice::from_raw_parts_mut((crate::HIGH + address) as *mut u8, PAGE) }.zeroize();
    Ok(())
}

fn invalidate_direct_alias(address: u64) {
    let va = crate::HIGH + address;
    // VAAE1IS takes VA[55:12]. The shared high alias is global and may
    // have been cached by any registered CPU under any user ASID.
    let operand = (va >> 12) & ((1u64 << 44) - 1);
    unsafe {
        core::arch::asm!(
            "dsb ishst", "tlbi vaae1is, {}", "dsb ish", "isb",
            in(reg) operand, options(nostack, preserves_flags),
        );
    }
}

fn commit_frame(ledger: &mut Ledger<'_>, frame: Frame) -> Result<(), SvcError> {
    ledger.commit(frame.handle, true, zero)?;
    let alias = direct_leaf(frame.address)?;
    // SAFETY: the canonical ordinary pool ledger owns the cleared frame.
    // Complete broadcast invalidation of the EL1 alias before any EL0 use.
    unsafe { alias.write_volatile(0) };
    invalidate_direct_alias(frame.address);
    Ok(())
}

fn reclaim(ledger: &mut Ledger<'_>, frame: Frame) -> Result<(), SvcError> {
    ledger.quarantine(frame.handle)?;
    ledger.reclaim(frame.handle, |pa| {
        let alias = direct_leaf(pa)?;
        // SAFETY: no mapping, pin, DMA or share is left and its unmap TLBI
        // has completed before the ledger lets us restore the direct map.
        if unsafe { alias.read_volatile() } == 0 {
            unsafe { alias.write_volatile(pa | DIRECT_FLAGS) };
            invalidate_direct_alias(pa);
        }
        zero(pa)
    })
}

fn page_entry(index: usize) -> *mut u64 {
    // Index is checked against the designated 2 MiB aperture on all paths.
    assert!(index < VM_PAGES);
    addr_of_mut!(VM_LEAF).cast::<u64>().wrapping_add(index)
}

fn publish_leaf(entry: *mut u64, mapping: Mapping) -> Result<(), SvcError> {
    let address = mapping.frame.address;
    if unsafe { entry.read_volatile() } != 0
        || unsafe { direct_leaf(address)?.read_volatile() } != 0
    {
        return Err(SvcError::Conflict);
    }
    let leaf = mmu::encode_user_leaf(PhysAddr(address), mapping.write, false)
        .map_err(|_| SvcError::Unauthorized)?;
    // SAFETY: checked absent entry in this stopped root. The frame has
    // already lost the high alias and this map is always UXN/PXN/non-global.
    unsafe { entry.write_volatile(leaf) };
    invalidate_user_asid(OWNER_ASID);
    Ok(())
}

pub(super) fn pinned<E>(
    fragment: Fragment,
    copy: impl FnOnce(u64) -> Result<E, SvcError>,
) -> Result<E, Errno> {
    let Some(handle) = fragment.managed else {
        return managed(copy(fragment.physical));
    };
    managed(with_business_ledger(|ledger| {
        let frame = fragment.physical & !(PAGE as u64 - 1);
        ledger.retain(handle, Reference::Pin, |pa| {
            if pa != frame {
                return Err(SvcError::Stale);
            }
            Ok(())
        })?;
        let result = copy(fragment.physical);
        // CopyWindow invalidation is complete on either returning path.
        ledger.release_ref(handle, Reference::Pin, |_| Ok(()))?;
        result
    }))
}

impl Vm {
    pub(super) fn prepare(space: Space, grant: Grant) -> Result<Self, Errno> {
        let page_count = usize::from(grant.owned_pages);
        let owner = Owner {
            slot: space.actor.id as u32,
            generation: space.actor.generation,
        };
        let owned = managed(with_business_ledger(|ledger| {
            let mut frames = [None; MAX_PAGES];
            for i in 0..page_count {
                let next = reserve_frame(ledger, owner).and_then(|frame| {
                    commit_frame(ledger, frame)?;
                    Ok(frame)
                });
                match next {
                    Ok(frame) => frames[i] = Some(frame),
                    Err(error) => {
                        for frame in frames[..i].iter().flatten().copied() {
                            reclaim(ledger, frame)?;
                        }
                        return Err(error);
                    }
                }
            }
            Ok(frames)
        }))?;
        // SAFETY: CPU0 owns these unpublished tables. VM_BASE has a separate
        // L1 index from every permitted PIE and stack placement.
        unsafe {
            let root = addr_of_mut!((*space.backing).root.0)
                .cast::<u64>()
                .add((VM_BASE >> 30) as usize);
            let middle = addr_of_mut!(VM_MIDDLE.0).cast::<u64>();
            if root.read_volatile() != 0 || middle.read_volatile() != 0 {
                return Err(Errno::Conflict);
            }
            middle.write_volatile(pa(addr_of!(VM_LEAF).cast()).0 | 3);
            root.write_volatile(pa(addr_of!(VM_MIDDLE).cast()).0 | 3);
        }
        tlbi();
        Ok(Self {
            owner,
            quota: usize::from(grant.vm_pages),
            page_count,
            owned,
            owned_mapped: false,
            regions: [None; REGION_SLOTS],
            receipts: [None; RECEIPTS],
            used: 0,
        })
    }

    pub(super) fn possesses(&self, slot: u32) -> bool {
        self.slot(slot)
            .is_some_and(|index| self.regions[index].is_some())
    }

    fn slot(&self, selector: u32) -> Option<usize> {
        let slot = selector.checked_sub(REGION_CAP)? as usize;
        (slot < self.regions.len()).then_some(slot)
    }

    fn region(&self, cap: u64) -> Result<usize, Errno> {
        let index = self.slot(cap as u32).ok_or(Errno::Auth)?;
        if self.regions[index].is_none() {
            return Err(Errno::Auth);
        }
        if cap >> 32 != self.owner.generation {
            return Err(Errno::Stale);
        }
        Ok(index)
    }

    fn retry(&self, id: u64, operation: Operation) -> Result<Option<usize>, Errno> {
        if id == 0 {
            return Err(Errno::Format);
        }
        if let Some(receipt) = self.receipts[..self.used]
            .iter()
            .flatten()
            .find(|r| r.id == id)
        {
            return if receipt.operation == operation {
                Ok(Some(receipt.region))
            } else {
                Err(Errno::Conflict)
            };
        }
        if self.used == RECEIPTS {
            return Err(Errno::Capacity);
        }
        if self.used != 0 && id < self.receipts[self.used - 1].unwrap().id {
            return Err(Errno::Stale);
        }
        Ok(None)
    }

    fn record(&mut self, id: u64, operation: Operation, region: usize) {
        self.receipts[self.used] = Some(Receipt {
            id,
            operation,
            region,
        });
        self.used += 1;
    }

    fn active_pages(&self) -> usize {
        self.regions
            .iter()
            .flatten()
            .map(|r| r.present.count_ones() as usize)
            .sum()
    }

    /// Keep a completion receipt for each page that may need its own unmap.
    fn reserve_receipt(&self, active_pages: usize) -> Result<(), Errno> {
        if self.used + 1 + active_pages > RECEIPTS {
            return Err(Errno::Capacity);
        }
        Ok(())
    }

    fn available(&self, start: usize, pages: usize) -> bool {
        start.checked_add(pages).is_some_and(|end| {
            end <= VM_PAGES
                && (start..end).all(|page| {
                    self.regions
                        .iter()
                        .flatten()
                        .all(|region| !region.owns(page))
                })
        })
    }

    fn choose(&self, hint: u64, pages: usize) -> Result<usize, Errno> {
        if hint != 0 {
            if !contains(hint) || !hint.is_multiple_of(PAGE as u64) {
                return Err(Errno::Format);
            }
            let start = ((hint - VM_BASE) / PAGE as u64) as usize;
            return if self.available(start, pages) {
                Ok(start)
            } else {
                Err(Errno::Conflict)
            };
        }
        (0..=VM_PAGES - pages)
            .find(|&start| self.available(start, pages))
            .ok_or(Errno::NoMemory)
    }

    pub(super) fn reserve(
        &mut self,
        space: Space,
        [hint, len, flags, id, reply, capacity]: [u64; 6],
    ) -> Result<(), Errno> {
        let pages = usize::try_from(len / PAGE as u64).map_err(|_| Errno::NoMemory)?;
        if pages == 0 || pages > self.quota {
            return Err(Errno::NoMemory);
        }
        let operation = Operation::Reserve {
            hint,
            length: len,
            flags,
        };
        let previous = self.retry(id, operation)?;
        visit_span(space, Some(self), reply, capacity, true, |_, _, _| Ok(()))?;
        let slot = if let Some(slot) = previous {
            slot
        } else {
            if recovery::audit_degraded() {
                return Err(Errno::Again);
            }
            let reserved = self.active_pages();
            if reserved > self.quota - pages {
                return Err(Errno::NoMemory);
            }
            self.reserve_receipt(reserved + pages)?;
            let region = self
                .regions
                .iter()
                .position(Option::is_none)
                .ok_or(Errno::Capacity)?;
            let start = self.choose(hint, pages)?;
            let mut state = [PageState::default(); MAX_PAGES];
            if flags == 1 {
                managed(with_business_ledger(|ledger| {
                    for i in 0..pages {
                        match reserve_frame(ledger, self.owner) {
                            Ok(frame) => state[i].reserved = Some(frame),
                            Err(error) => {
                                for reserved in state[..i].iter().filter_map(|s| s.reserved) {
                                    reclaim(ledger, reserved)?;
                                }
                                return Err(error);
                            }
                        }
                    }
                    Ok(())
                }))?;
            }
            self.regions[region] = Some(Region {
                start,
                pages,
                present: (1 << pages) - 1,
                state,
            });
            self.record(id, operation, region);
            region
        };
        let region = self.regions[slot].unwrap();
        let mut result = [0; REPLY_BYTES];
        let epoch = self.owner.generation;
        result[..8].copy_from_slice(&selector(epoch, REGION_CAP + slot as u32).to_le_bytes());
        result[8..16].copy_from_slice(&(VM_BASE + (region.start * PAGE) as u64).to_le_bytes());
        result[16..24].copy_from_slice(&len.to_le_bytes());
        result[24..].copy_from_slice(&epoch.to_le_bytes());
        copy_out(space, Some(self), reply, &result)
    }

    pub(super) fn map(&mut self, [cap, set, offset, flags, id, _]: [u64; 6]) -> Result<(), Errno> {
        let index = self.region(cap)?;
        check_selector(set, self.owner.generation, OWNED_PAGE_SLOT)?;
        let operation = Operation::Map {
            region: cap,
            page_set: set,
            offset,
            flags,
        };
        if self.retry(id, operation)?.is_some() {
            return Ok(());
        }
        if recovery::audit_degraded() {
            return Err(Errno::Again);
        }
        self.reserve_receipt(self.active_pages())?;
        let region = self.regions[index].as_mut().unwrap();
        let range = region.range(offset, self.page_count)?;
        if self.owned_mapped || range.clone().any(|i| region.state[i].mapping.is_some()) {
            return Err(Errno::Conflict);
        }
        // All ordinary owned frames were registered for this exact holder and
        // epoch during boot. Validate the destination and aliases before any
        // effects. Only this root can map their single live copy.
        managed(with_business_ledger(|ledger| {
            for (n, i) in range.clone().enumerate() {
                let frame = self.owned[n].ok_or(SvcError::Conflict)?;
                let pte = page_entry(region.start + i);
                if unsafe { pte.read_volatile() } != 0
                    || unsafe { direct_leaf(frame.address)?.read_volatile() } != 0
                {
                    return Err(SvcError::Conflict);
                }
            }
            for (n, i) in range.enumerate() {
                let frame = self.owned[n].unwrap();
                let mapping = Mapping {
                    frame,
                    owned: true,
                    write: flags == 2,
                };
                ledger
                    .retain(frame.handle, Reference::Mapping, |_| {
                        publish_leaf(page_entry(region.start + i), mapping)
                    })
                    .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                region.state[i].mapping = Some(mapping);
            }
            Ok(())
        }))?;
        self.owned_mapped = true;
        self.record(id, operation, index);
        Ok(())
    }

    pub(super) fn unmap(&mut self, [cap, offset, len, id, _, _]: [u64; 6]) -> Result<(), Errno> {
        let index = self.region(cap)?;
        let operation = Operation::Unmap {
            region: cap,
            offset,
            length: len,
        };
        if self.retry(id, operation)?.is_some() {
            return Ok(());
        }
        let pages = usize::try_from(len / PAGE as u64).map_err(|_| Errno::Format)?;
        let region = self.regions[index].as_mut().unwrap();
        let range = region.range(offset, pages)?;
        managed(with_business_ledger(|ledger| {
            for i in range {
                Self::drop_page(ledger, region, i).unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            }
            Ok(())
        }))?;
        self.owned_mapped = self.regions.iter().flatten().any(|region| {
            region
                .state
                .iter()
                .any(|state| state.mapping.is_some_and(|m| m.owned))
        });
        self.record(id, operation, index);
        Ok(())
    }

    fn drop_page(ledger: &mut Ledger<'_>, region: &mut Region, i: usize) -> Result<(), SvcError> {
        let state = &mut region.state[i];
        let entry = page_entry(region.start + i);
        if let Some(mapping) = state.mapping {
            ledger.release_ref(mapping.frame.handle, Reference::Mapping, |pa| {
                let expected = mmu::encode_user_leaf(PhysAddr(pa), mapping.write, false)
                    .map_err(|_| SvcError::Conflict)?;
                if unsafe { entry.read_volatile() } != expected {
                    return Err(SvcError::Conflict);
                }
                // SAFETY: synchronous fault/syscall owner is stopped. The
                // broadcast DSB/TLBI completes on all PEs before release.
                unsafe { entry.write_volatile(0) };
                invalidate_user_asid(OWNER_ASID);
                Ok(())
            })?;
            if !mapping.owned {
                reclaim(ledger, mapping.frame)?;
            }
        } else if unsafe { entry.read_volatile() } != 0 {
            return Err(SvcError::Conflict);
        }
        if let Some(frame) = state.reserved {
            reclaim(ledger, frame)?;
        }
        *state = PageState::default();
        region.present &= !(1 << i);
        Ok(())
    }

    fn mapping(&self, index: usize) -> Option<Mapping> {
        let region = self
            .regions
            .iter()
            .flatten()
            .find(|region| region.owns(index))?;
        region.state[index - region.start].mapping
    }

    pub(super) fn fragment(
        &self,
        space: Space,
        address: u64,
        count: usize,
        write: bool,
    ) -> Result<Fragment, Errno> {
        checked_user_span(address, count, VM_BASE, VM_END).map_err(|_| Errno::Fault)?;
        let offset = address - VM_BASE;
        let index = (offset / PAGE as u64) as usize;
        let mapping = self.mapping(index).ok_or(Errno::Fault)?;
        let entry = space.leaf(address, addr_of!(VM_MIDDLE), addr_of!(VM_LEAF))?;
        let physical = mmu::checked_user_leaf_span(
            entry,
            PhysAddr(mapping.frame.address),
            offset % PAGE as u64,
            count,
            write,
        )
        .map_err(|_| Errno::Fault)?;
        Ok(Fragment {
            physical: physical.0,
            managed: Some(mapping.frame.handle),
        })
    }

    pub(super) fn fault(&mut self, space: Space, context: &user::Context) -> bool {
        // Require a classified lower-EL AArch64 L3 translation abort in
        // this root's admitted aperture. Permission faults and fetches
        // still follow the ordinary task retirement path.
        let esr = context.esr;
        if !is_live_epoch(space.actor.generation)
            || esr >> 26 != 0x24
            || esr & 0x3f != 0x07
            || !contains(context.far)
        {
            return false;
        }
        let index = ((context.far - VM_BASE) / PAGE as u64) as usize;
        let Some(region) = self
            .regions
            .iter_mut()
            .flatten()
            .find(|region| region.owns(index))
        else {
            return false;
        };
        let state = &mut region.state[index - region.start];
        if state.mapping.is_some()
            || space.leaf(context.far, addr_of!(VM_MIDDLE), addr_of!(VM_LEAF)) != Ok(0)
        {
            return false;
        }
        let result = with_business_ledger(|ledger| {
            let frame = if let Some(frame) = state.reserved.take() {
                frame
            } else {
                reserve_frame(ledger, self.owner)?
            };
            commit_frame(ledger, frame).map_err(|error| match error {
                SvcError::Busy => SvcError::Conflict,
                other => other,
            })?;
            let mapping = Mapping {
                frame,
                owned: false,
                write: true,
            };
            ledger
                .retain(frame.handle, Reference::Mapping, |_| {
                    publish_leaf(page_entry(index), mapping)
                })
                .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
            state.mapping = Some(mapping);
            Ok(())
        });
        // A transient ledger turn on CPU0 is retried by reentering the same
        // faulting instruction. No EL0 progress or unpublished PTE escapes.
        matches!(result, Ok(()) | Err(SvcError::Busy))
    }

    pub(super) fn retire(&mut self) {
        loop {
            let outcome = with_business_ledger(|ledger| {
                for region in self.regions.iter_mut().flatten() {
                    for i in 0..region.pages {
                        if region.present & (1 << i) != 0 {
                            Self::drop_page(ledger, region, i)
                                .unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                        }
                    }
                }
                for frame in self.owned.iter_mut().filter_map(Option::take) {
                    reclaim(ledger, frame).unwrap_or_else(|_| fatal(BUSINESS_FAULT));
                }
                Ok(())
            });
            match outcome {
                Ok(()) => return,
                Err(SvcError::Busy) => poll_later(),
                Err(_) => fatal(BUSINESS_FAULT),
            }
        }
    }
}
