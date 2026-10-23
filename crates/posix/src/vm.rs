//! Bounded anonymous user mappings, with no hardware or allocation-policy dependency.
//!
//! Each `Vm` describes one private physical pool and one bounded user virtual window
//! (8 MiB normally, 16 MiB with `large-memory`).
//! Pool slots are indices, never physical addresses. Allocations default to RW/NX;
//! per-page permissions may become NONE or R/NX. The kernel must enforce the metadata
//! in PTEs; permissions do not change physical ownership or grant accounting.
//!
//! The kernel owns the physical pages, generation checks, AI admission and publication:
//! 1. Validate an AI memory grant before calling `allocate`.
//! 2. Zero every returned physical slot before making any returned PTE user-accessible.
//! 3. On `unmap`, revoke all returned PTEs and complete TLB invalidation before clearing
//!    physical memory, releasing its grant, reusing slots or calling `allocate` again.
//! 4. Perform the same revocation before replacing this metadata when a process exits.
//!
//! Returned batches are snapshots, not generation-checked authority. The kernel must
//! serialize these operations with user execution and guard against stale receipts.
use crate::Errno;

#[cfg(not(feature = "large-memory"))]
pub const BASE: u64 = 0x200000;
#[cfg(feature = "large-memory")]
pub const BASE: u64 = 0x04000000;
pub const END: u64 = BASE + (PAGE_COUNT * PAGE_SIZE) as u64;
pub const PAGE_SIZE: usize = 4096;
#[cfg(not(feature = "large-memory"))]
pub const PAGE_COUNT: usize = 2048;
#[cfg(feature = "large-memory")]
pub const PAGE_COUNT: usize = 4096;
const UNMAPPED: u16 = u16::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One user page and the backing slot reserved exclusively for it.
pub struct Page {
    pub address: u64,
    pub slot: usize,
}

#[derive(Debug, PartialEq, Eq)]
/// Compact snapshot of a newly reserved or removed virtual range.
pub struct PageBatch {
    start: u64,
    count: usize,
    slots: [u16; PAGE_COUNT],
}

impl PageBatch {
    /// Reusable caller-owned output. Kernel callers keep this in pinned metadata
    /// rather than returning an 8 KiB snapshot through a small exception stack.
    pub const fn new() -> Self {
        Self {
            start: 0,
            count: 0,
            slots: [UNMAPPED; PAGE_COUNT],
        }
    }

    pub const fn start(&self) -> u64 {
        self.start
    }

    pub const fn page_count(&self) -> usize {
        self.count
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = Page> + '_ {
        self.slots[..self.count]
            .iter()
            .enumerate()
            .map(|(i, slot)| Page {
                address: self.start + (i * PAGE_SIZE) as u64,
                slot: usize::from(*slot),
            })
    }
}

impl Default for PageBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// One part of a fully validated user copy, contained in a single backing page.
pub struct Fragment {
    pub address: u64,
    pub slot: usize,
    pub offset: usize,
    pub len: usize,
}

/// Borrows the metadata so a validated range cannot be changed during iteration.
pub struct Fragments<'a> {
    vm: &'a Vm,
    next: u64,
    end: u64,
}

impl Iterator for Fragments<'_> {
    type Item = Fragment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        let relative = (self.next - BASE) as usize;
        let offset = relative % PAGE_SIZE;
        let len = (self.end - self.next).min((PAGE_SIZE - offset) as u64) as usize;
        let fragment = Fragment {
            address: self.next,
            slot: usize::from(self.vm.slots[relative / PAGE_SIZE]),
            offset,
            len,
        };
        self.next += len as u64;
        Some(fragment)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = if self.next == self.end {
            0
        } else {
            ((self.end - 1 - BASE) / PAGE_SIZE as u64 - (self.next - BASE) / PAGE_SIZE as u64 + 1)
                as usize
        };
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Fragments<'_> {}
impl core::iter::FusedIterator for Fragments<'_> {}

/// Metadata for one externally owned, exclusively backed process memory pool.
pub struct Vm {
    slots: [u16; PAGE_COUNT],
    protections: [u8; PAGE_COUNT],
    physical_in_use: [bool; PAGE_COUNT],
    used: usize,
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    pub const fn new() -> Self {
        Self {
            slots: [UNMAPPED; PAGE_COUNT],
            protections: [0; PAGE_COUNT],
            physical_in_use: [false; PAGE_COUNT],
            used: 0,
        }
    }

    pub const fn used(&self) -> usize {
        self.used
    }

    pub const fn free(&self) -> usize {
        PAGE_COUNT - self.used
    }

    /// Atomically change already allocated pages to NONE (0), R (1), or RW (3).
    ///
    /// `start` must be page aligned, and the nonzero byte length covers its final
    /// partial page. Every covered page must be allocated; a hole leaves the entire
    /// range unchanged. Execute permission is never supported. The caller must stop
    /// user execution, update its PTEs and finish TLB synchronization before resuming.
    pub fn protect(&mut self, start: u64, len_bytes: usize, protection: u8) -> Result<(), Errno> {
        if !matches!(protection, 0 | 1 | 3)
            || !start.is_multiple_of(PAGE_SIZE as u64)
            || len_bytes == 0
            || !(BASE..END).contains(&start)
        {
            return Err(Errno::Inval);
        }
        let length = u64::try_from(len_bytes).map_err(|_| Errno::Inval)?;
        let end = start.checked_add(length).ok_or(Errno::Inval)?;
        if end > END {
            return Err(Errno::Inval);
        }
        self.validate(start, len_bytes)?;
        let first = ((start - BASE) / PAGE_SIZE as u64) as usize;
        let last = ((end - 1 - BASE) / PAGE_SIZE as u64) as usize;
        self.protections[first..=last].fill(protection);
        Ok(())
    }

    /// Return the allocated page's permissions, even when its current value is NONE.
    pub fn permissions(&self, address: u64) -> Result<u8, Errno> {
        self.validate(address, 1)?;
        Ok(self.protections[((address - BASE) / PAGE_SIZE as u64) as usize])
    }

    /// Check allocation and every page's permission before any user copy occurs.
    /// NONE denies both operations; R denies writing. Zero-length policy is left
    /// to the syscall adapter, as with `validate` and `fragments`.
    pub fn validate_access(&self, address: u64, len: usize, write: bool) -> Result<(), Errno> {
        self.validate(address, len)?;
        let first = ((address - BASE) / PAGE_SIZE as u64) as usize;
        // validate proved this addition cannot overflow and remains in the window.
        let last = ((address + len as u64 - 1 - BASE) / PAGE_SIZE as u64) as usize;
        let required = if write { 3 } else { 1 };
        if self.protections[first..=last]
            .iter()
            .any(|permission| permission & required != required)
        {
            return Err(Errno::Fault);
        }
        Ok(())
    }

    /// Reserve first-fit virtual pages using arbitrary free physical slots.
    ///
    /// Call only after external AI admission. Nothing becomes hardware-accessible
    /// here: the caller must zero the slots before publishing user page tables.
    /// An error leaves every mapping and capacity counter unchanged.
    pub fn allocate(&mut self, page_count: usize) -> Result<PageBatch, Errno> {
        let mut batch = PageBatch::new();
        self.allocate_into(page_count, &mut batch)?;
        Ok(batch)
    }

    /// Same transaction as `allocate`, using caller-owned scratch storage. On any
    /// error the output is empty, so a reused batch cannot expose stale receipts.
    pub fn allocate_into(&mut self, page_count: usize, batch: &mut PageBatch) -> Result<(), Errno> {
        batch.count = 0;
        batch.start = 0;
        if page_count == 0 {
            return Err(Errno::Inval);
        }
        if page_count > self.free() {
            return Err(Errno::Nomem);
        }
        let first = self
            .slots
            .windows(page_count)
            .position(|window| window.iter().all(|&slot| slot == UNMAPPED))
            .ok_or(Errno::Nomem)?;
        let mut selected = 0;
        for (slot, in_use) in self.physical_in_use.iter().enumerate() {
            if !in_use {
                batch.slots[selected] = slot as u16;
                selected += 1;
                if selected == page_count {
                    break;
                }
            }
        }
        // Keep this method failure-atomic even if internal accounting changes later.
        if selected != page_count {
            return Err(Errno::Nomem);
        }
        self.slots[first..first + page_count].copy_from_slice(&batch.slots[..page_count]);
        self.protections[first..first + page_count].fill(3);
        for &slot in &batch.slots[..page_count] {
            self.physical_in_use[usize::from(slot)] = true;
        }
        self.used += page_count;
        batch.start = BASE + (first * PAGE_SIZE) as u64;
        batch.count = page_count;
        Ok(())
    }

    /// Remove a complete page range after validating every page, including holes.
    ///
    /// The result lists pages requiring hardware revocation. Metadata slots become
    /// available immediately, so the caller must complete PTE/TLB revocation and
    /// physical clearing before any new allocation or user execution. This method
    /// never clears memory or releases the caller's AI grant.
    pub fn unmap(&mut self, start: u64, page_count: usize) -> Result<PageBatch, Errno> {
        let mut batch = PageBatch::new();
        self.unmap_into(start, page_count, &mut batch)?;
        Ok(batch)
    }

    /// Caller-owned form of `unmap`; failure clears the output without changing
    /// any mapping. The same revocation and serialization contract applies.
    pub fn unmap_into(
        &mut self,
        start: u64,
        page_count: usize,
        batch: &mut PageBatch,
    ) -> Result<(), Errno> {
        batch.count = 0;
        batch.start = 0;
        if page_count == 0
            || page_count > PAGE_COUNT
            || !start.is_multiple_of(PAGE_SIZE as u64)
            || !(BASE..END).contains(&start)
        {
            return Err(Errno::Inval);
        }
        let first = ((start - BASE) / PAGE_SIZE as u64) as usize;
        if page_count > PAGE_COUNT - first {
            return Err(Errno::Inval);
        }
        let range = first..first + page_count;
        if self.slots[range.clone()].contains(&UNMAPPED) {
            return Err(Errno::Fault);
        }
        batch.slots[..page_count].copy_from_slice(&self.slots[range.clone()]);
        self.slots[range.clone()].fill(UNMAPPED);
        self.protections[range].fill(0);
        for &slot in &batch.slots[..page_count] {
            self.physical_in_use[usize::from(slot)] = false;
        }
        self.used -= page_count;
        batch.start = start;
        batch.count = page_count;
        Ok(())
    }

    /// Validate allocation of a nonempty byte range, without checking permissions.
    ///
    /// Copies may start or end within a page. Unlike allocations and unmaps, their
    /// addresses do not need page alignment. Physical clearing/revocation may access
    /// NONE pages. User copy paths must additionally call `validate_access`.
    pub fn validate(&self, address: u64, len: usize) -> Result<(), Errno> {
        if len == 0 || !(BASE..END).contains(&address) {
            return Err(Errno::Fault);
        }
        let byte_count = u64::try_from(len).map_err(|_| Errno::Fault)?;
        let end = address.checked_add(byte_count).ok_or(Errno::Fault)?;
        if end > END {
            return Err(Errno::Fault);
        }
        let first = ((address - BASE) / PAGE_SIZE as u64) as usize;
        let last = ((end - 1 - BASE) / PAGE_SIZE as u64) as usize;
        if self.slots[first..=last].contains(&UNMAPPED) {
            return Err(Errno::Fault);
        }
        Ok(())
    }

    /// Validate allocation before exposing page-contained physical fragments.
    /// This deliberately permits NONE pages for physical maintenance; user copy
    /// paths must additionally call `validate_access` before obtaining fragments.
    pub fn fragments(&self, address: u64, len: usize) -> Result<Fragments<'_>, Errno> {
        self.validate(address, len)?;
        Ok(Fragments {
            vm: self,
            next: address,
            end: address + len as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[test]
    fn reusable_batch_clears_stale_receipts_and_preserves_mappings_on_failure() {
        let mut vm = Vm::new();
        let mut batch = PageBatch::new();
        vm.allocate_into(2, &mut batch).unwrap();
        assert_eq!(batch.start(), BASE);
        assert_eq!(batch.page_count(), 2);
        assert_eq!(vm.allocate_into(PAGE_COUNT, &mut batch), Err(Errno::Nomem));
        assert_eq!(batch.iter().count(), 0);
        assert_eq!(vm.used(), 2);
        assert_eq!(vm.unmap_into(BASE, 3, &mut batch), Err(Errno::Fault));
        assert_eq!(batch.page_count(), 0);
        assert_eq!(vm.validate(BASE, 2 * PAGE_SIZE), Ok(()));
        vm.unmap_into(BASE, 2, &mut batch).unwrap();
        assert_eq!(
            batch.iter().map(|page| page.slot).collect::<Vec<_>>(),
            [0, 1]
        );
        vm.allocate_into(PAGE_COUNT, &mut batch).unwrap();
        assert_eq!(batch.page_count(), PAGE_COUNT);
        assert_eq!(batch.iter().last().unwrap().address, END - PAGE_SIZE as u64);
        vm.unmap_into(BASE, PAGE_COUNT, &mut batch).unwrap();
        assert_eq!(vm.free(), PAGE_COUNT);
    }

    #[test]
    fn protected_reservation_can_activate_one_page_without_exposing_its_neighbor() {
        let mut vm = Vm::new();
        vm.allocate(2).unwrap();
        assert_eq!(vm.permissions(BASE), Ok(3));
        assert_eq!(vm.validate_access(BASE, 2 * PAGE_SIZE, true), Ok(()));
        vm.protect(BASE, 2 * PAGE_SIZE, 0).unwrap();
        assert_eq!(vm.validate_access(BASE, 1, false), Err(Errno::Fault));
        assert_eq!(vm.validate_access(BASE, 1, true), Err(Errno::Fault));
        assert_eq!(vm.validate(BASE, 2 * PAGE_SIZE), Ok(()));
        assert_eq!(vm.fragments(BASE, 2 * PAGE_SIZE).unwrap().count(), 2);
        let second = BASE + PAGE_SIZE as u64;
        vm.protect(second, PAGE_SIZE, 1).unwrap();
        assert_eq!(vm.validate_access(second, PAGE_SIZE, false), Ok(()));
        assert_eq!(
            vm.validate_access(second, PAGE_SIZE, true),
            Err(Errno::Fault)
        );
        vm.protect(second, PAGE_SIZE, 3).unwrap();
        assert_eq!(vm.validate_access(second, PAGE_SIZE, true), Ok(()));
        assert_eq!(vm.validate_access(BASE, 1, false), Err(Errno::Fault));
        assert_eq!(vm.used(), 2);
    }

    #[test]
    fn access_checks_every_page_before_allowing_a_cross_page_copy() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        vm.protect(BASE + PAGE_SIZE as u64, PAGE_SIZE, 1).unwrap();
        assert_eq!(vm.validate_access(BASE, PAGE_SIZE + 1, false), Ok(()));
        assert_eq!(
            vm.validate_access(BASE, PAGE_SIZE + 1, true),
            Err(Errno::Fault)
        );
        vm.protect(BASE + PAGE_SIZE as u64, PAGE_SIZE, 0).unwrap();
        assert_eq!(
            vm.validate_access(BASE, 3 * PAGE_SIZE, false),
            Err(Errno::Fault)
        );
        assert_eq!(vm.validate_access(BASE, PAGE_SIZE, true), Ok(()));
        assert_eq!(vm.validate_access(BASE, 0, false), Err(Errno::Fault));
        assert_eq!(vm.validate_access(u64::MAX, 2, false), Err(Errno::Fault));
    }

    #[test]
    fn protecting_a_range_with_a_hole_is_failure_atomic() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        vm.protect(BASE, PAGE_SIZE, 0).unwrap();
        vm.unmap(BASE + PAGE_SIZE as u64, 1).unwrap();
        assert_eq!(vm.protect(BASE, 3 * PAGE_SIZE, 1), Err(Errno::Fault));
        assert_eq!(vm.permissions(BASE), Ok(0));
        assert_eq!(vm.permissions(BASE + PAGE_SIZE as u64), Err(Errno::Fault));
        assert_eq!(vm.permissions(BASE + 2 * PAGE_SIZE as u64), Ok(3));
        assert_eq!(vm.used(), 2);
    }

    #[test]
    fn invalid_protection_alignment_and_overflow_do_not_change_permissions() {
        let mut vm = Vm::new();
        vm.allocate(PAGE_COUNT).unwrap();
        for (start, len, protection) in [
            (BASE + 1, PAGE_SIZE, 0),
            (BASE, 0, 0),
            (BASE, usize::MAX, 0),
            (END - PAGE_SIZE as u64, PAGE_SIZE + 1, 0),
            (u64::MAX - 4095, PAGE_SIZE, 0),
            (BASE, PAGE_SIZE, 2),
            (BASE, PAGE_SIZE, 4),
            (BASE, PAGE_SIZE, 7),
            (BASE, PAGE_SIZE, u8::MAX),
        ] {
            assert_eq!(vm.protect(start, len, protection), Err(Errno::Inval));
            assert_eq!(
                vm.validate_access(BASE, PAGE_COUNT * PAGE_SIZE, true),
                Ok(())
            );
        }
    }

    #[test]
    fn protection_length_covers_the_final_partial_page() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        vm.protect(BASE, PAGE_SIZE + 1, 1).unwrap();
        assert_eq!(vm.permissions(BASE + 2 * PAGE_SIZE as u64 - 1), Ok(1));
        assert_eq!(vm.permissions(BASE + 2 * PAGE_SIZE as u64), Ok(3));
    }

    #[test]
    fn no_access_pages_can_be_unmapped_and_reused_with_default_rw_permissions() {
        let mut vm = Vm::new();
        vm.allocate(2).unwrap();
        vm.protect(BASE, 2 * PAGE_SIZE, 0).unwrap();
        assert_eq!(vm.unmap(BASE, 2).unwrap().page_count(), 2);
        assert_eq!(vm.permissions(BASE), Err(Errno::Fault));
        assert_eq!(vm.permissions(END), Err(Errno::Fault));
        assert_eq!(vm.allocate(2).unwrap().start(), BASE);
        assert_eq!(vm.permissions(BASE), Ok(3));
        assert_eq!(vm.validate_access(BASE, 2 * PAGE_SIZE, true), Ok(()));
    }

    #[test]
    fn allocate_returns_pinned_slot_plan_and_accounts_capacity() {
        let mut vm = Vm::new();
        assert_eq!(vm.used(), 0);
        assert_eq!(vm.free(), PAGE_COUNT);
        let batch = vm.allocate(2).unwrap();
        assert_eq!(batch.start(), BASE);
        assert_eq!(batch.page_count(), 2);
        assert_eq!(batch.iter().len(), 2);
        assert_eq!(
            batch.iter().collect::<Vec<_>>(),
            [
                Page {
                    address: BASE,
                    slot: 0
                },
                Page {
                    address: BASE + PAGE_SIZE as u64,
                    slot: 1
                },
            ]
        );
        assert_eq!(vm.used(), 2);
        assert_eq!(vm.free(), PAGE_COUNT - 2);
    }

    #[test]
    fn zero_oversize_and_exhausted_allocations_do_not_change_metadata() {
        let mut vm = Vm::new();
        assert_eq!(vm.allocate(0), Err(Errno::Inval));
        assert_eq!(vm.allocate(PAGE_COUNT + 1), Err(Errno::Nomem));
        assert_eq!(vm.allocate(usize::MAX), Err(Errno::Nomem));
        assert_eq!(vm.used(), 0);
        vm.allocate(PAGE_COUNT).unwrap();
        let before = vm.slots;
        assert_eq!(vm.allocate(1), Err(Errno::Nomem));
        assert_eq!(vm.slots, before);
        assert_eq!(vm.free(), 0);
    }

    #[test]
    fn virtual_first_fit_can_use_discontiguous_physical_slots() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        vm.unmap(BASE, 1).unwrap();
        vm.unmap(BASE + 2 * PAGE_SIZE as u64, 1).unwrap();
        let batch = vm.allocate(2).unwrap();
        assert_eq!(batch.start(), BASE + 2 * PAGE_SIZE as u64);
        assert_eq!(batch.iter().map(|p| p.slot).collect::<Vec<_>>(), [0, 2]);
        let first_hole = vm.allocate(1).unwrap();
        assert_eq!(first_hole.start(), BASE);
        assert_eq!(first_hole.iter().next().unwrap().slot, 3);
    }

    #[test]
    fn fragmented_virtual_space_refuses_a_run_without_changing_any_mapping() {
        let mut vm = Vm::new();
        vm.allocate(PAGE_COUNT).unwrap();
        for i in (0..PAGE_COUNT).step_by(2) {
            vm.unmap(BASE + (i * PAGE_SIZE) as u64, 1).unwrap();
        }
        let before = vm.slots;
        let physical_before = vm.physical_in_use;
        assert_eq!(vm.free(), PAGE_COUNT / 2);
        assert_eq!(vm.allocate(2), Err(Errno::Nomem));
        assert_eq!(vm.slots, before);
        assert_eq!(vm.physical_in_use, physical_before);
    }

    #[test]
    fn unmap_reports_slots_and_makes_range_inaccessible() {
        let mut vm = Vm::new();
        vm.allocate(4).unwrap();
        let removed = vm.unmap(BASE + PAGE_SIZE as u64, 2).unwrap();
        assert_eq!(removed.start(), BASE + PAGE_SIZE as u64);
        assert_eq!(removed.page_count(), 2);
        assert_eq!(removed.iter().map(|p| p.slot).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(vm.used(), 2);
        assert_eq!(vm.validate(BASE, PAGE_SIZE), Ok(()));
        assert_eq!(vm.validate(BASE + PAGE_SIZE as u64, 1), Err(Errno::Fault));
        assert_eq!(vm.validate(BASE + 3 * PAGE_SIZE as u64, PAGE_SIZE), Ok(()));
    }

    #[test]
    fn unmap_hole_is_atomic_even_after_a_valid_prefix() {
        let mut vm = Vm::new();
        vm.allocate(4).unwrap();
        vm.unmap(BASE + 2 * PAGE_SIZE as u64, 1).unwrap();
        let before = vm.slots;
        let physical_before = vm.physical_in_use;
        assert_eq!(vm.unmap(BASE, 4), Err(Errno::Fault));
        assert_eq!(vm.slots, before);
        assert_eq!(vm.physical_in_use, physical_before);
        assert_eq!(vm.used(), 3);
    }

    #[test]
    fn unmap_rejects_invalid_alignment_count_bounds_and_overflow_atomically() {
        let mut vm = Vm::new();
        vm.allocate(PAGE_COUNT).unwrap();
        let before = vm.slots;
        for (address, count) in [
            (BASE, 0),
            (BASE + 1, 1),
            (BASE - PAGE_SIZE as u64, 1),
            (END, 1),
            (END - PAGE_SIZE as u64, 2),
            (BASE, usize::MAX),
            (u64::MAX - (PAGE_SIZE - 1) as u64, 1),
        ] {
            assert_eq!(vm.unmap(address, count), Err(Errno::Inval));
            assert_eq!(vm.slots, before);
            assert_eq!(vm.used(), PAGE_COUNT);
        }
    }

    #[test]
    fn validated_fragments_cover_exact_cross_page_range() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        let start = BASE + PAGE_SIZE as u64 - 2;
        let fragments = vm
            .fragments(start, PAGE_SIZE + 5)
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(
            fragments,
            [
                Fragment {
                    address: start,
                    slot: 0,
                    offset: PAGE_SIZE - 2,
                    len: 2
                },
                Fragment {
                    address: BASE + PAGE_SIZE as u64,
                    slot: 1,
                    offset: 0,
                    len: PAGE_SIZE
                },
                Fragment {
                    address: BASE + 2 * PAGE_SIZE as u64,
                    slot: 2,
                    offset: 0,
                    len: 3
                },
            ]
        );
        assert_eq!(
            fragments.iter().map(|f| f.len).sum::<usize>(),
            PAGE_SIZE + 5
        );
    }

    #[test]
    fn fragments_validate_whole_copy_before_exposing_any_prefix() {
        let mut vm = Vm::new();
        vm.allocate(3).unwrap();
        vm.unmap(BASE + PAGE_SIZE as u64, 1).unwrap();
        assert!(matches!(
            vm.fragments(BASE, PAGE_SIZE + 1),
            Err(Errno::Fault)
        ));
        assert!(matches!(
            vm.fragments(BASE, PAGE_SIZE * 3),
            Err(Errno::Fault)
        ));
        assert_eq!(vm.validate(BASE, PAGE_SIZE), Ok(()));
    }

    #[test]
    fn validation_rejects_zero_length_outside_window_and_wrapping_ranges() {
        let mut vm = Vm::new();
        vm.allocate(PAGE_COUNT).unwrap();
        for (address, len) in [
            (BASE, 0),
            (BASE - 1, 1),
            (END, 1),
            (END - 1, 2),
            (BASE, usize::MAX),
            (u64::MAX, 2),
        ] {
            assert_eq!(vm.validate(address, len), Err(Errno::Fault));
        }
        assert_eq!(vm.validate(BASE, PAGE_COUNT * PAGE_SIZE), Ok(()));
        assert_eq!(vm.validate(END - 1, 1), Ok(()));
    }

    #[test]
    fn last_page_and_iterator_end_are_exact() {
        let mut vm = Vm::new();
        vm.allocate(PAGE_COUNT).unwrap();
        let mut fragments = vm.fragments(END - 1, 1).unwrap();
        assert_eq!(
            fragments.next(),
            Some(Fragment {
                address: END - 1,
                slot: PAGE_COUNT - 1,
                offset: PAGE_SIZE - 1,
                len: 1,
            })
        );
        assert_eq!(fragments.next(), None);
        assert_eq!(fragments.next(), None);
    }

    #[test]
    fn repeated_reclamation_never_aliases_physical_slots() {
        let mut vm = Vm::new();
        for cycle in 0..32 {
            while let Ok(batch) = vm.allocate(1 + cycle % 5) {
                assert!(batch.iter().all(|p| p.slot < PAGE_COUNT));
            }
            assert!(vm.used() > 0);
            let mut seen = [false; PAGE_COUNT];
            for &slot in &vm.slots {
                if slot != UNMAPPED {
                    assert!(!seen[usize::from(slot)]);
                    seen[usize::from(slot)] = true;
                }
            }
            assert_eq!(seen, vm.physical_in_use);
            assert_eq!(seen.iter().filter(|used| **used).count(), vm.used());
            for i in 0..PAGE_COUNT {
                if vm.slots[i] != UNMAPPED {
                    vm.unmap(BASE + (i * PAGE_SIZE) as u64, 1).unwrap();
                }
            }
            assert_eq!(vm.used(), 0);
            assert_eq!(vm.free(), PAGE_COUNT);
        }
    }
}
