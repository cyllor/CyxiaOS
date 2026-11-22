//! Actual unmap bodies, VM/maps and PTE/alias algorithms. Grants, frame clearing
//! and shared-object release below are observation fixtures, not MMU evidence.
use crate::{Errno, runtime_fixture as runtime, space::*, staging::{PageTable, ProcessSpace}};
use crate::vm;
use std::{panic::{AssertUnwindSafe, catch_unwind}, sync::atomic::{AtomicUsize, Ordering}};

const PA: u64 = 0x00400000;
static RELEASES: AtomicUsize = AtomicUsize::new(0);
#[derive(Clone, Copy)]
struct Owner { task: u64 }
#[derive(Clone, Copy)]
struct Allocation { start: u64, pages: usize, redemption: u64 }
struct PageCount(u32);
struct ReleaseReceipt;
impl ReleaseReceipt {
    unsafe fn after_revoke(_: u64, _: Owner, pages: PageCount) -> Self {
        assert_eq!(pages.0, 2);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 2);
        Self
    }
}
struct Ledger;
impl Ledger {
    fn release_completed(&mut self, _: ReleaseReceipt) -> Result<(), ()> { Ok(()) }
}
struct Usage { allocations: u32, largest_free: u32 }
#[derive(Clone, Copy)]
struct Frame(u64);
mod pool {
    use super::*;
    pub fn check_owned(frame: Frame, owner: u64) -> Result<(), Errno> {
        if owner == 1 && (PA..PA + 8192).contains(&frame.0) { Ok(()) } else { Err(Errno::Io) }
    }
    pub fn release(frame: Frame, _: u64) -> Result<(), Errno> {
        assert_eq!(runtime::count(frame.0), 0, "freeing a still-published frame");
        RELEASES.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
enum Domain { Anonymous, SharedMappings }
mod ai {
    pub struct Counter;
    impl Counter { pub fn release(&mut self, _: u64) {} }
    pub fn record(_: super::Domain, f: impl FnOnce(&mut Counter)) { f(&mut Counter); }
}
// @HEAP_LIMITS@
struct Heap {
    allocations: [Option<Allocation>; ALLOCATIONS], owner: Option<Owner>,
    free_allocations: [u64; ALLOCATIONS / 64],
    frames: Vec<Option<Frame>>, vm: vm::Vm, batch: vm::PageBatch,
    tables: Vec<PageTable>, ledger: Ledger, usage: Usage,
}
impl Heap {
    // @HEAP_UNMAP@
}
use crate::shared_metadata::{Maps, BASE, PAGES};
const PAGE_SIZE: usize = 4096;
struct SharedMappings { maps: Maps, tables: Vec<PageTable> }
impl SharedMappings {
    // @SHARED_UNMAP@
}

#[repr(C, align(4096))]
struct Tables([u8; 8 * 4096]);
fn owner() -> (Box<Tables>, ProcessSpace) {
    let mut memory = Box::new(Tables([0; 8 * 4096]));
    let kernel = KernelMappings::new([0; 256], runtime::RAM).unwrap();
    let arena = unsafe { TableArena::from_raw(memory.0.as_mut_ptr(), 0x200000, 8) }.unwrap();
    let space = unsafe { AddressSpace::new(arena, &kernel, SpaceId { id: 1, generation: 1 }) }.unwrap();
    (memory, ProcessSpace::test_owner(Some(space)))
}
fn heap(space: &mut ProcessSpace) -> Heap {
    RELEASES.store(0, Ordering::Relaxed);
    let mut vm = vm::Vm::new();
    let mut batch = vm::PageBatch::new();
    vm.allocate_into(2, &mut batch).unwrap();
    let mut heap = Heap {
        allocations: [None; ALLOCATIONS], free_allocations: [u64::MAX; ALLOCATIONS / 64],
        owner: Some(Owner { task: 1 }), frames: vec![None; vm::PAGE_COUNT], vm, batch,
        tables: (0..vm::PAGE_COUNT / 512).map(|_| PageTable::empty()).collect(),
        ledger: Ledger, usage: Usage { allocations: 1, largest_free: 0 },
    };
    heap.store_allocation(0, Some(Allocation { start: vm::BASE, pages: 2, redemption: 1 }));
    for page in heap.batch.iter() {
        let pa = PA + page.slot as u64 * 4096;
        heap.frames[page.slot] = Some(Frame(pa));
        let i = ((page.address - vm::BASE) / 4096) as usize;
        heap.tables[i / 512].set(i % 512, pa, 3).unwrap();
    }
    heap.tables[0].synchronize(space, vm::BASE, true).unwrap();
    heap
}

#[test]
fn runtime_batch_heap_free_slots_preserve_first_fit_through_fill_and_reuse() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = owner();
    let mut heap = heap(&mut space);
    let allocation = heap.allocations[0];
    for slot in 1..ALLOCATIONS {
        assert_eq!(heap.free_allocation_slot(), Some(slot));
        heap.store_allocation(slot, allocation);
    }
    assert_eq!(heap.free_allocation_slot(), None);
    for slot in [ALLOCATIONS - 1, 64, 63] {
        heap.store_allocation(slot, None);
        assert_eq!(heap.free_allocation_slot(), Some(slot));
    }
    heap.store_allocation(63, allocation);
    assert_eq!(heap.free_allocation_slot(), Some(64));
    heap.store_allocation(64, allocation);
    assert_eq!(heap.free_allocation_slot(), Some(ALLOCATIONS - 1));
}

#[test]
fn runtime_batch_heap_unmap_revokes_real_ptes_before_frame_and_grant_release() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = owner();
    let mut heap = heap(&mut space);
    heap.unmap_with_revoke(vm::BASE, 2, |address, pages| space.revoke_range(address, pages).unwrap()).unwrap();
    assert_eq!(heap.vm.used(), 0);
    assert!(heap.allocations[0].is_none());
    assert_eq!(heap.free_allocation_slot(), Some(0));
    assert_eq!(heap.usage.allocations, 0);
    assert_eq!(RELEASES.load(Ordering::Relaxed), 2);
    assert!(space.root().unwrap().translate(vm::BASE).is_none());
    heap.tables[0].synchronize(&mut space, vm::BASE, false).unwrap();
    assert_eq!(runtime::count(PA), 0);
}

#[test]
fn runtime_batch_rejected_or_failed_heap_revoke_preserves_vm_frames_and_grants() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = owner();
    let mut heap = heap(&mut space);
    assert_eq!(heap.unmap_with_revoke(vm::BASE, 1, |_, _| panic!("invalid range reached revoke")), Err(Errno::Inval));
    let failed = catch_unwind(AssertUnwindSafe(|| {
        heap.unmap_with_revoke(vm::BASE, 2, |_, _| panic!("fixture revoke failure")).unwrap();
    }));
    assert!(failed.is_err());
    assert_eq!(heap.vm.used(), 2);
    assert!(heap.allocations[0].is_some());
    assert_eq!(heap.free_allocation_slot(), Some(1));
    assert!(heap.frames[0].is_some());
    assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
    assert_eq!(runtime::count(PA), 1 | 1 << 20);
    assert_eq!(runtime::count(PA + 4096), 1 | 1 << 20);
}

#[test]
fn runtime_batch_failed_alias_revoke_publishes_prefix_but_releases_no_heap_backing() {
    let _lock = runtime::TEST.lock().unwrap();
    runtime::reset();
    let (_memory, mut space) = owner();
    let mut heap = heap(&mut space);
    let epoch = space.root().unwrap().epoch();
    runtime::set_count(PA + 4096, 0);
    runtime::take_epoch_publications();
    let failed = catch_unwind(AssertUnwindSafe(|| {
        heap.unmap_with_revoke(vm::BASE, 2, |address, pages| space.revoke_range(address, pages).unwrap()).unwrap();
    }));
    // Restore the corrupted count before any test panic could run the root destructor.
    runtime::set_count(PA + 4096, 1 | 1 << 20);
    assert!(failed.is_err());
    assert!(space.root().unwrap().translate(vm::BASE).is_none());
    assert_eq!(space.root().unwrap().translate(vm::BASE + 4096).unwrap().physical, PA + 4096);
    assert_eq!(space.root().unwrap().epoch(), epoch + 1);
    assert_eq!(runtime::take_epoch_publications(), 1);
    assert_eq!(runtime::count(PA), 0);
    assert!(!runtime::gate());
    assert_eq!(heap.vm.used(), 2);
    assert!(heap.allocations[0].is_some());
    assert!(heap.frames[..2].iter().all(Option::is_some));
    assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
}

#[test]
fn runtime_batch_shared_last_mapping_revokes_before_releasing_object_backing() {
    let _lock = runtime::TEST.lock().unwrap(); runtime::reset();
    let (_memory, mut space) = owner();
    let mut shared = SharedMappings { maps: Maps::new(), tables: (0..PAGES / 512).map(|_| PageTable::empty()).collect() };
    let mapping = shared.maps.prepare(1, 0, 8192, 3, true).unwrap();
    shared.maps.insert(mapping).unwrap();
    shared.tables[0].set(0, PA, 3).unwrap();
    shared.tables[0].set(1, PA + 4096, 3).unwrap();
    shared.tables[0].synchronize(&mut space, BASE, true).unwrap();
    crate::shared_memory::DROPS.store(0, Ordering::Relaxed);
    assert_eq!(shared.unmap_with_revoke(BASE, 1, |_, _| panic!("invalid range reached revoke")), Err(Errno::Inval));
    shared.unmap_with_revoke(BASE, 2, |address, pages| space.revoke_range(address, pages).unwrap()).unwrap();
    assert_eq!(crate::shared_memory::DROPS.load(Ordering::Relaxed), 1);
    assert!(shared.maps.iter().next().is_none());
    assert!(space.root().unwrap().translate(BASE).is_none());
    shared.tables[0].synchronize(&mut space, BASE, false).unwrap();
}
