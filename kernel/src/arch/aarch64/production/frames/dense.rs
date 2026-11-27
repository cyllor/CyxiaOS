//! The canonical FrameMeta owner in the native 1 GiB profiles.
//! Static classifications are subregions of the reserved boot arena.
//! CPU0 owns all changes to the physical record table.

use super::super::role_loader::high_leaf;
#[cfg(feature = "v020-production-frame-pool")]
use super::super::{NativeRoleManifest, Role};
use super::{
    COUNT, Error, FrameMeta, Ledger, LedgerError, MemoryRegion, Ordering, PAGE, REGISTERED,
    RegionKind, install_ledger, publish_counts, report, service_arena, statics,
};
#[cfg(feature = "v020-production-frame-pool")]
use super::{evidence, native_ledger};
use core::ptr;
#[cfg(feature = "v020-production-frame-pool")]
use core::sync::atomic::AtomicU64;
use cyxia_contracts::BootInfo;
use cyxia_kernel_core::frame_meta_v0199::{Inventory, POOL_BYTES, RAM_BYTES, TABLE_BYTES};
#[cfg(feature = "v020-production-frame-pool")]
use cyxia_kernel_core::frame_meta_v0199::{Owner, Reference};
use cyxia_platform_virt::{KERNEL_POOL_END, RAM_BASE, USER_RAM_END, reserve_user_pool};

const EL1_RAM_LEAF: u64 = 0x0060_0000_0000_0703;
const MAP_BATCH: usize = 128 * PAGE as usize;
const ZERO_BATCH: usize = 1024;

#[cfg(feature = "v020-production-frame-pool")]
const PROBE_PAGES: usize = 4;
#[cfg(feature = "v020-production-frame-pool")]
static PROVED_FREE: AtomicU64 = AtomicU64::new(0);

fn mapped_page(pa: u64) -> Result<*mut u64, LedgerError> {
    if !pa.is_multiple_of(PAGE) || !(KERNEL_POOL_END..USER_RAM_END).contains(&pa) {
        return Err(LedgerError::Invalid);
    }
    // SAFETY: this PA is inside the allocated high-half RAM page table.
    // Only CPU0 changes the kernel leaves in the native lane.
    if unsafe { high_leaf(pa).read_volatile() } != (pa | EL1_RAM_LEAF) {
        return Err(LedgerError::Unauthorized);
    }
    Ok(ptr::without_provenance_mut((crate::HIGH + pa) as usize))
}

pub(in super::super) struct Registration {
    ledger: Ledger<'static>,
    inventory: Inventory,
    registered: u32,
    service_pages: u64,
    metadata: MemoryRegion,
    control: MemoryRegion,
    progress: MemoryRegion,
}

pub(in super::super) fn prepare(
    info: &mut BootInfo,
    checkpoint: &mut impl FnMut() -> Result<(), LedgerError>,
) -> Result<Registration, Error> {
    checkpoint().map_err(Error::Ledger)?;
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return Err(Error::Once);
    }
    let ram = info.ram[0];
    let previous_reservations = info.reserved_count;
    if info.ram_count != 1
        || ram.start.0 != RAM_BASE
        || ram.len != RAM_BYTES
        || ram.kind != RegionKind::Ram
        || previous_reservations > info.reserved.len()
    {
        return Err(Error::Range);
    }
    let arena = MemoryRegion {
        len: KERNEL_POOL_END - RAM_BASE,
        kind: RegionKind::Reserved,
        ..ram
    };
    let metadata = reserve_user_pool(info, TABLE_BYTES as u64).map_err(|_| Error::Range)?;
    checkpoint().map_err(Error::Ledger)?;
    let control = reserve_user_pool(info, POOL_BYTES).map_err(|_| Error::Range)?;
    checkpoint().map_err(Error::Ledger)?;
    let progress = reserve_user_pool(info, POOL_BYTES).map_err(|_| Error::Range)?;
    let end = metadata.end().map_err(|_| Error::Range)?;
    for start in (metadata.start.0..end).step_by(MAP_BATCH) {
        checkpoint().map_err(Error::Ledger)?;
        for pa in (start..end.min(start + MAP_BATCH as u64)).step_by(PAGE as usize) {
            mapped_page(pa).map_err(Error::Ledger)?;
        }
    }
    let table = mapped_page(metadata.start.0)
        .map_err(Error::Ledger)?
        .cast::<FrameMeta>();
    // SAFETY: BootInfo reserves the mapped table exclusively for this
    // one-shot owner. It has no allocator, EL0 or DMA borrowers.
    for offset in (0..COUNT).step_by(ZERO_BATCH) {
        checkpoint().map_err(Error::Ledger)?;
        unsafe { ptr::write_bytes(table.add(offset), 0, ZERO_BATCH.min(COUNT - offset)) };
    }
    // Every row is initialized, and the backing stays reserved for this boot.
    let rows = unsafe { core::slice::from_raw_parts_mut(table, COUNT) };
    let (mut ledger, inventory) = Ledger::initialize_checkpointed(
        rows,
        ram,
        [arena, metadata, control, progress],
        &info.reserved[..previous_reservations],
        checkpoint,
    )
    .map_err(Error::Ledger)?;
    checkpoint().map_err(Error::Ledger)?;
    let service = service_arena()?;
    let registered = ledger
        .register_arena_statics(&statics(service)?)
        .map_err(Error::Ledger)?;
    Ok(Registration {
        ledger,
        inventory,
        registered,
        service_pages: service.region.len / PAGE,
        metadata,
        control,
        progress,
    })
}

impl Registration {
    pub(in super::super) fn publish(self) {
        install_ledger(self.ledger);
        publish_counts(
            u64::from(self.registered),
            u64::from(self.inventory.permanent),
            self.service_pages,
        );
        report(
            "V020_SEC_M_DENSE_FRAME_TABLE",
            self.metadata.start.0,
            COUNT as u64,
            TABLE_BYTES as u64,
        );
        report(
            "V020_SEC_M_DENSE_FRAME_POOLS",
            self.control.start.0,
            self.progress.start.0,
            POOL_BYTES,
        );
        report(
            "V020_SEC_M_DENSE_FRAME_ROWS",
            u64::from(self.inventory.permanent),
            u64::from(self.inventory.free),
            0,
        );
    }
}

#[cfg(feature = "v020-production-frame-pool")]
fn zero_page(pa: u64) -> Result<(), LedgerError> {
    let page = mapped_page(pa)?;
    // SAFETY: the dense ledger supplies a reserved or fully quiescent
    // frame. Its verified direct mapping permits EL1-only access.
    unsafe { ptr::write_bytes(page, 0, PAGE as usize / size_of::<u64>()) };
    for word in 0..PAGE as usize / size_of::<u64>() {
        if unsafe { page.add(word).read_volatile() } != 0 {
            return Err(LedgerError::Unknown);
        }
    }
    Ok(())
}

#[cfg(feature = "v020-production-frame-pool")]
pub(super) fn exercise(manifest: &NativeRoleManifest) -> Result<(), LedgerError> {
    manifest.validate().map_err(|_| LedgerError::Unauthorized)?;
    let index = manifest
        .members
        .iter()
        .position(|role| role.role == Role::Supervisor)
        .ok_or(LedgerError::Unauthorized)?;
    let actor = manifest.members[index].actor;
    let owner = Owner {
        slot: index as u32,
        generation: actor.generation,
    };
    let mut ledger = native_ledger()
        .ok_or(LedgerError::Unauthorized)?
        .try_borrow_mut()
        .map_err(|_| LedgerError::Busy)?;
    let before = ledger.inventory()?;
    let mut handles = [None; PROBE_PAGES];
    for slot in &mut handles {
        let handle = ledger.reserve(owner)?;
        ledger.commit(handle, true, zero_page)?;
        *slot = Some(handle);
    }
    let allocated = ledger.inventory()?;
    if allocated.allocated != before.allocated + PROBE_PAGES as u32
        || allocated.free + PROBE_PAGES as u32 != before.free
    {
        return Err(LedgerError::Conflict);
    }
    let first = handles[0].ok_or(LedgerError::Conflict)?;
    let physical = ledger.address(first);
    let mut pinned_page = None;
    ledger.retain(first, Reference::Pin, |pa| {
        pinned_page = Some(mapped_page(pa)?);
        Ok(())
    })?;
    let page = pinned_page.ok_or(LedgerError::Conflict)?;
    // SAFETY: CPU0 holds the verified pin, no task or device has a mapping
    // of the probe page and its direct leaf is EL1-only and non-executable.
    unsafe { page.write_volatile(actor.id) };
    ledger.quarantine(first)?;
    if ledger.reclaim(first, |_| Err(LedgerError::Conflict)) != Err(LedgerError::Busy)
        || unsafe { page.read_volatile() } != actor.id
    {
        return Err(LedgerError::Conflict);
    }
    ledger.release_ref(first, Reference::Pin, |pa| mapped_page(pa).map(|_| ()))?;
    ledger.reclaim(first, zero_page)?;
    let successor = ledger.reserve(owner)?;
    if ledger.address(successor) != physical
        || successor.generation() != first.generation() + 1
        || ledger.retain(first, Reference::Pin, |_| Err(LedgerError::Conflict))
            != Err(LedgerError::Stale)
    {
        return Err(LedgerError::Conflict);
    }
    ledger.commit(successor, true, zero_page)?;
    handles[0] = Some(successor);
    for handle in handles.into_iter().flatten() {
        ledger.quarantine(handle)?;
        ledger.reclaim(handle, zero_page)?;
    }
    if ledger.inventory()? != before {
        return Err(LedgerError::Conflict);
    }
    PROVED_FREE.store(PROBE_PAGES as u64, Ordering::Release);
    report(
        "V020_SEC_M_DENSE_FRAME_OWNER",
        index as u64,
        actor.id,
        actor.generation,
    );
    report(
        "V020_SEC_M_DENSE_FRAME_REVOKE",
        physical,
        first.generation(),
        successor.generation(),
    );
    Ok(())
}

#[cfg(feature = "v020-production-frame-pool")]
pub(super) fn publish() {
    let free = PROVED_FREE.load(Ordering::Acquire);
    assert_eq!(free, PROBE_PAGES as u64);
    evidence::put(evidence::W14_FRAME_POOL_LIFECYCLE, 1);
    evidence::put(evidence::W14_FRAME_POOL_PAGES, PROBE_PAGES as u64);
    evidence::put(evidence::W14_FRAME_POOL_FREE, free);
    report("V020_W14_FRAME_POOL", 1, PROBE_PAGES as u64, free);
}
