//! V0.20 wave 11: register the production boot statics in a bounded sparse
//! FrameMeta ledger before any EL0 entry.
//!
//! The static ledger registers SMP and PIE page tables as Metadata, role
//! memory and the copy buffer as Control, and SMP stacks and the pinned
//! linker-placed network/staging region as Arena. Gaps between regions remain
//! unowned permanent rows. Device and guest owners still manage mappings,
//! DMA transactions and their lifecycle.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * ROWS_BACKING (static mut): the only `&mut` to it is created once in
//!   `register_production_statics`, guarded by the REGISTERED swap, on CPU0
//!   before any secondary CPU or EL0 role runs. The ledger borrowing it is
//!   dropped before return; nothing else reads or writes the rows.
//! * REGISTERED and the inventory counters (atomics): CPU0 only. REGISTERED
//!   makes the registration one-shot; the counters carry seal-time evidence.
//! * `__sec_n_start` / `__sec_n_end` (linker symbols): only their addresses are
//!   taken (`addr_of!`); the linker places the pinned arena on page boundaries.
//! * Registered statics are only addressed via `addr_of!` (no reference is
//!   formed); their PA is `VA - HIGH`, checked, failing Range on underflow.

use super::super::{
    DATA_PAGES, LEAVES, MIDDLES, PRIVATE_SPACES, Page, ROOTS, STACKS, Stacks, USER_STACKS, fatal,
    report,
};
use super::{
    BACKING, Backing, COPY_BUFFER, CopyBuffer, EXEC_TARGET, ExecTarget, ROLE_COUNT, TABLES, Tables,
    evidence,
};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};
use cyxia_kernel_core::frame_meta_v0199::{
    COUNT, FrameMeta, Inventory, Ledger, PAGE, StaticClass, StaticRegion,
};
use cyxia_kernel_core::security::Error as LedgerError;

#[cfg(feature = "v020-production-frame-pool")]
#[path = "frames/pool.rs"]
mod pool;

/// 16 MiB physical window, including the 12 MiB SEC-N guest frame pool.
/// The 160 KiB of row backing fits within the FrameMeta reservation.
const ROWS: usize = 4096;
const _: () = assert!(ROWS <= COUNT);
const STATICS: usize = 11;
/// Fatal code when production static registration fails.
const FATAL_FRAME_META: u64 = 0x5731_1290;

static mut ROWS_BACKING: [FrameMeta; ROWS] = [FrameMeta::ZERO; ROWS];
static REGISTERED: AtomicBool = AtomicBool::new(false);
static REGISTERED_PAGES: AtomicU64 = AtomicU64::new(0);
static PERMANENT_ROWS: AtomicU64 = AtomicU64::new(0);
static SERVICE_ARENA_PAGES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    /// Address underflow/overflow, or the window exceeds the row backing.
    Range,
    /// Registration already ran.
    Once,
    /// The kernel-core ledger rejected the registration.
    Ledger(LedgerError),
}

fn region(va: u64, len: usize, class: StaticClass) -> Result<StaticRegion, Error> {
    let pa = va.checked_sub(crate::HIGH).ok_or(Error::Range)?;
    Ok(StaticRegion {
        region: MemoryRegion {
            start: PhysAddr(pa),
            len: len as u64,
            kind: RegionKind::Reserved,
        },
        class,
    })
}

fn statics(service: StaticRegion) -> Result<[StaticRegion; STATICS], Error> {
    use StaticClass::{Arena, Control, Metadata};
    let spaces = core::mem::size_of::<[Page; PRIVATE_SPACES]>();
    Ok([
        region(addr_of!(ROOTS) as u64, spaces, Metadata)?,
        region(addr_of!(MIDDLES) as u64, spaces, Metadata)?,
        region(addr_of!(LEAVES) as u64, spaces, Metadata)?,
        region(addr_of!(DATA_PAGES) as u64, spaces, Control)?,
        region(addr_of!(USER_STACKS) as u64, spaces, Control)?,
        region(
            addr_of!(TABLES) as u64,
            core::mem::size_of::<[Tables; ROLE_COUNT]>(),
            Metadata,
        )?,
        region(
            addr_of!(BACKING) as u64,
            core::mem::size_of::<[Backing; ROLE_COUNT]>(),
            Control,
        )?,
        region(
            addr_of!(EXEC_TARGET) as u64,
            core::mem::size_of::<ExecTarget>(),
            Control,
        )?,
        region(
            addr_of!(COPY_BUFFER) as u64,
            core::mem::size_of::<CopyBuffer>(),
            Control,
        )?,
        region(
            addr_of!(STACKS) as u64,
            core::mem::size_of::<Stacks>(),
            Arena,
        )?,
        service,
    ])
}

/// `[lowest start, highest end)` over the registered regions.
fn window(regions: &[StaticRegion]) -> Result<(u64, u64), Error> {
    let mut base = u64::MAX;
    let mut end = 0u64;
    for r in regions {
        base = base.min(r.region.start.0);
        end = end.max(r.region.end().map_err(|_| Error::Range)?);
    }
    if base >= end {
        return Err(Error::Range);
    }
    Ok((base, end))
}

unsafe extern "C" {
    /// Page-aligned linker bounds of the `.bss.sec_n` section (aarch64.ld).
    static __sec_n_start: u8;
    static __sec_n_end: u8;
}

fn service_arena() -> Result<StaticRegion, Error> {
    let start = addr_of!(__sec_n_start) as usize;
    let stop = addr_of!(__sec_n_end) as usize;
    let bytes = stop.checked_sub(start).ok_or(Error::Range)?;
    region(start as u64, bytes, StaticClass::Arena)
}

/// Register the production statics once, before any EL0 entry.
fn register_production_statics() -> Result<(Inventory, u64), Error> {
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return Err(Error::Once);
    }
    let service = service_arena()?;
    let regions = statics(service)?;
    let (base, end) = window(&regions)?;
    let pages = (end - base).div_ceil(PAGE) as usize;
    if pages > ROWS {
        return Err(Error::Range);
    }
    // SAFETY: one-shot (REGISTERED swap above) on CPU0 before secondaries or
    // EL0 run; this is the only reference ever formed to ROWS_BACKING and the
    // ledger borrowing it is dropped before return.
    let rows = unsafe { &mut (&mut *addr_of_mut!(ROWS_BACKING))[..pages] };
    let ledger = Ledger::initialize_static_sparse(rows, base, &regions).map_err(Error::Ledger)?;
    let inventory = ledger.inventory().map_err(Error::Ledger)?;
    Ok((inventory, service.region.len / PAGE))
}

/// Registered static pages: the class tallies, never the unregistered gaps.
fn registered_pages(inv: &Inventory) -> u64 {
    u64::from(inv.arena)
        + u64::from(inv.firmware_extra)
        + u64::from(inv.metadata)
        + u64::from(inv.control)
        + u64::from(inv.progress)
}

/// run() entry hook: register or stop the boot (word 129 = 0, fatal).
pub(super) fn register_or_fatal() {
    match register_production_statics() {
        Ok((inv, service_pages)) if service_pages > 0 => {
            REGISTERED_PAGES.store(registered_pages(&inv), Ordering::Release);
            PERMANENT_ROWS.store(u64::from(inv.permanent), Ordering::Release);
            SERVICE_ARENA_PAGES.store(service_pages, Ordering::Release);
        }
        _ => {
            evidence::put(evidence::W11_FRAME_META, 0);
            fatal(FATAL_FRAME_META);
        }
    }
}

#[cfg(feature = "v020-production-frame-pool")]
pub(super) fn prove_pool_or_fatal(info: &mut cyxia_contracts::BootInfo) {
    pool::prove_or_fatal(info);
}

/// Evidence-seal hook: words 129/130 (the page is zeroed before the seal),
/// plus the serial row with the permanent and unregistered gap row counts.
pub(super) fn publish() {
    let pages = REGISTERED_PAGES.load(Ordering::Acquire);
    let permanent = PERMANENT_ROWS.load(Ordering::Acquire);
    let arena = SERVICE_ARENA_PAGES.load(Ordering::Acquire);
    evidence::put(evidence::W11_FRAME_META, u64::from(pages > 0));
    evidence::put(evidence::W11_FRAME_META_REGISTERED_STATIC_PAGES, pages);
    evidence::put(evidence::W11_FRAME_META_ARENA_PAGES, arena);
    report(
        "V020_W11_FRAME_META_ROWS",
        pages,
        permanent,
        permanent.saturating_sub(pages),
    );
    report("V020_W11_FRAME_META_ARENA", arena, pages - arena, 0);
    #[cfg(feature = "v020-production-frame-pool")]
    pool::publish();
}
