//! V0.20 wave 11: register the production boot statics in a bounded sparse
//! FrameMeta ledger before any EL0 entry.
//!
//! Registered (8 regions): smp ROOTS/MIDDLES/LEAVES (Metadata), smp
//! DATA_PAGES/USER_STACKS (Control), production PIE TABLES (Metadata),
//! production PIE BACKING and EXEC_TARGET (Control). The window runs from the
//! lowest to the highest registered PA; rows between registered regions (other
//! kernel statics) are published unowned PERMANENT but are NOT registered and
//! count toward no class. Evidence word 130 reports registered static pages
//! only; the serial row `V020_W11_FRAME_META_ROWS a=<registered> b=<all
//! permanent rows> c=<unregistered permanent gap rows>` reports the rest.
//! The ledger is a static authority record over linker-placed kernel statics:
//! it does not move, map, zero or own them.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * ROWS_BACKING (static mut): the only `&mut` to it is created once in
//!   `register_production_statics`, guarded by the REGISTERED swap, on CPU0
//!   before any secondary CPU or EL0 role runs. The ledger borrowing it is
//!   dropped before return; nothing else reads or writes the rows.
//! * REGISTERED / REGISTERED_PAGES / PERMANENT_ROWS (atomics): CPU0 only;
//!   REGISTERED makes the registration one-shot, the other two carry the
//!   inventory figures from registration to the evidence seal.
//! * `__sec_n_start` / `__sec_n_end` (linker symbols): only their addresses are
//!   taken (`addr_of!`); the window is checked disjoint from that section.
//! * Registered statics are only addressed via `addr_of!` (no reference is
//!   formed); their PA is `VA - HIGH`, checked, failing Range on underflow.

use super::super::{
    DATA_PAGES, LEAVES, MIDDLES, PRIVATE_SPACES, Page, ROOTS, USER_STACKS, fatal, report,
};
use super::{BACKING, Backing, EXEC_TARGET, ExecTarget, ROLE_COUNT, TABLES, Tables, evidence};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};
use cyxia_kernel_core::frame_meta_v0199::{
    COUNT, FrameMeta, Inventory, Ledger, PAGE, StaticClass, StaticRegion,
};
use cyxia_kernel_core::security::Error as LedgerError;

/// Row capacity of the static backing (4MiB window, 40KiB of rows). The
/// measured v020-production window is 522 rows; a larger window is Range.
const ROWS: usize = 1024;
const _: () = assert!(ROWS <= COUNT);
const STATICS: usize = 8;
/// Fatal code when production static registration fails.
const FATAL_FRAME_META: u64 = 0x5731_1290;

static mut ROWS_BACKING: [FrameMeta; ROWS] = [FrameMeta::ZERO; ROWS];
static REGISTERED: AtomicBool = AtomicBool::new(false);
static REGISTERED_PAGES: AtomicU64 = AtomicU64::new(0);
static PERMANENT_ROWS: AtomicU64 = AtomicU64::new(0);

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

fn statics() -> Result<[StaticRegion; STATICS], Error> {
    use StaticClass::{Control, Metadata};
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
    /// Linker bounds of the `.bss.sec_n` section (aarch64.ld).
    static __sec_n_start: u8;
    static __sec_n_end: u8;
}

/// The SEC-N guest/net pools (`.bss.sec_n`, unregistered this wave) must lie
/// wholly outside the registered window, so they never widen it or land in
/// its unowned gap rows.
fn outside_sec_n(base: u64, end: u64) -> Result<(), Error> {
    let start = (addr_of!(__sec_n_start) as u64)
        .checked_sub(crate::HIGH)
        .ok_or(Error::Range)?;
    let stop = (addr_of!(__sec_n_end) as u64)
        .checked_sub(crate::HIGH)
        .ok_or(Error::Range)?;
    if start == stop || stop <= base || start >= end {
        Ok(())
    } else {
        Err(Error::Range)
    }
}

/// Register the production statics once, before any EL0 entry.
pub(super) fn register_production_statics() -> Result<Inventory, Error> {
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return Err(Error::Once);
    }
    let regions = statics()?;
    let (base, end) = window(&regions)?;
    outside_sec_n(base, end)?;
    let pages = (end - base).div_ceil(PAGE) as usize;
    if pages > ROWS {
        return Err(Error::Range);
    }
    // SAFETY: one-shot (REGISTERED swap above) on CPU0 before secondaries or
    // EL0 run; this is the only reference ever formed to ROWS_BACKING and the
    // ledger borrowing it is dropped before return.
    let rows = unsafe { &mut (&mut *addr_of_mut!(ROWS_BACKING))[..pages] };
    let ledger = Ledger::initialize_static_sparse(rows, base, &regions).map_err(Error::Ledger)?;
    ledger.inventory().map_err(Error::Ledger)
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
        Ok(inv) if registered_pages(&inv) > 0 => {
            REGISTERED_PAGES.store(registered_pages(&inv), Ordering::Release);
            PERMANENT_ROWS.store(u64::from(inv.permanent), Ordering::Release);
        }
        _ => {
            evidence::put(evidence::W11_FRAME_META, 0);
            fatal(FATAL_FRAME_META);
        }
    }
}

/// Evidence-seal hook: words 129/130 (the page is zeroed before the seal),
/// plus the serial row with the permanent and unregistered gap row counts.
pub(super) fn publish() {
    let pages = REGISTERED_PAGES.load(Ordering::Acquire);
    let permanent = PERMANENT_ROWS.load(Ordering::Acquire);
    evidence::put(evidence::W11_FRAME_META, u64::from(pages > 0));
    evidence::put(evidence::W11_FRAME_META_REGISTERED_STATIC_PAGES, pages);
    report(
        "V020_W11_FRAME_META_ROWS",
        pages,
        permanent,
        permanent.saturating_sub(pages),
    );
}
