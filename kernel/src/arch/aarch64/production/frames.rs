//! Register the native boot statics before any EL0 entry. The 1 GiB
//! signed startup and frame-pool lane use the reserved dense table.
//!
//! The static ledger registers SMP and PIE page tables as Metadata, role
//! memory and the copy buffer as Control, and SMP stacks and the pinned
//! linker-placed network/staging region as Arena. Gaps between regions remain
//! unowned permanent rows. VirtIO queue admission assigns DMA pages in the
//! arena to one queue for the boot. The driver manages descriptor custody.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * ROWS_BACKING (static mut): the only `&mut` to it is created once in
//!   `register_production_statics`, guarded by the REGISTERED swap, on CPU0
//!   before any secondary CPU or EL0 role runs. REGISTERED_PAGES publishes the
//!   ledger to the boot CPU for checked copy-window and device operations.
//! * NATIVE_LEDGER is initialized once. Its native gate serializes CPU0 and,
//!   when explicitly provisioned, the sole business memory owner's foreground.
//!   An IRQ does not acquire the gate.
//! * REGISTERED and the inventory counters (atomics): CPU0 only. REGISTERED
//!   makes the registration one-shot; the counters carry seal-time evidence.
//! * `__sec_n_start` / `__sec_n_end` (linker symbols): only their addresses are
//!   taken (`addr_of!`); the linker places the pinned arena on page boundaries.
//! * Registered statics are only addressed via `addr_of!` (no reference is
//!   formed); their PA is `VA - HIGH`, checked, failing Range on underflow.

#[cfg(any(
    feature = "v020-production-frame-pool",
    not(all(cyxia_startup_catalog, feature = "prototype-memory"))
))]
use super::super::fatal;
#[cfg(any(
    feature = "v020-production-diagnostic",
    all(cyxia_startup_catalog, feature = "prototype-memory")
))]
use super::super::report;
use super::super::{
    DATA_PAGES, LEAVES, MIDDLES, PRIVATE_SPACES, Page, ROOTS, STACKS, Stacks, USER_STACKS,
};
use super::{BACKING, Backing, COPY_BUFFER, CopyBuffer, ROLE_COUNT, TABLES, Tables};
#[cfg(feature = "v020-production-diagnostic")]
use super::{EXEC_TARGET, ExecTarget, PLAN_POOL, PLAN_POOL_BYTES, evidence};
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
use cyxia_kernel_core::frame_meta_v0199::Inventory;
use cyxia_kernel_core::frame_meta_v0199::{
    COUNT, FrameMeta, Ledger, Owner, PAGE, StaticClass, StaticRegion,
};
use cyxia_kernel_core::security::Error as LedgerError;

#[cfg(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
))]
#[path = "frames/dense.rs"]
mod dense;
#[cfg(all(cyxia_startup_catalog, feature = "prototype-memory"))]
pub(super) use dense::prepare as prepare_signed;
#[cfg(all(
    feature = "v020-production-frame-pool",
    not(feature = "prototype-memory")
))]
#[path = "frames/pool.rs"]
mod pool;

/// Base 16 MiB window, including the 12 MiB SEC-N verifier frame pool.
/// The authenticated profile also pins a separate 95-page signer address
/// space. Reserve 128 additional rows for it and surrounding linker gaps.
/// The largest backing (165 KiB) fits within the FrameMeta reservation.
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
const ROWS: usize = if cfg!(feature = "v020-production-authenticated-net") {
    4096 + 128
} else {
    4096
};
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
const _: () = assert!(ROWS <= COUNT);
const STATICS: usize = if cfg!(feature = "v020-production-diagnostic") {
    12
} else {
    10
};
/// Fatal code when production static registration fails.
#[cfg(any(
    feature = "v020-production-frame-pool",
    not(all(cyxia_startup_catalog, feature = "prototype-memory"))
))]
const FATAL_FRAME_META: u64 = 0x5731_1290;

#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
static mut ROWS_BACKING: [FrameMeta; ROWS] = [FrameMeta::ZERO; ROWS];
static mut NATIVE_LEDGER: MaybeUninit<Ledger<'static>> = MaybeUninit::uninit();
static LEDGER_HELD: AtomicBool = AtomicBool::new(false);
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

fn role_storage() -> Result<[StaticRegion; 3], Error> {
    Ok([
        region(
            addr_of!(TABLES) as u64,
            core::mem::size_of::<[Tables; ROLE_COUNT]>(),
            StaticClass::Metadata,
        )?,
        region(
            addr_of!(BACKING) as u64,
            core::mem::size_of::<[Backing; ROLE_COUNT]>(),
            StaticClass::Control,
        )?,
        region(
            addr_of!(COPY_BUFFER) as u64,
            core::mem::size_of::<CopyBuffer>(),
            StaticClass::Control,
        )?,
    ])
}

#[cfg(cyxia_startup_catalog)]
pub(super) fn role_storage_registered() -> bool {
    role_storage().is_ok_and(|regions| {
        regions.into_iter().all(|entry| {
            let region = entry.region;
            region
                .end()
                .is_ok_and(|end| statically_pinned_span(region.start.0..end, entry.class))
        })
    })
}

fn statics(service: StaticRegion) -> Result<[StaticRegion; STATICS], Error> {
    use StaticClass::{Arena, Control, Metadata};
    let [tables, backing, copy] = role_storage()?;
    let spaces = core::mem::size_of::<[Page; PRIVATE_SPACES]>();
    Ok([
        region(addr_of!(ROOTS) as u64, spaces, Metadata)?,
        region(addr_of!(MIDDLES) as u64, spaces, Metadata)?,
        region(addr_of!(LEAVES) as u64, spaces, Metadata)?,
        region(addr_of!(DATA_PAGES) as u64, spaces, Control)?,
        region(addr_of!(USER_STACKS) as u64, spaces, Control)?,
        tables,
        backing,
        #[cfg(feature = "v020-production-diagnostic")]
        region(
            addr_of!(EXEC_TARGET) as u64,
            core::mem::size_of::<ExecTarget>(),
            Control,
        )?,
        copy,
        #[cfg(feature = "v020-production-diagnostic")]
        region(addr_of!(PLAN_POOL) as u64, PLAN_POOL_BYTES, Control)?,
        region(
            addr_of!(STACKS) as u64,
            core::mem::size_of::<Stacks>(),
            Arena,
        )?,
        service,
    ])
}

/// `[lowest start, highest end)` over the registered regions.
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
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
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
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
    // SAFETY: one-shot (REGISTERED swap above) on CPU0 before any secondary
    // or EL0 entry. No other mutable reference can reach the backing.
    let rows = unsafe { &mut (&mut *addr_of_mut!(ROWS_BACKING))[..pages] };
    let ledger = Ledger::initialize_static_sparse(rows, base, &regions).map_err(Error::Ledger)?;
    let inventory = ledger.inventory().map_err(Error::Ledger)?;
    install_ledger(ledger);
    Ok((inventory, service.region.len / PAGE))
}

fn install_ledger(ledger: Ledger<'static>) {
    // SAFETY: the exclusive boot claim has already been taken. The caller
    // publishes REGISTERED_PAGES only after the slot is initialized.
    unsafe { addr_of_mut!(NATIVE_LEDGER).write(MaybeUninit::new(ledger)) };
}

struct NativeLedgerGuard;

impl Deref for NativeLedgerGuard {
    type Target = Ledger<'static>;

    fn deref(&self) -> &Self::Target {
        // SAFETY: a guard is minted only after initialization and acquisition.
        unsafe { &*addr_of!(NATIVE_LEDGER).cast() }
    }
}

impl DerefMut for NativeLedgerGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard releases the sole foreground access on drop.
        unsafe { &mut *addr_of_mut!(NATIVE_LEDGER).cast() }
    }
}

impl Drop for NativeLedgerGuard {
    fn drop(&mut self) {
        LEDGER_HELD.store(false, Ordering::Release);
    }
}

fn acquire_ledger(slot: usize) -> Result<NativeLedgerGuard, LedgerError> {
    if cyxia_arch_aarch64::cpu::registered_slot() != Some(slot)
        || REGISTERED_PAGES.load(Ordering::Acquire) == 0
    {
        return Err(LedgerError::Unauthorized);
    }
    LEDGER_HELD
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| LedgerError::Busy)?;
    Ok(NativeLedgerGuard)
}

fn native_ledger() -> Result<NativeLedgerGuard, LedgerError> {
    acquire_ledger(0)
}

#[cfg(cyxia_business_task_services)]
pub(super) fn with_business_ledger<T>(
    access: impl FnOnce(&mut Ledger<'static>) -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let slot = cyxia_arch_aarch64::cpu::registered_slot().ok_or(LedgerError::Unauthorized)?;
    if slot != 0 && slot != super::signed_business::GROUP_CPU {
        return Err(LedgerError::Unauthorized);
    }
    let mut ledger = acquire_ledger(slot)?;
    access(&mut ledger)
}

#[cfg(any(cyxia_startup_catalog, feature = "v020-production-diagnostic"))]
pub(super) fn statically_pinned_control_span(span: core::ops::Range<u64>) -> bool {
    statically_pinned_span(span, StaticClass::Control)
}

fn statically_pinned_span(span: core::ops::Range<u64>, class: StaticClass) -> bool {
    native_ledger().is_ok_and(|ledger| ledger.statically_pinned(span, class))
}

pub(crate) fn claim_static_dma(
    span: core::ops::Range<u64>,
    owner: Owner,
) -> Result<(), LedgerError> {
    native_ledger()?.claim_static_dma(span, owner)
}

/// Registered static pages: the class tallies, never the unregistered gaps.
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
fn registered_pages(inv: &Inventory) -> u64 {
    u64::from(inv.arena)
        + u64::from(inv.firmware_extra)
        + u64::from(inv.metadata)
        + u64::from(inv.control)
        + u64::from(inv.progress)
}

/// run() entry hook: register or stop the boot (word 129 = 0, fatal).
#[cfg(not(all(
    feature = "prototype-memory",
    any(feature = "v020-production-frame-pool", cyxia_startup_catalog)
)))]
pub(super) fn register_or_fatal() {
    match register_production_statics() {
        Ok((inv, service_pages)) if service_pages > 0 => {
            publish_counts(
                registered_pages(&inv),
                u64::from(inv.permanent),
                service_pages,
            );
        }
        _ => {
            #[cfg(feature = "v020-production-diagnostic")]
            evidence::put(evidence::W11_FRAME_META, 0);
            fatal(FATAL_FRAME_META);
        }
    }
}

fn publish_counts(registered: u64, permanent: u64, service_pages: u64) {
    PERMANENT_ROWS.store(permanent, Ordering::Relaxed);
    SERVICE_ARENA_PAGES.store(service_pages, Ordering::Relaxed);
    REGISTERED_PAGES.store(registered, Ordering::Release);
}

#[cfg(feature = "v020-production-frame-pool")]
pub(super) fn prepare_pool_or_fatal(info: &mut cyxia_contracts::BootInfo) {
    #[cfg(feature = "prototype-memory")]
    dense::prepare(info, &mut || Ok(()))
        .unwrap_or_else(|_| fatal(FATAL_FRAME_META))
        .publish();
    #[cfg(not(feature = "prototype-memory"))]
    {
        register_or_fatal();
        pool::prove_or_fatal(info);
    }
}

#[cfg(all(feature = "v020-production-frame-pool", feature = "prototype-memory"))]
pub(super) fn prove_dense_pool_or_fatal(manifest: &super::NativeRoleManifest) {
    dense::exercise(manifest).unwrap_or_else(|_| fatal(FATAL_FRAME_META + 1));
}

/// Evidence-seal hook: words 129/130 (the page is zeroed before the seal),
/// plus the serial row with the permanent and unregistered gap row counts.
#[cfg(feature = "v020-production-diagnostic")]
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
    #[cfg(all(
        feature = "v020-production-frame-pool",
        not(feature = "prototype-memory")
    ))]
    pool::publish();
    #[cfg(all(feature = "v020-production-frame-pool", feature = "prototype-memory"))]
    dense::publish();
}
