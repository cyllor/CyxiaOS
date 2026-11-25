//! CPU0-only physical backing shared in capacity, never in user ownership.
//!
//! V0.19.9 authoritative accounting (bounded native attachment): this module
//! is compiled only under `full-os` (the desktop production pool), and init
//! attaches a pool-mode FrameMeta ledger (`frame_meta_v0199::PoolBridge`)
//! whenever that pool initializes. Every allocation / revocation is mirrored
//! fail-closed into the authoritative frame accounting, with conservation
//! checks at attach time and in the diagnostic status line. The attachment
//! gate is exactly the pool's own `full-os` gate: the former
//! `full-os + v0199-local-native` conjunction was never satisfiable in any
//! build (full-os is x86-only, and formal x86 builds select
//! --no-default-features, dropping v0199-local-native), which left the mirror
//! as unverified dead code. Default, host and non-full-os builds never
//! compile this module and stay bit-identical; an unattached FramePool
//! (recorder = None) is unchanged.
//!
//! VERIFICATION: host tests in cyxia-kernel-core (frame_meta_v0199) prove the
//! mirrored accounting, the conservation predicate and the exact static
//! attachment pattern used below, including the production init geometry
//! (a static row table sliced to the admitted window). The attachment is
//! compiled by the x86 full-OS production build:
//! `cargo build -p cyxia-kernel --target x86_64-unknown-none
//! --no-default-features --features full-os`. Producing that image locally
//! additionally requires the ported sysroot catalog (a separate, pre-existing
//! gap), and a native desktop boot receipt of the attached mirror remains
//! open. This is an accounting-mirror skeleton, NOT the general-allocator
//! cutover: replacing FramePool with the V0.19.9 ledger as the allocator
//! remains a later wave.
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind, TaskId};
#[cfg(feature = "full-os")]
use cyxia_kernel_core::frame_meta_v0199::{self as fm, PoolBridge};
use cyxia_kernel_core::frames::{
    FrameError, FrameHandle, FrameMeta, FramePool, FrameSnapshot, PageZeroer, RevokeComplete,
};
use cyxia_posix::Errno;

pub const PAGES: usize = 65536;
pub const BYTES: u64 = PAGES as u64 * 4096;
static mut METADATA: [FrameMeta; PAGES] = [FrameMeta::EMPTY; PAGES];
static mut POOL: Option<FramePool<'static>> = None;
static mut PEAK: usize = 0;
/// Authoritative mirror: one 40-byte row per pool page (2.5 MiB BSS,
/// compiled with this full-os module) and the bridge slot published
/// together with POOL. Rows beyond the admitted window stay untouched.
#[cfg(feature = "full-os")]
static mut LEDGER_ROWS: [fm::FrameMeta; PAGES] = [fm::FrameMeta::ZERO; PAGES];
#[cfg(feature = "full-os")]
static mut BRIDGE: Option<PoolBridge<'static>> = None;

fn error(value: FrameError) -> Errno {
    match value {
        FrameError::Capacity | FrameError::Again | FrameError::Exhausted => Errno::Nomem,
        _ => Errno::Io,
    }
}
fn with<T>(f: impl FnOnce(&mut FramePool<'static>) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: foreground CPU0 only. All APs have returned before these calls;
    // neither interrupts nor DMA access this metadata or its owned user pages.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(POOL) };
    f(pool.as_mut().ok_or(Errno::Nodev)?)
}
pub fn init(base: u64, bytes: u64) -> Result<(), Errno> {
    if base == 0
        || base % 4096 != 0
        || bytes == 0
        || bytes > BYTES
        || bytes % 4096 != 0
        || base.checked_add(bytes).is_none()
    {
        return Err(Errno::Inval);
    }
    // The caller exclusively reserved this exact range through firmware-aware
    // reserve_pool. Never describe the rest of RAM as allocatable here.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(POOL) };
    if pool.is_some() {
        return Err(Errno::Busy);
    }
    let region = MemoryRegion {
        start: PhysAddr(base),
        len: bytes,
        kind: RegionKind::Ram,
    };
    let metadata = unsafe { &mut *core::ptr::addr_of_mut!(METADATA) };
    let mut new_pool = FramePool::from_memory(&[region], &[], metadata).map_err(error)?;
    // The attachment gate is the module's own full-os gate: whenever this
    // desktop pool is built, the authoritative mirror is attached.
    #[cfg(feature = "full-os")]
    {
        // SAFETY: foreground CPU0 only, before POOL is published; no other
        // CPU, interrupt or DMA agent can reach these statics. The ledger
        // window is exactly the admitted pool geometry, so every pool page
        // has one authoritative row and nothing else is described.
        let rows: &'static mut [fm::FrameMeta] =
            unsafe { &mut *core::ptr::addr_of_mut!(LEDGER_ROWS) };
        let pages = (bytes / 4096) as usize;
        let ledger = fm::Ledger::initialize_pool(&mut rows[..pages], base, &[region], &[])
            .map_err(|_| Errno::Io)?;
        let bridge = PoolBridge::new(ledger).map_err(|_| Errno::Io)?;
        // Fail closed before publishing: the mirror must conserve the pool
        // geometry at attach time. A rejected ledger never silently falls
        // back to an unattached pool; once rows are published, re-init
        // refuses (Busy) exactly like the ledger's own anti-replay rule.
        bridge
            .conservation(new_pool.snapshot())
            .map_err(|_| Errno::Io)?;
        let slot: &'static mut Option<PoolBridge<'static>> =
            unsafe { &mut *core::ptr::addr_of_mut!(BRIDGE) };
        *slot = Some(bridge);
        new_pool.attach_recorder(slot.as_ref().unwrap());
    }
    *pool = Some(new_pool);
    Ok(())
}
struct Zero;
impl PageZeroer for Zero {
    fn zero(&mut self, page: PhysAddr) -> Result<(), FrameError> {
        // Only FramePool supplies pages from our exclusive firmware reservation.
        unsafe {
            core::ptr::write_bytes((crate::HIGH + page.0) as *mut u8, 0, 4096);
        }
        Ok(())
    }
}
pub fn allocate(owner: TaskId) -> Result<FrameHandle, Errno> {
    with(|pool| {
        let handle = pool.alloc_zeroed(owner, &mut Zero).map_err(error)?;
        let peak = unsafe { &mut *core::ptr::addr_of_mut!(PEAK) };
        *peak = (*peak).max(pool.snapshot().used);
        Ok(handle)
    })
}
pub fn check_owned(handle: FrameHandle, owner: TaskId) -> Result<(), Errno> {
    with(|pool| pool.check_owned(handle, owner).map_err(error))
}
pub fn release(handle: FrameHandle, owner: TaskId) -> Result<(), Errno> {
    with(|pool| {
        // Validate identity/owner before touching the physical address. The
        // caller has removed every affected user PTE after all APs returned.
        pool.begin_revoke(handle, owner).map_err(error)?;
        Zero.zero(handle.address()).map_err(error)?;
        pool.finish_revoke(handle, unsafe { RevokeComplete::after_unmap(handle) })
            .map_err(error)
    })
}
pub fn snapshot() -> Result<FrameSnapshot, Errno> {
    with(|pool| Ok(pool.snapshot()))
}
pub fn status(out: &mut impl core::fmt::Write) {
    if let Ok(s) = snapshot() {
        let peak = unsafe { *core::ptr::addr_of!(PEAK) };
        writeln!(out, "ANON_POOL capacity={} free={} used={} peak={} virtual_pages={} backing=BOOTSTRAP ownership=PRIVATE commit=MMAP\r",
                 s.capacity, s.free, s.used, peak, cyxia_posix::vm::PAGE_COUNT).unwrap();
        #[cfg(feature = "full-os")]
        {
            // SAFETY: CPU0-only diagnostic read. init publishes BRIDGE
            // together with POOL and never replaces it afterwards; the
            // ledger stays inspectable through shared borrows only.
            let bridge = unsafe { &*core::ptr::addr_of!(BRIDGE) };
            if let Some(bridge) = bridge.as_ref() {
                if let Ok(inv) = bridge.inventory() {
                    let verdict = if bridge.conservation(s).is_ok() {
                        "OK"
                    } else {
                        "DIVERGENCE"
                    };
                    writeln!(out, "ANON_POOL_LEDGER free={} reserved={} allocated={} quarantined={} permanent={} conservation={}\r",
                             inv.free, inv.reserved, inv.allocated, inv.quarantined, inv.permanent, verdict).unwrap();
                }
            }
        }
    }
}
