//! CPU0-only physical backing shared in capacity, never in user ownership.
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind, TaskId};
use cyxia_kernel_core::frames::{
    FrameError, FrameHandle, FrameMeta, FramePool, FrameSnapshot, PageZeroer, RevokeComplete,
};
use cyxia_posix::Errno;

pub const PAGES: usize = 65536;
pub const BYTES: u64 = PAGES as u64 * 4096;
static mut METADATA: [FrameMeta; PAGES] = [FrameMeta::EMPTY; PAGES];
static mut POOL: Option<FramePool<'static>> = None;
static mut PEAK: usize = 0;

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
    if base == 0 || base % 4096 != 0 || bytes == 0 || bytes > BYTES
        || bytes % 4096 != 0 || base.checked_add(bytes).is_none()
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
    *pool = Some(FramePool::from_memory(&[region], &[], metadata).map_err(error)?);
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
    }
}
