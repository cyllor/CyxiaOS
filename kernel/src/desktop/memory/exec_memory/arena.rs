//! CPU0-only shared executable backing for the full COSMIC session profile.
//! Physical runs are allocated on demand from one firmware-reserved window
//! instead of a static per-slot partition, so widening the process inventory no
//! longer multiplies the boot reservation by the per-image virtual window.
//! Ownership, generation and revoke-before-reuse stay with each image's grant
//! ledger; this pool only tracks contiguous physical runs and their owners.
use cyxia_kernel_core::contig_frames::ContigFramePool;
use cyxia_kernel_core::frames::FrameError;
use cyxia_kernel_core::grants::Owner;
use cyxia_posix::{Errno, usermem::MAX_PROCESSES};

/// Reviewed shared session exec budget, mirroring the full-OS anonymous pool's
/// fixed shared capacity. Aggregate executable demand of the ported session
/// components must be re-verified against this window when applets land; it is
/// a versioned constant, not a silent enlargement of any existing pool.
pub const PAGES: usize = 65536;
pub const BYTES: u64 = PAGES as u64 * 4096;
static mut POOL: Option<ContigFramePool<MAX_PROCESSES>> = None;

fn error(value: FrameError) -> Errno {
    match value {
        FrameError::Capacity | FrameError::Again | FrameError::Exhausted => Errno::Nomem,
        _ => Errno::Io,
    }
}
fn with<T>(
    f: impl FnOnce(&mut ContigFramePool<MAX_PROCESSES>) -> Result<T, Errno>,
) -> Result<T, Errno> {
    // SAFETY: foreground CPU0 only. Image load and clear run with every AP root
    // retired; neither interrupts nor DMA access this bookkeeping.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(POOL) };
    f(pool.as_mut().ok_or(Errno::Nodev)?)
}
pub fn init(base: u64, bytes: u64) -> Result<(), Errno> {
    if bytes > BYTES || bytes % 4096 != 0 {
        return Err(Errno::Inval);
    }
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(POOL) };
    if pool.is_some() {
        return Err(Errno::Busy);
    }
    // The caller exclusively reserved this exact range through firmware-aware
    // reserve_pool. Never describe the rest of RAM as allocatable here.
    *pool = Some(ContigFramePool::new(base, (bytes / 4096) as usize).map_err(error)?);
    Ok(())
}
pub fn allocate(pages: usize, owner: Owner) -> Result<u64, Errno> {
    with(|pool| pool.allocate(pages, owner.task).map_err(error))
}
pub fn release(base: u64, pages: usize, owner: Owner) -> Result<(), Errno> {
    with(|pool| pool.release(base, pages, owner.task).map_err(error))
}
