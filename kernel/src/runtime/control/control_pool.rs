//! Real, nonreclaimable 8 MiB control backing. Business mappings never allocate
//! from this owner. A sealed or executing allocation cannot be changed through
//! the pool; its exact execution pins survive an unknown completion.
#[path = "control_pool/ledger.rs"]
mod ledger;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_prototype::domains::{Error, ObjectKey};
pub use ledger::{Allocation, Lease};

pub const BYTES: usize = 8 * 1024 * 1024;
const CHUNK: usize = 4096;
#[repr(C, align(4096))]
struct Backing([u8; BYTES]);
struct BackingCell(UnsafeCell<Backing>);
unsafe impl Sync for BackingCell {}
static BACKING: BackingCell = BackingCell(UnsafeCell::new(Backing([0; BYTES])));
struct LedgerCell(UnsafeCell<ledger::Ledger>);
unsafe impl Sync for LedgerCell {}
static LEDGER: LedgerCell = LedgerCell(UnsafeCell::new(ledger::Ledger::new()));
static GATE: AtomicBool = AtomicBool::new(false);
// Native authoritative FrameMeta record for the control backing. The pool
// suballocation ledger above stays the exact boot-lifetime owner; this is an
// additional permanent frame accounting record, registered once under the
// pool gate before the first ledger operation. Host fixtures include this
// source with synthetic authority and keep the historical behavior.
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicU8;
#[cfg(target_os = "none")]
use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};
#[cfg(target_os = "none")]
use cyxia_kernel_core::frame_meta_v0199::{self as fm, FrameMeta, StaticClass, StaticRegion};
/// Bounded static table: exactly the registered control backing pages, far
/// inside the design's 10MiB global FrameMeta reservation (2048 x 40B).
#[cfg(target_os = "none")]
const FRAME_ROWS: usize = BYTES / CHUNK;
#[cfg(target_os = "none")]
struct FrameRowsCell(UnsafeCell<[FrameMeta; FRAME_ROWS]>);
#[cfg(target_os = "none")]
unsafe impl Sync for FrameRowsCell {}
#[cfg(target_os = "none")]
static FRAME_ROWS_BACKING: FrameRowsCell =
    FrameRowsCell(UnsafeCell::new([FrameMeta::ZERO; FRAME_ROWS]));
#[cfg(target_os = "none")]
struct FrameLedgerCell(UnsafeCell<Option<fm::Ledger<'static>>>);
#[cfg(target_os = "none")]
unsafe impl Sync for FrameLedgerCell {}
#[cfg(target_os = "none")]
static FRAME_LEDGER: FrameLedgerCell = FrameLedgerCell(UnsafeCell::new(None));
/// 0 pending, 1 registered, 2 failed. Failure is sticky and fail-closed:
/// no pool operation may proceed without the authoritative frame record.
#[cfg(target_os = "none")]
static FRAME_STATE: AtomicU8 = AtomicU8::new(0);
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 16]);
#[used]
#[unsafe(no_mangle)]
pub static CONTROL_POOL_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 16]);
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        GATE.store(false, Ordering::Release);
    }
}
#[cfg(target_os = "none")]
fn frame_error(e: cyxia_kernel_core::security::Error) -> Error {
    use cyxia_kernel_core::security::Error as Sec;
    match e {
        Sec::Invalid => Error::Range,
        Sec::Unauthorized => Error::Auth,
        Sec::Stale => Error::Stale,
        Sec::Conflict => Error::Conflict,
        Sec::Capacity | Sec::Exhausted => Error::Capacity,
        Sec::Busy => Error::Busy,
        Sec::Unknown => Error::Io,
    }
}
/// Single checked-arithmetic policy for the backing physical address:
/// `BACKING - HIGH`, failing `Error::Range` on underflow. Registration
/// propagates the error; evidence publication falls back to zero so a
/// failed or absent registration never exposes a fabricated address.
fn backing_pa() -> Result<u64, Error> {
    let base = BACKING.0.get() as usize;
    (base as u64).checked_sub(crate::HIGH).ok_or(Error::Range)
}
/// Register the physical backing window as Control permanent pages. Runs
/// exactly once while the pool gate is held; the kernel image (and thus the
/// backing) must sit inside the pinned boot/kernel/DMA arena.
#[cfg(target_os = "none")]
fn register_frame_authority() -> Result<(), Error> {
    let pa = backing_pa()?;
    if pa < cyxia_platform_virt::RAM_BASE
        || pa
            .checked_add(BYTES as u64)
            .is_none_or(|end| end > cyxia_platform_virt::KERNEL_POOL_END)
    {
        return Err(Error::Range);
    }
    let rows = unsafe { &mut *FRAME_ROWS_BACKING.0.get() };
    let region = MemoryRegion {
        start: PhysAddr(pa),
        len: BYTES as u64,
        kind: RegionKind::Reserved,
    };
    let ledger = fm::Ledger::initialize_static(
        rows,
        pa,
        &[StaticRegion {
            region,
            class: StaticClass::Control,
        }],
    )
    .map_err(frame_error)?;
    unsafe { *FRAME_LEDGER.0.get() = Some(ledger) };
    Ok(())
}
/// Publish the immutable registration record in evidence words 6..12; the
/// historical words 0..5 keep their exact meaning. A failed or absent
/// registration publishes zeros and leaves word 0 clear so downstream
/// verifiers fail closed.
#[cfg(target_os = "none")]
fn publish_frame_evidence() {
    let state = FRAME_STATE.load(Ordering::Acquire);
    let pa = if state == 1 {
        backing_pa().unwrap_or(0)
    } else {
        0
    };
    let (pages, table_bytes, permanent, free) = if state == 1 {
        match unsafe { (*FRAME_LEDGER.0.get()).as_ref() }.map(|l| l.inventory()) {
            Some(Ok(inv)) => (
                FRAME_ROWS as u64,
                (FRAME_ROWS * core::mem::size_of::<FrameMeta>()) as u64,
                u64::from(inv.permanent),
                u64::from(inv.free),
            ),
            _ => (0, 0, 0, 0),
        }
    } else {
        (0, 0, 0, 0)
    };
    for (i, value) in [
        0x4359_4652_414d_4501u64,
        u64::from(state),
        pa,
        pages,
        table_bytes,
        permanent,
        free,
    ]
    .into_iter()
    .enumerate()
    {
        CONTROL_POOL_EVIDENCE.0[i + 6].store(value, Ordering::Relaxed);
    }
}
fn with<R>(f: impl FnOnce(&mut ledger::Ledger) -> Result<R, Error>) -> Result<R, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    #[cfg(target_os = "none")]
    {
        match FRAME_STATE.load(Ordering::Acquire) {
            1 => {}
            2 => return Err(Error::Auth),
            _ => {
                let outcome = register_frame_authority().and_then(|()| {
                    // Conservation must hold before the record is published.
                    unsafe { (*FRAME_LEDGER.0.get()).as_ref() }
                        .ok_or(Error::NotReady)?
                        .inventory()
                        .map_err(frame_error)?;
                    Ok(())
                });
                match outcome {
                    Ok(()) => FRAME_STATE.store(1, Ordering::Release),
                    Err(e) => {
                        FRAME_STATE.store(2, Ordering::Release);
                        publish_frame_evidence();
                        return Err(e);
                    }
                }
                publish_frame_evidence();
            }
        }
    }
    let ledger = unsafe { &mut *LEDGER.0.get() };
    let result = f(ledger);
    let (pages, allocations, pins) = ledger.usage();
    for (i, value) in [
        BYTES as u64,
        // Word 2 keeps its historical saturating meaning: for u64 the
        // checked helper with a zero fallback clamps exactly like the
        // former saturating_sub, and publication only follows a successful
        // registration, where the subtraction cannot fail.
        backing_pa().unwrap_or(0),
        pages as u64,
        allocations as u64,
        pins as u64,
    ]
    .into_iter()
    .enumerate()
    {
        CONTROL_POOL_EVIDENCE.0[i + 1].store(value, Ordering::Relaxed);
    }
    CONTROL_POOL_EVIDENCE.0[0].store(0x4359_4350_4f4f_4c01, Ordering::Release);
    result
}
fn range(allocation: Allocation, offset: usize, len: usize) -> Result<*mut u8, Error> {
    if offset
        .checked_add(len)
        .is_none_or(|end| end > allocation.bytes())
    {
        return Err(Error::Range);
    }
    Ok(unsafe {
        BACKING
            .0
            .get()
            .cast::<u8>()
            .add(allocation.first() * 4096 + offset)
    })
}
pub fn allocate(owner: ObjectKey, pages: usize) -> Result<Allocation, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        return Err(Error::Auth);
    }
    with(|l| l.allocate(owner, pages))
}
pub const fn allocation_key(allocation: Allocation) -> ObjectKey {
    allocation.key()
}
/// The returned addresses do not confer permission to alias or write bytes.
/// Mapping owners must hold exact pins while an EL0 context can access them.
pub fn span(allocation: Allocation) -> Result<(usize, u64, usize), Error> {
    with(|l| {
        l.validate(allocation)?;
        let base = range(allocation, 0, 0)? as usize;
        Ok((
            base,
            (base as u64).checked_sub(crate::HIGH).ok_or(Error::Range)?,
            allocation.bytes(),
        ))
    })
}
pub fn validate_span(key: ObjectKey, base: usize, bytes: usize) -> Result<(), Error> {
    with(|l| {
        let a = l.find(key)?;
        let first = range(a, 0, 0)? as usize;
        if base != first || bytes == 0 || bytes > a.bytes() {
            return Err(Error::Range);
        }
        Ok(())
    })
}
pub fn write(allocation: Allocation, offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > CHUNK {
        return Err(Error::Range);
    }
    with(|l| {
        l.writable(allocation)?;
        let out = range(allocation, offset, bytes.len())?;
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        }
        Ok(())
    })
}
pub fn zero_chunk(allocation: Allocation, offset: usize, len: usize) -> Result<(), Error> {
    if len > CHUNK {
        return Err(Error::Range);
    }
    with(|l| {
        l.writable(allocation)?;
        let out = range(allocation, offset, len)?;
        unsafe {
            core::ptr::write_bytes(out, 0, len);
        }
        Ok(())
    })
}
pub fn read(allocation: Allocation, offset: usize, out: &mut [u8]) -> Result<(), Error> {
    if out.len() > CHUNK {
        return Err(Error::Range);
    }
    with(|l| {
        l.readable(allocation)?;
        let input = range(allocation, offset, out.len())?;
        unsafe {
            core::ptr::copy_nonoverlapping(input, out.as_mut_ptr(), out.len());
        }
        Ok(())
    })
}
/// Only bounded, pure projections may run while holding the pool gate. An
/// immutable read lease permits inspection while the model is mapped RO.
pub fn inspect<R>(
    allocation: Allocation,
    offset: usize,
    len: usize,
    f: impl FnOnce(&[u8]) -> R,
) -> Result<R, Error> {
    if len > CHUNK {
        return Err(Error::Range);
    }
    with(|l| {
        l.readable(allocation)?;
        let input = range(allocation, offset, len)?;
        Ok(f(unsafe { core::slice::from_raw_parts(input, len) }))
    })
}
pub fn seal(allocation: Allocation) -> Result<(), Error> {
    with(|l| l.seal(allocation, true))
}
pub fn unseal(allocation: Allocation) -> Result<(), Error> {
    with(|l| l.seal(allocation, false))
}
pub fn pin(allocation: Allocation) -> Result<Lease, Error> {
    with(|l| l.pin(allocation))
}
pub fn pin_readonly(allocation: Allocation) -> Result<Lease, Error> {
    with(|l| {
        if !l.sealed(allocation)? {
            return Err(Error::Auth);
        }
        l.pin(allocation)
    })
}
/// A Busy reply retains the original lease, allowing exact release retry.
pub fn unpin(lease: &Lease) -> Result<(), Error> {
    with(|l| l.unpin(lease))
}
pub fn usage() -> Result<(usize, usize, usize), Error> {
    with(|l| Ok(l.usage()))
}
/// Authoritative FrameMeta inventory of the registered control backing.
/// Registration is a prerequisite and any failure stays fail-closed; the
/// permanent pages can never be reserved, transitioned or reclaimed.
#[cfg(target_os = "none")]
pub fn frame_inventory() -> Result<fm::Inventory, Error> {
    with(|_| {
        unsafe { (*FRAME_LEDGER.0.get()).as_ref() }
            .ok_or(Error::NotReady)?
            .inventory()
            .map_err(frame_error)
    })
}
