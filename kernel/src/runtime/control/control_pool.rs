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
fn with<R>(f: impl FnOnce(&mut ledger::Ledger) -> Result<R, Error>) -> Result<R, Error> {
    GATE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Error::Busy)?;
    let _guard = Guard;
    let ledger = unsafe { &mut *LEDGER.0.get() };
    let result = f(ledger);
    let (pages, allocations, pins) = ledger.usage();
    let base = BACKING.0.get() as usize;
    for (i, value) in [
        BYTES as u64,
        (base as u64).saturating_sub(crate::HIGH),
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
