//! Restricted native EL0 broker calls on the existing protected shared
//! page. No public arbitrary syscall API, store, task, resource or policy RPC.
use crate::{abi, calls};
use core::sync::atomic::{Ordering, fence};
use cyxia_local_echo::broker_surface as allowed;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Rejected,
    Again,
    Closed,
    Invalid,
}
#[inline(always)]
fn page() -> *mut abi::Shared {
    abi::SHARED_VA as *mut abi::Shared
}
fn request(op: u64, input: &[u8], output: &mut [u8], arg0: u64) -> Result<(usize, u64), Error> {
    let len = input.len().max(output.len());
    if !allowed::allowed(op, len, arg0) {
        return Err(Error::Invalid);
    }
    let p = page();
    unsafe {
        let epoch = core::ptr::addr_of!((*p).boot_epoch).read_volatile();
        let generation = core::ptr::addr_of!((*p).service_generation).read_volatile();
        if !abi::valid_service_identity(&*p, epoch, generation) {
            return Err(Error::Invalid);
        }
        let current = core::ptr::addr_of!((*p).sequence).read_volatile();
        let next = current.checked_add(1).ok_or(Error::Invalid)?;
        core::ptr::addr_of_mut!((*p).op).write_volatile(op);
        core::ptr::addr_of_mut!((*p).len).write_volatile(len as u64);
        core::ptr::addr_of_mut!((*p).offset).write_volatile(0);
        core::ptr::addr_of_mut!((*p).arg0).write_volatile(arg0);
        core::ptr::addr_of_mut!((*p).arg1).write_volatile(0);
        core::ptr::addr_of_mut!((*p).arg2).write_volatile(0);
        core::ptr::addr_of_mut!((*p).status).write_volatile(abi::FAILED);
        let payload = core::ptr::addr_of_mut!((*p).payload).cast::<u8>();
        for (at, byte) in input.iter().enumerate() {
            payload.add(at).write_volatile(*byte);
        }
        fence(Ordering::Release);
        core::ptr::addr_of_mut!((*p).sequence).write_volatile(next);
        let _ = calls::call::<0x43>([0; 5], 0);
        fence(Ordering::Acquire);
        if core::ptr::addr_of!((*p).sequence).read_volatile() != next
            || !abi::valid_service_identity(&*p, epoch, generation)
        {
            return Err(Error::Invalid);
        }
        let status = core::ptr::addr_of!((*p).status).read_volatile();
        match status {
            abi::OK => {}
            abi::AGAIN => return Err(Error::Again),
            abi::EOF => return Err(Error::Closed),
            _ => return Err(Error::Rejected),
        }
        let n = core::ptr::addr_of!((*p).len).read_volatile() as usize;
        if n > len || n > allowed::PAYLOAD {
            return Err(Error::Invalid);
        }
        for (at, dst) in output.iter_mut().take(n).enumerate() {
            *dst = payload.add(at).read_volatile();
        }
        let result = core::ptr::addr_of!((*p).arg0).read_volatile();
        Ok((n, result))
    }
}
pub fn entropy(out: &mut [u8]) -> Result<(), Error> {
    for chunk in out.chunks_mut(allowed::PAYLOAD) {
        let (n, _) = request(allowed::ENTROPY, &[], chunk, 0)?;
        if n != chunk.len() {
            out.fill(0);
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
pub fn now() -> Result<u64, Error> {
    request(allowed::TIME, &[], &mut [], 0)?;
    unsafe { Ok(core::ptr::addr_of!((*page()).monotonic_ms).read_volatile()) }
}
pub fn unix_seconds() -> Option<u64> {
    let seconds = unsafe { core::ptr::addr_of!((*page()).unix_seconds).read_volatile() };
    (seconds != 0 && seconds < (1u64 << 63)).then_some(seconds)
}
pub fn boot_identity() -> Option<([u8; 32], [u8; 32])> {
    unsafe {
        let p = page();
        let epoch = core::ptr::addr_of!((*p).boot_epoch).read_volatile();
        let generation = core::ptr::addr_of!((*p).service_generation).read_volatile();
        if !abi::valid_service_identity(&*p, epoch, generation) {
            return None;
        }
        Some((
            core::ptr::addr_of!((*p).local_node).read_volatile(),
            core::ptr::addr_of!((*p).peer_node).read_volatile(),
        ))
    }
}
pub fn poll() -> Result<(bool, u64, u32, bool), Error> {
    let (_, connected) = request(allowed::POLL, &[], &mut [], 0)?;
    unsafe {
        let p = page();
        let generation = core::ptr::addr_of!((*p).connection_epoch).read_volatile();
        let ip = core::ptr::addr_of!((*p).domains.peer_ipv4).read_volatile();
        let ip = u32::try_from(ip).map_err(|_| Error::Invalid)?;
        match connected {
            0 | 1 | 3 => Ok((connected != 0, generation, ip, connected == 3)),
            _ => Err(Error::Invalid),
        }
    }
}
/// The caller must hold a pending ticket from this guest's admission ledger.
pub fn admission_granted(
    _ticket: cyxia_net_transport::admission::PendingTicket,
    generation: u64,
    source: u32,
) -> Result<(), Error> {
    connection_receipt(allowed::ADMISSION_GRANTED, generation, source)
}

pub fn poll_normal_close(generation: u64, source: u32) -> Result<(), Error> {
    connection_receipt(allowed::POLL_NORMAL_CLOSE, generation, source)
}

pub fn admission_retired(generation: u64, source: u32) -> Result<(), Error> {
    connection_receipt(allowed::ADMISSION_RETIRED, generation, source)
}

fn connection_receipt(op: u64, generation: u64, source: u32) -> Result<(), Error> {
    let mut receipt = [0u8; allowed::ADMISSION_RECEIPT_BYTES];
    receipt[..8].copy_from_slice(&generation.to_le_bytes());
    receipt[8..].copy_from_slice(&source.to_le_bytes());
    match request(op, &receipt, &mut [], 0)? {
        (0, 0) => Ok(()),
        _ => Err(Error::Invalid),
    }
}
pub fn read(out: &mut [u8]) -> Result<usize, Error> {
    let (n, _) = request(allowed::READ, &[], out, 0)?;
    Ok(n)
}
pub fn write_ciphertext(bytes: &[u8]) -> Result<usize, Error> {
    let (n, _) = request(
        allowed::WRITE,
        bytes,
        &mut [],
        allowed::DIRECT_TLS_CIPHERTEXT,
    )?;
    Ok(n)
}
pub fn close() {
    let _ = request(allowed::CLOSE, &[], &mut [], 0);
}
pub fn yield_cpu() {
    let _ = request(allowed::YIELD, &[], &mut [], 0);
}
/// Missing native device quiescence is a fail-closed service stop, never
/// a silent account reset or a new connection generation.
pub fn park() -> ! {
    close();
    loop {
        yield_cpu();
    }
}
