//! Dedicated scratch VirtIO-blk plumbing shared by the V0.19.9 §9.2.1 format
//! fixture (`v0199_format_fixture.rs`) and the V0.20 wave-11 opt-in media
//! staging lane (`production/media_staging.rs`).
//!
//! Each 4 KiB block is transferred in two contiguous four-sector requests.
//! Each request has its own validated and acknowledged device completion.
//! The lane uses synchronous isolated FLUSH for durability boundaries.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! Global invariant: both callers assert cpu::slot()==0 and drive the device
//! synchronously on CPU0 after the business CPUs were stopped (staging) or
//! while they only run the smp business fixture (format fixture); no IRQ
//! handler or secondary CPU touches the queue (completion interrupts are off).
//! * QUEUE (static mut BatchMemory): the device's DMA ring/bounce memory. One
//!   `&mut` is created by `attach` and moved into the returned ScratchBlock;
//!   `attach` is called at most once per boot. Under v020-production it lives
//!   in the `.bss.sec_n` range registered as permanently pinned static Arena
//!   pages. This accounts for the storage across requests, independently of
//!   the device queue's per-request DMA ownership.
//! * Transport::attach: MMIO window bounded to the virt board's virtio-mmio
//!   range 0x0a000000..0x0a200000 through the high-half device alias.
//! * LAST_ERROR_{CODE,SECTOR,SITE}, MAX_LATENCY_{NS,SECTOR}, SLOW (atomics):
//!   diagnostic only. Written by the CPU0 caller when a scratch request fails / completes,
//!   read by the same CPU0 caller afterwards (`last_error`, `max_latency_us`);
//!   they never influence control flow or DMA.
use super::*;
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_driver_virtio::{
    Error as DriverError, Platform, Transport,
    block::{BatchedBlockIo, Operation, SECTOR_BYTES},
    queue::{BatchMemory, Token},
};
use cyxia_kernel_core::security::{
    Error as SecurityError, file_index_v0199::BLOCK_BYTES, file_media_v0199::BLOCK_COUNT,
};

const TRANSFER_BYTES: usize = BLOCK_BYTES / 2;
const SECTORS_PER_TRANSFER: u64 = (TRANSFER_BYTES / SECTOR_BYTES) as u64;
const SECTORS_PER_BLOCK: u64 = (BLOCK_BYTES / SECTOR_BYTES) as u64;
const EMPTY_INPUT: [u8; TRANSFER_BYTES] = [0; TRANSFER_BYTES];
pub(crate) type ScratchBlock = BatchedBlockIo<TRANSFER_BYTES>;

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut QUEUE: BatchMemory = BatchMemory::zeroed();

// First failure of a scratch request, kept so the caller can report the real
// driver error instead of the collapsed `SecurityError::Unknown`.
static LAST_ERROR_CODE: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR_SECTOR: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR_SITE: AtomicU64 = AtomicU64::new(0);

/// Worst observed device completion latency per request kind (read, write,
/// flush), against the driver's fixed 250 ms per-request deadline.
static MAX_LATENCY_NS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
/// First sector of the request that set the worst latency, per kind.
static MAX_LATENCY_SECTOR: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
/// Completions at or above SLOW_NS (a fifth of the 250 ms deadline), per kind.
static SLOW: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
const SLOW_NS: u64 = 50_000_000;

fn observe(kind: u64, sector: u64, latency_ns: u64) {
    let k = kind as usize - 1;
    // CPU0 is the only writer (module header), so load/compare/store is exact.
    if latency_ns > MAX_LATENCY_NS[k].load(Ordering::Relaxed) {
        MAX_LATENCY_NS[k].store(latency_ns, Ordering::Relaxed);
        MAX_LATENCY_SECTOR[k].store(sector, Ordering::Relaxed);
    }
    if latency_ns >= SLOW_NS {
        SLOW[k].fetch_add(1, Ordering::Relaxed);
    }
}

/// Worst completion latency in microseconds as `(read, write, flush)`.
#[cfg(feature = "v020-production-media-staging")]
pub(crate) fn max_latency_us() -> (u64, u64, u64) {
    let us = |k: usize| MAX_LATENCY_NS[k].load(Ordering::Relaxed) / 1_000;
    (us(0), us(1), us(2))
}

/// Per kind `(read, write, flush)`: sector of the worst request and the number
/// of completions at or above 50 ms.
#[cfg(feature = "v020-production-media-staging")]
pub(crate) fn latency_detail() -> ([u64; 3], [u64; 3]) {
    let at = |a: &[AtomicU64; 3]| core::array::from_fn(|k| a[k].load(Ordering::Relaxed));
    (at(&MAX_LATENCY_SECTOR), at(&SLOW))
}

/// Request kind in the failure site code (`site = kind * 10 + phase`).
const KIND_READ: u64 = 1;
const KIND_WRITE: u64 = 2;
const KIND_FLUSH: u64 = 3;
/// Request phase in the failure site code.
const PHASE_BEGIN: u64 = 1;
const PHASE_DRAIN: u64 = 2;
const PHASE_POLL: u64 = 3;
const PHASE_ACK: u64 = 4;
/// Completion that the driver accepted but this layer rejected (wrong token
/// or operation); recorded with driver code 0.
const PHASE_MISMATCH: u64 = 5;

/// Record the first failure. `code` is the driver `Error` discriminant + 1,
/// or 0 when this layer (not the driver) rejected a completion.
fn record(code: u64, sector: u64, kind: u64, phase: u64) -> SecurityError {
    if LAST_ERROR_SITE.load(Ordering::Relaxed) == 0 {
        LAST_ERROR_CODE.store(code, Ordering::Relaxed);
        LAST_ERROR_SECTOR.store(sector, Ordering::Relaxed);
        LAST_ERROR_SITE.store(kind * 10 + phase, Ordering::Relaxed);
    }
    SecurityError::Unknown
}

fn driver(sector: u64, kind: u64, phase: u64) -> impl FnOnce(DriverError) -> SecurityError {
    move |e| record(e as u64 + 1, sector, kind, phase)
}

/// First recorded scratch failure as `(driver code, sector, site)`; `None` if
/// no request failed. Driver codes are `cyxia_driver_virtio::Error` order + 1
/// (Address=1 .. Timeout=6, Device=7, Response=8, Exhausted=9).
#[cfg(feature = "v020-production-media-staging")]
pub(crate) fn last_error() -> Option<(u64, u64, u64)> {
    let site = LAST_ERROR_SITE.load(Ordering::Relaxed);
    (site != 0).then(|| {
        (
            LAST_ERROR_CODE.load(Ordering::Relaxed),
            LAST_ERROR_SECTOR.load(Ordering::Relaxed),
            site,
        )
    })
}

/// Why no usable dedicated scratch block device was attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachError {
    /// No virtio-mmio block device (id 2) in the board range.
    Absent = 1,
    /// More than one block device: the scratch target is ambiguous.
    Ambiguous = 2,
    /// Not a writable modern VirtIO device with FLUSH.
    Device = 3,
    /// Not exactly 512 MiB.
    Geometry = 4,
    /// The bounded batch notify policy was refused.
    Policy = 5,
}

fn select(info: &BootInfo) -> Result<Transport, AttachError> {
    let mut selected = None;
    for resource in &info.virtio[..info.virtio_count] {
        if resource.base.0 < 0x0a000000
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|e| e > 0x0a200000)
        {
            continue;
        }
        // SAFETY: the window is inside the board's virtio-mmio range checked
        // above and mapped through the high-half device alias.
        let Ok(t) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if t.device_id() == 2 {
            if selected.is_some() {
                return Err(AttachError::Ambiguous);
            }
            selected = Some(t);
        }
    }
    selected.ok_or(AttachError::Absent)
}

/// Attach the one dedicated 512 MiB scratch block device. Call at most once.
pub(crate) fn attach(info: &BootInfo) -> Result<ScratchBlock, AttachError> {
    let transport = select(info)?;
    // SAFETY: attach is called at most once per boot on CPU0 (module header);
    // this is the only &mut to QUEUE and it moves into the device.
    let queue = unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) };
    let mut device = ScratchBlock::attach_writable_exact(
        transport,
        queue,
        u64::from(BLOCK_COUNT) * SECTORS_PER_BLOCK,
        &Board,
    )
    .map_err(|error| match error {
        DriverError::Response => AttachError::Geometry,
        _ => AttachError::Device,
    })?;
    // Bounded fixture notify policy: batch both requests for one block.
    // FLUSH requests stay synchronous regardless of the batch policy.
    let now = Board.now_ns();
    device
        .set_notify_policy(2, 1, now.saturating_add(120_000_000_000), now)
        .map_err(|_| AttachError::Policy)?;
    device.set_completion_interrupts(false, &Board);
    Ok(device)
}

fn operation(first: u64, i: usize, write: bool) -> Operation {
    let sector = first + i as u64 * SECTORS_PER_TRANSFER;
    if write {
        Operation::Write(sector)
    } else {
        Operation::Read(sector)
    }
}

// Validate the whole block before publishing either request. The transfer
// counts as complete only after both used records have been acknowledged.
pub(crate) fn sectors(
    device: &mut ScratchBlock,
    first: u64,
    write: Option<&[u8; BLOCK_BYTES]>,
    out: &mut [u8; BLOCK_BYTES],
) -> Result<(), SecurityError> {
    let result = transfer(device, first, write, out);
    finish_io(device, result)
}

fn finish_io(
    device: &mut ScratchBlock,
    result: Result<(), SecurityError>,
) -> Result<(), SecurityError> {
    if result.is_err()
        && let Some(stop) = device.stop_failed_mmio(&Board)
    {
        // An early media error might precede a verified BootEpoch. Report
        // the device observation without claiming a bound durable receipt.
        match stop {
            Ok(observed) => report("V020_SEC_D_BLOCK_MMIO_STOPPED", 2, 0, observed),
            Err(error) => report("V020_SEC_D_BLOCK_MMIO_UNKNOWN", 2, 0, error as u64),
        }
    }
    result
}

fn transfer(
    device: &mut ScratchBlock,
    first: u64,
    write: Option<&[u8; BLOCK_BYTES]>,
    out: &mut [u8; BLOCK_BYTES],
) -> Result<(), SecurityError> {
    let kind = if write.is_some() {
        KIND_WRITE
    } else {
        KIND_READ
    };
    if !first.is_multiple_of(SECTORS_PER_BLOCK)
        || device
            .sectors()
            .checked_sub(first)
            .is_none_or(|remaining| remaining < SECTORS_PER_BLOCK)
    {
        return Err(driver(first, kind, PHASE_BEGIN)(DriverError::Address));
    }
    let mut tokens: [Option<Token>; 2] = [None; 2];
    for (i, slot) in tokens.iter_mut().enumerate() {
        let input = write.map_or(&EMPTY_INPUT, |data| {
            data[i * TRANSFER_BYTES..]
                .first_chunk::<TRANSFER_BYTES>()
                .unwrap()
        });
        let sector = first + i as u64 * SECTORS_PER_TRANSFER;
        let op = operation(first, i, write.is_some());
        *slot = Some(
            device
                .begin(op, input, false, false, &Board)
                .map_err(driver(sector, kind, PHASE_BEGIN))?,
        );
    }
    device
        .drain(&Board)
        .map_err(driver(first, kind, PHASE_DRAIN))?;
    complete(device, first, &tokens, write.is_some(), out)
}

fn complete(
    device: &mut ScratchBlock,
    first: u64,
    tokens: &[Option<Token>; 2],
    write: bool,
    out: &mut [u8; BLOCK_BYTES],
) -> Result<(), SecurityError> {
    let kind = if write { KIND_WRITE } else { KIND_READ };
    let mut done = [false; 2];
    let mut remaining = tokens.len();
    let mut bytes = [0; TRANSFER_BYTES];
    while remaining != 0 {
        let Some(c) = device
            .poll(&mut bytes, &Board)
            .map_err(driver(first, kind, PHASE_POLL))?
        else {
            core::hint::spin_loop();
            continue;
        };
        let Some(i) = tokens.iter().position(|t| *t == Some(c.token)) else {
            return Err(record(0, first, kind, PHASE_MISMATCH));
        };
        let sector = first + i as u64 * SECTORS_PER_TRANSFER;
        if done[i] || c.operation != operation(first, i, write) {
            return Err(record(0, sector, kind, PHASE_MISMATCH));
        }
        observe(kind, sector, c.latency_ns);
        if !write {
            out[i * TRANSFER_BYTES..(i + 1) * TRANSFER_BYTES].copy_from_slice(&bytes);
        }
        device
            .acknowledge(c.token)
            .map_err(driver(sector, kind, PHASE_ACK))?;
        done[i] = true;
        remaining -= 1;
    }
    Ok(())
}

/// Synchronous isolated FLUSH: only the actual device completion, not queue
/// admission or a CPU barrier, may satisfy this call.
pub(crate) fn flush(device: &mut ScratchBlock) -> Result<(), SecurityError> {
    let result = issue_flush(device);
    finish_io(device, result)
}

fn issue_flush(device: &mut ScratchBlock) -> Result<(), SecurityError> {
    let token = device
        .begin(Operation::Flush, &EMPTY_INPUT, true, true, &Board)
        .map_err(driver(0, KIND_FLUSH, PHASE_BEGIN))?;
    let mut bytes = [0; TRANSFER_BYTES];
    loop {
        match device
            .poll(&mut bytes, &Board)
            .map_err(driver(0, KIND_FLUSH, PHASE_POLL))?
        {
            Some(c) => {
                if c.token != token || c.operation != Operation::Flush {
                    return Err(record(0, 0, KIND_FLUSH, PHASE_MISMATCH));
                }
                observe(KIND_FLUSH, 0, c.latency_ns);
                device
                    .acknowledge(c.token)
                    .map_err(driver(0, KIND_FLUSH, PHASE_ACK))?;
                return Ok(());
            }
            None => core::hint::spin_loop(),
        }
    }
}
