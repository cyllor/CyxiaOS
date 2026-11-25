//! Dedicated scratch VirtIO-blk plumbing shared by the V0.19.9 §9.2.1 format
//! fixture (`v0199_format_fixture.rs`) and the V0.20 wave-11 opt-in media
//! staging lane (`production/media_staging.rs`).
//!
//! Extracted verbatim from the format fixture (wave 11 Task 6): device
//! selection, the bounded batch notify policy, the eight-sector-per-block
//! request/validate/acknowledge loop and the synchronous isolated FLUSH. The
//! only behavioural change is that failures are returned to the caller instead
//! of panicking here; the fixture keeps its original `expect`/`assert` policy.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! Global invariant: both callers assert cpu::slot()==0 and drive the device
//! synchronously on CPU0 after the business CPUs were stopped (staging) or
//! while they only run the smp business fixture (format fixture); no IRQ
//! handler or secondary CPU touches the queue (completion interrupts are off).
//! * QUEUE (static mut BatchMemory): the device's DMA ring/bounce memory. One
//!   `&mut` is created by `attach` and moved into the returned BatchedBlock;
//!   `attach` is called at most once per boot. Under v020-production it lives
//!   in the dedicated `.bss.sec_n` link section (outside the wave-11 FrameMeta
//!   window, like the SEC-N pools); it is NOT FrameMeta-registered (open item).
//! * Transport::attach: MMIO window bounded to the virt board's virtio-mmio
//!   range 0x0a000000..0x0a200000 through the high-half device alias.
//! * LAST_ERROR_{CODE,SECTOR,SITE} (atomics): diagnostic only. Written by the
//!   CPU0 caller when a scratch request fails, read by the same CPU0 caller
//!   afterwards (`last_error`); they never influence control flow or DMA.
use super::*;
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_driver_virtio::{
    Error as DriverError, Platform, Transport,
    block::{BatchedBlock, Operation, SECTOR_BYTES},
    queue::{BatchMemory, Token},
};
use cyxia_kernel_core::security::{
    Error as SecurityError, file_index_v0199::BLOCK_BYTES, file_media_v0199::BLOCK_COUNT,
};

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut QUEUE: BatchMemory = BatchMemory::zeroed();

// First failure of a scratch request, kept so the caller can report the real
// driver error instead of the collapsed `SecurityError::Unknown`.
static LAST_ERROR_CODE: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR_SECTOR: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR_SITE: AtomicU64 = AtomicU64::new(0);

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
    /// Not a modern VirtIO device with FLUSH.
    Device = 3,
    /// Not exactly 512 MiB, or read-only.
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
pub(crate) fn attach(info: &BootInfo) -> Result<BatchedBlock, AttachError> {
    let transport = select(info)?;
    // SAFETY: attach is called at most once per boot on CPU0 (module header);
    // this is the only &mut to QUEUE and it moves into the device.
    let queue = unsafe { &mut *core::ptr::addr_of_mut!(QUEUE) };
    let mut device =
        BatchedBlock::attach(transport, queue, &Board).map_err(|_| AttachError::Device)?;
    if device.sectors() != u64::from(BLOCK_COUNT) * 8 || device.read_only() {
        return Err(AttachError::Geometry);
    }
    // Bounded fixture notify policy: one doorbell per eight-sector block.
    // FLUSH requests stay synchronous regardless of the batch policy.
    let now = Board.now_ns();
    device
        .set_notify_policy(8, 1, now.saturating_add(120_000_000_000), now)
        .map_err(|_| AttachError::Policy)?;
    device.set_completion_interrupts(false, &Board);
    Ok(device)
}

fn operation(first: u64, i: usize, write: bool) -> Operation {
    if write {
        Operation::Write(first + i as u64)
    } else {
        Operation::Read(first + i as u64)
    }
}

// One 4 KiB block is exactly eight 512-byte sector requests. The batch queue
// keeps all eight in flight under one bounded notify policy; every completion
// is individually validated and acknowledged before the block is reported
// complete. No buffered or inferred completion is accepted.
pub(crate) fn sectors(
    device: &mut BatchedBlock,
    first: u64,
    write: Option<&[u8; BLOCK_BYTES]>,
    out: &mut [u8; BLOCK_BYTES],
) -> Result<(), SecurityError> {
    let kind = if write.is_some() {
        KIND_WRITE
    } else {
        KIND_READ
    };
    let mut tokens: [Option<Token>; 8] = [None; 8];
    for (i, slot) in tokens.iter_mut().enumerate() {
        let mut input = [0; SECTOR_BYTES];
        if let Some(data) = write {
            input.copy_from_slice(&data[i * SECTOR_BYTES..(i + 1) * SECTOR_BYTES]);
        }
        let op = operation(first, i, write.is_some());
        *slot = Some(
            device
                .begin(op, &input, false, false, &Board)
                .map_err(driver(first + i as u64, kind, PHASE_BEGIN))?,
        );
    }
    device
        .drain(&Board)
        .map_err(driver(first, kind, PHASE_DRAIN))?;
    complete(device, first, &tokens, write.is_some(), out)
}

fn complete(
    device: &mut BatchedBlock,
    first: u64,
    tokens: &[Option<Token>; 8],
    write: bool,
    out: &mut [u8; BLOCK_BYTES],
) -> Result<(), SecurityError> {
    let kind = if write { KIND_WRITE } else { KIND_READ };
    let mut done = [false; 8];
    let mut remaining = 8usize;
    while remaining != 0 {
        let mut bytes = [0; SECTOR_BYTES];
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
        if done[i] || c.operation != operation(first, i, write) {
            return Err(record(0, first + i as u64, kind, PHASE_MISMATCH));
        }
        if !write {
            out[i * SECTOR_BYTES..(i + 1) * SECTOR_BYTES].copy_from_slice(&bytes);
        }
        device
            .acknowledge(c.token)
            .map_err(driver(first + i as u64, kind, PHASE_ACK))?;
        done[i] = true;
        remaining -= 1;
    }
    Ok(())
}

/// Synchronous isolated FLUSH: only the actual device completion, not queue
/// admission or a CPU barrier, may satisfy this call.
pub(crate) fn flush(device: &mut BatchedBlock) -> Result<(), SecurityError> {
    let token = device
        .begin(Operation::Flush, &[0; SECTOR_BYTES], true, true, &Board)
        .map_err(driver(0, KIND_FLUSH, PHASE_BEGIN))?;
    loop {
        let mut bytes = [0; SECTOR_BYTES];
        match device
            .poll(&mut bytes, &Board)
            .map_err(driver(0, KIND_FLUSH, PHASE_POLL))?
        {
            Some(c) => {
                if c.token != token || c.operation != Operation::Flush {
                    return Err(record(0, 0, KIND_FLUSH, PHASE_MISMATCH));
                }
                device
                    .acknowledge(c.token)
                    .map_err(driver(0, KIND_FLUSH, PHASE_ACK))?;
                return Ok(());
            }
            None => core::hint::spin_loop(),
        }
    }
}
