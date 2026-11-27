//! The virt board's terminal DMA inventory. Release publication precedes
//! both the queue addresses and QueueReady. Emergency stop owns registers
//! after CPU acknowledgement and never reads the abandoned queue storage.
use super::{Board, VIRTIO_MMIO_BYTES};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_driver_virtio::{Error, MappedRegion, Transport};

const DEVICE_IDS: [u32; 3] = [1, 2, 4];
const QUEUE_MASK: u64 = 3;
pub(crate) const DMA_STOP_DEVICES: usize = DEVICE_IDS.len();

// The low two bits of each aligned MMIO physical address describe the queue
// mask. One word keeps identity and inventory consistent even during a stop.
static REGISTERED: [AtomicU64; DMA_STOP_DEVICES] = [const { AtomicU64::new(0) }; DMA_STOP_DEVICES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredDma {
    pub mmio_pa: u64,
    pub device_id: u32,
    pub queues: u16,
}

pub(super) fn register(mmio_pa: u64, device_id: u32, queue: u32) -> Result<(), Error> {
    if cyxia_arch_aarch64::cpu::registered_slot() != Some(0) {
        return Err(Error::Busy);
    }
    let slot = DEVICE_IDS
        .iter()
        .position(|id| *id == device_id)
        .ok_or(Error::Unsupported)?;
    let registered = &REGISTERED[slot];
    let previous = registered.load(Ordering::Acquire);
    let queue_bit = 1 << queue;
    if (previous != 0 && previous & !QUEUE_MASK != mmio_pa) || previous & queue_bit != 0 {
        return Err(Error::Busy);
    }
    registered.store(mmio_pa | previous | queue_bit, Ordering::Release);
    Ok(())
}

pub(crate) fn registered_dma() -> [Option<RegisteredDma>; DMA_STOP_DEVICES] {
    core::array::from_fn(|slot| {
        let value = REGISTERED[slot].load(Ordering::Acquire);
        (value != 0).then_some(RegisteredDma {
            mmio_pa: value & !QUEUE_MASK,
            device_id: DEVICE_IDS[slot],
            queues: (value & QUEUE_MASK) as u16,
        })
    })
}

/// # Safety
/// CPU stop ACKs prove all former MMIO owners permanently stopped. This is
/// called solely by the elected terminal owner, once per registered device.
pub(crate) unsafe fn reset_registered_dma(device: RegisteredDma) -> Result<u64, Error> {
    if !registered_dma().contains(&Some(device)) {
        return Err(Error::Device);
    }
    let queues: &[u16] = match device.queues {
        1 => &[0],
        2 => &[1],
        3 => &[0, 1],
        _ => return Err(Error::Queue),
    };
    let region = MappedRegion {
        base: (crate::HIGH + device.mmio_pa) as usize,
        len: VIRTIO_MMIO_BYTES,
    };
    // SAFETY: the matching entry was registered through Board queue admission
    // while the MMIO mapping was pinned. The caller enforces terminal custody.
    unsafe { Transport::terminal_mmio_reset(region, device.device_id, queues, &Board) }
}
