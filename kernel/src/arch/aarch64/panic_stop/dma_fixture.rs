//! Native terminal-stop fixture for the three supported VirtIO-MMIO devices.
//! The scratch disk receives only a read, and all backing remains pinned.
use crate::virtio_platform::{Board, find_transport};
use core::ptr::addr_of_mut;
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{
    Error,
    block::{BatchedBlock, Operation, SECTOR_BYTES},
    net::BatchedNet,
    queue::BatchMemory,
    rng::BatchedRng,
};

#[unsafe(link_section = ".bss.sec_n.dma")]
static mut BLOCK: BatchMemory = BatchMemory::zeroed();
#[unsafe(link_section = ".bss.sec_n.dma")]
static mut RX: BatchMemory = BatchMemory::zeroed();
#[unsafe(link_section = ".bss.sec_n.dma")]
static mut TX: BatchMemory = BatchMemory::zeroed();
#[unsafe(link_section = ".bss.sec_n.dma")]
static mut RNG: BatchMemory = BatchMemory::zeroed();

pub(super) fn stage(info: &BootInfo) -> Result<(), Error> {
    let block = find_transport(info, 2)?;
    let net = find_transport(info, 1)?;
    let rng = find_transport(info, 4)?;
    // SAFETY: the post-SMP native fixture calls this once from CPU0 before
    // terminal entry. Each address names unique, permanently pinned backing.
    let (block_memory, rx, tx, rng_memory) = unsafe {
        (
            &mut *addr_of_mut!(BLOCK),
            &mut *addr_of_mut!(RX),
            &mut *addr_of_mut!(TX),
            &mut *addr_of_mut!(RNG),
        )
    };
    let mut block = BatchedBlock::attach_writable_exact(block, block_memory, 1_048_576, &Board)?;
    let mut net =
        BatchedNet::initialize_native(net, rx, tx, [0x52, 0x54, 0, 0x12, 0x34, 0x56], &Board)?;
    let mut rng = BatchedRng::attach_native(rng, rng_memory, &Board)?;
    block.set_completion_interrupts(false, &Board);
    net.set_completion_interrupts(false, &Board);
    rng.set_completion_interrupts(false, &Board);
    block.begin(Operation::Read(0), &[0; SECTOR_BYTES], true, true, &Board)?;
    rng.prefetch(&Board)?;
    if block.retained_requests() != (1, 0)
        || net.notify_stats().inflight == 0
        || rng.notify_stats().inflight == 0
    {
        return Err(Error::Response);
    }
    // No owner polls these chains before the elected stop owner takes over.
    crate::machine::log(b"V020_SEC_D_STOP_FIXTURE a=1 b=1 c=1\n");
    Ok(())
}
