//! Coherent x86 DMA adapter for pinned kernel-owned buffers.
use cyxia_driver_virtio::{Error, Platform};
pub struct Board;
unsafe extern "C" { static __kernel_end: u8; }

// SAFETY: shared drivers use permanently pinned kernel DMA queues/backing; the
// CPU0 foreground owns each queue. RAM is WB coherent, device registers UC/NX.
unsafe impl Platform for Board {
    fn physical(&self, address: usize, len: usize) -> Result<u64, Error> {
        let end = address.checked_add(len).ok_or(Error::Address)?;
        let kernel_end = core::ptr::addr_of!(__kernel_end) as usize;
        if len == 0 || address < crate::HIGH as usize + 0x10_0000 || end > kernel_end {
            return Err(Error::Address);
        }
        crate::machine::runtime::kernel_phys(address, len).map_err(|_| Error::Address)
    }
    unsafe fn sync(&self, _address: usize, _len: usize) { self.barrier(); }
    fn barrier(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
    fn now_ms(&self) -> u64 { self.now_ns() / 1_000_000 }
    fn now_ns(&self) -> u64 { crate::machine::runtime::now_ns() }
}
