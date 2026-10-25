//! DMA/cache adapter for the pinned ARM virt board; device protocol is separate.
use cyxia_driver_virtio::{Error, Platform};
pub struct Board;
// SAFETY: CPU0 owns statically pinned kernel DMA pools at HIGH+PA. This board
// maps the complete kernel load budget; IRQ handlers never access these queues.
unsafe impl Platform for Board {
    fn physical(&self, address: usize, len: usize) -> Result<u64, Error> {
        let pa = (address as u64)
            .checked_sub(super::HIGH)
            .ok_or(Error::Address)?;
        let end = pa.checked_add(len as u64).ok_or(Error::Address)?;
        if pa < cyxia_platform_virt::ENTRY || end > cyxia_platform_virt::KERNEL_POOL_END {
            return Err(Error::Address);
        }
        Ok(pa)
    }
    unsafe fn sync(&self, address: usize, len: usize) {
        let ctr: u64;
        unsafe {
            core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr);
        }
        let line = 4usize << ((ctr >> 16) & 15);
        let mut at = address & !(line - 1);
        let end = address + len;
        while at < end {
            unsafe {
                core::arch::asm!("dc civac, {}", in(reg) at, options(nostack));
            }
            at += line;
        }
        self.barrier();
    }
    fn barrier(&self) {
        unsafe {
            core::arch::asm!("dsb sy", options(nostack));
        }
    }
    fn now_ms(&self) -> u64 {
        cyxia_arch_aarch64::timer::ticks() / (cyxia_arch_aarch64::timer::frequency() / 1000).max(1)
    }
    fn now_ns(&self) -> u64 {
        let ticks = cyxia_arch_aarch64::timer::ticks();
        let frequency = cyxia_arch_aarch64::timer::frequency().max(1);
        ((u128::from(ticks) * 1_000_000_000) / u128::from(frequency)).min(u128::from(u64::MAX))
            as u64
    }
}
