//! DMA/cache adapter for the pinned ARM virt board; device protocol is separate.
#[cfg(any(feature = "v020-production", feature = "unified-runtime"))]
use core::ops::Range;
#[cfg(any(
    feature = "v020-production-diagnostic",
    cyxia_startup_catalog,
    feature = "unified-runtime"
))]
use core::ptr::addr_of;
use cyxia_driver_virtio::{Error, Platform};
#[cfg(any(
    feature = "v020-production-diagnostic",
    cyxia_startup_catalog,
    feature = "unified-runtime"
))]
use cyxia_kernel_core::{frame_meta_v0199::Owner, security::Error as LedgerError};
#[cfg(any(
    feature = "v020-panic-stop-dma-selftest",
    feature = "v020-production-diagnostic",
    cyxia_business_package,
    cyxia_resident_net
))]
use {cyxia_contracts::BootInfo, cyxia_driver_virtio::Transport};

#[cfg(any(feature = "v020-production", feature = "unified-runtime"))]
const VIRTIO_MMIO: Range<u64> = 0x0a00_0000..0x0a20_0000;
#[cfg(any(feature = "v020-production", feature = "unified-runtime"))]
const VIRTIO_MMIO_BYTES: usize = 0x200;

#[cfg(feature = "v020-production")]
#[path = "virtio_dma_stop.rs"]
mod dma_stop;
#[cfg(feature = "v020-production")]
pub(crate) use dma_stop::{DMA_STOP_DEVICES, registered_dma, reset_registered_dma};

pub struct Board;
// SAFETY: CPU0 admits statically pinned DMA pools at HIGH+PA. This board maps
// the complete kernel load budget; IRQ handlers never access these queues.
unsafe impl Platform for Board {
    fn diagnostic_stage(&self, stage: u64) {
        #[cfg(feature = "unified-runtime")]
        crate::network_diagnostics::stage(stage);
        #[cfg(not(feature = "unified-runtime"))]
        let _ = stage;
    }
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
    #[cfg(any(feature = "v020-production", feature = "unified-runtime"))]
    fn admit_queue_dma(
        &self,
        transport: usize,
        device: u32,
        index: u32,
        pa: u64,
        len: usize,
    ) -> Result<(), Error> {
        let transport_pa = (transport as u64)
            .checked_sub(crate::HIGH)
            .ok_or(Error::Address)?;
        if !VIRTIO_MMIO.contains(&transport_pa)
            || !transport_pa.is_multiple_of(4)
            || transport_pa + VIRTIO_MMIO_BYTES as u64 > VIRTIO_MMIO.end
        {
            return Err(Error::Address);
        }
        if !matches!((device, index), (1, 0 | 1) | (2 | 4, 0)) {
            return Err(Error::Unsupported);
        }
        #[cfg(any(
            feature = "v020-production-diagnostic",
            cyxia_startup_catalog,
            feature = "unified-runtime"
        ))]
        {
            let offset = (transport_pa - VIRTIO_MMIO.start) as u32;
            let owner = Owner {
                // Device slots are separate from task slots. The low bits of
                // the register-aligned offset distinguish the two net queues.
                slot: 0x8000_0000 | offset | index,
                // The block queue is one-shot even before BootEpoch publication.
                generation: 1,
            };
            let arena = dma_arena()?;
            let end = pa.checked_add(len as u64).ok_or(Error::Address)?;
            if pa < arena.start || end > arena.end {
                return Err(Error::Address);
            }
            #[cfg(any(feature = "v020-production-diagnostic", cyxia_startup_catalog))]
            let claim = crate::smp::production::frames::claim_static_dma(pa..end, owner);
            #[cfg(feature = "unified-runtime")]
            let claim = unified_dma::claim_static_dma(arena, pa..end, owner);
            claim.map_err(|error| match error {
                LedgerError::Busy => Error::Busy,
                _ => Error::Address,
            })?;
        }
        #[cfg(not(any(
            feature = "v020-production-diagnostic",
            cyxia_startup_catalog,
            feature = "unified-runtime"
        )))]
        let _ = (pa, len);
        #[cfg(feature = "v020-production")]
        dma_stop::register(transport_pa, device, index)?;
        Ok(())
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

#[cfg(any(
    feature = "v020-production-diagnostic",
    cyxia_startup_catalog,
    feature = "unified-runtime"
))]
fn dma_arena() -> Result<Range<u64>, Error> {
    unsafe extern "C" {
        static __sec_n_dma_start: u8;
        static __sec_n_dma_end: u8;
    }
    let start = (addr_of!(__sec_n_dma_start) as u64)
        .checked_sub(crate::HIGH)
        .ok_or(Error::Address)?;
    let end = (addr_of!(__sec_n_dma_end) as u64)
        .checked_sub(crate::HIGH)
        .ok_or(Error::Address)?;
    Ok(start..end)
}

#[cfg(feature = "unified-runtime")]
mod unified_dma {
    use super::{LedgerError, Owner, Range};
    use core::ptr::addr_of_mut;
    use cyxia_contracts::{MemoryRegion, PhysAddr, RegionKind};
    use cyxia_driver_virtio::queue::BatchMemory;
    use cyxia_kernel_core::frame_meta_v0199::{FrameMeta, Ledger, PAGE, StaticClass, StaticRegion};

    // Storage, network RX and TX, and entropy each have one native queue.
    const PAGES: usize = 4 * (size_of::<BatchMemory>() / PAGE as usize);
    static mut ROWS: [FrameMeta; PAGES] = [FrameMeta::ZERO; PAGES];
    static mut LEDGER: Option<Ledger<'static>> = None;

    pub(super) fn claim_static_dma(
        arena: Range<u64>,
        span: Range<u64>,
        owner: Owner,
    ) -> Result<(), LedgerError> {
        if cyxia_arch_aarch64::cpu::registered_slot() != Some(0) {
            return Err(LedgerError::Unauthorized);
        }
        // SAFETY: only CPU0 starts these devices. No IRQ or callback acquires
        // DMA admission, and ROWS is borrowed exclusively by the one ledger.
        let slot = unsafe { &mut *addr_of_mut!(LEDGER) };
        let ledger = match slot {
            Some(ledger) => ledger,
            None => {
                let len = arena
                    .end
                    .checked_sub(arena.start)
                    .ok_or(LedgerError::Invalid)?;
                let region = StaticRegion {
                    region: MemoryRegion {
                        start: PhysAddr(arena.start),
                        len,
                        kind: RegionKind::Reserved,
                    },
                    class: StaticClass::Arena,
                };
                let rows = unsafe { &mut *addr_of_mut!(ROWS) };
                slot.insert(Ledger::initialize_static(rows, arena.start, &[region])?)
            }
        };
        ledger.claim_static_dma(span, owner)
    }
}

/// Find the unique device of this type in the DTB-validated MMIO window.
#[cfg(any(
    feature = "v020-panic-stop-dma-selftest",
    feature = "v020-production-diagnostic",
    cyxia_business_package,
    cyxia_resident_net
))]
pub(crate) fn find_transport(info: &BootInfo, device_id: u32) -> Result<Transport, Error> {
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).ok_or(Error::Address)? {
        if !VIRTIO_MMIO.contains(&resource.base.0)
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > VIRTIO_MMIO.end)
        {
            continue;
        }
        // SAFETY: the boot owner probes only validated, mapped MMIO.
        let Ok(transport) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if transport.device_id() == device_id && selected.replace(transport).is_some() {
            return Err(Error::Device);
        }
    }
    selected.ok_or(Error::Device)
}
