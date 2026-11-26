//! SEC-N VirtIO-net device init for the V0.20 production boot.
//!
//! CPU0-only, one-shot init that brings up the REAL
//! `driver-virtio::net::BatchedNet` device on the pinned RX/TX DMA pools. Its
//! caller of record is the `v020-production` boot: `production/net.rs`
//! (`net::serve`, run() step after the advice chain) calls [`init`] once, wraps
//! the returned [`NetDevice`] for the smoltcp `tcp::Tcp` listener and relays TCP
//! bytes to the EL0 local-echo guest. This module itself owns no service and no
//! execution grant, and it never fabricates a completion witness.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * CLAIMED (atomic): admits CPU0 once; `init` is therefore one-shot per boot.
//! * RX / TX (static mut BatchMemory): the device's DMA pools. Under
//!   `v020-production` they live in the pinned `.bss.sec_n` arena, registered
//!   as permanent FrameMeta rows at boot. `init` forms the only `&mut` to each and moves both borrows
//!   into the driver: they are borrowed for the DEVICE'S LIFETIME, not for one
//!   call. In production the `NetDevice` holding them lives across the whole of
//!   `net::serve`, driven synchronously by CPU0 only (no IRQ handler or
//!   secondary CPU touches the queues).
//! * The pools are permanently pinned and never reclaimed, including on
//!   initialization failure (a FAILED device is not proof DMA stopped).
//! * The device is NEVER reset: dropping `NetDevice` at the end of
//!   `net::serve` neither releases the pools nor quiesces the device. It stays
//!   live and DMA-capable for the rest of the boot (including the opt-in media
//!   staging run): the host may keep DMA-ing received frames into the RX pool
//!   after `serve` returns. Nothing reads or writes RX/TX after that, so those
//!   writes land only in pinned, otherwise unused memory.
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, Transport, net::BatchedNet, queue::BatchMemory};

/// Board VirtIO MMIO window decoded from the DTB.
const VIRTIO_WINDOW_START: u64 = 0x0a00_0000;
const VIRTIO_WINDOW_END: u64 = 0x0a20_0000;

static CLAIMED: AtomicBool = AtomicBool::new(false);
// The statically registered production arena includes both pinned DMA pools.
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut RX: BatchMemory = BatchMemory::zeroed();
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut TX: BatchMemory = BatchMemory::zeroed();

/// A brought-up real VirtIO-net device. The driver owns the pinned DMA custody;
/// dropping this handle never releases the pages or resets the device.
pub struct NetDevice {
    pub net: BatchedNet,
}

/// Probe the DTB for the single VirtIO-net function and initialize the real
/// BatchedNet driver against the pinned RX/TX pools. CPU0-only, fail-closed.
pub fn init(info: &BootInfo) -> Result<NetDevice, Error> {
    // SAFETY: CLAIMED admits CPU0 once; the boot CPU alone probes DTB MMIO and
    // owns the static pinned DMA pools for this profile's entire lifetime.
    if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::Busy);
    }
    let transport = find_transport(info, 1)?;
    // SAFETY: single CPU0 foreground owner; the static pools are exclusively
    // borrowed here and stay pinned through every error path.
    let net = unsafe {
        BatchedNet::initialize(
            transport,
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            &Board,
        )
    }?;
    Ok(NetDevice { net })
}

/// Find one transport of the expected device type in the board window.
pub(crate) fn find_transport(info: &BootInfo, device_id: u32) -> Result<Transport, Error> {
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).ok_or(Error::Address)? {
        if resource.base.0 < VIRTIO_WINDOW_START
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > VIRTIO_WINDOW_END)
        {
            continue;
        }
        // SAFETY: boot CPU alone probes the mapped Device window; the transport
        // remains exclusively owned and pinned even if a later step fails.
        let Ok(transport) = (unsafe {
            Transport::attach(
                (crate::HIGH + resource.base.0) as usize,
                resource.len as usize,
            )
        }) else {
            continue;
        };
        if transport.device_id() == device_id {
            if selected.is_some() {
                return Err(Error::Device);
            }
            selected = Some(transport);
        }
    }
    selected.ok_or(Error::Device)
}
