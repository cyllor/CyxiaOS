//! SEC-N production VirtIO-net device init skeleton (T4 device wiring).
//!
//! Provides a clean, CPU0-only init API that the production boot dispatch (T1)
//! calls to bring up the REAL `driver-virtio::net::BatchedNet` device with pinned
//! DMA pages. This is a skeleton: it owns no service, no boot/dispatch path and
//! no execution grant, and it never fabricates a completion witness. The real
//! MMIO/IRQ/DMA custody is exercised only in a native fixture; the protected
//! EL1 dispatch that deploys the Echo service on top remains T1's open gate.
//!
//! # Integration contract T1 must supply (see net-transport::service docs)
//!
//! `init` returns a [`NetDevice`] owning the real driver. T1's production profile
//! must enable the `sec-n-native` feature (or fold this module into the production
//! feature set) and then:
//!   1. Wrap the device as `cyxia_net_transport::device::VirtioPort` (legacy
//!      same-turn ACK) or `cyxia_net_transport::virtio_custody::CustodyNet`
//!      (explicit TX receipt custody) and drive it through `tcp::Tcp`.
//!   2. Supply identity material, trusted clocks, source IPv4 + rate policy,
//!      reset/restart authority and the EL0 execution substrate from protected
//!      kernel state — never from a peer or wire frame.
//!   3. Reconcile real used-ring TX receipts so `tx_quiescent` can become true;
//!      retirement still requires TCP Closed + empty send queue + TLS drain +
//!      generation match (`Service::finish`).
//!
//! UNSAFE BOUNDARY: CPU0-only. `CLAIMED` admits the boot CPU once; the static
//! `RX`/`TX` BatchMemory pools are permanently pinned and never reclaimed,
//! including on initialization failure (a FAILED device is not proof DMA stopped).
//! Every `&mut` to the pools is created and consumed within this single synchronous
//! CPU0 call; no IRQ handler or secondary CPU touches them.
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, Transport, net::BatchedNet, queue::BatchMemory};

/// Net MMIO window decoded from the DTB (same window as the legacy bring-up).
const NET_WINDOW_START: u64 = 0x0a00_0000;
const NET_WINDOW_END: u64 = 0x0a20_0000;

static CLAIMED: AtomicBool = AtomicBool::new(false);
// v020-production keeps the pinned DMA pools in the dedicated `.bss.sec_n` link
// section, outside the wave-11 FrameMeta window (not FrameMeta-registered yet).
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
    let mut selected = None;
    for resource in info.virtio.get(..info.virtio_count).ok_or(Error::Address)? {
        if resource.base.0 < NET_WINDOW_START
            || resource
                .base
                .0
                .checked_add(resource.len)
                .is_none_or(|end| end > NET_WINDOW_END)
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
        if transport.device_id() == 1 {
            if selected.is_some() {
                return Err(Error::Device);
            }
            selected = Some(transport);
        }
    }
    let transport = selected.ok_or(Error::Device)?;
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
