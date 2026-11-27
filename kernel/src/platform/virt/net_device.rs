//! SEC-N VirtIO-net device init for the V0.20 production boot.
//!
//! CPU0-only, one-shot init that brings up the REAL
//! `driver-virtio::net::BatchedNet` device on the pinned RX/TX DMA pools. Its
//! caller of record is the `v020-production` boot: `production/net.rs`
//! (`net::serve`, run() step after the advice chain) calls [`with_device`] once,
//! borrows the device for the smoltcp `tcp::Tcp` listener and relays TCP
//! bytes to the EL0 local-echo guest. This module itself owns no service and no
//! execution grant, and it never fabricates a completion witness.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * CLAIMED (atomic): admits CPU0 once.
//! * RX / TX (static mut BatchMemory): the device's DMA pools. Under
//!   `v020-production` they live in the pinned `.bss.sec_n` arena, registered
//!   as permanent FrameMeta rows at boot. `with_device` forms the only mutable
//!   borrows and moves them into the driver. No IRQ or secondary touches them.
//! * OWNER (static NetDevice): holds the exact queue generations and terminal
//!   reset result for the whole boot. Only the serialized CPU0 callback can
//!   access the live driver. TERMINAL publishes immutable recovery readback
//!   after the callback's mutable borrow and the reset attempt have finished.
//! * The pools are permanently pinned and never reclaimed, including on
//!   initialization failure (a FAILED device is not proof DMA stopped).
//! * The foreground owner explicitly fences and resets both queues when its
//!   one-shot TCP stream ends. Both pools stay pinned, including on reset
//!   timeout or unproven credit retirement.
use crate::virtio_platform::Board;
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{
    Error, Transport,
    net::BatchedNet,
    queue::{BatchMemory, MAX_CHAINS, RetainedChain},
    reset::ResetProof,
};

/// Board VirtIO MMIO window decoded from the DTB.
const VIRTIO_WINDOW_START: u64 = 0x0a00_0000;
const VIRTIO_WINDOW_END: u64 = 0x0a20_0000;
const NATIVE_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

static CLAIMED: AtomicBool = AtomicBool::new(false);
static TERMINAL: AtomicBool = AtomicBool::new(false);
// The statically registered production arena includes both pinned DMA pools.
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut RX: BatchMemory = BatchMemory::zeroed();
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut TX: BatchMemory = BatchMemory::zeroed();
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut OWNER: MaybeUninit<NetDevice> = MaybeUninit::uninit();

struct NetDevice {
    net: BatchedNet,
    boot_epoch: u64,
    reset: Option<Result<[ResetProof; 2], Error>>,
}

pub(crate) struct TerminalCustody {
    pub(crate) reset: Result<[ResetProof; 2], Error>,
    pub(crate) chains: [[Option<RetainedChain>; MAX_CHAINS]; 2],
}

/// Run the one CPU0 service with the pinned driver and then freeze it.
pub(crate) fn with_device<R>(
    info: &BootInfo,
    boot_epoch: u64,
    serve: impl FnOnce(&mut BatchedNet) -> R,
) -> Result<R, Error> {
    if boot_epoch == 0 {
        return Err(Error::Address);
    }
    // SAFETY: CLAIMED admits CPU0 once; the boot CPU alone probes DTB MMIO and
    // owns the static pinned DMA pools for this profile's entire lifetime.
    if cyxia_arch_aarch64::cpu::slot() != 0 || CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(Error::Busy);
    }
    let transport = find_transport(info, 1)?;
    // SAFETY: single CPU0 foreground owner; the static pools are exclusively
    // borrowed here and stay pinned through every error path.
    let net = unsafe {
        BatchedNet::initialize_native(
            transport,
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            NATIVE_MAC,
            &Board,
        )
    }?;
    // SAFETY: the one-shot claim grants this scope exclusive OWNER access.
    // The callback cannot return a borrow of its argument. No reader can
    // reach OWNER until after it has stopped taking mutable references.
    let outcome = unsafe {
        let owner = core::ptr::addr_of_mut!(OWNER).cast::<NetDevice>();
        owner.write(NetDevice {
            net,
            boot_epoch,
            reset: None,
        });
        let owner = &mut *owner;
        let result = serve(&mut owner.net);
        owner.reset = Some(owner.net.stop_native(boot_epoch, &Board));
        result
    };
    TERMINAL.store(true, Ordering::Release);
    Ok(outcome)
}

/// Inspect the old generation in place without clearing pins or restarting
/// the device. Repeated reads of the same epoch see the same sealed state.
pub(crate) fn terminal_custody(boot_epoch: u64) -> Result<TerminalCustody, Error> {
    if cyxia_arch_aarch64::cpu::slot() != 0 || !TERMINAL.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    // SAFETY: the acquire observes initialized OWNER after its only mutable
    // references ended. The one-shot claim rules out any later writer.
    let owner = unsafe { (&*core::ptr::addr_of!(OWNER)).assume_init_ref() };
    if owner.boot_epoch != boot_epoch {
        return Err(Error::Response);
    }
    Ok(TerminalCustody {
        reset: owner.reset.ok_or(Error::Busy)?,
        chains: owner.net.stopped_chains().ok_or(Error::Response)?,
    })
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
