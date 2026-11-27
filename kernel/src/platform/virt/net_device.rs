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
use crate::virtio_platform::{Board, find_transport};
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, net::BatchedNet, queue::BatchMemory};
#[cfg(feature = "v020-production-diagnostic")]
use cyxia_driver_virtio::{
    queue::{MAX_CHAINS, RetainedChain},
    reset::ResetProof,
};

#[cfg(feature = "v020-production-diagnostic")]
const NATIVE_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

static CLAIMED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "v020-production-diagnostic")]
static TERMINAL: AtomicBool = AtomicBool::new(false);
// The statically registered production arena includes both pinned DMA pools.
#[unsafe(link_section = ".bss.sec_n.dma")]
#[unsafe(export_name = "V020_DMA_NET_RX_QUEUE")]
static mut RX: BatchMemory = BatchMemory::zeroed();
#[unsafe(link_section = ".bss.sec_n.dma")]
#[unsafe(export_name = "V020_DMA_NET_TX_QUEUE")]
static mut TX: BatchMemory = BatchMemory::zeroed();
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut OWNER: MaybeUninit<NetDevice> = MaybeUninit::uninit();

struct NetDevice {
    net: BatchedNet,
    #[cfg(feature = "v020-production-diagnostic")]
    boot_epoch: u64,
    #[cfg(feature = "v020-production-diagnostic")]
    reset: Option<Result<[ResetProof; 2], Error>>,
}

#[cfg(feature = "v020-production-diagnostic")]
pub(crate) struct TerminalCustody {
    pub(crate) reset: Result<[ResetProof; 2], Error>,
    pub(crate) chains: [[Option<RetainedChain>; MAX_CHAINS]; 2],
}

/// Run the one CPU0 service with the pinned driver and then freeze it.
#[cfg(feature = "v020-production-diagnostic")]
pub(crate) fn with_device<R>(
    info: &BootInfo,
    boot_epoch: u64,
    serve: impl FnOnce(&mut BatchedNet) -> R,
) -> Result<R, Error> {
    let owner = initialize(info, boot_epoch, NATIVE_MAC, &mut || Ok(()))?;
    let result = serve(&mut owner.net);
    owner.reset = Some(owner.net.stop_native(boot_epoch, &Board));
    TERMINAL.store(true, Ordering::Release);
    Ok(result)
}

/// Stage the permanent device owner on CPU0 before handing it to CPU1.
#[cfg(cyxia_resident_net)]
pub(crate) fn open_resident(
    info: &BootInfo,
    boot_epoch: u64,
    mac: [u8; 6],
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<&'static mut BatchedNet, Error> {
    initialize(info, boot_epoch, mac, checkpoint).map(|owner| &mut owner.net)
}

fn initialize(
    info: &BootInfo,
    boot_epoch: u64,
    mac: [u8; 6],
    checkpoint: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<&'static mut NetDevice, Error> {
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
        BatchedNet::initialize_native_with_checkpoint(
            transport,
            &mut *core::ptr::addr_of_mut!(RX),
            &mut *core::ptr::addr_of_mut!(TX),
            mac,
            &Board,
            checkpoint,
        )
    }?;
    // SAFETY: the one-shot claim grants sole ownership. Diagnostic
    // readback can access OWNER only after the terminal seal.
    Ok(unsafe {
        let owner = core::ptr::addr_of_mut!(OWNER).cast::<NetDevice>();
        owner.write(NetDevice {
            net,
            #[cfg(feature = "v020-production-diagnostic")]
            boot_epoch,
            #[cfg(feature = "v020-production-diagnostic")]
            reset: None,
        });
        &mut *owner
    })
}

/// Inspect the old generation in place without clearing pins or restarting
/// the device. Repeated reads of the same epoch see the same sealed state.
#[cfg(feature = "v020-production-diagnostic")]
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
