use super::*;

pub(crate) static UART: AtomicU64 = AtomicU64::new(0);
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static LOG_LOSS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "unified-runtime")]
#[repr(C, align(64))]
pub struct PanicEvidence {
    pub words: [AtomicU64; 8],
}
#[cfg(feature = "unified-runtime")]
#[used]
#[unsafe(no_mangle)]
pub static PANIC_EVIDENCE: PanicEvidence = PanicEvidence {
    words: [const { AtomicU64::new(0) }; 8],
};
pub(crate) fn log(s: &[u8]) {
    if let Err(PlatformError::Again) = try_log(s) {
        // Best-effort diagnostic caller drops this record; keep that loss visible.
        LOG_LOSS.fetch_add(1, Ordering::Relaxed);
        LOG_SEQUENCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
            .unwrap_or_else(|_| halt());
    }
}
pub(crate) fn try_log(s: &[u8]) -> Result<(), PlatformError> {
    let a = UART.load(Ordering::Relaxed);
    if a == 0 {
        return Err(PlatformError::Invalid);
    }
    let seq = LOG_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| x.checked_add(1))
        .unwrap_or_else(|_| halt());
    #[cfg(feature = "unified-runtime")]
    if domain_services::console_ready() {
        return match domain_services::enqueue_frame(1, seq, s) {
            Ok(()) => Ok(()),
            Err(cyxia_prototype::domains::Error::Busy | cyxia_prototype::domains::Error::Again) => {
                LOG_SEQUENCE.store(seq, Ordering::Relaxed);
                Err(PlatformError::Again)
            }
            Err(_) => {
                LOG_LOSS.fetch_add(1, Ordering::Relaxed);
                Err(PlatformError::Invalid)
            }
        };
    }
    let mut uart = unsafe {
        cyxia_driver_pl011::Pl011::attach(UartResource {
            base: PhysAddr(a),
            len: 4096,
        })
    }?;
    use cyxia_kernel_core::console::{TransmitError, write_frame};
    match write_frame(&mut uart, 1, seq, s) {
        Ok(written) => {
            interrupts::TEST_PROGRESS
                .bytes
                .fetch_add(written as u64, Ordering::Relaxed);
            Ok(())
        }
        Err(TransmitError::Again) => {
            // CPU0 foreground is the sole nonfatal writer. No byte escaped, so
            // a later attempt can use the same sequence without an artificial gap.
            LOG_SEQUENCE.store(seq, Ordering::Relaxed);
            Err(PlatformError::Again)
        }
        Err(error) => {
            if let TransmitError::Failed(written) = error {
                interrupts::TEST_PROGRESS
                    .bytes
                    .fetch_add(written as u64, Ordering::Relaxed);
            }
            LOG_LOSS.fetch_add(1, Ordering::Relaxed);
            Err(PlatformError::Invalid)
        }
    }
}

#[cfg(feature = "v020-production")]
#[repr(u64)]
pub(super) enum EmergencyTxStatus {
    Queued = 1,
    FifoFull = 2,
    Unavailable = 3,
    Deadline = 4,
    ConsoleUnconfirmed = 5,
}

#[cfg(feature = "v020-production")]
pub(super) struct EmergencyTx {
    pub(super) status: EmergencyTxStatus,
    pub(super) sequence: u64,
    pub(super) written: u64,
}

/// The once-only PANIC_STOP owner may use the boot-registered PL011 after
/// CPU0's ordinary writer is quiescent. This leaves ordinary queues,
/// counters, and device configuration alone.
#[cfg(feature = "v020-production")]
pub(super) fn emergency_stop_write(
    payload: &[u8; 27],
    began: u64,
    until: u64,
    console_quiescent: bool,
) -> EmergencyTx {
    use cyxia_arch_aarch64::timer;
    let discarded = |status| EmergencyTx {
        status,
        sequence: 0,
        written: 0,
    };
    if !console_quiescent {
        return discarded(EmergencyTxStatus::ConsoleUnconfirmed);
    }
    let base = UART.load(Ordering::Acquire);
    let sequence = LOG_SEQUENCE.load(Ordering::Relaxed);
    if base != HIGH + 0x0900_0000 || sequence == 0 {
        return discarded(EmergencyTxStatus::Unavailable);
    }
    // SAFETY: this is exactly the immutable Device mapping verified at boot.
    // The ordinary CPU0 writer is terminal and only the elected owner writes.
    let Ok(mut uart) = (unsafe {
        cyxia_driver_pl011::Pl011::attach(UartResource {
            base: PhysAddr(base),
            len: 4096,
        })
    }) else {
        return discarded(EmergencyTxStatus::Unavailable);
    };
    let mut frame = [0; 55];
    let Ok(size) = cyxia_contracts::transport::encode(1, sequence, payload, &mut frame) else {
        return discarded(EmergencyTxStatus::Unavailable);
    };
    if size != frame.len() {
        return discarded(EmergencyTxStatus::Unavailable);
    }
    let mut expired = false;
    let written = uart.try_write_before(&frame, || {
        expired = !(began..until).contains(&timer::ticks());
        !expired
    });
    EmergencyTx {
        status: if expired {
            EmergencyTxStatus::Deadline
        } else if written == frame.len() {
            EmergencyTxStatus::Queued
        } else {
            EmergencyTxStatus::FifoFull
        },
        sequence,
        written: written as u64,
    }
}

/// Admit a complete frame to the sole CPU0 writer. The resident console
/// drains the retained suffix after a short write before admitting another.
#[cfg(any(
    feature = "v020-production-signed-resident",
    all(
        feature = "v020-production",
        not(feature = "v020-production-diagnostic")
    )
))]
pub(crate) fn enqueue_resident_frame(
    pending: &mut cyxia_kernel_core::console::OutputQueue<128>,
    payload: &[u8],
) -> Result<(), PlatformError> {
    let sequence = LOG_SEQUENCE.load(Ordering::Relaxed);
    let next = sequence.checked_add(1).ok_or(PlatformError::Invalid)?;
    let mut frame = [0; 128];
    let size = cyxia_contracts::transport::encode(1, sequence, payload, &mut frame)
        .map_err(|_| PlatformError::Invalid)?;
    pending.enqueue(&frame[..size])?;
    LOG_SEQUENCE.store(next, Ordering::Relaxed);
    Ok(())
}
/// The current ordinary HAL owner accepts a complete transport frame
/// before advancing the sole writer's sequence. Emergency log() stays
/// independent. Call only from the serialized native console owner;
/// no direct/emergency writer may interleave an admitted partial frame.
#[cfg(feature = "v0199-epoch-disk-selftest")]
pub(crate) fn enqueue_v0199(
    owner: &mut cyxia_kernel_core::control_plane::d15_owner_v0199::Owner,
    payload: &[u8],
    now: u64,
) -> Result<usize, cyxia_kernel_core::control_plane::Error> {
    use cyxia_kernel_core::control_plane::Error;
    let seq = LOG_SEQUENCE.load(Ordering::Relaxed);
    let next = seq.checked_add(1).ok_or(Error::Exhausted)?;
    let mut frame = [0; 128];
    let n = cyxia_contracts::transport::encode(1, seq, payload, &mut frame)
        .map_err(|_| Error::Invalid)?;
    owner.enqueue(&frame[..n], now)?;
    LOG_SEQUENCE
        .compare_exchange(seq, next, Ordering::Relaxed, Ordering::Relaxed)
        .expect("serialized console writer");
    Ok(n)
}
pub(crate) fn halt() -> ! {
    loop {
        // v020-production parks with WFI. QEMU TCG implements WFE as a yield
        // hint that never sleeps the vCPU, so every CPU parked here burned one
        // host core for the rest of the boot; with the three halted business
        // CPUs that starved QEMU's device-completion path and pushed scratch
        // virtio-blk completions toward the driver's 250 ms deadline (wave-11
        // staging flake). WFI halts the vCPU until an interrupt is pending;
        // with DAIF masked it then just loops back here. Other profiles keep WFE.
        #[cfg(feature = "v020-production")]
        // SAFETY: masking DAIF and waiting for an interrupt touches no memory;
        // this CPU never leaves the loop.
        unsafe {
            core::arch::asm!("msr daifset, #15", "wfi")
        }
        #[cfg(not(feature = "v020-production"))]
        // SAFETY: masking DAIF and waiting for an event touches no memory;
        // this CPU never leaves the loop.
        unsafe {
            core::arch::asm!("msr daifset, #15", "wfe")
        }
    }
}
#[cfg(feature = "v020-production")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    smp::fatal(99)
}

#[cfg(not(feature = "v020-production"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    #[cfg(feature = "smp-selftest")]
    let Some(slot) = cyxia_arch_aarch64::cpu::registered_slot() else {
        halt()
    };
    #[cfg(feature = "unified-runtime")]
    {
        // Panic diagnostics never need the ordinary console/task/policy gate.
        // First writer keeps the original failure if a secondary also panics.
        if PANIC_EVIDENCE.words[0]
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let (elr, esr, far): (u64, u64, u64);
            unsafe {
                core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nostack, preserves_flags));
                core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nostack, preserves_flags));
                core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nostack, preserves_flags));
            }
            let (line, column, file) = info.location().map_or((0, 0, 0), |location| {
                let mut hash = 0xcbf29ce484222325u64;
                for byte in location.file().bytes() {
                    hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
                }
                (
                    u64::from(location.line()),
                    u64::from(location.column()),
                    hash,
                )
            });
            for (i, value) in [slot as u64, line, column, file, elr, esr, far]
                .into_iter()
                .enumerate()
            {
                PANIC_EVIDENCE.words[i + 1].store(value, Ordering::Relaxed);
            }
            PANIC_EVIDENCE.words[0].store(0x435950414e490001, Ordering::Release);
        }
    }
    #[cfg(not(feature = "unified-runtime"))]
    let _ = info;
    #[cfg(feature = "smp-selftest")]
    if slot != 0 {
        smp::fatal(99);
    }
    #[cfg(not(feature = "unified-runtime"))]
    log(b"FAIL panic\n");
    halt()
}
