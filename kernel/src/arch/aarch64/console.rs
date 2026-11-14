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
    }
    .unwrap();
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
pub(crate) fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("msr daifset, #15", "wfe") }
    }
}
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
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
            for (i, value) in [
                cyxia_arch_aarch64::cpu::slot() as u64,
                line,
                column,
                file,
                elr,
                esr,
                far,
            ]
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
    if cyxia_arch_aarch64::cpu::slot() != 0 {
        smp::fatal(99);
    }
    #[cfg(not(feature = "unified-runtime"))]
    log(b"FAIL panic\n");
    halt()
}
