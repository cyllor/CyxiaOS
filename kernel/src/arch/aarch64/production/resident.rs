//! Resident startup diagnostics for the AArch64 default image.
//!
//! Ordinary EL0 admission needs deployment startup authority, a verified
//! durable BootEpoch, and the remaining startup checks. The source tree
//! lacks the deployment inputs, so only the trusted diagnostic loop runs
//! here in SECURE_DEGRADED.

use super::{
    BootInfo, FAILURES, IRQS, ONLINE, Ordering, STOPPED, TIMER_IRQ, bring_up_production, cpu, gic,
    report_payload, timer,
};
use crate::{ExceptionFrame, UART, machine::enqueue_resident_frame};
use cyxia_contracts::{PhysAddr, UartResource};
use cyxia_driver_pl011::Pl011;
use cyxia_kernel_core::console::OutputQueue;

const STATUS: &[u8] = b"status";
const DISCARD_LINE: usize = STATUS.len() + 1;
const RX_BYTES_PER_TURN: usize = 16;

pub(super) fn timer_deadline() -> u64 {
    timer::ticks().saturating_add((timer::frequency() / 1_000).max(1))
}

pub(crate) fn exception(frame: &mut ExceptionFrame, kind: u64) {
    super::exception(frame, kind);
}

// CPU0 owns UART RX/TX after startup. The timer IRQ only rearms the timer
// and increments its counter. Foreground consumes at most one command per turn.
fn poll_console(
    uart: &mut Pl011,
    pending: &mut OutputQueue<128>,
    command: &mut usize,
    interrupts: u64,
) {
    pending.drain(uart, 128).expect("bounded PL011 transmit");
    if pending.pending() != 0 {
        return;
    }
    for _ in 0..RX_BYTES_PER_TURN {
        match uart.try_read() {
            Ok(Some(b'\n' | b'\r')) => {
                let matched = *command == STATUS.len();
                *command = 0;
                if matched {
                    let online = ONLINE.load(Ordering::Acquire);
                    let stopped = STOPPED.load(Ordering::Acquire);
                    let unavailable =
                        FAILURES
                            .iter()
                            .enumerate()
                            .fold(stopped, |mask, (slot, error)| {
                                mask | (u64::from(error.load(Ordering::Acquire) != 0) << slot)
                            });
                    let mut text = [0; 96];
                    let payload = report_payload(
                        &mut text,
                        "V020_RESIDENT_STATUS",
                        online,
                        unavailable,
                        interrupts,
                    );
                    enqueue_resident_frame(pending, payload).expect("resident status frame");
                    return;
                }
            }
            Ok(Some(byte)) if STATUS.get(*command) == Some(&byte) => *command += 1,
            Ok(Some(_)) | Err(_) => *command = DISCARD_LINE,
            Ok(None) => return,
        }
    }
}

pub(crate) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    bring_up_production(info);
    let resource = UartResource {
        base: PhysAddr(UART.load(Ordering::Relaxed)),
        len: info.uart.expect("boot console").len,
    };
    // SAFETY: boot configured this mapped console. This handle leaves the
    // configuration untouched, and this CPU exclusively owns diagnostic I/O.
    let mut uart = unsafe { Pl011::attach(resource) }.expect("resident console");
    let mut pending = OutputQueue::new();
    enqueue_resident_frame(
        &mut pending,
        b"V020_STARTUP state=SECURE_DEGRADED reason=missing_startup_authority command=status\n",
    )
    .expect("resident startup frame");
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");
    // SAFETY: fixed GIC and exception vectors are installed. The EL1 IRQ
    // handler rearms this timer even if the interrupt arrives before WFI.
    unsafe {
        timer::arm(timer_deadline());
        timer::enable_irqs();
    }
    let mut command = 0;
    let mut last_interrupt = 0;
    loop {
        let interrupts = IRQS[0].load(Ordering::Acquire);
        if interrupts != last_interrupt {
            last_interrupt = interrupts;
            poll_console(&mut uart, &mut pending, &mut command, interrupts);
        }
        timer::idle();
    }
}
