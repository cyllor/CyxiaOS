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
use cyxia_kernel_core::{
    console::OutputQueue,
    control_plane::{
        Error,
        role_budget_v0199::{Class, Cpu0BudgetLedger, Settlement},
    },
};

const STATUS: &[u8] = b"status";
const DISCARD_LINE: usize = STATUS.len() + 1;
const RX_BYTES_PER_TURN: usize = 16;
const TX_BYTES_PER_TURN: usize = 64;
const CONSOLE_TURN_NS: u64 = 1_000_000;
const DEGRADED_POLL_INTERVAL: u64 = 4;

struct ConsoleBudget {
    ledger: Cpu0BudgetLedger,
    frequency: u64,
}

impl ConsoleBudget {
    fn now_ns(&self) -> Result<u64, Error> {
        u64::try_from(u128::from(timer::ticks()) * 1_000_000_000 / u128::from(self.frequency))
            .map_err(|_| Error::Clock)
    }

    fn turn(&mut self, degraded: bool, work: impl FnOnce()) -> Result<Option<Settlement>, Error> {
        let cpu = cpu::slot();
        let start = self.now_ns()?;
        let reservation = if degraded {
            self.ledger
                .reserve_readonly_diagnostic(cpu, CONSOLE_TURN_NS, start)
        } else {
            self.ledger
                .reserve_kernel(cpu, Class::Coordination, CONSOLE_TURN_NS, start)
        };
        let grant = match reservation {
            Err(Error::Exhausted) => return Ok(None),
            result => result?,
        };
        work();
        let end = self.now_ns()?;
        // The generic counter provides a conservative elapsed-time debit
        // for a foreground console turn, with one tick of rounding margin.
        // Timer IRQ handling and WFI outside the turn are outside this scope.
        let bound = end
            .checked_sub(start)
            .and_then(|delta| delta.checked_add(1_000_000_000u64.div_ceil(self.frequency)))
            .ok_or(Error::Clock)?;
        self.ledger.settle(cpu, grant, bound, end).map(Some)
    }
}

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
    pending
        .drain(uart, TX_BYTES_PER_TURN)
        .expect("bounded PL011 transmit");
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
    let frequency = timer::frequency();
    assert_ne!(frequency, 0);
    let mut budget = ConsoleBudget {
        ledger: Cpu0BudgetLedger::new(),
        frequency,
    };
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
    let mut degraded = false;
    let mut notice = None;
    let mut accounting_fault = false;
    loop {
        let interrupts = IRQS[0].load(Ordering::Acquire);
        let interval = if degraded { DEGRADED_POLL_INTERVAL } else { 1 };
        if !accounting_fault && interrupts.wrapping_sub(last_interrupt) >= interval {
            last_interrupt = interrupts;
            let result = budget.turn(degraded, || {
                if pending.pending() == 0
                    && let Some(bound) = notice.take()
                {
                    let mut text = [0; 96];
                    let payload = report_payload(
                        &mut text,
                        "V020_RESIDENT_BUDGET_OVERRUN",
                        bound,
                        CONSOLE_TURN_NS,
                        interrupts,
                    );
                    enqueue_resident_frame(&mut pending, payload).expect("budget failure frame");
                }
                poll_console(&mut uart, &mut pending, &mut command, interrupts);
            });
            match result {
                Ok(Some(receipt)) if !degraded && receipt.overrun => {
                    degraded = true;
                    notice = Some(receipt.actual_ns);
                }
                Ok(_) => {}
                Err(_) => accounting_fault = true,
            }
        }
        timer::idle();
    }
}
