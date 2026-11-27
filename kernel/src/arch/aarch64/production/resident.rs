//! Resident startup diagnostics for the AArch64 default image.
//!
//! Ordinary EL0 admission needs deployment startup authority, a verified
//! durable BootEpoch, and the remaining startup checks. When deployment
//! inputs were pinned at build time, this path authenticates the signed
//! envelope before running read-only SECURE_DEGRADED diagnostics.

#[cfg(not(feature = "v020-production-signed-resident"))]
use super::bring_up_production;
use super::{
    BootInfo, FAILURES, IRQS, ONLINE, Ordering, STOPPED, TIMER_IRQ, cpu, gic, report_payload, timer,
};
#[cfg(not(feature = "v020-production-signed-resident"))]
use crate::ExceptionFrame;
use crate::{UART, machine::enqueue_resident_frame};
use cyxia_contracts::{PhysAddr, UartResource};
use cyxia_driver_pl011::Pl011;
use cyxia_kernel_core::{
    console::OutputQueue,
    control_plane::{
        Error,
        role_budget_v0199::{Class, Cpu0BudgetLedger, Settlement, Turn},
    },
};

#[cfg(cyxia_startup_catalog)]
#[path = "startup_catalog.rs"]
mod startup_catalog;

const STATUS: &[u8] = b"status";
const DISCARD_LINE: usize = STATUS.len() + 1;
const RX_BYTES_PER_TURN: usize = 16;
const TX_BYTES_PER_TURN: usize = 64;
const CONSOLE_TURN_NS: u64 = 1_000_000;
const DEGRADED_POLL_INTERVAL: u64 = 4;
#[cfg(cyxia_startup_catalog)]
const CATALOG_RECOVERY_NS: u64 =
    cyxia_kernel_core::control_plane::role_budget_v0199::CLASS_LIMITS[Class::Recovery as usize];

struct ResidentBudget {
    ledger: Cpu0BudgetLedger,
    frequency: u64,
}

impl ResidentBudget {
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
        self.settle(start, grant).map(Some)
    }

    fn settle(&mut self, start: u64, grant: Turn) -> Result<Settlement, Error> {
        let end = self.now_ns()?;
        // The generic counter provides a conservative elapsed-time debit
        // for a foreground turn, with one tick of rounding margin.
        let bound = end
            .checked_sub(start)
            .and_then(|delta| delta.checked_add(1_000_000_000u64.div_ceil(self.frequency)))
            .ok_or(Error::Clock)?;
        self.ledger.settle(cpu::slot(), grant, bound, end)
    }

    #[cfg(cyxia_startup_catalog)]
    fn verify_startup_envelope(&mut self) -> Result<(bool, Settlement), Error> {
        let (started, grant) = loop {
            let now = self.now_ns()?;
            match self
                .ledger
                .reserve_kernel(cpu::slot(), Class::Recovery, CATALOG_RECOVERY_NS, now)
            {
                Ok(grant) => break (now, grant),
                Err(Error::Exhausted) => timer::idle(),
                Err(error) => return Err(error),
            }
        };
        let verified = startup_catalog::authenticate().is_ok();
        Ok((verified, self.settle(started, grant)?))
    }
}

pub(super) fn timer_deadline() -> u64 {
    timer::ticks().saturating_add((timer::frequency() / 1_000).max(1))
}

#[cfg(not(feature = "v020-production-signed-resident"))]
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

#[cfg(not(feature = "v020-production-signed-resident"))]
pub(crate) fn run(info: &BootInfo) -> ! {
    assert_eq!(cpu::slot(), 0);
    bring_up_production(info);
    serve(info, None, Cpu0BudgetLedger::new())
}

pub(super) fn serve(
    info: &BootInfo,
    _startup_override: Option<&'static [u8]>,
    ledger: Cpu0BudgetLedger,
) -> ! {
    serve_with_queue(info, _startup_override, ledger, OutputQueue::new(), None)
}

pub(super) fn attach_console(info: &BootInfo) -> Pl011 {
    let resource = UartResource {
        base: PhysAddr(UART.load(Ordering::Relaxed)),
        len: info.uart.expect("boot console").len,
    };
    // SAFETY: boot configured this mapped console. This handle leaves the
    // configuration untouched, and this CPU exclusively owns diagnostic I/O.
    unsafe { Pl011::attach(resource) }.expect("resident console")
}

pub(super) fn serve_with_queue(
    info: &BootInfo,
    _startup_override: Option<&'static [u8]>,
    ledger: Cpu0BudgetLedger,
    mut pending: OutputQueue<128>,
    mut fault: Option<(&'static str, [u64; 3])>,
) -> ! {
    let mut uart = attach_console(info);
    let frequency = timer::frequency();
    assert_ne!(frequency, 0);
    let mut budget = ResidentBudget { ledger, frequency };
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");
    // SAFETY: fixed GIC and exception vectors are installed. The EL1 IRQ
    // handler rearms this timer even if the interrupt arrives before WFI.
    unsafe {
        timer::arm(timer_deadline());
        timer::enable_irqs();
    }
    #[cfg(not(cyxia_startup_catalog))]
    let (startup_banner, budget_degraded): (&[u8], _) = (
        _startup_override.unwrap_or(
            b"V020_STARTUP state=SECURE_DEGRADED reason=missing_startup_authority command=status\n",
        ),
        budget.ledger.ordinary_closed(),
    );
    #[cfg(cyxia_startup_catalog)]
    let catalog_check = budget.verify_startup_envelope();
    #[cfg(cyxia_startup_catalog)]
    let (startup_banner, budget_degraded): (&[u8], _) = match &catalog_check {
        Ok((true, cost)) if !cost.overrun && !cost.crossed_window => (
            b"V020_STARTUP state=SECURE_DEGRADED reason=catalog_verified_pending command=status\n",
            false,
        ),
        Ok((false, cost)) if !cost.overrun && !cost.crossed_window => (
            b"V020_STARTUP state=SECURE_DEGRADED reason=catalog_rejected command=status\n",
            false,
        ),
        _ => (
            b"V020_STARTUP state=SECURE_DEGRADED reason=catalog_budget command=status\n",
            true,
        ),
    };
    #[cfg(cyxia_startup_catalog)]
    let mut catalog_cost = catalog_check.ok().map(|(_, cost)| cost);
    let mut startup = Some(startup_banner);
    let mut command = 0;
    let mut last_interrupt = 0;
    let mut degraded = budget_degraded;
    let mut notice = None;
    let mut accounting_fault = false;
    loop {
        let interrupts = IRQS[0].load(Ordering::Acquire);
        let interval = if degraded { DEGRADED_POLL_INTERVAL } else { 1 };
        if !accounting_fault && interrupts.wrapping_sub(last_interrupt) >= interval {
            last_interrupt = interrupts;
            let result = budget.turn(degraded, || {
                if pending.pending() == 0 {
                    if let Some((label, [a, b, c])) = fault.take() {
                        let mut text = [0; 96];
                        let payload = report_payload(&mut text, label, a, b, c);
                        enqueue_resident_frame(&mut pending, payload)
                            .expect("resident fault frame");
                    } else if let Some(payload) = startup.take() {
                        enqueue_resident_frame(&mut pending, payload)
                            .expect("resident startup frame");
                    }
                }
                #[cfg(cyxia_startup_catalog)]
                if pending.pending() == 0
                    && let Some(cost) = catalog_cost.take()
                {
                    let mut text = [0; 96];
                    let flags = u64::from(cost.overrun) | (u64::from(cost.crossed_window) << 1);
                    let payload = report_payload(
                        &mut text,
                        "V020_STARTUP_CATALOG_COST",
                        cost.actual_ns,
                        CATALOG_RECOVERY_NS,
                        flags,
                    );
                    enqueue_resident_frame(&mut pending, payload)
                        .expect("startup catalog budget frame");
                }
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
