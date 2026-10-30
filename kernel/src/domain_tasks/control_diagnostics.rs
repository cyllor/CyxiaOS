//! First *consumed* physical-control budget failure, independent of the role.
//! Call only under the task-owner gate, after the scheduler's authoritative
//! settlement and before publishing its quarantine summary. Diagnostic data
//! cannot authorize execution, alter credit, or acknowledge an obligation.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::domains::{
    Error, WINDOW_NS,
    tasks::{CONTROL_BUDGET_NS, CPU_BUDGET_NS, ControlCredit},
};

pub(super) const MAGIC: u64 = 0x4359_4353_4554_0001;
#[repr(C, align(64))]
pub(super) struct Evidence([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
pub(super) static CONTROL_SETTLEMENT_EVIDENCE: Evidence = Evidence::new();
const _: () = assert!(core::mem::size_of::<Evidence>() == 512);

impl Evidence {
    pub(super) const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 64])
    }
    pub(super) fn settled(
        &self,
        credit: ControlCredit,
        actual_ns: u64,
        finished_ns: u64,
        result: Result<(), Error>,
        still_active: bool,
    ) {
        if result != Err(Error::Budget) || still_active {
            return;
        }
        let offset = match credit.cpu {
            1 => 2,
            2 => 26,
            _ => return, // begin_control admits only C workers on CPUs 1/2.
        };
        if self.0[offset].load(Ordering::Relaxed) == 0 {
            // A stopped reader may see state=1. It must not call that a
            // complete receipt; failure remains visible and cannot pass.
            self.0[offset].store(1, Ordering::Release);
            let control = credit
                .control_total_ns
                .saturating_sub(credit.reserved_ns)
                .saturating_add(actual_ns);
            let physical = credit
                .physical_total_ns
                .saturating_sub(credit.reserved_ns)
                .saturating_add(actual_ns);
            let end = credit.window.saturating_add(1).saturating_mul(WINDOW_NS);
            let flags = u64::from(actual_ns > credit.reserved_ns)
                | (u64::from(finished_ns > end) << 1)
                | (u64::from(control > CONTROL_BUDGET_NS) << 2)
                | (u64::from(physical > CPU_BUDGET_NS) << 3);
            for (i, value) in [
                u64::from(credit.cpu),
                credit.sequence,
                credit.core_generation,
                credit.window,
                credit.started_ns,
                finished_ns,
                credit.reserved_ns,
                actual_ns,
                credit.control_total_ns,
                control,
                credit.physical_total_ns,
                physical,
                flags,
                Error::Budget as u64 + 1,
            ]
            .into_iter()
            .enumerate()
            {
                self.0[offset + 1 + i].store(value, Ordering::Relaxed);
            }
            self.0[offset].store(2, Ordering::Release);
        }
        // The external task gate serializes all writers; no RMW retry or
        // allocation is needed. Subsequent failures never overwrite the first.
        let count = self.0[1].load(Ordering::Relaxed).saturating_add(1);
        self.0[1].store(count, Ordering::Relaxed);
        self.0[0].store(MAGIC, Ordering::Release);
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> [u64; 64] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
