//! Arm generic physical timer plus the prototype's per-vCPU execution clock.
//!
//! `ticks()` is the shared monotonic time source used for deadlines, leases and
//! timer programming. `cpu_ticks()` is intentionally separate: the locked QEMU
//! platform exposes host-thread CPU time through PMCCNTR_EL0 and the unified
//! runtime uses it only to debit actual execution. Mixing the clocks would
//! charge time spent descheduled, or time spent running another vCPU, to the
//! current task.
use core::arch::asm;

/// Frequency of the generic physical timer used for monotonic time.
pub fn frequency() -> u64 {
    let value;
    unsafe {
        asm!(
            "mrs {value}, cntfrq_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Shared monotonic physical-timer ticks. This is not a per-vCPU CPU clock.
pub fn ticks() -> u64 {
    let value;
    unsafe {
        asm!(
            "isb",
            "mrs {value}, cntpct_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// The locked prototype platform exposes PMCCNTR as a 1 GHz per-vCPU counter.
pub const fn cpu_frequency() -> u64 {
    1_000_000_000
}

/// Read the current CPU's execution counter.
pub fn cpu_ticks() -> u64 {
    let value;
    unsafe {
        asm!(
            "isb",
            "mrs {value}, pmccntr_el0",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Convert a per-vCPU PMU delta into nanoseconds without using the wall clock.
pub fn cpu_ns(delta: u64) -> u64 {
    ((u128::from(delta) * 1_000_000_000) / u128::from(cpu_frequency())).min(u128::from(u64::MAX))
        as u64
}

/// Return actual execution time since `start` on the same vCPU.
pub fn cpu_elapsed_ns(start: u64) -> u64 {
    cpu_ns(cpu_ticks().saturating_sub(start))
}

/// Enable the 64-bit execution counter for this CPU.
///
/// # Safety
/// The caller must run once during EL1 bring-up on the CPU being initialized.
/// The locked prototype QEMU must provide the CyxiaOS per-vCPU PMU timing patch
/// and run each guest vCPU on its own host thread. Stock QEMU's global virtual
/// PMU clock is not a valid CPU-accounting source.
pub unsafe fn init_cpu_accounting() {
    const ALL_COUNTERS: u64 = u32::MAX as u64;
    const CYCLE_COUNTER: u64 = 1 << 31;

    let mut pmcr: u64;
    unsafe {
        asm!(
            "mrs {pmcr}, pmcr_el0",
            pmcr = out(reg) pmcr,
            options(nomem, nostack, preserves_flags),
        );
    }

    // E: enable counters, C: reset PMCCNTR, LC: use the 64-bit cycle counter.
    // D is cleared explicitly so a platform cannot silently divide by 64.
    pmcr = (pmcr | (1 << 0) | (1 << 2) | (1 << 6)) & !(1 << 3);
    unsafe {
        asm!(
            "msr pmuserenr_el0, xzr",
            "msr pmintenclr_el1, {all}",
            "msr pmcntenclr_el0, {all}",
            "msr pmovsclr_el0, {all}",
            "msr pmccfiltr_el0, xzr",
            "msr pmcr_el0, {pmcr}",
            "msr pmcntenset_el0, {cycle}",
            "isb",
            all = in(reg) ALL_COUNTERS,
            pmcr = in(reg) pmcr,
            cycle = in(reg) CYCLE_COUNTER,
            options(nostack, preserves_flags),
        );
    }
}

/// # Safety
/// Caller owns the physical timer interrupt and has installed its handler.
pub unsafe fn arm(deadline: u64) {
    unsafe {
        asm!(
            "msr cntp_cval_el0, {deadline}",
            "mov x9, #1",
            "msr cntp_ctl_el0, x9",
            "isb",
            deadline = in(reg) deadline,
            out("x9") _,
            options(nostack, preserves_flags),
        );
    }
}

/// # Safety
/// Exception vectors and device state must be ready for IRQ entry.
pub unsafe fn enable_irqs() {
    unsafe {
        asm!(
            "msr daifclr, #2",
            "isb",
            options(nomem, nostack, preserves_flags),
        );
    }
}

pub fn idle() {
    unsafe {
        asm!("wfi", options(nomem, nostack, preserves_flags));
    }
}
