//! Arm generic physical timer. Caller owns the EL1 physical timer and IRQ.
use core::arch::asm;
pub fn frequency() -> u64 {
    let x;
    unsafe { asm!("mrs {}, cntfrq_el0",out(reg)x) }
    x
}
pub fn ticks() -> u64 {
    let x;
    unsafe { asm!("isb","mrs {}, cntpct_el0",out(reg)x) }
    x
}
/// # Safety
/// Caller owns the physical timer interrupt and has installed its handler.
pub unsafe fn arm(deadline: u64) {
    unsafe {
        asm!("msr cntp_cval_el0, {}","mov x9, #1","msr cntp_ctl_el0, x9","isb",in(reg)deadline,out("x9")_)
    }
}
/// # Safety
/// Exception vectors and device state must be ready for IRQ entry.
pub unsafe fn enable_irqs() {
    unsafe { asm!("msr daifclr, #2", "isb") }
}
pub fn idle() {
    unsafe { asm!("wfi") }
}
