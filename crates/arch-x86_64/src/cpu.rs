pub fn halt() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("cli", options(nostack));
    }
}
/// # Safety
/// A valid IDT and interrupt controller must be installed, with all unhandled
/// sources masked and interrupt-accessed state published.
pub unsafe fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti", options(nostack));
    }
}
/// Sleep with interrupts already enabled. A caller waiting for a predicate
/// should use `enable_and_wait` after checking it with interrupts disabled.
pub fn wait() {
    unsafe {
        core::arch::asm!("hlt", options(nostack));
    }
}
/// # Safety
/// Same preconditions as `enable_interrupts`; executes STI/HLT as one sequence
/// to close the interrupt-arrival race after a disabled predicate check.
pub unsafe fn enable_and_wait() {
    unsafe {
        core::arch::asm!("sti", "hlt", options(nostack));
    }
}
pub fn read_cr2() -> u64 {
    let value;
    unsafe {
        core::arch::asm!("mov {}, cr2", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
pub fn read_cr0() -> u64 {
    let value;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
pub fn read_cr3() -> u64 {
    let value;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}
