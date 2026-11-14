//! One bounded BSP user context. This is a mechanism, not a process scheduler.
core::arch::global_asm!(include_str!("user.S"), options(att_syntax));
unsafe extern "C" {
    fn x86_enter_user(entry: u64, stack: u64) -> u64;
    pub fn x86_user_probe();
    pub fn x86_user_fault_probe();
}

/// Enter a prevalidated CPL3 mapping and return when the trusted trap handler
/// requests termination. User IOPL is zero and the TSS denies all port I/O.
///
/// # Safety
/// BSP-only and non-reentrant; interrupts disabled on entry. GDT/TSS/IDT must
/// have been initialized. `entry` must be in the admitted user RX mapping and
/// `stack` must be the aligned top of its distinct user RW/NX stack. The caller
/// must validate every user trap and never trust user-supplied kernel pointers.
pub unsafe fn enter(entry: u64, stack: u64) -> u64 {
    assert!((4096..0x0000_8000_0000_0000).contains(&entry));
    assert!((4096..0x0000_8000_0000_0000).contains(&stack) && stack.is_multiple_of(16));
    unsafe { x86_enter_user(entry, stack) }
}
