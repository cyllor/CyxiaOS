//! One bounded BSP user context. This is a mechanism, not a process scheduler.
#[path = "context.rs"]
mod context;
pub use context::{
    Access, Context, Error, FaultReason, PreemptReason, Syscall, UserAbi, UserExit, UserFault,
    X86SignalState,
};
#[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
#[path = "user_runtime.rs"]
mod runtime;
#[cfg(all(feature = "runtime", target_arch = "x86_64", target_os = "none"))]
pub use runtime::{capture, cpu_slot, init_runtime_cpu, read_msr, resume, write_msr};
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
core::arch::global_asm!(include_str!("user.S"), options(att_syntax));
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub unsafe fn enter(entry: u64, stack: u64) -> u64 {
    assert!((4096..0x0000_8000_0000_0000).contains(&entry));
    assert!((4096..0x0000_8000_0000_0000).contains(&stack) && stack.is_multiple_of(16));
    unsafe { x86_enter_user(entry, stack) }
}
