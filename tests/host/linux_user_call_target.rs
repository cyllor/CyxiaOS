//! Cross-compile guard for the real Linux-personality syscall instruction.
#![no_std]
#[path = "../../ports/cosmic/smithay-wayland/linux_syscall.rs"]
mod linux_syscall;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cyxia_linux_call_guard(number: u64, a: u64, b: u64) -> i64 {
    unsafe { linux_syscall::syscall6(number, [a, b, 3, 4, 5, 6]) }
}
