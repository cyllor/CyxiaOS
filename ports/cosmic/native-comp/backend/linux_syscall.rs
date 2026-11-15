//! Real Linux-personality register boundary for musl desktop programs.
//! Logical Linux/custom syscall numbers are supplied by the caller; this module
//! never reinterprets an ARM exception frame as an x86 frame.
#![allow(dead_code)]

/// # Safety
/// The caller owns all pointer ranges for the duration of the synchronous call.
pub unsafe fn syscall6(number: u64, args: [u64; 6]) -> i64 {
    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    {
        let mut result = args[0];
        unsafe {
            core::arch::asm!(
                "svc #0", inlateout("x0") result,
                in("x1") args[1], in("x2") args[2], in("x3") args[3],
                in("x4") args[4], in("x5") args[5], in("x8") number,
                options(nostack),
            );
        }
        result as i64
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    {
        let mut result = number;
        unsafe {
            core::arch::asm!(
                "syscall", inlateout("rax") result,
                in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
                in("r10") args[3], in("r8") args[4], in("r9") args[5],
                lateout("rcx") _, lateout("r11") _, options(nostack),
            );
        }
        result as i64
    }
    #[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "linux", target_env = "musl")))]
    {
        let _ = (number, args);
        -38
    }
}
