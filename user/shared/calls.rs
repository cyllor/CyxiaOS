//! Cyxia native user-call ABI, independent of a kernel trap-frame layout.
//!
//! ARM: SVC immediate is NUMBER, x0..x4 carry arguments, x8 the operation;
//! x0..x3 carry results. x86: int 0x80, rax is NUMBER, rdi/rsi/rdx/r10/r8
//! carry arguments, r9 the operation; rdi/rsi/rdx/r10 carry results and rax
//! retains NUMBER. This is not the Linux syscall ABI.
#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
pub const ELF_MACHINE: u16 = 183;
#[cfg(target_arch = "x86_64")]
pub const ELF_MACHINE: u16 = 62;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("unsupported Cyxia user-call architecture");

/// # Safety
/// Run only in an admitted Cyxia user context whose kernel implements NUMBER.
/// All pointer arguments must satisfy that call's memory and lifetime contract.
#[inline(always)]
pub unsafe fn call<const NUMBER: u16>(args: [u64; 5], operation: u64) -> [u64; 4] {
    let [mut a, mut b, mut c, mut d, e] = args;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "svc #{number}", number = const NUMBER,
            inlateout("x0") a, inlateout("x1") b,
            inlateout("x2") c, inlateout("x3") d,
            inlateout("x4") e => _, inlateout("x8") operation => _,
            clobber_abi("C"), options(nostack)
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "int 0x80", inlateout("rax") u64::from(NUMBER) => _,
            inlateout("rdi") a, inlateout("rsi") b,
            inlateout("rdx") c, inlateout("r10") d,
            inlateout("r8") e => _, inlateout("r9") operation => _,
            clobber_abi("C"), options(nostack)
        );
    }
    [a, b, c, d]
}

/// Publish shared volatile data before its sequence number becomes visible.
#[inline(always)]
pub fn release_shared() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}

/// A real synchronous fault, used after an externally committed service probe.
/// # Safety
/// The caller accepts retirement of the current isolated user context.
#[inline(always)]
pub unsafe fn fault() -> ! {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("brk #0", options(noreturn, nostack)); }
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("ud2", options(noreturn, nostack)); }
}
