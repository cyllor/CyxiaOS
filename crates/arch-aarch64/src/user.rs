//! Per-CPU EL0 transitions. All memory management and policy belongs to the caller.
//!
//! Ordinary EL0 contexts own the complete Advanced SIMD/FP register bank while
//! entered. Audited integer-only fault probes instead execute immutable code with
//! no FP/SIMD opcodes and never touch that bank or its feature controls. Kernel
//! Rust, exception handlers and every routine they call must use the soft-float
//! ABI and must not access FP/SIMD registers. Only `user.S` may touch them. This
//! permits the lower-EL dispatcher to capture integer registers before the return
//! assembly conditionally saves FP/SIMD, without corrupting process values.
//!
//! Reference: Arm Cortex-A53 TRM, CPACR_EL1 and AArch64 thread registers:
//! <https://documentation-service.arm.com/static/6040c321ee937942ba301626>.
//! FPEN must be 0b11 to allow EL0 FP/SIMD; there is no mode allowing EL0 while
//! trapping only EL1. SVE/SME state is deliberately unsupported and must stay trapped.
use core::arch::asm;
use core::sync::atomic::{AtomicPtr, Ordering};
core::arch::global_asm!(include_str!("user.S"));
#[repr(C, align(16))]
#[derive(Default)]
pub struct Context {
    pub regs: [u64; 31],
    pub pc: u64,
    pub status: u64,
    pub sp: u64,
    pub esr: u64,
    pub far: u64,
    pub kind: u64,
    pub tpidr_el0: u64,
    /// All 128 bits of Q0-Q31, including the halves not preserved by the C ABI.
    pub simd: [[u64; 2]; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}
impl Context {
    /// Fresh process state, including all otherwise user-observable FP/TLS bits.
    pub const fn empty() -> Self {
        Self {
            regs: [0; 31],
            pc: 0,
            status: 0,
            sp: 0,
            esr: 0,
            far: 0,
            kind: 0,
            tpidr_el0: 0,
            simd: [[0; 2]; 32],
            fpcr: 0,
            fpsr: 0,
        }
    }
}
// These are an ABI with user.S. Keep every assembly-accessed field checked rather
// than relying on the total size alone; fresh Default contexts initialize all
// user-observable FP and TLS state to zero before the first execution.
const _: () = {
    assert!(core::mem::offset_of!(Context, regs) == 0);
    assert!(core::mem::offset_of!(Context, pc) == 248);
    assert!(core::mem::offset_of!(Context, status) == 256);
    assert!(core::mem::offset_of!(Context, sp) == 264);
    assert!(core::mem::offset_of!(Context, esr) == 272);
    assert!(core::mem::offset_of!(Context, far) == 280);
    assert!(core::mem::offset_of!(Context, kind) == 288);
    assert!(core::mem::offset_of!(Context, tpidr_el0) == 296);
    assert!(core::mem::offset_of!(Context, simd) == 304);
    assert!(core::mem::offset_of!(Context, fpcr) == 816);
    assert!(core::mem::offset_of!(Context, fpsr) == 824);
    assert!(core::mem::size_of::<Context>() == 832);
    assert!(core::mem::align_of::<Context>() == 16);
};
static ACTIVE: [AtomicPtr<Context>; super::cpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; super::cpu::MAX_CPUS];
static INTEGER_ONLY: [core::sync::atomic::AtomicBool; super::cpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; super::cpu::MAX_CPUS];
unsafe extern "C" {
    fn cyxia_enter_user(context: *mut Context, restore_fp: u64);
    fn cyxia_user_return();
}
/// # Safety
/// A registered CPU with a private pinned EL1 stack, no nested entry. Context and EL1 stack remain pinned until return. The
/// supplied TTBR0 must map only this process's validated user pages. IRQs must work.
/// All EL1 code, including interrupt handlers and memory intrinsics, must be built
/// for the soft-float ABI with no FP/SIMD instructions outside user.S. Higher ELs
/// must allow basic Advanced SIMD/FP. The transition traps SVE/SME while the user
/// runs because their additional register state is not saved. A context must be
/// initialized or reset before reuse by a different process so its full
/// integer, FP/SIMD and TLS state belongs exclusively to the entered process.
unsafe fn enter_inner(context: &mut Context, root: u64, restore_fp: bool) {
    let saved_daif: u64;
    // Do not expose a half-installed ACTIVE/TTBR0 pair to an IRQ.
    unsafe {
        asm!("mrs {}, daif", "msr daifset, #15", out(reg) saved_daif, options(nostack));
    }
    let slot = super::cpu::slot();
    let active = &ACTIVE[slot];
    assert!(active.load(Ordering::Relaxed).is_null());
    context.status &= 0xf0000000; // NZCV only; always EL0t, IRQ enabled, no privileged PSTATE.
    INTEGER_ONLY[slot].store(!restore_fp, Ordering::Relaxed);
    active.store(core::ptr::from_mut(context), Ordering::Relaxed);
    unsafe {
        asm!("dsb ishst","msr ttbr0_el1, {root}","mrs x9, tcr_el1","bic x9, x9, #0x80","msr tcr_el1, x9","isb","tlbi vmalle1is","dsb ish","isb",root=in(reg)root,out("x9")_);
        cyxia_enter_user(core::ptr::from_mut(context), u64::from(restore_fp));
        // user.S has disabled low walks, completed TLBI, saved all enabled user
        // state, and restored the original EL1 CPACR/TLS before returning.
    }
    active.store(core::ptr::null_mut(), Ordering::Relaxed);
    INTEGER_ONLY[slot].store(false, Ordering::Relaxed);
    unsafe {
        asm!("msr daif, {}", in(reg) saved_daif, options(nostack, preserves_flags));
    }
}
/// Enter a complete user context, including its private Advanced SIMD/FP bank.
///
/// # Safety
/// The caller must provide a pinned private context and validated address-space
/// root, on a registered CPU with no nested entry.
pub unsafe fn enter(context: &mut Context, root: u64) {
    unsafe { enter_inner(context, root, true) };
}
/// Enter a protection probe that must fault before executing any FP/SIMD
/// instruction. Its verified immutable code contains no such opcode. The
/// transition leaves both feature controls and the initialized FP/SIMD bank
/// untouched, avoiding architectural access to another context's state.
///
/// # Safety
/// In addition to [`enter`]'s contract, the entered code must be an audited
/// integer-only fault probe whose executable range was checked for FP/SIMD.
pub unsafe fn enter_integer_probe(context: &mut Context, root: u64) {
    unsafe { enter_inner(context, root, false) };
}
/// # Safety
/// Called only from a synchronous/IRQ AArch64 lower-EL vector, while enter() is
/// suspended. No Rust reference into the context is live in the user program.
/// Neither this function nor the exception/IRQ path may use FP/SIMD or modify
/// TPIDR_EL0. Enabled live hardware values are saved by user.S after capture returns;
/// integer-only probes do not execute FP/SIMD and leave their context bank untouched.
pub unsafe fn capture(
    regs: &[u64; 31],
    pc: u64,
    status: u64,
    esr: u64,
    far: u64,
    kind: u64,
) -> Option<u64> {
    let slot = super::cpu::slot();
    let p = ACTIVE[slot].load(Ordering::Relaxed);
    if p.is_null() || status & 15 != 0 {
        return None;
    }
    let sp: u64;
    unsafe {
        let context = &mut *p;
        if !INTEGER_ONLY[slot].load(Ordering::Relaxed) {
            asm!("mrs {}, sp_el0",out(reg)sp);
            context.regs.copy_from_slice(regs);
            context.sp = sp;
        }
        context.pc = pc;
        context.status = status;
        context.esr = esr;
        context.far = far;
        context.kind = kind;
    }
    Some(cyxia_user_return as *const () as u64)
}
