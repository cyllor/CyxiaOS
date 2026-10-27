.section .text.user_transition,"ax"
// The Rust target stays soft-float. Only this transition assembly uses FP/SIMD.
.arch armv8-a+fp+simd
.global cyxia_enter_user
.type cyxia_enter_user, %function
cyxia_enter_user:
 // Preserve the soft-float caller's state. EL0 cannot address this kernel stack.
 // Frame: x19-x30 [0,96), DAIF 96, Context* 104, CPACR 112, TPIDR_EL0 120,
 // restore-FP flag 128. x1 is zero only for an integer-only fault probe.
 sub sp, sp, #144
 stp x19, x20, [sp, #0]
 stp x21, x22, [sp, #16]
 stp x23, x24, [sp, #32]
 stp x25, x26, [sp, #48]
 stp x27, x28, [sp, #64]
 stp x29, x30, [sp, #80]
 mrs x9, daif
 str x9, [sp, #96]
 msr daifset, #15
 mov x30, x0
 str x30, [sp, #104]
 str x1, [sp, #128]
 cbz x1, .Luser_features_configured
 mrs x9, cpacr_el1
 str x9, [sp, #112]
 // Enable FP at EL0 and EL1 only for full restoration. The immutable integer
 // probe has no FP/SIMD opcodes and leaves feature controls completely untouched.
 bic x9, x9, #0x30000
 bic x9, x9, #0x3000000
 orr x9, x9, #0x300000
 msr cpacr_el1, x9
 isb
.Luser_features_configured:
 cbz x1, .Luser_integer_restore
 mrs x9, tpidr_el0
 str x9, [sp, #120]
 ldr x9, [x30, #296]
 msr tpidr_el0, x9
 ldr x9, [x30, #816]
 msr fpcr, x9
 ldr x9, [x30, #824]
 msr fpsr, x9
 // Eagerly restore every lane: fresh contexts cannot observe a previous user's FP.
 add x9, x30, #304
 ldp q0, q1, [x9, #0]
 ldp q2, q3, [x9, #32]
 ldp q4, q5, [x9, #64]
 ldp q6, q7, [x9, #96]
 ldp q8, q9, [x9, #128]
 ldp q10, q11, [x9, #160]
 ldp q12, q13, [x9, #192]
 ldp q14, q15, [x9, #224]
 ldp q16, q17, [x9, #256]
 ldp q18, q19, [x9, #288]
 ldp q20, q21, [x9, #320]
 ldp q22, q23, [x9, #352]
 ldp q24, q25, [x9, #384]
 ldp q26, q27, [x9, #416]
 ldp q28, q29, [x9, #448]
 ldp q30, q31, [x9, #480]
.Luser_integer_restore:
 ldr x9, [x30, #248]
 msr elr_el1, x9
 ldr x9, [x30, #256]
 msr spsr_el1, x9
 ldr x9, [x30, #264]
 msr sp_el0, x9
 ldp x0, x1, [x30, #0]
 ldp x2, x3, [x30, #16]
 ldp x4, x5, [x30, #32]
 ldp x6, x7, [x30, #48]
 ldp x8, x9, [x30, #64]
 ldp x10, x11, [x30, #80]
 ldp x12, x13, [x30, #96]
 ldp x14, x15, [x30, #112]
 ldp x16, x17, [x30, #128]
 ldp x18, x19, [x30, #144]
 ldp x20, x21, [x30, #160]
 ldp x22, x23, [x30, #176]
 ldp x24, x25, [x30, #192]
 ldp x26, x27, [x30, #208]
 ldp x28, x29, [x30, #224]
 ldr x30, [x30, #240]
 eret
.size cyxia_enter_user, .-cyxia_enter_user
.global cyxia_user_return
.type cyxia_user_return, %function
cyxia_user_return:
 // Exception dispatcher has selected EL1h with interrupts masked.
 msr daifset, #15
 ldr x10, [sp, #128]
 // Revoke low-address translations before saving state or allowing reclamation.
 mrs x9, tcr_el1
 orr x9, x9, #0x80
 msr tcr_el1, x9
 isb
 // Integer fault probes use a boot-unique ASID over one immutable root. The
 // ordinary path still invalidates globally before any pages can be reclaimed.
 cbz x10, .Luser_low_walks_revoked
 tlbi vmalle1is
 dsb ish
 isb
.Luser_low_walks_revoked:
 // Its integer-only Rust/IRQ path has left the complete user FP/TLS bank intact.
 ldr x30, [sp, #104]
 cbz x10, .Luser_integer_save
 add x9, x30, #304
 stp q0, q1, [x9, #0]
 stp q2, q3, [x9, #32]
 stp q4, q5, [x9, #64]
 stp q6, q7, [x9, #96]
 stp q8, q9, [x9, #128]
 stp q10, q11, [x9, #160]
 stp q12, q13, [x9, #192]
 stp q14, q15, [x9, #224]
 stp q16, q17, [x9, #256]
 stp q18, q19, [x9, #288]
 stp q20, q21, [x9, #320]
 stp q22, q23, [x9, #352]
 stp q24, q25, [x9, #384]
 stp q26, q27, [x9, #416]
 stp q28, q29, [x9, #448]
 stp q30, q31, [x9, #480]
 mrs x9, fpcr
 str x9, [x30, #816]
 mrs x9, fpsr
 str x9, [x30, #824]
.Luser_integer_save:
 cbz x10, .Luser_state_restored
 mrs x9, tpidr_el0
 str x9, [x30, #296]
 // Restore the original EL1 TLS and feature controls before returning to Rust.
 ldr x9, [sp, #120]
 msr tpidr_el0, x9
 cbz x10, .Luser_features_restored
 ldr x9, [sp, #112]
 msr cpacr_el1, x9
 isb
.Luser_features_restored:
.Luser_state_restored:
 ldp x19, x20, [sp, #0]
 ldp x21, x22, [sp, #16]
 ldp x23, x24, [sp, #32]
 ldp x25, x26, [sp, #48]
 ldp x27, x28, [sp, #64]
 ldp x29, x30, [sp, #80]
 ldr x9, [sp, #96]
 add sp, sp, #144
 msr daif, x9
 ret
.size cyxia_user_return, .-cyxia_user_return
