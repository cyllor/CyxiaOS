.section .text.cyxia_sha256,"ax"
.arch armv8-a+crypto
.global cyxia_sha256_compress_hw
.type cyxia_sha256_compress_hw, %function
cyxia_sha256_compress_hw:
 // This is an explicit, bounded EL1 crypto transition. The caller remains
 // soft-float; every user-observable SIMD/FP bit is restored before return.
 sub sp, sp, #560
 stp x29, x30, [sp, #0]
 mrs x9, daif
 str x9, [sp, #552]
 msr daifset, #15
 mrs x9, cpacr_el1
 str x9, [sp, #544]
 orr x10, x9, #0x300000
 msr cpacr_el1, x10
 isb
 mrs x9, fpcr
 str x9, [sp, #528]
 mrs x9, fpsr
 str x9, [sp, #536]
 stp q0, q1, [sp, #16]
 stp q2, q3, [sp, #48]
 stp q4, q5, [sp, #80]
 stp q6, q7, [sp, #112]
 stp q8, q9, [sp, #144]
 stp q10, q11, [sp, #176]
 stp q12, q13, [sp, #208]
 stp q14, q15, [sp, #240]
 stp q16, q17, [sp, #272]
 stp q18, q19, [sp, #304]
 stp q20, q21, [sp, #336]
 stp q22, q23, [sp, #368]
 stp q24, q25, [sp, #400]
 stp q26, q27, [sp, #432]
 stp q28, q29, [sp, #464]
 stp q30, q31, [sp, #496]
 bl cyxia_sha256_compress_inner
 ldp q0, q1, [sp, #16]
 ldp q2, q3, [sp, #48]
 ldp q4, q5, [sp, #80]
 ldp q6, q7, [sp, #112]
 ldp q8, q9, [sp, #144]
 ldp q10, q11, [sp, #176]
 ldp q12, q13, [sp, #208]
 ldp q14, q15, [sp, #240]
 ldp q16, q17, [sp, #272]
 ldp q18, q19, [sp, #304]
 ldp q20, q21, [sp, #336]
 ldp q22, q23, [sp, #368]
 ldp q24, q25, [sp, #400]
 ldp q26, q27, [sp, #432]
 ldp q28, q29, [sp, #464]
 ldp q30, q31, [sp, #496]
 ldr x9, [sp, #528]
 msr fpcr, x9
 ldr x9, [sp, #536]
 msr fpsr, x9
 ldr x9, [sp, #544]
 msr cpacr_el1, x9
 isb
 ldr x9, [sp, #552]
 msr daif, x9
 ldp x29, x30, [sp, #0]
 add sp, sp, #560
 ret
.size cyxia_sha256_compress_hw, .-cyxia_sha256_compress_hw
