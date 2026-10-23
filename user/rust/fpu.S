.section .text.fp_probe,"ax"
.arch armv8-a+fp+simd
.global cyxia_fp_probe
cyxia_fp_probe:
 sub sp, sp, #576
 str x19, [sp, #512]
 str x20, [sp, #520]
 str x21, [sp, #528]
 str x30, [sp, #536]
 mov x19, x0
 mrs x9, tpidr_el0
 cbnz x9, .Lfp_fail
 mrs x9, fpcr
 cbnz x9, .Lfp_fail
 mrs x9, fpsr
 cbnz x9, .Lfp_fail
 stp q0, q1, [sp, #0]
 stp q2, q3, [sp, #32]
 stp q4, q5, [sp, #64]
 stp q6, q7, [sp, #96]
 stp q8, q9, [sp, #128]
 stp q10, q11, [sp, #160]
 stp q12, q13, [sp, #192]
 stp q14, q15, [sp, #224]
 stp q16, q17, [sp, #256]
 stp q18, q19, [sp, #288]
 stp q20, q21, [sp, #320]
 stp q22, q23, [sp, #352]
 stp q24, q25, [sp, #384]
 stp q26, q27, [sp, #416]
 stp q28, q29, [sp, #448]
 stp q30, q31, [sp, #480]
 mov x9, #0
.Lfp_zero:
 ldr x10, [sp, x9]
 cbnz x10, .Lfp_fail
 add x9,x9,#8
 cmp x9,#512
 b.ne .Lfp_zero
 add x9,x19,#0
 dup v0.2d,x9
 add x9,x19,#1
 dup v1.2d,x9
 add x9,x19,#2
 dup v2.2d,x9
 add x9,x19,#3
 dup v3.2d,x9
 add x9,x19,#4
 dup v4.2d,x9
 add x9,x19,#5
 dup v5.2d,x9
 add x9,x19,#6
 dup v6.2d,x9
 add x9,x19,#7
 dup v7.2d,x9
 add x9,x19,#8
 dup v8.2d,x9
 add x9,x19,#9
 dup v9.2d,x9
 add x9,x19,#10
 dup v10.2d,x9
 add x9,x19,#11
 dup v11.2d,x9
 add x9,x19,#12
 dup v12.2d,x9
 add x9,x19,#13
 dup v13.2d,x9
 add x9,x19,#14
 dup v14.2d,x9
 add x9,x19,#15
 dup v15.2d,x9
 add x9,x19,#16
 dup v16.2d,x9
 add x9,x19,#17
 dup v17.2d,x9
 add x9,x19,#18
 dup v18.2d,x9
 add x9,x19,#19
 dup v19.2d,x9
 add x9,x19,#20
 dup v20.2d,x9
 add x9,x19,#21
 dup v21.2d,x9
 add x9,x19,#22
 dup v22.2d,x9
 add x9,x19,#23
 dup v23.2d,x9
 add x9,x19,#24
 dup v24.2d,x9
 add x9,x19,#25
 dup v25.2d,x9
 add x9,x19,#26
 dup v26.2d,x9
 add x9,x19,#27
 dup v27.2d,x9
 add x9,x19,#28
 dup v28.2d,x9
 add x9,x19,#29
 dup v29.2d,x9
 add x9,x19,#30
 dup v30.2d,x9
 add x9,x19,#31
 dup v31.2d,x9
 and x21,x19,#3
 lsl x21,x21,#22
 msr fpcr,x21
 mov x9,#16
 msr fpsr,x9
 msr tpidr_el0,x19
 mov x8,#19
 svc #0
 mov x20,x0
.Lfp_loop:
 mov x8,#18
 svc #0
 // Stay in EL0 across timer ticks. A short loop mostly exercised SVC switching
 // and could finish every iteration before an IRQ, missing that regression.
 mov x9,#0x300000
.Lfp_busy:
 subs x9,x9,#1
 b.ne .Lfp_busy
 stp q0, q1, [sp, #0]
 stp q2, q3, [sp, #32]
 stp q4, q5, [sp, #64]
 stp q6, q7, [sp, #96]
 stp q8, q9, [sp, #128]
 stp q10, q11, [sp, #160]
 stp q12, q13, [sp, #192]
 stp q14, q15, [sp, #224]
 stp q16, q17, [sp, #256]
 stp q18, q19, [sp, #288]
 stp q20, q21, [sp, #320]
 stp q22, q23, [sp, #352]
 stp q24, q25, [sp, #384]
 stp q26, q27, [sp, #416]
 stp q28, q29, [sp, #448]
 stp q30, q31, [sp, #480]
 ldp x9,x10,[sp,#0]
 add x11,x19,#0
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#16]
 add x11,x19,#1
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#32]
 add x11,x19,#2
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#48]
 add x11,x19,#3
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#64]
 add x11,x19,#4
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#80]
 add x11,x19,#5
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#96]
 add x11,x19,#6
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#112]
 add x11,x19,#7
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#128]
 add x11,x19,#8
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#144]
 add x11,x19,#9
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#160]
 add x11,x19,#10
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#176]
 add x11,x19,#11
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#192]
 add x11,x19,#12
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#208]
 add x11,x19,#13
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#224]
 add x11,x19,#14
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#240]
 add x11,x19,#15
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#256]
 add x11,x19,#16
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#272]
 add x11,x19,#17
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#288]
 add x11,x19,#18
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#304]
 add x11,x19,#19
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#320]
 add x11,x19,#20
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#336]
 add x11,x19,#21
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#352]
 add x11,x19,#22
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#368]
 add x11,x19,#23
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#384]
 add x11,x19,#24
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#400]
 add x11,x19,#25
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#416]
 add x11,x19,#26
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#432]
 add x11,x19,#27
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#448]
 add x11,x19,#28
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#464]
 add x11,x19,#29
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#480]
 add x11,x19,#30
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 ldp x9,x10,[sp,#496]
 add x11,x19,#31
 cmp x9,x11
 b.ne .Lfp_fail
 cmp x10,x11
 b.ne .Lfp_fail
 mrs x9,fpcr
 cmp x9,x21
 b.ne .Lfp_fail
 mrs x9,fpsr
 cmp x9,#16
 b.ne .Lfp_fail
 mrs x9,tpidr_el0
 cmp x9,x19
 b.ne .Lfp_fail
 mov x8,#19
 svc #0
 sub x0,x0,x20
 cmp x0,#300
 b.lo .Lfp_loop
 mov x0,#0
 b .Lfp_return
.Lfp_fail:
 mov x0,#1
.Lfp_return:
 ldr x19,[sp,#512]
 ldr x20,[sp,#520]
 ldr x21,[sp,#528]
 ldr x30,[sp,#536]
 add sp,sp,#576
 ret
