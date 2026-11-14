// Read-only, page-isolated EL0 test program. It is not an AI model or shell.
// x0: private cookie; x1: data/probe VA; x2: mode
// (zero = timer-only busy worker, four = bounded unified worker, other = probe).
// No calls into the kernel and no shared writable user pages.
.section .rodata.smp_user,"a"
.arch armv8-a+fp+simd
.balign 4096
.global smp_user_start
smp_user_start:
 cbz x2, smp_busy
 cmp x2, #4
 b.eq smp_bounded
 cmp x2, #5
 b.eq smp_registers
 b smp_probe
smp_busy:
 ldr x10, [x1]
 cmp x10, x0
 b.ne smp_cookie_bad
 ldr x11, [x1, #8]
 add x11, x11, #1
 str x11, [x1, #8]
 b smp_busy
smp_bounded:
 mov x12, #16
1:
 ldr x10, [x1]
 cmp x10, x0
 b.ne smp_cookie_bad
 ldr x11, [x1, #8]
 add x11, x11, #1
 str x11, [x1, #8]
 subs x12, x12, #1
 b.ne 1b
 // The private timer remains a hard backstop, but translated execution must
 // not depend on an asynchronously delivered PPI to end a prepaid turn.
 // Yield after a fixed instruction batch so one QEMU TB-chain cannot consume
 // more than the complete 10 ms builtin credit before interrupt delivery.
 svc #4
 b smp_bounded
smp_probe:
 cmp x2, #1
 b.eq smp_read
 cmp x2, #2
 b.eq smp_write
 br x1
smp_read:
 ldr x10, [x1]
 svc #1
 b .
smp_write:
 str x0, [x1]
 svc #2
 b .
smp_cookie_bad:
 svc #3
 b .
// Dedicated A06 architectural-boundary profile. Fresh state is checked by EL0
// before this task installs its own distinct patterns. x0 is a run-specific seed.
.macro fresh_gpr r
 cbnz x\r, smp_register_bad
.endm
.macro fresh_q r
 umov x10, v\r\().d[0]
 umov x11, v\r\().d[1]
 orr x10, x10, x11
 cbnz x10, smp_register_bad
.endm
.macro pattern_gpr r
 add x\r, x0, #\r
.endm
.macro pattern_q r
 add x10, x0, #(128+\r)
 fmov d\r, x10
 add x10, x0, #(256+\r)
 ins v\r\().d[1], x10
.endm
smp_registers:
.irp r,19,20,21,22,23,24,25,26,27,28,29
 fresh_gpr \r
.endr
 mrs x10, tpidr_el0
 cbnz x10, smp_register_bad
 mrs x10, fpcr
 cbnz x10, smp_register_bad
 mrs x10, fpsr
 cbnz x10, smp_register_bad
.irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
 fresh_q \r
.endr
 mov x10, #1
 str x10, [x1, #16]
.irp r,19,20,21,22,23,24,25,26,27,28,29
 pattern_gpr \r
.endr
 msr tpidr_el0, x0
.irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
 pattern_q \r
.endr
 and x10, x0, #3
 lsl x10, x10, #22
 msr fpcr, x10
 mov x11, #31
 udiv x10, x0, x11
 msub x10, x10, x11, x0
 add x10, x10, #1
 msr fpsr, x10
 mov x10, #1
 str x10, [x1, #24]
smp_register_loop:
 mov x12, #0x20
 lsl x12, x12, #16
1:
 subs x12, x12, #1
 b.ne 1b
 svc #0x606
 b smp_register_loop
smp_register_bad:
 svc #0x60f
 b .
.global smp_user_end
smp_user_end:
.balign 4096
