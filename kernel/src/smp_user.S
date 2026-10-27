// Read-only, page-isolated EL0 test program. It is not an AI model or shell.
// x0: private cookie; x1: data/probe VA; x2: mode
// (zero = timer-only busy worker, four = bounded unified worker, other = probe).
// No calls into the kernel and no shared writable user pages.
.section .rodata.smp_user,"a"
.balign 4096
.global smp_user_start
smp_user_start:
 cbz x2, smp_busy
 cmp x2, #4
 b.eq smp_bounded
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
.global smp_user_end
smp_user_end:
.balign 4096
