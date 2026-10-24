// Read-only, page-isolated EL0 test program. It is not an AI model or shell.
// x0: private cookie; x1: data/probe VA; x2: probe mode (zero = busy worker).
// No calls into the kernel and no shared writable user pages.
.section .rodata.smp_user,"a"
.balign 4096
.global smp_user_start
smp_user_start:
 cbnz x2, smp_probe
1:
 ldr x10, [x1]
 cmp x10, x0
 b.ne smp_cookie_bad
 ldr x11, [x1, #8]
 add x11, x11, #1
 str x11, [x1, #8]
 b 1b
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
