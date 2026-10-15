.section .text.boot,"ax"
.global _start
_start:
 msr daifset, #15
 mrs x0, CurrentEL
 cmp x0, #4
 b.ne 9f
 mrs x0, mpidr_el1
 and x0, x0, #0xff
 cbnz x0, 9f
 ldr x0, =__stack_top
 mov sp, x0
 ldr x0, =__bss_start
 ldr x1, =__bss_end
1: cmp x0, x1
 b.hs 2f
 stp xzr, xzr, [x0], #16
 b 1b
2: bl boot_entry
9: wfe
 b 9b
