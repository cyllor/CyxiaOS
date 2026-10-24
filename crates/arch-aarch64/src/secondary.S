// PSCI CPU_ON entry. CPU0 initialized immutable translation tables first.
// x0 is a bounded logical slot, NOT an MPIDR low-byte assumption.
.section .text.boot.secondary,"ax"
.balign 16
.global cyxia_secondary_start
cyxia_secondary_start:
 msr daifset, #15
 msr spsel, #1
 cmp x0, #{max_cpus}
 b.hs secondary_halt
 cbz x0, secondary_halt
 mov x19, x0
 mrs x1, CurrentEL
 cmp x1, #4
 b.ne secondary_halt
 mrs x1, sctlr_el1
 tst x1, #1
 b.ne secondary_halt
 msr tpidr_el1, x19
 msr cntp_ctl_el0, xzr
 ldr x0, =0x00000002b5193519
 msr tcr_el1, x0
 mov x0, #0xff
 msr mair_el1, x0
 ldr x0, =low_l1
 msr ttbr0_el1, x0
 ldr x0, =high_l1
 msr ttbr1_el1, x0
 dsb sy
 tlbi vmalle1
 dsb sy
 ic iallu
 dsb sy
 isb
 mrs x0, sctlr_el1
 ldr x1, =0x30d8181d
 orr x0, x0, x1
 msr sctlr_el1, x0
 isb
 ldr x0, =secondary_high
 br x0
secondary_halt:
 wfe
 b secondary_halt
.ltorg
.section .text.secondary_high,"ax"
secondary_high:
 ldr x0, =SMP_STACK_TOPS
 ldr x1, [x0, x19, lsl #3]
 cbz x1, secondary_high_halt
 mov sp, x1
 ldr x0, =exception_vectors
 msr vbar_el1, x0
 isb
 mrs x0, tcr_el1
 orr x0, x0, #0x80
 dsb ishst
 msr tcr_el1, x0
 isb
 tlbi vmalle1
 dsb ish
 isb
 mov x0, x19
 bl secondary_entry
secondary_high_halt:
 msr daifset, #15
 wfe
 b secondary_high_halt
