// This bootstrap is bound to the virt board via constants passed by the kernel.
.section .text.boot,"ax"
.global _start
_start:
 msr daifset, #15
 msr spsel, #1
 mrs x0, CurrentEL
 cmp x0, #4
 b.ne boot_halt
 mrs x0, mpidr_el1
 and x0, x0, #0xff
 cbnz x0, boot_halt
 // MMU/cache must be off at this specific bare-metal entry.
 mrs x0, sctlr_el1
 tst x0, #1
 b.ne boot_halt
 ldr x0, =__boot_bss_start
 ldr x1, =__boot_bss_end
1: cmp x0, x1
 b.hs 2f
 stp xzr, xzr, [x0], #16
 b 1b
2: ldr x0, =__bss_phys_start
 ldr x1, =__bss_phys_end
3: cmp x0, x1
 b.hs 4f
 stp xzr, xzr, [x0], #16
 b 3b
4: ldr x0, =ram_l2
 orr x0, x0, #3
 ldr x1, =low_l1
 str x0, [x1, #8]
 ldr x1, =high_l1
 str x0, [x1, #2056]
 ldr x0, =dev_l2
 orr x0, x0, #3
 str x0, [x1, #2048]
 // Device blocks, PXN + UXN, AF, AttrIndx 1. No normal-memory alias.
 ldr x0, =dev_l2
 ldr x1, ={gic_base}
 ldr x2, =0x0060000000000405
 orr x1, x1, x2
 str x1, [x0, #512]
 ldr x1, ={uart_base}
 orr x1, x1, x2
 str x1, [x0, #576]
 ldr x0, =ram_l2
 ldr x1, =ram_l3
 mov x2, #128
5: orr x3, x1, #3
 str x3, [x0], #8
 add x1, x1, #4096
 subs x2, x2, #1
 b.ne 5b
 ldr x0, =ram_l3
 ldr x1, ={ram_base}
 ldr x2, =0x50000000
 ldr x3, =__text_phys_start
 ldr x4, =__text_phys_end
 ldr x5, =__ro_phys_start
 ldr x6, =__ro_phys_end
 ldr x7, =__guard_phys
6: ldr x8, =0x0060000000000703
 cmp x1, x7
 b.eq 10f
 ldr x9, ={entry}
 cmp x1, x9
 b.eq 8f
 cmp x1, x3
 b.lo 7f
 cmp x1, x4
 b.lo 8f
7: cmp x1, x5
 b.lo 9f
 cmp x1, x6
 b.hs 9f
 orr x8, x8, #0x80
 b 9f
8: ldr x8, =0x0040000000000783
9: orr x8, x8, x1
 b 11f
10: mov x8, #0
11: str x8, [x0], #8
 add x1, x1, #4096
 cmp x1, x2
 b.lo 6b
 // 39-bit VA, 4K, WBWA inner-shareable walks, 40-bit PA.
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
 // RES1 plus MMU, data/instruction caches, stack alignment checks, WXN.
 ldr x1, =0x30d8181d
 orr x0, x0, x1
 msr sctlr_el1, x0
 isb
 ldr x0, =__stack_top
 mov sp, x0
 ldr x0, =high_entry
 br x0
boot_halt:
 wfe
 b boot_halt
.ltorg
.section .boot.bss,"aw",%nobits
.balign 4096
.global low_l1
low_l1: .skip 4096
high_l1: .skip 4096
dev_l2: .skip 4096
ram_l2: .skip 4096
ram_l3: .skip 524288
.section .text.highentry,"ax"
high_entry:
 ldr x0, =exception_vectors
 msr vbar_el1, x0
 isb
 // Disable TTBR0 walks before invalidating all old low translations.
 mrs x0, tcr_el1
 orr x0, x0, #0x80
 dsb ishst
 msr tcr_el1, x0
 isb
 tlbi vmalle1is
 dsb ish
 isb
 bl boot_entry
 b boot_halt_high
boot_halt_high:
 wfe
 b boot_halt_high
