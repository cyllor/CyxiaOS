// This bootstrap is bound to the virt board via constants passed by the kernel.
.section .text.boot.primary,"ax"
.global _start
_start:
 msr daifset, #15
 msr spsel, #1
 msr tpidr_el1, xzr
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
.if {software_pan}
 // Each CPU that copies has its own table path at the same private VA.
 // The control-only profile gives the secondaries a root with no window.
 ldr x2, =__copy_secondary_l1
 ldr x3, =ram_l2
 orr x3, x3, #3
.if {secondary_copy_windows}
 ldr x4, =__copy_secondary_l2
 ldr x5, =__copy_secondary_l3
.endif
 mov x6, #{secondary_copy_roots}
.Linit_secondary_copy:
 str x0, [x2, #2048]
 str x3, [x2, #2056]
.if {secondary_copy_windows}
 orr x7, x4, #3
 str x7, [x2, #2064]
 orr x7, x5, #3
 str x7, [x4]
 add x4, x4, #4096
 add x5, x5, #4096
.endif
 add x2, x2, #4096
 subs x6, x6, #1
 b.ne .Linit_secondary_copy
 // HIGH + 2 GiB is L1 slot 258, beyond the 1 GiB RAM alias.
 ldr x0, =__copy_window_l2
 orr x3, x0, #3
 str x3, [x1, #2064]
 ldr x3, =__copy_window_l3
 orr x3, x3, #3
 str x3, [x0]
.endif
 // Device blocks, PXN + UXN, AF, AttrIndx 1. No normal-memory alias.
 ldr x0, =dev_l2
 ldr x1, ={gic_base}
 ldr x2, =0x0060000000000405
 orr x1, x1, x2
 str x1, [x0, #512]
 ldr x1, ={uart_base}
 orr x1, x1, x2
 str x1, [x0, #576]
 // virt board VirtIO MMIO window; only DTB-discovered resources are accessed.
 ldr x1, =0x0a000000
 orr x1, x1, x2
 str x1, [x0, #640]
 ldr x0, =ram_l2
 ldr x1, =ram_l3
 mov x2, #{ram_table_count}
5: orr x3, x1, #3
 str x3, [x0], #8
 add x1, x1, #4096
 subs x2, x2, #1
 b.ne 5b
 ldr x0, =ram_l3
 ldr x1, ={ram_base}
 ldr x2, ={ram_end}
 ldr x3, =__text_phys_start
 ldr x4, =__text_phys_end
 ldr x5, =__ro_phys_start
 ldr x6, =__ro_phys_end
 ldr x7, =__guard_phys
 ldr x10, =__exception_stacks_phys
 ldr x11, =__exception_stacks_end_phys
.if {software_pan}
 ldr x13, =empty_l1
 ldr x14, =__copy_window_l2
 ldr x15, =.Lcopy_ancestors_end
.endif
6: ldr x8, =0x0060000000000703
 cmp x1, x7
 b.eq 10f
 // The shared low/high RAM leaves omit both guards in every exception bank.
 cmp x1, x10
 b.lo .Lordinary_boot_page
 cmp x1, x11
 b.hs .Lordinary_boot_page
 sub x12, x1, x10
 and x12, x12, #0x7fff
 cbz x12, 10f
 cmp x12, #0x5000
 b.eq 10f
.Lordinary_boot_page:
.if {software_pan}
 // The zeroed translation root keeps a read-only, execute-never alias.
 cmp x1, x13
 b.eq .Lreadonly_boot_page
 cmp x1, x14
 b.lo .Lkernel_boot_page
 cmp x1, x15
 b.lo .Lreadonly_boot_page
.Lkernel_boot_page:
.endif
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
.Lreadonly_boot_page:
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
.if {software_pan}
 // A1=1, AS=0. TTBR1 supplies the eight-bit ASID.
 ldr x0, =0x00000002b5593519
.else
 ldr x0, =0x00000002b5193519
.endif
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
.global high_l1
high_l1: .skip 4096
.if {software_pan}
.global empty_l1
empty_l1: .skip 4096
.global __copy_window_l2
__copy_window_l2: .skip 4096
.global __copy_secondary_l1
__copy_secondary_l1: .skip {secondary_copy_roots} * 4096
.if {secondary_copy_windows}
__copy_secondary_l2: .skip {secondary_copy_windows} * 4096
.endif
.Lcopy_ancestors_end:
.global __copy_window_l3
__copy_window_l3: .skip 4096
.if {secondary_copy_windows}
.global __copy_secondary_l3
__copy_secondary_l3: .skip {secondary_copy_windows} * 4096
.endif
.endif
dev_l2: .skip 4096
ram_l2: .skip 4096
.global ram_l3
ram_l3: .skip {ram_tables_bytes}

// The linker places an unmapped guard page immediately below this range.
.section .stack.primary,"aw",%nobits
.skip {exec_stack_bytes}

.section .text.highentry,"ax"
high_entry:
 mov x0, #0
 ldr x1, =__stack_base
 ldr x2, =__stack_top
 bl exception_register_stack
 ldr x0, =exception_vectors
 msr vbar_el1, x0
 isb
 // Retire the identity-mapped boot root before ordinary EL1 runs.
.if {software_pan}
 ldr x0, =empty_l1
 msr ttbr0_el1, x0
.else
 mrs x0, tcr_el1
 orr x0, x0, #0x80
 dsb ishst
 msr tcr_el1, x0
.endif
 isb
 tlbi vmalle1is
 dsb ish
 isb
 bl boot_entry
 b boot_halt_high
boot_halt_high:
 wfe
 b boot_halt_high
