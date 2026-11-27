ENTRY(_start)
HIGH = 0xffffffc000000000;
PHDRS { boot PT_LOAD FLAGS(5); tables PT_LOAD FLAGS(6); text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x40200000;
 .boot : { KEEP(*(.text.boot.primary)) KEEP(*(.text.boot)) KEEP(*(.text.boot.secondary)) } :boot
 ASSERT(SIZEOF(.boot) <= 4096, "all physical bootstrap entries must fit the executable boot page")
 . = ALIGN(4096);
 .boot_tables (NOLOAD) : { __boot_bss_start = .; *(.boot.bss) __boot_bss_end = .; } :tables
 . = HIGH + ALIGN(.,4096);
 __text_start = .;
 .text : AT(ADDR(.text)-HIGH) { *(.text .text.*) } :text
 . = ALIGN(4096); __text_end = .;
 __ro_start = .;
 .rodata : AT(ADDR(.rodata)-HIGH) { KEEP(*(.cyxia.boot)) *(.rodata .rodata.*) } :ro
 . = ALIGN(4096); __ro_end = .;
 .data : AT(ADDR(.data)-HIGH) { *(.data .data.*) *(.got .got.*) } :data
 .bss (NOLOAD) : AT(ADDR(.bss)-HIGH) {
  . = ALIGN(16); __bss_start = .;
  /* The pinned network/staging arena must not share a page with other statics. */
  __sec_n_start = .;
  *(.bss.sec_n .bss.sec_n.*)
  . = (. == __sec_n_start) ? . : ALIGN(4096);
  __sec_n_end = .;
  *(.bss .bss.*) *(COMMON)
  . = ALIGN(4096);
  __exception_scratch = .;
  . += 4 * 4096;
  __exception_scratch_end = .;
  . = ALIGN(16); __bss_end = .;
 }
 ASSERT(__sec_n_start == __sec_n_end || (__sec_n_start % 4096) == 0,
        "SEC-N arena must start on a page boundary")
 . = ALIGN(4096);
 .stack (NOLOAD) : AT(ADDR(.stack)-HIGH) {
  __stack_guard = .;
  . += 4096;
  __stack_base = .;
  KEEP(*(.stack.primary))
  __stack_top = .;
  /* Four 32 KiB banks: guard, 16 KiB IRQ, guard, 8 KiB emergency. */
  __exception_stacks = .;
  . += 4 * 32768;
  __exception_stacks_end = .;
 } :data
 ASSERT(__stack_top - __stack_base == 16384 || __stack_top - __stack_base == 262144,
        "unexpected primary EL1 execution stack size")
 . = ALIGN(4096);
 .test_progress (NOLOAD) : AT(ADDR(.test_progress)-HIGH) { KEEP(*(.test_progress)) . = ALIGN(4096); } :data
 __kernel_end = .;
 ASSERT(__kernel_end - HIGH <= 0x44000000, "kernel exceeds boot/DMA arena")
 __bss_phys_start = __bss_start-HIGH;
 __bss_phys_end = __bss_end-HIGH;
 __text_phys_start = __text_start-HIGH;
 __text_phys_end = __text_end-HIGH;
 __ro_phys_start = __ro_start-HIGH;
 __ro_phys_end = __ro_end-HIGH;
 __guard_phys = __stack_guard-HIGH;
 __exception_stacks_phys = __exception_stacks-HIGH;
 __exception_stacks_end_phys = __exception_stacks_end-HIGH;
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
