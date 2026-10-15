ENTRY(_start)
HIGH = 0xffffffc000000000;
PHDRS { boot PT_LOAD FLAGS(5); tables PT_LOAD FLAGS(6); text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x40200000;
 .boot : { KEEP(*(.text.boot)) } :boot
 . = ALIGN(4096);
 .boot_tables (NOLOAD) : { __boot_bss_start = .; *(.boot.bss) __boot_bss_end = .; } :tables
 . = HIGH + ALIGN(.,4096);
 __text_start = .;
 .text : AT(ADDR(.text)-HIGH) { *(.text .text.*) } :text
 . = ALIGN(4096); __text_end = .;
 __ro_start = .;
 .rodata : AT(ADDR(.rodata)-HIGH) { *(.rodata .rodata.*) } :ro
 . = ALIGN(4096); __ro_end = .;
 .data : AT(ADDR(.data)-HIGH) { *(.data .data.*) *(.got .got.*) } :data
 .bss (NOLOAD) : AT(ADDR(.bss)-HIGH) { . = ALIGN(16); __bss_start = .; *(.bss .bss.*) *(COMMON) . = ALIGN(16); __bss_end = .; }
 . = ALIGN(4096);
 .stack (NOLOAD) : AT(ADDR(.stack)-HIGH) { __stack_guard = .; . += 4096; . += 65536; __stack_top = .; } :data
 . = ALIGN(4096);
 .test_progress (NOLOAD) : AT(ADDR(.test_progress)-HIGH) { KEEP(*(.test_progress)) . = ALIGN(4096); } :data
 __kernel_end = .;
 __bss_phys_start = __bss_start-HIGH;
 __bss_phys_end = __bss_end-HIGH;
 __text_phys_start = __text_start-HIGH;
 __text_phys_end = __text_end-HIGH;
 __ro_phys_start = __ro_start-HIGH;
 __ro_phys_end = __ro_end-HIGH;
 __guard_phys = __stack_guard-HIGH;
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
