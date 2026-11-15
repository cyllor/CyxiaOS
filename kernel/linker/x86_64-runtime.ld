ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
HIGH = 0xffff800000000000;
PHDRS {
 boot PT_LOAD FLAGS(5);
 tables PT_LOAD FLAGS(6);
 text PT_LOAD FLAGS(5);
 ro PT_LOAD FLAGS(4);
 data PT_LOAD FLAGS(6);
}
SECTIONS {
 . = 0x100000;
 __kernel_phys_start = .;
 .boot : { KEEP(*(.boot)) } :boot
 ASSERT(SIZEOF(.boot) <= 8192, "Multiboot header window")
 . = ALIGN(4096);
 .boot_tables (NOLOAD) : {
   __boot_bss_start = .;
   *(.boot.bss)
   __boot_bss_end = .;
 } :tables
 . = HIGH + ALIGN(., 4096);
 __text_start = .;
 .text : AT(ADDR(.text) - HIGH) {
   *(.text .text.* .ltext .ltext.*)
   KEEP(*(.ap_trampoline))
   . = ALIGN(4096);
 } :text
 __text_end = .;
 __rodata_start = .;
 .rodata : AT(ADDR(.rodata) - HIGH) {
   KEEP(*(.cyxia.boot))
   *(.rodata .rodata.* .lrodata .lrodata.*)
   . = ALIGN(4096);
 } :ro
 __rodata_end = .;
 .data : AT(ADDR(.data) - HIGH) {
   *(.data .data.* .ldata .ldata.*)
   *(.got .got.* .lgot .lgot.*)
   QUAD(0)
   . = ALIGN(4096);
 } :data
 __load_phys_end = LOADADDR(.data) + SIZEOF(.data);
 .bss (NOLOAD) : AT(ADDR(.bss) - HIGH) {
   __bss_start = .;
   *(.bss .bss.* .lbss .lbss.*) *(COMMON)
   . = ALIGN(4096);
   __bss_end = .;
 } :data
 .stack (NOLOAD) : AT(ADDR(.stack) - HIGH) {
   __stack_guard_start = .;
   . += 4096;
   __stack_guard_end = .;
   . += 262144;
   __stack_top = .;
 } :data
 .trap_stack (NOLOAD) : AT(ADDR(.trap_stack) - HIGH) {
   __trap_stack_guard = .;
   . += 4096;
   . += 32768;
   __trap_stack_top = .;
 } :data
 .df_stack (NOLOAD) : AT(ADDR(.df_stack) - HIGH) {
   __df_stack_guard = .;
   . += 4096;
   . += 16384;
   __df_stack_top = .;
 } :data
 __kernel_end = .;
 __kernel_phys_end = ADDR(.df_stack) + SIZEOF(.df_stack) - HIGH;
 __bss_phys_start = __bss_start - HIGH;
 __bss_phys_end = __bss_end - HIGH;
 __stack_phys_top = __stack_top - HIGH;
 ASSERT(__kernel_phys_end <= 0x20000000, "formal kernel exceeds 512MiB load arena")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) *(.user.text) }
}
