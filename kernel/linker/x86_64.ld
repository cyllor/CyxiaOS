ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
PHDRS {
 text PT_LOAD FLAGS(5);
 user PT_LOAD FLAGS(5);
 ro PT_LOAD FLAGS(4);
 data PT_LOAD FLAGS(6);
}
SECTIONS {
 . = 0x100000;
 __kernel_start = .;
 __text_start = .;
 .boot : { KEEP(*(.boot)) } :text
 ASSERT(SIZEOF(.boot) <= 8192, "Multiboot header must fit the initial image window")
 .text : { *(.text .text.*) . = ALIGN(4096); } :text
 __text_end = .;
 __user_text_start = .;
 .user.text : { KEEP(*(.user.text)) . = ALIGN(4096); } :user
 __user_text_end = .;
 __rodata_start = .;
 .rodata : { KEEP(*(.cyxia.boot)) *(.rodata .rodata.*) . = ALIGN(4096); } :ro
 __rodata_end = .;
 .data : {
   *(.data .data.*) *(.got .got.*)
   /* Keep a file-backed final data page even when all Rust statics are BSS. */
   QUAD(0)
   . = ALIGN(4096);
   __load_end = .;
 } :data
 .bss (NOLOAD) : {
   __bss_start = .;
   *(.bss .bss.*) *(COMMON)
   . = ALIGN(4096);
   __bss_end = .;
 } :data
 .stack (NOLOAD) : {
   __stack_guard_start = .;
   . += 4096;
   __stack_guard_end = .;
   . += 262144;
   __stack_top = .;
 } :data
 /* A CPL3 interrupt must never overwrite the suspended kernel call stack. */
 .trap_stack (NOLOAD) : { . += 32768; __trap_stack_top = .; } :data
 .user_stack (NOLOAD) : {
   __user_stack_start = .;
   . += 16384;
   __user_stack_end = .;
 } :data
 __kernel_end = .;
 ASSERT(__kernel_end <= 0x4000000, "x86 boot image exceeds its 64 MiB arena")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}
