ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x40200000;
 .text : { KEEP(*(.text.boot)) *(.text .text.*) } :text
 . = ALIGN(4096);
 .rodata : { *(.rodata .rodata.*) } :ro
 . = ALIGN(4096);
 .data : { *(.data .data.*) *(.got .got.*) } :data
 .bss (NOLOAD) : { . = ALIGN(16); __bss_start = .; *(.bss .bss.*) *(COMMON) . = ALIGN(16); __bss_end = .; }
 . = ALIGN(4096);
 .stack (NOLOAD) : { . += 65536; __stack_top = .; } :data
 __kernel_end = .;
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
