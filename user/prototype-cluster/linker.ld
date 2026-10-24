ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x01000000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
 . = ALIGN(4096);
 .rodata : { *(.rodata .rodata.*) } :ro
 . = ALIGN(4096);
 .data : { *(.data .data.*) *(.got .got.*) } :data
 . = ALIGN(4096);
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
 . = ALIGN(4096);
 ASSERT(. < 0x01fc0000, "service overlaps guarded private stack")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
