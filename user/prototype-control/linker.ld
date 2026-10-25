ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); model PT_LOAD FLAGS(4); }
SECTIONS {
 . = 0x80000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
 . = ALIGN(4096);
 .rodata : { *(.rodata .rodata.*) *(.got .got.*) } :ro
 ASSERT(. <= 0x90000, "fixture code/rodata exceeds protected image")
 . = 0x90000;
 .model : { KEEP(*(.cyxia.model)) } :model
 . = ALIGN(4096);
 .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) } :model
 ASSERT(SIZEOF(.data) == 0, "fixture ELF cannot carry mutable global data")
 ASSERT(. <= 0xa0000, "fixture models exceed protected image")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
