ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
 . = 0x10000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) *(.rodata .rodata.*) } :text
 ASSERT(SIZEOF(.text) <= 4096, "pure task code must fit one page")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
