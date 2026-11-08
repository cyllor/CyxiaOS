ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
 . = 0x10000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) *(.rodata .rodata.*) } :text
 ASSERT(SIZEOF(.text) <= 16384, "A09 ordinary client must fit four RX pages")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
