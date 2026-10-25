ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); }
SECTIONS {
 . = 0x80000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
 . = ALIGN(4096);
 .rodata : { *(.rodata .rodata.*) *(.got .got.*) } :ro
 . = ALIGN(4096);
 .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) } :ro
 ASSERT(SIZEOF(.data) == 0, "learning ELF cannot carry mutable global data")
 ASSERT(. <= 0x100000, "learning RX/RO image exceeds reserved control code")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
