ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); ro PT_LOAD FLAGS(4); }
SECTIONS {
 . = 0x80000;
 .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
 . = ALIGN(4096);
 .rodata : { KEEP(*(.cyxia.model)) *(.rodata .rodata.*) *(.got .got.*) } :ro
 . = ALIGN(4096);
 .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) } :ro
 ASSERT(SIZEOF(.data) == 0, "controller ELF must not carry mutable global data")
 ASSERT(. <= 0xa0000, "controller image exceeds bounded arena")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}
