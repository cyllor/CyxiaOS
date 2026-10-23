ENTRY(_start)
PHDRS { code PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
 . = 0x100000;
 .text : { KEEP(*(.text.start)) *(.text .text.*) *(.rodata .rodata.*) } :code
 ASSERT(. <= 0x104000, "user code exceeds 16KiB")
 . = 0x104000;
 .data : { *(.data .data.*) } :data
 .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
 ASSERT(. <= 0x106000, "user data exceeds 8KiB")
 /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) }
}
