ENTRY(_start)
PHDRS {
  text PT_LOAD FLAGS(5);
  ro PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
  relro PT_GNU_RELRO FLAGS(4);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
  . = 0x1000;
  .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
  . = ALIGN(4096);
  .rodata : { KEEP(*(.rodata.role)) *(.rodata .rodata.*) BYTE(0); } :ro
  . = ALIGN(4096);
  /* Relocation destinations holding immutable pointers are written only
     during staging, then the entire aligned RELRO span is sealed. */
  .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) *(.got .got.*) BYTE(0); } :data :relro
  .dynamic : { *(.dynamic) } :data :relro
  . = ALIGN(4096);
  .data : { BYTE(0); *(.data .data.*) } :data
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
  ASSERT(. <= 0xf000, "native role data overlaps diagnostic result page")
  .role_probe 0xf000 : { KEEP(*(.role_probe)) BYTE(0); } :data
  /DISCARD/ : { *(.eh_frame*) *(.comment*) }
  ASSERT(. <= 0x10000, "native role exceeds its 64KiB image backing")
}
