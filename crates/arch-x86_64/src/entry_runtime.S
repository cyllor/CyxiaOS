.section .boot,"ax"
.balign 4
.global x86_multiboot_header
x86_multiboot_header:
    .long 0x1badb002,0x00010003,-(0x1badb002+0x00010003)
    .long x86_multiboot_header,__kernel_phys_start,__load_phys_end,__kernel_phys_end,_start
.code32
.global _start
_start:
    cli
    cld
    movl %eax,%ebp
    movl %ebx,%esi
    movl $__stack_phys_top,%esp
    movl $__boot_bss_start,%edi
    movl $__boot_bss_end,%ecx
    subl %edi,%ecx
    shrl $2,%ecx
    xorl %eax,%eax
    rep stosl
    movl $__bss_phys_start,%edi
    movl $__bss_phys_end,%ecx
    subl %edi,%ecx
    shrl $2,%ecx
    rep stosl
    movl %ebp,runtime_magic
    movl %esi,runtime_info
    cmpl $0x2badb002,%ebp
    jne runtime_failure
    movl $0x80000000,%eax
    cpuid
    cmpl $0x80000001,%eax
    jb runtime_failure
    movl $0x80000001,%eax
    cpuid
    andl $0x20100000,%edx
    cmpl $0x20100000,%edx
    jne runtime_failure
    movl $runtime_pdpt,%eax
    orl $3,%eax
    movl %eax,runtime_root
    movl %eax,runtime_root+2048
    movl $runtime_pd,%eax
    orl $3,%eax
    movl %eax,runtime_pdpt
    .if {ram_gib} == 2
    movl $(runtime_pd+4096),%eax
    orl $3,%eax
    movl %eax,runtime_pdpt+8
    .endif
    xorl %ecx,%ecx
1:  movl %ecx,%eax
    shll $21,%eax
    orl $0x83,%eax
    movl %eax,runtime_pd(,%ecx,8)
    incl %ecx
    cmpl $(512*{ram_gib}),%ecx
    jne 1b
    lgdt runtime_gdtr
    movl %cr4,%eax
    orl $0x630,%eax
    movl %eax,%cr4
    movl $runtime_root,%eax
    movl %eax,%cr3
    movl $0xc0000080,%ecx
    rdmsr
    orl $0x900,%eax
    wrmsr
    # Match AP caching policy without changing BIOS MTRR/PAT memory types.
    # Flush before clearing CD/NW; CR3 is fresh and CR0.PG enables new walks.
    wbinvd
    movl %cr0,%eax
    andl $0x9ffffff3,%eax
    orl $0x80010023,%eax
    movl %eax,%cr0
    ljmp $0x08,$runtime_long
runtime_failure:
    movw $0xf4,%dx
    movl $0x11,%eax
    outl %eax,%dx
2:  hlt
    jmp 2b
.code64
runtime_long:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    xorw %ax,%ax
    movw %ax,%fs
    movw %ax,%gs
    movabsq $__stack_top,%rsp
    andq $-16,%rsp
    xorq %rbp,%rbp
    movl runtime_magic(%rip),%edi
    movl runtime_info(%rip),%esi
    movabsq $x86_runtime_boot_entry,%rax
    call *%rax
3:  cli
    hlt
    jmp 3b
.balign 8
runtime_gdt:
    .quad 0,0x00af9a000000ffff,0x00cf92000000ffff
runtime_gdt_end:
runtime_gdtr:
    .word runtime_gdt_end-runtime_gdt-1
    .long runtime_gdt
.section .boot.bss,"aw",@nobits
.balign 4096
runtime_root: .skip 4096
runtime_pdpt: .skip 4096
runtime_pd: .skip (4096*{ram_gib})
runtime_magic: .long 0
runtime_info: .long 0
