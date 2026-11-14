# Multiboot v1 address header: QEMU/GRUB can load this flat image without
# interpreting its ELF64 container. All bootstrap addresses are below 4 GiB.
.section .boot,"ax"
.balign 4
.global x86_multiboot_header
x86_multiboot_header:
    .long 0x1badb002
    .long 0x00010003
    .long -(0x1badb002 + 0x00010003)
    .long x86_multiboot_header
    .long __kernel_start
    .long __load_end
    .long __kernel_end
    .long _start

.code32
.global _start
.type _start,@function
_start:
    cli
    cld
    movl %eax, %ebp
    movl %ebx, %esi
    # Multiboot specifies a usable flat data segment; install our own stack
    # before CPUID and before any Rust-generated instruction can execute.
    movl $__stack_top, %esp
    movl $__bss_start, %edi
    movl $__bss_end, %ecx
    subl %edi, %ecx
    shrl $2, %ecx
    xorl %eax, %eax
    rep stosl
    movl %ebp, x86_boot_magic
    movl %esi, x86_boot_info
    cmpl $0x2badb002, %ebp
    jne x86_boot_failure

    # This port requires long mode and NX; fail before setting reserved bits
    # on unsupported CPUs. SSE control bits permit compiler-generated SSE2.
    movl $0x80000000, %eax
    cpuid
    cmpl $0x80000001, %eax
    jb x86_boot_failure
    movl $0x80000001, %eax
    cpuid
    movl %edx, %eax
    andl $0x20100000, %eax
    cmpl $0x20100000, %eax
    jne x86_boot_failure

    movl $x86_boot_pdpt, %eax
    orl $3, %eax
    movl %eax, x86_boot_pml4
    movl $x86_boot_pd, %eax
    orl $3, %eax
    movl %eax, x86_boot_pdpt
    xorl %ecx, %ecx
1:
    movl %ecx, %eax
    shll $21, %eax
    orl $0x83, %eax
    movl %eax, x86_boot_pd(,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jne 1b

    lgdt x86_boot_gdtr
    movl %cr4, %eax
    orl $0x630, %eax
    movl %eax, %cr4
    movl $x86_boot_pml4, %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x900, %eax
    wrmsr
    movl %cr0, %eax
    andl $0xfffffff3, %eax
    orl $0x80010003, %eax
    movl %eax, %cr0
    ljmp $0x08, $x86_long_entry

x86_boot_failure:
    movw $0xf4, %dx
    movl $0x11, %eax
    outl %eax, %dx
2:  hlt
    jmp 2b

.code64
x86_long_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    movq $__stack_top, %rsp
    andq $-16, %rsp
    xorq %rbp, %rbp
    movl x86_boot_magic(%rip), %edi
    movl x86_boot_info(%rip), %esi
    call x86_boot_entry
3:  cli
    hlt
    jmp 3b
.size _start, .-_start

.balign 8
x86_boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
x86_boot_gdt_end:
x86_boot_gdtr:
    .word x86_boot_gdt_end - x86_boot_gdt - 1
    .long x86_boot_gdt

.section .bss.x86_boot,"aw",@nobits
.balign 4096
x86_boot_pml4:
    .skip 4096
x86_boot_pdpt:
    .skip 4096
x86_boot_pd:
    .skip 4096
x86_boot_magic:
    .long 0
x86_boot_info:
    .long 0
