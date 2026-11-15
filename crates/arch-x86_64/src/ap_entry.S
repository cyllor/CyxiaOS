# Relocatable one-page AP startup image. All internal absolute references use
# the destination physical page; kernel entry and stack are full 64-bit values.
.section .ap_trampoline,"ax"
.balign 16
.global x86_ap_trampoline_start, x86_ap_trampoline_end
.set AP_CODE, 0x7000
.set AP_MAILBOX, 0x8000
.code16
x86_ap_trampoline_start:
    cli
    cld
    xorw %ax,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    lgdt AP_CODE + (ap_gdtr - x86_ap_trampoline_start)
    movl %cr0,%eax
    orl $1,%eax
    movl %eax,%cr0
    ljmpl $0x08, $(AP_CODE + (ap_protected - x86_ap_trampoline_start))
.code32
ap_protected:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    movl $1,%eax
    cpuid
    testl $0x200,%edx
    jz ap_failure
    shrl $24,%ebx
    cmpl AP_MAILBOX + 32,%ebx
    jne ap_failure
    movl $0x80000000,%eax
    cpuid
    cmpl $0x80000001,%eax
    jb ap_failure
    movl $0x80000001,%eax
    cpuid
    andl $0x20100000,%edx
    cmpl $0x20100000,%edx
    jne ap_failure
    movl %cr4,%eax
    orl $0x620,%eax
    movl %eax,%cr4
    movl AP_MAILBOX,%eax
    movl %eax,%cr3
    movl $0xc0000080,%ecx
    rdmsr
    orl $0x900,%eax
    wrmsr
    # INIT leaves CD/NW set. Drain cache state before enabling normal caching;
    # firmware MTRR/PAT types remain intact and the fresh CR3 is already loaded.
    # The following serializing PG transition establishes new translations.
    wbinvd
    movl %cr0,%eax
    andl $0x9ffffff3,%eax
    orl $0x80010023,%eax
    movl %eax,%cr0
    ljmpl $0x18, $(AP_CODE + (ap_long - x86_ap_trampoline_start))
ap_failure:
    movl $1,AP_MAILBOX + 48
1:  cli
    hlt
    jmp 1b
.code64
ap_long:
    movw $0x10,%ax
    movw %ax,%ds
    movw %ax,%es
    movw %ax,%ss
    xorw %ax,%ax
    movw %ax,%fs
    movw %ax,%gs
    movq AP_MAILBOX + 8,%rsp
    andq $-16,%rsp
    xorq %rbp,%rbp
    movq AP_MAILBOX + 24,%rdi
    movq AP_MAILBOX + 40,%rsi
    movq AP_MAILBOX + 16,%rax
    call *%rax
2:  cli
    hlt
    jmp 2b
.balign 8
ap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
ap_gdt_end:
ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1
    .long AP_CODE + (ap_gdt - x86_ap_trampoline_start)
x86_ap_trampoline_end:
.code64
