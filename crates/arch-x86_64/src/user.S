.section .text.x86_user,"ax"
.code64
.global x86_enter_user
.type x86_enter_user,@function
x86_enter_user:
    cli
    cmpq $0, x86_user_saved_rsp(%rip)
    jne x86_user_fatal
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, x86_user_saved_rsp(%rip)
    movw $0x1b, %ax
    movw %ax, %ds
    movw %ax, %es
    pushq $0x1b
    pushq %rsi
    # IF=1, IOPL=0. No inherited direction, trap, nested-task or VM flags.
    pushq $0x202
    pushq $0x23
    pushq %rdi
    # Do not expose privileged pointers or caller registers to the user fixture.
    xorq %rax, %rax
    xorq %rbx, %rbx
    xorq %rcx, %rcx
    xorq %rdx, %rdx
    xorq %rbp, %rbp
    xorq %rsi, %rsi
    xorq %rdi, %rdi
    xorq %r8, %r8
    xorq %r9, %r9
    xorq %r10, %r10
    xorq %r11, %r11
    xorq %r12, %r12
    xorq %r13, %r13
    xorq %r14, %r14
    xorq %r15, %r15
    iretq
.size x86_enter_user, .-x86_enter_user

.global x86_user_return
.type x86_user_return,@function
x86_user_return:
    cli
    cmpq $0, x86_user_saved_rsp(%rip)
    je x86_user_fatal
    movq x86_user_saved_rsp(%rip), %rsp
    movq $0, x86_user_saved_rsp(%rip)
    movw $0x10, %dx
    movw %dx, %ds
    movw %dx, %es
    movw %dx, %ss
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
.size x86_user_return, .-x86_user_return

.global x86_user_fatal
x86_user_fatal:
    cli
    movw $0xf4, %dx
    movl $0x11, %eax
    outl %eax, %dx
1:  hlt
    jmp 1b

.section .bss.x86_user,"aw",@nobits
.balign 8
.global x86_user_saved_rsp
x86_user_saved_rsp:
    .quad 0

.section .user.text,"ax"
.code64
.global x86_user_probe
.type x86_user_probe,@function
x86_user_probe:
    movl $1, %eax
    int $0x80
    xorl %edi, %edi
    cmpq $0x43595831, %rax
    je 2f
    movl $1, %edi
2:  movl $2, %eax
    int $0x80
    ud2
.size x86_user_probe, .-x86_user_probe

.global x86_user_fault_probe
.type x86_user_fault_probe,@function
x86_user_fault_probe:
    movl $0x100000, %eax
    movb $0x5a, (%rax)
    movl $2, %edi
    movl $2, %eax
    int $0x80
    ud2
.size x86_user_fault_probe, .-x86_user_fault_probe
