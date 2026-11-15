.section .text.x86_traps,"ax"
.code64
.type x86_trap_common,@function
x86_trap_common:
    cld
    # The push order is the exact inverse of repr(C) TrapFrame. Interrupt
    # gates clear IF, and no Rust value is placed in a red zone.
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %rdi
    movq %rsp, %rbx
    andq $-16, %rsp
    call x86_trap
    movq %rbx, %rsp
    testq %rax, %rax
    je x86_trap_restore
    cmpq $1, %rax
    jne x86_user_fatal
    # Only a CPL3 trap may abandon its hardware frame. Return the status
    # stored in frame.rax to the suspended x86_enter_user call.
    movq 144(%rsp), %rax
    andl $3, %eax
    cmpl $3, %eax
    jne x86_user_fatal
    movq 112(%rsp), %rax
    jmp x86_user_return
x86_trap_restore:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    iretq
.size x86_trap_common, .-x86_trap_common
