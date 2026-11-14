.section .text.x86_traps,"ax"
.code64
.macro ISR_NOERR number
.global x86_isr_\number
.type x86_isr_\number,@function
x86_isr_\number:
    pushq $0
    pushq $\number
    jmp x86_trap_common
.endm
.macro ISR_ERROR number
.global x86_isr_\number
.type x86_isr_\number,@function
x86_isr_\number:
    pushq $\number
    jmp x86_trap_common
.endm
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERROR 8
ISR_NOERR 9
ISR_ERROR 10
ISR_ERROR 11
ISR_ERROR 12
ISR_ERROR 13
ISR_ERROR 14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERROR 17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERROR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERROR 29
ISR_ERROR 30
ISR_NOERR 31
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47
ISR_NOERR 128
ISR_NOERR 255

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

.section .rodata.x86_isr,"a"
.balign 8
.global x86_isr_table
x86_isr_table:
    .quad x86_isr_0, x86_isr_1, x86_isr_2, x86_isr_3
    .quad x86_isr_4, x86_isr_5, x86_isr_6, x86_isr_7
    .quad x86_isr_8, x86_isr_9, x86_isr_10, x86_isr_11
    .quad x86_isr_12, x86_isr_13, x86_isr_14, x86_isr_15
    .quad x86_isr_16, x86_isr_17, x86_isr_18, x86_isr_19
    .quad x86_isr_20, x86_isr_21, x86_isr_22, x86_isr_23
    .quad x86_isr_24, x86_isr_25, x86_isr_26, x86_isr_27
    .quad x86_isr_28, x86_isr_29, x86_isr_30, x86_isr_31
    .quad x86_isr_32, x86_isr_33, x86_isr_34, x86_isr_35
    .quad x86_isr_36, x86_isr_37, x86_isr_38, x86_isr_39
    .quad x86_isr_40, x86_isr_41, x86_isr_42, x86_isr_43
    .quad x86_isr_44, x86_isr_45, x86_isr_46, x86_isr_47
