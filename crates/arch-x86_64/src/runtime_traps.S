.section .text.x86_runtime_traps,"ax"
.code64
.global x86_runtime_syscall
x86_runtime_syscall:
    swapgs
    movq %rsp,%gs:24
    movq %gs:16,%rsp
    pushq $0x1b
    pushq %gs:24
    pushq %r11
    pushq $0x23
    pushq %rcx
    pushq $0
    pushq $256
    jmp x86_trap_common

.type x86_trap_common,@function
x86_trap_common:
    cld
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
    movq %rsp,%rbx
    subq $528,%rsp
    andq $-16,%rsp
    movq %rsp,%r12
    # No Rust/SSE instruction precedes preserving the interrupted FP bank.
    fxsave64 (%r12)
    testb $3,144(%rbx)
    jz 2f
    cmpq $256,120(%rbx)
    je 1f
    swapgs
1:  movq %gs:0,%r13
    testq %r13,%r13
    jz x86_runtime_fatal
    leaq 160(%r13),%rdi
    movq %r12,%rsi
    movl $64,%ecx
    rep movsq
    # Save user FS and the GS bank exchanged by SWAPGS, then restore kernel FS.
    movl $0xc0000100,%ecx
    rdmsr
    shlq $32,%rdx
    orq %rdx,%rax
    movq %rax,144(%r13)
    movl $0xc0000102,%ecx
    rdmsr
    shlq $32,%rdx
    orq %rdx,%rax
    movq %rax,152(%r13)
    movq %gs:40,%rax
    movq %rax,%rdx
    shrq $32,%rdx
    movl $0xc0000100,%ecx
    wrmsr
    fxrstor64 %gs:64
2:  movq %rbx,%rdi
    call x86_trap
    testb $3,144(%rbx)
    jnz x86_context_return
    fxrstor64 (%r12)
    movq %rbx,%rsp
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
    addq $16,%rsp
    iretq

.global x86_context_enter
x86_context_enter:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp,%gs:8
    movq %rdi,%r15
    fxsave64 %gs:64
    movl $0xc0000100,%ecx
    rdmsr
    shlq $32,%rdx
    orq %rdx,%rax
    movq %rax,%gs:40
    movq 144(%r15),%rax
    movq %rax,%rdx
    shrq $32,%rdx
    wrmsr
    movl $0xc0000102,%ecx
    movq 152(%r15),%rax
    movq %rax,%rdx
    shrq $32,%rdx
    wrmsr
    movq %rsi,%cr3
    fxrstor64 160(%r15)
    pushq $0x1b
    pushq 128(%r15)
    pushq 136(%r15)
    pushq $0x23
    pushq 120(%r15)
    movq 8(%r15),%r14
    movq 16(%r15),%r13
    movq 24(%r15),%r12
    movq 32(%r15),%r11
    movq 40(%r15),%r10
    movq 48(%r15),%r9
    movq 56(%r15),%r8
    movq 64(%r15),%rdi
    movq 72(%r15),%rsi
    movq 80(%r15),%rbp
    movq 88(%r15),%rdx
    movq 96(%r15),%rcx
    movq 104(%r15),%rbx
    movq 112(%r15),%rax
    movq 0(%r15),%r15
    swapgs
    iretq
x86_context_return:
    movq %gs:32,%rax
    movq %rax,%cr3
    movq %gs:8,%rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
x86_runtime_fatal:
    cli
3:  hlt
    jmp 3b
