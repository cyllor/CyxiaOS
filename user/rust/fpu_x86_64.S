// NativeOs FP/SIMD and actual FS-base isolation probe. No FSGSBASE dependency.
// SysV C entry: RDI=pid; return0 only after real yields and preserved state.
.section .text.fp_probe,"ax",@progbits
.global cyxia_fp_probe
.type cyxia_fp_probe,@function
cyxia_fp_probe:
 pushq %rbx
 pushq %rbp
 pushq %r12
 pushq %r13
 pushq %r14
 pushq %r15
 subq $840, %rsp
 movq %rdi, %r12
 fxsave64 (%rsp)
 cmpw $0x037f, 0(%rsp)
 jne .Lx_fp_fail
 cmpw $0, 2(%rsp)
 jne .Lx_fp_fail
 cmpb $0, 4(%rsp)
 jne .Lx_fp_fail
 cmpl $0x1f80, 24(%rsp)
 jne .Lx_fp_fail
 leaq 160(%rsp), %rsi
 movl $32, %ecx
.Lx_fp_fresh:
 cmpq $0, (%rsi)
 jne .Lx_fp_fail
 addq $8, %rsi
 decl %ecx
 jnz .Lx_fp_fresh
 movq $25, %rax
 movq $0x1003, %rdi
 leaq 792(%rsp), %rsi
 int $0x80
 testq %rax, %rax
 jnz .Lx_fp_fail
 cmpq $0, 792(%rsp)
 jne .Lx_fp_fail
 movq %r12, 784(%rsp)
 movq $25, %rax
 movq $0x1002, %rdi
 leaq 784(%rsp), %rsi
 int $0x80
 testq %rax, %rax
 jnz .Lx_fp_fail
 movq %fs:0, %rax
 cmpq %r12, %rax
 jne .Lx_fp_fail
 movw $0x077f, 800(%rsp)
 fldcw 800(%rsp)
 movl $0x3f80, 804(%rsp)
 ldmxcsr 804(%rsp)
 fld1
 fldpi
 leaq 0(%r12), %r13
 movq %r13, %xmm0
 punpcklqdq %xmm0, %xmm0
 leaq 1(%r12), %r13
 movq %r13, %xmm1
 punpcklqdq %xmm1, %xmm1
 leaq 2(%r12), %r13
 movq %r13, %xmm2
 punpcklqdq %xmm2, %xmm2
 leaq 3(%r12), %r13
 movq %r13, %xmm3
 punpcklqdq %xmm3, %xmm3
 leaq 4(%r12), %r13
 movq %r13, %xmm4
 punpcklqdq %xmm4, %xmm4
 leaq 5(%r12), %r13
 movq %r13, %xmm5
 punpcklqdq %xmm5, %xmm5
 leaq 6(%r12), %r13
 movq %r13, %xmm6
 punpcklqdq %xmm6, %xmm6
 leaq 7(%r12), %r13
 movq %r13, %xmm7
 punpcklqdq %xmm7, %xmm7
 leaq 8(%r12), %r13
 movq %r13, %xmm8
 punpcklqdq %xmm8, %xmm8
 leaq 9(%r12), %r13
 movq %r13, %xmm9
 punpcklqdq %xmm9, %xmm9
 leaq 10(%r12), %r13
 movq %r13, %xmm10
 punpcklqdq %xmm10, %xmm10
 leaq 11(%r12), %r13
 movq %r13, %xmm11
 punpcklqdq %xmm11, %xmm11
 leaq 12(%r12), %r13
 movq %r13, %xmm12
 punpcklqdq %xmm12, %xmm12
 leaq 13(%r12), %r13
 movq %r13, %xmm13
 punpcklqdq %xmm13, %xmm13
 leaq 14(%r12), %r13
 movq %r13, %xmm14
 punpcklqdq %xmm14, %xmm14
 leaq 15(%r12), %r13
 movq %r13, %xmm15
 punpcklqdq %xmm15, %xmm15
 movq $19, %rax
 int $0x80
 movq %rax, %rbx
 movq $4096, %r15
.Lx_fp_loop:
 movq $18, %rax
 int $0x80
 fxsave64 (%rsp)
 cmpw $0x077f, 0(%rsp)
 jne .Lx_fp_fail
 cmpl $0x3f80, 24(%rsp)
 jne .Lx_fp_fail
 movq %fs:0, %rax
 cmpq %r12, %rax
 jne .Lx_fp_fail
 leaq 0(%r12), %r13
 cmpq %r13, 160(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 168(%rsp)
 jne .Lx_fp_fail
 leaq 1(%r12), %r13
 cmpq %r13, 176(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 184(%rsp)
 jne .Lx_fp_fail
 leaq 2(%r12), %r13
 cmpq %r13, 192(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 200(%rsp)
 jne .Lx_fp_fail
 leaq 3(%r12), %r13
 cmpq %r13, 208(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 216(%rsp)
 jne .Lx_fp_fail
 leaq 4(%r12), %r13
 cmpq %r13, 224(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 232(%rsp)
 jne .Lx_fp_fail
 leaq 5(%r12), %r13
 cmpq %r13, 240(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 248(%rsp)
 jne .Lx_fp_fail
 leaq 6(%r12), %r13
 cmpq %r13, 256(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 264(%rsp)
 jne .Lx_fp_fail
 leaq 7(%r12), %r13
 cmpq %r13, 272(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 280(%rsp)
 jne .Lx_fp_fail
 leaq 8(%r12), %r13
 cmpq %r13, 288(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 296(%rsp)
 jne .Lx_fp_fail
 leaq 9(%r12), %r13
 cmpq %r13, 304(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 312(%rsp)
 jne .Lx_fp_fail
 leaq 10(%r12), %r13
 cmpq %r13, 320(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 328(%rsp)
 jne .Lx_fp_fail
 leaq 11(%r12), %r13
 cmpq %r13, 336(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 344(%rsp)
 jne .Lx_fp_fail
 leaq 12(%r12), %r13
 cmpq %r13, 352(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 360(%rsp)
 jne .Lx_fp_fail
 leaq 13(%r12), %r13
 cmpq %r13, 368(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 376(%rsp)
 jne .Lx_fp_fail
 leaq 14(%r12), %r13
 cmpq %r13, 384(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 392(%rsp)
 jne .Lx_fp_fail
 leaq 15(%r12), %r13
 cmpq %r13, 400(%rsp)
 jne .Lx_fp_fail
 cmpq %r13, 408(%rsp)
 jne .Lx_fp_fail
 fstpl 816(%rsp)
 movabsq $0x400921fb54442d18, %rax
 cmpq %rax, 816(%rsp)
 jne .Lx_fp_fail
 fstpl 824(%rsp)
 movabsq $0x3ff0000000000000, %rax
 cmpq %rax, 824(%rsp)
 jne .Lx_fp_fail
 fld1
 fldpi
 movq $19, %rax
 int $0x80
 subq %rbx, %rax
 cmpq $300, %rax
 jae .Lx_fp_pass
 decq %r15
 jnz .Lx_fp_loop
.Lx_fp_fail:
 movq $1, %r14
 jmp .Lx_fp_return
.Lx_fp_pass:
 xorq %r14, %r14
.Lx_fp_return:
 fninit
 movl $0x1f80, 804(%rsp)
 ldmxcsr 804(%rsp)
 movq $25, %rax
 movq $0x1002, %rdi
 xorq %rsi, %rsi
 int $0x80
 movq %r14, %rax
 addq $840, %rsp
 popq %r15
 popq %r14
 popq %r13
 popq %r12
 popq %rbp
 popq %rbx
 ret
.size cyxia_fp_probe,.-cyxia_fp_probe
.section .note.GNU-stack,"",@progbits
