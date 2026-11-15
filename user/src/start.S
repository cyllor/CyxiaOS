.section .text.start,"ax"
.global _start
_start:
#if defined(__aarch64__)
 // Loader supplies argc in x0 and argv in x1; stack is 16-byte aligned.
 bl main
 bl _exit
1: b 1b
#elif defined(__x86_64__)
 // NativeOs supplies argc/argv in RDI/RSI, with a private user stack.
 andq $-16, %rsp
 call main
 movq %rax, %rdi
 call _exit
 ud2
#else
#error Unsupported CyxiaOS native entry architecture
#endif
