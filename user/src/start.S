.section .text.start,"ax"
.global _start
_start:
 // Loader supplies argc in x0 and argv in x1; stack is 16-byte aligned.
 bl main
 bl _exit
1: b 1b
