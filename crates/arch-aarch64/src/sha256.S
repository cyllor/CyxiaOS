.section .text.cyxia_sha256,"ax"
.arch armv8-a+crypto
.p2align 4
.global cyxia_sha256_compress_hw
.type cyxia_sha256_compress_hw, %function

.macro CYXIA_SHA256_ROUND schedule
    ld1 {v15.4s}, [x4], #16
    add v15.4s, v15.4s, \schedule\().4s
    mov v16.16b, v0.16b
    sha256h q0, q1, v15.4s
    sha256h2 q1, q16, v15.4s
.endm

.macro CYXIA_SHA256_SCHEDULE schedule, next, third, fourth
    sha256su0 \schedule\().4s, \next\().4s
    sha256su1 \schedule\().4s, \third\().4s, \fourth\().4s
    CYXIA_SHA256_ROUND \schedule
.endm

cyxia_sha256_compress_hw:
    cbz x2, .Lsha256_return

    // Explicit bounded EL1 crypto transition. Kernel Rust remains soft-float;
    // every user-observable SIMD/FP bit and interrupt mask is restored.
    sub sp, sp, #560
    stp x29, x30, [sp, #0]
    mrs x9, daif
    str x9, [sp, #552]
    msr daifset, #15
    mrs x9, cpacr_el1
    str x9, [sp, #544]
    orr x10, x9, #0x300000
    msr cpacr_el1, x10
    isb
    mrs x9, fpcr
    str x9, [sp, #528]
    mrs x9, fpsr
    str x9, [sp, #536]
    stp q0, q1, [sp, #16]
    stp q2, q3, [sp, #48]
    stp q4, q5, [sp, #80]
    stp q6, q7, [sp, #112]
    stp q8, q9, [sp, #144]
    stp q10, q11, [sp, #176]
    stp q12, q13, [sp, #208]
    stp q14, q15, [sp, #240]
    stp q16, q17, [sp, #272]
    stp q18, q19, [sp, #304]
    stp q20, q21, [sp, #336]
    stp q22, q23, [sp, #368]
    stp q24, q25, [sp, #400]
    stp q26, q27, [sp, #432]
    stp q28, q29, [sp, #464]
    stp q30, q31, [sp, #496]

    ld1 {v0.4s}, [x0]
    add x9, x0, #16
    ld1 {v1.4s}, [x9]
    adrp x3, .Lsha256_k
    add x3, x3, :lo12:.Lsha256_k

.Lsha256_block:
    mov v2.16b, v0.16b
    mov v3.16b, v1.16b
    ld1 {v4.16b}, [x1], #16
    ld1 {v5.16b}, [x1], #16
    ld1 {v6.16b}, [x1], #16
    ld1 {v7.16b}, [x1], #16
    rev32 v4.16b, v4.16b
    rev32 v5.16b, v5.16b
    rev32 v6.16b, v6.16b
    rev32 v7.16b, v7.16b
    mov x4, x3

    CYXIA_SHA256_ROUND v4
    CYXIA_SHA256_ROUND v5
    CYXIA_SHA256_ROUND v6
    CYXIA_SHA256_ROUND v7

    CYXIA_SHA256_SCHEDULE v4, v5, v6, v7
    CYXIA_SHA256_SCHEDULE v5, v6, v7, v4
    CYXIA_SHA256_SCHEDULE v6, v7, v4, v5
    CYXIA_SHA256_SCHEDULE v7, v4, v5, v6

    CYXIA_SHA256_SCHEDULE v4, v5, v6, v7
    CYXIA_SHA256_SCHEDULE v5, v6, v7, v4
    CYXIA_SHA256_SCHEDULE v6, v7, v4, v5
    CYXIA_SHA256_SCHEDULE v7, v4, v5, v6

    CYXIA_SHA256_SCHEDULE v4, v5, v6, v7
    CYXIA_SHA256_SCHEDULE v5, v6, v7, v4
    CYXIA_SHA256_SCHEDULE v6, v7, v4, v5
    CYXIA_SHA256_SCHEDULE v7, v4, v5, v6

    add v0.4s, v0.4s, v2.4s
    add v1.4s, v1.4s, v3.4s
    subs x2, x2, #1
    b.ne .Lsha256_block

    st1 {v0.4s}, [x0]
    add x9, x0, #16
    st1 {v1.4s}, [x9]

    ldp q0, q1, [sp, #16]
    ldp q2, q3, [sp, #48]
    ldp q4, q5, [sp, #80]
    ldp q6, q7, [sp, #112]
    ldp q8, q9, [sp, #144]
    ldp q10, q11, [sp, #176]
    ldp q12, q13, [sp, #208]
    ldp q14, q15, [sp, #240]
    ldp q16, q17, [sp, #272]
    ldp q18, q19, [sp, #304]
    ldp q20, q21, [sp, #336]
    ldp q22, q23, [sp, #368]
    ldp q24, q25, [sp, #400]
    ldp q26, q27, [sp, #432]
    ldp q28, q29, [sp, #464]
    ldp q30, q31, [sp, #496]
    ldr x9, [sp, #528]
    msr fpcr, x9
    ldr x9, [sp, #536]
    msr fpsr, x9
    ldr x9, [sp, #544]
    msr cpacr_el1, x9
    isb
    ldr x9, [sp, #552]
    msr daif, x9
    ldp x29, x30, [sp, #0]
    add sp, sp, #560
.Lsha256_return:
    ret
.size cyxia_sha256_compress_hw, .-cyxia_sha256_compress_hw

.section .rodata.cyxia_sha256,"a",%progbits
.p2align 4
.Lsha256_k:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

.section .note.GNU-stack,"",%progbits
