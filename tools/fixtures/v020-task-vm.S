// ABI3 workload for the independently signed business package.
// Each assertion leaves its phase and observed result in the parent stack.

.equ ENTRY_BYTES, 40
.equ TASK_INFO_BYTES, 48
.equ VM_REPLY_BYTES, 32
.equ PROBE_BYTES, 128
.equ E_AUTH, -1
.equ E_STALE, -4
.equ E_CONFLICT, -5
.equ E_TIMEOUT, -6
.equ E_AGAIN, -13
.equ CHILD_EXIT, 37
.equ PAGE_BYTES, 4096

.macro call number
    mov x8, #\number
    svc #0
.endm

.macro zero_args
    mov x0, xzr
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
.endm

.macro retry_call number
    sub sp, sp, #48
    stp x0, x1, [sp]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    mov x28, #4096
1:
    ldp x0, x1, [sp]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    call \number
    cmp x0, #E_AGAIN
    b.ne 2f
    subs x28, x28, #1
    b.eq 2f
    zero_args
    call 0x02
    b 1b
2:
    add sp, sp, #48
.endm

.macro phase number
    mov x29, #\number
    str x29, [x19, #8]
.endm

.macro expect result
    mov x9, #\result
    cmp x0, x9
    b.ne .Lfailed
.endm

.macro spawn_args
    mov x0, x20
    mov x1, sp
    mov x2, #40
    add x3, sp, #48
    mov x4, #TASK_INFO_BYTES
    mov x5, xzr
.endm

.macro join_args
    mov x0, x24
    mov x1, x25
    mov x2, xzr
    add x3, sp, #48
    mov x4, #TASK_INFO_BYTES
    mov x5, xzr
.endm

.macro reserve_args request
    mov x0, xzr
    mov x1, #PAGE_BYTES
    mov x2, #1
    mov x3, #\request
    add x4, sp, #96
    mov x5, #VM_REPLY_BYTES
.endm

.macro map_args access, request
    mov x0, x22
    mov x1, x21
    mov x2, xzr
    mov x3, #\access
    mov x4, #\request
    mov x5, xzr
.endm

.macro unmap_args request
    mov x0, x22
    mov x1, xzr
    mov x2, #PAGE_BYTES
    mov x3, #\request
    mov x4, xzr
    mov x5, xzr
.endm

.text
.p2align 2
.global _start
_start:
    cmp x1, #8
    b.eq .Lchild
    cmp x1, #ENTRY_BYTES
    b.ne .Lidle

    // Fixed physical location relative to the top of the parent stack.
    sub x19, sp, #PROBE_BYTES
    sub sp, sp, #512
    adr x9, .Lprobe_tag
    ldr x9, [x9]
    str x9, [x19]
    phase 1
    ldr x9, [x0]
    adr x10, .Lentry_tag
    ldr x10, [x10]
    cmp x9, x10
    b.ne .Lfailed
    ldr w26, [x0, #8]          // Signed task group.
    ldr x27, [x0, #16]         // Signed package ID.
    ldp x20, x21, [x0, #24]    // Spawn selector and owned page set selector.

    // The child receives exactly the copied marker on its own stack.
    str x27, [sp]
    str w26, [sp, #8]
    str wzr, [sp, #12]
    mov x10, #1
    str x10, [sp, #16]
    mov w10, #8
    str w10, [sp, #24]
    str wzr, [sp, #28]
    adr x10, .Lchild_tag
    ldr x10, [x10]
    str x10, [sp, #32]

    phase 2
    add w10, w26, #1
    str w10, [sp, #8]
    spawn_args
    call 0x10
    expect E_AUTH
    ldp x10, x11, [sp, #48]
    orr x0, x10, x11
    expect 0
    str w26, [sp, #8]

    phase 3
    spawn_args
    retry_call 0x10
    expect 0
    ldp x24, x25, [sp, #48]
    cbz x24, .Lfailed
    cbz x25, .Lfailed
    stp x24, x25, [x19, #24]
    ldr w0, [sp, #80]
    expect 2
    ldr x0, [sp, #88]
    expect 1

    phase 4
    spawn_args
    call 0x10
    expect 0
    ldp x10, x11, [sp, #48]
    cmp x24, x10
    b.ne .Lfailed
    cmp x25, x11
    b.ne .Lfailed
    str xzr, [sp, #32]
    spawn_args
    call 0x10
    expect E_CONFLICT

    phase 5
    join_args
    add x1, x1, #1
    call 0x13
    expect E_STALE

    phase 6
    zero_args
    call 0x04                  // Bound the join loop by guest monotonic time.
    mov x27, #2
    lsl x27, x27, #30
    add x27, x0, x27
.Ljoin:
    join_args
    call 0x13
    cbz x0, .Ljoined
    expect E_TIMEOUT
    zero_args
    call 0x04
    cmp x0, x27
    b.hs .Lfailed
    zero_args
    call 0x02
    b .Ljoin
.Ljoined:
    ldrh w0, [sp, #68]
    expect 8
    ldr w0, [sp, #72]
    expect CHILD_EXIT
    str x0, [x19, #40]
    join_args
    call 0x13
    expect 0
    ldr w0, [sp, #72]
    expect CHILD_EXIT

    phase 7
    reserve_args 101
    retry_call 0x20
    expect 0
    ldp x22, x23, [sp, #96]
    ldr x0, [sp, #112]
    expect PAGE_BYTES
    cbz x22, .Lfailed
    cbz x23, .Lfailed
    stp x22, x23, [x19, #48]

    phase 8
    map_args 2, 102
    mov x10, #1
    add x1, x1, x10, lsl #32
    call 0x21
    expect E_STALE
    map_args 2, 102
    retry_call 0x21
    expect 0
    ldr x0, [x23]
    expect 0
    adr x10, .Lpage_marker
    ldr x10, [x10]
    str x10, [x23]
    ldr x0, [x23]
    cmp x0, x10
    b.ne .Lfailed
    str x0, [x19, #64]

    phase 9
    unmap_args 103
    retry_call 0x22
    expect 0
    unmap_args 103
    call 0x22
    expect 0

    phase 10
    reserve_args 104
    mov x0, x23               // Reuse the VA only after the original unmap.
    retry_call 0x20
    expect 0
    ldp x22, x23, [sp, #96]
    ldr x10, [x19, #56]
    cmp x23, x10
    b.ne .Lfailed
    ldr x0, [x23]             // Admitted anonymous page, populated on demand.
    expect 0
    adr x10, .Lanon_marker
    ldr x10, [x10]
    str x10, [x23]
    ldr x0, [x23]
    cmp x0, x10
    b.ne .Lfailed
    str x0, [x19, #80]
    unmap_args 105
    retry_call 0x22
    expect 0

    phase 11
    // Ordinary business tasks cannot use their spawn cap to report a plan.
    mov x0, x20
    mov x1, sp
    mov x2, #100
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    call 0x43
    expect E_AUTH
    phase 12
    b .Lidle

.Lfailed:
    str x0, [x19, #16]
    mov x10, #1
    str x10, [x19, #72]
    b .Lidle

.Lchild:
    ldr x9, [x0]
    adr x10, .Lchild_tag
    ldr x10, [x10]
    cmp x9, x10
    b.ne .Lchild_bad_args
    zero_args
    mov x0, #CHILD_EXIT
    call 0x01
.Lchild_bad_args:
    zero_args
    mov x0, #1
    call 0x01

.Lidle:
    zero_args
    call 0x02
    b .Lidle

.p2align 3
.Lprobe_tag:
    .ascii "CYXTVM01"
.Lentry_tag:
    .ascii "CYXTASK1"
.Lchild_tag:
    .ascii "CYXCHILD"
.Lpage_marker:
    .ascii "CYXFRAME"
.Lanon_marker:
    .ascii "CYXANON1"
