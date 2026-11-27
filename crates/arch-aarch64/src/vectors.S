// The frame's first 288 bytes are the Rust ExceptionFrame ABI. The tail
// holds banked state and the custody needed for one independent nested frame.
.equ FRAME_BYTES, 512
.equ FRAME_SP_EL0, 288
.equ FRAME_SP_EL1, 296
.equ FRAME_TPIDR_EL0, 304
.equ FRAME_KIND, 312
.equ FRAME_SCRATCH, 320
.equ FRAME_PRIOR_BASE, 328
.equ SCRATCH_BUSY, 352
.equ SCRATCH_DEPTH, 360
.equ SCRATCH_EXEC_BASE, 368
.equ SCRATCH_ACTIVE_BASE, 384
.equ SCRATCH_FATAL_STATE, 400
.equ SCRATCH_FATAL_KIND, 408
.equ SCRATCH_FATAL_SP, 416
.equ SCRATCH_FATAL_ELR, 424
.equ SCRATCH_FATAL_FAR, 440

.section .text.vectors,"ax"
.balign 2048
.global exception_vectors
exception_vectors:
.macro slot kind
 b vector_\kind
 .balign 128
.endm
.irp kind, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
 slot \kind
.endr

// The bootstrap publishes a bounded logical CPU slot in CONTEXTIDR_EL1
// before writing VBAR. This avoids assuming MPIDR.Aff0 equals the slot.
// Before checking SP, the only data stores are to that CPU's scratch page.
.macro route kind
vector_\kind:
 msr tpidr_el1, x0
 msr daifset, #15
 mrs x0, contextidr_el1
 cbz x0, .Lcpu0\@
 cmp x0, #1
 b.eq .Lcpu1\@
 cmp x0, #2
 b.eq .Lcpu2\@
 cmp x0, #3
 b.ne exception_unregistered
 ldr x0, =__exception_scratch + 3 * 4096
 b .Lscratch\@
.Lcpu0\@:
 ldr x0, =__exception_scratch
 b .Lscratch\@
.Lcpu1\@:
 ldr x0, =__exception_scratch + 4096
 b .Lscratch\@
.Lcpu2\@:
 ldr x0, =__exception_scratch + 2 * 4096
.Lscratch\@:
 str x1, [x0, #8]
 ldr x1, [x0, #SCRATCH_BUSY]
 cbnz x1, .Lbusy\@
 mov x1, #1
 str x1, [x0, #SCRATCH_BUSY]
 mrs x1, tpidr_el1
 str x1, [x0]
 mrs x1, contextidr_el1
 msr tpidr_el1, x1
 mov x1, #\kind
 b exception_entry
.Lbusy\@:
 mov x1, #\kind
 b exception_busy
.endm
.irp kind, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
 route \kind
.endr

exception_entry:
 stp x2, x3, [x0, #16]
 stp x4, x5, [x0, #32]
 stp x6, x7, [x0, #48]
 stp x8, x9, [x0, #64]
 stp x10, x11, [x0, #80]
 stp x12, x13, [x0, #96]
 stp x14, x15, [x0, #112]
 stp x16, x17, [x0, #128]
 stp x18, x19, [x0, #144]
 stp x20, x21, [x0, #160]
 stp x22, x23, [x0, #176]
 stp x24, x25, [x0, #192]
 stp x26, x27, [x0, #208]
 stp x28, x29, [x0, #224]
 str x30, [x0, #240]
 mrs x2, elr_el1
 mrs x3, spsr_el1
 stp x2, x3, [x0, #248]
 mrs x2, esr_el1
 mrs x3, far_el1
 stp x2, x3, [x0, #264]
 str xzr, [x0, #280]
 mrs x2, sp_el0
 mov x3, sp
 stp x2, x3, [x0, #FRAME_SP_EL0]
 mrs x2, tpidr_el0
 stp x2, x1, [x0, #FRAME_TPIDR_EL0]

 ldr x2, =EXCEPTION_ADMISSION_CLOSED
 ldar x2, [x2]
 cbnz x2, exception_emergency
 // Only current-EL SP_EL1 and lower AArch64 sync/IRQ may dispatch.
 cmp x1, #4
 b.lo exception_emergency
 cmp x1, #10
 b.hs exception_emergency
 cmp x1, #6
 b.eq exception_emergency
 cmp x1, #7
 b.eq exception_emergency

 ldr x2, [x0, #SCRATCH_DEPTH]
 cbz x2, exception_outer
 cmp x2, #1
 b.ne exception_emergency
 cmp x1, #4
 b.ne exception_emergency
 // A nested sync frame must fit strictly below the outer frame.
 ldp x4, x5, [x0, #SCRATCH_ACTIVE_BASE]
 b exception_check_sp
exception_outer:
 ldp x4, x5, [x0, #SCRATCH_EXEC_BASE]
exception_check_sp:
 tst x3, #15
 b.ne exception_emergency
 cmp x3, x5
 b.hi exception_emergency
 add x6, x4, #FRAME_BYTES
 cmp x3, x6
 b.lo exception_emergency
 // A guard access can fault while SP itself is still within bounds.
 cmp x1, #4
 b.ne exception_select_stack
 ldr x6, [x0, #264]
 lsr x7, x6, #26
 cmp x7, #0x26                 // SP alignment fault
 b.eq exception_emergency
 cmp x7, #0x25                 // Current-EL data abort
 b.ne exception_select_stack
 tbnz x6, #10, exception_select_stack   // FAR not valid
 ldr x6, [x0, #272]
 sub x7, x4, #1, lsl #12
 cmp x6, x7
 b.lo exception_select_stack
 cmp x6, x4
 b.hs exception_select_stack
.if {legacy_guard_probe}
 // The retired CPU0 page-table sanity probe has one exact expected fault.
 ldr x7, =__stack_guard
 cmp x6, x7
 b.ne exception_emergency
 ldr x6, [x0, #248]
 ldr x7, =probe_read_fault
 cmp x6, x7
 b.eq exception_select_stack
.endif
 b exception_emergency

exception_select_stack:
 cmp x1, #5
 b.eq exception_irq_stack
 cmp x1, #9
 b.ne exception_use_stack
exception_irq_stack:
 // There is no nested IRQ entry. Recoverable sync nesting on this stack
 // uses the active bounds recorded below, including the outer frame base.
 ldr x4, =__exception_stacks
 mrs x5, contextidr_el1
 add x4, x4, x5, lsl #15
 add x4, x4, #1, lsl #12
 add x3, x4, #4, lsl #12
exception_use_stack:
 sub x6, x3, #FRAME_BYTES
 // Transplant the complete, integer-only architectural snapshot. Neither
 // the exec stack nor the IRQ stack is touched before the checks above.
 .set copied, 0
 .rept 20
 ldp x7, x8, [x0, #copied]
 stp x7, x8, [x6, #copied]
 .set copied, copied + 16
 .endr
 str x0, [x6, #FRAME_SCRATCH]
 ldp x7, x8, [x0, #SCRATCH_ACTIVE_BASE]
 stp x7, x8, [x6, #FRAME_PRIOR_BASE]
 add x2, x2, #1
 str x2, [x0, #SCRATCH_DEPTH]
 stp x4, x6, [x0, #SCRATCH_ACTIVE_BASE]
 mov sp, x6
 str xzr, [x0, #SCRATCH_BUSY]
 mov x0, sp
 bl exception_dispatch

 // Restore interrupted SP even when dispatch used the IRQ stack and
 // deliberately selected the suspended EL1 caller as its return target.
 mov x30, sp
 ldr x0, [x30, #FRAME_SCRATCH]
 mov x2, #1
 str x2, [x0, #SCRATCH_BUSY]
 ldr x2, =EXCEPTION_ADMISSION_CLOSED
 ldar x2, [x2]
 ldr x1, [x30, #FRAME_KIND]
 cbnz x2, exception_emergency
 ldp x2, x3, [x30, #248]
 and x4, x3, #0x1f
 cbz x4, exception_restore_user
 cmp x4, #5
 b.ne exception_emergency
 b exception_restore_status
exception_restore_user:
 bic x3, x3, #0x200000       // Clear single-step state on EL0 return.
exception_restore_status:
 msr elr_el1, x2
 msr spsr_el1, x3
 ldp x2, x3, [x30, #FRAME_SP_EL0]
 msr sp_el0, x2
 ldr x2, [x30, #FRAME_TPIDR_EL0]
 msr tpidr_el0, x2
 ldp x7, x8, [x30, #FRAME_PRIOR_BASE]
 stp x7, x8, [x0, #SCRATCH_ACTIVE_BASE]
 ldr x2, [x0, #SCRATCH_DEPTH]
 sub x2, x2, #1
 str x2, [x0, #SCRATCH_DEPTH]
 mov sp, x3
 ldp x2, x3, [x30, #16]
 ldp x4, x5, [x30, #32]
 ldp x6, x7, [x30, #48]
 ldp x8, x9, [x30, #64]
 ldp x10, x11, [x30, #80]
 ldp x12, x13, [x30, #96]
 ldp x14, x15, [x30, #112]
 ldp x16, x17, [x30, #128]
 ldp x18, x19, [x30, #144]
 ldp x20, x21, [x30, #160]
 ldp x22, x23, [x30, #176]
 ldp x24, x25, [x30, #192]
 ldp x26, x27, [x30, #208]
 ldp x28, x29, [x30, #224]
 str xzr, [x0, #SCRATCH_BUSY]
 ldp x0, x1, [x30]
 ldr x30, [x30, #240]
 eret

exception_busy:
 // A fault during scratch transfer is terminal. A second exception on
 // the emergency path only marks the incomplete record and stops.
 ldr x2, [x0, #SCRATCH_FATAL_STATE]
 cbz x2, exception_emergency
 mov x2, #3
 str x2, [x0, #SCRATCH_FATAL_STATE]
 b exception_close_admission
exception_emergency:
 mov x2, #1
 str x2, [x0, #SCRATCH_FATAL_STATE]
 mov x3, sp
 cmp x1, #4
 b.hs 1f
 mrs x3, sp_el0
1:
 mrs x2, contextidr_el1
 msr tpidr_el1, x2
 ldr x4, =__exception_stacks
 add x4, x4, x2, lsl #15
 add x4, x4, #8, lsl #12
 msr spsel, #1
 mov sp, x4
 ldr x5, =EXCEPTION_ADMISSION_CLOSED
 mov x4, #1
 stlr x4, [x5]
 str x1, [x0, #SCRATCH_FATAL_KIND]
 str x3, [x0, #SCRATCH_FATAL_SP]
 mrs x2, elr_el1
 mrs x3, esr_el1
 stp x2, x3, [x0, #SCRATCH_FATAL_ELR]
 mrs x2, far_el1
 str x2, [x0, #SCRATCH_FATAL_FAR]
 add x2, x0, #SCRATCH_FATAL_STATE
 mov x3, #2
 stlr x3, [x2]
 b exception_stop
exception_unregistered:
 // No trusted scratch address for this CPU. Publish closure only.
exception_close_admission:
 ldr x0, =EXCEPTION_ADMISSION_CLOSED
 mov x1, #1
 stlr x1, [x0]
exception_stop:
 msr daifset, #15
 dsb ishst
 sev
1: wfe
 b 1b

// x0: firmware-verified logical slot, x1/x2: usable exec stack base/top.
// The bootstrap uses this before VBAR on both primary and secondary CPUs.
.global exception_register_stack
exception_register_stack:
 cmp x0, #4
 b.hs exception_unregistered
 msr contextidr_el1, x0
 ldr x3, =__exception_scratch
 add x3, x3, x0, lsl #12
 stp x1, x2, [x3, #SCRATCH_EXEC_BASE]
 ret
.ltorg

.global probe_read
probe_read:
.global probe_read_fault
probe_read_fault:
ldr x1, [x0]
ret
.global probe_write
probe_write:
.global probe_write_fault
probe_write_fault:
str xzr, [x0]
ret
.global irq_register_probe
irq_register_probe:
 stp x19, x20, [sp, #-32]!
 str x30, [sp, #16]
 mov x19, #0x1973
 mov x20, #0x2047
 mov x9, #0x9123
 mov x10, #0xa321
 wfi
 mov x11, #0x1973
 cmp x19, x11
 b.ne 1f
 mov x11, #0x2047
 cmp x20, x11
 b.ne 1f
 mov x11, #0x9123
 cmp x9, x11
 b.ne 1f
 mov x11, #0xa321
 cmp x10, x11
 b.ne 1f
 mov x0, #1
 b 2f
1: mov x0, #0
2: ldr x30, [sp, #16]
 ldp x19, x20, [sp], #32
 ret
