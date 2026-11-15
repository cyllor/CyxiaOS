# Resume detached threads after self-unmapping

Continue the approved complete CyxiaOS/COSMIC plan from `0847553`. Actual
unchanged COSMIC reproducibly ends with Fault139 during EGL initialization.
Targeted diagnostics resolve the rejected PC to musl `__unmapself+7`, immediately
after successful munmap. The existing x86 resume check requires a mapped RW/NX
stack, although the next instructions only set registers and invoke SYS_exit.
This is an architecture resume compatibility defect, not evidence of an EGL
renderer fault or a thread-capacity rejection.

Permit resume with an unmapped stack pointer within the existing lower-user
address range. Keep canonical/user-range checks so IRET cannot fault in the
kernel on a noncanonical RSP. Preserve executable, nonwritable instruction
mapping and all address-space ownership, W^X, TLB, FP/TLS and dispatch checks.
Memory access permissions remain enforced by the actual hardware when user
instructions access memory. Do not remap, pin or invent a substitute stack and
do not emulate libc's exit instructions.

Use the approved actual process/ISA and musl syscall seams. First show a real
minimal C pthread regression failing: detach a worker while it is alive, release
its gate, require tgkill(tid,0) to return ESRCH after exit, repeat for reclamation,
then verify joined-thread reuse. A completion flag alone precedes libc teardown
and is insufficient. Also execute a deliberately noncanonical-RSP case: the
process must be refused without a kernel panic, and normal subsequent work must
still pass. Validate per-process and shared-object reclamation. Both runs use
source/SDK/ELF-bound receipts and the serial native lease.

After fixing, rerun the unchanged actual COSMIC ELF and original Fault139 loop;
record the next real outcome rather than claiming a complete desktop. Remove
temporary DEBUG-egl139 instrumentation, run relevant host/native regressions,
perform independent Standards/Spec reviews, and commit on V0.17. Ordinary steps
are already authorized. Preserve `.qwen/`, prior evidence and original ELF.
