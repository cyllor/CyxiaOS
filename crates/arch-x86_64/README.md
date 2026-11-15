# x86 CPU state invariants

All three BSP/AP bootstrap paths run with interrupts disabled, retain firmware
MTRR/PAT memory types, load a fresh CR3, flush caches with WBINVD and clear CR0
CD/NW before the serializing paging-enable write. An AP must not retain INIT's
cache-disabled state. Device pages still select UC through their page mappings.
CR0.NE is set on every CPU so x87 errors use the native exception path, rather
than the legacy FERR/IRQ13 path that this APIC-based kernel does not admit.

The runtime saves x87/MMX/XMM0–15 and MXCSR before entering Rust from a user
trap, restores the kernel bank for handlers, and preserves interrupted kernel FP
state separately. OSXSAVE/FSGSBASE/PKE and EFER.FFXSR remain disabled; FFXSR would
otherwise omit the XMM bank at CPL0.

Signal restoration rejects reserved MXCSR bits and retains the original
processor-supplied MXCSR_MASK. User signal bytes cannot expand that mask, even
across consecutive restores or a cloned thread. Clone owns a separate full FP
bank and changes only the admitted child stack, TLS and return value.

References: Intel SDM volume 3, cache enabling/control; volume 1 section 11.6.6,
MXCSR restoration; AMD64 APM volume 4, FXSAVE/FXRSTOR and EFER.FFXSR.
