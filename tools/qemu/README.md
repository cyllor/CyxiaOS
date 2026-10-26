# CyxiaOS pinned QEMU 10.2.2

The native prototype separates two clocks:

- `CNT[P]CT_EL0`: shared monotonic time for deadlines, leases and aligned 100 ms windows;
- `PMCCNTR_EL0`: actual execution debit of the current vCPU.

Upstream QEMU system emulation derives PMCCNTR from the global virtual clock.
That makes one vCPU pay for time spent running sibling vCPUs. The pinned patch
uses the MTTCG vCPU thread CPU clock as the 1 GHz PMU source while retaining the
upstream monotonic timer. The native runner must therefore use
`-accel tcg,thread=multi` and the exact binary hash recorded in the build
manifest. This is an accounting correction, not a larger budget or a different
monotonic clock profile.

Upstream tag: `v10.2.2` (`f8ed81651e61d9c2166df6121ce2af0f44f06b3e`).
