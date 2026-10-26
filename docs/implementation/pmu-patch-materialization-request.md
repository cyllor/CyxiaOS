# Native replay CPU-clock repair request

This marker triggers the bounded workflow that replaces exactly three stale `Prefix.start` initializers with the real per-vCPU PMU clock, then builds both exact unified AArch64 node images before committing the source repair.

Attempt: 1 — repair the compile-time field mismatch without falling back to the shared monotonic wall clock.
