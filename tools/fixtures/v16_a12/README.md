# Public parser fixtures

These two numeric diagnostic banks come from node1 of the retained C4 `c4-fast-02` run. They contain request/object IDs, times and counters, with no private identity material or task payload.

They test parsing and cross-record rejection only. No ELF, QEMU, TLS, disk provenance or native PASS is supplied by these small fixtures. The complete native verdict requires the caller-selected build, source, formatter, QEMU and original raw capture.
