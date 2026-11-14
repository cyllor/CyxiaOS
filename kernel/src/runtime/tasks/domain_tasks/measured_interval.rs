//! Shared production seam for projecting actual per-vCPU execution onto its
//! observed shared-monotonic closing endpoint. No credit or label authority.
#[inline]
pub fn finish(
    cpu_elapsed: impl FnOnce() -> u64,
    shared_now: impl FnOnce() -> u64,
) -> (u64, u64, u64) {
    // The CPU delta must close before its shared-time endpoint. Sampling the
    // shared clock first would project execution performed by the later CPU
    // sample backward from an endpoint that predates that execution.
    let actual_ns = cpu_elapsed();
    let finished_ns = shared_now();
    (
        finished_ns.saturating_sub(actual_ns),
        finished_ns,
        actual_ns,
    )
}
