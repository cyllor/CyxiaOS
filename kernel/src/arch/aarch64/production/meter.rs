//! V0.20 wave 11: diagnostic timing of the in-vector 0x50 register / 0x41
//! publish bridge calls in the production boot.
//!
//! HONEST SCOPE: timing only. Every completed bridge call is observed, even
//! after an overrun. This is not a policy_lock, a new-work admission gate,
//! an IRQ-off measurement, or a CPU0 whole-window ledger (G1/G09).
//! The independent CriticalSectionMeter admission fault is not cleared or
//! bypassed here; this diagnostic wrapper has never authorized new work.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF):
//! OBSERVATIONS is touched only by the CPU0-only, non-reentrant in-vector
//! bridge wrapper and by CPU0 at the evidence seal. The mutable reference
//! exists only inside one synchronous closure and never spans the bridge.

use super::{evidence, now_ns, report};
use cyxia_kernel_core::control_plane::policy_lock_v0199::{
    CompletedSectionObservations, SectionKind,
};

static mut OBSERVATIONS: CompletedSectionObservations = CompletedSectionObservations::new();

fn with_observations<R>(f: impl FnOnce(&mut CompletedSectionObservations) -> R) -> R {
    // SAFETY: CPU0-only, non-reentrant; see module boundary registration.
    f(unsafe { &mut *core::ptr::addr_of_mut!(OBSERVATIONS) })
}

/// Observe the whole synchronous bridge call, preserving its exact result.
/// A regressing clock records an unmeasured attempt; it never invents time.
pub(super) fn metered<T>(f: impl FnOnce() -> T) -> T {
    let start_ns = now_ns();
    let out = f();
    let end_ns = now_ns();
    with_observations(|m| m.record(SectionKind::EffectiveWork, start_ns, end_ns));
    out
}

/// Publish measured overruns separately from unmeasured clock samples.
pub(super) fn publish() {
    let ((in_budget, overruns, unmeasured), max_elapsed_ns) =
        with_observations(|m| (m.counts(), m.max_elapsed_ns()));
    evidence::put(evidence::W11_POLICY_LOCK_METERED, 1);
    evidence::put(evidence::W11_POLICY_LOCK_SETTLED_IN_BUDGET, in_budget);
    evidence::put(
        evidence::W11_POLICY_LOCK_OVERRUN_OR_UNMEASURED,
        overruns.saturating_add(unmeasured),
    );
    evidence::put(evidence::W11_POLICY_LOCK_MEASURED_OVERRUNS, overruns);
    evidence::put(evidence::W11_POLICY_LOCK_MAX_ELAPSED_NS, max_elapsed_ns);
    report(
        "V020_W11_POLICY_LOCK_METER",
        in_budget,
        overruns,
        unmeasured,
    );
}
