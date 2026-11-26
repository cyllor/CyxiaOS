//! V0.20 wave 11: policy_lock critical-section METERING of the in-vector
//! 0x50 register / 0x41 publish bridge calls in the production boot.
//!
//! HONEST SCOPE: metering only. A `CriticalSectionMeter` (EffectiveWork, budget
//! `WORK_BUDGET_NS`) measures the wall time of each bridge call with the
//! architectural timer. IRQ-off enforcement and a production policy_lock
//! object are NOT done here (G1); nothing is masked or locked by this module.
//! `full_authority=false`.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * METER (static mut CriticalSectionMeter): const-initialized. Touched ONLY
//!   by `with_meter`, whose callers (`metered`) run only from the in-vector
//!   0x50 / 0x41 dispatch arms, both of which return before the bridge call
//!   unless `cpu == 0`, and never re-entrantly (the bridge call does not
//!   dispatch). The `&mut` lives only inside one synchronous closure; no safe
//!   fn returns a reference to it.
//! * ATTEMPTS / MAX_ELAPSED_NS (atomics): written by CPU0 in `metered`,
//!   read by CPU0 at the evidence seal (`publish`).

use super::{evidence, now_ns, report};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_kernel_core::control_plane::policy_lock_v0199::{CriticalSectionMeter, SectionKind};

static mut METER: CriticalSectionMeter = CriticalSectionMeter::new();
static ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static MAX_ELAPSED_NS: AtomicU64 = AtomicU64::new(0);

/// Run `f` with the scoped meter. The reference never escapes the closure.
fn with_meter<R>(f: impl FnOnce(&mut CriticalSectionMeter) -> R) -> R {
    // SAFETY: see the METER registration in the module header (CPU0-only,
    // non-reentrant, reference confined to this call).
    f(unsafe { &mut *core::ptr::addr_of_mut!(METER) })
}

/// Meter `f` as one EffectiveWork critical section. `f`'s result is passed
/// through unchanged; a failed begin/settle or an overrun is counted (word
/// 137) but never alters or suppresses the result.
pub(super) fn metered<T>(f: impl FnOnce() -> T) -> T {
    let begun = with_meter(|m| m.begin(SectionKind::EffectiveWork, now_ns())).is_ok();
    let out = f();
    if begun && let Ok(settlement) = with_meter(|m| m.end(now_ns())) {
        MAX_ELAPSED_NS.fetch_max(settlement.elapsed_ns, Ordering::Relaxed);
    }
    ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    out
}

/// Publish measured overruns separately from attempts denied by the latch.
pub(super) fn publish() {
    let (settled, overruns) = with_meter(|m| (m.settled_count(), m.overrun_count()));
    let in_budget = settled - overruns;
    let unmeasured = ATTEMPTS.load(Ordering::Relaxed) - settled;
    evidence::put(evidence::W11_POLICY_LOCK_METERED, 1);
    evidence::put(evidence::W11_POLICY_LOCK_SETTLED_IN_BUDGET, in_budget);
    evidence::put(
        evidence::W11_POLICY_LOCK_OVERRUN_OR_UNMEASURED,
        overruns + unmeasured,
    );
    evidence::put(evidence::W11_POLICY_LOCK_MEASURED_OVERRUNS, overruns);
    evidence::put(
        evidence::W11_POLICY_LOCK_MAX_ELAPSED_NS,
        MAX_ELAPSED_NS.load(Ordering::Relaxed),
    );
    report(
        "V020_W11_POLICY_LOCK_METER",
        in_budget,
        overruns,
        unmeasured,
    );
}
