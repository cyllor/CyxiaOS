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
//! * SETTLED / OVER_BUDGET (atomics): written by CPU0 in `metered`, read by
//!   CPU0 at the evidence seal (`publish`).

use super::{evidence, now_ns};
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_kernel_core::control_plane::policy_lock_v0199::{
    CriticalSectionMeter, OverrunClass, SectionKind,
};

static mut METER: CriticalSectionMeter = CriticalSectionMeter::new();
/// Scopes that settled within budget.
static SETTLED: AtomicU64 = AtomicU64::new(0);
/// Scopes that overran, failed to begin/settle (clock, denied, busy).
static OVER_BUDGET: AtomicU64 = AtomicU64::new(0);

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
    let within_budget = begun
        && matches!(
            with_meter(|m| m.end(now_ns())),
            Ok(s) if s.overrun_class == OverrunClass::None
        );
    let counter = if within_budget { &SETTLED } else { &OVER_BUDGET };
    counter.fetch_add(1, Ordering::Relaxed);
    out
}

/// Evidence seal: words 135..137 (CPU0, after the business CPUs stopped).
pub(super) fn publish() {
    evidence::put(evidence::W11_POLICY_LOCK_METERED, 1);
    evidence::put(
        evidence::W11_CRITICAL_SECTIONS,
        SETTLED.load(Ordering::Relaxed),
    );
    evidence::put(
        evidence::W11_OVER_BUDGET,
        OVER_BUDGET.load(Ordering::Relaxed),
    );
}
