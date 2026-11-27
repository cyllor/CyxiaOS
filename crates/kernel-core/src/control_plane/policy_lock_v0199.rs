//! Critical-section budget metering and lock-order scaffolding for the G1
//! lock-chain freeze (V0.19.9 implementation spec §3.2).
//!
//! Baseline: `docs/design/baselines/v0.19.9-implementation-spec.txt`
//! - L1530-1532: lock order 注册表→核心/资源账本→policy_lock→任务→CPU ID
//!   升序运行队列→地址空间→页元数据→端点/设备队列; short critical sections
//!   use try_lock(acquire/release), never wait under IRQ-off or while holding
//!   another lock; failure releases in reverse order and restores IRQ.
//! - L1534: policy_lock only copies bounded fields / swaps the root; no
//!   allocation, IPC, waiting or device operations inside.
//! - L1542: policy_lock single-hold effective work ≤45μs and the whole local
//!   IRQ-mask→restore interval ≤50μs; overrun is diagnosed and new
//!   optimizations are closed, references are never force-released.
//! - L1546-1548: one continuous IRQ-off interval's acquisition attempts,
//!   lock-order checks, releases, barriers and IRQ restore overhead total
//!   ≤5μs; effective held work totals ≤45μs; measured DAIF-mask→restore total
//!   ≤50μs. Single/multiple locks share ONE interval budget.
//! - L1550: failure releases in reverse order, restores IRQ, yields after at
//!   most 4 independent attempt intervals.
//! - L1552: a holder anomaly/overrun never force-unlocks; new admission is
//!   closed; fail-stop if ledger consistency cannot be proven.
//! - L1554: at most 8 actual locks per continuous IRQ-off interval; lock-order
//!   levels are not a stackable quota.
//! - L1556-1558: G1 must freeze the lock-chain call graph, maximum depth and
//!   the worst-case instruction/path metering scheme; the design 5μs is NOT a
//!   measured guarantee.
//! - L5031: 45+5≤50μs remains mandatory metering. L7340: `lock_work_max_us`
//!   = 45 (fixed prototype configuration).
//!
//! Historical note: the v1.3-era contract carried a single 50μs policy_lock
//! cap (`docs/superpowers/plans/2026-10-30-native-progress.md` L17); V0.19.9
//! splits it into ≤45μs effective work plus ≤5μs acquisition overhead inside
//! a ≤50μs total IRQ-off interval.
//!
//! SCOPE — this module is the MEASUREMENT/ENFORCEMENT SCAFFOLDING the G1
//! freeze will use. It is NOT the freeze itself and does NOT claim it:
//! - The production `policy_lock` object, the DAIF mask/restore enforcement
//!   points, the try_lock machinery and the frozen lock-chain call graph with
//!   its worst-case metering scheme remain the freeze's deliverables.
//! - Timestamps are caller-supplied monotonic nanoseconds (the same trust
//!   model as [`super::role_budget_v0199`]); this ledger records observations,
//!   it does not read a hardware counter and does not certify the design 5μs.
//! - An overrun latches a sticky fault and closes new metered admission
//!   (fail-closed, L1552). There is deliberately NO reset/clear API: clearing
//!   a fault is a recovery/rebuild decision outside this scaffold, mirroring
//!   the role budget's rule that a new window never clears an execution fault.
use super::Error;

/// Effective held work budget per interval: ≤45μs (spec L1542, L1548, L7340).
pub const WORK_BUDGET_NS: u64 = 45_000;
/// Whole local IRQ-mask→restore interval budget: ≤50μs (spec L1542, L1548).
pub const IRQ_OFF_BUDGET_NS: u64 = 50_000;
/// Acquisition/order-check/release/barrier/IRQ-restore overhead budget per
/// continuous IRQ-off interval: ≤5μs (spec L1546). 45+5≤50 is mandatory
/// metering (spec L5031), not a measured guarantee (spec L1558).
pub const ACQUISITION_BUDGET_NS: u64 = 5_000;
/// At most 8 actual locks per continuous IRQ-off interval (spec L1554).
pub const MAX_LOCKS_PER_IRQ_OFF: usize = 8;
/// At most 4 independent attempt intervals before yielding (spec L1550:
/// "最多 4 个独立尝试区间后让出并在外层绝对截止内重试").
///
/// ENFORCEMENT IS A G1-FREEZE DELIVERABLE, not this scaffold's. The quota
/// bounds the try_lock *retry loop*: after ≤4 independent failed attempt
/// intervals the acquirer yields and retries within an outer absolute
/// deadline. That loop — try-failure accounting, yield, and the outer
/// deadline — lives in the production try_lock machinery the freeze will
/// build (see the module SCOPE note). This meter only measures time scopes
/// (`begin`/`end`) and records acquisitions against the lock order
/// (`record_acquire`); a settled scope is a measurement, not a failed
/// attempt, so there is no honest place to enforce the quota here without
/// inventing semantics the baseline does not specify. The constant is kept
/// as the frozen quota value the freeze binds to; `max_try_intervals_*`
/// tests pin its value and source.
pub const MAX_TRY_INTERVALS: usize = 4;

/// Which measurement scope a begin/end interval represents. The G1 freeze
/// instrumentation opens these scopes around the real enforcement points;
/// single and multiple locks share one interval budget (spec L1548), so the
/// caller aggregates work/overhead across the locks of one IRQ-off interval
/// before settling the corresponding scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    /// Effective held work (policy_lock copy/root-swap and other bounded
    /// critical-section work), budget [`WORK_BUDGET_NS`].
    EffectiveWork,
    /// Whole continuous IRQ-off interval, DAIF mask→restore, budget
    /// [`IRQ_OFF_BUDGET_NS`].
    IrqOffInterval,
    /// Acquisition attempts, lock-order checks, releases, barriers and IRQ
    /// restore overhead, budget [`ACQUISITION_BUDGET_NS`].
    AcquisitionOverhead,
}
impl SectionKind {
    pub const fn budget_ns(self) -> u64 {
        match self {
            Self::EffectiveWork => WORK_BUDGET_NS,
            Self::IrqOffInterval => IRQ_OFF_BUDGET_NS,
            Self::AcquisitionOverhead => ACQUISITION_BUDGET_NS,
        }
    }
    pub const fn overrun_class(self) -> OverrunClass {
        match self {
            Self::EffectiveWork => OverrunClass::Work,
            Self::IrqOffInterval => OverrunClass::IrqOff,
            Self::AcquisitionOverhead => OverrunClass::Acquisition,
        }
    }
}

/// Diagnostic verdict of a settled interval. `None` means within budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverrunClass {
    None,
    Work,
    IrqOff,
    Acquisition,
}

/// Receipt of one settled measurement scope. An overrun is reported here AND
/// latched as a sticky [`Fault`]; settlement itself never panics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settlement {
    pub kind: SectionKind,
    pub elapsed_ns: u64,
    pub overrun_class: OverrunClass,
}

/// Sticky fail-closed fault. The first fault is retained; later violations
/// never overwrite it and no API clears it (spec L1552: close new admission).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// A settled interval exceeded its scope budget (spec L1542/L1546/L1548).
    BudgetOverrun {
        kind: SectionKind,
        elapsed_ns: u64,
        budget_ns: u64,
    },
    /// An acquisition would violate the declared lock order (spec L1530).
    /// `blocking` is the highest held rank that forbids `next`.
    LockOrderViolation { next: LockRank, blocking: LockRank },
    /// More than [`MAX_LOCKS_PER_IRQ_OFF`] actual locks in one continuous
    /// IRQ-off interval (spec L1554).
    LockCountExceeded { held: usize },
}

/// Declared global lock order (spec L1530): acquisitions must proceed in
/// strictly ascending rank; run-queue locks additionally follow ascending
/// CPU ID. This is the rank registry contract the G1 freeze will bind to the
/// real lock objects; it is a pure ordering contract, not a lock impl.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockRank {
    /// 注册表
    Registry,
    /// 核心/资源账本
    CoreResourceLedger,
    /// policy_lock
    PolicyLock,
    /// 任务
    Task,
    /// CPU ID 升序运行队列
    RunQueue,
    /// 地址空间
    AddressSpace,
    /// 页元数据
    PageMeta,
    /// 端点/设备队列
    EndpointDeviceQueue,
}

/// The declared order, low rank first (spec L1530).
pub const LOCK_ORDER: [LockRank; 8] = [
    LockRank::Registry,
    LockRank::CoreResourceLedger,
    LockRank::PolicyLock,
    LockRank::Task,
    LockRank::RunQueue,
    LockRank::AddressSpace,
    LockRank::PageMeta,
    LockRank::EndpointDeviceQueue,
];

pub const fn rank_value(rank: LockRank) -> u8 {
    rank as u8
}

/// Pure lock-order check: returns the highest held rank that forbids
/// acquiring `next` (any held rank ≥ `next`), or `None` when the acquisition
/// respects the declared order. Equal ranks are violations: the baseline
/// short critical sections are non-recursive try_lock (spec L1532).
pub fn order_violation(held: &[LockRank], next: LockRank) -> Option<LockRank> {
    held.iter()
        .copied()
        .filter(|h| rank_value(*h) >= rank_value(next))
        .max_by_key(|h| rank_value(*h))
}

/// Convenience predicate form of [`order_violation`].
pub fn acquire_respects_order(held: &[LockRank], next: LockRank) -> bool {
    order_violation(held, next).is_none()
}

/// Pure run-queue sub-order check (spec L1530 "CPU ID 升序运行队列"): returns
/// the highest held CPU ID that forbids acquiring `next_cpu`'s run-queue
/// lock, or `None` when ascending order is respected.
pub fn runqueue_cpu_order_violation(held_cpus: &[usize], next_cpu: usize) -> Option<usize> {
    held_cpus.iter().copied().filter(|c| *c >= next_cpu).max()
}

/// Completed interval diagnostics, independent of admission and lock custody.
/// This observes work that actually ran; it never authorizes new work and
/// cannot clear a CriticalSectionMeter fault. One owner supplies sequential
/// start/end timestamps. Invalid clock samples are counted, not clamped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedSectionObservations {
    last_ns: u64,
    in_budget: u64,
    overruns: u64,
    unmeasured: u64,
    max_elapsed_ns: u64,
}

impl CompletedSectionObservations {
    pub const fn new() -> Self {
        Self {
            last_ns: 0,
            in_budget: 0,
            overruns: 0,
            unmeasured: 0,
            max_elapsed_ns: 0,
        }
    }

    pub fn record(&mut self, kind: SectionKind, start_ns: u64, end_ns: u64) {
        let valid = start_ns >= self.last_ns && end_ns >= start_ns;
        // Keep the observed high-water mark even when the interval is invalid.
        self.last_ns = self.last_ns.max(start_ns).max(end_ns);
        if !valid {
            self.unmeasured = self.unmeasured.saturating_add(1);
            return;
        }
        let elapsed_ns = end_ns - start_ns;
        self.max_elapsed_ns = self.max_elapsed_ns.max(elapsed_ns);
        if elapsed_ns > kind.budget_ns() {
            self.overruns = self.overruns.saturating_add(1);
        } else {
            self.in_budget = self.in_budget.saturating_add(1);
        }
    }

    /// In-budget, measured overruns, and unmeasured completed attempts.
    pub const fn counts(&self) -> (u64, u64, u64) {
        (self.in_budget, self.overruns, self.unmeasured)
    }

    pub const fn max_elapsed_ns(&self) -> u64 {
        self.max_elapsed_ns
    }
}

impl Default for CompletedSectionObservations {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-supplied monotonic-ns critical-section meter (role_budget_v0199
/// trust model). One active scope at a time; a bad clock retains ownership
/// instead of inventing a duration; an overrun latches a sticky fault and
/// closes new admission. No reset API exists by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriticalSectionMeter {
    active: Option<(SectionKind, u64)>,
    last_ns: u64,
    fault: Option<Fault>,
    /// Diagnostic tally of settled scopes. Uses `saturating_add` (counting
    /// discipline: spec L5826 checked counts, L7424 saturating diagnostic
    /// counts) so a pathological caller cannot wrap it. No budget or
    /// admission decision reads this counter; saturation never changes a
    /// settlement verdict. See [`Self::end`].
    settled: u64,
    /// Diagnostic tally of overrun settlements. Bounded by 1 in practice:
    /// the first overrun latches the sticky fault and closes admission, so
    /// no further scope can settle. `saturating_add` is used defensively for
    /// the same counting discipline as `settled`.
    overruns: u64,
}
impl Default for CriticalSectionMeter {
    fn default() -> Self {
        Self::new()
    }
}
impl CriticalSectionMeter {
    pub const fn new() -> Self {
        Self {
            active: None,
            last_ns: 0,
            fault: None,
            settled: 0,
            overruns: 0,
        }
    }
    /// Open a measurement scope at monotonic `now_ns`. Fail-closed: a latched
    /// fault denies new admission (spec L1552); a nested scope is Busy; a
    /// regressing clock is Clock and changes nothing.
    pub fn begin(&mut self, kind: SectionKind, now_ns: u64) -> Result<(), Error> {
        if self.fault.is_some() {
            return Err(Error::Denied);
        }
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        if now_ns < self.last_ns {
            return Err(Error::Clock);
        }
        self.active = Some((kind, now_ns));
        self.last_ns = now_ns;
        Ok(())
    }
    /// Settle the active scope at monotonic `now_ns`. The elapsed interval is
    /// charged in full to the scope's budget; an overrun is returned in the
    /// settlement AND latched as the sticky fault (first fault wins). A bad
    /// clock keeps the scope open (fail-closed) rather than clamping time.
    /// Idempotent: a second end without a new begin is Stale and changes
    /// nothing. Zero elapsed is legal and within budget.
    ///
    /// The `settled`/`overruns` tallies advance with `saturating_add` (spec
    /// L5826/L7424 counting discipline): they saturate at `u64::MAX` rather
    /// than wrap. They are diagnostic only — the budget verdict and the
    /// sticky-fault/admission logic never read them — so saturation cannot
    /// mask an overrun or admit a violation.
    pub fn end(&mut self, now_ns: u64) -> Result<Settlement, Error> {
        let (kind, start_ns) = self.active.ok_or(Error::Stale)?;
        if now_ns < self.last_ns {
            return Err(Error::Clock);
        }
        let elapsed_ns = now_ns - start_ns;
        let budget_ns = kind.budget_ns();
        let overrun_class = if elapsed_ns > budget_ns {
            kind.overrun_class()
        } else {
            OverrunClass::None
        };
        if overrun_class != OverrunClass::None {
            // Saturating diagnostic count (spec L7424); bounded by 1 in
            // practice because the sticky fault below closes admission.
            self.overruns = self.overruns.saturating_add(1);
            if self.fault.is_none() {
                self.fault = Some(Fault::BudgetOverrun {
                    kind,
                    elapsed_ns,
                    budget_ns,
                });
            }
        }
        self.active = None;
        self.last_ns = now_ns;
        // Saturating diagnostic count (spec L5826/L7424): never wraps, and
        // no verdict or admission decision depends on it.
        self.settled = self.settled.saturating_add(1);
        Ok(Settlement {
            kind,
            elapsed_ns,
            overrun_class,
        })
    }
    /// Record an actual lock acquisition against the declared rank registry.
    /// A rank violation or exceeding [`MAX_LOCKS_PER_IRQ_OFF`] latches a
    /// sticky fault and denies the acquisition (fail-closed, spec L1530 /
    /// L1554). `held` is the caller's set of locks already held in the
    /// current continuous IRQ-off interval; run-queue CPU sub-order is
    /// checked separately via [`runqueue_cpu_order_violation`].
    pub fn record_acquire(&mut self, held: &[LockRank], next: LockRank) -> Result<(), Error> {
        if self.fault.is_some() {
            return Err(Error::Denied);
        }
        if held.len() >= MAX_LOCKS_PER_IRQ_OFF {
            self.fault = Some(Fault::LockCountExceeded { held: held.len() });
            return Err(Error::Denied);
        }
        if let Some(blocking) = order_violation(held, next) {
            self.fault = Some(Fault::LockOrderViolation { next, blocking });
            return Err(Error::Denied);
        }
        Ok(())
    }
    pub const fn fault(&self) -> Option<Fault> {
        self.fault
    }
    pub const fn faulted(&self) -> bool {
        self.fault.is_some()
    }
    pub const fn active_kind(&self) -> Option<SectionKind> {
        match self.active {
            Some((kind, _)) => Some(kind),
            None => None,
        }
    }
    pub const fn settled_count(&self) -> u64 {
        self.settled
    }
    pub const fn overrun_count(&self) -> u64 {
        self.overruns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settle(kind: SectionKind, start: u64, end: u64) -> Settlement {
        let mut m = CriticalSectionMeter::new();
        m.begin(kind, start).unwrap();
        m.end(end).unwrap()
    }

    #[test]
    fn completed_observations_continue_after_first_overrun() {
        let mut m = CompletedSectionObservations::new();
        m.record(SectionKind::EffectiveWork, 0, WORK_BUDGET_NS + 1);
        m.record(SectionKind::EffectiveWork, 50_000, 140_000);
        m.record(SectionKind::EffectiveWork, 150_000, 195_000);
        assert_eq!(m.counts(), (1, 2, 0));
        assert_eq!(m.max_elapsed_ns(), 90_000);
    }

    #[test]
    fn completed_observations_reject_regressing_clock_without_inventing_time() {
        let mut m = CompletedSectionObservations::new();
        m.record(SectionKind::EffectiveWork, 100, 200);
        m.record(SectionKind::EffectiveWork, 199, 300);
        m.record(SectionKind::EffectiveWork, 400, 399);
        m.record(SectionKind::EffectiveWork, 399, 401);
        m.record(SectionKind::EffectiveWork, 401, 401);
        assert_eq!(m.counts(), (2, 0, 3));
        assert_eq!(m.max_elapsed_ns(), 100);
    }

    #[test]
    fn diagnostic_observation_does_not_reopen_admission() {
        let mut gate = CriticalSectionMeter::new();
        gate.begin(SectionKind::EffectiveWork, 0).unwrap();
        gate.end(WORK_BUDGET_NS + 1).unwrap();
        let fault = gate.fault();
        let mut observations = CompletedSectionObservations::new();
        observations.record(SectionKind::EffectiveWork, 50_000, 140_000);
        assert_eq!(observations.counts(), (0, 1, 0));
        assert_eq!(
            gate.begin(SectionKind::EffectiveWork, 150_000),
            Err(Error::Denied)
        );
        assert_eq!(gate.fault(), fault);
    }

    #[test]
    fn budget_boundaries_are_exact_at_45_50_5_us() {
        // Effective work: 45μs passes, 45μs+1ns overruns (spec L1542/L7340).
        let ok = settle(SectionKind::EffectiveWork, 1_000, 1_000 + WORK_BUDGET_NS);
        assert_eq!(ok.elapsed_ns, 45_000);
        assert_eq!(ok.overrun_class, OverrunClass::None);
        let over = settle(
            SectionKind::EffectiveWork,
            1_000,
            1_000 + WORK_BUDGET_NS + 1,
        );
        assert_eq!(over.overrun_class, OverrunClass::Work);
        // Whole IRQ-off interval: 50μs passes, 50μs+1ns overruns (L1542).
        let ok = settle(SectionKind::IrqOffInterval, 0, IRQ_OFF_BUDGET_NS);
        assert_eq!(ok.overrun_class, OverrunClass::None);
        let over = settle(SectionKind::IrqOffInterval, 0, IRQ_OFF_BUDGET_NS + 1);
        assert_eq!(over.overrun_class, OverrunClass::IrqOff);
        // Acquisition overhead: 5μs passes, 5μs+1ns overruns (L1546).
        let ok = settle(
            SectionKind::AcquisitionOverhead,
            7,
            7 + ACQUISITION_BUDGET_NS,
        );
        assert_eq!(ok.overrun_class, OverrunClass::None);
        let over = settle(
            SectionKind::AcquisitionOverhead,
            7,
            7 + ACQUISITION_BUDGET_NS + 1,
        );
        assert_eq!(over.overrun_class, OverrunClass::Acquisition);
        // 45+5≤50 mandatory metering (L5031): the split budgets sum to the
        // total cap exactly.
        assert_eq!(WORK_BUDGET_NS + ACQUISITION_BUDGET_NS, IRQ_OFF_BUDGET_NS);
    }

    #[test]
    fn overrun_latches_sticky_fault_and_closes_admission() {
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 100).unwrap();
        let s = m.end(100 + WORK_BUDGET_NS + 1).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::Work);
        assert!(m.faulted());
        assert_eq!(
            m.fault(),
            Some(Fault::BudgetOverrun {
                kind: SectionKind::EffectiveWork,
                elapsed_ns: WORK_BUDGET_NS + 1,
                budget_ns: WORK_BUDGET_NS,
            })
        );
        // Fail-closed: new metered admission is denied (spec L1552).
        assert_eq!(
            m.begin(SectionKind::EffectiveWork, 100_000),
            Err(Error::Denied)
        );
        assert_eq!(
            m.record_acquire(&[], LockRank::Registry),
            Err(Error::Denied)
        );
        // There is no reset API: the fault and the counters persist, and no
        // further scope can be opened or settled on this meter.
        assert_eq!(m.overrun_count(), 1);
        assert_eq!(m.settled_count(), 1);
        assert_eq!(m.end(200_000), Err(Error::Stale));
        assert!(m.faulted());
    }

    #[test]
    fn first_fault_wins_over_later_violations() {
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::AcquisitionOverhead, 0).unwrap();
        m.end(ACQUISITION_BUDGET_NS + 1).unwrap();
        let first = m.fault();
        assert!(matches!(first, Some(Fault::BudgetOverrun { .. })));
        // Subsequent violations are denied without overwriting the fault.
        assert_eq!(
            m.record_acquire(&[LockRank::PolicyLock], LockRank::Registry),
            Err(Error::Denied)
        );
        assert_eq!(m.fault(), first);
        assert_eq!(m.overrun_count(), 1);
    }

    #[test]
    fn rank_registry_enforces_declared_order() {
        // The declared order itself is strictly ascending (spec L1530).
        for w in LOCK_ORDER.windows(2) {
            assert!(rank_value(w[0]) < rank_value(w[1]));
        }
        // Ascending acquisition along the full chain is legal.
        let mut m = CriticalSectionMeter::new();
        let mut held = [LockRank::Registry; 8];
        let mut n = 0;
        for rank in LOCK_ORDER {
            assert!(acquire_respects_order(&held[..n], rank));
            m.record_acquire(&held[..n], rank).unwrap();
            held[n] = rank;
            n += 1;
        }
        assert!(!m.faulted());
        // Equal rank is a violation (non-recursive try_lock, spec L1532).
        assert_eq!(
            order_violation(&[LockRank::PolicyLock], LockRank::PolicyLock),
            Some(LockRank::PolicyLock)
        );
        // Descending acquisition reports the highest blocking held rank.
        assert_eq!(
            order_violation(
                &[LockRank::Registry, LockRank::Task, LockRank::PageMeta],
                LockRank::PolicyLock
            ),
            Some(LockRank::PageMeta)
        );
        assert!(!acquire_respects_order(
            &[LockRank::Task],
            LockRank::Registry
        ));
        // Empty held set: any first lock is legal.
        assert!(acquire_respects_order(&[], LockRank::EndpointDeviceQueue));
    }

    #[test]
    fn rank_violation_latches_fault_and_denies() {
        let mut m = CriticalSectionMeter::new();
        assert_eq!(
            m.record_acquire(&[LockRank::Task], LockRank::PolicyLock),
            Err(Error::Denied)
        );
        assert_eq!(
            m.fault(),
            Some(Fault::LockOrderViolation {
                next: LockRank::PolicyLock,
                blocking: LockRank::Task,
            })
        );
        // Fail-closed afterwards, even for a legal acquisition.
        assert_eq!(
            m.record_acquire(&[], LockRank::Registry),
            Err(Error::Denied)
        );
        assert_eq!(m.begin(SectionKind::EffectiveWork, 0), Err(Error::Denied));
    }

    #[test]
    fn runqueue_suborder_is_ascending_cpu_id() {
        assert_eq!(runqueue_cpu_order_violation(&[], 0), None);
        assert_eq!(runqueue_cpu_order_violation(&[0, 1], 2), None);
        assert_eq!(runqueue_cpu_order_violation(&[0, 2], 1), Some(2));
        assert_eq!(runqueue_cpu_order_violation(&[1], 1), Some(1));
    }

    #[test]
    fn lock_count_cap_is_eight_actual_locks() {
        let mut m = CriticalSectionMeter::new();
        // Eight held locks already fill the interval quota (spec L1554);
        // a ninth acquisition is denied and latches the fault.
        let held = LOCK_ORDER;
        assert_eq!(held.len(), MAX_LOCKS_PER_IRQ_OFF);
        assert_eq!(
            m.record_acquire(&held, LockRank::EndpointDeviceQueue),
            Err(Error::Denied)
        );
        assert_eq!(m.fault(), Some(Fault::LockCountExceeded { held: 8 }));
        // Seven held locks plus one more is exactly the cap and legal.
        let mut m2 = CriticalSectionMeter::new();
        m2.record_acquire(&LOCK_ORDER[..7], LockRank::EndpointDeviceQueue)
            .unwrap();
        assert!(!m2.faulted());
    }

    #[test]
    fn overrun_settles_but_preserves_result() {
        // Over budget by 1ns: settles (not an Err), classed as a work overrun.
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        let s = m.end(WORK_BUDGET_NS + 1).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::Work);
        assert_eq!(m.settled_count(), 1);
        assert_eq!(m.overrun_count(), 1);
        // Exactly at budget is not an overrun.
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        let s = m.end(WORK_BUDGET_NS).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::None);
        assert_eq!(m.overrun_count(), 0);
        // End before begin: Clock error, and metering fails sticky-closed.
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 100).unwrap();
        assert_eq!(m.end(99), Err(Error::Clock));
        // Scope stays open: a new begin is refused (Busy), no silent reset.
        assert_eq!(m.begin(SectionKind::EffectiveWork, 200), Err(Error::Busy));
        // An overrun latches the fault; later admission is denied.
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        m.end(WORK_BUDGET_NS + 1).unwrap();
        assert_eq!(
            m.begin(SectionKind::EffectiveWork, 99_999),
            Err(Error::Denied)
        );
    }

    #[test]
    fn settlement_is_idempotent_and_counters_monotone() {
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 10).unwrap();
        let s = m.end(10 + 1_000).unwrap();
        assert_eq!(s.elapsed_ns, 1_000);
        assert_eq!(s.overrun_class, OverrunClass::None);
        assert_eq!(m.settled_count(), 1);
        // A second end without a new begin changes nothing.
        assert_eq!(m.end(20 + 1_000), Err(Error::Stale));
        assert_eq!(m.settled_count(), 1);
        assert_eq!(m.overrun_count(), 0);
        assert!(!m.faulted());
        assert_eq!(m.active_kind(), None);
        // A fresh scope settles independently.
        m.begin(SectionKind::IrqOffInterval, 2_000).unwrap();
        let s2 = m.end(2_000 + 2_000).unwrap();
        assert_eq!(s2.kind, SectionKind::IrqOffInterval);
        assert_eq!(m.settled_count(), 2);
    }

    #[test]
    fn zero_time_guard_and_clock_regression() {
        // Zero elapsed is legal and within budget; boot timestamp 0 is valid.
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        let s = m.end(0).unwrap();
        assert_eq!(s.elapsed_ns, 0);
        assert_eq!(s.overrun_class, OverrunClass::None);
        assert!(!m.faulted());
        // Regressing clock at begin is rejected without state change.
        assert_eq!(m.begin(SectionKind::EffectiveWork, 0), Ok(()));
        assert_eq!(
            m.end(1),
            Ok(Settlement {
                kind: SectionKind::EffectiveWork,
                elapsed_ns: 1,
                overrun_class: OverrunClass::None,
            })
        );
        assert_eq!(m.begin(SectionKind::EffectiveWork, 0), Err(Error::Clock));
        assert_eq!(m.active_kind(), None);
        // Regressing clock at end keeps the scope open (bad clock retains
        // ownership; no invented duration, no silent reset).
        m.begin(SectionKind::IrqOffInterval, 100).unwrap();
        assert_eq!(m.end(99), Err(Error::Clock));
        assert_eq!(m.active_kind(), Some(SectionKind::IrqOffInterval));
        assert_eq!(m.settled_count(), 2);
        // The scope can still settle correctly at a valid later timestamp.
        let s = m.end(100 + IRQ_OFF_BUDGET_NS).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::None);
        assert_eq!(m.settled_count(), 3);
    }

    #[test]
    fn nested_begin_and_end_without_begin_are_protocol_errors() {
        let mut m = CriticalSectionMeter::new();
        assert_eq!(m.end(0), Err(Error::Stale));
        m.begin(SectionKind::EffectiveWork, 5).unwrap();
        assert_eq!(m.begin(SectionKind::IrqOffInterval, 6), Err(Error::Busy));
        assert_eq!(m.active_kind(), Some(SectionKind::EffectiveWork));
        m.end(6).unwrap();
        assert!(!m.faulted());
    }

    #[test]
    fn diagnostic_counters_saturate_and_never_change_verdicts() {
        // Counting discipline (spec L5826 checked counts / L7424 saturating
        // diagnostic counts): the settled/overrun tallies use saturating_add,
        // so a pathological caller cannot wrap them. They are diagnostic
        // only — no budget or admission decision reads them — so saturation
        // must not alter a settlement verdict or suppress the sticky fault.
        // The fields are private but reachable from this child test module,
        // letting us pin the ceiling without 2^64 iterations.
        let mut m = CriticalSectionMeter {
            active: None,
            last_ns: 0,
            fault: None,
            settled: u64::MAX,
            overruns: 0,
        };
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        let s = m.end(WORK_BUDGET_NS).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::None);
        // Saturated at the ceiling, not wrapped back to 0.
        assert_eq!(m.settled_count(), u64::MAX);
        assert!(!m.faulted());

        // The overrun tally saturates too, and the sticky fault still
        // latches and closes admission even at the counter ceiling.
        let mut m = CriticalSectionMeter {
            active: None,
            last_ns: 0,
            fault: None,
            settled: u64::MAX,
            overruns: u64::MAX,
        };
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        let s = m.end(WORK_BUDGET_NS + 1).unwrap();
        assert_eq!(s.overrun_class, OverrunClass::Work);
        assert_eq!(m.overrun_count(), u64::MAX);
        assert_eq!(m.settled_count(), u64::MAX);
        assert!(m.faulted());
        assert_eq!(
            m.begin(SectionKind::EffectiveWork, WORK_BUDGET_NS + 2),
            Err(Error::Denied)
        );

        // On a fresh meter the tallies increment normally (no premature cap).
        let mut m = CriticalSectionMeter::new();
        m.begin(SectionKind::EffectiveWork, 0).unwrap();
        m.end(1).unwrap();
        assert_eq!(m.settled_count(), 1);
        assert_eq!(m.overrun_count(), 0);
    }

    #[test]
    fn max_try_intervals_constant_pins_spec_l1550() {
        // Spec L1550: "最多 4 个独立尝试区间后让出并在外层绝对截止内重试" —
        // yield after at most 4 independent attempt intervals, retry within
        // an outer absolute deadline. The constant records that frozen quota;
        // enforcement belongs to the G1-freeze try_lock retry loop (yield +
        // outer deadline), which this measurement scaffold deliberately does
        // not implement (see the constant's doc note). Pin the value and its
        // source so a future edit cannot silently drift it.
        assert_eq!(MAX_TRY_INTERVALS, 4);
        // It is a distinct quota from the per-interval actual-lock cap
        // (spec L1554), not a restatement of it.
        assert_ne!(MAX_TRY_INTERVALS, MAX_LOCKS_PER_IRQ_OFF);
        assert_eq!(MAX_LOCKS_PER_IRQ_OFF, 8);
    }
}
