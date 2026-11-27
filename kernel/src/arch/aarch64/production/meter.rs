//! The D01 fixture installs its validated policy root under a measured
//! nonblocking lock. Bridge observations separately time completed vector
//! calls for the diagnostic verifier. Formal lock-chain coverage includes
//! other target owners and acquisition paths.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF):
//! OBSERVATIONS is touched only by the CPU0-only, non-reentrant in-vector
//! bridge wrapper and by CPU0 at the evidence seal. The mutable reference
//! exists only inside one synchronous closure and never spans the bridge.

use super::{
    BOOT, CALLER_NONE, CTRL_EPOCH, PLAN_SEQ, PLAN_VERSION, TIMER_IRQ, VECTOR_CALLER, binding, cpu,
    evidence, gic, now_ns, report, timer,
};
use core::{
    arch::asm,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use cyxia_kernel_core::control_plane::{
    Error,
    action_schema_v2::ActionV2,
    apply_report_v1::PlanKey,
    apply_work_v1::ApplyWorkV1,
    policy_lock_v0199::{CompletedSectionObservations, IrqOffTiming, SectionKind},
};

static mut OBSERVATIONS: CompletedSectionObservations = CompletedSectionObservations::new();

const IRQ_MASK: u64 = 1 << 7;
const WEIGHT_BITS: u32 = u16::BITS;

pub(super) struct PreparedWeight(u64);

/// The fixture's protected D01 target, in its existing registered page. The
/// release store installs the version and weight together; observers need
/// only one acquire load. A clock fault or overrun closes later admissions.
#[repr(C, align(4096))]
pub(super) struct ExecTarget {
    installed: AtomicU64,
    held: AtomicBool,
    closed: AtomicBool,
}

impl ExecTarget {
    pub(super) const fn new() -> Self {
        Self {
            installed: AtomicU64::new(0),
            held: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    /// Authenticate and decode the exact resource work before occupying the
    /// target lock. Only the RegisteredDecisionGate's EL1 claim calls this.
    pub(super) fn prepare(&self, work: &ApplyWorkV1<'_>) -> Result<PreparedWeight, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::NotReady);
        }
        let live = binding();
        if !live.active
            || work.key
                != (PlanKey {
                    boot_epoch: BOOT,
                    controller_epoch: CTRL_EPOCH,
                    plan_seq: PLAN_SEQ,
                })
            || work.action_index != 0
            || work.domain != live.domain
            || work.target != live.target
            || work.executor_generation != live.executor_generation
            || work.plan_version != PLAN_VERSION
        {
            return Err(Error::Denied);
        }
        let ActionV2::GroupWeight(weight) = ActionV2::decode(work.domain, 1, work.payload)? else {
            return Err(Error::Denied);
        };
        let version = work
            .plan_version
            .checked_mul(1u64 << WEIGHT_BITS)
            .ok_or(Error::Exhausted)?;
        Ok(PreparedWeight(version | u64::from(weight)))
    }

    pub(super) fn installed_weight(&self, plan_version: u64) -> Option<u16> {
        let root = self.installed.load(Ordering::Acquire);
        (root != 0 && root >> WEIGHT_BITS == plan_version).then_some(root as u16)
    }

    /// Install admitted work once in the CPU0 foreground. The outer boot
    /// fixture leaves IRQ masked. Mask its sole enabled timer source first
    /// so that the measured interval starts from genuinely unmasked DAIF.I
    /// without a pending fixture timer entering an inactive EL0 context.
    pub(super) fn commit(&self, prepared: PreparedWeight) -> Result<Option<IrqOffTiming>, Error> {
        if cpu::slot() != 0
            || VECTOR_CALLER[0].load(Ordering::Acquire) != CALLER_NONE
            || self.closed.load(Ordering::Acquire)
        {
            return Err(Error::Denied);
        }
        let saved_daif: u64;
        // SAFETY: CPU0 reads its own saved IRQ mask in foreground.
        unsafe { asm!("mrs {}, daif", out(reg) saved_daif, options(nostack, preserves_flags)) };
        if saved_daif & IRQ_MASK == 0 {
            return Err(Error::Denied);
        }
        let frequency = timer::frequency();
        if frequency == 0 {
            self.closed.store(true, Ordering::Release);
            return Err(Error::Clock);
        }
        let irq = TIMER_IRQ.load(Ordering::Acquire) as u32;
        let was_enabled = gic().enabled(irq);
        gic().mask(irq).map_err(|_| Error::Denied)?;
        // SAFETY: the installed exception vectors are live. The fixture's
        // local timer is stopped and now masked at the distributor. This
        // CPU is outside EL0 and does not own a replayable vector caller.
        unsafe {
            asm!("dsb sy", "isb", options(nostack, preserves_flags));
            timer::enable_irqs();
        }
        let (installed, timing) = self.try_commit_irq_off(prepared, frequency);
        // SAFETY: restore the exact outer IRQ state before restoring its
        // banked timer interrupt enable. No EL0 runs inside this function.
        unsafe {
            asm!("msr daif, {}", "isb", in(reg) saved_daif, options(nostack, preserves_flags))
        };
        if was_enabled {
            gic().unmask(irq).expect("restore the registered timer PPI");
        }
        let timing = timing.ok();
        if timing.is_none_or(|t| t.exceeded() != 0) {
            self.closed.store(true, Ordering::Release);
        }
        // A measured overrun after the release store does not erase an
        // installed root or turn an accepted effect into a failed one.
        installed.map(|()| timing)
    }

    #[inline(never)]
    fn try_commit_irq_off(
        &self,
        prepared: PreparedWeight,
        frequency: u64,
    ) -> (Result<(), Error>, Result<IrqOffTiming, Error>) {
        let start: u64;
        // SAFETY: called only with IRQ enabled by commit(). Time samples
        // carry memory clobbers to keep the release store inside the scope.
        unsafe {
            asm!("isb", "mrs {}, cntpct_el0", "msr daifset, #2", "isb",
                out(reg) start, options(nostack, preserves_flags));
        }
        let (outcome, work_start, work_end) = if self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            let work_start = sample_ticks();
            let outcome = if self.installed.load(Ordering::Relaxed) == 0 {
                self.installed.store(prepared.0, Ordering::Release);
                Ok(())
            } else {
                Err(Error::Stale)
            };
            let work_end = sample_ticks();
            self.held.store(false, Ordering::Release);
            (outcome, work_start, work_end)
        } else {
            (Err(Error::Busy), start, start)
        };
        let end: u64;
        // SAFETY: restore the I bit to the enabled state used at the start.
        // The last timestamp is a conservative upper bound on IRQ-off time.
        unsafe {
            asm!("msr daifclr, #2", "isb", "mrs {}, cntpct_el0",
                out(reg) end, options(nostack, preserves_flags));
        }
        (
            outcome,
            IrqOffTiming::from_ticks(start, work_start, work_end, end, frequency),
        )
    }
}

#[inline(always)]
fn sample_ticks() -> u64 {
    let count: u64;
    // SAFETY: native EL1 reads its own fixed-frequency architectural counter.
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) count, options(nostack, preserves_flags)) };
    count
}

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
