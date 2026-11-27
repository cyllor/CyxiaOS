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
        let (installed, [before, work_start, work_end, after]) = self.try_commit_irq_off(prepared);
        // IRQ is enabled here. Convert and latch the real sampled bounds
        // before restoring the fixture's outer mask and timer routing.
        let timing = IrqOffTiming::from_ticks(before, work_start, work_end, after, frequency).ok();
        if timing.is_none_or(|t| t.exceeded() != 0) {
            self.closed.store(true, Ordering::Release);
        }
        // SAFETY: restore the exact outer IRQ state before restoring its
        // banked timer interrupt enable. No EL0 runs inside this function.
        unsafe {
            asm!("msr daif, {}", "isb", in(reg) saved_daif, options(nostack, preserves_flags))
        };
        if was_enabled {
            gic().unmask(irq).expect("restore the registered timer PPI");
        }
        // A measured overrun after the release store does not erase an
        // installed root or turn an accepted effect into a failed one.
        installed.map(|()| timing)
    }

    #[inline(never)]
    fn try_commit_irq_off(&self, prepared: PreparedWeight) -> (Result<(), Error>, [u64; 4]) {
        let before: u64;
        let work_start: u64;
        let work_end: u64;
        let after: u64;
        let lock_failed: u32;
        let prior: u64;
        // SAFETY: CPU0 enters with IRQ enabled and owns the timer handoff.
        // Both precomputed addresses refer to aligned, live atomics in this
        // target. One acquire-exclusive attempt owns the byte only after a
        // successful store-exclusive. Its owner installs and releases with
        // release ordering. A failed attempt never writes the root or unlocks
        // the existing holder. Every exit restores IRQ before the last tick.
        // No compiler-generated loads, stores, or conversions can enter
        // this mask-to-restore interval.
        unsafe {
            asm!(
                "isb",
                "mrs {before}, cntpct_el0",
                "msr daifset, #2",
                "isb",
                "ldaxrb {lock_failed:w}, [{held}]",
                "cbnz {lock_failed:w}, 3f",
                "stxrb {lock_failed:w}, {one:w}, [{held}]",
                "cbnz {lock_failed:w}, 4f",
                "isb",
                "mrs {work_start}, cntpct_el0",
                "ldr {prior}, [{root}]",
                "cbnz {prior}, 2f",
                "stlr {new_root}, [{root}]",
                "2:",
                "isb",
                "mrs {work_end}, cntpct_el0",
                "stlrb wzr, [{held}]",
                "msr daifclr, #2",
                "isb",
                "mrs {after}, cntpct_el0",
                "b 5f",
                "3:",
                "clrex",
                "4:",
                "msr daifclr, #2",
                "isb",
                "mrs {after}, cntpct_el0",
                "mov {prior}, xzr",
                "mov {work_start}, {before}",
                "mov {work_end}, {before}",
                "5:",
                held = in(reg) self.held.as_ptr(),
                root = in(reg) self.installed.as_ptr(),
                new_root = in(reg) prepared.0,
                one = in(reg) 1u32,
                before = out(reg) before,
                work_start = out(reg) work_start,
                work_end = out(reg) work_end,
                after = out(reg) after,
                lock_failed = out(reg) lock_failed,
                prior = out(reg) prior,
                options(nostack, preserves_flags),
            );
        }
        let installed = if lock_failed != 0 {
            Err(Error::Busy)
        } else if prior != 0 {
            Err(Error::Stale)
        } else {
            Ok(())
        };
        (installed, [before, work_start, work_end, after])
    }
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
