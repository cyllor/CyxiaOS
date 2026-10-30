//! Bounded, prepaid boot self-test on the bootstrap C owner (CPU1).
//! No DecisionKey, candidate set, policy root or cluster identity is created.
use super::*;
use cyxia_prototype::domains::{Error, tasks::ControlCredit};

static STATUS: AtomicU64 = AtomicU64::new(0); // idle / pending / pass / failure
static STARTED: AtomicU64 = AtomicU64::new(0);
const RECOVERY_NS: u64 = 8_000_000;

pub(super) struct Check {
    context: Option<user::Context>,
    bill: Option<(ControlCredit, u64, u64, Option<bool>)>,
    last_window: Option<u64>,
    spent: u64,
}
impl Check {
    pub(super) const fn new() -> Self {
        Self {
            context: None,
            bill: None,
            last_window: None,
            spent: 0,
        }
    }
    fn settle(&mut self) -> bool {
        let Some((credit, actual, end, result)) = self.bill else {
            return true;
        };
        match crate::domain_tasks::complete_control(credit, actual, end) {
            Err(Error::Busy) => return false,
            Ok(()) => {
                if let Some(passed) = result {
                    let _ = STATUS.compare_exchange(
                        1,
                        if passed { 2 } else { 3 },
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            }
            Err(_) => {
                STATUS.store(3, Ordering::Release);
            }
        }
        self.bill = None;
        true
    }
    pub(super) fn step(&mut self) -> bool {
        if cpu::slot() != 1 {
            return false;
        }
        if !self.settle() {
            return true;
        }
        if STATUS.load(Ordering::Acquire) != 1 {
            self.context = None;
            return false;
        }
        let now = crate::domain_tasks::now_ns();
        let window = now / 100_000_000;
        if now.saturating_sub(STARTED.load(Ordering::Acquire)) >= 1_000_000_000
            || self.spent >= RECOVERY_NS
        {
            self.context = None;
            STATUS.store(3, Ordering::Release);
            return true;
        }
        if self.last_window == Some(window) {
            return true;
        }
        let Ok(Some(credit)) = crate::domain_tasks::begin_control(RECOVERY_NS, false) else {
            return true;
        };
        self.last_window = Some(window);
        let begin = timer::cpu_ticks();
        let context = self.context.get_or_insert_with(|| {
            fresh(if crate::boot_recovery::model_corruption() {
                7
            } else {
                6
            })
        });
        execute(context, 3);
        let result = if context.kind == 9 {
            None // real preemption, resume later without resetting the deadline
        } else {
            Some(
                context.kind == 8
                    && context.esr >> 26 == 0x15
                    && context.esr & 0xffff == 0x543
                    && context.regs[0] == cyxia_prototype::boot_model::OUTPUT_MAGIC
                    && context.regs[1] == 1
                    && context.regs[2] == cyxia_prototype::boot_model::CASES as u64,
            )
        };
        let kind = context.kind;
        if result.is_some() {
            self.context = None;
        }
        // Record the diagnostic checkpoint first; its serialization belongs to
        // this same prepaid span. The later enclosing sample is authoritative.
        let checkpoint = self.spent.saturating_add(timer::cpu_elapsed_ns(begin));
        crate::boot_recovery::model_turn(checkpoint, kind, result);
        let actual = timer::cpu_elapsed_ns(begin);
        let end = crate::domain_tasks::now_ns();
        self.spent = self.spent.saturating_add(actual);
        let result = if self.spent > RECOVERY_NS
            || end.saturating_sub(STARTED.load(Ordering::Acquire)) >= 1_000_000_000
        {
            Some(false)
        } else {
            result
        };
        self.bill = Some((credit, actual, end, result));
        let _ = self.settle();
        true
    }
}
pub(super) fn request() {
    assert_eq!(cpu::slot(), 0);
    assert_eq!(STATUS.load(Ordering::Acquire), 0);
    STARTED.store(crate::domain_tasks::now_ns(), Ordering::Relaxed);
    STATUS.store(1, Ordering::Release);
    wake_workers();
}
pub(super) fn result() -> Option<bool> {
    match STATUS.load(Ordering::Acquire) {
        2 => Some(true),
        3 => Some(false),
        _ => None,
    }
}
pub(super) fn cancel() {
    let _ = STATUS.compare_exchange(1, 3, Ordering::AcqRel, Ordering::Relaxed);
}
