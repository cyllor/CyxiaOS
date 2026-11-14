//! Bounded, prepaid boot self-test on the bootstrap C owner (CPU1).
//! No DecisionKey, candidate set, policy root or cluster identity is created.
use super::*;
use cyxia_prototype::domains::{Error, tasks::ControlCredit};

// Generic failure and a validated model rejection are deliberately distinct.
// Only the latter may publish a completed negative model-test receipt.
static STATUS: AtomicU64 = AtomicU64::new(0); // idle / pending / pass / failure / rejected
static STARTED: AtomicU64 = AtomicU64::new(0);
static FINAL_CPU: AtomicU64 = AtomicU64::new(0);
const RECOVERY_NS: u64 = 8_000_000;
const WALL_NS: u64 = 1_000_000_000;

/// Stopped diagnostic only, never an authority or an acceptance receipt.
/// CPU1 alone writes words 8..48; CPU0 alone writes words 48..64. A stopped
/// reader may observe an intermediate stage and must retain it as incomplete.
/// 8 steps, 9 admissions, 10 no-credit, 11 admission error, 12 settlement Busy,
/// 13 settlement error, 14 credit sequence, 15 reserved, 16 actual, 17 total CPU,
/// 18 physical finish, 19 exit kind, 20 entry PC, 21 exit PC, 22 model result,
/// 23 first terminal cause, 24 last admission time, 25 stage, 26 credit window,
/// 27 settlement (1 OK/2 error/3 Busy), 28 bill pending, 29 entry wall,
/// 30 return wall, 31 CPU counter before, 32 CPU counter after.
/// Causes: 1 vectors passed, 2 vectors rejected, 3 CPU limit, 4 wall deadline,
/// 5 settlement error, 6 externally cancelled, 7 invalid EL0 completion.
/// CPU0: 48 request time, 49 cancellation time, 50 cancellation CAS succeeded.
#[repr(C, align(64))]
struct BootModelDebug([AtomicU64; 64]);
#[used]
#[unsafe(no_mangle)]
static A01_BOOT_MODEL_DEBUG: BootModelDebug = BootModelDebug([const { AtomicU64::new(0) }; 64]);
fn debug_put(index: usize, value: u64) {
    A01_BOOT_MODEL_DEBUG.0[index].store(value, Ordering::Release);
}
fn debug_count(index: usize) {
    let word = &A01_BOOT_MODEL_DEBUG.0[index];
    // Each counter has one CPU writer; no exclusive retry loop is necessary.
    word.store(
        word.load(Ordering::Relaxed).saturating_add(1),
        Ordering::Release,
    );
}
fn debug_terminal(cause: u64) {
    if A01_BOOT_MODEL_DEBUG.0[23].load(Ordering::Relaxed) == 0 {
        debug_put(23, cause);
    }
}
fn expired(now: u64) -> bool {
    now.saturating_sub(STARTED.load(Ordering::Acquire)) >= WALL_NS
}
fn model_response(context: &user::Context) -> Option<bool> {
    (context.kind == 8
        && context.esr >> 26 == 0x15
        && context.esr & 0xffff == 0x543
        && context.regs[0] == cyxia_prototype::boot_model::OUTPUT_MAGIC
        && context.regs[1] <= 1
        && context.regs[2] == cyxia_prototype::boot_model::CASES as u64)
        .then_some(context.regs[1] == 1)
}
#[derive(Clone, Copy)]
struct Bill {
    credit: ControlCredit,
    actual: u64,
    end: u64,
    terminal: bool,
    response: Option<bool>,
}

pub(super) struct Check {
    context: Option<user::Context>,
    bill: Option<Bill>,
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
        let Some(bill) = self.bill else {
            return true;
        };
        match crate::domain_tasks::complete_control(bill.credit, bill.actual, bill.end) {
            Err(Error::Busy) => {
                debug_count(12);
                debug_put(27, 3);
                return false;
            }
            Ok(()) => {
                debug_put(27, 1);
                if bill.terminal {
                    let late = expired(crate::domain_tasks::now_ns());
                    let bounded = self.spent <= RECOVERY_NS && !late;
                    let status = match (bounded, bill.response) {
                        (true, Some(true)) => 2,
                        (true, Some(false)) => 4,
                        _ => 3,
                    };
                    FINAL_CPU.store(self.spent, Ordering::Relaxed);
                    let published =
                        STATUS.compare_exchange(1, status, Ordering::AcqRel, Ordering::Relaxed);
                    debug_terminal(if published.is_err() {
                        6
                    } else if late {
                        4
                    } else {
                        match status {
                            2 => 1,
                            4 => 2,
                            _ => 7,
                        }
                    });
                }
            }
            Err(error) => {
                debug_put(13, error as u64 + 1);
                debug_put(27, 2);
                debug_terminal(5);
                STATUS.store(3, Ordering::Release);
            }
        }
        self.bill = None;
        debug_put(28, 0);
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
        debug_count(8);
        let now = crate::domain_tasks::now_ns();
        debug_put(24, now);
        let window = now / 100_000_000;
        if expired(now) || self.spent >= RECOVERY_NS {
            debug_terminal(if self.spent >= RECOVERY_NS { 3 } else { 4 });
            self.context = None;
            STATUS.store(3, Ordering::Release);
            return true;
        }
        if self.last_window == Some(window) {
            return true;
        }
        let credit = match crate::domain_tasks::begin_control(RECOVERY_NS, false) {
            Ok(Some(credit)) => credit,
            Ok(None) => {
                debug_count(10);
                return true;
            }
            Err(error) => {
                debug_put(11, error as u64 + 1);
                return true;
            }
        };
        self.last_window = Some(window);
        let begin = timer::cpu_ticks();
        debug_put(31, begin);
        debug_count(9);
        debug_put(14, credit.sequence);
        debug_put(15, credit.reserved_ns);
        debug_put(26, credit.window);
        let context = self.context.get_or_insert_with(|| {
            fresh(if crate::boot_recovery::model_corruption() {
                7
            } else {
                6
            })
        });
        debug_put(20, context.pc);
        debug_put(29, crate::domain_tasks::now_ns());
        debug_put(25, 1);
        execute(context, 3);
        debug_put(25, 2);
        debug_put(30, crate::domain_tasks::now_ns());
        debug_put(21, context.pc);
        let response = model_response(context);
        let kind = context.kind;
        debug_put(19, kind);
        debug_put(22, response.map_or(0, |passed| if passed { 1 } else { 2 }));
        if kind != 9 {
            self.context = None;
        }
        // A returned SVC is not a completed test until its exact bill settles.
        // Keep the intermediate checkpoint pending, including valid rejection.
        let checkpoint = self.spent.saturating_add(timer::cpu_elapsed_ns(begin));
        crate::boot_recovery::model_turn(checkpoint, kind, None);
        let cpu_end = timer::cpu_ticks();
        let actual = timer::cpu_ns(cpu_end.saturating_sub(begin));
        let end = crate::domain_tasks::now_ns();
        self.spent = self.spent.saturating_add(actual);
        let limit = self.spent > RECOVERY_NS || expired(end);
        if limit {
            debug_terminal(if self.spent > RECOVERY_NS { 3 } else { 4 });
        }
        // Publish the exact bill used below, never a replacement measurement.
        debug_put(32, cpu_end);
        debug_put(16, actual);
        debug_put(17, self.spent);
        debug_put(18, end);
        debug_put(28, 1);
        debug_put(25, 3);
        self.bill = Some(Bill {
            credit,
            actual,
            end,
            terminal: kind != 9 || limit,
            response: if limit { None } else { response },
        });
        let _ = self.settle();
        true
    }
}
pub(super) fn request() {
    assert_eq!(cpu::slot(), 0);
    assert_eq!(STATUS.load(Ordering::Acquire), 0);
    let now = crate::domain_tasks::now_ns();
    debug_put(48, now);
    debug_put(1, 1);
    debug_put(0, 0x4359_424d_4447_0001);
    STARTED.store(now, Ordering::Relaxed);
    STATUS.store(1, Ordering::Release);
    wake_workers();
}
pub(super) fn result() -> Option<bool> {
    match STATUS.load(Ordering::Acquire) {
        status @ (2 | 4) => {
            let passed = status == 2;
            // CPU0 observes only a successfully settled, uncancelled response.
            // A cancellation winning the pending-state CAS can never take this
            // path, even if CPU1 had already returned from its model SVC.
            crate::boot_recovery::model_settled(FINAL_CPU.load(Ordering::Acquire), passed);
            Some(passed)
        }
        3 => Some(false),
        _ => None,
    }
}
pub(super) fn cancel() {
    debug_put(49, crate::domain_tasks::now_ns());
    let cancelled = STATUS.compare_exchange(1, 3, Ordering::AcqRel, Ordering::Relaxed);
    debug_put(50, u64::from(cancelled.is_ok()));
}
