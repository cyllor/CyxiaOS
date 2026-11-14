//! Per-CPU custody for a dispatch's evidence, including an irreversible
//! unstarted cancellation. No new dispatch may replace a retained custodian.
use super::cancellation::Binding;
use super::*;
enum Phase {
    Active,
    Completed {
        binding: Binding,
        first: u64,
        last: u64,
    },
    Cancelled(Cancellation),
}
struct Captured {
    binding: Binding,
    poisoned: bool,
    phase: Phase,
    refund: Option<CpuDebit>,
    owner: Option<crate::learning_evidence::OwnerAttempt>,
    warm: Option<crate::learning_prewarm::Attempt>,
}
struct Captures(core::cell::UnsafeCell<[Option<Captured>; 64]>);
// Only CPU i accesses slot i; IRQ handlers never access these cells.
unsafe impl Sync for Captures {}
static CAPTURES: Captures = Captures(core::cell::UnsafeCell::new([const { None }; 64]));
pub(super) const OWNED_BYTES: usize = core::mem::size_of::<Captures>();
fn cell(slot: usize) -> &'static mut Option<Captured> {
    assert!(slot < 64 && cpu::slot() == slot);
    // No reference escapes a synchronous metadata operation or crosses a
    // progress callback; each slot has exactly one CPU producer.
    unsafe { &mut *CAPTURES.0.get().cast::<Option<Captured>>().add(slot) }
}
pub(super) fn available(slot: usize) -> bool {
    cell(slot).is_none()
}
pub(super) fn track(
    slot: usize,
    result: Result<Option<Credit>, Error>,
) -> Result<Option<Credit>, Error> {
    if let Ok(Some(credit)) = &result {
        let cell = cell(slot);
        if cell.is_some() {
            return Err(Error::Conflict);
        }
        *cell = Some(Captured {
            poisoned: false,
            binding: Binding {
                sequence: credit.sequence,
                thread: credit.thread,
                cpu: slot,
            },
            phase: Phase::Active,
            refund: None,
            owner: crate::learning_evidence::attempt_work(credit.thread, credit.optional)
                .ok()
                .flatten(),
            warm: crate::learning_prewarm::attempt_task(credit.thread),
        });
    }
    result
}
pub(super) fn finish(slot: usize, first: u64, last: u64) {
    let cell = cell(slot);
    let Some(capture) = cell.as_mut() else {
        return;
    };
    // A second finish cannot rewrite completed times, repeat warm billing or
    // manufacture work from an unstarted cancellation. Keep the cell occupied
    // throughout callbacks; these paths never invoke progress or wait.
    if !matches!(capture.phase, Phase::Active) {
        return;
    }
    capture.phase = Phase::Completed {
        binding: capture.binding,
        first,
        last,
    };
    if let Some(mut warm) = capture.warm.take() {
        let _ = crate::learning_prewarm::finish(&mut warm, first, last);
    }
    if finish_completed(capture, matches!(slot, 2 | 3)) {
        *cell = None;
    }
}
fn finish_completed(capture: &mut Captured, retain: bool) -> bool {
    let Phase::Completed {
        binding,
        first,
        last,
    } = &capture.phase
    else {
        return false;
    };
    if capture.poisoned || *binding != capture.binding || binding.cpu != cpu::slot() {
        return false;
    }
    if let Some(owner) = capture.owner.as_mut() {
        let result = crate::learning_evidence::finish_attempt(owner, *first, *last);
        if retain
            && result == Err(crate::learning_evidence::Error::Busy)
            && owner.retryable_completion()
        {
            return false;
        }
        // Terminal failures retain their ordinary loss rules. CPU0 continues
        // using the shared handoff so a suspended collector's I/O progress does
        // not wait for itself. Business CPU2/3 keep Busy in this original cell.
        capture.owner = None;
    }
    true
}
/// Caller has just successfully cancelled this exact physical dispatch while
/// holding the task gate. Refund remains owned here until it succeeds.
pub(super) fn cancelled(slot: usize, dispatch: Dispatch, refund: Option<CpuDebit>) {
    let proof = Cancellation::new(dispatch);
    if let Some(capture) = cell(slot).as_mut() {
        if matches!(capture.phase, Phase::Active) {
            capture.phase = Phase::Cancelled(proof);
            capture.refund = refund;
        }
    } else {
        // Preserve even a custody violation as a closed slot; no replacement
        // body or successful evidence may be invented for it.
        *cell(slot) = Some(Captured {
            poisoned: true,
            binding: proof.binding,
            phase: Phase::Cancelled(proof),
            refund,
            owner: None,
            warm: None,
        });
    }
}
/// At most one bounded retirement attempt; Unknown/Busy retains the original
/// proof and every unfinished custodian. Never invokes progress or waits.
pub(super) fn retire(slot: usize) -> bool {
    let Some(capture) = cell(slot).as_mut() else {
        return true;
    };
    if matches!(capture.phase, Phase::Completed { .. }) {
        if !finish_completed(capture, true) {
            return false;
        }
        *cell(slot) = None;
        return true;
    }
    let Phase::Cancelled(proof) = &capture.phase else {
        return false;
    };
    if capture.poisoned || proof.binding != capture.binding {
        return false;
    }
    if let Some(debit) = capture.refund {
        if locked(|s| s.background.complete(debit, 0, now_ns())).is_err() {
            return false;
        }
        capture.refund = None;
    }
    if let Some(owner) = capture.owner.as_mut() {
        match crate::learning_evidence::cancel_unstarted(owner, proof) {
            Ok(()) => capture.owner = None,
            Err(crate::learning_evidence::Error::Busy) => return false,
            // An invalid/already-excluded token retains ordinary loss rules.
            Err(_) => {
                capture.owner = None;
            }
        }
    }
    if let Some(warm) = capture.warm.as_mut() {
        // Invalid tokens retain the ordinary prewarm loss path on drop.
        let _ = crate::learning_prewarm::cancel_unstarted(warm, proof);
        capture.warm = None;
    }
    *cell(slot) = None;
    true
}
