//! Bounded execution accounting. A proposal is not an execution receipt.
//!
//! The owner supplies the actual outcome after the mechanism returns. Counters
//! survive object reuse, saturate instead of wrapping, and do not select policy.
use cyxia_contracts::DecisionSource;

#[derive(Clone, Copy, Debug, Default)]
pub struct Attempt {
    pub proposed: bool,
    pub evaluated: bool,
    pub approved: bool,
    pub model: u64,
}
impl Attempt {
    pub fn proposed(&mut self, model: u64) {
        self.proposed = true;
        self.evaluated = false;
        self.approved = false;
        self.model = model;
    }
    pub fn decided(&mut self, approved: bool, model: u64) {
        self.proposed(model);
        self.evaluated = true;
        self.approved = approved;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Committed,
    Denied,
    Capacity,
    Invalid,
    Failed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub requests: u64,
    pub proposals: u64,
    pub approved: u64,
    pub denied: u64,
    pub capacity: u64,
    pub invalid: u64,
    pub failed: u64,
    pub committed: u64,
    pub granted: u64,
    pub released: u64,
    pub grant_units: u64,
    pub release_units: u64,
    pub ai: u64,
    pub guard: u64,
    pub cancelled: u64,
    pub enters: u64,
    pub returns: u64,
    pub elapsed_ms: u64,
    pub last_model: u64,
    pub last_errno: u64,
}
impl Counters {
    pub const ZERO: Self = Self {
        requests: 0,
        proposals: 0,
        approved: 0,
        denied: 0,
        capacity: 0,
        invalid: 0,
        failed: 0,
        committed: 0,
        granted: 0,
        released: 0,
        grant_units: 0,
        release_units: 0,
        ai: 0,
        guard: 0,
        cancelled: 0,
        enters: 0,
        returns: 0,
        elapsed_ms: 0,
        last_model: 0,
        last_errno: 0,
    };
    pub fn admission(&mut self, attempt: Attempt, outcome: Outcome, errno: u64) {
        self.requests = self.requests.saturating_add(1);
        if attempt.proposed {
            self.proposals = self.proposals.saturating_add(1);
            self.last_model = attempt.model;
        }
        if attempt.approved {
            self.approved = self.approved.saturating_add(1);
        }
        self.last_errno = errno;
        let counter = match outcome {
            Outcome::Committed => {
                if attempt.approved {
                    self.ai = self.ai.saturating_add(1);
                }
                &mut self.committed
            }
            Outcome::Denied => &mut self.denied,
            Outcome::Capacity => &mut self.capacity,
            Outcome::Invalid => &mut self.invalid,
            Outcome::Failed => &mut self.failed,
        };
        *counter = counter.saturating_add(1);
    }
    /// Called for each selected proposal, including speculative thread choices.
    pub fn proposal(&mut self, model: u64) {
        self.requests = self.requests.saturating_add(1);
        self.proposals = self.proposals.saturating_add(1);
        self.approved = self.approved.saturating_add(1);
        self.last_model = model;
    }
    /// Exactly once per selected dispatch that actually enters its context.
    pub fn dispatch(&mut self, source: DecisionSource) {
        self.committed = self.committed.saturating_add(1);
        match source {
            DecisionSource::AiDirect => self.ai = self.ai.saturating_add(1),
            DecisionSource::SafetyGuard => self.guard = self.guard.saturating_add(1),
            _ => {}
        }
    }
    pub fn cancelled(&mut self) {
        self.cancelled = self.cancelled.saturating_add(1);
    }
    pub fn entered(&mut self) {
        self.enters = self.enters.saturating_add(1);
    }
    pub fn returned(&mut self) {
        self.returns = self.returns.saturating_add(1);
    }
    /// Wall time includes synchronous syscall work; it is not EL0 CPU time.
    pub fn elapsed(&mut self, milliseconds: u64) {
        self.elapsed_ms = self.elapsed_ms.saturating_add(milliseconds);
    }
    pub fn grant(&mut self, units: u64) {
        self.granted = self.granted.saturating_add(1);
        self.grant_units = self.grant_units.saturating_add(units);
    }
    pub fn release(&mut self, units: u64) {
        self.released = self.released.saturating_add(1);
        self.release_units = self.release_units.saturating_add(units);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_later_pool_evaluation_cannot_inherit_an_earlier_approval() {
        let mut attempt = Attempt::default();
        attempt.decided(true, 8193);
        attempt.proposed(8193);
        // A failing second pool evaluation has no result or whole-request approval.
        assert!(attempt.proposed);
        assert!(!attempt.evaluated);
        assert!(!attempt.approved);
        let mut counters = Counters::ZERO;
        counters.admission(attempt, Outcome::Failed, 5);
        assert_eq!(
            (counters.requests, counters.proposals, counters.failed),
            (1, 1, 1)
        );
        assert_eq!(
            (counters.approved, counters.committed, counters.ai),
            (0, 0, 0)
        );
    }
    #[test]
    fn admission_outcomes_do_not_invent_model_calls_or_executions() {
        let mut c = Counters::ZERO;
        c.admission(Attempt::default(), Outcome::Capacity, 12);
        let mut a = Attempt::default();
        a.decided(false, 8194);
        c.admission(a, Outcome::Denied, 12);
        a.decided(true, 8194);
        c.admission(a, Outcome::Failed, 5);
        c.grant(4);
        c.admission(a, Outcome::Committed, 0);
        c.release(4);
        assert_eq!((c.requests, c.proposals, c.approved), (4, 3, 2));
        assert_eq!((c.capacity, c.denied, c.failed, c.committed), (1, 1, 1, 1));
        assert_eq!((c.ai, c.grant_units, c.release_units), (1, 4, 4));
    }
    #[test]
    fn terminated_before_entry_and_speculation_are_not_execution() {
        let mut c = Counters::ZERO;
        c.proposal(12289);
        c.cancelled();
        assert_eq!((c.proposals, c.committed, c.ai, c.enters), (1, 0, 0, 0));
        c.proposal(12289);
        c.dispatch(DecisionSource::SafetyGuard);
        for _ in 0..3 {
            c.entered();
            c.returned();
        }
        c.elapsed(4);
        assert_eq!(
            (c.committed, c.ai, c.guard, c.enters, c.returns),
            (1, 0, 1, 3, 3)
        );
        assert_eq!(c.elapsed_ms, 4);
    }
    #[test]
    fn saturation_and_new_object_attempt_keep_global_totals() {
        let mut c = Counters {
            requests: u64::MAX,
            grant_units: u64::MAX - 1,
            ..Counters::ZERO
        };
        c.admission(Attempt::default(), Outcome::Invalid, 22);
        c.grant(2);
        c.admission(Attempt::default(), Outcome::Invalid, 22);
        assert_eq!(
            (c.requests, c.invalid, c.grant_units),
            (u64::MAX, 2, u64::MAX)
        );
    }
}
