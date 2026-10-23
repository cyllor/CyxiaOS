//! Bounded local-model allowance for *new* checkpoint block submissions.
//! Completion, recovery and ordering remain executor mechanisms. Static model
//! parameters were fitted to a declared synthetic target, not measured benefits.
use crate::Error;
#[rustfmt::skip]
#[path = "storage_weights.rs"]
mod weights;

pub const MODEL_ID: u64 = 20481;
pub const WINDOW_MS: u64 = 8;

pub fn operation_budget(runnable: usize) -> Result<u8, Error> {
    if runnable > 8 {
        return Err(Error::Invalid);
    }
    let score = weights::SHARE[0] + weights::SHARE[1] * runnable as i32;
    Ok(if score >= 0 { 4 } else { 1 })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub decisions: u64,
    pub submitted: u64,
    pub deferred_polls: u64,
    pub quota: u8,
    pub used: u8,
    pub runnable: usize,
}

pub struct Window {
    start: Option<u64>,
    last_now: u64,
    status: Status,
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

impl Window {
    pub const fn new() -> Self {
        Self {
            start: None,
            last_now: 0,
            status: Status {
                decisions: 0,
                submitted: 0,
                deferred_polls: 0,
                quota: 0,
                used: 0,
                runnable: 0,
            },
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Revoke unspent allowance without refunding work in the current window.
    pub fn invalidate(&mut self) {
        self.status.quota = 0;
    }

    /// Inspect the trusted observation before each submission. Changed pressure
    /// revalidates a plan without refunding work already spent in this window.
    /// Call only when the executor has a new operation ready, never to complete
    /// an already-submitted operation. A false result is bounded backpressure.
    pub fn prepare(&mut self, now: u64, runnable: usize) -> Result<bool, Error> {
        if runnable > 8 || now < self.last_now {
            return Err(Error::Invalid);
        }
        let expired = self.start.is_none_or(|start| now - start >= WINDOW_MS);
        if expired || self.status.quota == 0 || runnable != self.status.runnable {
            let next = self
                .status
                .decisions
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
            let quota = operation_budget(runnable)?;
            if expired {
                self.start = Some(now);
                self.status.used = 0;
            }
            self.status.quota = quota;
            self.status.runnable = runnable;
            self.status.decisions = next;
        }
        self.last_now = now;
        if self.status.used >= self.status.quota {
            self.status.deferred_polls = self.status.deferred_polls.saturating_add(1);
            return Ok(false);
        }
        Ok(true)
    }

    /// Redeem only after the driver accepts the new submission. CPU0 serializes
    /// prepare/begin/consume; no inference, completion or wait is allowed between.
    pub fn consume(&mut self) -> Result<(), Error> {
        if self.start.is_none() || self.status.used >= self.status.quota {
            return Err(Error::Invariant);
        }
        self.status.used += 1;
        self.status.submitted = self.status.submitted.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fitted_model_changes_actual_submission_allowance() {
        for runnable in 0..=8 {
            let mut window = Window::new();
            let expected = if runnable <= 1 { 4 } else { 1 };
            for _ in 0..expected {
                assert!(window.prepare(10, runnable).unwrap());
                window.consume().unwrap();
            }
            assert!(!window.prepare(10, runnable).unwrap());
            assert_eq!(window.status().submitted, expected);
            assert_eq!(window.status().decisions, 1);
            assert!(!window.prepare(17, runnable).unwrap());
            assert!(window.prepare(18, runnable).unwrap());
            assert_eq!(window.status().used, 0);
        }
    }

    #[test]
    fn changing_pressure_does_not_refund_spent_work() {
        let mut window = Window::new();
        assert!(window.prepare(0, 0).unwrap());
        window.consume().unwrap();
        assert!(!window.prepare(0, 8).unwrap());
        assert!(window.prepare(0, 0).unwrap());
        for _ in 0..3 {
            window.consume().unwrap();
        }
        assert!(!window.prepare(0, 8).unwrap());
        assert!(!window.prepare(0, 0).unwrap());
        assert_eq!(window.status().submitted, 4);
    }

    #[test]
    fn invalid_observation_and_replay_cannot_mint_work() {
        let mut window = Window::new();
        assert_eq!(window.consume(), Err(Error::Invariant));
        assert_eq!(window.prepare(0, 9), Err(Error::Invalid));
        assert_eq!(window.status().decisions, 0);
        assert!(window.prepare(20, 8).unwrap());
        assert_eq!(window.prepare(19, 8), Err(Error::Invalid));
        window.consume().unwrap();
        assert_eq!(window.consume(), Err(Error::Invariant));
        window.invalidate();
        assert_eq!(window.consume(), Err(Error::Invariant));
        assert!(!window.prepare(20, 8).unwrap());
        assert_eq!(window.status().submitted, 1);
    }
}
