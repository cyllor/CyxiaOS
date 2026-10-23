//! One-shot display pacing decisions from bounded, integer local inference.
//!
//! This policy cannot access pixels or input events. It chooses a 0/1 ms delay
//! before an already admitted rectangle is submitted. The caller owns one
//! staging slot and must finish accepted DMA regardless of process lifetime.
//! Completion latency is feedback to fixed weights, not online weight learning.
use cyxia_contracts::DecisionSource;
#[path = "display_weights.rs"]
#[rustfmt::skip]
mod weights;

pub const MODEL: u64 = 0x6001;
pub const VERSION: u32 = 1;
pub const MAX_PIXELS: usize = 16384;
const WAIT_BUDGET_INTERVAL: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Invalid,
    Exhausted,
    State,
    Clock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Queued,
    Submitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    None,
    Admitted,
    Submitted,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub id: u64,
    pub owner: u32,
    pub pixels: usize,
    pub accepted_at: u64,
    pub ready_at: u64,
    pub delay_ms: u8,
    pub score: i32,
    pub source: DecisionSource,
    pub observed_fence_ms: u64,
    pub observed_completed: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct Status {
    pub phase: Phase,
    pub outcome: Outcome,
    pub proposals: u64,
    pub admitted: u64,
    pub ai_admitted: u64,
    pub guard_admitted: u64,
    pub submitted: u64,
    pub completed: u64,
    pub failed: u64,
    pub busy: u64,
    pub invalid: u64,
    pub clock_rejected: u64,
    pub guards: u64,
    pub delayed: u64,
    pub planned_wait_ms: u64,
    pub actual_queue_ms: u64,
    pub max_queue_ms: u64,
    pub fence_ms: u64,
    pub max_fence_ms: u64,
    pub latest: Option<Plan>,
}

pub struct Pacer {
    status: Status,
    submitted_at: u64,
    since_wait: u8,
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

impl Pacer {
    pub const fn new() -> Self {
        Self {
            status: Status {
                phase: Phase::Idle,
                outcome: Outcome::None,
                proposals: 0,
                admitted: 0,
                ai_admitted: 0,
                guard_admitted: 0,
                submitted: 0,
                completed: 0,
                failed: 0,
                busy: 0,
                invalid: 0,
                clock_rejected: 0,
                guards: 0,
                delayed: 0,
                planned_wait_ms: 0,
                actual_queue_ms: 0,
                max_queue_ms: 0,
                fence_ms: 0,
                max_fence_ms: 0,
                latest: None,
            },
            submitted_at: 0,
            since_wait: 0,
        }
    }

    pub fn status(&self) -> Status {
        self.status
    }

    /// Validate and commit one local-model decision. Busy/invalid calls do not
    /// infer or replace the existing plan. No other request can overtake it.
    pub fn admit(&mut self, owner: u32, pixels: usize, now: u64) -> Result<Plan, Error> {
        if owner == 0 || pixels == 0 || pixels > MAX_PIXELS {
            self.status.invalid = self.status.invalid.saturating_add(1);
            return Err(Error::Invalid);
        }
        if self.status.phase != Phase::Idle {
            self.status.busy = self.status.busy.saturating_add(1);
            return Err(Error::Busy);
        }
        let Some(id) = self.status.admitted.checked_add(1) else {
            self.status.invalid = self.status.invalid.saturating_add(1);
            return Err(Error::Exhausted);
        };
        let features = [
            1,
            self.status.fence_ms.min(16) as i32,
            i32::from(self.since_wait),
            0,
        ];
        let score = weights::DISPLAY
            .iter()
            .zip(features)
            .map(|(w, x)| w * x)
            .sum();
        self.status.proposals = self.status.proposals.saturating_add(1);
        let (delay_ms, source) = pacing_choice(score, self.since_wait);
        // Hard overhead ceiling, independent of model quality: at most one
        // planned millisecond per eight completed rectangles. It never adds
        // delay or selects an alternative optimizer when a model is rejected.
        let Some(ready_at) = now.checked_add(u64::from(delay_ms)) else {
            self.status.clock_rejected = self.status.clock_rejected.saturating_add(1);
            return Err(Error::Clock);
        };
        let plan = Plan {
            id,
            owner,
            pixels,
            accepted_at: now,
            ready_at,
            delay_ms,
            score,
            source,
            observed_fence_ms: self.status.fence_ms,
            observed_completed: self.since_wait,
        };
        if delay_ms != 0 {
            self.since_wait = 0;
            self.status.delayed = self.status.delayed.saturating_add(1);
            self.status.planned_wait_ms = self
                .status
                .planned_wait_ms
                .saturating_add(u64::from(delay_ms));
        }
        self.status.admitted = id;
        if source == DecisionSource::AiDirect {
            self.status.ai_admitted = self.status.ai_admitted.saturating_add(1);
        } else {
            self.status.guard_admitted = self.status.guard_admitted.saturating_add(1);
            self.status.guards = self.status.guards.saturating_add(1);
        }
        self.status.latest = Some(plan);
        self.status.phase = Phase::Queued;
        self.status.outcome = Outcome::Admitted;
        Ok(plan)
    }

    pub fn ready(&self, now: u64) -> bool {
        self.status.phase == Phase::Queued
            && self.status.latest.is_some_and(|plan| now >= plan.ready_at)
    }

    /// The driver has accepted the transfer. A queued proposal alone is not a
    /// submitted/completed resource receipt.
    pub fn submitted(&mut self, now: u64) -> Result<(), Error> {
        if !self.ready(now) {
            return Err(Error::State);
        }
        let plan = self.status.latest.ok_or(Error::State)?;
        let queued = now.checked_sub(plan.accepted_at).ok_or(Error::Clock)?;
        self.status.actual_queue_ms = self.status.actual_queue_ms.saturating_add(queued);
        self.status.max_queue_ms = self.status.max_queue_ms.max(queued);
        self.status.submitted = self.status.submitted.saturating_add(1);
        self.status.phase = Phase::Submitted;
        self.status.outcome = Outcome::Submitted;
        self.submitted_at = now;
        Ok(())
    }

    /// Called only after the matching transfer AND flush fence, or a real
    /// driver failure. Owner death is not cancellation and must not call this.
    pub fn finish(&mut self, now: u64, success: bool) -> Result<(), Error> {
        if self.status.phase == Phase::Idle || (success && self.status.phase != Phase::Submitted) {
            return Err(Error::State);
        }
        if success {
            let latency = now.checked_sub(self.submitted_at).ok_or(Error::Clock)?;
            self.status.fence_ms = latency;
            self.status.max_fence_ms = self.status.max_fence_ms.max(latency);
            self.status.completed = self.status.completed.saturating_add(1);
            self.status.outcome = Outcome::Completed;
            self.since_wait = self.since_wait.saturating_add(1).min(WAIT_BUDGET_INTERVAL);
        } else {
            self.status.failed = self.status.failed.saturating_add(1);
            self.status.outcome = Outcome::Failed;
        }
        self.status.phase = Phase::Idle;
        Ok(())
    }
}

fn pacing_choice(score: i32, completed: u8) -> (u8, DecisionSource) {
    if score >= 0 && completed < WAIT_BUDGET_INTERVAL {
        (0, DecisionSource::SafetyGuard)
    } else {
        (u8::from(score >= 0), DecisionSource::AiDirect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(pacer: &mut Pacer, now: &mut u64, fence: u64) -> Plan {
        let plan = pacer.admit(7, MAX_PIXELS, *now).unwrap();
        if plan.ready_at != 0 {
            assert!(!pacer.ready(plan.ready_at - 1));
        }
        *now = plan.ready_at;
        pacer.submitted(*now).unwrap();
        *now += fence;
        pacer.finish(*now, true).unwrap();
        plan
    }

    #[test]
    fn measured_fence_feedback_changes_real_model_output() {
        let mut pacer = Pacer::new();
        let mut now = 10;
        for _ in 0..8 {
            assert_eq!(complete(&mut pacer, &mut now, 4).delay_ms, 0);
        }
        let delayed = complete(&mut pacer, &mut now, 1);
        assert_eq!(delayed.delay_ms, 1);
        assert_eq!(delayed.observed_fence_ms, 4);
        assert_eq!(complete(&mut pacer, &mut now, 1).delay_ms, 0);
        assert_eq!(pacer.status().delayed, 1);
        assert_eq!(pacer.status().ai_admitted, pacer.status().admitted);
        assert_eq!(pacer.status().guard_admitted, 0);
    }

    #[test]
    fn overhead_guard_has_a_distinct_non_ai_source() {
        assert_eq!(pacing_choice(1, 7), (0, DecisionSource::SafetyGuard));
        assert_eq!(pacing_choice(1, 8), (1, DecisionSource::AiDirect));
        assert_eq!(pacing_choice(-1, 7), (0, DecisionSource::AiDirect));
    }

    #[test]
    fn full_frame_has_bounded_planned_cost_and_distinct_actual_latency() {
        let mut pacer = Pacer::new();
        let mut now = 10;
        for _ in 0..48 {
            complete(&mut pacer, &mut now, 250);
        }
        let status = pacer.status();
        assert!(status.planned_wait_ms <= 6);
        assert_eq!(status.completed, 48);
        assert_eq!(status.fence_ms, 250);
        let plan = pacer.admit(7, 1, now).unwrap();
        pacer.submitted(plan.ready_at + 20).unwrap();
        assert!(pacer.status().actual_queue_ms > pacer.status().planned_wait_ms);
        assert!(pacer.status().max_queue_ms >= 20);
    }

    #[test]
    fn busy_or_invalid_call_cannot_replace_pending_owner_or_infer() {
        let mut pacer = Pacer::new();
        assert_eq!(pacer.admit(0, 1, 1), Err(Error::Invalid));
        assert_eq!(pacer.admit(1, MAX_PIXELS + 1, 1), Err(Error::Invalid));
        let plan = pacer.admit(7, 4, 10).unwrap();
        assert_eq!(pacer.admit(0, 4, 11), Err(Error::Invalid));
        assert_eq!(pacer.admit(8, 4, 11), Err(Error::Busy));
        assert_eq!(pacer.status().latest, Some(plan));
        assert_eq!(pacer.status().proposals, 1);
        assert_eq!(pacer.finish(11, true), Err(Error::State));
        pacer.submitted(11).unwrap();
        assert_eq!(pacer.admit(8, 4, 12), Err(Error::Busy));
        pacer.finish(13, true).unwrap();
        assert_eq!(pacer.finish(13, true), Err(Error::State));
    }

    #[test]
    fn submission_failure_is_not_success_and_clock_cannot_wrap() {
        let mut pacer = Pacer::new();
        let mut now = 0;
        for _ in 0..8 {
            complete(&mut pacer, &mut now, 4);
        }
        let previous = pacer.status().latest;
        assert_eq!(pacer.admit(1, 4, u64::MAX), Err(Error::Clock));
        assert_eq!(pacer.status().phase, Phase::Idle);
        assert_eq!(pacer.status().clock_rejected, 1);
        assert_eq!(pacer.status().latest, previous);
        pacer.admit(1, 4, now).unwrap();
        pacer.finish(now, false).unwrap();
        let status = pacer.status();
        assert_eq!(status.failed, 1);
        assert_eq!(status.admitted, 9);
        assert_eq!(status.submitted, 8);
        assert_eq!(status.completed, 8);
    }

    #[test]
    fn every_full_frame_window_respects_the_pacing_ceiling() {
        let mut pacer = Pacer::new();
        let mut now = 10;
        let mut delays = [0u8; 160];
        for delay in &mut delays {
            *delay = complete(&mut pacer, &mut now, 250).delay_ms;
        }
        for frame in delays.windows(48) {
            assert!(frame.iter().map(|delay| u32::from(*delay)).sum::<u32>() <= 6);
        }
    }
}
