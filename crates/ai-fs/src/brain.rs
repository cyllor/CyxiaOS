//! Local, bounded integer models. Only metadata crosses this boundary.
use crate::weights;
use crate::{Error, NODES};

pub(crate) type Features = [i32; 4];
#[derive(Clone, Copy)]
struct Sample {
    x: Features,
    reused: bool,
}
const EMPTY: Sample = Sample {
    x: [0; 4],
    reused: false,
};

pub(crate) fn score(w: Features, x: Features) -> i32 {
    w.into_iter().zip(x).map(|(a, b)| a * b).sum()
}
fn correct(w: Features, samples: &[Sample]) -> usize {
    samples
        .iter()
        .filter(|s| (score(w, s.x) >= 0) == s.reused)
        .count()
}
fn canary(w: Features) -> usize {
    weights::CANARY
        .iter()
        .filter(|(x, y)| (score(w, *x) >= 0) == *y)
        .count()
}
#[derive(Clone, Copy, Debug)]
pub struct LearningStatus {
    pub version: u64,
    pub samples: usize,
    pub candidate: bool,
    pub rollback: bool,
    pub trained: u64,
    pub weights: [i32; 4],
    pub train_requests: u64,
    pub insufficient_samples: u64,
    pub validation_rejections: u64,
    pub publications: u64,
    pub rollbacks: u64,
    pub validation: Option<ValidationStatus>,
}
/// Classification checks on the frozen objective. These are not measured cache
/// hit-rate or latency improvements and must not be reported as such.
#[derive(Clone, Copy, Debug)]
pub struct ValidationStatus {
    pub active_holdout_correct: usize,
    pub candidate_holdout_correct: usize,
    pub active_canary_correct: usize,
    pub candidate_canary_correct: usize,
}
pub(crate) struct Brain {
    active: Features,
    candidate: Option<Features>,
    previous: Option<Features>,
    version: u64,
    samples: [Sample; 64],
    sample_count: usize,
    sample_next: usize,
    pending: [Features; NODES],
    valid: [bool; NODES],
    trained: u64,
    train_requests: u64,
    insufficient_samples: u64,
    validation_rejections: u64,
    publications: u64,
    rollbacks: u64,
    validation: Option<ValidationStatus>,
}
impl Brain {
    pub const fn new() -> Self {
        Self {
            active: weights::REUSE,
            candidate: None,
            previous: None,
            version: 1,
            samples: [EMPTY; 64],
            sample_count: 0,
            sample_next: 0,
            pending: [[0; 4]; NODES],
            valid: [false; NODES],
            trained: 0,
            train_requests: 0,
            insufficient_samples: 0,
            validation_rejections: 0,
            publications: 0,
            rollbacks: 0,
            validation: None,
        }
    }
    pub fn status(&self) -> LearningStatus {
        LearningStatus {
            version: self.version,
            samples: self.sample_count,
            candidate: self.candidate.is_some(),
            rollback: self.previous.is_some(),
            trained: self.trained,
            weights: self.active,
            train_requests: self.train_requests,
            insufficient_samples: self.insufficient_samples,
            validation_rejections: self.validation_rejections,
            publications: self.publications,
            rollbacks: self.rollbacks,
            validation: self.validation,
        }
    }
    pub fn admit(&self, free_after: usize, growth: usize) -> bool {
        score(
            weights::ADMISSION,
            [1, free_after as i32, growth.div_ceil(256) as i32, 0],
        ) >= 0
    }
    pub fn rank(&self, x: Features) -> i32 {
        score(self.active, x)
    }
    pub fn observe_read(
        &mut self,
        selected: usize,
        features: [Features; NODES],
        valid: [bool; NODES],
    ) {
        // Each read transition contributes exactly two rows (one event group).
        // The 48/16 split separates whole events, including all NODES slots.
        // A one-file system duplicates its positive row; there is no negative file.
        if self.valid[selected] {
            let start = self.sample_next / 2;
            let negative = (0..NODES)
                .map(|offset| (start + offset) % NODES)
                .find(|i| self.valid[*i] && *i != selected)
                .unwrap_or(selected);
            for i in [selected, negative] {
                self.samples[self.sample_next] = Sample {
                    x: self.pending[i],
                    reused: i == selected,
                };
                self.sample_next = (self.sample_next + 1) % 64;
                self.sample_count = (self.sample_count + 1).min(64);
            }
        }
        self.pending = features;
        self.valid = valid;
    }
    pub fn invalidate_history(&mut self) {
        // Mutations/reused node IDs must never label an old identity as the new file.
        self.valid = [false; NODES];
    }
    pub fn train(&mut self) -> Result<(), Error> {
        self.train_requests = self.train_requests.saturating_add(1);
        self.candidate = None;
        self.validation = None;
        if self.sample_count < 64 {
            self.insufficient_samples = self.insufficient_samples.saturating_add(1);
            return Err(Error::NeedSamples);
        }
        let mut ordered = [EMPTY; 64];
        for (i, s) in ordered.iter_mut().enumerate() {
            *s = self.samples[(self.sample_next + i) % 64];
        }
        let mut w = self.active;
        for _ in 0..8 {
            for s in &ordered[..48] {
                if (score(w, s.x) >= 0) != s.reused {
                    let sign = if s.reused { 1 } else { -1 };
                    for (weight, x) in w.iter_mut().zip(s.x) {
                        *weight = (*weight + sign * x).clamp(-512, 512);
                    }
                }
            }
        }
        self.trained = self.trained.saturating_add(1);
        let validation = ValidationStatus {
            active_holdout_correct: correct(self.active, &ordered[48..]),
            candidate_holdout_correct: correct(w, &ordered[48..]),
            active_canary_correct: canary(self.active),
            candidate_canary_correct: canary(w),
        };
        self.validation = Some(validation);
        if w == self.active
            || validation.candidate_holdout_correct < validation.active_holdout_correct
            || validation.candidate_canary_correct < validation.active_canary_correct
        {
            self.validation_rejections = self.validation_rejections.saturating_add(1);
            return Err(Error::CandidateRejected);
        }
        self.candidate = Some(w);
        Ok(())
    }
    pub fn apply(&mut self) -> Result<(), Error> {
        let w = self.candidate.ok_or(Error::NoCandidate)?;
        let next = self.version.checked_add(1).ok_or(Error::Exhausted)?;
        self.previous = Some(self.active);
        self.active = w;
        self.version = next;
        self.candidate = None;
        self.validation = None;
        self.publications = self.publications.saturating_add(1);
        // Start a new learning window; do not repeatedly promote on the same holdout.
        self.sample_count = 0;
        self.sample_next = 0;
        self.invalidate_history();
        Ok(())
    }
    pub fn rollback(&mut self) -> Result<(), Error> {
        let w = self.previous.ok_or(Error::NoCandidate)?;
        let next = self.version.checked_add(1).ok_or(Error::Exhausted)?;
        self.active = w;
        self.previous = None;
        self.candidate = None;
        self.validation = None;
        self.rollbacks = self.rollbacks.saturating_add(1);
        self.version = next;
        self.sample_count = 0;
        self.sample_next = 0;
        self.invalidate_history();
        Ok(())
    }
}
