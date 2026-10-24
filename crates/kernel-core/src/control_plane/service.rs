//! Trusted, single-owner ingress for an independent EL0 controller. No model is
//! called here. Input snapshots and actor/CPU identities are supplied by EL1;
//! user output is copied once before validation. A consumed response cannot be
//! replayed, even when its action is rejected by the core owner later.
use super::{
    Epochs, Identity,
    cores::{Phase, ScaleProposal, Snapshot},
};
use cyxia_control_model::abi::{Error, Input, OUTPUT_WORDS, Output};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub grow_windows: u32,
    pub shrink_windows: u32,
    pub high: i16,
    pub low: i16,
    pub minimum_benefit: i16,
    pub dwell_ticks: u64,
    pub request_ticks: u64,
    pub window_ticks: u64,
}
impl Config {
    pub fn validate(self) -> Result<Self, Error> {
        if self.grow_windows < 2
            || self.shrink_windows < 4
            || self.high <= self.low
            || self.low < 0
            || self.minimum_benefit <= 0
            || self.request_ticks == 0
            || self.dwell_ticks == 0
            || self.window_ticks == 0
        {
            return Err(Error::Invalid);
        }
        Ok(self)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Hold,
    Scale(ScaleProposal),
}
pub struct Port {
    actor: Identity,
    epochs: Epochs,
    config: Config,
    sequence: u64,
    pending: Option<Input>,
    high: u32,
    low: u32,
    last: u64,
    changed: u64,
    clock_failed: bool,
    last_window: u64,
    last_sample: u64,
}
impl Port {
    pub fn new(actor: Identity, epochs: Epochs, config: Config, now: u64) -> Result<Self, Error> {
        if !actor.valid() || !epochs.valid() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            actor,
            epochs,
            config: config.validate()?,
            sequence: 0,
            pending: None,
            high: 0,
            low: 0,
            last: now,
            changed: now,
            clock_failed: false,
            last_window: 0,
            last_sample: 0,
        })
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if self.clock_failed || now < self.last {
            self.clock_failed = true;
            self.pending = None;
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
    pub fn issue(&mut self, mut input: Input, now: u64) -> Result<Input, Error> {
        self.time(now)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if [
            input.boot,
            input.controller,
            input.model_epoch,
            input.resources,
            input.cores,
        ] != [
            self.epochs.boot,
            self.epochs.controller,
            self.epochs.model,
            self.epochs.resources,
            self.epochs.cores,
        ] {
            return Err(Error::Stale);
        }
        if input.window <= self.last_window || input.sample_start < self.last_sample {
            return Err(Error::Stale);
        }
        if input.sampled_at > now
            || input
                .sampled_at
                .checked_sub(input.sample_start)
                .ok_or(Error::Invalid)?
                < self.config.window_ticks
        {
            return Err(Error::Invalid);
        }
        let seq = self.sequence.checked_add(1).ok_or(Error::Capacity)?;
        input.sequence = seq;
        input.issued = now;
        input.expires = input
            .sampled_at
            .checked_add(self.config.request_ticks)
            .ok_or(Error::Capacity)?;
        if now >= input.expires {
            return Err(Error::Expired);
        }
        input.validate()?;
        if self.last_window != 0
            && (self.last_window.checked_add(1) != Some(input.window)
                || input.sample_start != self.last_sample)
        {
            self.high = 0;
            self.low = 0;
        }
        self.last_window = input.window;
        self.last_sample = input.sampled_at;
        self.sequence = seq;
        self.pending = Some(input);
        Ok(input)
    }
    pub fn accept(
        &mut self,
        actor: Identity,
        cpu: usize,
        words: [u64; OUTPUT_WORDS],
        current: Snapshot,
        now: u64,
    ) -> Result<Decision, Error> {
        self.time(now)?;
        if actor != self.actor || cpu >= 64 || current.control & (1 << cpu) == 0 {
            return Err(Error::Denied);
        }
        let p = self.pending.ok_or(Error::Stale)?;
        let out = Output::decode(words)?;
        if out.boot != p.boot
            || out.model_epoch != p.model_epoch
            || out.resources != p.resources
            || out.window != p.window
            || out.sequence != p.sequence
            || out.controller != p.controller
            || out.cores != p.cores
            || current.generation != p.cores
            || current.control != p.control
            || current.online != p.online
            || current.phase != Phase::Stable
        {
            return Err(Error::Stale);
        }
        if now >= p.expires {
            self.pending = None;
            self.high = 0;
            self.low = 0;
            return Err(Error::Expired);
        }
        // Each completed measurement window contributes once, not every retry.
        self.pending = None;
        self.high = if p.features[0] >= self.config.high
            && p.features[1] >= self.config.high
            && p.features[2] >= self.config.minimum_benefit
        {
            self.high.saturating_add(1)
        } else {
            0
        };
        self.low = if p.features[0] <= self.config.low && p.features[1] <= self.config.low {
            self.low.saturating_add(1)
        } else {
            0
        };
        if out.desired == p.control {
            return Ok(Decision::Hold);
        }
        let change = out.desired ^ p.control;
        if change.count_ones() != 1
            || out.desired == 0
            || out.desired == p.online
            || out.desired & !p.online != 0
            || p.protected_control & !out.desired != 0
            || p.protected_business & out.desired != 0
        {
            return Err(Error::Denied);
        }
        let grow = out.desired.count_ones() > p.control.count_ones();
        if out.action != if grow { 1 } else { 2 } {
            return Err(Error::Invalid);
        }
        if now - self.changed < self.config.dwell_ticks
            || (grow && self.high < self.config.grow_windows)
            || (!grow && self.low < self.config.shrink_windows)
        {
            return Ok(Decision::Hold);
        }
        Ok(Decision::Scale(ScaleProposal {
            generation: p.cores,
            resource_epoch: p.resources,
            sequence: p.sequence,
            desired_control: out.desired,
            deadline: p.expires,
        }))
    }
    /// Call only after CoreOwner actually committed. Rejected suggestions never
    /// pretend the action occurred or reset dwell accounting to a fake success.
    pub fn published(&mut self, epochs: Epochs, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if epochs.boot != self.epochs.boot
            || epochs.controller != self.epochs.controller
            || epochs.model != self.epochs.model
            || epochs.resources < self.epochs.resources
            || epochs.cores <= self.epochs.cores
        {
            return Err(Error::Stale);
        }
        self.epochs = epochs;
        self.pending = None;
        self.high = 0;
        self.low = 0;
        self.changed = now;
        Ok(())
    }
    pub fn expire(&mut self, now: u64) -> Result<bool, Error> {
        self.time(now)?;
        if self.pending.is_some_and(|p| now >= p.expires) {
            self.pending = None;
            self.high = 0;
            self.low = 0;
            return Ok(true);
        }
        Ok(false)
    }
    /// Kernel-authenticated lifecycle restart. Sequence high-water survives and
    /// all outstanding replies of the old controller become stale.
    pub fn restart(&mut self, actor: Identity, epochs: Epochs, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if !actor.valid()
            || !epochs.valid()
            || epochs.boot != self.epochs.boot
            || epochs.controller <= self.epochs.controller
            || epochs.model < self.epochs.model
            || epochs.resources < self.epochs.resources
            || epochs.cores < self.epochs.cores
        {
            return Err(Error::Stale);
        }
        self.actor = actor;
        self.epochs = epochs;
        self.pending = None;
        self.high = 0;
        self.low = 0;
        self.changed = now;
        Ok(())
    }
    /// A trusted model/constraint change withdraws pending work without
    /// resetting response sequence or sample-window replay protection.
    pub fn invalidate(&mut self, epochs: Epochs, now: u64) -> Result<(), Error> {
        self.time(now)?;
        if !epochs.valid()
            || epochs.boot != self.epochs.boot
            || epochs.controller != self.epochs.controller
            || epochs.model < self.epochs.model
            || epochs.resources < self.epochs.resources
            || epochs.cores < self.epochs.cores
            || epochs == self.epochs
        {
            return Err(Error::Stale);
        }
        self.epochs = epochs;
        self.pending = None;
        self.high = 0;
        self.low = 0;
        self.changed = now;
        Ok(())
    }
    pub fn epochs(&self) -> Epochs {
        self.epochs
    }
}
