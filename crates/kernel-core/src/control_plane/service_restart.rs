//! Same-BootEpoch lifecycle gate for a restartable EL0 service.
//!
//! This state carries no service-owned memory. Architecture code must close
//! admission, prove the old context stopped, preserve kernel custody and reset
//! private memory before calling `reset_complete`.
use super::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Resetting,
    Recovering,
    Ready,
    Isolated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    Restart { generation: u64 },
    Isolate,
}

pub struct Lifecycle {
    boot: u64,
    generation: u64,
    consecutive_faults: u8,
    phase: Phase,
}

impl Lifecycle {
    pub fn new(boot: u64, generation: u64) -> Result<Self, Error> {
        if boot == 0 || generation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot,
            generation,
            consecutive_faults: 0,
            phase: Phase::Recovering,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn ready(&self) -> bool {
        matches!(self.phase, Phase::Ready)
    }

    pub const fn accepts(&self, boot: u64, generation: u64) -> bool {
        boot == self.boot
            && generation == self.generation
            && matches!(self.phase, Phase::Recovering | Phase::Ready)
    }

    pub fn fault(&mut self, boot: u64, generation: u64) -> Result<RestartDecision, Error> {
        if !self.accepts(boot, generation) {
            return Err(Error::Stale);
        }
        self.consecutive_faults = self.consecutive_faults.saturating_add(1);
        if self.consecutive_faults >= 2 {
            self.phase = Phase::Isolated;
            return Ok(RestartDecision::Isolate);
        }
        let Some(next) = self.generation.checked_add(1) else {
            self.phase = Phase::Isolated;
            return Err(Error::Exhausted);
        };
        self.generation = next;
        self.phase = Phase::Resetting;
        Ok(RestartDecision::Restart { generation: next })
    }

    pub fn reset_complete(&mut self, boot: u64, generation: u64) -> Result<(), Error> {
        if self.phase == Phase::Isolated {
            return Err(Error::Busy);
        }
        if self.phase != Phase::Resetting || boot != self.boot || generation != self.generation {
            return Err(Error::Stale);
        }
        self.phase = Phase::Recovering;
        Ok(())
    }

    /// Only the authenticated peer READY transition proves that durable replay
    /// and exact custody reconciliation completed for this service generation.
    pub fn peer_ready(&mut self, boot: u64, generation: u64) -> Result<(), Error> {
        if self.phase != Phase::Recovering || boot != self.boot || generation != self.generation {
            return Err(Error::Stale);
        }
        self.consecutive_faults = 0;
        self.phase = Phase::Ready;
        Ok(())
    }
}
