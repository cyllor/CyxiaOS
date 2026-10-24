//! Per-thread accounting primitive. A timer/context-switch adapter must charge
//! real CPU time and program a timer before dispatch. This module alone does not
//! prove a hardware deadline, syscall latency bound, or multicore enforcement.
use super::{Error, Identity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub thread: Identity,
    pub sequence: u64,
    pub window: u64,
    pub starts_at: u64,
    pub ends_at: u64,
    pub quota: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    lease: Lease,
    spent: u64,
    last_time: u64,
}
impl Budget {
    fn validate(l: Lease, now: u64) -> Result<(), Error> {
        if !l.thread.valid()
            || l.window == 0
            || l.sequence == 0
            || l.quota == 0
            || l.starts_at > now
            || l.starts_at >= l.ends_at
        {
            return Err(Error::Invalid);
        }
        if l.ends_at <= now {
            return Err(Error::Expired);
        }
        if l.quota > l.ends_at - l.starts_at {
            return Err(Error::Denied);
        }
        Ok(())
    }
    /// Called only once for a newly admitted kernel thread identity.
    pub fn new(lease: Lease, now: u64) -> Result<Self, Error> {
        Self::validate(lease, now)?;
        Ok(Self {
            lease,
            spent: 0,
            last_time: now,
        })
    }
    /// Same-window replacement carries consumed CPU time forward. A new plan,
    /// model epoch or publisher restart cannot refill an already spent window.
    pub fn replace(&mut self, lease: Lease, now: u64) -> Result<(), Error> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        Self::validate(lease, now)?;
        if lease.thread != self.lease.thread
            || lease.sequence <= self.lease.sequence
            || lease.window < self.lease.window
        {
            return Err(Error::Stale);
        }
        let spent = if lease.window == self.lease.window {
            if lease.starts_at != self.lease.starts_at || lease.ends_at != self.lease.ends_at {
                return Err(Error::Denied);
            }
            self.spent
        } else {
            if now < self.lease.ends_at || lease.starts_at < self.lease.ends_at {
                return Err(Error::Denied);
            }
            0
        };
        self.lease = lease;
        self.spent = spent;
        self.last_time = now;
        Ok(())
    }
    /// Maximum legal next dispatch, bounded by quota AND absolute expiry.
    pub fn allowance(&self, now: u64, requested: u64) -> Result<u64, Error> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        if now >= self.lease.ends_at {
            return Ok(0);
        }
        Ok(requested
            .min(self.lease.quota.saturating_sub(self.spent))
            .min(self.lease.ends_at - now))
    }
    /// Returns true when the adapter must stop dispatching this thread. Even an
    /// overrun/late timer is charged and never creates a fresh allowance.
    pub fn charge(&mut self, elapsed: u64, now: u64) -> Result<bool, Error> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        self.spent = self.spent.saturating_add(elapsed);
        self.last_time = now;
        Ok(self.spent >= self.lease.quota || now >= self.lease.ends_at)
    }
    pub const fn spent(&self) -> u64 {
        self.spent
    }
    pub const fn lease(&self) -> Lease {
        self.lease
    }
}
