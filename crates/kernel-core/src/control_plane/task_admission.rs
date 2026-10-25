//! CPU0 final execution authority for a single bounded pure-task slot. TLS and
//! protocol validation are supplied by the protected cluster service; this
//! ledger binds those facts to the active transport epoch and frozen resources.
use super::Error;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Called by the sole task executor between EL0 entries. Cancellation and
/// expiry of queued/suspended work do not require an execution credit.
pub fn expire_quiescent(
    state: &AtomicU64,
    cancelled: &AtomicBool,
    now: u64,
    deadline: &AtomicU64,
) -> bool {
    // Acquire the queued/suspended publication before reading its metadata.
    // CPU0 cannot release/reuse the slot in either state; CPU3 alone executes it.
    if matches!(state.load(Ordering::Acquire), 2 | 3)
        && (cancelled.load(Ordering::Acquire) || now >= deadline.load(Ordering::Relaxed))
    {
        state.store(5, Ordering::Release);
        true
    } else {
        false
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub cpu_milli: u64,
    pub memory_pages: u64,
    pub runtime_ms: u64,
    pub contract: [u8; 16],
    pub input_hash: [u8; 32],
    pub package_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartRequest {
    pub token: u64,
    pub contract: [u8; 16],
    pub grant: u64,
    pub deadline: u64,
    pub session: u64,
    pub input_hash: [u8; 32],
}
#[derive(Clone, Copy)]
struct Reservation {
    token: u64,
    terms: Terms,
    expires: u64,
    session: u64,
    generation: u64,
    deadline: Option<u64>,
    grant: u64,
    started: bool,
}
pub struct Authority {
    epoch: u64,
    generation: u64,
    level: u64,
    last_rx: u64,
    serial: u64,
    reservation: Option<Reservation>,
}
impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}
impl Authority {
    pub const fn new() -> Self {
        Self {
            epoch: 0,
            generation: 1,
            level: 0,
            last_rx: 0,
            serial: 0,
            reservation: None,
        }
    }
    pub fn disconnect(&mut self) {
        if self.level != 0 {
            self.generation = self.generation.saturating_add(1);
            self.level = 0;
        }
    }
    pub fn session(&mut self, epoch: u64, level: u64, now: u64) -> Result<(), Error> {
        if level == 0 {
            self.disconnect();
            return Ok(());
        }
        if epoch == 0 || level > 2 || now < self.last_rx || self.generation == u64::MAX {
            return Err(Error::Invalid);
        }
        if self.level != 0 && (self.epoch != epoch || now - self.last_rx >= 1500) {
            self.disconnect();
        }
        if level == 2 && self.level == 0 {
            return Err(Error::NotReady);
        }
        if level == 1 && self.level == 2 {
            self.disconnect();
        }
        self.epoch = epoch;
        self.level = level;
        self.last_rx = now;
        Ok(())
    }
    fn ready(&self, now: u64) -> Result<(), Error> {
        if self.level != 2 || now < self.last_rx || now - self.last_rx >= 1500 {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    pub fn reserve(&mut self, terms: Terms, installed: [u8; 32], now: u64) -> Result<u64, Error> {
        self.ready(now)?;
        if self.reservation.is_some() {
            return Err(Error::Busy);
        }
        if terms.cpu_milli != 100
            || terms.memory_pages != 16
            || !(1..=60000).contains(&terms.runtime_ms)
            || terms.contract == [0; 16]
            || terms.package_hash != installed
        {
            return Err(Error::Invalid);
        }
        let token = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let expires = now.checked_add(2000).ok_or(Error::Exhausted)?;
        self.serial = token;
        self.reservation = Some(Reservation {
            token,
            terms,
            expires,
            session: self.epoch,
            generation: self.generation,
            deadline: None,
            grant: 0,
            started: false,
        });
        Ok(token)
    }
    pub fn grant(
        &mut self,
        token: u64,
        contract: [u8; 16],
        grant: u64,
        deadline: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.ready(now)?;
        let r = self.reservation.as_mut().ok_or(Error::NotReady)?;
        if r.token != token
            || r.terms.contract != contract
            || grant != 1
            || r.generation != self.generation
            || r.session != self.epoch
        {
            return Err(Error::Stale);
        }
        if let Some(old) = r.deadline {
            return if old == deadline && r.grant == grant {
                Ok(())
            } else {
                Err(Error::Stale)
            };
        }
        if now >= r.expires || deadline <= now || deadline - now > r.terms.runtime_ms {
            return Err(Error::Expired);
        }
        r.deadline = Some(deadline);
        r.grant = grant;
        Ok(())
    }
    pub fn start(&mut self, request: StartRequest, now: u64) -> Result<(), Error> {
        self.ready(now)?;
        let r = self.reservation.as_mut().ok_or(Error::NotReady)?;
        if r.token != request.token
            || r.terms.contract != request.contract
            || r.grant != request.grant
            || r.deadline != Some(request.deadline)
            || r.session != request.session
            || request.session != self.epoch
            || r.generation != self.generation
            || r.terms.input_hash != request.input_hash
            || r.started
        {
            return Err(Error::Stale);
        }
        if now >= request.deadline {
            return Err(Error::Expired);
        }
        r.started = true;
        Ok(())
    }
    pub fn release(&mut self, token: u64) -> Result<(), Error> {
        if self.reservation.as_ref().is_none_or(|r| r.token != token) {
            return Err(Error::Stale);
        }
        self.reservation = None;
        Ok(())
    }
}
