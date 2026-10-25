use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

const TOKEN: u64 = 1_000_000_000;
const BURST: u64 = 4 * TOKEN;
pub const SOURCE_CAPACITY: usize = 32;
pub const HANDSHAKE_SLOTS: usize = 4;
pub const RECOVERY_SLOTS: usize = 2;
#[derive(Clone, Copy, Debug, Default)]
pub struct IngressCounters {
    pub attempts: u64,
    pub rejected: u64,
    pub failures: u64,
    pub accepted: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthTicket {
    pub slot: u8,
    pub generation: u64,
}
#[derive(Clone, Copy)]
struct Source {
    ip: [u8; 4],
    tokens: u64,
    last_seen: u64,
    active: u8,
}
#[derive(Clone, Copy)]
struct Session {
    key: ObjectKey,
    authorized: bool,
}
#[derive(Clone, Copy)]
struct Active {
    ticket: AuthTicket,
    source: Option<usize>,
    session: Option<usize>,
}
pub struct SecurityIngress {
    sources: [Option<Source>; SOURCE_CAPACITY],
    sessions: [Option<Session>; RECOVERY_SLOTS],
    slots: [Option<Active>; HANDSHAKE_SLOTS + RECOVERY_SLOTS],
    stamp: PolicyStamp,
    rate: u16,
    changed: Option<u64>,
    tokens: u64,
    now: u64,
    sequence: u64,
    pub counters: IngressCounters,
}
impl SecurityIngress {
    pub const fn new(now: u64) -> Self {
        Self {
            sources: [None; SOURCE_CAPACITY],
            sessions: [None; RECOVERY_SLOTS],
            slots: [None; HANDSHAKE_SLOTS + RECOVERY_SLOTS],
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            rate: 16,
            changed: None,
            tokens: BURST,
            now,
            sequence: 0,
            counters: IngressCounters {
                attempts: 0,
                rejected: 0,
                failures: 0,
                accepted: 0,
            },
        }
    }
    fn accrual(&self, now: u64, source: bool) -> u128 {
        let end = if self.stamp.version != 0 {
            now.min(self.stamp.installed_until_ns).max(self.now)
        } else {
            self.now
        };
        let selected = if source { self.rate.min(8) } else { self.rate };
        let baseline = if source { 8 } else { 16 };
        u128::from(end - self.now) * u128::from(selected) + u128::from(now - end) * baseline
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Stale);
        }
        let global = self.accrual(now, false);
        let source = self.accrual(now, true);
        self.tokens = (u128::from(self.tokens) + global).min(u128::from(BURST)) as u64;
        for s in self.sources.iter_mut().flatten() {
            s.tokens = (u128::from(s.tokens) + source).min(u128::from(BURST)) as u64;
        }
        self.now = now;
        Ok(())
    }
    pub fn effective_rate(&self, now: u64) -> Result<u16, Error> {
        if now < self.now {
            return Err(Error::Stale);
        }
        Ok(if self.stamp.live(now) { self.rate } else { 16 })
    }
    pub fn install(&mut self, stamp: PolicyStamp, rate: u16, now: u64) -> Result<(), Error> {
        Action::UnauthRate(rate).validate()?;
        self.time(now)?;
        self.stamp.accepts(stamp, now)?;
        if self.stamp.version == stamp.version {
            return if self.rate == rate {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        let prior = self.effective_rate(now)?;
        if rate != prior
            && self
                .changed
                .is_some_and(|at| now.saturating_sub(at) < TOKEN)
        {
            return Err(Error::Busy);
        }
        if rate != prior {
            self.changed = Some(now);
        }
        self.stamp = stamp;
        self.rate = rate;
        Ok(())
    }
    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        self.counters.rejected = self.counters.rejected.saturating_add(1);
        Err(error)
    }
    fn source(&mut self, ip: [u8; 4], now: u64) -> Result<usize, Error> {
        if let Some(i) = self
            .sources
            .iter()
            .position(|s| s.is_some_and(|s| s.ip == ip))
        {
            return Ok(i);
        }
        let free = self
            .sources
            .iter()
            .position(Option::is_none)
            .or_else(|| {
                self.sources
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| {
                        s.as_ref()
                            .filter(|s| {
                                s.active == 0
                                    && s.tokens == BURST
                                    && now.saturating_sub(s.last_seen) >= TOKEN
                            })
                            .map(|s| (i, s.last_seen))
                    })
                    .min_by_key(|(_, seen)| *seen)
                    .map(|(i, _)| i)
            })
            .ok_or(Error::Capacity)?;
        self.sources[free] = Some(Source {
            ip,
            tokens: BURST,
            last_seen: now,
            active: 0,
        });
        Ok(free)
    }
    pub fn begin(&mut self, ip: [u8; 4], now: u64) -> Result<AuthTicket, Error> {
        self.time(now)?;
        self.counters.attempts = self.counters.attempts.saturating_add(1);
        let i = match self.source(ip, now) {
            Ok(i) => i,
            Err(e) => return self.reject(e),
        };
        self.sources[i].as_mut().unwrap().last_seen = now;
        let Some(slot) = self.slots[..HANDSHAKE_SLOTS]
            .iter()
            .position(Option::is_none)
        else {
            return self.reject(Error::Again);
        };
        if self.tokens < TOKEN || self.sources[i].unwrap().tokens < TOKEN {
            return self.reject(Error::Again);
        }
        let generation = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let ticket = AuthTicket {
            slot: slot as u8,
            generation,
        };
        self.tokens -= TOKEN;
        let source = self.sources[i].as_mut().unwrap();
        source.tokens -= TOKEN;
        source.active += 1;
        self.sequence = generation;
        self.slots[slot] = Some(Active {
            ticket,
            source: Some(i),
            session: None,
        });
        self.counters.accepted = self.counters.accepted.saturating_add(1);
        Ok(ticket)
    }
    /// Only the authenticated transport owner may call this after verification.
    pub fn authorize_recovery_session(&mut self, key: ObjectKey) -> Result<(), Error> {
        if key.id == 0 || key.generation == 0 {
            return Err(Error::Auth);
        }
        if self
            .sessions
            .iter()
            .flatten()
            .any(|s| s.key == key && s.authorized)
        {
            return Ok(());
        }
        if self.sessions.iter().flatten().any(|s| s.key.id == key.id) {
            return Err(Error::Stale);
        }
        let slot = self
            .sessions
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Session {
            key,
            authorized: true,
        });
        Ok(())
    }
    pub fn begin_recovery(&mut self, key: ObjectKey, now: u64) -> Result<AuthTicket, Error> {
        self.time(now)?;
        let session = self
            .sessions
            .iter()
            .position(|s| s.is_some_and(|s| s.key == key && s.authorized))
            .ok_or(Error::Auth)?;
        let slot = HANDSHAKE_SLOTS + session;
        if self.slots[slot].is_some() {
            return Err(Error::Busy);
        }
        let generation = self.sequence.checked_add(1).ok_or(Error::Overflow)?;
        let ticket = AuthTicket {
            slot: slot as u8,
            generation,
        };
        self.sequence = generation;
        self.slots[slot] = Some(Active {
            ticket,
            source: None,
            session: Some(session),
        });
        Ok(ticket)
    }
    pub fn revoke_recovery_session(&mut self, key: ObjectKey) -> Result<(), Error> {
        let i = self
            .sessions
            .iter()
            .position(|s| s.is_some_and(|s| s.key == key))
            .ok_or(Error::Stale)?;
        if self.slots[HANDSHAKE_SLOTS + i].is_none() {
            self.sessions[i] = None;
        } else {
            self.sessions[i].as_mut().unwrap().authorized = false;
        }
        Ok(())
    }
    pub fn finish(
        &mut self,
        ticket: AuthTicket,
        authenticated: bool,
        now: u64,
    ) -> Result<(), Error> {
        self.time(now)?;
        let slot = usize::from(ticket.slot);
        let active = self
            .slots
            .get(slot)
            .copied()
            .flatten()
            .filter(|a| a.ticket == ticket)
            .ok_or(Error::Stale)?;
        self.slots[slot] = None;
        if let Some(i) = active.source {
            self.sources[i].as_mut().unwrap().active -= 1;
            if !authenticated {
                self.counters.failures = self.counters.failures.saturating_add(1);
            }
        }
        if let Some(i) = active.session
            && self.sessions[i].is_some_and(|s| !s.authorized)
        {
            self.sessions[i] = None;
        }
        // Failed TLS construction/verification never refunds either bucket.
        Ok(())
    }
    pub fn active(&self) -> (usize, usize) {
        (
            self.slots[..HANDSHAKE_SLOTS].iter().flatten().count(),
            self.slots[HANDSHAKE_SLOTS..].iter().flatten().count(),
        )
    }
}
