//! Challenge-bound liveness. Freshness is measured on the requesting node;
//! delayed or repeated heartbeats cannot renew their validity from arrival time.
//! This is failure suspicion, not quorum/election/ownership transfer.
use super::{
    Clock, Digest, Error, Incarnation, Result, Scope, Signature,
    auth::Crypto,
    codec::Bytes,
    membership::{Active, Membership},
    storage::Store,
};
#[derive(Clone, Copy)]
struct Probe {
    nonce: Digest,
    sequence: u64,
    sent: u64,
    deadline: u64,
}
pub struct Health {
    scope: Scope,
    local: Incarnation,
    remote: Incarnation,
    highwater: u64,
    pending: Option<Probe>,
    healthy_until: Option<u64>,
    clock: Clock,
}
impl Health {
    pub fn new(active: &Active<'_>, remote: Incarnation) -> Result<Self> {
        if remote == active.local() || active.member(remote.node)?.identity != remote {
            return Err(Error::WrongOwner);
        }
        Ok(Self {
            scope: active.scope(),
            local: active.local(),
            remote,
            highwater: 0,
            pending: None,
            healthy_until: None,
            clock: Clock::default(),
        })
    }
    pub fn probe(&mut self, nonce: Digest, now: u64, deadline: u64) -> Result<Bytes> {
        self.clock.observe(now)?;
        if nonce == [0; 32] || deadline <= now {
            return Err(Error::Invalid);
        }
        let sequence = self.highwater.checked_add(1).ok_or(Error::Exhausted)?;
        let p = Probe {
            nonce,
            sequence,
            sent: now,
            deadline,
        };
        let bytes = self.bytes(p)?;
        self.pending = Some(p);
        self.highwater = sequence;
        Ok(bytes)
    }
    fn bytes(&self, p: Probe) -> Result<Bytes> {
        let mut b = Bytes::new();
        b.put(b"CYXIA/LIVENESS/v1\0")?;
        b.scope(self.scope)?;
        b.incarnation(self.local)?;
        b.incarnation(self.remote)?;
        b.put(&p.nonce)?;
        b.u64(p.sequence)?;
        Ok(b)
    }
    pub fn response(
        &mut self,
        crypto: &impl Crypto,
        active: &Active<'_>,
        signature: &Signature,
        now: u64,
    ) -> Result<()> {
        self.clock.observe(now)?;
        if self.scope != active.scope()
            || self.local != active.local()
            || active.member(self.remote.node)?.identity != self.remote
        {
            return Err(Error::Stale);
        }
        let p = self.pending.ok_or(Error::Replay)?;
        if now < p.sent {
            return Err(Error::Clock);
        }
        if now >= p.deadline {
            return Err(Error::Expired);
        }
        if !crypto.verify(self.remote.node, self.bytes(p)?.as_slice(), signature) {
            return Err(Error::Authentication);
        }
        self.healthy_until = Some(p.deadline);
        self.pending = None;
        Ok(())
    }
    pub fn healthy(&mut self, now: u64) -> Result<bool> {
        self.clock.observe(now)?;
        Ok(self.healthy_until.is_some_and(|until| now < until))
    }
    /// Freeze shared new work; never erase membership history or mint a new ID.
    pub fn enforce(
        &mut self,
        membership: &mut Membership,
        store: &mut impl Store,
        now: u64,
    ) -> Result<bool> {
        let valid = self.healthy(now);
        let scope = membership.active().map(|a| a.scope()).ok();
        if valid != Ok(true) || scope != Some(self.scope) {
            membership.isolate(store)?;
            return valid.map(|_| false);
        }
        Ok(true)
    }
}
