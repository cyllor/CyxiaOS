//! Canonical signed framing and per-authenticated-session replay gate.
//! Framing does not implement sockets, encryption or reliable delivery. Sequence
//! numbers must increase; reorder/retry semantics belong to the reliable sender.
use super::{
    Clock, Digest, Error, Incarnation, NodeId, Result, Scope, Signature,
    auth::Crypto,
    codec::{Bytes, Reader},
    membership::Active,
};
pub const MAX_PAYLOAD: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Membership = 1,
    Contract = 2,
    Task = 3,
    Result = 4,
    Replication = 5,
}
impl Kind {
    fn read(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Membership),
            2 => Ok(Self::Contract),
            3 => Ok(Self::Task),
            4 => Ok(Self::Result),
            5 => Ok(Self::Replication),
            _ => Err(Error::Version),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Envelope<'a> {
    pub kind: Kind,
    pub scope: Scope,
    pub sender: Incarnation,
    pub receiver: NodeId,
    pub session: Digest,
    pub sequence: u64,
    pub payload: &'a [u8],
}
impl Envelope<'_> {
    pub fn signing_bytes(&self) -> Result<Bytes> {
        if !self.scope.valid()
            || !self.sender.valid()
            || !self.receiver.valid()
            || self.sender.node == self.receiver
            || self.session == [0; 32]
            || self.sequence == 0
            || self.payload.len() > MAX_PAYLOAD
        {
            return Err(Error::Invalid);
        }
        let mut b = Bytes::new();
        b.put(b"CYXNET01")?;
        b.u16(1)?;
        b.u8(self.kind as u8)?;
        b.u8(0)?;
        b.scope(self.scope)?;
        b.incarnation(self.sender)?;
        b.put(&self.receiver.0)?;
        b.put(&self.session)?;
        b.u64(self.sequence)?;
        b.u16(self.payload.len() as u16)?;
        b.put(self.payload)?;
        Ok(b)
    }
    pub fn packet(&self, signature: &Signature) -> Result<Bytes> {
        let mut b = self.signing_bytes()?;
        b.put(signature)?;
        Ok(b)
    }
}
pub fn decode(packet: &[u8]) -> Result<(Envelope<'_>, Signature)> {
    let mut r = Reader::new(packet);
    if r.get::<8>()? != *b"CYXNET01" {
        return Err(Error::Invalid);
    }
    if r.u16()? != 1 {
        return Err(Error::Version);
    }
    let kind = Kind::read(r.u8()?)?;
    if r.u8()? != 0 {
        return Err(Error::Invalid);
    }
    let scope = r.scope()?;
    let sender = r.incarnation()?;
    let receiver = NodeId(r.get()?);
    let session = r.get()?;
    let sequence = r.u64()?;
    let len = r.u16()? as usize;
    if len > MAX_PAYLOAD {
        return Err(Error::Capacity);
    }
    let payload = r.slice(len)?;
    let signature = r.get()?;
    r.end()?;
    let envelope = Envelope {
        kind,
        scope,
        sender,
        receiver,
        session,
        sequence,
        payload,
    };
    envelope.signing_bytes()?;
    Ok((envelope, signature))
}
pub struct Receiver {
    scope: Scope,
    local: Incarnation,
    peer: Incarnation,
    session: Digest,
    highwater: u64,
    deadline: u64,
    clock: Clock,
}
impl Receiver {
    /// session is a fresh CSPRNG nonce agreed by the authenticated handshake;
    /// never recreate a Receiver with a reused nonce after process recovery.
    pub fn new(
        active: &Active<'_>,
        peer: Incarnation,
        session: Digest,
        now: u64,
        deadline: u64,
    ) -> Result<Self> {
        if peer == active.local()
            || active.member(peer.node)?.identity != peer
            || session == [0; 32]
            || deadline <= now
        {
            return Err(Error::Invalid);
        }
        let mut clock = Clock::default();
        clock.observe(now)?;
        Ok(Self {
            scope: active.scope(),
            local: active.local(),
            peer,
            session,
            highwater: 0,
            deadline,
            clock,
        })
    }
    pub fn accept<'a>(
        &mut self,
        crypto: &impl Crypto,
        active: &Active<'_>,
        packet: &'a [u8],
        now: u64,
    ) -> Result<Envelope<'a>> {
        self.clock.observe(now)?;
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        let (e, sig) = decode(packet)?;
        if active.scope() != self.scope
            || active.local() != self.local
            || e.scope != self.scope
            || e.sender != self.peer
            || e.receiver != self.local.node
            || e.session != self.session
        {
            return Err(Error::Stale);
        }
        if e.sequence <= self.highwater {
            return Err(Error::Replay);
        }
        if !crypto.verify(e.sender.node, e.signing_bytes()?.as_slice(), &sig) {
            return Err(Error::Authentication);
        }
        self.highwater = e.sequence;
        Ok(e)
    }
    pub fn highwater(&self) -> u64 {
        self.highwater
    }
}
