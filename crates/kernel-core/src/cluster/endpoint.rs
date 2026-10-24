//! Final-operation fencing at OwnerNode, not a coordinator-only lease check.
//! An operation must remain represented by its Permit until every side effect
//! and DMA/write reference is complete. New ownership is blocked while any old
//! operation is in flight. Recovery requires the real backend to prove drain.
use super::{
    Clock, Error, Incarnation, ObjectId, Result,
    codec::{Bytes, Reader},
    contracts::{InstallIntent, LeaseToken, Ledger},
    membership::Active,
    storage::{self, Key, Store},
};
const KIND: u16 = 3;
pub const MAX_OPERATIONS: usize = 64;
/// Implement at the device/VM/remote target that can actually stop old effects.
/// No automatic takeover is possible for a target that cannot provide proof.
pub trait DrainBackend {
    fn drained(&mut self, token: LeaseToken) -> bool;
}
pub struct DrainReceipt {
    token: LeaseToken,
}
impl DrainReceipt {
    pub(crate) fn token(&self) -> LeaseToken {
        self.token
    }
}
#[derive(Clone, Copy)]
struct State {
    floor: u64,
    token: Option<LeaseToken>,
    closed: bool,
}
pub struct Permit {
    slot: usize,
    id: u64,
    token: LeaseToken,
}
impl Permit {
    pub fn token(&self) -> LeaseToken {
        self.token
    }
}
pub struct Endpoint<const O: usize> {
    owner: Incarnation,
    resource: ObjectId,
    state: State,
    revision: u64,
    poisoned: bool,
    recovering: bool,
    quiesced: bool,
    operations: [Option<(u64, LeaseToken)>; O],
    next_operation: u64,
    clock: Clock,
}
impl<const O: usize> Endpoint<O> {
    pub fn open(store: &mut impl Store, owner: Incarnation, resource: ObjectId) -> Result<Self> {
        if O == 0 || O > MAX_OPERATIONS || !owner.valid() || !resource.valid() {
            return Err(Error::Invalid);
        }
        let mut this = Self {
            owner,
            resource,
            state: State {
                floor: 0,
                token: None,
                closed: true,
            },
            revision: 0,
            poisoned: false,
            recovering: false,
            quiesced: true,
            operations: [None; O],
            next_operation: 0,
            clock: Clock::default(),
        };
        if let Some((rev, b)) = storage::load(store, this.key())? {
            let mut r = Reader::new(b.as_slice());
            storage::read_header(&mut r, KIND)?;
            if r.get::<32>()? != owner.node.0 || r.get::<16>()? != resource.0 {
                return Err(Error::Corrupt);
            }
            let floor = r.u64()?;
            let closed = match r.u8()? {
                0 => false,
                1 => true,
                _ => return Err(Error::Corrupt),
            };
            let token = match r.u8()? {
                0 => None,
                1 => Some(LeaseToken::read(&mut r)?),
                _ => return Err(Error::Corrupt),
            };
            r.end()?;
            if token.is_some_and(|t| {
                t.owner.node != owner.node || t.resource != resource || t.serial != floor
            }) || (!closed && token.is_none())
            {
                return Err(Error::Corrupt);
            }
            this.state = State {
                floor,
                token,
                closed,
            };
            this.revision = rev;
            this.recovering = token.is_some();
            this.quiesced = token.is_none();
        }
        Ok(this)
    }
    fn key(&self) -> Key {
        let mut id = [0; 32];
        id[..16].copy_from_slice(&self.resource.0);
        Key { kind: KIND, id }
    }
    fn save(&mut self, store: &mut impl Store, next: State) -> Result<()> {
        let mut b = Bytes::new();
        storage::header(&mut b, KIND)?;
        b.put(&self.owner.node.0)?;
        b.put(&self.resource.0)?;
        b.u64(next.floor)?;
        b.u8(u8::from(next.closed))?;
        match next.token {
            Some(t) => {
                b.u8(1)?;
                t.write(&mut b)?;
            }
            None => b.u8(0)?,
        }
        storage::save(
            store,
            self.key(),
            &mut self.revision,
            &mut self.poisoned,
            &b,
        )?;
        self.state = next;
        Ok(())
    }
    pub fn in_flight(&self) -> usize {
        self.operations.iter().flatten().count()
    }
    pub fn floor(&self) -> u64 {
        self.state.floor
    }
    pub fn install(
        &mut self,
        store: &mut impl Store,
        intent: &InstallIntent,
        active: &Active<'_>,
        now: u64,
    ) -> Result<()> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        self.clock.observe(now)?;
        let t = intent.token();
        if t.owner != self.owner || t.resource != self.resource || active.local() != self.owner {
            return Err(Error::WrongOwner);
        }
        if t.scope != active.scope() || active.member(t.consumer.node)?.identity != t.consumer {
            return Err(Error::Stale);
        }
        if now >= t.expires_at {
            return Err(Error::Expired);
        }
        if self.recovering {
            return Err(Error::Reconcile);
        }
        if self.state.token == Some(t) && !self.state.closed {
            return Ok(());
        }
        if t.serial <= self.state.floor {
            return Err(Error::Stale);
        }
        if !self.state.closed || !self.quiesced || self.in_flight() != 0 {
            return Err(Error::Busy);
        }
        self.save(
            store,
            State {
                floor: t.serial,
                token: Some(t),
                closed: false,
            },
        )?;
        self.quiesced = false;
        Ok(())
    }
    pub fn check(
        &self,
        token: LeaseToken,
        active: &Active<'_>,
        actor: Incarnation,
        now: u64,
    ) -> Result<()> {
        if self.poisoned || self.recovering {
            return Err(Error::Reconcile);
        }
        if self.clock.broken || now < self.clock.last {
            return Err(Error::Clock);
        }
        if self.state.closed || self.state.token != Some(token) {
            return Err(Error::Stale);
        }
        if active.local() != self.owner || token.owner != self.owner || actor != token.consumer {
            return Err(Error::WrongOwner);
        }
        if token.scope != active.scope() || active.member(actor.node)?.identity != actor {
            return Err(Error::Stale);
        }
        if now >= token.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }
    /// An installed fence is necessary but not sufficient. New effects also
    /// require a live GRANTED ledger entry, never GrantIntent or Revoking.
    pub fn begin<const N: usize>(
        &mut self,
        token: LeaseToken,
        ledger: &Ledger<N>,
        active: &Active<'_>,
        actor: Incarnation,
        now: u64,
    ) -> Result<Permit> {
        self.clock.observe(now)?;
        self.check(token, active, actor, now)?;
        let (authorized, _) = ledger.execution(token.contract, self, active, now)?;
        if authorized != token {
            return Err(Error::Stale);
        }
        let slot = self
            .operations
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let id = self.next_operation.checked_add(1).ok_or(Error::Exhausted)?;
        self.operations[slot] = Some((id, token));
        self.next_operation = id;
        Ok(Permit { slot, id, token })
    }
    /// Release after actual completion; no model, membership or lease gate here.
    pub fn owns(&self, permit: &Permit) -> bool {
        self.operations.get(permit.slot) == Some(&Some((permit.id, permit.token)))
    }
    pub fn finish_ref(&mut self, permit: &Permit) -> Result<()> {
        let slot = self.operations.get_mut(permit.slot).ok_or(Error::Stale)?;
        if *slot != Some((permit.id, permit.token)) {
            return Err(Error::Stale);
        }
        *slot = None;
        Ok(())
    }
    pub fn finish(&mut self, permit: Permit) -> Result<()> {
        self.finish_ref(&permit)
    }
    pub fn revoke(&mut self, store: &mut impl Store, token: LeaseToken) -> Result<()> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if self.state.token != Some(token) {
            return Err(Error::Stale);
        }
        if !self.state.closed {
            let mut next = self.state;
            next.closed = true;
            self.save(store, next)?;
        }
        Ok(())
    }
    /// Recovery never resurrects a lease. Close the old token durably, then
    /// require real quiescence before returning a capacity-release receipt.
    pub fn drain(
        &mut self,
        store: &mut impl Store,
        backend: &mut impl DrainBackend,
    ) -> Result<DrainReceipt> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        let token = self.state.token.ok_or(Error::NotReady)?;
        self.revoke(store, token)?;
        if self.in_flight() != 0 {
            return Err(Error::Busy);
        }
        if !backend.drained(token) {
            return Err(Error::Unsupported);
        }
        self.recovering = false;
        self.quiesced = true;
        Ok(DrainReceipt { token })
    }
}
