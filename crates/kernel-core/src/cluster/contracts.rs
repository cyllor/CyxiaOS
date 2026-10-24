//! Owner-local durable resource reservations, grant intents, and terminal receipts.
//! Tombstones are retained: a full ledger rejects new IDs instead of silently
//! forgetting an executed operation. TTL never releases a committed resource.
use super::{
    Clock, Error, Incarnation, ObjectId, Quota, Result, Scope,
    admission::Admission,
    codec::{Bytes, Reader},
    endpoint::{DrainReceipt, Endpoint},
    membership::Active,
    storage::{self, Key, Store},
};
use crate::control_plane::{Identity, policy::Environment};
const KIND: u16 = 2;
pub const MAX_CONTRACTS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: ObjectId,
    pub resource: ObjectId,
    pub consumer: Incarnation,
    pub subject: Identity,
    pub quota: Quota,
    pub isa: u16,
    pub abi: u32,
    /// Absolute ticks on OwnerNode, bound to its BootEpoch, NOT sender time.
    pub reservation_until: u64,
    pub lease_until: u64,
}
impl Request {
    fn valid(self) -> bool {
        self.id.valid()
            && self.resource.valid()
            && self.consumer.valid()
            && self.subject.valid()
            && self.quota.valid()
            && self.isa != 0
            && self.abi != 0
            && self.reservation_until != 0
            && self.lease_until >= self.reservation_until
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        b.put(&self.id.0)?;
        b.put(&self.resource.0)?;
        b.incarnation(self.consumer)?;
        b.u64(self.subject.id)?;
        b.u64(self.subject.generation)?;
        b.quota(self.quota)?;
        b.u16(self.isa)?;
        b.u32(self.abi)?;
        b.u64(self.reservation_until)?;
        b.u64(self.lease_until)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let q = Self {
            id: ObjectId(r.get()?),
            resource: ObjectId(r.get()?),
            consumer: r.incarnation()?,
            subject: Identity {
                id: r.u64()?,
                generation: r.u64()?,
            },
            quota: r.quota()?,
            isa: r.u16()?,
            abi: r.u32()?,
            reservation_until: r.u64()?,
            lease_until: r.u64()?,
        };
        if !q.valid() {
            return Err(Error::Corrupt);
        }
        Ok(q)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    Reserved = 1,
    GrantIntent = 2,
    Granted = 3,
    Revoking = 4,
    Released = 5,
}
impl Stage {
    fn read(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Reserved),
            2 => Ok(Self::GrantIntent),
            3 => Ok(Self::Granted),
            4 => Ok(Self::Revoking),
            5 => Ok(Self::Released),
            _ => Err(Error::Corrupt),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseToken {
    pub scope: Scope,
    pub owner: Incarnation,
    pub consumer: Incarnation,
    pub contract: ObjectId,
    pub resource: ObjectId,
    pub serial: u64,
    pub expires_at: u64,
}
impl LeaseToken {
    pub fn valid(self) -> bool {
        self.scope.valid()
            && self.owner.valid()
            && self.consumer.valid()
            && self.contract.valid()
            && self.resource.valid()
            && self.serial != 0
            && self.expires_at != 0
    }
    pub fn canonical(self) -> Result<Bytes> {
        let mut b = Bytes::new();
        b.put(b"CYXIA/LEASE/v1\0")?;
        self.write(&mut b)?;
        Ok(b)
    }
    pub(crate) fn write(self, b: &mut Bytes) -> Result<()> {
        b.scope(self.scope)?;
        b.incarnation(self.owner)?;
        b.incarnation(self.consumer)?;
        b.put(&self.contract.0)?;
        b.put(&self.resource.0)?;
        b.u64(self.serial)?;
        b.u64(self.expires_at)
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let t = Self {
            scope: r.scope()?,
            owner: r.incarnation()?,
            consumer: r.incarnation()?,
            contract: ObjectId(r.get()?),
            resource: ObjectId(r.get()?),
            serial: r.u64()?,
            expires_at: r.u64()?,
        };
        if !t.valid() {
            return Err(Error::Corrupt);
        }
        Ok(t)
    }
}
#[derive(Clone, Copy)]
struct Entry {
    request: Request,
    scope: Scope,
    owner: Incarnation,
    stage: Stage,
    serial: u64,
}
impl Entry {
    fn token(self) -> LeaseToken {
        LeaseToken {
            scope: self.scope,
            owner: self.owner,
            consumer: self.request.consumer,
            contract: self.request.id,
            resource: self.request.resource,
            serial: self.serial,
            expires_at: self.request.lease_until,
        }
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        self.request.write(b)?;
        b.scope(self.scope)?;
        b.incarnation(self.owner)?;
        b.u8(self.stage as u8)?;
        b.u64(self.serial)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let e = Self {
            request: Request::read(r)?,
            scope: r.scope()?,
            owner: r.incarnation()?,
            stage: Stage::read(r.u8()?)?,
            serial: r.u64()?,
        };
        if !e.scope.valid()
            || !e.owner.valid()
            || (matches!(
                e.stage,
                Stage::GrantIntent | Stage::Granted | Stage::Revoking
            ) && e.serial == 0)
        {
            return Err(Error::Corrupt);
        }
        Ok(e)
    }
}
/// Constructible only after persisting the owner's unique monotonic grant intent.
/// This is not a grant receipt and cannot by itself start a task.
pub struct InstallIntent {
    token: LeaseToken,
}
impl InstallIntent {
    pub fn token(&self) -> LeaseToken {
        self.token
    }
}
pub struct Ledger<const N: usize> {
    owner: Incarnation,
    capacity: Quota,
    max_lease: u64,
    entries: [Option<Entry>; N],
    eligible: [bool; N],
    highwater: u64,
    revision: u64,
    poisoned: bool,
    clock: Clock,
}
impl<const N: usize> Ledger<N> {
    pub fn open(
        store: &mut impl Store,
        owner: Incarnation,
        capacity: Quota,
        max_lease: u64,
    ) -> Result<Self> {
        if N == 0 || N > MAX_CONTRACTS || !owner.valid() || !capacity.valid() || max_lease == 0 {
            return Err(Error::Invalid);
        }
        let mut this = Self {
            owner,
            capacity,
            max_lease,
            entries: [None; N],
            eligible: [false; N],
            highwater: 0,
            revision: 0,
            poisoned: false,
            clock: Clock::default(),
        };
        if let Some((rev, b)) = storage::load(
            store,
            Key {
                kind: KIND,
                id: owner.node.0,
            },
        )? {
            let mut r = Reader::new(b.as_slice());
            storage::read_header(&mut r, KIND)?;
            if r.get::<32>()? != owner.node.0 || r.u16()? as usize != N {
                return Err(Error::Corrupt);
            }
            this.highwater = r.u64()?;
            for slot in &mut this.entries {
                *slot = match r.u8()? {
                    0 => None,
                    1 => Some(Entry::read(&mut r)?),
                    _ => return Err(Error::Corrupt),
                };
            }
            r.end()?;
            this.revision = rev;
            this.invariant()?;
        }
        // Recovered intents/grants remain charged but cannot resume execution.
        Ok(this)
    }
    fn invariant(&self) -> Result<()> {
        for (i, e) in self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.map(|e| (i, e)))
        {
            if e.owner.node != self.owner.node || e.serial > self.highwater {
                return Err(Error::Corrupt);
            }
            for f in self.entries[..i].iter().flatten() {
                if f.request.id == e.request.id
                    || (f.stage != Stage::Released
                        && e.stage != Stage::Released
                        && f.request.resource == e.request.resource)
                {
                    return Err(Error::Corrupt);
                }
            }
        }
        self.used()?;
        Ok(())
    }
    fn live(&mut self, now: u64) -> Result<()> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        self.clock.observe(now)
    }
    fn index(&self, id: ObjectId) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.is_some_and(|e| e.request.id == id))
            .ok_or(Error::NotReady)
    }
    fn save(
        &mut self,
        store: &mut impl Store,
        entries: [Option<Entry>; N],
        highwater: u64,
    ) -> Result<()> {
        let mut b = Bytes::new();
        storage::header(&mut b, KIND)?;
        b.put(&self.owner.node.0)?;
        b.u16(N as u16)?;
        b.u64(highwater)?;
        for entry in entries {
            match entry {
                None => b.u8(0)?,
                Some(e) => {
                    b.u8(1)?;
                    e.write(&mut b)?;
                }
            }
        }
        storage::save(
            store,
            Key {
                kind: KIND,
                id: self.owner.node.0,
            },
            &mut self.revision,
            &mut self.poisoned,
            &b,
        )?;
        self.entries = entries;
        self.highwater = highwater;
        Ok(())
    }
    pub fn used(&self) -> Result<Quota> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        let mut total = Quota::default();
        for e in self.entries.iter().flatten() {
            if e.stage != Stage::Released {
                total = total.checked_add(e.request.quota)?;
            }
        }
        Ok(total)
    }
    pub fn status(&self, id: ObjectId) -> Result<Stage> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        Ok(self.entries[self.index(id)?].ok_or(Error::NotReady)?.stage)
    }
    pub fn needs_reconcile(&self, id: ObjectId) -> Result<bool> {
        if self.poisoned {
            return Ok(true);
        }
        let i = self.index(id)?;
        Ok(self.poisoned
            || (!self.eligible[i] && self.entries[i].is_some_and(|e| e.stage != Stage::Released)))
    }
    pub fn prepare<const D: usize>(
        &mut self,
        store: &mut impl Store,
        active: &Active<'_>,
        request: Request,
        admission: &Admission<'_, D>,
        env: Environment,
    ) -> Result<Stage> {
        self.live(env.now)?;
        if active.local() != self.owner {
            return Err(Error::WrongOwner);
        }
        if !request.valid() || request.subject != admission.subject() {
            return Err(Error::Invalid);
        }
        let local = active.member(self.owner.node)?;
        if active.member(request.consumer.node)?.identity != request.consumer {
            return Err(Error::Stale);
        }
        if local.isa != request.isa || local.abi != request.abi {
            return Err(Error::Unsupported);
        }
        if let Ok(i) = self.index(request.id) {
            let e = self.entries[i].ok_or(Error::NotReady)?;
            return if e.request == request && e.scope == active.scope() && e.owner == self.owner {
                Ok(e.stage)
            } else {
                Err(Error::Conflict)
            };
        }
        if !self.used()?.checked_add(request.quota)?.fits(self.capacity) {
            return Err(Error::Capacity);
        }
        let mut subject_total = request.quota;
        for entry in self.entries.iter().flatten() {
            if entry.stage != Stage::Released && entry.request.subject == request.subject {
                subject_total = subject_total.checked_add(entry.request.quota)?;
            }
        }
        let policy_until = admission.check(subject_total, env)?;
        if request.reservation_until <= env.now
            || request.reservation_until > policy_until
            || request.lease_until <= env.now
            || request.lease_until - env.now > self.max_lease
        {
            return Err(Error::Expired);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|e| e.request.resource == request.resource && e.stage != Stage::Released)
        {
            return Err(Error::Busy);
        }
        let i = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut next = self.entries;
        next[i] = Some(Entry {
            request,
            scope: active.scope(),
            owner: self.owner,
            stage: Stage::Reserved,
            serial: 0,
        });
        self.save(store, next, self.highwater)?;
        self.eligible[i] = true;
        Ok(Stage::Reserved)
    }
    pub fn begin_grant(
        &mut self,
        store: &mut impl Store,
        active: &Active<'_>,
        id: ObjectId,
        now: u64,
    ) -> Result<InstallIntent> {
        self.live(now)?;
        let i = self.index(id)?;
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        if !self.eligible[i] {
            return Err(Error::Reconcile);
        }
        if active.local() != self.owner || e.owner != self.owner || e.scope != active.scope() {
            return Err(Error::Stale);
        }
        if now >= e.request.lease_until {
            return Err(Error::Expired);
        }
        if matches!(e.stage, Stage::GrantIntent | Stage::Granted) {
            return Ok(InstallIntent { token: e.token() });
        }
        if e.stage != Stage::Reserved {
            return Err(Error::NotReady);
        }
        if now >= e.request.reservation_until {
            return Err(Error::Expired);
        }
        if !self.used()?.fits(self.capacity) {
            return Err(Error::Capacity);
        }
        let serial = self.highwater.checked_add(1).ok_or(Error::Exhausted)?;
        e.serial = serial;
        e.stage = Stage::GrantIntent;
        let mut next = self.entries;
        next[i] = Some(e);
        self.save(store, next, serial)?;
        Ok(InstallIntent { token: e.token() })
    }
    /// Grant succeeds only after the final operation endpoint durably installed
    /// this exact fence. Failed/delayed install never becomes a granted contract.
    pub fn commit_grant<const O: usize>(
        &mut self,
        store: &mut impl Store,
        active: &Active<'_>,
        id: ObjectId,
        endpoint: &Endpoint<O>,
        now: u64,
    ) -> Result<LeaseToken> {
        self.live(now)?;
        let i = self.index(id)?;
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        if !self.eligible[i] {
            return Err(Error::Reconcile);
        }
        if !matches!(e.stage, Stage::GrantIntent | Stage::Granted) {
            return Err(Error::NotReady);
        }
        endpoint.check(e.token(), active, e.request.consumer, now)?;
        if e.stage != Stage::Granted {
            e.stage = Stage::Granted;
            let mut next = self.entries;
            next[i] = Some(e);
            self.save(store, next, self.highwater)?;
        }
        Ok(e.token())
    }
    pub fn execution<const O: usize>(
        &self,
        id: ObjectId,
        endpoint: &Endpoint<O>,
        active: &Active<'_>,
        now: u64,
    ) -> Result<(LeaseToken, Request)> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if self.clock.broken || now < self.clock.last {
            return Err(Error::Clock);
        }
        let i = self.index(id)?;
        let e = self.entries[i].ok_or(Error::NotReady)?;
        if !self.eligible[i] {
            return Err(Error::Reconcile);
        }
        if e.stage != Stage::Granted {
            return Err(Error::NotReady);
        }
        endpoint.check(e.token(), active, e.request.consumer, now)?;
        Ok((e.token(), e.request))
    }
    pub fn mark_revoking(
        &mut self,
        store: &mut impl Store,
        id: ObjectId,
        now: u64,
    ) -> Result<LeaseToken> {
        self.live(now)?;
        let i = self.index(id)?;
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        if !matches!(
            e.stage,
            Stage::GrantIntent | Stage::Granted | Stage::Revoking
        ) {
            return Err(Error::NotReady);
        }
        if e.stage != Stage::Revoking {
            e.stage = Stage::Revoking;
            let mut next = self.entries;
            next[i] = Some(e);
            self.save(store, next, self.highwater)?;
        }
        Ok(e.token())
    }
    /// Completion/release remains possible without a model or active membership.
    pub fn release(
        &mut self,
        store: &mut impl Store,
        receipt: DrainReceipt,
        now: u64,
    ) -> Result<()> {
        self.live(now)?;
        let token = receipt.token();
        let i = self.index(token.contract)?;
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        if e.token() != token {
            return Err(Error::Stale);
        }
        if e.stage == Stage::Released {
            return Ok(());
        }
        if !matches!(
            e.stage,
            Stage::GrantIntent | Stage::Granted | Stage::Revoking
        ) {
            return Err(Error::NotReady);
        }
        e.stage = Stage::Released;
        let mut next = self.entries;
        next[i] = Some(e);
        self.save(store, next, self.highwater)?;
        self.eligible[i] = false;
        Ok(())
    }
    /// Only uncommitted reservations can expire without endpoint drain evidence.
    pub fn expire_reservations(&mut self, store: &mut impl Store, now: u64) -> Result<usize> {
        self.live(now)?;
        let mut next = self.entries;
        let mut count = 0;
        for e in next.iter_mut().flatten() {
            if e.stage == Stage::Reserved
                && (e.owner != self.owner || now >= e.request.reservation_until)
            {
                e.stage = Stage::Released;
                count += 1;
            }
        }
        if count > 0 {
            self.save(store, next, self.highwater)?;
        }
        Ok(count)
    }
}
