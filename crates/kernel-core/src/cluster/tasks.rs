//! Durable activation deduplication. Persist Running BEFORE invoking launch;
//! ambiguous launch/restart becomes Uncertain, never an automatic second launch.
//! At-most-one launch attempt is not exactly-once external physical effects.
use super::{
    Clock, Digest, Error, ObjectId, Result,
    codec::{Bytes, Reader},
    contracts::{LeaseToken, Ledger},
    endpoint::{Endpoint, Permit},
    membership::Active,
    storage::{self, Key, Store},
};
const KIND: u16 = 4;
pub const MAX_TASKS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub task: ObjectId,
    pub activation: u64,
    pub operation: ObjectId,
    pub contract: ObjectId,
    pub payload_digest: Digest,
    pub isa: u16,
    pub abi: u32,
}
impl Request {
    fn valid(self) -> bool {
        self.task.valid()
            && self.activation != 0
            && self.operation.valid()
            && self.contract.valid()
            && self.payload_digest != [0; 32]
            && self.isa != 0
            && self.abi != 0
    }
    fn write(self, b: &mut Bytes) -> Result<()> {
        b.put(&self.task.0)?;
        b.u64(self.activation)?;
        b.put(&self.operation.0)?;
        b.put(&self.contract.0)?;
        b.put(&self.payload_digest)?;
        b.u16(self.isa)?;
        b.u32(self.abi)
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let q = Self {
            task: ObjectId(r.get()?),
            activation: r.u64()?,
            operation: ObjectId(r.get()?),
            contract: ObjectId(r.get()?),
            payload_digest: r.get()?,
            isa: r.u16()?,
            abi: r.u32()?,
        };
        if !q.valid() {
            return Err(Error::Corrupt);
        }
        Ok(q)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub code: i32,
    pub digest: Digest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Prepared = 1,
    Running = 2,
    Completed = 3,
    NotStarted = 4,
    Uncertain = 5,
}
impl Status {
    fn read(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Running),
            3 => Ok(Self::Completed),
            4 => Ok(Self::NotStarted),
            5 => Ok(Self::Uncertain),
            _ => Err(Error::Corrupt),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    NotStarted,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Completed(Outcome),
    NotStarted,
    Unknown,
}
pub trait Executor {
    /// Called synchronously once, under the owner's management serializer.
    /// Spawn the real native executable; preserve operation identity at devices.
    fn launch(
        &mut self,
        request: Request,
        lease: LeaseToken,
    ) -> core::result::Result<(), LaunchError>;
    /// Query real execution/device state, not a guess from a timeout.
    fn reconcile(&mut self, request: Request, lease: LeaseToken) -> Observation;
}
#[derive(Clone, Copy)]
struct Entry {
    request: Request,
    lease: LeaseToken,
    status: Status,
    outcome: Option<Outcome>,
}
impl Entry {
    fn write(self, b: &mut Bytes) -> Result<()> {
        self.request.write(b)?;
        self.lease.write(b)?;
        b.u8(self.status as u8)?;
        match self.outcome {
            None => b.u8(0)?,
            Some(o) => {
                b.u8(1)?;
                b.u32(o.code as u32)?;
                b.put(&o.digest)?;
            }
        }
        Ok(())
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let request = Request::read(r)?;
        let lease = LeaseToken::read(r)?;
        let status = Status::read(r.u8()?)?;
        let outcome = match r.u8()? {
            0 => None,
            1 => Some(Outcome {
                code: r.u32()? as i32,
                digest: r.get()?,
            }),
            _ => return Err(Error::Corrupt),
        };
        if request.contract != lease.contract || (status == Status::Completed) != outcome.is_some()
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            request,
            lease,
            status,
            outcome,
        })
    }
}
pub struct Book<const T: usize> {
    node: super::NodeId,
    entries: [Option<Entry>; T],
    permits: [Option<Permit>; T],
    revision: u64,
    poisoned: bool,
    recovered: [bool; T],
    clock: Clock,
}
impl<const T: usize> Book<T> {
    pub fn open(store: &mut impl Store, node: super::NodeId) -> Result<Self> {
        if T == 0 || T > MAX_TASKS || !node.valid() {
            return Err(Error::Invalid);
        }
        let mut this = Self {
            node,
            entries: [None; T],
            permits: core::array::from_fn(|_| None),
            revision: 0,
            poisoned: false,
            recovered: [false; T],
            clock: Clock::default(),
        };
        if let Some((rev, b)) = storage::load(
            store,
            Key {
                kind: KIND,
                id: node.0,
            },
        )? {
            let mut r = Reader::new(b.as_slice());
            storage::read_header(&mut r, KIND)?;
            if r.get::<32>()? != node.0 || r.u16()? as usize != T {
                return Err(Error::Corrupt);
            }
            for i in 0..T {
                this.entries[i] = match r.u8()? {
                    0 => None,
                    1 => Some(Entry::read(&mut r)?),
                    _ => return Err(Error::Corrupt),
                };
                if let Some(e) = this.entries[i] {
                    if e.lease.owner.node != node {
                        return Err(Error::Corrupt);
                    }
                    this.recovered[i] = true;
                    for old in this.entries[..i].iter().flatten() {
                        if old.request.operation == e.request.operation
                            || (old.request.task == e.request.task
                                && old.request.activation >= e.request.activation)
                        {
                            return Err(Error::Corrupt);
                        }
                    }
                }
            }
            r.end()?;
            this.revision = rev;
        }
        Ok(this)
    }
    fn live(&mut self, now: u64) -> Result<()> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        self.clock.observe(now)
    }
    fn index(&self, task: ObjectId, activation: u64) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| {
                e.is_some_and(|e| e.request.task == task && e.request.activation == activation)
            })
            .ok_or(Error::NotReady)
    }
    fn save(&mut self, store: &mut impl Store, next: [Option<Entry>; T]) -> Result<()> {
        let mut b = Bytes::new();
        storage::header(&mut b, KIND)?;
        b.put(&self.node.0)?;
        b.u16(T as u16)?;
        for entry in next {
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
                id: self.node.0,
            },
            &mut self.revision,
            &mut self.poisoned,
            &b,
        )?;
        self.entries = next;
        Ok(())
    }
    pub fn query(&self, task: ObjectId, activation: u64) -> Result<(Status, Option<Outcome>)> {
        let i = self.index(task, activation)?;
        let e = self.entries[i].ok_or(Error::NotReady)?;
        let status = if self.recovered[i] && e.status == Status::Running {
            Status::Uncertain
        } else {
            e.status
        };
        Ok((status, e.outcome))
    }
    pub fn prepare<const N: usize, const O: usize>(
        &mut self,
        store: &mut impl Store,
        request: Request,
        ledger: &Ledger<N>,
        endpoint: &Endpoint<O>,
        active: &Active<'_>,
        now: u64,
    ) -> Result<Status> {
        self.live(now)?;
        if !request.valid() {
            return Err(Error::Invalid);
        }
        if let Ok(i) = self.index(request.task, request.activation) {
            let e = self.entries[i].ok_or(Error::NotReady)?;
            return if e.request == request {
                Ok(self.query(request.task, request.activation)?.0)
            } else {
                Err(Error::Conflict)
            };
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|e| e.request.operation == request.operation)
        {
            return Err(Error::Conflict);
        }
        if self.entries.iter().flatten().any(|e| {
            e.request.task == request.task
                && (e.request.activation >= request.activation
                    || !matches!(e.status, Status::Completed | Status::NotStarted))
        }) {
            return Err(Error::Stale);
        }
        let (lease, q) = ledger.execution(request.contract, endpoint, active, now)?;
        if active.local().node != self.node || q.isa != request.isa || q.abi != request.abi {
            return Err(Error::Unsupported);
        }
        let i = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut next = self.entries;
        next[i] = Some(Entry {
            request,
            lease,
            status: Status::Prepared,
            outcome: None,
        });
        self.save(store, next)?;
        Ok(Status::Prepared)
    }
    /// All final guards are rechecked at launch, not merely at PREPARE. The
    /// borrowed membership/ledger and exclusive endpoint prevent safe Rust
    /// callers from concurrently mutating them during this invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn start<const N: usize, const O: usize>(
        &mut self,
        store: &mut impl Store,
        task: ObjectId,
        activation: u64,
        ledger: &Ledger<N>,
        endpoint: &mut Endpoint<O>,
        active: &Active<'_>,
        now: u64,
        executor: &mut impl Executor,
    ) -> Result<Status> {
        self.live(now)?;
        let i = self.index(task, activation)?;
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        if e.status != Status::Prepared {
            return Ok(self.query(task, activation)?.0);
        }
        if self.recovered[i] {
            return Err(Error::Reconcile);
        }
        let (lease, _) = ledger.execution(e.request.contract, endpoint, active, now)?;
        if lease != e.lease {
            return Err(Error::Stale);
        }
        e.status = Status::Running;
        let mut next = self.entries;
        next[i] = Some(e);
        self.save(store, next)?;
        let permit = match endpoint.begin(lease, active, lease.consumer, now) {
            Ok(p) => p,
            Err(error) => {
                e.status = Status::NotStarted;
                let mut next = self.entries;
                next[i] = Some(e);
                self.save(store, next)?;
                return Err(error);
            }
        };
        self.permits[i] = Some(permit);
        match executor.launch(e.request, lease) {
            Ok(()) => Ok(Status::Running),
            Err(LaunchError::Unknown) => {
                e.status = Status::Uncertain;
                let mut next = self.entries;
                next[i] = Some(e);
                self.save(store, next)?;
                Ok(Status::Uncertain)
            }
            Err(LaunchError::NotStarted) => {
                self.terminal(store, i, Status::NotStarted, None, endpoint)?;
                Ok(Status::NotStarted)
            }
        }
    }
    fn terminal<const O: usize>(
        &mut self,
        store: &mut impl Store,
        i: usize,
        status: Status,
        outcome: Option<Outcome>,
        endpoint: &mut Endpoint<O>,
    ) -> Result<()> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if let Some(p) = &self.permits[i]
            && !endpoint.owns(p)
        {
            return Err(Error::WrongOwner);
        }
        let mut e = self.entries[i].ok_or(Error::NotReady)?;
        e.status = status;
        e.outcome = outcome;
        let mut next = self.entries;
        next[i] = Some(e);
        self.save(store, next)?;
        if let Some(p) = &self.permits[i] {
            endpoint.finish_ref(p)?;
        }
        self.permits[i] = None;
        self.recovered[i] = false;
        Ok(())
    }
    /// Actual completion does not wait for fresh AI, connectivity or leases.
    pub fn complete<const O: usize>(
        &mut self,
        store: &mut impl Store,
        task: ObjectId,
        activation: u64,
        outcome: Outcome,
        endpoint: &mut Endpoint<O>,
    ) -> Result<Outcome> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        if outcome.digest == [0; 32] {
            return Err(Error::Invalid);
        }
        let i = self.index(task, activation)?;
        let e = self.entries[i].ok_or(Error::NotReady)?;
        if e.status == Status::Completed {
            return if e.outcome == Some(outcome) {
                Ok(outcome)
            } else {
                Err(Error::Conflict)
            };
        }
        if self.recovered[i] || e.status != Status::Running {
            return Err(Error::Reconcile);
        }
        self.terminal(store, i, Status::Completed, Some(outcome), endpoint)?;
        Ok(outcome)
    }
    pub fn reconcile<const O: usize>(
        &mut self,
        store: &mut impl Store,
        task: ObjectId,
        activation: u64,
        endpoint: &mut Endpoint<O>,
        executor: &mut impl Executor,
    ) -> Result<Status> {
        if self.poisoned {
            return Err(Error::Reconcile);
        }
        let i = self.index(task, activation)?;
        let e = self.entries[i].ok_or(Error::NotReady)?;
        if matches!(e.status, Status::Completed | Status::NotStarted) {
            return Ok(e.status);
        }
        if e.status == Status::Prepared {
            self.terminal(store, i, Status::NotStarted, None, endpoint)?;
            return Ok(Status::NotStarted);
        }
        match executor.reconcile(e.request, e.lease) {
            Observation::Unknown => Ok(Status::Uncertain),
            Observation::NotStarted => {
                self.terminal(store, i, Status::NotStarted, None, endpoint)?;
                Ok(Status::NotStarted)
            }
            Observation::Completed(o) => {
                if o.digest == [0; 32] {
                    return Err(Error::Invalid);
                }
                self.terminal(store, i, Status::Completed, Some(o), endpoint)?;
                Ok(Status::Completed)
            }
        }
    }
}
