use super::{EMPTY_KEY, UNSET, valid_key};
use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

pub const FILE_STAT_BY_CAP: u16 = 1;
pub const TASK_QUERY_BY_CAP: u16 = 2;
pub const MAX_VECTOR: usize = 16;
const CAPABILITIES: usize = 256;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceItem {
    pub op: u16,
    pub flags: u16,
    pub cap: u64,
    pub object_gen: u64,
    pub tag: u64,
}
impl ServiceItem {
    const EMPTY: Self = Self {
        op: 0,
        flags: 0,
        cap: 0,
        object_gen: 0,
        tag: 0,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemStatus {
    Pending,
    Value(u64),
    Error(Error),
    Cancelled,
    TimedOut,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemCompletion {
    pub tag: u64,
    pub status: ItemStatus,
}
impl ItemCompletion {
    const EMPTY: Self = Self {
        tag: 0,
        status: ItemStatus::Pending,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedItem {
    pub op: u16,
    pub object: ObjectKey,
    pub tag: u64,
}
impl ResolvedItem {
    const EMPTY: Self = Self {
        op: 0,
        object: EMPTY_KEY,
        tag: 0,
    };
}
pub trait ServiceBackend {
    /// Caller serializes object lifetime with this batch. Each object is checked
    /// immediately before dispatch; the native service must also check the
    /// supplied generation when dequeuing if dispatch crosses a blocking IPC.
    fn validate_object(&mut self, object: ObjectKey, op: u16) -> Result<(), Error>;
    /// Perform one actual service IPC/batch, not one IPC for each item. Only the
    /// two read-only operations can reach this callback. Individual completion
    /// slots preserve successes even if another item times out or the batch
    /// transport fails. Leaving a slot empty never means success.
    fn call_batch(
        &mut self,
        service: ObjectKey,
        items: &[ResolvedItem],
        results: &mut [Option<Result<u64, Error>>],
    ) -> Result<(), Error>;
}
#[derive(Clone, Copy)]
struct Capability {
    id: u64,
    owner: ObjectKey,
    object: ObjectKey,
    service: ObjectKey,
    rights: u8,
}
pub struct SubmitVector {
    caller: ObjectKey,
    items: [ServiceItem; MAX_VECTOR],
    results: [ItemCompletion; MAX_VECTOR],
    count: usize,
    deadline_ns: u64,
    submitted_ns: u64,
}
impl SubmitVector {
    pub fn results(&self) -> &[ItemCompletion] {
        &self.results[..self.count]
    }
    pub fn complete(&self) -> bool {
        !self
            .results()
            .iter()
            .any(|r| r.status == ItemStatus::Pending)
    }
    pub fn cancel(&mut self, tag: u64) -> Result<ItemStatus, Error> {
        let r = self.results[..self.count]
            .iter_mut()
            .find(|r| r.tag == tag)
            .ok_or(Error::NotFound)?;
        if r.status == ItemStatus::Pending {
            r.status = ItemStatus::Cancelled;
        }
        Ok(r.status)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStats {
    pub vectors: u64,
    pub items: u64,
    pub ipc_calls: u64,
    pub completed: u64,
    pub errors: u64,
    pub elapsed_ns: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceStep {
    pub ipc_calls: usize,
    pub completed: usize,
    pub remaining: usize,
}
pub struct ServiceBatch {
    capabilities: [Option<Capability>; CAPABILITIES],
    serial: u64,
    stamp: PolicyStamp,
    applied_version: u64,
    batch: usize,
    last_now: u64,
    stats: ServiceStats,
}
impl Default for ServiceBatch {
    fn default() -> Self {
        Self::new()
    }
}
impl ServiceBatch {
    pub const fn new() -> Self {
        Self {
            capabilities: [None; CAPABILITIES],
            serial: 0,
            stamp: UNSET,
            applied_version: 0,
            batch: 1,
            last_now: 0,
            stats: ServiceStats {
                vectors: 0,
                items: 0,
                ipc_calls: 0,
                completed: 0,
                errors: 0,
                elapsed_ns: 0,
            },
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        self.last_now = now;
        Ok(())
    }
    /// Trusted capability issuer. Rights bit0 permits FILE_STAT; bit1 TASK_QUERY.
    pub fn grant(
        &mut self,
        owner: ObjectKey,
        object: ObjectKey,
        service: ObjectKey,
        rights: u8,
    ) -> Result<u64, Error> {
        valid_key(owner)?;
        valid_key(object)?;
        valid_key(service)?;
        if rights == 0 || rights & !3 != 0 {
            return Err(Error::Auth);
        }
        let slot = self
            .capabilities
            .iter_mut()
            .find(|c| c.is_none())
            .ok_or(Error::Capacity)?;
        let id = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        *slot = Some(Capability {
            id,
            owner,
            object,
            service,
            rights,
        });
        self.serial = id;
        Ok(id)
    }
    pub fn revoke(&mut self, owner: ObjectKey, cap: u64) -> Result<(), Error> {
        let slot = self
            .capabilities
            .iter_mut()
            .find(|c| c.is_some_and(|c| c.id == cap && c.owner == owner))
            .ok_or(Error::Auth)?;
        *slot = None;
        Ok(())
    }
    pub fn revoke_object(&mut self, object: ObjectKey) {
        for c in &mut self.capabilities {
            if c.is_some_and(|c| c.object == object) {
                *c = None;
            }
        }
    }
    pub fn revoke_owner(&mut self, owner: ObjectKey) {
        for c in &mut self.capabilities {
            if c.is_some_and(|c| c.owner == owner) {
                *c = None;
            }
        }
    }
    pub fn policy(&self, now: u64) -> u8 {
        if self.stamp.live(now) {
            self.batch as u8
        } else {
            1
        }
    }
    pub fn policy_receipt(&self) -> u64 {
        self.applied_version
    }
    pub fn install(&mut self, batch: u8, stamp: PolicyStamp, now: u64) -> Result<(), Error> {
        self.time(now)?;
        Action::ServiceBatch(batch).validate()?;
        self.stamp.accepts(stamp, now)?;
        if stamp.version == self.stamp.version && usize::from(batch) != self.batch {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.batch = usize::from(batch);
        Ok(())
    }
    /// Copies and preflights the entire vector before any service callback. Bad
    /// capabilities are item errors, but bad flags/op/tags reject the vector.
    pub fn preflight(
        &self,
        caller: ObjectKey,
        items: &[ServiceItem],
        deadline_ns: u64,
        now: u64,
    ) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Stale);
        }
        valid_key(caller)?;
        if items.is_empty() || items.len() > MAX_VECTOR {
            return Err(Error::Format);
        }
        if deadline_ns <= now {
            return Err(Error::Expired);
        }
        for (i, item) in items.iter().enumerate() {
            if item.flags != 0
                || !matches!(item.op, FILE_STAT_BY_CAP | TASK_QUERY_BY_CAP)
                || items[..i].iter().any(|p| p.tag == item.tag)
            {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
    pub fn submit(
        &mut self,
        caller: ObjectKey,
        items: &[ServiceItem],
        deadline_ns: u64,
        now: u64,
    ) -> Result<SubmitVector, Error> {
        self.preflight(caller, items, deadline_ns, now)?;
        self.time(now)?;
        let mut vector = SubmitVector {
            caller,
            items: [ServiceItem::EMPTY; MAX_VECTOR],
            results: [ItemCompletion::EMPTY; MAX_VECTOR],
            count: items.len(),
            deadline_ns,
            submitted_ns: now,
        };
        vector.items[..items.len()].copy_from_slice(items);
        for (i, item) in vector.items[..vector.count].iter().enumerate() {
            vector.results[i].tag = item.tag;
        }
        self.stats.vectors = self.stats.vectors.saturating_add(1);
        self.stats.items = self.stats.items.saturating_add(items.len() as u64);
        Ok(vector)
    }
    fn resolve(&self, caller: ObjectKey, item: ServiceItem) -> Result<Capability, Error> {
        let cap = self
            .capabilities
            .iter()
            .flatten()
            .find(|c| c.id == item.cap)
            .copied()
            .ok_or(Error::Auth)?;
        if cap.owner != caller || cap.rights & (1u8 << (item.op - 1)) == 0 {
            return Err(Error::Auth);
        }
        if cap.object.generation != item.object_gen {
            return Err(Error::Stale);
        }
        Ok(cap)
    }
    fn finish(&mut self, vector: &mut SubmitVector, index: usize, status: ItemStatus, now: u64) {
        if vector.results[index].status != ItemStatus::Pending {
            return;
        }
        vector.results[index].status = status;
        self.stats.completed = self.stats.completed.saturating_add(1);
        if !matches!(status, ItemStatus::Value(_)) {
            self.stats.errors = self.stats.errors.saturating_add(1);
        }
        self.stats.elapsed_ns = self
            .stats
            .elapsed_ns
            .saturating_add(now.saturating_sub(vector.submitted_ns));
    }
    /// One bounded batch of currently available items for one service. Never
    /// waits to fill a batch; later calls revalidate capabilities and generations.
    pub fn step(
        &mut self,
        vector: &mut SubmitVector,
        now: u64,
        backend: &mut impl ServiceBackend,
    ) -> Result<ServiceStep, Error> {
        self.time(now)?;
        if now < vector.submitted_ns {
            return Err(Error::Stale);
        }
        let before = vector
            .results()
            .iter()
            .filter(|r| r.status == ItemStatus::Pending)
            .count();
        if now >= vector.deadline_ns {
            for i in 0..vector.count {
                self.finish(vector, i, ItemStatus::TimedOut, now);
            }
            return Ok(ServiceStep {
                ipc_calls: 0,
                completed: before,
                remaining: 0,
            });
        }
        let limit = if self.stamp.live(now) { self.batch } else { 1 };
        let mut service = None;
        let mut resolved = [ResolvedItem::EMPTY; 8];
        let mut indexes = [0usize; 8];
        let mut count = 0;
        for i in 0..vector.count {
            if vector.results[i].status != ItemStatus::Pending {
                continue;
            }
            let item = vector.items[i];
            let cap = match self.resolve(vector.caller, item) {
                Ok(c) => c,
                Err(e) => {
                    self.finish(vector, i, ItemStatus::Error(e), now);
                    continue;
                }
            };
            if service.is_some_and(|s| s != cap.service) || count == limit {
                continue;
            }
            if let Err(e) = backend.validate_object(cap.object, item.op) {
                self.finish(
                    vector,
                    i,
                    if e == Error::Expired {
                        ItemStatus::TimedOut
                    } else {
                        ItemStatus::Error(e)
                    },
                    now,
                );
                continue;
            }
            service = Some(cap.service);
            indexes[count] = i;
            resolved[count] = ResolvedItem {
                op: item.op,
                object: cap.object,
                tag: item.tag,
            };
            count += 1;
        }
        let ipc_calls = usize::from(count != 0);
        if let Some(service) = service {
            let mut values = [None; 8];
            self.stats.ipc_calls = self.stats.ipc_calls.saturating_add(1);
            let transport = backend.call_batch(service, &resolved[..count], &mut values[..count]);
            if self.stamp.live(now)
                && (transport.is_ok() || values[..count].iter().any(Option::is_some))
            {
                self.applied_version = self.stamp.version;
            }
            for i in 0..count {
                let result = values[i].unwrap_or_else(|| Err(transport.err().unwrap_or(Error::Io)));
                let status = match result {
                    Ok(v) => ItemStatus::Value(v),
                    Err(Error::Expired) => ItemStatus::TimedOut,
                    Err(e) => ItemStatus::Error(e),
                };
                self.finish(vector, indexes[i], status, now);
            }
        }
        let remaining = vector
            .results()
            .iter()
            .filter(|r| r.status == ItemStatus::Pending)
            .count();
        Ok(ServiceStep {
            ipc_calls,
            completed: before - remaining,
            remaining,
        })
    }
    pub fn stats(&self) -> ServiceStats {
        self.stats
    }
}
