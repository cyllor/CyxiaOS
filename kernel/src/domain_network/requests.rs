//! Bounded application-to-service handoff. Payload custody is released only
//! after the isolated service acknowledges a durably recorded submission.
use core::{cell::UnsafeCell, sync::atomic::{AtomicBool, Ordering}};
use cyxia_prototype::domains::{Error, ObjectKey};
use sha2::{Digest, Sha256};
#[path = "../../../user/prototype-cluster/src/application.rs"]
pub(crate) mod wire;

const CAPACITY: usize = 32;
const HISTORY: usize = 4096;
const FIRST_ID: u64 = 4097;
#[derive(Clone, Copy)]
struct Record {
    actor: ObjectKey,
    sequence: u64,
    length: usize,
    hash: [u8; 32],
    submitted_ns: u64,
    available: bool,
    expected: u64,
    completion: Option<wire::Completion>,
    cancelled_ns: Option<u64>,
    state: u64,
    target: ObjectKey,
}
#[derive(Clone, Copy)]
struct Payload { record: usize, bytes: [u8; wire::MAX_INPUT] }
pub(crate) struct Queue<const H: usize = HISTORY> {
    boot: u64,
    records: [Option<Record>; H],
    used: usize,
    outstanding: usize,
    payloads: [Option<Payload>; CAPACITY],
    cursor: usize,
}
impl<const H: usize> Queue<H> {
    pub(crate) const fn new() -> Self {
        Self { boot: 0, records: [None; H], used: 0, outstanding: 0,
            payloads: [None; CAPACITY], cursor: 0 }
    }
    pub(crate) fn initialize(&mut self, boot: u64) -> Result<(), Error> {
        if boot == 0 || self.boot != 0 && self.boot != boot { return Err(Error::Stale); }
        self.boot = boot;
        Ok(())
    }
    fn key(&self, index: usize) -> ObjectKey {
        ObjectKey { id: FIRST_ID + index as u64, generation: self.boot }
    }
    fn index(&self, key: ObjectKey) -> Result<usize, Error> {
        if self.boot == 0 || key.generation != self.boot { return Err(Error::Stale); }
        let i = usize::try_from(key.id.checked_sub(FIRST_ID).ok_or(Error::NotFound)?)
            .map_err(|_| Error::NotFound)?;
        if i >= self.used { return Err(Error::NotFound); }
        Ok(i)
    }
    pub(crate) fn submit(&mut self, actor: ObjectKey, sequence: u64, input: &[u8], now: u64) -> Result<ObjectKey, Error> {
        self.admit(actor, sequence, input, now, true)
    }
    pub(crate) fn reserve(&mut self, actor: ObjectKey, sequence: u64, input: &[u8], now: u64) -> Result<ObjectKey, Error> {
        self.admit(actor, sequence, input, now, false)
    }
    fn admit(&mut self, actor: ObjectKey, sequence: u64, input: &[u8], now: u64, available: bool) -> Result<ObjectKey, Error> {
        if self.boot == 0 { return Err(Error::NotReady); }
        if actor.id == 0 || actor.generation == 0 || sequence == 0 { return Err(Error::Auth); }
        if input.is_empty() || input.len() > wire::MAX_INPUT || !input.len().is_multiple_of(8) {
            return Err(Error::Range);
        }
        let hash: [u8; 32] = Sha256::digest(input).into();
        let expected = input.chunks_exact(8).fold(0u64, |sum, v| sum.wrapping_add(u64::from_le_bytes(v.try_into().unwrap())));
        let mut high = 0;
        for (i, record) in self.records[..self.used].iter().enumerate() {
            let record = record.as_ref().unwrap();
            if record.actor != actor { continue; }
            high = high.max(record.sequence);
            if record.sequence == sequence {
                if record.cancelled_ns.is_some() { return Err(Error::Stale); }
                return if record.length == input.len() && record.hash == hash {
                    Ok(self.key(i))
                } else { Err(Error::Conflict) };
            }
        }
        if sequence <= high { return Err(Error::Stale); }
        if self.used == H || self.outstanding == CAPACITY { return Err(Error::Capacity); }
        let slot = self.payloads.iter().position(Option::is_none).ok_or(Error::Capacity)?;
        let i = self.used;
        let mut bytes = [0; wire::MAX_INPUT];
        bytes[..input.len()].copy_from_slice(input);
        self.payloads[slot] = Some(Payload { record: i, bytes });
        self.records[i] = Some(Record { actor, sequence, length: input.len(), hash, submitted_ns: now,
            available, expected, completion: None, cancelled_ns: None,
            state: wire::QUEUED, target: ObjectKey::default() });
        self.used += 1;
        self.outstanding += 1;
        Ok(self.key(i))
    }
    pub(crate) fn release(&mut self, actor: ObjectKey, key: ObjectKey, at: u64, now: u64) -> Result<(), Error> {
        if at > now { return Err(Error::Again); }
        let i = self.index(key)?; let r = self.records[i].as_mut().unwrap();
        if r.actor != actor { return Err(Error::Auth); }
        if r.cancelled_ns.is_some() { return Err(Error::Stale); }
        if r.available { return if r.submitted_ns == at { Ok(()) } else { Err(Error::Conflict) }; }
        if r.state != wire::QUEUED || at < r.submitted_ns { return Err(Error::Stale); }
        r.submitted_ns = at; r.available = true; Ok(())
    }
    pub(crate) fn completion(&self, actor: ObjectKey, key: ObjectKey) -> Result<Option<wire::Completion>, Error> {
        let r = self.records[self.index(key)?].as_ref().unwrap();
        if r.actor != actor { return Err(Error::Auth); } Ok(r.completion)
    }
    /// Retire only a future preparation payload which was never handed to the
    /// service. A released/unknown task must use its real completion protocol.
    pub(crate) fn cancel_reserved(&mut self, actor: ObjectKey, key: ObjectKey, now: u64) -> Result<u64, Error> {
        let i = self.index(key)?; let r = self.records[i].as_mut().unwrap();
        if r.actor != actor { return Err(Error::Auth); }
        if let Some(at) = r.cancelled_ns { return Ok(at); }
        if r.available || r.state != wire::QUEUED || r.completion.is_some() || now < r.submitted_ns { return Err(Error::Busy); }
        r.cancelled_ns = Some(now); self.outstanding -= 1;
        for payload in &mut self.payloads { if payload.as_ref().is_some_and(|p| p.record == i) { *payload = None; } }
        Ok(now)
    }
    pub(crate) fn finish(&mut self, value: wire::Completion, now: u64) -> Result<(), Error> {
        let i = self.index(value.key)?; let r = self.records[i].as_mut().unwrap();
        if r.completion.is_some() { return if r.completion == Some(value) { Ok(()) } else { Err(Error::Conflict) }; }
        if !r.available || value.closed != 1 || value.finished_ns < r.submitted_ns || value.finished_ns > now
            || r.target != value.target || !matches!(r.state, wire::LOCAL | wire::REMOTE | wire::REJECTED)
            || !matches!(value.outcome, 1 | 2) || value.outcome == 1 && (r.state == wire::REJECTED || value.value != r.expected) {
            return Err(Error::Conflict);
        }
        r.completion = Some(value); Ok(())
    }
    pub(crate) fn status(&self, actor: ObjectKey, key: ObjectKey) -> Result<[u64; 3], Error> {
        let r = self.records[self.index(key)?].as_ref().unwrap();
        if r.actor != actor { return Err(Error::Auth); }
        if r.cancelled_ns.is_some() { return Err(Error::Stale); }
        Ok([r.state, r.target.id, r.target.generation])
    }
    pub(crate) fn next(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        for offset in 0..CAPACITY {
            let slot = (self.cursor + offset) % CAPACITY;
            let Some(payload) = self.payloads[slot].as_ref() else { continue; };
            let r = self.records[payload.record].as_ref().unwrap();
            if !r.available { continue; }
            let size = wire::Submission { actor: r.actor, sequence: r.sequence,
                key: self.key(payload.record), submitted_ns: r.submitted_ns,
                input: &payload.bytes[..r.length] }.encode(output)?;
            self.cursor = (slot + 1) % CAPACITY;
            return Ok(size);
        }
        Err(Error::Again)
    }
    pub(crate) fn acknowledge(&mut self, status: wire::Status) -> Result<(), Error> {
        status.validate()?;
        if status.state == wire::QUEUED { return Err(Error::Format); }
        let i = self.index(status.key)?;
        let r = self.records[i].as_mut().unwrap();
        if !r.available { return Err(Error::Auth); }
        let prior = wire::Status { key: status.key, state: r.state, target: r.target };
        if prior.terminal() {
            return if prior == status { Ok(()) } else { Err(Error::Conflict) };
        }
        if r.state == wire::UNKNOWN && status.state == wire::PENDING { return Ok(()); }
        if status.terminal() { self.outstanding -= 1; }
        r.state = status.state;
        r.target = status.target;
        for payload in &mut self.payloads {
            if payload.as_ref().is_some_and(|p| p.record == i) { *payload = None; }
        }
        Ok(())
    }
}

struct Storage { gate: AtomicBool, queue: UnsafeCell<Queue> }
unsafe impl Sync for Storage {}
static STORAGE: Storage = Storage { gate: AtomicBool::new(false), queue: UnsafeCell::new(Queue::new()) };
fn with<R>(f: impl FnOnce(&mut Queue) -> Result<R, Error>) -> Result<R, Error> {
    if STORAGE.gate.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return Err(Error::Busy);
    }
    struct Release;
    impl Drop for Release { fn drop(&mut self) { STORAGE.gate.store(false, Ordering::Release); } }
    let _release = Release;
    f(unsafe { &mut *STORAGE.queue.get() })
}
pub(super) fn initialize(boot: u64) -> Result<(), Error> { with(|q| q.initialize(boot)) }
pub fn submit(actor: ObjectKey, sequence: u64, bytes: &[u8]) -> Result<ObjectKey, Error> {
    with(|q| q.submit(actor, sequence, bytes, crate::domain_platform::now_ns()))
}
pub fn status(actor: ObjectKey, key: ObjectKey) -> Result<[u64; 3], Error> { with(|q| q.status(actor, key)) }
pub(super) fn reserve(actor: ObjectKey, sequence: u64, bytes: &[u8]) -> Result<ObjectKey, Error> {
    with(|q| q.reserve(actor, sequence, bytes, crate::domain_platform::now_ns()))
}
pub(super) fn release(actor: ObjectKey, key: ObjectKey, at: u64) -> Result<(), Error> {
    with(|q| q.release(actor, key, at, crate::domain_platform::now_ns()))
}
pub(super) fn completion(actor: ObjectKey, key: ObjectKey) -> Result<Option<wire::Completion>, Error> { with(|q| q.completion(actor, key)) }
pub(super) fn cancel_reserved(actor: ObjectKey, key: ObjectKey) -> Result<u64, Error> {
    with(|q| q.cancel_reserved(actor, key, crate::domain_platform::now_ns()))
}
pub(super) fn broker(phase: u64, payload: &mut [u8; 4096], len: usize) -> Result<usize, Error> {
    with(|q| match phase {
        13 => q.next(payload),
        14 => { q.acknowledge(wire::Status::decode(payload.get(..len).ok_or(Error::Format)?)?)?; Ok(0) }
        28 => { q.finish(wire::Completion::decode(payload.get(..len).ok_or(Error::Format)?)?, crate::domain_platform::now_ns())?; Ok(0) }
        _ => Err(Error::Unsupported),
    })
}
