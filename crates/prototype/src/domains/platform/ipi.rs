//! Preallocated wake mailboxes, independent of all ordinary completion queues.
//! An ACK proves only that the named CPU observed this wake request. It is not
//! a quiescence, reference-release, DMA-stop or ownership-transfer certificate.
use crate::domains::Error;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

pub const IPI_CPUS: usize = 64;
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const PENDING: u8 = 2;
const HANDLING: u8 = 3;
const ACKNOWLEDGED: u8 = 4;
const CONSUMED: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpiKey {
    pub request_id: u64,
    pub cpu: u16,
    pub cpu_generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiResult {
    Observed,
    StaleGeneration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpiAck {
    pub key: IpiKey,
    pub observed_generation: u64,
    pub result: IpiResult,
    pub completed_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiProgress {
    Pending,
    Acknowledged(IpiAck),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiPublication {
    New,
    Existing(IpiProgress),
}

struct Mailbox {
    registered_generation: AtomicU64,
    state: AtomicU8,
    request: AtomicU64,
    generation: AtomicU64,
    observed_generation: AtomicU64,
    completed_ns: AtomicU64,
    result: AtomicU8,
}
impl Mailbox {
    const fn new() -> Self {
        Self {
            registered_generation: AtomicU64::new(0),
            state: AtomicU8::new(EMPTY),
            request: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            observed_generation: AtomicU64::new(0),
            completed_ns: AtomicU64::new(0),
            result: AtomicU8::new(0),
        }
    }
    fn matches(&self, key: IpiKey) -> bool {
        self.request.load(Ordering::Relaxed) == key.request_id
            && self.generation.load(Ordering::Relaxed) == key.cpu_generation
    }
}

pub struct IpiMailboxes {
    slots: [Mailbox; IPI_CPUS],
}
impl Default for IpiMailboxes {
    fn default() -> Self {
        Self::new()
    }
}
impl IpiMailboxes {
    pub const fn new() -> Self {
        Self {
            slots: [const { Mailbox::new() }; IPI_CPUS],
        }
    }
    fn slot(&self, cpu: u16) -> Result<&Mailbox, Error> {
        self.slots.get(usize::from(cpu)).ok_or(Error::Range)
    }
    /// Registration never erases an old request or an unconsumed completion.
    /// The receiver will explicitly reject a pending request from an old CPU
    /// generation; its original key and result remain available to a successor.
    pub fn register(&self, cpu: u16, generation: u64) -> Result<(), Error> {
        if generation == 0 {
            return Err(Error::Format);
        }
        let slot = self.slot(cpu)?;
        let previous = slot.registered_generation.load(Ordering::Acquire);
        if generation < previous {
            return Err(Error::Stale);
        }
        slot.registered_generation
            .compare_exchange(previous, generation, Ordering::Release, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        Ok(())
    }
    /// The sole sender/consumer must publish before issuing the hardware SGI.
    /// An existing pending request is queried, never executed as a new request.
    pub fn publish(&self, key: IpiKey) -> Result<IpiPublication, Error> {
        if key.request_id == 0 || key.cpu_generation == 0 {
            return Err(Error::Format);
        }
        let slot = self.slot(key.cpu)?;
        let state = slot.state.load(Ordering::Acquire);
        if state == WRITING {
            return Err(Error::Busy);
        }
        if slot.matches(key) {
            return self.query(key).map(IpiPublication::Existing);
        }
        if slot.registered_generation.load(Ordering::Acquire) != key.cpu_generation {
            return Err(Error::Stale);
        }
        if !matches!(state, EMPTY | CONSUMED) {
            return Err(Error::Busy);
        }
        if slot.generation.load(Ordering::Relaxed) == key.cpu_generation
            && key.request_id <= slot.request.load(Ordering::Relaxed)
        {
            return Err(Error::Stale);
        }
        slot.state
            .compare_exchange(state, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        if slot.registered_generation.load(Ordering::Acquire) != key.cpu_generation {
            slot.state.store(state, Ordering::Release);
            return Err(Error::Stale);
        }
        // Recheck under publication ownership: a concurrent replacement
        // sender may have consumed a newer completed request since our first
        // snapshot. A reused CONSUMED state must not permit an ID rollback.
        if slot.matches(key) {
            slot.state.store(state, Ordering::Release);
            return self.query(key).map(IpiPublication::Existing);
        }
        if slot.generation.load(Ordering::Relaxed) == key.cpu_generation
            && key.request_id <= slot.request.load(Ordering::Relaxed)
        {
            slot.state.store(state, Ordering::Release);
            return Err(Error::Stale);
        }
        slot.request.store(key.request_id, Ordering::Relaxed);
        slot.generation.store(key.cpu_generation, Ordering::Relaxed);
        slot.observed_generation.store(0, Ordering::Relaxed);
        slot.completed_ns.store(0, Ordering::Relaxed);
        slot.result.store(0, Ordering::Relaxed);
        slot.state.store(PENDING, Ordering::Release);
        Ok(IpiPublication::New)
    }
    /// Called only by the named CPU's actual SGI handler. Bounded atomics only:
    /// no allocation, ordinary completion credit, policy gate or owner borrow.
    pub fn receive(&self, cpu: u16, actual_generation: u64, now_ns: u64) -> Option<IpiAck> {
        let slot = self.slot(cpu).ok()?;
        slot.state
            .compare_exchange(PENDING, HANDLING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let key = IpiKey {
            request_id: slot.request.load(Ordering::Relaxed),
            cpu,
            cpu_generation: slot.generation.load(Ordering::Relaxed),
        };
        let observed = slot.registered_generation.load(Ordering::Acquire);
        let result = if actual_generation != 0
            && actual_generation == observed
            && key.cpu_generation == actual_generation
        {
            IpiResult::Observed
        } else {
            IpiResult::StaleGeneration
        };
        let ack = IpiAck {
            key,
            observed_generation: actual_generation,
            result,
            completed_ns: now_ns,
        };
        slot.observed_generation
            .store(actual_generation, Ordering::Relaxed);
        slot.completed_ns.store(now_ns, Ordering::Relaxed);
        slot.result
            .store(u8::from(result == IpiResult::Observed), Ordering::Relaxed);
        slot.state.store(ACKNOWLEDGED, Ordering::Release);
        Some(ack)
    }
    pub fn query(&self, key: IpiKey) -> Result<IpiProgress, Error> {
        let slot = self.slot(key.cpu)?;
        for _ in 0..3 {
            let before = slot.state.load(Ordering::Acquire);
            if before == EMPTY {
                return Err(Error::NotFound);
            }
            if before == WRITING {
                return Err(Error::Busy);
            }
            if !slot.matches(key) {
                return Err(Error::Stale);
            }
            let value = if matches!(before, ACKNOWLEDGED | CONSUMED) {
                IpiProgress::Acknowledged(IpiAck {
                    key,
                    observed_generation: slot.observed_generation.load(Ordering::Relaxed),
                    result: if slot.result.load(Ordering::Relaxed) == 1 {
                        IpiResult::Observed
                    } else {
                        IpiResult::StaleGeneration
                    },
                    completed_ns: slot.completed_ns.load(Ordering::Relaxed),
                })
            } else {
                IpiProgress::Pending
            };
            if slot.state.load(Ordering::Acquire) == before && slot.matches(key) {
                return Ok(value);
            }
        }
        Err(Error::Busy)
    }
    /// Explicit receipt consumption authorizes slot reuse. A replacement
    /// supervisor can query/consume the same key; timeout alone never frees it.
    pub fn consume(&self, key: IpiKey) -> Result<IpiAck, Error> {
        let IpiProgress::Acknowledged(ack) = self.query(key)? else {
            return Err(Error::NotReady);
        };
        let slot = self.slot(key.cpu)?;
        match slot.state.compare_exchange(
            ACKNOWLEDGED,
            WRITING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if !slot.matches(key) {
                    slot.state.store(ACKNOWLEDGED, Ordering::Release);
                    return Err(Error::Stale);
                }
                slot.state.store(CONSUMED, Ordering::Release);
                Ok(ack)
            }
            Err(CONSUMED) if slot.matches(key) => Ok(ack),
            _ => Err(Error::Busy),
        }
    }
}
