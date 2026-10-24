//! Admission reads never acquire the coordinator or policy gate. The resource
//! owner still validates its own initialized baseline, ownership and real use.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{Error, ObjectKey},
    policy::{ExecutionState, Prerequisite, dependency_allowed},
};

pub const CAPACITY: usize = 512;
struct Entry {
    domain: AtomicU64,
    id: AtomicU64,
    generation: AtomicU64,
    version: AtomicU64,
    until: AtomicU64,
    state: AtomicU64,
}
impl Entry {
    const fn empty() -> Self {
        Self {
            domain: AtomicU64::new(0),
            id: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            version: AtomicU64::new(0),
            until: AtomicU64::new(0),
            state: AtomicU64::new(0),
        }
    }
}
pub struct AdmissionView {
    sequence: AtomicU64,
    entries: [Entry; CAPACITY],
}
impl AdmissionView {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            entries: [const { Entry::empty() }; CAPACITY],
        }
    }
    /// The protected CPU0 coordinator is the sole writer. Publish the intent
    /// before allowing an executor to change its actual resource parameters.
    pub fn publish(
        &self,
        slot: usize,
        prerequisite: Prerequisite,
        version: u64,
        until: u64,
        state: ExecutionState,
    ) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        let e = &self.entries[slot];
        e.domain
            .store(u64::from(prerequisite.domain), Ordering::Relaxed);
        e.id.store(prerequisite.target.id, Ordering::Relaxed);
        e.generation
            .store(prerequisite.target.generation, Ordering::Relaxed);
        e.version.store(version, Ordering::Relaxed);
        e.until.store(until, Ordering::Relaxed);
        e.state.store(
            match state {
                ExecutionState::Pending => 1,
                ExecutionState::Applied => 2,
                ExecutionState::Failed(_) => 3,
                ExecutionState::Unknown => 4,
            },
            Ordering::Relaxed,
        );
        self.sequence.fetch_add(1, Ordering::Release);
    }
    /// Clear only after the real owner proves the terminal object is dead.
    pub fn retire(&self, slot: usize) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.entries[slot].state.store(0, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }
    pub fn admit(&self, prerequisite: Prerequisite, consumer: u16, now: u64) -> Result<u64, Error> {
        if !dependency_allowed(prerequisite.domain, consumer) {
            return Err(Error::Unsupported);
        }
        let ObjectKey { id, generation } = prerequisite.target;
        if id == 0 || generation == 0 {
            return Err(Error::Stale);
        }
        let before = self.sequence.load(Ordering::Acquire);
        if before & 1 != 0 {
            return Err(Error::Busy);
        }
        let mut result = Ok(0);
        for e in &self.entries {
            let state = e.state.load(Ordering::Relaxed);
            if state == 0
                || e.domain.load(Ordering::Relaxed) != u64::from(prerequisite.domain)
                || e.id.load(Ordering::Relaxed) != id
                || e.generation.load(Ordering::Relaxed) != generation
            {
                continue;
            }
            result = match state {
                2 if now < e.until.load(Ordering::Relaxed) => Ok(e.version.load(Ordering::Relaxed)),
                2 => Ok(0),
                1 => Err(Error::Busy),
                4 => Err(Error::NotReady),
                _ => Err(Error::Conflict),
            };
            break;
        }
        core::sync::atomic::fence(Ordering::Acquire);
        if before != self.sequence.load(Ordering::Acquire) {
            Err(Error::Busy)
        } else {
            result
        }
    }
}
