//! Bounded two-native-node cluster safety core, called by a serialized EL1 owner.
//!
//! No discovery packet, AI proposal, timeout or CommitProof grants execution.
//! Authentication, durable storage, clocks and actual device/process operations
//! are required adapters; none has an accept-all production implementation here.
//! This is not Raft, a network stack, a replicated filesystem or SMP bring-up.
#![forbid(unsafe_code)]
pub mod admission;
pub mod auth;
pub mod boot;
mod codec;
pub mod contracts;
pub mod endpoint;
pub mod health;
pub mod membership;
pub mod replication;
pub mod storage;
pub mod tasks;
pub mod wire;
pub use codec::Bytes;

pub type Digest = [u8; 32];
pub type Signature = [u8; 64];
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; 16]);
impl NodeId {
    pub fn valid(self) -> bool {
        self.0 != [0; 32]
    }
}
impl ObjectId {
    pub fn valid(self) -> bool {
        self.0 != [0; 16]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Version,
    Authentication,
    NativeRequired,
    Stale,
    Replay,
    Conflict,
    Capacity,
    Exhausted,
    NotReady,
    Expired,
    Clock,
    Storage,
    Reconcile,
    Busy,
    Policy,
    Unsupported,
    Corrupt,
    WrongOwner,
}
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incarnation {
    pub node: NodeId,
    pub boot: u64,
}
impl Incarnation {
    pub fn valid(self) -> bool {
        self.node.valid() && self.boot != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub cluster: ObjectId,
    pub config_epoch: u64,
    pub config_digest: Digest,
    pub activation_epoch: u64,
}
impl Scope {
    pub fn valid(self) -> bool {
        self.cluster.valid()
            && self.config_epoch != 0
            && self.config_digest != [0; 32]
            && self.activation_epoch != 0
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Quota {
    pub cpu_ticks: u64,
    pub memory_pages: u64,
    pub io_units: u64,
}
impl Quota {
    pub fn valid(self) -> bool {
        self != Self::default()
    }
    pub fn fits(self, limit: Self) -> bool {
        self.cpu_ticks <= limit.cpu_ticks
            && self.memory_pages <= limit.memory_pages
            && self.io_units <= limit.io_units
    }
    pub fn checked_add(self, other: Self) -> Result<Self> {
        Ok(Self {
            cpu_ticks: self
                .cpu_ticks
                .checked_add(other.cpu_ticks)
                .ok_or(Error::Exhausted)?,
            memory_pages: self
                .memory_pages
                .checked_add(other.memory_pages)
                .ok_or(Error::Exhausted)?,
            io_units: self
                .io_units
                .checked_add(other.io_units)
                .ok_or(Error::Exhausted)?,
        })
    }
}
/// Local monotonic ticks only. Remote timestamps must never be compared to this.
#[derive(Default)]
pub(crate) struct Clock {
    pub(crate) last: u64,
    pub(crate) broken: bool,
}
impl Clock {
    pub fn observe(&mut self, now: u64) -> Result<()> {
        if self.broken || now < self.last {
            self.broken = true;
            return Err(Error::Clock);
        }
        self.last = now;
        Ok(())
    }
}
