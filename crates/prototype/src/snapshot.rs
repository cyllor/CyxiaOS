//! Immutable business-namespace snapshots and their non-rollback control plane.
//!
//! All persistence goes through the single-writer journal. Callers own the
//! business-write barrier, capabilities, root references, device quiescence,
//! and complete inode-tree validation. This module never interprets an I/O
//! failure as cancellation. Its fixed manager contains only control/catalog
//! state and a monotonic-clock anchor; transaction pages are caller-owned.
//!
//! The request-object header/watermark encoding and request query/ACK opcodes
//! 0x2a/0x2b complete fields left unspecified by the V1.4 design. They are
//! versioned independently as SnapshotRequestSchemaV1.

mod codec;
mod manager;
mod requests;
pub use codec::*;
pub use manager::Manager;
pub use requests::{RequestRecord, format_request_block};

use crate::{journal, storage};
pub type Workspace = [[u8; storage::BLOCK_SIZE]; 40];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Invalid,
    Corrupt,
    NoSpace,
    Stale,
    Conflict,
    Sequence,
    Busy,
    Frozen,
    Retention,
    Counter,
    Permission,
    NotMounted,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Journal(journal::Error<E>),
    Format(storage::Error),
    Status(Status),
}
impl<E> From<storage::Error> for Error<E> {
    fn from(value: storage::Error) -> Self {
        Self::Format(value)
    }
}
impl<E> From<journal::Error<E>> for Error<E> {
    fn from(value: journal::Error<E>) -> Self {
        Self::Journal(value)
    }
}
impl<E> From<Status> for Error<E> {
    fn from(value: Status) -> Self {
        Self::Status(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub key: FileReqKey,
    pub expected_live_view_epoch: u64,
}

/// Implemented by the kernel's trusted local monotonic time source. Wire
/// requests, wall clocks and model predictions must never implement this role.
pub trait MonotonicClock {
    fn monotonic_ns(&mut self) -> Option<u64>;
}

pub const SECOND_NS: u64 = 1_000_000_000;
pub const MIN_RETENTION_SECONDS: u64 = 3_600;
pub const DEFAULT_RETENTION_SECONDS: u64 = 86_400;
pub const MAX_RETENTION_SECONDS: u64 = 604_800;
pub const SHORT_PERIOD_SECONDS: u64 = 21_600;
pub const SHORT_RETENTION_SECONDS: u64 = 64_800;
pub const LONG_PERIOD_SECONDS: u64 = 172_800;
pub const LONG_RETENTION_SECONDS: u64 = 518_400;
pub const INODE_IMAGE_PAGES: usize = 14;
pub const OP_CREATE: u16 = 0x20;
pub const OP_EXTEND: u16 = 0x21;
pub const OP_DELETE: u16 = 0x22;
pub const OP_RESTORE: u16 = 0x23;
pub const OP_FREEZE_SET: u16 = 0x27;
pub const OP_FREEZE_CLEAR: u16 = 0x28;
pub const OP_OPEN_WRITES: u16 = 0x29;
pub const OP_REQUEST_QUERY: u16 = 0x2a;
pub const OP_REQUEST_ACK: u16 = 0x2b;

#[cfg(test)]
mod tests;
