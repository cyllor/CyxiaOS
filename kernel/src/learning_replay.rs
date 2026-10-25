//! Native replay producer. Every label comes from protected workload, root
//! publication, execution, and CPU evidence; the numerical worker only receives
//! sealed grouped samples after all eighteen families meet the frozen split.
use cyxia_prototype::domains::Error as DomainError;
pub use cyxia_prototype::learning::Error;
#[path = "learning_replay/archive.rs"]
pub(crate) mod archive;
#[path = "learning_replay/archive_packet.rs"]
mod archive_packet;
#[path = "learning_replay/data.rs"]
pub mod data;
#[path = "learning_replay/late_archive.rs"]
pub(crate) mod late_archive;
#[path = "learning_replay/owner.rs"]
mod owner;
#[path = "learning_replay/preparation_archive.rs"]
pub(crate) mod preparation_archive;
pub use owner::{control_step, init, pause_for_peer, quiescent, service_io, service_step, status};
pub(crate) const WORKSPACE_PEAK_BYTES: usize = owner::WORKSPACE_PEAK_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    Training,
    Validation,
}
fn native_error(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Stale => Error::Stale,
        DomainError::Capacity => Error::Capacity,
        DomainError::Budget => Error::Budget,
        DomainError::Expired => Error::Deadline,
        DomainError::Schema => Error::Schema,
        DomainError::Conflict => Error::Conflict,
        DomainError::Range | DomainError::Overflow => Error::Numeric,
        _ => Error::Evidence,
    }
}
fn evidence_error(error: crate::learning_evidence::Error) -> Error {
    use crate::learning_evidence::Error as E;
    match error {
        E::Busy | E::NotReady => Error::Unknown,
        E::Stale => Error::Stale,
        E::Capacity => Error::Capacity,
        E::Capture(error) => error,
        E::Owner => Error::Evidence,
    }
}
fn domain_error(error: Error) -> DomainError {
    match error {
        Error::Unknown => DomainError::Busy,
        Error::Stale => DomainError::Stale,
        Error::Capacity => DomainError::Capacity,
        Error::Budget => DomainError::Budget,
        Error::Deadline => DomainError::Expired,
        Error::Schema => DomainError::Schema,
        Error::Numeric => DomainError::Overflow,
        _ => DomainError::Conflict,
    }
}
