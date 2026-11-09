//! Native replay producer. Every label comes from protected workload, root
//! publication, execution, and CPU evidence; the numerical worker only receives
//! sealed grouped samples after all eighteen families meet the frozen split.
use cyxia_prototype::domains::Error as DomainError;
#[path = "learning_replay/prewarm_progress.rs"]
pub(crate) mod prewarm_progress;
#[path = "learning_replay/prewarm_status.rs"]
mod prewarm_status;

#[path = "learning_replay/collection_profile.rs"]
mod collection_profile;
use collection_profile::CollectionProfile;
const COLLECTION_PROFILE: CollectionProfile =
    include!(concat!(env!("OUT_DIR"), "/learning-collection.rs"));
/// Fixed ELF profile ABI: magic, version, profile, witness bytes, archive-ref bytes.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".cyxia.boot")]
pub static LEARNING_COLLECTION_V16_LAYOUT: [u64; 5] = [
    0x43594c434f4c3136,
    if COLLECTION_PROFILE.bounded() { 2 } else { 1 },
    COLLECTION_PROFILE as u64,
    1024,
    96,
];
pub(crate) const fn bounded_profile() -> bool {
    COLLECTION_PROFILE.bounded()
}
#[path = "learning_replay/bounded_data.rs"]
mod bounded_data;
#[path = "learning_replay/bounded_export.rs"]
mod bounded_export;
#[path = "learning_replay/sample_export.rs"]
mod sample_export;
#[path = "learning_replay/sample_witness.rs"]
mod sample_witness;
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
/// Scheduling only: published execution and already-owned drain/source closure
/// retain progress until their gate clears the reason. Service revalidates rights.
pub fn baseline_activation_pending() -> bool {
    crate::domain_control::replay::baseline_activation_pending() || owner::service_pending()
}
/// Queued admission keeps its original execution/Drain reason. Closing or
/// sealing a capture requests service only, without another admission turn.
pub fn admission_progress_pending() -> bool {
    crate::domain_control::replay::baseline_activation_pending() || owner::drain_pending()
}
/// Scheduling reason for already-entered Drain only; this grants no authority.
pub fn owned_drain_pending() -> bool {
    owner::drain_pending()
}
pub use owner::{control_step, init, pause_for_peer, quiescent, service_io, service_step, status};
pub(crate) use owner::{prewarm_service_hint, service_owned_prewarm};
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
