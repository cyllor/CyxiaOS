//! Verification can retry an unavailable owner without rewriting its retained
//! scope or receipt. A permanent mismatch remains invalid evidence. This maps
//! lookup errors only: a retained failed publication is checked as a failed
//! fact by the caller, never reclassified from its original error code here.
use cyxia_prototype::{domains::Error, learning};

/// A bounded verifier may yield only when the root gate was unavailable.
/// Actual retained facts which are not ready (including a non-APPLIED
/// baseline) remain Unknown errors. This does not classify PlanReceipt states.
pub(super) fn bounded_lookup(result: Result<(), Error>) -> Result<bool, learning::Error> {
    match result {
        Ok(()) => Ok(true),
        Err(Error::Busy) => Ok(false),
        Err(error) => Err(evidence_error(error)),
    }
}

pub(super) fn evidence_error(error: Error) -> learning::Error {
    match error {
        Error::Busy | Error::Again | Error::NotReady => learning::Error::Unknown,
        Error::Format
        | Error::Auth
        | Error::Schema
        | Error::Stale
        | Error::Capacity
        | Error::Budget
        | Error::Conflict
        | Error::Expired
        | Error::Unsupported
        | Error::NotFound
        | Error::Exists
        | Error::NotDirectory
        | Error::IsDirectory
        | Error::NotEmpty
        | Error::Range
        | Error::Io
        | Error::Overflow => learning::Error::Evidence,
    }
}
