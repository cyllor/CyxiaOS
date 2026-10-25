//! The same lookup-error classification used by the protected replay root.
//! These checks create neither publication receipts nor replay samples.
#[path = "../../../kernel/src/domain_control/replay/verification.rs"]
mod verification;
use cyxia_prototype::{domains::Error, learning};

#[test]
fn unavailable_root_or_owner_remains_retryable() {
    // Each can occur before a verifier has read the original retained facts.
    // None proves that the exact scope, baseline, or adoption is invalid.
    for error in [Error::Busy, Error::Again, Error::NotReady] {
        assert_eq!(
            verification::evidence_error(error),
            learning::Error::Unknown
        );
    }
}

#[test]
fn mismatches_and_exhausted_deadlines_cannot_become_retries() {
    for error in [
        Error::Format,
        Error::Auth,
        Error::Schema,
        Error::Stale,
        Error::Capacity,
        Error::Budget,
        Error::Conflict,
        Error::Expired,
        Error::Unsupported,
        Error::NotFound,
        Error::Exists,
        Error::NotDirectory,
        Error::IsDirectory,
        Error::NotEmpty,
        Error::Range,
        Error::Io,
        Error::Overflow,
    ] {
        assert_eq!(
            verification::evidence_error(error),
            learning::Error::Evidence
        );
    }
}

#[test]
fn bounded_verification_yields_only_for_gate_busy_not_retained_unknown() {
    assert_eq!(verification::bounded_lookup(Ok(())), Ok(true));
    assert_eq!(verification::bounded_lookup(Err(Error::Busy)), Ok(false));
    // The synchronous API intentionally maps all three to Unknown. The
    // bounded verifier must not turn real not-ready facts into infinite retry.
    for error in [Error::Again, Error::NotReady] {
        assert_eq!(
            verification::bounded_lookup(Err(error)),
            Err(learning::Error::Unknown)
        );
    }
    for error in [Error::Auth, Error::Stale, Error::Expired, Error::Conflict] {
        assert_eq!(
            verification::bounded_lookup(Err(error)),
            Err(learning::Error::Evidence)
        );
    }
}
