//! Retry classification for actual paid EL0 coordinator turns, not native proof.
#[path = "../../../kernel/src/prototype_runtime/governance/outcome.rs"]
mod outcome;

use cyxia_prototype::domains::Error;

#[test]
fn command_entry_has_the_existing_two_ms_cpu_envelope_without_changing_probe_modes() {
    assert_eq!(outcome::entry_slice_ns(0), Ok(2_000_000));
    assert_eq!(outcome::entry_slice_ns(4), Ok(100_000));
    for mode in 1..=3 {
        assert_eq!(outcome::entry_slice_ns(mode), Ok(20_000_000));
    }
    assert_eq!(outcome::entry_slice_ns(5), Err(Error::Conflict));
    assert_eq!(outcome::entry_slice_ns(u64::MAX), Err(Error::Conflict));
}

#[test]
fn contended_owner_or_pool_does_not_permanently_fault_the_coordinator() {
    assert_eq!(outcome::failure_code(Err(Error::Busy)), None);
    assert_eq!(outcome::failure_code(Err(Error::NotReady)), None);
    assert_eq!(outcome::failure_code(Ok(())), None);
}

#[test]
fn authority_generation_budget_and_malformed_results_remain_fatal() {
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
        Error::Again,
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
            outcome::failure_code(Err(error)),
            Some(0x700 + error as u64)
        );
    }
}
