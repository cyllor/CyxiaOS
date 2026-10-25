//! Exercise the production first-failure latch without supplying any replay
//! authorization, learning samples, or native completion evidence.
#[path = "../../../kernel/src/learning_replay/diagnostic.rs"]
#[allow(dead_code)]
mod diagnostic;
use cyxia_prototype::{domains::Error, learning, policy::ExecutionState};
use diagnostic::{Attempt, Evidence, MAGIC, Site};

#[test]
fn transient_lookup_does_not_hide_the_first_actual_failure() {
    let bank = Evidence::new();
    let mut attempt = Attempt::new(70);
    attempt.words[3] = 6; // actual Run phase + 1
    attempt.words[10] = 11;
    for error in [Error::Busy, Error::Again, Error::NotReady] {
        attempt.site(Site::RunRoot);
        assert!(!attempt.retain_in(&bank, error, None, 75));
        assert_eq!(bank.snapshot(), [0; 32]);
    }
    attempt.site(Site::RunBaselineRecord);
    attempt.nested(6, Some(learning::Error::Evidence));
    assert!(attempt.retain_in(&bank, Error::Conflict, None, 80));
    let original = bank.snapshot();
    assert_eq!(original[0], 2);
    assert_eq!(original[1], MAGIC);
    assert_eq!(original[2], 1);
    assert_eq!(original[3], 6);
    assert_eq!(original[4], Site::RunBaselineRecord as u64);
    assert_eq!(original[5], Error::Conflict as u64 + 1);
    assert_eq!(original[6], original[5]);
    assert_eq!(original[7], 6);
    assert_eq!(original[8], learning::Error::Evidence as u64 + 1);
    assert_eq!(original[9], 80);
    assert_eq!(original[10], 11);
    assert_eq!(original[31], 70);
    attempt.site(Site::Drain);
    assert!(!attempt.retain_in(&bank, Error::Expired, Some(Error::Stale), 99));
    assert_eq!(bank.snapshot(), original);
}

#[test]
fn a_retained_terminal_busy_is_distinct_from_an_unavailable_lookup() {
    let bank = Evidence::new();
    let mut attempt = Attempt::new(100);
    attempt.site(Site::RunRenew);
    attempt.receipt(Some((7, 0, ExecutionState::Failed(Error::Busy))));
    assert!(attempt.retain_in(&bank, Error::Busy, Some(Error::Busy), 105));
    let words = bank.snapshot();
    assert_eq!(words[5], Error::Busy as u64 + 1);
    assert_eq!(words[6], words[5]);
    assert_eq!(words[24], words[5]);
    assert_eq!(&words[27..31], &[7, 0, 3, Error::Busy as u64 + 1]);
}

#[test]
fn a_new_call_site_clears_only_its_nested_error() {
    let mut attempt = Attempt::new(100);
    attempt.receipt(Some((7, 2, ExecutionState::Unknown)));
    attempt.site(Site::RunArm);
    attempt.nested(6, Some(learning::Error::Deadline));
    attempt.site(Site::RunWork);
    assert_eq!(attempt.words[7], 0);
    assert_eq!(attempt.words[8], 0);
    assert_eq!(&attempt.words[27..31], &[7, 2, 4, 0]);
}
