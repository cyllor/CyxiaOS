//! Boundary tests invoke the production post-owner-callback clock check.
#[path = "../../../kernel/src/domain_control/publication_clock.rs"]
mod publication_clock;
use cyxia_prototype::{
    domains::{ObjectKey, WINDOW_NS},
    learning::{Error, governance::CanaryPermit},
    policy::PUBLICATION_BUDGET_NS,
};
use publication_clock::PublicationClock;

fn permit() -> CanaryPermit {
    CanaryPermit {
        id: 3,
        active_generation: 9,
        candidate_hash: [7; 32],
        target: ObjectKey {
            id: 15,
            generation: 1,
        },
        start_ns: 10 * WINDOW_NS,
        expires_ns: 110 * WINDOW_NS,
        windows: 100,
        quota: 100,
    }
}
fn clock(started_ns: u64) -> PublicationClock {
    PublicationClock {
        started_ns,
        deadline_ns: started_ns + 50_000_000,
        permit: permit(),
    }
}

#[test]
fn last_legal_callback_cannot_publish_after_exact_permit_expiry() {
    let expiry = permit().expires_ns;
    let commit = expiry - 100_000;
    let final_clock = clock(commit - 10_000);
    assert_eq!(final_clock.check(commit, expiry - 1), Ok(()));
    assert_eq!(final_clock.check(commit, expiry), Err(Error::Deadline));
    // The old commit clock is legal and neither 500us nor the job deadline
    // is exceeded, but the actual final callback has crossed the permit end.
    assert_eq!(
        final_clock.check(commit, expiry + 10_000),
        Err(Error::Deadline)
    );
}

#[test]
fn last_callback_cannot_charge_publication_to_the_previous_100ms_window() {
    let boundary = permit().start_ns + 3 * WINDOW_NS;
    let commit = boundary - 100_000;
    let final_clock = clock(commit - 10_000);
    assert_eq!(final_clock.check(commit, boundary - 1), Ok(()));
    assert_eq!(final_clock.check(commit, boundary), Err(Error::Deadline));
    assert_eq!(
        final_clock.check(commit, boundary + 10_000),
        Err(Error::Deadline)
    );
}

#[test]
fn start_deadline_and_cpu_budget_bounds_are_not_renewed_by_the_callback() {
    let start = permit().start_ns;
    assert_eq!(clock(start).check(start, start), Ok(()));
    assert_eq!(
        clock(start - 1).check(start - 1, start),
        Err(Error::Deadline)
    );
    let mut final_clock = clock(start);
    final_clock.deadline_ns = start + 250_000;
    assert_eq!(final_clock.check(start, start + 250_000), Ok(()));
    assert_eq!(
        final_clock.check(start, start + 250_001),
        Err(Error::Deadline)
    );
    assert_eq!(
        clock(start).check(start, start + PUBLICATION_BUDGET_NS),
        Ok(())
    );
    assert_eq!(
        clock(start).check(start, start + PUBLICATION_BUDGET_NS + 1),
        Err(Error::Budget)
    );
}

#[test]
fn backwards_clocks_cannot_hide_cost_or_move_the_commit_before_issuance() {
    let start = permit().start_ns + 1_000_000;
    assert_eq!(clock(start).check(start - 1, start), Err(Error::Deadline));
    assert_eq!(
        clock(start).check(start + 100, start + 99),
        Err(Error::Deadline)
    );
}
