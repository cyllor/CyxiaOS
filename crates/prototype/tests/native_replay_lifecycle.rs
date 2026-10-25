//! The production root/coordinator lifecycle state, exercised with synthetic
//! host identities. These tests create no replay samples or native receipts.
#[path = "../../../kernel/src/domain_control/replay/lifecycle.rs"]
mod lifecycle;
use cyxia_prototype::{domains::Error, learning::capture::RunKey, policy::ExecutionState};
use lifecycle::{CloseGate, WorkActivation};

fn run(generation: u64) -> RunKey {
    RunKey {
        boot_epoch: 4,
        trial_id: 9,
        generation,
    }
}

#[test]
fn capture_ready_without_owner_entry_can_close_without_starting_work() {
    let work = WorkActivation::new();
    let mut gate = CloseGate::new();
    // Capture/history can already exist; no owner activation was entered.
    assert!(!work.entered());
    assert_eq!(gate.begin(run(1), false, false), Ok(true));
    assert_eq!(gate.closing(), Some(run(1)));
    assert_eq!(gate.activated(), None);
    assert!(!work.complete());
    assert_eq!(gate.finish_activation(run(1)), Err(Error::Auth));
    // The root's cut is immutable across owner drain / archive retries.
    assert_eq!(gate.begin(run(1), false, false), Ok(true));
    assert_eq!(gate.begin(run(2), false, false), Err(Error::Stale));
}

#[test]
fn published_pending_and_unknown_require_original_activation_instead_of_waiting() {
    for state in [ExecutionState::Pending, ExecutionState::Unknown] {
        assert!(!state.terminal());
        let mut gate = CloseGate::new();
        let mut work = WorkActivation::new();
        // The native caller saw a real retained Desired/stop command. Its
        // still-unsettled state cannot turn publication into non-publication.
        assert_eq!(gate.begin(run(1), true, true), Ok(false));
        assert_eq!(gate.closing(), None);
        work.enter();
        assert!(work.entered());
        assert!(!work.complete());
        work.finish().unwrap();
        gate.finish_activation(run(1)).unwrap();
        assert_eq!(gate.begin(run(1), false, false), Err(Error::Conflict));
        assert_eq!(gate.activated(), Some(run(1)));
    }
}

#[test]
fn unresolved_prepared_publication_leaves_owner_and_gate_unchanged() {
    let work = WorkActivation::new();
    let mut gate = CloseGate::new();
    assert_eq!(gate.begin(run(1), false, true), Err(Error::Busy));
    assert_eq!(gate.closing(), None);
    assert!(!work.entered());
    // Only a later actual root observation of settled non-publication closes.
    assert_eq!(gate.begin(run(1), false, false), Ok(true));
}

#[test]
fn busy_after_a_facade_effect_never_reverts_to_unactivated() {
    let mut work = WorkActivation::new();
    assert_eq!(work.finish(), Err(Error::Conflict));
    work.enter();
    // The facade returned Busy after entering. A retry must keep the same
    // activation, with no unactivated-abort transition available.
    assert!(work.entered());
    assert!(!work.complete());
    work.enter();
    assert!(work.entered());
    assert!(!work.complete());
    work.finish().unwrap();
    work.enter();
    work.finish().unwrap();
    assert!(work.complete());
}

#[test]
fn successful_activation_metadata_is_idempotent_and_exact() {
    let mut gate = CloseGate::new();
    gate.finish_activation(run(1)).unwrap();
    gate.finish_activation(run(1)).unwrap();
    assert_eq!(gate.finish_activation(run(2)), Err(Error::Stale));
    assert_eq!(gate.closing(), None);
    assert_eq!(gate.activated(), Some(run(1)));
}

#[test]
fn waiting_restoration_still_drives_real_owner_before_retry() {
    use core::cell::Cell;
    let step = Cell::new(0);
    for error in [Error::Busy, Error::Again, Error::NotReady, Error::Stale] {
        step.set(0);
        assert_eq!(
            lifecycle::restore_and_drain(
                || {
                    assert_eq!(step.get(), 0);
                    step.set(1);
                    Err(error)
                },
                || {
                    assert_eq!(step.get(), 1);
                    step.set(2);
                    Ok(true)
                },
            ),
            Err(error)
        );
        assert_eq!(step.get(), 2);
    }
    assert_eq!(
        lifecycle::restore_and_drain(|| Ok(()), || Ok(false)),
        Ok(false)
    );
    assert_eq!(
        lifecycle::restore_and_drain(|| Ok(()), || Ok(true)),
        Ok(true)
    );
    assert_eq!(
        lifecycle::restore_and_drain(|| Ok(()), || Err(Error::Busy)),
        Err(Error::Busy)
    );
}
