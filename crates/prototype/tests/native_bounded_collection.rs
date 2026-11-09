#![allow(dead_code)]
//! Host-only fixtures driving production bounded collection transitions.
//! These do not construct AcceptedSample or grant replay authority.
#[path = "../../../kernel/src/learning_replay/bounded_data.rs"]
mod bounded;
use bounded::{Ledger, MAX_ATTEMPTS, Reference, Release};
fn reference(trial: u64, generation: u64) -> Reference {
    Reference {
        key: [1, trial, generation],
        object: [100 + trial, 1],
        offset: 0,
        bytes: 2048,
        digest: [trial as u8; 32],
    }
}
fn admitted(l: &mut Ledger, trial: u64, kind: u64) {
    l.admit(trial, trial, 1, kind, 100).unwrap();
}
fn completed(l: &mut Ledger, t: u64, ok: bool) {
    l.capture(t, 1).unwrap();
    if ok {
        l.verified(t, [t as u8; 32]).unwrap();
    } else {
        l.error(t, 10, 123).unwrap();
        l.excluded(t, 17).unwrap();
    }
    l.journal(t, 0, reference(t, 1)).unwrap();
    for b in [
        Release::Capture,
        Release::History,
        Release::Work,
        Release::Root,
        Release::Permit,
    ] {
        l.release(t, b).unwrap();
    }
}
fn witness(b: u64, c: u64) -> [u8; 1024] {
    let mut w = [0; 1024];
    w[32..40].copy_from_slice(&b.to_le_bytes());
    w[40..48].copy_from_slice(&c.to_le_bytes());
    w[48..80].fill(b as u8);
    w[80..112].fill(c as u8);
    w
}
#[test]
fn excluded_baseline_cleanup_then_actual_pair_selection() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, false);
    assert_eq!(l.row(0)[5], 10);
    assert_eq!(l.row(0)[6], 17);
    admitted(&mut l, 2, 2);
    completed(&mut l, 2, true);
    admitted(&mut l, 3, 1);
    completed(&mut l, 3, true);
    l.store(&witness(2, 3)).unwrap();
    assert_eq!(l.selected().unwrap(), [reference(2, 1), reference(3, 1)]);
    assert!(l.references_closed());
    assert_eq!(l.count(), 3);
    assert!(l.admit(4, 4, 1, 2, 100).is_err());
}
#[test]
fn excluded_candidate_preserves_superseded_baseline_and_own_failure() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, true);
    admitted(&mut l, 2, 1);
    completed(&mut l, 2, false);
    l.supersede().unwrap();
    assert_eq!(l.row(0)[7], 5);
    assert_eq!(l.row(1)[5], 10);
    admitted(&mut l, 3, 2);
    completed(&mut l, 3, true);
    admitted(&mut l, 4, 1);
    completed(&mut l, 4, true);
    l.store(&witness(3, 4)).unwrap();
    assert_eq!(l.selected().unwrap()[0].key[1], 3);
    assert_eq!(l.row(0)[16], 1);
    assert_eq!(l.journals(), 4);
}
#[test]
fn six_real_admissions_bound_before_seventh_resources_and_cleanup_not_skipped() {
    let mut l = Ledger::new();
    for t in 1..=MAX_ATTEMPTS as u64 {
        assert!(l.can_admit());
        admitted(&mut l, t, 2);
        if t < 6 {
            completed(&mut l, t, false);
        }
    }
    assert!(!l.can_admit());
    assert!(l.admit(7, 7, 1, 2, 100).is_err());
    assert!(!l.references_closed());
    completed(&mut l, 6, false);
    assert!(l.references_closed());
    assert!(l.exhausted());
    assert_eq!(l.count(), 6);
}
#[test]
fn preparation_only_and_late_journal_are_durable_refs_not_credit_ack() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    l.error(1, 2, 222).unwrap();
    l.excluded(1, 17).unwrap();
    l.journal(1, 1, reference(1, 0)).unwrap();
    for b in [Release::Work, Release::Root, Release::Permit] {
        l.release(1, b).unwrap();
    }
    assert!(l.references_closed());
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, true);
    l.journal(1, 2, reference(1, 1)).unwrap();
    assert_eq!(l.journals(), 2);
}
#[test]
fn missing_readback_and_unreleased_reference_prevent_completion() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    l.capture(1, 1).unwrap();
    for b in [
        Release::Capture,
        Release::History,
        Release::Work,
        Release::Root,
        Release::Permit,
    ] {
        l.release(1, b).unwrap();
    }
    assert!(!l.references_closed());
    assert!(l.selected().is_err());
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    l.journal(1, 1, reference(1, 0)).unwrap();
    assert!(!l.references_closed());
}
#[test]
fn store_is_terminal_even_if_witness_selection_invalid() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, true);
    admitted(&mut l, 2, 1);
    completed(&mut l, 2, true);
    assert!(l.store(&witness(1, 4)).is_err());
    assert!(l.stored());
    assert!(!l.can_admit());
    assert!(l.supersede().is_err());
    assert!(l.store(&witness(1, 2)).is_err());
}
#[test]
fn stale_duplicate_wrong_kind_and_changed_error_denied() {
    let mut l = Ledger::new();
    assert!(l.admit(1, 1, 0, 2, 100).is_err());
    admitted(&mut l, 1, 2);
    assert!(l.admit(1, 2, 1, 2, 100).is_err());
    l.error(1, 10, 123).unwrap();
    l.error(1, 10, 123).unwrap();
    assert!(l.error(1, 20, 124).is_err());
    assert!(l.journal(1, 0, reference(2, 1)).is_err());
    completed(&mut l, 1, false);
    assert!(l.store(&witness(1, 1)).is_err());
}

#[test]
fn outstanding_baseline_root_transfers_but_unclosed_exclusion_blocks_admission() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    assert!(!l.can_admit());
    l.root(1, 4).unwrap();
    l.capture(1, 1).unwrap();
    l.verified(1, [1; 32]).unwrap();
    l.journal(1, 0, reference(1, 1)).unwrap();
    for r in [
        Release::Capture,
        Release::History,
        Release::Work,
        Release::Permit,
    ] {
        l.release(1, r).unwrap();
    }
    assert!(l.can_admit());
    assert!(!l.references_closed());
    admitted(&mut l, 2, 1);
    completed(&mut l, 2, true);
    l.release_root_chain();
    assert!(l.references_closed());
    assert_eq!(l.closed(), 2);
}
#[test]
fn only_expected_exclusion_codes_can_restart_and_supplement_requires_final_actual_ack() {
    assert_eq!(bounded::EVIDENCE_BYTES, 8192);
    assert_eq!(bounded::MAGIC, 0x4359424441543136);
    for original in [2, 4, 5, 6, 7, 18, 19] {
        let mut l = Ledger::new();
        admitted(&mut l, 1, 2);
        l.error(1, original, 123).unwrap();
        l.excluded(1, 17).unwrap();
        assert!(!l.retryable());
    }
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, false);
    assert!(l.retryable());
    assert!(l.supplement(None, [1, 0, 1], 0, true).is_err());
    assert!(l.supplement(None, [1, 0, 1], 41, false).is_err());
    let bytes = l.supplement(None, [1, 0, 1], 41, true).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert!(bytes[2816..].iter().all(|v| *v == 0));
}
#[path = "../../../kernel/src/domain_control/baseline_cause.rs"]
mod baseline_cause;

#[test]
fn baseline_root_retention_precedes_actual_permit_release_then_candidate_admission() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    l.root(1, 4).unwrap();
    l.capture(1, 1).unwrap();
    l.verified(1, [1; 32]).unwrap();
    l.journal(1, 0, reference(1, 1)).unwrap();
    for r in [Release::Capture, Release::History, Release::Work] {
        l.release(1, r).unwrap();
    }
    assert!(l.may_continue());
    assert!(!l.can_admit()); // Root retained before permit release.
    l.release(1, Release::Permit).unwrap();
    assert!(l.can_admit());
    admitted(&mut l, 2, 1);
}
#[test]
fn wrong_canonical_and_selected_export_never_pass_and_store_remains_terminal() {
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, true);
    admitted(&mut l, 2, 1);
    completed(&mut l, 2, true);
    let mut w = witness(1, 2);
    w[48] ^= 1;
    assert!(l.store(&w).is_err());
    assert!(l.stored());
    assert!(l.selected().is_err());
    assert!(!l.can_admit());
}

#[test]
fn retained_busy_then_later_hard_io_recovery_never_reopens_admission_or_store() {
    use cyxia_prototype::domains::Error;
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    l.capture(1, 1).unwrap();
    l.error(1, 10, 123).unwrap();
    l.excluded(1, 17).unwrap();
    l.observe_incoming(1, Error::Io, 200, 10).unwrap();
    assert_eq!(l.row(0)[5], 10);
    assert_eq!(l.row(0)[55], 18);
    assert_eq!(l.hard_stop(), [1, 18, 200, 10]);
    assert!(!l.may_continue());
    assert!(!l.can_admit());
    assert!(!l.references_closed());
    // The failed writer can later recover, but that never clears the hard stop.
    l.journal(1, 0, reference(1, 1)).unwrap();
    for r in [
        Release::Capture,
        Release::History,
        Release::Work,
        Release::Root,
        Release::Permit,
    ] {
        l.release(1, r).unwrap();
    }
    assert!(l.references_closed());
    assert!(!l.retryable());
    assert!(l.admit(2, 2, 1, 2, 100).is_err());
    assert!(l.store(&witness(1, 2)).is_err());
    assert!(!l.stored());
    let bytes = l.supplement(None, [1, 0, 1], 41, true).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[4064..4072].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(bytes[4072..4080].try_into().unwrap()),
        18
    );
    l.observe_incoming(1, Error::Auth, 201, 11).unwrap();
    assert_eq!(l.hard_stop(), [1, 18, 200, 10]);
    assert_eq!(l.row(0)[55], 18);
}
#[test]
fn hard_fault_after_existing_store_keeps_identity_but_can_never_be_success() {
    use cyxia_prototype::domains::Error;
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, true);
    admitted(&mut l, 2, 1);
    completed(&mut l, 2, true);
    let w = witness(1, 2);
    l.store(&w).unwrap();
    l.observe_incoming(2, Error::Io, 300, 10).unwrap();
    assert!(l.stored());
    assert_eq!(l.selected_trials(), [1, 2]);
    assert_eq!(l.hard_stop(), [2, 18, 300, 10 | (1u64 << 63)]);
    assert!(!l.retryable());
    assert!(!l.can_admit());
    assert!(l.store(&w).is_err());
    assert!(l.supplement(Some(&w), [0, 2, 2], 41, true).is_ok());
}

#[test]
fn hard_failure_after_final_immutable_snapshot_leaves_new_fault_record_owed() {
    use cyxia_prototype::domains::Error;
    let mut l = Ledger::new();
    admitted(&mut l, 1, 2);
    completed(&mut l, 1, false);
    let snapshot = l.supplement(None, [1, 0, 1], 41, true).unwrap();
    assert!(l.snapshot_current(&snapshot));
    l.observe_incoming(1, Error::Io, 400, 24).unwrap();
    assert!(!l.snapshot_current(&snapshot));
    assert!(!l.can_admit());
    assert!(!l.retryable());
}
