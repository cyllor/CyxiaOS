//! Production transition seams with host fixtures; never creates training labels.
#[path = "../../../kernel/src/learning_replay/collection_profile.rs"]
mod collection_profile;
use collection_profile::{CollectionProfile as P, ReleaseFacts};
#[test]
fn full_schedule_unchanged() {
    assert_eq!(P::Full.first_family(), 0);
    assert!(!P::Full.pair_complete(2, 2, 1));
    assert_eq!(P::CoreSetOnePair.first_family(), 1);
    assert_eq!(P::CoreSetDataOnePair.first_family(), 1);
    assert!(P::CoreSetDataOnePair.bounded() && P::CoreSetDataOnePair.focused());
    assert!(!P::CoreSetDataOnePair.pair_complete(2, 2, 1));
    assert!(!P::Full.focused() && !P::CoreSetOnePair.bounded());
    assert!(!P::CoreSetOnePair.pair_complete(1, 1, 0));
    assert!(!P::CoreSetOnePair.pair_complete(2, 1, 1));
    assert!(P::CoreSetOnePair.pair_complete(2, 2, 1));
}
#[test]
fn every_trial_obligation_blocks_completion() {
    let clean = ReleaseFacts {
        owner_clear: true,
        work_quiescent: true,
        pending_baseline: false,
        witness_durable: true,
        credit_settled: true,
    };
    assert!(clean.complete());
    assert!(
        !ReleaseFacts {
            owner_clear: false,
            ..clean
        }
        .complete()
    );
    assert!(
        !ReleaseFacts {
            work_quiescent: false,
            ..clean
        }
        .complete()
    );
    assert!(
        !ReleaseFacts {
            pending_baseline: true,
            ..clean
        }
        .complete()
    );
    assert!(
        !ReleaseFacts {
            witness_durable: false,
            ..clean
        }
        .complete()
    );
    assert!(
        !ReleaseFacts {
            credit_settled: false,
            ..clean
        }
        .complete()
    );
    assert!(clean.complete()); // repeated final poll is idempotent
}

#[path = "../../../kernel/src/prototype_runtime/learning_turn_fence.rs"]
mod learning_turn_fence;
#[test]
fn released_input_does_not_acknowledge_unsettled_paid_turn() {
    let fence = learning_turn_fence::Fence::new();
    assert!(!fence.settled(0));
    fence.begin(41);
    let release_ticket = fence.ticket();
    assert_eq!(release_ticket, 41);
    // Loan disappearance inside the turn has no authority to settle its bill.
    assert!(!fence.settled(release_ticket));
    // Production learning::settle invokes this only after both exact bills.
    fence.acknowledge(41);
    assert!(fence.settled(release_ticket));
    fence.begin(42);
    assert!(fence.settled(release_ticket));
    assert!(!fence.settled(fence.ticket()));
    fence.acknowledge(42);
    assert!(fence.settled(42));
}
