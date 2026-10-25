//! Exercise the production placement observation and candidate-local legal
//! predicates. Missing peer telemetry must stay absent through encoding.
#[allow(dead_code)]
#[path = "../../../user/prototype-cluster/src/abi.rs"]
pub mod abi;
mod unified {
    pub use crate::abi;
}
#[path = "../../../kernel/src/domain_network/placement_legal.rs"]
mod placement_legal;
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    features::{self, RawFeatures},
};

#[test]
fn missing_peer_or_capacity_excludes_only_remote_choice() {
    let key = ObjectKey {
        id: 81,
        generation: 3,
    };
    let mut feedback = abi::DomainFeedback::default();
    feedback.waiting[7] = abi::PendingPlacementWire {
        request_id: key.id,
        request_generation: key.generation,
        queued_us: 120,
        cpu_milli: 100,
        memory_pages: 16,
        peer_ready: 0,
    };
    for stage in 0..5 {
        if stage == 1 {
            feedback.waiting[7].peer_ready = 1;
        }
        if stage == 2 {
            feedback.peer_cpu_milli = 100;
        }
        if stage == 3 {
            feedback.peer_memory_pages = 16;
        }
        if stage == 4 {
            feedback.measurement_valid = 4;
        }
        assert_eq!(placement_legal::legal(0, key, &feedback, 0), Ok(()));
        assert_eq!(placement_legal::legal(2, key, &feedback, 0), Ok(()));
        assert_eq!(
            placement_legal::legal(1, key, &feedback, 0),
            if stage == 4 {
                Ok(())
            } else {
                Err(Error::Capacity)
            }
        );
    }
    for choice in 0..3 {
        assert_eq!(
            placement_legal::legal(
                choice,
                ObjectKey {
                    generation: 4,
                    ..key
                },
                &feedback,
                0
            ),
            Err(Error::Stale)
        );
    }
}

#[test]
fn fresh_waiting_request_without_peer_scores_local_and_defer_with_absent_peer_slots() {
    let key = ObjectKey {
        id: 81,
        generation: 3,
    };
    let mut feedback = abi::DomainFeedback::default();
    feedback.measurement_ms = 1000;
    // Stale storage is intentionally nonzero; the validity bit, not the raw
    // number, determines whether it can be used as a measurement.
    feedback.cluster = [250, 100, 300, 9999];
    feedback.waiting[7] = abi::PendingPlacementWire {
        request_id: key.id,
        request_generation: key.generation,
        queued_us: 120,
        cpu_milli: 100,
        memory_pages: 16,
        peer_ready: 0,
    };
    let observed = placement_legal::observation(key, &feedback, 1005).unwrap();
    assert_eq!(observed.values, [0, 0, 0, 120]);
    assert_eq!(observed.present, 0b1000);
    let raw = RawFeatures {
        domain: observed.values,
        domain_present: observed.present,
        ..RawFeatures::default()
    };
    for choice in [0, 2] {
        assert_eq!(placement_legal::legal(choice, key, &feedback, 1005), Ok(()));
        let encoded = features::encode(Action::Placement(choice), raw).unwrap();
        assert_eq!(&encoded.values[24..27], &[0; 3]);
        assert_eq!(&encoded.values[32..36], &[0, 0, 0, 256]);
    }
    assert_eq!(
        placement_legal::legal(1, key, &feedback, 1005),
        Err(Error::Capacity)
    );
    assert_eq!(
        features::encode(Action::Placement(1), raw),
        Err(Error::NotReady)
    );
    assert_eq!(
        features::encode(Action::TxBatch(4), raw),
        Err(Error::NotReady)
    );
    assert_eq!(
        features::encode(Action::OfferCpu(100), raw),
        Err(Error::NotReady)
    );

    feedback.measurement_valid = 4;
    let complete = placement_legal::observation(key, &feedback, 1005).unwrap();
    assert_eq!(complete.values, [250, 100, 300, 120]);
    assert_eq!(complete.present, features::DOMAIN_PRESENT_ALL);
}

#[test]
fn stale_or_recycled_waiting_feedback_is_not_scoreable_or_legal() {
    let key = ObjectKey {
        id: 81,
        generation: 3,
    };
    let mut feedback = abi::DomainFeedback::default();
    feedback.measurement_ms = 1000;
    feedback.measurement_valid = 4;
    feedback.peer_cpu_milli = 100;
    feedback.peer_memory_pages = 16;
    feedback.waiting[0] = abi::PendingPlacementWire {
        request_id: key.id,
        request_generation: key.generation,
        queued_us: 120,
        cpu_milli: 100,
        memory_pages: 16,
        peer_ready: 1,
    };
    assert!(placement_legal::observation(key, &feedback, 1100).is_ok());
    for now in [999, 1101] {
        assert_eq!(
            placement_legal::observation(key, &feedback, now),
            Err(Error::NotReady)
        );
        for choice in 0..3 {
            assert_eq!(
                placement_legal::legal(choice, key, &feedback, now),
                Err(Error::NotReady)
            );
        }
    }
    let recycled = ObjectKey {
        generation: key.generation + 1,
        ..key
    };
    assert_eq!(
        placement_legal::observation(recycled, &feedback, 1000),
        Err(Error::Stale)
    );
    feedback.waiting[0].peer_ready = 2;
    assert_eq!(
        placement_legal::legal(1, key, &feedback, 1000),
        Err(Error::Capacity)
    );
}

#[test]
fn noncanonical_or_missing_required_domain_measurements_are_rejected() {
    let raw = RawFeatures {
        domain_present: 0b1000,
        ..RawFeatures::default()
    };
    assert_eq!(
        features::encode(
            Action::Placement(2),
            RawFeatures {
                domain_present: 0,
                ..raw
            }
        ),
        Err(Error::NotReady)
    );
    assert_eq!(
        features::encode(
            Action::Placement(2),
            RawFeatures {
                domain_present: 0b1_1000,
                ..raw
            }
        ),
        Err(Error::Format)
    );
    assert_eq!(
        features::encode(
            Action::Placement(2),
            RawFeatures {
                domain: [1, 0, 0, 0],
                ..raw
            }
        ),
        Err(Error::Format)
    );
}

#[test]
fn measured_zero_and_absent_zero_have_distinct_canonical_hash_vectors() {
    use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
    // Fixed vectors were calculated from the documented little-endian byte
    // sequence independently of CandidateSet and the native input decoder.
    for (mask, expected) in [
        (
            0b1000,
            "37f63b0aa0c0580d600c42b2577b7c37f639618fc5f0727986ceaf4c63aea9f7",
        ),
        (
            0b1111,
            "880bdbe99cbaf6a799bf7ab71a4d25b80e2057895b03aec19dde4d60bcb4ff30",
        ),
    ] {
        let raw = RawFeatures {
            domain_present: mask,
            ..RawFeatures::default()
        };
        let set = CandidateSet::new(
            Snapshot {
                sequence: 1,
                taken_ns: 10,
                ledger_generation: 1,
                core_generation: 1,
            },
            ObjectKey {
                id: 81,
                generation: 3,
            },
            ModelBinding {
                generation: 1,
                model_hash: [3; 32],
                schema_hash: [4; 32],
            },
            &[Candidate {
                action: Action::Placement(2),
                features: raw,
            }],
            Some(Action::Placement(2)),
        )
        .unwrap();
        let digest: String = set
            .hash()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(digest, expected);
        assert_eq!(set.verify_integrity(), Ok(()));
        let encoded = features::encode(Action::Placement(2), raw).unwrap();
        assert_eq!(&encoded.values[24..28], &[0; 4]);
        assert_eq!(
            &encoded.values[32..36],
            if mask == 0b1000 {
                &[0, 0, 0, 256]
            } else {
                &[256; 4]
            }
        );
    }
}
