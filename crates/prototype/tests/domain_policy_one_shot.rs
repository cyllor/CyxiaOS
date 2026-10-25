use cyxia_prototype::{
    domains::{
        Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS,
        maintenance::{RecoveryBackend, RecoverySupervisor},
    },
    features::RawFeatures,
    policy::{
        Candidate, CandidateSet, ExecutionState, ModelBinding, Publisher, Registry, Snapshot,
    },
    policy_wire::{Decision, Envelope},
};

const SNAPSHOT: u64 = 123_000_000;
const ONE_SHOT: [Action; 8] = [
    Action::ControlSet(2),
    Action::ControlSet(6),
    Action::RecoveryRecipe(0),
    Action::RecoveryRecipe(1),
    Action::RecoveryRecipe(2),
    Action::Placement(0),
    Action::Placement(1),
    Action::Placement(2),
];
const PERSISTENT: [Action; 15] = [
    Action::CpuWeight(2),
    Action::SpawnTokens(2),
    Action::Cache {
        pages: 256,
        batch: 16,
    },
    Action::Filesystem {
        readahead: 2,
        flush: 8,
    },
    Action::Ipc {
        budget: 32,
        batch: 4,
    },
    Action::IrqTarget(0),
    Action::SoftCoalesce(200),
    Action::ServiceBatch(4),
    Action::IoShare(250),
    Action::TxBatch(4),
    Action::NotifyBatch(2),
    Action::UnauthRate(16),
    Action::BackgroundBudget(100),
    Action::ConsoleBatch(8),
    Action::OfferCpu(100),
];

#[test]
fn every_one_shot_has_zero_lease_and_never_becomes_a_live_policy() {
    for action in ONE_SHOT {
        let stamp = PolicyStamp::for_action(action, 7, SNAPSHOT, SNAPSHOT + 1).unwrap();
        assert_eq!(stamp.installed_until_ns, 0, "{action:?}");
        assert_eq!(stamp.validate_action(action), Ok(()));
        for now in [0, SNAPSHOT - 1, SNAPSHOT, SNAPSHOT + POLICY_NS, u64::MAX] {
            assert!(!stamp.live(now), "{action:?} at {now}");
        }
    }
}

#[test]
fn persistent_leases_remain_anchored_to_the_original_snapshot() {
    for action in PERSISTENT {
        let stamp = PolicyStamp::for_action(action, 7, SNAPSHOT, SNAPSHOT + WINDOW_NS).unwrap();
        assert_eq!(stamp.installed_until_ns, SNAPSHOT + POLICY_NS, "{action:?}");
        assert!(!stamp.live(SNAPSHOT - 1));
        assert!(stamp.live(SNAPSHOT));
        assert!(stamp.live(SNAPSHOT + POLICY_NS - 1));
        assert!(!stamp.live(SNAPSHOT + POLICY_NS));
        assert_eq!(stamp.accepts_action(action, stamp, u64::MAX), Ok(()));
        assert!(!stamp.live(u64::MAX));
    }
    assert_eq!(
        PolicyStamp::new(7, SNAPSHOT, SNAPSHOT + 1).unwrap(),
        PolicyStamp::for_action(Action::CpuWeight(2), 7, SNAPSHOT, SNAPSHOT + 1).unwrap()
    );
}

#[test]
fn persistent_owners_reject_zero_lease_even_as_an_identical_retry() {
    let zero = PolicyStamp {
        version: 7,
        snapshot_ns: SNAPSHOT,
        installed_until_ns: 0,
    };
    for action in PERSISTENT {
        assert_eq!(
            zero.validate_action(action),
            Err(Error::Format),
            "{action:?}"
        );
        assert_eq!(
            PolicyStamp::default().accepts_action(action, zero, SNAPSHOT),
            Err(Error::Format)
        );
        assert_eq!(
            zero.accepts_action(action, zero, u64::MAX),
            Err(Error::Format)
        );
    }
    assert_eq!(zero.accepts(zero, SNAPSHOT), Err(Error::Format));
}

#[test]
fn one_shot_owners_reject_installed_leases_even_as_identical_retries() {
    let persistent = PolicyStamp::new(7, SNAPSHOT, SNAPSHOT).unwrap();
    for action in ONE_SHOT {
        for until in [1, SNAPSHOT, persistent.installed_until_ns, u64::MAX] {
            let wrong = PolicyStamp {
                installed_until_ns: until,
                ..persistent
            };
            assert_eq!(
                wrong.validate_action(action),
                Err(Error::Format),
                "{action:?}"
            );
            assert_eq!(
                PolicyStamp::default().accepts_action(action, wrong, SNAPSHOT),
                Err(Error::Format)
            );
            assert_eq!(
                wrong.accepts_action(action, wrong, u64::MAX),
                Err(Error::Format)
            );
        }
    }
}

#[test]
fn exact_receipts_survive_expiry_but_conflicting_identity_cannot_renew_them() {
    for action in ONE_SHOT.into_iter().chain(PERSISTENT) {
        let old = PolicyStamp::for_action(action, 7, SNAPSHOT, SNAPSHOT).unwrap();
        assert_eq!(
            old.accepts_action(action, old, u64::MAX),
            Ok(()),
            "{action:?}"
        );
        assert_eq!(old.validate_action(action), Ok(()));
        let changed = PolicyStamp::for_action(action, 7, SNAPSHOT + 1, SNAPSHOT + 1).unwrap();
        assert_eq!(
            old.accepts_action(action, changed, SNAPSHOT + 1),
            Err(Error::Conflict)
        );
        let malformed = PolicyStamp {
            installed_until_ns: old.installed_until_ns + 1,
            ..old
        };
        assert_eq!(
            old.accepts_action(action, malformed, SNAPSHOT),
            Err(Error::Conflict)
        );
    }
}

#[test]
fn new_one_shot_is_still_subject_to_the_admission_window_and_version_order() {
    for action in ONE_SHOT {
        let old = PolicyStamp::for_action(action, 7, SNAPSHOT, SNAPSHOT).unwrap();
        let next = PolicyStamp::for_action(action, 8, SNAPSHOT, SNAPSHOT).unwrap();
        assert_eq!(
            old.accepts_action(action, next, SNAPSHOT - 1),
            Err(Error::Range)
        );
        assert_eq!(
            old.accepts_action(action, next, SNAPSHOT + WINDOW_NS),
            Ok(())
        );
        assert_eq!(
            old.accepts_action(action, next, SNAPSHOT + WINDOW_NS + 1),
            Err(Error::Expired)
        );
        assert_eq!(
            next.accepts_action(action, old, SNAPSHOT),
            Err(Error::Stale)
        );
        assert_eq!(
            PolicyStamp::for_action(action, 0, SNAPSHOT, SNAPSHOT),
            Err(Error::Stale)
        );
        assert_eq!(
            PolicyStamp::for_action(action, 8, SNAPSHOT, SNAPSHOT + WINDOW_NS + 1),
            Err(Error::Expired)
        );
    }
}

#[test]
fn lease_arithmetic_cannot_wrap_or_masquerade_as_a_zero_lease() {
    let last = u64::MAX - POLICY_NS;
    for action in PERSISTENT {
        let final_lease = PolicyStamp::for_action(action, 7, last, last).unwrap();
        assert_eq!(final_lease.installed_until_ns, u64::MAX);
        assert!(final_lease.live(u64::MAX - 1));
        assert!(!final_lease.live(u64::MAX));
        assert_eq!(
            PolicyStamp::for_action(action, 7, last + 1, last + 1),
            Err(Error::Overflow)
        );
        let forged_zero = PolicyStamp {
            version: 7,
            snapshot_ns: last + 1,
            installed_until_ns: 0,
        };
        assert_eq!(forged_zero.validate_action(action), Err(Error::Overflow));
    }
}

#[test]
fn registered_set_stamp_preserves_the_real_action_lifetime() {
    let publisher = Publisher {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        controller_epoch: 2,
    };
    let model = ModelBinding {
        generation: 3,
        model_hash: [4; 32],
        schema_hash: [5; 32],
    };
    let mut registry = Registry::new(6, publisher, model).unwrap();
    for (sequence, action) in [
        Action::ControlSet(2),
        Action::RecoveryRecipe(0),
        Action::Placement(2),
    ]
    .into_iter()
    .chain(PERSISTENT)
    .enumerate()
    {
        let raw = RawFeatures {
            control_capacity: Some(700),
            ..RawFeatures::default()
        };
        let set = CandidateSet::new(
            Snapshot {
                sequence: sequence as u64 + 1,
                taken_ns: SNAPSHOT,
                ledger_generation: 7,
                core_generation: 8,
            },
            ObjectKey {
                id: 9,
                generation: 10,
            },
            model,
            &[Candidate {
                action,
                features: raw,
            }],
            Some(action),
        )
        .unwrap();
        registry.register(publisher, &set).unwrap();
        let decision = Decision {
            action,
            candidate_index: 0,
            envelope: Envelope {
                controller_epoch: publisher.controller_epoch,
                decision_seq: sequence as u64 + 1,
                snapshot_seq: set.snapshot.sequence,
                target: set.target,
                ledger_generation: set.snapshot.ledger_generation,
                core_generation: set.snapshot.core_generation,
                expires_local_ns: SNAPSHOT + WINDOW_NS,
                model_hash: model.model_hash,
                candidate_set_hash: set.hash(),
            },
        };
        let stamp = registry.stamp(decision, 11, SNAPSHOT + 1).unwrap();
        assert_eq!(
            stamp.installed_until_ns,
            if action.one_shot() {
                0
            } else {
                SNAPSHOT + POLICY_NS
            },
            "{action:?}"
        );
        assert_eq!(stamp.validate_action(action), Ok(()));
    }
}

fn recovery_id(sequence: u64) -> ApplyId {
    ApplyId {
        boot_epoch: 1,
        controller_epoch: 2,
        plan_seq: sequence,
        action_index: 0,
        target: ObjectKey {
            id: 3,
            generation: 4,
        },
    }
}

#[test]
fn recovery_policy_retry_retains_pending_obligation_and_exact_stamp_after_admission_expiry() {
    let mut owner = RecoverySupervisor::new();
    owner.register(recovery_id(1).target, 1).unwrap();
    let stamp = PolicyStamp::for_action(Action::RecoveryRecipe(1), 7, SNAPSHOT, SNAPSHOT).unwrap();
    let initial = owner
        .begin_policy(recovery_id(1), 1, stamp, SNAPSHOT)
        .unwrap();
    assert_eq!(initial.state, ExecutionState::Pending);
    assert_eq!(initial.generation, 5);
    assert_eq!(initial.finished_ns, 0);
    assert_eq!(
        owner.begin_policy(recovery_id(1), 1, stamp, u64::MAX),
        Ok(initial)
    );
    for changed in [
        PolicyStamp {
            version: 8,
            ..stamp
        },
        PolicyStamp {
            snapshot_ns: SNAPSHOT + 1,
            ..stamp
        },
        PolicyStamp {
            installed_until_ns: SNAPSHOT + POLICY_NS,
            ..stamp
        },
    ] {
        assert_eq!(
            owner.begin_policy(recovery_id(1), 1, changed, SNAPSHOT + 1),
            Err(Error::Conflict)
        );
    }
    assert_eq!(
        owner.begin_policy(recovery_id(1), 2, stamp, SNAPSHOT + 1),
        Err(Error::Conflict)
    );
    assert_eq!(owner.query(recovery_id(1)), Ok(initial));
    let later = SNAPSHOT + POLICY_NS + 1;
    let next = PolicyStamp::for_action(Action::RecoveryRecipe(1), 8, later, later).unwrap();
    assert_eq!(
        owner.begin_policy(recovery_id(2), 1, next, later),
        Err(Error::Busy)
    );
    assert_eq!(owner.query(recovery_id(1)), Ok(initial));
}

#[test]
fn recovery_rejected_admission_does_not_consume_the_request_or_create_an_obligation() {
    let mut owner = RecoverySupervisor::new();
    owner.register(recovery_id(1).target, 1).unwrap();
    let stamp = PolicyStamp::for_action(Action::RecoveryRecipe(1), 7, SNAPSHOT, SNAPSHOT).unwrap();
    let later = SNAPSHOT + WINDOW_NS + 1;
    assert_eq!(
        owner.begin_policy(recovery_id(1), 1, stamp, later),
        Err(Error::Expired)
    );
    assert_eq!(owner.query(recovery_id(1)), Err(Error::Stale));
    let leased = PolicyStamp::new(7, later, later).unwrap();
    assert_eq!(
        owner.begin_policy(recovery_id(1), 1, leased, later),
        Err(Error::Format)
    );
    assert_eq!(owner.query(recovery_id(1)), Err(Error::Stale));
    let fresh = PolicyStamp::for_action(Action::RecoveryRecipe(1), 7, later, later).unwrap();
    assert_eq!(
        owner
            .begin_policy(recovery_id(1), 1, fresh, later)
            .unwrap()
            .state,
        ExecutionState::Pending
    );
}

#[derive(Default)]
struct AmbiguousRecovery {
    stops: usize,
    starts: usize,
    stopped: bool,
    running: bool,
}
impl RecoveryBackend for AmbiguousRecovery {
    fn close_admission(&mut self, target: ObjectKey) -> Result<(), Error> {
        assert_eq!(target, recovery_id(1).target);
        Ok(())
    }
    fn readonly_drained(&mut self, _: ObjectKey) -> Result<bool, Error> {
        Ok(true)
    }
    fn request_stop(&mut self, _: ObjectKey) -> Result<(), Error> {
        self.stops += 1;
        Err(Error::Io)
    }
    fn stopped(&mut self, _: ObjectKey) -> Result<bool, Error> {
        Ok(self.stopped)
    }
    fn start_generation(&mut self, _: ObjectKey, generation: u64) -> Result<(), Error> {
        assert_eq!(generation, 5);
        self.starts += 1;
        Err(Error::Io)
    }
    fn running(&mut self, _: ObjectKey, generation: u64) -> Result<bool, Error> {
        assert_eq!(generation, 5);
        Ok(self.running)
    }
}

#[test]
fn zero_lease_unknown_recovery_survives_history_pressure_and_only_queries_stop_start() {
    let mut owner = RecoverySupervisor::new();
    owner.register(recovery_id(1).target, 1).unwrap();
    let stamp = PolicyStamp::for_action(Action::RecoveryRecipe(1), 7, SNAPSHOT, SNAPSHOT).unwrap();
    owner
        .begin_policy(recovery_id(1), 1, stamp, SNAPSHOT)
        .unwrap();
    let mut backend = AmbiguousRecovery::default();
    for delta in 1..=3 {
        owner
            .poll(recovery_id(1), SNAPSHOT + delta, &mut backend)
            .unwrap();
    }
    assert_eq!(
        owner.query(recovery_id(1)).unwrap().state,
        ExecutionState::Unknown
    );
    assert_eq!((backend.stops, backend.starts), (1, 0));
    let late = SNAPSHOT + POLICY_NS + 1;
    for sequence in 2..=285 {
        let no_op =
            PolicyStamp::for_action(Action::RecoveryRecipe(0), sequence + 7, late, late).unwrap();
        assert_eq!(
            owner
                .begin_policy(recovery_id(sequence), 0, no_op, late)
                .unwrap()
                .state,
            ExecutionState::Applied
        );
    }
    let held = owner.begin_policy(recovery_id(1), 1, stamp, late).unwrap();
    assert_eq!(held.state, ExecutionState::Unknown);
    assert_eq!(held.finished_ns, 0);
    assert_eq!(
        owner
            .poll(recovery_id(1), late + 1, &mut backend)
            .unwrap()
            .state,
        ExecutionState::Unknown
    );
    assert_eq!((backend.stops, backend.starts), (1, 0));
    backend.stopped = true;
    owner.poll(recovery_id(1), late + 2, &mut backend).unwrap();
    owner.poll(recovery_id(1), late + 3, &mut backend).unwrap();
    assert_eq!((backend.stops, backend.starts), (1, 1));
    assert_eq!(
        owner
            .poll(recovery_id(1), late + 4, &mut backend)
            .unwrap()
            .state,
        ExecutionState::Unknown
    );
    backend.running = true;
    let completed = owner.poll(recovery_id(1), late + 5, &mut backend).unwrap();
    assert_eq!(completed.state, ExecutionState::Applied);
    assert_eq!(completed.finished_ns, late + 5);
    assert_eq!(
        owner.begin_policy(recovery_id(1), 1, stamp, u64::MAX),
        Ok(completed)
    );
    assert_eq!(
        owner.poll(recovery_id(1), u64::MAX, &mut backend),
        Ok(completed)
    );
    assert_eq!((backend.stops, backend.starts), (1, 1));
}

#[test]
fn independent_safety_recovery_cannot_be_relabelled_as_a_model_adoption() {
    let mut owner = RecoverySupervisor::new();
    owner.register(recovery_id(1).target, 1).unwrap();
    let initial = owner.begin(recovery_id(1), 1, SNAPSHOT).unwrap();
    let stamp = PolicyStamp::for_action(Action::RecoveryRecipe(1), 7, SNAPSHOT, SNAPSHOT).unwrap();
    assert_eq!(
        owner.begin_policy(recovery_id(1), 1, stamp, SNAPSHOT),
        Err(Error::Conflict)
    );
    assert_eq!(owner.begin(recovery_id(1), 1, u64::MAX), Ok(initial));
    assert_eq!(owner.query(recovery_id(1)), Ok(initial));
}
