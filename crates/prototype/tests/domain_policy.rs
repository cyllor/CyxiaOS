use cyxia_prototype::{domains::*, features::*, policy::*, policy_wire::*};

fn publisher() -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: 9,
    }
}
fn binding() -> ModelBinding {
    ModelBinding {
        generation: 1,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    }
}
fn candidates() -> CandidateSet {
    let choices = [8, 2, 4, 1].map(|n| Candidate {
        action: Action::CpuWeight(n),
        features: RawFeatures::default(),
    });
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: 10,
            ledger_generation: 3,
            core_generation: 2,
        },
        ObjectKey {
            id: 1,
            generation: 1,
        },
        binding(),
        &choices,
        Some(Action::CpuWeight(2)),
    )
    .unwrap()
}
fn frame(set: &CandidateSet, sequence: u64, base: u64) -> Vec<u8> {
    let header = PlanHeader {
        plan_seq: sequence,
        base_plan_version: base,
        active_model_generation: set.model.generation,
        controller_epoch: 9,
        snapshot_seq: set.snapshot.sequence,
        active_until_local_ns: set.snapshot.taken_ns + POLICY_NS,
    };
    let d = Decision {
        action: set.get(1).unwrap().action,
        candidate_index: 1,
        envelope: Envelope {
            controller_epoch: 9,
            decision_seq: sequence,
            snapshot_seq: set.snapshot.sequence,
            target: set.target,
            ledger_generation: set.snapshot.ledger_generation,
            core_generation: set.snapshot.core_generation,
            expires_local_ns: set.snapshot.taken_ns + WINDOW_NS,
            model_hash: set.model.model_hash,
            candidate_set_hash: set.hash(),
        },
    };
    let mut out = vec![0; MAX_PLAN_BYTES];
    let n = encode_plan(header, &[d], &mut out).unwrap();
    out.truncate(n);
    out
}
struct Times {
    first: u64,
    second: u64,
    calls: usize,
}
impl Clock for Times {
    fn now_ns(&mut self) -> u64 {
        self.calls += 1;
        if self.calls <= 2 {
            self.first
        } else {
            self.second
        }
    }
}
#[derive(Default)]
struct Owner {
    prepares: usize,
    publishes: usize,
    cancels: usize,
    move_during_prepare: bool,
    moved: bool,
}
impl Executor for Owner {
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        if self.moved {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.prepares += 1;
        self.moved = self.move_during_prepare;
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        if self.moved {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.publishes += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.cancels += 1;
    }
}
fn ready() -> (Registry, CandidateSet, Owner) {
    let set = candidates();
    let mut registry = Registry::new(11, publisher(), binding()).unwrap();
    registry.register(publisher(), &set).unwrap();
    (registry, set, Owner::default())
}
fn clock() -> Times {
    Times {
        first: 11,
        second: 12,
        calls: 0,
    }
}

#[test]
fn job_deadline_is_rechecked_after_validation_before_publish() {
    let (mut registry, set, mut owner) = ready();
    let bytes = frame(&set, 1, 0);
    let receipt = registry
        .submit_job(
            publisher(),
            &bytes,
            49_900_000,
            50_000_000,
            &mut Times {
                first: 49_900_000,
                second: 50_100_000,
                calls: 0,
            },
            &mut owner,
        )
        .unwrap();
    assert_eq!(receipt.version, 0);
    assert_eq!(receipt.actions[0], ExecutionState::Failed(Error::Expired));
    assert_eq!(owner.prepares, 1);
    assert_eq!(owner.cancels, 1);
    assert_eq!(owner.publishes, 0);
    assert!(!registry.optimization_stopped());
    // The failed identity remains queryable; a late retry cannot revive it.
    assert_eq!(
        registry
            .submit_job(
                publisher(),
                &bytes,
                60_000_000,
                50_000_000,
                &mut clock(),
                &mut owner
            )
            .unwrap(),
        receipt
    );
}

#[test]
fn exact_numeric_candidate_order_and_current_are_bound() {
    let set = candidates();
    assert_eq!(
        set.iter().map(|c| c.action).collect::<Vec<_>>(),
        vec![
            Action::CpuWeight(1),
            Action::CpuWeight(2),
            Action::CpuWeight(4),
            Action::CpuWeight(8)
        ]
    );
    let mut changed = set;
    changed.snapshot.core_generation += 1;
    let mut registry = Registry::new(11, publisher(), binding()).unwrap();
    assert_eq!(
        registry.register(publisher(), &changed),
        Err(Error::Conflict)
    );
}
#[test]
fn feature_schema_never_hides_domain_inputs_in_unused_slots() {
    let raw = RawFeatures {
        common: [1000, 1000, 64, 1000, 1000, 1000, 100, 1],
        domain: [64, 100000, 1000, 10000],
        ..RawFeatures::default()
    };
    let f = encode(Action::CpuWeight(8), raw).unwrap();
    assert_eq!(f.values[0], 256);
    assert_eq!(&f.values[16..24], &[256; 8]);
    assert_eq!(&f.values[24..28], &[256; 4]);
    assert_eq!(&f.values[28..32], &[0; 4]);
    assert_eq!(&f.values[36..40], &[0; 4]);
    assert_eq!(f.values[41], 256);
    assert_eq!(f.clipped, 0);
    assert_eq!(normalize(u64::MAX, u64::MAX), Ok((256, false)));
    assert_eq!(normalize(1, 512), Ok((1, false)));
}
#[test]
fn raw_saturation_does_not_erase_candidate_identity() {
    let set = candidates();
    let mut choices = set.iter().collect::<Vec<_>>();
    for c in &mut choices {
        c.features.common[0] = 1001;
    }
    let changed = CandidateSet::new(
        set.snapshot,
        set.target,
        set.model,
        &choices,
        Some(Action::CpuWeight(2)),
    )
    .unwrap();
    assert_ne!(changed.hash(), set.hash());
    assert_ne!(
        encode(choices[0].action, choices[0].features)
            .unwrap()
            .clipped,
        0
    );
    choices[0].features.common[7] = 2;
    assert_eq!(
        encode(choices[0].action, choices[0].features),
        Err(Error::Range)
    );
}
#[test]
fn wire_round_trips_every_family_and_rejects_trailing_bytes() {
    let actions = [
        Action::CpuWeight(8),
        Action::ControlSet(6),
        Action::SpawnTokens(4),
        Action::Cache {
            pages: 1024,
            batch: 32,
        },
        Action::Filesystem {
            readahead: 8,
            flush: 16,
        },
        Action::Ipc {
            budget: 64,
            batch: 8,
        },
        Action::IrqTarget(3),
        Action::SoftCoalesce(200),
        Action::ServiceBatch(8),
        Action::IoShare(750),
        Action::TxBatch(16),
        Action::NotifyBatch(8),
        Action::UnauthRate(32),
        Action::BackgroundBudget(400),
        Action::RecoveryRecipe(2),
        Action::ConsoleBatch(64),
        Action::OfferCpu(1000),
        Action::Placement(2),
    ];
    for action in actions {
        let mut bytes = [0; 32];
        let n = encode_payload(action, 31, &mut bytes).unwrap();
        assert_eq!(
            decode_payload(action.domain(), action.kind(), &bytes[..n]),
            Ok((action, 31))
        );
        assert_eq!(
            decode_payload(action.domain(), action.kind(), &bytes[..n + 1]),
            Err(Error::Format)
        );
    }
    let mut bytes = frame(&candidates(), 1, 0);
    assert_eq!(decode_plan(&bytes).unwrap().len(), 1);
    bytes.push(0);
    assert!(matches!(decode_plan(&bytes), Err(Error::Format)));
}
#[test]
fn exact_retry_survives_ttl_and_model_change_without_republishing() {
    let (mut registry, set, mut owner) = ready();
    let bytes = frame(&set, 1, 0);
    let first = registry
        .submit(publisher(), &bytes, &mut clock(), &mut owner)
        .unwrap();
    assert_eq!(first.version, 1);
    assert_eq!(first.state(), ExecutionState::Pending);
    registry
        .change_model(
            publisher(),
            ModelBinding {
                generation: 2,
                ..binding()
            },
        )
        .unwrap();
    let again = registry
        .submit(
            publisher(),
            &bytes,
            &mut Times {
                first: u64::MAX,
                second: u64::MAX,
                calls: 0,
            },
            &mut owner,
        )
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(owner.publishes, 1);
}
#[test]
fn prepare_cannot_publish_a_snapshot_that_expired_while_waiting() {
    let (mut registry, set, mut owner) = ready();
    let result = registry
        .submit(
            publisher(),
            &frame(&set, 1, 0),
            &mut Times {
                first: 11,
                second: WINDOW_NS + 11,
                calls: 0,
            },
            &mut owner,
        )
        .unwrap();
    assert_eq!(result.state(), ExecutionState::Failed(Error::Expired));
    assert_eq!(result.version, 0);
    assert_eq!((owner.prepares, owner.publishes, owner.cancels), (1, 0, 1));
    assert_eq!(registry.version(), 0);
}
#[test]
fn resource_generation_is_rechecked_after_prepare() {
    let (mut registry, set, mut owner) = ready();
    owner.move_during_prepare = true;
    let result = registry
        .submit(publisher(), &frame(&set, 1, 0), &mut clock(), &mut owner)
        .unwrap();
    assert_eq!(result.state(), ExecutionState::Failed(Error::Stale));
    assert_eq!(owner.publishes, 0);
    assert_eq!(owner.cancels, 1);
}
#[test]
fn duplicate_identity_cannot_change_payload_or_release_unknown() {
    let (mut registry, set, mut owner) = ready();
    let bytes = frame(&set, 1, 0);
    let r = registry
        .submit(publisher(), &bytes, &mut clock(), &mut owner)
        .unwrap();
    let apply = ApplyId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: 1,
        action_index: 0,
        target: set.target,
    };
    registry
        .reconcile(apply, 1, ExecutionState::Unknown)
        .unwrap();
    let old = registry
        .submit(publisher(), &bytes, &mut clock(), &mut owner)
        .unwrap();
    assert_eq!(old.state(), ExecutionState::Unknown);
    let mut conflicting = bytes.clone();
    conflicting[24] = 1;
    assert_eq!(
        registry.submit(publisher(), &conflicting, &mut clock(), &mut owner),
        Err(Error::Conflict)
    );
    assert_eq!(
        registry.reconcile(
            ApplyId {
                target: ObjectKey {
                    id: 1,
                    generation: 2
                },
                ..apply
            },
            r.version,
            ExecutionState::Applied
        ),
        Err(Error::Stale)
    );
    registry
        .reconcile(apply, 1, ExecutionState::Applied)
        .unwrap();
    assert_eq!(
        registry.reconcile(apply, 1, ExecutionState::Failed(Error::Io)),
        Err(Error::Conflict)
    );
}
#[test]
fn stamp_retry_does_not_renew_lease_and_old_versions_do_not_revive() {
    let old = PolicyStamp::new(2, 10, 20).unwrap();
    assert_eq!(old.installed_until_ns, 10 + POLICY_NS);
    assert_eq!(old.accepts(old, u64::MAX), Ok(()));
    assert!(!old.live(10 + POLICY_NS));
    assert_eq!(
        old.accepts(
            PolicyStamp {
                installed_until_ns: old.installed_until_ns + 1,
                ..old
            },
            20
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        old.accepts(PolicyStamp::new(1, 10, 20).unwrap(), 20),
        Err(Error::Stale)
    );
}
#[test]
fn pending_capacity_never_evicts_unknown_work() {
    let (mut registry, set, mut owner) = ready();
    for seq in 1..=64 {
        let result = registry
            .submit(
                publisher(),
                &frame(&set, seq, seq - 1),
                &mut clock(),
                &mut owner,
            )
            .unwrap();
        assert_eq!(result.version, seq);
    }
    assert_eq!(
        registry.submit(publisher(), &frame(&set, 65, 64), &mut clock(), &mut owner),
        Err(Error::Capacity)
    );
    assert_eq!(
        registry
            .query(
                publisher(),
                PlanId {
                    boot_epoch: 11,
                    controller_epoch: 9,
                    plan_seq: 1
                }
            )
            .unwrap()
            .state(),
        ExecutionState::Pending
    );
}
#[test]
fn arbitrary_dependency_edges_are_rejected() {
    assert!(dependency_allowed(3, 4));
    assert!(dependency_allowed(5, 10));
    assert!(!dependency_allowed(10, 3));
    assert!(!dependency_allowed(1, 13));
}

struct ScriptClock(std::collections::VecDeque<u64>);
impl Clock for ScriptClock {
    fn now_ns(&mut self) -> u64 {
        self.0.pop_front().expect("unexpected clock read")
    }
}

#[test]
fn publication_checks_time_after_revalidation() {
    let (mut registry, set, mut owner) = ready();
    let mut time = ScriptClock([11, 12, 13, 500_012, 500_013].into());
    let receipt = registry
        .submit(publisher(), &frame(&set, 1, 0), &mut time, &mut owner)
        .unwrap();
    assert_eq!(receipt.state(), ExecutionState::Failed(Error::Budget));
    assert_eq!(receipt.version, 0);
    assert_eq!((owner.prepares, owner.publishes, owner.cancels), (1, 0, 1));
    assert!(registry.optimization_stopped());
}

#[test]
fn installed_publication_survives_overrun_and_blocks_new_optimization() {
    let (mut registry, set, mut owner) = ready();
    let bytes = frame(&set, 1, 0);
    let mut time = ScriptClock([11, 12, 13, 14, 500_012].into());
    let receipt = registry
        .submit(publisher(), &bytes, &mut time, &mut owner)
        .unwrap();
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.state(), ExecutionState::Pending);
    assert_eq!((owner.publishes, owner.cancels), (1, 0));
    assert!(registry.optimization_stopped());
    let mut retry_clock = ScriptClock([u64::MAX].into());
    assert_eq!(
        registry.submit(publisher(), &bytes, &mut retry_clock, &mut owner),
        Ok(receipt)
    );
    let mut new_clock = ScriptClock([20].into());
    assert_eq!(
        registry.submit(publisher(), &frame(&set, 2, 1), &mut new_clock, &mut owner),
        Err(Error::Budget)
    );
    let apply = ApplyId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: 1,
        action_index: 0,
        target: set.target,
    };
    assert_eq!(
        registry
            .reconcile(apply, 1, ExecutionState::Applied)
            .unwrap()
            .state(),
        ExecutionState::Applied
    );
}

#[test]
fn protected_predecode_cost_is_inside_publication_budget() {
    let (mut registry, set, mut owner) = ready();
    let mut time = ScriptClock([500_012, 500_013].into());
    let receipt = registry
        .submit_bounded(publisher(), &frame(&set, 1, 0), 11, &mut time, &mut owner)
        .unwrap();
    assert_eq!(receipt.state(), ExecutionState::Failed(Error::Budget));
    assert_eq!(owner.prepares, 0);
    assert_eq!(owner.publishes, 0);
}
