use cyxia_prototype::{
    domains::*, features::RawFeatures, learning::governance::CommitGate, policy::*, policy_wire::*,
};

fn publisher() -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: 9,
    }
}
fn model() -> ModelBinding {
    ModelBinding {
        generation: 1,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    }
}
#[derive(Clone, Copy)]
struct Fixed {
    snapshot: Snapshot,
    target: ObjectKey,
    model: ModelBinding,
    action: Action,
    hash: [u8; 32],
}
impl Fixed {
    fn register(self, registry: &mut Registry) -> Self {
        Self {
            hash: registry
                .register_baseline(
                    publisher(),
                    self.snapshot,
                    self.target,
                    self.model,
                    self.action,
                )
                .unwrap(),
            ..self
        }
    }
    fn decision(self, sequence: u64) -> Decision {
        Decision {
            action: self.action,
            candidate_index: 0,
            envelope: Envelope {
                controller_epoch: 9,
                decision_seq: sequence,
                snapshot_seq: self.snapshot.sequence,
                target: self.target,
                ledger_generation: self.snapshot.ledger_generation,
                core_generation: self.snapshot.core_generation,
                expires_local_ns: self.snapshot.taken_ns + WINDOW_NS,
                model_hash: self.model.model_hash,
                candidate_set_hash: self.hash,
            },
        }
    }
    fn frame(self, sequence: u64, base: u64) -> Vec<u8> {
        self.frame_actions(sequence, base, &[self.decision(sequence)])
    }
    fn frame_actions(self, sequence: u64, base: u64, actions: &[Decision]) -> Vec<u8> {
        let header = PlanHeader {
            plan_seq: sequence,
            base_plan_version: base,
            active_model_generation: self.model.generation,
            controller_epoch: 9,
            snapshot_seq: self.snapshot.sequence,
            active_until_local_ns: if self.action.one_shot() {
                0
            } else {
                self.snapshot.taken_ns + POLICY_NS
            },
        };
        let mut bytes = vec![0; MAX_PLAN_BYTES];
        let len = encode_plan(header, actions, &mut bytes).unwrap();
        bytes.truncate(len);
        bytes
    }
}
fn binding() -> Fixed {
    Fixed {
        snapshot: Snapshot {
            sequence: 2,
            taken_ns: 10,
            ledger_generation: 3,
            core_generation: 2,
        },
        target: ObjectKey {
            id: 12,
            generation: 1,
        },
        model: model(),
        action: Action::CpuWeight(2),
        hash: [0; 32],
    }
}
fn registry() -> Registry {
    Registry::new(11, publisher(), model()).unwrap()
}

struct Time(u64);
impl Clock for Time {
    fn now_ns(&mut self) -> u64 {
        self.0
    }
}
struct NoClock;
impl Clock for NoClock {
    fn now_ns(&mut self) -> u64 {
        panic!("a retained identity must not re-enter execution")
    }
}
struct ScriptClock(std::collections::VecDeque<u64>);
impl Clock for ScriptClock {
    fn now_ns(&mut self) -> u64 {
        self.0.pop_front().expect("unexpected clock read")
    }
}

#[derive(Default)]
struct Effects {
    checks: usize,
    prepares: usize,
    cancels: usize,
    publishes: usize,
}
struct BaselineOwner {
    fixed: Fixed,
    effects: Effects,
    authorizations: usize,
    model_authorizations: usize,
    busy: bool,
    generation_changes: bool,
    moved: bool,
    revoke_on: usize,
    seen: Option<RegisteredSet>,
}
impl BaselineOwner {
    fn new(fixed: Fixed) -> Self {
        Self {
            fixed,
            effects: Effects::default(),
            authorizations: 0,
            model_authorizations: 0,
            busy: false,
            generation_changes: false,
            moved: false,
            revoke_on: 0,
            seen: None,
        }
    }
}
impl Executor for BaselineOwner {
    fn authorize_baseline(
        &mut self,
        active: ModelBinding,
        set: &RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        self.authorizations += 1;
        self.seen = Some(*set);
        if self.authorizations == self.revoke_on
            || active != self.fixed.model
            || set.model != active
            || set.snapshot != self.fixed.snapshot
            || set.target != self.fixed.target
            || set.baseline_action() != Some(self.fixed.action)
            || set.action(1).is_some()
            || set.canary_permit().is_some()
        {
            return Err(Error::Auth);
        }
        Ok(())
    }
    fn authorize_model(
        &mut self,
        active: ModelBinding,
        set: &RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        self.model_authorizations += 1;
        if set.model == active {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    fn check(&mut self, decision: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        self.effects.checks += 1;
        if self.busy {
            return Err(Error::Busy);
        }
        if self.moved
            || decision.envelope.ledger_generation != self.fixed.snapshot.ledger_generation
            || decision.envelope.core_generation != self.fixed.snapshot.core_generation
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.effects.prepares += 1;
        self.moved = self.generation_changes;
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
        self.effects.publishes += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.effects.cancels += 1;
    }
}
#[derive(Default)]
struct ModelAuthorityOnly(Effects);
impl Executor for ModelAuthorityOnly {
    // Deliberately permissive model authority still cannot confer baseline
    // authority. This exercises Registry's purpose gate, not a test wrapper.
    fn authorize_model(&mut self, _: ModelBinding, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        self.0.checks += 1;
        Ok(())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.0.prepares += 1;
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.0.publishes += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.0.cancels += 1;
    }
}

#[test]
fn fixed_baseline_has_no_fabricated_features_and_cannot_be_published_by_model_authority() {
    let mut registry = registry();
    let fixed = binding().register(&mut registry);
    let missing = Candidate {
        action: fixed.action,
        features: RawFeatures {
            domain_present: 0,
            ..RawFeatures::default()
        },
    };
    assert!(
        matches!(
            CandidateSet::new(
                fixed.snapshot,
                fixed.target,
                fixed.model,
                &[missing],
                Some(fixed.action)
            ),
            Err(Error::NotReady)
        ),
        "ordinary AI feature requirements remain strict"
    );
    let scored = CandidateSet::new(
        fixed.snapshot,
        fixed.target,
        fixed.model,
        &[Candidate {
            action: fixed.action,
            features: RawFeatures::default(),
        }],
        Some(fixed.action),
    )
    .unwrap();
    assert_ne!(
        fixed.hash,
        scored.hash(),
        "a fixed registration cannot alias a scored candidate set"
    );
    assert_eq!(registry.registered_action(fixed.hash, 0), Ok(fixed.action));
    assert_eq!(registry.registered_action(fixed.hash, 1), Err(Error::Range));
    let mut ordinary = ModelAuthorityOnly::default();
    let failed = registry
        .submit_job(
            publisher(),
            &fixed.frame(2, 0),
            11,
            50_000_010,
            &mut Time(11),
            &mut ordinary,
        )
        .unwrap();
    assert_eq!(
        (failed.version, failed.state()),
        (0, ExecutionState::Failed(Error::Auth))
    );
    assert_eq!(
        (ordinary.0.checks, ordinary.0.prepares, ordinary.0.publishes),
        (0, 0, 0)
    );
    let mut owner = BaselineOwner::new(fixed);
    let published = registry
        .submit_job(
            publisher(),
            &fixed.frame(3, 0),
            12,
            50_000_010,
            &mut Time(12),
            &mut owner,
        )
        .unwrap();
    assert_eq!(
        (published.version, published.state()),
        (1, ExecutionState::Pending)
    );
    assert_eq!((owner.authorizations, owner.model_authorizations), (3, 3));
    assert_eq!(
        (
            owner.effects.checks,
            owner.effects.prepares,
            owner.effects.publishes
        ),
        (2, 1, 1)
    );
    let registered = owner.seen.unwrap();
    let gate = CommitGate::new(11, model()).unwrap();
    assert_eq!(
        registered.authorize_with_gate(model(), &gate, 12),
        Err(Error::Auth),
        "the shared Active/Canary gate cannot authorize a fixed baseline"
    );
}

#[test]
fn baseline_hash_binds_original_snapshot_model_target_action_and_registry_authority() {
    let original = binding();
    let mut registry = registry();
    let fixed = original.register(&mut registry);
    assert_eq!(original.register(&mut registry).hash, fixed.hash);
    let variants = [
        Fixed {
            snapshot: Snapshot {
                sequence: 3,
                ..original.snapshot
            },
            ..original
        },
        Fixed {
            snapshot: Snapshot {
                taken_ns: 11,
                ..original.snapshot
            },
            ..original
        },
        Fixed {
            snapshot: Snapshot {
                ledger_generation: 4,
                ..original.snapshot
            },
            ..original
        },
        Fixed {
            snapshot: Snapshot {
                core_generation: 3,
                ..original.snapshot
            },
            ..original
        },
        Fixed {
            target: ObjectKey {
                id: 13,
                ..original.target
            },
            ..original
        },
        Fixed {
            target: ObjectKey {
                generation: 2,
                ..original.target
            },
            ..original
        },
        Fixed {
            action: Action::CpuWeight(4),
            ..original
        },
    ];
    let hashes: Vec<_> = variants
        .into_iter()
        .map(|v| v.register(&mut registry).hash)
        .collect();
    assert!(hashes.iter().all(|h| *h != fixed.hash));
    for (i, hash) in hashes.iter().enumerate() {
        assert!(!hashes[..i].contains(hash));
    }
    for next in [
        ModelBinding {
            generation: 2,
            ..model()
        },
        ModelBinding {
            model_hash: [7; 32],
            ..model()
        },
        ModelBinding {
            schema_hash: [8; 32],
            ..model()
        },
    ] {
        assert_eq!(
            registry.register_baseline(
                publisher(),
                original.snapshot,
                original.target,
                next,
                original.action
            ),
            Err(Error::Stale)
        );
        let mut changed = Registry::new(11, publisher(), next).unwrap();
        assert_ne!(
            Fixed {
                model: next,
                ..original
            }
            .register(&mut changed)
            .hash,
            fixed.hash
        );
    }
    let mut rebooted = Registry::new(12, publisher(), model()).unwrap();
    assert_ne!(original.register(&mut rebooted).hash, fixed.hash);
    assert_eq!(
        registry.register_baseline(
            Publisher {
                controller_epoch: 10,
                ..publisher()
            },
            original.snapshot,
            original.target,
            model(),
            original.action
        ),
        Err(Error::Auth)
    );
    assert_eq!(
        registry.register_baseline(
            publisher(),
            Snapshot {
                sequence: 0,
                ..original.snapshot
            },
            original.target,
            model(),
            original.action
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        registry.register_baseline(
            publisher(),
            original.snapshot,
            ObjectKey {
                generation: 0,
                ..original.target
            },
            model(),
            original.action
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        registry.register_baseline(
            publisher(),
            original.snapshot,
            original.target,
            model(),
            Action::OfferCpu(0)
        ),
        Err(Error::Range)
    );
}

#[test]
fn failed_baseline_identity_is_terminal_and_new_attempt_keeps_original_snapshot_and_deadline() {
    let mut registry = registry();
    let fixed = binding().register(&mut registry);
    let mut owner = BaselineOwner::new(fixed);
    owner.busy = true;
    let bytes = fixed.frame(2, 0);
    let failed = registry
        .submit_job(
            publisher(),
            &bytes,
            11,
            50_000_010,
            &mut Time(11),
            &mut owner,
        )
        .unwrap();
    assert_eq!(
        (failed.version, failed.state()),
        (0, ExecutionState::Failed(Error::Busy))
    );
    owner.busy = false;
    assert_eq!(
        registry.submit_job(
            publisher(),
            &bytes,
            u64::MAX,
            u64::MAX,
            &mut NoClock,
            &mut owner
        ),
        Ok(failed)
    );
    assert_eq!(
        (
            owner.authorizations,
            owner.effects.checks,
            owner.effects.publishes
        ),
        (1, 1, 0)
    );
    let changed = Fixed {
        snapshot: Snapshot {
            taken_ns: 12,
            ..fixed.snapshot
        },
        ..fixed
    }
    .register(&mut registry);
    assert_eq!(
        registry.submit_job(
            publisher(),
            &changed.frame(2, 0),
            12,
            50_000_010,
            &mut NoClock,
            &mut owner
        ),
        Err(Error::Conflict)
    );
    let published = registry
        .submit_job(
            publisher(),
            &fixed.frame(3, 0),
            12,
            50_000_010,
            &mut Time(12),
            &mut owner,
        )
        .unwrap();
    assert_eq!((published.version, owner.effects.publishes), (1, 1));
    let late = registry
        .submit_job(
            publisher(),
            &fixed.frame(4, 1),
            50_000_011,
            50_000_010,
            &mut Time(50_000_011),
            &mut owner,
        )
        .unwrap();
    assert_eq!(
        (late.version, late.state()),
        (0, ExecutionState::Failed(Error::Expired))
    );
    assert_eq!(
        owner.effects.publishes, 1,
        "a fresh plan sequence cannot renew the original deadline"
    );
    assert_eq!(registry.query(publisher(), failed.id), Ok(failed));
}

#[test]
fn fixed_publication_rechecks_live_owner_generation_and_baseline_authority_before_commit() {
    for revoked in [false, true] {
        let mut registry = registry();
        let fixed = binding().register(&mut registry);
        let mut owner = BaselineOwner::new(fixed);
        owner.generation_changes = !revoked;
        owner.revoke_on = if revoked { 3 } else { 0 };
        let failed = registry
            .submit_job(
                publisher(),
                &fixed.frame(2, 0),
                11,
                50_000_010,
                &mut Time(11),
                &mut owner,
            )
            .unwrap();
        assert_eq!(
            (failed.version, failed.state()),
            (
                0,
                ExecutionState::Failed(if revoked { Error::Auth } else { Error::Stale })
            )
        );
        assert_eq!(
            (
                owner.effects.prepares,
                owner.effects.cancels,
                owner.effects.publishes
            ),
            (1, 1, 0)
        );
        assert_eq!(registry.version(), 0);
    }
}

#[test]
fn fixed_publication_preserves_wall_deadline_and_cpu_publication_cap() {
    for (times, error) in [
        ([11, 12, 50_000_011, 50_000_012], Error::Expired),
        (
            [
                11,
                12,
                PUBLICATION_BUDGET_NS + 12,
                PUBLICATION_BUDGET_NS + 13,
            ],
            Error::Budget,
        ),
    ] {
        let mut registry = registry();
        let fixed = binding().register(&mut registry);
        let mut owner = BaselineOwner::new(fixed);
        let failed = registry
            .submit_job(
                publisher(),
                &fixed.frame(2, 0),
                11,
                50_000_010,
                &mut ScriptClock(times.into()),
                &mut owner,
            )
            .unwrap();
        assert_eq!(
            (failed.version, failed.state()),
            (0, ExecutionState::Failed(error))
        );
        assert_eq!(
            (
                owner.effects.prepares,
                owner.effects.cancels,
                owner.effects.publishes
            ),
            (1, 1, 0)
        );
    }
}

#[test]
fn a_fixed_registration_never_authorizes_a_mixed_plan_or_changed_action() {
    let mut registry = registry();
    let fixed = binding().register(&mut registry);
    let other = Fixed {
        target: ObjectKey {
            id: 13,
            ..fixed.target
        },
        ..fixed
    }
    .register(&mut registry);
    let mut owner = BaselineOwner::new(fixed);
    let mixed = fixed.frame_actions(2, 0, &[fixed.decision(2), other.decision(3)]);
    let failed = registry
        .submit_job(
            publisher(),
            &mixed,
            11,
            50_000_010,
            &mut Time(11),
            &mut owner,
        )
        .unwrap();
    assert_eq!(
        (failed.version, failed.state()),
        (0, ExecutionState::Failed(Error::Auth))
    );
    assert_eq!(
        (
            owner.authorizations,
            owner.effects.prepares,
            owner.effects.publishes
        ),
        (0, 0, 0)
    );
    let mut changed = fixed.decision(4);
    changed.action = Action::CpuWeight(4);
    let failed = registry
        .submit_job(
            publisher(),
            &fixed.frame_actions(4, 0, &[changed]),
            12,
            50_000_010,
            &mut Time(12),
            &mut owner,
        )
        .unwrap();
    assert_eq!(
        (failed.version, failed.state()),
        (0, ExecutionState::Failed(Error::Conflict))
    );
    assert_eq!((owner.effects.prepares, owner.effects.publishes), (0, 0));
}
