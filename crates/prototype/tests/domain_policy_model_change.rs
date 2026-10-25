use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, WINDOW_NS},
    features::RawFeatures,
    policy::{
        Candidate, CandidateSet, Clock, ExecutionState, Executor, ModelBinding, Publisher,
        RegisteredSet, Registry, Snapshot,
    },
    policy_wire::{Decision, Envelope, MAX_PLAN_BYTES, Plan, PlanHeader, encode_plan},
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
fn original() -> ModelBinding {
    ModelBinding {
        generation: 1,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    }
}
fn candidates(model: ModelBinding) -> CandidateSet {
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: 10,
            ledger_generation: 1,
            core_generation: 1,
        },
        ObjectKey {
            id: 20,
            generation: 1,
        },
        model,
        &[Candidate {
            action: Action::CpuWeight(1),
            features: RawFeatures::default(),
        }],
        Some(Action::CpuWeight(1)),
    )
    .unwrap()
}
fn frame(set: &CandidateSet, sequence: u64, base: u64) -> Vec<u8> {
    let mut bytes = vec![0; MAX_PLAN_BYTES];
    let len = encode_plan(
        PlanHeader {
            plan_seq: sequence,
            base_plan_version: base,
            active_model_generation: set.model.generation,
            controller_epoch: 9,
            snapshot_seq: 1,
            active_until_local_ns: 10 + POLICY_NS,
        },
        &[Decision {
            action: Action::CpuWeight(1),
            candidate_index: 0,
            envelope: Envelope {
                controller_epoch: 9,
                decision_seq: sequence,
                snapshot_seq: 1,
                target: set.target,
                ledger_generation: 1,
                core_generation: 1,
                expires_local_ns: 10 + WINDOW_NS,
                model_hash: set.model.model_hash,
                candidate_set_hash: set.hash(),
            },
        }],
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}
struct Time(u64);
impl Clock for Time {
    fn now_ns(&mut self) -> u64 {
        self.0
    }
}
#[derive(Default)]
struct Owner {
    published: usize,
}
impl Executor for Owner {
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.published += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {}
}

#[test]
fn failed_or_abandoned_model_prepare_preserves_admission_and_active_identity() {
    let current = original();
    let next = ModelBinding {
        generation: 2,
        model_hash: [4; 32],
        ..current
    };
    let mut registry = Registry::new(11, publisher(), current).unwrap();
    let set = candidates(current);
    registry.register(publisher(), &set).unwrap();
    let wrong = Publisher {
        controller_epoch: 10,
        ..publisher()
    };
    assert_eq!(
        registry.prepare_model_change(wrong, next).err(),
        Some(Error::Auth)
    );
    assert_eq!(
        registry.prepare_model_change(publisher(), current).err(),
        Some(Error::Stale)
    );
    let prepared = registry.prepare_model_change(publisher(), next).unwrap();
    assert_eq!(prepared.binding(), next);
    drop(prepared);
    assert_eq!(registry.model(), current);
    assert_eq!(registry.version(), 0);
    let mut owner = Owner::default();
    let receipt = registry
        .submit(publisher(), &frame(&set, 1, 0), &mut Time(11), &mut owner)
        .unwrap();
    assert_eq!(receipt.version, 1);
    assert_eq!(owner.published, 1);
}

#[test]
fn infallible_model_commit_invalidates_unpublished_sets_but_retains_unknown_custody() {
    let current = original();
    let next = ModelBinding {
        generation: 2,
        model_hash: [4; 32],
        ..current
    };
    let mut registry = Registry::new(11, publisher(), current).unwrap();
    let set = candidates(current);
    registry.register(publisher(), &set).unwrap();
    let bytes = frame(&set, 1, 0);
    let mut owner = Owner::default();
    let receipt = registry
        .submit(publisher(), &bytes, &mut Time(11), &mut owner)
        .unwrap();
    let unknown = registry
        .reconcile(
            ApplyId {
                boot_epoch: 11,
                controller_epoch: 9,
                plan_seq: 1,
                action_index: 0,
                target: set.target,
            },
            receipt.version,
            ExecutionState::Unknown,
        )
        .unwrap();
    let prepared = registry.prepare_model_change(publisher(), next).unwrap();
    // This signature has no Result and performs no external callback. Other
    // protected owners can commit after every fallible prepare has succeeded.
    let actual: ModelBinding = prepared.commit();
    assert_eq!(actual, next);
    assert_eq!(registry.model(), next);
    assert_eq!(registry.version(), receipt.version);
    assert_eq!(registry.query_model(publisher(), receipt.id), Ok(current));
    assert_eq!(registry.query(publisher(), receipt.id), Ok(unknown));
    assert_eq!(
        registry.submit(publisher(), &bytes, &mut Time(u64::MAX), &mut owner),
        Ok(unknown)
    );
    assert_eq!(owner.published, 1);
    let rejected = registry
        .submit(publisher(), &frame(&set, 2, 1), &mut Time(12), &mut owner)
        .unwrap();
    assert_eq!(rejected.version, 0);
    assert_eq!(rejected.state(), ExecutionState::Failed(Error::Stale));
    let fresh = candidates(next);
    registry.register(publisher(), &fresh).unwrap();
    let published = registry
        .submit(publisher(), &frame(&fresh, 3, 1), &mut Time(12), &mut owner)
        .unwrap();
    assert_eq!(published.version, 2);
    assert_eq!(registry.query_model(publisher(), published.id), Ok(next));
}

#[test]
fn legacy_change_model_preserves_authorization_and_strictly_increasing_generation() {
    let current = original();
    let next = ModelBinding {
        generation: 8,
        model_hash: [4; 32],
        ..current
    };
    let mut legacy = Registry::new(11, publisher(), current).unwrap();
    let mut prepared = Registry::new(11, publisher(), current).unwrap();
    let wrong = Publisher {
        controller_epoch: 10,
        ..publisher()
    };
    assert_eq!(legacy.change_model(wrong, next), Err(Error::Auth));
    assert_eq!(
        prepared.prepare_model_change(wrong, next).err(),
        Some(Error::Auth)
    );
    assert_eq!(legacy.change_model(publisher(), current), Err(Error::Stale));
    assert_eq!(
        prepared.prepare_model_change(publisher(), current).err(),
        Some(Error::Stale)
    );
    legacy.change_model(publisher(), next).unwrap();
    assert_eq!(
        prepared
            .prepare_model_change(publisher(), next)
            .unwrap()
            .commit(),
        next
    );
    assert_eq!(legacy.model(), prepared.model());
    let returned = ModelBinding {
        generation: 9,
        ..current
    };
    legacy.change_model(publisher(), returned).unwrap();
    prepared
        .prepare_model_change(publisher(), returned)
        .unwrap()
        .commit();
    assert_eq!(legacy.model(), returned);
    assert_eq!(prepared.model(), returned);
    assert_eq!(legacy.change_model(publisher(), next), Err(Error::Stale));
    assert_eq!(
        prepared.prepare_model_change(publisher(), next).err(),
        Some(Error::Stale)
    );
}
