//! Synthetic protected-owner fixtures test the publication protocol. They are
//! not native CPU evidence or an accepted 144/72 experiment dataset.
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::{
    domains::{Action, ApplyId, Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS},
    features::RawFeatures,
    learning::{
        Error as LearningError,
        governance::{
            CanaryPermit, CanaryReceipt, CommitGate, ControlAuthority, ExtraBudget, Governance,
            GovernanceAuthority, RestorationReceipt, RestorationRequest, Role, ScoreProof, Stage,
            TargetRegistration, WorkReceipt,
        },
        reward::WorkRequest,
    },
    policy::{
        Candidate, CandidateSet, Clock, ExecutionState, Executor, ModelBinding, PlanId,
        PlanReceipt, Publisher, RegisteredSet, Registry, Snapshot, TERMINAL_HISTORY,
    },
    policy_wire::{Decision, Envelope, MAX_PLAN_BYTES, Plan, PlanHeader, encode_plan},
};
use std::collections::VecDeque;

const START: u64 = 10 * WINDOW_NS;
fn console() -> ObjectKey {
    ObjectKey {
        id: 15,
        generation: 1,
    }
}
fn publisher() -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: 9,
    }
}
fn plan_id(sequence: u64) -> PlanId {
    PlanId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: sequence,
    }
}
fn apply_id(sequence: u64, target: ObjectKey) -> ApplyId {
    ApplyId {
        boot_epoch: 11,
        controller_epoch: 9,
        plan_seq: sequence,
        action_index: 0,
        target,
    }
}

struct Owners;
impl ControlAuthority for Owners {
    fn authorize(
        &self,
        _: Role,
        cpu: u16,
        generation: u64,
        workspace: u32,
    ) -> Result<(), LearningError> {
        if cpu == 1 && generation == 1 && workspace <= 1024 * 1024 {
            Ok(())
        } else {
            Err(LearningError::State)
        }
    }
}
impl GovernanceAuthority for Owners {
    fn registered_noncritical_console(
        &self,
        target: TargetRegistration,
    ) -> Result<(), LearningError> {
        if target.key == console() && target.baseline == Action::ConsoleBatch(1) {
            Ok(())
        } else {
            Err(LearningError::Evidence)
        }
    }
    fn legal_console(
        &self,
        target: ObjectKey,
        action: Action,
        _: u64,
    ) -> Result<(), LearningError> {
        if target == console() && matches!(action, Action::ConsoleBatch(1 | 8 | 32 | 64)) {
            Ok(())
        } else {
            Err(LearningError::Safety)
        }
    }
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), LearningError> {
        if receipt.evidence_hash == [7; 32] {
            Ok(())
        } else {
            Err(LearningError::Evidence)
        }
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        digest: [u8; 32],
    ) -> Result<(), LearningError> {
        if digest != [0; 32] {
            Ok(())
        } else {
            Err(LearningError::Evidence)
        }
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), LearningError> {
        Ok(())
    }
    fn verify_restoration(
        &self,
        request: RestorationRequest,
        receipt: &RestorationReceipt,
    ) -> Result<(), LearningError> {
        if receipt.boot_epoch == request.boot_epoch
            && receipt.restoration_id == request.id
            && receipt.target == request.target.key
            && receipt.actual == request.target.baseline
            && receipt.evidence_hash == [8; 32]
        {
            Ok(())
        } else {
            Err(LearningError::Evidence)
        }
    }
}

fn candidates(
    model: ModelBinding,
    now: u64,
    target: ObjectKey,
    actions: &[Action],
) -> CandidateSet {
    let choices: Vec<_> = actions
        .iter()
        .map(|action| Candidate {
            action: *action,
            features: RawFeatures {
                control_capacity: Some(1000),
                ..RawFeatures::default()
            },
        })
        .collect();
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: now,
            ledger_generation: 1,
            core_generation: 1,
        },
        target,
        model,
        &choices,
        Some(actions[0]),
    )
    .unwrap()
}
fn canary_model(original: ModelBinding, permit: CanaryPermit) -> ModelBinding {
    ModelBinding {
        model_hash: permit.candidate_hash,
        ..original
    }
}
fn canary_set(original: ModelBinding, permit: CanaryPermit, now: u64) -> CandidateSet {
    // One legal candidate makes the protected score's selected action explicit.
    candidates(
        canary_model(original, permit),
        now,
        console(),
        &[Action::ConsoleBatch(8)],
    )
}
fn with_canary(
    run: impl FnOnce(
        &mut Governance<'_, '_>,
        &mut CommitGate,
        &mut ExtraBudget,
        CanaryPermit,
        ModelBinding,
    ),
) {
    support::with_candidate(|candidate, old| {
        let original = ModelBinding {
            generation: 7,
            model_hash: candidate.parent_hash(),
            schema_hash: support::schemas().feature.hash,
        };
        let mut gate = CommitGate::new(11, original).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        for window in 0..10 {
            let families = if window == 0 {
                &support::FAMILIES[..]
            } else {
                &support::FAMILIES[..1]
            };
            for (index, family) in families.iter().enumerate() {
                let now = window * WINDOW_NS + index as u64 * 10_000;
                let credit = budget
                    .reserve(Role::Shadow, 1, 1, 1024 * 1024, now, 10_000, &Owners)
                    .unwrap();
                let set = candidates(original, now, console(), &support::choices(*family));
                let proof = governance.score_shadow(&set, &credit).unwrap();
                let cost = budget.settle(credit, 5_000, now + 5_000).unwrap();
                governance.record_shadow(proof, cost).unwrap();
            }
            governance
                .close_shadow_window((window + 1) * WINDOW_NS)
                .unwrap();
        }
        assert_eq!(governance.stage(), Stage::Ready);
        let permit = governance
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                START,
                &Owners,
            )
            .unwrap();
        run(&mut governance, &mut gate, &mut budget, permit, original);
    });
}
fn decision(set: &CandidateSet, sequence: u64) -> Decision {
    Decision {
        action: set.get(0).unwrap().action,
        candidate_index: 0,
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
    }
}
fn frame(set: &CandidateSet, sequence: u64, base: u64) -> Vec<u8> {
    frame_with(set, sequence, base, &[decision(set, sequence)])
}
fn frame_with(set: &CandidateSet, sequence: u64, base: u64, decisions: &[Decision]) -> Vec<u8> {
    let mut bytes = vec![0; MAX_PLAN_BYTES];
    let len = encode_plan(
        PlanHeader {
            plan_seq: sequence,
            base_plan_version: base,
            active_model_generation: set.model.generation,
            controller_epoch: 9,
            snapshot_seq: set.snapshot.sequence,
            active_until_local_ns: set.snapshot.taken_ns + POLICY_NS,
        },
        decisions,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(len);
    bytes
}
struct FixedClock(u64);
impl Clock for FixedClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        let wall_ns = { self.0 };
        publication_time(wall_ns)
    }
}
struct ScriptClock(VecDeque<u64>);
impl Clock for ScriptClock {
    fn read(&mut self) -> cyxia_prototype::policy::PublicationTime {
        let wall_ns = { self.0.pop_front().expect("unexpected clock read") };
        publication_time(wall_ns)
    }
}
#[derive(Default)]
struct OrdinaryOwner {
    prepares: usize,
    publishes: usize,
    cancels: usize,
}
impl Executor for OrdinaryOwner {
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.prepares += 1;
        Ok(())
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn publish(&mut self, _: &Plan, _: u64, _: u64) -> Result<(), Error> {
        self.publishes += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.cancels += 1;
    }
}
fn learning_error(error: LearningError) -> Error {
    match error {
        LearningError::Unknown => Error::NotReady,
        LearningError::Budget => Error::Budget,
        LearningError::Deadline => Error::Expired,
        LearningError::Stale | LearningError::State => Error::Stale,
        LearningError::Conflict => Error::Conflict,
        _ => Error::Auth,
    }
}
struct GatedOwner<'a, 'data, 'model> {
    gate: &'a mut CommitGate,
    governance: &'a mut Governance<'data, 'model>,
    proof: Option<(ScoreProof, WorkReceipt)>,
    prepares: usize,
    publishes: usize,
    cancels: usize,
    is_canary: bool,
    fail_prepare: bool,
    revoke_in_revalidate: bool,
    freeze_in_revalidate: bool,
}
impl<'a, 'data, 'model> GatedOwner<'a, 'data, 'model> {
    fn new(gate: &'a mut CommitGate, governance: &'a mut Governance<'data, 'model>) -> Self {
        Self {
            gate,
            governance,
            proof: None,
            prepares: 0,
            publishes: 0,
            cancels: 0,
            is_canary: false,
            fail_prepare: false,
            revoke_in_revalidate: false,
            freeze_in_revalidate: false,
        }
    }
    fn score(&mut self, set: &CandidateSet, budget: &mut ExtraBudget, now: u64) {
        let credit = budget
            .reserve(Role::Canary, 1, 1, 1024 * 1024, now, 10_000, &Owners)
            .unwrap();
        let proof = self.governance.score_canary(set, &credit).unwrap();
        let cost = budget.settle(credit, 1_000, now + 1_000).unwrap();
        self.proof = Some((proof, cost));
    }
}
impl Executor for GatedOwner<'_, '_, '_> {
    fn authorize_model(
        &mut self,
        active: ModelBinding,
        set: &RegisteredSet,
        now: u64,
    ) -> Result<(), Error> {
        set.authorize_with_gate(active, self.gate, now)?;
        self.is_canary = set.canary_permit().is_some();
        Ok(())
    }
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        Ok(())
    }
    fn prepare(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        self.prepares += 1;
        if self.fail_prepare {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    fn revalidate(&mut self, _: &Plan, _: u64) -> Result<(), Error> {
        if self.revoke_in_revalidate {
            self.governance.abort(self.gate, LearningError::Safety);
        }
        if self.freeze_in_revalidate {
            self.governance.freeze().map_err(learning_error)?;
        }
        Ok(())
    }
    fn publish(&mut self, plan: &Plan, version: u64, now: u64) -> Result<(), Error> {
        if self.is_canary {
            let (proof, cost) = self.proof.take().ok_or(Error::NotReady)?;
            let action = plan.action(0).unwrap();
            proof
                .verify_selection(
                    action.envelope.candidate_set_hash,
                    ModelBinding {
                        model_hash: action.envelope.model_hash,
                        ..self.gate.active()
                    },
                    action.envelope.target,
                    plan.header.active_until_local_ns - POLICY_NS,
                    action.candidate_index,
                    action.action,
                )
                .map_err(learning_error)?;
            let stamp = PolicyStamp::for_action(
                action.action,
                version,
                plan.header.active_until_local_ns - POLICY_NS,
                now,
            )?;
            self.governance
                .publish(
                    self.gate,
                    now,
                    proof,
                    cost,
                    apply_id(plan.header.plan_seq, action.envelope.target),
                    stamp,
                    &Owners,
                )
                .map_err(learning_error)?;
        }
        self.publishes += 1;
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &Plan) {
        self.cancels += 1;
    }
}
fn failed(receipt: PlanReceipt, error: Error) {
    assert_eq!(receipt.version, 0);
    assert_eq!(receipt.state(), ExecutionState::Failed(error));
}

#[test]
fn candidate_cannot_enter_ordinary_registration_or_default_executor() {
    with_canary(|governance, gate, _, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        let unscoped = set.hash();
        assert_eq!(registry.register(publisher(), &set), Err(Error::Stale));
        let mut forged = permit;
        forged.id += 1;
        assert_eq!(
            registry.register_canary(publisher(), &mut set, forged, gate, START),
            Err(Error::Stale)
        );
        assert_eq!(set.hash(), unscoped);
        assert_eq!(set.canary_permit(), None);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        assert_ne!(set.hash(), unscoped);
        assert_eq!(set.canary_permit(), Some(permit));
        assert_eq!(set.hash_for_canary(permit), Ok(set.hash()));
        assert_eq!(set.verify_integrity(), Ok(()));
        let mut altered_binding = set;
        altered_binding.target.generation += 1;
        assert_eq!(altered_binding.verify_integrity(), Err(Error::Conflict));
        assert_eq!(registry.registered_action(unscoped, 0), Err(Error::Stale));
        assert_eq!(
            registry.registered_action(set.hash(), 0),
            Ok(set.get(0).unwrap().action)
        );
        assert_eq!(registry.register(publisher(), &set), Err(Error::Stale));
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let mut ordinary = OrdinaryOwner::default();
        let result = registry
            .submit(
                publisher(),
                &frame(&set, 1, 0),
                &mut FixedClock(START),
                &mut ordinary,
            )
            .unwrap();
        failed(result, Error::Stale);
        assert_eq!((ordinary.prepares, ordinary.publishes), (0, 0));
        assert_eq!(
            registry.query_model(publisher(), result.id),
            Err(Error::NotReady)
        );
        assert_eq!(registry.model(), original);
        assert_eq!(gate.active(), original);
        assert_eq!(governance.submissions().count(), 0);
    });
}

#[test]
fn permit_registration_binds_model_schema_object_generation_domain_and_time() {
    with_canary(|_, gate, _, permit, original| {
        let candidate = canary_model(original, permit);
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let cases = [
            (
                ModelBinding {
                    generation: original.generation + 1,
                    ..candidate
                },
                console(),
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                ModelBinding {
                    schema_hash: [91; 32],
                    ..candidate
                },
                console(),
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                ModelBinding {
                    model_hash: [92; 32],
                    ..candidate
                },
                console(),
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                original,
                console(),
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                candidate,
                ObjectKey {
                    id: 16,
                    ..console()
                },
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                candidate,
                ObjectKey {
                    generation: 2,
                    ..console()
                },
                START,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                candidate,
                console(),
                START,
                Action::CpuWeight(1),
                START,
                Error::Auth,
            ),
            (
                candidate,
                console(),
                START - 1,
                Action::ConsoleBatch(8),
                START,
                Error::Stale,
            ),
            (
                candidate,
                console(),
                START,
                Action::ConsoleBatch(8),
                START - 1,
                Error::Range,
            ),
            (
                candidate,
                console(),
                permit.expires_ns,
                Action::ConsoleBatch(8),
                permit.expires_ns,
                Error::Stale,
            ),
            (
                candidate,
                console(),
                START,
                Action::ConsoleBatch(8),
                START + WINDOW_NS + 1,
                Error::Expired,
            ),
        ];
        for (model, target, snapshot, action, now, error) in cases {
            let mut set = candidates(model, snapshot, target, &[action]);
            let hash = set.hash();
            assert_eq!(
                registry.register_canary(publisher(), &mut set, permit, gate, now),
                Err(error)
            );
            assert_eq!(set.hash(), hash);
            assert_eq!(set.canary_permit(), None);
        }
        for altered in [
            CanaryPermit {
                candidate_hash: [92; 32],
                ..permit
            },
            CanaryPermit {
                target: ObjectKey {
                    generation: 2,
                    ..console()
                },
                ..permit
            },
            CanaryPermit {
                active_generation: original.generation + 1,
                ..permit
            },
            CanaryPermit {
                start_ns: START - 1,
                ..permit
            },
            CanaryPermit {
                expires_ns: permit.expires_ns + 1,
                ..permit
            },
            CanaryPermit {
                windows: permit.windows + 1,
                ..permit
            },
            CanaryPermit {
                quota: permit.quota - 1,
                ..permit
            },
        ] {
            let mut set = canary_set(original, permit, START);
            assert_eq!(
                registry.register_canary(publisher(), &mut set, altered, gate, START),
                Err(Error::Stale)
            );
        }
    });
}

#[test]
fn extending_permit_changes_canonical_hash_and_cannot_rebind_old_candidate() {
    with_canary(|governance, gate, _, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut old = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut old, permit, gate, START)
            .unwrap();
        let old_hash = old.hash();
        governance.extend(gate, START + 1, 200, &Owners).unwrap();
        let extended = gate.permit().unwrap();
        assert_ne!(permit, extended);
        assert_eq!(
            registry.register_canary(publisher(), &mut old, extended, gate, START + 1),
            Err(Error::Stale)
        );
        assert_eq!(old.hash(), old_hash);
        let mut new = canary_set(original, extended, START);
        registry
            .register_canary(publisher(), &mut new, extended, gate, START + 1)
            .unwrap();
        assert_ne!(old.hash(), new.hash());
        let mut owner = GatedOwner::new(gate, governance);
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&old, 1, 0),
                    &mut FixedClock(START + 1),
                    &mut owner,
                )
                .unwrap(),
            Error::Stale,
        );
        assert_eq!(owner.prepares, 0);
        assert_eq!(owner.governance.submissions().count(), 0);
    });
}

#[test]
fn final_commit_clock_rejects_permit_that_expires_during_authorization() {
    with_canary(|governance, gate, _, permit, original| {
        let end = permit.expires_ns;
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, end - 100_000);
        registry
            .register_canary(publisher(), &mut set, permit, gate, end - 100_000)
            .unwrap();
        let mut owner = GatedOwner::new(gate, governance);
        let mut clock = ScriptClock([end - 4, end - 3, end - 2, end - 1, end, end + 1].into());
        failed(
            registry
                .submit(publisher(), &frame(&set, 1, 0), &mut clock, &mut owner)
                .unwrap(),
            Error::Stale,
        );
        assert!(clock.0.is_empty());
        assert_eq!((owner.prepares, owner.publishes, owner.cancels), (1, 0, 1));
        assert_eq!(owner.governance.submissions().count(), 0);
    });
}

#[test]
fn revocation_after_prepare_rejects_canary_and_excludes_active_until_restored() {
    with_canary(|governance, gate, _, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let active = candidates(original, START, console(), &[Action::ConsoleBatch(1)]);
        registry.register(publisher(), &active).unwrap();
        let unrelated = candidates(
            original,
            START,
            ObjectKey {
                id: 77,
                generation: 1,
            },
            &[Action::CpuWeight(1)],
        );
        registry.register(publisher(), &unrelated).unwrap();
        let mut owner = GatedOwner::new(gate, governance);
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&active, 1, 0),
                    &mut FixedClock(START),
                    &mut owner,
                )
                .unwrap(),
            Error::Busy,
        );
        owner.revoke_in_revalidate = true;
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 2, 0),
                    &mut FixedClock(START),
                    &mut owner,
                )
                .unwrap(),
            Error::Stale,
        );
        owner.revoke_in_revalidate = false;
        assert_eq!(owner.governance.stage(), Stage::Restoring);
        assert_eq!(owner.gate.permit(), None);
        assert_eq!(owner.gate.restoration_pending(), Some(console()));
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&active, 3, 0),
                    &mut FixedClock(START),
                    &mut owner,
                )
                .unwrap(),
            Error::Busy,
        );
        let accepted = registry
            .submit(
                publisher(),
                &frame(&unrelated, 4, 0),
                &mut FixedClock(START),
                &mut owner,
            )
            .unwrap();
        assert_eq!(accepted.version, 1);
        assert_eq!(registry.query_model(publisher(), accepted.id), Ok(original));
        assert_eq!(owner.governance.submissions().count(), 0);
    });
}

#[test]
fn frozen_governance_cannot_publish_with_a_still_matching_permit() {
    with_canary(|governance, gate, budget, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let mut owner = GatedOwner::new(gate, governance);
        owner.score(&set, budget, START);
        owner.freeze_in_revalidate = true;
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 1, 0),
                    &mut FixedClock(START + 2_000),
                    &mut owner,
                )
                .unwrap(),
            Error::Stale,
        );
        assert_eq!(owner.gate.permit(), Some(permit));
        assert_eq!(owner.governance.stage(), Stage::Frozen);
        assert_eq!(owner.governance.submissions().count(), 0);
        assert_eq!((owner.prepares, owner.publishes, owner.cancels), (1, 0, 1));
    });
}

#[test]
fn canary_multi_action_plan_is_rejected_before_any_reservation() {
    with_canary(|governance, gate, _, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let first = decision(&set, 1);
        let mut second = decision(&set, 2);
        second.action = Action::CpuWeight(1);
        let bytes = frame_with(&set, 1, 0, &[first, second]);
        let mut owner = GatedOwner::new(gate, governance);
        failed(
            registry
                .submit(publisher(), &bytes, &mut FixedClock(START), &mut owner)
                .unwrap(),
            Error::Auth,
        );
        assert_eq!((owner.prepares, owner.publishes), (0, 0));
        assert_eq!(owner.governance.submissions().count(), 0);
    });
}

#[test]
fn quota_pending_and_original_model_are_recorded_only_at_real_publication() {
    with_canary(|governance, gate, budget, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let mut owner = GatedOwner::new(gate, governance);
        owner.score(&set, budget, START);
        owner.fail_prepare = true;
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 1, 0),
                    &mut FixedClock(START + 2_000),
                    &mut owner,
                )
                .unwrap(),
            Error::Busy,
        );
        assert!(owner.proof.is_some());
        assert_eq!(owner.governance.submissions().count(), 0);
        owner.fail_prepare = false;
        let bytes = frame(&set, 2, 0);
        let accepted = registry
            .submit(
                publisher(),
                &bytes,
                &mut FixedClock(START + 3_000),
                &mut owner,
            )
            .unwrap();
        assert_eq!(accepted.version, 1);
        assert_eq!(accepted.state(), ExecutionState::Pending);
        assert_eq!(registry.model(), original);
        assert_eq!(
            registry.query_model(publisher(), accepted.id),
            Ok(canary_model(original, permit))
        );
        let submission = owner.governance.submissions().next().unwrap();
        assert_eq!(submission.apply, apply_id(2, console()));
        assert_eq!(submission.state, ExecutionState::Pending);
        assert_eq!(submission.action, Action::ConsoleBatch(8));
        assert_eq!(owner.governance.submissions().count(), 1);
        // The Registry keeps the accepted identity before looking up the old
        // permit or invoking an executor a second time.
        assert_eq!(
            registry.submit(
                publisher(),
                &bytes,
                &mut FixedClock(permit.expires_ns + 1),
                &mut owner
            ),
            Ok(accepted)
        );
        assert_eq!(owner.publishes, 1);
        owner.score(&set, budget, START + 4_000);
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 3, 1),
                    &mut FixedClock(START + 6_000),
                    &mut owner,
                )
                .unwrap(),
            Error::NotReady,
        );
        assert_eq!(owner.governance.submissions().count(), 1);
        owner
            .governance
            .reconcile(
                owner.gate,
                CanaryReceipt {
                    apply: submission.apply,
                    plan_version: submission.stamp.version,
                    executor_generation: 1,
                    model: submission.model,
                    state: ExecutionState::Applied,
                    actual: Some(submission.action),
                    started_ns: submission.published_ns + 1,
                    finished_ns: submission.published_ns + 2,
                    installed_until_ns: submission.stamp.installed_until_ns,
                    evidence_hash: [7; 32],
                },
                &Owners,
            )
            .unwrap();
        registry
            .reconcile(
                submission.apply,
                submission.stamp.version,
                ExecutionState::Applied,
            )
            .unwrap();
        owner.score(&set, budget, START + 7_000);
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 4, 1),
                    &mut FixedClock(START + 9_000),
                    &mut owner,
                )
                .unwrap(),
            Error::Budget,
        );
        assert_eq!(owner.publishes, 1);
        assert_eq!(owner.governance.submissions().count(), 1);
        assert_eq!(owner.governance.stage(), Stage::Restoring);
        assert_eq!(
            registry.query_model(publisher(), accepted.id),
            Ok(submission.model)
        );
    });
}

#[test]
fn unknown_custody_keeps_original_model_across_aba_and_registration_history_reuse() {
    let original = ModelBinding {
        generation: 7,
        model_hash: [3; 32],
        schema_hash: [5; 32],
    };
    let mut registry = Registry::new(11, publisher(), original).unwrap();
    let set = candidates(original, START, console(), &[Action::ConsoleBatch(1)]);
    registry.register(publisher(), &set).unwrap();
    let bytes = frame(&set, 1, 0);
    let mut owner = OrdinaryOwner::default();
    let first = registry
        .submit(publisher(), &bytes, &mut FixedClock(START), &mut owner)
        .unwrap();
    let unknown = registry
        .reconcile(
            apply_id(1, console()),
            first.version,
            ExecutionState::Unknown,
        )
        .unwrap();
    registry
        .change_model(
            publisher(),
            ModelBinding {
                generation: 8,
                model_hash: [4; 32],
                ..original
            },
        )
        .unwrap();
    let returned = ModelBinding {
        generation: 9,
        ..original
    };
    registry.change_model(publisher(), returned).unwrap();
    assert_ne!(returned, original);
    for index in 0..TERMINAL_HISTORY + 1 {
        let sequence = index as u64 + 2;
        let target = ObjectKey {
            id: sequence + 100,
            generation: 1,
        };
        let set = candidates(returned, START, target, &[Action::CpuWeight(1)]);
        registry.register(publisher(), &set).unwrap();
        let receipt = registry
            .submit(
                publisher(),
                &frame(&set, sequence, registry.version()),
                &mut FixedClock(START),
                &mut owner,
            )
            .unwrap();
        assert_ne!(receipt.version, 0);
        registry
            .reconcile(
                apply_id(sequence, target),
                receipt.version,
                ExecutionState::Applied,
            )
            .unwrap();
    }
    assert_eq!(registry.query(publisher(), plan_id(1)), Ok(unknown));
    assert_eq!(registry.query_model(publisher(), plan_id(1)), Ok(original));
    let before = owner.publishes;
    assert_eq!(
        registry.submit(publisher(), &bytes, &mut FixedClock(u64::MAX), &mut owner),
        Ok(unknown)
    );
    assert_eq!(owner.publishes, before);
    assert_eq!(registry.register(publisher(), &set), Err(Error::Stale));
    assert_eq!(
        registry
            .reconcile(
                apply_id(1, console()),
                first.version,
                ExecutionState::Applied
            )
            .unwrap()
            .state(),
        ExecutionState::Applied
    );
    assert_eq!(registry.query_model(publisher(), plan_id(1)), Ok(original));
}

#[test]
fn old_canary_candidate_stays_stale_when_active_hash_returns_with_a_new_generation() {
    with_canary(|_, gate, _, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let mut set = canary_set(original, permit, START);
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        registry
            .change_model(
                publisher(),
                ModelBinding {
                    generation: 8,
                    model_hash: [92; 32],
                    ..original
                },
            )
            .unwrap();
        registry
            .change_model(
                publisher(),
                ModelBinding {
                    generation: 9,
                    ..original
                },
            )
            .unwrap();
        assert_eq!(
            registry.register_canary(publisher(), &mut set, permit, gate, START),
            Err(Error::Stale)
        );
        let mut owner = OrdinaryOwner::default();
        failed(
            registry
                .submit(
                    publisher(),
                    &frame(&set, 1, 0),
                    &mut FixedClock(START),
                    &mut owner,
                )
                .unwrap(),
            Error::Stale,
        );
        assert_eq!(owner.prepares, 0);
    });
}

#[test]
fn score_proof_cannot_authorize_another_legal_choice_or_extended_scope() {
    with_canary(|governance, gate, budget, permit, original| {
        let mut registry = Registry::new(11, publisher(), original).unwrap();
        let model = canary_model(original, permit);
        let mut set = candidates(
            model,
            START,
            console(),
            &[
                Action::ConsoleBatch(1),
                Action::ConsoleBatch(8),
                Action::ConsoleBatch(32),
            ],
        );
        registry
            .register_canary(publisher(), &mut set, permit, gate, START)
            .unwrap();
        let credit = budget
            .reserve(Role::Canary, 1, 1, 1024 * 1024, START, 10_000, &Owners)
            .unwrap();
        let proof = governance.score_canary(&set, &credit).unwrap();
        budget.settle(credit, 1_000, START + 1_000).unwrap();
        let selected = (0..set.len())
            .find(|index| {
                proof
                    .verify_selection(
                        set.hash(),
                        model,
                        console(),
                        START,
                        *index as u16,
                        set.get(*index).unwrap().action,
                    )
                    .is_ok()
            })
            .unwrap();
        let action = set.get(selected).unwrap().action;
        let other = (selected + 1) % set.len();
        assert_eq!(
            proof.verify_selection(
                set.hash(),
                model,
                console(),
                START,
                other as u16,
                set.get(other).unwrap().action
            ),
            Err(LearningError::Evidence)
        );
        assert_eq!(
            proof.verify_selection(
                set.hash(),
                model,
                console(),
                START,
                selected as u16,
                set.get(other).unwrap().action
            ),
            Err(LearningError::Evidence)
        );
        assert_eq!(
            proof.verify_selection(set.hash(), model, console(), START, other as u16, action),
            Err(LearningError::Evidence)
        );
        assert_eq!(
            proof.verify_selection(
                set.hash(),
                original,
                console(),
                START,
                selected as u16,
                action
            ),
            Err(LearningError::Evidence)
        );
        assert_eq!(
            proof.verify_selection(
                set.hash(),
                model,
                ObjectKey {
                    generation: 2,
                    ..console()
                },
                START,
                selected as u16,
                action
            ),
            Err(LearningError::Evidence)
        );
        assert_eq!(
            proof.verify_selection(
                set.hash(),
                model,
                console(),
                START + 1,
                selected as u16,
                action
            ),
            Err(LearningError::Evidence)
        );
        governance
            .extend(gate, START + 2_000, 200, &Owners)
            .unwrap();
        let extended = gate.permit().unwrap();
        let mut fresh = candidates(
            model,
            START,
            console(),
            &[
                Action::ConsoleBatch(1),
                Action::ConsoleBatch(8),
                Action::ConsoleBatch(32),
            ],
        );
        registry
            .register_canary(publisher(), &mut fresh, extended, gate, START + 2_000)
            .unwrap();
        assert_ne!(fresh.hash(), set.hash());
        assert_eq!(
            proof.verify_selection(
                fresh.hash(),
                model,
                console(),
                START,
                selected as u16,
                action
            ),
            Err(LearningError::Evidence)
        );
        assert_eq!(governance.submissions().count(), 0);
    });
}

// Legacy fixtures deliberately advance execution and wall time together.
fn publication_time(wall_ns: u64) -> cyxia_prototype::policy::PublicationTime {
    cyxia_prototype::policy::PublicationTime {
        wall_ns,
        cpu: cyxia_prototype::policy::CpuTime {
            cpu: 0,
            ns: wall_ns,
        },
    }
}
