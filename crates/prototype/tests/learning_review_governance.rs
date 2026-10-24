//! Independent, synthetic governance counterexamples. No native experiment
//! or physical CPU accounting is claimed by this test authority.
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    features::RawFeatures,
    learning::{
        Error, Family,
        data::FrozenData,
        governance::*,
        manifest::{ModelManifest, SealedModel},
        reward::{RequestResult, RewardWorkspace, WorkRequest},
        train::Trainer,
        validate::{
            ReferenceCase, ReferenceSelection, ReferenceSuite, ValidatedCandidate,
            integer_reference,
        },
    },
    model::MODEL_BYTES,
    policy::{Candidate, CandidateSet, ExecutionState, ModelBinding, Snapshot},
};
use sha2::{Digest, Sha256};

struct Owners;
impl ControlAuthority for Owners {
    fn authorize(
        &self,
        _: Role,
        cpu: u16,
        core_generation: u64,
        workspace: u32,
    ) -> Result<(), Error> {
        if cpu == 1 && core_generation == 1 && workspace <= 1024 * 1024 {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
}
impl GovernanceAuthority for Owners {
    fn registered_noncritical_console(&self, target: TargetRegistration) -> Result<(), Error> {
        if target.key == console() && target.baseline == Action::ConsoleBatch(1) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn legal_console(&self, target: ObjectKey, action: Action, _: u64) -> Result<(), Error> {
        if target == console() && matches!(action, Action::ConsoleBatch(1 | 8 | 32 | 64)) {
            Ok(())
        } else {
            Err(Error::Safety)
        }
    }
    fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), Error> {
        if receipt.evidence_hash == [7; 32] {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        digest: [u8; 32],
    ) -> Result<(), Error> {
        if digest != [0; 32] {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn verify_restoration(
        &self,
        _: RestorationRequest,
        receipt: &RestorationReceipt,
    ) -> Result<(), Error> {
        if receipt.evidence_hash == [8; 32] {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
}
fn console() -> ObjectKey {
    ObjectKey {
        id: 15,
        generation: 1,
    }
}
fn original(candidate: &ValidatedCandidate<'_>) -> ModelBinding {
    ModelBinding {
        generation: 7,
        model_hash: candidate.parent_hash(),
        schema_hash: support::schemas().feature.hash,
    }
}
fn set(family: Family, model: ModelBinding, now: u64) -> CandidateSet {
    let actions = support::choices(family);
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
        console(),
        model,
        &choices,
        Some(actions[0]),
    )
    .unwrap()
}
fn shadow_at(
    governance: &mut Governance<'_, '_>,
    gate: &CommitGate,
    budget: &mut ExtraBudget,
    first_window: u64,
) {
    for window in first_window..first_window + 10 {
        let families = if window == first_window {
            &support::FAMILIES[..]
        } else {
            &support::FAMILIES[..1]
        };
        for (index, family) in families.iter().enumerate() {
            let now = window * WINDOW_NS + index as u64 * 10_000;
            let credit = budget
                .reserve(Role::Shadow, 1, 1, 1024 * 1024, now, 10_000, &Owners)
                .unwrap();
            let proof = governance
                .score_shadow(&set(*family, gate.active(), now), &credit)
                .unwrap();
            let receipt = budget.settle(credit, 5_000, now + 5_000).unwrap();
            governance.record_shadow(proof, receipt).unwrap();
        }
        governance
            .close_shadow_window((window + 1) * WINDOW_NS)
            .unwrap();
    }
    assert_eq!(governance.stage(), Stage::Ready);
}
fn begin(
    governance: &mut Governance<'_, '_>,
    gate: &mut CommitGate,
    budget: &mut ExtraBudget,
) -> CanaryPermit {
    shadow_at(governance, gate, budget, 0);
    governance
        .begin_canary(
            gate,
            TargetRegistration {
                key: console(),
                baseline: Action::ConsoleBatch(1),
            },
            10 * WINDOW_NS,
            &Owners,
        )
        .unwrap()
}

fn restoration(request: RestorationRequest) -> RestorationReceipt {
    RestorationReceipt {
        boot_epoch: request.boot_epoch,
        restoration_id: request.id,
        target: request.target.key,
        actual: request.target.baseline,
        actual_version: 0,
        executor_generation: 1,
        state: ExecutionState::Applied,
        evidence_hash: [8; 32],
    }
}
fn publish(
    governance: &mut Governance<'_, '_>,
    gate: &mut CommitGate,
    budget: &mut ExtraBudget,
    now: u64,
) -> Submission {
    let permit = gate.permit().unwrap();
    let binding = ModelBinding {
        model_hash: permit.candidate_hash,
        ..gate.active()
    };
    let credit = budget
        .reserve(Role::Canary, 1, 1, 1024 * 1024, now, 10_000, &Owners)
        .unwrap();
    let proof = governance
        .score_canary(
            &set(
                Family {
                    domain: 15,
                    kind: 1,
                },
                binding,
                now,
            ),
            &credit,
        )
        .unwrap();
    let cost = budget.settle(credit, 5_000, now + 5_000).unwrap();
    governance
        .publish(
            gate,
            now + 5_000,
            proof,
            cost,
            ApplyId {
                boot_epoch: 1,
                controller_epoch: 3,
                plan_seq: 1,
                action_index: 0,
                target: console(),
            },
            PolicyStamp::new(1, now, now + 5_000).unwrap(),
            &Owners,
        )
        .unwrap();
    governance.submissions().next().unwrap()
}
fn receipt(submission: Submission, finished_ns: u64) -> CanaryReceipt {
    CanaryReceipt {
        apply: submission.apply,
        plan_version: submission.stamp.version,
        executor_generation: 1,
        model: submission.model,
        state: ExecutionState::Applied,
        actual: Some(submission.action),
        started_ns: submission.stamp.snapshot_ns + 6_000,
        finished_ns,
        installed_until_ns: submission.stamp.installed_until_ns,
        evidence_hash: [7; 32],
    }
}
fn observations(start: u64) -> Vec<WorkRequest> {
    (0..100)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: start + i * 1_000_000,
            result: RequestResult::Completed {
                finished_ns: start + i * 1_000_000 + 1_000,
            },
        })
        .collect()
}
fn finish_measurements(
    governance: &mut Governance<'_, '_>,
    gate: &mut CommitGate,
    permit: CanaryPermit,
) {
    let mut work = RewardWorkspace::new();
    for second in 0..10 {
        let requests = observations(permit.start_ns + second * 1_000_000_000);
        governance
            .observe_second(
                gate,
                second as u16,
                &requests,
                &requests,
                &mut work,
                &Owners,
            )
            .unwrap();
    }
}
fn with_differently_registered_candidate(
    old: &[u8; MODEL_BYTES],
    run: impl FnOnce(&ValidatedCandidate<'_>),
) {
    let (training, validation) = support::dataset();
    let data = FrozenData::freeze(&training, &validation, 8, support::schemas()).unwrap();
    let mut training = Trainer::start(old, &data).unwrap();
    while training.step_next().unwrap() {}
    let trained = training.finish().unwrap();
    let mut cases = Vec::new();
    let mut selections = Vec::new();
    let probes = support::probes(trained.bytes());
    for set in &probes {
        let first = cases.len();
        let mut best = 0;
        let mut score = i16::MIN;
        for (index, candidate) in set.iter().enumerate() {
            let input = cyxia_prototype::features::encode(candidate.action, candidate.features)
                .unwrap()
                .values;
            let trace = integer_reference(trained.bytes(), &input);
            if index == 0 || trace.output > score {
                best = index;
                score = trace.output;
            }
            cases.push(ReferenceCase { input, trace });
        }
        selections.push(ReferenceSelection {
            first: first as u16,
            count: set.len() as u16,
            selected: best as u16,
        });
    }
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(trained.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&trained, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let sealed =
        SealedModel::seal(trained.bytes(), manifest, support::schemas(), &vectors).unwrap();
    let candidate = ValidatedCandidate::register(old, sealed, &data, &probes).unwrap();
    run(&candidate);
}

#[test]
fn equal_serials_from_independent_budget_owners_are_not_interchangeable() {
    let mut first = ExtraBudget::new();
    let mut second = ExtraBudget::new();
    let first_credit = first
        .reserve(Role::Shadow, 1, 1, 1024, 0, 1_000, &Owners)
        .unwrap();
    let second_credit = second
        .reserve(Role::Shadow, 1, 1, 1024, 0, 1_000, &Owners)
        .unwrap();
    assert_eq!(
        first.settle(second_credit, 100, 100).err(),
        Some(Error::Stale)
    );
    assert_eq!(first.spent_ns(), 0);
    first.settle(first_credit, 100, 100).unwrap();
    assert_eq!(
        second
            .reserve(Role::Shadow, 1, 1, 1024, WINDOW_NS, 1_000, &Owners)
            .err(),
        Some(Error::Unknown)
    );
}

#[test]
fn a_preexisting_mandatory_overrun_cannot_issue_a_successful_extra_work_receipt() {
    let mut budget = ExtraBudget::new();
    let credit = budget
        .reserve(Role::Shadow, 1, 1, 1024, 0, 1_000_000, &Owners)
        .unwrap();
    assert_eq!(budget.record_mandatory(0, 62_000_000), Err(Error::Budget));
    assert!(budget.faulted());
    assert_eq!(
        budget.settle(credit, 1_000_000, 1_000_000).err(),
        Some(Error::Budget)
    );
    assert_eq!(budget.spent_ns(), 1_000_000);
}

#[test]
fn canary_start_cannot_precede_the_ten_completed_shadow_windows() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        shadow_at(&mut governance, &gate, &mut budget, 0);
        assert!(
            governance
                .begin_canary(
                    &mut gate,
                    TargetRegistration {
                        key: console(),
                        baseline: Action::ConsoleBatch(1)
                    },
                    0,
                    &Owners
                )
                .is_err()
        );
        assert_eq!(gate.permit(), None);
        assert_eq!(governance.stage(), Stage::Ready);
    });
}

#[test]
fn governance_clock_overflow_rejects_without_mutating_the_permit() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        assert_eq!(
            Governance::new(&gate, candidate, old, u64::MAX).err(),
            Some(Error::Numeric)
        );
        let canary_window = u64::MAX / WINDOW_NS - 101;
        let start = canary_window * WINDOW_NS;
        let mut governance = Governance::new(&gate, candidate, old, canary_window - 10).unwrap();
        let mut budget = ExtraBudget::new();
        shadow_at(&mut governance, &gate, &mut budget, canary_window - 10);
        let permit = governance
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                start,
                &Owners,
            )
            .unwrap();
        assert_eq!(
            governance.extend(&mut gate, start + 1, 300, &Owners),
            Err(Error::Numeric)
        );
        assert_eq!(gate.permit(), Some(permit));
        assert_eq!(governance.stage(), Stage::Canary);
    });
}

#[test]
fn late_real_applied_is_retained_but_cannot_keep_a_canary_alive() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        let permit = begin(&mut governance, &mut gate, &mut budget);
        let submitted = publish(
            &mut governance,
            &mut gate,
            &mut budget,
            permit.start_ns + 1_000,
        );
        let late = receipt(submitted, submitted.stamp.snapshot_ns + 60_000_000);
        let _ = governance.reconcile(&mut gate, late, &Owners);
        assert_eq!(governance.submissions().next().unwrap().receipt, Some(late));
        assert_eq!(
            governance.submissions().next().unwrap().state,
            ExecutionState::Applied
        );
        assert_eq!(governance.stage(), Stage::Restoring);
        assert_eq!(governance.reason(), Some(Error::Deadline));
        assert_eq!(gate.permit(), None);
        assert_eq!(gate.restoration_pending(), Some(console()));
    });
}

#[test]
fn missing_apply_deadline_revokes_permission_without_erasing_unknown_work() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        let permit = begin(&mut governance, &mut gate, &mut budget);
        let submitted = publish(
            &mut governance,
            &mut gate,
            &mut budget,
            permit.start_ns + 1_000,
        );
        governance.tick(&mut gate, submitted.stamp.snapshot_ns + 60_000_000);
        assert_eq!(governance.stage(), Stage::Restoring);
        assert_eq!(governance.reason(), Some(Error::Deadline));
        let retained = governance.submissions().next().unwrap();
        assert_eq!(retained.apply, submitted.apply);
        assert_eq!(retained.state, ExecutionState::Unknown);
        assert_eq!(retained.receipt, None);
        assert_eq!(gate.permit(), None);
        assert_eq!(gate.restoration_pending(), Some(console()));
    });
}

#[test]
fn a_stale_governance_instance_cannot_roll_back_an_aba_active_generation() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        let mut governance = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        let permit = begin(&mut governance, &mut gate, &mut budget);
        let submitted = publish(
            &mut governance,
            &mut gate,
            &mut budget,
            permit.start_ns + 1_000,
        );
        governance
            .reconcile(
                &mut gate,
                receipt(submitted, submitted.stamp.snapshot_ns + 7_000),
                &Owners,
            )
            .unwrap();
        finish_measurements(&mut governance, &mut gate, permit);
        governance.freeze().unwrap();
        let promoted = governance.promote(&mut gate, permit.expires_ns).unwrap();
        // The same parameter hash after two more protected switches is a
        // different Active binding. This represents the post-ABA gate state.
        let after_aba = ModelBinding {
            generation: promoted.generation + 2,
            ..promoted
        };
        let mut current_gate = CommitGate::new(1, after_aba).unwrap();
        assert!(governance.rollback(&mut current_gate).is_err());
        assert_eq!(current_gate.active(), after_aba);
    });
}

#[test]
fn a_shadow_score_proof_is_bound_to_its_exact_candidate_registration() {
    support::with_candidate(|candidate, old| {
        with_differently_registered_candidate(old, |other| {
            assert_ne!(candidate.registration_hash(), other.registration_hash());
            let gate = CommitGate::new(1, original(candidate)).unwrap();
            let source = Governance::new(&gate, candidate, old, 0).unwrap();
            let mut destination = Governance::new(&gate, other, old, 0).unwrap();
            let mut budget = ExtraBudget::new();
            let credit = budget
                .reserve(Role::Shadow, 1, 1, 1024, 0, 1_000, &Owners)
                .unwrap();
            let proof = source
                .score_shadow(&set(support::FAMILIES[0], gate.active(), 0), &credit)
                .unwrap();
            let cost = budget.settle(credit, 100, 100).unwrap();
            assert!(destination.record_shadow(proof, cost).is_err());
            assert_eq!(
                destination.close_shadow_window(WINDOW_NS),
                Err(Error::DataIncomplete)
            );
        });
    });
}

#[test]
fn an_older_baseline_receipt_cannot_release_a_later_canary_restoration() {
    support::with_candidate(|candidate, old| {
        let mut gate = CommitGate::new(1, original(candidate)).unwrap();
        let mut first = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        begin(&mut first, &mut gate, &mut budget);
        first.abort(&mut gate, Error::Validation);
        let old_request = gate.restoration_request().unwrap();
        let old_receipt = restoration(old_request);
        first.restored(&mut gate, old_receipt, &Owners).unwrap();
        assert_eq!(gate.restoration_pending(), None);

        let mut second = Governance::new(&gate, candidate, old, 20).unwrap();
        shadow_at(&mut second, &gate, &mut budget, 20);
        let permit = second
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: console(),
                    baseline: Action::ConsoleBatch(1),
                },
                30 * WINDOW_NS,
                &Owners,
            )
            .unwrap();
        let submitted = publish(&mut second, &mut gate, &mut budget, permit.start_ns + 1_000);
        second
            .reconcile(
                &mut gate,
                receipt(submitted, submitted.stamp.snapshot_ns + 7_000),
                &Owners,
            )
            .unwrap();
        second.abort(&mut gate, Error::Validation);
        let new_request = gate.restoration_request().unwrap();
        assert_ne!(new_request.id, old_request.id);
        assert!(second.restored(&mut gate, old_receipt, &Owners).is_err());
        assert_eq!(gate.restoration_request(), Some(new_request));
        assert_eq!(
            gate.check_active_publication(gate.active(), console()),
            Err(Error::State)
        );
        second
            .restored(&mut gate, restoration(new_request), &Owners)
            .unwrap();
        assert_eq!(gate.restoration_pending(), None);
    });
}
