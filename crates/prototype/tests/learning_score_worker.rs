//! Synthetic replay and protected-runtime fixtures only. These tests execute
//! the real pure EL0 score module; they do not provide a native reward corpus.
#[path = "../../../user/prototype-learning/src/compute.rs"]
mod compute;
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey, PolicyStamp},
    features::RawFeatures,
    learning::{
        Error, Family,
        governance::*,
        reward::WorkRequest,
        score::{EncoderState, PreparedScore},
        score_wire,
        validate::ValidatedCandidate,
        worker::{CompletionAuthority, CompletionClaim},
        worker_wire::{self as wire, JobBinding},
    },
    model::Model,
    policy::{Candidate, CandidateSet, ModelBinding, Publisher, Registry, Snapshot},
};
use sha2::{Digest, Sha256};
use std::cell::Cell;
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
struct Owners;
impl ControlAuthority for Owners {
    fn authorize(&self, _: Role, cpu: u16, generation: u64, bytes: u32) -> Result<(), Error> {
        if cpu == 1 && generation == 1 && bytes <= 1024 * 1024 {
            Ok(())
        } else {
            Err(Error::State)
        }
    }
}
impl GovernanceAuthority for Owners {
    fn registered_noncritical_console(&self, t: TargetRegistration) -> Result<(), Error> {
        if t.key == key(15) && t.baseline == Action::ConsoleBatch(1) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn legal_console(&self, t: ObjectKey, a: Action, _: u64) -> Result<(), Error> {
        if t == key(15) && matches!(a, Action::ConsoleBatch(1 | 8 | 32 | 64)) {
            Ok(())
        } else {
            Err(Error::Evidence)
        }
    }
    fn verify_receipt(&self, _: &CanaryReceipt) -> Result<(), Error> {
        Err(Error::DataIncomplete)
    }
    fn verify_measurement(
        &self,
        _: CanaryPermit,
        _: u16,
        _: &[WorkRequest],
        _: &[WorkRequest],
        _: [u8; 32],
    ) -> Result<(), Error> {
        Err(Error::DataIncomplete)
    }
    fn authorize_extension(
        &self,
        _: [u8; 32],
        _: CanaryPermit,
        _: u64,
        _: u16,
    ) -> Result<(), Error> {
        Err(Error::DataIncomplete)
    }
    fn verify_restoration(
        &self,
        _: RestorationRequest,
        _: &RestorationReceipt,
    ) -> Result<(), Error> {
        Err(Error::DataIncomplete)
    }
}
fn original(candidate: &ValidatedCandidate<'_>) -> ModelBinding {
    ModelBinding {
        generation: 7,
        model_hash: candidate.parent_hash(),
        schema_hash: support::schemas().feature.hash,
    }
}
fn binding(id: u64) -> JobBinding {
    JobBinding {
        boot_epoch: 11,
        job_id: id,
        controller_epoch: 9,
        core_generation: 1,
        model_generation: 7,
        data_generation: 7,
        role_context: key(99),
        image_hash: [9; 32],
        ledger_generation: 1,
    }
}
fn candidates(family: Family, model: ModelBinding, now: u64, id: u64) -> CandidateSet {
    let choices: Vec<_> = support::choices(family)
        .into_iter()
        .map(|action| Candidate {
            action,
            features: RawFeatures {
                control_capacity: Some(1000),
                ..RawFeatures::default()
            },
        })
        .collect();
    CandidateSet::new(
        Snapshot {
            sequence: id,
            taken_ns: now,
            ledger_generation: 1,
            core_generation: 1,
        },
        key(15),
        model,
        &choices,
        Some(choices[0].action),
    )
    .unwrap()
}
fn encode(mut encoder: EncoderState<'_>) -> (Vec<u8>, PreparedScore) {
    let n = encoder.input_len();
    assert!(n <= score_wire::MAX_INPUT_BYTES && n < 11 * 1024);
    let mut input = vec![0xa5; n + 16];
    while !encoder.step(&mut input[..n]).unwrap().done {}
    assert!(input[n..].iter().all(|v| *v == 0xa5));
    let job = encoder.finish(&input).unwrap();
    input.truncate(n);
    assert_eq!(
        wire::input_identity(&input).unwrap(),
        (job.identity(), 1024 * 1024)
    );
    (input, job)
}
fn run(input: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa5; wire::OUTPUT_LIMIT];
    let n = compute::run(input, &mut out, |_| {}).unwrap();
    assert_eq!(n, 4096);
    assert!(out[n..].iter().all(|v| *v == 0xa5));
    out.truncate(n);
    out
}
fn receipt(budget: &mut ExtraBudget, role: Role, now: u64) -> WorkReceipt {
    let credit = budget
        .reserve(role, 1, 1, 1024 * 1024, now, 100_000, &Owners)
        .unwrap();
    budget.settle(credit, 10_000, now + 10_000).unwrap()
}
struct Runtime {
    claim: CompletionClaim,
    work: WorkIdentity,
    quiescent: Cell<bool>,
    consumed: Cell<bool>,
}
impl Runtime {
    fn new(job: &PreparedScore, output: &[u8], work: &WorkReceipt) -> Self {
        let report = score_wire::Report::decode(output).unwrap();
        Self {
            claim: CompletionClaim {
                identity: job.identity(),
                output_hash: Sha256::digest(output).into(),
                output_bytes: output.len() as u32,
                completed_steps: report.steps,
            },
            work: work.identity(),
            quiescent: Cell::new(true),
            consumed: Cell::new(false),
        }
    }
}
impl CompletionAuthority for Runtime {
    fn verify_completion(&self, _: &CompletionClaim) -> Result<(), Error> {
        Err(Error::State)
    }
    fn verify_score_completion(&self, c: &CompletionClaim, w: &WorkReceipt) -> Result<(), Error> {
        if !self.quiescent.get() {
            return Err(Error::Unknown);
        }
        if self.consumed.get() || *c != self.claim || w.identity() != self.work {
            return Err(Error::Evidence);
        }
        self.consumed.set(true);
        Ok(())
    }
}

#[test]
fn independent_scores_cover_shadow_windows_and_publish_only_the_exact_scoped_canary() {
    support::with_candidate(|candidate, old| {
        let active = original(candidate);
        let mut gate = CommitGate::new(11, active).unwrap();
        let mut gov = Governance::new(&gate, candidate, old, 0).unwrap();
        let mut budget = ExtraBudget::new();
        let mut id = 0;
        for window in 0..10 {
            let families = if window == 0 {
                &support::FAMILIES[..]
            } else {
                &support::FAMILIES[..1]
            };
            for (index, f) in families.iter().enumerate() {
                id += 1;
                let now = window * WINDOW_NS + index as u64 * 1_000_000;
                let set = candidates(*f, active, now, id);
                let (input, mut job) = encode(
                    gov.prepare_score(&set, Role::Shadow, binding(id), 1024 * 1024, now)
                        .unwrap(),
                );
                let output = run(&input);
                let cost = receipt(&mut budget, Role::Shadow, now);
                let runtime = Runtime::new(&job, &output, &cost);
                let scored = gov
                    .accept_score(&mut job, &output, &cost, &runtime, now + 10_000)
                    .unwrap();
                assert_eq!(scored.proof().scores(), scored.scores());
                assert_eq!(wire::output_identity(&output).unwrap().0, job.identity());
                for (i, c) in set.iter().enumerate() {
                    let input = cyxia_prototype::features::encode(c.action, c.features)
                        .unwrap()
                        .values;
                    assert_eq!(
                        scored.scores()[i],
                        Model::parse(candidate.model().bytes())
                            .unwrap()
                            .score(&input)
                    );
                    assert_eq!(
                        scored.prior_scores()[i],
                        Model::parse(old).unwrap().score(&input)
                    );
                }
                assert_eq!(
                    scored.proof().verify_selection(
                        set.hash(),
                        set.model,
                        set.target,
                        now,
                        scored.selected(),
                        set.get(scored.selected() as usize).unwrap().action
                    ),
                    Err(Error::State)
                );
                gov.record_shadow(scored.into_proof(), cost).unwrap();
            }
            gov.close_shadow_window((window + 1) * WINDOW_NS).unwrap();
        }
        assert_eq!(gov.stage(), Stage::Ready);
        let now = 10 * WINDOW_NS;
        let permit = gov
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: key(15),
                    baseline: Action::ConsoleBatch(1),
                },
                now,
                &Owners,
            )
            .unwrap();
        let model = ModelBinding {
            model_hash: permit.candidate_hash,
            ..active
        };
        let mut set = candidates(
            Family {
                domain: 15,
                kind: 1,
            },
            model,
            now,
            100,
        );
        assert_eq!(
            gov.prepare_score(&set, Role::Canary, binding(100), 1024 * 1024, now)
                .err()
                .map(|_| ()),
            Some(())
        ); // unscoped is not a native permit
        let publisher = Publisher {
            object: key(7),
            controller_epoch: 9,
        };
        let mut registry = Registry::new(11, publisher, active).unwrap();
        registry
            .register_canary(publisher, &mut set, permit, &gate, now)
            .unwrap();
        let (input, mut job) = encode(
            gov.prepare_score(&set, Role::Canary, binding(100), 1024 * 1024, now)
                .unwrap(),
        );
        let output = run(&input);
        let cost = receipt(&mut budget, Role::Canary, now);
        let runtime = Runtime::new(&job, &output, &cost);
        let scored = gov
            .accept_score(&mut job, &output, &cost, &runtime, now + 10_000)
            .unwrap();
        let selected = scored.selected();
        let action = set.get(usize::from(selected)).unwrap().action;
        scored
            .proof()
            .verify_selection(set.hash(), model, key(15), now, selected, action)
            .unwrap();
        assert_eq!(
            scored.proof().scores(),
            &score_wire::Report::decode(&output).unwrap().scores[..set.len()]
        );
        let stamp = PolicyStamp::for_action(action, 1, now, now + 10_000).unwrap();
        gov.publish(
            &mut gate,
            now + 10_000,
            scored.into_proof(),
            cost,
            ApplyId {
                boot_epoch: 11,
                controller_epoch: 9,
                plan_seq: 1,
                action_index: 0,
                target: key(15),
            },
            stamp,
            &Owners,
        )
        .unwrap();
        assert_eq!(gov.submissions().count(), 1);
        assert_eq!(
            gov.prepare_score(&set, Role::Canary, binding(101), 1024 * 1024, now + 20_000)
                .err()
                .map(|_| ()),
            Some(())
        ); // pending is not another quota
    });
}
#[test]
fn score_import_requires_exact_receipt_and_real_quiescence_not_ordinary_completion() {
    support::with_candidate(|candidate, old| {
        let active = original(candidate);
        let gate = CommitGate::new(11, active).unwrap();
        let gov = Governance::new(&gate, candidate, old, 0).unwrap();
        let set = candidates(
            Family {
                domain: 15,
                kind: 1,
            },
            active,
            0,
            1,
        );
        let (input, mut job) = encode(
            gov.prepare_score(&set, Role::Shadow, binding(1), 1024 * 1024, 0)
                .unwrap(),
        );
        let output = run(&input);
        let mut budget = ExtraBudget::new();
        let cost = receipt(&mut budget, Role::Shadow, 0);
        let mut other = ExtraBudget::new();
        let wrong = receipt(&mut other, Role::Shadow, 0);
        let runtime = Runtime::new(&job, &output, &cost);
        assert_eq!(
            gov.accept_score(&mut job, &output, &wrong, &runtime, 10_000)
                .err(),
            Some(Error::Evidence)
        );
        assert!(!job.consumed());
        runtime.quiescent.set(false);
        assert_eq!(
            gov.accept_score(&mut job, &output, &cost, &runtime, 10_000)
                .err(),
            Some(Error::Unknown)
        );
        assert!(!job.consumed());
        struct NumericOnly;
        impl CompletionAuthority for NumericOnly {
            fn verify_completion(&self, _: &CompletionClaim) -> Result<(), Error> {
                Ok(())
            }
        }
        assert_eq!(
            gov.accept_score(&mut job, &output, &cost, &NumericOnly, 10_000)
                .err(),
            Some(Error::Evidence)
        );
        runtime.quiescent.set(true);
        gov.accept_score(&mut job, &output, &cost, &runtime, 10_000)
            .unwrap();
        assert!(job.consumed());
        assert_eq!(
            gov.accept_score(&mut job, &output, &cost, &runtime, 10_000)
                .err(),
            Some(Error::State)
        );
    });
}
#[test]
fn all_scores_are_authenticated_even_when_tampering_preserves_the_same_selection() {
    support::with_candidate(|candidate, old| {
        let active = original(candidate);
        let gate = CommitGate::new(11, active).unwrap();
        let gov = Governance::new(&gate, candidate, old, 0).unwrap();
        let set = candidates(
            Family {
                domain: 15,
                kind: 1,
            },
            active,
            0,
            2,
        );
        let (input, mut job) = encode(
            gov.prepare_score(&set, Role::Shadow, binding(2), 1024 * 1024, 0)
                .unwrap(),
        );
        let output = run(&input);
        let mut budget = ExtraBudget::new();
        let cost = receipt(&mut budget, Role::Shadow, 0);
        let runtime = Runtime::new(&job, &output, &cost);
        let mut corrupt = score_wire::Report::decode(&output).unwrap();
        for score in &mut corrupt.prior[..usize::from(corrupt.count)] {
            *score = score.saturating_add(1);
        }
        let mut bytes = vec![0; 4096];
        corrupt.encode(&mut bytes).unwrap();
        assert_eq!(
            gov.accept_score(&mut job, &bytes, &cost, &runtime, 10_000)
                .err(),
            Some(Error::Evidence)
        );
        let mut corrupt = score_wire::Report::decode(&output).unwrap();
        let not_selected = (usize::from(corrupt.selected) + 1) % usize::from(corrupt.count);
        corrupt.scores[not_selected] = i16::MIN;
        corrupt.encode(&mut bytes).unwrap();
        assert_eq!(
            gov.accept_score(&mut job, &bytes, &cost, &runtime, 10_000)
                .err(),
            Some(Error::Evidence)
        );
        assert!(!job.consumed());
        gov.accept_score(&mut job, &output, &cost, &runtime, 10_000)
            .unwrap();
    });
}
#[test]
fn stale_or_rebound_jobs_and_corrupt_inputs_never_create_a_score_proof() {
    support::with_candidate(|candidate, old| {
        let active = original(candidate);
        let gate = CommitGate::new(11, active).unwrap();
        let gov = Governance::new(&gate, candidate, old, 0).unwrap();
        let set = candidates(
            Family {
                domain: 15,
                kind: 1,
            },
            active,
            0,
            3,
        );
        let (input, mut job) = encode(
            gov.prepare_score(&set, Role::Shadow, binding(3), 1024 * 1024, 0)
                .unwrap(),
        );
        let output = run(&input);
        let mut budget = ExtraBudget::new();
        let cost = receipt(&mut budget, Role::Shadow, 0);
        let runtime = Runtime::new(&job, &output, &cost);
        assert_eq!(
            gov.accept_score(&mut job, &output, &cost, &runtime, 50_000_001)
                .err(),
            Some(Error::Stale)
        );
        assert!(!runtime.consumed.get());
        let mut corrupt = input.clone();
        corrupt[score_wire::INPUTS] ^= 1;
        let mut out = vec![0; 4096];
        assert_eq!(
            compute::run(&corrupt, &mut out, |_| {}).err(),
            Some(Error::Evidence)
        );
        let (_, mut other) = encode(
            gov.prepare_score(&set, Role::Shadow, binding(4), 1024 * 1024, 0)
                .unwrap(),
        );
        assert_eq!(
            gov.accept_score(&mut other, &output, &cost, &runtime, 10_000)
                .err(),
            Some(Error::Evidence)
        );
        assert!(wire::Report::decode(&output).is_err());
        assert!(wire::Header::decode(&input).is_err());
        gov.accept_score(&mut job, &output, &cost, &runtime, 10_000)
            .unwrap();
    });
}
