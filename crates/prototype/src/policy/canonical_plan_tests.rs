//! Host fixtures exercising actual encoder and Registry transition seams.
extern crate std;
use super::*;
use crate::{
    features::RawFeatures,
    policy_wire::{Decision, Envelope, PlanHeader},
};
use std::{collections::VecDeque, vec::Vec};

fn publisher() -> Publisher {
    Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: 9,
    }
}
fn set() -> CandidateSet {
    CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: 10,
            ledger_generation: 3,
            core_generation: 2,
        },
        ObjectKey {
            id: 4153,
            generation: 11,
        },
        ModelBinding {
            generation: 1,
            model_hash: [3; 32],
            schema_hash: [5; 32],
        },
        &[0, 2].map(|recipe| Candidate {
            action: Action::RecoveryRecipe(recipe),
            features: RawFeatures::default(),
        }),
        Some(Action::RecoveryRecipe(0)),
    )
    .unwrap()
}
fn canonical() -> CanonicalPlan<384> {
    let set = set();
    CanonicalPlan::encode(
        PlanHeader {
            plan_seq: 397,
            base_plan_version: 0,
            active_model_generation: 1,
            controller_epoch: 9,
            snapshot_seq: 1,
            active_until_local_ns: 0,
        },
        &[Decision {
            action: Action::RecoveryRecipe(2),
            candidate_index: 1,
            envelope: Envelope {
                controller_epoch: 9,
                decision_seq: 397,
                snapshot_seq: 1,
                target: set.target,
                ledger_generation: 3,
                core_generation: 2,
                expires_local_ns: 100_000_010,
                model_hash: set.model.model_hash,
                candidate_set_hash: set.hash(),
            },
        }],
    )
    .unwrap()
}
fn ready() -> Registry {
    let set = set();
    let mut registry = Registry::new(11, publisher(), set.model).unwrap();
    registry.register(publisher(), &set).unwrap();
    registry
}
fn at(wall_ns: u64, ns: u64) -> PublicationTime {
    PublicationTime {
        wall_ns,
        cpu: CpuTime { cpu: 2, ns },
    }
}
struct ClockFixture {
    samples: VecDeque<PublicationTime>,
    seen: Vec<PublicationTime>,
}
impl Clock for ClockFixture {
    fn read(&mut self) -> PublicationTime {
        let t = self.samples.pop_front().unwrap();
        self.seen.push(t);
        t
    }
}
#[derive(Default, Debug, PartialEq, Eq)]
struct Owner {
    calls: Vec<u8>,
    fail_second: bool,
    refuse_model: bool,
}
impl<P: PlanView> Executor<P> for Owner {
    fn check(&mut self, _: Decision, _: &RegisteredSet, _: u64) -> Result<(), Error> {
        self.calls.push(1);
        if self.fail_second && self.calls.contains(&2) {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn prepare(&mut self, _: &P, _: u64) -> Result<(), Error> {
        self.calls.push(2);
        Ok(())
    }
    fn revalidate(&mut self, _: &P, _: u64) -> Result<(), Error> {
        self.calls.push(3);
        Ok(())
    }
    fn authorize_model(
        &mut self,
        active: ModelBinding,
        set: &RegisteredSet,
        _: u64,
    ) -> Result<(), Error> {
        self.calls.push(4);
        if self.refuse_model && self.calls.contains(&2) || set.model != active {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }
    fn publish(&mut self, _: &P, _: u64, _: u64) -> Result<(), Error> {
        self.calls.push(5);
        Ok(())
    }
    fn cancel_prepared(&mut self, _: &P) {
        self.calls.push(6)
    }
}
fn run(typed: bool, mode: u8) -> (PlanReceipt, bool, Vec<PublicationTime>, Owner, [u8; 32]) {
    let mut registry = ready();
    let plan = canonical();
    let mut owner = Owner {
        fail_second: mode == 1,
        refuse_model: mode == 2,
        ..Owner::default()
    };
    let mut points = [at(11, 10), at(12, 20), at(13, 30), at(14, 40), at(15, 50)];
    if mode == 3 {
        points[2] = at(60_000_011, 30);
        points[3] = at(60_000_012, 40);
    }
    if mode == 4 {
        points[4] = at(15, 518_872);
    }
    if mode == 5 {
        points[2] = at(13, 500_001);
        points[3] = at(14, 500_001);
    }
    let mut clock = ClockFixture {
        samples: points.into(),
        seen: Vec::new(),
    };
    let budget = PublicationBudget::fresh(at(10, 0));
    let receipt = if typed {
        registry.submit_canonical_job_debited(
            publisher(),
            &plan,
            budget,
            50_000_010,
            &mut clock,
            &mut owner,
        )
    } else {
        registry.submit_job_debited(
            publisher(),
            plan.bytes(),
            budget,
            50_000_010,
            &mut clock,
            &mut owner,
        )
    }
    .unwrap();
    let digest = registry
        .records()
        .find(|r| r.receipt.id == receipt.id)
        .unwrap()
        .digest;
    (
        receipt,
        registry.optimization_stopped(),
        clock.seen,
        owner,
        digest,
    )
}
#[test]
fn actual_typed_submission_removes_decode_and_preserves_receipt_bytes() {
    super::decode_probe::reset();
    let generic = run(false, 0);
    assert_eq!(super::decode_probe::count(), 1);
    super::decode_probe::reset();
    let typed = run(true, 0);
    assert_eq!(super::decode_probe::count(), 0);
    assert_eq!(generic, typed);
    assert_eq!(typed.0.version, 1);
    assert_eq!(typed.2.len(), 5);
    assert_eq!(typed.4, plan_receipt_digest(canonical().bytes()));
}
#[test]
fn typed_and_generic_keep_mutable_second_validation_model_wall_and_cpu_failures() {
    for mode in 1..=5 {
        let generic = run(false, mode);
        let typed = run(true, mode);
        assert_eq!(generic, typed, "mode {mode}");
        if mode == 4 {
            assert_eq!(typed.0.version, 1);
            assert!(typed.1);
            assert_eq!(typed.2.len(), 5);
        } else {
            assert_eq!(typed.0.version, 0);
            let expected = match mode {
                1 => Error::Stale,
                2 => Error::Auth,
                3 => Error::Expired,
                5 => Error::Budget,
                _ => unreachable!(),
            };
            assert_eq!(typed.0.state(), ExecutionState::Failed(expected));
            assert!(typed.3.calls.contains(&6));
        }
    }
}
#[test]
fn canonical_storage_is_independent_and_encoder_rejects_invalid_decisions() {
    let cap = canonical();
    let decoded = policy_wire::decode_plan(cap.bytes()).unwrap();
    let mut decisions = [decoded.action(0).unwrap()];
    let before = cap.bytes().to_vec();
    decisions[0].candidate_index = 32;
    assert!(CanonicalPlan::<384>::encode(decoded.header, &decisions).is_err());
    assert_eq!(cap.bytes(), before);
    assert!(cap.storage()[cap.bytes().len()..].iter().all(|b| *b == 0));
    assert!(CanonicalPlan::<64>::encode(decoded.header, &[decoded.action(0).unwrap()]).is_err());
    for index in [0, 14, 208, 211] {
        let mut bytes = before.clone();
        bytes[index] ^= 0x80;
        assert!(policy_wire::decode_plan(&bytes).is_err());
    }
}

#[test]
fn typed_retry_retains_exact_original_receipt_and_rejects_new_bytes_for_same_identity() {
    let mut registry = ready();
    let original = canonical();
    let mut owner = Owner::default();
    let mut clock = ClockFixture {
        samples: [at(11, 10), at(12, 20), at(13, 30), at(14, 40), at(15, 50)].into(),
        seen: Vec::new(),
    };
    let budget = PublicationBudget::fresh(at(10, 0));
    let first = registry
        .submit_canonical_job_debited(
            publisher(),
            &original,
            budget,
            50_000_010,
            &mut clock,
            &mut owner,
        )
        .unwrap();
    let calls = owner.calls.clone();
    let empty = || ClockFixture {
        samples: VecDeque::new(),
        seen: Vec::new(),
    };
    let retry = registry
        .submit_canonical_job_debited(
            publisher(),
            &original,
            budget,
            50_000_010,
            &mut empty(),
            &mut owner,
        )
        .unwrap();
    assert_eq!(retry, first);
    assert_eq!(owner.calls, calls);
    let mut decision = original.action(0).unwrap();
    decision.action = Action::RecoveryRecipe(0);
    decision.candidate_index = 0;
    let different = CanonicalPlan::<384>::encode(original.header(), &[decision]).unwrap();
    assert_ne!(original.bytes(), different.bytes());
    assert_eq!(
        registry.submit_canonical_job_debited(
            publisher(),
            &different,
            budget,
            50_000_010,
            &mut empty(),
            &mut owner
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        registry.submit_job_debited(
            publisher(),
            different.bytes(),
            budget,
            50_000_010,
            &mut empty(),
            &mut owner
        ),
        Err(Error::Conflict)
    );
    assert_eq!(owner.calls, calls);
}

#[test]
fn action_schema_source_remains_exact_historical_bytes() {
    let actual: [u8; 32] = Sha256::digest(include_bytes!("../policy_wire.rs")).into();
    assert_eq!(
        actual,
        [
            0xe6, 0x8f, 0x50, 0x95, 0xf9, 0xcc, 0xe9, 0x6c, 0x00, 0x36, 0xe8, 0x76, 0x5b, 0x6f,
            0x30, 0x3f, 0x5d, 0x7f, 0xf2, 0xa1, 0x12, 0xbb, 0x5b, 0xd1, 0x3b, 0x96, 0x35, 0x51,
            0xe5, 0x81, 0x2f, 0x5b
        ]
    );
}
