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
    run_kind(u8::from(typed), mode)
}
fn run_kind(kind: u8, mode: u8) -> (PlanReceipt, bool, Vec<PublicationTime>, Owner, [u8; 32]) {
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
    let receipt = if kind == 2 {
        let single =
            SingleCanonicalPlan::<384>::encode(plan.header(), plan.action(0).unwrap()).unwrap();
        registry.submit_single_canonical_job_debited(
            publisher(),
            &single,
            budget,
            50_000_010,
            &mut clock,
            &mut owner,
        )
    } else if kind == 1 {
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
fn single_canonical_preserves_every_mutable_check_timestamp_and_receipt_byte() {
    for mode in 0..=5 {
        decode_probe::reset();
        let single = run_kind(2, mode);
        assert_eq!(decode_probe::count(), 0);
        let untrusted = run_kind(0, mode);
        assert_eq!(decode_probe::count(), 1);
        assert_eq!(single, untrusted, "mode {mode}");
    }
}
#[test]
fn single_canonical_owns_its_validated_decision_and_rejects_structural_tampering() {
    let original = canonical();
    let mut decision = original.action(0).unwrap();
    let single = SingleCanonicalPlan::<384>::encode(original.header(), decision).unwrap();
    assert_eq!(single.bytes(), original.bytes());
    assert_eq!(single.header(), original.header());
    assert_eq!(single.len(), 1);
    assert_eq!(single.action(0), Some(decision));
    assert_eq!(single.action(1), None);
    assert!(
        single.storage()[single.bytes().len()..]
            .iter()
            .all(|b| *b == 0)
    );
    decision.candidate_index = 32;
    assert!(SingleCanonicalPlan::<384>::encode(original.header(), decision).is_err());
    assert_eq!(single.bytes(), original.bytes());
    assert!(
        SingleCanonicalPlan::<64>::encode(original.header(), original.action(0).unwrap()).is_err()
    );
    let mut header = original.header();
    header.controller_epoch = 0;
    assert!(SingleCanonicalPlan::<384>::encode(header, original.action(0).unwrap()).is_err());
    for index in [0, 14, 208, 211] {
        let mut changed = single.bytes().to_vec();
        changed[index] ^= 0x80;
        assert!(policy_wire::decode_plan(&changed).is_err());
    }
}
#[test]
fn single_canonical_retries_keep_original_receipt_and_reject_changed_same_identity() {
    let mut registry = ready();
    let original = canonical();
    let single =
        SingleCanonicalPlan::<384>::encode(original.header(), original.action(0).unwrap()).unwrap();
    let mut owner = Owner::default();
    let mut clock = ClockFixture {
        samples: [at(11, 10), at(12, 20), at(13, 30), at(14, 40), at(15, 50)].into(),
        seen: Vec::new(),
    };
    let budget = PublicationBudget::fresh(at(10, 0));
    let first = registry
        .submit_single_canonical_job_debited(
            publisher(),
            &single,
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
    assert_eq!(
        registry
            .submit_single_canonical_job_debited(
                publisher(),
                &single,
                budget,
                50_000_010,
                &mut empty(),
                &mut owner
            )
            .unwrap(),
        first
    );
    let mut d = original.action(0).unwrap();
    d.action = Action::RecoveryRecipe(0);
    d.candidate_index = 0;
    let changed = SingleCanonicalPlan::<384>::encode(original.header(), d).unwrap();
    assert_eq!(
        registry.submit_single_canonical_job_debited(
            publisher(),
            &changed,
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

fn actual_spawn_fixture() -> (CandidateSet, SingleCanonicalPlan<384>, Publisher) {
    let input_raw = include_bytes!("../../tests/fixtures/a03-d02-job111-public/input.bin");
    let output_raw = include_bytes!("../../tests/fixtures/a03-d02-job111-public/output.bin");
    let model_raw = include_bytes!("../../tests/fixtures/a03-d02-job111-public/model.bin");
    let input: [u64; 512] = core::array::from_fn(|i| {
        u64::from_le_bytes(input_raw[i * 8..i * 8 + 8].try_into().unwrap())
    });
    let output: [u64; 512] = core::array::from_fn(|i| {
        u64::from_le_bytes(output_raw[i * 8..i * 8 + 8].try_into().unwrap())
    });
    assert_eq!((input[2], input[8], input[9]), (111, 2, 1));
    let choices: Vec<_> = (0..input[15] as usize)
        .map(|i| {
            let at = 64 + 10 * i;
            let (action, index) = policy_wire::decode_payload(
                2,
                1,
                &input_raw[(at + 1) * 8..(at + 1) * 8 + input[at] as usize],
            )
            .unwrap();
            assert_eq!(usize::from(index), i);
            Candidate {
                action,
                features: RawFeatures {
                    common: input[24..32].try_into().unwrap(),
                    domain: input[32..36].try_into().unwrap(),
                    domain_present: input[40] as u8,
                    target: crate::features::TargetFeatures {
                        values: core::array::from_fn(|j| {
                            (input[at + 7] & (1 << j) != 0).then_some(input[at + 3 + j])
                        }),
                    },
                    control_capacity: None,
                },
            }
        })
        .collect();
    let (prior, index) =
        policy_wire::decode_payload(2, 1, &input_raw[405 * 8..405 * 8 + input[404] as usize])
            .unwrap();
    assert_eq!(index, 0);
    let model = ModelBinding {
        generation: input[13],
        model_hash: Sha256::digest(model_raw).into(),
        schema_hash: Sha256::digest(include_bytes!("../features.rs")).into(),
    };
    let set = CandidateSet::new(
        Snapshot {
            sequence: input[38],
            taken_ns: input[4],
            ledger_generation: input[7],
            core_generation: input[6],
        },
        ObjectKey {
            id: input[10],
            generation: input[11],
        },
        model,
        &choices,
        Some(prior),
    )
    .unwrap();
    assert_eq!(
        set.hash(),
        <[u8; 32]>::try_from(&input_raw[160..192]).unwrap()
    );
    let parsed = policy_wire::decode_plan(&output_raw[128..128 + output[5] as usize]).unwrap();
    let plan = SingleCanonicalPlan::encode(parsed.header, parsed.action(0).unwrap()).unwrap();
    assert_eq!(plan.bytes(), &output_raw[128..128 + output[5] as usize]);
    let who = Publisher {
        object: ObjectKey {
            id: 7,
            generation: 1,
        },
        controller_epoch: input[3],
    };
    (set, plan, who)
}
fn distinct_spawn_set(original: &CandidateSet, serial: u64) -> CandidateSet {
    CandidateSet::new(
        Snapshot {
            sequence: serial,
            ..original.snapshot
        },
        ObjectKey {
            id: 0x1000 + serial,
            generation: 1,
        },
        original.model,
        &original.iter().collect::<Vec<_>>(),
        Some(original.get(0).unwrap().action),
    )
    .unwrap()
}
#[test]
fn recent_registration_actual_d02_submission_needs_one_full_hash_search_comparison() {
    let (set, plan, who) = actual_spawn_fixture();
    let mut registry = Registry::new(1, who, set.model).unwrap();
    // Restore the captured base version in this host state fixture. This is
    // not a native Registry/owner witness or a training sample.
    registry.version = plan.header().base_plan_version;
    for serial in 1..64 {
        registry
            .register(who, &distinct_spawn_set(&set, serial))
            .unwrap();
    }
    registry.register(who, &set).unwrap();
    assert_eq!(registry.registered_count, 64);
    let base = set.snapshot.taken_ns;
    let points = [
        at(base + 1, 10),
        at(base + 2, 20),
        at(base + 3, 30),
        at(base + 4, 40),
        at(base + 5, 50),
    ];
    let mut clock = ClockFixture {
        samples: points.into(),
        seen: Vec::new(),
    };
    let mut owner = Owner::default();
    registration_lookup_probe::reset();
    let receipt = registry
        .submit_single_canonical_job_debited(
            who,
            &plan,
            PublicationBudget::fresh(at(base, 0)),
            base + 50_000_000,
            &mut clock,
            &mut owner,
        )
        .unwrap();
    let comparisons = registration_lookup_probe::count();
    assert_eq!(receipt.version, 73);
    assert_eq!(clock.seen, points);
    assert_eq!(owner.calls, run_kind(2, 0).3.calls);
    assert_eq!(
        registry
            .records()
            .find(|r| r.receipt.id == receipt.id)
            .unwrap()
            .digest,
        plan_receipt_digest(plan.bytes())
    );
    assert_eq!(
        comparisons, 1,
        "the latest actual D02 job must not search all64 registered hashes before the unchanged mutable gates"
    );
}
#[test]
fn recent_registration_keeps_old_and_interleaved_hashes_and_idempotent_registration() {
    let (set, plan, who) = actual_spawn_fixture();
    let mut registry = Registry::new(1, who, set.model).unwrap();
    registry.register(who, &set).unwrap();
    for serial in 1..64 {
        registry
            .register(who, &distinct_spawn_set(&set, serial))
            .unwrap();
    }
    let cursor = registry.registered_cursor;
    registry.register(who, &set).unwrap();
    assert_eq!(registry.registered_cursor, cursor);
    assert_eq!(registry.registered_count, 64);
    assert_eq!(
        registry
            .registered_hashes
            .iter()
            .filter(|h| **h == set.hash())
            .count(),
        1
    );
    let mut cached = None;
    assert_eq!(
        registry
            .registered_decision_cached(plan.action(0).unwrap(), &mut cached)
            .unwrap()
            .hash,
        set.hash()
    );
    assert_eq!(cached, registry.registered_index(set.hash()));
    assert_eq!(cached, Some(0));
    // Matching only a hash prefix is never a hint hit or registration.
    let mut wrong = plan.action(0).unwrap();
    wrong.envelope.candidate_set_hash[31] ^= 1;
    assert_eq!(
        registry.recent_registered_index(wrong.envelope.candidate_set_hash),
        None
    );
    assert_eq!(
        registry.registered_decision_cached(wrong, &mut None).err(),
        Some(Error::Stale)
    );
}
#[test]
fn recent_registration_wrap_clear_and_repopulation_never_use_an_inactive_slot() {
    let (set, plan, who) = actual_spawn_fixture();
    let mut registry = Registry::new(1, who, set.model).unwrap();
    assert_eq!(registry.recent_registered_index([0; 32]), None);
    for serial in 1..=150 {
        let new = distinct_spawn_set(&set, serial);
        registry.register(who, &new).unwrap();
        let mut decision = plan.action(0).unwrap();
        decision.envelope.candidate_set_hash = new.hash();
        let mut cached = None;
        assert_eq!(
            registry
                .registered_decision_cached(decision, &mut cached)
                .unwrap()
                .hash,
            new.hash()
        );
        assert_eq!(cached, registry.registered_index(new.hash()));
        assert_eq!(cached, Some((serial as usize - 1) % 64));
    }
    let old_hash = registry.registered_hashes[0];
    registry.clear_registrations();
    assert_eq!(registry.recent_registered_index(old_hash), None);
    let mut decision = plan.action(0).unwrap();
    decision.envelope.candidate_set_hash = old_hash;
    assert_eq!(
        registry
            .registered_decision_cached(decision, &mut None)
            .err(),
        Some(Error::Stale)
    );
    registry.register(who, &set).unwrap();
    let mut cached = None;
    assert_eq!(
        registry
            .registered_decision_cached(plan.action(0).unwrap(), &mut cached)
            .unwrap()
            .hash,
        set.hash()
    );
    assert_eq!(cached, Some(0));
    // Only bounded active slots are eligible for the hint; malformed internal
    // cursor/count values cannot turn zeroed or out-of-range bytes into a hit.
    registry.registered_cursor = 64;
    assert_eq!(registry.recent_registered_index(set.hash()), None);
    registry.registered_cursor = 0;
    assert_eq!(registry.recent_registered_index(set.hash()), None);
    registry.registered_count = 65;
    assert_eq!(registry.recent_registered_index(set.hash()), None);
}
#[test]
fn recent_registration_hint_does_not_cache_model_authority_or_survive_slot_reuse() {
    let (set, plan, who) = actual_spawn_fixture();
    let mut registry = Registry::new(1, who, set.model).unwrap();
    registry.version = plan.header().base_plan_version;
    registry.register(who, &set).unwrap();
    let mut cached = None;
    registry
        .registered_decision_cached(plan.action(0).unwrap(), &mut cached)
        .unwrap();
    for serial in 1..=64 {
        registry
            .register(who, &distinct_spawn_set(&set, serial))
            .unwrap();
    }
    assert_eq!(
        registry
            .registered_decision_cached(plan.action(0).unwrap(), &mut cached)
            .err(),
        Some(Error::Stale)
    );
    registry.register(who, &set).unwrap();
    let base = set.snapshot.taken_ns;
    let mut owner = Owner {
        refuse_model: true,
        ..Owner::default()
    };
    let mut clock = ClockFixture {
        samples: [
            at(base + 1, 10),
            at(base + 2, 20),
            at(base + 3, 30),
            at(base + 4, 40),
            at(base + 5, 50),
        ]
        .into(),
        seen: Vec::new(),
    };
    let receipt = registry
        .submit_single_canonical_job_debited(
            who,
            &plan,
            PublicationBudget::fresh(at(base, 0)),
            base + 50_000_000,
            &mut clock,
            &mut owner,
        )
        .unwrap();
    assert_eq!(receipt.version, 0);
    assert_eq!(receipt.state(), ExecutionState::Failed(Error::Auth));
    assert!(owner.calls.contains(&2) && owner.calls.contains(&6));
    assert!(!owner.calls.contains(&5));
}
