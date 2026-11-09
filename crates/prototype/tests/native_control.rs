pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_control/reply.rs"]
mod root_reply;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use domains::{Action, ObjectKey, POLICY_NS};
use sha2::{Digest, Sha256};
#[test]
fn actual_d03_job297_reply_replays_full_model_and_canonical_bytes() {
    actual_reply_fixture(
        include_bytes!("fixtures/a03-d03-job297-public/input.bin"),
        include_bytes!("fixtures/a03-d03-job297-public/output.bin"),
        include_bytes!("fixtures/a03-d03-job297-public/model.bin"),
        (297, 3, 1),
        [
            "9f1bad2d941a5db650d7491c4372f7b1a7e2b207f85766d0cc3fbc1b6dea2d67",
            "bf531ca88e8e4e0e50c66b5bb0e14b580ccada3363ba45207de3b56903fe43c6",
            "9b9bf87a969d7b0c6be3a9ea0564714d87cf12f1578037867d945c210c5f0ca3",
        ],
        512457,
    );
}
#[test]
fn actual_d02_job111_reply_replays_full_model_and_canonical_bytes() {
    actual_reply_fixture(
        include_bytes!("fixtures/a03-d02-job111-public/input.bin"),
        include_bytes!("fixtures/a03-d02-job111-public/output.bin"),
        include_bytes!("fixtures/a03-d02-job111-public/model.bin"),
        (111, 2, 1),
        [
            "4e9643bf020c19c099a85b42adf2d81f543a1eb1785764b3c7ec196496dc3bae",
            "5ab88b0fc9fb7f64fd67dfd5bac25a6a4660a94830906dd2f25d574e91ffbb18",
            "9b9bf87a969d7b0c6be3a9ea0564714d87cf12f1578037867d945c210c5f0ca3",
        ],
        518999,
    );
}
fn actual_reply_fixture(
    input_raw: &[u8; 4096],
    output_raw: &[u8; 4096],
    package: &[u8; 2772],
    identity: (u64, u64, u64),
    hashes: [&str; 3],
    original_ns: u64,
) {
    // Public ABI bytes from a preserved failed VM. Host replay/elapsed time
    // never substitutes for the original native cap or creates training data.
    assert_eq!(format!("{:x}", Sha256::digest(input_raw)), hashes[0]);
    assert_eq!(format!("{:x}", Sha256::digest(output_raw)), hashes[1]);
    assert_eq!(format!("{:x}", Sha256::digest(package)), hashes[2]);
    let input: [u64; 512] = core::array::from_fn(|i| {
        u64::from_le_bytes(input_raw[i * 8..i * 8 + 8].try_into().unwrap())
    });
    let output: [u64; 512] = core::array::from_fn(|i| {
        u64::from_le_bytes(output_raw[i * 8..i * 8 + 8].try_into().unwrap())
    });
    assert_eq!((input[2], input[8], input[9]), identity);
    let parsed = model::Model::parse(package).unwrap();
    let mut evaluated = [0; 512];
    native::evaluate(&input, &parsed, &mut evaluated).unwrap();
    assert_eq!(
        evaluated, output,
        "actual scores, selection and full Plan must replay exactly"
    );
    let choices: Vec<_> = (0..input[15] as usize)
        .map(|i| {
            let (action, features) = native::candidate(&input, i).unwrap();
            Candidate { action, features }
        })
        .collect();
    let binding = ModelBinding {
        generation: input[13],
        model_hash: Sha256::digest(package).into(),
        schema_hash: Sha256::digest(include_bytes!("../src/features.rs")).into(),
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
        binding,
        &choices,
        Some(native::prior(&input).unwrap()),
    )
    .unwrap();
    let expected = || root_reply::Expected {
        set: &set,
        sequence: input[2],
        controller: input[3],
        base_version: input[12],
        started_ns: input[4],
        boot_epoch: input[14],
        output_magic: abi::OUTPUT_MAGIC,
    };
    let verified = root_reply::verify(expected(), &output).unwrap();
    assert_eq!(verified.selected, output[4] as usize);
    let decoded = policy_wire::decode_plan(verified.canonical.bytes()).unwrap();
    let legacy = cyxia_prototype::policy::CanonicalPlan::<384>::encode(
        decoded.header,
        &[decoded.action(0).unwrap()],
    )
    .unwrap();
    assert_eq!(verified.canonical.bytes(), legacy.bytes());
    assert_eq!(verified.canonical.storage(), legacy.storage());
    assert_eq!(
        Sha256::digest(verified.canonical.bytes()),
        Sha256::digest(legacy.bytes())
    );
    let begin = std::time::Instant::now();
    for _ in 0..10_000 {
        std::hint::black_box(
            root_reply::verify(expected(), std::hint::black_box(&output)).unwrap(),
        );
    }
    println!(
        "actual_reply_component job={} iterations=10000 verified_bytes={} elapsed_ns={} host_guidance_only=true original_native_combined_ns={}",
        identity.0,
        core::mem::size_of::<root_reply::Verified>(),
        begin.elapsed().as_nanos(),
        original_ns
    );
    for word in [0, 4, 5, 16, 33, 63, 64, 511] {
        let mut changed = output;
        changed[word] ^= 1;
        assert!(
            root_reply::verify(expected(), &changed).is_err(),
            "actual job{} word{word}",
            identity.0
        );
    }
}
#[test]
fn d03_single_action_root_reply_keeps_only_the_one_validated_decision() {
    let choices = [(64, 4), (256, 16)].map(|(pages, batch)| Candidate {
        action: Action::Cache { pages, batch },
        features: features::RawFeatures::default(),
    });
    let (input, package, set) = input_for(&choices, choices[0].action);
    let parsed = model::Model::parse(&package).unwrap();
    let mut output = [0; 512];
    native::evaluate(&input, &parsed, &mut output).unwrap();
    let began = std::time::Instant::now();
    for _ in 0..10_000 {
        let got = root_reply::verify(
            root_reply::Expected {
                set: std::hint::black_box(&set),
                sequence: input[2],
                controller: input[3],
                base_version: input[12],
                started_ns: input[4],
                boot_epoch: input[14],
                output_magic: abi::OUTPUT_MAGIC,
            },
            std::hint::black_box(&output),
        )
        .unwrap();
        std::hint::black_box(got);
    }
    println!(
        "d03_reply_component iterations=10000 verified_bytes={} elapsed_ns={}",
        core::mem::size_of::<root_reply::Verified>(),
        began.elapsed().as_nanos()
    );
    assert!(
        core::mem::size_of::<root_reply::Verified>() <= 1024,
        "the native one-action reply must not initialize/copy sixteen Decision slots"
    );
    let expected = || root_reply::Expected {
        set: &set,
        sequence: input[2],
        controller: input[3],
        base_version: input[12],
        started_ns: input[4],
        boot_epoch: input[14],
        output_magic: abi::OUTPUT_MAGIC,
    };
    for word in (0..8).chain(16..512) {
        let mut changed = output;
        changed[word] ^= 1;
        assert!(
            root_reply::verify(expected(), &changed).is_err(),
            "D03 word {word}"
        );
    }
}
fn input_for(choices: &[Candidate], current: Action) -> ([u64; 512], [u8; 2772], CandidateSet) {
    let bytes = abi::model_bytes();
    let binding = ModelBinding {
        generation: 1,
        model_hash: Sha256::digest(bytes).into(),
        schema_hash: Sha256::digest(include_bytes!("../src/features.rs")).into(),
    };
    let set = CandidateSet::new(
        Snapshot {
            sequence: 1,
            taken_ns: 10,
            ledger_generation: 1,
            core_generation: 1,
        },
        ObjectKey {
            id: 10,
            generation: 1,
        },
        binding,
        choices,
        Some(current),
    )
    .unwrap();
    let mut input = [0; 512];
    input[..16].copy_from_slice(&[
        abi::INPUT_MAGIC,
        3,
        1,
        1,
        10,
        100000000,
        1,
        1,
        u64::from(current.domain()),
        u64::from(current.kind()),
        10,
        1,
        0,
        1,
        1,
        set.len() as u64,
    ]);
    let raw = set.get(0).unwrap().features;
    input[24..32].copy_from_slice(&raw.common);
    input[32..36].copy_from_slice(&raw.domain);
    input[36..40].copy_from_slice(&[
        1,
        1,
        1,
        if current.one_shot() {
            0
        } else {
            10 + POLICY_NS
        },
    ]);
    input[40] = u64::from(raw.domain_present);
    for (at, hash) in [(16, binding.model_hash), (20, set.hash())] {
        for i in 0..4 {
            input[at + i] = u64::from_le_bytes(hash[8 * i..8 * i + 8].try_into().unwrap());
        }
    }
    for (i, c) in set.iter().enumerate() {
        let mut p = [0; 16];
        let n = policy_wire::encode_payload(c.action, i as u16, &mut p).unwrap();
        input[64 + i * 10] = n as u64;
        input[65 + i * 10] = u64::from_le_bytes(p[..8].try_into().unwrap());
        input[66 + i * 10] = u64::from_le_bytes(p[8..].try_into().unwrap());
    }
    let mut prior = [0; 16];
    input[404] = cyxia_prototype::learning::baseline::encode(current, &mut prior).unwrap() as u64;
    input[405] = u64::from_le_bytes(prior[..8].try_into().unwrap());
    input[406] = u64::from_le_bytes(prior[8..].try_into().unwrap());
    (input, bytes, set)
}
fn input() -> ([u64; 512], [u8; 2772]) {
    let choices = [1, 4, 8].map(|v| Candidate {
        action: Action::TxBatch(v),
        features: features::RawFeatures::default(),
    });
    let (input, bytes, _) = input_for(&choices, Action::TxBatch(4));
    (input, bytes)
}
#[test]
fn actual_el0_module_builds_formal_plan_with_stable_integer_argmax() {
    let (input, bytes) = input();
    let model = model::Model::parse(&bytes).unwrap();
    let mut out = [99; 512];
    native::evaluate(&input, &model, &mut out).unwrap();
    assert_eq!(out[4], 0);
    assert_eq!(out[6], 3);
    let raw: Vec<u8> = out[16..64].iter().flat_map(|v| v.to_le_bytes()).collect();
    let plan = policy_wire::decode_plan(&raw[..out[5] as usize]).unwrap();
    assert_eq!(plan.action(0).unwrap().action, Action::TxBatch(1));
    assert!(out[64..].iter().all(|v| *v == 0));
}

#[test]
fn protected_precleared_output_matches_the_general_api() {
    let (input, bytes) = input();
    let model = model::Model::parse(&bytes).unwrap();
    let mut general = [99; 512];
    let mut protected = [0; 512];
    native::evaluate(&input, &model, &mut general).unwrap();
    native::evaluate_precleared(&input, &model, &mut protected).unwrap();
    assert_eq!(protected, general);
    assert!(protected[64..].iter().all(|word| *word == 0));
}

#[test]
fn stopped_offer_owner_state_replays_without_becoming_an_ai_action() {
    let candidate = Candidate {
        action: Action::OfferCpu(100),
        features: features::RawFeatures::default(),
    };
    let (input, bytes, set) = input_for(&[candidate], Action::OfferCpu(0));
    assert_eq!(native::prior(&input), Ok(Action::OfferCpu(0)));
    let model = model::Model::parse(&bytes).unwrap();
    let mut output = [0; 512];
    native::evaluate(&input, &model, &mut output).unwrap();
    let encoded: Vec<_> = output[16..64]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    let plan = policy_wire::decode_plan(&encoded[..output[5] as usize]).unwrap();
    assert_eq!(plan.action(0).unwrap().action, Action::OfferCpu(100));
    let replay = CandidateSet::new(
        set.snapshot,
        set.target,
        set.model,
        &[candidate],
        Some(native::prior(&input).unwrap()),
    )
    .unwrap();
    assert_eq!(replay.hash(), set.hash());
    assert!(
        CandidateSet::new(
            set.snapshot,
            set.target,
            set.model,
            &[
                candidate,
                Candidate {
                    action: Action::OfferCpu(250),
                    ..candidate
                }
            ],
            Some(Action::OfferCpu(0))
        )
        .is_err()
    );
    assert!(
        CandidateSet::new(
            set.snapshot,
            set.target,
            set.model,
            &[Candidate {
                action: Action::OfferCpu(0),
                ..candidate
            }],
            Some(Action::OfferCpu(0))
        )
        .is_err()
    );
    let mut false_family = input;
    false_family[8] = 12;
    assert!(native::prior(&false_family).is_err());
    let mut false_candidate = input;
    false_candidate[65] = 0;
    assert!(native::evaluate(&false_candidate, &model, &mut output).is_err());
}
#[test]
fn el0_rejects_noncanonical_candidate_and_reserved_bits() {
    let (mut input, bytes) = input();
    let model = model::Model::parse(&bytes).unwrap();
    let mut out = [0; 512];
    input[64 + 9] = 1;
    assert_eq!(
        native::evaluate(&input, &model, &mut out),
        Err(domains::Error::Format)
    );
    input[64 + 9] = 0;
    input[65] = (input[65] & !0xffff) | 1;
    assert_eq!(
        native::evaluate(&input, &model, &mut out),
        Err(domains::Error::Conflict)
    );
}

fn replay_candidates(input: &[u64; 512], source: &CandidateSet) -> CandidateSet {
    // The independent evidence verifier reconstructs the immutable set from
    // the recorded native input using this same production decoder.
    let choices: Vec<_> = (0..input[15] as usize)
        .map(|i| {
            let (action, features) = native::candidate(input, i).unwrap();
            Candidate { action, features }
        })
        .collect();
    CandidateSet::new(
        source.snapshot,
        source.target,
        source.model,
        &choices,
        Some(Action::Placement(2)),
    )
    .unwrap()
}

#[test]
fn native_placement_missingness_is_scored_and_bound_by_independent_replay() {
    let raw = features::RawFeatures {
        domain: [0, 0, 0, 120],
        domain_present: 0b1000,
        ..features::RawFeatures::default()
    };
    let choices = [0, 2].map(|choice| Candidate {
        action: Action::Placement(choice),
        features: raw,
    });
    let (mut input, bytes, set) = input_for(&choices, Action::Placement(2));
    let model = model::Model::parse(&bytes).unwrap();
    let mut output = [0; 512];
    native::evaluate(&input, &model, &mut output).unwrap();
    assert_eq!(output[6], 2);
    assert_eq!(native::candidate(&input, 0).unwrap().1, raw);
    assert_eq!(replay_candidates(&input, &set).hash(), set.hash());

    // Changing only missing peer metrics into measured zero must change the
    // hash checked by independent replay, even with identical raw numbers.
    input[40] = u64::from(features::DOMAIN_PRESENT_ALL);
    let changed = replay_candidates(&input, &set);
    assert_ne!(changed.hash(), set.hash());
    assert_eq!(changed.get(0).unwrap().features.domain, raw.domain);

    let mixed = [choices[0], changed.get(1).unwrap()];
    assert_eq!(
        CandidateSet::new(
            set.snapshot,
            set.target,
            set.model,
            &mixed,
            Some(Action::Placement(2))
        )
        .unwrap_err(),
        domains::Error::Conflict
    );
}

#[test]
fn native_decoder_rejects_invalid_presence_and_absent_required_metrics() {
    let (input, bytes) = input();
    let model = model::Model::parse(&bytes).unwrap();
    for (mask, expected) in [
        (0, domains::Error::NotReady),
        (16, domains::Error::Format),
        (1 << 40, domains::Error::Format),
    ] {
        let mut altered = input;
        altered[40] = mask;
        assert_eq!(
            native::evaluate(&altered, &model, &mut [0; 512]),
            Err(expected)
        );
    }
    let raw = features::RawFeatures {
        domain_present: 0b1000,
        ..features::RawFeatures::default()
    };
    let (mut input, _, _) = input_for(
        &[Candidate {
            action: Action::Placement(2),
            features: raw,
        }],
        Action::Placement(2),
    );
    input[32] = 1;
    assert_eq!(native::candidate(&input, 0), Err(domains::Error::Format));
}

#[test]
fn actual_core_control_output_is_checked_against_protected_root_job() {
    let choices = [2, 6].map(|mask| Candidate {
        action: Action::ControlSet(mask),
        features: features::RawFeatures {
            control_capacity: Some(u64::from(mask.count_ones()) * 1000),
            ..features::RawFeatures::default()
        },
    });
    let (mut input, bytes, set) = input_for(&choices, Action::ControlSet(2));
    for (i, candidate) in choices.iter().enumerate() {
        input[64 + i * 10 + 8] = candidate.features.control_capacity.unwrap();
    }
    let model = model::Model::parse(&bytes).unwrap();
    let mut output = [0; 512];
    native::evaluate(&input, &model, &mut output).unwrap();
    let expected = || root_reply::Expected {
        set: &set,
        sequence: 1,
        controller: 1,
        base_version: 0,
        started_ns: 10,
        boot_epoch: 1,
        output_magic: abi::OUTPUT_MAGIC,
    };
    let reply = root_reply::verify(expected(), &output).unwrap();
    assert_eq!(reply.action, Action::ControlSet(2));
    assert_eq!(reply.selected, 0);
    assert_eq!(reply.scores[0], reply.scores[1]);
    let plan = policy_wire::decode_plan(reply.canonical.bytes()).unwrap();
    assert_eq!(plan.action(0).unwrap().envelope.target, set.target);
    assert_eq!(plan.header.active_until_local_ns, 0);
    // EL0 cannot change the owning root identity, selection, model, frozen
    // snapshot, or canonical padding even when all scores look plausible.
    for word in [0, 1, 2, 3, 4, 5, 6, 7].into_iter().chain(16..512) {
        let mut changed = output;
        changed[word] ^= 1;
        assert!(
            root_reply::verify(expected(), &changed).is_err(),
            "word {word}"
        );
    }
    let mut wrong = expected();
    wrong.base_version = 1;
    assert!(root_reply::verify(wrong, &output).is_err());
    let mut wrong = expected();
    wrong.started_ns = 11;
    assert!(root_reply::verify(wrong, &output).is_err());
    let mut wrong_set = set;
    wrong_set.target.generation += 1;
    let mut wrong = expected();
    wrong.set = &wrong_set;
    assert!(root_reply::verify(wrong, &output).is_err());
}
