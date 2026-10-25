pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use domains::{Action, ObjectKey, POLICY_NS};
use sha2::{Digest, Sha256};
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
