pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use domains::{Action, ObjectKey, POLICY_NS};
use sha2::{Digest, Sha256};
fn input() -> ([u64; 512], [u8; 2772]) {
    let bytes = abi::model_bytes();
    let binding = ModelBinding {
        generation: 1,
        model_hash: Sha256::digest(bytes).into(),
        schema_hash: Sha256::digest(include_bytes!("../src/features.rs")).into(),
    };
    let choices = [1, 4, 8].map(|v| Candidate {
        action: Action::TxBatch(v),
        features: features::RawFeatures::default(),
    });
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
        &choices,
        Some(Action::TxBatch(4)),
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
        10,
        1,
        10,
        1,
        0,
        1,
        1,
        3,
    ]);
    input[36..40].copy_from_slice(&[1, 1, 1, 10 + POLICY_NS]);
    for (at, hash) in [(16, binding.model_hash), (20, set.hash())] {
        for i in 0..4 {
            input[at + i] = u64::from_le_bytes(hash[8 * i..8 * i + 8].try_into().unwrap());
        }
    }
    for (i, c) in choices.into_iter().enumerate() {
        let mut p = [0; 16];
        let n = policy_wire::encode_payload(c.action, i as u16, &mut p).unwrap();
        input[64 + i * 10] = n as u64;
        input[65 + i * 10] = u64::from_le_bytes(p[..8].try_into().unwrap());
        input[66 + i * 10] = u64::from_le_bytes(p[8..].try_into().unwrap());
    }
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
