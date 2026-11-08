//! Independently replay the full MLP/typed candidate/Plan identity behind each
//! captured native owner transition. This never produces native observations.
pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use sha2::{Digest, Sha256};
use std::{env, fs};
const ROW: usize = 896;
const WORDS: usize = 128 + 8 * ROW;
fn require(ok: bool, msg: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(msg.into()) }
}
fn digest(words: &[u64]) -> [u8; 32] {
    let mut h = Sha256::new();
    for value in words {
        h.update(value.to_le_bytes());
    }
    h.finalize().into()
}
fn hash(words: &[u64], at: usize) -> [u8; 32] {
    let mut h = [0; 32];
    for i in 0..4 {
        h[i * 8..i * 8 + 8].copy_from_slice(&words[at + i].to_le_bytes());
    }
    h
}
fn replay(row: &[u64], package: &[u8], schema: [u8; 32]) -> Result<[u64; 2], String> {
    let r = &row[192..832];
    let input: [u64; 512] = r[32..544].try_into().unwrap();
    require(
        input[0] == abi::INPUT_MAGIC && input[1] == 3 && input[8..10] == [1, 2],
        "not the actual ABI3 CoreSet scorer",
    )?;
    let model_hash: [u8; 32] = Sha256::digest(package).into();
    let model = model::Model::parse(package).map_err(|e| format!("model {e:?}"))?;
    require(
        hash(&input, 16) == model_hash
            && hash(&row[128..160], 16) == model_hash
            && hash(&row[128..160], 20) == schema
            && digest(&input) == hash(r, 608),
        "model/schema/raw input hash mismatch",
    )?;
    let binding = ModelBinding {
        generation: input[13],
        model_hash,
        schema_hash: schema,
    };
    let mut choices = Vec::new();
    require(
        (2..=32).contains(&input[15]),
        "two legal alternatives required",
    )?;
    for index in 0..input[15] as usize {
        let (action, features) =
            native::candidate(&input, index).map_err(|e| format!("candidate {e:?}"))?;
        require(
            matches!(action, domains::Action::ControlSet(2 | 6)),
            "non-CoreSet alternative",
        )?;
        choices.push(Candidate { action, features });
    }
    let current = native::prior(&input).map_err(|e| format!("prior {e:?}"))?;
    require(
        current == domains::Action::ControlSet(row[34]),
        "prior is not actual source owner",
    )?;
    let set = CandidateSet::new(
        Snapshot {
            sequence: input[38],
            taken_ns: input[4],
            ledger_generation: input[7],
            core_generation: input[6],
        },
        domains::ObjectKey {
            id: input[10],
            generation: input[11],
        },
        binding,
        &choices,
        Some(current),
    )
    .map_err(|e| format!("candidate set {e:?}"))?;
    require(
        set.hash() == hash(&input, 20),
        "typed candidate ordering/hash differs",
    )?;
    let mut output = [0; 512];
    native::evaluate(&input, &model, &mut output).map_err(|e| format!("full MLP replay {e:?}"))?;
    require(
        output[..64] == r[544..608] && digest(&output) == hash(r, 21),
        "actual output/full score/Plan hash differs from model replay",
    )?;
    require(
        r[17] == output[4] && r[13] == row[12] && r[14..16] == [2, 0] && r[30] == 1,
        "model output has no actual matching APPLIED version",
    )?;
    let mut bytes = [0u8; 384];
    for (i, v) in output[16..64].iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    require(output[5] as usize <= bytes.len(), "oversized Plan")?;
    let plan = policy_wire::decode_plan(&bytes[..output[5] as usize])
        .map_err(|e| format!("Plan {e:?}"))?;
    require(
        plan.len() == 1,
        "actual CoreAction requires a one-action Plan",
    )?;
    let action = plan.action(0).unwrap();
    let e = action.envelope;
    require(
        plan.header.controller_epoch == row[3]
            && plan.header.plan_seq == row[4]
            && row[5] == 0
            && e.controller_epoch == row[3]
            && e.decision_seq == row[14]
            && e.target.id == row[6]
            && e.target.generation == row[7]
            && action.action == domains::Action::ControlSet(row[8])
            && e.candidate_set_hash == set.hash()
            && e.model_hash == model_hash
            && plan.header.base_plan_version == input[12]
            && r[13] > plan.header.base_plan_version,
        "CoreAction/ApplyId/DecisionKey differs from actual selected Plan",
    )?;
    require(
        r[10].saturating_add(r[11]).saturating_add(r[29]) <= 2_000_000
            && r[12] <= 500_000
            && r[9] >= r[8]
            && r[9] - r[8] <= 50_000_000,
        "published scorer exceeded unchanged CPU/wall/publication budgets",
    )?;
    Ok([input[24], input[26]])
}
fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    require(
        args.len() == 3,
        "usage: verify-ownership-evidence CAPTURE RAW_MODEL",
    )?;
    let data = fs::read(&args[1]).map_err(|e| e.to_string())?;
    require(data.len() == WORDS * 8, "wrong ownership bank size")?;
    let words: Vec<u64> = data
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    require(
        words[0] == 0x43594f574e313531
            && words[1] == 1
            && words[4] >= 2
            && words[4] <= 8
            && words[5] == 0
            && words[6] == 0,
        "missing complete native owner bank",
    )?;
    let package = fs::read(&args[2]).map_err(|e| e.to_string())?;
    let schema: [u8; 32] = Sha256::digest(include_bytes!("../src/features.rs")).into();
    let mut pressure = Vec::new();
    for i in 0..words[4] as usize {
        let row = &words[128 + i * ROW..128 + (i + 1) * ROW];
        require(
            row[0] > 0 && row[0].is_multiple_of(2) && row[1] == 31,
            "unsettled actual ownership chain",
        )?;
        pressure.push(replay(row, &package, schema)?);
    }
    require(
        pressure[0][0] > pressure[1][0] || pressure[0][1] > pressure[1][1],
        "control-load decline is not present in actual observed input",
    )?;
    println!(
        "{{\"status\":\"MODEL_REPLAY_VALID\",\"replayed\":{},\"full_integer_mlp\":true,\"native_acceptance_status\":\"NOT_RUN\"}}",
        words[4]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put_hash(words: &mut [u64], at: usize, hash: [u8; 32]) {
        for (i, b) in hash.chunks_exact(8).enumerate() {
            words[at + i] = u64::from_le_bytes(b.try_into().unwrap());
        }
    }
    fn fixture() -> (Vec<u64>, Vec<u8>, [u8; 32]) {
        let package = abi::domain_model_bytes().to_vec();
        let model_hash = Sha256::digest(&package).into();
        let schema: [u8; 32] = Sha256::digest(include_bytes!("../src/features.rs")).into();
        let model = model::Model::parse(&package).unwrap();
        let binding = ModelBinding {
            generation: 1,
            model_hash,
            schema_hash: schema,
        };
        let raw = features::RawFeatures {
            common: [700, 0, 10, 0, 0, 0, 0, 0],
            domain_present: features::DOMAIN_PRESENT_ALL,
            ..Default::default()
        };
        let choices = [2u64, 6].map(|mask| Candidate {
            action: domains::Action::ControlSet(mask),
            features: features::RawFeatures {
                control_capacity: Some(mask.count_ones() as u64 * 1000),
                ..raw
            },
        });
        let snapshot = Snapshot {
            sequence: 20,
            taken_ns: 1_000_000_000,
            ledger_generation: 9,
            core_generation: 1,
        };
        let set = CandidateSet::new(
            snapshot,
            domains::ObjectKey {
                id: 50,
                generation: 1,
            },
            binding,
            &choices,
            Some(domains::Action::ControlSet(2)),
        )
        .unwrap();
        let mut input = [0; 512];
        input[..16].copy_from_slice(&[
            abi::INPUT_MAGIC,
            3,
            20,
            1,
            snapshot.taken_ns,
            1_000_000,
            1,
            9,
            1,
            2,
            50,
            1,
            0,
            1,
            7,
            2,
        ]);
        put_hash(&mut input, 16, model_hash);
        put_hash(&mut input, 20, set.hash());
        input[24..32].copy_from_slice(&raw.common);
        input[40] = u64::from(raw.domain_present);
        input[36..39].copy_from_slice(&[20; 3]);
        input[39] = if choices[0].action.one_shot() {
            0
        } else {
            snapshot.taken_ns + 10_000_000_000
        };
        for (i, c) in choices.iter().enumerate() {
            let mut payload = [0; 16];
            let n = policy_wire::encode_payload(c.action, i as u16, &mut payload).unwrap();
            let at = 64 + i * 10;
            input[at] = n as u64;
            input[at + 1] = u64::from_le_bytes(payload[..8].try_into().unwrap());
            input[at + 2] = u64::from_le_bytes(payload[8..].try_into().unwrap());
            input[at + 8] = c.features.control_capacity.unwrap();
        }
        input[400..404].copy_from_slice(&[2, 13, 15, 0]);
        let mut prior = [0; 16];
        input[404] = policy_wire::encode_payload(domains::Action::ControlSet(2), 0, &mut prior)
            .unwrap() as u64;
        input[405] = u64::from_le_bytes(prior[..8].try_into().unwrap());
        input[406] = u64::from_le_bytes(prior[8..].try_into().unwrap());
        let mut output = [0; 512];
        native::evaluate(&input, &model, &mut output).unwrap();
        let selected = output[4] as usize;
        let domains::Action::ControlSet(actual) = choices[selected].action else {
            unreachable!()
        };
        let mut row = vec![0; 896];
        row[2..9].copy_from_slice(&[7, 1, 20, 0, 50, 1, actual]);
        row[12] = 1;
        row[14] = 20;
        row[18] = 1;
        row[19] = 9;
        row[34] = 2;
        put_hash(&mut row, 144, model_hash);
        put_hash(&mut row, 148, schema);
        let r = &mut row[192..832];
        r[8] = snapshot.taken_ns;
        r[9] = snapshot.taken_ns + 1_000;
        r[10] = 100;
        r[11] = 100;
        r[12] = 100;
        r[13] = 1;
        r[14] = 2;
        r[17] = selected as u64;
        r[19] = 1;
        r[30] = 1;
        r[32..544].copy_from_slice(&input);
        r[544..608].copy_from_slice(&output[..64]);
        put_hash(r, 608, digest(&input));
        put_hash(r, 21, digest(&output));
        (row, package, schema)
    }
    #[test]
    fn full_mlp_and_plan_replay_reject_score_key_and_rehashed_candidate_mutations() {
        let (row, package, schema) = fixture();
        assert!(replay(&row, &package, schema).is_ok());
        for index in [192 + 544 + 8, 192 + 544 + 4, 6, 192 + 21] {
            let mut bad = row.clone();
            bad[index] ^= 1;
            assert!(
                replay(&bad, &package, schema).is_err(),
                "mutation {index} escaped actual model/Plan replay"
            );
        }
        let mut bad = row.clone();
        bad[192 + 32 + 20] ^= 1;
        let h = digest(&bad[224..736]);
        put_hash(&mut bad[192..832], 608, h);
        assert!(
            replay(&bad, &package, schema).is_err(),
            "rehashing raw bytes bypassed typed CandidateSet hash"
        );
    }
}
