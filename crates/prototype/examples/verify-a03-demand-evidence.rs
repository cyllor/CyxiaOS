//! Exact model/CandidateSet/Plan replay of the retained ordinary quiet job.
//! This proves no native execution or Applied ownership by itself.
pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use sha2::{Digest, Sha256};
use std::{env, fs};
fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn words(path: &str, count: usize) -> Result<Vec<u64>, String> {
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    require(raw.len() == count * 8, "wrong raw evidence width")?;
    Ok(raw
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect())
}
fn hash(w: &[u64], at: usize) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&w[at + i].to_le_bytes());
    }
    out
}
fn digest(w: &[u64]) -> [u8; 32] {
    let mut h = Sha256::new();
    for v in w {
        h.update(v.to_le_bytes());
    }
    h.finalize().into()
}
fn main() -> Result<(), String> {
    let a: Vec<_> = env::args().collect();
    require(
        a.len() == 5,
        "usage: verify-a03-demand-evidence QUIET_RECORD RAW_MODEL DEMAND CONTROL",
    )?;
    let row = words(&a[1], 640)?;
    let demand = words(&a[3], 128)?;
    let control = words(&a[4], 512 + 64 * 640)?;
    let package = fs::read(&a[2]).map_err(|e| e.to_string())?;
    let schema: [u8; 32] = Sha256::digest(include_bytes!("../src/features.rs")).into();
    let model_hash: [u8; 32] = Sha256::digest(&package).into();
    let parsed = model::Model::parse(&package).map_err(|e| format!("model: {e:?}"))?;
    require(
        demand[0..4] == [0x4359413033443136, 1, 128, 1]
            && demand[4] > 0
            && demand[4] % 2 == 0
            && demand[5] == 6
            && demand[14] == 0,
        "ordinary scene has not completed",
    )?;
    require(
        control[0..2] == [0x435958444f4d3031, 1]
            && control[2] > 0
            && control[3] == (1 << 18) - 1
            && control[12..14] == [64, 640]
            && hash(&control, 16) == model_hash
            && hash(&control, 20) == schema,
        "wrong ordinary control/model/schema identity",
    )?;
    let input: [u64; 512] = row[32..544].try_into().unwrap();
    require(
        row[639] > 0
            && row[639] % 2 == 0
            && row[0] == row[1]
            && row[0] == demand[40]
            && row[13] == demand[41]
            && row[13] > 0
            && matches!(row[14], 1 | 2)
            && row[15] == 0
            && row[19] == 1
            && row[30] == 1,
        "quiet job is not the retained successful ordinary root reply",
    )?;
    require(
        input[0..2] == [abi::INPUT_MAGIC, 3]
            && input[8..10] == [1, 2]
            && input[2] == row[0]
            && input[3] == row[6]
            && input[10..12] == row[4..6]
            && input[14] == row[7]
            && row[7] == control[2]
            && input[13] == control[14]
            && hash(&input, 16) == model_hash
            && digest(&input) == hash(&row, 608),
        "actual ABI3 input identity/hash mismatch",
    )?;
    require(
        input[4] == demand[43]
            && input[4] > demand[10]
            && row[8] >= input[4]
            && row[9] >= row[8]
            && demand[42] >= row[9]
            && demand[11] >= demand[42]
            && row[9] - row[8] <= 50_000_000
            && row[10].saturating_add(row[11]).saturating_add(row[29]) <= 2_000_000
            && row[12].checked_add(row[29]).is_some_and(|v| v <= 500_000)
            && row[18] == 0,
        "quiet input predates drain or exceeds unchanged inference/publication budgets",
    )?;
    require((1..=2).contains(&input[15]), "CoreSet candidate bound")?;
    let mut choices = Vec::new();
    for index in 0..input[15] as usize {
        let (action, features) =
            native::candidate(&input, index).map_err(|e| format!("candidate: {e:?}"))?;
        require(
            matches!(action, domains::Action::ControlSet(2 | 6)),
            "wrong CoreSet alternative",
        )?;
        choices.push(Candidate { action, features });
    }
    let prior = native::prior(&input).map_err(|e| format!("prior: {e:?}"))?;
    require(
        prior == domains::Action::ControlSet(input[400]),
        "prior differs from actual source owner",
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
        ModelBinding {
            generation: input[13],
            model_hash,
            schema_hash: schema,
        },
        &choices,
        Some(prior),
    )
    .map_err(|e| format!("CandidateSet: {e:?}"))?;
    require(
        set.hash() == hash(&input, 20),
        "typed candidate ordering/hash mismatch",
    )?;
    let mut expected = [0; 512];
    native::evaluate(&input, &parsed, &mut expected)
        .map_err(|e| format!("full MLP/Plan: {e:?}"))?;
    require(
        expected[..64] == row[544..608]
            && digest(&expected) == hash(&row, 21)
            && expected[4] == row[17],
        "full integer scores/selected Plan/output digest mismatch",
    )?;
    let selected = choices[expected[4] as usize].action;
    let domains::Action::ControlSet(selected) = selected else {
        return Err("not CoreSet".into());
    };
    println!(
        "{{\"status\":\"QUIET_MODEL_REPLAY_VALID\",\"full_integer_mlp\":true,\"job\":{},\"version\":{},\"prior_control\":{},\"selected_control\":{},\"native_acceptance_status\":\"NOT_RUN\",\"applied_owner_verified\":false}}",
        row[0], row[13], input[400], selected
    );
    Ok(())
}
