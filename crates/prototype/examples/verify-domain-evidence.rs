//! Replay captured native inputs through the exact isolated-controller source.
//! Requires real guest captures; never generates native execution evidence.
pub use cyxia_prototype::{domains, features, model, policy_wire};
#[allow(dead_code)]
#[path = "../../../user/prototype-runtime/abi.rs"]
mod abi;
#[path = "../../../user/prototype-runtime/native.rs"]
mod native;
use cyxia_prototype::policy::{Candidate, CandidateSet, ModelBinding, Snapshot};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs};

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn hash(words: &[u64], at: usize) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&words[at + i].to_le_bytes());
    }
    out
}
fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    require(
        (2..=3).contains(&args.len()),
        "usage: verify-domain-evidence CAPTURE [RAW_MODEL]",
    )?;
    let data = fs::read(&args[1]).map_err(|e| e.to_string())?;
    require(
        data.len() == (512 + 64 * 640) * 8,
        "incorrect native evidence size",
    )?;
    let words: Vec<u64> = data
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect();
    require(
        words[0] == 0x435958444f4d3031 && words[1] == 1 && words[2] > 0,
        "native evidence header",
    )?;
    require(
        words[3] == (1 << 18) - 1 && words[12] == 64 && words[13] == 640,
        "all eighteen action families must be registered",
    )?;
    require(words[25] == 0, "native resource confirmation failed")?;
    require(words[28] == 0, "native stability receipt failed")?;
    let package = if args.len() == 3 {
        fs::read(&args[2]).map_err(|e| e.to_string())?
    } else {
        abi::domain_model_bytes().to_vec()
    };
    let parsed = model::Model::parse(&package).map_err(|e| format!("model: {e:?}"))?;
    let model_hash: [u8; 32] = Sha256::digest(&package).into();
    let schema_hash: [u8; 32] = Sha256::digest(include_bytes!("../src/features.rs")).into();
    require(
        hash(&words, 16) == model_hash && hash(&words, 20) == schema_hash,
        "capture model/schema differs from verifier build",
    )?;
    let mut seen = BTreeSet::new();
    let mut replayed = 0;
    let mut accepted = 0;
    let mut applied = 0;
    let mut rejected = 0;
    let mut aborted = 0;
    let mut interrupted = 0;
    let mut invalid_replies = 0;
    let mut domains = BTreeSet::new();
    let mut applied_domains = BTreeSet::new();
    let mut versions = BTreeSet::new();
    for slot in 0..64 {
        let r = &words[512 + slot * 640..512 + (slot + 1) * 640];
        if r[639] & 1 != 0 {
            interrupted += 1;
            continue;
        }
        if r[0] == 0 {
            continue;
        }
        require(
            r[0] == r[1] && seen.insert(r[1]),
            "duplicate or mismatched native sequence",
        )?;
        let input: [u64; 512] = r[32..544].try_into().unwrap();
        require(
            input[2] == r[1]
                && input[3] == r[6]
                && input[8] == r[2]
                && input[9] == r[3]
                && input[10] == r[4]
                && input[11] == r[5]
                && input[14] == words[2]
                && r[7] == words[2],
            "input identity binding",
        )?;
        let mut digest = Sha256::new();
        for word in input {
            digest.update(word.to_le_bytes());
        }
        require(
            <[u8; 32]>::from(digest.finalize()) == hash(r, 608),
            "raw input hash",
        )?;
        let binding = ModelBinding {
            generation: input[13],
            model_hash,
            schema_hash,
        };
        require(
            hash(&input, 16) == model_hash && binding.generation == words[14],
            "active model binding",
        )?;
        let mut choices = Vec::new();
        for index in 0..usize::try_from(input[15]).map_err(|e| e.to_string())? {
            let (action, features) =
                native::candidate(&input, index).map_err(|e| format!("candidate: {e:?}"))?;
            choices.push(Candidate { action, features });
        }
        let current = native::prior(&input).map_err(|e| format!("prior: {e:?}"))?;
        if let domains::Action::ControlSet(mask) = current {
            require(mask == input[400], "current control ownership binding")?;
        }
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
        .map_err(|e| format!("candidate set: {e:?}"))?;
        require(
            set.len() == choices.len() && set.hash() == hash(&input, 20),
            "candidate set hash/order",
        )?;
        for dependency in input[408..416].chunks_exact(4) {
            if dependency[0] == 0 {
                require(
                    dependency == [0; 4],
                    "absent prerequisite has nonzero identity",
                )?;
            } else {
                require(
                    dependency[0] <= 16
                        && cyxia_prototype::policy::dependency_allowed(
                            dependency[0] as u16,
                            r[2] as u16,
                        )
                        && dependency[1] != 0
                        && dependency[2] != 0,
                    "invalid fixed prerequisite binding",
                )?;
            }
        }
        if r[30] == 0 {
            continue;
        }
        require(
            r[9] >= r[8] && r[14] >= 1 && r[14] <= 4,
            "receipt time/state",
        )?;
        if r[19] == 0 {
            require(
                r[13] == 0 && r[14] == 3 && r[17] == u64::MAX,
                "aborted reply must not publish",
            )?;
            aborted += 1;
            continue;
        }
        let mut expected = [0; 512];
        native::evaluate(&input, &parsed, &mut expected).map_err(|e| format!("replay: {e:?}"))?;
        if expected[..64] != r[544..608] {
            require(
                r[13] == 0 && r[14] == 3 && r[15] != 0,
                "invalid EL0 reply reached publication",
            )?;
            invalid_replies += 1;
            rejected += 1;
            continue;
        }
        require(
            expected[..64] == r[544..608],
            "EL0 reply differs from exact schema/model/Plan replay",
        )?;
        // Admission can reject an authentic reply before decoding a selection:
        // elapsed/CPU overflow or a changed protected snapshot generation. The
        // raw reply still must replay exactly, and no version may be published.
        // Every decoded or published selection must retain the exact index.
        let rejected_before_selection = r[13] == 0
            && r[14] == 3
            && matches!(r[15], 4 | 8 | 19)
            && r[17] == u64::MAX;
        require(r[17] == expected[4] || rejected_before_selection,
            "selected candidate receipt binding")?;
        replayed += 1;
        domains.insert(r[2]);
        if r[13] == 0 {
            require(
                r[14] == 3 && r[15] != 0,
                "rejected inference must retain an error",
            )?;
            rejected += 1;
            continue;
        }
        require(versions.insert(r[13]), "duplicate publication version")?;
        require(
            r[9] - r[8] <= 50_000_000
                && r[10].saturating_add(r[11]).saturating_add(r[29]) <= 2_000_000,
            "published inference exceeded admission budget",
        )?;
        require(
            r[18] == u64::from(r[12] > 500_000),
            "publication overrun flag",
        )?;
        require(
            r[12] <= 500_000,
            "published policy exceeded publication budget",
        )?;
        accepted += 1;
        if r[14] == 2 {
            require(
                r[28] >= r[9],
                "executor completion predates publication receipt",
            )?;
            applied += 1;
            applied_domains.insert(r[2]);
        }
    }
    require(
        replayed > 0 && accepted > 0 && applied > 0,
        "no real replayable publication and execution",
    )?;
    println!(
        "{{\"status\":\"PASS\",\"boot_epoch\":{},\"replayed\":{replayed},\"accepted\":{accepted},\"applied\":{applied},\"rejected\":{rejected},\"invalid_replies\":{invalid_replies},\"aborted\":{aborted},\"interrupted_slots\":{interrupted},\"domains\":{:?},\"applied_domains\":{:?},\"trained_model\":false,\"physical_realtime_verified\":false}}",
        words[2],
        domains.into_iter().collect::<Vec<_>>(),
        applied_domains.into_iter().collect::<Vec<_>>()
    );
    Ok(())
}
