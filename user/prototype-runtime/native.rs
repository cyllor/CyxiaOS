//! ABI3: score protected, typed candidates and return a formal one-action plan.
use crate::{
    abi,
    domains::{Action, Error},
    features::{self, RawFeatures, TargetFeatures},
    model,
    policy_wire::{self, Decision, Envelope, PlanHeader},
};
pub const ABI: u64 = 3;
pub const INPUT_WORDS: usize = 512;
pub const OUTPUT_WORDS: usize = 512;

pub fn candidate(input: &[u64; INPUT_WORDS], index: usize) -> Result<(Action, RawFeatures), Error> {
    if index >= 32 || index >= usize::try_from(input[15]).map_err(|_| Error::Range)? {
        return Err(Error::Range);
    }
    let at = 64 + index * 10;
    let len = usize::try_from(input[at]).map_err(|_| Error::Range)?;
    if !(3..=16).contains(&len)
        || input[at + 7] & !15 != 0
        || input[at + 9] != 0
        || input[40] & !u64::from(features::DOMAIN_PRESENT_ALL) != 0
    {
        return Err(Error::Format);
    }
    let mut payload = [0; 16];
    payload[..8].copy_from_slice(&input[at + 1].to_le_bytes());
    payload[8..].copy_from_slice(&input[at + 2].to_le_bytes());
    if payload[len..].iter().any(|b| *b != 0) {
        return Err(Error::Format);
    }
    let (action, encoded_index) = policy_wire::decode_payload(
        u16::try_from(input[8]).map_err(|_| Error::Range)?,
        u16::try_from(input[9]).map_err(|_| Error::Range)?,
        &payload[..len],
    )?;
    if usize::from(encoded_index) != index {
        return Err(Error::Conflict);
    }
    let mut target = TargetFeatures::default();
    for i in 0..4 {
        if input[at + 7] & (1 << i) != 0 {
            target.values[i] = Some(input[at + 3 + i]);
        } else if input[at + 3 + i] != 0 {
            return Err(Error::Format);
        }
    }
    let control_capacity = if matches!(action, Action::ControlSet(_)) {
        Some(input[at + 8])
    } else {
        if input[at + 8] != 0 {
            return Err(Error::Format);
        }
        None
    };
    let raw = RawFeatures {
        common: input[24..32].try_into().map_err(|_| Error::Format)?,
        domain: input[32..36].try_into().map_err(|_| Error::Format)?,
        domain_present: input[40] as u8,
        target,
        control_capacity,
    };
    features::encode(action, raw)?;
    Ok((action, raw))
}
fn hash(input: &[u64; INPUT_WORDS], at: usize) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&input[at + i].to_le_bytes());
    }
    out
}
pub fn evaluate(
    input: &[u64; INPUT_WORDS],
    model: &model::Model<'_>,
    output: &mut [u64; OUTPUT_WORDS],
) -> Result<(), Error> {
    if input[0] != abi::INPUT_MAGIC
        || input[1] != ABI
        || [2, 3, 5, 6, 7, 10, 11, 13, 14, 36, 37, 38]
            .iter()
            .any(|i| input[*i] == 0)
        || !(1..=32).contains(&input[15])
    {
        return Err(Error::Format);
    }
    let count = input[15] as usize;
    let mut selected = 0;
    let mut best = i16::MIN;
    let mut scores = [0i16; 32];
    let mut previous = None;
    for (index, score) in scores.iter_mut().take(count).enumerate() {
        let (action, raw) = candidate(input, index)?;
        if previous.is_some_and(|old| old >= action.order()) {
            return Err(Error::Conflict);
        }
        previous = Some(action.order());
        *score = model.score(&features::encode(action, raw)?.values);
        if index == 0 || *score > best {
            best = *score;
            selected = index;
        }
    }
    let (action, _) = candidate(input, selected)?;
    let header = PlanHeader {
        plan_seq: input[37],
        base_plan_version: input[12],
        active_model_generation: input[13],
        controller_epoch: input[3],
        snapshot_seq: input[38],
        active_until_local_ns: input[39],
    };
    let decision = Decision {
        action,
        candidate_index: selected as u16,
        envelope: Envelope {
            controller_epoch: input[3],
            decision_seq: input[36],
            snapshot_seq: input[38],
            target: crate::domains::ObjectKey {
                id: input[10],
                generation: input[11],
            },
            ledger_generation: input[7],
            core_generation: input[6],
            expires_local_ns: input[4]
                .checked_add(crate::domains::WINDOW_NS)
                .ok_or(Error::Overflow)?,
            model_hash: hash(input, 16),
            candidate_set_hash: hash(input, 20),
        },
    };
    let mut bytes = [0u8; 384];
    let len = policy_wire::encode_plan(header, &[decision], &mut bytes)?;
    output.fill(0);
    output[..8].copy_from_slice(&[
        abi::OUTPUT_MAGIC,
        ABI,
        input[2],
        input[3],
        selected as u64,
        len as u64,
        count as u64,
        input[14],
    ]);
    for (i, score) in scores.into_iter().enumerate() {
        output[8 + i / 4] |= u64::from(score as u16) << (16 * (i % 4));
    }
    for (i, chunk) in bytes[..len].chunks(8).enumerate() {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        output[16 + i] = u64::from_le_bytes(word);
    }
    Ok(())
}
