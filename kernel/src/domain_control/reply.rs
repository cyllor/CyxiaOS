//! Canonical root verification shared by policy publication and ordinary
//! read-only CACP work. This module cannot publish or create executor custody.
use cyxia_prototype::{
    domains::{Action, Error, POLICY_NS, WINDOW_NS},
    policy::CandidateSet,
    policy_wire::{self, Decision, Envelope, PlanHeader},
};

pub(super) struct Expected<'a> {
    pub set: &'a CandidateSet,
    pub sequence: u64,
    pub controller: u64,
    pub base_version: u64,
    pub started_ns: u64,
    pub boot_epoch: u64,
    pub output_magic: u64,
}
pub(super) struct Verified {
    pub action: Action,
    pub selected: usize,
    pub scores: [i16; 32],
    pub bytes: [u8; 384],
    pub len: usize,
}
pub(super) fn verify(expected: Expected<'_>, output: &[u64; 512]) -> Result<Verified, Error> {
    let set = expected.set;
    if output[..4]
        != [
            expected.output_magic,
            3,
            expected.sequence,
            expected.controller,
        ]
        || output[6] != set.len() as u64
        || output[7] != expected.boot_epoch
    {
        return Err(Error::Format);
    }
    let selected = usize::try_from(output[4]).map_err(|_| Error::Range)?;
    let candidate = set.get(selected).ok_or(Error::Range)?;
    let (mut best, mut best_score) = (0, i16::MIN);
    let mut scores = [0i16; 32];
    for (i, score) in scores.iter_mut().enumerate() {
        *score = ((output[8 + i / 4] >> (16 * (i % 4))) as u16) as i16;
        if i < set.len() {
            if i == 0 || *score > best_score {
                best = i;
                best_score = *score;
            }
        } else if *score != 0 {
            return Err(Error::Format);
        }
    }
    if best != selected {
        return Err(Error::Conflict);
    }
    let header = PlanHeader {
        plan_seq: expected.sequence,
        base_plan_version: expected.base_version,
        active_model_generation: set.model.generation,
        controller_epoch: expected.controller,
        snapshot_seq: set.snapshot.sequence,
        active_until_local_ns: if candidate.action.one_shot() {
            0
        } else {
            expected
                .started_ns
                .checked_add(POLICY_NS)
                .ok_or(Error::Overflow)?
        },
    };
    let decision = Decision {
        action: candidate.action,
        candidate_index: selected as u16,
        envelope: Envelope {
            controller_epoch: expected.controller,
            decision_seq: expected.sequence,
            snapshot_seq: set.snapshot.sequence,
            target: set.target,
            ledger_generation: set.snapshot.ledger_generation,
            core_generation: set.snapshot.core_generation,
            expires_local_ns: expected
                .started_ns
                .checked_add(WINDOW_NS)
                .ok_or(Error::Overflow)?,
            model_hash: set.model.model_hash,
            candidate_set_hash: set.hash(),
        },
    };
    let mut canonical = [0; 384];
    let len = policy_wire::encode_plan(header, &[decision], &mut canonical)?;
    let mut bytes = [0u8; 384];
    for (i, word) in output[16..64].iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    if output[5] != len as u64 || bytes != canonical || output[64..].iter().any(|v| *v != 0) {
        return Err(Error::Conflict);
    }
    Ok(Verified {
        action: candidate.action,
        selected,
        scores,
        bytes,
        len,
    })
}
