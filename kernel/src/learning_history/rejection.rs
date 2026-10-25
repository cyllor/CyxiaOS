//! Lossless negative journal rows for an actual rejected root publication.
//! These rows contain the original Plan bytes, never a scored model input or
//! an execution receipt. Only the protected root supplies their authority.
use cyxia_prototype::{
    domains::Error,
    policy::{ExecutionState, ModelBinding, PlanReceipt, Snapshot},
    policy_wire::{self, Decision, PlanHeader},
};
use sha2::{Digest, Sha256};

pub(super) const FLAG: u64 = 128;
pub(super) const SLOT_BYTES: usize = 6144;
pub(super) const PLAN_OFFSET: usize = 2048;
const HEADER_BYTES: usize = 768;

#[derive(Clone, Copy)]
pub(super) struct Facts {
    pub receipt: PlanReceipt,
    pub snapshot: Snapshot,
    pub header: PlanHeader,
    pub decision: Decision,
    pub model: ModelBinding,
    pub received_ns: u64,
    pub observed_ns: u64,
    pub wall_deadline_ns: u64,
    pub plan_hash: [u8; 32],
}

fn put(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed rejection field"),
    )
}
fn state(value: ExecutionState) -> (u64, u64) {
    match value {
        ExecutionState::Pending => (0, 0),
        ExecutionState::Applied => (1, 0),
        ExecutionState::Unknown => (2, 0),
        ExecutionState::Failed(error) => (3, error as u64),
    }
}

/// Append once per actual PlanId. A changed retry cannot replace its original
/// rejection, and no error path partially changes the retained journal.
pub(super) fn append(bytes: &mut [u8], used: &mut usize, facts: &Facts) -> Result<bool, Error> {
    let receipt = facts.receipt;
    let id = receipt.id;
    let snapshot = facts.snapshot;
    let header = facts.header;
    let decision = facts.decision;
    let envelope = decision.envelope;
    if bytes.len() % SLOT_BYTES != 0 || *used > bytes.len() / SLOT_BYTES {
        return Err(Error::Capacity);
    }
    if receipt.version != 0
        || receipt.published_ns != 0
        || receipt.action_count != 1
        || !matches!(receipt.actions[0], ExecutionState::Failed(_))
        || id.boot_epoch == 0
        || id.controller_epoch == 0
        || id.plan_seq == 0
        || (id.controller_epoch, id.plan_seq) != (header.controller_epoch, header.plan_seq)
        || envelope.controller_epoch != header.controller_epoch
        || snapshot.sequence == 0
        || snapshot.ledger_generation == 0
        || snapshot.core_generation == 0
        || header.snapshot_seq != snapshot.sequence
        || envelope.snapshot_seq != snapshot.sequence
        || envelope.ledger_generation != snapshot.ledger_generation
        || envelope.core_generation != snapshot.core_generation
        || envelope.target.id == 0
        || envelope.target.generation == 0
        || envelope.decision_seq == 0
        || envelope.candidate_set_hash == [0; 32]
        || facts.model.generation == 0
        || facts.model.model_hash == [0; 32]
        || facts.model.schema_hash == [0; 32]
        || header.active_model_generation != facts.model.generation
        || envelope.model_hash != facts.model.model_hash
        || snapshot.taken_ns > facts.received_ns
        || facts.received_ns > facts.observed_ns
        || facts.wall_deadline_ns < snapshot.taken_ns
    {
        return Err(Error::Conflict);
    }
    let mut plan = [0; 384];
    let count = policy_wire::encode_plan(header, &[decision], &mut plan)?;
    let actual_hash: [u8; 32] = Sha256::digest(&plan[..count]).into();
    if actual_hash != facts.plan_hash {
        return Err(Error::Conflict);
    }
    let mut metadata = [0; HEADER_BYTES];
    put(&mut metadata, 0, FLAG);
    put(&mut metadata, 8, envelope.decision_seq);
    metadata[16..48].copy_from_slice(&envelope.candidate_set_hash);
    metadata[48..80].copy_from_slice(&actual_hash);
    put(&mut metadata, 80, facts.model.generation);
    metadata[88..120].copy_from_slice(&facts.model.model_hash);
    metadata[120..152].copy_from_slice(&facts.model.schema_hash);
    for (i, value) in [
        snapshot.sequence,
        snapshot.taken_ns,
        snapshot.ledger_generation,
        snapshot.core_generation,
        envelope.target.id,
        envelope.target.generation,
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut metadata, 152 + i * 8, value);
    }
    metadata[200..202].copy_from_slice(&decision.action.domain().to_le_bytes());
    metadata[202..204].copy_from_slice(&decision.action.kind().to_le_bytes());
    metadata[204..206].copy_from_slice(&receipt.action_count.to_le_bytes());
    metadata[206..208].copy_from_slice(&decision.candidate_index.to_le_bytes());
    // 208..272 remains empty: a fixed-baseline rejection has no model scores.
    for (i, value) in [id.boot_epoch, id.controller_epoch, id.plan_seq]
        .into_iter()
        .enumerate()
    {
        put(&mut metadata, 272 + i * 8, value);
    }
    metadata[296..304].copy_from_slice(b"CYREJCT1");
    for (offset, value) in [
        (304, 1),
        (312, count as u64),
        (320, receipt.version),
        (328, receipt.published_ns),
        (336, facts.observed_ns),
        (344, facts.wall_deadline_ns),
        (352, facts.received_ns),
    ] {
        put(&mut metadata, offset, value);
    }
    let (tag, code) = state(receipt.actions[0]);
    put(&mut metadata, 424, tag);
    put(&mut metadata, 432, code);
    // Retain the complete original action-state array, including unused slots.
    for (i, value) in receipt.actions.into_iter().enumerate() {
        let (tag, code) = state(value);
        put(&mut metadata, 512 + i * 16, tag);
        put(&mut metadata, 520 + i * 16, code);
    }
    for row in bytes[..*used * SLOT_BYTES].chunks_exact(SLOT_BYTES) {
        if word(row, 0) == FLAG
            && (word(row, 272), word(row, 280), word(row, 288))
                == (id.boot_epoch, id.controller_epoch, id.plan_seq)
        {
            return if row[..HEADER_BYTES] == metadata
                && row[PLAN_OFFSET..PLAN_OFFSET + count] == plan[..count]
            {
                Ok(false)
            } else {
                Err(Error::Conflict)
            };
        }
    }
    if *used == bytes.len() / SLOT_BYTES {
        return Err(Error::Capacity);
    }
    let row = &mut bytes[*used * SLOT_BYTES..(*used + 1) * SLOT_BYTES];
    row.fill(0);
    row[..HEADER_BYTES].copy_from_slice(&metadata);
    row[PLAN_OFFSET..PLAN_OFFSET + count].copy_from_slice(&plan[..count]);
    *used += 1;
    Ok(true)
}
