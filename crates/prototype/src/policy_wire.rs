//! Exact little-endian PolicyEnvelope v1 and PlanHeader v1 framing.
use crate::domains::{Action, Error, ObjectKey};

pub const ENVELOPE_BYTES: usize = 144;
pub const PLAN_HEADER_BYTES: usize = 64;
pub const MAX_PAYLOAD: usize = 256;
pub const MAX_ACTIONS: usize = 16;
pub const MAX_PLAN_BYTES: usize = 6464;
pub const ENVELOPE_MAGIC: u32 = 0x43595031;
pub const PLAN_MAGIC: u32 = 0x43594c31;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlanHeader {
    pub plan_seq: u64,
    pub base_plan_version: u64,
    pub active_model_generation: u64,
    pub controller_epoch: u64,
    pub snapshot_seq: u64,
    pub active_until_local_ns: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Envelope {
    pub controller_epoch: u64,
    pub decision_seq: u64,
    pub snapshot_seq: u64,
    pub target: ObjectKey,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub expires_local_ns: u64,
    pub model_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub envelope: Envelope,
    pub action: Action,
    pub candidate_index: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Plan {
    pub header: PlanHeader,
    actions: [Option<Decision>; MAX_ACTIONS],
    count: usize,
}
impl Plan {
    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn action(&self, index: usize) -> Option<Decision> {
        self.actions.get(index).copied().flatten()
    }
    pub fn iter(&self) -> impl Iterator<Item = Decision> + '_ {
        self.actions[..self.count].iter().filter_map(|v| *v)
    }
}
fn u16_at(b: &[u8], i: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u32_at(b: &[u8], i: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn u64_at(b: &[u8], i: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        b.get(i..i + 8)
            .ok_or(Error::Format)?
            .try_into()
            .map_err(|_| Error::Format)?,
    ))
}
fn put16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn payload_len(action: Action) -> usize {
    match action {
        Action::ControlSet(_) => 10,
        Action::Cache { .. } => 8,
        Action::Filesystem { .. } => 6,
        Action::Ipc { .. } => 5,
        Action::ServiceBatch(_) | Action::TxBatch(_) | Action::NotifyBatch(_) => 3,
        _ => 4,
    }
}
pub fn encode_payload(action: Action, index: u16, out: &mut [u8]) -> Result<usize, Error> {
    action.validate()?;
    if index >= 32 {
        return Err(Error::Range);
    }
    let n = payload_len(action);
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    put16(b, 0, index);
    match action {
        Action::ControlSet(mask) => put64(b, 2, mask),
        Action::Cache { pages, batch } => {
            put32(b, 2, pages);
            put16(b, 6, batch);
        }
        Action::Filesystem { readahead, flush } => {
            put16(b, 2, readahead);
            put16(b, 4, flush);
        }
        Action::Ipc { budget, batch } => {
            put16(b, 2, budget);
            b[4] = batch;
        }
        Action::ServiceBatch(v) | Action::TxBatch(v) | Action::NotifyBatch(v) => b[2] = v,
        Action::CpuWeight(v)
        | Action::SpawnTokens(v)
        | Action::IrqTarget(v)
        | Action::SoftCoalesce(v)
        | Action::IoShare(v)
        | Action::UnauthRate(v)
        | Action::BackgroundBudget(v)
        | Action::RecoveryRecipe(v)
        | Action::ConsoleBatch(v)
        | Action::OfferCpu(v)
        | Action::Placement(v) => put16(b, 2, v),
    }
    Ok(n)
}
pub fn decode_payload(domain: u16, kind: u16, b: &[u8]) -> Result<(Action, u16), Error> {
    let index = u16_at(b, 0)?;
    if index >= 32 {
        return Err(Error::Range);
    }
    let action = match (domain, kind) {
        (1, 1) => Action::CpuWeight(u16_at(b, 2)?),
        (1, 2) => Action::ControlSet(u64_at(b, 2)?),
        (2, 1) => Action::SpawnTokens(u16_at(b, 2)?),
        (3, 1) => Action::Cache {
            pages: u32_at(b, 2)?,
            batch: u16_at(b, 6)?,
        },
        (4, 1) => Action::Filesystem {
            readahead: u16_at(b, 2)?,
            flush: u16_at(b, 4)?,
        },
        (5, 1) => Action::Ipc {
            budget: u16_at(b, 2)?,
            batch: *b.get(4).ok_or(Error::Format)?,
        },
        (6, 1) => Action::IrqTarget(u16_at(b, 2)?),
        (7, 1) => Action::SoftCoalesce(u16_at(b, 2)?),
        (8, 1) => Action::ServiceBatch(*b.get(2).ok_or(Error::Format)?),
        (9, 1) => Action::IoShare(u16_at(b, 2)?),
        (10, 1) => Action::TxBatch(*b.get(2).ok_or(Error::Format)?),
        (11, 1) => Action::NotifyBatch(*b.get(2).ok_or(Error::Format)?),
        (12, 1) => Action::UnauthRate(u16_at(b, 2)?),
        (13, 1) => Action::BackgroundBudget(u16_at(b, 2)?),
        (14, 1) => Action::RecoveryRecipe(u16_at(b, 2)?),
        (15, 1) => Action::ConsoleBatch(u16_at(b, 2)?),
        (16, 1) => Action::OfferCpu(u16_at(b, 2)?),
        (16, 2) => Action::Placement(u16_at(b, 2)?),
        _ => return Err(Error::Unsupported),
    };
    if b.len() != payload_len(action) {
        return Err(Error::Format);
    }
    action.validate()?;
    Ok((action, index))
}
fn validate(header: PlanHeader, actions: &[Decision]) -> Result<(), Error> {
    if actions.is_empty() || actions.len() > MAX_ACTIONS {
        return Err(Error::Capacity);
    }
    if header.plan_seq == 0
        || header.controller_epoch == 0
        || header.snapshot_seq == 0
        || header.active_model_generation == 0
    {
        return Err(Error::Stale);
    }
    let first = actions[0];
    let mut last_decision = 0;
    for (i, d) in actions.iter().enumerate() {
        d.action.validate()?;
        let e = d.envelope;
        if e.controller_epoch != header.controller_epoch
            || e.snapshot_seq != header.snapshot_seq
            || e.ledger_generation != first.envelope.ledger_generation
            || e.core_generation != first.envelope.core_generation
            || e.model_hash != first.envelope.model_hash
        {
            return Err(Error::Conflict);
        }
        if e.target.id == 0
            || e.target.generation == 0
            || e.ledger_generation == 0
            || e.core_generation == 0
            || e.decision_seq <= last_decision
        {
            return Err(Error::Stale);
        }
        last_decision = e.decision_seq;
        if d.candidate_index >= 32 {
            return Err(Error::Range);
        }
        if d.action.single_action() && actions.len() != 1 {
            return Err(Error::Conflict);
        }
        if d.action.one_shot() != (header.active_until_local_ns == 0) {
            return Err(Error::Format);
        }
        for old in &actions[..i] {
            if old.action.domain() == d.action.domain()
                && old.action.kind() == d.action.kind()
                && old.envelope.target.id == e.target.id
            {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}
pub fn encode_plan(
    header: PlanHeader,
    actions: &[Decision],
    out: &mut [u8],
) -> Result<usize, Error> {
    validate(header, actions)?;
    let total = actions.iter().try_fold(PLAN_HEADER_BYTES, |n, d| {
        n.checked_add(ENVELOPE_BYTES + payload_len(d.action))
            .ok_or(Error::Overflow)
    })?;
    if total > MAX_PLAN_BYTES {
        return Err(Error::Capacity);
    }
    let b = out.get_mut(..total).ok_or(Error::Capacity)?;
    b.fill(0);
    put32(b, 0, PLAN_MAGIC);
    put16(b, 4, 1);
    put16(b, 6, PLAN_HEADER_BYTES as u16);
    put32(b, 8, total as u32);
    put16(b, 12, actions.len() as u16);
    for (i, value) in [
        header.plan_seq,
        header.base_plan_version,
        header.active_model_generation,
        header.controller_epoch,
        header.snapshot_seq,
        header.active_until_local_ns,
    ]
    .into_iter()
    .enumerate()
    {
        put64(b, 16 + i * 8, value);
    }
    let mut at = PLAN_HEADER_BYTES;
    for d in actions {
        let e = d.envelope;
        let n = payload_len(d.action);
        let b = &mut b[at..at + ENVELOPE_BYTES + n];
        put32(b, 0, ENVELOPE_MAGIC);
        put16(b, 4, 1);
        put16(b, 6, ENVELOPE_BYTES as u16);
        put16(b, 8, d.action.domain());
        put16(b, 10, d.action.kind());
        put32(b, 12, n as u32);
        for (i, value) in [
            e.controller_epoch,
            e.decision_seq,
            e.snapshot_seq,
            e.target.id,
            e.target.generation,
            e.ledger_generation,
            e.core_generation,
            e.expires_local_ns,
        ]
        .into_iter()
        .enumerate()
        {
            put64(b, 16 + i * 8, value);
        }
        b[80..112].copy_from_slice(&e.model_hash);
        b[112..144].copy_from_slice(&e.candidate_set_hash);
        encode_payload(d.action, d.candidate_index, &mut b[ENVELOPE_BYTES..])?;
        at += ENVELOPE_BYTES + n;
    }
    Ok(total)
}
pub fn decode_plan(b: &[u8]) -> Result<Plan, Error> {
    if b.len() < PLAN_HEADER_BYTES
        || b.len() > MAX_PLAN_BYTES
        || u32_at(b, 0)? != PLAN_MAGIC
        || u16_at(b, 4)? != 1
        || u16_at(b, 6)? != PLAN_HEADER_BYTES as u16
        || u32_at(b, 8)? as usize != b.len()
        || u16_at(b, 14)? != 0
    {
        return Err(Error::Format);
    }
    let count = usize::from(u16_at(b, 12)?);
    if count == 0 || count > MAX_ACTIONS {
        return Err(Error::Capacity);
    }
    let header = PlanHeader {
        plan_seq: u64_at(b, 16)?,
        base_plan_version: u64_at(b, 24)?,
        active_model_generation: u64_at(b, 32)?,
        controller_epoch: u64_at(b, 40)?,
        snapshot_seq: u64_at(b, 48)?,
        active_until_local_ns: u64_at(b, 56)?,
    };
    let mut actions = [None; MAX_ACTIONS];
    let mut at = PLAN_HEADER_BYTES;
    for item in actions.iter_mut().take(count) {
        let end = at.checked_add(ENVELOPE_BYTES).ok_or(Error::Overflow)?;
        let e = b.get(at..end).ok_or(Error::Format)?;
        if u32_at(e, 0)? != ENVELOPE_MAGIC
            || u16_at(e, 4)? != 1
            || u16_at(e, 6)? != ENVELOPE_BYTES as u16
        {
            return Err(Error::Format);
        }
        let len = u32_at(e, 12)? as usize;
        if len > MAX_PAYLOAD {
            return Err(Error::Capacity);
        }
        let next = end.checked_add(len).ok_or(Error::Overflow)?;
        let (action, candidate_index) = decode_payload(
            u16_at(e, 8)?,
            u16_at(e, 10)?,
            b.get(end..next).ok_or(Error::Format)?,
        )?;
        *item = Some(Decision {
            action,
            candidate_index,
            envelope: Envelope {
                controller_epoch: u64_at(e, 16)?,
                decision_seq: u64_at(e, 24)?,
                snapshot_seq: u64_at(e, 32)?,
                target: ObjectKey {
                    id: u64_at(e, 40)?,
                    generation: u64_at(e, 48)?,
                },
                ledger_generation: u64_at(e, 56)?,
                core_generation: u64_at(e, 64)?,
                expires_local_ns: u64_at(e, 72)?,
                model_hash: e[80..112].try_into().map_err(|_| Error::Format)?,
                candidate_set_hash: e[112..144].try_into().map_err(|_| Error::Format)?,
            },
        });
        at = next;
    }
    if at != b.len() {
        return Err(Error::Format);
    }
    // Fixed stack storage avoids an allocator in both EL0 and EL1.
    let first = actions[0].ok_or(Error::Format)?;
    let mut flat = [first; MAX_ACTIONS];
    for i in 0..count {
        flat[i] = actions[i].ok_or(Error::Format)?;
    }
    validate(header, &flat[..count])?;
    Ok(Plan {
        header,
        actions,
        count,
    })
}
