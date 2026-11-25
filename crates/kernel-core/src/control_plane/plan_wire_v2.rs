//! V0.19.9 native single-device PlanHeader/PolicyEnvelope v2 reader.
//!
//! This decoder is not the old prototype policy_wire::Plan v1, and no v1
//! input is upgraded by changing a version number. Verifying bytes is only
//! a precondition: publication requires the registered DecisionRecord v3
//! sidecar, native controller/publisher identity, fresh RuleProfile/ledger,
//! exact SHA256 plan_digest and atomic prepare/publish/reconcile gates.
use super::{
    Error,
    decision_record_v3::{DECISION_BYTES, DecisionRecordV3, DecisionSource},
};

pub const PLAN_HEADER_BYTES: usize = 64;
pub const POLICY_ENVELOPE_BYTES: usize = 144;
pub const PLAN_MAGIC: u32 = 0x4359_4c31;
pub const POLICY_MAGIC: u32 = 0x4359_5031;
pub const PLAN_VERSION: u16 = 2;
pub const POLICY_VERSION: u16 = 2;
pub const MAX_ACTIONS: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = 256;
pub const MAX_PLAN_BYTES: usize =
    PLAN_HEADER_BYTES + MAX_ACTIONS * (POLICY_ENVELOPE_BYTES + MAX_PAYLOAD_BYTES);

fn le16(b: &[u8], at: usize) -> Result<u16, Error> {
    let x = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([x[0], x[1]]))
}
fn le32(b: &[u8], at: usize) -> Result<u32, Error> {
    let x = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}
fn le64(b: &[u8], at: usize) -> Result<u64, Error> {
    let x = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([
        x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
    ]))
}
fn hash(b: &[u8], at: usize) -> Result<[u8; 32], Error> {
    b.get(at..at + 32)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanHeaderV2 {
    pub plan_seq: u64,
    pub base_plan_version: u64,
    pub active_model_generation: u64,
    pub controller_epoch: u64,
    pub snapshot_seq: u64,
    pub active_until_local_ns: u64,
    pub action_count: u16,
    pub flags: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyActionV2<'a> {
    pub domain_id: u16,
    pub action_kind: u16,
    pub controller_epoch: u64,
    pub decision_seq: u64,
    pub snapshot_seq: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub expires_local_ns: u64,
    pub model_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
    pub candidate_index: u16,
    /// The bytes after the 2-byte index are the ActionSchema v2 static
    /// action payload; domain-specific semantic validation remains required.
    pub action_payload: &'a [u8],
}
pub struct PlanV2<'a> {
    bytes: &'a [u8],
    offsets: [usize; MAX_ACTIONS],
    pub header: PlanHeaderV2,
    pub ledger_generation: u64,
    pub core_generation: u64,
}

fn action_at(frame: &[u8], at: usize) -> Result<(PolicyActionV2<'_>, usize), Error> {
    let h = frame
        .get(
            at..at
                .checked_add(POLICY_ENVELOPE_BYTES)
                .ok_or(Error::Invalid)?,
        )
        .ok_or(Error::Invalid)?;
    if le32(h, 0)? != POLICY_MAGIC
        || le16(h, 4)? != POLICY_VERSION
        || usize::from(le16(h, 6)?) != POLICY_ENVELOPE_BYTES
    {
        return Err(Error::Invalid);
    }
    let n = usize::try_from(le32(h, 12)?).map_err(|_| Error::Invalid)?;
    if !(2..=MAX_PAYLOAD_BYTES).contains(&n) {
        return Err(Error::Invalid);
    }
    let end = at
        .checked_add(POLICY_ENVELOPE_BYTES)
        .and_then(|v| v.checked_add(n))
        .ok_or(Error::Invalid)?;
    let payload = frame
        .get(at + POLICY_ENVELOPE_BYTES..end)
        .ok_or(Error::Invalid)?;
    let a = PolicyActionV2 {
        domain_id: le16(h, 8)?,
        action_kind: le16(h, 10)?,
        controller_epoch: le64(h, 16)?,
        decision_seq: le64(h, 24)?,
        snapshot_seq: le64(h, 32)?,
        target_id: le64(h, 40)?,
        target_generation: le64(h, 48)?,
        ledger_generation: le64(h, 56)?,
        core_generation: le64(h, 64)?,
        expires_local_ns: le64(h, 72)?,
        model_hash: hash(h, 80)?,
        candidate_set_hash: hash(h, 112)?,
        candidate_index: le16(payload, 0)?,
        action_payload: &payload[2..],
    };
    if !(1..=15).contains(&a.domain_id)
        || a.action_kind != 1
        || a.decision_seq == 0
        || a.controller_epoch == 0
        || a.snapshot_seq == 0
        || a.target_generation == 0
        || a.ledger_generation == 0
        || a.core_generation == 0
        || a.expires_local_ns == 0
        || a.candidate_index >= 32
        || a.candidate_set_hash == [0; 32]
    {
        return Err(Error::Invalid);
    }
    super::action_schema_v2::ActionV2::decode(a.domain_id, a.action_kind, a.action_payload)?;
    Ok((a, end))
}

impl<'a> PlanV2<'a> {
    pub fn decode(frame: &'a [u8]) -> Result<Self, Error> {
        if frame.len() < PLAN_HEADER_BYTES
            || frame.len() > MAX_PLAN_BYTES
            || le32(frame, 0)? != PLAN_MAGIC
            || le16(frame, 4)? != PLAN_VERSION
            || usize::from(le16(frame, 6)?) != PLAN_HEADER_BYTES
            || usize::try_from(le32(frame, 8)?).map_err(|_| Error::Invalid)? != frame.len()
        {
            return Err(Error::Invalid);
        }
        let count = usize::from(le16(frame, 12)?);
        let flags = le16(frame, 14)?;
        let header = PlanHeaderV2 {
            plan_seq: le64(frame, 16)?,
            base_plan_version: le64(frame, 24)?,
            active_model_generation: le64(frame, 32)?,
            controller_epoch: le64(frame, 40)?,
            snapshot_seq: le64(frame, 48)?,
            active_until_local_ns: le64(frame, 56)?,
            action_count: count as u16,
            flags,
        };
        if count == 0
            || count > MAX_ACTIONS
            || flags > 1
            || header.plan_seq == 0
            || header.controller_epoch == 0
            || header.snapshot_seq == 0
            || (flags == 0 && header.active_model_generation != 0)
            || (flags == 1 && header.active_model_generation == 0)
        {
            return Err(Error::Invalid);
        }
        let mut offsets = [0usize; MAX_ACTIONS];
        let mut at = PLAN_HEADER_BYTES;
        let mut first_ledger = None;
        let mut first_core = None;
        let mut first_model_hash = None;
        let mut last_decision_seq = 0u64;
        let mut keys = [(0u16, 0u64, 0u16); MAX_ACTIONS];
        let mut found_d14 = false;
        for i in 0..count {
            offsets[i] = at;
            let (a, next) = action_at(frame, at)?;
            if a.controller_epoch != header.controller_epoch
                || a.snapshot_seq != header.snapshot_seq
                || (flags == 0 && a.model_hash != [0; 32])
                || (flags == 1 && a.model_hash == [0; 32])
                || keys[..i].contains(&(a.domain_id, a.target_id, a.action_kind))
                || a.decision_seq <= last_decision_seq
            {
                return Err(Error::Invalid);
            }
            if let Some(current_model_hash) = first_model_hash {
                if a.model_hash != current_model_hash {
                    return Err(Error::Invalid);
                }
            } else {
                first_model_hash = Some(a.model_hash);
            }
            last_decision_seq = a.decision_seq;
            if let Some(seen_generation) = first_ledger {
                if a.ledger_generation != seen_generation {
                    return Err(Error::Invalid);
                }
            } else {
                first_ledger = Some(a.ledger_generation);
            }
            if let Some(seen_generation) = first_core {
                if a.core_generation != seen_generation {
                    return Err(Error::Invalid);
                }
            } else {
                first_core = Some(a.core_generation);
            }
            if a.domain_id == 14 {
                found_d14 = true;
            }
            keys[i] = (a.domain_id, a.target_id, a.action_kind);
            at = next;
        }
        if at != frame.len() || (found_d14 && (count != 1 || header.active_until_local_ns != 0)) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            bytes: frame,
            offsets,
            header,
            ledger_generation: first_ledger.ok_or(Error::Invalid)?,
            core_generation: first_core.ok_or(Error::Invalid)?,
        })
    }

    pub fn action(&self, index: usize) -> Result<PolicyActionV2<'a>, Error> {
        if index >= usize::from(self.header.action_count) {
            return Err(Error::Invalid);
        }
        Ok(action_at(self.bytes, self.offsets[index])?.0)
    }

    /// Require exact v3 sidecar consistency before the native authority gate.
    /// This deliberately does not calculate the plan SHA256, register decisions,
    /// authenticate the publisher or make any work executable.
    pub fn matches_untrusted_sidecars(
        &self,
        records: &[[u8; DECISION_BYTES]],
    ) -> Result<(), Error> {
        if records.len() != usize::from(self.header.action_count) {
            return Err(Error::Invalid);
        }
        let mut decision_seqs = [0u64; MAX_ACTIONS];
        let mut rules_generation = None;
        let mut rules_hash = None;
        let mut plan_digest = None;
        for (index, bytes) in records.iter().enumerate() {
            let rec = DecisionRecordV3::decode(bytes)?;
            let act = self.action(index)?;
            if rec.action_index != index as u16
                || rec.plan_seq != self.header.plan_seq
                || rec.controller_epoch != self.header.controller_epoch
                || rec.snapshot_seq != self.header.snapshot_seq
                || rec.decision_seq != act.decision_seq
                || rec.domain_id != act.domain_id
                || rec.action_kind != act.action_kind
                || rec.target_id != act.target_id
                || rec.target_generation != act.target_generation
                || rec.ledger_generation != act.ledger_generation
                || rec.core_generation != act.core_generation
                || rec.decision_expires_ns != act.expires_local_ns
                || rec.candidate_set_hash != act.candidate_set_hash
                || rec.selected_index != act.candidate_index
                || decision_seqs[..index].contains(&rec.decision_seq)
                || (self.header.flags == 0 && rec.source == DecisionSource::AiAssisted)
                || (self.header.flags == 1 && rec.source != DecisionSource::AiAssisted)
                || (self.header.flags == 1
                    && rec.advice_model_generation != self.header.active_model_generation)
            {
                return Err(Error::Denied);
            }
            if rules_generation
                .is_some_and(|seen_generation| seen_generation != rec.rules_generation)
                || rules_hash.is_some_and(|h| h != rec.rules_hash)
                || plan_digest.is_some_and(|h| h != rec.plan_digest)
            {
                return Err(Error::Denied);
            }
            decision_seqs[index] = rec.decision_seq;
            rules_generation = Some(rec.rules_generation);
            rules_hash = Some(rec.rules_hash);
            plan_digest = Some(rec.plan_digest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> [u8; 212] {
        let mut b = [0u8; 212];
        b[0..4].copy_from_slice(&PLAN_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&64u16.to_le_bytes());
        b[8..12].copy_from_slice(&212u32.to_le_bytes());
        b[12..14].copy_from_slice(&1u16.to_le_bytes());
        for (at, v) in [(16, 1u64), (40, 2), (48, 3), (56, 10000)] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        let h = 64;
        b[h..h + 4].copy_from_slice(&POLICY_MAGIC.to_le_bytes());
        b[h + 4..h + 6].copy_from_slice(&2u16.to_le_bytes());
        b[h + 6..h + 8].copy_from_slice(&144u16.to_le_bytes());
        b[h + 8..h + 10].copy_from_slice(&1u16.to_le_bytes());
        b[h + 10..h + 12].copy_from_slice(&1u16.to_le_bytes());
        b[h + 12..h + 16].copy_from_slice(&4u32.to_le_bytes());
        for (at, v) in [
            (16, 2u64),
            (24, 4),
            (32, 3),
            (40, 17),
            (48, 1),
            (56, 5),
            (64, 6),
            (72, 200),
        ] {
            b[h + at..h + at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[h + 112] = 1;
        b[h + 144..h + 146].copy_from_slice(&1u16.to_le_bytes());
        b[h + 146..h + 148].copy_from_slice(&2u16.to_le_bytes());
        b
    }
    #[test]
    fn decode_local_plan_v2_without_making_it_executable() {
        let b = plan();
        let p = PlanV2::decode(&b).unwrap();
        assert_eq!(p.header.plan_seq, 1);
        assert_eq!(p.header.action_count, 1);
        assert_eq!(p.action(0).unwrap().candidate_index, 1);
        assert_eq!(p.action(0).unwrap().action_payload, &[2u8, 0]);
        assert!(p.action(1).is_err());
    }
    #[test]
    fn old_v1_and_malformed_or_cross_domain_plan_are_rejected() {
        let mut b = plan();
        b[4] = 1;
        assert!(PlanV2::decode(&b).is_err());
        assert!(PlanV2::decode(&plan()[..211]).is_err());
        b = plan();
        b[64 + 8] = 16;
        assert!(PlanV2::decode(&b).is_err());
        b = plan();
        b[64 + 16] = 3;
        assert!(PlanV2::decode(&b).is_err());
        b = plan();
        b[64 + 12] = 0;
        assert!(PlanV2::decode(&b).is_err());
        b = plan();
        b[64 + 144..64 + 146].copy_from_slice(&32u16.to_le_bytes());
        assert!(PlanV2::decode(&b).is_err());
        b = plan();
        b[14] = 1;
        assert!(PlanV2::decode(&b).is_err()); // AI flag needs model id
    }
    fn registered_decision() -> [u8; DECISION_BYTES] {
        let mut b = [0u8; DECISION_BYTES];
        b[0..4].copy_from_slice(&0x4359_4431u32.to_le_bytes());
        b[4..6].copy_from_slice(&3u16.to_le_bytes());
        b[6..8].copy_from_slice(&256u16.to_le_bytes());
        for (at, value) in [
            (8, 1u64),
            (16, 2),
            (24, 4),
            (32, 1),
            (40, 3),
            (48, 17),
            (56, 1),
            (64, 5),
            (72, 6),
            (80, 7),
            (144, 200),
        ] {
            b[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        b[88..92].copy_from_slice(&8u32.to_le_bytes());
        b[94..96].copy_from_slice(&1u16.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[102..104].copy_from_slice(&1u16.to_le_bytes());
        b[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        b[108..112].copy_from_slice(&2u32.to_le_bytes());
        b[152..156].copy_from_slice(&0b11u32.to_le_bytes());
        b[156..158].copy_from_slice(&1u16.to_le_bytes());
        b[160] = 1;
        b[192] = 2;
        b[224] = 1;
        b
    }
    #[test]
    fn sidecar_cross_binding_checks_native_target_epoch_and_actual_candidate_index() {
        let plan = plan();
        let decoded = PlanV2::decode(&plan).unwrap();
        assert!(
            decoded
                .matches_untrusted_sidecars(&[registered_decision()])
                .is_ok()
        );

        let mut changed = registered_decision();
        changed[102..104].copy_from_slice(&0u16.to_le_bytes());
        changed[156..158].copy_from_slice(&0u16.to_le_bytes());
        // This is a structurally valid other fallback, but it did not match
        // the actual PolicyEnvelope's frozen chosen candidate index.
        assert!(decoded.matches_untrusted_sidecars(&[changed]).is_err());
        changed = registered_decision();
        changed[72..80].copy_from_slice(&9u64.to_le_bytes());
        assert!(decoded.matches_untrusted_sidecars(&[changed]).is_err());
        changed = registered_decision();
        changed[104..106].copy_from_slice(&0u16.to_le_bytes());
        assert!(decoded.matches_untrusted_sidecars(&[changed]).is_err());
        changed = registered_decision();
        changed[4] = 2;
        assert!(decoded.matches_untrusted_sidecars(&[changed]).is_err());
    }

    #[test]
    fn multi_action_plan_v2_requires_one_model_and_increasing_decision_sequences() {
        let one = plan();
        let mut two = [0u8; 360];
        two[..212].copy_from_slice(&one);
        two[212..].copy_from_slice(&one[64..212]);
        two[8..12].copy_from_slice(&360u32.to_le_bytes());
        two[12..14].copy_from_slice(&2u16.to_le_bytes());
        // The second action must be a different target and later decision.
        two[212 + 40..212 + 48].copy_from_slice(&18u64.to_le_bytes());
        two[212 + 24..212 + 32].copy_from_slice(&5u64.to_le_bytes());
        assert!(PlanV2::decode(&two).is_ok());
        two[212 + 24..212 + 32].copy_from_slice(&4u64.to_le_bytes());
        assert!(PlanV2::decode(&two).is_err()); // replayed decision sequence
        two[212 + 24..212 + 32].copy_from_slice(&5u64.to_le_bytes());
        two[14..16].copy_from_slice(&1u16.to_le_bytes()); // AI mode
        two[32..40].copy_from_slice(&1u64.to_le_bytes()); // active model gen
        two[64 + 80..64 + 112].copy_from_slice(&[3u8; 32]);
        two[212 + 80..212 + 112].copy_from_slice(&[4u8; 32]);
        assert!(PlanV2::decode(&two).is_err()); // model mismatch
        two[212 + 80..212 + 112].copy_from_slice(&[3u8; 32]);
        assert!(PlanV2::decode(&two).is_ok());
    }
    #[test]
    fn sidecar_count_cannot_be_forged_into_a_ready_to_publish_plan() {
        let frame = plan();
        let p = PlanV2::decode(&frame).unwrap();
        assert!(p.matches_untrusted_sidecars(&[]).is_err());
    }
}
