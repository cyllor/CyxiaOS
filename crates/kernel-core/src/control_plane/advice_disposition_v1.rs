//! V0.19.9 240-byte AdviceDisposition v1: immutable causal evidence.
//!
//! Byte validation and linking never grant policy authority. Only an
//! authenticated EL1 owner may copy in an actual AdviceEnvelope v1 and the
//! independently registered DecisionRecord v3 and commit one final disposition
//! per AdviceKey. This parser alone is not that registration service.
use super::{
    Error, Identity,
    advice_envelope_v1::AdviceEnvelopeV1,
    decision_record_v3::{DecisionRecordV3, DecisionSource},
};
use sha2::{Digest, Sha256};

pub const DISPOSITION_BYTES: usize = 240;
pub const DISPOSITION_MAGIC: u32 = 0x4359_4144;
pub const DISPOSITION_VERSION: u16 = 1;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let s = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}
fn hash_at(b: &[u8], at: usize) -> Result<[u8; 32], Error> {
    b.get(at..at + 32)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
fn sensitive(domain: u16) -> bool {
    matches!(domain, 6 | 11 | 12 | 14)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdviceDispositionV1 {
    pub boot_epoch: u64,
    pub advisor_epoch: u64,
    pub advice_seq: u64,
    pub snapshot_seq: u64,
    pub controller_epoch: u64,
    pub decision_seq: u64,
    pub target: Identity,
    pub model_generation: u64,
    pub processed_ns: u64,
    pub domain_id: u16,
    pub action_kind: u16,
    pub state: u16,
    pub reason_code: u16,
    pub allowed_mask: u32,
    pub fallback_index: u16,
    pub recommended_index: u16,
    pub selected_index: u16,
    pub choice_policy: u16,
    pub candidate_set_hash: [u8; 32],
    pub advice_digest: [u8; 32],
    pub decision_digest: [u8; 32],
    pub rules_hash: [u8; 32],
}

impl AdviceDispositionV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DISPOSITION_BYTES
            || u32_at(bytes, 0)? != DISPOSITION_MAGIC
            || u16_at(bytes, 4)? != DISPOSITION_VERSION
            || usize::from(u16_at(bytes, 6)?) != DISPOSITION_BYTES
            || u32_at(bytes, 108)? != 0
        {
            return Err(Error::Invalid);
        }
        let result = Self {
            boot_epoch: u64_at(bytes, 8)?,
            advisor_epoch: u64_at(bytes, 16)?,
            advice_seq: u64_at(bytes, 24)?,
            snapshot_seq: u64_at(bytes, 32)?,
            controller_epoch: u64_at(bytes, 40)?,
            decision_seq: u64_at(bytes, 48)?,
            target: Identity {
                id: u64_at(bytes, 56)?,
                generation: u64_at(bytes, 64)?,
            },
            model_generation: u64_at(bytes, 72)?,
            processed_ns: u64_at(bytes, 80)?,
            domain_id: u16_at(bytes, 88)?,
            action_kind: u16_at(bytes, 90)?,
            state: u16_at(bytes, 92)?,
            reason_code: u16_at(bytes, 94)?,
            allowed_mask: u32_at(bytes, 96)?,
            fallback_index: u16_at(bytes, 100)?,
            recommended_index: u16_at(bytes, 102)?,
            selected_index: u16_at(bytes, 104)?,
            choice_policy: u16_at(bytes, 106)?,
            candidate_set_hash: hash_at(bytes, 112)?,
            advice_digest: hash_at(bytes, 144)?,
            decision_digest: hash_at(bytes, 176)?,
            rules_hash: hash_at(bytes, 208)?,
        };
        if !result.structural_valid() {
            return Err(Error::Invalid);
        }
        Ok(result)
    }

    fn structural_valid(&self) -> bool {
        if self.boot_epoch == 0
            || self.advisor_epoch == 0
            || self.advice_seq == 0
            || self.snapshot_seq == 0
            || !self.target.valid()
            || self.model_generation == 0
            || self.processed_ns == 0
            || !(1..=15).contains(&self.domain_id)
            || self.action_kind != 1
            || self.recommended_index >= 32
            || self.candidate_set_hash == [0; 32]
            || self.advice_digest == [0; 32]
        {
            return false;
        }
        match self.state {
            1 | 2 => {
                let valid_reason = if self.state == 1 {
                    self.reason_code == 0
                } else {
                    (1..=4).contains(&self.reason_code)
                };
                valid_reason
                    && !sensitive(self.domain_id)
                    && self.controller_epoch != 0
                    && self.decision_seq != 0
                    && self.decision_digest != [0; 32]
                    && self.rules_hash != [0; 32]
                    && self.allowed_mask != 0
                    && self.selected_index < 32
                    && self.fallback_index < 32
                    && self.choice_policy <= 1
                    && self.allowed_mask & (1u32 << self.selected_index) != 0
                    && self.allowed_mask & (1u32 << self.fallback_index) != 0
                    && (self.state != 1
                        || (self.choice_policy == 1
                            && self.recommended_index == self.selected_index))
                    && (self.state != 2 || self.selected_index == self.fallback_index)
            }
            3..=6 => {
                let reason = match self.state {
                    3 => self.reason_code == 5,
                    4 => self.reason_code == 4,
                    5 => self.reason_code == 6,
                    6 => self.reason_code == 2 && sensitive(self.domain_id),
                    _ => false,
                };
                reason
                    && self.controller_epoch == 0
                    && self.decision_seq == 0
                    && self.decision_digest == [0; 32]
                    && self.allowed_mask == 0
                    && self.fallback_index == u16::MAX
                    && self.selected_index == u16::MAX
                    && self.choice_policy == u16::MAX
            }
            _ => false,
        }
    }

    /// Every disposition, including observation/expiry without a decision,
    /// must describe the exact previously recorded advice. A digest alone
    /// cannot authorize replacing its target, scope or recommended ordinal.
    pub fn matches_advice(self, boot_epoch: u64, advice_wire: &[u8]) -> Result<(), Error> {
        let advice = AdviceEnvelopeV1::decode(advice_wire)?;
        if self.boot_epoch != boot_epoch
            || self.advice_digest != sha256(advice_wire)
            || self.advisor_epoch != advice.advisor_epoch
            || self.advice_seq != advice.advice_seq
            || self.snapshot_seq != advice.snapshot_seq
            || self.target != advice.target
            || self.model_generation != advice.active_model_generation
            || self.domain_id != advice.domain
            || self.action_kind != advice.action_kind
            || self.recommended_index != advice.recommended_index
            || self.candidate_set_hash != advice.candidate_set_hash
        {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// A successful causal pair is *necessary*, never sufficient, to register
    /// an AI-assisted decision or an AI-rejection fallback. EL1 must still
    /// authenticate roles and the frozen snapshot and enforce key uniqueness.
    pub fn matches_decision_pair(
        self,
        boot_epoch: u64,
        advice_wire: &[u8],
        decision_wire: &[u8],
    ) -> Result<(), Error> {
        if !matches!(self.state, 1 | 2) || self.boot_epoch != boot_epoch {
            return Err(Error::Denied);
        }
        self.matches_advice(boot_epoch, advice_wire)?;
        let advice = AdviceEnvelopeV1::decode(advice_wire)?;
        let decision = DecisionRecordV3::decode(decision_wire)?;
        if self.decision_digest != sha256(decision_wire)
            || self.controller_epoch != decision.controller_epoch
            || self.decision_seq != decision.decision_seq
            || self.boot_epoch != decision.boot_epoch
            || self.snapshot_seq != decision.snapshot_seq
            || self.target.id != decision.target_id
            || self.target.generation != decision.target_generation
            || self.domain_id != decision.domain_id
            || self.action_kind != decision.action_kind
            || advice.ledger_generation != decision.ledger_generation
            || advice.core_generation != decision.core_generation
            || self.processed_ns >= decision.decision_expires_ns
            || self.allowed_mask != decision.allowed_mask
            || self.fallback_index != decision.fallback_index
            || self.selected_index != decision.selected_index
            || self.choice_policy != decision.choice_policy
            || self.rules_hash != decision.rules_hash
            || self.candidate_set_hash != decision.candidate_set_hash
            || !decision.matches_candidate_count(usize::from(advice.candidate_count))
        {
            return Err(Error::Denied);
        }
        match self.state {
            1 if decision.source == DecisionSource::AiAssisted
                && decision.reason_code == 8
                && decision.advisor_epoch == self.advisor_epoch
                && decision.advice_seq == self.advice_seq
                && decision.advice_model_generation == self.model_generation
                && decision.recommended_index == self.recommended_index
                && self.processed_ns < advice.expires_ns =>
            {
                Ok(())
            }
            2 if decision.source == DecisionSource::RuleOnly
                && decision.reason_code == 7
                && decision.advisor_epoch == 0
                && decision.advice_seq == 0
                && decision.advice_model_generation == 0 =>
            {
                Ok(())
            }
            _ => Err(Error::Denied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn advice() -> [u8; 152] {
        let mut a = [0u8; 152];
        a[0..4].copy_from_slice(&0x4359_4131u32.to_le_bytes());
        a[4..6].copy_from_slice(&1u16.to_le_bytes());
        a[6..8].copy_from_slice(&152u16.to_le_bytes());
        for (offset, value) in [
            (8, 7u64),
            (16, 9),
            (24, 4),
            (32, 17),
            (40, 5),
            (48, 2),
            (56, 3),
            (64, 200),
            (72, 6),
        ] {
            a[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        a[80..82].copy_from_slice(&1u16.to_le_bytes());
        a[82..84].copy_from_slice(&1u16.to_le_bytes());
        a[84..86].copy_from_slice(&0u16.to_le_bytes());
        a[86..88].copy_from_slice(&2u16.to_le_bytes());
        a[88..120].copy_from_slice(&[3; 32]);
        a[120..152].copy_from_slice(&[4; 32]);
        a
    }
    fn decision() -> [u8; 256] {
        let mut d = [0u8; 256];
        d[0..4].copy_from_slice(&0x4359_4431u32.to_le_bytes());
        d[4..6].copy_from_slice(&3u16.to_le_bytes());
        d[6..8].copy_from_slice(&256u16.to_le_bytes());
        for (offset, value) in [
            (8, 1u64),
            (16, 2),
            (24, 3),
            (32, 8),
            (40, 4),
            (48, 17),
            (56, 5),
            (64, 2),
            (72, 3),
            (80, 5),
            (144, 200),
        ] {
            d[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        d[88..92].copy_from_slice(&1u32.to_le_bytes());
        d[94..96].copy_from_slice(&1u16.to_le_bytes());
        d[96..98].copy_from_slice(&1u16.to_le_bytes());
        d[102..104].copy_from_slice(&1u16.to_le_bytes());
        d[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        d[108..112].copy_from_slice(&7u32.to_le_bytes());
        d[152..156].copy_from_slice(&0b11u32.to_le_bytes());
        d[156..158].copy_from_slice(&1u16.to_le_bytes());
        d[158..160].copy_from_slice(&1u16.to_le_bytes());
        d[160..192].copy_from_slice(&[5; 32]);
        d[192..224].copy_from_slice(&[6; 32]);
        d[224..256].copy_from_slice(&[4; 32]);
        d
    }
    fn disposition(a: &[u8], d: &[u8]) -> [u8; 240] {
        let mut b = [0u8; 240];
        b[0..4].copy_from_slice(&DISPOSITION_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&1u16.to_le_bytes());
        b[6..8].copy_from_slice(&240u16.to_le_bytes());
        for (offset, value) in [
            (8, 1u64),
            (16, 7),
            (24, 9),
            (32, 4),
            (40, 2),
            (48, 3),
            (56, 17),
            (64, 5),
            (72, 6),
            (80, 150),
        ] {
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        b[88..90].copy_from_slice(&1u16.to_le_bytes());
        b[90..92].copy_from_slice(&1u16.to_le_bytes());
        b[92..94].copy_from_slice(&2u16.to_le_bytes());
        b[94..96].copy_from_slice(&3u16.to_le_bytes());
        b[96..100].copy_from_slice(&3u32.to_le_bytes());
        b[100..102].copy_from_slice(&1u16.to_le_bytes());
        b[104..106].copy_from_slice(&1u16.to_le_bytes());
        b[106..108].copy_from_slice(&1u16.to_le_bytes());
        b[112..144].copy_from_slice(&[4; 32]);
        b[144..176].copy_from_slice(&sha256(a));
        b[176..208].copy_from_slice(&sha256(d));
        b[208..240].copy_from_slice(&[5; 32]);
        b
    }

    #[test]
    fn rejected_fallback_is_linked_to_actual_advice_and_rule_only_decision() {
        let a = advice();
        let d = decision();
        let b = disposition(&a, &d);
        let parsed = AdviceDispositionV1::decode(&b).unwrap();
        assert_eq!(parsed.state, 2);
        assert_eq!(parsed.matches_decision_pair(1, &a, &d), Ok(()));
        assert_eq!(parsed.matches_decision_pair(2, &a, &d), Err(Error::Denied));
        let mut bad_advice = a;
        bad_advice[8] ^= 1;
        assert!(parsed.matches_decision_pair(1, &bad_advice, &d).is_err());
        let mut bad_decision = d;
        bad_decision[48] ^= 1;
        assert!(parsed.matches_decision_pair(1, &a, &bad_decision).is_err());
    }

    #[test]
    fn adopted_disposition_requires_current_ai_decision_and_matching_advice_key() {
        let a = advice();
        let mut d = decision();
        d[98] = 2;
        d[99] = 1;
        d[100] = 1;
        d[101] = 1;
        d[102..104].copy_from_slice(&0u16.to_le_bytes());
        d[104..106].copy_from_slice(&0u16.to_le_bytes());
        d[108..112].copy_from_slice(&8u32.to_le_bytes());
        d[112..120].copy_from_slice(&7u64.to_le_bytes());
        d[120..128].copy_from_slice(&9u64.to_le_bytes());
        d[128..136].copy_from_slice(&6u64.to_le_bytes());
        let mut b = disposition(&a, &d);
        b[92..94].copy_from_slice(&1u16.to_le_bytes());
        b[94..96].copy_from_slice(&0u16.to_le_bytes());
        b[104..106].copy_from_slice(&0u16.to_le_bytes());
        b[176..208].copy_from_slice(&sha256(&d));
        let parsed = AdviceDispositionV1::decode(&b).unwrap();
        assert_eq!(parsed.matches_decision_pair(1, &a, &d), Ok(()));
        let mut other = d;
        other[102..104].copy_from_slice(&1u16.to_le_bytes());
        other[104..106].copy_from_slice(&1u16.to_le_bytes());
        assert!(DecisionRecordV3::decode(&other).is_ok());
        let mut rebound = b;
        rebound[176..208].copy_from_slice(&sha256(&other));
        assert_eq!(
            AdviceDispositionV1::decode(&rebound)
                .unwrap()
                .matches_decision_pair(1, &a, &other),
            Err(Error::Denied)
        );
        d[120..128].copy_from_slice(&10u64.to_le_bytes());
        assert!(parsed.matches_decision_pair(1, &a, &d).is_err());
    }

    #[test]
    fn no_decision_is_observation_only_and_old_or_malformed_records_fail() {
        let a = advice();
        let d = decision();
        let mut b = disposition(&a, &d);
        b[92..94].copy_from_slice(&5u16.to_le_bytes()); // SHADOW_ONLY
        b[94..96].copy_from_slice(&6u16.to_le_bytes());
        b[40..56].fill(0); // no DecisionKey
        b[96..102].fill(0); // no allowed set
        b[100..102].copy_from_slice(&u16::MAX.to_le_bytes());
        b[104..108].copy_from_slice(&[255; 4]); // selected/choice_policy absent
        b[176..208].fill(0);
        assert!(AdviceDispositionV1::decode(&b).is_ok());
        assert_eq!(
            AdviceDispositionV1::decode(&b)
                .unwrap()
                .matches_decision_pair(1, &a, &d),
            Err(Error::Denied)
        );
        b[108] = 1;
        assert!(AdviceDispositionV1::decode(&b).is_err());
        assert!(AdviceDispositionV1::decode(&b[..239]).is_err());
        let mut b = disposition(&a, &d);
        b[4] = 2;
        assert!(AdviceDispositionV1::decode(&b).is_err());
        let mut b = disposition(&a, &d);
        b[92..94].copy_from_slice(&6u16.to_le_bytes());
        b[94..96].copy_from_slice(&2u16.to_le_bytes());
        assert!(AdviceDispositionV1::decode(&b).is_err()); // sensitive only
    }
    #[test]
    fn causal_pair_denies_relabelled_resource_generations_and_expired_decision() {
        let a = advice();
        // The disposition digest is recomputed over the forged decision:
        // byte integrity alone cannot substitute for matching its scope.
        for at in [64usize, 72, 224] {
            let mut d = decision();
            d[at] ^= 1;
            let b = disposition(&a, &d);
            assert_eq!(
                AdviceDispositionV1::decode(&b)
                    .unwrap()
                    .matches_decision_pair(1, &a, &d),
                Err(Error::Denied)
            );
        }
        let d = decision();
        let mut b = disposition(&a, &d);
        b[80..88].copy_from_slice(&200u64.to_le_bytes());
        assert_eq!(
            AdviceDispositionV1::decode(&b)
                .unwrap()
                .matches_decision_pair(1, &a, &d),
            Err(Error::Denied)
        );
        // Expired-advice fallback remains a rule-only decision when it has
        // its own current admission deadline, not an AI adoption.
        let mut d = decision();
        d[144..152].copy_from_slice(&250u64.to_le_bytes());
        let mut b = disposition(&a, &d);
        b[80..88].copy_from_slice(&200u64.to_le_bytes());
        b[94..96].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(
            AdviceDispositionV1::decode(&b)
                .unwrap()
                .matches_decision_pair(1, &a, &d),
            Ok(())
        );
    }
}
