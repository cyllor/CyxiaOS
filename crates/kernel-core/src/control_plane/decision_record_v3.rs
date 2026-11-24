//! V0.19.9 DecisionRecord v3: strict 256-byte, no-alloc parser.
//!
//! Parsing or checking a RuleMatch is NOT a decision registration and can
//! never authorize a published Plan. Only the authenticated deterministic
//! controller may register frozen bytes with the EL1 sidecar; the unique
//! publisher must subsequently prove an exact matching registration.
use super::{Error, rule_profile_v2::RuleMatch};

pub const DECISION_BYTES: usize = 256;
pub const DECISION_MAGIC: u32 = 0x4359_4431;
pub const DECISION_VERSION: u16 = 3;

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let a = b.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([a[0], a[1]]))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let a = b.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([a[0], a[1], a[2], a[3]]))
}
fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let a = b.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]))
}
fn hash_at(b: &[u8], at: usize) -> Result<[u8; 32], Error> {
    b.get(at..at + 32).ok_or(Error::Invalid)?
        .try_into().map_err(|_| Error::Invalid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionSource {
    RuleOnly,
    AiAssisted,
    AuthorizedTrial,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionRecordV3 {
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub decision_seq: u64,
    pub plan_seq: u64,
    pub snapshot_seq: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub rules_generation: u64,
    pub rule_id: u32,
    pub action_index: u16,
    pub domain_id: u16,
    pub action_kind: u16,
    pub mode: u8,
    pub source: DecisionSource,
    pub disposition: u8,
    pub advice_present: bool,
    pub selected_index: u16,
    pub recommended_index: u16,
    pub reason_code: u32,
    pub advisor_epoch: u64,
    pub advice_seq: u64,
    pub advice_model_generation: u64,
    pub trial_permit_id: u64,
    pub decision_expires_ns: u64,
    pub allowed_mask: u32,
    pub fallback_index: u16,
    pub choice_policy: u16,
    pub rules_hash: [u8; 32],
    pub plan_digest: [u8; 32],
    pub candidate_set_hash: [u8; 32],
}

impl DecisionRecordV3 {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DECISION_BYTES
            || u32_at(bytes, 0)? != DECISION_MAGIC
            || u16_at(bytes, 4)? != DECISION_VERSION
            || usize::from(u16_at(bytes, 6)?) != DECISION_BYTES
            || u16_at(bytes, 106)? != 0
        {
            return Err(Error::Invalid);
        }
        let domain_id = u16_at(bytes, 94)?;
        let mode = bytes[98];
        let raw_source = bytes[99];
        // The sensitive-domain error must be returned after verifying outer
        // length and a recognizable domain, before interpreting action schema.
        if (domain_id == 6 || domain_id == 11 || domain_id == 12 || domain_id == 14)
            && raw_source == 1
        {
            return Err(Error::Denied);
        }
        let source = match raw_source {
            0 => DecisionSource::RuleOnly,
            1 => DecisionSource::AiAssisted,
            2 => DecisionSource::AuthorizedTrial,
            _ => return Err(Error::Invalid),
        };
        let advice_present = match bytes[101] {
            0 => false, 1 => true, _ => return Err(Error::Invalid),
        };
        let entry = Self {
            boot_epoch: u64_at(bytes, 8)?,
            controller_epoch: u64_at(bytes, 16)?,
            decision_seq: u64_at(bytes, 24)?,
            plan_seq: u64_at(bytes, 32)?,
            snapshot_seq: u64_at(bytes, 40)?,
            target_id: u64_at(bytes, 48)?,
            target_generation: u64_at(bytes, 56)?,
            ledger_generation: u64_at(bytes, 64)?,
            core_generation: u64_at(bytes, 72)?,
            rules_generation: u64_at(bytes, 80)?,
            rule_id: u32_at(bytes, 88)?,
            action_index: u16_at(bytes, 92)?,
            domain_id,
            action_kind: u16_at(bytes, 96)?,
            mode,
            source,
            disposition: bytes[100],
            advice_present,
            selected_index: u16_at(bytes, 102)?,
            recommended_index: u16_at(bytes, 104)?,
            reason_code: u32_at(bytes, 108)?,
            advisor_epoch: u64_at(bytes, 112)?,
            advice_seq: u64_at(bytes, 120)?,
            advice_model_generation: u64_at(bytes, 128)?,
            trial_permit_id: u64_at(bytes, 136)?,
            decision_expires_ns: u64_at(bytes, 144)?,
            allowed_mask: u32_at(bytes, 152)?,
            fallback_index: u16_at(bytes, 156)?,
            choice_policy: u16_at(bytes, 158)?,
            rules_hash: hash_at(bytes, 160)?,
            plan_digest: hash_at(bytes, 192)?,
            candidate_set_hash: hash_at(bytes, 224)?,
        };
        if !entry.structural_valid() { return Err(Error::Invalid); }
        Ok(entry)
    }
    fn structural_valid(&self) -> bool {
        if self.boot_epoch == 0 || self.controller_epoch == 0
            || self.decision_seq == 0 || self.plan_seq == 0
            || self.snapshot_seq == 0 || self.target_generation == 0
            || self.ledger_generation == 0 || self.core_generation == 0
            || self.rules_generation == 0 || self.rule_id == 0
            || self.action_index >= 16 || !(1..=15).contains(&self.domain_id)
            || self.action_kind != 1 || self.mode > 2
            || self.decision_expires_ns == 0 || self.choice_policy > 2
            || self.allowed_mask == 0 || self.selected_index >= 32
            || self.fallback_index >= 32
            || self.allowed_mask & (1u32 << self.selected_index) == 0
            || self.allowed_mask & (1u32 << self.fallback_index) == 0
            || self.rules_hash == [0; 32]
            || self.plan_digest == [0; 32]
            || self.candidate_set_hash == [0; 32]
        {
            return false;
        }
        match self.source {
            DecisionSource::RuleOnly => {
                self.disposition == 0 && !self.advice_present
                    && self.trial_permit_id == 0
                    && self.choice_policy <= 1
                    && self.selected_index == self.fallback_index
                    && self.recommended_index == u16::MAX
                    && self.advisor_epoch == 0 && self.advice_seq == 0
                    && self.advice_model_generation == 0
                    && matches!(self.reason_code, 1 | 2 | 3 | 4 | 6 | 7)
            }
            DecisionSource::AiAssisted => {
                self.mode == 2 && self.disposition == 1 && self.advice_present
                    && !matches!(self.domain_id, 6 | 11 | 12 | 14)
                    && self.choice_policy == 1
                    && self.trial_permit_id == 0
                    && self.advisor_epoch != 0 && self.advice_seq != 0
                    && self.advice_model_generation != 0
                    && self.recommended_index < 32
                    && self.selected_index == self.recommended_index
                    && self.reason_code == 8
            }
            DecisionSource::AuthorizedTrial => {
                self.disposition == 3 && !self.advice_present
                    && self.choice_policy == 2 && self.trial_permit_id != 0
                    && self.selected_index == self.fallback_index
                    && self.allowed_mask.count_ones() == 1
                    && self.recommended_index == u16::MAX
                    && self.advisor_epoch == 0 && self.advice_seq == 0
                    && self.advice_model_generation == 0
                    && self.reason_code == 5
            }
        }
    }

    /// Exact frozen candidate/rule equality is necessary but NOT sufficient
    /// for authorization. A registered decision also requires independent
    /// RuleProfile evaluation and capability/ledger/epoch/plan digest checks.
    pub fn matches_rule(self, rule: RuleMatch) -> bool {
        self.source != DecisionSource::AuthorizedTrial
            && self.rule_id == rule.rule_id
            && self.choice_policy == rule.choice_policy
            && self.allowed_mask == rule.allowed_mask
            && self.fallback_index == rule.fallback_index
    }

    /// Mask bits outside the trusted candidate count are forbidden.
    pub fn matches_candidate_count(self, candidate_count: usize) -> bool {
        if candidate_count == 0 || candidate_count > 32 {
            return false;
        }
        let full = if candidate_count == 32 { u32::MAX }
            else { (1u32 << candidate_count) - 1 };
        self.allowed_mask & !full == 0
            && usize::from(self.selected_index) < candidate_count
            && usize::from(self.fallback_index) < candidate_count
            && (self.recommended_index == u16::MAX
                || usize::from(self.recommended_index) < candidate_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn baseline() -> [u8; DECISION_BYTES] {
        let mut b = [0u8; DECISION_BYTES];
        b[0..4].copy_from_slice(&DECISION_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&DECISION_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(DECISION_BYTES as u16).to_le_bytes());
        for (at,value) in [
            (8, 1u64), (16, 2), (24, 3), (32, 4), (40, 5),
            (48, 17), (56, 6), (64, 7), (72, 8), (80, 9),
            (144, 200),
        ] { b[at..at+8].copy_from_slice(&value.to_le_bytes()); }
        b[88..92].copy_from_slice(&10u32.to_le_bytes());
        b[92..94].copy_from_slice(&0u16.to_le_bytes());
        b[94..96].copy_from_slice(&1u16.to_le_bytes());
        b[96..98].copy_from_slice(&1u16.to_le_bytes());
        b[102..104].copy_from_slice(&1u16.to_le_bytes());
        b[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
        b[108..112].copy_from_slice(&2u32.to_le_bytes());
        b[152..156].copy_from_slice(&0b11u32.to_le_bytes());
        b[156..158].copy_from_slice(&1u16.to_le_bytes());
        b[160] = 1; b[192] = 2; b[224] = 3;
        b
    }
    #[test]
    fn canonical_rule_only_v3_and_rule_binding_are_read_only() {
        let record = DecisionRecordV3::decode(&baseline()).unwrap();
        assert_eq!(record.source, DecisionSource::RuleOnly);
        assert_eq!(record.selected_index, 1);
        assert!(record.matches_candidate_count(2));
        assert!(!record.matches_candidate_count(1));
        assert!(record.matches_rule(RuleMatch {
            rule_id: 10, choice_policy: 0,
            allowed_mask: 0b11, fallback_index: 1,
        }));
        assert!(!record.matches_rule(RuleMatch {
            rule_id: 11, choice_policy: 0,
            allowed_mask: 0b11, fallback_index: 1,
        }));
    }
    #[test]
    fn canonical_assisted_and_trial_records_still_require_external_authority() {
        let mut ai=baseline();
        ai[98] = 2; // ASSISTED
        ai[99] = 1; // AI_ASSISTED
        ai[100] = 1; // ADOPTED
        ai[101] = 1; // advice present
        ai[104..106].copy_from_slice(&1u16.to_le_bytes());
        ai[108..112].copy_from_slice(&8u32.to_le_bytes());
        ai[112..120].copy_from_slice(&11u64.to_le_bytes());
        ai[120..128].copy_from_slice(&12u64.to_le_bytes());
        ai[128..136].copy_from_slice(&13u64.to_le_bytes());
        ai[158..160].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            DecisionRecordV3::decode(&ai).unwrap().source,
            DecisionSource::AiAssisted
        );
        ai[94..96].copy_from_slice(&12u16.to_le_bytes());
        assert_eq!(DecisionRecordV3::decode(&ai), Err(Error::Denied));

        let mut trial=baseline();
        trial[99] = 2;
        trial[100] = 3;
        trial[108..112].copy_from_slice(&5u32.to_le_bytes());
        trial[136..144].copy_from_slice(&14u64.to_le_bytes());
        trial[152..156].copy_from_slice(&0b10u32.to_le_bytes());
        trial[158..160].copy_from_slice(&2u16.to_le_bytes());
        let parsed=DecisionRecordV3::decode(&trial).unwrap();
        assert_eq!(parsed.source, DecisionSource::AuthorizedTrial);
        assert!(!parsed.matches_rule(RuleMatch {
            rule_id: 10, choice_policy: 2,
            allowed_mask: 0b10, fallback_index: 1,
        }));
    }
    #[test]
    fn malformed_lengths_retired_disposition_and_rule_bypass_fail_closed() {
        assert!(DecisionRecordV3::decode(&baseline()[..255]).is_err());
        for (offset, value) in [
            (4, 1u8), (6, 0), (99, 3), (100, 2), (101, 2),
            (106, 1), (152, 0), (156, 3), (160, 0),
        ] {
            let mut b=baseline();
            b[offset]=value;
            assert!(DecisionRecordV3::decode(&b).is_err(), "byte {offset}");
        }
        let mut b=baseline();
        b[108..112].copy_from_slice(&7u32.to_le_bytes());
        assert!(DecisionRecordV3::decode(&b).is_ok());
        // reason7 requires an independently frozen Disposition; a parsed
        // record alone is never sufficient to register or execute it.
    }
}
