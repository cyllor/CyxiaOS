//! Canonical 152-byte AdviceEnvelope v1 reader for authenticated local IPC.
//!
//! The EL1 owner, NOT the model, supplies TrustedAdviceScope (snapshots,
//! ordinals, role epoch and hashes). A decoded advice may only nominate a
//! candidate for a subsequent independent RuleProfile/ledger review.
//! This module does not assign capabilities or publish plans.
use super::{
    Epochs, Error, Identity,
    advisory::{Advice, TrustedScope},
};

pub const ADVICE_BYTES: usize = 152;
pub const ADVICE_MAGIC: u32 = 0x4359_4131;
pub const ADVICE_VERSION: u16 = 1;
pub const MAX_ADVICE_LIFETIME_NS: u64 = 100_000_000;

fn le16(bytes: &[u8], at: usize) -> Result<u16, Error> {
    let s = bytes.get(at..at + 2).ok_or(Error::Invalid)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn le32(bytes: &[u8], at: usize) -> Result<u32, Error> {
    let s = bytes.get(at..at + 4).ok_or(Error::Invalid)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le64(bytes: &[u8], at: usize) -> Result<u64, Error> {
    let s = bytes.get(at..at + 8).ok_or(Error::Invalid)?;
    Ok(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}
fn digest(bytes: &[u8], at: usize) -> Result<[u8; 32], Error> {
    bytes.get(at..at + 32).ok_or(Error::Invalid)?
        .try_into().map_err(|_| Error::Invalid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdviceEnvelopeV1 {
    pub advisor_epoch: u64,
    pub advice_seq: u64,
    pub snapshot_seq: u64,
    pub target: Identity,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub expires_ns: u64,
    pub active_model_generation: u64,
    pub domain: u16,
    pub action_kind: u16,
    pub recommended_index: u16,
    pub candidate_count: u16,
    pub model_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
}

/// Snapshot and candidate information owned by trusted native EL1, never
/// reconstructed from a model-supplied envelope. Candidate ordinals/values
/// are read only from the frozen action table.
pub struct TrustedAdviceScope<'a> {
    pub epochs: Epochs,
    pub advisor_epoch: u64,
    pub snapshot_seq: u64,
    pub domain: u16,
    pub target: Identity,
    pub sampled_ns: u64,
    pub now_ns: u64,
    pub action_kind: u16,
    pub candidates: &'a [u16],
    pub model_hash: [u8; 32],
    pub candidate_set_hash: [u8; 32],
}
impl<'a> TrustedAdviceScope<'a> {
    pub fn review_scope(&self) -> TrustedScope {
        TrustedScope {
            epochs: self.epochs,
            domain: self.domain as usize,
            target: self.target,
            now_ns: self.now_ns,
        }
    }
}
impl AdviceEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ADVICE_BYTES
            || le32(bytes, 0)? != ADVICE_MAGIC
            || le16(bytes, 4)? != ADVICE_VERSION
            || usize::from(le16(bytes, 6)?) != ADVICE_BYTES
        {
            return Err(Error::Invalid);
        }
        let result = Self {
            advisor_epoch: le64(bytes, 8)?,
            advice_seq: le64(bytes, 16)?,
            snapshot_seq: le64(bytes, 24)?,
            target: Identity {
                id: le64(bytes, 32)?,
                generation: le64(bytes, 40)?,
            },
            ledger_generation: le64(bytes, 48)?,
            core_generation: le64(bytes, 56)?,
            expires_ns: le64(bytes, 64)?,
            active_model_generation: le64(bytes, 72)?,
            domain: le16(bytes, 80)?,
            action_kind: le16(bytes, 82)?,
            recommended_index: le16(bytes, 84)?,
            candidate_count: le16(bytes, 86)?,
            model_hash: digest(bytes, 88)?,
            candidate_set_hash: digest(bytes, 120)?,
        };
        if result.advisor_epoch == 0
            || result.advice_seq == 0
            || result.snapshot_seq == 0
            || !result.target.valid()
            || result.ledger_generation == 0
            || result.core_generation == 0
            || result.expires_ns == 0
            || result.active_model_generation == 0
            || !(1..=15).contains(&result.domain)
            || result.action_kind != 1
            || !(1..=32).contains(&result.candidate_count)
            || result.recommended_index >= result.candidate_count
            || result.model_hash == [0; 32]
            || result.candidate_set_hash == [0; 32]
        {
            return Err(Error::Invalid);
        }
        Ok(result)
    }

    /// Fail closed on unknown sender-owned data. Only the trusted candidate
    /// *value*, not an untrusted index, enters the pre-existing advisory path.
    pub fn into_advice(self, scope: &TrustedAdviceScope<'_>) -> Result<Advice, Error> {
        if !scope.epochs.valid()
            || !scope.target.valid()
            || scope.advisor_epoch == 0
            || scope.snapshot_seq == 0
            || !(1..=15).contains(&scope.domain)
            || scope.action_kind != 1
            || scope.candidates.is_empty()
            || scope.candidates.len() > 32
            || self.advisor_epoch != scope.advisor_epoch
            || self.snapshot_seq != scope.snapshot_seq
            || self.target != scope.target
            || self.ledger_generation != scope.epochs.resources
            || self.core_generation != scope.epochs.cores
            || self.active_model_generation != scope.epochs.model
            || self.domain != scope.domain
            || self.action_kind != scope.action_kind
            || usize::from(self.candidate_count) != scope.candidates.len()
            || self.model_hash != scope.model_hash
            || self.candidate_set_hash != scope.candidate_set_hash
            || scope.sampled_ns > scope.now_ns
            || self.expires_ns <= scope.now_ns
            || self.expires_ns <= scope.sampled_ns
            || !scope.sampled_ns.checked_add(MAX_ADVICE_LIFETIME_NS)
                .is_some_and(|end| self.expires_ns <= end)
        {
            return Err(Error::Denied);
        }
        let candidate = *scope.candidates.get(usize::from(self.recommended_index))
            .ok_or(Error::Invalid)?;
        Ok(Advice {
            epochs: scope.epochs,
            model_generation: scope.epochs.model,
            domain: usize::from(scope.domain),
            target: scope.target,
            candidate,
            snapshot_ns: scope.sampled_ns,
            expires_ns: self.expires_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes() -> [u8; ADVICE_BYTES] {
        let mut b = [0u8; ADVICE_BYTES];
        b[0..4].copy_from_slice(&ADVICE_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&ADVICE_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(ADVICE_BYTES as u16).to_le_bytes());
        for (at, v) in [
            (8, 7u64), (16, 1), (24, 42), (32, 17),
            (40, 5), (48, 9), (56, 11), (64, 200),
            (72, 6),
        ] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[80..82].copy_from_slice(&3u16.to_le_bytes());
        b[82..84].copy_from_slice(&1u16.to_le_bytes());
        b[84..86].copy_from_slice(&2u16.to_le_bytes());
        b[86..88].copy_from_slice(&3u16.to_le_bytes());
        b[88] = 1;
        b[120] = 2;
        b
    }
    fn scope<'a>(candidates: &'a [u16]) -> TrustedAdviceScope<'a> {
        let mut model_hash = [0u8; 32]; model_hash[0] = 1;
        let mut candidate_set_hash = [0u8; 32]; candidate_set_hash[0] = 2;
        TrustedAdviceScope {
            epochs: Epochs {
                boot: 1, controller: 3, model: 6, resources: 9, cores: 11,
            },
            advisor_epoch: 7,
            snapshot_seq: 42,
            domain: 3,
            target: Identity { id: 17, generation: 5 },
            sampled_ns: 100,
            now_ns: 150,
            action_kind: 1,
            candidates,
            model_hash,
            candidate_set_hash,
        }
    }

    #[test]
    fn exact_152_byte_frame_uses_trusted_candidate_value() {
        let frame = AdviceEnvelopeV1::decode(&bytes()).unwrap();
        let verified = frame.into_advice(&scope(&[1, 2, 4])).unwrap();
        assert_eq!(verified.candidate, 4);
        assert_eq!(verified.epochs.resources, 9);
        assert_eq!(verified.model_generation, 6);
        let mut protected = scope(&[1, 2, 4]);
        protected.now_ns = 200;
        assert!(frame.into_advice(&protected).is_err());
        protected.now_ns = 150;
        protected.advisor_epoch = 8;
        assert!(frame.into_advice(&protected).is_err());
    }

    #[test]
    fn reject_old_schema_extra_tail_wrong_indices_and_unauthorized_scope() {
        assert!(AdviceEnvelopeV1::decode(&bytes()[..151]).is_err());
        let mut bad = bytes();
        bad[4] = 2;
        assert!(AdviceEnvelopeV1::decode(&bad).is_err());
        bad = bytes(); bad[86..88].copy_from_slice(&33u16.to_le_bytes());
        assert!(AdviceEnvelopeV1::decode(&bad).is_err());
        bad = bytes(); bad[84..86].copy_from_slice(&3u16.to_le_bytes());
        assert!(AdviceEnvelopeV1::decode(&bad).is_err());
        bad = bytes(); bad[82..84].copy_from_slice(&2u16.to_le_bytes());
        assert!(AdviceEnvelopeV1::decode(&bad).is_err());

        let frame = AdviceEnvelopeV1::decode(&bytes()).unwrap();
        let mut protected = scope(&[1, 2, 4]);
        protected.target.generation += 1;
        assert!(frame.into_advice(&protected).is_err());
        protected = scope(&[1, 2, 4]);
        protected.candidate_set_hash = [9; 32];
        assert!(frame.into_advice(&protected).is_err());
        protected = scope(&[1, 2, 4]);
        protected.epochs.model += 1;
        assert!(frame.into_advice(&protected).is_err());
        protected = scope(&[1, 2, 4]);
        protected.sampled_ns = u64::MAX;
        protected.now_ns = u64::MAX;
        assert!(frame.into_advice(&protected).is_err());
    }
    #[test]
    fn over_100ms_lifetime_never_reaches_advisory_review() {
        let mut b = bytes();
        b[64..72].copy_from_slice(&100_000_201u64.to_le_bytes());
        let frame = AdviceEnvelopeV1::decode(&b).unwrap();
        assert!(frame.into_advice(&scope(&[1, 2, 4])).is_err());
    }
}
