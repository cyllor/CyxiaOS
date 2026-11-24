//! Canonical SecurityFinding v2 risk-report wire, not an action proposal.
//!
//! EL1 authenticates the role and builds FrozenObservation from protected
//! snapshot metadata. A REVIEW_RESTRICTION hint requests an independent
//! deterministic review. It is never an allow, deny, policy, or execution.
use super::{Error, Identity};

pub const FINDING_BYTES: usize = 192;
pub const FINDING_MAGIC: u32 = 0x4359_4644;
pub const FINDING_VERSION: u16 = 2;
pub const MAX_FINDING_AGE_NS: u64 = 100_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityFinding {
    pub boot_epoch: u64,
    pub security_epoch: u64,
    pub finding_seq: u64,
    pub snapshot_seq: u64,
    pub target: Identity,
    pub expires_ns: u64,
    pub kind: u16,
    pub severity: u8,
    pub hint: u8,
    pub evidence_count: u16,
    pub evidence_digest: [u8; 32],
    pub model_hash: [u8; 32],
    pub config_hash: [u8; 32],
    pub score_q8_8: i16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenObservation {
    pub boot_epoch: u64,
    pub security_epoch: u64,
    pub snapshot_seq: u64,
    pub domain_id: u16,
    pub target: Identity,
    pub sampled_ns: u64,
    pub now_ns: u64,
    pub model_hash: [u8; 32],
    pub config_hash: [u8; 32],
}

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

/// The observation class comes from the trusted snapshot, not model scoring.
pub const fn domain_for_kind(kind: u16) -> Option<u16> {
    match kind {
        1 => Some(12), // AUTH_ANOMALY
        2 => Some(3),  // MEMORY_FAULT
        3 => Some(10), // NETWORK_ABUSE
        4 => Some(11), // DEVICE_ANOMALY
        5 => Some(4),  // FILE_RECOVERY
        _ => None,
    }
}
impl SecurityFinding {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != FINDING_BYTES
            || u32_at(bytes, 0)? != FINDING_MAGIC
            || u16_at(bytes, 4)? != FINDING_VERSION
            || usize::from(u16_at(bytes, 6)?) != FINDING_BYTES
            || u16_at(bytes, 70)? != 0
            || bytes[170..].iter().any(|b| *b != 0)
        {
            return Err(Error::Invalid);
        }
        let value = Self {
            boot_epoch: u64_at(bytes, 8)?,
            security_epoch: u64_at(bytes, 16)?,
            finding_seq: u64_at(bytes, 24)?,
            snapshot_seq: u64_at(bytes, 32)?,
            target: Identity { id: u64_at(bytes, 40)?, generation: u64_at(bytes, 48)? },
            expires_ns: u64_at(bytes, 56)?,
            kind: u16_at(bytes, 64)?,
            severity: bytes[66],
            hint: bytes[67],
            evidence_count: u16_at(bytes, 68)?,
            evidence_digest: hash_at(bytes, 72)?,
            model_hash: hash_at(bytes, 104)?,
            config_hash: hash_at(bytes, 136)?,
            score_q8_8: u16_at(bytes, 168)? as i16,
        };
        if !value.structurally_valid() { return Err(Error::Invalid); }
        Ok(value)
    }
    fn structurally_valid(&self) -> bool {
        self.boot_epoch != 0 && self.security_epoch != 0
            && self.finding_seq != 0 && self.snapshot_seq != 0
            && self.target.valid() && self.expires_ns != 0
            && domain_for_kind(self.kind).is_some()
            && self.hint <= 1 && self.evidence_count != 0
            && self.evidence_digest != [0; 32]
            && self.model_hash != [0; 32] && self.config_hash != [0; 32]
            && match self.score_q8_8 {
                1..=255 => self.severity == 1,
                256..=511 => self.severity == 2,
                512..=i16::MAX => self.severity == 3,
                _ => false,
            }
    }
    /// True merely requests a new deterministic RuleProfile review.
    pub fn requests_review(&self, trusted: FrozenObservation) -> bool {
        self.structurally_valid()
            && self.hint == 1
            && self.boot_epoch == trusted.boot_epoch
            && self.security_epoch == trusted.security_epoch
            && self.snapshot_seq == trusted.snapshot_seq
            && domain_for_kind(self.kind) == Some(trusted.domain_id)
            && self.target == trusted.target
            && self.model_hash == trusted.model_hash
            && self.config_hash == trusted.config_hash
            && trusted.sampled_ns <= trusted.now_ns
            && trusted.now_ns < self.expires_ns
            && self.expires_ns <= trusted.sampled_ns.saturating_add(MAX_FINDING_AGE_NS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire() -> [u8; FINDING_BYTES] {
        let mut b = [0u8; FINDING_BYTES];
        b[0..4].copy_from_slice(&FINDING_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&FINDING_VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&(FINDING_BYTES as u16).to_le_bytes());
        for (at, v) in [(8, 1u64), (16, 2), (24, 3), (32, 4), (40, 5), (48, 6), (56, 190)] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[64..66].copy_from_slice(&1u16.to_le_bytes());
        b[66] = 2;
        b[67] = 1;
        b[68..70].copy_from_slice(&1u16.to_le_bytes());
        b[72] = 1;
        b[104] = 2;
        b[136] = 3;
        b[168..170].copy_from_slice(&256i16.to_le_bytes());
        b
    }
    fn observation() -> FrozenObservation {
        FrozenObservation {
            boot_epoch: 1, security_epoch: 2, snapshot_seq: 4,
            domain_id: 12, target: Identity { id: 5, generation: 6 },
            sampled_ns: 100, now_ns: 150,
            model_hash: { let mut h=[0;32]; h[0]=2; h },
            config_hash: { let mut h=[0;32]; h[0]=3; h },
        }
    }
    #[test]
    fn canonical_finding_is_only_independent_review_request() {
        let f = SecurityFinding::decode(&wire()).unwrap();
        assert!(f.requests_review(observation()));
        let mut stale = observation(); stale.snapshot_seq += 1;
        assert!(!f.requests_review(stale));
        let mut other_domain = observation(); other_domain.domain_id = 1;
        assert!(!f.requests_review(other_domain));
        let mut old = observation(); old.now_ns = 190;
        assert!(!f.requests_review(old));
    }
    #[test]
    fn corrupt_length_reserved_kind_score_and_legacy_format_fail_closed() {
        for (at, value) in [(0, 0), (4, 1), (6, 0), (64, 99), (66, 3), (67, 2), (70, 1), (171, 1)] {
            let mut b = wire(); b[at] = value;
            assert!(SecurityFinding::decode(&b).is_err(), "offset {at}");
        }
        assert!(SecurityFinding::decode(&wire()[..191]).is_err());
        let mut b=wire(); b[168..170].copy_from_slice(&(-1i16).to_le_bytes());
        assert!(SecurityFinding::decode(&b).is_err());
        let mut b=wire(); b[136]=0;
        assert!(SecurityFinding::decode(&b).is_err());
    }
}
