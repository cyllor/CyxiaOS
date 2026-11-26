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
    Ok(u64::from_le_bytes([
        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
    ]))
}
fn hash_at(b: &[u8], at: usize) -> Result<[u8; 32], Error> {
    b.get(at..at + 32)
        .ok_or(Error::Invalid)?
        .try_into()
        .map_err(|_| Error::Invalid)
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
            target: Identity {
                id: u64_at(bytes, 40)?,
                generation: u64_at(bytes, 48)?,
            },
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
        if !value.structurally_valid() {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    fn structurally_valid(&self) -> bool {
        self.boot_epoch != 0
            && self.security_epoch != 0
            && self.finding_seq != 0
            && self.snapshot_seq != 0
            && self.target.valid()
            && self.expires_ns != 0
            && domain_for_kind(self.kind).is_some()
            && self.hint <= 1
            && self.evidence_count != 0
            && self.evidence_digest != [0; 32]
            && self.model_hash != [0; 32]
            && self.config_hash != [0; 32]
            && match self.score_q8_8 {
                1..=255 => self.severity == 1,
                256..=511 => self.severity == 2,
                512..=i16::MAX => self.severity == 3,
                _ => false,
            }
    }
    fn matches_scope(&self, trusted: FrozenObservation) -> bool {
        self.structurally_valid()
            && self.boot_epoch == trusted.boot_epoch
            && self.security_epoch == trusted.security_epoch
            && self.snapshot_seq == trusted.snapshot_seq
            && domain_for_kind(self.kind) == Some(trusted.domain_id)
            && self.target == trusted.target
            && self.model_hash == trusted.model_hash
            && self.config_hash == trusted.config_hash
            && trusted.sampled_ns <= trusted.now_ns
            && trusted.now_ns < self.expires_ns
            && trusted
                .sampled_ns
                .checked_add(MAX_FINDING_AGE_NS)
                .is_some_and(|end| self.expires_ns <= end)
    }

    /// True merely requests a new deterministic RuleProfile review.
    pub fn requests_review(&self, trusted: FrozenObservation) -> bool {
        self.hint == 1 && self.matches_scope(trusted)
    }
}

/// Canonical FindingDisposition v2, generated only by the protected
/// consumer. A REVIEWED disposition is an observation of an independent
/// rule result, not an execution receipt or an authorization token.
pub const FINDING_DISPOSITION_BYTES: usize = 128;
pub const FINDING_DISPOSITION_MAGIC: u32 = 0x4359_4650;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingDisposition {
    pub boot_epoch: u64,
    pub security_epoch: u64,
    pub finding_seq: u64,
    pub snapshot_seq: u64,
    pub processed_ns: u64,
    pub state: u16,
    pub reason_code: u16,
    pub model_hash: [u8; 32],
    pub finding_digest: [u8; 32],
}
impl FindingDisposition {
    fn valid(&self) -> bool {
        self.boot_epoch != 0
            && self.security_epoch != 0
            && self.finding_seq != 0
            && self.snapshot_seq != 0
            && self.model_hash != [0; 32]
            && self.finding_digest != [0; 32]
            && matches!(
                (self.state, self.reason_code),
                (1, 0) | (2, 1 | 2) | (3, 3) | (4, 4..=6) | (5, 7 | 8)
            )
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != FINDING_DISPOSITION_BYTES
            || u32_at(b, 0)? != FINDING_DISPOSITION_MAGIC
            || u16_at(b, 4)? != 2
            || u16_at(b, 6)? != 128
            || u32_at(b, 52)? != 0
            || b[120..].iter().any(|v| *v != 0)
        {
            return Err(Error::Invalid);
        }
        let d = Self {
            boot_epoch: u64_at(b, 8)?,
            security_epoch: u64_at(b, 16)?,
            finding_seq: u64_at(b, 24)?,
            snapshot_seq: u64_at(b, 32)?,
            processed_ns: u64_at(b, 40)?,
            state: u16_at(b, 48)?,
            reason_code: u16_at(b, 50)?,
            model_hash: hash_at(b, 56)?,
            finding_digest: hash_at(b, 88)?,
        };
        if !d.valid() {
            return Err(Error::Invalid);
        }
        Ok(d)
    }
    pub fn encode(self) -> Result<[u8; FINDING_DISPOSITION_BYTES], Error> {
        if !self.valid() {
            return Err(Error::Invalid);
        }
        let mut b = [0; FINDING_DISPOSITION_BYTES];
        b[..4].copy_from_slice(&FINDING_DISPOSITION_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&2u16.to_le_bytes());
        b[6..8].copy_from_slice(&128u16.to_le_bytes());
        for (at, v) in [
            (8, self.boot_epoch),
            (16, self.security_epoch),
            (24, self.finding_seq),
            (32, self.snapshot_seq),
            (40, self.processed_ns),
        ] {
            b[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        b[48..50].copy_from_slice(&self.state.to_le_bytes());
        b[50..52].copy_from_slice(&self.reason_code.to_le_bytes());
        b[56..88].copy_from_slice(&self.model_hash);
        b[88..120].copy_from_slice(&self.finding_digest);
        Ok(b)
    }
}
fn finding_sha256(b: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).into()
}

/// Trusted EL1 adapter supplies the independent consumer outcome, never a
/// role7 message. The Reviewed variants require a separately authenticated
/// controller observation; this ledger does not create that proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingResolution {
    Recorded,
    IgnoredPolicy,
    IgnoredBackpressure,
    Expired,
    InvalidTarget,
    IndependentRuleRejected,
    IndependentRuleEntered,
}
impl FindingResolution {
    fn pair(self) -> (u16, u16) {
        match self {
            Self::Recorded => (1, 0),
            Self::IgnoredPolicy => (2, 1),
            Self::IgnoredBackpressure => (2, 2),
            Self::Expired => (3, 3),
            Self::InvalidTarget => (4, 6),
            Self::IndependentRuleRejected => (5, 7),
            Self::IndependentRuleEntered => (5, 8),
        }
    }
}
#[derive(Clone, Copy)]
struct DispositionStamp {
    processed_ns: u64,
    resolution: FindingResolution,
}

/// Protected role7/role11 evaluation and review custody. The native EL1
/// adapter supplies these scopes from an authorized 0x40 snapshot, binds
/// both actor identities and the offline mode, and separately accounts CPU.
/// No field or method grants an action, capability, restriction or APPLIED.
pub const FINDING_SLOTS: usize = 16;
pub const EVALUATIONS_PER_WINDOW: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingMode {
    Disabled,
    Shadow,
    Assisted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredObservation {
    pub scope: FrozenObservation,
    pub evidence_count: u16,
    pub evidence_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewTarget {
    pub finding_seq: u64,
    pub domain_id: u16,
    pub target: Identity,
    pub evidence_digest: [u8; 32],
    /// Only an index for a fresh independent deterministic review.
    pub request_review: bool,
}

#[derive(Clone, Copy)]
struct FindingRow {
    observation: RegisteredObservation,
    mode: FindingMode,
    expires_ns: u64,
    finding: Option<SecurityFinding>,
    consumed: bool,
    review_eligible: bool,
    finding_digest: [u8; 32],
    terminal: Option<DispositionStamp>,
    audit_acked: bool,
}
const _: () = assert!(core::mem::size_of::<Option<FindingRow>>() <= 512);

pub struct FindingCustody {
    security: Identity,
    supervisor: Identity,
    boot_epoch: u64,
    security_epoch: u64,
    high_water: u64,
    last_ns: u64,
    window: u64,
    evaluations: u8,
    rows: [Option<FindingRow>; FINDING_SLOTS],
}

impl FindingCustody {
    pub fn new(
        security: Identity,
        supervisor: Identity,
        boot_epoch: u64,
        security_epoch: u64,
    ) -> Result<Self, Error> {
        if !security.valid()
            || !supervisor.valid()
            || security.id == supervisor.id
            || boot_epoch == 0
            || security_epoch == 0
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            security,
            supervisor,
            boot_epoch,
            security_epoch,
            high_water: 0,
            last_ns: 0,
            window: 0,
            evaluations: 0,
            rows: [None; FINDING_SLOTS],
        })
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_ns {
            return Err(Error::Clock);
        }
        self.last_ns = now;
        let window = now / MAX_FINDING_AGE_NS;
        if window != self.window {
            self.window = window;
            self.evaluations = 0;
        }
        Ok(())
    }
    fn same_context(a: FrozenObservation, b: FrozenObservation) -> bool {
        a.boot_epoch == b.boot_epoch
            && a.security_epoch == b.security_epoch
            && a.snapshot_seq == b.snapshot_seq
            && a.domain_id == b.domain_id
            && a.target == b.target
    }
    fn valid_observation(&self, o: RegisteredObservation) -> bool {
        let s = o.scope;
        s.boot_epoch == self.boot_epoch
            && s.security_epoch == self.security_epoch
            && s.snapshot_seq != 0
            && s.target.valid()
            && (1..=5).any(|kind| domain_for_kind(kind) == Some(s.domain_id))
            && s.sampled_ns <= s.now_ns
            && s.sampled_ns
                .checked_add(MAX_FINDING_AGE_NS)
                .is_some_and(|end| s.now_ns < end)
            && s.model_hash != [0; 32]
            && s.config_hash != [0; 32]
            && o.evidence_count != 0
            && o.evidence_digest != [0; 32]
    }
    /// Reserve before copying an authorized safety view to EL0. Full queues
    /// and exhausted evaluation counts drop only advisory work.
    pub fn reserve(
        &mut self,
        actor: Identity,
        observation: RegisteredObservation,
        mode: FindingMode,
    ) -> Result<(), Error> {
        if actor != self.security || mode == FindingMode::Disabled {
            return Err(Error::Denied);
        }
        if !self.valid_observation(observation) {
            return Err(Error::Invalid);
        }
        self.time(observation.scope.now_ns)?;
        if self
            .rows
            .iter()
            .flatten()
            .any(|r| Self::same_context(r.observation.scope, observation.scope))
        {
            return Err(Error::Busy);
        }
        if self.evaluations >= EVALUATIONS_PER_WINDOW {
            return Err(Error::Exhausted);
        }
        let at = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Exhausted)?;
        let expires_ns = observation
            .scope
            .sampled_ns
            .checked_add(MAX_FINDING_AGE_NS)
            .ok_or(Error::Invalid)?;
        self.rows[at] = Some(FindingRow {
            observation,
            mode,
            expires_ns,
            finding: None,
            consumed: false,
            review_eligible: false,
            finding_digest: [0; 32],
            terminal: None,
            audit_acked: false,
        });
        self.evaluations += 1;
        Ok(())
    }
    pub fn submit(&mut self, actor: Identity, wire: &[u8], now: u64) -> Result<(), Error> {
        if actor != self.security {
            return Err(Error::Denied);
        }
        let finding = SecurityFinding::decode(wire)?;
        self.time(now)?;
        let domain = domain_for_kind(finding.kind).ok_or(Error::Invalid)?;
        let at = self
            .rows
            .iter()
            .position(|r| {
                r.is_some_and(|r| {
                    let s = r.observation.scope;
                    s.boot_epoch == finding.boot_epoch
                        && s.security_epoch == finding.security_epoch
                        && s.snapshot_seq == finding.snapshot_seq
                        && s.target == finding.target
                        && s.domain_id == domain
                })
            })
            .ok_or(Error::Stale)?;
        let row = self.rows[at].as_mut().ok_or(Error::Stale)?;
        if row.consumed || row.terminal.is_some() {
            return Err(Error::Stale);
        }
        let mut scope = row.observation.scope;
        scope.now_ns = now;
        if !finding.matches_scope(scope)
            || finding.evidence_count != row.observation.evidence_count
            || finding.evidence_digest != row.observation.evidence_digest
        {
            return Err(Error::Denied);
        }
        if let Some(existing) = row.finding {
            return if existing == finding {
                Ok(())
            } else {
                Err(Error::Denied)
            };
        }
        if finding.finding_seq <= self.high_water {
            return Err(Error::Stale);
        }
        row.finding = Some(finding);
        row.finding_digest = finding_sha256(wire);
        self.high_water = finding.finding_seq;
        Ok(())
    }
    /// Only role11 may consume. SHADOW, mode downgrade and missing current
    /// offline authorization yield observation-only evidence. A stale or
    /// relabelled context never creates a review target.
    pub fn consume(
        &mut self,
        actor: Identity,
        finding_seq: u64,
        current: RegisteredObservation,
        mode: FindingMode,
        offline_review_allowed: bool,
    ) -> Result<ReviewTarget, Error> {
        if actor != self.supervisor {
            return Err(Error::Denied);
        }
        if !self.valid_observation(current) {
            return Err(Error::Invalid);
        }
        self.time(current.scope.now_ns)?;
        let row = self
            .rows
            .iter_mut()
            .flatten()
            .find(|r| r.finding.is_some_and(|f| f.finding_seq == finding_seq))
            .ok_or(Error::Stale)?;
        // InvalidTarget can finalize an admitted finding before review. Its
        // retained terminal evidence must never be turned back into work,
        // including after the audit owner has acknowledged the disposition.
        if row.consumed || row.terminal.is_some() {
            return Err(Error::Stale);
        }
        let f = row.finding.ok_or(Error::NotReady)?;
        let mut registered = row.observation;
        registered.scope.now_ns = current.scope.now_ns;
        if registered != current || !f.matches_scope(current.scope) {
            return Err(Error::Denied);
        }
        row.consumed = true;
        row.review_eligible = row.mode == FindingMode::Assisted
            && mode == FindingMode::Assisted
            && offline_review_allowed
            && f.hint == 1;
        // Retain the context tombstone until expiry so a reread of the same
        // snapshot cannot reserve another evaluation and reissue its finding.
        Ok(ReviewTarget {
            finding_seq,
            domain_id: current.scope.domain_id,
            target: f.target,
            evidence_digest: f.evidence_digest,
            request_review: row.review_eligible,
        })
    }
    fn disposition(row: &FindingRow) -> Result<FindingDisposition, Error> {
        let f = row.finding.ok_or(Error::NotReady)?;
        let stamp = row.terminal.ok_or(Error::NotReady)?;
        let (state, reason_code) = stamp.resolution.pair();
        Ok(FindingDisposition {
            boot_epoch: f.boot_epoch,
            security_epoch: f.security_epoch,
            finding_seq: f.finding_seq,
            snapshot_seq: f.snapshot_seq,
            processed_ns: stamp.processed_ns,
            state,
            reason_code,
            model_hash: f.model_hash,
            finding_digest: row.finding_digest,
        })
    }

    /// Freeze exactly one disposition for an authenticated admitted finding.
    /// The protected consumer must independently establish InvalidTarget or
    /// either rule outcome. No score/hint can establish those facts.
    pub fn finalize(
        &mut self,
        actor: Identity,
        finding_seq: u64,
        resolution: FindingResolution,
        now: u64,
    ) -> Result<FindingDisposition, Error> {
        if actor != self.supervisor {
            return Err(Error::Denied);
        }
        self.time(now)?;
        let row = self
            .rows
            .iter_mut()
            .flatten()
            .find(|r| r.finding.is_some_and(|f| f.finding_seq == finding_seq))
            .ok_or(Error::Stale)?;
        if let Some(old) = row.terminal {
            return if old.resolution == resolution {
                Self::disposition(row)
            } else {
                Err(Error::Denied)
            };
        }
        let f = row.finding.ok_or(Error::NotReady)?;
        use FindingResolution::*;
        let valid = match resolution {
            Expired => now >= f.expires_ns,
            InvalidTarget => true, // trusted consumer's current target check
            Recorded | IgnoredPolicy => row.consumed && !row.review_eligible && now < f.expires_ns,
            IgnoredBackpressure => row.consumed && now < f.expires_ns,
            IndependentRuleRejected | IndependentRuleEntered => {
                row.consumed && row.review_eligible && now < f.expires_ns
            }
        };
        if !valid {
            return Err(Error::Denied);
        }
        row.terminal = Some(DispositionStamp {
            processed_ns: now,
            resolution,
        });
        Self::disposition(row)
    }
    pub fn query_disposition(
        &self,
        actor: Identity,
        finding_seq: u64,
    ) -> Result<FindingDisposition, Error> {
        if actor != self.supervisor {
            return Err(Error::Denied);
        }
        let row = self
            .rows
            .iter()
            .flatten()
            .find(|r| r.finding.is_some_and(|f| f.finding_seq == finding_seq))
            .ok_or(Error::Stale)?;
        Self::disposition(row)
    }
    /// The EL1 audit owner must record the exact disposition before ACK.
    /// ACK never grants review permission; the context remains a tombstone
    /// until its evaluation lifetime expires.
    pub fn acknowledge_disposition(
        &mut self,
        actor: Identity,
        finding_seq: u64,
        digest: [u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        if actor != self.supervisor {
            return Err(Error::Denied);
        }
        self.time(now)?;
        let row = self
            .rows
            .iter_mut()
            .flatten()
            .find(|r| r.finding.is_some_and(|f| f.finding_seq == finding_seq))
            .ok_or(Error::Stale)?;
        if finding_sha256(&Self::disposition(row)?.encode()?) != digest {
            return Err(Error::Denied);
        }
        row.audit_acked = true;
        Ok(())
    }
    pub fn reap_expired(&mut self, actor: Identity, now: u64) -> Result<usize, Error> {
        if actor != self.supervisor {
            return Err(Error::Denied);
        }
        self.time(now)?;
        let mut count = 0;
        for slot in &mut self.rows {
            let Some(row) = slot.as_mut() else {
                continue;
            };
            if let Some(f) = row.finding {
                if row.terminal.is_none() && now >= f.expires_ns {
                    row.terminal = Some(DispositionStamp {
                        processed_ns: now,
                        resolution: FindingResolution::Expired,
                    });
                }
                if !row.audit_acked {
                    continue;
                }
            }
            if now >= row.expires_ns {
                *slot = None;
                count += 1;
            }
        }
        Ok(count)
    }
    pub fn occupied(&self) -> usize {
        self.rows.iter().flatten().count()
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
        for (at, v) in [
            (8, 1u64),
            (16, 2),
            (24, 3),
            (32, 4),
            (40, 5),
            (48, 6),
            (56, 190),
        ] {
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
            boot_epoch: 1,
            security_epoch: 2,
            snapshot_seq: 4,
            domain_id: 12,
            target: Identity {
                id: 5,
                generation: 6,
            },
            sampled_ns: 100,
            now_ns: 150,
            model_hash: {
                let mut h = [0; 32];
                h[0] = 2;
                h
            },
            config_hash: {
                let mut h = [0; 32];
                h[0] = 3;
                h
            },
        }
    }
    #[test]
    fn canonical_finding_is_only_independent_review_request() {
        let f = SecurityFinding::decode(&wire()).unwrap();
        assert!(f.requests_review(observation()));
        let mut stale = observation();
        stale.snapshot_seq += 1;
        assert!(!f.requests_review(stale));
        let mut other_domain = observation();
        other_domain.domain_id = 1;
        assert!(!f.requests_review(other_domain));
        let mut old = observation();
        old.now_ns = 190;
        assert!(!f.requests_review(old));
    }
    #[test]
    fn overflowing_finding_deadline_is_never_a_valid_review_request() {
        let mut finding = SecurityFinding::decode(&wire()).unwrap();
        finding.expires_ns = u64::MAX;
        let mut trusted = observation();
        trusted.sampled_ns = u64::MAX - 100;
        trusted.now_ns = u64::MAX - 2;
        assert!(!finding.requests_review(trusted));
    }
    #[test]
    fn corrupt_length_reserved_kind_score_and_legacy_format_fail_closed() {
        for (at, value) in [
            (0, 0),
            (4, 1),
            (6, 0),
            (64, 99),
            (66, 3),
            (67, 2),
            (70, 1),
            (171, 1),
        ] {
            let mut b = wire();
            b[at] = value;
            assert!(SecurityFinding::decode(&b).is_err(), "offset {at}");
        }
        assert!(SecurityFinding::decode(&wire()[..191]).is_err());
        let mut b = wire();
        b[168..170].copy_from_slice(&(-1i16).to_le_bytes());
        assert!(SecurityFinding::decode(&b).is_err());
        let mut b = wire();
        b[136] = 0;
        assert!(SecurityFinding::decode(&b).is_err());
    }
    const ROLE7: Identity = Identity {
        id: 7,
        generation: 1,
    };
    const ROLE11: Identity = Identity {
        id: 11,
        generation: 1,
    };
    fn registered() -> RegisteredObservation {
        RegisteredObservation {
            scope: observation(),
            evidence_count: 1,
            evidence_digest: {
                let mut h = [0; 32];
                h[0] = 1;
                h
            },
        }
    }
    #[test]
    fn bounded_context_custody_binds_evidence_and_consumes_review_once() {
        let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
        let o = registered();
        assert_eq!(q.submit(ROLE7, &wire(), 150), Err(Error::Stale));
        assert_eq!(
            q.reserve(ROLE7, o, FindingMode::Disabled),
            Err(Error::Denied)
        );
        q.reserve(ROLE7, o, FindingMode::Assisted).unwrap();
        let mut wrong = wire();
        wrong[72] = 9;
        assert_eq!(q.submit(ROLE7, &wrong, 150), Err(Error::Denied));
        assert_eq!(q.submit(ROLE11, &wire(), 150), Err(Error::Denied));
        q.submit(ROLE7, &wire(), 150).unwrap();
        q.submit(ROLE7, &wire(), 150).unwrap();
        let mut current = o;
        current.scope.now_ns = 151;
        assert_eq!(
            q.consume(ROLE7, 3, current, FindingMode::Assisted, true),
            Err(Error::Denied)
        );
        let mut forged = current;
        forged.scope.target.generation += 1;
        assert_eq!(
            q.consume(ROLE11, 3, forged, FindingMode::Assisted, true),
            Err(Error::Denied)
        );
        assert!(
            q.consume(ROLE11, 3, current, FindingMode::Assisted, true)
                .unwrap()
                .request_review
        );
        assert_eq!(
            q.consume(ROLE11, 3, current, FindingMode::Assisted, true),
            Err(Error::Stale)
        );
        assert_eq!(
            q.reserve(ROLE7, current, FindingMode::Assisted),
            Err(Error::Busy)
        );
        assert_eq!(q.submit(ROLE7, &wire(), 151), Err(Error::Stale));
        let disp = q
            .finalize(ROLE11, 3, FindingResolution::IndependentRuleRejected, 152)
            .unwrap();
        q.acknowledge_disposition(ROLE11, 3, finding_sha256(&disp.encode().unwrap()), 153)
            .unwrap();
        assert_eq!(q.reap_expired(ROLE11, 100 + MAX_FINDING_AGE_NS), Ok(1));
        assert_eq!(q.occupied(), 0);
    }
    #[test]
    fn shadow_and_offline_downgrade_never_enqueue_review() {
        for (registered_mode, current_mode, authorized) in [
            (FindingMode::Shadow, FindingMode::Assisted, true),
            (FindingMode::Assisted, FindingMode::Shadow, true),
            (FindingMode::Assisted, FindingMode::Assisted, false),
            (FindingMode::Assisted, FindingMode::Disabled, true),
        ] {
            let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
            let o = registered();
            q.reserve(ROLE7, o, registered_mode).unwrap();
            q.submit(ROLE7, &wire(), 150).unwrap();
            assert!(
                !q.consume(ROLE11, 3, o, current_mode, authorized)
                    .unwrap()
                    .request_review
            );
        }
    }
    #[test]
    fn fixed_evaluation_window_and_slots_cannot_be_refilled_by_retries() {
        let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
        for i in 0..16u64 {
            let mut o = registered();
            o.scope.snapshot_seq = 10 + i;
            o.scope.sampled_ns = 100 + (i / 4) * MAX_FINDING_AGE_NS;
            o.scope.now_ns = o.scope.sampled_ns;
            q.reserve(ROLE7, o, FindingMode::Shadow).unwrap();
            if i % 4 == 3 {
                o.scope.snapshot_seq += 100;
                assert_eq!(
                    q.reserve(ROLE7, o, FindingMode::Shadow),
                    Err(Error::Exhausted)
                );
            }
        }
        assert_eq!(q.occupied(), 16);
        let mut o = registered();
        o.scope.snapshot_seq = 99;
        o.scope.sampled_ns = 4 * MAX_FINDING_AGE_NS + 100;
        o.scope.now_ns = o.scope.sampled_ns;
        assert_eq!(
            q.reserve(ROLE7, o, FindingMode::Shadow),
            Err(Error::Exhausted)
        );
        assert_eq!(q.reap_expired(ROLE7, o.scope.now_ns), Err(Error::Denied));
        assert_eq!(q.reap_expired(ROLE11, o.scope.now_ns), Ok(16));
        q.reserve(ROLE7, o, FindingMode::Shadow).unwrap();
    }

    #[test]
    fn disposition_is_canonical_idempotent_and_retained_until_audit_ack() {
        let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
        let o = registered();
        q.reserve(ROLE7, o, FindingMode::Shadow).unwrap();
        q.submit(ROLE7, &wire(), 150).unwrap();
        assert!(
            !q.consume(ROLE11, 3, o, FindingMode::Assisted, true)
                .unwrap()
                .request_review
        );
        assert_eq!(
            q.finalize(ROLE11, 3, FindingResolution::IndependentRuleEntered, 151),
            Err(Error::Denied)
        );
        assert_eq!(
            q.finalize(ROLE7, 3, FindingResolution::Recorded, 151),
            Err(Error::Denied)
        );
        let d = q
            .finalize(ROLE11, 3, FindingResolution::Recorded, 151)
            .unwrap();
        assert_eq!(d.finding_digest, finding_sha256(&wire()));
        let bytes = d.encode().unwrap();
        assert_eq!(FindingDisposition::decode(&bytes), Ok(d));
        for (at, val) in [(4, 1), (6, 0), (48, 5), (50, 7), (52, 1), (120, 1)] {
            let mut bad = bytes;
            bad[at] = val;
            assert!(FindingDisposition::decode(&bad).is_err());
        }
        assert_eq!(
            q.finalize(ROLE11, 3, FindingResolution::Recorded, 152),
            Ok(d)
        );
        assert_eq!(
            q.finalize(ROLE11, 3, FindingResolution::IgnoredPolicy, 152),
            Err(Error::Denied)
        );
        assert_eq!(q.reap_expired(ROLE11, 100 + MAX_FINDING_AGE_NS), Ok(0));
        assert_eq!(q.occupied(), 1);
        assert_eq!(
            q.acknowledge_disposition(ROLE11, 3, [0; 32], 100 + MAX_FINDING_AGE_NS),
            Err(Error::Denied)
        );
        q.acknowledge_disposition(ROLE11, 3, finding_sha256(&bytes), 100 + MAX_FINDING_AGE_NS)
            .unwrap();
        assert_eq!(q.reap_expired(ROLE11, 100 + MAX_FINDING_AGE_NS), Ok(1));
        assert_eq!(q.query_disposition(ROLE11, 3), Err(Error::Stale));
    }
    #[test]
    fn expired_admitted_finding_is_not_silently_erased() {
        let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
        q.reserve(ROLE7, registered(), FindingMode::Assisted)
            .unwrap();
        q.submit(ROLE7, &wire(), 150).unwrap();
        assert_eq!(q.reap_expired(ROLE11, 190), Ok(0));
        let d = q.query_disposition(ROLE11, 3).unwrap();
        assert_eq!((d.state, d.reason_code, d.processed_ns), (3, 3, 190));
        assert_eq!(q.reap_expired(ROLE11, 100 + MAX_FINDING_AGE_NS), Ok(0));
        assert_eq!(
            q.finalize(
                ROLE11,
                3,
                FindingResolution::IndependentRuleEntered,
                100 + MAX_FINDING_AGE_NS
            ),
            Err(Error::Denied)
        );
        assert_eq!(q.occupied(), 1);
    }

    #[test]
    fn invalid_target_disposition_cannot_reenter_review_before_or_after_audit_ack() {
        for acknowledged in [false, true] {
            let mut q = FindingCustody::new(ROLE7, ROLE11, 1, 2).unwrap();
            let mut current = registered();
            q.reserve(ROLE7, current, FindingMode::Assisted).unwrap();
            q.submit(ROLE7, &wire(), 150).unwrap();
            let terminal = q
                .finalize(ROLE11, 3, FindingResolution::InvalidTarget, 151)
                .unwrap();
            let terminal_wire = terminal.encode().unwrap();
            let digest = finding_sha256(&terminal_wire);
            if acknowledged {
                q.acknowledge_disposition(ROLE11, 3, digest, 152).unwrap();
            }

            // A delayed review attempt still has matching observation bytes
            // and a live deadline, but the protected consumer has already
            // invalidated this FindingKey. ACK cannot reopen it either.
            current.scope.now_ns = 153;
            assert_eq!(
                q.consume(ROLE11, 3, current, FindingMode::Assisted, true),
                Err(Error::Stale)
            );
            assert_eq!(
                q.query_disposition(ROLE11, 3).unwrap().encode().unwrap(),
                terminal_wire
            );
            assert_eq!(q.occupied(), 1);
            assert_eq!(
                q.finalize(ROLE11, 3, FindingResolution::IndependentRuleEntered, 154),
                Err(Error::Denied)
            );

            // Keep the context tombstone until its evaluation lifetime ends;
            // unacknowledged terminal evidence must retain its credit longer.
            assert_eq!(q.reap_expired(ROLE11, 190), Ok(0));
            let context_end = 100 + MAX_FINDING_AGE_NS;
            assert_eq!(
                q.reap_expired(ROLE11, context_end),
                Ok(usize::from(acknowledged))
            );
            if !acknowledged {
                assert_eq!(q.occupied(), 1);
                assert_eq!(q.query_disposition(ROLE11, 3), Ok(terminal));
                q.acknowledge_disposition(ROLE11, 3, digest, context_end)
                    .unwrap();
                assert_eq!(q.reap_expired(ROLE11, context_end), Ok(1));
            }
            assert_eq!(q.occupied(), 0);
        }
    }
}
