//! Verdict v4 wire codec from V0.19.9 安§0.9 and 安§7.4.
//!
//! Callers bind the decoded fields to a frozen run manifest and to the
//! original evidence before using a record for acceptance.

use super::Error;
use sha2::{Digest, Sha256};

pub const VERDICT_BYTES: usize = 320;
const HEADER: [u8; 8] = [0x32, 0x56, 0x59, 0x43, 4, 0, 0x40, 1];
const DIGEST_OFFSET: usize = 288;
const LABEL: &[u8] = b"CYX/VERDICT/v4";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    NotRun = 0,
    Pass = 1,
    Fail = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ProofClass {
    RuntimeQemu = 1,
    StaticEl1 = 2,
    ArchA53 = 3,
    ModelCheck = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerdictV4 {
    pub run_id: u64,
    pub test_id: u32,
    pub status: Status,
    pub proof_class: ProofClass,
    pub checker_id: u32,
    pub checker_version: u32,
    pub reason_code: u32,
    pub evidence_count: u32,
    pub boot_epoch: u64,
    pub controller_epoch: u64,
    pub security_epoch: u64,
    pub object_or_stream_generation: u64,
    pub seed: u64,
    pub fault_point_id: u64,
    pub design_hash: [u8; 32],
    pub binary_hash: [u8; 32],
    pub security_profile_hash: [u8; 32],
    pub input_hash: [u8; 32],
    pub rule_hash: [u8; 32],
    pub evidence_digest: [u8; 32],
}

fn stable_test_id(id: u32) -> bool {
    let number = id as u16;
    match id >> 16 {
        1 | 2 | 6 | 7 => (1..=13).contains(&number),
        3 => (1..=15).contains(&number),
        4 => (1..=16).contains(&number),
        5 => (1..=14).contains(&number),
        8 => matches!(number, 1..=11 | 15..=16),
        9 => matches!(number, 1..=8 | 13..=15),
        10 => (1..=6).contains(&number),
        _ => false,
    }
}

fn field<const N: usize>(bytes: &[u8; VERDICT_BYTES], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

fn record_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LABEL);
    hash.update(prefix);
    hash.finalize().into()
}

impl VerdictV4 {
    fn validate_fields(&self) -> Result<(), Error> {
        let valid_reason = match self.status {
            Status::NotRun => matches!(self.reason_code, 1 | 2 | 7 | 8 | 9),
            Status::Pass => self.reason_code == 0,
            Status::Fail => matches!(self.reason_code, 3..=6),
        };
        let has_evidence = self.evidence_count != 0;
        if self.run_id == 0
            || !stable_test_id(self.test_id)
            || self.checker_id >> 16 != self.test_id >> 16
            || self.checker_id as u16 == 0
            || self.checker_version == 0
            || !valid_reason
            || has_evidence != (self.evidence_digest != [0; 32])
            || (!has_evidence && self.status != Status::NotRun)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let raw: &[u8; VERDICT_BYTES] = bytes.try_into().map_err(|_| Error::Invalid)?;
        if raw[..8] != HEADER
            || raw[88..96] != [0; 8]
            || raw[DIGEST_OFFSET..] != record_digest(&raw[..DIGEST_OFFSET])
        {
            return Err(Error::Invalid);
        }
        let status = match u16::from_le_bytes(field(raw, 20)) {
            0 => Status::NotRun,
            1 => Status::Pass,
            2 => Status::Fail,
            _ => return Err(Error::Invalid),
        };
        let proof_class = match u16::from_le_bytes(field(raw, 22)) {
            1 => ProofClass::RuntimeQemu,
            2 => ProofClass::StaticEl1,
            3 => ProofClass::ArchA53,
            4 => ProofClass::ModelCheck,
            _ => return Err(Error::Invalid),
        };
        let record = Self {
            run_id: u64::from_le_bytes(field(raw, 8)),
            test_id: u32::from_le_bytes(field(raw, 16)),
            status,
            proof_class,
            checker_id: u32::from_le_bytes(field(raw, 24)),
            checker_version: u32::from_le_bytes(field(raw, 28)),
            reason_code: u32::from_le_bytes(field(raw, 32)),
            evidence_count: u32::from_le_bytes(field(raw, 36)),
            boot_epoch: u64::from_le_bytes(field(raw, 40)),
            controller_epoch: u64::from_le_bytes(field(raw, 48)),
            security_epoch: u64::from_le_bytes(field(raw, 56)),
            object_or_stream_generation: u64::from_le_bytes(field(raw, 64)),
            seed: u64::from_le_bytes(field(raw, 72)),
            fault_point_id: u64::from_le_bytes(field(raw, 80)),
            design_hash: field(raw, 96),
            binary_hash: field(raw, 128),
            security_profile_hash: field(raw, 160),
            input_hash: field(raw, 192),
            rule_hash: field(raw, 224),
            evidence_digest: field(raw, 256),
        };
        record.validate_fields()?;
        Ok(record)
    }

    pub fn encode(&self) -> Result<[u8; VERDICT_BYTES], Error> {
        self.validate_fields()?;
        let mut raw = [0; VERDICT_BYTES];
        raw[..8].copy_from_slice(&HEADER);
        raw[8..16].copy_from_slice(&self.run_id.to_le_bytes());
        raw[16..20].copy_from_slice(&self.test_id.to_le_bytes());
        raw[20..22].copy_from_slice(&(self.status as u16).to_le_bytes());
        raw[22..24].copy_from_slice(&(self.proof_class as u16).to_le_bytes());
        raw[24..28].copy_from_slice(&self.checker_id.to_le_bytes());
        raw[28..32].copy_from_slice(&self.checker_version.to_le_bytes());
        raw[32..36].copy_from_slice(&self.reason_code.to_le_bytes());
        raw[36..40].copy_from_slice(&self.evidence_count.to_le_bytes());
        raw[40..48].copy_from_slice(&self.boot_epoch.to_le_bytes());
        raw[48..56].copy_from_slice(&self.controller_epoch.to_le_bytes());
        raw[56..64].copy_from_slice(&self.security_epoch.to_le_bytes());
        raw[64..72].copy_from_slice(&self.object_or_stream_generation.to_le_bytes());
        raw[72..80].copy_from_slice(&self.seed.to_le_bytes());
        raw[80..88].copy_from_slice(&self.fault_point_id.to_le_bytes());
        raw[96..128].copy_from_slice(&self.design_hash);
        raw[128..160].copy_from_slice(&self.binary_hash);
        raw[160..192].copy_from_slice(&self.security_profile_hash);
        raw[192..224].copy_from_slice(&self.input_hash);
        raw[224..256].copy_from_slice(&self.rule_hash);
        raw[256..288].copy_from_slice(&self.evidence_digest);
        let digest = record_digest(&raw[..DIGEST_OFFSET]);
        raw[DIGEST_OFFSET..].copy_from_slice(&digest);
        Ok(raw)
    }
}
