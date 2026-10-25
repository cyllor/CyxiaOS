//! Durable application identity and copied input, before any placement intent.
use alloc::vec::Vec;
use cyxia_prototype::domains::{Error, ObjectKey, platform::PlacementRequest};
use crate::application::{Submission, MAX_INPUT, SUBMISSION_HEADER};

pub const MAGIC: &[u8; 6] = b"CXAPP1";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub actor: ObjectKey,
    pub sequence: u64,
    pub key: ObjectKey,
    pub submitted_ns: u64,
    pub package_hash: [u8; 32],
    pub input: Vec<u8>,
}
impl Record {
    pub fn from_submission(s: Submission<'_>, package_hash: [u8; 32]) -> Self {
        Self { actor: s.actor, sequence: s.sequence, key: s.key,
            submitted_ns: s.submitted_ns, package_hash, input: s.input.to_vec() }
    }
    pub fn request(&self, peer: ObjectKey) -> PlacementRequest {
        PlacementRequest { key: self.key, payload_hash: ring::digest::digest(
            &ring::digest::SHA256, &self.input).as_ref().try_into().unwrap(),
            package_hash: self.package_hash, cpu_milli: 100, memory_pages: 16,
            isa: 183, abi: 1, peer: Some(peer) }
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = alloc::vec![0; MAGIC.len() + 32 + SUBMISSION_HEADER + self.input.len() + 32];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        bytes[MAGIC.len()..MAGIC.len() + 32].copy_from_slice(&self.package_hash);
        let end = bytes.len() - 32;
        Submission { actor: self.actor, sequence: self.sequence, key: self.key,
            submitted_ns: self.submitted_ns, input: &self.input }
            .encode(&mut bytes[MAGIC.len() + 32..end])?;
        let hash = ring::digest::digest(&ring::digest::SHA256, &bytes[..end]);
        bytes[end..].copy_from_slice(hash.as_ref());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let minimum = MAGIC.len() + 32 + SUBMISSION_HEADER + 8 + 32;
        if bytes.len() < minimum || bytes.len() > minimum - 8 + MAX_INPUT
            || !bytes.starts_with(MAGIC) { return Err(Error::Format); }
        let end = bytes.len() - 32;
        if ring::digest::digest(&ring::digest::SHA256, &bytes[..end]).as_ref() != &bytes[end..] {
            return Err(Error::Auth);
        }
        let submission = Submission::decode(&bytes[MAGIC.len() + 32..end])?;
        Ok(Self::from_submission(submission, bytes[MAGIC.len()..MAGIC.len() + 32].try_into().unwrap()))
    }
}
