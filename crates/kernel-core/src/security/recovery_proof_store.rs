//! Custody of RecoveryProof v2 summaries in a separately authorized file.
//! The signed locator allocates no blocks and changes no baseline metadata.
//! This store authenticates the file's identity. Its page hashes detect torn
//! or inconsistent updates on the protected medium.

use super::{
    Error,
    durable_role_epoch_v0199::ConfirmedBootPolicy,
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{BUSINESS_INODES, CANONICAL_BUSINESS_START},
    file_media_v0199::{BLOCK_COUNT, INODE_START},
    file_mount_v1::{Acl, MountEvidence},
    file_structure_v1::{BLOCK, INODE_BYTES, Inode, SystemKind},
    offline_config_v1::VerifiedOfflineConfig,
    recovery_proof_v2::{
        ACCUMULATOR_COUNT, FLAG_DEGRADED, FLAG_OVERFLOW, RECOVERY_PROOF_BYTES, RecoveryProofV2,
    },
};
use crate::control_plane::{
    Identity,
    cpu0_v0199::BUSINESS_THREAD_ID_BASE,
    role_manifest_v0199::{ROLES, Role},
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const LOCATOR_BYTES: usize = 104;
const LOCATOR_DOMAIN: &[u8; 21] = b"CYX/RECOVERY-STORE/v1";
const PAGE_DOMAIN: &[u8] = b"CYX/RECOVERY-PROOF-PAGE/v1";
const PAGE_MAGIC: &[u8; 8] = b"CYXRPR01";
const SPILL_PAGE_MAGIC: &[u8; 8] = b"CYXRPR02";
const RECORDS: usize = 8;
const PROOFS_START: usize = 160;
const WRITER_START: usize = PROOFS_START + RECORDS * RECOVERY_PROOF_BYTES;
const WRITER_BYTES: usize = 56;
// CPU0 keeps its existing location. Empty CPU1–3 entries reproduce the
// zero padding of the earlier CPU0-only pages.
const WRITER_END: usize = WRITER_START + WRITER_BYTES * ACCUMULATOR_COUNT;
// A spill record uses the canonical non-reserved prefix of RecoveryProof v2.
// Each CPU can retain two unresolved boot generations, even if another CPU
// continues accumulating while all eight published records await ACK.
const PROOF_PREFIX: usize = 160;
const SPILL_PER_CPU: usize = 2;
const SPILL_RECORDS: usize = SPILL_PER_CPU * ACCUMULATOR_COUNT;
const SPILL_START: usize = WRITER_END + 40;
const SPILL_BYTES: usize = 8 + PROOF_PREFIX;
const SATURATED_PROOF: usize = SPILL_START + SPILL_RECORDS * SPILL_BYTES;
const SPILL_END: usize = SATURATED_PROOF + PROOF_PREFIX;
const PAGE_SEAL: usize = BLOCK - 32;
const AUDIT_PAYLOAD: usize = 144;
const ACL_BYTES: usize = 64;
const _: () = assert!(SPILL_END <= PAGE_SEAL);

type Hash = [u8; 32];

fn hash(parts: &[&[u8]]) -> Hash {
    let mut state = Sha256::new();
    for part in parts {
        state.update(part);
    }
    state.finalize().into()
}

fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[derive(Clone, Copy)]
pub struct RecoveryLocator {
    fs_uuid: [u8; 16],
    config_digest: Hash,
    inode: u32,
    first_block: u32,
    inode_generation: u64,
    metadata_digest: Hash,
    carrier: Hash,
}

impl RecoveryLocator {
    /// Verify the separate locator against the already authorized config and
    /// its pinned deployment key. An empty pair leaves custody disabled.
    ///
    /// The signed message is the literal locator domain followed by 104
    /// bytes. The locator holds the magic, filesystem UUID, SHA-256 of the
    /// full config wire, little-endian inode and first block, little-endian
    /// inode generation, and SHA-256 of the raw inode followed by the ACL.
    pub fn verify(
        config: &VerifiedOfflineConfig<'_>,
        key: &[u8; 32],
        locator: &[u8],
        signature: &[u8],
    ) -> Result<Option<Self>, Error> {
        if locator.is_empty() && signature.is_empty() {
            return Ok(None);
        }
        if locator.len() != LOCATOR_BYTES || locator.get(..8) != Some(b"CYXRPF01") {
            return Err(Error::Invalid);
        }
        let sig = Signature::from_bytes(signature.try_into().map_err(|_| Error::Invalid)?);
        let mut message = [0; LOCATOR_DOMAIN.len() + LOCATOR_BYTES];
        message[..LOCATOR_DOMAIN.len()].copy_from_slice(LOCATOR_DOMAIN);
        message[LOCATOR_DOMAIN.len()..].copy_from_slice(locator);
        VerifyingKey::from_bytes(key)
            .and_then(|key| key.verify_strict(&message, &sig))
            .map_err(|_| Error::Unauthorized)?;

        let value = Self {
            fs_uuid: locator[8..24].try_into().unwrap(),
            config_digest: locator[24..56].try_into().unwrap(),
            inode: u32at(locator, 56),
            first_block: u32at(locator, 60),
            inode_generation: u64at(locator, 64),
            metadata_digest: locator[72..104].try_into().unwrap(),
            carrier: hash(&[
                b"CYX/RECOVERY-CARRIER/v1",
                &locator[8..24],
                &locator[56..104],
            ]),
        };
        // Inode 0 is the root directory. Only ordinary data extents at or
        // after the canonical business start are eligible for the carrier.
        if value.fs_uuid != config.header().fs_uuid
            || value.config_digest != config.digest()
            || value.inode == 0
            || value.inode >= BUSINESS_INODES
            || !(CANONICAL_BUSINESS_START..BLOCK_COUNT - 1).contains(&value.first_block)
            || value.inode_generation == 0
        {
            return Err(Error::Conflict);
        }
        Ok(Some(value))
    }

    pub fn same_carrier(self, other: Self) -> bool {
        self.carrier == other.carrier
    }

    pub const fn inode_slot(self) -> u32 {
        self.inode
    }

    pub const fn physical_blocks(self) -> core::ops::Range<u32> {
        self.first_block..self.first_block + 2
    }

    fn verify_file(
        self,
        mounted: &MountEvidence,
        io: &mut impl EpochBlockIo,
        scratch: &mut [u8; BLOCK],
    ) -> Result<(), Error> {
        if mounted.boot.fs_uuid != self.fs_uuid {
            return Err(Error::Conflict);
        }
        let acl_home = mounted
            .baseline_system()
            .and_then(|objects| objects.iter().find(|object| object.kind == SystemKind::Acl))
            .ok_or(Error::Conflict)?
            .first_block;
        let inode_at = self.inode as usize * INODE_BYTES;
        io.read(INODE_START + (inode_at / BLOCK) as u32, scratch)?;
        let offset = inode_at % BLOCK;
        let raw_inode: [u8; INODE_BYTES] =
            scratch[offset..offset + INODE_BYTES].try_into().unwrap();
        let acl_at = self.inode as usize * ACL_BYTES;
        io.read(acl_home + (acl_at / BLOCK) as u32, scratch)?;
        let offset = acl_at % BLOCK;
        let raw_acl = &scratch[offset..offset + ACL_BYTES];
        self.verify_file_metadata(&raw_inode, raw_acl)
    }

    /// Validate the signed carrier's exact immutable inode and ACL bytes.
    /// The enclosing file owner must also reserve its two raw data blocks.
    pub fn verify_file_metadata(
        self,
        raw_inode: &[u8; INODE_BYTES],
        raw_acl: &[u8],
    ) -> Result<(), Error> {
        let inode = Inode::decode(raw_inode)?;
        let acl = Acl::decode(raw_acl)?;
        if hash(&[raw_inode, raw_acl]) != self.metadata_digest
            || inode.kind != 1
            || inode.generation != self.inode_generation
            || inode.size != (2 * BLOCK) as u64
            || inode.extents != 1
            || inode.runs[0].physical != self.first_block
            || inode.runs[0].logical != 0
            || inode.runs[0].count != 2
            || acl.state != 1
            || acl.inode_id != self.inode
            || acl.inode_generation != self.inode_generation
            || acl.owner_rights != 0
            || acl.system_rights != 0
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

/// The CPU0 foreground owner supplies preallocated page buffers.
pub struct Workspace {
    target: [u8; BLOCK],
    observed: [u8; BLOCK],
}

impl Workspace {
    pub const fn new() -> Self {
        Self {
            target: [0; BLOCK],
            observed: [0; BLOCK],
        }
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Ack {
    boot: u64,
    generation: u64,
    digest: Hash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Writer {
    boot: u64,
    generation: u64,
    count: u64,
    digest: Hash,
}

impl Writer {
    const EMPTY: Self = Self {
        boot: 0,
        generation: 0,
        count: 0,
        digest: [0; 32],
    };

    fn from_proof(proof: &RecoveryProofV2) -> Self {
        Self {
            boot: proof.boot_epoch,
            generation: proof.cpu_generation,
            count: proof.total_count,
            digest: proof.chain_digest,
        }
    }

    fn advances(self, prior: Self, proof: &RecoveryProofV2) -> bool {
        if self.boot != prior.boot {
            return self.boot > prior.boot;
        }
        self.generation >= prior.generation
            && self.count > prior.count
            && (prior.count.checked_add(1) != Some(self.count)
                || proof.verify_chain_from(&prior.digest))
    }

    fn valid(self, page_boot: u64) -> bool {
        self == Self::EMPTY
            || ((1..=page_boot).contains(&self.boot)
                && self.generation != 0
                && self.count != 0
                && self.digest != [0; 32])
    }

    fn covers(self, prior: Self) -> bool {
        prior == Self::EMPTY
            || self.boot > prior.boot
            || self.boot == prior.boot
                && (self == prior
                    || self.generation >= prior.generation && self.count > prior.count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofPersistence {
    Queued { sequence: u64 },
    Deferred,
    Saturated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditStatus {
    pub pending: u64,
    pub retired: u64,
    pub deferred: u64,
    /// Historical number of events that had to be counted without a replay
    /// slot. This count saturates and remains visible after the FIFO drains.
    pub saturated: u64,
    pub first_saturated_boot: u64,
    pub last_saturated_boot: u64,
    pub saturated_cpu_mask: u32,
    pub reader_available: bool,
    pub uncertain: bool,
}

impl AuditStatus {
    pub const fn fifo_full(self) -> bool {
        self.pending == RECORDS as u64
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DeferredProof {
    since: u64,
    proof: RecoveryProofV2,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Spill {
    operations: u64,
    deferred: [Option<DeferredProof>; SPILL_RECORDS],
    saturated: u64,
    first_saturated_boot: u64,
    last_saturated_boot: u64,
    saturated_cpu_mask: u32,
    last_saturated_proof: Option<RecoveryProofV2>,
}

impl Spill {
    const EMPTY: Self = Self {
        operations: 0,
        deferred: [None; SPILL_RECORDS],
        saturated: 0,
        first_saturated_boot: 0,
        last_saturated_boot: 0,
        saturated_cpu_mask: 0,
        last_saturated_proof: None,
    };

    fn decode(raw: &[u8; BLOCK], extended: bool) -> Result<Self, Error> {
        if !extended {
            if raw[WRITER_END..PAGE_SEAL].iter().any(|&byte| byte != 0) {
                return Err(Error::Conflict);
            }
            return Ok(Self::EMPTY);
        }
        let mut spill = Self {
            operations: u64at(raw, WRITER_END),
            saturated: u64at(raw, WRITER_END + 8),
            first_saturated_boot: u64at(raw, WRITER_END + 16),
            last_saturated_boot: u64at(raw, WRITER_END + 24),
            saturated_cpu_mask: u32at(raw, WRITER_END + 32),
            last_saturated_proof: decode_proof_prefix(&raw[SATURATED_PROOF..SPILL_END])?,
            ..Self::EMPTY
        };
        if spill.operations == 0
            || raw[WRITER_END + 36..SPILL_START]
                .iter()
                .any(|&byte| byte != 0)
            || raw[SPILL_END..PAGE_SEAL].iter().any(|&byte| byte != 0)
        {
            return Err(Error::Conflict);
        }
        for (index, entry) in spill.deferred.iter_mut().enumerate() {
            let offset = SPILL_START + index * SPILL_BYTES;
            let since = u64at(raw, offset);
            let proof = decode_proof_prefix(&raw[offset + 8..offset + SPILL_BYTES])?;
            *entry = match (since, proof) {
                (0, None) => None,
                (since, Some(proof))
                    if since != 0 && proof.cpu_id as usize == index / SPILL_PER_CPU =>
                {
                    Some(DeferredProof { since, proof })
                }
                _ => return Err(Error::Conflict),
            };
        }
        Ok(spill)
    }

    fn validate(
        &self,
        generation: u64,
        boot: u64,
        mut queued: [Writer; ACCUMULATOR_COUNT],
        writers: &[Writer; ACCUMULATOR_COUNT],
    ) -> Result<(), Error> {
        for (index, entry) in self.deferred.iter().enumerate() {
            let Some(entry) = entry else { continue };
            let cpu_start = index / SPILL_PER_CPU * SPILL_PER_CPU;
            if self.deferred[cpu_start..index]
                .iter()
                .flatten()
                .any(|previous| previous.proof.boot_epoch == entry.proof.boot_epoch)
            {
                return Err(Error::Conflict);
            }
        }
        let mut since = 0;
        let retained = || self.deferred.iter().flatten();
        for _ in retained() {
            let entry = retained()
                .filter(|entry| entry.since > since)
                .min_by_key(|entry| entry.since)
                .ok_or(Error::Conflict)?;
            if entry.since > generation {
                return Err(Error::Conflict);
            }
            since = entry.since;
            advance_writer(&entry.proof, boot, &mut queued)?;
        }
        if queued
            .iter()
            .zip(writers)
            .any(|(&pending, &intake)| !intake.covers(pending))
        {
            return Err(Error::Conflict);
        }
        match self.last_saturated_proof {
            Some(proof) => {
                let mut validated = [Writer::EMPTY; ACCUMULATOR_COUNT];
                advance_writer(&proof, boot, &mut validated)?;
                let cpu = proof.cpu_id as usize;
                if self.saturated == 0
                    || !(1..=proof.boot_epoch).contains(&self.first_saturated_boot)
                    || self.last_saturated_boot != proof.boot_epoch
                    || self.saturated_cpu_mask & (1 << cpu) == 0
                    || self.saturated_cpu_mask >> ACCUMULATOR_COUNT != 0
                    || !writers[cpu].covers(validated[cpu])
                {
                    return Err(Error::Conflict);
                }
            }
            None if self.saturated != 0
                || self.first_saturated_boot != 0
                || self.last_saturated_boot != 0
                || self.saturated_cpu_mask != 0 =>
            {
                return Err(Error::Conflict);
            }
            None => {}
        }
        Ok(())
    }

    fn encode(&self, out: &mut [u8; BLOCK]) {
        put64(out, WRITER_END, self.operations);
        put64(out, WRITER_END + 8, self.saturated);
        put64(out, WRITER_END + 16, self.first_saturated_boot);
        put64(out, WRITER_END + 24, self.last_saturated_boot);
        out[WRITER_END + 32..WRITER_END + 36]
            .copy_from_slice(&self.saturated_cpu_mask.to_le_bytes());
        for (index, entry) in self.deferred.iter().enumerate() {
            if let Some(entry) = entry {
                let offset = SPILL_START + index * SPILL_BYTES;
                put64(out, offset, entry.since);
                encode_proof_prefix(&entry.proof, &mut out[offset + 8..offset + SPILL_BYTES]);
            }
        }
        if let Some(proof) = self.last_saturated_proof {
            encode_proof_prefix(&proof, &mut out[SATURATED_PROOF..SPILL_END]);
        }
    }

    fn oldest(&self) -> Option<usize> {
        self.deferred
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.as_ref().map(|entry| (entry.since, index)))
            .min()
            .map(|(_, index)| index)
    }

    fn ingest(
        &mut self,
        proof: RecoveryProofV2,
        prior: Writer,
        generation: u64,
    ) -> Result<ProofPersistence, Error> {
        self.operations = self.operations.checked_add(1).ok_or(Error::Exhausted)?;
        let start = proof.cpu_id as usize * SPILL_PER_CPU;
        let rows = &mut self.deferred[start..start + SPILL_PER_CPU];
        if let Some(existing) = rows
            .iter_mut()
            .flatten()
            .find(|row| row.proof.boot_epoch == proof.boot_epoch)
        {
            if !can_coalesce(&existing.proof, &proof) {
                return Err(Error::Conflict);
            }
            existing.proof = proof;
            return Ok(ProofPersistence::Deferred);
        }
        if let Some(empty) = rows.iter_mut().find(|row| row.is_none()) {
            *empty = Some(DeferredProof {
                since: generation,
                proof,
            });
            return Ok(ProofPersistence::Deferred);
        }
        // Even repeated cold starts cannot evict either retained proof. At
        // the bound, keep a sticky event-count lower bound and the most
        // recent actual input as a witness for the adjacent page transition.
        let delta = if prior.boot == proof.boot_epoch {
            proof
                .total_count
                .checked_sub(prior.count)
                .ok_or(Error::Conflict)?
        } else {
            proof.total_count
        };
        if self.saturated == 0 {
            self.first_saturated_boot = proof.boot_epoch;
        }
        self.saturated = self.saturated.saturating_add(delta);
        self.last_saturated_boot = proof.boot_epoch;
        self.saturated_cpu_mask |= 1 << proof.cpu_id;
        self.last_saturated_proof = Some(proof);
        Ok(ProofPersistence::Saturated)
    }
}

fn can_coalesce(prior: &RecoveryProofV2, proof: &RecoveryProofV2) -> bool {
    let delta = proof.total_count.checked_sub(prior.total_count);
    let events = proof
        .unknown_count
        .checked_sub(prior.unknown_count)
        .and_then(|value| value.checked_add(proof.revoke_count.checked_sub(prior.revoke_count)?))
        .and_then(|value| {
            value.checked_add(proof.recovery_count.checked_sub(prior.recovery_count)?)
        });
    proof.cpu_generation == prior.cpu_generation
        && delta
            .zip(events)
            .is_some_and(|(delta, events)| delta > 0 && events <= delta)
}

fn decode_proof_prefix(raw: &[u8]) -> Result<Option<RecoveryProofV2>, Error> {
    if raw.iter().all(|&byte| byte == 0) {
        return Ok(None);
    }
    let mut canonical = [0; RECOVERY_PROOF_BYTES];
    canonical[..PROOF_PREFIX].copy_from_slice(raw);
    RecoveryProofV2::decode(&canonical).map(Some)
}

fn encode_proof_prefix(proof: &RecoveryProofV2, out: &mut [u8]) {
    let mut canonical = [0; RECOVERY_PROOF_BYTES];
    proof.encode(&mut canonical);
    out.copy_from_slice(&canonical[..PROOF_PREFIX]);
}

#[derive(Clone, Copy)]
struct Page {
    generation: u64,
    boot: u64,
    retired: u64,
    ack: Ack,
    prior_digest: Hash,
    seal: Hash,
    writers: [Writer; ACCUMULATOR_COUNT],
    proofs: [Option<RecoveryProofV2>; RECORDS],
    count: usize,
    spill: Spill,
}

impl Page {
    const EMPTY: Self = Self {
        generation: 0,
        boot: 0,
        retired: 0,
        ack: Ack {
            boot: 0,
            generation: 0,
            digest: [0; 32],
        },
        prior_digest: [0; 32],
        seal: [0; 32],
        writers: [Writer::EMPTY; ACCUMULATOR_COUNT],
        proofs: [None; RECORDS],
        count: 0,
        spill: Spill::EMPTY,
    };

    fn decode(raw: &[u8; BLOCK], carrier: Hash, slot: u64, last_boot: u64) -> Result<Self, Error> {
        if raw.iter().all(|&byte| byte == 0) {
            return Ok(Self::EMPTY);
        }
        let extended = match &raw[..8] {
            magic if magic == PAGE_MAGIC => false,
            magic if magic == SPILL_PAGE_MAGIC => true,
            _ => return Err(Error::Conflict),
        };
        let seal = hash(&[PAGE_DOMAIN, &raw[..PAGE_SEAL]]);
        if raw[8..40] != carrier || raw[PAGE_SEAL..] != seal {
            return Err(Error::Conflict);
        }
        let mut page = Self {
            generation: u64at(raw, 40),
            boot: u64at(raw, 48),
            retired: u64at(raw, 56),
            ack: Ack {
                boot: u64at(raw, 64),
                generation: u64at(raw, 72),
                digest: raw[80..112].try_into().unwrap(),
            },
            prior_digest: raw[112..144].try_into().unwrap(),
            count: usize::from(u16::from_le_bytes(raw[144..146].try_into().unwrap())),
            seal,
            writers: core::array::from_fn(|cpu| {
                let offset = WRITER_START + cpu * WRITER_BYTES;
                Writer {
                    boot: u64at(raw, offset),
                    generation: u64at(raw, offset + 8),
                    count: u64at(raw, offset + 16),
                    digest: raw[offset + 24..offset + WRITER_BYTES].try_into().unwrap(),
                }
            }),
            spill: Spill::decode(raw, extended)?,
            ..Self::EMPTY
        };
        if page.generation == 0
            || (page.generation - 1) % 2 != slot
            || !(1..=last_boot).contains(&page.boot)
            || page.count > RECORDS
            || page.retired.checked_add(page.count as u64).is_none()
            || (page.generation == 1) != (page.prior_digest == [0; 32])
            || page.writers == Self::EMPTY.writers
            || page.writers.iter().any(|writer| !writer.valid(page.boot))
            || raw[146..PROOFS_START].iter().any(|&byte| byte != 0)
        {
            return Err(Error::Conflict);
        }
        if page.retired == 0 && page.ack != Ack::default()
            || page.retired != 0
                && (!(1..=page.boot).contains(&page.ack.boot)
                    || page.ack.generation == 0
                    || page.ack.digest == [0; 32])
            || page
                .retired
                .checked_mul(2)
                .and_then(|n| n.checked_add(page.count as u64))
                .and_then(|n| n.checked_add(page.spill.operations))
                != Some(page.generation)
        {
            return Err(Error::Conflict);
        }
        let mut last = [Writer::EMPTY; ACCUMULATOR_COUNT];
        for (i, slot) in page.proofs[..page.count].iter_mut().enumerate() {
            let start = PROOFS_START + i * RECOVERY_PROOF_BYTES;
            let proof = RecoveryProofV2::decode(&raw[start..start + RECOVERY_PROOF_BYTES])?;
            advance_writer(&proof, page.boot, &mut last)?;
            *slot = Some(proof);
        }
        let end = PROOFS_START + page.count * RECOVERY_PROOF_BYTES;
        if raw[end..WRITER_START].iter().any(|&byte| byte != 0) {
            return Err(Error::Conflict);
        }
        if extended {
            page.spill
                .validate(page.generation, page.boot, last, &page.writers)?;
        } else if last
            .iter()
            .zip(page.writers)
            .any(|(&retained, writer)| retained != Writer::EMPTY && retained != writer)
        {
            return Err(Error::Conflict);
        }
        Ok(page)
    }

    fn encode(&mut self, carrier: Hash, out: &mut [u8; BLOCK]) {
        out.fill(0);
        out[..8].copy_from_slice(if self.spill.operations == 0 {
            PAGE_MAGIC
        } else {
            SPILL_PAGE_MAGIC
        });
        out[8..40].copy_from_slice(&carrier);
        for (at, v) in [
            (40, self.generation),
            (48, self.boot),
            (56, self.retired),
            (64, self.ack.boot),
            (72, self.ack.generation),
        ] {
            put64(out, at, v);
        }
        out[80..112].copy_from_slice(&self.ack.digest);
        out[112..144].copy_from_slice(&self.prior_digest);
        out[144..146].copy_from_slice(&(self.count as u16).to_le_bytes());
        for (i, proof) in self.proofs[..self.count].iter().enumerate() {
            let start = PROOFS_START + i * RECOVERY_PROOF_BYTES;
            proof.unwrap().encode(
                (&mut out[start..start + RECOVERY_PROOF_BYTES])
                    .try_into()
                    .unwrap(),
            );
        }
        for (cpu, writer) in self.writers.iter().enumerate() {
            let offset = WRITER_START + cpu * WRITER_BYTES;
            put64(out, offset, writer.boot);
            put64(out, offset + 8, writer.generation);
            put64(out, offset + 16, writer.count);
            out[offset + 24..offset + WRITER_BYTES].copy_from_slice(&writer.digest);
        }
        if self.spill.operations != 0 {
            self.spill.encode(out);
        }
        self.seal = hash(&[PAGE_DOMAIN, &out[..PAGE_SEAL]]);
        out[PAGE_SEAL..].copy_from_slice(&self.seal);
    }

    fn follows(&self, prior: &Self) -> bool {
        if prior.generation.checked_add(1) != Some(self.generation)
            || self.boot < prior.boot
            || self.prior_digest != prior.seal
        {
            return false;
        }
        if self.spill.operations != prior.spill.operations {
            return self.follows_spill(prior);
        }
        if self.retired == prior.retired && self.count == prior.count + 1 {
            return self.ack == prior.ack
                && self.proofs[..prior.count] == prior.proofs[..prior.count]
                && self.proofs[prior.count].is_some_and(|proof| self.follows_append(prior, proof));
        }
        prior.count == self.count + 1
            && prior.retired.checked_add(1) == Some(self.retired)
            && self.ack.boot == self.boot
            && self.ack.generation >= prior.ack.generation
            && self.ack.digest == audit_digest(self.retired, &prior.proofs[0].unwrap())
            && self.writers == prior.writers
            && self.spill == prior.spill
            && self.proofs[..self.count] == prior.proofs[1..prior.count]
    }

    fn follows_append(&self, prior: &Self, proof: RecoveryProofV2) -> bool {
        if let Some(index) = prior.spill.oldest() {
            // A deferred writer may be from an archived boot. Its intake
            // floor already advanced on deferral, and another boot may
            // have advanced it again. Promotion only consumes this slot.
            let mut spill = prior.spill;
            let pending = spill.deferred[index].take().unwrap();
            proof == pending.proof && self.writers == prior.writers && self.spill == spill
        } else {
            let mut writers = prior.writers;
            proof.boot_epoch == self.boot
                && advance_writer(&proof, self.boot, &mut writers).is_ok()
                && self.writers == writers
                && self.spill == prior.spill
        }
    }

    fn follows_spill(&self, prior: &Self) -> bool {
        if self.retired != prior.retired
            || self.ack != prior.ack
            || self.count != RECORDS
            || self.count != prior.count
            || self.proofs != prior.proofs
            || prior.spill.operations.checked_add(1) != Some(self.spill.operations)
        {
            return false;
        }
        let mut changed = self
            .spill
            .deferred
            .iter()
            .zip(prior.spill.deferred.iter())
            .filter(|(current, old)| current != old);
        let proof = match changed.next() {
            Some((Some(record), _)) if changed.next().is_none() => record.proof,
            None if self.spill.last_saturated_proof.is_some() => {
                self.spill.last_saturated_proof.unwrap()
            }
            _ => return false,
        };
        if proof.boot_epoch != self.boot {
            return false;
        }
        let mut writers = prior.writers;
        let mut spill = prior.spill;
        advance_writer(&proof, self.boot, &mut writers).is_ok()
            && spill
                .ingest(proof, prior.writers[proof.cpu_id as usize], self.generation)
                .is_ok()
            && self.writers == writers
            && self.spill == spill
    }

    fn home_offset(&self) -> u32 {
        ((self.generation - 1) % 2) as u32
    }
}

fn advance_writer(
    proof: &RecoveryProofV2,
    latest_boot: u64,
    writers: &mut [Writer; ACCUMULATOR_COUNT],
) -> Result<(), Error> {
    let prior = writers
        .get_mut(proof.cpu_id as usize)
        .ok_or(Error::Conflict)?;
    let valid_object = match (proof.cpu_id, proof.last_object_id) {
        (0, 0) => proof.last_object_generation == 1,
        (0, id) => {
            proof.last_object_generation != 0 && ROLES.iter().any(|role| u64::from(role.id()) == id)
        }
        (cpu, id) => {
            id == BUSINESS_THREAD_ID_BASE + u64::from(cpu)
                && proof.last_object_generation == proof.boot_epoch
        }
    };
    if !(1..=latest_boot).contains(&proof.boot_epoch)
        || proof.cpu_generation == 0
        || proof.last_event_id != proof.total_count
        || proof.total_count == 0
        || proof.flags & !(FLAG_DEGRADED | FLAG_OVERFLOW) != 0
        || proof.flags & FLAG_DEGRADED == 0
        || (proof.flags & FLAG_OVERFLOW != 0) != (proof.total_count == u64::MAX)
        || proof.chain_digest == [0; 32]
        || proof.last_event_digest == [0; 32]
        || !valid_object
        || proof.last_failure_code > 0x3f
        || proof
            .unknown_count
            .checked_add(proof.revoke_count)
            .and_then(|count| count.checked_add(proof.recovery_count))
            .is_none_or(|count| count > proof.total_count)
    {
        return Err(Error::Conflict);
    }
    if proof.total_count == 1 && !proof.verify_chain_from(&[0; 32]) {
        return Err(Error::Conflict);
    }
    let writer = Writer::from_proof(proof);
    if !writer.advances(*prior, proof) {
        return Err(Error::Conflict);
    }
    *prior = writer;
    Ok(())
}

fn audit_payload(seq: u64, proof: &RecoveryProofV2) -> [u8; AUDIT_PAYLOAD] {
    let mut payload = [0; AUDIT_PAYLOAD];
    payload[..2].copy_from_slice(&1u16.to_le_bytes());
    put64(&mut payload, 8, seq);
    let r = &mut payload[16..];
    r[..4].copy_from_slice(&0x4359_4155u32.to_le_bytes());
    for (at, value) in [
        (4, 2u16),
        (6, 128),
        (24, 10),
        (26, 1),
        (28, 3),
        (30, u16::MAX),
    ] {
        r[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (at, value) in [
        (8, proof.boot_epoch),
        (16, seq),
        (32, 0),
        (40, proof.cpu_generation),
        (48, u64::from(proof.cpu_id)),
        (56, proof.cpu_generation),
    ] {
        put64(r, at, value);
    }
    let mut encoded = [0; RECOVERY_PROOF_BYTES];
    proof.encode(&mut encoded);
    r[64..96].copy_from_slice(&hash(&[&encoded]));
    let digest = hash(&[b"CYX/AUDIT/v2", &r[..96]]);
    r[96..].copy_from_slice(&digest);
    payload
}

fn audit_digest(seq: u64, proof: &RecoveryProofV2) -> Hash {
    audit_payload(seq, proof)[112..].try_into().unwrap()
}

pub struct RecoveryProofStore {
    locator: RecoveryLocator,
    last_boot: u64,
    page: Page,
    boot: u64,
    writer_generation: u64,
    reader: Option<Identity>,
    reader_closed: bool,
    delivered: u8,
    pending_ack: Option<Ack>,
    uncertain: bool,
}

impl RecoveryProofStore {
    pub fn open(
        locator: RecoveryLocator,
        mounted: &MountEvidence,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<Self, Error> {
        locator.verify_file(mounted, io, &mut work.observed)?;
        Self::open_pages(locator, mounted.boot.boot_epoch, io, work)
    }

    fn open_pages(
        locator: RecoveryLocator,
        last_boot: u64,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<Self, Error> {
        let first = locator.first_block;
        io.read(first, &mut work.target)?;
        let low = Page::decode(&work.target, locator.carrier, 0, last_boot)?;
        io.read(first + 1, &mut work.observed)?;
        let high = Page::decode(&work.observed, locator.carrier, 1, last_boot)?;
        let page = if low.generation == 0 && high.generation == 0 {
            Page::EMPTY
        } else {
            let (prior, newest) = if low.generation > high.generation {
                (high, low)
            } else {
                (low, high)
            };
            if !newest.follows(&prior) {
                return Err(Error::Conflict);
            }
            // A complete prior write may have been interrupted before its
            // flush. Confirm a real flush and fresh read in this boot.
            io.flush()?;
            let (expected, observed) = if newest.home_offset() == 0 {
                (&work.target, &mut work.observed)
            } else {
                (&work.observed, &mut work.target)
            };
            io.read(first + newest.home_offset(), observed)?;
            if observed != expected {
                return Err(Error::Unknown);
            }
            newest
        };
        Ok(Self {
            locator,
            last_boot,
            page,
            boot: 0,
            writer_generation: 0,
            reader: None,
            reader_closed: false,
            delivered: 0,
            pending_ack: None,
            uncertain: false,
        })
    }

    /// This call follows allocation of the new on-media BootEpoch. The old
    /// DMA owner has stopped and recovered, and this boot starts its own
    /// delivery bitmap. A previously isolated Supervisor gets no reader.
    pub fn bind(
        &mut self,
        policy: &ConfirmedBootPolicy<'_>,
        writer_generation: u64,
    ) -> Result<(), Error> {
        let epoch = policy.boot_epoch();
        if self.boot != 0
            || self.last_boot.checked_add(1) != Some(epoch)
            || !policy.matches_config_digest(self.locator.config_digest)
            || writer_generation == 0
        {
            return Err(Error::Conflict);
        }
        if let Ok(generation) = policy.service_generation(Role::Supervisor) {
            if generation < self.page.ack.generation {
                return Err(Error::Stale);
            }
            self.reader = Some(Identity {
                id: u64::from(Role::Supervisor.id()),
                generation,
            });
        }
        self.boot = epoch;
        self.writer_generation = writer_generation;
        Ok(())
    }

    pub fn reader_available(&self, actor: Identity) -> bool {
        self.check_reader(actor).is_ok()
    }

    /// EL1 closes the exact stopped consumer. Delivery alone conveys no
    /// authority to retire a record after takeover. An ACK already admitted
    /// still belongs to the foreground disk owner until it is settled.
    pub fn close_reader(&mut self, actor: Identity) -> Result<(), Error> {
        if self.boot == 0 || self.reader != Some(actor) {
            return Err(Error::Unauthorized);
        }
        self.reader_closed = true;
        self.delivered = 0;
        Ok(())
    }

    pub fn replace_reader(
        &mut self,
        old: Identity,
        policy: &ConfirmedBootPolicy<'_>,
    ) -> Result<(), Error> {
        if self.boot != policy.boot_epoch()
            || !policy.matches_config_digest(self.locator.config_digest)
        {
            return Err(Error::Unauthorized);
        }
        self.replace_reader_confirmed(old, policy.service_generation(Role::Supervisor)?)
    }

    fn replace_reader_confirmed(&mut self, old: Identity, generation: u64) -> Result<(), Error> {
        self.check_closed_reader(old)?;
        if old.generation.checked_add(1) != Some(generation) {
            return Err(Error::Stale);
        }
        if self.pending_ack.is_some() {
            return Err(Error::Busy);
        }
        self.reader = Some(Identity { generation, ..old });
        self.reader_closed = false;
        Ok(())
    }

    /// Terminal proof for retiring a closed reader's old transport. This
    /// only observes the read-back durable ACK and grants no reader rights.
    pub fn retired_ack_confirmed(
        &self,
        old: Identity,
        seq: u64,
        digest: Hash,
    ) -> Result<(), Error> {
        self.check_closed_reader(old)?;
        let ack = self.ack_identity(old, digest);
        if let Some(pending) = self.pending_ack {
            return if pending == ack && self.page.retired.checked_add(1) == Some(seq) {
                Err(Error::Busy)
            } else {
                Err(Error::Conflict)
            };
        }
        if self.page.retired != seq {
            return Err(Error::Stale);
        }
        if self.page.ack != ack {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn check_closed_reader(&self, actor: Identity) -> Result<(), Error> {
        if self.boot == 0 || self.reader != Some(actor) {
            return Err(Error::Unauthorized);
        }
        if !self.reader_closed {
            return Err(Error::Busy);
        }
        if self.uncertain {
            return Err(Error::Unknown);
        }
        Ok(())
    }

    /// Custody inventory suitable for the boot owner's protected report.
    pub fn inventory(&self) -> (u64, u64) {
        (self.page.count as u64, self.page.retired)
    }

    pub fn audit_status(&self) -> AuditStatus {
        AuditStatus {
            pending: self.page.count as u64,
            retired: self.page.retired,
            deferred: self.page.spill.deferred.iter().flatten().count() as u64,
            saturated: self.page.spill.saturated,
            first_saturated_boot: self.page.spill.first_saturated_boot,
            last_saturated_boot: self.page.spill.last_saturated_boot,
            saturated_cpu_mask: self.page.spill.saturated_cpu_mask,
            reader_available: self
                .reader
                .is_some_and(|actor| self.reader_available(actor)),
            uncertain: self.uncertain,
        }
    }

    /// The collector remains able to account for new evidence while its
    /// consumer is closed or the published queue is full. A ready promotion
    /// gets priority over new intake.
    pub fn can_persist_proof(&self) -> bool {
        self.boot != 0 && !self.uncertain && !self.can_promote()
    }

    pub fn can_append(&self) -> bool {
        self.boot != 0
            && !self.uncertain
            && self.page.count < RECORDS
            && self.page.spill.oldest().is_none()
    }

    pub fn can_promote(&self) -> bool {
        self.boot != 0
            && !self.uncertain
            && self.page.count < RECORDS
            && self.page.spill.oldest().is_some()
    }

    fn check_reader(&self, actor: Identity) -> Result<(), Error> {
        if self.boot == 0 || self.reader_closed || self.reader != Some(actor) {
            return Err(Error::Unauthorized);
        }
        if self.uncertain {
            return Err(Error::Unknown);
        }
        Ok(())
    }

    pub fn read(&self, actor: Identity, after: u64) -> Result<[u8; AUDIT_PAYLOAD], Error> {
        self.check_reader(actor)?;
        let i = after.saturating_sub(self.page.retired);
        if i >= self.page.count as u64 {
            return Ok([0; AUDIT_PAYLOAD]);
        }
        let seq = self.page.retired + i + 1;
        Ok(audit_payload(seq, &self.page.proofs[i as usize].unwrap()))
    }

    /// Native copyout calls this only after complete delivery to the same
    /// live holder. A boot or reader takeover does not inherit the bitmap.
    pub fn confirm_delivery(
        &mut self,
        actor: Identity,
        seq: u64,
        digest: Hash,
    ) -> Result<(), Error> {
        self.check_reader(actor)?;
        let i = seq
            .checked_sub(self.page.retired)
            .and_then(|n| n.checked_sub(1))
            .filter(|i| *i < self.page.count as u64)
            .ok_or(Error::Stale)? as usize;
        if audit_digest(seq, &self.page.proofs[i].unwrap()) != digest {
            return Err(Error::Conflict);
        }
        self.delivered |= 1 << i;
        Ok(())
    }

    fn ack_identity(&self, actor: Identity, digest: Hash) -> Ack {
        Ack {
            boot: self.boot,
            generation: actor.generation,
            digest,
        }
    }

    pub fn check_ack(&self, actor: Identity, seq: u64, digest: Hash) -> Result<(), Error> {
        self.check_reader(actor)?;
        if seq == self.page.retired && self.page.ack == self.ack_identity(actor, digest) {
            return Ok(());
        }
        if self.page.count == 0 || self.page.retired.checked_add(1) != Some(seq) {
            return Err(Error::Stale);
        }
        if self.delivered & 1 == 0 {
            return Err(Error::Unauthorized);
        }
        if digest != audit_digest(seq, &self.page.proofs[0].unwrap()) {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    /// Reserve an ACK only. A metered foreground commit must run before an
    /// exact retry from this live reader receives success.
    pub fn ack(&mut self, actor: Identity, seq: u64, digest: Hash) -> Result<(), Error> {
        self.check_ack(actor, seq, digest)?;
        if seq == self.page.retired {
            return Ok(());
        }
        self.pending_ack = Some(self.ack_identity(actor, digest));
        Err(Error::Busy)
    }

    pub fn has_pending_ack(&self) -> bool {
        !self.uncertain && self.pending_ack.is_some()
    }

    pub fn persist_ack(
        &mut self,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<Option<u64>, Error> {
        let Some(ack) = self.pending_ack else {
            return Ok(None);
        };
        let mut next = self.next_page()?;
        next.ack = ack;
        next.retired = next.retired.checked_add(1).ok_or(Error::Exhausted)?;
        next.count -= 1;
        next.proofs.copy_within(1.., 0);
        next.proofs[next.count] = None;
        self.commit(next, io, work)?;
        self.delivered >>= 1;
        self.pending_ack = None;
        Ok(Some(self.page.retired))
    }

    pub fn append(
        &mut self,
        proof: RecoveryProofV2,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<(), Error> {
        let mut next = self.next_page()?;
        if next.count == RECORDS {
            return Err(Error::Capacity);
        }
        if next.spill.oldest().is_some() {
            return Err(Error::Busy);
        }
        self.validate_intake(&proof)?;
        advance_writer(&proof, self.boot, &mut next.writers)?;
        next.proofs[next.count] = Some(proof);
        next.count += 1;
        self.commit(next, io, work)
    }

    /// Make a newly observed proof durable before releasing its live writer
    /// custody. Only an append to the FIFO assigns an audit sequence. While
    /// full, retain a cumulative summary in the writer's spill slots or,
    /// after they exhaust, increment the explicit saturation witness.
    pub fn persist_proof(
        &mut self,
        proof: RecoveryProofV2,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<ProofPersistence, Error> {
        if self.page.count < RECORDS {
            self.append(proof, io, work)?;
            return Ok(ProofPersistence::Queued {
                sequence: self.page.retired + self.page.count as u64,
            });
        }
        self.validate_intake(&proof)?;
        let mut next = self.next_page()?;
        advance_writer(&proof, self.boot, &mut next.writers)?;
        let result = next.spill.ingest(
            proof,
            self.page.writers[proof.cpu_id as usize],
            next.generation,
        )?;
        self.commit(next, io, work)?;
        Ok(result)
    }

    /// Move the oldest unassigned summary into the next FIFO sequence as one
    /// durable operation. An ACK of an existing record is still a separate
    /// operation and cannot race this transition under the CPU0 owner.
    pub fn promote(
        &mut self,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<Option<u64>, Error> {
        if self.page.count == RECORDS || self.page.spill.oldest().is_none() {
            return Ok(None);
        }
        let mut next = self.next_page()?;
        let index = next.spill.oldest().ok_or(Error::Conflict)?;
        let entry = next.spill.deferred[index].take().ok_or(Error::Conflict)?;
        next.proofs[next.count] = Some(entry.proof);
        next.count += 1;
        self.commit(next, io, work)?;
        Ok(Some(self.page.retired + self.page.count as u64))
    }

    fn validate_intake(&self, proof: &RecoveryProofV2) -> Result<(), Error> {
        // A business slot reaches CPU0 only after a stopped-writer handoff.
        let generation = self
            .writer_generation
            .checked_add(u64::from(proof.cpu_id != 0))
            .ok_or(Error::Exhausted)?;
        if proof.boot_epoch != self.boot || proof.cpu_generation != generation {
            return Err(Error::Stale);
        }
        Ok(())
    }

    fn next_page(&self) -> Result<Page, Error> {
        if self.uncertain {
            return Err(Error::Unknown);
        }
        if self.boot == 0 {
            return Err(Error::Unauthorized);
        }
        let mut next = self.page;
        next.generation = next.generation.checked_add(1).ok_or(Error::Exhausted)?;
        next.prior_digest = next.seal;
        next.boot = self.boot;
        Ok(next)
    }

    fn commit(
        &mut self,
        mut next: Page,
        io: &mut impl EpochBlockIo,
        work: &mut Workspace,
    ) -> Result<(), Error> {
        if next.retired.checked_add(next.count as u64).is_none() {
            return Err(Error::Exhausted);
        }
        if !next.follows(&self.page) {
            return Err(Error::Conflict);
        }
        let home = self.locator.first_block + next.home_offset();
        next.encode(self.locator.carrier, &mut work.target);
        self.uncertain = true;
        io.write(home, &work.target)?;
        io.flush()?;
        io.read(home, &mut work.observed)?;
        if work.observed != work.target {
            return Err(Error::Unknown);
        }
        self.page = next;
        self.uncertain = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "recovery_proof_store_tests.rs"]
mod tests;
