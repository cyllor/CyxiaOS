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
const RECORDS: usize = 8;
const PROOFS_START: usize = 160;
const WRITER_START: usize = PROOFS_START + RECORDS * RECOVERY_PROOF_BYTES;
const WRITER_BYTES: usize = 56;
// CPU0 keeps its existing location. Empty CPU1–3 entries reproduce the
// zero padding of the earlier CPU0-only pages.
const WRITER_END: usize = WRITER_START + WRITER_BYTES * ACCUMULATOR_COUNT;
const PAGE_SEAL: usize = BLOCK - 32;
const AUDIT_PAYLOAD: usize = 144;
const ACL_BYTES: usize = 64;
const _: () = assert!(WRITER_END <= PAGE_SEAL);

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
        let inode = Inode::decode(&raw_inode)?;
        let acl_at = self.inode as usize * ACL_BYTES;
        io.read(acl_home + (acl_at / BLOCK) as u32, scratch)?;
        let offset = acl_at % BLOCK;
        let raw_acl = &scratch[offset..offset + ACL_BYTES];
        let acl = Acl::decode(raw_acl)?;
        if hash(&[&raw_inode, raw_acl]) != self.metadata_digest
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
    };

    fn decode(raw: &[u8; BLOCK], carrier: Hash, slot: u64, last_boot: u64) -> Result<Self, Error> {
        if raw.iter().all(|&byte| byte == 0) {
            return Ok(Self::EMPTY);
        }
        let seal = hash(&[PAGE_DOMAIN, &raw[..PAGE_SEAL]]);
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
            ..Self::EMPTY
        };
        if raw[..8] != *PAGE_MAGIC
            || raw[8..40] != carrier
            || raw[PAGE_SEAL..] != seal
            || page.generation == 0
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
        if last
            .iter()
            .zip(page.writers)
            .any(|(&retained, writer)| retained != Writer::EMPTY && retained != writer)
            || raw[end..WRITER_START].iter().any(|&byte| byte != 0)
            || raw[WRITER_END..PAGE_SEAL].iter().any(|&byte| byte != 0)
        {
            return Err(Error::Conflict);
        }
        Ok(page)
    }

    fn encode(&mut self, carrier: Hash, out: &mut [u8; BLOCK]) {
        out.fill(0);
        out[..8].copy_from_slice(PAGE_MAGIC);
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
        if self.retired == prior.retired && self.count == prior.count + 1 {
            return self.ack == prior.ack
                && self.proofs[..prior.count] == prior.proofs[..prior.count]
                && self.proofs[prior.count].is_some_and(|proof| {
                    // Decode and append both validate this CPU index before
                    // constructing a page.
                    let cpu = proof.cpu_id as usize;
                    let writer = Writer::from_proof(&proof);
                    let mut writers = prior.writers;
                    writers[cpu] = writer;
                    proof.boot_epoch == self.boot
                        && writer.advances(prior.writers[cpu], &proof)
                        && self.writers == writers
                });
        }
        prior.count == self.count + 1
            && prior.retired.checked_add(1) == Some(self.retired)
            && self.ack.boot == self.boot
            && self.ack.generation >= prior.ack.generation
            && self.ack.digest == audit_digest(self.retired, &prior.proofs[0].unwrap())
            && self.writers == prior.writers
            && self.proofs[..self.count] == prior.proofs[1..prior.count]
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
        self.boot > 0 && !self.uncertain && self.reader == Some(actor)
    }

    /// Custody inventory suitable for the boot owner's protected report.
    pub fn inventory(&self) -> (u64, u64) {
        (self.page.count as u64, self.page.retired)
    }

    pub fn can_append(&self) -> bool {
        self.boot > 0 && !self.uncertain && self.page.count < RECORDS
    }

    fn check_reader(&self, actor: Identity) -> Result<(), Error> {
        if self.boot == 0 || self.reader != Some(actor) {
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
        // A business slot reaches CPU0 only after a stopped-writer handoff.
        let generation = self
            .writer_generation
            .checked_add(u64::from(proof.cpu_id != 0))
            .ok_or(Error::Exhausted)?;
        if proof.boot_epoch != self.boot || proof.cpu_generation != generation {
            return Err(Error::Stale);
        }
        advance_writer(&proof, self.boot, &mut next.writers)?;
        next.proofs[next.count] = Some(proof);
        next.count += 1;
        self.commit(next, io, work)
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
