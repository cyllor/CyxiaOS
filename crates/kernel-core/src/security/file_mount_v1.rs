//! Baseline-v1 and unified-v1 mount checks join filesystem structure with
//! protected system objects, persistent principal identities and ACLs.
//! These checks consume the exclusive native post-replay disk view.
//! They do not issue file capabilities, clear UNKNOWN receipts or certify
//! that a signed startup catalog or writable production service exists.
pub use super::file_media_unified_v1::mount::MountedSnapshots;
use super::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{FileStreamIndexV4, SecurityStateStoreV2},
    file_media_unified_v1::{
        BASELINE_SYSTEM_BLOCKS, BASELINE_SYSTEM_OBJECTS, UNIFIED_SYSTEM_BLOCKS,
        UNIFIED_SYSTEM_OBJECTS, UnifiedSystemKind, UnifiedSystemObject, decode_object_envelope,
        mount::verify_snapshot_homes, unified_map_from_baseline,
    },
    file_media_v0199::{SuperblockV1, crc32c_zeroed},
    file_receipt_store_v0199::{self, RECEIPT_STORE_BYTES, ReceiptStoreSummary},
    file_structure_v1::{self, BLOCK, INODES, Inode, StructureEvidence, SystemKind, SystemObject},
    offline_config_v1::{Principal, VerifiedOfflineConfig},
};
use sha2::{Digest, Sha256};
const ACL_BYTES: usize = 64;
const ACL_STORE: usize = INODES * ACL_BYTES;
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const DIR_RIGHTS: u32 = (1 << 10) | (1 << 11) | (1 << 12) | (1 << 14);
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acl {
    pub inode_id: u32,
    pub state: u32,
    pub inode_generation: u64,
    pub principal: Principal,
    pub owner_rights: u32,
    pub system_rights: u32,
    pub acl_generation: u64,
    pub parent: u32,
}
impl Acl {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != ACL_BYTES
            || u32at(b, 52) != 0
            || u32at(b, 56) != 0
            || u32at(b, 60) != crc32c_zeroed(b, 60)?
        {
            return Err(Error::Invalid);
        }
        let a = Self {
            inode_id: u32at(b, 0),
            state: u32at(b, 4),
            inode_generation: u64at(b, 8),
            principal: Principal {
                id: u64at(b, 16),
                generation: u64at(b, 24),
            },
            owner_rights: u32at(b, 32),
            system_rights: u32at(b, 36),
            acl_generation: u64at(b, 40),
            parent: u32at(b, 48),
        };
        if a.inode_id >= INODES as u32
            || a.state > 2
            || a.parent >= INODES as u32
            || (a.owner_rights | a.system_rights) & !(FILE_RIGHTS | DIR_RIGHTS) != 0
        {
            return Err(Error::Invalid);
        }
        Ok(a)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub inodes: u32,
    pub blocks: u32,
    pub directory_slots: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountEvidence {
    pub structure: StructureEvidence,
    pub boot: BootEpochStoreV1,
    pub security: SecurityStateStoreV2,
    pub receipts: ReceiptStoreSummary,
    pub usage: [Usage; 16],
    pub system_blocks: u32,
    pub snapshot: Option<MountedSnapshots>,
    baseline_system: Option<[SystemObject; 4]>,
}

impl MountEvidence {
    pub(super) const fn baseline_system(&self) -> Option<&[SystemObject; 4]> {
        self.baseline_system.as_ref()
    }

    /// A historical root by itself grants neither write admission nor file access.
    pub const fn writes_open(&self) -> bool {
        match self.snapshot {
            Some(snapshot) => snapshot.writes_open(),
            None => self.baseline_system.is_some(),
        }
    }

    /// Use the previously durable write gate to qualify committed redo.
    /// New writes require this boot's independently qualified admission.
    pub const fn permits_replay_of_file_writes(&self) -> bool {
        match self.snapshot {
            Some(snapshot) => snapshot.has_open_proof(),
            None => self.writes_open(),
        }
    }

    /// Qualify a verified open receipt for this running boot. Cold mount
    /// always starts closed. The native owner must authenticate the separate
    /// protection role, exact current boot and durable restore/open evidence.
    pub fn authorize_snapshot_writes(
        &mut self,
        gate: &super::snapshot_restore_gate::RestoreGate,
        verify_current_boot: impl FnOnce(BootEpochStoreV1) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let snapshot = self.snapshot.as_mut().ok_or(Error::Unauthorized)?;
        snapshot.qualify_writes(gate, || verify_current_boot(self.boot))
    }

    /// Owners without native CoW may change homes only while every slot is
    /// free. DELETING also protects its blocks until verified GC retirement.
    pub fn may_overwrite_in_place(&self) -> bool {
        self.writes_open()
            && self
                .snapshot
                .is_none_or(|snapshot| !snapshot.retains_roots())
    }
}
pub struct Workspace {
    structure: file_structure_v1::Workspace,
    boot: [u8; BLOCK],
    security: [u8; BLOCK],
    index: [u8; BLOCK],
    receipts: [u8; RECEIPT_STORE_BYTES],
    acl: [u8; ACL_STORE],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            structure: file_structure_v1::Workspace::new(),
            boot: [0; BLOCK],
            security: [0; BLOCK],
            index: [0; BLOCK],
            receipts: [0; RECEIPT_STORE_BYTES],
            acl: [0; ACL_STORE],
        }
    }

    /// Protected history marks from the successful exclusive mount. Query
    /// before reusing this workspace for any different committed view.
    pub fn history_owns(&self, block: u32) -> bool {
        self.structure.history_owns(block)
    }

    /// Validate the transaction cursor of every receipt retained in the
    /// checkpointed homes of the exclusive mount. A bound terminal result
    /// needs a retained transaction identity within the selected checkpoint.
    pub fn verify_checkpointed_receipts(&self, checkpoint: SuperblockV1) -> Result<(), Error> {
        use super::file_media_v0199::{FileReceiptV4, RECEIPT_BYTES};

        for raw in self.receipts.chunks_exact(RECEIPT_BYTES) {
            if raw.iter().all(|&byte| byte == 0) {
                continue;
            }
            let receipt = FileReceiptV4::decode(raw)?;
            let terminal_effect = matches!(receipt.status, 3 | 4)
                || receipt.status == 6 && receipt.operation_digest != [0; 32];
            if receipt.fs_uuid != checkpoint.fs_uuid
                || receipt.log_epoch >= checkpoint.log_epoch
                || receipt.commit_lsn > checkpoint.checkpoint_lsn
                || terminal_effect && receipt.commit_lsn == 0
            {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }

    /// Tie every current-epoch receipt to its independently checked redo
    /// transaction. The mount owner has already validated store and index
    /// structure in the committed overlay.
    pub fn verify_resident_receipt_commits(
        &self,
        checkpoint: SuperblockV1,
        mut verify: impl FnMut(usize, &super::file_media_v0199::FileReceiptV4) -> Result<(), Error>,
    ) -> Result<(), Error> {
        use super::file_media_v0199::{FileReceiptV4, RECEIPT_BYTES};

        for (slot, raw) in self.receipts.chunks_exact(RECEIPT_BYTES).enumerate() {
            if raw.iter().all(|&byte| byte == 0) {
                continue;
            }
            let receipt = FileReceiptV4::decode(raw)?;
            if receipt.log_epoch == checkpoint.log_epoch {
                verify(slot, &receipt)?;
            }
        }
        Ok(())
    }

    /// Check the receipt/query view captured by a successful exclusive mount
    /// after the owner independently verifies the single paired BootEpoch redo.
    /// That transaction changes only the boot and security homes, so the
    /// receipt and index images from the same mount remain valid. This is
    /// read-only custody evidence, not a FILE_RECEIPT_QUERY role qualification.
    pub fn confirmed_receipt_query_digest(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        config: &VerifiedOfflineConfig<'_>,
    ) -> Result<[u8; 32], Error> {
        self.confirmed_receipt_query_digest_metered(prior, committed, config, &mut || Ok(()))
    }

    pub fn confirmed_receipt_query_digest_metered(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        config: &VerifiedOfflineConfig<'_>,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<[u8; 32], Error> {
        let old_security = prior.security;
        let expected = SecurityStateStoreV2 {
            state_generation: old_security
                .state_generation
                .checked_add(1)
                .ok_or(Error::Exhausted)?,
            last_boot_epoch: old_security
                .last_boot_epoch
                .checked_add(1)
                .ok_or(Error::Exhausted)?,
            ..old_security
        };
        self.confirmed_receipt_query_digest_for(prior, committed, config, &expected, checkpoint)
    }

    /// Rebind the read-only receipt view after a signed TLS transition
    /// changed only the two protected boot homes.
    pub fn confirmed_receipt_query_digest_after_tls(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        transition: super::boot_epoch_v1::TlsBootTransition<'_>,
    ) -> Result<[u8; 32], Error> {
        self.confirmed_receipt_query_digest_after_tls_metered(
            prior,
            committed,
            transition,
            &mut || Ok(()),
        )
    }

    pub fn confirmed_receipt_query_digest_after_tls_metered(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        transition: super::boot_epoch_v1::TlsBootTransition<'_>,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<[u8; 32], Error> {
        let expected = transition.successor_state(&prior.security)?;
        self.confirmed_receipt_query_digest_for(
            prior,
            committed,
            transition.current().config(),
            &expected,
            checkpoint,
        )
    }

    fn confirmed_receipt_query_digest_for(
        &self,
        prior: &MountEvidence,
        committed: &SecurityStateStoreV2,
        config: &VerifiedOfflineConfig<'_>,
        expected: &SecurityStateStoreV2,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<[u8; 32], Error> {
        checkpoint()?;
        let old_boot = BootEpochStoreV1::decode(&self.boot)?;
        let old_security = SecurityStateStoreV2::decode(&self.security)?;
        checkpoint()?;
        let receipts = file_receipt_store_v0199::scan_receipts_with_index(
            &self.receipts,
            &self.index,
            old_boot.fs_uuid,
        )?;
        if old_boot != prior.boot
            || old_security != prior.security
            || !old_boot.matches(&old_security)
            || receipts != prior.receipts
        {
            return Err(Error::Conflict);
        }
        if committed != expected {
            return Err(Error::Conflict);
        }
        checkpoint()?;
        let _view = super::file_receipt_query_v4::MountedReceiptQuery::new(
            &self.receipts,
            &self.index,
            config,
            committed,
        )?;
        let mut digest = Sha256::new();
        for block in self
            .receipts
            .chunks_exact(BLOCK)
            .chain([self.index.as_slice()])
        {
            checkpoint()?;
            digest.update(block);
        }
        Ok(digest.finalize().into())
    }
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = assert!(core::mem::size_of::<Workspace>() <= 192 * 1024);
fn blocks(io: &mut impl EpochBlockIo, first: u32, out: &mut [u8]) -> Result<(), Error> {
    if !out.len().is_multiple_of(BLOCK) {
        return Err(Error::Invalid);
    }
    for (i, b) in out.chunks_exact_mut(BLOCK).enumerate() {
        io.read(
            first.checked_add(i as u32).ok_or(Error::Invalid)?,
            b.try_into().unwrap(),
        )?;
    }
    Ok(())
}
fn inspect_acls<K>(
    acl: &[u8; ACL_STORE],
    inodes: &[Inode; INODES],
    principals: &[Principal; 16],
    system_kind: impl Fn(usize) -> Option<K>,
    mut policy: impl FnMut(Acl, Inode, Option<K>) -> Result<(), Error>,
) -> Result<([Usage; 16], u32), Error> {
    let mut usage = [Usage::default(); 16];
    let mut system_blocks = 0u32;
    for (i, raw) in acl.chunks_exact(ACL_BYTES).enumerate() {
        let a = Acl::decode(raw)?;
        let inode = inodes[i];
        if a.inode_id != i as u32 || a.inode_generation != inode.generation {
            return Err(Error::Conflict);
        }
        let owner = principals.iter().position(|p| *p == a.principal);
        let hidden = system_kind(i);
        if inode.kind == 0 {
            // Initial empty and retained tombstone have no access authority.
            // The signed volume policy decides any retained identity fields.
            if a.state == 1
                || a.owner_rights != 0
                || a.system_rights != 0
                || a.state == 0 && inode.generation != 0
                || a.state == 2 && inode.generation == 0
                || (a.principal.id != 0 || a.principal.generation != 0) && owner.is_none()
            {
                return Err(Error::Conflict);
            }
        } else {
            let slot = owner.ok_or(Error::Unauthorized)?;
            let mask = if inode.kind == 1 {
                FILE_RIGHTS
            } else {
                DIR_RIGHTS
            };
            if a.state != 1
                || a.acl_generation == 0
                || a.parent != inode.parent
                || (a.owner_rights | a.system_rights) & !mask != 0
                || hidden.is_some() && a.owner_rights != 0
            {
                return Err(Error::Unauthorized);
            }
            let n = inode.runs[..usize::from(inode.extents)]
                .iter()
                .try_fold(0u32, |sum, r| sum.checked_add(r.count))
                .ok_or(Error::Capacity)?;
            if hidden.is_some() {
                system_blocks = system_blocks.checked_add(n).ok_or(Error::Capacity)?;
            } else {
                let u = &mut usage[slot];
                u.inodes = u.inodes.checked_add(1).ok_or(Error::Capacity)?;
                u.blocks = u.blocks.checked_add(n).ok_or(Error::Capacity)?;
                if inode.kind == 2 {
                    u.directory_slots = u
                        .directory_slots
                        .checked_add((inode.size / 128) as u32)
                        .ok_or(Error::Capacity)?;
                }
            }
        }
        policy(a, inode, hidden)?;
    }
    Ok((usage, system_blocks))
}
struct BaselinePayloads {
    boot: BootEpochStoreV1,
    security: SecurityStateStoreV2,
    receipts: ReceiptStoreSummary,
    system: [SystemObject; 4],
}
fn read_baseline_payloads(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
) -> Result<BaselinePayloads, Error> {
    for (i, p) in principals.iter().enumerate() {
        if p.id == 0 || p.generation == 0 || principals[..i].iter().any(|old| old.id == p.id) {
            return Err(Error::Invalid);
        }
    }
    for s in system {
        match s.kind {
            SystemKind::BootEpoch => io.read(s.first_block, &mut w.boot)?,
            SystemKind::Security => io.read(s.first_block, &mut w.security)?,
            SystemKind::Receipts => {
                blocks(io, s.first_block, &mut w.receipts)?;
                io.read(s.first_block + 6, &mut w.index)?;
            }
            SystemKind::Acl => blocks(io, s.first_block, &mut w.acl)?,
        }
    }
    let boot = BootEpochStoreV1::decode(&w.boot)?;
    let security = SecurityStateStoreV2::decode(&w.security)?;
    let index = FileStreamIndexV4::decode(&w.index)?;
    if boot.fs_uuid != sb.fs_uuid
        || !boot.matches(&security)
        || index.fs_uuid != sb.fs_uuid
        || index
            .groups
            .iter()
            .zip(principals)
            .any(|(g, p)| g.manifest_principal_id != p.id || g.boot_epoch > boot.boot_epoch)
    {
        return Err(Error::Conflict);
    }
    let receipts =
        file_receipt_store_v0199::scan_receipts_with_index(&w.receipts, &w.index, sb.fs_uuid)?;
    Ok(BaselinePayloads {
        boot,
        security,
        receipts,
        system: *system,
    })
}
impl BaselinePayloads {
    fn mount_evidence(
        self,
        structure: StructureEvidence,
        (usage, system_blocks): ([Usage; 16], u32),
        expected_objects: usize,
        expected_blocks: u32,
    ) -> Result<MountEvidence, Error> {
        if system_blocks != expected_blocks
            || usage.iter().map(|u| u.blocks).sum::<u32>() + system_blocks != structure.data_blocks
            || usage.iter().map(|u| u.inodes).sum::<u32>() + expected_objects as u32
                != u32::from(structure.live_inodes)
        {
            return Err(Error::Conflict);
        }
        Ok(MountEvidence {
            structure,
            boot: self.boot,
            security: self.security,
            receipts: self.receipts,
            usage,
            system_blocks,
            snapshot: None,
            baseline_system: (expected_objects == BASELINE_SYSTEM_OBJECTS).then_some(self.system),
        })
    }
}
/// All four object payloads are copied from the actual stable disk view,
/// then cross-validated with the full inode scan. The trusted ACL policy
/// must accept every inode, including the root and hidden system files.
pub fn validate(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<SystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    file_structure_v1::validate_system_layout(system)?;
    let payloads = read_baseline_payloads(io, sb, system, principals, w)?;
    let structure =
        file_structure_v1::scan_baseline(sb, system, &mut w.structure, |b, out| io.read(b, out))?;
    let counters = inspect_acls(
        &w.acl,
        w.structure.inodes(),
        principals,
        |i| {
            system
                .iter()
                .find(|s| usize::from(s.inode) == i)
                .map(|s| s.kind)
        },
        policy,
    )?;
    payloads.mount_evidence(
        structure,
        counters,
        BASELINE_SYSTEM_OBJECTS,
        BASELINE_SYSTEM_BLOCKS,
    )
}
fn verify_snapshot_objects(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    snapshot: &[UnifiedSystemObject; 4],
    block: &mut [u8; BLOCK],
) -> Result<(), Error> {
    for s in snapshot {
        io.read(s.first_block, block)?;
        let envelope = decode_object_envelope(s.kind, block)?;
        if envelope.fs_uuid != sb.fs_uuid || envelope.generation != s.generation {
            return Err(Error::Conflict);
        }
        for tail in s.first_block + 1..s.first_block + s.kind.blocks() {
            io.read(tail, block)?;
            if block.iter().any(|&byte| byte != 0) {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}
/// Read-only validation of the unified v1 homes under the caller's mount
/// exclusion. The manifest fixes the identity and extents of all eight
/// hidden objects. Snapshot payloads and continuation blocks must be zero
/// while their formats await golden vectors. Every ACL requires the
/// independent trusted policy's acceptance.
pub fn validate_unified(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    baseline: &[SystemObject; 4],
    snapshot: &[UnifiedSystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<UnifiedSystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    let system = unified_map_from_baseline(baseline, snapshot)?;
    // Use the index buffer only before reading the protected index. The
    // mount's receipt query custody must retain its exact validated bytes
    // across the later paired BootEpoch transaction. No extra workspace or
    // disk reads are required under the same exclusive read-only mount.
    verify_snapshot_objects(io, sb, snapshot, &mut w.index)?;
    let payloads = read_baseline_payloads(io, sb, baseline, principals, w)?;
    let structure =
        file_structure_v1::scan_unified(sb, &system, &mut w.structure, |b, out| io.read(b, out))?;
    let counters = inspect_acls(
        &w.acl,
        w.structure.inodes(),
        principals,
        |i| {
            system
                .iter()
                .find(|s| usize::from(s.inode) == i)
                .map(|s| s.kind)
        },
        policy,
    )?;
    payloads.mount_evidence(
        structure,
        counters,
        UNIFIED_SYSTEM_OBJECTS,
        UNIFIED_SYSTEM_BLOCKS,
    )
}
/// Validate nonempty snapshot homes under the authenticated eight-object
/// layout. The caller binds the manifest to the signed principal table and
/// supplies either checkpointed or fully verified committed redo contents.
pub fn validate_unified_resident(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    baseline: &[SystemObject; 4],
    snapshot: &[UnifiedSystemObject; 4],
    principals: &[Principal; 16],
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<UnifiedSystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    let system = unified_map_from_baseline(baseline, snapshot)?;
    let mut snapshots = verify_snapshot_homes(io, sb, snapshot, &mut w.index)?;
    let payloads = read_baseline_payloads(io, sb, baseline, principals, w)?;
    let (structure, historical_only) = file_structure_v1::scan_unified_history(
        sb,
        &system,
        &mut w.structure,
        |b, out| io.read(b, out),
        snapshots.catalog.as_ref(),
    )?;
    let counters = inspect_acls(
        &w.acl,
        w.structure.inodes(),
        principals,
        |i| {
            system
                .iter()
                .find(|s| usize::from(s.inode) == i)
                .map(|s| s.kind)
        },
        policy,
    )?;
    let mut mounted = payloads.mount_evidence(
        structure,
        counters,
        UNIFIED_SYSTEM_OBJECTS,
        UNIFIED_SYSTEM_BLOCKS,
    )?;
    snapshots.historical_only_blocks = historical_only;
    mounted.snapshot = Some(snapshots);
    mounted.baseline_system = Some(*baseline);
    Ok(mounted)
}

/// Compute the bitmap after dropping one verified retiring root. The caller
/// retains the mount's exclusive freeze while calculating and publishing it.
#[cfg(not(target_os = "none"))]
pub(super) fn gc_bitmap_after(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    baseline: &[SystemObject; 4],
    snapshot: &[UnifiedSystemObject; 4],
    w: &mut Workspace,
    retained: &super::file_media_unified_v1::catalog_candidate::CatalogRecord,
    bitmap_after: &mut [[u8; BLOCK]; 4],
) -> Result<u32, Error> {
    let system = unified_map_from_baseline(baseline, snapshot)?;
    file_structure_v1::scan_gc_reclaim(
        sb,
        &system,
        &mut w.structure,
        |b, out| io.read(b, out),
        retained,
        bitmap_after,
    )
}

/// Production callers must obtain the system object locations from an
/// authenticated boot catalog. The exact signed principal table, security
/// minima and configuration digest are then enforced before checkpoint.
pub fn validate_signed(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    system: &[SystemObject; 4],
    config: &VerifiedOfflineConfig<'_>,
    w: &mut Workspace,
    policy: impl FnMut(Acl, Inode, Option<SystemKind>) -> Result<(), Error>,
) -> Result<MountEvidence, Error> {
    let e = validate(io, sb, system, config.principals(), w, policy)?;
    config.check_committed(&e.security)?;
    Ok(e)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::security::{
        file_media_unified_v1::{
            CANONICAL_BUSINESS_START, CATALOG_INODE, ENVELOPE_BYTES, RESERVED_INODE_START,
            SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_REQUEST_START,
            SNAPSHOT_SLOT_START, encode_object_envelope, protection_candidate::ProtectionRecord,
        },
        file_media_v0199::{BITMAP_START, DATA_START, INODE_START},
        file_structure_v1::{Extent, INODE_BYTES},
    };
    use std::{boxed::Box, collections::BTreeMap};
    const STATE_HOME: u32 = 7000;
    const BOOT_HOME: u32 = 7002;
    const RECEIPTS: u32 = 7003;
    const ACL: u32 = 7010;
    const ROOT: u32 = 7014;

    #[test]
    fn checkpoint_bounds_require_transaction_evidence_for_bound_terminal_results() {
        use crate::security::file_media_v0199::{FileReceiptV4, RECEIPT_BYTES, local_request_id};

        let checkpoint = SuperblockV1 {
            fs_uuid: [1; 16],
            generation: 3,
            log_epoch: 3,
            checkpoint_lsn: 13,
        };
        let record = FileReceiptV4 {
            fs_uuid: checkpoint.fs_uuid,
            issued_boot_epoch: 2,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
            log_epoch: 0,
            txid: 0,
            commit_lsn: 0,
            write_seq: 0,
            status: 1,
            result: 0,
            completed_prefix: 0,
            operation_digest: [0; 32],
            output_digest: [0; 32],
            request_id: local_request_id(0, 0, 1).unwrap(),
            owner_principal_id: 1,
        };
        let done = FileReceiptV4 {
            status: 3,
            operation_digest: [2; 32],
            ..record
        };
        let committed = FileReceiptV4 {
            log_epoch: 2,
            txid: 2,
            commit_lsn: 13,
            ..done
        };
        let mut workspace = Workspace::new();
        for (receipt, expected) in [
            (record, Ok(())),
            (done, Err(Error::Conflict)),
            (committed, Ok(())),
            (
                FileReceiptV4 {
                    commit_lsn: 14,
                    ..committed
                },
                Err(Error::Conflict),
            ),
            (
                FileReceiptV4 {
                    log_epoch: 3,
                    ..committed
                },
                Err(Error::Conflict),
            ),
        ] {
            workspace.receipts[..RECEIPT_BYTES].copy_from_slice(&receipt.encode().unwrap());
            assert_eq!(workspace.verify_checkpointed_receipts(checkpoint), expected);
        }
    }

    fn p16(b: &mut [u8], i: usize, v: u16) {
        b[i..i + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(b: &mut [u8], i: usize, v: u32) {
        b[i..i + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], i: usize, v: u64) {
        b[i..i + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn seal(b: &mut [u8], at: usize) {
        let c = crc32c_zeroed(b, at).unwrap();
        p32(b, at, c);
    }
    fn inode(b: &mut [u8], kind: u16, size: u64, home: u32, n: u32) {
        b.fill(0);
        p32(b, 0, 0x4359494e);
        p16(b, 4, kind);
        if kind != 0 {
            p64(b, 8, 1);
            p64(b, 16, size);
            p64(b, 40, 1);
            if n != 0 {
                p16(b, 32, 1);
                p32(b, 52, home);
                p32(b, 56, n);
            }
        }
        seal(b, 252);
    }
    struct Disk(BTreeMap<u32, Box<[u8; BLOCK]>>);
    impl EpochBlockIo for Disk {
        fn read(&mut self, b: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            if let Some(v) = self.0.get(&b) {
                *out = **v;
            } else {
                out.fill(0);
            }
            Ok(())
        }
        fn write(&mut self, _: u32, _: &[u8; BLOCK]) -> Result<(), Error> {
            panic!("read-only mount validation")
        }
        fn flush(&mut self) -> Result<(), Error> {
            panic!("read-only mount validation")
        }
    }
    fn systems() -> [SystemObject; 4] {
        [
            SystemObject {
                kind: SystemKind::BootEpoch,
                inode: 2,
                generation: 1,
                first_block: BOOT_HOME,
            },
            SystemObject {
                kind: SystemKind::Receipts,
                inode: 3,
                generation: 1,
                first_block: RECEIPTS,
            },
            SystemObject {
                kind: SystemKind::Acl,
                inode: 4,
                generation: 1,
                first_block: ACL,
            },
            SystemObject {
                kind: SystemKind::Security,
                inode: 5,
                generation: 1,
                first_block: STATE_HOME,
            },
        ]
    }
    fn fixture() -> Disk {
        let mut d = Disk(BTreeMap::new());
        for page in 0..4u32 {
            let mut b = [0; BLOCK];
            let start = page * BLOCK as u32 * 8;
            for at in start..start + BLOCK as u32 * 8 {
                if at < 4118 || (STATE_HOME..=ROOT).contains(&at) {
                    let v = at - start;
                    b[(v / 8) as usize] |= 1 << (v % 8);
                }
            }
            d.0.insert(4098 + page, Box::new(b));
        }
        for page in 0..16u32 {
            let mut b = [0; BLOCK];
            for (j, slot) in b.chunks_exact_mut(256).enumerate() {
                match page * 16 + j as u32 {
                    0 => inode(slot, 2, 128, ROOT, 1),
                    1 => inode(slot, 1, 8, STATE_HOME + 1, 1),
                    2 => inode(slot, 1, 4096, BOOT_HOME, 1),
                    3 => inode(slot, 1, 7 * 4096, RECEIPTS, 7),
                    4 => inode(slot, 1, 4 * 4096, ACL, 4),
                    5 => inode(slot, 1, 4096, STATE_HOME, 1),
                    _ => inode(slot, 0, 0, 0, 0),
                }
            }
            d.0.insert(4102 + page, Box::new(b));
        }
        let mut root = [0; BLOCK];
        p32(&mut root, 0, 1);
        p16(&mut root, 4, 1);
        p64(&mut root, 8, 1);
        root[16] = b'x';
        seal(&mut root[..128], 124);
        d.0.insert(ROOT, Box::new(root));
        for page in 0..4u32 {
            let mut b = [0; BLOCK];
            for (j, slot) in b.chunks_exact_mut(64).enumerate() {
                let id = page * 64 + j as u32;
                p32(slot, 0, id);
                if id < 6 {
                    p32(slot, 4, 1);
                    p64(slot, 8, 1);
                    p64(slot, 16, 1);
                    p64(slot, 24, 1);
                    p64(slot, 40, 1);
                    if id == 0 {
                        p32(slot, 32, 1 << 14);
                    } else if id == 1 {
                        p32(slot, 32, 1 << 8);
                    } else {
                        p32(slot, 36, FILE_RIGHTS);
                    }
                }
                seal(slot, 60);
            }
            d.0.insert(ACL + page, Box::new(b));
        }
        let mut index = [0; BLOCK];
        p32(&mut index, 0, 0x43595349);
        p16(&mut index, 4, 4);
        p16(&mut index, 6, 64);
        index[8..24].fill(1);
        p64(&mut index, 32, 1);
        for i in 0..16 {
            p64(&mut index, 64 + 24 * i + 16, i as u64 + 1);
        }
        seal(&mut index, 4092);
        d.0.insert(RECEIPTS + 6, Box::new(index));
        let boot = BootEpochStoreV1 {
            fs_uuid: [1; 16],
            boot_epoch: 2,
        }
        .encode()
        .unwrap();
        let security = SecurityStateStoreV2 {
            fs_uuid: [1; 16],
            state_generation: 3,
            rule_min_generation: 1,
            security_min_generation: 1,
            key_generation: 1,
            isolated_service_bitmap: 0,
            last_boot_epoch: 2,
            offline_config_generation: 1,
            offline_config_hash: [3; 32],
            service_generations: [1; 16],
        }
        .encode()
        .unwrap();
        d.0.insert(BOOT_HOME, Box::new(boot));
        d.0.insert(STATE_HOME, Box::new(security));
        d
    }

    impl Disk {
        fn inode_slot(&mut self, id: u16) -> &mut [u8] {
            let page = INODE_START + u32::from(id) / 16;
            let offset = (usize::from(id) % 16) * INODE_BYTES;
            &mut self.0.get_mut(&page).unwrap()[offset..offset + INODE_BYTES]
        }

        fn acl_slot(&mut self, id: u16) -> &mut [u8] {
            let page = ACL + u32::from(id) / 64;
            let offset = (usize::from(id) % 64) * ACL_BYTES;
            &mut self.0.get_mut(&page).unwrap()[offset..offset + ACL_BYTES]
        }

        fn set_allocated(&mut self, block: u32, allocated: bool) {
            let byte = (block / 8) as usize;
            let page = BITMAP_START + (byte / BLOCK) as u32;
            let slot = &mut self.0.get_mut(&page).unwrap()[byte % BLOCK];
            let mask = 1 << (block % 8);
            if allocated {
                *slot |= mask;
            } else {
                *slot &= !mask;
            }
        }
    }

    fn unified_fixture() -> (Disk, [SystemObject; 4], [UnifiedSystemObject; 4]) {
        let mut disk = fixture();
        let mut baseline = systems();
        for s in &mut baseline {
            let old = s.inode;
            inode(disk.inode_slot(old), 0, 0, 0, 0);
            let acl = disk.acl_slot(old);
            acl.fill(0);
            p32(acl, 0, u32::from(old));
            seal(acl, 60);
            s.inode = UnifiedSystemKind::from_baseline(s.kind).inode_slot();
        }
        let snapshot = [
            UnifiedSystemKind::SnapshotCatalog,
            UnifiedSystemKind::SnapshotSlot,
            UnifiedSystemKind::SnapshotRequest,
            UnifiedSystemKind::SnapshotProtection,
        ]
        .map(|kind| UnifiedSystemObject {
            kind,
            inode: kind.inode_slot(),
            generation: 1,
            first_block: kind.fixed_first_block().unwrap(),
        });
        for s in unified_map_from_baseline(&baseline, &snapshot).unwrap() {
            let count = s.kind.blocks();
            inode(
                disk.inode_slot(s.inode),
                1,
                u64::from(count) * BLOCK as u64,
                s.first_block,
                count,
            );
            let acl = disk.acl_slot(s.inode);
            p32(acl, 4, 1);
            p64(acl, 8, 1);
            p64(acl, 16, 1);
            p64(acl, 24, 1);
            p32(acl, 36, FILE_RIGHTS);
            p64(acl, 40, 1);
            seal(acl, 60);
            for block in s.first_block..s.first_block + count {
                disk.set_allocated(block, true);
            }
            if s.kind.is_new_snapshot_object() {
                let mut head = Box::new([0; BLOCK]);
                encode_object_envelope(s.kind, [1; 16], s.generation, &mut *head).unwrap();
                disk.0.insert(s.first_block, head);
            }
        }
        // Baseline homes are relocatable, so an ordinary file may use DATA_START.
        disk.set_allocated(STATE_HOME + 1, false);
        disk.set_allocated(DATA_START, true);
        inode(disk.inode_slot(1), 1, 8, DATA_START, 1);
        (disk, baseline, snapshot)
    }

    const CHECKPOINT: SuperblockV1 = SuperblockV1 {
        fs_uuid: [1; 16],
        generation: 2,
        checkpoint_lsn: 4,
        log_epoch: 2,
    };

    fn principals() -> [Principal; 16] {
        core::array::from_fn(|i| Principal {
            id: i as u64 + 1,
            generation: 1,
        })
    }

    const HISTORY_FILE: u32 = 7050;
    const HISTORY_ROOT: u32 = 7051;

    fn add_snapshot(disk: &mut Disk, slot: u32, deleting: bool, physical: u32) {
        use crate::security::file_media_unified_v1::{
            SLOT_MIRROR_BLOCKS, SNAPSHOT_STRIDE,
            catalog_candidate::{CatalogBinding, CatalogEntry, CatalogRecord},
            protection_candidate::{ProtectionRecord, RestorePhase},
            slot_candidate::{SlotDescriptor, SlotIdentity},
        };
        let identity = SlotIdentity {
            fs_uuid: CHECKPOINT.fs_uuid,
            snapshot_id: u64::from(slot) + 1,
            slot,
            slot_generation: 1,
            captured_live_view_epoch: 1,
            capture_commit_lsn: 3,
            created_online_age_ns: 10,
        };
        let descriptor_home = SNAPSHOT_SLOT_START + slot * SNAPSHOT_STRIDE;
        let mut mirrors = Sha256::new();
        for page in 0..SLOT_MIRROR_BLOCKS {
            let mut raw = Box::new(*disk.0[&(INODE_START + page)]);
            if page == 0 {
                inode(&mut raw[..INODE_BYTES], 2, 128, HISTORY_ROOT, 1);
                inode(&mut raw[INODE_BYTES..2 * INODE_BYTES], 1, 8, physical, 1);
            }
            mirrors.update(&*raw);
            disk.0.insert(descriptor_home + 1 + page, raw);
        }
        disk.0.insert(HISTORY_ROOT, disk.0[&ROOT].clone());
        disk.set_allocated(HISTORY_ROOT, true);
        disk.set_allocated(HISTORY_FILE, true);
        let raw = disk
            .0
            .entry(descriptor_home)
            .or_insert_with(|| Box::new([0; BLOCK]));
        SlotDescriptor {
            identity,
            store_generation: (slot == 0).then_some(1),
            inode_image_sha256: mirrors.finalize().into(),
        }
        .encode(raw)
        .unwrap();
        let binding = CatalogBinding {
            identity,
            descriptor_sha256: Sha256::digest(&**raw).into(),
        };
        let raw = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
        let mut catalog =
            CatalogRecord::decode(SNAPSHOT_CATALOG_BLOCK, raw).unwrap_or(CatalogRecord {
                fs_uuid: CHECKPOINT.fs_uuid,
                generation: 2,
                entries: [CatalogEntry::Free { slot_generation: 0 }; 8],
                next_snapshot_id: 1,
            });
        catalog.entries[slot as usize] = if deleting {
            CatalogEntry::Deleting {
                binding,
                root_drop_commit_lsn: 4,
            }
        } else {
            CatalogEntry::Active(binding)
        };
        catalog.next_snapshot_id = catalog.next_snapshot_id.max(identity.snapshot_id + 1);
        catalog.encode(raw).unwrap();
        let raw = disk.0.get_mut(&SNAPSHOT_PROTECTION_BLOCK).unwrap();
        let mut protection = ProtectionRecord::decode(&raw[..]).unwrap_or(ProtectionRecord {
            fs_uuid: CHECKPOINT.fs_uuid,
            object_generation: 2,
            protection_generation: 1,
            live_view_epoch: 1,
            online_age_ns: 20,
            retention_deadlines: [0; 8],
            writes_open: false,
            restore_phase: RestorePhase::Idle,
            cleanup_frozen: false,
            reopen_proof_digest: [0; 32],
            restore_obligation_digest: [0; 32],
        });
        protection.retention_deadlines[slot as usize] = 15;
        protection.encode(raw).unwrap();
    }

    #[test]
    fn signed_snapshot_mount_checks_each_tree_and_its_exact_bitmap_union() {
        for deleting in [false, true] {
            let (mut disk, baseline, snapshot) = unified_fixture();
            let mut work = Workspace::new();
            let verify = |disk: &mut Disk, work: &mut Workspace| {
                validate_unified_resident(
                    disk,
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &principals(),
                    work,
                    |_, _, _| Ok(()),
                )
            };
            let genesis = verify(&mut disk, &mut work).unwrap();
            assert!(genesis.snapshot.unwrap().catalog.is_none());
            assert!(!genesis.writes_open());
            assert!(!genesis.permits_replay_of_file_writes());
            add_snapshot(&mut disk, 0, deleting, HISTORY_FILE);
            let mounted = verify(&mut disk, &mut work).unwrap();
            assert_eq!(mounted.snapshot.unwrap().historical_only_blocks, 2);
            assert!(!mounted.may_overwrite_in_place());

            disk.set_allocated(HISTORY_FILE, false);
            assert_eq!(verify(&mut disk, &mut work), Err(Error::Conflict));
            disk.set_allocated(HISTORY_FILE, true);
            let bad_child = &mut disk.0.get_mut(&HISTORY_ROOT).unwrap()[..128];
            p64(bad_child, 8, 99);
            seal(bad_child, 124);
            assert_eq!(verify(&mut disk, &mut work), Err(Error::Conflict));
            // Even a well-formed historical mirror must reject a reference
            // to a hidden system block and a forged open-gate digest.
            add_snapshot(&mut disk, 0, deleting, SNAPSHOT_REQUEST_START);
            assert_eq!(verify(&mut disk, &mut work), Err(Error::Conflict));
            add_snapshot(&mut disk, 0, deleting, HISTORY_FILE);
            let raw = disk.0.get_mut(&SNAPSHOT_PROTECTION_BLOCK).unwrap();
            let mut p = ProtectionRecord::decode(&raw[..]).unwrap();
            p.writes_open = true;
            p.reopen_proof_digest = [1; 32];
            p.encode(raw).unwrap();
            assert_eq!(verify(&mut disk, &mut work), Err(Error::Conflict));
        }
    }

    struct PowerDisk {
        durable: Disk,
        pending: BTreeMap<u32, Box<[u8; BLOCK]>>,
        flushes: usize,
        cut_at: usize,
        cut_after_flush: bool,
    }

    impl EpochBlockIo for PowerDisk {
        fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            if let Some(bytes) = self.pending.get(&block) {
                *out = **bytes;
                Ok(())
            } else {
                self.durable.read(block, out)
            }
        }

        fn write(&mut self, block: u32, bytes: &[u8; BLOCK]) -> Result<(), Error> {
            self.pending.insert(block, Box::new(*bytes));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Error> {
            self.flushes += 1;
            if self.flushes == self.cut_at && !self.cut_after_flush {
                self.pending.clear();
                return Err(Error::Unknown);
            }
            self.durable.0.append(&mut self.pending);
            if self.flushes == self.cut_at {
                Err(Error::Unknown)
            } else {
                Ok(())
            }
        }
    }

    fn superblocks(disk: &mut Disk) {
        for (block, generation, lsn) in [(0, 1, 0), (1, 2, 4)] {
            let mut raw = Box::new([0; BLOCK]);
            p32(&mut raw[..], 0, 0x4359_4653);
            p16(&mut raw[..], 4, 1);
            p16(&mut raw[..], 6, 80);
            p32(&mut raw[..], 8, BLOCK as u32);
            p32(
                &mut raw[..],
                12,
                super::super::file_media_v0199::BLOCK_COUNT,
            );
            raw[16..32].copy_from_slice(&CHECKPOINT.fs_uuid);
            p64(&mut raw[..], 32, generation);
            p64(&mut raw[..], 40, lsn);
            p64(&mut raw[..], 48, generation);
            p32(&mut raw[..], 56, BITMAP_START);
            p32(&mut raw[..], 60, INODE_START);
            p32(&mut raw[..], 64, DATA_START);
            p32(&mut raw[..], 68, INODES as u32);
            seal(&mut raw[..], 76);
            disk.0.insert(block, raw);
        }
    }

    #[test]
    fn freeze_set_replays_only_the_verified_durable_prefix() {
        use crate::{
            control_plane::{Identity, role_manifest_v0199::Role},
            security::{
                file_media_unified_v1::{
                    SNAP_CAP_PROTECTION, SNAP_OP_FREEZE_SET, SnapshotEnrollment,
                    request_store::{RequestState, RequestStoreHeader, Watermark},
                },
                recovery_v1::{
                    RecoveryWorkspace,
                    resident::{Journal, Record, snapshot::ProtectionReplay},
                },
                snapshot_protection_tx_v1::freeze_set,
                snapshot_service_v4::{
                    CallBinding, FileReqKey, RECOVERY_SLOT, SnapshotGrant, SnapshotRequest,
                    encode_request,
                },
            },
        };
        fn inspect_protection<'a, I: EpochBlockIo>(
            disk: &'a mut I,
            work: &'a mut RecoveryWorkspace,
            sb: SuperblockV1,
        ) -> (Journal<'a, I>, ProtectionReplay) {
            let mut replay = ProtectionReplay::default();
            let mut tx = None;
            let mut index = 0;
            let journal = Journal::inspect(disk, work, sb, None, |record| {
                match record {
                    Record::Begin(plan) => {
                        index = 0;
                        tx = Some(plan);
                    }
                    Record::Image { home, contents } => {
                        replay.image(tx.ok_or(Error::Conflict)?, index, home, contents, 1)?;
                        index += 1;
                    }
                    Record::End { committed } => replay.finish(committed, false)?,
                }
                Ok(())
            })
            .unwrap();
            (journal, replay)
        }

        fn mount(
            disk: &mut impl EpochBlockIo,
            checkpoint: SuperblockV1,
            baseline: &[SystemObject; 4],
            snapshot: &[UnifiedSystemObject; 4],
        ) -> MountEvidence {
            validate_unified_resident(
                disk,
                checkpoint,
                baseline,
                snapshot,
                &principals(),
                &mut Workspace::new(),
                |_, _, _| Ok(()),
            )
            .unwrap()
        }
        let key = FileReqKey {
            fs_uuid: CHECKPOINT.fs_uuid,
            client_slot: RECOVERY_SLOT,
            client_generation: 1,
            request_seq: 1,
        };
        let mut body = [0; 16];
        p64(&mut body, 0, 1);
        p32(&mut body, 8, 1);
        let mut wire = [0; 128];
        let len = encode_request(
            SNAP_OP_FREEZE_SET,
            key.request_seq,
            Some(key),
            0,
            &body,
            9,
            &mut wire,
        )
        .unwrap();
        let request = SnapshotRequest::decode(&wire[..len], 9).unwrap();

        for (cut_at, cut_after_flush) in
            std::iter::once((0, false)).chain((1..=4).flat_map(|at| [(at, false), (at, true)]))
        {
            let (mut disk, baseline, snapshot) = unified_fixture();
            add_snapshot(&mut disk, 0, false, HISTORY_FILE);
            superblocks(&mut disk);
            let mut watermarks = [Watermark::EMPTY; 16];
            watermarks[RECOVERY_SLOT as usize].client_generation = 1;
            RequestStoreHeader {
                fs_uuid: key.fs_uuid,
                generation: 1,
                watermarks,
            }
            .encode(disk.0.get_mut(&SNAPSHOT_REQUEST_START).unwrap())
            .unwrap();
            let mut mounted = mount(&mut disk, CHECKPOINT, &baseline, &snapshot);
            let original = mounted.snapshot.unwrap();
            let binding = CallBinding {
                holder: Identity {
                    id: u64::from(Role::Supervisor.id()),
                    generation: 1,
                },
                boot_epoch: mounted.boot.boot_epoch,
                service_generation: 1,
                endpoint: 1,
                selector: 9,
                fs_uuid: key.fs_uuid,
            };
            let grant = SnapshotGrant {
                binding,
                enrollment: SnapshotEnrollment::RecoverySupervisor,
                capability_word: SNAP_CAP_PROTECTION,
                principal: Some((RECOVERY_SLOT, key.client_generation)),
                history_prefix_sha256: None,
            };
            let mut disk = PowerDisk {
                durable: disk,
                pending: BTreeMap::new(),
                flushes: 0,
                cut_at,
                cut_after_flush,
            };
            let mut work = RecoveryWorkspace::new();
            let (journal, _) = inspect_protection(&mut disk, &mut work, CHECKPOINT);
            let mut writer = journal.into_writer().unwrap();
            let mut pages = [[0; BLOCK]; 2];
            let mut checked = 0;
            if cut_at == 0 {
                let stale = CallBinding {
                    boot_epoch: binding.boot_epoch + 1,
                    ..binding
                };
                assert_eq!(
                    freeze_set(
                        &mut writer,
                        &mut mounted,
                        stale,
                        SnapshotGrant {
                            binding: stale,
                            ..grant
                        },
                        &request,
                        &mut pages,
                        |_| panic!("stale boot must fail before reservation"),
                    ),
                    Err(Error::Stale),
                );
                let busy = freeze_set(
                    &mut writer,
                    &mut mounted,
                    binding,
                    grant,
                    &request,
                    &mut pages,
                    |_| {
                        checked += 1;
                        if checked == 2 {
                            Err(Error::Busy)
                        } else {
                            Ok(())
                        }
                    },
                );
                assert_eq!(busy, Err(Error::Busy));
                assert_eq!(writer.evidence().unwrap().transactions, 0);
            }
            let result = freeze_set(
                &mut writer,
                &mut mounted,
                binding,
                grant,
                &request,
                &mut pages,
                |_| Ok(()),
            );
            if cut_at == 0 {
                let receipt = result.unwrap();
                assert_eq!(
                    (receipt.state, receipt.commit_lsn),
                    (RequestState::Done, 12)
                );
                assert_eq!(
                    freeze_set(
                        &mut writer,
                        &mut mounted,
                        binding,
                        grant,
                        &request,
                        &mut pages,
                        |_| panic!("retry must keep exact terminal")
                    ),
                    Ok(receipt),
                );
                assert_eq!(writer.evidence().unwrap().transactions, 2);
            } else {
                assert_eq!(result, Err(Error::Unknown));
            }
            drop(writer);
            assert!(disk.pending.is_empty());
            disk.cut_at = 0;

            let (admitted, committed) = match (cut_at, cut_after_flush) {
                (0, _) | (4, true) => (true, true),
                (1, _) | (2, false) => (false, false),
                _ => (true, false),
            };
            let (mut journal, replay) = inspect_protection(&mut disk, &mut work, CHECKPOINT);
            let checkpoint = SuperblockV1 {
                checkpoint_lsn: journal.evidence().last_commit_lsn,
                ..CHECKPOINT
            };
            let visible = mount(&mut journal.view(), checkpoint, &baseline, &snapshot);
            let snapshots = visible.snapshot.unwrap();
            replay
                .verify(
                    &mut journal.raw_view(),
                    CHECKPOINT,
                    Some(&snapshots),
                    &mut pages[0],
                )
                .unwrap();
            assert_eq!(
                replay.committed_operation(),
                committed.then_some((SNAP_OP_FREEZE_SET, 12))
            );
            assert_eq!(
                snapshots.requests.nonterminal,
                usize::from(admitted && !committed)
            );
            assert_eq!(snapshots.catalog_sha256, original.catalog_sha256);
            assert_eq!(
                snapshots.historical_only_blocks,
                original.historical_only_blocks
            );
            assert!(!visible.writes_open());
            let protection = snapshots.protection.unwrap();
            assert_eq!(protection.cleanup_frozen, committed);
            assert_eq!(
                protection.protection_generation,
                if committed { 2 } else { 1 }
            );
            if admitted && !committed {
                let next = journal
                    .checkpoint(|io, _| {
                        assert_eq!(mount(io, checkpoint, &baseline, &snapshot), visible);
                        Ok(())
                    })
                    .unwrap();
                let mut recovered = mount(&mut disk.durable, next, &baseline, &snapshot);
                let header = disk.durable.0[&SNAPSHOT_REQUEST_START].clone();
                let resume_cut = match (cut_at, cut_after_flush) {
                    (2, true) => 0,
                    (3, false) => 1,
                    (3, true) => 3,
                    (4, false) => 4,
                    _ => unreachable!(),
                };
                disk.flushes = 0;
                disk.cut_at = resume_cut;
                disk.cut_after_flush = true;
                let (opened, _) = inspect_protection(&mut disk, &mut work, next);
                let mut writer = opened.into_writer().unwrap();
                let settled = freeze_set(
                    &mut writer,
                    &mut recovered,
                    binding,
                    grant,
                    &request,
                    &mut pages,
                    |plan| {
                        if plan.begin_lsn == next.checkpoint_lsn + 1 {
                            assert_eq!(plan.log_blocks, 4);
                        }
                        Ok(())
                    },
                );
                if resume_cut == 0 {
                    let receipt = settled.unwrap();
                    assert_eq!(receipt.state, RequestState::Done);
                    assert_eq!(receipt.commit_lsn, next.checkpoint_lsn + 7);
                    assert_eq!(receipt.key, key);
                } else {
                    assert_eq!(settled, Err(Error::Unknown));
                }
                assert_eq!(
                    recovered.snapshot.unwrap().requests.generation,
                    snapshots.requests.generation
                );
                drop(writer);
                assert_eq!(disk.durable.0[&SNAPSHOT_REQUEST_START], header);
                let (mut fresh, replay) = inspect_protection(&mut disk, &mut work, next);
                let effective = SuperblockV1 {
                    checkpoint_lsn: fresh.evidence().last_commit_lsn,
                    ..next
                };
                let mounted = mount(&mut fresh.view(), effective, &baseline, &snapshot);
                replay
                    .verify(
                        &mut fresh.raw_view(),
                        next,
                        mounted.snapshot.as_ref(),
                        &mut pages[0],
                    )
                    .unwrap();
                let finished = matches!(resume_cut, 0 | 4);
                assert_eq!(
                    replay.committed_operation(),
                    finished.then_some((SNAP_OP_FREEZE_SET, next.checkpoint_lsn + 7)),
                );
                let current = mounted.snapshot.unwrap();
                assert_eq!(current.requests.nonterminal, usize::from(!finished));
                assert_eq!(current.catalog_sha256, snapshots.catalog_sha256);
                assert_eq!(current.protection.unwrap().cleanup_frozen, finished);
                assert!(!mounted.writes_open());
            }
        }
    }

    #[test]
    fn deleting_snapshot_gc_hands_off_only_checkpointed_exact_bitmap() {
        use crate::{
            control_plane::Identity,
            security::{
                file_media_unified_v1::{
                    SNAP_CAP_DELETE_EXPIRED, SNAP_OP_DELETE_EXPIRED, SNAPSHOT_STRIDE,
                    SnapshotEnrollment,
                    catalog_candidate::{
                        CatalogContext, CatalogEntry,
                        lifecycle::{
                            CaptureWorkspace, ExpectedState, GcVolume, GcWorkspace,
                            SnapshotMutationCall, admit_expiration, mark_expired,
                            retire_deleted_snapshot,
                        },
                    },
                    request_store::{RequestState, RequestStoreHeader, Watermark},
                    slot_candidate::SlotDescriptor,
                },
                recovery_v1::{
                    RecoveryWorkspace, RedoWriter, recover_checkpoint_with_evidence, scan,
                },
                snapshot_service_v4::{
                    CallBinding, FileReqKey, SnapshotGrant, SnapshotKey, SnapshotRequest,
                    encode_request,
                },
            },
        };
        const SLOT: u32 = 6;
        let p = principals();
        let cuts = (0..=7)
            .map(|gc_cut| (gc_cut, 0))
            .chain((1..=3).map(|delete_cut| (0, delete_cut)));
        for (cut_at, delete_cut) in cuts {
            let (mut disk, baseline, snapshot) = unified_fixture();
            // This version shares its regular file block with the live root.
            // Only the independently owned history directory block is freed.
            let missing_receipt = cut_at == 6;
            add_snapshot(&mut disk, SLOT, missing_receipt, DATA_START);
            disk.set_allocated(HISTORY_FILE, false);
            superblocks(&mut disk);
            let home = SNAPSHOT_SLOT_START + SLOT * SNAPSHOT_STRIDE;
            let target = SlotDescriptor::decode(home, &disk.0[&home])
                .unwrap()
                .identity;
            let mut mount = Workspace::new();
            let mut redo = RecoveryWorkspace::new();
            let mut disk = PowerDisk {
                durable: disk,
                pending: BTreeMap::new(),
                flushes: 0,
                cut_at: 0,
                cut_after_flush: false,
            };
            let (checkpoint, deletion_lsn) = if missing_receipt {
                (CHECKPOINT, CHECKPOINT.checkpoint_lsn)
            } else {
                let mut verify = |io: &mut PowerDisk, sb| {
                    validate_unified_resident(
                        io,
                        sb,
                        &baseline,
                        &snapshot,
                        &p,
                        &mut mount,
                        |_, _, _| Ok(()),
                    )
                };
                let key = FileReqKey {
                    fs_uuid: target.fs_uuid,
                    client_slot: 14,
                    client_generation: 1,
                    request_seq: 1,
                };
                let snapshot_key = SnapshotKey {
                    fs_uuid: target.fs_uuid,
                    snapshot_id: target.snapshot_id,
                    slot: target.slot,
                    slot_generation: target.slot_generation,
                }
                .encode()
                .unwrap();
                let mut frame = [0; 128];
                let used = encode_request(
                    SNAP_OP_DELETE_EXPIRED,
                    1,
                    Some(key),
                    0,
                    &snapshot_key,
                    9,
                    &mut frame,
                )
                .unwrap();
                let request = SnapshotRequest::decode(&frame[..used], 9).unwrap();
                let mut watermarks = [Watermark::EMPTY; 16];
                watermarks[14] = Watermark {
                    client_generation: 1,
                    highest_accepted_seq: 0,
                };
                RequestStoreHeader {
                    fs_uuid: target.fs_uuid,
                    generation: 1,
                    watermarks,
                }
                .encode(disk.durable.0.get_mut(&SNAPSHOT_REQUEST_START).unwrap())
                .unwrap();
                let mounted = verify(&mut disk, CHECKPOINT).unwrap();
                let staged = mounted.snapshot.unwrap();
                let protection = staged.protection.unwrap();
                let binding = CallBinding {
                    holder: Identity {
                        id: 14,
                        generation: 1,
                    },
                    boot_epoch: mounted.boot.boot_epoch,
                    service_generation: 1,
                    endpoint: 1,
                    selector: 9,
                    fs_uuid: target.fs_uuid,
                };
                let call = SnapshotMutationCall {
                    mount: &mounted,
                    binding,
                    grant: SnapshotGrant {
                        binding,
                        enrollment: SnapshotEnrollment::InternalMaintenance,
                        capability_word: SNAP_CAP_DELETE_EXPIRED,
                        principal: Some((key.client_slot, key.client_generation)),
                        history_prefix_sha256: None,
                    },
                    request: &request,
                };
                let mut writer = RedoWriter::open(&mut disk, &mut redo, CHECKPOINT).unwrap();
                let mut work = CaptureWorkspace::new();
                let admitted = admit_expiration(&mut writer, call, &mut work, |_| Ok(())).unwrap();
                assert_eq!(admitted.record.state, RequestState::Pending);
                let retry = admit_expiration(&mut writer, call, &mut work, |_| {
                    panic!("DELETE admission repeated")
                })
                .unwrap();
                assert_eq!(retry.record, admitted.record);
                assert!(retry.reserved.is_none());
                let expected = ExpectedState {
                    catalog: CatalogContext {
                        fs_uuid: target.fs_uuid,
                        catalog_generation: staged.catalog.unwrap().generation,
                        slot_store_generation: 1,
                        live_view_epoch: protection.live_view_epoch,
                        committed_lsn: admitted.reserved.unwrap().transaction().commit_lsn,
                        online_age_ns: protection.online_age_ns,
                    },
                    catalog_sha256: staged.catalog_sha256,
                    protection_sha256: staged.protection_sha256,
                };
                let planned = writer.prepare(2).unwrap();
                if delete_cut > 0 {
                    drop(writer);
                    disk.flushes = 0;
                    disk.cut_at = delete_cut.min(2);
                    disk.cut_after_flush = delete_cut == 3;
                    writer = RedoWriter::open(&mut disk, &mut redo, CHECKPOINT).unwrap();
                }
                let done = mark_expired(&mut writer, expected, call, &mut work, |plan, seen| {
                    assert_eq!(seen, target);
                    assert_eq!(*plan, planned);
                    Ok(())
                });
                if delete_cut > 0 {
                    assert!(matches!(done, Err(Error::Unknown)));
                    drop(writer);
                    assert!(disk.pending.is_empty());
                    disk.cut_at = 0;
                    let mut reopened = RecoveryWorkspace::new();
                    let evidence = scan(&mut disk, &mut reopened).unwrap();
                    let committed = delete_cut == 3;
                    let lsn = if committed {
                        planned.commit_lsn
                    } else {
                        expected.catalog.committed_lsn
                    };
                    assert_eq!(evidence.last_commit_lsn, lsn);
                    recover_checkpoint_with_evidence(&mut disk, &mut reopened, |io, old| {
                        let effective = SuperblockV1 {
                            checkpoint_lsn: lsn,
                            ..old
                        };
                        let staged = verify(io, effective)?.snapshot.unwrap();
                        assert_eq!(staged.has_committed_deletion(SLOT as usize), committed);
                        assert_eq!(staged.requests.nonterminal, usize::from(!committed));
                        assert_eq!(staged.historical_only_blocks, 1);
                        let entry = staged.catalog.unwrap().entries[SLOT as usize];
                        if committed {
                            assert!(matches!(
                                entry,
                                CatalogEntry::Deleting { binding, root_drop_commit_lsn }
                                    if binding.identity == target && root_drop_commit_lsn == lsn
                            ));
                        } else {
                            assert!(matches!(entry, CatalogEntry::Active(binding) if binding.identity == target));
                        }
                        Ok(())
                    })
                    .unwrap();
                    continue;
                }
                let done = done.unwrap().transaction();
                let retry = admit_expiration(&mut writer, call, &mut work, |_| {
                    panic!("terminal DELETE repeated")
                })
                .unwrap();
                assert_eq!(retry.record.state, RequestState::Done);
                assert_eq!(retry.record.commit_lsn, done.commit_lsn);
                assert_eq!(retry.record.txid, done.txid);
                assert_eq!(retry.record.request_digest, admitted.record.request_digest);
                assert!(retry.reserved.is_none());
                let (_, checkpoint) = writer
                    .checkpoint_verified(|io, old| {
                        let effective = SuperblockV1 {
                            checkpoint_lsn: done.commit_lsn,
                            ..old
                        };
                        let staged = verify(io, effective)?.snapshot.unwrap();
                        assert!(staged.has_committed_deletion(SLOT as usize));
                        assert_eq!(staged.historical_only_blocks, 1);
                        Ok(())
                    })
                    .unwrap();
                (checkpoint, done.commit_lsn)
            };
            disk.flushes = 0;
            disk.cut_at = cut_at;
            let mut gc = GcWorkspace::new();
            let writer = RedoWriter::open(&mut disk, &mut redo, checkpoint).unwrap();
            let result = retire_deleted_snapshot(
                writer,
                GcVolume {
                    baseline: &baseline,
                    snapshot: &snapshot,
                    principals: &p,
                },
                target,
                &mut mount,
                &mut gc,
                |_, _, _| Ok(()),
                |seen, lsn| {
                    assert!(!missing_receipt, "no prior DELETE receipt");
                    assert_eq!(seen, target);
                    assert_eq!(lsn, deletion_lsn);
                    Ok(())
                },
                |_| Ok(()),
            );
            if missing_receipt {
                assert!(matches!(result, Err(Error::Conflict)));
                assert_eq!(disk.flushes, 0);
                continue;
            }
            if matches!(cut_at, 0 | 5 | 7) {
                let proof = result.unwrap();
                assert_eq!(proof.released(), 1);
                if cut_at == 5 {
                    disk.durable.set_allocated(HISTORY_ROOT, true);
                    assert_eq!(
                        proof.handoff(&mut disk, &mut gc, |_, _| panic!("changed bitmap")),
                        Err(Error::Conflict)
                    );
                    continue;
                }
                if cut_at == 7 {
                    let raw = disk.durable.0.get_mut(&SNAPSHOT_PROTECTION_BLOCK).unwrap();
                    let mut changed = ProtectionRecord::decode(&raw[..]).unwrap();
                    changed.online_age_ns += 1;
                    changed.encode(raw).unwrap();
                    assert_eq!(
                        proof.handoff(&mut disk, &mut gc, |_, _| panic!("changed protection root")),
                        Err(Error::Conflict)
                    );
                    continue;
                }
                proof
                    .handoff(&mut disk, &mut gc, |published, bits| {
                        let has =
                            |block: u32| bits[0][block as usize / 8] & (1 << (block % 8)) != 0;
                        assert_eq!(published.generation, checkpoint.generation + 1);
                        assert!(has(DATA_START));
                        assert!(has(ROOT));
                        assert!(has(SNAPSHOT_PROTECTION_BLOCK));
                        assert!(!has(HISTORY_ROOT));
                        Ok(())
                    })
                    .unwrap();
                continue;
            }
            assert!(matches!(result, Err(Error::Unknown)), "cut {cut_at}");
            // Cold reopen discards volatile writes, the old owner workspace,
            // and all allocator state. A prior incomplete log cannot free.
            let mut reread = RecoveryWorkspace::new();
            let e = scan(&mut disk, &mut reread).unwrap();
            assert_eq!(e.superblock, checkpoint);
            let mut verify = |disk: &mut PowerDisk, effective: SuperblockV1| {
                validate_unified_resident(
                    disk,
                    effective,
                    &baseline,
                    &snapshot,
                    &p,
                    &mut mount,
                    |_, _, _| Ok(()),
                )
            };
            if cut_at <= 2 {
                let entry = verify(&mut disk, checkpoint)
                    .unwrap()
                    .snapshot
                    .unwrap()
                    .catalog
                    .unwrap()
                    .entries[SLOT as usize];
                assert!(matches!(entry, CatalogEntry::Deleting { .. }));
                assert_eq!(e.last_commit_lsn, deletion_lsn);
                continue;
            }
            recover_checkpoint_with_evidence(&mut disk, &mut reread, |disk, old| {
                let effective = SuperblockV1 {
                    checkpoint_lsn: e.last_commit_lsn,
                    ..old
                };
                let snap = verify(disk, effective)?.snapshot.unwrap();
                assert!(matches!(
                    snap.catalog.unwrap().entries[SLOT as usize],
                    CatalogEntry::Free { slot_generation: 1 }
                ));
                assert_eq!(snap.historical_only_blocks, 0);
                Ok(())
            })
            .unwrap();
        }
    }

    #[test]
    fn restored_write_gate_requires_independent_current_durable_open() {
        use crate::{
            control_plane::Identity,
            security::{
                file_media_unified_v1::{
                    SNAP_CAP_PROTECTION, SNAP_OP_OPEN_WRITES, SNAP_OP_RESTORE, SnapshotEnrollment,
                    catalog_candidate::{
                        CatalogContext,
                        lifecycle::{
                            CaptureWorkspace, ExpectedState, SnapshotMutationCall,
                            admit_open_writes, commit_open_writes,
                        },
                    },
                    protection_candidate::RestorePhase,
                    request_store::{
                        RequestRecord, RequestState, RequestStoreHeader, Watermark, record_location,
                    },
                    slot_candidate::SlotDescriptor,
                },
                recovery_v1::{
                    RecoveryWorkspace, RedoWriter, recover_checkpoint_with_evidence, scan,
                },
                snapshot_restore_gate::{
                    Commit, Phase, Prepared, Recovered, RestoreGate, RestoreKey, SnapshotKey, View,
                },
                snapshot_service_v4::{
                    CallBinding, FileReqKey, SnapshotGrant, SnapshotKey as WireKey,
                    SnapshotRequest, encode_request,
                },
            },
        };
        for cut_at in 0..=3 {
            let (mut disk, baseline, snapshot) = unified_fixture();
            add_snapshot(&mut disk, 0, false, DATA_START);
            add_snapshot(&mut disk, 3, false, DATA_START);
            disk.set_allocated(HISTORY_FILE, false);
            disk.set_allocated(ROOT, false);
            inode(disk.inode_slot(0), 2, 128, HISTORY_ROOT, 1);
            superblocks(&mut disk);
            let descriptor =
                SlotDescriptor::decode(SNAPSHOT_SLOT_START, &disk.0[&SNAPSHOT_SLOT_START]).unwrap();
            let key = FileReqKey {
                fs_uuid: CHECKPOINT.fs_uuid,
                client_slot: 15,
                client_generation: 1,
                request_seq: 1,
            };
            let open_key = FileReqKey {
                request_seq: 2,
                ..key
            };
            let source = WireKey {
                fs_uuid: key.fs_uuid,
                snapshot_id: 1,
                slot: 0,
                slot_generation: 1,
            };
            let decode = |op, key: FileReqKey, epoch, body: &[u8]| {
                let mut raw = [0; 256];
                let len = encode_request(op, key.request_seq, Some(key), epoch, body, 9, &mut raw)
                    .unwrap();
                RequestRecord::pending(&SnapshotRequest::decode(&raw[..len], 9).unwrap()).unwrap()
            };
            let mut body = [0; 48];
            body[..40].copy_from_slice(&source.encode().unwrap());
            p32(&mut body, 40, 2);
            let mut restored = decode(SNAP_OP_RESTORE, key, 1, &body);
            restored.state = RequestState::Done;
            restored.new_live_view_epoch = 2;
            restored.log_epoch = 1;
            restored.txid = 2;
            restored.commit_lsn = 4;
            let mut result = [0; 96];
            result[..40].copy_from_slice(&source.encode().unwrap());
            p64(&mut result, 40, 1);
            p64(&mut result, 48, 2);
            result[56..72].copy_from_slice(&key.fs_uuid);
            p64(&mut result, 72, restored.log_epoch);
            p64(&mut result, 80, restored.txid);
            p32(&mut result, 88, 1);
            restored.replace_payload(&result).unwrap();
            restored.seal_result().unwrap();
            body.fill(0);
            p64(&mut body, 0, 1);
            body[8..44].copy_from_slice(&key.encode().unwrap());
            let mut open_raw = [0; 256];
            let open_len = encode_request(
                SNAP_OP_OPEN_WRITES,
                open_key.request_seq,
                Some(open_key),
                2,
                &body,
                9,
                &mut open_raw,
            )
            .unwrap();
            let open = SnapshotRequest::decode(&open_raw[..open_len], 9).unwrap();
            let mut watermark = [Watermark::EMPTY; 16];
            watermark[15] = Watermark {
                client_generation: 1,
                highest_accepted_seq: 1,
            };
            RequestStoreHeader {
                fs_uuid: key.fs_uuid,
                generation: 2,
                watermarks: watermark,
            }
            .encode(disk.0.get_mut(&SNAPSHOT_REQUEST_START).unwrap())
            .unwrap();
            let mut page = Box::new([0; BLOCK]);
            let (home, range) = record_location(56).unwrap();
            restored
                .encode((&mut page[range]).try_into().unwrap())
                .unwrap();
            disk.0.insert(home, page);
            let raw = disk.0.get_mut(&SNAPSHOT_PROTECTION_BLOCK).unwrap();
            let mut p = ProtectionRecord::decode(&raw[..]).unwrap();
            p.live_view_epoch = 2;
            p.restore_phase = RestorePhase::RestoredFrozen;
            p.cleanup_frozen = true;
            p.restore_obligation_digest = restored.result_digest;
            p.encode(raw).unwrap();
            let mut expected = ExpectedState {
                catalog: CatalogContext {
                    fs_uuid: key.fs_uuid,
                    catalog_generation: 2,
                    slot_store_generation: 1,
                    live_view_epoch: 2,
                    committed_lsn: 4,
                    online_age_ns: 20,
                },
                catalog_sha256: Sha256::digest(&*disk.0[&SNAPSHOT_CATALOG_BLOCK]).into(),
                protection_sha256: Sha256::digest(&*disk.0[&SNAPSHOT_PROTECTION_BLOCK]).into(),
            };
            let recovery = Identity {
                id: 12,
                generation: 1,
            };
            let supervisor = Identity {
                id: 11,
                generation: 1,
            };
            let view = View {
                fs_uuid: key.fs_uuid,
                live_epoch: 2,
                protection_generation: 1,
                root_hash: descriptor.inode_image_sha256,
                retention_watermark: 20,
            };
            let prior = View {
                live_epoch: 1,
                root_hash: [1; 32],
                ..view
            };
            let restore_key = RestoreKey {
                principal: recovery,
                request_seq: key.request_seq,
            };
            let index = &*disk.0[&(RECEIPTS + 6)];
            let security = &*disk.0[&STATE_HOME];
            let prepared = Prepared {
                key: restore_key,
                snapshot: SnapshotKey {
                    fs_uuid: key.fs_uuid,
                    snapshot_id: 1,
                    slot: 0,
                    generation: 1,
                    root_hash: view.root_hash,
                },
                prior,
                next_live_epoch: 2,
                system_index_hash: Sha256::digest(index).into(),
                security_hash: Sha256::digest(security).into(),
                request_hash: restored.request_digest,
            };
            let commit = Commit {
                key: restore_key,
                txid: restored.txid,
                log_epoch: restored.log_epoch,
                commit_lsn: restored.commit_lsn,
                view,
                request_hash: restored.request_digest,
            };
            let mut gate = RestoreGate::recover_frozen(
                view,
                recovery,
                supervisor,
                Recovered::RestoredFrozen(prepared, commit),
                index,
                security,
                |_, _| Ok(()),
            )
            .unwrap();
            let mut other_gate = RestoreGate::recover_frozen(
                view,
                recovery,
                supervisor,
                Recovered::RestoredFrozen(
                    prepared,
                    Commit {
                        txid: commit.txid + 1,
                        ..commit
                    },
                ),
                index,
                security,
                |_, _| Ok(()),
            )
            .unwrap();
            other_gate
                .reopen_next_protection(supervisor, view, |_, _| Ok(()))
                .unwrap();
            let mut disk = PowerDisk {
                durable: disk,
                pending: BTreeMap::new(),
                flushes: 0,
                cut_at: 0,
                cut_after_flush: false,
            };
            let mut redo = RecoveryWorkspace::new();
            let mut work = CaptureWorkspace::new();
            let (mount, binding, grant);
            {
                let mut writer = RedoWriter::open(&mut disk, &mut redo, CHECKPOINT).unwrap();
                mount = validate_unified_resident(
                    &mut writer.committed_view(),
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &principals(),
                    &mut Workspace::new(),
                    |_, _, _| Ok(()),
                )
                .unwrap();
                assert_eq!(mount.snapshot.unwrap().completed_restore(), Some(&restored));
                binding = CallBinding {
                    holder: supervisor,
                    boot_epoch: mount.boot.boot_epoch,
                    service_generation: 1,
                    endpoint: 1,
                    selector: 9,
                    fs_uuid: key.fs_uuid,
                };
                grant = SnapshotGrant {
                    binding,
                    enrollment: SnapshotEnrollment::RecoverySupervisor,
                    capability_word: SNAP_CAP_PROTECTION,
                    principal: Some((open_key.client_slot, open_key.client_generation)),
                    history_prefix_sha256: None,
                };
                let call = SnapshotMutationCall {
                    mount: &mount,
                    binding,
                    grant,
                    request: &open,
                };
                let wrong = CallBinding {
                    holder: recovery,
                    ..binding
                };
                assert!(matches!(
                    admit_open_writes(
                        &mut writer,
                        &gate,
                        SnapshotMutationCall {
                            binding: wrong,
                            grant: SnapshotGrant {
                                binding: wrong,
                                ..grant
                            },
                            ..call
                        },
                        &mut work,
                        |_| panic!("independent protection actor required"),
                    ),
                    Err(Error::Unauthorized)
                ));
                let stale = CallBinding {
                    boot_epoch: binding.boot_epoch + 1,
                    ..binding
                };
                assert!(matches!(
                    admit_open_writes(
                        &mut writer,
                        &gate,
                        SnapshotMutationCall {
                            binding: stale,
                            grant: SnapshotGrant {
                                binding: stale,
                                ..grant
                            },
                            ..call
                        },
                        &mut work,
                        |_| panic!("stale boot"),
                    ),
                    Err(Error::Stale)
                ));
                let admitted =
                    admit_open_writes(&mut writer, &gate, call, &mut work, |_| Ok(())).unwrap();
                assert_eq!(admitted.record.state, RequestState::Pending);
                expected.catalog.committed_lsn =
                    admitted.reserved.unwrap().transaction().commit_lsn;
                let retry = admit_open_writes(&mut writer, &gate, call, &mut work, |_| {
                    panic!("same-key retry executed twice")
                })
                .unwrap();
                assert_eq!(retry.record, admitted.record);
                assert!(retry.reserved.is_none());
                assert!(!gate.may_write(2, 1));
            }
            disk.flushes = 0;
            disk.cut_at = cut_at.min(2);
            disk.cut_after_flush = cut_at == 3;
            let mut writer = RedoWriter::open(&mut disk, &mut redo, CHECKPOINT).unwrap();
            let call = SnapshotMutationCall {
                mount: &mount,
                binding,
                grant,
                request: &open,
            };
            for (wrong, error) in [
                (
                    CallBinding {
                        holder: recovery,
                        ..binding
                    },
                    Error::Unauthorized,
                ),
                (
                    CallBinding {
                        boot_epoch: binding.boot_epoch + 1,
                        ..binding
                    },
                    Error::Stale,
                ),
            ] {
                assert_eq!(
                    commit_open_writes(
                        &mut writer,
                        expected,
                        &mut gate,
                        SnapshotMutationCall {
                            binding: wrong,
                            grant: SnapshotGrant {
                                binding: wrong,
                                ..grant
                            },
                            ..call
                        },
                        &mut work,
                        |_| panic!("unauthorized OPEN_WRITES effect"),
                    )
                    .err(),
                    Some(error),
                );
            }
            assert_eq!(gate.phase(), Phase::RestoredFrozen);
            let opened = commit_open_writes(
                &mut writer,
                expected,
                &mut gate,
                call,
                &mut work,
                |_| Ok(()),
            );
            if cut_at == 0 {
                let tx = opened.unwrap().transaction();
                assert!(gate.may_write(2, 2));
                assert!(!gate.may_write(2, 1));
                assert!(!gate.may_write(1, 2));
                let checkpoint = SuperblockV1 {
                    checkpoint_lsn: tx.commit_lsn,
                    ..CHECKPOINT
                };
                let mut mounted = validate_unified_resident(
                    &mut writer.committed_view(),
                    checkpoint,
                    &baseline,
                    &snapshot,
                    &principals(),
                    &mut Workspace::new(),
                    |_, _, _| Ok(()),
                )
                .unwrap();
                assert!(mounted.snapshot.unwrap().has_open_proof());
                assert!(mounted.snapshot.unwrap().protection.unwrap().cleanup_frozen);
                assert!(mounted.permits_replay_of_file_writes());
                assert!(!mounted.writes_open());
                assert_eq!(
                    mounted.authorize_snapshot_writes(&other_gate, |_| panic!(
                        "different RESTORE transaction"
                    )),
                    Err(Error::Stale)
                );
                assert_eq!(
                    mounted.authorize_snapshot_writes(&gate, |_| Err(Error::Unauthorized)),
                    Err(Error::Unauthorized)
                );
                assert!(!mounted.writes_open());
                mounted
                    .authorize_snapshot_writes(&gate, |boot| {
                        assert_eq!(boot.boot_epoch, 2);
                        assert_eq!(boot.fs_uuid, CHECKPOINT.fs_uuid);
                        Ok(())
                    })
                    .unwrap();
                assert!(mounted.writes_open());
                assert!(!mounted.may_overwrite_in_place());
                assert_eq!(
                    mounted.authorize_snapshot_writes(&gate, |_| Err(Error::Stale)),
                    Err(Error::Stale)
                );
                assert!(
                    !mounted.writes_open(),
                    "failed BootEpoch recheck closes writes"
                );
                mounted
                    .authorize_snapshot_writes(&gate, |_| Ok(()))
                    .unwrap();
                assert_eq!(
                    mounted.authorize_snapshot_writes(&other_gate, |_| panic!(
                        "different RESTORE transaction"
                    )),
                    Err(Error::Stale)
                );
                assert!(!mounted.writes_open(), "stale restore gate closes writes");
            } else {
                assert!(matches!(opened, Err(Error::Unknown)));
                assert_eq!(gate.phase(), Phase::ReopeningUnknown);
                assert!(!gate.may_write(2, 1));
                assert!(!gate.may_write(2, 2));
                let raw = &disk.durable.0[&SNAPSHOT_PROTECTION_BLOCK][..];
                assert_eq!(
                    ProtectionRecord::decode(raw).unwrap().restore_phase,
                    RestorePhase::RestoredFrozen
                );
                if cut_at == 3 {
                    assert_eq!(
                        gate.reconcile_reopen(supervisor, view, |_, _| panic!("wrong generation")),
                        Err(Error::Stale)
                    );
                    let mut reread = RecoveryWorkspace::new();
                    let evidence = scan(&mut disk, &mut reread).unwrap();
                    recover_checkpoint_with_evidence(&mut disk, &mut reread, |disk, prior| {
                        let effective = SuperblockV1 {
                            checkpoint_lsn: evidence.last_commit_lsn,
                            ..prior
                        };
                        let mounted = validate_unified_resident(
                            disk,
                            effective,
                            &baseline,
                            &snapshot,
                            &principals(),
                            &mut Workspace::new(),
                            |_, _, _| Ok(()),
                        )?;
                        assert!(mounted.snapshot.unwrap().has_open_proof());
                        assert!(mounted.permits_replay_of_file_writes());
                        assert!(!mounted.writes_open());
                        gate.reconcile_reopen_next_protection(
                            supervisor,
                            view,
                            |current, commit| {
                                assert_eq!(current, view);
                                assert_eq!(commit.commit_lsn, restored.commit_lsn);
                                assert_eq!(
                                    mounted
                                        .snapshot
                                        .unwrap()
                                        .protection
                                        .unwrap()
                                        .protection_generation,
                                    2
                                );
                                Ok(())
                            },
                        )?;
                        assert!(gate.may_write(2, 2));
                        Ok(())
                    })
                    .unwrap();
                }
            }
        }
    }

    #[test]
    fn unified_mount_accounts_for_all_eight_hidden_objects() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let map = unified_map_from_baseline(&baseline, &snapshot).unwrap();
        let mut seen = 0;
        let e = validate_unified(
            &mut disk,
            CHECKPOINT,
            &baseline,
            &snapshot,
            &principals(),
            &mut Workspace::new(),
            |acl, _, hidden| {
                seen += 1;
                assert_eq!(
                    hidden,
                    map.iter()
                        .find(|s| u32::from(s.inode) == acl.inode_id)
                        .map(|s| s.kind)
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, INODES);
        assert_eq!(e.system_blocks, 151);
        assert_eq!(
            e.structure,
            StructureEvidence {
                live_inodes: 10,
                data_blocks: 153,
                directory_entries: 1,
            }
        );
        assert_eq!(
            e.usage[0],
            Usage {
                inodes: 2,
                blocks: 2,
                directory_slots: 1,
            }
        );
        assert!(e.usage[1..].iter().all(|u| *u == Usage::default()));
    }

    fn signed_fixture(wire: &mut [u8; 577]) -> VerifiedOfflineConfig<'_> {
        use crate::security::offline_config_v1::{CatalogBindings, SIGNATURE_LABEL};
        use ed25519_dalek::{Signer, SigningKey};

        // A host-only signature, using the fixture's actual UUID and principals.
        p32(wire, 0, 0x4359_4f46);
        p16(wire, 4, 1);
        p16(wire, 6, 256);
        p32(wire, 8, 577);
        p32(wire, 12, 257);
        wire[16..32].copy_from_slice(&CHECKPOINT.fs_uuid);
        for at in [32, 40, 48, 56] {
            p64(wire, at, 1);
        }
        wire[64..96].fill(2);
        wire[96..128].fill(3);
        wire[128..160].fill(4);
        for (i, principal) in principals().iter().enumerate() {
            p64(wire, 256 + i * 16, principal.id);
            p64(wire, 264 + i * 16, principal.generation);
        }
        wire[512] = 42;
        let payload_hash = Sha256::digest(&wire[256..513]);
        wire[160..192].copy_from_slice(&payload_hash);
        let signer = SigningKey::from_bytes(&[0x37; 32]);
        let mut message = [0u8; SIGNATURE_LABEL.len() + 513];
        message[..SIGNATURE_LABEL.len()].copy_from_slice(SIGNATURE_LABEL);
        message[SIGNATURE_LABEL.len()..].copy_from_slice(&wire[..513]);
        wire[513..].copy_from_slice(&signer.sign(&message).to_bytes());
        let catalog = CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 1,
            rule_hash: [2; 32],
            security_hash: [3; 32],
            key_manifest_hash: [4; 32],
        };
        let mut scratch = [0u8; SIGNATURE_LABEL.len() + 513];
        VerifiedOfflineConfig::verify(
            wire,
            &signer.verifying_key().to_bytes(),
            catalog,
            &mut scratch,
            |_, _, payload| {
                if payload == [42] {
                    Ok(())
                } else {
                    Err(Error::Invalid)
                }
            },
        )
        .unwrap()
    }

    #[test]
    fn unified_mount_retains_signed_receipt_query_inputs_after_snapshot_scan() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let mut wire = [0; 577];
        let config = signed_fixture(&mut wire);
        let mut state =
            SecurityStateStoreV2::decode(disk.0.get(&STATE_HOME).unwrap().as_ref()).unwrap();
        state.offline_config_hash = config.digest();
        disk.0.insert(STATE_HOME, Box::new(state.encode().unwrap()));
        let mut expected = Sha256::new();
        for block in RECEIPTS..RECEIPTS + 7 {
            let mut raw = [0; BLOCK];
            disk.read(block, &mut raw).unwrap();
            expected.update(raw);
        }
        let expected: [u8; 32] = expected.finalize().into();

        let mut w = Workspace::new();
        let prior = validate_unified(
            &mut disk,
            CHECKPOINT,
            &baseline,
            &snapshot,
            config.principals(),
            &mut w,
            |_, _, _| Ok(()),
        )
        .unwrap();
        // The mount owner supplies the independently confirmed paired state.
        let committed = SecurityStateStoreV2 {
            state_generation: state.state_generation + 1,
            last_boot_epoch: state.last_boot_epoch + 1,
            ..state
        };
        assert_eq!(
            w.confirmed_receipt_query_digest(&prior, &committed, &config),
            Ok(expected)
        );
        assert_eq!(
            w.confirmed_receipt_query_digest(&prior, &state, &config),
            Err(Error::Conflict)
        );
        let mut checkpoints = 0;
        assert_eq!(
            w.confirmed_receipt_query_digest_metered(&prior, &committed, &config, &mut || {
                checkpoints += 1;
                if checkpoints == 4 {
                    return Err(Error::Busy);
                }
                Ok(())
            }),
            Err(Error::Busy)
        );
    }

    #[test]
    fn signed_fsync_binds_then_recovers_segmented_data_and_receipt() {
        check_signed_fsync_roundtrip(121, None);
    }

    #[test]
    fn signed_fsync_growth_preserves_adjacent_owner_and_recovers_new_extent() {
        check_signed_fsync_roundtrip(1, Some(3));
    }

    #[test]
    fn signed_fsync_growth_resumes_across_checkpoint_without_exposing_tail() {
        check_signed_fsync_roundtrip(121, Some(3));
    }

    #[test]
    fn signed_fsync_growth_checkpoints_initialized_new_extents() {
        check_signed_fsync_roundtrip(1, Some(125));
    }

    #[test]
    fn signed_fsync_first_extent_durably_grows_an_empty_file() {
        check_signed_fsync_roundtrip(0, Some(2));
    }

    #[test]
    fn signed_fsync_first_extent_keeps_only_initialized_prefix_at_checkpoint() {
        check_signed_fsync_roundtrip(0, Some(122));
    }

    #[test]
    fn signed_fsync_business_floor_allocates_first_extent_above_snapshot_reserve() {
        check_signed_fsync_roundtrip_at(0, Some(122), CANONICAL_BUSINESS_START);
    }

    #[test]
    fn signed_fsync_business_floor_allocates_disjoint_growth_above_snapshot_reserve() {
        check_signed_fsync_roundtrip_at(1, Some(3), CANONICAL_BUSINESS_START);
    }

    #[test]
    fn signed_fsync_extends_across_bitmap_boundary_and_cold_recovers() {
        let boundary = BLOCK as u32 * 8;
        check_signed_fsync_roundtrip_with_layout(
            1,
            Some(2),
            boundary - 1,
            boundary - 2,
            Some(boundary + 1),
        );
    }

    fn check_signed_fsync_roundtrip(initial_pages: usize, added_pages: Option<usize>) {
        check_signed_fsync_roundtrip_at(initial_pages, added_pages, DATA_START);
    }

    fn check_signed_fsync_roundtrip_at(
        initial_pages: usize,
        added_pages: Option<usize>,
        allocation_floor: u32,
    ) {
        check_signed_fsync_roundtrip_with_layout(
            initial_pages,
            added_pages,
            allocation_floor,
            9000,
            None,
        );
    }

    fn check_signed_fsync_roundtrip_with_layout(
        initial_pages: usize,
        added_pages: Option<usize>,
        allocation_floor: u32,
        data_start: u32,
        neighbor_home: Option<u32>,
    ) {
        use crate::security::{
            file_admission_flow_v1::FileAdmissionFlowV1,
            file_auth_context_v1::{AdmissionLedgerV1, AuthContextV1, AuthorityFacts},
            file_auth_v3::{
                AdmitRequestV3, CompleteRequestV1, FILE_SERVICE_ROLE, TerminalState, Verdict,
            },
            file_fsync_v1::{
                FsyncJob, FsyncProgress, FsyncWorkspace, commit_segment, commit_segment_with_floor,
            },
            file_media_v0199::{BLOCK_COUNT, FileReceiptV4, RECEIPT_BYTES},
            file_receipt_query_v4::ReceiptKey,
            file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION},
            recovery_v1::{
                RecoveryWorkspace, RedoTransaction, RedoWriter, recover_checkpoint_with_evidence,
                retire_checkpointed_log,
            },
        };
        use std::fs::{File, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};

        struct FileDisk(File);
        impl EpochBlockIo for FileDisk {
            fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
                self.0
                    .seek(SeekFrom::Start(u64::from(block) * BLOCK as u64))
                    .and_then(|_| self.0.read_exact(out))
                    .map_err(|_| Error::Unknown)
            }
            fn write(&mut self, block: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
                self.0
                    .seek(SeekFrom::Start(u64::from(block) * BLOCK as u64))
                    .and_then(|_| self.0.write_all(data))
                    .map_err(|_| Error::Unknown)
            }
            fn flush(&mut self) -> Result<(), Error> {
                self.0.sync_data().map_err(|_| Error::Unknown)
            }
        }
        struct RemoveImage(std::path::PathBuf);
        impl Drop for RemoveImage {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        fn superblock(sb: SuperblockV1) -> [u8; BLOCK] {
            let mut raw = [0; BLOCK];
            p32(&mut raw, 0, 0x4359_4653);
            p16(&mut raw, 4, 1);
            p16(&mut raw, 6, 80);
            p32(&mut raw, 8, BLOCK as u32);
            p32(&mut raw, 12, BLOCK_COUNT);
            raw[16..32].copy_from_slice(&sb.fs_uuid);
            p64(&mut raw, 32, sb.generation);
            p64(&mut raw, 40, sb.checkpoint_lsn);
            p64(&mut raw, 48, sb.log_epoch);
            for (offset, value) in [
                (56, BITMAP_START),
                (60, INODE_START),
                (64, DATA_START),
                (68, 256),
            ] {
                p32(&mut raw, offset, value);
            }
            seal(&mut raw, 76);
            raw
        }
        const BITS_PER_BITMAP: u32 = BLOCK as u32 * 8;
        const FSYNC: u64 = 1 << 13;
        const CAP: u64 = 9;
        const BOOT: u64 = 2;
        let growing = added_pages.is_some();
        let target_pages = initial_pages + added_pages.unwrap_or(0);
        let segmented = target_pages > 120;
        let target_size = (target_pages - 1) * BLOCK + 17;
        let initial_size = if initial_pages == 0 {
            0
        } else if growing {
            (initial_pages - 1) * BLOCK + 8
        } else {
            target_size
        };
        let adjacent = data_start + initial_pages as u32;
        let neighbor_block = neighbor_home.unwrap_or(adjacent);
        let merge_adjacent =
            initial_pages != 0 && allocation_floor == adjacent && neighbor_block != adjacent;
        // Slot 106 straddles the last two pages of the store. They must
        // survive reuse of the receipt scan buffer for the growth bitmaps.
        let receipt_slot = if merge_adjacent { 106 } else { 21 };
        let mut source = fixture();
        source.set_allocated(STATE_HOME + 1, false);
        for block in data_start..adjacent {
            source.set_allocated(block, true);
        }
        inode(
            source.inode_slot(1),
            1,
            initial_size as u64,
            data_start,
            initial_pages as u32,
        );
        if growing {
            // A second live ordinary inode owns the physical neighbor.
            // Fill its entire extent so any unintended overwrite is visible.
            source.set_allocated(neighbor_block, true);
            source.0.insert(neighbor_block, Box::new([0xa5; BLOCK]));
            inode(source.inode_slot(6), 1, BLOCK as u64, neighbor_block, 1);
            inode(source.inode_slot(0), 2, 256, ROOT, 1);
            let acl = source.acl_slot(6);
            p32(acl, 4, 1);
            p64(acl, 8, 1);
            p64(acl, 16, 2);
            p64(acl, 24, 1);
            p32(acl, 32, 1 << 8);
            p64(acl, 40, 1);
            seal(acl, 60);
            let sibling = &mut source.0.get_mut(&ROOT).unwrap()[128..256];
            p32(sibling, 0, 6);
            p16(sibling, 4, 1);
            p64(sibling, 8, 1);
            sibling[16] = b'y';
            seal(sibling, 124);
        }
        let acl = source.acl_slot(1);
        p32(acl, 32, FILE_RIGHTS);
        seal(acl, 60);
        let mut wire = [0; 577];
        let config = signed_fixture(&mut wire);
        let mut state = SecurityStateStoreV2::decode(source.0[&STATE_HOME].as_ref()).unwrap();
        state.offline_config_hash = config.digest();
        source
            .0
            .insert(STATE_HOME, Box::new(state.encode().unwrap()));
        let key = ReceiptKey {
            fs_uuid: CHECKPOINT.fs_uuid,
            issued_boot_epoch: BOOT,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
        };
        let mut index = FileStreamIndexV4::decode(source.0[&(RECEIPTS + 6)].as_ref()).unwrap();
        index.groups[0].flags = 1;
        index.groups[0].generation = 1;
        index.groups[0].boot_epoch = BOOT;
        index.streams[0].flags = 1;
        index.streams[0].generation = 1;
        index.streams[0].issued_hi = 1;
        index
            .encode_into(source.0.get_mut(&(RECEIPTS + 6)).unwrap())
            .unwrap();
        let issued = FileReceiptV4 {
            fs_uuid: key.fs_uuid,
            issued_boot_epoch: BOOT,
            group_id: 0,
            group_generation: 1,
            stream_slot: 0,
            stream_generation: 1,
            request_seq: 1,
            log_epoch: 0,
            txid: 0,
            commit_lsn: 0,
            write_seq: 0,
            status: 1,
            result: 0,
            completed_prefix: 0,
            operation_digest: [0; 32],
            output_digest: [0; 32],
            request_id: key.request_id().unwrap(),
            owner_principal_id: 1,
        }
        .encode()
        .unwrap();
        let mut first = [0; BLOCK];
        let mut second = [0; BLOCK];
        let receipt_home = RECEIPTS + (receipt_slot * RECEIPT_BYTES / BLOCK) as u32;
        let receipt_at = receipt_slot * RECEIPT_BYTES % BLOCK;
        first[receipt_at..].copy_from_slice(&issued[..BLOCK - receipt_at]);
        second[..RECEIPT_BYTES - (BLOCK - receipt_at)]
            .copy_from_slice(&issued[BLOCK - receipt_at..]);
        source.0.insert(receipt_home, Box::new(first));
        source.0.insert(receipt_home + 1, Box::new(second));
        source.0.insert(
            0,
            Box::new(superblock(SuperblockV1 {
                generation: 1,
                checkpoint_lsn: 0,
                log_epoch: 1,
                ..CHECKPOINT
            })),
        );
        source.0.insert(1, Box::new(superblock(CHECKPOINT)));

        let path = std::env::temp_dir().join(std::format!(
            "cyx-fsync-test-{}-{initial_pages}-{target_pages}-{allocation_floor}.raw",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let image = RemoveImage(path);
        file.set_len(u64::from(BLOCK_COUNT) * BLOCK as u64).unwrap();
        let mut disk = FileDisk(file);
        for (block, data) in source.0 {
            disk.write(block, &data).unwrap();
        }
        disk.flush().unwrap();
        let system = systems();
        let mut mount_workspace = Workspace::new();
        let mounted = validate_signed(
            &mut disk,
            CHECKPOINT,
            &system,
            &config,
            &mut mount_workspace,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            (mounted.receipts.occupied, mounted.receipts.unresolved),
            (1, 1)
        );

        let mut frozen = std::vec![0; target_pages * BLOCK];
        for (index, page) in frozen[..target_size].chunks_mut(BLOCK).enumerate() {
            page.fill(0x59 + index as u8);
        }
        let pages: std::vec::Vec<&[u8; BLOCK]> = frozen
            .chunks_exact(BLOCK)
            .map(|page| page.try_into().unwrap())
            .collect();
        let mut frame = [0; REQUEST_HEADER + 8];
        p32(&mut frame, 0, REQUEST_MAGIC);
        p16(&mut frame, 4, REQUEST_VERSION);
        p16(&mut frame, 6, REQUEST_HEADER as u16);
        p16(&mut frame, 8, 5);
        p32(&mut frame, 12, 8);
        p64(&mut frame, 16, key.request_id().unwrap());
        p64(&mut frame, REQUEST_HEADER, 17);
        let mut sized_frozen = std::vec::Vec::new();
        if growing {
            sized_frozen.extend_from_slice(&(target_size as u64).to_le_bytes());
            sized_frozen.extend_from_slice(&frozen);
        }
        let mut flow = FileAdmissionFlowV1::freeze(
            AuthContextV1::new(3, 1, FILE_SERVICE_ROLE, 1, BOOT).unwrap(),
            &frame,
            CAP,
            AdmitRequestV3 {
                auth_context_id: 0,
                target_id: 1,
                target_generation: 1,
                required_rights: FSYNC,
                request_seq: 1,
                prepared_version: 0,
                acl_generation: 1,
                frozen_data_digest: [0; 32],
                operation_digest: [0; 32],
            },
            0,
            if growing { &sized_frozen } else { &frozen },
        )
        .unwrap();
        let mut ledger = AdmissionLedgerV1::new(BOOT).unwrap();
        flow.admit(
            &mut ledger,
            &AuthorityFacts {
                current_generation: 1,
                verdict: Verdict::Admitted,
                deny_generation: 0,
                accepted_local_ns: 1,
            },
        )
        .unwrap();
        flow.execute(&mut ledger, flow.request().prepared_version, true)
            .unwrap();
        let mut job = FsyncJob {
            config: &config,
            mounted: &mounted,
            admission: &flow,
            ledger: &ledger,
            inode_id: 1,
            cap_selector: CAP,
            frame: &frame,
            key,
            grown_size: growing.then_some(target_size),
            pages: &pages,
        };
        let mut work = FsyncWorkspace::new();
        let mut journal = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(&mut disk, &mut journal, CHECKPOINT).unwrap();
        if allocation_floor == CANONICAL_BUSINESS_START {
            let before = writer.evidence();
            for invalid in [DATA_START - 1, BLOCK_COUNT] {
                assert_eq!(
                    commit_segment_with_floor(&mut writer, &job, &mut work, invalid, |_| {
                        panic!("invalid allocation floor reserved redo")
                    })
                    .err(),
                    Some(Error::Invalid)
                );
            }
            assert_eq!(
                commit_segment_with_floor(&mut writer, &job, &mut work, BLOCK_COUNT - 1, |_| {
                    panic!("exhausted allocation range reserved redo")
                })
                .err(),
                Some(Error::Capacity)
            );
            assert_eq!(writer.evidence(), before);
        }
        let mut committed = |writer: &mut RedoWriter<'_, FileDisk>, job: &FsyncJob<'_>, blocks| {
            let reserve = |plan: &RedoTransaction| {
                assert_eq!(plan.log_blocks, blocks);
                Ok(())
            };
            let result = if allocation_floor == DATA_START {
                commit_segment(writer, job, &mut work, reserve)
            } else {
                commit_segment_with_floor(writer, job, &mut work, allocation_floor, reserve)
            };
            let FsyncProgress::Committed { receipt, redo } = result.unwrap() else {
                panic!("expected durable segment");
            };
            assert_eq!(receipt.commit_lsn, redo.transaction().commit_lsn);
            (receipt, redo.ordered_digest())
        };
        let mut raw = [0; BLOCK];
        let mut bitmaps_before = [[0; BLOCK]; 2];
        let first_bitmap = allocation_floor / BITS_PER_BITMAP;
        let last_bitmap = added_pages.map_or(first_bitmap, |added| {
            (allocation_floor + added as u32 - 1) / BITS_PER_BITMAP
        });
        let bitmap_count = (last_bitmap - first_bitmap + 1) as usize;
        for (page, bits) in bitmaps_before[..bitmap_count].iter_mut().enumerate() {
            writer
                .read_committed(BITMAP_START + first_bitmap + page as u32, bits)
                .unwrap();
        }
        let (bound, _) = committed(&mut writer, &job, 8);
        assert_eq!((bound.status, bound.completed_prefix), (2, 0));
        writer.read_committed(INODE_START, &mut raw).unwrap();
        let initial = Inode::decode(&raw[256..512]).unwrap();
        let initial_extents = usize::from(initial_pages != 0);
        assert_eq!(initial.size, initial_size as u64);
        assert_eq!(usize::from(initial.extents), initial_extents);
        let first_candidate = if initial_pages == 0 {
            allocation_floor
        } else {
            data_start
        };
        writer.read_committed(first_candidate, &mut raw).unwrap();
        assert!(raw.iter().all(|&byte| byte == 0));
        for (page, bits) in bitmaps_before[..bitmap_count].iter().enumerate() {
            writer
                .read_committed(BITMAP_START + first_bitmap + page as u32, &mut raw)
                .unwrap();
            assert_eq!(&raw, bits);
        }
        let (mut writer, final_epoch) = if !segmented {
            (writer, CHECKPOINT.log_epoch)
        } else {
            let prefix_pages = 120usize;
            let prefix_size = prefix_pages * BLOCK;
            let prefix_growth = prefix_pages.saturating_sub(initial_pages);
            let prefix_log_blocks = if prefix_growth == 0 { 248 } else { 252 };
            let (prefix, _) = committed(&mut writer, &job, prefix_log_blocks);
            assert_eq!(
                (prefix.status, prefix.completed_prefix as usize),
                (2, prefix_size)
            );
            writer.read_committed(INODE_START, &mut raw).unwrap();
            let current = Inode::decode(&raw[256..512]).unwrap();
            assert_eq!(current.durable_write_seq, 0);
            assert_eq!(current.size, initial_size.max(prefix_size) as u64);
            assert_eq!(
                usize::from(current.extents),
                initial_extents + usize::from(prefix_growth != 0)
            );
            if prefix_growth != 0 {
                assert_eq!(
                    current.runs[initial_extents],
                    Extent {
                        logical: initial_pages as u32,
                        physical: allocation_floor,
                        count: prefix_growth as u32,
                    }
                );
                writer
                    .read_committed_at(BITMAP_START, prefix.commit_lsn, &mut raw)
                    .unwrap();
                for block in allocation_floor..allocation_floor + prefix_growth as u32 {
                    let bit = block as usize;
                    bitmaps_before[0][bit / 8] |= 1 << (bit % 8);
                    writer
                        .read_committed_at(block, prefix.commit_lsn, &mut raw)
                        .unwrap();
                    assert_eq!(
                        &raw,
                        pages[initial_pages + (block - allocation_floor) as usize]
                    );
                }
            }
            writer.read_committed(BITMAP_START, &mut raw).unwrap();
            assert_eq!(raw, bitmaps_before[0]);
            let untouched = if prefix_growth == 0 {
                data_start + prefix_pages as u32
            } else {
                allocation_floor + prefix_growth as u32
            };
            writer.read_committed(untouched, &mut raw).unwrap();
            assert!(raw.iter().all(|&byte| byte == 0));
            let (before_final, checkpoint) =
                recover_checkpoint_with_evidence(&mut disk, &mut journal, |io, sb| {
                    let state = validate_signed(
                        io,
                        sb,
                        &system,
                        &config,
                        &mut mount_workspace,
                        |_, _, _| Ok(()),
                    )?;
                    assert_eq!((state.receipts.occupied, state.receipts.unresolved), (1, 1));
                    Ok(())
                })
                .unwrap();
            assert_eq!(before_final.transactions, 2);
            assert_eq!(checkpoint.checkpoint_lsn, prefix.commit_lsn);
            assert!(retire_checkpointed_log(&mut disk, &mut journal, checkpoint).unwrap() > 0);
            (
                RedoWriter::open(&mut disk, &mut journal, checkpoint).unwrap(),
                prefix.log_epoch + 1,
            )
        };
        let final_pages = target_pages - usize::from(segmented) * 120;
        // Data + both receipt blocks, index, inode and allocated bitmap pages.
        let bitmap_homes = if growing { bitmap_count as u32 } else { 0 };
        let final_log_blocks = 2 + 2 * (final_pages as u32 + 4 + bitmap_homes);
        let (done, committed_digest) = committed(&mut writer, &job, final_log_blocks);
        assert_eq!(done.log_epoch, final_epoch);
        if growing {
            for block in allocation_floor..allocation_floor + added_pages.unwrap() as u32 {
                let page = (block / BITS_PER_BITMAP - first_bitmap) as usize;
                let bit = (block % BITS_PER_BITMAP) as usize;
                bitmaps_before[page][bit / 8] |= 1 << (bit % 8);
            }
            for (page, bits) in bitmaps_before[..bitmap_count].iter().enumerate() {
                writer
                    .read_committed_at(
                        BITMAP_START + first_bitmap + page as u32,
                        done.commit_lsn,
                        &mut raw,
                    )
                    .unwrap();
                assert_eq!(&raw, bits, "unexpected allocated blocks");
            }
            writer.read_committed(neighbor_block, &mut raw).unwrap();
            assert_eq!(raw, [0xa5; BLOCK]);
        }
        assert_eq!(
            (done.status, done.completed_prefix as usize, done.write_seq),
            (3, target_size, 17)
        );
        let mut changed = pages.clone();
        changed[0] = &[0; BLOCK];
        job.pages = &changed;
        assert_eq!(
            commit_segment(&mut writer, &job, &mut work, |_| panic!("changed snapshot")).err(),
            Some(Error::Conflict)
        );
        job.pages = &pages;
        assert!(matches!(
            commit_segment(&mut writer, &job, &mut work, |_| panic!("already committed")).unwrap(),
            FsyncProgress::AlreadyDone(receipt) if receipt == done
        ));
        ledger
            .complete(
                FILE_SERVICE_ROLE,
                false,
                &CompleteRequestV1 {
                    admission_id: flow.admission_id(),
                    terminal_state: TerminalState::Done,
                    evidence_digest: committed_digest,
                },
            )
            .unwrap();
        let terminal_job = FsyncJob {
            config: &config,
            mounted: &mounted,
            admission: &flow,
            ledger: &ledger,
            inode_id: 1,
            cap_selector: CAP,
            frame: &frame,
            key,
            grown_size: growing.then_some(target_size),
            pages: &pages,
        };
        assert_eq!(
            commit_segment(&mut writer, &terminal_job, &mut work, |_| panic!(
                "terminal admission"
            ))
            .err(),
            Some(Error::Unauthorized)
        );
        drop(disk);

        let mut disk = FileDisk(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&image.0)
                .unwrap(),
        );
        let mut reopened = RecoveryWorkspace::new();
        let (evidence, next) =
            recover_checkpoint_with_evidence(&mut disk, &mut reopened, |io, sb| {
                let mounted =
                    validate_signed(io, sb, &system, &config, &mut mount_workspace, |_, _, _| {
                        Ok(())
                    })?;
                assert_eq!(
                    (mounted.receipts.occupied, mounted.receipts.unresolved),
                    (1, 0)
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(evidence.transactions, if segmented { 1 } else { 2 });
        assert_eq!(next.checkpoint_lsn, done.commit_lsn);
        disk.read(INODE_START, &mut raw).unwrap();
        let current = Inode::decode(&raw[256..512]).unwrap();
        assert_eq!(current.durable_write_seq, 17);
        assert_eq!(current.size, target_size as u64);
        if growing {
            let neighbor = Inode::decode(&raw[6 * INODE_BYTES..7 * INODE_BYTES]).unwrap();
            assert_eq!(
                neighbor.runs[0],
                Extent {
                    logical: 0,
                    physical: neighbor_block,
                    count: 1
                }
            );
            assert_eq!(neighbor.durable_write_seq, 0);
            assert_eq!(
                usize::from(current.extents),
                initial_extents + usize::from(!merge_adjacent)
            );
            if initial_extents != 0 {
                assert_eq!(
                    current.runs[0],
                    Extent {
                        logical: 0,
                        physical: data_start,
                        count: if merge_adjacent {
                            target_pages as u32
                        } else {
                            initial_pages as u32
                        },
                    }
                );
            }
            if !merge_adjacent {
                assert_eq!(
                    current.runs[initial_extents],
                    Extent {
                        logical: initial_pages as u32,
                        physical: allocation_floor,
                        count: added_pages.unwrap() as u32,
                    }
                );
            }
            disk.read(neighbor_block, &mut raw).unwrap();
            assert_eq!(raw, [0xa5; BLOCK]);
        }
        let mut contents = Sha256::new();
        let mut logical = 0;
        for block in current.runs[..usize::from(current.extents)]
            .iter()
            .flat_map(|run| run.physical..run.physical + run.count)
        {
            disk.read(block, &mut raw).unwrap();
            assert_eq!(&raw, pages[logical]);
            contents.update(raw);
            logical += 1;
        }
        assert_eq!(logical, target_pages);
        assert_eq!(&contents.finalize()[..], &done.output_digest);
        if allocation_floor == CANONICAL_BUSINESS_START {
            for block in SNAPSHOT_CATALOG_BLOCK..CANONICAL_BUSINESS_START {
                disk.read(block, &mut raw).unwrap();
                assert!(raw.iter().all(|&byte| byte == 0));
            }
        }
        let mut receipt = [0; RECEIPT_BYTES];
        disk.read(receipt_home, &mut raw).unwrap();
        receipt[..BLOCK - receipt_at].copy_from_slice(&raw[receipt_at..]);
        disk.read(receipt_home + 1, &mut raw).unwrap();
        receipt[BLOCK - receipt_at..].copy_from_slice(&raw[..RECEIPT_BYTES - (BLOCK - receipt_at)]);
        assert_eq!(FileReceiptV4::decode(&receipt).unwrap(), done);
    }

    #[test]
    fn unified_mount_denies_corrupt_homes() {
        #[derive(Debug)]
        enum Fault {
            ReservedTombstone,
            HiddenGeneration,
            SharedExtent,
            MissingAllocation,
            OrphanAllocation,
            HiddenDirectoryEntry,
            EnvelopeUuid,
            EnvelopeGeneration,
            EnvelopePayload,
            ContinuationBlock,
        }
        let mut w = Workspace::new();
        let p = principals();
        for fault in [
            Fault::ReservedTombstone,
            Fault::HiddenGeneration,
            Fault::SharedExtent,
            Fault::MissingAllocation,
            Fault::OrphanAllocation,
            Fault::HiddenDirectoryEntry,
            Fault::EnvelopeUuid,
            Fault::EnvelopeGeneration,
            Fault::EnvelopePayload,
            Fault::ContinuationBlock,
        ] {
            let (mut disk, baseline, snapshot) = unified_fixture();
            let expected = match fault {
                Fault::ReservedTombstone => {
                    let tombstone = disk.inode_slot(RESERVED_INODE_START);
                    p64(tombstone, 8, 1);
                    seal(tombstone, 252);
                    let acl = disk.acl_slot(RESERVED_INODE_START);
                    p32(acl, 4, 2);
                    p64(acl, 8, 1);
                    seal(acl, 60);
                    Error::Conflict
                }
                Fault::HiddenGeneration => {
                    let hidden = disk.inode_slot(CATALOG_INODE);
                    p64(hidden, 8, 2);
                    seal(hidden, 252);
                    Error::Conflict
                }
                Fault::SharedExtent => {
                    inode(disk.inode_slot(1), 1, 8, SNAPSHOT_SLOT_START, 1);
                    Error::Conflict
                }
                Fault::MissingAllocation => {
                    disk.set_allocated(SNAPSHOT_PROTECTION_BLOCK, false);
                    Error::Conflict
                }
                Fault::OrphanAllocation => {
                    disk.set_allocated(DATA_START + 1, true);
                    Error::Conflict
                }
                Fault::HiddenDirectoryEntry => {
                    let root = disk.inode_slot(0);
                    p64(root, 16, 256);
                    seal(root, 252);
                    let entry = &mut disk.0.get_mut(&ROOT).unwrap()[128..256];
                    p32(entry, 0, u32::from(CATALOG_INODE));
                    p16(entry, 4, 1);
                    p64(entry, 8, 1);
                    entry[16] = b'y';
                    seal(entry, 124);
                    Error::Invalid
                }
                Fault::EnvelopeUuid => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    head[8..24].fill(2);
                    seal(&mut **head, 32);
                    Error::Conflict
                }
                Fault::EnvelopeGeneration => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    p64(&mut **head, 24, 2);
                    seal(&mut **head, 32);
                    Error::Conflict
                }
                Fault::EnvelopePayload => {
                    let head = disk.0.get_mut(&SNAPSHOT_CATALOG_BLOCK).unwrap();
                    head[ENVELOPE_BYTES] = 1;
                    seal(&mut **head, 32);
                    Error::Invalid
                }
                Fault::ContinuationBlock => {
                    let mut tail = Box::new([0; BLOCK]);
                    tail[BLOCK - 1] = 1;
                    disk.0.insert(SNAPSHOT_PROTECTION_BLOCK - 1, tail);
                    Error::Conflict
                }
            };
            assert_eq!(
                validate_unified(
                    &mut disk,
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &p,
                    &mut w,
                    |_, _, _| panic!("invalid home reached ACL policy")
                ),
                Err(expected),
                "{fault:?}"
            );
        }
    }

    #[test]
    fn unified_mount_requires_hidden_owner_denial_and_independent_acl_policy() {
        let (mut disk, baseline, snapshot) = unified_fixture();
        let mut w = Workspace::new();
        let p = principals();
        for (owner_rights, deny_policy) in [(0, true), (1 << 8, false)] {
            let hidden = disk.acl_slot(CATALOG_INODE);
            p32(hidden, 32, owner_rights);
            seal(hidden, 60);
            assert_eq!(
                validate_unified(
                    &mut disk,
                    CHECKPOINT,
                    &baseline,
                    &snapshot,
                    &p,
                    &mut w,
                    |_, _, hidden| {
                        if deny_policy && hidden == Some(UnifiedSystemKind::SnapshotCatalog) {
                            return Err(Error::Unauthorized);
                        }
                        Ok(())
                    }
                ),
                Err(Error::Unauthorized)
            );
        }
    }

    #[test]
    fn joined_mount_denies_wrong_acl_principal_hidden_right_and_split_boot() {
        let mut d = fixture();
        let sb = SuperblockV1 {
            fs_uuid: [1; 16],
            generation: 1,
            checkpoint_lsn: 0,
            log_epoch: 1,
        };
        let p = core::array::from_fn(|i| Principal {
            id: i as u64 + 1,
            generation: 1,
        });
        let mut w = Workspace::new();
        let mut seen = 0;
        let v = validate(&mut d, sb, &systems(), &p, &mut w, |_, _, _| {
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 256);
        assert_eq!(v.system_blocks, 13);
        assert_eq!(v.structure.live_inodes, 6);
        assert_eq!(
            v.usage[0],
            Usage {
                inodes: 2,
                blocks: 2,
                directory_slots: 1
            }
        );
        let mut bad = fixture();
        let b = &mut bad.0.get_mut(&ACL).unwrap()[64..128];
        p64(b, 24, 2);
        seal(b, 60);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| Ok(())),
            Err(Error::Unauthorized)
        );
        let mut bad = fixture();
        let b = &mut bad.0.get_mut(&ACL).unwrap()[128..192];
        p32(b, 32, 1 << 8);
        seal(b, 60);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| Ok(())),
            Err(Error::Unauthorized)
        );
        let mut bad = fixture();
        bad.0.insert(
            BOOT_HOME,
            Box::new(
                BootEpochStoreV1 {
                    fs_uuid: [1; 16],
                    boot_epoch: 1,
                }
                .encode()
                .unwrap(),
            ),
        );
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| panic!(
                "split boot stores"
            )),
            Err(Error::Conflict)
        );
        let mut bad = fixture();
        let b = bad.0.get_mut(&(RECEIPTS + 6)).unwrap();
        p64(&mut **b, 80, 99);
        seal(&mut **b, 4092);
        assert_eq!(
            validate(&mut bad, sb, &systems(), &p, &mut w, |_, _, _| panic!(
                "principal mismatch"
            )),
            Err(Error::Conflict)
        );
    }
}
