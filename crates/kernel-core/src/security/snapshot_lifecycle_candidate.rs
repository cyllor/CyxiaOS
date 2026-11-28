//! Host-only D7 mutation candidate over the existing v1 redo writer.
//! The protected owner supplies the pinned current state, exact operation
//! authorization, frozen root/COW custody and real journal reservation.
//! These transitions do not install native mounts, grants or request recovery.

use sha2::{Digest, Sha256};

use crate::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{
        BITMAP_START, INODE_START, PERIODIC_SLOTS, SHORT_TIER_SLOTS, SNAP_OP_DELETE_EXPIRED,
        SNAP_OP_OPEN_WRITES, SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_PROTECTION_BLOCK,
        SNAPSHOT_REQUEST_START, SNAPSHOT_STRIDE, SUPER_BYTES, SuperblockV1, UnifiedSystemKind,
        UnifiedSystemObject,
        protection_candidate::{ProtectionRecord, RestorePhase},
        request_store::{
            RequestRecord, RequestState, RequestStoreHeader, inspect_positioned_request_store,
            inspect_request_store, record_location, record_partition,
        },
        slot_candidate::{SlotDescriptor, SlotIdentity, validate_mirror_page},
        unified_superblock_pair,
    },
    file_mount_v1::{self, Acl, MountEvidence, MountedSnapshots, Workspace as MountWorkspace},
    file_structure_v1::{Inode, SystemKind, SystemObject},
    offline_config_v1::Principal,
    recovery_v1::{CommittedRedo, RedoImage, RedoTransaction, RedoWriter},
    snapshot_restore_gate::{RestoreGate, SnapshotKey},
    snapshot_service_v4::{
        CallBinding, FileReqKey, Operation, SnapshotGrant, SnapshotKey as WireSnapshotKey,
        SnapshotRequest,
    },
};

use super::{
    CatalogBinding, CatalogContext, CatalogEntry, CatalogRecord, slot_class, verify_catalog,
};

const SLOT_BLOCKS: usize = SNAPSHOT_STRIDE as usize;
const CAPTURE_HOMES: usize = SLOT_BLOCKS + 2;

/// Exact hashes and committed counters independently pinned by the owner
/// as part of the same quiescent volume state. On-disk self-claims are not
/// expected values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedState {
    pub catalog: CatalogContext,
    pub catalog_sha256: [u8; 32],
    pub protection_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SlotClass {
    Periodic = 1,
    OnDemand = 2,
}

/// Resolved by the owner after the CREATE capability and request checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRequest {
    pub slot: u32,
    pub class: SlotClass,
    /// Absolute deadline in the owner's authenticated online-age clock.
    pub retention_deadline: u64,
}

/// Descriptor, 14 exact mirror pages, catalog and protection after-images.
/// Reusable as one 17-page staging slot under the owner’s exclusive reservation.
pub struct CaptureWorkspace {
    pages: [[u8; SUPER_BYTES]; CAPTURE_HOMES],
}

impl CaptureWorkspace {
    pub const fn new() -> Self {
        Self {
            pages: [[0; SUPER_BYTES]; CAPTURE_HOMES],
        }
    }
}

impl Default for CaptureWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<CaptureWorkspace>() == 17 * SUPER_BYTES);

fn read_current<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
) -> Result<(CatalogRecord, ProtectionRecord), Error> {
    let journal = writer.evidence().ok_or(Error::Unknown)?;
    let context = expected.catalog;
    if journal.superblock.fs_uuid != context.fs_uuid {
        return Err(Error::Conflict);
    }
    if journal.last_commit_lsn != context.committed_lsn {
        return Err(Error::Stale);
    }
    let mut raw = [0; SUPER_BYTES];
    writer.read_committed(SNAPSHOT_PROTECTION_BLOCK, &mut raw)?;
    if hash(&raw) != expected.protection_sha256 {
        return Err(Error::Conflict);
    }
    let protection = ProtectionRecord::decode(&raw)?;
    if protection.fs_uuid != context.fs_uuid
        || protection.live_view_epoch != context.live_view_epoch
        || protection.online_age_ns != context.online_age_ns
    {
        return Err(Error::Conflict);
    }
    writer.read_committed(SNAPSHOT_CATALOG_BLOCK, &mut raw)?;
    if hash(&raw) != expected.catalog_sha256 {
        return Err(Error::Conflict);
    }
    let catalog = verify_catalog(SNAPSHOT_CATALOG_BLOCK, &raw, context, |block, page| {
        writer.read_committed(block, page)
    })?;
    for (entry, deadline) in catalog.entries.iter().zip(protection.retention_deadlines) {
        if let Some((binding, _)) = entry.binding()
            && deadline <= binding.identity.created_online_age_ns
        {
            return Err(Error::Conflict);
        }
    }
    Ok((catalog, protection))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Capture the current committed business inode view in one durable redo.
/// The mounted owner has already stopped new writes, drained prior accepted
/// work and obtained exact COW/block references for these roots. The
/// `reserve` callback checks the exact after-images against that freeze and
/// keeps the capture roots pinned through device completion.
///
/// An UNKNOWN result retains the original obligation. The caller must
/// reconcile the journal and its request before attempting another capture.
pub fn commit_capture<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    request: CaptureRequest,
    work: &mut CaptureWorkspace,
    reserve: impl FnOnce(&RedoTransaction, SlotIdentity, &[RedoImage<'_>]) -> Result<(), Error>,
) -> Result<(SlotIdentity, CommittedRedo), Error> {
    let (mut catalog, mut protection) = read_current(writer, expected)?;
    let slot = request.slot as usize;
    let Some(&entry) = catalog.entries.get(slot) else {
        return Err(Error::Invalid);
    };
    if slot_class(slot) != request.class as u8 {
        return Err(Error::Unauthorized);
    }
    let CatalogEntry::Free { slot_generation } = entry else {
        return Err(Error::Busy);
    };
    if protection.writes_open
        || protection.restore_phase != RestorePhase::Idle
        || protection.retention_deadlines[slot] > protection.online_age_ns
    {
        return Err(Error::Busy);
    }
    if request.retention_deadline <= protection.online_age_ns {
        return Err(Error::Invalid);
    }
    let plan = writer.prepare(CAPTURE_HOMES)?;
    let identity = SlotIdentity {
        fs_uuid: catalog.fs_uuid,
        snapshot_id: catalog.next_snapshot_id,
        slot: request.slot,
        slot_generation: slot_generation.checked_add(1).ok_or(Error::Exhausted)?,
        captured_live_view_epoch: protection.live_view_epoch,
        capture_commit_lsn: expected.catalog.committed_lsn,
        created_online_age_ns: protection.online_age_ns,
    };
    let descriptor_block = identity.descriptor_block()?;
    catalog.generation = catalog.generation.checked_add(1).ok_or(Error::Exhausted)?;
    catalog.next_snapshot_id = catalog
        .next_snapshot_id
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    protection.object_generation = protection
        .object_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;

    let mut mirror_hash = Sha256::new();
    for (index, page) in work.pages[1..SLOT_BLOCKS].iter_mut().enumerate() {
        let index = index as u32;
        writer.read_committed(INODE_START + index, page)?;
        validate_mirror_page(index, page)?;
        mirror_hash.update(page);
    }
    SlotDescriptor {
        identity,
        store_generation: (slot == 0).then_some(expected.catalog.slot_store_generation),
        inode_image_sha256: mirror_hash.finalize().into(),
    }
    .encode(&mut work.pages[0])?;
    catalog.entries[slot] = CatalogEntry::Active(CatalogBinding {
        identity,
        descriptor_sha256: hash(&work.pages[0]),
    });
    catalog.encode(&mut work.pages[SLOT_BLOCKS])?;
    protection.retention_deadlines[slot] = request.retention_deadline;
    protection.encode(&mut work.pages[SLOT_BLOCKS + 1])?;

    let images: [RedoImage<'_>; CAPTURE_HOMES] = core::array::from_fn(|index| RedoImage {
        home: match index {
            SLOT_BLOCKS => SNAPSHOT_CATALOG_BLOCK,
            i if i < SLOT_BLOCKS => descriptor_block + i as u32,
            _ => SNAPSHOT_PROTECTION_BLOCK,
        },
        contents: &work.pages[index],
    });
    let committed = writer.append(plan, &images, |redo| reserve(redo, identity, &images))?;
    Ok((identity, committed))
}

fn active_binding(
    catalog: &CatalogRecord,
    identity: SlotIdentity,
) -> Result<CatalogBinding, Error> {
    match catalog.entries.get(identity.slot as usize) {
        Some(CatalogEntry::Active(binding)) if binding.identity == identity => Ok(*binding),
        _ => Err(Error::Stale),
    }
}

/// Bind a restore lookup to the exact active historical slot in the same
/// frozen committed volume. The independent checker reads the complete
/// historical root, proves its reachability and ownership, and supplies the
/// resulting root hash for RestoreGate. A mirror checksum supplies metadata
/// integrity. Preparation and reopening need their own authority and
/// durable transition evidence.
pub fn verify_restore_source<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    identity: SlotIdentity,
    verify_root: impl FnOnce(CatalogBinding, &mut dyn EpochBlockIo) -> Result<[u8; 32], Error>,
) -> Result<SnapshotKey, Error> {
    let (catalog, protection) = read_current(writer, expected)?;
    let binding = active_binding(&catalog, identity)?;
    if protection.writes_open || protection.restore_phase != RestorePhase::Idle {
        return Err(Error::Busy);
    }
    let root_hash = verify_root(binding, &mut writer.committed_view())?;
    if root_hash == [0; 32] {
        return Err(Error::Conflict);
    }
    Ok(SnapshotKey {
        fs_uuid: identity.fs_uuid,
        snapshot_id: identity.snapshot_id,
        slot: identity.slot as u16,
        generation: identity.slot_generation,
        root_hash,
    })
}

/// Extend an exact active slot by publishing only the protection block.
/// The caller owns EXTEND authority and its request state. No descriptor,
/// mirror, live epoch, protection generation or gate state is changed.
pub fn extend_retention<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    identity: SlotIdentity,
    retention_deadline: u64,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<CommittedRedo, Error> {
    let (catalog, mut protection) = read_current(writer, expected)?;
    let slot = active_binding(&catalog, identity)?.identity.slot as usize;
    if protection.restore_phase != RestorePhase::Idle {
        return Err(Error::Busy);
    }
    if retention_deadline <= protection.retention_deadlines[slot]
        || retention_deadline <= protection.online_age_ns
    {
        return Err(Error::Conflict);
    }
    protection.object_generation = protection
        .object_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    protection.retention_deadlines[slot] = retention_deadline;
    let mut contents = [0; SUPER_BYTES];
    protection.encode(&mut contents)?;
    let plan = writer.prepare(1)?;
    writer.append(
        plan,
        &[RedoImage {
            home: SNAPSHOT_PROTECTION_BLOCK,
            contents: &contents,
        }],
        reserve,
    )
}

fn expiring_binding(
    catalog: &CatalogRecord,
    protection: &ProtectionRecord,
    target: WireSnapshotKey,
) -> Result<CatalogBinding, Error> {
    let slot = target.slot as usize;
    let Some(CatalogEntry::Active(binding)) = catalog.entries.get(slot) else {
        return Err(Error::Stale);
    };
    let identity = binding.identity;
    if target.fs_uuid != identity.fs_uuid
        || target.snapshot_id != identity.snapshot_id
        || target.slot_generation != identity.slot_generation
    {
        return Err(Error::Stale);
    }
    if protection.writes_open
        || protection.restore_phase != RestorePhase::Idle
        || protection.cleanup_frozen
        || protection.online_age_ns < protection.retention_deadlines[slot]
    {
        return Err(Error::Busy);
    }
    if slot_class(slot) == SlotClass::Periodic as u8 {
        let short = SHORT_TIER_SLOTS as usize;
        let layer = if slot < short {
            0..short
        } else {
            short..PERIODIC_SLOTS as usize
        };
        let peers = catalog.entries[layer]
            .iter()
            .filter(|entry| matches!(entry, CatalogEntry::Active(_)))
            .count();
        if peers < 2 {
            return Err(Error::Busy);
        }
    }
    Ok(*binding)
}

/// Reserve DELETE_EXPIRED for the exact authorized principal and active root.
/// A same-key retry returns the original receipt before planning a new drop.
pub fn admit_expiration<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    call: SnapshotMutationCall<'_>,
    work: &mut CaptureWorkspace,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<SnapshotAdmission, Error> {
    let Operation::DeleteExpired(target) = call.request.operation else {
        return Err(Error::Invalid);
    };
    admit_mutation(
        writer,
        call,
        work,
        None,
        |snapshot, _| {
            let catalog = snapshot.catalog.as_ref().ok_or(Error::Stale)?;
            let protection = snapshot.protection.as_ref().ok_or(Error::Stale)?;
            expiring_binding(catalog, protection, target)?;
            Ok(())
        },
        reserve,
    )
}

/// Publish the DELETING catalog entry and exact DONE receipt together.
/// The protected owner blocks new readers and verifies earlier reference
/// obligations in `reserve`. The root's blocks remain in GC custody.
pub fn mark_expired<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    call: SnapshotMutationCall<'_>,
    work: &mut CaptureWorkspace,
    reserve: impl FnOnce(&RedoTransaction, SlotIdentity) -> Result<(), Error>,
) -> Result<CommittedRedo, Error> {
    let Operation::DeleteExpired(target) = call.request.operation else {
        return Err(Error::Invalid);
    };
    let [catalog_page, request_page, scratch, ..] = &mut work.pages;
    let key = verify_mutation_call(writer, call, scratch)?;
    let (mut catalog, protection) = read_current(writer, expected)?;
    let binding = expiring_binding(&catalog, &protection, target)?;
    let journal = writer.evidence().ok_or(Error::Unknown)?;
    writer.read_committed(SNAPSHOT_REQUEST_START, scratch)?;
    let header = RequestStoreHeader::decode(scratch)?.ok_or(Error::Conflict)?;
    let mut pending = None;
    let requests = inspect_positioned_request_store(
        journal.superblock.fs_uuid,
        header.generation,
        journal.last_commit_lsn,
        |home, page| writer.read_committed(home, page),
        |index, record| {
            if record.log_epoch > journal.superblock.log_epoch {
                return Err(Error::Conflict);
            }
            if record.key == key {
                pending = Some((index, *record));
            }
            Ok(())
        },
    )?;
    let (index, pending) = pending.ok_or(Error::Stale)?;
    if requests.nonterminal != 1 || pending.state != RequestState::Pending {
        return Err(Error::Busy);
    }
    if pending.operation != SNAP_OP_DELETE_EXPIRED
        || pending.request_digest != call.request.digest()?
    {
        return Err(Error::Conflict);
    }

    let plan = writer.prepare(2)?;
    catalog.generation = catalog.generation.checked_add(1).ok_or(Error::Exhausted)?;
    catalog.entries[target.slot as usize] = CatalogEntry::Deleting {
        binding,
        root_drop_commit_lsn: plan.commit_lsn,
    };
    catalog.encode(catalog_page)?;

    let mut terminal = pending;
    terminal.state = RequestState::Done;
    terminal.log_epoch = plan.log_epoch;
    terminal.txid = plan.txid;
    terminal.commit_lsn = plan.commit_lsn;
    let mut result = [0; 56];
    result[..40].copy_from_slice(&target.encode()?);
    result[40..48].copy_from_slice(&plan.commit_lsn.to_le_bytes());
    result[48..52].copy_from_slice(&1u32.to_le_bytes());
    terminal.replace_payload(&result)?;
    terminal.seal_result()?;
    pending.permits_transition(&terminal)?;
    let (home, range) = record_location(index)?;
    writer.read_committed(home, request_page)?;
    terminal.encode(
        (&mut request_page[range])
            .try_into()
            .map_err(|_| Error::Conflict)?,
    )?;
    let images = [
        RedoImage {
            home: SNAPSHOT_CATALOG_BLOCK,
            contents: catalog_page,
        },
        RedoImage {
            home,
            contents: request_page,
        },
    ];
    writer.append(plan, &images, |plan| reserve(plan, binding.identity))
}

/// The stopped caller and copied D7 request. The protected owner supplies
/// the exact live grant and the authoritative service generation from its
/// registry. This host candidate checks their binding and reads BootEpoch
/// from committed media; it has no native dispatch or registry.
#[derive(Clone, Copy)]
pub struct SnapshotMutationCall<'a> {
    pub mount: &'a MountEvidence,
    pub binding: CallBinding,
    pub grant: SnapshotGrant,
    pub request: &'a SnapshotRequest<'a>,
}

pub struct SnapshotAdmission {
    pub record: RequestRecord,
    pub reserved: Option<CommittedRedo>,
}

/// Persist the exact PENDING request and sequence watermark together. The
/// caller retains the checked grant, exclusive media ownership and progress
/// reservation; qualification of a later write still requires the DONE proof.
pub fn admit_open_writes<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    gate: &RestoreGate,
    call: SnapshotMutationCall<'_>,
    work: &mut CaptureWorkspace,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<SnapshotAdmission, Error> {
    let request = call.request;
    let Operation::OpenWrites { restore, .. } = request.operation else {
        return Err(Error::Invalid);
    };
    admit_mutation(
        writer,
        call,
        work,
        Some(restore),
        |snapshot, restored| {
            let protection = snapshot.protection.ok_or(Error::Stale)?;
            request.verify_new_mutation(
                protection.live_view_epoch,
                protection.protection_generation,
            )?;
            if protection.restore_phase != RestorePhase::RestoredFrozen
                || protection.writes_open
                || gate.view().protection_generation != protection.protection_generation
            {
                return Err(Error::Stale);
            }
            if !snapshot
                .catalog
                .as_ref()
                .is_some_and(CatalogRecord::has_periodic_coverage)
            {
                return Err(Error::Busy);
            }
            let (prepared, commit) = gate.restore_for_reopen(call.binding.holder, gate.view())?;
            let restored = restored.ok_or(Error::Stale)?;
            if snapshot.completed_restore() != Some(&restored)
                || !restored.identifies_restore(prepared, commit)
            {
                return Err(Error::Conflict);
            }
            Ok(())
        },
        reserve,
    )
}

fn verify_mutation_call<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    call: SnapshotMutationCall<'_>,
    scratch: &mut [u8; SUPER_BYTES],
) -> Result<FileReqKey, Error> {
    call.request.verify_grant(call.binding, call.grant, &[])?;
    if call.mount.snapshot.is_none() {
        return Err(Error::Unauthorized);
    }
    let boot_home = call
        .mount
        .baseline_system()
        .and_then(|objects| {
            objects
                .iter()
                .find(|object| object.kind == SystemKind::BootEpoch)
        })
        .ok_or(Error::Unauthorized)?
        .first_block;
    let journal = writer.evidence().ok_or(Error::Unknown)?;
    let boot = call.mount.boot;
    let key = call.request.durable_key.ok_or(Error::Invalid)?;
    if boot.boot_epoch != call.binding.boot_epoch
        || boot.fs_uuid != key.fs_uuid
        || journal.superblock.fs_uuid != boot.fs_uuid
    {
        return Err(Error::Stale);
    }
    if journal.incomplete_tail {
        return Err(Error::Unknown);
    }

    writer.read_committed(boot_home, scratch)?;
    if BootEpochStoreV1::decode(scratch)? != boot {
        return Err(Error::Stale);
    }
    Ok(key)
}

fn admit_mutation<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    call: SnapshotMutationCall<'_>,
    work: &mut CaptureWorkspace,
    prerequisite: Option<FileReqKey>,
    qualify: impl FnOnce(&MountedSnapshots, Option<RequestRecord>) -> Result<(), Error>,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<SnapshotAdmission, Error> {
    let snapshot = call.mount.snapshot.as_ref().ok_or(Error::Unauthorized)?;
    let [header_page, request_page, scratch, ..] = &mut work.pages;
    let key = verify_mutation_call(writer, call, scratch)?;
    let journal = writer.evidence().ok_or(Error::Unknown)?;
    writer.read_committed(SNAPSHOT_REQUEST_START, header_page)?;
    let mut header = RequestStoreHeader::decode(header_page)?.ok_or(Error::Conflict)?;
    let mut retained = None;
    let mut prior = None;
    let requests = inspect_request_store(
        key.fs_uuid,
        header.generation,
        journal.last_commit_lsn,
        |block, page| writer.read_committed(block, page),
        |record| {
            if record.log_epoch > journal.superblock.log_epoch {
                return Err(Error::Conflict);
            }
            if record.key == key {
                retained = Some(*record);
            }
            if Some(record.key) == prerequisite {
                prior = Some(*record);
            }
            Ok(())
        },
    )?;
    // Inspect the exact previously retained request before generation checks
    // for a new side effect. Any uncertain prior outcome is returned as-is.
    if let Some(record) = retained {
        if record.request_digest != call.request.digest()? {
            return Err(Error::Conflict);
        }
        return Ok(SnapshotAdmission {
            record,
            reserved: None,
        });
    }
    if requests.nonterminal != 0 {
        return Err(Error::Busy);
    }
    snapshot.verify_current(scratch, |block, page| writer.read_committed(block, page))?;
    qualify(snapshot, prior)?;

    let mark = &mut header.watermarks[key.client_slot as usize];
    if key.client_generation != mark.client_generation
        || key.request_seq <= mark.highest_accepted_seq
    {
        return Err(Error::Stale);
    }
    *mark = mark.next(key)?;
    header.generation = header.generation.checked_add(1).ok_or(Error::Exhausted)?;
    header.encode(header_page)?;

    // Each principal may consume only its physically reserved class.
    let partition = record_partition(key.client_slot).ok_or(Error::Invalid)?;
    let mut current_home = None;
    let mut free = None;
    for index in partition {
        let (row_home, range) = record_location(index)?;
        if current_home != Some(row_home) {
            writer.read_committed(row_home, request_page)?;
            current_home = Some(row_home);
        }
        if request_page[range.clone()].iter().all(|&byte| byte == 0) {
            free = Some((row_home, range));
            break;
        }
    }
    let (home, range) = free.ok_or(Error::Capacity)?;
    let record = RequestRecord::pending(call.request)?;
    record.encode(
        (&mut request_page[range])
            .try_into()
            .map_err(|_| Error::Conflict)?,
    )?;
    let images = [
        RedoImage {
            home: SNAPSHOT_REQUEST_START,
            contents: header_page,
        },
        RedoImage {
            home,
            contents: request_page,
        },
    ];
    let committed = writer.append(writer.prepare(images.len())?, &images, reserve)?;
    Ok(SnapshotAdmission {
        record,
        reserved: Some(committed),
    })
}

/// Complete a reserved OPEN_WRITES request under the independent protection
/// role. The prior restore must be durably completed, and the two records
/// must identify the same live epoch and exact restore transaction. The
/// write gate changes only after the protection and terminal record images
/// commit together. Any lost reply keeps the in-memory gate UNKNOWN.
pub fn commit_open_writes<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    gate: &mut RestoreGate,
    call: SnapshotMutationCall<'_>,
    work: &mut CaptureWorkspace,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<CommittedRedo, Error> {
    let Operation::OpenWrites { restore, .. } = call.request.operation else {
        return Err(Error::Invalid);
    };
    let [page, gate_page, ..] = &mut work.pages;
    let key = verify_mutation_call(writer, call, page)?;
    let actor = call.binding.holder;
    let (catalog, mut protection) = read_current(writer, expected)?;
    call.request
        .verify_new_mutation(protection.live_view_epoch, protection.protection_generation)?;
    let view = gate.view();
    let (prepared, restore_commit) = gate.restore_for_reopen(actor, view)?;
    if protection.restore_phase != RestorePhase::RestoredFrozen
        || protection.writes_open
        || view.fs_uuid != protection.fs_uuid
        || view.live_epoch != protection.live_view_epoch
        || view.protection_generation != protection.protection_generation
    {
        return Err(Error::Stale);
    }
    if !catalog.has_periodic_coverage() {
        return Err(Error::Busy);
    }

    let journal = writer.evidence().ok_or(Error::Unknown)?;
    writer.read_committed(SNAPSHOT_REQUEST_START, page)?;
    let header = RequestStoreHeader::decode(page)?.ok_or(Error::Conflict)?;
    let mut open = None;
    let mut restored = None;
    let requests = inspect_positioned_request_store(
        expected.catalog.fs_uuid,
        header.generation,
        expected.catalog.committed_lsn,
        |home, out| writer.read_committed(home, out),
        |index, record| {
            if record.log_epoch > journal.superblock.log_epoch {
                return Err(Error::Conflict);
            }
            if record.key == key {
                open = Some((index, *record));
            }
            if record.key == restore {
                restored = Some(*record);
            }
            Ok(())
        },
    )?;
    if requests.nonterminal != 1 {
        return Err(Error::Busy);
    }
    let (index, open) = open.ok_or(Error::Stale)?;
    if open.operation != SNAP_OP_OPEN_WRITES
        || open.state != RequestState::Pending
        || open.old_live_view_epoch != protection.live_view_epoch
    {
        return Err(Error::Stale);
    }
    let restored = restored.ok_or(Error::Stale)?;
    if open.request_digest != call.request.digest()?
        || !restored.identifies_restore(prepared, restore_commit)
        || restored.new_live_view_epoch != protection.live_view_epoch
        || restored.result_digest != protection.restore_obligation_digest
    {
        return Err(Error::Conflict);
    }

    let plan = writer.prepare(2)?;
    protection.object_generation = protection
        .object_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    protection.protection_generation = protection
        .protection_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    let mut terminal = open;
    terminal.state = RequestState::Done;
    terminal.new_live_view_epoch = protection.live_view_epoch;
    terminal.log_epoch = plan.log_epoch;
    terminal.txid = plan.txid;
    terminal.commit_lsn = plan.commit_lsn;
    let mut result = [0; 16];
    result[..8].copy_from_slice(&protection.protection_generation.to_le_bytes());
    result[8..12].copy_from_slice(&u32::from(protection.cleanup_frozen).to_le_bytes());
    terminal.replace_payload(&result)?;
    terminal.seal_result()?;
    open.permits_transition(&terminal)?;
    let (home, range) = record_location(index)?;
    writer.read_committed(home, page)?;
    terminal.encode((&mut page[range]).try_into().map_err(|_| Error::Invalid)?)?;
    protection.writes_open = true;
    protection.restore_phase = RestorePhase::Idle;
    protection.restore_obligation_digest = [0; 32];
    protection.reopen_proof_digest = terminal.result_digest;
    protection.encode(gate_page)?;
    let images = [
        RedoImage {
            home,
            contents: page,
        },
        RedoImage {
            home: SNAPSHOT_PROTECTION_BLOCK,
            contents: gate_page,
        },
    ];
    let mut committed = None;
    gate.reopen_next_protection(actor, view, |_, _| {
        committed = Some(writer.append(plan, &images, reserve)?);
        Ok(())
    })?;
    committed.ok_or(Error::Unknown)
}

/// Reuses the file owner's GC pages while all new writes are fenced.
pub struct GcWorkspace {
    bitmap: [[u8; SUPER_BYTES]; 4],
    catalog: [u8; SUPER_BYTES],
    protection: [u8; SUPER_BYTES],
}

impl GcWorkspace {
    pub const fn new() -> Self {
        Self {
            bitmap: [[0; SUPER_BYTES]; 4],
            catalog: [0; SUPER_BYTES],
            protection: [0; SUPER_BYTES],
        }
    }
}

impl Default for GcWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(core::mem::size_of::<GcWorkspace>() <= 48 * 1024);

pub struct GcVolume<'a> {
    pub baseline: &'a [SystemObject; 4],
    pub snapshot: &'a [UnifiedSystemObject; 4],
    pub principals: &'a [Principal; 16],
}

/// Move-only proof of a fully checkpointed allocation change. Software
/// remains fenced while the owner installs this exact bitmap revision.
pub struct CheckpointedGc {
    checkpoint: SuperblockV1,
    bitmap_sha256: [u8; 32],
    released: u32,
}

impl CheckpointedGc {
    pub const fn released(&self) -> u32 {
        self.released
    }

    pub const fn checkpoint(&self) -> SuperblockV1 {
        self.checkpoint
    }

    /// Re-observe the durable homes under the same exclusive ownership
    /// before handing the new generation to the real allocator. A lost
    /// handoff result must be reconciled from its exact allocator generation.
    pub fn handoff(
        self,
        io: &mut impl EpochBlockIo,
        work: &mut GcWorkspace,
        install_once: impl FnOnce(SuperblockV1, &[[u8; SUPER_BYTES]; 4]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        io.read(0, &mut work.catalog)?;
        io.read(1, &mut work.protection)?;
        if unified_superblock_pair(&work.catalog, &work.protection)? != self.checkpoint {
            return Err(Error::Stale);
        }
        for (i, page) in work.bitmap.iter_mut().enumerate() {
            io.read(BITMAP_START + i as u32, page)?;
        }
        if bitmap_hash(&work.bitmap) != self.bitmap_sha256 {
            return Err(Error::Conflict);
        }
        install_once(self.checkpoint, &work.bitmap)
    }
}

fn bitmap_hash(bitmap: &[[u8; SUPER_BYTES]; 4]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for page in bitmap {
        digest.update(page);
    }
    digest.finalize().into()
}

/// Retire one previously dropped root. Two full root censuses compute the
/// exact bitmap delta while the file owner keeps writes and each external
/// pin fenced. One redo commits the bitmap, catalog and retention together.
/// Allocation remains closed until a complete checkpoint and matching raw
/// homes have been confirmed. No user request can supply the pin proof.
#[allow(clippy::too_many_arguments)]
pub fn retire_deleted_snapshot<I: EpochBlockIo>(
    mut writer: RedoWriter<'_, I>,
    volume: GcVolume<'_>,
    target: SlotIdentity,
    mount_work: &mut MountWorkspace,
    work: &mut GcWorkspace,
    mut policy: impl FnMut(Acl, Inode, Option<UnifiedSystemKind>) -> Result<(), Error>,
    prove_quiescent: impl FnOnce(SlotIdentity, u64) -> Result<(), Error>,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<CheckpointedGc, Error> {
    let epoch = writer.evidence().ok_or(Error::Unknown)?;
    let before = SuperblockV1 {
        checkpoint_lsn: epoch.last_commit_lsn,
        ..epoch.superblock
    };
    let prior = file_mount_v1::validate_unified_resident(
        &mut writer.committed_view(),
        before,
        volume.baseline,
        volume.snapshot,
        volume.principals,
        mount_work,
        &mut policy,
    )?;
    let staged = prior.snapshot.ok_or(Error::Unauthorized)?;
    let mut catalog = staged.catalog.ok_or(Error::Conflict)?;
    let mut protection = staged.protection.ok_or(Error::Conflict)?;
    let slot = target.slot as usize;
    let Some(CatalogEntry::Deleting {
        binding,
        root_drop_commit_lsn,
    }) = catalog.entries.get(slot)
    else {
        return Err(Error::Stale);
    };
    if binding.identity != target || *root_drop_commit_lsn > before.checkpoint_lsn {
        return Err(Error::Conflict);
    }
    if !staged.has_committed_deletion(slot) {
        return Err(Error::Conflict);
    }
    if protection.writes_open
        || protection.restore_phase != RestorePhase::Idle
        || protection.retention_deadlines[slot] > protection.online_age_ns
        || staged.requests.nonterminal != 0
    {
        return Err(Error::Busy);
    }
    prove_quiescent(target, *root_drop_commit_lsn)?;
    catalog.entries[slot] = CatalogEntry::Free {
        slot_generation: target.slot_generation,
    };
    catalog.generation = catalog.generation.checked_add(1).ok_or(Error::Exhausted)?;
    protection.retention_deadlines[slot] = 0;
    protection.object_generation = protection
        .object_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    let released = file_mount_v1::gc_bitmap_after(
        &mut writer.committed_view(),
        before,
        volume.baseline,
        volume.snapshot,
        mount_work,
        &catalog,
        &mut work.bitmap,
    )?;

    catalog.encode(&mut work.catalog)?;
    protection.encode(&mut work.protection)?;
    let bitmap_sha256 = bitmap_hash(&work.bitmap);
    let plan = writer.prepare(6)?;
    let images: [RedoImage<'_>; 6] = core::array::from_fn(|at| match at {
        4 => RedoImage {
            home: SNAPSHOT_CATALOG_BLOCK,
            contents: &work.catalog,
        },
        5 => RedoImage {
            home: SNAPSHOT_PROTECTION_BLOCK,
            contents: &work.protection,
        },
        _ => RedoImage {
            home: BITMAP_START + at as u32,
            contents: &work.bitmap[at],
        },
    });
    let commit = writer.append(plan, &images, reserve)?;
    let (_, checkpoint) = writer.checkpoint_verified(|io, current| {
        let effective = SuperblockV1 {
            checkpoint_lsn: commit.transaction().commit_lsn,
            ..current
        };
        let mounted = file_mount_v1::validate_unified_resident(
            io,
            effective,
            volume.baseline,
            volume.snapshot,
            volume.principals,
            mount_work,
            policy,
        )?;
        let observed = mounted.snapshot.ok_or(Error::Conflict)?;
        if observed.catalog != Some(catalog) || observed.protection != Some(protection) {
            return Err(Error::Conflict);
        }
        for (i, page) in work.bitmap.iter_mut().enumerate() {
            io.read(BITMAP_START + i as u32, page)?;
        }
        if bitmap_hash(&work.bitmap) != bitmap_sha256 {
            return Err(Error::Conflict);
        }
        Ok(())
    })?;
    Ok(CheckpointedGc {
        checkpoint,
        bitmap_sha256,
        released,
    })
}
