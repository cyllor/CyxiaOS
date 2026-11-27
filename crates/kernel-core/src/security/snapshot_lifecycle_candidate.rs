//! Host-only D7 mutation candidate over the existing v1 redo writer.
//! The protected owner supplies the pinned current state, exact operation
//! authorization, frozen root/COW custody and real journal reservation.
//! These transitions do not install native mounts, grants or request recovery.

use sha2::{Digest, Sha256};

use crate::security::{
    Error,
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{
        INODE_START, PERIODIC_SLOTS, SHORT_TIER_SLOTS, SNAPSHOT_CATALOG_BLOCK,
        SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_STRIDE, SUPER_BYTES,
        protection_candidate::{ProtectionRecord, RestorePhase},
        slot_candidate::{SlotDescriptor, SlotIdentity, validate_mirror_page},
    },
    recovery_v1::{CommittedRedo, RedoImage, RedoTransaction, RedoWriter},
    snapshot_restore_gate::SnapshotKey,
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

/// Drop the selected active root from lookup by durably marking its slot
/// DELETING at the exact redo LSN. The protected owner independently
/// authorizes deletion, blocks new readers and verifies all prior reference
/// obligations in `reserve`. The slot and its bytes remain in GC custody.
pub fn mark_expired<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    expected: ExpectedState,
    identity: SlotIdentity,
    reserve: impl FnOnce(&RedoTransaction) -> Result<(), Error>,
) -> Result<CommittedRedo, Error> {
    let (mut catalog, protection) = read_current(writer, expected)?;
    let binding = active_binding(&catalog, identity)?;
    let slot = identity.slot as usize;
    if protection.writes_open
        || protection.restore_phase != RestorePhase::Idle
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
    let plan = writer.prepare(1)?;
    catalog.generation = catalog.generation.checked_add(1).ok_or(Error::Exhausted)?;
    catalog.entries[slot] = CatalogEntry::Deleting {
        binding,
        root_drop_commit_lsn: plan.commit_lsn,
    };
    let mut contents = [0; SUPER_BYTES];
    catalog.encode(&mut contents)?;
    writer.append(
        plan,
        &[RedoImage {
            home: SNAPSHOT_CATALOG_BLOCK,
            contents: &contents,
        }],
        reserve,
    )
}
