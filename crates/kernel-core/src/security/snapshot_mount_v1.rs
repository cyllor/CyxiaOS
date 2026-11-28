//! Snapshot object checks for the signed unified volume, over one exclusive
//! committed view. The mount verifies data custody separately from permissions.

use super::{
    ENVELOPE_BYTES, Error, SNAP_OP_OPEN_WRITES, SNAP_OP_RESTORE, SUPER_BYTES, SuperblockV1,
    UnifiedSystemKind, UnifiedSystemObject,
    catalog_candidate::{CatalogContext, CatalogEntry, CatalogRecord, verify_catalog},
    decode_envelope_header,
    protection_candidate::{ProtectionRecord, RestorePhase},
    request_store::{RequestRecord, RequestState, RequestStoreEvidence, inspect_request_store},
};
use crate::security::{epoch_redo_v0199::EpochBlockIo, snapshot_service_v4::request_digest};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountedSnapshots {
    pub catalog: Option<CatalogRecord>,
    pub protection: Option<ProtectionRecord>,
    pub catalog_sha256: [u8; 32],
    pub protection_sha256: [u8; 32],
    pub historical_only_blocks: u32,
    pub requests: RequestStoreEvidence,
    durable_open: bool,
    write_qualified: bool,
}

impl MountedSnapshots {
    pub const fn writes_open(&self) -> bool {
        self.write_qualified
    }

    pub const fn has_open_proof(&self) -> bool {
        self.durable_open
    }

    pub(crate) fn qualify_writes(
        &mut self,
        gate: &crate::security::snapshot_restore_gate::RestoreGate,
        verify_boot: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let p = self.protection.ok_or(Error::Stale)?;
        if !self.has_open_proof()
            || !self
                .catalog
                .as_ref()
                .is_some_and(CatalogRecord::has_periodic_coverage)
            || gate.view().fs_uuid != p.fs_uuid
            || !gate.may_write(p.live_view_epoch, p.protection_generation)
        {
            return Err(Error::Stale);
        }
        verify_boot()?;
        self.write_qualified = true;
        Ok(())
    }

    pub fn retains_roots(&self) -> bool {
        self.catalog.as_ref().is_some_and(|catalog| {
            catalog
                .entries
                .iter()
                .any(|entry| entry.binding().is_some())
        })
    }

    /// The file owner borrowed this committed view exclusively. Re-observe the
    /// catalog and protection roots just before using an older mount witness.
    pub fn verify_current(
        &self,
        page: &mut [u8; SUPER_BYTES],
        mut read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for (block, expected) in [
            (super::SNAPSHOT_CATALOG_BLOCK, self.catalog_sha256),
            (super::SNAPSHOT_PROTECTION_BLOCK, self.protection_sha256),
        ] {
            read(block, page)?;
            if hash(page) != expected {
                return Err(Error::Stale);
            }
        }
        Ok(())
    }
}

fn hash(page: &[u8; SUPER_BYTES]) -> [u8; 32] {
    Sha256::digest(page).into()
}

fn trailing_zero(
    io: &mut impl EpochBlockIo,
    object: UnifiedSystemObject,
    page: &mut [u8; SUPER_BYTES],
) -> Result<(), Error> {
    for block in object.first_block + 1..object.first_block + object.kind.blocks() {
        io.read(block, page)?;
        if page.iter().any(|&byte| byte != 0) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

pub(crate) fn verify_snapshot_homes(
    io: &mut impl EpochBlockIo,
    sb: SuperblockV1,
    objects: &[UnifiedSystemObject; 4],
    page: &mut [u8; SUPER_BYTES],
) -> Result<MountedSnapshots, Error> {
    use UnifiedSystemKind::{SnapshotCatalog, SnapshotProtection, SnapshotRequest, SnapshotSlot};

    let object = |kind| {
        objects
            .iter()
            .find(|entry| entry.kind == kind)
            .copied()
            .ok_or(Error::Invalid)
    };
    let catalog_object = object(SnapshotCatalog)?;
    let slot_object = object(SnapshotSlot)?;
    let request_object = object(SnapshotRequest)?;
    let protection_object = object(SnapshotProtection)?;
    let mut read_head = |object: UnifiedSystemObject, page: &mut [u8; SUPER_BYTES]| {
        io.read(object.first_block, page)?;
        let header = decode_envelope_header(object.kind, page)?;
        // The signed manifest fixes inode identity and minimum object
        // generations. Catalog/Protection data can progress independently.
        if header.fs_uuid != sb.fs_uuid || header.generation < object.generation {
            return Err(Error::Conflict);
        }
        Ok(header.generation)
    };

    let slot_generation = read_head(slot_object, page)?;
    let slot_empty = page[ENVELOPE_BYTES..].iter().all(|&byte| byte == 0);
    let protection_generation = read_head(protection_object, page)?;
    let protection_sha256 = hash(page);
    let protection = if page[ENVELOPE_BYTES..].iter().all(|&byte| byte == 0) {
        if protection_generation != protection_object.generation {
            return Err(Error::Conflict);
        }
        None
    } else {
        Some(ProtectionRecord::decode(page)?)
    };
    let request_generation = read_head(request_object, page)?;
    let catalog_generation = read_head(catalog_object, page)?;
    let catalog_sha256 = hash(page);
    let catalog = match protection {
        Some(p) => {
            let context = CatalogContext {
                fs_uuid: sb.fs_uuid,
                catalog_generation,
                slot_store_generation: slot_generation,
                live_view_epoch: p.live_view_epoch,
                committed_lsn: sb.checkpoint_lsn,
                online_age_ns: p.online_age_ns,
            };
            let catalog =
                verify_catalog(catalog_object.first_block, page, context, |block, out| {
                    io.read(block, out)
                })?;
            for (entry, deadline) in catalog.entries.iter().zip(p.retention_deadlines) {
                match entry {
                    CatalogEntry::Free { slot_generation }
                        if deadline > p.online_age_ns || *slot_generation == 0 && deadline != 0 =>
                    {
                        return Err(Error::Conflict);
                    }
                    CatalogEntry::Deleting { .. } if deadline > p.online_age_ns => {
                        return Err(Error::Conflict);
                    }
                    CatalogEntry::Active(binding) | CatalogEntry::Deleting { binding, .. }
                        if deadline <= binding.identity.created_online_age_ns =>
                    {
                        return Err(Error::Conflict);
                    }
                    _ => {}
                }
            }
            if p.restore_phase == RestorePhase::RestoredFrozen && p.live_view_epoch <= 1 {
                return Err(Error::Conflict);
            }
            Some(catalog)
        }
        None => {
            if !slot_empty
                || slot_generation != slot_object.generation
                || catalog_generation != catalog_object.generation
                || page[ENVELOPE_BYTES..].iter().any(|&byte| byte != 0)
            {
                return Err(Error::Conflict);
            }
            trailing_zero(io, slot_object, page)?;
            None
        }
    };
    let mut proof_matches = 0;
    let mut restored: Option<RequestRecord> = None;
    let mut opened: Option<RequestRecord> = None;
    let requests = inspect_request_store(
        sb.fs_uuid,
        request_generation,
        sb.checkpoint_lsn,
        |block, page| io.read(block, page),
        |row| {
            if row.log_epoch > sb.log_epoch {
                return Err(Error::Conflict);
            }
            if let Some(p) = protection {
                if row.key.client_slot != 15 {
                    return Ok(());
                }
                if p.writes_open
                    && row.operation == SNAP_OP_RESTORE
                    && row.state == RequestState::Done
                    && row.new_live_view_epoch == p.live_view_epoch
                    && restored.replace(*row).is_some()
                {
                    return Err(Error::Conflict);
                }
                let matched = match p.restore_phase {
                    RestorePhase::Idle => {
                        p.writes_open
                            && row.operation == SNAP_OP_OPEN_WRITES
                            && row.state == RequestState::Done
                            && row.new_live_view_epoch == p.live_view_epoch
                            && row.result_digest == p.reopen_proof_digest
                            && super::le64(row.payload(), 0)? == p.protection_generation
                            && super::le32(row.payload(), 8)? == u32::from(p.cleanup_frozen)
                    }
                    RestorePhase::Prepared => {
                        row.operation == SNAP_OP_RESTORE
                            && !row.state.terminal()
                            && row.old_live_view_epoch == p.live_view_epoch
                            && row.request_digest == p.restore_obligation_digest
                    }
                    RestorePhase::RestoredFrozen => {
                        row.operation == SNAP_OP_RESTORE
                            && row.state == RequestState::Done
                            && row.new_live_view_epoch == p.live_view_epoch
                            && row.result_digest == p.restore_obligation_digest
                    }
                };
                proof_matches += usize::from(matched);
                if matched && p.writes_open {
                    opened = Some(*row);
                }
            }
            Ok(())
        },
    )?;
    let writes_open = if let Some(p) = protection {
        if (p.writes_open || p.restore_phase != RestorePhase::Idle) && proof_matches != 1 {
            return Err(Error::Conflict);
        }
        if p.writes_open {
            let (restore, open) = restored.zip(opened).ok_or(Error::Conflict)?;
            let mut body = [0; 48];
            let prior_generation = p
                .protection_generation
                .checked_sub(1)
                .filter(|&g| g != 0)
                .ok_or(Error::Conflict)?;
            body[..8].copy_from_slice(&prior_generation.to_le_bytes());
            body[8..44].copy_from_slice(&restore.key.encode()?);
            if restore.commit_lsn >= open.commit_lsn
                || restore.log_epoch > open.log_epoch
                || open.request_digest
                    != request_digest(SNAP_OP_OPEN_WRITES, open.key, p.live_view_epoch, &body)?
            {
                return Err(Error::Conflict);
            }
        }
        p.writes_open && requests.nonterminal == 0
    } else {
        if request_generation != request_object.generation || requests.occupied != 0 {
            return Err(Error::Conflict);
        }
        false
    };
    Ok(MountedSnapshots {
        catalog,
        protection,
        catalog_sha256,
        protection_sha256,
        historical_only_blocks: 0,
        requests,
        durable_open: writes_open,
        write_qualified: false,
    })
}
