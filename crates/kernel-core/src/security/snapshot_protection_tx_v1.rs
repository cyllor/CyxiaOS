//! The closed-gate PROTECTION path shares the file owner's committed redo view.

use super::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{
        SNAP_OP_FREEZE_SET, SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_REQUEST_START, SUPER_BYTES,
        protection_candidate::{ProtectionRecord, RestorePhase},
        request_store::{
            RequestRecord, RequestState, RequestStoreHeader, inspect_positioned_request_store,
            record_location, record_partition,
        },
    },
    file_mount_v1::MountEvidence,
    file_structure_v1::SystemKind,
    recovery_v1::{RedoImage, RedoTransaction, RedoWriter},
    snapshot_service_v4::{CallBinding, Operation, RECOVERY_SLOT, SnapshotGrant, SnapshotRequest},
};

pub(crate) fn frozen_protection(mut prior: ProtectionRecord) -> Result<ProtectionRecord, Error> {
    if prior.writes_open || prior.restore_phase == RestorePhase::Prepared {
        return Err(Error::Busy);
    }
    prior.object_generation = prior
        .object_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    prior.protection_generation = prior
        .protection_generation
        .checked_add(1)
        .ok_or(Error::Exhausted)?;
    prior.cleanup_frozen = true;
    Ok(prior)
}

/// Reserve one request under this boot's distinct protection grant, then
/// commit its exact terminal row and protection generations together.
/// Exact retries preserve their key and digest. A checkpointed PENDING can
/// settle under renewed authority while its protected view remains current.
pub fn freeze_set<I: EpochBlockIo>(
    writer: &mut RedoWriter<'_, I>,
    mount: &mut MountEvidence,
    binding: CallBinding,
    grant: SnapshotGrant,
    request: &SnapshotRequest<'_>,
    pages: &mut [[u8; SUPER_BYTES]; 2],
    mut reserve: impl FnMut(&RedoTransaction) -> Result<(), Error>,
) -> Result<RequestRecord, Error> {
    if !matches!(request.operation, Operation::FreezeSet { .. }) {
        return Err(Error::Invalid);
    }
    request.verify_grant(binding, grant, &[])?;
    let key = request.durable_key.ok_or(Error::Invalid)?;
    if key.client_slot != RECOVERY_SLOT {
        return Err(Error::Unauthorized);
    }
    let boot_home = mount
        .baseline_system()
        .and_then(|objects| {
            objects
                .iter()
                .find(|object| object.kind == SystemKind::BootEpoch)
        })
        .ok_or(Error::Unauthorized)?
        .first_block;
    let snapshots = mount.snapshot.as_mut().ok_or(Error::Unauthorized)?;
    let evidence = writer.evidence().ok_or(Error::Unknown)?;
    if evidence.incomplete_tail {
        return Err(Error::Unknown);
    }
    let [header_page, row_page] = pages;
    writer.read_committed(boot_home, header_page)?;
    if evidence.superblock.fs_uuid != binding.fs_uuid
        || mount.boot.boot_epoch != binding.boot_epoch
        || BootEpochStoreV1::decode(header_page)? != mount.boot
    {
        return Err(Error::Stale);
    }
    snapshots.verify_current(header_page, |home, page| writer.read_committed(home, page))?;
    let prior = snapshots.protection.ok_or(Error::Busy)?;

    let mut retained = None;
    let mut protection_committed_this_epoch = false;
    let requests = inspect_positioned_request_store(
        key.fs_uuid,
        snapshots.requests.generation,
        evidence.last_commit_lsn,
        |home, page| writer.read_committed(home, page),
        |index, row| {
            if row.log_epoch > evidence.superblock.log_epoch {
                return Err(Error::Conflict);
            }
            if row.key == key {
                retained = Some((index, *row));
            }
            if row.operation == SNAP_OP_FREEZE_SET && row.log_epoch == evidence.superblock.log_epoch
            {
                protection_committed_this_epoch = true;
            }
            Ok(())
        },
    )?;
    if let Some((index, record)) = retained {
        if record.request_digest != request.digest()? {
            return Err(Error::Conflict);
        }
        let (home, _) = record_location(index)?;
        if record.state != RequestState::Pending || writer.has_current_after_image(home) {
            return Ok(record);
        }
    }
    if requests != snapshots.requests {
        return Err(Error::Stale);
    }
    let resuming = retained.is_some();
    if requests.nonterminal != usize::from(resuming)
        || snapshots.writes_open()
        || protection_committed_this_epoch
    {
        return Err(Error::Busy);
    }
    request.verify_new_mutation(prior.live_view_epoch, prior.protection_generation)?;
    let protection = frozen_protection(prior)?;
    writer.read_committed(SNAPSHOT_REQUEST_START, header_page)?;
    let mut header = RequestStoreHeader::decode(header_page)?.ok_or(Error::Busy)?;
    let mark = &mut header.watermarks[RECOVERY_SLOT as usize];
    let (row_home, row, pending) = if let Some((index, prior)) = retained {
        if mark.client_generation != key.client_generation
            || mark.highest_accepted_seq != key.request_seq
        {
            return Err(Error::Conflict);
        }
        let (home, row) = record_location(index)?;
        writer.read_committed(home, row_page)?;
        (home, row, prior)
    } else {
        *mark = mark.next(key)?;
        header.generation = header.generation.checked_add(1).ok_or(Error::Exhausted)?;
        header.encode(header_page)?;
        let partition = record_partition(RECOVERY_SLOT).ok_or(Error::Conflict)?;
        let (home, _) = record_location(partition.start)?;
        if record_location(partition.end - 1)?.0 != home {
            return Err(Error::Conflict);
        }
        writer.read_committed(home, row_page)?;
        let mut free = None;
        for index in partition {
            let (_, bytes) = record_location(index)?;
            if row_page[bytes.clone()].iter().all(|&byte| byte == 0) {
                free = Some(bytes);
                break;
            }
        }
        (
            home,
            free.ok_or(Error::Capacity)?,
            RequestRecord::pending(request)?,
        )
    };

    // A new admission writes its header and row. After a cold checkpoint,
    // reassert only the existing PENDING row under this boot's authorization.
    let images = if resuming { 1 } else { 2 };
    // Two settlement images and an additional BEGIN/COMMIT occupy the
    // same total width as three added image slots in the extent preflight.
    let extent = writer.prepare(images + 3)?;
    let admission = writer.prepare(images)?;
    let settlement_blocks = writer.prepare(2)?.log_blocks;
    let settlement = RedoTransaction {
        txid: admission.txid.checked_add(1).ok_or(Error::Exhausted)?,
        begin_lsn: admission
            .commit_lsn
            .checked_add(1)
            .ok_or(Error::Exhausted)?,
        commit_lsn: admission
            .commit_lsn
            .checked_add(4)
            .ok_or(Error::Exhausted)?,
        first_log_block: admission.first_log_block + admission.log_blocks,
        log_blocks: settlement_blocks,
        ..admission
    };
    if extent.log_blocks != admission.log_blocks + settlement.log_blocks {
        return Err(Error::Conflict);
    }
    let mut terminal = pending;
    terminal.state = RequestState::Done;
    terminal.log_epoch = settlement.log_epoch;
    terminal.txid = settlement.txid;
    terminal.commit_lsn = settlement.commit_lsn;
    let mut payload = [0; 16];
    payload[..8].copy_from_slice(&protection.protection_generation.to_le_bytes());
    payload[8..12].copy_from_slice(&1u32.to_le_bytes());
    payload[12..16].copy_from_slice(&1u32.to_le_bytes());
    terminal.replace_payload(&payload)?;
    terminal.seal_result()?;
    pending.permits_transition(&terminal)?;
    reserve(&admission)?;
    reserve(&settlement)?;
    writer.verify_append_extent(extent)?;

    let raw = &mut row_page[row.clone()];
    if resuming {
        if RequestRecord::decode(raw)? != pending {
            return Err(Error::Conflict);
        }
    } else {
        pending.encode(raw.try_into().map_err(|_| Error::Conflict)?)?;
    }
    let images = [
        RedoImage {
            home: SNAPSHOT_REQUEST_START,
            contents: header_page,
        },
        RedoImage {
            home: row_home,
            contents: row_page,
        },
    ];
    writer.append(admission, &images[usize::from(resuming)..], |_| Ok(()))?;
    if !resuming {
        snapshots.requests.generation = header.generation;
        snapshots.requests.occupied += 1;
        snapshots.requests.nonterminal = 1;
    }

    terminal.encode(
        (&mut row_page[row])
            .try_into()
            .map_err(|_| Error::Conflict)?,
    )?;
    protection.encode(header_page)?;
    let images = [
        RedoImage {
            home: row_home,
            contents: row_page,
        },
        RedoImage {
            home: SNAPSHOT_PROTECTION_BLOCK,
            contents: header_page,
        },
    ];
    writer.append(settlement, &images, |_| Ok(()))?;
    snapshots.requests.nonterminal = 0;
    snapshots.record_freeze(protection, header_page);
    Ok(terminal)
}
