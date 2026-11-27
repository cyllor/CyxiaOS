//! Resume retirement of the first checkpoint's exact FSYNC journal.
//! Only the test manifest and its fully validated checkpointed homes can
//! reconstruct these compatible epoch-1 records. No home is replayed here.

use super::{
    BITMAP_START, BLOCK, BOUND_LSN, BOUND_STATUS, Disk, FROZEN, INODE_START, LEGACY_FINAL_LSN,
    LOG_END, RECEIPT_AT, RECEIPT_BYTES, RECEIPTS_HOME, SCRATCH_FILE_BLOCK, SIZE_BYTES,
    SnapshotLayout, allocate_second_data_home, authority, baseline_fsync_genesis_metadata,
    file_size, issued_index, issued_receipt, reopen, report, version_inode_page, volume,
};
use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_media_v0199::{FileReceiptV4, SuperblockV1},
    file_mount_v1::MountEvidence,
    offline_config_v1::VerifiedOfflineConfig,
    recovery_v1::{RedoImage, RedoTransaction, verify_checkpointed_transaction_residue},
};

pub(super) fn initial_residue_present(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
) -> Result<bool, Error> {
    // A boot-only log occupies the first six blocks. If none of the initial
    // file record slots survived, distinguish boot-only activity from a
    // remaining initial boot record before entering the retirement path.
    match volume::require_zero_blocks(disk, super::ISSUE_START..LOG_END) {
        Ok(()) => {}
        Err(Error::Conflict) => return Ok(true),
        Err(e) => return Err(e),
    }
    match authority::recovery_log(disk, checkpoint, Some(config)) {
        Ok(authority::BootLog::Empty) => Ok(true),
        Ok(_) => Ok(false),
        Err(Error::Invalid | Error::Conflict | Error::Stale) => Ok(true),
        Err(e) => Err(e),
    }
}

pub(super) fn resume(
    disk: &mut Disk,
    checkpoint: SuperblockV1,
    config: &VerifiedOfflineConfig<'_>,
    receipt: FileReceiptV4,
) -> Result<MountEvidence, Error> {
    if checkpoint.generation != 2
        || checkpoint.checkpoint_lsn != receipt.commit_lsn
        || reopen::identify(disk, Some(config))? != checkpoint
    {
        return Err(Error::Conflict);
    }
    let mode = SnapshotLayout::BaselineFsyncFile;
    volume::unified_map(disk, checkpoint, mode)?;
    let size = file_size(receipt);
    let bound = receipt.status == BOUND_STATUS;
    let mounted = volume::validate_fsync_homes(disk, checkpoint, config, 1, size, bound)?;
    let mut bitmap = [0; BLOCK];
    let mut inode = [0; BLOCK];
    let mut index = [0; BLOCK];
    let manifest = volume::format_manifest(Some(config));
    baseline_fsync_genesis_metadata(&manifest, &mut bitmap, &mut inode, &mut index)?;
    issued_index(&mut index)?;
    verify_home(disk, RECEIPTS_HOME + 6, &index)?;
    if !bound {
        version_inode_page(&mut inode, size, receipt.write_seq)?;
    }
    let pages = size.div_ceil(BLOCK);
    if pages == 2 {
        allocate_second_data_home(&mut bitmap)?;
    }
    verify_home(disk, INODE_START, &inode)?;
    verify_home(disk, BITMAP_START, &bitmap)?;

    let mut next = volume::FIRST_LOG_BLOCK;
    let mut lsn = 1;
    let mut txid = 1;
    let mut verify_next = |disk: &mut Disk, images: &[RedoImage<'_>]| {
        let plan = RedoTransaction {
            fs_uuid: checkpoint.fs_uuid,
            log_epoch: 1,
            txid,
            begin_lsn: lsn,
            commit_lsn: lsn + images.len() as u64 + 1,
            first_log_block: next,
            log_blocks: 2 + 2 * images.len() as u32,
        };
        verify_checkpointed_transaction_residue(disk, plan, images)?;
        next += plan.log_blocks;
        lsn = plan.commit_lsn + 1;
        txid += 1;
        Ok(())
    };
    verify_next(
        disk,
        &[
            RedoImage {
                home: volume::SECURITY_HOME,
                contents: &mounted.security.encode()?,
            },
            RedoImage {
                home: volume::BOOT_HOME,
                contents: &BootEpochStoreV1 {
                    fs_uuid: checkpoint.fs_uuid,
                    boot_epoch: 1,
                }
                .encode()?,
            },
        ],
    )?;
    let legacy = receipt.commit_lsn == LEGACY_FINAL_LSN;
    let binding = FileReceiptV4 {
        log_epoch: 1,
        txid: 3,
        commit_lsn: if legacy { BOUND_LSN - 1 } else { BOUND_LSN },
        write_seq: receipt.write_seq,
        status: BOUND_STATUS,
        operation_digest: receipt.operation_digest,
        ..issued_receipt()
    };
    let mut stored = [0; 2 * BLOCK];
    for (record, includes_index) in [(issued_receipt(), true), (binding, !legacy)] {
        stored[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES].copy_from_slice(&record.encode()?);
        let images = receipt_images(&stored, &index);
        let count = 2 + usize::from(includes_index);
        verify_next(disk, &images[..count])?;
    }
    if !bound {
        stored[RECEIPT_AT..RECEIPT_AT + RECEIPT_BYTES].copy_from_slice(&receipt.encode()?);
        // SAFETY: the one-shot CPU0 owner just verified the exact retained
        // DONE receipt and loaded these pages in read_retained_receipt.
        let snapshot = unsafe { &*core::ptr::addr_of!(FROZEN) };
        let data = &snapshot[SIZE_BYTES..].as_chunks::<BLOCK>().0[..pages];
        let mut images: [RedoImage<'_>; 7] = core::array::from_fn(|_| RedoImage {
            home: 0,
            contents: &[0; BLOCK],
        });
        for (offset, page) in data.iter().enumerate() {
            images[offset] = RedoImage {
                home: SCRATCH_FILE_BLOCK + offset as u32,
                contents: page,
            };
        }
        let mut count = pages;
        for image in receipt_images(&stored, &index)
            .into_iter()
            .take(if legacy { 2 } else { 3 })
        {
            images[count] = image;
            count += 1;
        }
        if pages == 2 {
            images[count] = RedoImage {
                home: BITMAP_START,
                contents: &bitmap,
            };
            count += 1;
        }
        images[count] = RedoImage {
            home: INODE_START,
            contents: &inode,
        };
        verify_next(disk, &images[..=count])?;
    }
    if lsn != checkpoint.checkpoint_lsn + 1 || next > LOG_END {
        return Err(Error::Conflict);
    }
    volume::require_zero_blocks(disk, next..BITMAP_START)?;

    // A cut may have occurred right after writing the alternate header.
    // Reconfirm that header with FLUSH before erasing any original record.
    disk.flush().map_err(|_| Error::Unknown)?;
    let start = volume::FIRST_LOG_BLOCK;
    let mut raw = [0; BLOCK];
    let mut retired = 0;
    for block in start..next {
        disk.read(block, &mut raw).map_err(|_| Error::Unknown)?;
        if raw.iter().any(|&byte| byte != 0) {
            disk.write(block, &[0; BLOCK]).map_err(|_| Error::Unknown)?;
            retired += 1;
        }
    }
    if retired != 0 {
        disk.flush().map_err(|_| Error::Unknown)?;
    }
    volume::require_zero_blocks(disk, start..next).map_err(|_| Error::Unknown)?;
    report(
        "V020_FSYNC_CHECKPOINT_RETIRE",
        1,
        checkpoint.checkpoint_lsn,
        retired,
    );
    Ok(mounted)
}

fn receipt_images<'a>(stored: &'a [u8; 2 * BLOCK], index: &'a [u8; BLOCK]) -> [RedoImage<'a>; 3] {
    [
        RedoImage {
            home: RECEIPTS_HOME,
            contents: stored[..BLOCK].try_into().unwrap(),
        },
        RedoImage {
            home: RECEIPTS_HOME + 1,
            contents: stored[BLOCK..].try_into().unwrap(),
        },
        RedoImage {
            home: RECEIPTS_HOME + 6,
            contents: index,
        },
    ]
}

fn verify_home(disk: &mut Disk, home: u32, expected: &[u8; BLOCK]) -> Result<(), Error> {
    let mut raw = [0; BLOCK];
    disk.read(home, &mut raw)?;
    if raw != *expected {
        return Err(Error::Conflict);
    }
    Ok(())
}
