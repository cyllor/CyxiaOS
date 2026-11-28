//! Native mount implementation exercised against a sparse power-cut device.
//! An acknowledged FLUSH is durable; interrupted writes may be lost or visible.

use super::*;
use cyxia_kernel_core::security::{
    boot_epoch_v1::TlsBootPolicy,
    file_format_v1::{self, FormatWorkspace, SCRATCH_FILE_BLOCK, SCRATCH_FILE_DATA},
    file_index_v0199::{FileStreamIndexV4, GroupIndex, SecurityStateStoreV2, StreamIndex},
    file_media_v0199::{BLOCK_COUNT, FileReceiptV4, INODE_START, RECEIPT_BYTES, local_request_id},
    recovery_v1::{RecoveryWorkspace, RedoImage, RedoTransaction, RedoWriter},
};
use sha2::{Digest, Sha256};

const RECEIPT_SLOT: usize = 21;
const RECEIPTS: u32 = volume::RECEIPTS_HOME;
const NEW_DATA: [u8; BLOCK_BYTES] = [b'F'; BLOCK_BYTES];

fn replica(blocks: &BTreeMap<u32, [u8; BLOCK_BYTES]>) -> Disk {
    Disk {
        blocks: blocks
            .iter()
            .filter(|(_, block)| block.iter().any(|&byte| byte != 0))
            .map(|(&block, bytes)| (block, *bytes))
            .collect(),
        ..Disk::default()
    }
}

fn receipt_pages(receipt: FileReceiptV4) -> [[u8; BLOCK_BYTES]; 2] {
    let mut pages = [0; BLOCK_BYTES * 2];
    let at = RECEIPT_SLOT * RECEIPT_BYTES;
    pages[at..at + RECEIPT_BYTES].copy_from_slice(&receipt.encode().unwrap());
    *pages.as_chunks::<BLOCK_BYTES>().0.first_chunk().unwrap()
}

fn closure<'a>(
    receipt: &'a [[u8; BLOCK_BYTES]; 2],
    index: &'a [u8; BLOCK_BYTES],
) -> [RedoImage<'a>; 3] {
    [
        RedoImage {
            home: RECEIPTS,
            contents: &receipt[0],
        },
        RedoImage {
            home: RECEIPTS + 1,
            contents: &receipt[1],
        },
        RedoImage {
            home: RECEIPTS + 6,
            contents: index,
        },
    ]
}

#[test]
fn signed_file_redo_recovers_cuts_and_keeps_exact_receipt_closure() {
    let _owner = STAGING_OWNER.lock().unwrap();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let policy = TlsBootPolicy::new(&verified, None).unwrap();
    let mut disk = Disk::default();
    let initial = file_format_v1::format_baseline_with_fsync_scratch_file(
        &mut disk,
        BLOCK_COUNT,
        &volume::format_manifest(Some(&verified)),
        &mut FormatWorkspace::new(),
    )
    .unwrap()
    .superblock;
    authority::allocate_boot(
        &mut disk,
        initial,
        &policy.resident_state(0).unwrap(),
        authority::BootUpdate::Tls(policy),
        volume::Checkpoints::Resident,
    )
    .unwrap();
    let (checkpoint, mounted) = reopen::recover_resident(&mut disk, initial, &verified).unwrap();
    authority::allocate_boot(
        &mut disk,
        checkpoint,
        &mounted.security,
        authority::BootUpdate::Tls(policy),
        volume::Checkpoints::Resident,
    )
    .unwrap();

    let mut inode_home = disk.blocks[&INODE_START];
    let raw = &mut inode_home[256..512];
    raw[16..24].copy_from_slice(&(BLOCK_BYTES as u64).to_le_bytes());
    raw[24..32].copy_from_slice(&1u64.to_le_bytes());
    let crc = crc32c_zeroed(raw, 252).unwrap();
    raw[252..].copy_from_slice(&crc.to_le_bytes());
    let mut directory = disk.blocks[&CANONICAL_BUSINESS_START];
    directory[16..26].copy_from_slice(b"status.txt");
    let crc = crc32c_zeroed(&directory[..128], 124).unwrap();
    directory[124..128].copy_from_slice(&crc.to_le_bytes());

    let mut index = FileStreamIndexV4::decode(&disk.blocks[&(RECEIPTS + 6)]).unwrap();
    let owner = verified.principals()[0].id;
    index.generation += 1;
    index.groups[0] = GroupIndex {
        generation: 1,
        flags: 1,
        boot_epoch: 2,
        manifest_principal_id: owner,
    };
    index.streams[0] = StreamIndex {
        generation: 1,
        flags: 1,
        issued_hi: 1,
        retired_through: 0,
    };
    let request_id = local_request_id(0, 0, 1).unwrap();
    index.global_request_id_hi = request_id;
    let mut index_page = [0; BLOCK_BYTES];
    index.encode_into(&mut index_page).unwrap();
    let issued = FileReceiptV4 {
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
        request_id,
        owner_principal_id: owner,
    };
    let mut expected_security = policy.resident_state(2).unwrap();
    expected_security.state_generation += 1;
    expected_security.service_generations[7] += 1;
    let state = expected_security.encode().unwrap();
    let mut work = RecoveryWorkspace::new();
    let mut writer = RedoWriter::open(&mut disk, &mut work, checkpoint).unwrap();
    let plan = writer.prepare(3).unwrap();
    writer
        .append(plan, &closure(&receipt_pages(issued), &index_page), |_| {
            Ok(())
        })
        .unwrap();
    let plan = writer.prepare(1).unwrap();
    writer
        .append(
            plan,
            &[RedoImage {
                home: volume::SECURITY_HOME,
                contents: &state,
            }],
            |_| Ok(()),
        )
        .unwrap();
    let plan = writer.prepare(3).unwrap();
    let binding = FileReceiptV4 {
        log_epoch: plan.log_epoch,
        txid: plan.txid,
        commit_lsn: plan.commit_lsn,
        write_seq: 1,
        status: 2,
        operation_digest: Sha256::digest(b"frozen native file transaction").into(),
        ..issued
    };
    let bound_pages = receipt_pages(binding);
    writer
        .append(plan, &closure(&bound_pages, &index_page), |_| Ok(()))
        .unwrap();
    let final_tx = writer.prepare(6).unwrap();
    let done = FileReceiptV4 {
        log_epoch: final_tx.log_epoch,
        txid: final_tx.txid,
        commit_lsn: final_tx.commit_lsn,
        completed_prefix: BLOCK_BYTES as u32,
        output_digest: Sha256::digest(NEW_DATA).into(),
        status: 3,
        ..binding
    };
    let done_pages = receipt_pages(done);
    let finish = |disk: &mut Disk, record: &[[u8; BLOCK_BYTES]; 2]| {
        let mut work = RecoveryWorkspace::new();
        let mut writer = RedoWriter::open(disk, &mut work, checkpoint)?;
        let [receipt_first, receipt_second, index] = closure(record, &index_page);
        writer
            .append(
                final_tx,
                &[
                    RedoImage {
                        home: SCRATCH_FILE_BLOCK,
                        contents: &NEW_DATA,
                    },
                    RedoImage {
                        home: INODE_START,
                        contents: &inode_home,
                    },
                    RedoImage {
                        home: CANONICAL_BUSINESS_START,
                        contents: &directory,
                    },
                    receipt_first,
                    receipt_second,
                    index,
                ],
                |_| Ok(()),
            )
            .map(|_| ())
    };
    let staged = replica(&disk.blocks);
    let verify = |disk: &mut Disk, done_expected: bool| {
        let sb = reopen::identify(disk, Some(&verified))
            .or_else(|_| {
                // The resident cursor can advance past the boot-only test profile.
                volume::read_checkpoint_for(
                    disk,
                    &mut [0; BLOCK_BYTES],
                    Some(&verified),
                    volume::Checkpoints::Resident,
                )
            })
            .unwrap();
        let (recovered, mounted) = reopen::recover_resident(disk, sb, &verified).unwrap();
        let expected = if done_expected { done } else { binding };
        let lsn = expected.commit_lsn;
        assert_eq!(recovered.generation, 3);
        assert_eq!(recovered.checkpoint_lsn, lsn);
        assert_eq!(mounted.boot.boot_epoch, 2);
        assert_eq!(mounted.security, expected_security);
        assert_eq!(mounted.receipts.occupied, 1);
        assert_eq!(mounted.receipts.unresolved, usize::from(!done_expected));
        assert_eq!(mounted.receipts.across_block, 1);
        let mut seen = [0; BLOCK_BYTES];
        disk.read(SCRATCH_FILE_BLOCK, &mut seen).unwrap();
        if done_expected {
            assert_eq!(seen, NEW_DATA);
            assert_eq!(disk.blocks[&CANONICAL_BUSINESS_START], directory);
        } else {
            assert_eq!(&seen[..SCRATCH_FILE_DATA.len()], SCRATCH_FILE_DATA);
        }
        assert_eq!(disk.blocks[&(RECEIPTS + 6)], index_page);
        let expected = receipt_pages(expected);
        for (offset, page) in expected.iter().enumerate() {
            assert_eq!(disk.blocks[&(RECEIPTS + offset as u32)], *page);
        }
        assert!(volume::require_zero_blocks(disk, volume::FIRST_LOG_BLOCK..BITMAP_START).is_ok());
    };

    // Every 4 KiB append cut, including either half of a full-page REDO.
    for write in 0..u64::from(final_tx.log_blocks) {
        let mut interrupted = replica(&staged.blocks);
        interrupted.fail_before_write = Some(write);
        assert_eq!(finish(&mut interrupted, &done_pages), Err(Error::Unknown));
        verify(&mut replica(&interrupted.blocks), false);
    }
    // Both failed append FLUSH completions, with or without the writes
    // they covered becoming observable after the power cut.
    for flush in 0..2 {
        let mut interrupted = replica(&staged.blocks);
        interrupted.durable = Some(interrupted.blocks.clone());
        interrupted.fail_before_flush = Some(flush);
        assert_eq!(finish(&mut interrupted, &done_pages), Err(Error::Unknown));
        verify(&mut replica(interrupted.durable.as_ref().unwrap()), false);
        verify(&mut replica(&interrupted.blocks), flush == 1);
    }
    let mut committed = replica(&staged.blocks);
    finish(&mut committed, &done_pages).unwrap();
    let mut recovered = replica(&committed.blocks);
    verify(&mut recovered, true);
    assert_eq!((recovered.writes, recovered.flushes), (49, 43));

    // Every recovery home, checkpoint and retirement write/FLUSH cut.
    // Alternate between cache loss and a write whose completion was lost.
    let reopen_once =
        |disk: &mut Disk| reopen::recover_resident(disk, checkpoint, &verified).map(|_| ());
    for (writes, count) in [(true, recovered.writes), (false, recovered.flushes)] {
        for cut in 0..count {
            let mut interrupted = replica(&committed.blocks);
            interrupted.durable = Some(interrupted.blocks.clone());
            if writes {
                interrupted.fail_before_write = Some(cut);
            } else {
                interrupted.fail_before_flush = Some(cut);
            }
            assert_eq!(reopen_once(&mut interrupted), Err(Error::Unknown));
            verify(&mut replica(interrupted.durable.as_ref().unwrap()), true);
            verify(&mut replica(&interrupted.blocks), true);
        }
    }

    let reject_without_mutation = |mut untrusted: Disk| {
        let before = (untrusted.writes, untrusted.flushes);
        assert!(reopen_once(&mut untrusted).is_err());
        assert_eq!((untrusted.writes, untrusted.flushes), before);
    };
    let mut torn = replica(&committed.blocks);
    let RedoTransaction {
        first_log_block,
        log_blocks,
        ..
    } = final_tx;
    torn.blocks
        .get_mut(&(first_log_block + log_blocks - 1))
        .unwrap()[96] ^= 1;
    reject_without_mutation(torn);

    let mut mismatched = replica(&staged.blocks);
    finish(
        &mut mismatched,
        &receipt_pages(FileReceiptV4 {
            txid: done.txid + 1,
            ..done
        }),
    )
    .unwrap();
    reject_without_mutation(mismatched);

    let mut forbidden = replica(&staged.blocks);
    let mut writer = RedoWriter::open(&mut forbidden, &mut work, checkpoint).unwrap();
    let plan = writer.prepare(1).unwrap();
    writer
        .append(
            plan,
            &[RedoImage {
                home: volume::BOOT_HOME,
                contents: &NEW_DATA,
            }],
            |_| Ok(()),
        )
        .unwrap();
    reject_without_mutation(forbidden);

    assert_eq!(
        SecurityStateStoreV2::decode(&recovered.blocks[&volume::SECURITY_HOME]),
        Ok(expected_security)
    );
}
