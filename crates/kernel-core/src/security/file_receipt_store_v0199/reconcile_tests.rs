extern crate std;

use super::*;
use crate::security::{
    file_format_v1::{FormatManifest, FormatWorkspace, format},
    file_index_v0199::{FileStreamIndexV4, GroupIndex, StreamIndex},
    file_media_v0199::{BLOCK_COUNT, SuperblockV1},
    file_mount_v1::{Workspace, validate_signed},
    file_structure_v1::SystemObject,
    offline_config_v1::{CatalogBindings, SIGNATURE_LABEL},
    recovery_proof_v2::EIO,
    recovery_v1::{RecoveryWorkspace, retire_checkpointed_log},
};
use sha2::{Digest, Sha256};
use std::{boxed::Box, cell::Cell, collections::BTreeMap, rc::Rc};

const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
const RECEIPTS: u32 = 7003;
const STATE: u32 = 7000;
const BOOT: u32 = 7001;
const SYSTEM: [SystemObject; 4] = [
    SystemObject {
        kind: SystemKind::Security,
        inode: 253,
        generation: 1,
        first_block: STATE,
    },
    SystemObject {
        kind: SystemKind::BootEpoch,
        inode: 252,
        generation: 1,
        first_block: BOOT,
    },
    SystemObject {
        kind: SystemKind::Receipts,
        inode: 254,
        generation: 1,
        first_block: RECEIPTS,
    },
    SystemObject {
        kind: SystemKind::Acl,
        inode: 255,
        generation: 1,
        first_block: 7010,
    },
];
const KEY: ReceiptKey = ReceiptKey {
    fs_uuid: UUID,
    issued_boot_epoch: 1,
    group_id: 0,
    group_generation: 1,
    stream_slot: 0,
    stream_generation: 1,
    request_seq: 1,
};
const DIGEST: [u8; 32] = [9; 32];
const SLOT: usize = 21; // spans the first two receipt blocks

#[derive(Default)]
struct Disk {
    blocks: BTreeMap<u32, [u8; BLOCK]>,
    fail_flush: Rc<Cell<bool>>,
}

impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
        *out = self.blocks.get(&block).copied().unwrap_or([0; BLOCK]);
        Ok(())
    }

    fn write(&mut self, block: u32, image: &[u8; BLOCK]) -> Result<(), Error> {
        if image.iter().all(|&byte| byte == 0) {
            self.blocks.remove(&block);
        } else {
            self.blocks.insert(block, *image);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.fail_flush.replace(false) {
            Err(Error::Unknown)
        } else {
            Ok(())
        }
    }
}

fn verify_config() -> VerifiedOfflineConfig<'static> {
    const WIRE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/v020-signed-scratch/config.bin"
    ));
    // The fixture is signed by RFC 8032 test vector 1.
    const PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    VerifiedOfflineConfig::verify(
        WIRE,
        &PUBLIC_KEY,
        CatalogBindings {
            rule_generation: 1,
            security_generation: 1,
            key_generation: 1,
            rule_hash: Sha256::digest(b"scratch/test/rules/1").into(),
            security_hash: Sha256::digest(b"scratch/test/security/1").into(),
            key_manifest_hash: Sha256::digest(b"scratch/test/keys/1").into(),
        },
        &mut [0; SIGNATURE_LABEL.len() + WIRE.len() - 64],
        |_, _, lists| {
            if lists == [0; 12] {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        },
    )
    .unwrap()
}

fn write_boot(writer: &mut RedoWriter<'_, Disk>, state: &mut SecurityStateStoreV2, epoch: u64) {
    state.state_generation += 1;
    state.last_boot_epoch = epoch;
    writer
        .append(
            writer.prepare(2).unwrap(),
            &[
                RedoImage {
                    home: STATE,
                    contents: &state.encode().unwrap(),
                },
                RedoImage {
                    home: BOOT,
                    contents: &BootEpochStoreV1 {
                        fs_uuid: UUID,
                        boot_epoch: epoch,
                    }
                    .encode()
                    .unwrap(),
                },
            ],
            |_| Ok(()),
        )
        .unwrap();
}

fn retained_mount(
    disk: &mut Disk,
    recover: &mut RecoveryWorkspace,
    config: &VerifiedOfflineConfig<'_>,
    status: u16,
    prefix: u32,
) -> (SuperblockV1, MountEvidence, FileReceiptV4) {
    let mut state = SecurityStateStoreV2 {
        fs_uuid: UUID,
        state_generation: 1,
        rule_min_generation: 1,
        security_min_generation: 1,
        key_generation: 1,
        isolated_service_bitmap: 0,
        last_boot_epoch: 0,
        offline_config_generation: 1,
        offline_config_hash: config.digest(),
        service_generations: [1; 16],
    };
    let formatted = format(
        disk,
        BLOCK_COUNT,
        &FormatManifest {
            fs_uuid: UUID,
            root_block: 7014,
            system: SYSTEM,
            principals: *config.principals(),
            security: state,
        },
        &mut FormatWorkspace::new(),
    )
    .unwrap();
    let mut writer = RedoWriter::open(disk, recover, formatted.superblock).unwrap();
    write_boot(&mut writer, &mut state, 1);
    let mut index_block = [0; BLOCK];
    writer
        .read_committed(RECEIPTS + 6, &mut index_block)
        .unwrap();
    let mut index = FileStreamIndexV4::decode(&index_block).unwrap();
    index.generation += 1;
    index.groups[0] = GroupIndex {
        generation: 1,
        flags: 1,
        boot_epoch: 1,
        manifest_principal_id: 1,
    };
    index.streams[0] = StreamIndex {
        generation: 1,
        flags: 1,
        issued_hi: 1,
        retired_through: 0,
    };
    index.encode_into(&mut index_block).unwrap();
    let plan = writer.prepare(3).unwrap();
    let record = FileReceiptV4 {
        fs_uuid: UUID,
        issued_boot_epoch: KEY.issued_boot_epoch,
        group_id: KEY.group_id,
        group_generation: KEY.group_generation,
        stream_slot: KEY.stream_slot,
        stream_generation: KEY.stream_generation,
        request_seq: KEY.request_seq,
        log_epoch: plan.log_epoch,
        txid: plan.txid,
        commit_lsn: plan.commit_lsn,
        write_seq: 7,
        status,
        result: 0,
        completed_prefix: prefix,
        operation_digest: DIGEST,
        output_digest: [0; 32],
        request_id: KEY.request_id().unwrap(),
        owner_principal_id: 1,
    };
    let mut receipts = [0; RECEIPT_STORE_BYTES];
    let at = SLOT * RECEIPT_BYTES;
    receipts[at..at + RECEIPT_BYTES].copy_from_slice(&record.encode().unwrap());
    let images = receipt_images(
        &receipts,
        &index_block,
        RECEIPTS,
        home_closure(SLOT).unwrap().receipt,
    );
    writer.append(plan, &images, |_| Ok(())).unwrap();
    write_boot(&mut writer, &mut state, 2);
    let mut work = Box::new(Workspace::new());
    let (_, checkpoint) = writer
        .checkpoint_verified(|io, sb| {
            validate_signed(io, sb, &SYSTEM, config, &mut work, |_, _, _| Ok(())).map(|_| ())
        })
        .unwrap();
    retire_checkpointed_log(disk, recover, checkpoint).unwrap();
    let mounted = validate_signed(disk, checkpoint, &SYSTEM, config, &mut work, |_, _, _| {
        Ok(())
    })
    .unwrap();
    (checkpoint, mounted, record)
}

#[test]
fn requires_exact_identity_and_proof_before_persisting_partial() {
    let config = verify_config();
    let mut disk = Disk::default();
    let mut recovery = Box::new(RecoveryWorkspace::new());
    let (checkpoint, mounted, original) =
        retained_mount(&mut disk, &mut recovery, &config, UNKNOWN, 4096);
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
    let mut work = ReceiptRecoveryWorkspace::new();
    let job = ReceiptRecoveryJob {
        mounted: &mounted,
        config: &config,
        key: KEY,
        operation_digest: DIGEST,
    };
    let initial = writer.evidence();
    let other_key = ReceiptRecoveryJob {
        key: ReceiptKey {
            group_generation: 2,
            ..KEY
        },
        ..job
    };
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &other_key,
            &mut work,
            |_, _| panic!(),
            |_| panic!()
        ),
        Ok(ReceiptRecoveryOutcome::Unrecorded)
    ));
    let other_operation = ReceiptRecoveryJob {
        operation_digest: [3; 32],
        ..job
    };
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &other_operation,
            &mut work,
            |_, _| panic!(),
            |_| panic!()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &job,
            &mut work,
            |_, old| {
                assert_eq!(*old, original);
                Ok(ReceiptDisposition::Pending)
            },
            |_| panic!()
        ),
        Ok(ReceiptRecoveryOutcome::Retained)
    ));
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &job,
            &mut work,
            |_, _| {
                Ok(ReceiptDisposition::FsyncPrefix {
                    bytes: 8192,
                    result: EIO,
                })
            },
            |_| panic!()
        ),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &job,
            &mut work,
            |_, _| { Ok(ReceiptDisposition::NoEffect { result: EIO }) },
            |_| panic!()
        ),
        Err(Error::Conflict)
    ));
    assert_eq!(writer.evidence(), initial);

    let ReceiptRecoveryOutcome::Published { receipt, commit } = reconcile_receipt(
        &mut writer,
        &job,
        &mut work,
        |_, _| {
            Ok(ReceiptDisposition::FsyncPrefix {
                bytes: 4096,
                result: EIO,
            })
        },
        |plan| {
            assert_eq!(plan.log_blocks, 8);
            Ok(())
        },
    )
    .unwrap() else {
        panic!("expected committed partial receipt")
    };
    assert_eq!(
        receipt,
        FileReceiptV4 {
            status: PARTIAL,
            result: EIO,
            commit_lsn: commit.transaction().commit_lsn,
            log_epoch: commit.transaction().log_epoch,
            txid: commit.transaction().txid,
            ..original
        }
    );
    assert!(
        matches!(reconcile_receipt(&mut writer, &job, &mut work, |_, _| panic!(), |_| panic!()),
        Ok(ReceiptRecoveryOutcome::Confirmed(same)) if same == receipt)
    );
    assert_eq!(writer.evidence().unwrap().transactions, 1);
    let mut output = [0x99; BLOCK];
    assert_eq!(
        writer.read_committed_at_transaction(
            RECEIPTS,
            receipt.commit_lsn,
            receipt.txid + 1,
            &mut output,
        ),
        Err(Error::Conflict)
    );
    assert_eq!(output, [0x99; BLOCK]);

    let mut mount_work = Box::new(Workspace::new());
    let (_, next) = writer
        .checkpoint_verified(|io, sb| {
            validate_signed(io, sb, &SYSTEM, &config, &mut mount_work, |_, _, _| Ok(())).map(|_| ())
        })
        .unwrap();
    retire_checkpointed_log(&mut disk, &mut recovery, next).unwrap();
    let mounted = validate_signed(
        &mut disk,
        next,
        &SYSTEM,
        &config,
        &mut mount_work,
        |_, _, _| Ok(()),
    )
    .unwrap();
    assert_eq!(mounted.receipts.unresolved, 0);
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, next).unwrap();
    let reopened_job = ReceiptRecoveryJob {
        mounted: &mounted,
        ..job
    };
    assert!(
        matches!(reconcile_receipt(&mut writer, &reopened_job, &mut work, |_, _| panic!(), |_| panic!()),
        Ok(ReceiptRecoveryOutcome::Confirmed(same)) if same == receipt)
    );
    assert_eq!(writer.evidence().unwrap().transactions, 0);
}

#[test]
fn uncertain_receipt_flush_retains_obligation() {
    let config = verify_config();
    let mut disk = Disk::default();
    let flush = disk.fail_flush.clone();
    let mut recovery = Box::new(RecoveryWorkspace::new());
    let (checkpoint, mounted, _) = retained_mount(&mut disk, &mut recovery, &config, BOUND, 0);
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
    let mut work = ReceiptRecoveryWorkspace::new();
    let job = ReceiptRecoveryJob {
        mounted: &mounted,
        config: &config,
        key: KEY,
        operation_digest: DIGEST,
    };
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &job,
            &mut work,
            |_, _| Ok(ReceiptDisposition::NoEffect { result: EIO }),
            |_| {
                flush.set(true);
                Ok(())
            },
        ),
        Err(Error::Unknown)
    ));
    assert!(writer.evidence().is_none());
    assert!(matches!(
        reconcile_receipt(&mut writer, &job, &mut work, |_, _| panic!(), |_| panic!(),),
        Err(Error::Unknown)
    ));
}

#[test]
fn proved_zero_effect_is_durable_without_reopening_the_operation() {
    let config = verify_config();
    let mut disk = Disk::default();
    let mut recovery = Box::new(RecoveryWorkspace::new());
    let (checkpoint, mounted, old) = retained_mount(&mut disk, &mut recovery, &config, BOUND, 0);
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
    let mut work = ReceiptRecoveryWorkspace::new();
    let job = ReceiptRecoveryJob {
        mounted: &mounted,
        config: &config,
        key: KEY,
        operation_digest: DIGEST,
    };
    let before = writer.evidence();
    assert!(matches!(
        reconcile_receipt(
            &mut writer,
            &job,
            &mut work,
            |_, _| Ok(ReceiptDisposition::NoEffect { result: EIO }),
            |_| Err(Error::Capacity),
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(writer.evidence(), before);

    let ReceiptRecoveryOutcome::Published { receipt, commit } = reconcile_receipt(
        &mut writer,
        &job,
        &mut work,
        |_, record| {
            assert_eq!(*record, old);
            Ok(ReceiptDisposition::NoEffect { result: EIO })
        },
        |_| Ok(()),
    )
    .unwrap() else {
        panic!("expected verified cancelled receipt");
    };
    assert_eq!(
        receipt,
        FileReceiptV4 {
            status: CANCELLED,
            result: EIO,
            log_epoch: commit.transaction().log_epoch,
            txid: commit.transaction().txid,
            commit_lsn: commit.transaction().commit_lsn,
            ..old
        }
    );
    assert_eq!(writer.evidence().unwrap().distinct_home_blocks, 3);
}
