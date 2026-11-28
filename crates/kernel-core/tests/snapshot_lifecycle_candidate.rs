use cyxia_kernel_core::security::{
    Error,
    epoch_redo_v0199::EpochBlockIo,
    file_media_unified_v1::{
        BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, SLOT_MIRROR_BYTES,
        SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_PROTECTION_BLOCK, SNAPSHOT_SLOT_START, SNAPSHOT_SLOTS,
        SNAPSHOT_STRIDE, SUPER_BYTES, SuperblockV1, UnifiedSystemKind,
        catalog_candidate::{
            CatalogContext, CatalogEntry, CatalogRecord,
            lifecycle::{
                CaptureRequest, CaptureWorkspace, ExpectedState, SlotClass, commit_capture,
                extend_retention, verify_restore_source,
            },
            verify_catalog,
        },
        encode_object_envelope,
        protection_candidate::{ProtectionRecord, RestorePhase},
    },
    file_media_v0199::crc32c_zeroed,
    recovery_v1::{RecoveryWorkspace, RedoWriter},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const UUID: [u8; 16] = *b"CYX-G1-SLOT-VEC!";
const MIRROR: &[u8; SLOT_MIRROR_BYTES] =
    include_bytes!("../../../tools/fixtures/v020-g1-slot-mirror.bin");

#[derive(Default)]
struct Disk {
    blocks: BTreeMap<u32, [u8; SUPER_BYTES]>,
    writes: usize,
    flushes: usize,
    fail_first_flush: bool,
}

impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; SUPER_BYTES]) -> Result<(), Error> {
        *out = self.blocks.get(&block).copied().unwrap_or([0; SUPER_BYTES]);
        Ok(())
    }

    fn write(&mut self, block: u32, data: &[u8; SUPER_BYTES]) -> Result<(), Error> {
        assert!(
            (2..BITMAP_START).contains(&block),
            "append writes only the log"
        );
        self.blocks.insert(block, *data);
        self.writes += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.flushes += 1;
        if self.fail_first_flush && self.flushes == 1 {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}

fn fixture() -> (Disk, SuperblockV1, ExpectedState) {
    let mut disk = Disk::default();
    let mut raw = [0; SUPER_BYTES];
    raw[..4].copy_from_slice(&0x4359_4653u32.to_le_bytes());
    raw[4..6].copy_from_slice(&1u16.to_le_bytes());
    raw[6..8].copy_from_slice(&80u16.to_le_bytes());
    raw[8..12].copy_from_slice(&(SUPER_BYTES as u32).to_le_bytes());
    raw[12..16].copy_from_slice(&BLOCK_COUNT.to_le_bytes());
    raw[16..32].copy_from_slice(&UUID);
    raw[32..40].copy_from_slice(&1u64.to_le_bytes());
    raw[40..48].copy_from_slice(&50u64.to_le_bytes());
    raw[48..56].copy_from_slice(&1u64.to_le_bytes());
    raw[56..60].copy_from_slice(&BITMAP_START.to_le_bytes());
    raw[60..64].copy_from_slice(&INODE_START.to_le_bytes());
    raw[64..68].copy_from_slice(&DATA_START.to_le_bytes());
    raw[68..72].copy_from_slice(&256u32.to_le_bytes());
    let crc = crc32c_zeroed(&raw, 76).unwrap();
    raw[76..80].copy_from_slice(&crc.to_le_bytes());
    let superblock = SuperblockV1::decode(&raw).unwrap();
    disk.blocks.insert(0, raw);
    disk.blocks.insert(1, raw);

    let mut catalog = CatalogRecord {
        fs_uuid: UUID,
        generation: 2,
        next_snapshot_id: 5,
        entries: [CatalogEntry::Free { slot_generation: 0 }; SNAPSHOT_SLOTS as usize],
    };
    catalog.entries[6] = CatalogEntry::Free { slot_generation: 3 };
    catalog.encode(&mut raw).unwrap();
    disk.blocks.insert(SNAPSHOT_CATALOG_BLOCK, raw);
    let catalog_sha256 = Sha256::digest(raw).into();

    let mut retention_deadlines = [0; SNAPSHOT_SLOTS as usize];
    retention_deadlines[6] = 80;
    ProtectionRecord {
        fs_uuid: UUID,
        object_generation: 4,
        protection_generation: 12,
        live_view_epoch: 7,
        online_age_ns: 100,
        retention_deadlines,
        writes_open: false,
        restore_phase: RestorePhase::Idle,
        cleanup_frozen: false,
        reopen_proof_digest: [0; 32],
        restore_obligation_digest: [0; 32],
    }
    .encode(&mut raw)
    .unwrap();
    disk.blocks.insert(SNAPSHOT_PROTECTION_BLOCK, raw);
    let protection_sha256 = Sha256::digest(raw).into();

    encode_object_envelope(UnifiedSystemKind::SnapshotSlot, UUID, 1, &mut raw).unwrap();
    disk.blocks.insert(SNAPSHOT_SLOT_START, raw);
    for (index, page) in MIRROR.chunks_exact(SUPER_BYTES).enumerate() {
        disk.blocks
            .insert(INODE_START + index as u32, page.try_into().unwrap());
    }
    (
        disk,
        superblock,
        ExpectedState {
            catalog: CatalogContext {
                fs_uuid: UUID,
                catalog_generation: 2,
                slot_store_generation: 1,
                live_view_epoch: 7,
                committed_lsn: 50,
                online_age_ns: 100,
            },
            catalog_sha256,
            protection_sha256,
        },
    )
}

const REQUEST: CaptureRequest = CaptureRequest {
    slot: 6,
    class: SlotClass::OnDemand,
    retention_deadline: 145,
};

#[test]
fn capture_and_retention_replay_bind_one_frozen_view() {
    let (mut disk, checkpoint, before) = fixture();
    let mut recovery = RecoveryWorkspace::new();
    let mut capture = CaptureWorkspace::new();
    let (identity, commit_lsn) = {
        let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
        let (identity, committed) = commit_capture(
            &mut writer,
            before,
            REQUEST,
            &mut capture,
            |plan, identity, images| {
                assert_eq!(plan.log_blocks, 36);
                assert_eq!(identity.capture_commit_lsn, 50);
                assert_eq!(images.len(), 17);
                assert_eq!(images[1].contents, &MIRROR[..SUPER_BYTES]);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((identity.snapshot_id, identity.slot_generation), (5, 4));
        assert_eq!(identity.captured_live_view_epoch, 7);
        assert_eq!(identity.created_online_age_ns, 100);
        (identity, committed.transaction().commit_lsn)
    };
    assert_eq!((disk.writes, disk.flushes), (36, 2));
    assert!(
        !disk
            .blocks
            .contains_key(&(SNAPSHOT_SLOT_START + 6 * SNAPSHOT_STRIDE))
    );

    // Reopen from the actual journal, independent of the original writer.
    let mut recovery = RecoveryWorkspace::new();
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
    assert_eq!(writer.evidence().unwrap().distinct_home_blocks, 17);
    let mut raw = [0; SUPER_BYTES];
    let mut after = before;
    after.catalog.committed_lsn = commit_lsn;
    after.catalog.catalog_generation = 3;
    writer
        .read_committed_at(SNAPSHOT_CATALOG_BLOCK, commit_lsn, &mut raw)
        .unwrap();
    after.catalog_sha256 = Sha256::digest(raw).into();
    let catalog = verify_catalog(SNAPSHOT_CATALOG_BLOCK, &raw, after.catalog, |block, buf| {
        writer
            .read_committed_at(block, commit_lsn, buf)
            .or_else(|error| {
                if block == SNAPSHOT_SLOT_START {
                    writer.read_committed(block, buf)
                } else {
                    Err(error)
                }
            })
    })
    .unwrap();
    assert_eq!(catalog.next_snapshot_id, 6);
    assert!(
        matches!(catalog.entries[6], CatalogEntry::Active(binding) if binding.identity == identity)
    );

    writer
        .read_committed_at(SNAPSHOT_PROTECTION_BLOCK, commit_lsn, &mut raw)
        .unwrap();
    after.protection_sha256 = Sha256::digest(raw).into();
    let mut expected_protection = ProtectionRecord::decode(&raw).unwrap();
    assert_eq!(expected_protection.retention_deadlines[6], 145);
    assert!(!expected_protection.writes_open);
    let first_mirror = SNAPSHOT_SLOT_START + identity.slot * SNAPSHOT_STRIDE + 1;
    let restore_root = [0x6d; 32];
    let restore = verify_restore_source(&mut writer, after, identity, |binding, committed_view| {
        assert_eq!(binding.identity, identity);
        let mut page = [0; SUPER_BYTES];
        committed_view.read(first_mirror, &mut page)?;
        assert_eq!(&page, &MIRROR[..SUPER_BYTES]);
        assert!(matches!(
            committed_view.write(first_mirror, &page),
            Err(Error::Unauthorized)
        ));
        Ok(restore_root)
    })
    .unwrap();
    assert_eq!(restore.fs_uuid, identity.fs_uuid);
    assert_eq!(restore.slot as u32, identity.slot);
    assert_eq!(restore.snapshot_id, identity.snapshot_id);
    assert_eq!(restore.generation, identity.slot_generation);
    assert_eq!(restore.root_hash, restore_root);
    assert!(matches!(
        verify_restore_source(&mut writer, after, identity, |_, _| Err(Error::Unknown)),
        Err(Error::Unknown)
    ));
    assert!(matches!(
        commit_capture(&mut writer, after, REQUEST, &mut capture, |_, _, _| {
            panic!("occupied slot must not reach its reservation")
        }),
        Err(Error::Busy)
    ));
    assert!(matches!(
        extend_retention(&mut writer, after, identity, 144, |_| {
            panic!("shortening must not reach its reservation")
        }),
        Err(Error::Conflict)
    ));
    let extended = extend_retention(&mut writer, after, identity, 150, |plan| {
        assert_eq!(plan.log_blocks, 4);
        Ok(())
    })
    .unwrap();
    let extension_lsn = extended.transaction().commit_lsn;
    writer
        .read_committed_at(SNAPSHOT_PROTECTION_BLOCK, extension_lsn, &mut raw)
        .unwrap();
    expected_protection.retention_deadlines[6] = 150;
    expected_protection.object_generation += 1;
    assert_eq!(ProtectionRecord::decode(&raw).unwrap(), expected_protection);
    assert!(matches!(
        extend_retention(&mut writer, after, identity, 155, |_| panic!(
            "stale owner view"
        )),
        Err(Error::Stale)
    ));
    // The captured mirror is still committed at its original capture.
    writer
        .read_committed_at(first_mirror, commit_lsn, &mut raw)
        .unwrap();
    assert_eq!(&raw, &MIRROR[..SUPER_BYTES]);
}

#[test]
fn preflight_respects_slot_partition_and_uncertain_commit_keeps_writer_closed() {
    let (mut disk, checkpoint, state) = fixture();
    disk.fail_first_flush = true;
    let mut recovery = RecoveryWorkspace::new();
    let mut work = CaptureWorkspace::new();
    let mut writer = RedoWriter::open(&mut disk, &mut recovery, checkpoint).unwrap();
    let wrong_class = CaptureRequest {
        class: SlotClass::Periodic,
        ..REQUEST
    };
    assert!(matches!(
        commit_capture(&mut writer, state, wrong_class, &mut work, |_, _, _| {
            panic!("wrong slot class must not reach its reservation")
        }),
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        commit_capture(&mut writer, state, REQUEST, &mut work, |_, _, _| Err(
            Error::Busy
        )),
        Err(Error::Busy)
    ));
    assert!(matches!(
        commit_capture(&mut writer, state, REQUEST, &mut work, |_, _, _| Ok(())),
        Err(Error::Unknown)
    ));
    assert!(matches!(
        commit_capture(&mut writer, state, REQUEST, &mut work, |_, _, _| panic!(
            "unknown journal"
        )),
        Err(Error::Unknown)
    ));
    assert_eq!((disk.writes, disk.flushes), (35, 1));
}
