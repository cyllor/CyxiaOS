//! Exercise the opt-in native staging glue on a sparse, throw-away host volume.
use std::{collections::BTreeMap, sync::Mutex};

use cyxia_kernel_core::security::{
    Error,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::BLOCK_BYTES,
    file_media_unified_v1::CANONICAL_BUSINESS_START,
    file_media_v0199::{BITMAP_START, crc32c_zeroed},
};

#[path = "../../../kernel/src/arch/aarch64/production/media_staging/authority.rs"]
mod authority;
#[path = "../../../kernel/src/arch/aarch64/production/media_staging/reopen.rs"]
mod reopen;
#[path = "../../../kernel/src/arch/aarch64/production/media_staging/signed.rs"]
mod signed;
#[path = "../../../kernel/src/arch/aarch64/production/media_staging/volume.rs"]
mod volume;
use volume::SnapshotLayout::{
    AllocatedEnvelopes, AllocatedEnvelopesWithFile, AllocatedEnvelopesWithWritableFile,
    EmptyEnvelopes, LegacyZero,
};

#[derive(Default)]
struct Disk {
    blocks: BTreeMap<u32, [u8; BLOCK_BYTES]>,
    reads: u64,
    writes: u64,
    flushes: u64,
    first_flush_writes: Option<u64>,
    fail_before_write: Option<u64>,
    fail_before_flush: Option<u64>,
}

impl EpochBlockIo for Disk {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), Error> {
        self.reads += 1;
        match self.blocks.get(&block) {
            Some(data) => *out = *data,
            None => out.fill(0),
        }
        Ok(())
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_BYTES]) -> Result<(), Error> {
        if self.fail_before_write == Some(self.writes) {
            return Err(Error::Unknown);
        }
        self.writes += 1;
        self.blocks.insert(block, *data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.fail_before_flush == Some(self.flushes) {
            return Err(Error::Unknown);
        }
        self.first_flush_writes.get_or_insert(self.writes);
        self.flushes += 1;
        Ok(())
    }
}

// These native static workspaces belong to one CPU0 at a time.
static STAGING_OWNER: Mutex<()> = Mutex::new(());

#[test]
fn resident_startup_reclaims_genesis_preparations_in_durable_tail_first_order() {
    use cyxia_kernel_core::security::boot_epoch_v1::{BootEpochStoreV1, TlsBootPolicy};
    use reopen::BootLogRecovery;

    let _owner = STAGING_OWNER.lock().unwrap();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let policy = TlsBootPolicy::new(&verified, None).unwrap();
    let mut clean = Disk::default();
    let checkpoint = volume::format(&mut clean, Some(&verified), LegacyZero).unwrap();
    let previous = policy.resident_state(0).unwrap();
    let append = |disk: &mut Disk, previous: &_| {
        authority::allocate_boot(
            disk,
            checkpoint,
            previous,
            authority::BootUpdate::Tls(policy),
            volume::Checkpoints::Resident,
        )
    };
    let interrupted = |writes| {
        let mut disk = Disk {
            blocks: clean.blocks.clone(),
            fail_before_write: Some(writes),
            ..Disk::default()
        };
        assert_eq!(append(&mut disk, &previous).err(), Some(Error::Unknown));
        // Reopen a new owner against the media left by the failed append.
        Disk {
            blocks: disk.blocks,
            ..Disk::default()
        }
    };
    for (writes, cleared) in [0, 1, 2, 2, 3, 3].into_iter().enumerate() {
        let mut disk = interrupted(writes as u64);
        let (selected, mounted, disposition) =
            reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None)
                .unwrap();
        let expected = if cleared == 0 {
            BootLogRecovery::Empty
        } else {
            BootLogRecovery::DiscardedPreparation {
                cleared_blocks: cleared,
            }
        };
        assert_eq!(disposition, expected);
        assert_eq!(selected, checkpoint);
        assert_eq!(mounted.boot.boot_epoch, 0);
        assert_eq!(mounted.security, previous);
        assert_eq!(
            (disk.writes, disk.flushes),
            (cleared.into(), cleared.into())
        );
        assert!(disk.blocks == clean.blocks);
    }

    let full_preparation = interrupted(5);
    let materialized = [
        volume::FIRST_LOG_BLOCK + 3,
        volume::FIRST_LOG_BLOCK + 1,
        volume::FIRST_LOG_BLOCK,
    ];
    for cut in 0..materialized.len() {
        for during_flush in [false, true] {
            let mut disk = Disk {
                blocks: full_preparation.blocks.clone(),
                fail_before_write: (!during_flush).then_some(cut as u64),
                fail_before_flush: during_flush.then_some(cut as u64),
                ..Disk::default()
            };
            assert_eq!(
                reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None)
                    .err(),
                Some(Error::Unknown)
            );
            let zeroed = cut + usize::from(during_flush);
            assert_eq!((disk.writes, disk.flushes), (zeroed as u64, cut as u64));
            for (index, block) in materialized.iter().enumerate() {
                let expected = if index < zeroed {
                    [0; BLOCK_BYTES]
                } else {
                    full_preparation.blocks[block]
                };
                assert_eq!(disk.blocks[block], expected);
            }
            // A failed FLUSH can leave the last zeroed block either durable
            // or absent. This instance observes the write, which is a valid
            // shorter prefix when the new owner reads it after reset.
            disk.fail_before_write = None;
            disk.fail_before_flush = None;
            let (_, mounted, _) =
                reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None)
                    .unwrap();
            assert_eq!(mounted.security, previous);
            assert!(disk.blocks == clean.blocks);
            let (next, _) = append(&mut disk, &mounted.security).unwrap();
            assert_eq!(next, 1);
        }
    }

    for (block, offset) in [
        (volume::FIRST_LOG_BLOCK, 56),
        (volume::FIRST_LOG_BLOCK + 2, 0),
        (volume::FIRST_LOG_BLOCK + 5, 32),
        (BITMAP_START - 1, 0),
    ] {
        let mut disk = Disk {
            blocks: full_preparation.blocks.clone(),
            ..Disk::default()
        };
        disk.blocks.get_mut(&block).unwrap()[offset] ^= 1;
        assert!(
            reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None)
                .is_err()
        );
        assert_eq!((disk.writes, disk.flushes), (0, 0));
    }
    let mut missing = Disk {
        blocks: full_preparation.blocks.clone(),
        ..Disk::default()
    };
    missing
        .blocks
        .insert(volume::FIRST_LOG_BLOCK + 1, [0; BLOCK_BYTES]);
    assert!(
        reopen::recover_resident_with_reconciliation(&mut missing, checkpoint, policy, None)
            .is_err()
    );
    assert_eq!((missing.writes, missing.flushes), (0, 0));

    let mut advanced_home = full_preparation;
    advanced_home.blocks.insert(
        volume::BOOT_HOME,
        BootEpochStoreV1 {
            fs_uuid: previous.fs_uuid,
            boot_epoch: 1,
        }
        .encode()
        .unwrap(),
    );
    assert!(
        reopen::recover_resident_with_reconciliation(&mut advanced_home, checkpoint, policy, None)
            .is_err()
    );
    assert_eq!((advanced_home.writes, advanced_home.flushes), (0, 0));

    // The restarted owner can observe a whole COMMIT even though the old
    // owner's second FLUSH returned UNKNOWN. Protect it before any home write.
    let mut uncertain_commit = Disk {
        blocks: clean.blocks,
        fail_before_flush: Some(1),
        ..Disk::default()
    };
    assert_eq!(
        append(&mut uncertain_commit, &previous).err(),
        Some(Error::Unknown)
    );
    let mut disk = Disk {
        blocks: uncertain_commit.blocks,
        fail_before_flush: Some(0),
        ..Disk::default()
    };
    assert_eq!(
        reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None).err(),
        Some(Error::Unknown)
    );
    assert_eq!(disk.writes, 0);
    disk.fail_before_flush = None;
    let (selected, mounted, disposition) =
        reopen::recover_resident_with_reconciliation(&mut disk, checkpoint, policy, None).unwrap();
    assert_eq!(disk.first_flush_writes, Some(0));
    assert_eq!((selected.generation, selected.checkpoint_lsn), (2, 4));
    assert_eq!(mounted.boot.boot_epoch, 1);
    assert_eq!(disposition, BootLogRecovery::Replayed);
}

#[test]
fn signed_boot_recovery_resumes_at_durable_boundaries() {
    let _owner = STAGING_OWNER.lock().unwrap();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let config = Some(&verified);
    let mut prepared = Disk::default();
    let first = volume::format(&mut prepared, config, LegacyZero).unwrap();
    let mount = volume::mount(&mut prepared, first, config, LegacyZero).unwrap();
    assert_eq!(
        authority::boot_epoch(&mut prepared, first, &mount.security, config),
        Ok(1)
    );

    for completed_writes in 1..=9 {
        let mut disk = Disk {
            blocks: prepared.blocks.clone(),
            ..Disk::default()
        };
        if completed_writes < 9 {
            disk.fail_before_write = Some(completed_writes);
            assert_eq!(
                reopen::recover(&mut disk, first, config, LegacyZero).err(),
                Some(Error::Unknown)
            );
            disk.fail_before_write = None;
        } else {
            // Recovery fully retired the old log, then the boot ended
            // before the next epoch transaction was issued.
            reopen::recover(&mut disk, first, config, LegacyZero).unwrap();
        }
        assert_eq!(disk.writes, completed_writes);
        let selected = reopen::identify(&mut disk, config).unwrap();
        let (checkpoint, mounted) = reopen::recover(&mut disk, selected, config, LegacyZero)
            .unwrap_or_else(|e| panic!("recovery after {completed_writes} writes: {e:?}"));
        assert_eq!((checkpoint.generation, checkpoint.checkpoint_lsn), (2, 4));
        assert_eq!(mounted.boot.boot_epoch, 1);
        assert_eq!(
            authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
            Ok(2)
        );
    }
}

#[test]
fn signed_unified_genesis_matches_the_independent_full_image_vector() {
    use cyxia_kernel_core::security::file_media_v0199::BLOCK_COUNT;
    use sha2::{Digest, Sha256};

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let sb = volume::format(&mut disk, Some(&verified), AllocatedEnvelopes).unwrap();
    let mut hash = Sha256::new();
    let zero = [0; BLOCK_BYTES];
    for block in 0..BLOCK_COUNT {
        hash.update(disk.blocks.get(&block).unwrap_or(&zero));
    }
    assert_eq!(
        format!("{:x}", hash.finalize()),
        include_str!("../../../tools/fixtures/v020-g1-genesis.sha256").trim(),
    );

    let before_mount = (disk.writes, disk.flushes);
    let config = Some(&verified);
    assert_eq!(reopen::identify(&mut disk, config), Ok(sb));
    let mounted = volume::mount(&mut disk, sb, config, AllocatedEnvelopes).unwrap();
    assert_eq!(mounted.security.offline_config_hash, verified.digest());
    assert_eq!(mounted.boot.boot_epoch, 0);
    assert_eq!(mounted.system_blocks, 151);
    assert_eq!(mounted.structure.live_inodes, 9);
    assert_eq!(mounted.structure.directory_entries, 0);
    assert_eq!(mounted.receipts.occupied, 0);
    assert_eq!((disk.writes, disk.flushes), before_mount);
}

#[test]
fn lifecycle_reopen_uses_the_signed_volume_and_generations() {
    use cyxia_kernel_core::security::offline_config_v1::{
        CatalogBindings, HEADER, SIGNATURE_LABEL, VerifiedOfflineConfig,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let _owner = STAGING_OWNER.lock().unwrap();
    let key = SigningKey::from_bytes(&[0x37; 32]);
    let uuid = *b"CYX-LIFECYCLE-02";
    let mut wire = signed::WIRE[..signed::WIRE.len() - 64].to_vec();
    wire[16..32].copy_from_slice(&uuid);
    for (at, generation) in [(32, 7u64), (40, 9), (48, 4), (56, 3)] {
        wire[at..at + 8].copy_from_slice(&generation.to_le_bytes());
    }
    for (slot, principal) in wire[HEADER..HEADER + 256].chunks_exact_mut(16).enumerate() {
        principal[..8].copy_from_slice(&(40 + slot as u64).to_le_bytes());
        principal[8..].copy_from_slice(&3u64.to_le_bytes());
    }
    let payload_hash = Sha256::digest(&wire[HEADER..]);
    wire[160..192].copy_from_slice(&payload_hash);
    let bindings = CatalogBindings {
        rule_generation: 9,
        security_generation: 4,
        key_generation: 3,
        rule_hash: wire[64..96].try_into().unwrap(),
        security_hash: wire[96..128].try_into().unwrap(),
        key_manifest_hash: wire[128..160].try_into().unwrap(),
    };
    let signature = key.sign(&[SIGNATURE_LABEL, &wire].concat()).to_bytes();
    wire.extend_from_slice(&signature);
    let verified = VerifiedOfflineConfig::verify(
        &wire,
        &key.verifying_key().to_bytes(),
        bindings,
        &mut [0; 1024],
        |header, _, lists| signed::verify_lifecycle_payload(header, lists),
    )
    .unwrap();
    let config = Some(&verified);

    let mut disk = Disk::default();
    let first = volume::format(&mut disk, config, LegacyZero).unwrap();
    let mount = volume::mount(&mut disk, first, config, LegacyZero).unwrap();
    assert_eq!(mount.security.fs_uuid, uuid);
    assert_eq!(mount.security.offline_config_generation, 7);
    assert_eq!(mount.security.rule_min_generation, 9);
    assert_eq!(mount.security.security_min_generation, 4);
    assert_eq!(mount.security.key_generation, 3);
    assert_eq!(
        authority::boot_epoch(&mut disk, first, &mount.security, config),
        Ok(1)
    );

    let other = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let io_before = (disk.writes, disk.flushes);
    assert_eq!(
        reopen::identify(&mut disk, Some(&other)),
        Err(Error::Conflict)
    );
    assert_eq!((disk.writes, disk.flushes), io_before);

    let selected = reopen::identify(&mut disk, config).unwrap();
    let (checkpoint, mount) = reopen::recover(&mut disk, selected, config, LegacyZero).unwrap();
    assert_eq!((checkpoint.fs_uuid, mount.boot.boot_epoch), (uuid, 1));
    assert_eq!(mount.security.offline_config_hash, verified.digest());
    let (_, owner) =
        authority::boot_epoch_owner(&mut disk, checkpoint, &mount.security, config).unwrap();
    assert_eq!(
        owner.confirmed_boot_policy(&verified).unwrap().boot_epoch(),
        2
    );
}

#[test]
fn signed_resident_reopens_a_baseline_volume_with_ordinary_file_homes() {
    use cyxia_kernel_core::security::{
        file_format_v1::{self, FormatWorkspace, SCRATCH_FILE_BLOCK, SCRATCH_FILE_DATA},
        file_media_v0199::BLOCK_COUNT,
        recovery_v1::{RecoveryWorkspace, RedoImage, RedoWriter, retire_checkpointed_log},
    };

    let _owner = STAGING_OWNER.lock().unwrap();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let config = Some(&verified);
    let mut disk = Disk::default();
    let first = file_format_v1::format_baseline_with_fsync_scratch_file(
        &mut disk,
        BLOCK_COUNT,
        &volume::format_manifest(config),
        &mut FormatWorkspace::new(),
    )
    .unwrap()
    .superblock;
    let mut file = [0; BLOCK_BYTES];
    disk.read(SCRATCH_FILE_BLOCK, &mut file).unwrap();
    assert_eq!(&file[..SCRATCH_FILE_DATA.len()], SCRATCH_FILE_DATA);

    let (checkpoint, mounted) = reopen::recover_resident(&mut disk, first, &verified).unwrap();
    assert_eq!(mounted.structure.directory_entries, 1);
    assert_eq!(mounted.boot.boot_epoch, 0);
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
        Ok(1)
    );
    let (checkpoint, mounted) = reopen::recover_resident(&mut disk, first, &verified).unwrap();
    assert_eq!(mounted.structure.directory_entries, 1);
    assert_eq!(mounted.boot.boot_epoch, 1);
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
        Ok(2)
    );

    // A normal directory metadata transaction advances the checkpoint beyond
    // the boot-only LSN. Provision it through the frozen v1 redo writer.
    let mut directory = [0; BLOCK_BYTES];
    disk.read(CANONICAL_BUSINESS_START, &mut directory).unwrap();
    directory[16..26].copy_from_slice(b"status.txt");
    let crc = crc32c_zeroed(&directory[..128], 124).unwrap();
    directory[124..128].copy_from_slice(&crc.to_le_bytes());
    let images = [RedoImage {
        home: CANONICAL_BUSINESS_START,
        contents: &directory,
    }];
    let mut journal = RecoveryWorkspace::new();
    let mut writer = RedoWriter::open(&mut disk, &mut journal, checkpoint).unwrap();
    let plan = writer.prepare(images.len()).unwrap();
    writer.append(plan, &images, |_| Ok(())).unwrap();
    let (_, checkpoint) = writer
        .checkpoint_verified(|disk, sb| {
            volume::validate_resident_homes(disk, sb, 2, &verified).map(|_| ())
        })
        .unwrap();
    assert_eq!((checkpoint.generation, checkpoint.checkpoint_lsn), (3, 11));
    retire_checkpointed_log(&mut disk, &mut journal, checkpoint).unwrap();

    let (selected, mounted) = reopen::recover_resident(&mut disk, checkpoint, &verified).unwrap();
    assert_eq!(selected, checkpoint);
    assert_eq!(mounted.structure.directory_entries, 1);
    assert_eq!(mounted.boot.boot_epoch, 2);
    let (epoch, _) = authority::boot_epoch_owner_for(
        &mut disk,
        checkpoint,
        &mounted.security,
        config,
        volume::Checkpoints::Resident,
    )
    .unwrap();
    assert_eq!(epoch, 3);
    let (selected, mounted) = reopen::recover_resident(&mut disk, checkpoint, &verified).unwrap();
    assert_eq!((selected.generation, selected.checkpoint_lsn), (4, 15));
    assert_eq!(mounted.boot.boot_epoch, 3);
    assert_eq!(disk.blocks[&CANONICAL_BUSINESS_START], directory);
    let mut reopened = [0; BLOCK_BYTES];
    disk.read(SCRATCH_FILE_BLOCK, &mut reopened).unwrap();
    assert_eq!(reopened, file);
}

#[test]
fn signed_tls_boot_pair_rotates_replays_and_revokes_without_changing_file_homes() {
    use cyxia_kernel_core::security::{
        boot_epoch_v1::{TlsBootPolicy, TlsBootTransition},
        network::deployment::{BYTES as MANIFEST_BYTES, KeyManifest},
        offline_config_v1::{CatalogBindings, SIGNATURE_LABEL, VerifiedOfflineConfig},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let _owner = STAGING_OWNER.lock().unwrap();
    let key = SigningKey::from_bytes(&[0x39; 32]);
    let public = key.verifying_key().to_bytes();
    let sign_config = |generation: u64, key_generation: u64, manifest: &[u8]| {
        let mut wire = signed::WIRE[..signed::WIRE.len() - 64].to_vec();
        wire[32..40].copy_from_slice(&generation.to_le_bytes());
        wire[56..64].copy_from_slice(&key_generation.to_le_bytes());
        wire[128..160].copy_from_slice(&Sha256::digest(manifest));
        let signature = key.sign(&[SIGNATURE_LABEL, &wire].concat()).to_bytes();
        wire.extend_from_slice(&signature);
        wire
    };
    fn verify<'a>(wire: &'a [u8], public: &[u8; 32]) -> VerifiedOfflineConfig<'a> {
        let bindings = CatalogBindings {
            rule_generation: u64::from_le_bytes(wire[40..48].try_into().unwrap()),
            security_generation: u64::from_le_bytes(wire[48..56].try_into().unwrap()),
            key_generation: u64::from_le_bytes(wire[56..64].try_into().unwrap()),
            rule_hash: wire[64..96].try_into().unwrap(),
            security_hash: wire[96..128].try_into().unwrap(),
            key_manifest_hash: wire[128..160].try_into().unwrap(),
        };
        VerifiedOfflineConfig::verify(
            wire,
            public,
            bindings,
            &mut [0; 1024],
            |header, _, lists| signed::verify_lifecycle_payload(header, lists),
        )
        .unwrap()
    }
    let network_manifest = |generation: u64, predecessor: [u8; 32], enabled: bool| {
        let mut wire = [0u8; MANIFEST_BYTES];
        wire[..8].copy_from_slice(b"CYXNET01");
        for at in [8, 16, 24] {
            wire[at..at + 8].copy_from_slice(&generation.to_le_bytes());
        }
        wire[32..64].copy_from_slice(&predecessor);
        if enabled {
            wire[64..72].copy_from_slice(&[10, 0, 2, 15, 10, 0, 2, 2]);
            wire[72] = 24;
            wire[73] = 1;
            wire[74..76].copy_from_slice(&7u16.to_le_bytes());
            wire[76..82].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
            wire[88..120].fill(4 + generation as u8);
            wire[120..152].fill(1 + generation as u8);
            wire[152..184].fill(7);
        } else {
            wire[73] = 2;
        }
        wire
    };
    let old_manifest = network_manifest(1, [0; 32], true);
    let old_wire = sign_config(1, 1, &old_manifest);
    let old_config = verify(&old_wire, &public);
    let old_manifest = KeyManifest::parse(&old_manifest).unwrap().unwrap();
    let old = TlsBootPolicy::new(&old_config, Some(old_manifest)).unwrap();
    let active_manifest = network_manifest(2, old_config.digest(), true);
    let active_wire = sign_config(2, 2, &active_manifest);
    let active_config = verify(&active_wire, &public);
    let active_manifest = KeyManifest::parse(&active_manifest).unwrap().unwrap();
    let active = TlsBootPolicy::new(&active_config, Some(active_manifest)).unwrap();
    let rotate = TlsBootTransition::new(old, active).unwrap();
    let mut unrotated_manifest = network_manifest(3, active_config.digest(), true);
    let listener = active_manifest.listener().unwrap();
    unrotated_manifest[88..120].copy_from_slice(&listener.local_pin);
    unrotated_manifest[120..152].copy_from_slice(&listener.peer_pin);
    let unrotated_wire = sign_config(3, 3, &unrotated_manifest);
    let unrotated_config = verify(&unrotated_wire, &public);
    let unrotated = TlsBootPolicy::new(
        &unrotated_config,
        KeyManifest::parse(&unrotated_manifest).unwrap(),
    )
    .unwrap();
    assert_eq!(
        TlsBootTransition::new(active, unrotated).err(),
        Some(Error::Conflict),
    );
    let revoked_manifest = network_manifest(3, active_config.digest(), false);
    let revoked_wire = sign_config(3, 3, &revoked_manifest);
    let revoked_config = verify(&revoked_wire, &public);
    let revoked_manifest = KeyManifest::parse(&revoked_manifest).unwrap().unwrap();
    let revoked = TlsBootPolicy::new(&revoked_config, Some(revoked_manifest)).unwrap();
    let revoke = TlsBootTransition::new(active, revoked).unwrap();
    assert!(TlsBootTransition::new(old, revoked).is_err());
    assert!(TlsBootTransition::new(revoked, active).is_err());

    let mut disk = Disk::default();
    let first = volume::format(&mut disk, Some(&old_config), LegacyZero).unwrap();
    let mounted = volume::mount(&mut disk, first, Some(&old_config), LegacyZero).unwrap();
    assert_eq!(
        authority::boot_epoch(&mut disk, first, &mounted.security, Some(&old_config)),
        Ok(1)
    );
    let immutable = disk.blocks[&CANONICAL_BUSINESS_START];
    let (checkpoint, mounted) =
        reopen::recover_resident_with_tls(&mut disk, first, active, Some(rotate)).unwrap();
    assert_eq!(mounted.security, old.resident_state(1).unwrap());
    assert!(reopen::recover_resident_with_tls(&mut disk, checkpoint, active, None).is_err());

    let boot = |d: &mut Disk, checkpoint, before: &_, update| {
        authority::allocate_boot(d, checkpoint, before, update, volume::Checkpoints::Resident)
    };
    for update in [
        authority::BootUpdate::Tls(old),
        authority::BootUpdate::Rotate(rotate),
    ] {
        let mut incomplete = Disk {
            blocks: disk.blocks.clone(),
            fail_before_write: Some(5),
            ..Disk::default()
        };
        assert_eq!(
            boot(&mut incomplete, checkpoint, &mounted.security, update).err(),
            Some(Error::Unknown)
        );
        incomplete.fail_before_write = None;
        if matches!(update, authority::BootUpdate::Rotate(_)) {
            let effects = (incomplete.writes, incomplete.flushes);
            assert!(
                reopen::recover_resident_with_tls(&mut incomplete, checkpoint, old, None).is_err()
            );
            assert_eq!((incomplete.writes, incomplete.flushes), effects);
        }
        let (unchanged_checkpoint, recovered) =
            reopen::recover_resident_with_tls(&mut incomplete, checkpoint, active, Some(rotate))
                .unwrap();
        assert_eq!(unchanged_checkpoint, checkpoint);
        assert_eq!(recovered.security, mounted.security);
        assert_eq!(recovered.boot, mounted.boot);
        assert!(incomplete.blocks == disk.blocks);
    }

    let (epoch, authority) = boot(
        &mut disk,
        checkpoint,
        &mounted.security,
        authority::BootUpdate::Rotate(rotate),
    )
    .unwrap();
    assert_eq!(epoch, 2);
    let policy = authority.confirmed_boot_policy(&active_config).unwrap();
    assert!(active_manifest.installation().authorize(policy).is_ok());
    assert!(old_manifest.installation().authorize(policy).is_err());
    let after = authority::verified_pair_state_for(&mut disk, checkpoint, |state| {
        assert_eq!(*state, active.resident_state(2)?);
        Ok(())
    })
    .unwrap();
    volume::confirm_tls_receipts(&mounted, &after, rotate).unwrap();
    let io = (disk.writes, disk.flushes);
    assert!(reopen::recover_resident_with_tls(&mut disk, checkpoint, old, None).is_err());
    assert_eq!((disk.writes, disk.flushes), io);
    for before_write in 0..9 {
        let mut reboot = Disk {
            blocks: disk.blocks.clone(),
            fail_before_write: Some(before_write),
            ..Disk::default()
        };
        assert_eq!(
            reopen::recover_resident_with_tls(&mut reboot, checkpoint, active, Some(rotate)).err(),
            Some(Error::Unknown)
        );
        reboot.fail_before_write = None;
        let selected = volume::read_checkpoint_for(
            &mut reboot,
            &mut [0; BLOCK_BYTES],
            Some(&active_config),
            volume::Checkpoints::Resident,
        )
        .unwrap();
        let (_, mounted) =
            reopen::recover_resident_with_tls(&mut reboot, selected, active, Some(rotate)).unwrap();
        assert_eq!(mounted.security, after);
    }

    // The native owner retires the key-changing redo before service
    // publication; the next deployment needs only its public predecessor.
    let (checkpoint, _) =
        reopen::recover_resident_with_tls(&mut disk, checkpoint, active, Some(rotate)).unwrap();
    let (checkpoint, mounted) =
        reopen::recover_resident_with_tls(&mut disk, checkpoint, revoked, Some(revoke)).unwrap();
    let (epoch, authority) = boot(
        &mut disk,
        checkpoint,
        &mounted.security,
        authority::BootUpdate::Rotate(revoke),
    )
    .unwrap();
    assert_eq!(epoch, 3);
    let policy = authority.confirmed_boot_policy(&revoked_config).unwrap();
    assert_eq!(
        revoked_manifest.installation().authorize(policy).err(),
        Some(Error::Unauthorized)
    );
    assert_eq!(
        policy.service_generation(cyxia_kernel_core::control_plane::role_manifest_v0199::ROLES[0]),
        Ok(1)
    );
    assert!(reopen::recover_resident_with_tls(&mut disk, checkpoint, active, None).is_err());
    let (checkpoint, mounted) =
        reopen::recover_resident_with_tls(&mut disk, checkpoint, revoked, Some(revoke)).unwrap();
    assert_eq!(mounted.security, revoked.resident_state(3).unwrap());
    assert_eq!(disk.blocks[&CANONICAL_BUSINESS_START], immutable);
    let (epoch, authority) = boot(
        &mut disk,
        checkpoint,
        &mounted.security,
        authority::BootUpdate::Tls(revoked),
    )
    .unwrap();
    assert_eq!(epoch, 4);
    let policy = authority.confirmed_boot_policy(&revoked_config).unwrap();
    assert_eq!(
        revoked_manifest.installation().authorize(policy).err(),
        Some(Error::Unauthorized)
    );
}

#[test]
fn staging_rejects_a_dirty_journal_tail_before_granting_a_boot_epoch() {
    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let sb = volume::format(&mut disk, None, LegacyZero).unwrap();
    let io_before_mount = (disk.writes, disk.flushes);

    let last = BITMAP_START - 1;
    disk.blocks.get_mut(&last).unwrap()[BLOCK_BYTES - 1] = 1;
    let reads_before_mount = disk.reads;
    assert_eq!(
        volume::mount(&mut disk, sb, None, LegacyZero).err(),
        Some(Error::Conflict)
    );
    assert_eq!(disk.reads - reads_before_mount, 4096);
    assert_eq!((disk.writes, disk.flushes), io_before_mount);

    disk.blocks.get_mut(&last).unwrap()[BLOCK_BYTES - 1] = 0;
    let mount = volume::mount(&mut disk, sb, None, LegacyZero).unwrap();
    assert_eq!(volume::unified_map(&mut disk, sb, LegacyZero), Ok(151));
    assert_eq!((disk.writes, disk.flushes), io_before_mount);
    let epoch = authority::boot_epoch(&mut disk, sb, &mount.security, None).unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(authority::admission_flow(epoch), Ok(()));
    // The epoch journal append must leave the reserved snapshot ranges empty.
    assert_eq!(volume::unified_map(&mut disk, sb, LegacyZero), Ok(151));
    disk.blocks
        .insert(CANONICAL_BUSINESS_START - 1, [1; BLOCK_BYTES]);
    assert_eq!(
        volume::unified_map(&mut disk, sb, LegacyZero),
        Err(Error::Conflict)
    );
    assert_eq!(
        (disk.writes, disk.flushes),
        (io_before_mount.0 + 6, io_before_mount.1 + 2)
    );
    let corrupt_io = (disk.writes, disk.flushes);
    assert_eq!(
        reopen::recover(&mut disk, sb, None, LegacyZero).err(),
        Some(Error::Conflict)
    );
    disk.blocks.remove(&(CANONICAL_BUSINESS_START - 1));

    // Both a valid foreign UUID and a corrupt single copy deny reopening.
    let saved_headers = [disk.blocks[&0], disk.blocks[&1]];
    for i in 0..2 {
        let raw = disk.blocks.get_mut(&i).unwrap();
        raw[16..32].fill(9);
        let crc = crc32c_zeroed(raw, 76).unwrap();
        raw[76..80].copy_from_slice(&crc.to_le_bytes());
    }
    assert_eq!(reopen::identify(&mut disk, None), Err(Error::Conflict));
    disk.blocks.insert(0, saved_headers[0]);
    disk.blocks.get_mut(&1).unwrap()[76] ^= 1;
    assert!(reopen::identify(&mut disk, None).is_err());
    disk.blocks.insert(1, saved_headers[1]);
    let mut blank = Disk::default();
    assert!(reopen::identify(&mut blank, None).is_err());
    assert_eq!((blank.writes, blank.flushes), (0, 0));

    // A malformed transaction, a nonempty tail and a foreign committed policy
    // each stop before any writes, including a checkpoint or journal reset.
    disk.blocks.get_mut(&7).unwrap()[0] ^= 1;
    assert!(reopen::recover(&mut disk, sb, None, LegacyZero).is_err());
    disk.blocks.get_mut(&7).unwrap()[0] ^= 1;
    disk.blocks.get_mut(&last).unwrap()[0] = 1;
    assert_eq!(
        reopen::recover(&mut disk, sb, None, LegacyZero).err(),
        Some(Error::Conflict)
    );
    disk.blocks.get_mut(&last).unwrap()[0] = 0;
    let mut foreign_policy = volume::security(None);
    foreign_policy.key_generation += 1;
    let original = disk
        .blocks
        .insert(volume::SECURITY_HOME, foreign_policy.encode().unwrap())
        .unwrap();
    assert_eq!(
        reopen::recover(&mut disk, sb, None, LegacyZero).err(),
        Some(Error::Conflict)
    );
    disk.blocks.insert(volume::SECURITY_HOME, original);
    assert_eq!((disk.writes, disk.flushes), corrupt_io);

    let immutable = disk
        .blocks
        .iter()
        .filter(|(b, _)| **b >= 8 && **b != volume::BOOT_HOME && **b != volume::SECURITY_HOME)
        .map(|(b, raw)| (*b, *raw))
        .collect::<BTreeMap<_, _>>();
    // Two reopens exercise both slots of the alternating checkpoint.
    for prior in 1..=2 {
        let selected = reopen::identify(&mut disk, None).unwrap();
        let before = (disk.writes, disk.flushes);
        let (checkpoint, mounted) = reopen::recover(&mut disk, selected, None, LegacyZero).unwrap();
        assert_eq!(checkpoint.generation, prior + 1);
        assert_eq!(checkpoint.checkpoint_lsn, prior * 4);
        assert_eq!(mounted.boot.boot_epoch, prior);
        assert_eq!(
            mounted.security,
            volume::expected_state(prior, None).unwrap()
        );
        let confirmed =
            authority::boot_epoch(&mut disk, checkpoint, &mounted.security, None).unwrap();
        assert_eq!(confirmed, prior + 1);
        assert_eq!(authority::admission_flow(confirmed), Ok(()));
        assert_eq!(
            authority::verify_previous_pair(&mut disk, checkpoint, None),
            Ok(confirmed)
        );
        assert_eq!((disk.writes - before.0, disk.flushes - before.1), (15, 5));
    }
    for (block, raw) in immutable {
        assert_eq!(disk.blocks[&block], raw);
    }
}

#[test]
fn signed_scratch_checks_envelope_and_mounted_state_before_mutation() {
    use cyxia_kernel_core::security::offline_config_v1::{HEADER, SIGNATURE_LABEL};
    use ed25519_dalek::{Signer, SigningKey};
    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let mut scratch = [0; 1024];

    // The wrong TEST policy can carry a perfectly valid signature. Use the
    // public RFC 8032 test key to exercise the signed schema and UUID checks.
    let test_key = SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let mut bad_signature = signed::WIRE.to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut bad_payload = signed::WIRE.to_vec();
    bad_payload[HEADER] ^= 1;
    let mut bad_catalog = signed::WIRE.to_vec();
    bad_catalog[64] ^= 1;
    let mut cases = vec![
        (vec![], Error::Invalid),
        (bad_signature, Error::Unauthorized),
        (bad_payload, Error::Conflict),
        (bad_catalog, Error::Conflict),
    ];
    for offset in [16, 32, 192, 200] {
        let (body, _) = signed::WIRE.split_at(signed::WIRE.len() - 64);
        let mut body = body.to_vec();
        body[offset] = 2;
        let signature = test_key.sign(&[SIGNATURE_LABEL, &body].concat());
        body.extend_from_slice(&signature.to_bytes());
        cases.push((body, Error::Unauthorized));
    }
    for (bad, expected) in cases {
        let result = signed::verify(&bad, &mut scratch)
            .and_then(|verified| volume::format(&mut disk, Some(&verified), LegacyZero));
        assert_eq!(result.err(), Some(expected));
        assert_eq!((disk.reads, disk.writes, disk.flushes), (0, 0, 0));
    }

    let verified = signed::verify(signed::WIRE, &mut scratch).unwrap();
    assert!(scratch.iter().all(|&byte| byte == 0));
    let config = Some(&verified);
    let sb = volume::format(&mut disk, config, LegacyZero).unwrap();
    let mount = volume::mount(&mut disk, sb, config, LegacyZero).unwrap();
    assert_eq!(mount.security.offline_config_hash, verified.digest());
    assert_eq!(
        authority::boot_epoch(&mut disk, sb, &mount.security, config),
        Ok(1)
    );
    let before = (disk.writes, disk.flushes);
    // Unsigned and signed volumes cannot borrow each other's epoch.
    assert_eq!(
        reopen::recover(&mut disk, sb, None, LegacyZero).err(),
        Some(Error::Conflict)
    );
    // Exchange valid six-block transactions with a legacy disk. The signed
    // home is authentic and the transplanted redo is internally consistent;
    // its foreign committed digest alone must fence replay before any write.
    let mut legacy = Disk::default();
    let legacy_sb = volume::format(&mut legacy, None, LegacyZero).unwrap();
    let legacy_mount = volume::mount(&mut legacy, legacy_sb, None, LegacyZero).unwrap();
    assert_eq!(
        authority::boot_epoch(&mut legacy, legacy_sb, &legacy_mount.security, None),
        Ok(1)
    );
    let legacy_io = (legacy.writes, legacy.flushes);
    assert_eq!(
        reopen::recover(&mut legacy, legacy_sb, config, LegacyZero).err(),
        Some(Error::Conflict)
    );
    assert_eq!((legacy.writes, legacy.flushes), legacy_io);
    let range = volume::FIRST_LOG_BLOCK..volume::FIRST_LOG_BLOCK + authority::BOOT_LOG_BLOCKS;
    for block in range.clone() {
        std::mem::swap(
            disk.blocks.get_mut(&block).unwrap(),
            legacy.blocks.get_mut(&block).unwrap(),
        );
    }
    assert_eq!(
        reopen::recover(&mut disk, sb, config, LegacyZero).err(),
        Some(Error::Conflict)
    );
    assert_eq!((disk.writes, disk.flushes), before);
    for block in range {
        std::mem::swap(
            disk.blocks.get_mut(&block).unwrap(),
            legacy.blocks.get_mut(&block).unwrap(),
        );
    }
    let original = disk.blocks[&volume::SECURITY_HOME];
    let state = mount.security;
    let mut wrong_hash = state.offline_config_hash;
    wrong_hash[0] ^= 1;
    use cyxia_kernel_core::security::file_index_v0199::SecurityStateStoreV2 as State;
    for (mutated, expected) in [
        (
            State {
                offline_config_hash: wrong_hash,
                ..state
            },
            Error::Conflict,
        ),
        (
            State {
                offline_config_generation: 2,
                ..state
            },
            Error::Stale,
        ),
        (
            State {
                rule_min_generation: 2,
                ..state
            },
            Error::Stale,
        ),
        (
            State {
                security_min_generation: 2,
                ..state
            },
            Error::Stale,
        ),
        (
            State {
                key_generation: 2,
                ..state
            },
            Error::Stale,
        ),
    ] {
        disk.blocks
            .insert(volume::SECURITY_HOME, mutated.encode().unwrap());
        assert_eq!(
            reopen::recover(&mut disk, sb, config, LegacyZero).err(),
            Some(expected)
        );
        assert_eq!(
            authority::boot_epoch(&mut disk, sb, &mutated, config),
            Err(expected)
        );
    }
    disk.blocks.insert(volume::SECURITY_HOME, original);
    assert_eq!((disk.writes, disk.flushes), before);

    let (checkpoint, mount) = reopen::recover(&mut disk, sb, config, LegacyZero).unwrap();
    assert_eq!(mount.security.last_boot_epoch, 1);
    assert_eq!(mount.security.offline_config_hash, verified.digest());
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mount.security, config),
        Ok(2)
    );
    assert_eq!(
        authority::verify_previous_pair(&mut disk, checkpoint, config),
        Ok(2)
    );
    assert_eq!(
        volume::unified_map(&mut disk, checkpoint, LegacyZero),
        Ok(151)
    );
}

#[test]
fn signed_startup_requires_authority_before_io_and_binds_exact_committed_state() {
    use cyxia_kernel_core::{
        control_plane::role_manifest_v0199::ROLES,
        security::{
            boot_epoch_v1::{BootEpochAuthority, BootEpochTx, BootPairRedo},
            durable_role_epoch_v0199::SlotBinding,
        },
    };

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let sb = volume::format(&mut disk, Some(&verified), LegacyZero).unwrap();
    let state_raw = disk.blocks[&volume::SECURITY_HOME];
    let boot_raw = disk.blocks[&volume::BOOT_HOME];
    let sb_raw = disk.blocks[&0];
    let slots = core::array::from_fn(|index| SlotBinding {
        role: ROLES[index],
        slot: index as u8,
    });
    let tx = BootEpochTx {
        superblock_raw: &sb_raw,
        first_log_block: volume::FIRST_LOG_BLOCK,
        state_home: volume::SECURITY_HOME,
        boot_home: volume::BOOT_HOME,
        txid: sb.generation,
        commit_lsn: sb.checkpoint_lsn + 4,
    };
    let mut pair = BootPairRedo::new();
    let mut recovered = BootEpochAuthority::open(&state_raw, &boot_raw, slots, |_| Ok(())).unwrap();
    let before = (disk.reads, disk.writes, disk.flushes);
    assert_eq!(
        recovered.allocate_for_startup(&mut disk, &mut pair, tx, &verified),
        Err(Error::Unauthorized)
    );
    assert_eq!((disk.reads, disk.writes, disk.flushes), before);
    assert_eq!(recovered.confirmed_epoch(), None);
    assert!(matches!(
        recovered.confirmed_boot_policy(&verified),
        Err(Error::Unauthorized)
    ));

    let mut startup =
        BootEpochAuthority::open_for_startup(&state_raw, &boot_raw, slots, &verified, |_| Ok(()))
            .unwrap();
    assert!(matches!(
        startup.confirmed_boot_policy(&verified),
        Err(Error::Unauthorized)
    ));
    let binding = startup
        .allocate_for_startup(&mut disk, &mut pair, tx, &verified)
        .unwrap();
    assert_eq!(binding.epoch(), 1);
    let state = authority::verified_pair_state(&mut disk, sb, Some(&verified)).unwrap();
    assert_eq!(binding.verify_state(&state), Ok(()));
    let policy = startup.confirmed_boot_policy(&verified).unwrap();
    assert_eq!(policy.boot_epoch(), binding.epoch());
    check_boot_scoped_ipc(&policy);
    let mut other = state;
    other.service_generations[0] += 1;
    assert_eq!(verified.check_committed(&other), Ok(()));
    assert_eq!(binding.verify_state(&other), Err(Error::Conflict));
    let before_retry = (disk.reads, disk.writes, disk.flushes);
    assert_eq!(
        startup.allocate_for_startup(&mut disk, &mut pair, tx, &verified),
        Err(Error::Conflict)
    );
    assert_eq!((disk.reads, disk.writes, disk.flushes), before_retry);
}

fn check_boot_scoped_ipc(
    policy: &cyxia_kernel_core::security::durable_role_epoch_v0199::ConfirmedBootPolicy<'_>,
) {
    use cyxia_kernel_core::{
        control_plane::{
            Identity,
            control_rpc_v1::Error as IpcError,
            role_manifest_v0199::{NativeRole, NativeRoleManifest, PrivateRegion, ROLES},
        },
        security::{
            cap_record_v3::{CapRecordV3, IPC_SEND, Label, StaticControlCaps},
            ipc_receive_v3::{DirectionalEndpoint, Endpoint, svc},
        },
    };
    // Host fixture for the independently authorized catalog and live registry.
    let manifest = NativeRoleManifest {
        online_mask: 15,
        other_protected_pool_bytes: 4096,
        other_control_ns_per_100ms: 100,
        members: core::array::from_fn(|index| NativeRole {
            role: ROLES[index],
            actor: Identity {
                id: u64::from(ROLES[index].id()),
                generation: policy.service_generation(ROLES[index]).unwrap(),
            },
            ttbr0_root: 0x100000 + index as u64 * 4096,
            private_rw: PrivateRegion {
                base: 0x200000 + index as u64 * 4096,
                bytes: 4096,
            },
            caps: ROLES[index].allowed_caps(),
            control_ns_per_100ms: 100,
            cpu_mask: 1,
            thread_count: 1,
            endpoint_id: 10 + index as u64,
        }),
    };
    let sender = manifest.members[0].actor;
    let receiver = manifest.members[2].actor;
    let target = Identity {
        id: 20,
        generation: 1,
    };
    let label = Label::AdviceSend;
    let record = CapRecordV3 {
        cap_id: 1,
        holder: sender,
        target,
        parent_cap_id: 0,
        parent_generation: 0,
        deny_generation: 1,
        rights: IPC_SEND,
        object_kind: 4,
        state: 1,
        depth: 0,
        source_role: u32::from(ROLES[0].id()),
        owner_group: u32::MAX,
        record_generation: 1,
    };
    let mut caps = StaticControlCaps::<2>::new(policy);
    assert_eq!(
        caps.issue_root(policy, &manifest, label, record, |_, _| Err(
            Error::Unauthorized
        )),
        Err(Error::Unauthorized)
    );
    let handle = caps
        .issue_root(
            policy,
            &manifest,
            label,
            record,
            |actual_label, actual_record| {
                assert_eq!((actual_label, *actual_record), (label, record));
                Ok(())
            },
        )
        .unwrap();
    let endpoint = Endpoint {
        id: target.id,
        generation: target.generation,
        receiver,
    };
    let mut queue = DirectionalEndpoint::<2>::new(endpoint, sender).unwrap();
    let mut regs = [0; 31];
    regs[..6].copy_from_slice(&[handle, 0x1000, 1, 1, 0, 1]);
    regs[8] = 0x30;
    let valid = manifest.validated().unwrap();
    let caller = svc::Caller {
        policy,
        manifest: &valid,
        actor: sender,
        cpu: 0,
        abi: 3,
    };
    assert_eq!(
        svc::send(
            &mut queue,
            &caps,
            caller,
            0x5600_0000,
            &regs,
            label,
            b"A",
            |actual| {
                assert_eq!(*actual, record);
                Ok(())
            },
            0,
            |_| Ok(())
        ),
        Ok(())
    );

    let mut replacement = manifest;
    replacement.members[0].actor.generation += 1;
    let replaced = replacement.validated().unwrap();
    let stale = svc::Caller {
        manifest: &replaced,
        ..caller
    };
    regs[3] = 2;
    assert_eq!(
        svc::send(
            &mut queue,
            &caps,
            stale,
            0x5600_0000,
            &regs,
            label,
            b"B",
            |_| panic!("stale actor reached live object check"),
            0,
            |_| panic!("stale actor reached IPC payload admission")
        ),
        Err(IpcError::Auth)
    );
    assert_eq!(queue.pending(), 1);
}

#[test]
fn staging_snapshot_envelopes_are_checked_before_replay() {
    use cyxia_kernel_core::security::file_media_unified_v1::{
        ENVELOPE_BYTES, ObjectEnvelope, SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_PROTECTION_BLOCK,
        SNAPSHOT_REQUEST_START, SNAPSHOT_SLOT_START, UnifiedSystemKind, decode_object_envelope,
        encode_object_envelope,
    };

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let mut scratch = [0; 1024];
    let verified = signed::verify(signed::WIRE, &mut scratch).unwrap();
    let config = Some(&verified);
    let sb = volume::format(&mut disk, config, EmptyEnvelopes).unwrap();
    let heads = [
        (UnifiedSystemKind::SnapshotCatalog, SNAPSHOT_CATALOG_BLOCK),
        (UnifiedSystemKind::SnapshotSlot, SNAPSHOT_SLOT_START),
        (UnifiedSystemKind::SnapshotRequest, SNAPSHOT_REQUEST_START),
        (
            UnifiedSystemKind::SnapshotProtection,
            SNAPSHOT_PROTECTION_BLOCK,
        ),
    ];
    let saved = heads.map(|(kind, block)| {
        let mut raw = [0; BLOCK_BYTES];
        disk.read(block, &mut raw).unwrap();
        assert_eq!(
            decode_object_envelope(kind, &raw),
            Ok(ObjectEnvelope {
                kind,
                fs_uuid: sb.fs_uuid,
                generation: 1,
            }),
            "formatted head at block {block}"
        );
        raw
    });
    assert_eq!(disk.first_flush_writes, Some(38));
    assert_eq!((disk.writes, disk.flushes), (4136, 4));
    let mount = volume::mount(&mut disk, sb, config, EmptyEnvelopes).unwrap();
    assert_eq!(volume::unified_map(&mut disk, sb, EmptyEnvelopes), Ok(151));
    assert_eq!(
        authority::boot_epoch(&mut disk, sb, &mount.security, config),
        Ok(1)
    );
    let before = (disk.writes, disk.flushes);
    let (kind, block) = heads[0];

    let mut bad_crc = saved[0];
    bad_crc[32] ^= 1;
    let mut bad_payload = saved[0];
    bad_payload[ENVELOPE_BYTES] = 1;
    let crc = crc32c_zeroed(&bad_payload, 32).unwrap();
    bad_payload[32..36].copy_from_slice(&crc.to_le_bytes());
    let mut wrong_uuid = [0; BLOCK_BYTES];
    encode_object_envelope(kind, [9; 16], 1, &mut wrong_uuid).unwrap();
    let mut wrong_generation = [0; BLOCK_BYTES];
    encode_object_envelope(kind, sb.fs_uuid, 2, &mut wrong_generation).unwrap();
    for (raw, expected) in [
        (bad_crc, Error::Invalid),
        (bad_payload, Error::Invalid),
        (saved[1], Error::Invalid),
        (wrong_uuid, Error::Conflict),
        (wrong_generation, Error::Conflict),
    ] {
        disk.blocks.insert(block, raw);
        assert_eq!(
            reopen::recover(&mut disk, sb, config, EmptyEnvelopes).err(),
            Some(expected)
        );
    }

    // A legacy staging image has the same verified baseline data and redo,
    // but all four snapshot envelope heads read as zero.
    for (_, head) in heads {
        disk.blocks.remove(&head);
    }
    assert_eq!(
        reopen::recover(&mut disk, sb, config, EmptyEnvelopes).err(),
        Some(Error::Invalid)
    );
    for ((_, head), raw) in heads.into_iter().zip(saved) {
        disk.blocks.insert(head, raw);
    }

    for tail in [SNAPSHOT_REQUEST_START - 1, SNAPSHOT_PROTECTION_BLOCK - 1] {
        let mut dirty = [0; BLOCK_BYTES];
        dirty[BLOCK_BYTES - 1] = 1;
        assert!(disk.blocks.insert(tail, dirty).is_none());
        assert_eq!(
            reopen::recover(&mut disk, sb, config, EmptyEnvelopes).err(),
            Some(Error::Conflict)
        );
        disk.blocks.remove(&tail);
    }
    assert_eq!((disk.writes, disk.flushes), before);

    let (checkpoint, mount) = reopen::recover(&mut disk, sb, config, EmptyEnvelopes).unwrap();
    assert_eq!(mount.boot.boot_epoch, 1);
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mount.security, config),
        Ok(2)
    );
    assert_eq!(
        volume::unified_map(&mut disk, checkpoint, EmptyEnvelopes),
        Ok(151)
    );
    for ((_, head), raw) in heads.into_iter().zip(saved) {
        assert_eq!(disk.blocks[&head], raw);
    }
}

#[test]
fn allocated_unified_staging_checks_allocations_before_replay() {
    use cyxia_kernel_core::security::file_media_unified_v1::SNAPSHOT_CATALOG_BLOCK;

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let mut scratch = [0; 1024];
    let verified = signed::verify(signed::WIRE, &mut scratch).unwrap();
    let config = Some(&verified);
    let sb = volume::format(&mut disk, config, AllocatedEnvelopes).unwrap();
    assert_eq!(disk.first_flush_writes, Some(172));
    assert_eq!((disk.writes, disk.flushes), (4270, 4));
    let mount = volume::mount(&mut disk, sb, config, AllocatedEnvelopes).unwrap();
    assert_eq!(
        (
            mount.structure.live_inodes,
            mount.system_blocks,
            mount.structure.data_blocks
        ),
        (9, 151, 152)
    );
    assert_eq!(mount.usage[0].inodes, 1);
    assert_eq!(mount.usage[0].blocks, 1);
    assert_eq!(
        authority::boot_epoch(&mut disk, sb, &mount.security, config),
        Ok(1)
    );

    let before = (disk.writes, disk.flushes);
    let bitmap = disk.blocks[&BITMAP_START];
    let index = (SNAPSHOT_CATALOG_BLOCK / 8) as usize;
    let bit = 1 << (SNAPSHOT_CATALOG_BLOCK % 8);
    assert_ne!(bitmap[index] & bit, 0);
    disk.blocks.get_mut(&BITMAP_START).unwrap()[index] &= !bit;
    assert_eq!(
        reopen::recover(&mut disk, sb, config, AllocatedEnvelopes).err(),
        Some(Error::Conflict)
    );
    disk.blocks.insert(BITMAP_START, bitmap);
    let root = disk.blocks[&CANONICAL_BUSINESS_START];
    // A dirty physical slot beyond the logical root size still violates
    // the immutable scratch layout and must be rejected before replay.
    disk.blocks.get_mut(&CANONICAL_BUSINESS_START).unwrap()[128 + 4] = 1;
    assert_eq!(
        reopen::recover(&mut disk, sb, config, AllocatedEnvelopes).err(),
        Some(Error::Conflict)
    );
    disk.blocks.insert(CANONICAL_BUSINESS_START, root);
    // Matching headers with the older four-object mount do not admit an
    // allocated snapshot layout through the wrong mode.
    assert!(reopen::recover(&mut disk, sb, config, EmptyEnvelopes).is_err());
    assert_eq!((disk.writes, disk.flushes), before);

    let (checkpoint, mounted) = reopen::recover(&mut disk, sb, config, AllocatedEnvelopes).unwrap();
    assert_eq!((checkpoint.generation, mounted.boot.boot_epoch), (2, 1));
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
        Ok(2)
    );
    assert_eq!((disk.writes, disk.flushes), (before.0 + 15, before.1 + 5));
    assert_eq!(disk.blocks[&BITMAP_START], bitmap);
}

#[test]
fn signed_file_staging_checks_immutable_homes_before_replay() {
    use cyxia_kernel_core::security::{
        file_media_v0199::{DATA_START, INODE_START},
        file_mount_v1::Acl,
        file_structure_v1::{Extent, INODE_BYTES, Inode},
    };

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let layout = AllocatedEnvelopesWithFile;
    assert_eq!(
        volume::format(&mut disk, None, layout),
        Err(Error::Unauthorized)
    );
    assert_eq!((disk.reads, disk.writes, disk.flushes), (0, 0, 0));
    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let config = Some(&verified);
    let sb = volume::format(&mut disk, config, layout).unwrap();
    assert_eq!(disk.first_flush_writes, Some(173));
    assert_eq!((disk.writes, disk.flushes), (4271, 4));

    let inode_page = disk.blocks[&INODE_START];
    let file = Inode::decode(&inode_page[INODE_BYTES..2 * INODE_BYTES]).unwrap();
    assert_eq!(
        (file.kind, file.generation, file.size, file.extents),
        (1, 1, 29, 1)
    );
    assert_eq!(
        (file.parent, file.parent_generation, file.durable_write_seq),
        (0, 1, 0)
    );
    assert_eq!(
        file.runs[0],
        Extent {
            logical: 0,
            physical: 4270,
            count: 1
        }
    );
    let acl_block = DATA_START + 8;
    let acls = disk.blocks[&acl_block];
    for (slot, rights) in [(0, 0x5000), (1, 0x0100)] {
        assert_eq!(
            Acl::decode(&acls[slot * 64..(slot + 1) * 64]),
            Ok(Acl {
                inode_id: slot as u32,
                state: 1,
                inode_generation: 1,
                principal: verified.principals()[0],
                owner_rights: rights,
                system_rights: 0,
                acl_generation: 1,
                parent: 0,
            })
        );
    }
    let root = disk.blocks[&CANONICAL_BUSINESS_START];
    let dirent: [u8; 128] = root[..128].try_into().unwrap();
    assert_eq!(&dirent[..4], &1u32.to_le_bytes());
    assert_eq!(&dirent[4..6], &10u16.to_le_bytes());
    assert_eq!(&dirent[8..16], &1u64.to_le_bytes());
    assert_eq!(&dirent[16..26], b"readme.txt");
    let contents = *b"CyxiaOS V0.20 signed scratch\n";
    let data = disk.blocks[&4270];
    assert_eq!(data[..contents.len()], contents);
    assert!(data[contents.len()..].iter().all(|&v| v == 0));

    let seal = |slot: &mut [u8], at| {
        let crc = crc32c_zeroed(slot, at).unwrap();
        slot[at..at + 4].copy_from_slice(&crc.to_le_bytes());
    };
    let mut missing_bit = disk.blocks[&BITMAP_START];
    let mask = 1 << (4270 % 8);
    assert_ne!(missing_bit[4270 / 8] & mask, 0);
    missing_bit[4270 / 8] &= !mask;
    let mut wrong_size = inode_page;
    wrong_size[INODE_BYTES + 16..INODE_BYTES + 24].copy_from_slice(&28u64.to_le_bytes());
    seal(&mut wrong_size[INODE_BYTES..2 * INODE_BYTES], 252);
    let mut root_acl = acls;
    root_acl[32..36].copy_from_slice(&(1u32 << 14).to_le_bytes());
    seal(&mut root_acl[..64], 60);
    let mut child_acl = acls;
    child_acl[64 + 36..64 + 40].copy_from_slice(&(1u32 << 8).to_le_bytes());
    seal(&mut child_acl[64..128], 60);
    let mut renamed = root;
    renamed[16] = b'R';
    seal(&mut renamed[..128], 124);
    let mut extra_slot = root;
    extra_slot[128..256].copy_from_slice(&dirent);
    let mut wrong_data = data;
    wrong_data[0] ^= 1;
    let mut dirty_padding = data;
    dirty_padding[BLOCK_BYTES - 1] = 1;
    let corruptions = [
        ("bitmap", BITMAP_START, missing_bit, Error::Conflict),
        ("inode size", INODE_START, wrong_size, Error::Conflict),
        ("root ACL", acl_block, root_acl, Error::Unauthorized),
        ("file ACL", acl_block, child_acl, Error::Unauthorized),
        ("name", CANONICAL_BUSINESS_START, renamed, Error::Conflict),
        (
            "unused slot",
            CANONICAL_BUSINESS_START,
            extra_slot,
            Error::Conflict,
        ),
        ("data", 4270, wrong_data, Error::Conflict),
        ("padding", 4270, dirty_padding, Error::Conflict),
    ];
    let before = (disk.writes, disk.flushes);
    for (name, block, corrupt, expected) in &corruptions {
        let original = disk.blocks.insert(*block, *corrupt).unwrap();
        assert_eq!(
            volume::mount(&mut disk, sb, config, layout).err(),
            Some(*expected),
            "{name}"
        );
        disk.blocks.insert(*block, original);
    }
    assert_eq!((disk.writes, disk.flushes), before);

    let mounted = volume::mount(&mut disk, sb, config, layout).unwrap();
    assert_eq!(mounted.security.offline_config_hash, verified.digest());
    assert_eq!(mounted.structure.live_inodes, 10);
    assert_eq!(mounted.structure.directory_entries, 1);
    assert_eq!(
        (mounted.system_blocks, mounted.structure.data_blocks),
        (151, 153)
    );
    assert_eq!((mounted.usage[0].inodes, mounted.usage[0].blocks), (2, 2));
    let epoch = authority::boot_epoch(&mut disk, sb, &mounted.security, config).unwrap();
    assert_eq!(epoch, 1);
    assert_eq!(authority::admission_flow(epoch), Ok(()));
    assert_eq!(
        volume::read_scratch_file(
            &mut disk,
            &mut [0; BLOCK_BYTES],
            layout,
            verified.principals()[0]
        )
        .map(|file| (file.dirent, file.data)),
        Ok((dirent, contents))
    );

    let before = (disk.writes, disk.flushes);
    for (name, block, corrupt, expected) in corruptions {
        let original = disk.blocks.insert(block, corrupt).unwrap();
        assert_eq!(
            reopen::recover(&mut disk, sb, config, layout).err(),
            Some(expected),
            "{name}"
        );
        disk.blocks.insert(block, original);
    }
    assert!(reopen::recover(&mut disk, sb, config, AllocatedEnvelopes).is_err());
    assert_eq!(
        reopen::recover(&mut disk, sb, config, AllocatedEnvelopesWithWritableFile).err(),
        Some(Error::Unauthorized)
    );
    assert_eq!((disk.writes, disk.flushes), before);

    let (checkpoint, mounted) = reopen::recover(&mut disk, sb, config, layout).unwrap();
    assert_eq!((checkpoint.generation, mounted.boot.boot_epoch), (2, 1));
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
        Ok(2)
    );
    assert_eq!((disk.writes, disk.flushes), (before.0 + 15, before.1 + 5));
    assert_eq!(
        volume::read_scratch_file(
            &mut disk,
            &mut [0; BLOCK_BYTES],
            layout,
            verified.principals()[0]
        )
        .map(|file| (file.dirent, file.data)),
        Ok((dirent, contents))
    );
}

#[test]
fn signed_writable_scratch_requires_exact_owner_acl_before_replay() {
    use cyxia_kernel_core::security::{
        file_format_v1::{SCRATCH_FILE_BLOCK, SCRATCH_FILE_DATA},
        file_media_v0199::DATA_START,
    };

    let _owner = STAGING_OWNER.lock().unwrap();
    let mut disk = Disk::default();
    let layout = AllocatedEnvelopesWithWritableFile;
    assert_eq!(
        volume::format(&mut disk, None, layout),
        Err(Error::Unauthorized)
    );
    assert_eq!((disk.reads, disk.writes, disk.flushes), (0, 0, 0));

    let verified = signed::verify(signed::WIRE, &mut [0; 1024]).unwrap();
    let config = Some(&verified);
    let sb = volume::format(&mut disk, config, layout).unwrap();
    let mounted = volume::mount(&mut disk, sb, config, layout).unwrap();
    assert_eq!((disk.writes, disk.flushes), (4271, 4));
    let owner = verified.principals()[0];
    let file = volume::read_scratch_file(&mut disk, &mut [0; BLOCK_BYTES], layout, owner).unwrap();
    assert_eq!(
        (&file.data, file.acl.principal, file.acl.owner_rights),
        (SCRATCH_FILE_DATA, owner, 0x0300)
    );
    assert_eq!(
        authority::boot_epoch(&mut disk, sb, &mounted.security, config),
        Ok(1)
    );

    let before = (disk.writes, disk.flushes);
    assert_eq!(
        reopen::recover(&mut disk, sb, config, AllocatedEnvelopesWithFile).err(),
        Some(Error::Unauthorized)
    );
    let acl_block = DATA_START + 8;
    let original = disk.blocks[&acl_block];
    let file_block = disk.blocks[&SCRATCH_FILE_BLOCK];
    for rights in [0x0100u32, 0x0200, 0x2300] {
        let raw = disk.blocks.get_mut(&acl_block).unwrap();
        let entry = &mut raw[64..128];
        entry[32..36].copy_from_slice(&rights.to_le_bytes());
        let crc = crc32c_zeroed(entry, 60).unwrap();
        entry[60..64].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            volume::read_scratch_file(&mut disk, &mut [0; BLOCK_BYTES], layout, owner),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            reopen::recover(&mut disk, sb, config, layout).err(),
            Some(Error::Unauthorized)
        );
    }
    assert_eq!((disk.writes, disk.flushes), before);
    disk.blocks.insert(acl_block, original);

    let (checkpoint, mounted) = reopen::recover(&mut disk, sb, config, layout).unwrap();
    assert_eq!((checkpoint.generation, mounted.boot.boot_epoch), (2, 1));
    assert_eq!(
        authority::boot_epoch(&mut disk, checkpoint, &mounted.security, config),
        Ok(2)
    );
    assert_eq!((disk.writes, disk.flushes), (before.0 + 15, before.1 + 5));
    assert_eq!(disk.blocks[&acl_block], original);
    assert_eq!(disk.blocks[&SCRATCH_FILE_BLOCK], file_block);
}
