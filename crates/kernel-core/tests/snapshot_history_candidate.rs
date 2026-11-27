#![cfg(feature = "snapshot-history-candidate")]

use cyxia_kernel_core::security::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    file_format_v1::scratch_file_dirent,
    file_media_unified_v1::{
        INODE_START, SLOT_MIRROR_BLOCKS, SLOT_MIRROR_BYTES, SNAP_CAP_HISTORY_READ,
        SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_SLOT_START, SNAPSHOT_STRIDE, SUPER_BYTES,
        UnifiedSystemKind,
        catalog_candidate::{CatalogBinding, CatalogContext, CatalogEntry, CatalogRecord},
        encode_object_envelope,
        history_candidate::{HistoryCaller, HistoryReadGrant, HistorySource, read_history},
        slot_candidate::{SlotDescriptor, SlotIdentity},
    },
    file_media_v0199::crc32c_zeroed,
    file_mount_v1::Acl,
    offline_config_v1::Principal,
    snapshot_read_v4::history_prefix_digest,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const UUID: [u8; 16] = *b"CYX-HISTORY-VEC!";
const FILE: &[u8] = b"/readme.txt";
const LIVE_DATA_BLOCK: u32 = 4270;

fn put(raw: &mut [u8], offset: usize, value: impl AsRef<[u8]>) {
    let bytes = value.as_ref();
    raw[offset..offset + bytes.len()].copy_from_slice(bytes);
}

fn seal(raw: &mut [u8], offset: usize) {
    let crc = crc32c_zeroed(raw, offset).unwrap();
    put(raw, offset, crc.to_le_bytes());
}

fn inode(kind: u16, size: u64, block: u32) -> [u8; 256] {
    let live = u16::from(kind != 0);
    let mut raw = [0; 256];
    put(&mut raw, 0, 0x4359494eu32.to_le_bytes());
    put(&mut raw, 4, kind.to_le_bytes());
    put(&mut raw, 8, u64::from(live).to_le_bytes());
    put(&mut raw, 16, size.to_le_bytes());
    put(&mut raw, 32, live.to_le_bytes());
    put(&mut raw, 40, u64::from(live).to_le_bytes());
    put(&mut raw, 52, block.to_le_bytes());
    put(&mut raw, 56, u32::from(live).to_le_bytes());
    seal(&mut raw, 252);
    raw
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn archived_files_are_read_from_the_authorized_slot_and_historical_extent() {
    let full: Vec<u8> = (0..SUPER_BYTES).map(|i| (i % 251) as u8).collect();
    for (index, content, oracle_catalog, oracle_file) in [
        (
            0,
            b"Archived January report\n".as_slice(),
            "868446cadd7f2031115e6601f18c7fcd893219bfbb1b0f0c79afa6e21e23416c",
            "8ff5342893e8f798b9b417bd8a028525a8a54689898bedd7474ee8ece51d51c4",
        ),
        (
            7,
            full.as_slice(),
            "d1648211fd3d282c9a28692e861fbd3b8811797e8697f7baf943fc77d6bcc0be",
            "d67c656e01756650d77717b0839985a056ec28ffe174601d690fc407a2ceffca",
        ),
    ] {
        let root = 4300 + index * 2;
        let data = root + 1;
        let slot = SlotIdentity {
            fs_uuid: UUID,
            snapshot_id: 10 + u64::from(index),
            slot: index,
            slot_generation: 4 + u64::from(index),
            captured_live_view_epoch: 8,
            capture_commit_lsn: 33,
            created_online_age_ns: 180_000_000_000,
        };
        let mut mirror = vec![0; SLOT_MIRROR_BYTES];
        for record in mirror.chunks_exact_mut(256) {
            record.copy_from_slice(&inode(0, 0, 0));
        }
        mirror[..256].copy_from_slice(&inode(2, 128, root));
        mirror[256..512].copy_from_slice(&inode(1, content.len() as u64, data));
        let mut descriptor = [0; SUPER_BYTES];
        SlotDescriptor {
            identity: slot,
            store_generation: (index == 0).then_some(2),
            inode_image_sha256: sha(&mirror),
        }
        .encode(&mut descriptor)
        .unwrap();
        let mut entries = [CatalogEntry::Free { slot_generation: 0 }; 8];
        entries[index as usize] = CatalogEntry::Active(CatalogBinding {
            identity: slot,
            descriptor_sha256: sha(&descriptor),
        });
        let mut catalog = [0; SUPER_BYTES];
        CatalogRecord {
            fs_uuid: UUID,
            generation: 3,
            next_snapshot_id: slot.snapshot_id + 1,
            entries,
        }
        .encode(&mut catalog)
        .unwrap();
        assert_eq!(hex(&sha(&catalog)), oracle_catalog);
        assert_eq!(hex(&sha(content)), oracle_file);

        let descriptor_block = SNAPSHOT_SLOT_START + index * SNAPSHOT_STRIDE;
        let mut blocks = BTreeMap::from([
            (SNAPSHOT_CATALOG_BLOCK, catalog),
            (descriptor_block, descriptor),
            (LIVE_DATA_BLOCK, [0x8b; SUPER_BYTES]),
        ]);
        if index != 0 {
            let mut head = [0; SUPER_BYTES];
            encode_object_envelope(UnifiedSystemKind::SnapshotSlot, UUID, 2, &mut head).unwrap();
            blocks.insert(SNAPSHOT_SLOT_START, head);
        }
        for (offset, page) in mirror.chunks_exact(SUPER_BYTES).enumerate() {
            blocks.insert(
                descriptor_block + 1 + offset as u32,
                page.try_into().unwrap(),
            );
        }
        let mut empty = [0; 128];
        put(&mut empty, 0, u32::MAX.to_le_bytes());
        seal(&mut empty, 124);
        let mut directory = [0; SUPER_BYTES];
        for entry in directory.chunks_exact_mut(128) {
            entry.copy_from_slice(&empty);
        }
        directory[..128].copy_from_slice(&scratch_file_dirent().unwrap());
        blocks.insert(root, directory);
        let mut page = [0; SUPER_BYTES];
        page[..content.len()].copy_from_slice(content);
        blocks.insert(data, page);

        let source = HistorySource {
            catalog: CatalogContext {
                fs_uuid: UUID,
                catalog_generation: 3,
                slot_store_generation: 2,
                live_view_epoch: 9,
                committed_lsn: 42,
                online_age_ns: 190_000_000_000,
            },
            catalog_sha256: sha(&catalog),
            root_block: root,
            data_block: data,
            data_sha256: sha(content),
        };
        let principal = Principal {
            id: 1,
            generation: 1,
        };
        let caller = HistoryCaller {
            boot: BootEpochStoreV1 {
                fs_uuid: UUID,
                boot_epoch: 2,
            },
            principal,
            file_acl: Acl {
                inode_id: 1,
                state: 1,
                inode_generation: 1,
                principal,
                owner_rights: 1 << 8,
                system_rights: 0,
                acl_generation: 3,
                parent: 0,
            },
        };
        let grant = HistoryReadGrant {
            boot_epoch: 2,
            principal,
            snapshot: slot,
            snapshot_rights: SNAP_CAP_HISTORY_READ,
            acl_generation: 3,
            prefix: FILE,
            prefix_sha256: history_prefix_digest(FILE),
        };
        let mut out = [0xa5; SUPER_BYTES];
        let mut reads = Vec::new();
        let result = read_history(
            &source,
            caller,
            grant,
            FILE,
            |block, output| {
                reads.push(block);
                *output = *blocks.get(&block).ok_or(Error::Invalid)?;
                Ok(())
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(
            (result.snapshot, result.bytes, result.data_sha256),
            (slot, content.len(), sha(content))
        );
        assert_eq!(&out[..result.bytes], content);
        assert_eq!(out, page);
        assert_eq!(reads.first(), Some(&SNAPSHOT_CATALOG_BLOCK));
        assert_eq!(&reads[reads.len() - 2..], &[root, data]);
        assert_eq!(
            reads.len(),
            SLOT_MIRROR_BLOCKS as usize + 4 + usize::from(index != 0)
        );
        assert!(!reads.contains(&LIVE_DATA_BLOCK) && !reads.contains(&INODE_START));

        let mut stale = caller;
        stale.file_acl.acl_generation += 1;
        assert_eq!(
            read_history(
                &source,
                stale,
                grant,
                FILE,
                |_, _| panic!("expired ACL before I/O"),
                &mut out
            ),
            Err(Error::Stale)
        );
        assert_eq!(out, page);
    }
}
