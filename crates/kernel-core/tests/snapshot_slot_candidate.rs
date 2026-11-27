use cyxia_kernel_core::security::{
    Error,
    file_media_unified_v1::{
        SLOT_MIRROR_BYTES, SNAPSHOT_SLOT_START, SNAPSHOT_STRIDE, SUPER_BYTES, UnifiedSystemKind,
        encode_object_envelope,
        slot_candidate::{SlotDescriptor, SlotIdentity, verify_slot},
    },
    file_structure_v1::INODE_BYTES,
    snapshot_list_v4::EmptyCatalog,
    snapshot_read_v4::EmptySnapshotView,
};

const UUID: [u8; 16] = *b"CYX-G1-SLOT-VEC!";
const VECTORS: &str = include_str!("../../../tools/fixtures/v020-g1-slot.tsv");
const MIRROR: &[u8; SLOT_MIRROR_BYTES] =
    include_bytes!("../../../tools/fixtures/v020-g1-slot-mirror.bin");

fn hex(digits: &str) -> Vec<u8> {
    assert!(digits.len().is_multiple_of(2));
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
        .collect()
}

fn empty_catalog_envelope(kind: UnifiedSystemKind) -> [u8; SUPER_BYTES] {
    let mut raw = [0; SUPER_BYTES];
    encode_object_envelope(kind, UUID, 9, &mut raw).unwrap();
    raw
}

#[test]
fn independent_vectors_bind_descriptor_geometry_and_every_business_inode_page() {
    let catalog = EmptyCatalog::verify(
        &empty_catalog_envelope(UnifiedSystemKind::SnapshotCatalog),
        UUID,
        9,
        1,
    )
    .unwrap();
    let mut cases = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split('\t').collect();
        let [name, slot, verdict, variant, proof, prefix] = columns[..] else {
            panic!("invalid slot vector row: {line}");
        };
        let slot: u32 = slot.parse().unwrap();
        let binding = SlotIdentity {
            fs_uuid: UUID,
            snapshot_id: 0x1020_3040_5060_7080 + u64::from(slot),
            slot,
            slot_generation: 0xfedc_ba98_7654_3210,
            captured_live_view_epoch: 11,
            capture_commit_lsn: 0x0102_0304_0506_0708,
            created_online_age_ns: 36_000_000_000,
        };
        let mut descriptor = [0; SUPER_BYTES];
        let prefix = hex(prefix);
        descriptor[..prefix.len()].copy_from_slice(&prefix);
        let proof = hex(proof).try_into().unwrap();
        let mut image = MIRROR.to_vec();
        let last_inode = image.len() - INODE_BYTES;
        match variant {
            "original" => (),
            "last-generation" => image.copy_within(INODE_BYTES..2 * INODE_BYTES, last_inode),
            "without-root" => image.copy_within(INODE_BYTES..2 * INODE_BYTES, 0),
            _ => panic!("unknown mirror vector: {variant}"),
        }
        let descriptor_block = SNAPSHOT_SLOT_START + slot * SNAPSHOT_STRIDE;
        let store_generation = (slot == 0).then_some(9);
        let mut calls = 0;
        let result = verify_slot(binding, store_generation, &proof, |block, raw| {
            assert_eq!(block, descriptor_block + calls, "{name}");
            if calls == 0 {
                *raw = descriptor;
            } else {
                let offset = (calls as usize - 1) * SUPER_BYTES;
                raw.copy_from_slice(&image[offset..offset + SUPER_BYTES]);
            }
            calls += 1;
            Ok(())
        });
        match verdict {
            "accept" => {
                let decoded = result.unwrap();
                assert_eq!(calls, 15, "{name}");
                assert_eq!(decoded.identity, binding, "{name}");
                let mut reencoded = [0xff; SUPER_BYTES];
                decoded.encode(&mut reencoded).unwrap();
                assert_eq!(reencoded, descriptor, "{name}");
                assert_eq!(
                    SlotDescriptor::decode(descriptor_block, &descriptor),
                    Ok(decoded)
                );
                let staged = EmptySnapshotView::verify(catalog, |block, raw| {
                    if block == u64::from(descriptor_block) {
                        *raw = descriptor;
                    } else if block == u64::from(SNAPSHOT_SLOT_START) {
                        *raw = empty_catalog_envelope(UnifiedSystemKind::SnapshotSlot);
                    } else {
                        raw.fill(0);
                    }
                    Ok(())
                });
                let error = if slot == 0 {
                    Error::Invalid
                } else {
                    Error::Conflict
                };
                assert_eq!(staged, Err(error), "{name}");
            }
            "invalid" => assert_eq!(result, Err(Error::Invalid), "{name}"),
            "conflict" => assert_eq!(result, Err(Error::Conflict), "{name}"),
            _ => panic!("unknown result: {verdict}"),
        }
        cases += 1;
    }
    assert_eq!(cases, 14);
}
