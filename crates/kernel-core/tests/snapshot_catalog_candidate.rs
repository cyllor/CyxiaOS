use cyxia_kernel_core::security::{
    Error,
    file_media_unified_v1::{
        SLOT_MIRROR_BYTES, SNAPSHOT_CATALOG_BLOCK, SNAPSHOT_SLOT_START, SNAPSHOT_SLOTS,
        SNAPSHOT_STRIDE, SUPER_BYTES, UnifiedSystemKind,
        catalog_candidate::{CatalogContext, CatalogEntry, CatalogRecord, verify_catalog},
        encode_object_envelope,
        slot_candidate::{SlotDescriptor, SlotIdentity},
    },
    snapshot_list_v4::EmptyCatalog,
};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../tools/fixtures/v020-g1-catalog.tsv");
const MIRROR: &[u8; SLOT_MIRROR_BYTES] =
    include_bytes!("../../../tools/fixtures/v020-g1-slot-mirror.bin");
const UUID: [u8; 16] = *b"CYX-G1-SLOT-VEC!";
const OTHER_UUID: [u8; 16] = *b"NOT-THE-SLOT-ID!";
const INITIAL_SNAPSHOT_ID: u64 = 0x1020_3040_5060_7080;
const CAPTURE_LSN: u64 = 0x0102_0304_0506_0708;
const CAPTURE_EPOCH: u64 = 11;
const CAPTURE_AGE: u64 = 36_000_000_000;
const SLOT_GENERATION: u64 = 0xfedc_ba98_7654_3210;
const SLOT_STORE_GENERATION: u64 = 9;
const CATALOG_GENERATION: u64 = 17;

fn fixed_context(name: &str) -> CatalogContext {
    let mut context = CatalogContext {
        fs_uuid: UUID,
        catalog_generation: CATALOG_GENERATION,
        slot_store_generation: SLOT_STORE_GENERATION,
        live_view_epoch: CAPTURE_EPOCH,
        committed_lsn: CAPTURE_LSN + 1,
        online_age_ns: CAPTURE_AGE,
    };
    match name {
        "current" => (),
        "other-volume" => context.fs_uuid = OTHER_UUID,
        "prior-catalog" => context.catalog_generation -= 1,
        "prior-slotstore" => context.slot_store_generation -= 1,
        "prior-epoch" => context.live_view_epoch -= 1,
        "prior-lsn" => context.committed_lsn -= 2,
        "before-drop" => context.committed_lsn -= 1,
        "prior-age" => context.online_age_ns -= 1,
        _ => panic!("unknown context fixture: {name}"),
    }
    context
}

fn fixture_descriptor(
    index: u32,
    source: &str,
    mirror_sha256: [u8; 32],
    raw: &mut [u8; SUPER_BYTES],
) {
    if index == 0 && source != "live-head" {
        let uuid = if source == "foreign-empty-head" {
            OTHER_UUID
        } else {
            UUID
        };
        encode_object_envelope(
            UnifiedSystemKind::SnapshotSlot,
            uuid,
            SLOT_STORE_GENERATION,
            raw,
        )
        .unwrap();
        return;
    }
    let mut identity = SlotIdentity {
        fs_uuid: UUID,
        snapshot_id: INITIAL_SNAPSHOT_ID + u64::from(index),
        slot: index,
        slot_generation: SLOT_GENERATION,
        captured_live_view_epoch: CAPTURE_EPOCH,
        capture_commit_lsn: CAPTURE_LSN,
        created_online_age_ns: CAPTURE_AGE,
    };
    if index == 7 {
        match source {
            "foreign-tail" => identity.fs_uuid = OTHER_UUID,
            "stale-tail" => identity.slot_generation -= 1,
            "other-tail-capture" => identity.capture_commit_lsn += 1,
            "empty-head" | "live-head" | "foreign-empty-head" => (),
            _ => panic!("unknown slot source: {source}"),
        }
    }
    SlotDescriptor {
        identity,
        store_generation: (index == 0).then_some(SLOT_STORE_GENERATION),
        inode_image_sha256: mirror_sha256,
    }
    .encode(raw)
    .unwrap();
}

fn parse_page(prefix: &str) -> [u8; SUPER_BYTES] {
    assert!(prefix.len().is_multiple_of(2));
    let mut page = [0; SUPER_BYTES];
    for (index, byte) in page[..prefix.len() / 2].iter_mut().enumerate() {
        let at = 2 * index;
        *byte = u8::from_str_radix(&prefix[at..at + 2], 16).unwrap();
    }
    page
}

fn expected_reads(spec: &str) -> Vec<u32> {
    if spec == "-" {
        return Vec::new();
    }
    spec.split(',')
        .flat_map(|range| {
            let (first, count) = range.split_once(':').unwrap();
            let first: u32 = first.parse().unwrap();
            let count: u32 = count.parse().unwrap();
            first..first + count
        })
        .collect()
}

#[test]
fn independent_catalog_vectors_bind_exact_immutable_slot_pages() {
    let mirror_sha256: [u8; 32] = Sha256::digest(MIRROR).into();
    let mut cases = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let columns: Vec<_> = line.split('\t').collect();
        let [name, verdict, context, source, reads, block, prefix] = columns[..] else {
            panic!("invalid catalog vector row: {line}");
        };
        let raw = parse_page(prefix);
        let block = block.parse().unwrap();
        let mut actual_reads = Vec::new();
        let result = verify_catalog(block, &raw, fixed_context(context), |address, page| {
            assert!(
                address >= SNAPSHOT_SLOT_START,
                "{name}: slot block {address}"
            );
            actual_reads.push(address);
            let relative = address - SNAPSHOT_SLOT_START;
            let index = relative / SNAPSHOT_STRIDE;
            assert!(index < SNAPSHOT_SLOTS, "{name}: slot number {index}");
            let offset = relative % SNAPSHOT_STRIDE;
            if offset == 0 {
                fixture_descriptor(index, source, mirror_sha256, page);
            } else {
                let at = (offset as usize - 1) * SUPER_BYTES;
                page.copy_from_slice(&MIRROR[at..at + SUPER_BYTES]);
            }
            Ok(())
        });
        assert_eq!(actual_reads, expected_reads(reads), "{name}");
        let active_mount = EmptyCatalog::verify(&raw, UUID, CATALOG_GENERATION, 1);
        match verdict {
            "accept" => {
                let record = result.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(record.fs_uuid, UUID, "{name}");
                assert_eq!(record.generation, CATALOG_GENERATION, "{name}");
                assert_eq!(record.next_snapshot_id, INITIAL_SNAPSHOT_ID + 8, "{name}");
                if name == "retired-head-bytes" {
                    assert_eq!(
                        record.entries[0],
                        CatalogEntry::Free {
                            slot_generation: SLOT_GENERATION
                        }
                    );
                }
                if name == "post-collection-watermark" {
                    assert_eq!(record.entries[0], CatalogEntry::Free { slot_generation: 6 });
                    assert_eq!(
                        record.entries[7],
                        CatalogEntry::Free {
                            slot_generation: SLOT_GENERATION
                        }
                    );
                }
                if name == "deleting-capture" {
                    let CatalogEntry::Deleting {
                        binding,
                        root_drop_commit_lsn,
                    } = record.entries[7]
                    else {
                        panic!("expected deleting slot");
                    };
                    assert_eq!(binding.identity.capture_commit_lsn, CAPTURE_LSN);
                    assert_eq!(root_drop_commit_lsn, CAPTURE_LSN + 1);
                }
                let mut encoded = [0xff; SUPER_BYTES];
                record.encode(&mut encoded).unwrap();
                assert_eq!(encoded, raw, "{name}");
                assert_eq!(CatalogRecord::decode(block, &encoded), Ok(record), "{name}");
                assert_eq!(active_mount, Err(Error::Invalid), "{name}");
            }
            "invalid" => assert_eq!(result, Err(Error::Invalid), "{name}"),
            "conflict" => assert_eq!(result, Err(Error::Conflict), "{name}"),
            _ => panic!("unknown catalog vector verdict: {verdict}"),
        }
        if name == "approved-empty-envelope" {
            assert!(active_mount.is_ok());
        }
        cases += 1;
    }
    assert_eq!(cases, 39);
}

#[test]
fn catalog_encoder_rejects_a_binding_for_another_row_or_volume() {
    let prefix = VECTORS
        .lines()
        .find_map(|line| {
            line.starts_with("first-and-last\t")
                .then(|| line.rsplit_once('\t').unwrap().1)
        })
        .unwrap();
    let raw = parse_page(prefix);
    let original = CatalogRecord::decode(SNAPSHOT_CATALOG_BLOCK, &raw).unwrap();
    let CatalogEntry::Active(binding) = original.entries[7] else {
        panic!("fixture must bind slot seven");
    };
    let mut catalog = original;
    catalog.entries.swap(0, 7);
    let mut encoded = raw;
    assert_eq!(catalog.encode(&mut encoded), Err(Error::Conflict));
    assert_eq!(encoded, raw);

    catalog = original;
    let mut foreign = binding;
    foreign.identity.fs_uuid = OTHER_UUID;
    catalog.entries[7] = CatalogEntry::Active(foreign);
    assert_eq!(catalog.encode(&mut encoded), Err(Error::Conflict));
    assert_eq!(encoded, raw);
}
