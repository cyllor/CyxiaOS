use cyxia_kernel_core::security::{
    Error,
    file_media_unified_v1::{
        ENVELOPE_BYTES, LEGACY_SCHEMA_V2_MAGIC, SNAP_MAX_REQUEST_BYTES, SNAP_OP_ACK_REQUEST,
        SNAP_OP_CREATE, SNAP_OP_HISTORY_OPEN, SNAP_OP_QUERY, SNAPSHOT_REQUEST_START,
        SNAPSHOT_SLOT_START, SNAPSHOT_STRIDE, SUPER_BYTES, UnifiedSystemKind,
        encode_object_envelope,
    },
    file_media_v0199::crc32c_zeroed,
    file_read_v4::ROOT_SELECTOR,
    file_service_v4::{REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION},
    snapshot_list_v4::{EmptyCatalog, LIST_ENDPOINT, LIST_SELECTOR, ListError, ListRequest},
    snapshot_read_v4::{EmptySnapshotView, HISTORY_SELECTOR, ReadRequest, history_prefix_digest},
};
use cyxia_prototype::snapshot::{SnapshotKey, history_prefix_digest as v18_prefix_digest};
use sha2::{Digest, Sha256};

const REQUEST_ID: u64 = 0x0102_0304_0506_0708;
const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
const CATALOG_GENERATION: u64 = 29;
const BOOT_EPOCH: u64 = 13;
const VECTORS: &str = include_str!("../../../tools/fixtures/v020-snapshot-read-v4.tsv");

fn frame(op: u16, payload_len: usize) -> Vec<u8> {
    let mut bytes = vec![0; REQUEST_HEADER + payload_len];
    bytes[..4].copy_from_slice(&REQUEST_MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&REQUEST_VERSION.to_le_bytes());
    bytes[6..8].copy_from_slice(&(REQUEST_HEADER as u16).to_le_bytes());
    bytes[8..10].copy_from_slice(&op.to_le_bytes());
    bytes[12..16].copy_from_slice(&(payload_len as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&REQUEST_ID.to_le_bytes());
    bytes
}

fn envelope(kind: UnifiedSystemKind) -> [u8; SUPER_BYTES] {
    let mut raw = [0; SUPER_BYTES];
    encode_object_envelope(kind, UUID, CATALOG_GENERATION, &mut raw).unwrap();
    raw
}

const KEY: SnapshotKey = SnapshotKey {
    fs_uuid: UUID,
    snapshot_id: 91,
    slot: 7,
    slot_generation: 43,
};

fn query_frame(key: SnapshotKey) -> Vec<u8> {
    let mut bytes = frame(SNAP_OP_QUERY, 40);
    key.encode(&mut bytes[REQUEST_HEADER..]).unwrap();
    bytes
}

fn history_frame(key: SnapshotKey, path: &[u8]) -> Vec<u8> {
    let mut bytes = frame(SNAP_OP_HISTORY_OPEN, 48 + path.len());
    let payload = &mut bytes[REQUEST_HEADER..];
    key.encode(&mut payload[..40]).unwrap();
    payload[40..42].copy_from_slice(&(path.len() as u16).to_le_bytes());
    payload[48..].copy_from_slice(path);
    bytes
}

fn hex_vector(digits: &str) -> Vec<u8> {
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn independent_vectors_bind_the_history_key_scope_and_staging_frame() {
    let key = SnapshotKey {
        snapshot_id: 0x5060_7080_90a0_b0c0,
        slot_generation: 0xfedc_ba98_7654_3210,
        ..KEY
    };
    let prefix = "/团队".as_bytes();
    let digest: [u8; 32] = VECTORS
        .lines()
        .find_map(|line| line.strip_prefix("prefix-digest\tdigest\t"))
        .map(hex_vector)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(history_prefix_digest(prefix), digest);

    let view = slot_proof(&envelope(UnifiedSystemKind::SnapshotSlot), None).unwrap();
    let mut count = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        let [name, verdict, digits] = fields[..] else {
            panic!("malformed snapshot read vector row: {line}");
        };
        let raw = hex_vector(digits);
        match (name, verdict) {
            ("prefix-digest", "digest") => assert_eq!(raw, digest),
            ("query", "accept") => {
                assert_eq!(raw, query_frame(key));
                let request = ReadRequest::decode(&raw).unwrap();
                assert_eq!(request.request_id, REQUEST_ID);
                assert_eq!(request.path(), None);
                assert!(request.authorized(LIST_SELECTOR, &view, b"", &[0; 32]));
            }
            ("history", "accept") | ("history-sibling", "scope") => {
                let path = if verdict == "accept" {
                    "/团队/报告.txt"
                } else {
                    "/团队预览/报告.txt"
                };
                assert_eq!(raw, history_frame(key, path.as_bytes()));
                let request = ReadRequest::decode(&raw).unwrap();
                assert_eq!(request.request_id, REQUEST_ID);
                assert_eq!(request.path(), Some(path.as_bytes()));
                assert_eq!(
                    request.authorized(HISTORY_SELECTOR, &view, prefix, &digest),
                    verdict == "accept",
                    "{name}"
                );
            }
            (_, "format") => {
                assert_eq!(ReadRequest::decode(&raw), Err(ListError::Format), "{name}")
            }
            (_, "schema") => {
                assert_eq!(ReadRequest::decode(&raw), Err(ListError::Schema), "{name}")
            }
            _ => panic!("unknown snapshot read vector: {name} {verdict}"),
        }
        count += 1;
    }
    assert_eq!(count, 11);
}

#[test]
fn read_requests_share_the_snapshot_v4_header_errors() {
    let good = query_frame(KEY);
    for len in 0..REQUEST_HEADER {
        assert_eq!(ReadRequest::decode(&good[..len]), Err(ListError::Format));
    }
    for offset in [0, 6, 8, 10, 12, 24] {
        let mut malformed = good.clone();
        malformed[offset] ^= 0x80;
        assert_eq!(ReadRequest::decode(&malformed), Err(ListError::Format));
        assert_eq!(ListRequest::decode(&malformed), Err(ListError::Format));
    }
    let mut no_id = good.clone();
    no_id[16..24].fill(0);
    assert_eq!(ReadRequest::decode(&no_id), Err(ListError::Format));
    let mut old_abi = good.clone();
    old_abi[4..6].copy_from_slice(&(REQUEST_VERSION - 1).to_le_bytes());
    assert_eq!(ReadRequest::decode(&old_abi), Err(ListError::Schema));
    let mut legacy = [0; 64];
    legacy[..4].copy_from_slice(&LEGACY_SCHEMA_V2_MAGIC.to_le_bytes());
    legacy[4..6].copy_from_slice(&2u16.to_le_bytes());
    legacy[6..8].copy_from_slice(&64u16.to_le_bytes());
    legacy[8..10].copy_from_slice(&SNAP_OP_QUERY.to_le_bytes());
    assert_eq!(ReadRequest::decode(&legacy), Err(ListError::Schema));

    for op in (SNAP_OP_CREATE..=SNAP_OP_ACK_REQUEST)
        .filter(|op| !matches!(*op, SNAP_OP_QUERY | SNAP_OP_HISTORY_OPEN))
    {
        assert_eq!(
            ReadRequest::decode(&frame(op, 0)),
            Err(ListError::Unsupported),
            "op {op:#x}"
        );
    }
    assert_eq!(ListRequest::decode(&good), Err(ListError::Unsupported));
    let limit = SNAP_MAX_REQUEST_BYTES - REQUEST_HEADER;
    assert_eq!(
        ReadRequest::decode(&frame(SNAP_OP_CREATE, limit)),
        Err(ListError::Unsupported)
    );
    assert_eq!(
        ReadRequest::decode(&frame(SNAP_OP_CREATE, limit + 1)),
        Err(ListError::Format)
    );
}

#[test]
fn read_requests_require_the_exact_v18_key() {
    let query = query_frame(KEY);
    let request = ReadRequest::decode(&query).unwrap();
    assert_eq!(request.request_id, REQUEST_ID);
    assert_eq!(request.op, SNAP_OP_QUERY);
    assert_eq!(request.path(), None);
    for len in [0, 39, 41] {
        let mut wrong_len = frame(SNAP_OP_QUERY, len);
        let copied = len.min(40);
        wrong_len[REQUEST_HEADER..REQUEST_HEADER + copied]
            .copy_from_slice(&query[REQUEST_HEADER..REQUEST_HEADER + copied]);
        assert_eq!(ReadRequest::decode(&wrong_len), Err(ListError::Format));
    }
    let history = history_frame(KEY, b"/readme.txt");
    let request = ReadRequest::decode(&history).unwrap();
    assert_eq!(request.request_id, REQUEST_ID);
    assert_eq!(request.op, SNAP_OP_HISTORY_OPEN);
    assert_eq!(request.path(), Some(b"/readme.txt".as_slice()));

    for good in [query, history] {
        for range in [0..16, 16..24, 32..40] {
            let mut invalid_key = good.clone();
            invalid_key[REQUEST_HEADER + range.start..REQUEST_HEADER + range.end].fill(0);
            assert_eq!(ReadRequest::decode(&invalid_key), Err(ListError::Format));
        }
        let mut invalid_slot = good.clone();
        invalid_slot[REQUEST_HEADER + 24..REQUEST_HEADER + 28].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(ReadRequest::decode(&invalid_slot), Err(ListError::Format));
        let mut reserved = good;
        reserved[REQUEST_HEADER + 31] = 1;
        assert_eq!(ReadRequest::decode(&reserved), Err(ListError::Format));
    }
    assert!(ReadRequest::decode(&query_frame(SnapshotKey { slot: 0, ..KEY })).is_ok());
}

#[test]
fn history_request_requires_exact_length_and_canonical_absolute_path() {
    let mut longest = [b'/'; 512];
    for component in longest.chunks_exact_mut(64) {
        component[1..].fill(b'a');
    }
    for path in [b"/".as_slice(), "/é/資料".as_bytes(), &longest] {
        let history = history_frame(KEY, path);
        assert_eq!(ReadRequest::decode(&history).unwrap().path(), Some(path));
    }

    let mut long_component = [b'a'; 65];
    long_component[0] = b'/';
    let mut too_long = longest[..511].to_vec();
    too_long.extend_from_slice(b"/b");
    for invalid in [
        b"".as_slice(),
        b"team",
        b"/team/",
        b"/team//file",
        b"//team",
        b"/./file",
        b"/team/..",
        b"/a\0b",
        b"/\x80",
        &long_component,
        &too_long,
    ] {
        assert_eq!(
            ReadRequest::decode(&history_frame(KEY, invalid)),
            Err(ListError::Format),
            "path {invalid:?}"
        );
    }
    let good = history_frame(KEY, b"/team");
    for len in 40..48 {
        let mut short = frame(SNAP_OP_HISTORY_OPEN, len);
        short[REQUEST_HEADER..].copy_from_slice(&good[REQUEST_HEADER..REQUEST_HEADER + len]);
        assert_eq!(ReadRequest::decode(&short), Err(ListError::Format));
    }
    for offset in 40..48 {
        let mut malformed = good.clone();
        malformed[REQUEST_HEADER + offset] ^= 1;
        assert_eq!(ReadRequest::decode(&malformed), Err(ListError::Format));
    }
}

fn catalog_proof() -> EmptyCatalog {
    EmptyCatalog::verify(
        &envelope(UnifiedSystemKind::SnapshotCatalog),
        UUID,
        CATALOG_GENERATION,
        BOOT_EPOCH,
    )
    .unwrap()
}

fn slot_proof(
    head: &[u8; SUPER_BYTES],
    corrupt_tail: Option<u64>,
) -> Result<EmptySnapshotView, Error> {
    EmptySnapshotView::verify(catalog_proof(), |block, raw| {
        if block == u64::from(SNAPSHOT_SLOT_START) {
            *raw = *head;
        } else {
            raw.fill(0);
            if Some(block) == corrupt_tail {
                raw[SUPER_BYTES - 1] = 1;
            }
        }
        Ok(())
    })
}

#[test]
fn read_authorization_binds_selector_uuid_canonical_scope_and_v18_digest() {
    let view = slot_proof(&envelope(UnifiedSystemKind::SnapshotSlot), None).unwrap();
    let prefix = b"/team";
    let digest = v18_prefix_digest(prefix);
    assert_eq!(HISTORY_SELECTOR, 0x534e_4150_0000_0026);
    assert_eq!(history_prefix_digest(prefix), digest);
    let query = query_frame(KEY);
    let query = ReadRequest::decode(&query).unwrap();
    assert!(query.authorized(LIST_SELECTOR, &view, b"", &[0; 32]));
    for selector in [0, LIST_ENDPOINT, HISTORY_SELECTOR, ROOT_SELECTOR] {
        assert!(!query.authorized(selector, &view, prefix, &digest));
    }

    for path in [prefix.as_slice(), b"/team/file"] {
        let wire = history_frame(KEY, path);
        let history = ReadRequest::decode(&wire).unwrap();
        assert!(history.authorized(HISTORY_SELECTOR, &view, prefix, &digest));
        assert!(history.authorized(HISTORY_SELECTOR, &view, b"/", &v18_prefix_digest(b"/")));
        for selector in [0, LIST_SELECTOR, LIST_ENDPOINT, ROOT_SELECTOR] {
            assert!(!history.authorized(selector, &view, prefix, &digest));
        }
        for bad_prefix in [b"".as_slice(), b"/team/", b"/other"] {
            assert!(!history.authorized(
                HISTORY_SELECTOR,
                &view,
                bad_prefix,
                &v18_prefix_digest(bad_prefix)
            ));
        }
        assert!(!history.authorized(HISTORY_SELECTOR, &view, b"/", &digest));
        assert!(!history.authorized(HISTORY_SELECTOR, &view, prefix, &[0; 32]));
    }
    let collision = history_frame(KEY, b"/teamish/file");
    assert!(!ReadRequest::decode(&collision).unwrap().authorized(
        HISTORY_SELECTOR,
        &view,
        prefix,
        &digest
    ));

    let wrong_volume = SnapshotKey {
        fs_uuid: [0xff; 16],
        ..KEY
    };
    let query = query_frame(wrong_volume);
    let history = history_frame(wrong_volume, prefix);
    assert!(!ReadRequest::decode(&query).unwrap().authorized(
        LIST_SELECTOR,
        &view,
        prefix,
        &digest
    ));
    assert!(!ReadRequest::decode(&history).unwrap().authorized(
        HISTORY_SELECTOR,
        &view,
        prefix,
        &digest
    ));
}

#[test]
fn empty_view_reads_all_120_absolute_blocks_in_order_and_hashes_the_range() {
    const BLOCKS: usize = 120;
    let catalog = catalog_proof();
    let mut disk_bytes = vec![0; BLOCKS * SUPER_BYTES];
    disk_bytes[..SUPER_BYTES].copy_from_slice(&envelope(UnifiedSystemKind::SnapshotSlot));
    let mut read_count = 0;
    let view = EmptySnapshotView::verify(catalog, |block, out| {
        assert_eq!(block, u64::from(SNAPSHOT_SLOT_START) + read_count as u64);
        let start = read_count * SUPER_BYTES;
        out.copy_from_slice(&disk_bytes[start..start + SUPER_BYTES]);
        read_count += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(read_count, BLOCKS);
    assert_eq!(view.catalog(), catalog);
    let expected: [u8; 32] = Sha256::digest(&disk_bytes).into();
    assert_eq!(view.slot_digest(), expected);
}

#[test]
fn empty_view_rejects_corrupt_slots_identity_mismatches_and_io_errors() {
    let kind = UnifiedSystemKind::SnapshotSlot;
    let head = envelope(kind);
    assert_eq!(slot_proof(&[0; SUPER_BYTES], None), Err(Error::Invalid));
    assert_eq!(
        slot_proof(&envelope(UnifiedSystemKind::SnapshotCatalog), None),
        Err(Error::Invalid)
    );
    let mut bad_crc = head;
    bad_crc[32] ^= 1;
    assert_eq!(slot_proof(&bad_crc, None), Err(Error::Invalid));
    let mut nonzero_payload = head;
    nonzero_payload[ENVELOPE_BYTES] = 1;
    let crc = crc32c_zeroed(&nonzero_payload, 32).unwrap();
    nonzero_payload[32..36].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(slot_proof(&nonzero_payload, None), Err(Error::Invalid));

    for (uuid, generation) in [
        ([1; 16], CATALOG_GENERATION),
        (UUID, CATALOG_GENERATION + 1),
    ] {
        let mut wrong = [0; SUPER_BYTES];
        encode_object_envelope(kind, uuid, generation, &mut wrong).unwrap();
        assert_eq!(slot_proof(&wrong, None), Err(Error::Conflict));
    }
    for block in [
        SNAPSHOT_SLOT_START + 1,
        SNAPSHOT_SLOT_START + SNAPSHOT_STRIDE,
        SNAPSHOT_REQUEST_START - 1,
    ] {
        assert_eq!(
            slot_proof(&head, Some(u64::from(block))),
            Err(Error::Conflict)
        );
    }
    assert_eq!(
        EmptySnapshotView::verify(catalog_proof(), |block, out| {
            if block == u64::from(SNAPSHOT_REQUEST_START - 1) {
                return Err(Error::Unknown);
            }
            if block == u64::from(SNAPSHOT_SLOT_START) {
                *out = head;
            } else {
                out.fill(0);
            }
            Ok(())
        }),
        Err(Error::Unknown)
    );
}
