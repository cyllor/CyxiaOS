use cyxia_kernel_core::security::{
    Error,
    file_media_unified_v1::{
        ENVELOPE_BYTES, LEGACY_SCHEMA_V2_MAGIC, SNAP_MAX_REQUEST_BYTES, SNAP_OP_ACK_REQUEST,
        SNAP_OP_CREATE, SNAP_OP_LIST, SUPER_BYTES, UnifiedSystemKind, encode_object_envelope,
    },
    file_media_v0199::crc32c_zeroed,
    file_service_v4::{
        REPLY_HEADER, REQUEST_HEADER, REQUEST_MAGIC, REQUEST_VERSION, Reply, Request,
    },
    snapshot_list_v4::{EmptyCatalog, LIST_ENDPOINT, LIST_SELECTOR, ListError, ListRequest},
};
use sha2::{Digest, Sha256};

const REQUEST_ID: u64 = 0x0102_0304_0506_0708;
const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
const CATALOG_GENERATION: u64 = 29;
const BOOT_EPOCH: u64 = 13;
const SERVICE_GENERATION: u64 = 31;

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

#[test]
fn list_has_a_separate_endpoint_and_a_zero_payload_request() {
    assert_eq!(LIST_ENDPOINT, 0x534e_4150_0000_0011);
    assert_eq!(LIST_SELECTOR, 0x534e_4150_0000_0024);
    let list = frame(SNAP_OP_LIST, 0);
    assert_eq!(ListRequest::decode(&list).unwrap().request_id, REQUEST_ID);
    assert_eq!(Request::decode(&list, LIST_SELECTOR), Err(Error::Invalid));

    let ordinary_close = frame(6, 4);
    assert!(Request::decode(&ordinary_close, 1).is_ok());
    assert_eq!(ListRequest::decode(&ordinary_close), Err(ListError::Format));
}

#[test]
fn list_rejects_bad_framing_field_by_field() {
    let good = frame(SNAP_OP_LIST, 0);
    for short in 0..REQUEST_HEADER {
        assert_eq!(ListRequest::decode(&good[..short]), Err(ListError::Format));
    }
    for (offset, name) in [
        (0, "magic"),
        (6, "header length"),
        (8, "unknown op"),
        (10, "flags"),
        (12, "payload length"),
        (31, "auth context"),
    ] {
        let mut malformed = good.clone();
        malformed[offset] ^= 0x80;
        assert_eq!(
            ListRequest::decode(&malformed),
            Err(ListError::Format),
            "{name}"
        );
    }
    let mut bad = good.clone();
    bad[16..24].fill(0);
    assert_eq!(ListRequest::decode(&bad), Err(ListError::Format));
    bad = good.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(ListRequest::decode(&bad), Err(ListError::Format));
    bad = good;
    bad.push(0);
    assert_eq!(ListRequest::decode(&bad), Err(ListError::Format));
    assert_eq!(
        ListRequest::decode(&frame(SNAP_OP_LIST, 1)),
        Err(ListError::Format)
    );
    assert_eq!(ListError::Format.errno(), -2);
}

#[test]
fn list_distinguishes_schema_errors_and_unsupported_snapshot_ops() {
    let mut old = frame(SNAP_OP_LIST, 0);
    old[4..6].copy_from_slice(&(REQUEST_VERSION - 1).to_le_bytes());
    assert_eq!(ListRequest::decode(&old), Err(ListError::Schema));
    let mut legacy = [0; 64];
    legacy[..4].copy_from_slice(&LEGACY_SCHEMA_V2_MAGIC.to_le_bytes());
    legacy[4..6].copy_from_slice(&2u16.to_le_bytes());
    legacy[6..8].copy_from_slice(&64u16.to_le_bytes());
    legacy[8..10].copy_from_slice(&SNAP_OP_LIST.to_le_bytes());
    assert_eq!(ListRequest::decode(&legacy), Err(ListError::Schema));
    assert_eq!(ListError::Schema.errno(), -3);

    for op in (SNAP_OP_CREATE..=SNAP_OP_ACK_REQUEST).filter(|op| *op != SNAP_OP_LIST) {
        assert_eq!(
            ListRequest::decode(&frame(op, 0)),
            Err(ListError::Unsupported),
            "op {op:#x}"
        );
    }
    let limit = SNAP_MAX_REQUEST_BYTES - REQUEST_HEADER;
    assert_eq!(
        ListRequest::decode(&frame(SNAP_OP_CREATE, limit)),
        Err(ListError::Unsupported)
    );
    assert_eq!(
        ListRequest::decode(&frame(SNAP_OP_CREATE, limit + 1)),
        Err(ListError::Format)
    );
    let mut malformed = frame(SNAP_OP_CREATE, 0);
    malformed[10] = 1;
    assert_eq!(ListRequest::decode(&malformed), Err(ListError::Format));
    assert_eq!(ListError::Unsupported.errno(), -11);
}

fn envelope(kind: UnifiedSystemKind) -> [u8; SUPER_BYTES] {
    let mut raw = [0; SUPER_BYTES];
    encode_object_envelope(kind, UUID, CATALOG_GENERATION, &mut raw).unwrap();
    raw
}

#[test]
fn empty_catalog_verifies_kind_identity_generation_epoch_and_entire_block() {
    let raw = envelope(UnifiedSystemKind::SnapshotCatalog);
    let proof = EmptyCatalog::verify(&raw, UUID, CATALOG_GENERATION, BOOT_EPOCH).unwrap();
    let identity_digest: [u8; 32] = Sha256::digest(raw).into();
    assert_eq!(proof.fs_uuid(), UUID);
    assert_eq!(proof.boot_epoch(), BOOT_EPOCH);
    assert_eq!(proof.generation(), CATALOG_GENERATION);
    assert_eq!(proof.digest(), identity_digest);
    assert!(EmptyCatalog::verify(&raw, [9; 16], CATALOG_GENERATION, BOOT_EPOCH).is_err());
    assert!(EmptyCatalog::verify(&raw, UUID, CATALOG_GENERATION + 1, BOOT_EPOCH).is_err());
    assert!(EmptyCatalog::verify(&raw, UUID, CATALOG_GENERATION, 0).is_err());

    let slot = envelope(UnifiedSystemKind::SnapshotSlot);
    assert!(EmptyCatalog::verify(&slot, UUID, CATALOG_GENERATION, BOOT_EPOCH).is_err());
    let mut bad_crc = raw;
    bad_crc[32] ^= 1;
    assert!(EmptyCatalog::verify(&bad_crc, UUID, CATALOG_GENERATION, BOOT_EPOCH).is_err());
    for offset in [36, ENVELOPE_BYTES, SUPER_BYTES - 1] {
        let mut nonzero = raw;
        nonzero[offset] = 0x80;
        let crc = crc32c_zeroed(&nonzero, 32).unwrap();
        nonzero[32..36].copy_from_slice(&crc.to_le_bytes());
        assert!(EmptyCatalog::verify(&nonzero, UUID, CATALOG_GENERATION, BOOT_EPOCH).is_err());
    }
}

#[test]
fn verified_catalog_emits_the_exact_volatile_reply_v3_header() {
    let raw = envelope(UnifiedSystemKind::SnapshotCatalog);
    let proof = EmptyCatalog::verify(&raw, UUID, CATALOG_GENERATION, BOOT_EPOCH).unwrap();
    let request = ListRequest::decode(&frame(SNAP_OP_LIST, 0)).unwrap();
    let reply = proof.reply(request, SERVICE_GENERATION).unwrap();
    let mut expected = [0; REPLY_HEADER];
    expected[..8].copy_from_slice(b"RFYC\x03\0\x80\0");
    expected[8..16].copy_from_slice(&REQUEST_ID.to_le_bytes());
    expected[16..24].copy_from_slice(&SERVICE_GENERATION.to_le_bytes());
    expected[72..80].copy_from_slice(&CATALOG_GENERATION.to_le_bytes());
    assert_eq!(reply, expected);

    let decoded = Reply::decode(&reply).unwrap();
    assert_eq!(decoded.request_id, REQUEST_ID);
    assert_eq!(decoded.service_generation, SERVICE_GENERATION);
    assert_eq!(decoded.target_generation, CATALOG_GENERATION);
    assert!(decoded.output.is_empty());
    assert_eq!(proof.reply(request, 0), Err(Error::Invalid));
    assert_eq!(
        proof.reply(ListRequest { request_id: 0 }, SERVICE_GENERATION),
        Err(Error::Invalid)
    );
}
