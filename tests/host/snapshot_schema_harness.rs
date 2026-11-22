#[path = "../../user/prototype-task/snapshot_abi.rs"]
mod wire;
use wire::*;

fn request_key() -> [u8; 36] {
    let mut key = [0; 36];
    key[..16].fill(7);
    put_u32(&mut key, 16, 3);
    put_u64(&mut key, 20, 11);
    put_u64(&mut key, 28, 19);
    key
}
fn key() -> [u8; 40] {
    let mut key = [0; 40];
    key[..16].fill(7);
    put_u64(&mut key, 16, 9);
    put_u32(&mut key, 24, 6);
    put_u64(&mut key, 32, 4);
    key
}
#[test]
fn header_and_response_have_independent_golden_offsets() {
    let mut request = RequestBuffer::new(SNAP_CREATE, 257, request_key(), 5);
    let payload = [0x10, 0x0e, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0];
    request.set_payload(&payload).unwrap();
    assert_eq!(&request.bytes[..16], &[0x32, 0x46, 0x59, 0x43, 2, 0, 64, 0, 32, 0, 0, 0, 80, 0, 0, 0]);
    assert_eq!(&request.bytes[16..52], &request_key());
    assert_eq!(&request.bytes[52..64], &[1, 1, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
    let decoded = Request::decode(request.as_bytes()).unwrap();
    assert_eq!(decoded.expected_live_view_epoch, 5);
    assert_eq!(decoded.payload, payload);
    let mut response = [0xa5; 128];
    assert_eq!(response_header(&mut response, SNAP_CREATE, -116, 4, 0), Ok(32));
    assert_eq!(&response[..16], &[0x32, 0x46, 0x59, 0x43, 2, 0, 32, 0, 32, 0, 0, 0, 32, 0, 0, 0]);
    assert_eq!(&response[16..32], &[0x8c, 0xff, 0xff, 0xff, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
}
#[test]
fn malformed_fields_are_rejected_before_payload_interpretation() {
    let good = RequestBuffer::new(SNAP_LIST, 256, [0; 36], 0);
    assert!(Request::decode(good.as_bytes()).is_ok());
    for (at, value) in [(4, 1), (6, 32), (10, 1), (12, 63), (16, 1), (56, 1)] {
        let mut bad = good;
        bad.bytes[at] = value;
        assert!(Request::decode(bad.as_bytes()).is_err(), "accepted field at {at}");
    }
    let bad = RequestBuffer::new(0x2c, 256, [0; 36], 0);
    assert!(matches!(Request::decode(bad.as_bytes()), Err(WireError::Unsupported)));
    assert!(Request::decode(&[0; 63]).is_err());
}
#[test]
fn historical_paths_are_canonical_and_component_scoped() {
    for path in [b"/team/a".as_slice(), b"/team", b"/"] {
        assert!(canonical_path(path));
    }
    for path in [b"/team/../secret".as_slice(), b"/team//a", b"/team/./a", b"team/a", b"/team/", b"/team/a\0"] {
        assert!(!canonical_path(path));
    }
    assert!(within_prefix(b"/team/a", b"/team"));
    assert!(!within_prefix(b"/teamish/a", b"/team"));
    assert!(!within_prefix(b"/", b"/team"));
    let mut request = RequestBuffer::new(SNAP_OPEN, 256, [0; 36], 0);
    let mut payload = [0; 55];
    payload[..40].copy_from_slice(&key());
    put_u16(&mut payload, 40, 7);
    payload[48..].copy_from_slice(b"/team/a");
    request.set_payload(&payload).unwrap();
    assert!(Request::decode(request.as_bytes()).is_ok());
    request.bytes[HEADER_BYTES + 42] = 1;
    assert!(Request::decode(request.as_bytes()).is_err());
}
#[test]
fn opaque_keys_are_complete_and_readonly_requests_have_no_mutation_key() {
    assert!(snapshot_key_valid(&key()));
    let mut wrong = key();
    wrong[28] = 1;
    assert!(!snapshot_key_valid(&wrong));
    wrong = key();
    wrong[24] = 8;
    assert!(!snapshot_key_valid(&wrong));
    assert!(request_key_valid(&request_key(), false));
    assert!(!request_key_valid(&[0; 36], false));
    let mut query = RequestBuffer::new(QUERY_REQUEST, 256, [0; 36], 0);
    query.set_payload(&request_key()).unwrap();
    assert!(Request::decode(query.as_bytes()).is_ok());
    query.bytes[16..52].copy_from_slice(&request_key());
    assert!(Request::decode(query.as_bytes()).is_err());
}
