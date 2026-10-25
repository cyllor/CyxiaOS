use cyxia_prototype::cluster::wire::*;
#[test]
fn config_has_spec_offsets_and_rejects_trailing_or_unsorted_nodes() {
    let c = Config {
        trust_domain: [1; 32],
        nodes: [[2; 32], [3; 32]],
        counters: [4, 5],
        nonces: [[6; 32], [7; 32]],
        schema: [8; 32],
        policy: [9; 32],
        epoch: 10,
    };
    let bytes = c.encode();
    assert_eq!(bytes.len(), 252);
    assert_eq!(&bytes[100..108], &4u64.to_le_bytes());
    assert_eq!(&bytes[244..252], &10u64.to_le_bytes());
    assert_eq!(Config::decode(&bytes), Ok(c));
    let mut bad = bytes;
    bad[36..68].fill(4);
    assert!(Config::decode(&bad).is_err());
    assert!(Config::decode(&bytes[..251]).is_err());
}
#[test]
fn header_rejects_flags_unknown_type_and_oversize_before_body_allocation() {
    let h = Header {
        kind: 1,
        body_len: 64,
        sequence: 1,
        request: [0; 16],
        cluster: [0; 32],
        epoch: 0,
        sender_boot: 1,
        receiver_boot: 0,
    };
    let bytes = h.encode();
    assert_eq!(Header::decode(&bytes), Ok(h));
    let mut bad = bytes;
    bad[10] = 1;
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes;
    bad[6] = 7;
    assert!(Header::decode(&bad).is_err());
    let mut bad = bytes;
    bad[12..16].copy_from_slice(&65537u32.to_le_bytes());
    assert!(Header::decode(&bad).is_err());
}

#[test]
fn replay_status_and_opaque_kernel_billing_frames_keep_bounded_authenticated_header_rules() {
    let h = Header { kind: 48, body_len: 2048, sequence: 1, request: [7; 16], cluster: [8; 32],
        epoch: 2, sender_boot: 3, receiver_boot: 4 };
    for kind in [48, 0x8030, 0x8031, 56] {
        let value = Header { kind, ..h }; assert_eq!(Header::decode(&value.encode()), Ok(value));
        assert!(Header::decode(&Header { receiver_boot: 0, ..value }.encode()).is_err());
        assert!(Header::decode(&Header { sequence: 0, ..value }.encode()).is_err());
        assert!(Header::decode(&Header { body_len: 65537, ..value }.encode()).is_err());
    }
    for kind in [47, 50, 55, 57] { assert!(Header::decode(&Header { kind, ..h }.encode()).is_err()); }
}
