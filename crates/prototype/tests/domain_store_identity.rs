#[path = "../../../kernel/src/unified_store/identity.rs"]
mod identity;

fn record(version: &[u8; 5]) -> [u8; 85] {
    let mut record = [0; 85];
    record[..5].copy_from_slice(version);
    record[5..21].copy_from_slice(&[0x24; 16]);
    record[21..53].copy_from_slice(&[0x31; 32]);
    record[53..85].copy_from_slice(&[0x47; 32]);
    record
}

#[test]
fn native_and_legacy_exact_85_byte_identity_records_can_initialize_empty_volume() {
    for version in [b"CXID1", b"CXID2"] {
        let bytes = record(version);
        assert!(identity::initial_identity_allowed(0, 0, &bytes));
    }
}

#[test]
fn identity_version_support_does_not_relax_key_or_empty_volume_requirements() {
    for version in [b"CXID1", b"CXID2"] {
        let bytes = record(version);
        for key in [1, u64::MAX] {
            assert!(!identity::initial_identity_allowed(key, 0, &bytes));
        }
        for used in [1, 85, u64::MAX] {
            assert!(!identity::initial_identity_allowed(0, used, &bytes));
        }
    }
}

#[test]
fn truncation_suffixes_unknown_versions_and_header_corruption_are_rejected() {
    for version in [b"CXID1", b"CXID2"] {
        let bytes = record(version);
        for len in 0..85 {
            assert!(!identity::initial_identity_allowed(0, 0, &bytes[..len]));
        }
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(!identity::initial_identity_allowed(0, 0, &extended));
        for index in 0..5 {
            let mut corrupt = bytes;
            corrupt[index] ^= 0x80;
            assert!(!identity::initial_identity_allowed(0, 0, &corrupt));
        }
    }
    for version in [b"CXID0", b"CXID3", b"CXID\0", b"CXE1\0"] {
        assert!(!identity::initial_identity_allowed(0, 0, &record(version)));
    }
}
