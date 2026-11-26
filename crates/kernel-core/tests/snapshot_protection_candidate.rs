use cyxia_kernel_core::security::file_media_unified_v1::{
    SUPER_BYTES, UnifiedSystemKind, decode_object_envelope, protection_candidate::ProtectionRecord,
};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../tools/fixtures/v020-g1-protection.tsv");

fn hex(digits: &str) -> Vec<u8> {
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).unwrap())
        .collect()
}

#[test]
fn independent_wire_vectors_bind_the_candidate_without_opening_the_mount() {
    let mut rows = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        let [case, verdict, sha, prefix] = fields[..] else {
            panic!("bad ProtectionStore vector row: {line}");
        };
        let prefix = hex(prefix);
        let mut raw = [0; SUPER_BYTES];
        raw[..prefix.len()].copy_from_slice(&prefix);
        assert_eq!(Sha256::digest(raw).as_slice(), hex(sha), "{case}");
        let record = ProtectionRecord::decode(&raw);
        assert_eq!(record.is_ok(), verdict == "accept", "{case}");
        if let Ok(record) = record {
            let mut reproduced = [0; SUPER_BYTES];
            record.encode(&mut reproduced).unwrap();
            assert!(raw == reproduced, "{case}");
        }
        assert_eq!(
            decode_object_envelope(UnifiedSystemKind::SnapshotProtection, &raw).is_ok(),
            case == "empty-envelope",
            "{case}",
        );
        rows += 1;
    }
    assert_eq!(rows, 10);
}
