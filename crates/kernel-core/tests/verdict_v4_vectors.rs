use cyxia_kernel_core::security::{
    Error,
    verdict_v4::{ProofClass, Status, VERDICT_BYTES, VerdictV4},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const VECTORS: &str = include_str!("../../../tools/fixtures/v0199-verdict-v4.tsv");

fn hex(digits: &str) -> Vec<u8> {
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn proof(wire: &str) -> ProofClass {
    match wire {
        "1" => ProofClass::RuntimeQemu,
        "2" => ProofClass::StaticEl1,
        "3" => ProofClass::ArchA53,
        "4" => ProofClass::ModelCheck,
        _ => panic!("invalid fixture proof class"),
    }
}

fn fixture(
    test_id: u32,
    proof_class: ProofClass,
    status: Status,
    reason_code: u32,
    evidence_count: u32,
) -> VerdictV4 {
    let ramp = |start: u8| core::array::from_fn(|i| start + i as u8);
    VerdictV4 {
        run_id: 0x0123_4567_89ab_cdef,
        test_id,
        status,
        proof_class,
        checker_id: (test_id & 0xffff_0000) | 0x3412,
        checker_version: 0x0102_0304,
        reason_code,
        evidence_count,
        boot_epoch: 0x1011_1213_1415_1617,
        controller_epoch: 0x1819_1a1b_1c1d_1e1f,
        security_epoch: 0x2021_2223_2425_2627,
        object_or_stream_generation: 0x2829_2a2b_2c2d_2e2f,
        seed: 0x3031_3233_3435_3637,
        fault_point_id: 0x3839_3a3b_3c3d_3e3f,
        design_hash: ramp(1),
        binary_hash: ramp(33),
        security_profile_hash: ramp(65),
        input_hash: ramp(97),
        rule_hash: ramp(129),
        evidence_digest: if evidence_count == 0 {
            [0; 32]
        } else {
            ramp(161)
        },
    }
}

#[test]
fn positive_reference_bytes_cover_proof_classes_and_reason_codes() {
    let mut reasons = BTreeSet::new();
    let mut classes = BTreeSet::new();
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        let [name, case, class, status, reason, count, wire] = fields[..] else {
            panic!("malformed Verdict v4 reference vector");
        };
        let expected = fixture(
            u32::from_str_radix(case, 16).unwrap(),
            proof(class),
            match status {
                "0" => Status::NotRun,
                "1" => Status::Pass,
                "2" => Status::Fail,
                _ => panic!("invalid fixture status"),
            },
            reason.parse().unwrap(),
            count.parse().unwrap(),
        );
        let raw = hex(wire);
        assert_eq!(VerdictV4::decode(&raw), Ok(expected.clone()), "{name}");
        assert_eq!(expected.encode().unwrap(), raw.as_slice(), "{name}");
        reasons.insert(expected.reason_code);
        classes.insert(expected.proof_class as u16);
    }
    assert_eq!(reasons, (0..10).collect());
    assert_eq!(classes, (1..=4).collect());
}

#[test]
fn all_262_g4_records_match_the_reference_corpus() {
    let expected = VECTORS
        .lines()
        .find_map(|line| line.strip_prefix("# g4-corpus-sha256: "))
        .unwrap();
    let mut digest = Sha256::new();
    let mut keys = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for key in VECTORS
        .lines()
        .filter_map(|line| line.strip_prefix("# g4-pairs: "))
        .flat_map(str::split_ascii_whitespace)
    {
        let (case, class) = key.split_once('-').unwrap();
        let test = u32::from_str_radix(case, 16).unwrap();
        let class = proof(class);
        let record = fixture(test, class, Status::NotRun, 2, 0);
        let bytes = record.encode().unwrap();
        assert_eq!(VerdictV4::decode(&bytes), Ok(record));
        digest.update(bytes);
        assert!(keys.insert((test, class as u16)));
        ids.insert(test);
    }
    assert_eq!((keys.len(), ids.len()), (262, 127));
    assert_eq!(digest.finalize().as_slice(), hex(expected));
}

fn reseal(raw: &mut [u8; VERDICT_BYTES]) {
    let mut digest = Sha256::new();
    digest.update(b"CYX/VERDICT/v4");
    digest.update(&raw[..288]);
    raw[288..].copy_from_slice(&digest.finalize());
}

#[test]
fn rehashed_invalid_fields_are_rejected() {
    let mut pass = fixture(0x0005_0008, ProofClass::RuntimeQemu, Status::Pass, 0, 2);
    let original = pass.encode().unwrap();
    for (offset, bytes) in [
        (0, &[0; 4][..]),
        (4, &[3, 0]),
        (6, &[0x3f, 1]),
        (8, &[0; 8]),
        (16, &[0x0c, 0, 8, 0]), // Deleted A12.
        (20, &[3, 0]),
        (22, &[5, 0]),
        (24, &[1, 0, 6, 0]),
        (24, &[0, 0, 5, 0]),
        (28, &[0; 4]),
        (32, &[4, 0, 0, 0]),
        (36, &[0; 4]),
        (88, &[1]),
        (256, &[0; 32]),
    ] {
        let mut changed = original;
        changed[offset..offset + bytes.len()].copy_from_slice(bytes);
        reseal(&mut changed);
        assert_eq!(VerdictV4::decode(&changed), Err(Error::Invalid), "{offset}");
    }
    assert_eq!(VerdictV4::decode(&original[..319]), Err(Error::Invalid));
    let mut wrong_digest = original;
    wrong_digest[319] ^= 1;
    assert_eq!(VerdictV4::decode(&wrong_digest), Err(Error::Invalid));
    pass.evidence_count = 0;
    pass.evidence_digest = [0; 32];
    assert_eq!(pass.encode(), Err(Error::Invalid));
}
