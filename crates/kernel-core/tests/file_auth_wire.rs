use std::collections::BTreeMap;

use cyxia_kernel_core::security::{
    Error,
    file_auth_v3::{
        ADMIT_REPLY_BYTES, ADMIT_REQUEST_BYTES, AdmitReplyV3, AdmitRequestV3, COMPLETE_REPLY_BYTES,
        COMPLETE_REQUEST_BYTES, CompleteReplyV1, CompleteRequestV1, FileAuthOp, discriminate_op,
        frozen_data_digest, operation_digest,
    },
};

const VECTORS: &str = include_str!("../../../tools/fixtures/v020-g1-file-auth-wire.tsv");
const CONTEXT: u64 = 0x1122_3344_5566_7788;
const ADMISSION: u64 = 0xfedc_ba98_7654_3210;

struct Vector<'a> {
    kind: &'a str,
    context: &'a str,
    expect: &'a str,
    input: Vec<u8>,
    output: Vec<u8>,
}

fn hex(digits: &str) -> Vec<u8> {
    if digits == "-" {
        return Vec::new();
    }
    assert_eq!(digits.len() % 2, 0);
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

fn vectors() -> BTreeMap<&'static str, Vector<'static>> {
    let mut result = BTreeMap::new();
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        let [name, kind, context, expect, input, output] = fields[..] else {
            panic!("bad fixture row {line:?}");
        };
        assert!(
            result
                .insert(
                    name,
                    Vector {
                        kind,
                        context,
                        expect,
                        input: hex(input),
                        output: hex(output),
                    },
                )
                .is_none(),
            "duplicate fixture row {name}"
        );
    }
    result
}

fn accepted<T>(side: Result<T, Error>, expected: &str, name: &str) -> Option<T> {
    match expected {
        "accept" => Some(side.unwrap_or_else(|error| panic!("{name}: {error:?}"))),
        "schema" | "invalid" => {
            assert!(matches!(side, Err(Error::Invalid)), "{name}");
            None
        }
        other => panic!("unknown expected outcome {other} for {name}"),
    }
}

#[test]
fn file_auth_frames_match_independent_request_and_reply_bytes() {
    let rows = vectors();
    for (&name, vector) in &rows {
        let raw = vector.input.as_slice();
        let value = vector.context;
        let expected = vector.expect;
        let op = match vector.kind {
            "admit-request" => Some(FileAuthOp::AdmitV3),
            "complete-request" => Some(FileAuthOp::CompleteV1),
            _ => None,
        };
        if let Some(op) = op {
            let expected_op = if expected == "schema" {
                Err(Error::Invalid)
            } else {
                Ok(op)
            };
            assert_eq!(discriminate_op(raw), expected_op, "{name}");
        }
        match vector.kind {
            "admit-request" => {
                if let Some(admit) = accepted(AdmitRequestV3::decode(raw), expected, name) {
                    assert_eq!(admit.auth_context_id, CONTEXT, "{name}");
                    assert_eq!(admit.target_id, 127, "{name}");
                    assert_eq!(admit.target_generation, 0x1_0000_0203, "{name}");
                    assert_eq!(admit.required_rights, 0x2000, "{name}");
                    assert_eq!(admit.request_seq, 0x0100_0000_0000_0029, "{name}");
                    assert_eq!(admit.prepared_version, 0x8877_6655_4433_2211, "{name}");
                    assert_eq!(admit.acl_generation, 0x40805, "{name}");
                    let mut encoded = [0xff; ADMIT_REQUEST_BYTES];
                    admit.encode(&mut encoded);
                    assert_eq!(encoded.as_slice(), raw, "{name}");
                }
            }
            "admit-reply" => {
                if let Some(reply) = accepted(AdmitReplyV3::decode(raw), expected, name) {
                    let verdict: u16 = value.parse().unwrap();
                    assert_eq!(reply.verdict.as_u16(), verdict, "{name}");
                    assert_eq!(reply.auth_context_id, CONTEXT, "{name}");
                    assert_eq!(reply.deny_generation, 0x10005, "{name}");
                    let grant = if verdict == 1 {
                        (ADMISSION, 0x1_2345_6789)
                    } else {
                        (0, 0)
                    };
                    assert_eq!(
                        (reply.admission_id, reply.accepted_local_ns),
                        grant,
                        "{name}"
                    );
                    let mut encoded = [0xff; ADMIT_REPLY_BYTES];
                    reply.encode(&mut encoded).unwrap();
                    assert_eq!(encoded.as_slice(), raw, "{name}");
                }
            }
            "complete-request" => {
                if let Some(report) = accepted(CompleteRequestV1::decode(raw), expected, name) {
                    let state: u16 = value.parse().unwrap();
                    assert_eq!(report.admission_id, ADMISSION, "{name}");
                    assert_eq!(report.terminal_state.as_u16(), state, "{name}");
                    assert_eq!(report.terminal_state.is_terminal(), state != 3, "{name}");
                    assert_eq!(
                        report.terminal_state.receipt_status(true),
                        [3, 4, 5, 6][usize::from(state - 1)],
                        "{name}"
                    );
                    assert_eq!(report.evidence_digest.as_slice(), &raw[24..56], "{name}");
                    let mut encoded = [0xff; COMPLETE_REQUEST_BYTES];
                    report.encode(&mut encoded).unwrap();
                    assert_eq!(encoded.as_slice(), raw, "{name}");
                }
            }
            "complete-reply" => {
                if let Some(reply) = accepted(CompleteReplyV1::decode(raw), expected, name) {
                    assert_eq!(reply.result, value.parse::<i32>().unwrap(), "{name}");
                    let mut encoded = [0xff; COMPLETE_REPLY_BYTES];
                    reply.encode(&mut encoded);
                    assert_eq!(encoded.as_slice(), raw, "{name}");
                }
            }
            "frozen" | "binding" => {}
            kind => panic!("unknown wire kind {kind} for {name}"),
        }
    }
}

#[test]
fn file_auth_digests_match_independent_sha256_and_reject_changed_binding() {
    let rows = vectors();
    for (proposal_name, data_name) in [
        ("admit-frozen", "frozen-data-digest"),
        ("admit-no-data", "empty-data-digest"),
    ] {
        let proposal = AdmitRequestV3::decode(&rows[proposal_name].input).unwrap();
        let data = &rows[data_name];
        assert_eq!(proposal.frozen_data_digest.as_slice(), data.output);
        assert_eq!(frozen_data_digest(&data.input), proposal.frozen_data_digest);
    }

    for (&name, row) in rows.iter().filter(|(_, row)| row.kind == "binding") {
        let (boot_epoch, proposal) = row.context.split_once(':').unwrap();
        let proposal = AdmitRequestV3::decode(&rows[proposal].input).unwrap();
        let digest = operation_digest(boot_epoch.parse().unwrap(), &row.input, &proposal);
        match row.expect {
            "invalid" => assert_eq!(digest, Err(Error::Invalid), "{name}"),
            "accept" | "mismatch" => {
                let digest = digest.unwrap_or_else(|error| panic!("{name}: {error:?}"));
                assert_eq!(digest.as_slice(), row.output, "{name}");
                assert_eq!(
                    digest == proposal.operation_digest,
                    row.expect == "accept",
                    "{name}"
                );
            }
            expected => panic!("unknown expected outcome {expected} for {name}"),
        }
    }
}
