use cyxia_contracts::tls_signer::{Request, certificate_verify_hash, certificate_verify_message};

const REQUEST: Request = Request {
    boot_epoch: 11,
    verifier_generation: 12,
    conn_id: 13,
    conn_generation: 14,
    key_generation: 15,
    nonce: 16,
    expires_ns: 17,
    transcript_hash: [0x58; 32],
};

#[test]
fn request_preserves_frozen_signer_v2_offsets() {
    let wire = REQUEST.encode();
    assert_eq!(&wire[..8], &[0x47, 0x53, 0x59, 0x43, 2, 0, 112, 0]);
    assert_eq!(&wire[32..40], &14u64.to_le_bytes());
    assert_eq!(&wire[48..56], &16u64.to_le_bytes());
    assert_eq!(&wire[64..96], &REQUEST.transcript_hash);
    assert_eq!(&wire[96..98], &1u16.to_le_bytes());
    assert_eq!(Request::decode(&wire), Some(REQUEST));
}

#[test]
fn completion_matches_only_its_issued_connection_and_key_generation() {
    let signature = [0x7b; 64];
    let wire = REQUEST.encode_reply(&signature);
    assert_eq!(REQUEST.reply_signature(&wire), Some(signature));
    let next = Request {
        key_generation: 16,
        ..REQUEST
    };
    assert_eq!(next.reply_signature(&wire), None);
    let next = Request {
        conn_generation: 15,
        ..REQUEST
    };
    assert_eq!(next.reply_signature(&wire), None);
}

#[test]
fn certificate_verify_uses_the_standard_server_context() {
    let message = certificate_verify_message(&REQUEST.transcript_hash);
    assert_eq!(&message[..64], &[0x20; 64]);
    assert_eq!(&message[64..98], b"TLS 1.3, server CertificateVerify\0");
    assert_eq!(
        certificate_verify_hash(&message),
        Some(REQUEST.transcript_hash)
    );
}
