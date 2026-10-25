#![cfg(feature = "tls")]
use cyxia_cluster_transport::tls::{IdentitySigner, node_id, public_key};
use rustls::pki_types::CertificateDer;
#[test]
fn membership_signatures_bind_exact_message_and_pinned_node() {
    let cert = CertificateDer::from(&include_bytes!("fixtures/a-test-cert.der")[..]);
    let public = public_key(&cert).unwrap();
    let signer = IdentitySigner::new(include_bytes!("fixtures/a-test-key.der"), public).unwrap();
    assert_eq!(signer.public_key(), public);
    let signature = signer.sign(b"formation-proof");
    assert!(IdentitySigner::verify(
        &public,
        &node_id(&cert).unwrap(),
        b"formation-proof",
        &signature
    ));
    assert!(!IdentitySigner::verify(
        &public,
        &[0; 32],
        b"formation-proof",
        &signature
    ));
    assert!(!IdentitySigner::verify(
        &public,
        &node_id(&cert).unwrap(),
        b"other-proof",
        &signature
    ));
    assert!(IdentitySigner::new(include_bytes!("fixtures/b-test-key.der"), public).is_err());
}
