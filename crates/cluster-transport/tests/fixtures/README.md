These Ed25519 keys and self-signed certificates are public test fixtures only.
Never provision them into a guest image or real node. Generated locally with
OpenSSL 3.6.3 for reciprocal pinning, signature, and key mismatch tests.
The closed pairing verifier authenticates the SHA-256 fingerprint of the raw
Ed25519 public key and the live TLS CertificateVerify signature, not the dates.
