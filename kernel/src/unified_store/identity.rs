//! Exact initial identity framing shared by the native broker and host checks.
//! Existing-record identity equality and key-to-NodeID binding remain checked
//! by Driver::construct before any recovered protocol state is accepted.
pub(super) fn initial_identity_allowed(key: u64, used: u64, bytes: &[u8]) -> bool {
    // Both versions encode exactly magic[5] + UUID[16] + local[32] + peer[32].
    // CXID2 selects the native placement record family; it is not a prefix
    // wildcard or permission to replace an identity on an initialized volume.
    key == 0
        && used == 0
        && bytes.len() == 85
        && (&bytes[..5] == b"CXID1" || &bytes[..5] == b"CXID2")
}
