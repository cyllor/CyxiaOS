//! Append namespace admission shared by the native broker and host checks.
//! Existing-record identity equality and key-to-NodeID binding remain checked
//! by Driver::construct before any recovered protocol state is accepted.
pub(super) fn append_allowed(key: u64, used: u64, bytes: &[u8]) -> bool {
    if used == 0 || bytes.starts_with(b"CXID") {
        return initial_identity_allowed(key, used, bytes);
    }
    // Key zero means an append without a cluster Engine effect sequence. The
    // durable application input and placement intent/receipt have their own
    // immutable request identities, so they also use this namespace after the
    // first identity record. It must not permit a second identity or arbitrary
    // anonymous records. Driver recovery validates each journal's full framing,
    // payload hash and identity before it accepts any execution state.
    key != 0 || bytes.starts_with(b"CXAPP1") || bytes.starts_with(b"CXDP2")
}

pub(super) fn initial_identity_allowed(key: u64, used: u64, bytes: &[u8]) -> bool {
    // Both versions encode exactly magic[5] + UUID[16] + local[32] + peer[32].
    // CXID2 selects the native placement record family; it is not a prefix
    // wildcard or permission to replace an identity on an initialized volume.
    key == 0
        && used == 0
        && bytes.len() == 85
        && (&bytes[..5] == b"CXID1" || &bytes[..5] == b"CXID2")
}
