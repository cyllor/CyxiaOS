//! Boot catalog signing message for an independently supplied business PIE.

const LABEL: &[u8] = b"CYX/STARTUP-BUSINESS-PACKAGE/v1";
const MESSAGE_BYTES: usize = LABEL.len() + 32 + 32;

pub(super) fn business_package_message(
    config_digest: [u8; 32],
    package_digest: [u8; 32],
) -> [u8; MESSAGE_BYTES] {
    let mut message = [0; MESSAGE_BYTES];
    let (label, body) = message.split_at_mut(LABEL.len());
    let (config, package) = body.split_at_mut(32);
    label.copy_from_slice(LABEL);
    config.copy_from_slice(&config_digest);
    package.copy_from_slice(&package_digest);
    message
}
