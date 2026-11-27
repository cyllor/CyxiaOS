//! Signing message shared by the offline build and the boot verifier.

const LABEL: &[u8] = b"CYX/STARTUP-LIFECYCLE-PACKAGES/v1";
const RECORD_BYTES: usize = 2 + 32 + 32;
const MESSAGE_BYTES: usize = LABEL.len() + 32 + 8 * RECORD_BYTES;

#[derive(Clone, Copy)]
pub struct LifecyclePackageDigest {
    pub role: u16,
    pub image: [u8; 32],
    pub relocations: [u8; 32],
}

pub(super) fn lifecycle_package_message(
    config_digest: [u8; 32],
    packages: [LifecyclePackageDigest; 8],
) -> [u8; MESSAGE_BYTES] {
    let mut message = [0; MESSAGE_BYTES];
    let (label, body) = message.split_at_mut(LABEL.len());
    label.copy_from_slice(LABEL);
    let (config, records) = body.split_at_mut(32);
    config.copy_from_slice(&config_digest);
    for (record, package) in records.chunks_exact_mut(RECORD_BYTES).zip(packages) {
        record[..2].copy_from_slice(&package.role.to_le_bytes());
        record[2..34].copy_from_slice(&package.image);
        record[34..].copy_from_slice(&package.relocations);
    }
    message
}
