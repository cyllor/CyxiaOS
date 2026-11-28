//! Boot catalog signing message for an independently supplied business PIE.

const LABEL: &[u8] = b"CYX/STARTUP-BUSINESS-PACKAGE/v1";
const MESSAGE_BYTES: usize = LABEL.len() + 32 + 32;
const TASK_LABEL: &[u8] = b"CYX/STARTUP-BUSINESS-TASK-SERVICES/v1";
pub const TASK_SERVICES_BYTES: usize = 32;
const TASK_MESSAGE_BYTES: usize = TASK_LABEL.len() + 32 + 32 + TASK_SERVICES_BYTES;

pub(super) fn task_services_message(
    config_digest: [u8; 32],
    package_digest: [u8; 32],
    grants: &[u8; TASK_SERVICES_BYTES],
) -> [u8; TASK_MESSAGE_BYTES] {
    let mut message = [0; TASK_MESSAGE_BYTES];
    let (label, body) = message.split_at_mut(TASK_LABEL.len());
    let (config, body) = body.split_at_mut(32);
    let (package, policy) = body.split_at_mut(32);
    label.copy_from_slice(TASK_LABEL);
    config.copy_from_slice(&config_digest);
    package.copy_from_slice(&package_digest);
    policy.copy_from_slice(grants);
    message
}

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
