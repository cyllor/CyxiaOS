//! Detached boot permission for the ABI3 FILE_SERVICE package.

use super::{Error, PinnedStartupCatalog, VerifiedOfflineConfig, verify_startup_signature};
use crate::security::{file_auth_v3::FILE_SERVICE_ROLE, syscall_v3::ABI_VERSION};

const MAGIC: &[u8; 8] = b"CYXFSV01";
const DOMAIN: &[u8] = b"CYX/STARTUP-FILE-OWNER/v1";
pub const BYTES: usize = 24;
pub const CPU: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOwnerGrant {
    pub budget_ns: u64,
}

impl FileOwnerGrant {
    pub fn verify(
        catalog: &PinnedStartupCatalog<'_>,
        policy: &VerifiedOfflineConfig<'_>,
        package: [u8; 32],
        wire: &[u8; BYTES],
        signature: &[u8; 64],
    ) -> Result<Self, Error> {
        if policy.wire() != catalog.offline_config {
            return Err(Error::Conflict);
        }
        let budget_ns = u64::from_le_bytes(wire[16..].try_into().unwrap());
        if &wire[..8] != MAGIC
            || wire[8..10] != (FILE_SERVICE_ROLE as u16).to_le_bytes()
            || wire[10..12] != ABI_VERSION.to_le_bytes()
            || wire[12..14] != (CPU as u16).to_le_bytes()
            || wire[14..16] != [0; 2]
            || budget_ns == 0
            || package == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let mut message = [0; DOMAIN.len() + 64 + BYTES];
        let (prefix, body) = message.split_at_mut(DOMAIN.len());
        let (config, asset) = body.split_at_mut(32);
        let (image, grant) = asset.split_at_mut(32);
        prefix.copy_from_slice(DOMAIN);
        config.copy_from_slice(&policy.digest());
        image.copy_from_slice(&package);
        grant.copy_from_slice(wire);
        verify_startup_signature(catalog.boot_public_key, signature, &message)?;
        Ok(Self { budget_ns })
    }
}
