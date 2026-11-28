//! Detached boot permission for the ABI3 FILE_SERVICE package.

use super::{Error, PinnedStartupCatalog, VerifiedOfflineConfig, verify_startup_signature};
use crate::security::{
    file_auth_v3::FILE_SERVICE_ROLE, file_media_unified_v1::BUSINESS_INODES,
    offline_config_v1::Principal, syscall_v3::ABI_VERSION,
};

const MAGIC: &[u8; 8] = b"CYXFSV01";
const DOMAIN: &[u8] = b"CYX/STARTUP-FILE-OWNER/v1";
pub const BYTES: usize = 24;
pub const CPU: usize = 3;
pub const CLIENT_BYTES: usize = 64;
const CLIENT_DOMAIN: &[u8] = b"CYX/STARTUP-FILE-CLIENT/v1";

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

/// Offline grant for one signed CPU3 business client. The native mount must
/// still verify the ordinary inode, exact ACL owner and generations.
/// Wire offsets are magic 0, UUID 8, inode (u32) 24, principal slot 28,
/// CPU 29, ABI (u16) 30, inode generation 32, ACL generation 40, principal
/// ID 48 and principal generation 56. All integer fields are little-endian.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileClientGrant {
    pub fs_uuid: [u8; 16],
    pub inode: u32,
    pub inode_generation: u64,
    pub acl_generation: u64,
    pub principal: Principal,
    /// `CYXFCL02` explicitly opts in to ordinary WRITE and FSYNC authority.
    pub writable: bool,
}

impl FileClientGrant {
    pub fn verify(
        catalog: &PinnedStartupCatalog<'_>,
        policy: &VerifiedOfflineConfig<'_>,
        business: [u8; 32],
        owner: [u8; 32],
        wire: &[u8; CLIENT_BYTES],
        signature: &[u8; 64],
    ) -> Result<Self, Error> {
        if policy.wire() != catalog.offline_config {
            return Err(Error::Conflict);
        }
        let word = |offset| u64::from_le_bytes(wire[offset..offset + 8].try_into().unwrap());
        let writable = match &wire[..8] {
            b"CYXFCL01" => false,
            b"CYXFCL02" => true,
            _ => return Err(Error::Invalid),
        };
        let grant = Self {
            fs_uuid: wire[8..24].try_into().unwrap(),
            inode: u32::from_le_bytes(wire[24..28].try_into().unwrap()),
            inode_generation: word(32),
            acl_generation: word(40),
            principal: Principal {
                id: word(48),
                generation: word(56),
            },
            writable,
        };
        if wire[29] as usize != CPU
            || wire[30..32] != ABI_VERSION.to_le_bytes()
            || grant.fs_uuid != policy.header().fs_uuid
            || !(1..BUSINESS_INODES).contains(&grant.inode)
            || grant.inode_generation == 0
            || grant.acl_generation == 0
            || policy.principals().get(usize::from(wire[28])) != Some(&grant.principal)
            || business == [0; 32]
            || owner == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let mut message = [0; CLIENT_DOMAIN.len() + 96 + CLIENT_BYTES];
        let (domain, rest) = message.split_at_mut(CLIENT_DOMAIN.len());
        let (config, rest) = rest.split_at_mut(32);
        let (client_image, rest) = rest.split_at_mut(32);
        let (owner_image, grant_bytes) = rest.split_at_mut(32);
        domain.copy_from_slice(CLIENT_DOMAIN);
        config.copy_from_slice(&policy.digest());
        client_image.copy_from_slice(&business);
        owner_image.copy_from_slice(&owner);
        grant_bytes.copy_from_slice(wire);
        verify_startup_signature(catalog.boot_public_key, signature, &message)?;
        Ok(grant)
    }
}
