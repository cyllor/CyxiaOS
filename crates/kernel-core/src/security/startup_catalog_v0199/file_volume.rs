//! Detached authority for the native canonical unified v1 volume.

use super::{Error, VerifiedOfflineConfig, verify_startup_signature};
use crate::security::{
    file_media_unified_v1::{UNIFIED_SYSTEM_OBJECTS, UnifiedSystemKind as Kind},
    file_media_v0199::DATA_START,
    offline_config_v1::Principal,
};

const MAGIC: &[u8; 8] = b"CYXFVOL1";
const DOMAIN: &[u8] = b"CYX/STARTUP-FILE-VOLUME/v1";
const HEADER: usize = 40;
const ENTRY: usize = 16;
pub const BYTES: usize = HEADER + UNIFIED_SYSTEM_OBJECTS * ENTRY;
const MESSAGE_BYTES: usize = DOMAIN.len() + 32 + BYTES;

const MAP: [(Kind, u32); UNIFIED_SYSTEM_OBJECTS] = [
    (Kind::SnapshotCatalog, DATA_START + 13),
    (Kind::BootEpoch, DATA_START),
    (Kind::SnapshotSlot, DATA_START + 14),
    (Kind::SnapshotProtection, DATA_START + 150),
    (Kind::SnapshotRequest, DATA_START + 134),
    (Kind::Receipts, DATA_START + 1),
    (Kind::Acl, DATA_START + 8),
    (Kind::Security, DATA_START + 12),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnifiedFileVolume {
    root_owner: Principal,
}

impl UnifiedFileVolume {
    pub const fn root_owner(self) -> Principal {
        self.root_owner
    }

    pub fn verify(
        config: &VerifiedOfflineConfig<'_>,
        key: &[u8; 32],
        wire: &[u8],
        signature: &[u8],
    ) -> Result<Option<Self>, Error> {
        if wire.is_empty() && signature.is_empty() {
            return Ok(None);
        }
        let wire: &[u8; BYTES] = wire.try_into().map_err(|_| Error::Invalid)?;
        let signature = signature.try_into().map_err(|_| Error::Invalid)?;
        let root_owner = Principal {
            id: u64::from_le_bytes(wire[24..32].try_into().unwrap()),
            generation: u64::from_le_bytes(wire[32..40].try_into().unwrap()),
        };
        verify_startup_signature(key, signature, &message(config.digest(), wire))?;
        if !config.principals().contains(&root_owner) {
            return Err(Error::Unauthorized);
        }
        if *wire != encode(config.header().fs_uuid, root_owner) {
            return Err(Error::Conflict);
        }
        Ok(Some(Self { root_owner }))
    }
}

fn encode(uuid: [u8; 16], root_owner: Principal) -> [u8; BYTES] {
    let mut wire = [0; BYTES];
    wire[..8].copy_from_slice(MAGIC);
    wire[8..24].copy_from_slice(&uuid);
    wire[24..32].copy_from_slice(&root_owner.id.to_le_bytes());
    wire[32..40].copy_from_slice(&root_owner.generation.to_le_bytes());
    for (entry, (kind, first)) in wire[HEADER..].chunks_exact_mut(ENTRY).zip(MAP) {
        entry[..2].copy_from_slice(&kind.inode_slot().to_le_bytes());
        entry[2..4].copy_from_slice(&(kind.blocks() as u16).to_le_bytes());
        entry[4..8].copy_from_slice(&first.to_le_bytes());
        entry[8..16].copy_from_slice(&1u64.to_le_bytes());
    }
    wire
}

fn message(config_digest: [u8; 32], wire: &[u8; BYTES]) -> [u8; MESSAGE_BYTES] {
    let mut out = [0; MESSAGE_BYTES];
    let (domain, body) = out.split_at_mut(DOMAIN.len());
    let (digest, contents) = body.split_at_mut(32);
    domain.copy_from_slice(DOMAIN);
    digest.copy_from_slice(&config_digest);
    contents.copy_from_slice(wire);
    out
}
