//! Read-only D7 fixture with one occupied snapshot and one historical file.
//! The trusted owner supplies independently authenticated capture bounds, block
//! custody, caller, grant, and current ACL. Nothing here admits an unverified
//! volume, issues a capability, or modifies a catalogue or disk block.

use sha2::{Digest, Sha256};

use super::{
    BLOCK_COUNT, CANONICAL_BUSINESS_START, Error, INODE_BYTES, SLOT_MIRROR_BLOCKS,
    SNAP_CAP_HISTORY_READ, SNAPSHOT_CATALOG_BLOCK, SUPER_BYTES, cap_word_valid,
    catalog_candidate::{CatalogContext, CatalogEntry, verify_catalog},
    crc32c_zeroed,
    slot_candidate::SlotIdentity,
};
use crate::security::{
    boot_epoch_v1::BootEpochStoreV1,
    file::validate_absolute_path,
    file_format_v1::{
        SCRATCH_FILE_GENERATION, SCRATCH_FILE_INODE, SCRATCH_FILE_OWNER_RIGHTS, scratch_file_dirent,
    },
    file_mount_v1::Acl,
    file_structure_v1::{Extent, Inode},
    offline_config_v1::Principal,
    snapshot_read_v4::history_prefix_digest,
};

const FILE: &[u8] = b"/readme.txt";
const DIRENT: usize = 128;

/// Independent expectations from the read-only fixture owner. The root and
/// data blocks must be owned exclusively by the selected captured view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySource {
    pub catalog: CatalogContext,
    pub catalog_sha256: [u8; 32],
    pub root_block: u32,
    pub data_block: u32,
    pub data_sha256: [u8; 32],
}

/// Trusted capability table values, after caller authentication and lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryReadGrant<'a> {
    pub boot_epoch: u64,
    pub principal: Principal,
    pub snapshot: SlotIdentity,
    pub snapshot_rights: u32,
    pub acl_generation: u64,
    pub prefix: &'a [u8],
    pub prefix_sha256: [u8; 32],
}

/// Identities checked independently of the capability being presented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryCaller {
    pub boot: BootEpochStoreV1,
    pub principal: Principal,
    pub file_acl: Acl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRead {
    pub snapshot: SlotIdentity,
    pub bytes: usize,
    pub data_sha256: [u8; 32],
}

pub fn read_history(
    source: &HistorySource,
    caller: HistoryCaller,
    grant: HistoryReadGrant<'_>,
    path: &[u8],
    mut read: impl FnMut(u32, &mut [u8; SUPER_BYTES]) -> Result<(), Error>,
    out: &mut [u8; SUPER_BYTES],
) -> Result<HistoryRead, Error> {
    validate_absolute_path(path)?;
    if caller.boot.boot_epoch == 0 || caller.boot.boot_epoch != grant.boot_epoch {
        return Err(Error::Stale);
    }
    if !cap_word_valid(grant.snapshot_rights)
        || grant.snapshot_rights & SNAP_CAP_HISTORY_READ == 0
        || caller.principal.id == 0
        || caller.principal.generation == 0
        || caller.principal != grant.principal
        || caller.file_acl.principal != caller.principal
        || caller.file_acl.state != 1
        || caller.file_acl.inode_id != SCRATCH_FILE_INODE
        || caller.file_acl.owner_rights & SCRATCH_FILE_OWNER_RIGHTS == 0
        || caller.file_acl.acl_generation == 0
        || caller.file_acl.parent != 0
        || source.catalog.fs_uuid != caller.boot.fs_uuid
        || grant.snapshot.fs_uuid != caller.boot.fs_uuid
        || path != FILE
        || !matches!(grant.prefix, b"/" | FILE)
        || history_prefix_digest(grant.prefix) != grant.prefix_sha256
    {
        return Err(Error::Unauthorized);
    }
    if grant.acl_generation != caller.file_acl.acl_generation {
        return Err(Error::Stale);
    }
    let business = CANONICAL_BUSINESS_START..BLOCK_COUNT;
    if !business.contains(&source.root_block)
        || !business.contains(&source.data_block)
        || source.root_block == source.data_block
    {
        return Err(Error::Conflict);
    }

    let mut raw = [0; SUPER_BYTES];
    read(SNAPSHOT_CATALOG_BLOCK, &mut raw)?;
    let catalog_digest: [u8; 32] = Sha256::digest(raw).into();
    if catalog_digest != source.catalog_sha256 {
        return Err(Error::Conflict);
    }
    let mut captured = None;
    let mirror_first = grant.snapshot.descriptor_block()? + 1;
    let mirrors = mirror_first..mirror_first + SLOT_MIRROR_BLOCKS;
    let catalog = verify_catalog(
        SNAPSHOT_CATALOG_BLOCK,
        &raw,
        source.catalog,
        |block, buf| {
            read(block, buf)?;
            if block == mirror_first {
                // Retain the inodes from the same bytes that verify_slot hashes.
                captured = Some((
                    Inode::decode(&buf[..INODE_BYTES])?,
                    Inode::decode(&buf[INODE_BYTES..2 * INODE_BYTES])?,
                ));
            }
            if mirrors.contains(&block) {
                let first = if block == mirror_first {
                    2 * INODE_BYTES
                } else {
                    0
                };
                for bytes in buf[first..].chunks_exact(INODE_BYTES) {
                    if Inode::decode(bytes)?.kind != 0 {
                        return Err(Error::Conflict);
                    }
                }
            }
            Ok(())
        },
    )?;
    if !matches!(catalog.entries[grant.snapshot.slot as usize], CatalogEntry::Active(binding)
            if binding.identity == grant.snapshot)
    {
        return Err(Error::Stale);
    }
    if catalog
        .entries
        .iter()
        .filter(|entry| !matches!(entry, CatalogEntry::Free { .. }))
        .count()
        != 1
    {
        return Err(Error::Conflict);
    }
    let (root, inode) = captured.ok_or(Error::Conflict)?;
    if inode.generation != SCRATCH_FILE_GENERATION
        || inode.generation != caller.file_acl.inode_generation
        || inode.parent != 0
        || inode.parent_generation != root.generation
    {
        return Err(Error::Stale);
    }
    if root.kind != 2
        || root.size != DIRENT as u64
        || inode.kind != 1
        || !(1..=SUPER_BYTES as u64).contains(&inode.size)
        || [root, inode]
            .into_iter()
            .zip([source.root_block, source.data_block])
            .any(|(inode, block)| {
                inode.extents != 1
                    || inode.runs[0]
                        != (Extent {
                            logical: 0,
                            physical: block,
                            count: 1,
                        })
            })
    {
        return Err(Error::Conflict);
    }

    read(source.root_block, &mut raw)?;
    let mut unused = [0; DIRENT];
    unused[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let crc = crc32c_zeroed(&unused, DIRENT - 4)?;
    unused[DIRENT - 4..].copy_from_slice(&crc.to_le_bytes());
    if raw[..DIRENT] != scratch_file_dirent()?
        || raw[DIRENT..]
            .chunks_exact(DIRENT)
            .any(|slot| slot != unused)
    {
        return Err(Error::Conflict);
    }

    read(source.data_block, &mut raw)?;
    let bytes = inode.size as usize;
    let digest: [u8; 32] = Sha256::digest(&raw[..bytes]).into();
    if digest != source.data_sha256 || raw[bytes..].iter().any(|&byte| byte != 0) {
        return Err(Error::Conflict);
    }
    *out = raw;
    Ok(HistoryRead {
        snapshot: grant.snapshot,
        bytes,
        data_sha256: digest,
    })
}
