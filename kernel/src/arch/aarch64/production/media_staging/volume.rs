//! Staging volume: fixed TEST manifest, v1 format, frozen v1 mount validation
//! and the ratified (golden-vector-pending) N=8 unified map on the scratch disk.
//!
//! The manifest is an UNSIGNED fixed staging input, not a signed boot catalog.
//! The four baseline objects sit on the ratified unified inode slots
//! (225/229/230/231) at the unified host canonical-map positions, and the root
//! directory at the first canonical business block, so the same image passes
//! both the frozen `file_mount_v1` four-object validator and the unified
//! map bridge. The four new snapshot objects are map entries only: the
//! baseline formatter never allocates or writes their fixed ranges, which must
//! stay all-zero until their payload layouts are frozen (G1 D7).
//! Host mirror: kernel-core `file_format_v1` test
//! `unified_slot_staging_manifest_formats_mounts_and_allocates_boot_epoch`.
//!
//! UNSAFE BOUNDARY: FORMAT / MOUNT (static mut workspaces, `.bss.sec_n`, NOT
//! FrameMeta-registered): each `&mut` is created inside one synchronous CPU0
//! call made only from `media_staging::stage`, which is one-shot (STAGED swap).
use super::Disk;
use core::mem::MaybeUninit;
use cyxia_kernel_core::security::{
    Error as SecurityError,
    epoch_redo_v0199::EpochBlockIo,
    file_format_v1::{self, FormatManifest, FormatWorkspace},
    file_index_v0199::{BLOCK_BYTES, SecurityStateStoreV2},
    file_media_unified_v1::{
        self as unified, ACL_INODE, BOOT_INODE, CANONICAL_BUSINESS_START, RECEIPTS_INODE,
        SECURITY_INODE, SNAPSHOT_CATALOG_BLOCK, UnifiedSystemKind, UnifiedSystemObject,
    },
    file_media_v0199::{BLOCK_COUNT, DATA_START, SuperblockV1},
    file_mount_v1::{self, Acl, MountEvidence, Workspace as MountWorkspace},
    file_structure_v1::{Inode, SystemKind, SystemObject},
    offline_config_v1::Principal,
};

const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
pub(super) const BOOT_HOME: u32 = DATA_START;
const RECEIPTS_HOME: u32 = DATA_START + 1;
const ACL_HOME: u32 = DATA_START + 8;
pub(super) const SECURITY_HOME: u32 = DATA_START + 12;
const ROOT: u32 = CANONICAL_BUSINESS_START;
/// Rights masks identical to the frozen formatter / v1 mount validator.
const SYSTEM_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const ROOT_OWNER_RIGHTS: u32 = 1 << 14;

const fn object(kind: SystemKind, inode: u16, first_block: u32) -> SystemObject {
    SystemObject {
        kind,
        inode,
        generation: 1,
        first_block,
    }
}
const SYSTEM: [SystemObject; 4] = [
    object(SystemKind::BootEpoch, BOOT_INODE, BOOT_HOME),
    object(SystemKind::Receipts, RECEIPTS_INODE, RECEIPTS_HOME),
    object(SystemKind::Acl, ACL_INODE, ACL_HOME),
    object(SystemKind::Security, SECURITY_INODE, SECURITY_HOME),
];

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
// Uninitialised storage in the BSS-only section (`FormatWorkspace::new()` is
// not all-zero, so it cannot be a BSS initialiser). No validity is assumed
// for these bytes: `format` writes `FormatWorkspace::new()` before any use.
static mut FORMAT: MaybeUninit<FormatWorkspace> = MaybeUninit::uninit();
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut MOUNT: MountWorkspace = MountWorkspace::new();

fn principals() -> [Principal; 16] {
    core::array::from_fn(|i| Principal {
        id: i as u64 + 1,
        generation: 1,
    })
}

pub(super) fn security() -> SecurityStateStoreV2 {
    SecurityStateStoreV2 {
        fs_uuid: UUID,
        state_generation: 1,
        rule_min_generation: 1,
        security_min_generation: 1,
        key_generation: 1,
        isolated_service_bitmap: 0,
        last_boot_epoch: 0,
        offline_config_generation: 1,
        offline_config_hash: [0x5a; 32],
        service_generations: [1; 16],
    }
}

/// Run the frozen v1 formatter on the all-zero scratch (full 512 MiB scan).
/// A non-zero image is rejected before any write. Only the step and FLUSH
/// COUNTS are checked here (15 steps, 4 flushes); the §9.2.1 FLUSH order is
/// the formatter's own contract and is not re-asserted by this lane.
pub(super) fn format(disk: &mut Disk) -> Result<SuperblockV1, SecurityError> {
    let manifest = FormatManifest {
        fs_uuid: UUID,
        root_block: ROOT,
        system: SYSTEM,
        principals: principals(),
        security: security(),
    };
    // SAFETY: one-shot CPU0 call (module header); this is the only borrow of
    // FORMAT and it ends on return. The value is initialised at runtime here.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(FORMAT) };
    let w = slot.write(FormatWorkspace::new());
    let e = file_format_v1::format(disk, BLOCK_COUNT, &manifest, w)?;
    let expected = SuperblockV1 {
        fs_uuid: UUID,
        generation: 1,
        checkpoint_lsn: 0,
        log_epoch: 1,
    };
    if e.superblock != expected || (e.system_blocks, e.data_blocks) != (13, 14) {
        return Err(SecurityError::Conflict);
    }
    if w.steps().len() != 15 || disk.flushes != 4 {
        return Err(SecurityError::Conflict);
    }
    Ok(e.superblock)
}

fn expected_acl(id: u32) -> (u64, u64, u32, u32, u64) {
    if id == 0 {
        (1, 1, ROOT_OWNER_RIGHTS, 0, 1)
    } else if SYSTEM.iter().any(|s| u32::from(s.inode) == id) {
        (1, 1, 0, SYSTEM_RIGHTS, 1)
    } else {
        (0, 0, 0, 0, 0)
    }
}

/// Staging-only immutable ACL policy: principals[0] owns the root (TRAVERSE)
/// and the four hidden system objects (READ|WRITE|FSYNC). No general user
/// access and no recovery authority is issued.
fn staging_acl(a: Acl, inode: Inode, system: Option<SystemKind>) -> Result<(), SecurityError> {
    let home = SYSTEM.iter().find(|s| u32::from(s.inode) == a.inode_id);
    let live = a.inode_id == 0 || home.is_some();
    let rights = (
        a.principal.id,
        a.principal.generation,
        a.owner_rights,
        a.system_rights,
        a.acl_generation,
    );
    let first = inode.runs[0].physical;
    if rights != expected_acl(a.inode_id)
        || a.parent != 0
        || a.state != u32::from(live)
        || a.inode_generation != u64::from(live)
        || home.is_some() != system.is_some()
        || (a.inode_id == 0) != (inode.kind == 2)
        || a.inode_id == 0 && first != ROOT
        || home.is_some_and(|s| first != s.first_block)
    {
        return Err(SecurityError::Unauthorized);
    }
    Ok(())
}

/// Validate the formatted image ON DISK through the frozen v1 mount contract.
pub(super) fn mount(disk: &mut Disk, sb: SuperblockV1) -> Result<MountEvidence, SecurityError> {
    // SAFETY: one-shot CPU0 call (module header); the borrow ends on return.
    let w = unsafe { &mut *core::ptr::addr_of_mut!(MOUNT) };
    let e = file_mount_v1::validate(disk, sb, &SYSTEM, &principals(), w, staging_acl)?;
    if e.security != security()
        || e.boot.fs_uuid != UUID
        || e.boot.boot_epoch != 0
        || e.structure.live_inodes != 5
        || e.structure.data_blocks != 14
        || e.system_blocks != 13
        || e.receipts.occupied != 0
    {
        return Err(SecurityError::Conflict);
    }
    Ok(e)
}

fn snapshot_object(kind: UnifiedSystemKind) -> Result<UnifiedSystemObject, SecurityError> {
    Ok(UnifiedSystemObject {
        kind,
        inode: kind.inode_slot(),
        generation: 1,
        first_block: kind.fixed_first_block().ok_or(SecurityError::Invalid)?,
    })
}

/// Ratified N=8 unified map (golden-vector-pending): bridge the formatted
/// baseline objects, gate the on-disk superblock pair (BaselineV1 only) and
/// require the never-allocated snapshot ranges to still read all-zero.
pub(super) fn unified_map(disk: &mut Disk, sb: SuperblockV1) -> Result<u32, SecurityError> {
    let snapshot = [
        snapshot_object(UnifiedSystemKind::SnapshotCatalog)?,
        snapshot_object(UnifiedSystemKind::SnapshotSlot)?,
        snapshot_object(UnifiedSystemKind::SnapshotRequest)?,
        snapshot_object(UnifiedSystemKind::SnapshotProtection)?,
    ];
    let map = unified::unified_map_from_baseline(&SYSTEM, &snapshot)?;
    let evidence = unified::validate_unified_system_map(&map)?;
    let mut first = [0; BLOCK_BYTES];
    let mut second = [0; BLOCK_BYTES];
    disk.read(0, &mut first)?;
    disk.read(1, &mut second)?;
    if unified::unified_superblock_pair(&first, &second)? != sb {
        return Err(SecurityError::Conflict);
    }
    let mut block = [0; BLOCK_BYTES];
    for b in SNAPSHOT_CATALOG_BLOCK..CANONICAL_BUSINESS_START {
        disk.read(b, &mut block)?;
        if block.iter().any(|&v| v != 0) {
            return Err(SecurityError::Conflict);
        }
    }
    Ok(evidence.system_blocks)
}
