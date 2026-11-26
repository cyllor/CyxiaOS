//! Staging volume: fixed TEST manifest, v1 format, frozen v1 mount validation
//! and the ratified (golden-vector-pending) N=8 unified map on the scratch disk.
//!
//! The layout is a fixed staging input. The signed lane binds the config digest
//! and principal table to its independently pinned test catalog.
//! The four baseline objects sit on the ratified unified inode slots
//! (225/229/230/231) at the unified host canonical-map positions, and the root
//! directory at the first canonical business block, so the same image passes
//! both the frozen `file_mount_v1` four-object validator and the unified
//! map bridge. The baseline inode and bitmap layout covers those four objects
//! and the root. The opt-in envelopes lane places D1.5 heads in the four
//! separate scratch ranges, with empty payloads and unused blocks (G1 D7).
//! The unified lane allocates all eight system inodes and joins their ACL,
//! extent, and bitmap evidence to the baseline protected payload checks.
//! The signed file layouts add one ordinary file to the root. The writable
//! profile authorizes boot-local overwrites with the mounted owner ACL.
//! The legacy lanes require the snapshot ranges to be all-zero.
//! Host mirror: kernel-core `file_format_v1` test
//! `unified_slot_staging_manifest_formats_mounts_and_allocates_boot_epoch`.
//!
//! UNSAFE BOUNDARY: FORMAT / MOUNT are static workspaces in the FrameMeta
//! `.bss.sec_n` Arena. Each `&mut` is created inside one synchronous CPU0
//! call made only from `media_staging::stage`, which is one-shot (STAGED swap).
use super::Disk;
use core::{mem::MaybeUninit, ops::Range};
use cyxia_kernel_core::security::{
    Error as SecurityError,
    epoch_redo_v0199::EpochBlockIo,
    file_format_v1::{
        self, FormatManifest, FormatWorkspace, SCRATCH_FILE_BLOCK, SCRATCH_FILE_DATA,
        SCRATCH_FILE_GENERATION, SCRATCH_FILE_INODE, SCRATCH_FILE_OWNER_RIGHTS,
        SCRATCH_ROOT_OWNER_RIGHTS, SCRATCH_WRITABLE_FILE_OWNER_RIGHTS,
    },
    file_index_v0199::{BLOCK_BYTES, FileStreamIndexV4, SecurityStateStoreV2},
    file_media_unified_v1::{
        self as unified, ACL_INODE, BOOT_INODE, CANONICAL_BUSINESS_START, RECEIPTS_INODE,
        SECURITY_INODE, SNAPSHOT_CATALOG_BLOCK, UNIFIED_SYSTEM_BLOCKS, UnifiedSystemKind,
        UnifiedSystemObject,
    },
    file_media_v0199::{BITMAP_START, BLOCK_COUNT, DATA_START, SuperblockV1, crc32c_zeroed},
    file_mount_v1::{self, Acl, MountEvidence, Workspace as MountWorkspace},
    file_structure_v1::{Extent, Inode, SystemKind, SystemObject},
    offline_config_v1::{Principal, VerifiedOfflineConfig},
};

pub(super) const UUID: [u8; 16] = *b"CYX-W11-STAGING!";
pub(super) const FIRST_LOG_BLOCK: u32 = 2;
pub(super) const BOOT_HOME: u32 = DATA_START;
const RECEIPTS_HOME: u32 = DATA_START + 1;
const ACL_HOME: u32 = DATA_START + 8;
pub(super) const SECURITY_HOME: u32 = DATA_START + 12;
const ROOT: u32 = CANONICAL_BUSINESS_START;
const ROOT_SLOT_BYTES: usize = 128;
const ACL_ENTRY_BYTES: usize = 64;
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

pub(super) const SNAPSHOT_ENVELOPE_COUNT: usize = 4;
pub(super) const SNAPSHOT_ENVELOPE_GENERATION: u64 = 1;

const fn snapshot_object(kind: UnifiedSystemKind) -> UnifiedSystemObject {
    UnifiedSystemObject {
        kind,
        inode: kind.inode_slot(),
        generation: SNAPSHOT_ENVELOPE_GENERATION,
        first_block: kind
            .fixed_first_block()
            .expect("snapshot has a fixed first block"),
    }
}

const SNAPSHOTS: [UnifiedSystemObject; SNAPSHOT_ENVELOPE_COUNT] = [
    snapshot_object(UnifiedSystemKind::SnapshotCatalog),
    snapshot_object(UnifiedSystemKind::SnapshotSlot),
    snapshot_object(UnifiedSystemKind::SnapshotRequest),
    snapshot_object(UnifiedSystemKind::SnapshotProtection),
];

#[derive(Clone, Copy)]
pub(super) enum SnapshotLayout {
    LegacyZero,
    EmptyEnvelopes,
    AllocatedEnvelopes,
    AllocatedEnvelopesWithFile,
    AllocatedEnvelopesWithWritableFile,
}

impl SnapshotLayout {
    const fn allocated(self) -> bool {
        matches!(
            self,
            Self::AllocatedEnvelopes
                | Self::AllocatedEnvelopesWithFile
                | Self::AllocatedEnvelopesWithWritableFile
        )
    }

    const fn has_file(self) -> bool {
        self.file_owner_rights().is_some()
    }

    const fn file_owner_rights(self) -> Option<u32> {
        match self {
            Self::AllocatedEnvelopesWithFile => Some(SCRATCH_FILE_OWNER_RIGHTS),
            Self::AllocatedEnvelopesWithWritableFile => Some(SCRATCH_WRITABLE_FILE_OWNER_RIGHTS),
            Self::LegacyZero | Self::EmptyEnvelopes | Self::AllocatedEnvelopes => None,
        }
    }

    const fn system_blocks(self) -> u32 {
        if self.allocated() {
            UNIFIED_SYSTEM_BLOCKS
        } else {
            13
        }
    }
}

#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
// Uninitialised storage in the BSS-only section (`FormatWorkspace::new()` is
// not all-zero, so it cannot be a BSS initialiser). No validity is assumed
// for these bytes: `format` writes `FormatWorkspace::new()` before any use.
static mut FORMAT: MaybeUninit<FormatWorkspace> = MaybeUninit::uninit();
#[cfg_attr(target_os = "none", unsafe(link_section = ".bss.sec_n"))]
static mut MOUNT: MountWorkspace = MountWorkspace::new();

/// Signed lanes always pass the verified envelope. The legacy scratch lane
/// owns a different genesis digest, so it cannot reopen a signed volume.
pub(super) type Config<'a> = Option<&'a VerifiedOfflineConfig<'a>>;

fn principals(config: Config<'_>) -> [Principal; 16] {
    if let Some(config) = config {
        return *config.principals();
    }
    core::array::from_fn(|i| Principal {
        id: i as u64 + 1,
        generation: 1,
    })
}

pub(super) fn security(config: Config<'_>) -> SecurityStateStoreV2 {
    SecurityStateStoreV2 {
        fs_uuid: UUID,
        state_generation: 1,
        rule_min_generation: 1,
        security_min_generation: 1,
        key_generation: 1,
        isolated_service_bitmap: 0,
        last_boot_epoch: 0,
        offline_config_generation: 1,
        offline_config_hash: config.map_or([0x5a; 32], VerifiedOfflineConfig::digest),
        service_generations: [1; 16],
    }
}

/// Include the D1.5 heads in the formatter's first metadata flush. The full
/// zero scan has passed and the baseline superblocks are still unpublished.
struct EnvelopeFormatDisk<'a> {
    disk: &'a mut Disk,
    fs_uuid: [u8; 16],
    pending: bool,
}

impl EpochBlockIo for EnvelopeFormatDisk<'_> {
    fn read(&mut self, block: u32, out: &mut [u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        self.disk.read(block, out)
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_BYTES]) -> Result<(), SecurityError> {
        self.disk.write(block, data)
    }

    fn flush(&mut self) -> Result<(), SecurityError> {
        if self.pending {
            let mut raw = [0; BLOCK_BYTES];
            for object in SNAPSHOTS {
                unified::encode_object_envelope(
                    object.kind,
                    self.fs_uuid,
                    object.generation,
                    &mut raw,
                )?;
                self.disk.write(object.first_block, &raw)?;
            }
            self.pending = false;
        }
        self.disk.flush()
    }
}

/// Run the frozen v1 formatter on the all-zero scratch (full 512 MiB scan).
/// A non-zero image is rejected before any write. The formatter owns the
/// ordered writes and readbacks. This adapter checks its returned counts.
pub(super) fn format(
    disk: &mut Disk,
    config: Config<'_>,
    snapshots: SnapshotLayout,
) -> Result<SuperblockV1, SecurityError> {
    if snapshots.has_file() && config.is_none() {
        return Err(SecurityError::Unauthorized);
    }
    let security = security(config);
    if let Some(config) = config {
        config.check_committed(&security)?;
    }
    let manifest = FormatManifest {
        fs_uuid: UUID,
        root_block: ROOT,
        system: SYSTEM,
        principals: principals(config),
        security,
    };
    // SAFETY: one-shot CPU0 call (module header); this is the only borrow of
    // FORMAT and it ends on return. The value is initialised at runtime here.
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(FORMAT) };
    let w = slot.write(FormatWorkspace::new());
    let e = match snapshots {
        SnapshotLayout::LegacyZero => file_format_v1::format(disk, BLOCK_COUNT, &manifest, w)?,
        SnapshotLayout::EmptyEnvelopes => {
            checked_map()?;
            let mut writer = EnvelopeFormatDisk {
                disk,
                fs_uuid: manifest.fs_uuid,
                pending: true,
            };
            file_format_v1::format(&mut writer, BLOCK_COUNT, &manifest, w)?
        }
        SnapshotLayout::AllocatedEnvelopes => {
            file_format_v1::format_unified(disk, BLOCK_COUNT, &manifest, &SNAPSHOTS, w)?
        }
        SnapshotLayout::AllocatedEnvelopesWithFile => {
            file_format_v1::format_unified_with_scratch_file(
                disk,
                BLOCK_COUNT,
                &manifest,
                &SNAPSHOTS,
                w,
            )?
        }
        SnapshotLayout::AllocatedEnvelopesWithWritableFile => {
            file_format_v1::format_unified_with_writable_scratch_file(
                disk,
                BLOCK_COUNT,
                &manifest,
                &SNAPSHOTS,
                w,
            )?
        }
    };
    let expected = SuperblockV1 {
        fs_uuid: UUID,
        generation: 1,
        checkpoint_lsn: 0,
        log_epoch: 1,
    };
    let system_blocks = snapshots.system_blocks();
    let data_blocks = system_blocks + 1 + u32::from(snapshots.has_file());
    if e.superblock != expected || (e.system_blocks, e.data_blocks) != (system_blocks, data_blocks)
    {
        return Err(SecurityError::Conflict);
    }
    let expected_steps =
        if snapshots.allocated() { 19 } else { 15 } + usize::from(snapshots.has_file());
    if w.steps().len() != expected_steps || disk.flushes != 4 {
        return Err(SecurityError::Conflict);
    }
    Ok(e.superblock)
}

fn scratch_file_acl(owner: Principal, owner_rights: u32) -> Acl {
    Acl {
        inode_id: SCRATCH_FILE_INODE,
        state: 1,
        inode_generation: SCRATCH_FILE_GENERATION,
        principal: owner,
        owner_rights,
        system_rights: 0,
        acl_generation: 1,
        parent: 0,
    }
}

/// Staging-only ACL policy. Slot 0 owns the root and hidden system objects.
/// Its rights on the staged file must match the signed boot's selected layout.
fn staging_acl(
    a: Acl,
    inode: Inode,
    system: Option<UnifiedSystemKind>,
    snapshots: SnapshotLayout,
    owner: Principal,
) -> Result<(), SecurityError> {
    let allocated_snapshots = if snapshots.allocated() {
        &SNAPSHOTS[..]
    } else {
        &[]
    };
    let home = SYSTEM
        .iter()
        .find(|s| u32::from(s.inode) == a.inode_id)
        .map(|s| (UnifiedSystemKind::from_baseline(s.kind), s.first_block))
        .or_else(|| {
            allocated_snapshots
                .iter()
                .find(|s| u32::from(s.inode) == a.inode_id)
                .map(|s| (s.kind, s.first_block))
        });
    let root = a.inode_id == 0;
    let file_rights = snapshots
        .file_owner_rights()
        .filter(|_| a.inode_id == SCRATCH_FILE_INODE);
    let file = file_rights.is_some();
    let live = root || file || home.is_some();
    if snapshots.allocated()
        && (inode.parent_generation != u64::from(live)
            || inode.durable_write_seq != 0
            || root && inode.size != ROOT_SLOT_BYTES as u64)
    {
        return Err(SecurityError::Conflict);
    }
    if file
        && (inode.kind != 1
            || inode.size != SCRATCH_FILE_DATA.len() as u64
            || inode.extents != 1
            || inode.runs[0]
                != (Extent {
                    logical: 0,
                    physical: SCRATCH_FILE_BLOCK,
                    count: 1,
                }))
    {
        return Err(SecurityError::Conflict);
    }
    let expected = if let Some(owner_rights) = file_rights {
        scratch_file_acl(owner, owner_rights)
    } else {
        let owner_rights = if root && snapshots.has_file() {
            SCRATCH_ROOT_OWNER_RIGHTS
        } else if root {
            ROOT_OWNER_RIGHTS
        } else {
            0
        };
        Acl {
            inode_id: a.inode_id,
            state: u32::from(live),
            inode_generation: u64::from(live),
            principal: if live {
                owner
            } else {
                Principal {
                    id: 0,
                    generation: 0,
                }
            },
            owner_rights,
            system_rights: if home.is_some() { SYSTEM_RIGHTS } else { 0 },
            acl_generation: u64::from(live),
            parent: 0,
        }
    };
    let first = inode.runs[0].physical;
    if a != expected
        || home.map(|(kind, _)| kind) != system
        || root != (inode.kind == 2)
        || root && first != ROOT
        || home.is_some_and(|(_, block)| first != block)
    {
        return Err(SecurityError::Unauthorized);
    }
    Ok(())
}

pub(super) fn require_zero_blocks(disk: &mut Disk, range: Range<u32>) -> Result<(), SecurityError> {
    let mut block = [0; BLOCK_BYTES];
    for index in range {
        disk.read(index, &mut block)?;
        if block.iter().any(|&v| v != 0) {
            return Err(SecurityError::Conflict);
        }
    }
    Ok(())
}

fn read_root(
    disk: &mut Disk,
    raw: &mut [u8; BLOCK_BYTES],
    first: Option<&[u8; ROOT_SLOT_BYTES]>,
) -> Result<(), SecurityError> {
    disk.read(ROOT, raw)?;
    let mut empty_slot = [0; ROOT_SLOT_BYTES];
    empty_slot[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let checksum_at = ROOT_SLOT_BYTES - 4;
    let checksum = crc32c_zeroed(&empty_slot, checksum_at)?;
    empty_slot[checksum_at..].copy_from_slice(&checksum.to_le_bytes());
    // Verify the entire physical block, including the unused directory slots.
    if raw[..ROOT_SLOT_BYTES] != *first.unwrap_or(&empty_slot)
        || raw[ROOT_SLOT_BYTES..]
            .chunks_exact(ROOT_SLOT_BYTES)
            .any(|slot| slot != empty_slot)
    {
        return Err(SecurityError::Conflict);
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ScratchFile {
    pub(super) dirent: [u8; ROOT_SLOT_BYTES],
    pub(super) data: [u8; SCRATCH_FILE_DATA.len()],
    pub(super) acl: Acl,
}

/// Read the sealed ACL, root slot and full file block from the exclusive disk.
pub(super) fn read_scratch_file(
    disk: &mut Disk,
    raw: &mut [u8; BLOCK_BYTES],
    snapshots: SnapshotLayout,
    owner: Principal,
) -> Result<ScratchFile, SecurityError> {
    let owner_rights = snapshots
        .file_owner_rights()
        .ok_or(SecurityError::Invalid)?;
    let acl_offset = SCRATCH_FILE_INODE as usize * ACL_ENTRY_BYTES;
    disk.read(ACL_HOME + (acl_offset / BLOCK_BYTES) as u32, raw)?;
    let offset = acl_offset % BLOCK_BYTES;
    let acl = Acl::decode(&raw[offset..offset + ACL_ENTRY_BYTES])?;
    if acl != scratch_file_acl(owner, owner_rights) {
        return Err(SecurityError::Unauthorized);
    }
    let expected = file_format_v1::scratch_file_dirent()?;
    read_root(disk, raw, Some(&expected))?;
    let dirent = raw[..ROOT_SLOT_BYTES].try_into().unwrap();
    disk.read(SCRATCH_FILE_BLOCK, raw)?;
    let (data, padding) = raw.split_at(SCRATCH_FILE_DATA.len());
    if data != SCRATCH_FILE_DATA || padding.iter().any(|&byte| byte != 0) {
        return Err(SecurityError::Conflict);
    }
    Ok(ScratchFile {
        dirent,
        data: data.try_into().unwrap(),
        acl,
    })
}

/// The formatter just zeroed and flushed the full redo area. Verify the empty
/// journal on disk before trusting any home blocks as the mounted state.
pub(super) fn mount(
    disk: &mut Disk,
    sb: SuperblockV1,
    config: Config<'_>,
    snapshots: SnapshotLayout,
) -> Result<MountEvidence, SecurityError> {
    require_zero_blocks(disk, FIRST_LOG_BLOCK..BITMAP_START)?;
    validate_homes(disk, sb, 0, config, snapshots)
}

pub(super) fn expected_state(
    epoch: u64,
    config: Config<'_>,
) -> Result<SecurityStateStoreV2, SecurityError> {
    Ok(SecurityStateStoreV2 {
        state_generation: epoch.checked_add(1).ok_or(SecurityError::Exhausted)?,
        last_boot_epoch: epoch,
        ..security(config)
    })
}

/// Both boot modes use exactly the staging manifest and ACL policy. The only
/// mutable homes in this fixture are the paired security and boot epochs.
pub(super) fn validate_homes(
    disk: &mut Disk,
    sb: SuperblockV1,
    epoch: u64,
    config: Config<'_>,
    snapshots: SnapshotLayout,
) -> Result<MountEvidence, SecurityError> {
    if snapshots.has_file() && config.is_none() {
        return Err(SecurityError::Unauthorized);
    }
    // SAFETY: one-shot CPU0 call (module header); the borrow ends on return.
    let w = unsafe { &mut *core::ptr::addr_of_mut!(MOUNT) };
    let principals = principals(config);
    let policy = |acl, inode, kind| staging_acl(acl, inode, kind, snapshots, principals[0]);
    let e = if snapshots.allocated() {
        file_mount_v1::validate_unified(disk, sb, &SYSTEM, &SNAPSHOTS, &principals, w, policy)?
    } else {
        file_mount_v1::validate(disk, sb, &SYSTEM, &principals, w, |acl, inode, kind| {
            policy(acl, inode, kind.map(UnifiedSystemKind::from_baseline))
        })?
    };
    if let Some(config) = config {
        config.check_committed(&e.security)?;
    }
    let system_blocks = snapshots.system_blocks();
    let files = u16::from(snapshots.has_file());
    let live_inodes = if snapshots.allocated() { 9 } else { 5 } + files;
    if e.security != expected_state(epoch, config)?
        || e.boot.fs_uuid != UUID
        || e.boot.boot_epoch != epoch
        || e.structure.live_inodes != live_inodes
        || e.structure.data_blocks != system_blocks + 1 + u32::from(files)
        || e.structure.directory_entries != u32::from(files)
        || e.system_blocks != system_blocks
        || e.receipts.occupied != 0
    {
        return Err(SecurityError::Conflict);
    }
    let mut raw = [0; BLOCK_BYTES];
    if snapshots.has_file() {
        read_scratch_file(disk, &mut raw, snapshots, principals[0])?;
    } else if snapshots.allocated() {
        read_root(disk, &mut raw, None)?;
    }
    // FILE_AUTH runs in memory. A live/recycled stream or a modified global
    // index on this volume indicates a different file owner.
    disk.read(RECEIPTS_HOME + 6, &mut raw)?;
    let index = FileStreamIndexV4::decode(&raw)?;
    if index.generation != 1
        || index.global_request_id_hi != 0
        || index.groups.iter().any(|group| group.flags != 0)
        || index.streams.iter().any(|stream| stream.flags != 0)
    {
        return Err(SecurityError::Conflict);
    }
    Ok(e)
}

/// The exclusive mount workspace retains the seven receipt/index blocks
/// read by validate_homes. Only the known paired boot transaction has run
/// since that mount; its independently verified state is required here.
#[cfg(feature = "v020-production-media-signed")]
pub(super) fn confirmed_receipt_query_digest(
    mounted: &MountEvidence,
    committed: &SecurityStateStoreV2,
    config: &VerifiedOfflineConfig<'_>,
) -> Result<[u8; 32], SecurityError> {
    // SAFETY: same one-shot CPU0 owner as validate_homes; all mutable
    // workspace borrows have ended, and no other CPU can access MOUNT.
    let workspace = unsafe { &*core::ptr::addr_of!(MOUNT) };
    workspace.confirmed_receipt_query_digest(mounted, committed, config)
}

fn checked_map() -> Result<[UnifiedSystemObject; unified::UNIFIED_SYSTEM_OBJECTS], SecurityError> {
    let map = unified::unified_map_from_baseline(&SYSTEM, &SNAPSHOTS)?;
    if map.iter().any(|object| {
        (object.first_block..object.first_block + object.kind.blocks()).contains(&ROOT)
    }) {
        return Err(SecurityError::Conflict);
    }
    Ok(map)
}

fn verify_snapshot_envelopes(disk: &mut Disk, fs_uuid: [u8; 16]) -> Result<(), SecurityError> {
    let mut raw = [0; BLOCK_BYTES];
    for object in SNAPSHOTS {
        disk.read(object.first_block, &mut raw)?;
        let envelope = unified::decode_object_envelope(object.kind, &raw)?;
        if envelope.fs_uuid != fs_uuid || envelope.generation != object.generation {
            return Err(SecurityError::Conflict);
        }
        let end = object.first_block + object.kind.blocks();
        require_zero_blocks(disk, object.first_block + 1..end)?;
    }
    Ok(())
}

/// Return the selected v1 checkpoint and its bytes for the paired boot grant.
pub(super) fn read_checkpoint(
    disk: &mut Disk,
    raw: &mut [u8; BLOCK_BYTES],
) -> Result<SuperblockV1, SecurityError> {
    let mut other = [0; BLOCK_BYTES];
    disk.read(0, raw)?;
    disk.read(1, &mut other)?;
    let sb = unified::unified_superblock_pair(raw, &other)?;
    let a = SuperblockV1::decode(raw)?;
    let b = SuperblockV1::decode(&other)?;
    // A completed staging boot has exactly one boot pair per generation.
    // The formatter writes identical generation 1 headers; subsequently the
    // frozen checkpoint procedure alternates copies, starting with slot 1.
    for copy in [a, b] {
        if copy.fs_uuid != UUID
            || copy.log_epoch != copy.generation
            || (copy.generation - 1).checked_mul(4) != Some(copy.checkpoint_lsn)
        {
            return Err(SecurityError::Conflict);
        }
    }
    if sb.generation > 1 && (a == b || (sb == a) != (sb.generation % 2 == 1)) {
        return Err(SecurityError::Conflict);
    }
    if sb != a {
        *raw = other;
    }
    Ok(sb)
}

/// Check the N=8 manifest geometry and each mode's snapshot bytes.
/// Allocated layouts additionally require structural and ACL validation.
pub(super) fn unified_map(
    disk: &mut Disk,
    sb: SuperblockV1,
    snapshots: SnapshotLayout,
) -> Result<u32, SecurityError> {
    let map = checked_map()?;
    let evidence = unified::validate_unified_system_map(&map)?;
    let mut first = [0; BLOCK_BYTES];
    let mut second = [0; BLOCK_BYTES];
    disk.read(0, &mut first)?;
    disk.read(1, &mut second)?;
    if unified::unified_superblock_pair(&first, &second)? != sb {
        return Err(SecurityError::Conflict);
    }
    match snapshots {
        SnapshotLayout::LegacyZero => {
            require_zero_blocks(disk, SNAPSHOT_CATALOG_BLOCK..CANONICAL_BUSINESS_START)?;
        }
        SnapshotLayout::EmptyEnvelopes
        | SnapshotLayout::AllocatedEnvelopes
        | SnapshotLayout::AllocatedEnvelopesWithFile
        | SnapshotLayout::AllocatedEnvelopesWithWritableFile => {
            verify_snapshot_envelopes(disk, sb.fs_uuid)?;
        }
    }
    Ok(evidence.system_blocks)
}
