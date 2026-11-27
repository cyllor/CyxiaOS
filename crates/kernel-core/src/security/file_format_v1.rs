//! V1 new-image formatters (V0.19.9 §9.2/§9.2.1/§9.6 and V0.20 G1 D1/D4).
//!
//! Each entry point accepts an exactly 512 MiB (131072 x 4096) all-zero
//! new image, rejects any existing content before the first write, and
//! publishes initial metadata in the fixed §9.2.1 order:
//! bitmap/inode table/root directory/system objects -> FLUSH ->
//! zero the log region 2..4098 -> FLUSH -> two byte-identical initial
//! superblocks (generation=1, log_epoch=1, checkpoint_lsn=0), each
//! FLUSH-confirmed and read back. `format` publishes the four baseline
//! objects. `format_unified` publishes all eight objects, including the
//! generation-1 D1.5 snapshot envelopes and zero tails pending D7 vectors.
//! The scratch file profiles also allocate one root file and write its data
//! before that first metadata FLUSH. The writable profile adds FILE_WRITE to
//! that file's owner ACL for the boot-local overwrite service.
//!
//! Byte-source derivation:
//! - Superblock/inode/directory/bitmap/ACL encodings: §9.2/§9.2.1 layouts,
//!   cross-checked against the frozen decoders in file_media_v0199,
//!   file_structure_v1 and file_mount_v1 before publication.
//! - BootEpochStore initial count 0: §9.6 "新镜像计数初值为 0"; canonical
//!   encoder boot_epoch_v1::BootEpochStoreV1::encode.
//! - SecurityStateStore v2 initial image: caller-supplied trusted offline
//!   manifest values (§9.6 "格式化初值来自可信离线清单"), written through
//!   the canonical file_index_v0199 encoder.
//! - FileStreamIndex v4 / receipt store: file_index_v0199 decoder rules and
//!   file_receipt_store_v0199 (six all-zero receipt blocks + one index).
//! - System object inode slots/extents and the root directory block location
//!   come from the caller's trusted build manifest (§9.2.1). The unified
//!   path checks the eight-object map against the D1.2 layout.
//!
//! Documented gaps (the baseline does not fix these initial wire values):
//! - Empty root directory size: the frozen v1 fixtures use a one-block root
//!   with size=128 per declared slot. This formatter writes one 4 KiB root
//!   block whose 32 physical slots are all sealed empty (inode_id=0xFFFFFFFF
//!   plus CRC per §9.2.1) and declares size=128. A zero-size extent-less root
//!   also passes the v1 scan; the one-block convention follows the existing
//!   fixtures and keeps a ready root directory block.
//! - Initial ACL ownership/rights: the baseline delegates them to the trusted
//!   volume manifest. Following the only existing concrete reference
//!   (tools/verify_v0199_epoch_disk.py and the file_mount_v1 fixture),
//!   principals[0] owns the root (owner_rights=FILE_TRAVERSE bit14) and all
//!   system objects (owner_rights=0, system_rights=READ|WRITE|FSYNC
//!   bits 8/9/13), acl_generation=1. Production boot wiring must supply the
//!   signed manifest's actual ownership; this is format, not authority.
//! - Fresh free inode slots start at generation 0 (§9.2.1 retained-generation
//!   rule applies to freed tombstones); FileStreamIndex initial generation=1
//!   and global_request_id_hi=0 follow the frozen fixtures.
//! - EpochBlockIo has no capacity query; the adapter must report the real
//!   device block count and only exactly 131072 is accepted.
use super::{
    Error,
    boot_epoch_v1::BootEpochStoreV1,
    epoch_redo_v0199::EpochBlockIo,
    file_index_v0199::{
        CRC_OFFSET as INDEX_CRC, FileStreamIndexV4, INDEX_HEADER, INDEX_MAGIC, INDEX_VERSION,
        SecurityStateStoreV2,
    },
    file_media_unified_v1::{self as unified, UnifiedSystemKind, UnifiedSystemObject},
    file_media_v0199::{
        BITMAP_START, BLOCK_COUNT, DATA_START, INODE_START, SUPER_MAGIC, SUPER_VERSION,
        SuperblockV1, crc32c_zeroed,
    },
    file_structure_v1::{BLOCK, INODE_BYTES, INODES, SystemKind, SystemObject},
    offline_config_v1::Principal,
};
const LOG_START: u32 = 2;
const BITMAP_BLOCKS: u32 = 4;
const INODE_BLOCKS: u32 = 16;
const DIR_SLOT_BYTES: usize = 128;
const ACL_BYTES: usize = 64;
const ACL_ENTRIES_PER_BLOCK: usize = BLOCK / ACL_BYTES;
const RECEIPT_HOME_BLOCKS: u32 = 6;
const ROOT_SIZE: u64 = 128;
const INODE_MAGIC: u32 = 0x4359_494e;
// CapabilityRightsSchema v3 bit8..14 = READ/WRITE/CREATE/REMOVE/ENUM/FSYNC/
// TRAVERSE; masks identical to the frozen file_mount_v1 validator.
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const ROOT_OWNER_RIGHTS: u32 = 1 << 14;
pub const SCRATCH_ROOT_OWNER_RIGHTS: u32 = ROOT_OWNER_RIGHTS | (1 << 12);
pub const SCRATCH_FILE_OWNER_RIGHTS: u32 = 1 << 8;
pub const SCRATCH_FILE_WRITE_RIGHTS: u32 = 1 << 9;
pub const SCRATCH_FILE_FSYNC_RIGHTS: u32 = 1 << 13;
pub const SCRATCH_WRITABLE_FILE_OWNER_RIGHTS: u32 =
    SCRATCH_FILE_OWNER_RIGHTS | SCRATCH_FILE_WRITE_RIGHTS;
pub const SCRATCH_FSYNC_FILE_OWNER_RIGHTS: u32 =
    SCRATCH_WRITABLE_FILE_OWNER_RIGHTS | SCRATCH_FILE_FSYNC_RIGHTS;
pub const SCRATCH_FILE_INODE: u32 = 1;
pub const SCRATCH_FILE_GENERATION: u64 = 1;
pub const SCRATCH_FILE_BLOCK: u32 = unified::CANONICAL_BUSINESS_START + 1;
pub const SCRATCH_FILE_NAME: &[u8; 10] = b"readme.txt";
pub const SCRATCH_FILE_DATA: &[u8; 29] = b"CyxiaOS V0.20 signed scratch\n";
const MAX_STEPS: usize = 20;
fn p16(b: &mut [u8], i: usize, v: u16) {
    b[i..i + 2].copy_from_slice(&v.to_le_bytes());
}
fn p32(b: &mut [u8], i: usize, v: u32) {
    b[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
fn p64(b: &mut [u8], i: usize, v: u64) {
    b[i..i + 8].copy_from_slice(&v.to_le_bytes());
}
const fn kind_blocks(kind: SystemKind) -> u32 {
    UnifiedSystemKind::from_baseline(kind).blocks()
}
/// One completed operation in the exact §9.2.1 publication sequence.
/// `Flush` steps carry first=0/blocks=0; every other step names the exact
/// contiguous block range it touched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatOp {
    ScanZero,
    Bitmap,
    InodeTable,
    RootDirectory,
    SystemObject,
    Flush,
    ZeroLog,
    Superblock,
    FileData,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatStep {
    pub op: FormatOp,
    pub first: u32,
    pub blocks: u32,
}
/// Trusted build/volume/offline manifest inputs. Locations and identities are
/// never guessed here; the authenticated boot catalog supplies them.
pub struct FormatManifest {
    pub fs_uuid: [u8; 16],
    pub root_block: u32,
    pub system: [SystemObject; 4],
    pub principals: [Principal; 16],
    pub security: SecurityStateStoreV2,
}
/// Bounded no-heap workspace: one write buffer, one readback buffer and the
/// fixed-capacity operation trace (15 baseline, 19 unified, or 20 with the file).
pub struct FormatWorkspace {
    block: [u8; BLOCK],
    readback: [u8; BLOCK],
    steps: [FormatStep; MAX_STEPS],
    len: usize,
}
impl Default for FormatWorkspace {
    fn default() -> Self {
        Self::new()
    }
}
impl FormatWorkspace {
    pub const fn new() -> Self {
        Self {
            block: [0; BLOCK],
            readback: [0; BLOCK],
            steps: [FormatStep {
                op: FormatOp::Flush,
                first: 0,
                blocks: 0,
            }; MAX_STEPS],
            len: 0,
        }
    }
    pub fn steps(&self) -> &[FormatStep] {
        &self.steps[..self.len]
    }
}
const _: () = assert!(core::mem::size_of::<FormatWorkspace>() <= 16 * 1024);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatEvidence {
    pub superblock: SuperblockV1,
    pub root_block: u32,
    pub system_blocks: u32,
    pub data_blocks: u32,
}
fn record(w: &mut FormatWorkspace, op: FormatOp, first: u32, blocks: u32) {
    // All fixed publication sequences fit in MAX_STEPS.
    debug_assert!(w.len < MAX_STEPS);
    if w.len < MAX_STEPS {
        w.steps[w.len] = FormatStep { op, first, blocks };
        w.len += 1;
    }
}
fn flush(io: &mut impl EpochBlockIo, w: &mut FormatWorkspace) -> Result<(), Error> {
    io.flush().map_err(|_| Error::Unknown)?;
    record(w, FormatOp::Flush, 0, 0);
    Ok(())
}
fn validate_manifest(m: &FormatManifest) -> Result<(), Error> {
    if m.fs_uuid == [0; 16] {
        return Err(Error::Invalid);
    }
    // Same layout rules as the frozen file_mount_v1::system_layout.
    for (i, s) in m.system.iter().enumerate() {
        let count = kind_blocks(s.kind);
        if s.inode == 0
            || usize::from(s.inode) >= INODES
            || s.generation == 0
            || s.first_block < DATA_START
            || s.first_block
                .checked_add(count)
                .is_none_or(|end| end > BLOCK_COUNT)
            || m.system[..i]
                .iter()
                .any(|old| old.inode == s.inode || old.kind == s.kind)
        {
            return Err(Error::Invalid);
        }
    }
    if m.root_block < DATA_START
        || m.root_block >= BLOCK_COUNT
        || m.system
            .iter()
            .any(|s| (s.first_block..s.first_block + kind_blocks(s.kind)).contains(&m.root_block))
    {
        return Err(Error::Invalid);
    }
    for (i, p) in m.principals.iter().enumerate() {
        if p.id == 0 || p.generation == 0 || m.principals[..i].iter().any(|old| old.id == p.id) {
            return Err(Error::Invalid);
        }
    }
    // Fresh-image invariants; remaining security initial values are the
    // trusted offline manifest's authority (see module doc gaps).
    if m.security.fs_uuid != m.fs_uuid || m.security.last_boot_epoch != 0 {
        return Err(Error::Conflict);
    }
    if m.security.state_generation != 1 || m.security.isolated_service_bitmap != 0 {
        return Err(Error::Invalid);
    }
    // Canonical encoder re-decodes its own output: rejects zero config
    // generation/hash and every other frozen v2 field rule.
    m.security.encode()?;
    Ok(())
}
fn allocated(
    block: u32,
    root_block: u32,
    system: &[UnifiedSystemObject],
    scratch_file: bool,
) -> bool {
    block < DATA_START
        || block == root_block
        || scratch_file && block == SCRATCH_FILE_BLOCK
        || system
            .iter()
            .any(|s| (s.first_block..s.first_block + s.kind.blocks()).contains(&block))
}
fn write_bitmap(
    io: &mut impl EpochBlockIo,
    root_block: u32,
    system: &[UnifiedSystemObject],
    scratch_file: bool,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for page in 0..BITMAP_BLOCKS {
        bitmap_page(&mut w.block, page, root_block, system, scratch_file);
        io.write(BITMAP_START + page, &w.block)
            .map_err(|_| Error::Unknown)?;
    }
    record(w, FormatOp::Bitmap, BITMAP_START, BITMAP_BLOCKS);
    Ok(())
}

fn bitmap_page(
    out: &mut [u8; BLOCK],
    page: u32,
    root_block: u32,
    system: &[UnifiedSystemObject],
    scratch_file: bool,
) {
    let base = page * (BLOCK as u32 * 8);
    for (byte, slot) in out.iter_mut().enumerate() {
        let mut bits = 0u8;
        for bit in 0..8u32 {
            if allocated(
                base + byte as u32 * 8 + bit,
                root_block,
                system,
                scratch_file,
            ) {
                bits |= 1 << bit;
            }
        }
        *slot = bits;
    }
}
fn seal_inode(
    slot: &mut [u8],
    kind: u16,
    generation: u64,
    size: u64,
    physical: u32,
    count: u32,
) -> Result<(), Error> {
    // Slot is pre-zeroed; parent_inode stays 0 (root) for every live inode.
    p32(slot, 0, INODE_MAGIC);
    p16(slot, 4, kind);
    p64(slot, 8, generation);
    if kind != 0 {
        p64(slot, 16, size);
        p64(slot, 40, 1);
        if count != 0 {
            p16(slot, 32, 1);
            p32(slot, 48, 0);
            p32(slot, 52, physical);
            p32(slot, 56, count);
        }
    }
    let crc = crc32c_zeroed(slot, 252)?;
    p32(slot, 252, crc);
    Ok(())
}
fn write_inodes(
    io: &mut impl EpochBlockIo,
    root_block: u32,
    system: &[UnifiedSystemObject],
    scratch_file: bool,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for page in 0..INODE_BLOCKS {
        inode_page(&mut w.block, page, root_block, system, scratch_file)?;
        io.write(INODE_START + page, &w.block)
            .map_err(|_| Error::Unknown)?;
    }
    record(w, FormatOp::InodeTable, INODE_START, INODE_BLOCKS);
    Ok(())
}

fn inode_page(
    out: &mut [u8; BLOCK],
    page: u32,
    root_block: u32,
    system: &[UnifiedSystemObject],
    scratch_file: bool,
) -> Result<(), Error> {
    out.fill(0);
    for (slot, entry) in out.chunks_exact_mut(INODE_BYTES).enumerate() {
        let id = page as usize * (BLOCK / INODE_BYTES) + slot;
        if id == 0 {
            seal_inode(entry, 2, 1, ROOT_SIZE, root_block, 1)?;
        } else if scratch_file && id == SCRATCH_FILE_INODE as usize {
            seal_inode(
                entry,
                1,
                SCRATCH_FILE_GENERATION,
                SCRATCH_FILE_DATA.len() as u64,
                SCRATCH_FILE_BLOCK,
                1,
            )?;
        } else if let Some(s) = system.iter().find(|s| usize::from(s.inode) == id) {
            let count = s.kind.blocks();
            seal_inode(
                entry,
                1,
                s.generation,
                u64::from(count) * BLOCK as u64,
                s.first_block,
                count,
            )?;
        } else {
            // Fresh free slot: magic + generation 0 + valid CRC only.
            seal_inode(entry, 0, 0, 0, 0, 0)?;
        }
    }
    Ok(())
}

fn baseline_system(m: &FormatManifest) -> [UnifiedSystemObject; 4] {
    m.system.map(|s| UnifiedSystemObject {
        kind: UnifiedSystemKind::from_baseline(s.kind),
        inode: s.inode,
        generation: s.generation,
        first_block: s.first_block,
    })
}

/// Pure encoding of the three nontrivial genesis metadata homes that the
/// signed baseline FSYNC fixture can change. Shares the actual formatter's
/// encoders so recovery can authenticate homes even after partial replay.
pub fn baseline_fsync_genesis_metadata(
    m: &FormatManifest,
    first_bitmap: &mut [u8; BLOCK],
    first_inode: &mut [u8; BLOCK],
    stream_index: &mut [u8; BLOCK],
) -> Result<(), Error> {
    let system = baseline_system(m);
    bitmap_page(first_bitmap, 0, m.root_block, &system, true);
    inode_page(first_inode, 0, m.root_block, &system, true)?;
    encode_index(m, stream_index)
}

/// The canonical populated v1 root slot for the signed scratch file.
pub fn scratch_file_dirent() -> Result<[u8; DIR_SLOT_BYTES], Error> {
    let mut slot = [0; DIR_SLOT_BYTES];
    p32(&mut slot, 0, SCRATCH_FILE_INODE);
    p16(&mut slot, 4, SCRATCH_FILE_NAME.len() as u16);
    p64(&mut slot, 8, SCRATCH_FILE_GENERATION);
    slot[16..16 + SCRATCH_FILE_NAME.len()].copy_from_slice(SCRATCH_FILE_NAME);
    let crc = crc32c_zeroed(&slot, 124)?;
    p32(&mut slot, 124, crc);
    Ok(slot)
}

fn write_root(
    io: &mut impl EpochBlockIo,
    m: &FormatManifest,
    scratch_file: bool,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    w.block.fill(0);
    for b in w.block.chunks_exact_mut(DIR_SLOT_BYTES) {
        p32(b, 0, u32::MAX);
        let crc = crc32c_zeroed(b, 124)?;
        p32(b, 124, crc);
    }
    if scratch_file {
        w.block[..DIR_SLOT_BYTES].copy_from_slice(&scratch_file_dirent()?);
    }
    io.write(m.root_block, &w.block)
        .map_err(|_| Error::Unknown)?;
    record(w, FormatOp::RootDirectory, m.root_block, 1);
    Ok(())
}
fn encode_index(m: &FormatManifest, b: &mut [u8; BLOCK]) -> Result<(), Error> {
    b.fill(0);
    p32(b, 0, INDEX_MAGIC);
    p16(b, 4, INDEX_VERSION);
    p16(b, 6, INDEX_HEADER as u16);
    b[8..24].copy_from_slice(&m.fs_uuid);
    // global_request_id_hi=0; initial generation 1 per the frozen fixtures.
    p64(b, 32, 1);
    for (i, p) in m.principals.iter().enumerate() {
        // Inactive group: generation/flags/boot_epoch stay zero; the slot is
        // permanently bound to its unique manifest principal.
        p64(b, INDEX_HEADER + i * 24 + 16, p.id);
    }
    let crc = crc32c_zeroed(b, INDEX_CRC)?;
    p32(b, INDEX_CRC, crc);
    FileStreamIndexV4::decode(b)?;
    Ok(())
}
fn seal_acl_entry(
    owner: Principal,
    system: &[UnifiedSystemObject],
    scratch_owner_rights: Option<u32>,
    id: usize,
    b: &mut [u8],
) -> Result<(), Error> {
    let (generation, owner_rights, system_rights) = if id == 0 {
        let rights = if scratch_owner_rights.is_some() {
            SCRATCH_ROOT_OWNER_RIGHTS
        } else {
            ROOT_OWNER_RIGHTS
        };
        (1, rights, 0)
    } else if id == SCRATCH_FILE_INODE as usize
        && let Some(rights) = scratch_owner_rights
    {
        (SCRATCH_FILE_GENERATION, rights, 0)
    } else {
        system
            .iter()
            .find(|s| usize::from(s.inode) == id)
            .map_or((0, 0, 0), |s| (s.generation, 0, FILE_RIGHTS))
    };
    p32(b, 0, id as u32);
    if generation != 0 {
        p32(b, 4, 1);
        p64(b, 8, generation);
        p64(b, 16, owner.id);
        p64(b, 24, owner.generation);
        p32(b, 32, owner_rights);
        p32(b, 36, system_rights);
        p64(b, 40, 1);
        // parent_inode at 48 stays 0, matching the live inode parents.
    }
    let crc = crc32c_zeroed(b, 60)?;
    p32(b, 60, crc);
    Ok(())
}
fn write_system(
    io: &mut impl EpochBlockIo,
    m: &FormatManifest,
    system: &[UnifiedSystemObject],
    scratch_owner_rights: Option<u32>,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for s in system {
        let first = s.first_block;
        let count = s.kind.blocks();
        match s.kind {
            UnifiedSystemKind::BootEpoch => {
                w.block = BootEpochStoreV1 {
                    fs_uuid: m.fs_uuid,
                    boot_epoch: 0,
                }
                .encode()?;
                io.write(first, &w.block).map_err(|_| Error::Unknown)?;
            }
            UnifiedSystemKind::Security => {
                w.block = m.security.encode()?;
                io.write(first, &w.block).map_err(|_| Error::Unknown)?;
            }
            UnifiedSystemKind::Receipts => {
                w.block.fill(0);
                for i in 0..RECEIPT_HOME_BLOCKS {
                    io.write(first + i, &w.block).map_err(|_| Error::Unknown)?;
                }
                encode_index(m, &mut w.block)?;
                io.write(first + RECEIPT_HOME_BLOCKS, &w.block)
                    .map_err(|_| Error::Unknown)?;
            }
            UnifiedSystemKind::Acl => {
                for page in 0..(INODES * ACL_BYTES / BLOCK) as u32 {
                    w.block.fill(0);
                    for j in 0..ACL_ENTRIES_PER_BLOCK {
                        let id = page as usize * ACL_ENTRIES_PER_BLOCK + j;
                        seal_acl_entry(
                            m.principals[0],
                            system,
                            scratch_owner_rights,
                            id,
                            &mut w.block[j * ACL_BYTES..(j + 1) * ACL_BYTES],
                        )?;
                    }
                    io.write(first + page, &w.block)
                        .map_err(|_| Error::Unknown)?;
                }
            }
            UnifiedSystemKind::SnapshotCatalog
            | UnifiedSystemKind::SnapshotSlot
            | UnifiedSystemKind::SnapshotRequest
            | UnifiedSystemKind::SnapshotProtection => {
                unified::encode_object_envelope(s.kind, m.fs_uuid, s.generation, &mut w.block)?;
                io.write(first, &w.block).map_err(|_| Error::Unknown)?;
                w.block.fill(0);
                for block in first + 1..first + count {
                    io.write(block, &w.block).map_err(|_| Error::Unknown)?;
                }
            }
        }
        record(w, FormatOp::SystemObject, first, count);
    }
    Ok(())
}
fn encode_superblock(sb: &SuperblockV1, b: &mut [u8; BLOCK]) -> Result<(), Error> {
    b.fill(0);
    p32(b, 0, SUPER_MAGIC);
    p16(b, 4, SUPER_VERSION);
    p16(b, 6, 80);
    p32(b, 8, BLOCK as u32);
    p32(b, 12, BLOCK_COUNT);
    b[16..32].copy_from_slice(&sb.fs_uuid);
    p64(b, 32, sb.generation);
    p64(b, 40, sb.checkpoint_lsn);
    p64(b, 48, sb.log_epoch);
    p32(b, 56, BITMAP_START);
    p32(b, 60, INODE_START);
    p32(b, 64, DATA_START);
    p32(b, 68, INODES as u32);
    p32(b, 72, 0);
    let crc = crc32c_zeroed(b, 76)?;
    p32(b, 76, crc);
    if SuperblockV1::decode(b)? != *sb {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// Format only a fully zero, exactly 131072-block device. `total_blocks` is
/// the adapter-reported real capacity; any other value is refused before any
/// I/O. An interrupted format must be treated as an invalid image: this
/// function never erases existing content and never retries a failed write.
/// The returned trace records the exact completed §9.2.1 sequence; a failure
/// after the first write leaves an UNKNOWN obligation with no superblock
/// publication guaranteed.
pub fn format(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    format_layout(io, total_blocks, m, None, None, w)
}

/// Format the signed diagnostic baseline-v1 file fixture. Its ordinary file
/// and exact FSYNC ACL are initialized before publishing either superblock.
pub fn format_baseline_with_fsync_scratch_file(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    format_layout(
        io,
        total_blocks,
        m,
        None,
        Some(SCRATCH_FSYNC_FILE_OWNER_RIGHTS),
        w,
    )
}

/// Format an all-zero v1 image with the eight-object D1 scratch layout.
/// The full map, root block, and initial snapshot generations are checked
/// before I/O. The four D1.5 heads and their zero tails join the first
/// metadata FLUSH and use the envelope fields pending D7 vectors.
pub fn format_unified(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    snapshots: &[UnifiedSystemObject; 4],
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    format_layout(io, total_blocks, m, Some(snapshots), None, w)
}

/// Format the canonical unified scratch layout with one immutable root file.
/// The caller supplies the verified offline policy through the manifest.
pub fn format_unified_with_scratch_file(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    snapshots: &[UnifiedSystemObject; 4],
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    format_layout(
        io,
        total_blocks,
        m,
        Some(snapshots),
        Some(SCRATCH_FILE_OWNER_RIGHTS),
        w,
    )
}

/// Format the canonical unified scratch layout with a READ|WRITE owner ACL
/// for the fixture's boot-local overwrite service.
pub fn format_unified_with_writable_scratch_file(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    snapshots: &[UnifiedSystemObject; 4],
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    format_layout(
        io,
        total_blocks,
        m,
        Some(snapshots),
        Some(SCRATCH_WRITABLE_FILE_OWNER_RIGHTS),
        w,
    )
}

fn format_layout(
    io: &mut impl EpochBlockIo,
    total_blocks: u32,
    m: &FormatManifest,
    snapshots: Option<&[UnifiedSystemObject; 4]>,
    scratch_owner_rights: Option<u32>,
    w: &mut FormatWorkspace,
) -> Result<FormatEvidence, Error> {
    w.len = 0;
    if total_blocks != BLOCK_COUNT {
        return Err(Error::Capacity);
    }
    validate_manifest(m)?;
    let baseline;
    let unified_system;
    let system: &[UnifiedSystemObject] = match snapshots {
        Some(snapshots) => {
            unified_system = unified::unified_map_from_baseline(&m.system, snapshots)?;
            if snapshots.iter().any(|s| s.generation != 1) {
                return Err(Error::Invalid);
            }
            if unified_system
                .iter()
                .any(|s| (s.first_block..s.first_block + s.kind.blocks()).contains(&m.root_block))
            {
                return Err(Error::Conflict);
            }
            &unified_system
        }
        None => {
            baseline = baseline_system(m);
            &baseline
        }
    };
    let scratch_file = scratch_owner_rights.is_some();
    if scratch_file
        && (m.root_block != unified::CANONICAL_BUSINESS_START
            || allocated(SCRATCH_FILE_BLOCK, m.root_block, system, false)
            || system
                .iter()
                .any(|s| u32::from(s.inode) == SCRATCH_FILE_INODE))
    {
        return Err(Error::Conflict);
    }
    // Whole-image zero verification with bounded one-block reads, before any
    // write. First non-zero block rejects the entire image untouched.
    for block in 0..BLOCK_COUNT {
        io.read(block, &mut w.block)?;
        if w.block.iter().any(|&v| v != 0) {
            return Err(Error::Conflict);
        }
    }
    record(w, FormatOp::ScanZero, 0, BLOCK_COUNT);
    write_bitmap(io, m.root_block, system, scratch_file, w)?;
    write_inodes(io, m.root_block, system, scratch_file, w)?;
    write_root(io, m, scratch_file, w)?;
    write_system(io, m, system, scratch_owner_rights, w)?;
    if scratch_file {
        w.block.fill(0);
        w.block[..SCRATCH_FILE_DATA.len()].copy_from_slice(SCRATCH_FILE_DATA);
        io.write(SCRATCH_FILE_BLOCK, &w.block)
            .map_err(|_| Error::Unknown)?;
        record(w, FormatOp::FileData, SCRATCH_FILE_BLOCK, 1);
    }
    flush(io, w)?;
    // Explicit log zeroing is contractual even though the scan proved the
    // region zero; it carries its own FLUSH boundary.
    w.block.fill(0);
    for block in LOG_START..BITMAP_START {
        io.write(block, &w.block).map_err(|_| Error::Unknown)?;
    }
    record(w, FormatOp::ZeroLog, LOG_START, BITMAP_START - LOG_START);
    flush(io, w)?;
    let sb = SuperblockV1 {
        fs_uuid: m.fs_uuid,
        generation: 1,
        checkpoint_lsn: 0,
        log_epoch: 1,
    };
    encode_superblock(&sb, &mut w.block)?;
    for dest in 0..2u32 {
        io.write(dest, &w.block).map_err(|_| Error::Unknown)?;
        record(w, FormatOp::Superblock, dest, 1);
        flush(io, w)?;
        io.read(dest, &mut w.readback).map_err(|_| Error::Unknown)?;
        if w.readback != w.block
            || SuperblockV1::decode(&w.readback).map_err(|_| Error::Unknown)? != sb
        {
            return Err(Error::Unknown);
        }
    }
    let system_blocks: u32 = system.iter().map(|s| s.kind.blocks()).sum();
    Ok(FormatEvidence {
        superblock: sb,
        root_block: m.root_block,
        system_blocks,
        data_blocks: system_blocks + 1 + u32::from(scratch_file),
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::file_media_v0199::{
        SUPER_BYTES, crc32c_payload, preflight_baseline_checkpoint, probe_snapshot_media_pair,
    };
    use super::super::file_mount_v1::{self, Acl, Workspace as MountWorkspace};
    use super::super::file_structure_v1::{Extent, Inode};
    use super::*;
    use std::{boxed::Box, collections::BTreeMap, vec::Vec};
    const ROOT: u32 = DATA_START;
    const BOOT: u32 = DATA_START + 1;
    const RECEIPTS: u32 = DATA_START + 2;
    const ACL: u32 = DATA_START + 9;
    const SECURITY: u32 = DATA_START + 13;
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Op {
        Write(u32),
        Flush,
    }
    struct Disk {
        blocks: BTreeMap<u32, Box<[u8; BLOCK]>>,
        ops: Vec<Op>,
        reads: u32,
        capacity: u32,
        flushes: u32,
        fail_flush: u32,
        fail_read: Option<u32>,
        lie_readback: bool,
    }
    impl Disk {
        fn blank() -> Self {
            Self {
                blocks: BTreeMap::new(),
                ops: Vec::new(),
                reads: 0,
                capacity: BLOCK_COUNT,
                flushes: 0,
                fail_flush: 0,
                fail_read: None,
                lie_readback: false,
            }
        }
    }
    impl EpochBlockIo for Disk {
        fn read(&mut self, b: u32, out: &mut [u8; BLOCK]) -> Result<(), Error> {
            self.reads += 1;
            if self.fail_read == Some(b) {
                return Err(Error::Unknown);
            }
            if b >= self.capacity {
                return Err(Error::Invalid);
            }
            if let Some(v) = self.blocks.get(&b) {
                *out = **v;
            } else {
                out.fill(0);
            }
            if self.lie_readback && b < 2 && self.blocks.contains_key(&b) {
                out[BLOCK - 1] ^= 1;
            }
            Ok(())
        }
        fn write(&mut self, b: u32, data: &[u8; BLOCK]) -> Result<(), Error> {
            self.ops.push(Op::Write(b));
            if b >= self.capacity {
                return Err(Error::Invalid);
            }
            self.blocks.insert(b, Box::new(*data));
            Ok(())
        }
        fn flush(&mut self) -> Result<(), Error> {
            self.ops.push(Op::Flush);
            self.flushes += 1;
            if self.flushes == self.fail_flush {
                return Err(Error::Unknown);
            }
            Ok(())
        }
    }
    fn manifest() -> FormatManifest {
        FormatManifest {
            fs_uuid: [1; 16],
            root_block: ROOT,
            system: [
                SystemObject {
                    kind: SystemKind::BootEpoch,
                    inode: 2,
                    generation: 1,
                    first_block: BOOT,
                },
                SystemObject {
                    kind: SystemKind::Receipts,
                    inode: 3,
                    generation: 1,
                    first_block: RECEIPTS,
                },
                SystemObject {
                    kind: SystemKind::Acl,
                    inode: 4,
                    generation: 1,
                    first_block: ACL,
                },
                SystemObject {
                    kind: SystemKind::Security,
                    inode: 5,
                    generation: 1,
                    first_block: SECURITY,
                },
            ],
            principals: core::array::from_fn(|i| Principal {
                id: i as u64 + 1,
                generation: 1,
            }),
            security: SecurityStateStoreV2 {
                fs_uuid: [1; 16],
                state_generation: 1,
                rule_min_generation: 1,
                security_min_generation: 1,
                key_generation: 1,
                isolated_service_bitmap: 0,
                last_boot_epoch: 0,
                offline_config_generation: 1,
                offline_config_hash: [0x5a; 32],
                service_generations: [1; 16],
            },
        }
    }
    fn formatted() -> (Disk, FormatManifest, FormatWorkspace, FormatEvidence) {
        let mut d = Disk::blank();
        let m = manifest();
        let mut w = FormatWorkspace::new();
        let e = format(&mut d, BLOCK_COUNT, &m, &mut w).unwrap();
        (d, m, w, e)
    }
    fn bitmap_bit(d: &Disk, block: u32) -> bool {
        let page = &d.blocks[&(BITMAP_START + block / (BLOCK as u32 * 8))];
        let within = block % (BLOCK as u32 * 8);
        page[(within / 8) as usize] & (1 << (within % 8)) != 0
    }
    fn inode_slot(d: &Disk, id: u32) -> Box<[u8; INODE_BYTES]> {
        let page = &d.blocks[&(INODE_START + id / 16)];
        let mut slot = [0u8; INODE_BYTES];
        slot.copy_from_slice(
            &page[(id % 16) as usize * INODE_BYTES..((id % 16) + 1) as usize * INODE_BYTES],
        );
        Box::new(slot)
    }
    // Independent bitwise CRC32C reference, not the production table code.
    fn reference_crc(b: &[u8], zero_at: usize) -> u32 {
        let mut crc = u32::MAX;
        for (i, &byte) in b.iter().enumerate() {
            crc ^= u32::from(if (zero_at..zero_at + 4).contains(&i) {
                0
            } else {
                byte
            });
            for _ in 0..8 {
                crc = (crc >> 1) ^ (if crc & 1 != 0 { 0x82f6_3b78 } else { 0 });
            }
        }
        !crc
    }
    #[test]
    fn golden_format_passes_full_mount_validation_and_checkpoint_preflight() {
        let (mut d, m, w, e) = formatted();
        assert_eq!(
            e.superblock,
            SuperblockV1 {
                fs_uuid: [1; 16],
                generation: 1,
                checkpoint_lsn: 0,
                log_epoch: 1
            }
        );
        assert_eq!(
            (e.root_block, e.system_blocks, e.data_blocks),
            (ROOT, 13, 14)
        );
        // Full 512 MiB scan plus the two superblock readbacks, nothing else.
        assert_eq!(d.reads, BLOCK_COUNT + 2);
        let sb0 = *d.blocks[&0];
        let sb1 = *d.blocks[&1];
        assert_eq!(sb0, sb1);
        assert_eq!(SuperblockV1::decode(&sb0).unwrap(), e.superblock);
        assert_eq!(probe_snapshot_media_pair(&sb0, &sb1).unwrap().generation, 1);
        let mut scratch = [0u8; 2 * SUPER_BYTES];
        assert_eq!(
            preflight_baseline_checkpoint(&sb0, &sb1, &mut scratch, |b, out| d.read(b, out)),
            Ok(e.superblock)
        );
        let mut mw = MountWorkspace::new();
        let v = file_mount_v1::validate(
            &mut d,
            e.superblock,
            &m.system,
            &m.principals,
            &mut mw,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(v.system_blocks, 13);
        assert_eq!(v.structure.live_inodes, 5);
        assert_eq!(v.structure.data_blocks, 14);
        assert_eq!(v.structure.directory_entries, 0);
        assert_eq!(v.boot.boot_epoch, 0);
        assert_eq!(v.receipts.occupied, 0);
        assert_eq!(
            v.usage[0],
            file_mount_v1::Usage {
                inodes: 1,
                blocks: 1,
                directory_slots: 1
            }
        );
        assert!(w.steps().len() == 15);
    }
    #[test]
    fn exact_section_9_2_1_trace_and_flush_order() {
        let (d, _m, w, _e) = formatted();
        let step = |op, first, blocks| FormatStep { op, first, blocks };
        assert_eq!(
            w.steps(),
            &[
                step(FormatOp::ScanZero, 0, BLOCK_COUNT),
                step(FormatOp::Bitmap, BITMAP_START, 4),
                step(FormatOp::InodeTable, INODE_START, 16),
                step(FormatOp::RootDirectory, ROOT, 1),
                step(FormatOp::SystemObject, BOOT, 1),
                step(FormatOp::SystemObject, RECEIPTS, 7),
                step(FormatOp::SystemObject, ACL, 4),
                step(FormatOp::SystemObject, SECURITY, 1),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::ZeroLog, LOG_START, 4096),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::Superblock, 0, 1),
                step(FormatOp::Flush, 0, 0),
                step(FormatOp::Superblock, 1, 1),
                step(FormatOp::Flush, 0, 0),
            ]
        );
        // Device-level order: 34 metadata writes, FLUSH, 4096 log writes,
        // FLUSH, superblock 0, FLUSH, superblock 1, FLUSH.
        let mut metadata: Vec<u32> = (BITMAP_START..INODE_START).collect();
        metadata.extend(INODE_START..DATA_START);
        metadata.extend([ROOT, BOOT]);
        metadata.extend(RECEIPTS..RECEIPTS + 7);
        metadata.extend(ACL..ACL + 4);
        metadata.push(SECURITY);
        assert_eq!(metadata.len(), 34);
        let expected: Vec<Op> = metadata.iter().map(|&b| Op::Write(b)).collect();
        assert_eq!(&d.ops[..34], &expected[..]);
        assert_eq!(d.ops[34], Op::Flush);
        for i in 0..4096u32 {
            assert_eq!(d.ops[35 + i as usize], Op::Write(LOG_START + i));
        }
        assert_eq!(
            &d.ops[4131..],
            &[Op::Flush, Op::Write(0), Op::Flush, Op::Write(1), Op::Flush]
        );
        assert_eq!(d.ops.len(), 4136);
        assert_eq!(d.flushes, 4);
    }
    #[test]
    fn rejects_non_zero_image_in_any_region_without_writing() {
        for dirty in [
            0u32,
            1,
            2,
            4097,
            4098,
            4101,
            4102,
            4117,
            4118,
            70000,
            BLOCK_COUNT - 1,
        ] {
            let mut d = Disk::blank();
            let mut b = [0u8; BLOCK];
            b[BLOCK - 1] = 1;
            d.blocks.insert(dirty, Box::new(b));
            let mut w = FormatWorkspace::new();
            assert_eq!(
                format(&mut d, BLOCK_COUNT, &manifest(), &mut w),
                Err(Error::Conflict),
                "block {dirty}"
            );
            assert!(d.ops.is_empty());
            assert_eq!(d.reads, dirty + 1);
            assert!(w.steps().is_empty());
        }
    }
    #[test]
    fn rejects_wrong_capacity_before_any_io() {
        for capacity in [0u32, 1, 4096, BLOCK_COUNT - 1, BLOCK_COUNT + 1, u32::MAX] {
            let mut d = Disk::blank();
            d.capacity = capacity;
            let mut w = FormatWorkspace::new();
            assert_eq!(
                format(&mut d, capacity, &manifest(), &mut w),
                Err(Error::Capacity)
            );
            assert_eq!(d.reads, 0);
            assert!(d.ops.is_empty());
        }
    }
    #[test]
    fn superblock_crc32c_golden_and_both_copies_published() {
        assert_eq!(crc32c_payload(b"123456789"), 0xe306_9283);
        let (d, m, _w, e) = formatted();
        // Independently constructed golden superblock, bitwise reference CRC.
        let mut g = [0u8; BLOCK];
        g[0..4].copy_from_slice(&SUPER_MAGIC.to_le_bytes());
        g[4..6].copy_from_slice(&1u16.to_le_bytes());
        g[6..8].copy_from_slice(&80u16.to_le_bytes());
        g[8..12].copy_from_slice(&4096u32.to_le_bytes());
        g[12..16].copy_from_slice(&BLOCK_COUNT.to_le_bytes());
        g[16..32].copy_from_slice(&m.fs_uuid);
        g[32..40].copy_from_slice(&1u64.to_le_bytes());
        g[48..56].copy_from_slice(&1u64.to_le_bytes());
        g[56..60].copy_from_slice(&BITMAP_START.to_le_bytes());
        g[60..64].copy_from_slice(&INODE_START.to_le_bytes());
        g[64..68].copy_from_slice(&DATA_START.to_le_bytes());
        g[68..72].copy_from_slice(&256u32.to_le_bytes());
        let crc = reference_crc(&g, 76);
        g[76..80].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(*d.blocks[&0], g);
        assert_eq!(*d.blocks[&1], g);
        assert_eq!(
            u32::from_le_bytes(g[76..80].try_into().unwrap()),
            reference_crc(&g, 76)
        );
        assert!(g[80..].iter().all(|&v| v == 0));
        assert_eq!(SuperblockV1::decode(&g).unwrap(), e.superblock);
    }
    #[test]
    fn reserved_bitmap_bits_root_inode_fields_and_free_slots() {
        let (d, m, _w, _e) = formatted();
        for block in 0..BLOCK_COUNT {
            let expected = block < DATA_START || (ROOT..SECURITY + 1).contains(&block);
            assert_eq!(bitmap_bit(&d, block), expected, "block {block}");
        }
        let root = Inode::decode(&*inode_slot(&d, 0)).unwrap();
        assert_eq!(root.kind, 2);
        assert_eq!(root.generation, 1);
        assert_eq!(root.size, ROOT_SIZE);
        assert_eq!(root.durable_write_seq, 0);
        assert_eq!(root.parent, 0);
        assert_eq!(root.parent_generation, 1);
        assert_eq!(root.extents, 1);
        assert_eq!(
            root.runs[0],
            Extent {
                logical: 0,
                physical: ROOT,
                count: 1
            }
        );
        for s in &m.system {
            let inode = Inode::decode(&*inode_slot(&d, u32::from(s.inode))).unwrap();
            let count = kind_blocks(s.kind);
            assert_eq!(inode.kind, 1);
            assert_eq!(inode.generation, s.generation);
            assert_eq!(inode.size, u64::from(count) * BLOCK as u64);
            assert_eq!(inode.parent, 0);
            assert_eq!(inode.parent_generation, 1);
            assert_eq!(inode.extents, 1);
            assert_eq!(
                inode.runs[0],
                Extent {
                    logical: 0,
                    physical: s.first_block,
                    count
                }
            );
        }
        for id in [1u32, 6, 100, 255] {
            let raw = inode_slot(&d, id);
            let inode = Inode::decode(&*raw).unwrap();
            assert_eq!(inode.kind, 0);
            assert_eq!(inode.generation, 0);
            assert_eq!(
                u32::from_le_bytes(raw[0..4].try_into().unwrap()),
                INODE_MAGIC
            );
            assert!(raw[16..252].iter().all(|&v| v == 0));
            assert_eq!(
                u32::from_le_bytes(raw[252..256].try_into().unwrap()),
                reference_crc(&*raw, 252)
            );
        }
        // Root directory block: every physical slot is a sealed empty slot.
        let root_block = &d.blocks[&ROOT];
        for slot in root_block.chunks_exact(DIR_SLOT_BYTES) {
            assert_eq!(u32::from_le_bytes(slot[0..4].try_into().unwrap()), u32::MAX);
            assert!(slot[4..124].iter().all(|&v| v == 0));
            assert_eq!(
                u32::from_le_bytes(slot[124..128].try_into().unwrap()),
                reference_crc(slot, 124)
            );
        }
    }
    #[test]
    fn system_object_blocks_match_validator_expectations() {
        let (d, m, _w, _e) = formatted();
        let boot = BootEpochStoreV1::decode(&*d.blocks[&BOOT]).unwrap();
        assert_eq!(
            boot,
            BootEpochStoreV1 {
                fs_uuid: m.fs_uuid,
                boot_epoch: 0
            }
        );
        assert_eq!(*d.blocks[&BOOT], boot.encode().unwrap());
        let security = SecurityStateStoreV2::decode(&*d.blocks[&SECURITY]).unwrap();
        assert_eq!(security, m.security);
        assert!(boot.matches(&security));
        for i in 0..RECEIPT_HOME_BLOCKS {
            assert!(d.blocks[&(RECEIPTS + i)].iter().all(|&v| v == 0));
        }
        let index = FileStreamIndexV4::decode(&*d.blocks[&(RECEIPTS + 6)]).unwrap();
        assert_eq!(index.fs_uuid, m.fs_uuid);
        assert_eq!(index.global_request_id_hi, 0);
        assert_eq!(index.generation, 1);
        for (i, g) in index.groups.iter().enumerate() {
            assert_eq!(g.manifest_principal_id, m.principals[i].id);
            assert_eq!((g.generation, g.flags, g.boot_epoch), (0, 0, 0));
        }
        assert!(index.streams.iter().all(|s| (
            s.generation,
            s.flags,
            s.issued_hi,
            s.retired_through
        ) == (0, 0, 0, 0)));
        for page in 0..4u32 {
            let raw = &d.blocks[&(ACL + page)];
            for (j, entry) in raw.chunks_exact(ACL_BYTES).enumerate() {
                let id = page as usize * ACL_ENTRIES_PER_BLOCK + j;
                let a = Acl::decode(entry).unwrap();
                assert_eq!(a.inode_id, id as u32);
                let live = id == 0 || m.system.iter().any(|s| usize::from(s.inode) == id);
                if live {
                    let generation = if id == 0 {
                        1
                    } else {
                        m.system
                            .iter()
                            .find(|s| usize::from(s.inode) == id)
                            .unwrap()
                            .generation
                    };
                    assert_eq!(a.state, 1);
                    assert_eq!(a.inode_generation, generation);
                    assert_eq!(a.principal, m.principals[0]);
                    assert_eq!(a.acl_generation, 1);
                    assert_eq!(a.parent, 0);
                    if id == 0 {
                        assert_eq!(a.owner_rights, ROOT_OWNER_RIGHTS);
                        assert_eq!(a.system_rights, 0);
                    } else {
                        assert_eq!(a.owner_rights, 0);
                        assert_eq!(a.system_rights, FILE_RIGHTS);
                    }
                } else {
                    assert_eq!(a.state, 0);
                    assert_eq!(a.inode_generation, 0);
                    assert_eq!(
                        a.principal,
                        Principal {
                            id: 0,
                            generation: 0
                        }
                    );
                    assert_eq!(
                        (a.owner_rights, a.system_rights, a.acl_generation),
                        (0, 0, 0)
                    );
                }
                assert_eq!(
                    u32::from_le_bytes(entry[60..64].try_into().unwrap()),
                    reference_crc(entry, 60)
                );
            }
        }
    }
    #[test]
    fn reformat_of_already_formatted_image_is_rejected() {
        let (mut d, m, _w, _e) = formatted();
        let ops = d.ops.len();
        let reads = d.reads;
        let mut w2 = FormatWorkspace::new();
        assert_eq!(
            format(&mut d, BLOCK_COUNT, &m, &mut w2),
            Err(Error::Conflict)
        );
        assert_eq!(d.ops.len(), ops);
        assert_eq!(d.reads, reads + 1);
        assert!(w2.steps().is_empty());
    }
    #[test]
    fn invalid_manifest_rejected_before_any_io() {
        let mut bad = manifest();
        bad.fs_uuid = [0; 16];
        let mut cases: Vec<FormatManifest> = std::vec![bad];
        let mut bad = manifest();
        bad.root_block = DATA_START - 1;
        cases.push(bad);
        let mut bad = manifest();
        bad.root_block = BLOCK_COUNT;
        cases.push(bad);
        let mut bad = manifest();
        bad.root_block = BOOT;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[0].inode = 0;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[1].inode = 2;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[1].kind = SystemKind::BootEpoch;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[0].generation = 0;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[0].first_block = DATA_START - 1;
        cases.push(bad);
        let mut bad = manifest();
        bad.system[1].first_block = BLOCK_COUNT - 6;
        cases.push(bad);
        let mut bad = manifest();
        bad.principals[3].id = 0;
        cases.push(bad);
        let mut bad = manifest();
        bad.principals[3].generation = 0;
        cases.push(bad);
        let mut bad = manifest();
        bad.principals[3].id = 1;
        cases.push(bad);
        let mut bad = manifest();
        bad.security.fs_uuid = [2; 16];
        cases.push(bad);
        let mut bad = manifest();
        bad.security.last_boot_epoch = 1;
        cases.push(bad);
        let mut bad = manifest();
        bad.security.state_generation = 2;
        cases.push(bad);
        let mut bad = manifest();
        bad.security.isolated_service_bitmap = 1;
        cases.push(bad);
        let mut bad = manifest();
        bad.security.offline_config_generation = 0;
        cases.push(bad);
        let mut bad = manifest();
        bad.security.offline_config_hash = [0; 32];
        cases.push(bad);
        for m in cases {
            let mut d = Disk::blank();
            let mut w = FormatWorkspace::new();
            assert!(format(&mut d, BLOCK_COUNT, &m, &mut w).is_err());
            assert_eq!(d.reads, 0);
            assert!(d.ops.is_empty());
            assert!(w.steps().is_empty());
        }
    }
    #[test]
    fn flush_failure_and_readback_lie_leave_unknown_without_publication() {
        // First FLUSH (metadata boundary) fails: no log zeroing, no headers.
        let mut d = Disk::blank();
        d.fail_flush = 1;
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format(&mut d, BLOCK_COUNT, &manifest(), &mut w),
            Err(Error::Unknown)
        );
        assert!(!d.ops.contains(&Op::Write(0)));
        assert!(!d.ops.contains(&Op::Write(1)));
        assert_eq!(w.steps().len(), 8);
        assert_eq!(w.steps().last().unwrap().op, FormatOp::SystemObject);
        // Superblock 0 FLUSH fails: header 1 must never be written.
        let mut d = Disk::blank();
        d.fail_flush = 3;
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format(&mut d, BLOCK_COUNT, &manifest(), &mut w),
            Err(Error::Unknown)
        );
        assert!(d.ops.contains(&Op::Write(0)));
        assert!(!d.ops.contains(&Op::Write(1)));
        // Device lies on readback: publication is not confirmed.
        let mut d = Disk::blank();
        d.lie_readback = true;
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format(&mut d, BLOCK_COUNT, &manifest(), &mut w),
            Err(Error::Unknown)
        );
        assert_eq!(
            *w.steps().last().unwrap(),
            FormatStep {
                op: FormatOp::Flush,
                first: 0,
                blocks: 0
            }
        );
    }
    #[test]
    fn scan_read_error_propagates_without_writes() {
        let mut d = Disk::blank();
        d.fail_read = Some(70000);
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format(&mut d, BLOCK_COUNT, &manifest(), &mut w),
            Err(Error::Unknown)
        );
        assert_eq!(d.reads, 70001);
        assert!(d.ops.is_empty());
        assert!(w.steps().is_empty());
    }
    fn staging_manifest() -> FormatManifest {
        let obj = |kind, inode, first_block| SystemObject {
            kind,
            inode,
            generation: 1,
            first_block,
        };
        let mut m = manifest();
        m.root_block = unified::CANONICAL_BUSINESS_START;
        m.system = [
            obj(SystemKind::BootEpoch, unified::BOOT_INODE, DATA_START),
            obj(
                SystemKind::Receipts,
                unified::RECEIPTS_INODE,
                DATA_START + 1,
            ),
            obj(SystemKind::Acl, unified::ACL_INODE, DATA_START + 8),
            obj(
                SystemKind::Security,
                unified::SECURITY_INODE,
                DATA_START + 12,
            ),
        ];
        m
    }
    fn staging_snapshots() -> [UnifiedSystemObject; 4] {
        [
            UnifiedSystemKind::SnapshotCatalog,
            UnifiedSystemKind::SnapshotSlot,
            UnifiedSystemKind::SnapshotRequest,
            UnifiedSystemKind::SnapshotProtection,
        ]
        .map(|kind| UnifiedSystemObject {
            kind,
            inode: kind.inode_slot(),
            generation: 1,
            first_block: kind.fixed_first_block().unwrap(),
        })
    }
    #[test]
    fn unified_format_materializes_eight_system_objects_before_publication() {
        let m = staging_manifest();
        let snapshots = staging_snapshots();
        let map = unified::unified_map_from_baseline(&m.system, &snapshots).unwrap();
        let mut d = Disk::blank();
        let mut w = FormatWorkspace::new();
        let e = format_unified(&mut d, BLOCK_COUNT, &m, &snapshots, &mut w).unwrap();
        assert_eq!(
            (e.root_block, e.system_blocks, e.data_blocks),
            (4269, 151, 152)
        );
        assert_eq!(d.reads, BLOCK_COUNT + 2);
        let (sb0, sb1) = (*d.blocks[&0], *d.blocks[&1]);
        assert_eq!(sb0, sb1);
        assert_eq!(
            unified::unified_superblock_pair(&sb0, &sb1),
            Ok(SuperblockV1 {
                fs_uuid: m.fs_uuid,
                generation: 1,
                checkpoint_lsn: 0,
                log_epoch: 1,
            })
        );

        let mut metadata: Vec<_> = (BITMAP_START..DATA_START).map(Op::Write).collect();
        metadata.push(Op::Write(m.root_block));
        for object in &map {
            let range = object.first_block..object.first_block + object.kind.blocks();
            metadata.extend(range.map(Op::Write));
        }
        assert_eq!(metadata.len(), 172);
        let mut ops = metadata;
        ops.push(Op::Flush);
        ops.extend((LOG_START..BITMAP_START).map(Op::Write));
        ops.extend([Op::Flush, Op::Write(0), Op::Flush, Op::Write(1), Op::Flush]);
        assert_eq!(d.ops, ops);
        assert_eq!(w.steps().len(), 19);
        for (step, object) in w.steps()[4..12].iter().zip(map) {
            assert_eq!(
                *step,
                FormatStep {
                    op: FormatOp::SystemObject,
                    first: object.first_block,
                    blocks: object.kind.blocks(),
                }
            );
        }
        assert_eq!(w.steps()[12].op, FormatOp::Flush);

        for block in 0..BLOCK_COUNT {
            assert_eq!(
                bitmap_bit(&d, block),
                block <= m.root_block,
                "block {block}"
            );
        }
        let acl_home = m.system[2].first_block;
        for object in map {
            let id = u32::from(object.inode);
            let blocks = object.kind.blocks();
            let inode = Inode::decode(&*inode_slot(&d, id)).unwrap();
            assert_eq!((inode.kind, inode.generation, inode.extents), (1, 1, 1));
            assert_eq!((inode.parent, inode.parent_generation), (0, 1));
            assert_eq!(inode.size, u64::from(blocks) * BLOCK as u64);
            assert_eq!(
                inode.runs[0],
                Extent {
                    logical: 0,
                    physical: object.first_block,
                    count: blocks
                }
            );
            let acl = &d.blocks[&(acl_home + id / ACL_ENTRIES_PER_BLOCK as u32)];
            let offset = id as usize % ACL_ENTRIES_PER_BLOCK * ACL_BYTES;
            assert_eq!(
                Acl::decode(&acl[offset..offset + ACL_BYTES]),
                Ok(Acl {
                    inode_id: id,
                    state: 1,
                    inode_generation: 1,
                    principal: m.principals[0],
                    owner_rights: 0,
                    system_rights: FILE_RIGHTS,
                    acl_generation: 1,
                    parent: 0,
                })
            );
        }
        for id in u32::from(unified::RESERVED_INODE_START)..INODES as u32 {
            let inode = Inode::decode(&*inode_slot(&d, id)).unwrap();
            assert_eq!((inode.kind, inode.generation), (0, 0));
        }
        for object in snapshots {
            assert_eq!(
                unified::decode_object_envelope(object.kind, &*d.blocks[&object.first_block]),
                Ok(unified::ObjectEnvelope {
                    kind: object.kind,
                    fs_uuid: m.fs_uuid,
                    generation: 1
                })
            );
            for block in object.first_block + 1..object.first_block + object.kind.blocks() {
                assert_eq!(*d.blocks[&block], [0; BLOCK]);
            }
        }
    }
    #[test]
    fn unified_format_rejects_inconsistent_map_before_io() {
        let snapshots = staging_snapshots();
        let mut root_overlaps = staging_manifest();
        root_overlaps.root_block = snapshots[1].first_block + 1;
        let mut baseline_overlaps = staging_manifest();
        baseline_overlaps.system[1].first_block = snapshots[0].first_block - 1;
        let mut wrong_slot = staging_manifest();
        wrong_slot.system[0].inode = 20;
        let mut moved = snapshots;
        moved[2].first_block += 1;
        let mut non_initial = snapshots;
        non_initial[0].generation = 2;
        for (m, snapshots, error) in [
            (root_overlaps, snapshots, Error::Conflict),
            (baseline_overlaps, snapshots, Error::Conflict),
            (wrong_slot, snapshots, Error::Invalid),
            (staging_manifest(), moved, Error::Invalid),
            (staging_manifest(), non_initial, Error::Invalid),
        ] {
            let mut d = Disk::blank();
            let mut w = FormatWorkspace::new();
            assert_eq!(
                format_unified(&mut d, BLOCK_COUNT, &m, &snapshots, &mut w),
                Err(error)
            );
            assert_eq!(d.reads, 0);
            assert!(d.ops.is_empty());
            assert!(w.steps().is_empty());
        }
    }
    #[test]
    fn unified_format_failed_metadata_flush_leaves_superblocks_unpublished() {
        let m = staging_manifest();
        let snapshots = staging_snapshots();
        let mut d = Disk::blank();
        d.fail_flush = 1;
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format_unified(&mut d, BLOCK_COUNT, &m, &snapshots, &mut w),
            Err(Error::Unknown)
        );
        assert_eq!(d.reads, BLOCK_COUNT);
        assert_eq!(d.ops.len(), 173);
        assert_eq!(d.ops.last(), Some(&Op::Flush));
        assert_eq!(w.steps().len(), 12);
        assert!(!d.blocks.contains_key(&0));
        assert!(!d.blocks.contains_key(&1));
        assert!(!d.blocks.contains_key(&LOG_START));
    }
    #[test]
    fn scratch_file_data_is_included_in_the_first_flush() {
        let m = staging_manifest();
        let mut d = Disk::blank();
        d.fail_flush = 1;
        let mut w = FormatWorkspace::new();
        assert_eq!(
            format_unified_with_scratch_file(&mut d, BLOCK_COUNT, &m, &staging_snapshots(), &mut w),
            Err(Error::Unknown)
        );
        assert_eq!(d.reads, BLOCK_COUNT);
        assert!(bitmap_bit(&d, SCRATCH_FILE_BLOCK));
        let block = &d.blocks[&SCRATCH_FILE_BLOCK];
        let (data, padding) = block.split_at(SCRATCH_FILE_DATA.len());
        assert_eq!(data, b"CyxiaOS V0.20 signed scratch\n");
        assert!(padding.iter().all(|&byte| byte == 0));
        assert_eq!(
            w.steps().last(),
            Some(&FormatStep {
                op: FormatOp::FileData,
                first: SCRATCH_FILE_BLOCK,
                blocks: 1,
            })
        );
        assert_eq!(
            d.ops[d.ops.len() - 2..],
            [Op::Write(SCRATCH_FILE_BLOCK), Op::Flush]
        );
        assert!(!d.blocks.contains_key(&0));
        assert!(!d.blocks.contains_key(&1));
        assert!(!d.blocks.contains_key(&LOG_START));
    }
    // Mirrors the V0.20 wave-11 media-staging baseline map and boot epoch.
    #[test]
    fn unified_slot_staging_manifest_formats_mounts_and_allocates_boot_epoch() {
        use super::super::boot_epoch_v1::{BootEpochAuthority, BootEpochTx, BootPairRedo};
        use super::super::durable_role_epoch_v0199::SlotBinding;
        use crate::control_plane::role_manifest_v0199::ROLES;
        let m = staging_manifest();
        let mut d = Disk::blank();
        let mut w = FormatWorkspace::new();
        let e = format(&mut d, BLOCK_COUNT, &m, &mut w).unwrap();
        let mut mw = MountWorkspace::new();
        let v = file_mount_v1::validate(
            &mut d,
            e.superblock,
            &m.system,
            &m.principals,
            &mut mw,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!((v.system_blocks, v.structure.live_inodes), (13, 5));
        let map = unified::unified_map_from_baseline(&m.system, &staging_snapshots()).unwrap();
        assert_eq!(
            unified::validate_unified_system_map(&map)
                .unwrap()
                .system_blocks,
            151
        );
        let (sb0, sb1) = (*d.blocks[&0], *d.blocks[&1]);
        assert_eq!(
            unified::unified_superblock_pair(&sb0, &sb1),
            Ok(e.superblock)
        );
        // The baseline formatter never touches the new snapshot ranges.
        assert!((4131..4269).all(|b| !d.blocks.contains_key(&b)));
        let state = *d.blocks[&(DATA_START + 12)];
        let boot = *d.blocks[&DATA_START];
        let slots = core::array::from_fn(|i| SlotBinding {
            role: ROLES[i],
            slot: i as u8,
        });
        let mut auth = BootEpochAuthority::open(&state, &boot, slots, |s| {
            if *s == v.security {
                Ok(())
            } else {
                Err(Error::Conflict)
            }
        })
        .unwrap();
        assert_eq!(auth.confirmed_epoch(), None);
        let tx = BootEpochTx {
            superblock_raw: &sb0,
            first_log_block: 2,
            state_home: DATA_START + 12,
            boot_home: DATA_START,
            txid: 1,
            commit_lsn: 4,
        };
        let mut pair = BootPairRedo::new();
        assert_eq!(auth.allocate(&mut d, &mut pair, tx).unwrap().epoch(), 1);
        assert_eq!(auth.confirmed_epoch(), Some(1));
        let mut again = BootPairRedo::new();
        assert_eq!(
            auth.allocate(&mut d, &mut again, tx).err(),
            Some(Error::Conflict)
        );
    }
}
