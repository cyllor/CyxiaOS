//! Baseline-v1 new-image formatter contract (V0.19.9 §9.2/§9.2.1/§9.6).
//!
//! Contract layer only: accepts an exactly 512 MiB (131072 x 4096) all-zero
//! new image, rejects any existing content before the first write, and
//! publishes initial metadata in the fixed §9.2.1 order:
//! bitmap/inode table/root directory/four system objects -> FLUSH ->
//! zero the log region 2..4098 -> FLUSH -> two byte-identical initial
//! superblocks (generation=1, log_epoch=1, checkpoint_lsn=0), each
//! FLUSH-confirmed and read back. This is not a damage-recovery path and
//! never erases existing content. Native boot wiring is a later release
//! gate; nothing here is wired into kernel/.
//!
//! Byte-source derivation (every written byte comes from the baseline or a
//! frozen module):
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
//!   come from the caller's trusted build manifest (§9.2.1); this module
//!   fixes no production locations.
//!
//! Documented gaps (the baseline does not fix these initial wire values):
//! - Empty root directory size: the frozen v1 fixtures use a one-block root
//!   with size=128 per declared slot. This formatter writes one 4 KiB root
//!   block whose 256 physical slots are all sealed empty (inode_id=0xFFFFFFFF
//!   plus CRC per §9.2.1) and declares size=128. A zero-size extent-less root
//!   also passes the v1 scan; the one-block convention follows the existing
//!   fixtures and keeps a ready root directory block.
//! - Initial ACL ownership/rights: the baseline delegates them to the trusted
//!   volume manifest. Following the only existing concrete reference
//!   (tools/verify_v0199_epoch_disk.py and the file_mount_v1 fixture),
//!   principals[0] owns the root (owner_rights=FILE_TRAVERSE bit14) and all
//!   four system objects (owner_rights=0, system_rights=READ|WRITE|FSYNC
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
const DIR_SLOTS: usize = BLOCK / DIR_SLOT_BYTES;
const ACL_BYTES: usize = 64;
const ACL_ENTRIES_PER_BLOCK: usize = BLOCK / ACL_BYTES;
const RECEIPT_HOME_BLOCKS: u32 = 6;
const SYSTEM_BLOCKS: u32 = 13;
const ROOT_SIZE: u64 = 128;
const INODE_MAGIC: u32 = 0x4359_494e;
// CapabilityRightsSchema v3 bit8..14 = READ/WRITE/CREATE/REMOVE/ENUM/FSYNC/
// TRAVERSE; masks identical to the frozen file_mount_v1 validator.
const FILE_RIGHTS: u32 = (1 << 8) | (1 << 9) | (1 << 13);
const ROOT_OWNER_RIGHTS: u32 = 1 << 14;
const MAX_STEPS: usize = 16;
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
    match kind {
        SystemKind::BootEpoch | SystemKind::Security => 1,
        SystemKind::Receipts => 7,
        SystemKind::Acl => 4,
    }
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
/// fixed-capacity operation trace (the complete sequence needs 15 steps).
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
    // The fixed §9.2.1 sequence is statically shorter than MAX_STEPS.
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
fn allocated(block: u32, m: &FormatManifest) -> bool {
    if block < DATA_START || block == m.root_block {
        return true;
    }
    m.system
        .iter()
        .any(|s| block >= s.first_block && block < s.first_block + kind_blocks(s.kind))
}
fn write_bitmap(
    io: &mut impl EpochBlockIo,
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for page in 0..BITMAP_BLOCKS {
        w.block.fill(0);
        let base = page * (BLOCK as u32 * 8);
        for (byte, slot) in w.block.iter_mut().enumerate() {
            let mut bits = 0u8;
            for bit in 0..8u32 {
                if allocated(base + byte as u32 * 8 + bit, m) {
                    bits |= 1 << bit;
                }
            }
            *slot = bits;
        }
        io.write(BITMAP_START + page, &w.block)
            .map_err(|_| Error::Unknown)?;
    }
    record(w, FormatOp::Bitmap, BITMAP_START, BITMAP_BLOCKS);
    Ok(())
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
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for page in 0..INODE_BLOCKS {
        w.block.fill(0);
        for slot in 0..(BLOCK / INODE_BYTES) {
            let id = page as usize * (BLOCK / INODE_BYTES) + slot;
            let b = &mut w.block[slot * INODE_BYTES..(slot + 1) * INODE_BYTES];
            if id == 0 {
                seal_inode(b, 2, 1, ROOT_SIZE, m.root_block, 1)?;
            } else if let Some(s) = m.system.iter().find(|s| usize::from(s.inode) == id) {
                let count = kind_blocks(s.kind);
                seal_inode(
                    b,
                    1,
                    s.generation,
                    u64::from(count) * BLOCK as u64,
                    s.first_block,
                    count,
                )?;
            } else {
                // Fresh free slot: magic + generation 0 + valid CRC only.
                seal_inode(b, 0, 0, 0, 0, 0)?;
            }
        }
        io.write(INODE_START + page, &w.block)
            .map_err(|_| Error::Unknown)?;
    }
    record(w, FormatOp::InodeTable, INODE_START, INODE_BLOCKS);
    Ok(())
}
fn write_root(
    io: &mut impl EpochBlockIo,
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    w.block.fill(0);
    for slot in 0..DIR_SLOTS {
        let b = &mut w.block[slot * DIR_SLOT_BYTES..(slot + 1) * DIR_SLOT_BYTES];
        p32(b, 0, u32::MAX);
        let crc = crc32c_zeroed(b, 124)?;
        p32(b, 124, crc);
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
fn seal_acl_entry(m: &FormatManifest, id: usize, b: &mut [u8]) -> Result<(), Error> {
    let system = m.system.iter().find(|s| usize::from(s.inode) == id);
    let live = id == 0 || system.is_some();
    p32(b, 0, id as u32);
    if live {
        let generation = if id == 0 {
            1
        } else {
            system.map_or(0, |s| s.generation)
        };
        p32(b, 4, 1);
        p64(b, 8, generation);
        p64(b, 16, m.principals[0].id);
        p64(b, 24, m.principals[0].generation);
        if id == 0 {
            p32(b, 32, ROOT_OWNER_RIGHTS);
        } else {
            p32(b, 36, FILE_RIGHTS);
        }
        p64(b, 40, 1);
        // parent_inode at 48 stays 0, matching root/system inode parents.
    }
    let crc = crc32c_zeroed(b, 60)?;
    p32(b, 60, crc);
    Ok(())
}
fn write_system(
    io: &mut impl EpochBlockIo,
    m: &FormatManifest,
    w: &mut FormatWorkspace,
) -> Result<(), Error> {
    for s in &m.system {
        let first = s.first_block;
        match s.kind {
            SystemKind::BootEpoch => {
                w.block = BootEpochStoreV1 {
                    fs_uuid: m.fs_uuid,
                    boot_epoch: 0,
                }
                .encode()?;
                io.write(first, &w.block).map_err(|_| Error::Unknown)?;
            }
            SystemKind::Security => {
                w.block = m.security.encode()?;
                io.write(first, &w.block).map_err(|_| Error::Unknown)?;
            }
            SystemKind::Receipts => {
                w.block.fill(0);
                for i in 0..RECEIPT_HOME_BLOCKS {
                    io.write(first + i, &w.block).map_err(|_| Error::Unknown)?;
                }
                encode_index(m, &mut w.block)?;
                io.write(first + RECEIPT_HOME_BLOCKS, &w.block)
                    .map_err(|_| Error::Unknown)?;
            }
            SystemKind::Acl => {
                for page in 0..(INODES * ACL_BYTES / BLOCK) as u32 {
                    w.block.fill(0);
                    for j in 0..ACL_ENTRIES_PER_BLOCK {
                        let id = page as usize * ACL_ENTRIES_PER_BLOCK + j;
                        seal_acl_entry(m, id, &mut w.block[j * ACL_BYTES..(j + 1) * ACL_BYTES])?;
                    }
                    io.write(first + page, &w.block)
                        .map_err(|_| Error::Unknown)?;
                }
            }
        }
        record(w, FormatOp::SystemObject, first, kind_blocks(s.kind));
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
    w.len = 0;
    if total_blocks != BLOCK_COUNT {
        return Err(Error::Capacity);
    }
    validate_manifest(m)?;
    // Whole-image zero verification with bounded one-block reads, before any
    // write. First non-zero block rejects the entire image untouched.
    for block in 0..BLOCK_COUNT {
        io.read(block, &mut w.block)?;
        if w.block.iter().any(|&v| v != 0) {
            return Err(Error::Conflict);
        }
    }
    record(w, FormatOp::ScanZero, 0, BLOCK_COUNT);
    write_bitmap(io, m, w)?;
    write_inodes(io, m, w)?;
    write_root(io, m, w)?;
    write_system(io, m, w)?;
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
    Ok(FormatEvidence {
        superblock: sb,
        root_block: m.root_block,
        system_blocks: SYSTEM_BLOCKS,
        data_blocks: SYSTEM_BLOCKS + 1,
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
}
