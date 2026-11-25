//! Fixed disk-format codecs for the v1.4 immutable-snapshot profile.
//!
//! These codecs validate local structure, checksums, bounds, and reserved bytes.
//! They do **not** validate filesystem-wide bitmap/ownership/reference consistency,
//! SHA-256 transaction digests, adjacent records, durability, or recovery order.
//! In particular, decoding a COMMIT does not establish that a transaction committed.
//!
//! This implementation requires nonzero filesystem UUID, generations, epochs and
//! transaction IDs. It supports only transactions with 1..=128 REDOs; the design
//! does not define the last-REDO field for a no-op transaction. These restrictions
//! are format choices, not additional claims about the design's normative text.
//! Encoders validate everything before writing and leave output unchanged on error.

pub const BLOCK_SIZE: usize = 4096;
pub const TOTAL_BLOCKS: u32 = 131_072;
pub const BITMAP_START: u32 = 4098;
pub const INODE_START: u32 = 4102;
pub const CONTROL_START: u32 = 4118;
pub const CATALOG_START: u32 = 4119;
pub const SNAPSHOT_START: u32 = 4120;
pub const SNAPSHOT_SLOTS: u32 = 8;
pub const SNAPSHOT_STRIDE: u32 = 15;
pub const BUSINESS_INODE_COUNT: u32 = 224;
pub const SYSTEM_ROOT_INODE: u32 = 224;
pub const BOOT_INODE: u32 = 225;
/// Legacy media identity: inode numbers of the two reserved system volumes.
/// Directory entries and inode validation on existing media reference these
/// exact numbers, so the CLUSTER_* names are kept for disk compatibility even
/// though the single-machine profile has no cluster runtime. Do not rename.
pub const CLUSTER_INODES: [u32; 2] = [226, 227];
pub const REQUEST_INODE: u32 = 228;
pub const DATA_START: u32 = 4240;
pub const SYSTEM_ROOT_BLOCK: u32 = DATA_START;
pub const BOOT_BLOCK: u32 = DATA_START + 1;
/// Legacy media identity: first block of the reserved-volume file region.
/// On-disk extents point at these blocks; the name is format identity, not a
/// live cluster concept. Do not rename.
pub const CLUSTER_START: u32 = DATA_START + 2;
/// Legacy media identity: fixed block reservation per reserved volume file.
/// Existing inode extents and bitmap ownership depend on this exact size.
/// Do not rename.
pub const CLUSTER_FILE_BLOCKS: u32 = 2048;
pub const SNAPSHOT_REQUEST_START: u32 = DATA_START + 4098;
pub const SNAPSHOT_REQUEST_BLOCKS: u32 = 16;
pub const FIRST_BUSINESS_BLOCK: u32 = DATA_START + 4114;
pub const INODE_COUNT: u32 = 256;
pub const INODE_SIZE: usize = 256;
pub const DIRECTORY_SLOT_SIZE: usize = 128;
pub const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;
pub const MAX_DIRECTORY_SIZE: u64 = 256 * DIRECTORY_SLOT_SIZE as u64;
pub const MAX_REDOS: u32 = 128;
pub const MAX_ORDERED: usize = 128;
pub const MAX_INLINE_EXTENTS: usize = 16;
pub const MAX_INDIRECT_EXTENTS: usize = 338;
pub const MAX_EXTENTS: usize = MAX_INLINE_EXTENTS + MAX_INDIRECT_EXTENTS;
pub const LOG_HEADER_SIZE: usize = 64;
const SUPERBLOCK_MAGIC: u32 = 0x4359_4653;
const INODE_MAGIC: u32 = 0x4359_494e;
const LOG_MAGIC: u32 = 0x4359_4c47;
const EXTENT_MAGIC: u32 = 0x4359_4558;

/// The complete mutable-home domain. All later blocks are immutable CoW data.
pub const fn is_redo_home(block: u32) -> bool {
    block >= BITMAP_START && block < FIRST_BUSINESS_BLOCK
}

pub const fn is_business_block(block: u32) -> bool {
    block >= FIRST_BUSINESS_BLOCK && block < TOTAL_BLOCKS
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Checksum,
    Magic,
    Version,
    Layout,
    Reserved,
    Identity,
    Counter,
    Conflict,
    InodeType,
    Extent,
    Name,
    LogType,
    Payload,
    Range,
}

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut index = 0;
    while index < table.len() {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = (value >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(value & 1));
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

// One compile-time 1 KiB read-only table keeps page validation bounded on
// platforms without CRC instructions. No mutable state or runtime allocation.
static CRC32C_TABLE: [u32; 256] = crc32c_table();

fn crc_byte(crc: u32, byte: u8) -> u32 {
    (crc >> 8) ^ CRC32C_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize]
}

/// Reflected CRC32C (Castagnoli), with initial and final XOR of 0xffffffff.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = crc_byte(crc, byte);
    }
    !crc
}

pub(crate) fn checksum(bytes: &[u8], offset: usize) -> u32 {
    let mut crc = u32::MAX;
    for (index, &byte) in bytes.iter().enumerate() {
        crc = crc_byte(
            crc,
            if (offset..offset + 4).contains(&index) {
                0
            } else {
                byte
            },
        );
    }
    !crc
}

// Callers establish the exact structure length before using fixed field offsets.
// No attacker-supplied offset is passed to these helpers.
fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn check_len(bytes: &[u8], length: usize) -> Result<(), Error> {
    if bytes.len() != length {
        Err(Error::Length)
    } else {
        Ok(())
    }
}
fn zeros(bytes: &[u8]) -> Result<(), Error> {
    if bytes.iter().any(|&byte| byte != 0) {
        Err(Error::Reserved)
    } else {
        Ok(())
    }
}
fn check_checksum(bytes: &[u8], offset: usize) -> Result<(), Error> {
    if u32_at(bytes, offset) != checksum(bytes, offset) {
        Err(Error::Checksum)
    } else {
        Ok(())
    }
}
fn write_checksum(bytes: &mut [u8], offset: usize) {
    let crc = checksum(bytes, offset);
    put32(bytes, offset, crc);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    pub fs_uuid: [u8; 16],
    pub generation: u64,
    pub checkpoint_lsn: u64,
    pub log_epoch: u64,
}

impl Superblock {
    fn validate(&self) -> Result<(), Error> {
        if self.fs_uuid == [0; 16] {
            return Err(Error::Identity);
        }
        if self.generation == 0 || self.log_epoch == 0 {
            return Err(Error::Counter);
        }
        Ok(())
    }

    pub fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        check_len(bytes, BLOCK_SIZE)?;
        self.validate()?;
        bytes.fill(0);
        put32(bytes, 0, SUPERBLOCK_MAGIC);
        put16(bytes, 4, 2);
        put16(bytes, 6, 112);
        put32(bytes, 8, BLOCK_SIZE as u32);
        put32(bytes, 12, TOTAL_BLOCKS);
        bytes[16..32].copy_from_slice(&self.fs_uuid);
        put64(bytes, 32, self.generation);
        put64(bytes, 40, self.checkpoint_lsn);
        put64(bytes, 48, self.log_epoch);
        put32(bytes, 56, BITMAP_START);
        put32(bytes, 60, INODE_START);
        put32(bytes, 64, DATA_START);
        put32(bytes, 68, INODE_COUNT);
        put32(bytes, 76, CONTROL_START);
        put32(bytes, 80, CATALOG_START);
        put32(bytes, 84, SNAPSHOT_START);
        put32(bytes, 88, SNAPSHOT_SLOTS);
        put32(bytes, 92, SNAPSHOT_STRIDE);
        put32(bytes, 96, BUSINESS_INODE_COUNT);
        put32(bytes, 100, SYSTEM_ROOT_INODE);
        write_checksum(bytes, 108);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        check_len(bytes, BLOCK_SIZE)?;
        if u32_at(bytes, 0) != SUPERBLOCK_MAGIC {
            return Err(Error::Magic);
        }
        // A v1 image needs an offline export/import; never reinterpret it in place.
        if u16_at(bytes, 4) != 2 {
            return Err(Error::Version);
        }
        check_checksum(bytes, 108)?;
        if u16_at(bytes, 6) != 112
            || u32_at(bytes, 8) != BLOCK_SIZE as u32
            || u32_at(bytes, 12) != TOTAL_BLOCKS
            || u32_at(bytes, 56) != BITMAP_START
            || u32_at(bytes, 60) != INODE_START
            || u32_at(bytes, 64) != DATA_START
            || u32_at(bytes, 68) != INODE_COUNT
            || u32_at(bytes, 72) != 0
            || u32_at(bytes, 76) != CONTROL_START
            || u32_at(bytes, 80) != CATALOG_START
            || u32_at(bytes, 84) != SNAPSHOT_START
            || u32_at(bytes, 88) != SNAPSHOT_SLOTS
            || u32_at(bytes, 92) != SNAPSHOT_STRIDE
            || u32_at(bytes, 96) != BUSINESS_INODE_COUNT
            || u32_at(bytes, 100) != SYSTEM_ROOT_INODE
            || u32_at(bytes, 104) != 0
        {
            return Err(Error::Layout);
        }
        zeros(&bytes[112..])?;
        let mut fs_uuid = [0; 16];
        fs_uuid.copy_from_slice(&bytes[16..32]);
        let value = Self {
            fs_uuid,
            generation: u64_at(bytes, 32),
            checkpoint_lsn: u64_at(bytes, 40),
            log_epoch: u64_at(bytes, 48),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Select a valid checkpoint without guessing across conflicting identities.
/// One corrupt copy may be ignored; two individually valid but inconsistent
/// copies fail closed. Equal-generation identical copies are valid at format.
pub fn select_superblock(first: &[u8], second: &[u8]) -> Result<Superblock, Error> {
    match (Superblock::decode(first), Superblock::decode(second)) {
        (Ok(a), Ok(b)) => {
            if a.fs_uuid != b.fs_uuid {
                return Err(Error::Conflict);
            }
            if a.generation == b.generation {
                return if a == b { Ok(a) } else { Err(Error::Conflict) };
            }
            let (older, newer) = if a.generation < b.generation {
                (a, b)
            } else {
                (b, a)
            };
            if newer.checkpoint_lsn < older.checkpoint_lsn || newer.log_epoch <= older.log_epoch {
                return Err(Error::Conflict);
            }
            Ok(newer)
        }
        (Ok(value), Err(_)) | (Err(_), Ok(value)) => Ok(value),
        (Err(error), Err(_)) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InodeKind {
    Free,
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    pub logical_start: u32,
    pub physical_start: u32,
    pub block_count: u32,
}

impl Extent {
    pub const EMPTY: Self = Self {
        logical_start: 0,
        physical_start: 0,
        block_count: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inode {
    pub kind: InodeKind,
    pub generation: u64,
    pub size: u64,
    pub durable_write_seq: u64,
    pub extent_count: u16,
    pub parent_inode: u32,
    pub parent_generation: u64,
    pub extents: [Extent; 16],
    pub ext_block: u32,
    pub ext_count: u16,
}

impl Inode {
    /// Check only this slot. The caller must additionally check parent and
    /// directory generations, allocation bitmap, and physical ownership across
    /// all inodes before using it as filesystem state.
    pub fn validate(&self, inode_id: u32) -> Result<(), Error> {
        if inode_id >= INODE_COUNT {
            return Err(Error::Range);
        }
        if self.generation == 0 {
            return Err(Error::Counter);
        }
        let count = usize::from(self.extent_count);
        if count > self.extents.len() {
            return Err(Error::Extent);
        }
        if self.kind == InodeKind::Free {
            if inode_id == 0
                || inode_id == SYSTEM_ROOT_INODE
                || self.size != 0
                || self.durable_write_seq != 0
                || count != 0
                || self.parent_inode != 0
                || self.parent_generation != 0
                || self.extents != [Extent::EMPTY; 16]
                || self.ext_block != 0
                || self.ext_count != 0
            {
                return Err(Error::Layout);
            }
            return Ok(());
        }
        if self.parent_inode >= INODE_COUNT
            || self.parent_generation == 0
            || (inode_id < BUSINESS_INODE_COUNT) != (self.parent_inode < BUSINESS_INODE_COUNT)
        {
            return Err(Error::Identity);
        }
        if inode_id == 0 || inode_id == SYSTEM_ROOT_INODE {
            if self.kind != InodeKind::Directory
                || self.generation != 1
                || self.parent_inode != inode_id
                || self.parent_generation != 1
            {
                return Err(Error::Identity);
            }
        } else if self.parent_inode == inode_id {
            return Err(Error::Identity);
        }
        let maximum = if self.kind == InodeKind::Directory {
            if !self.size.is_multiple_of(DIRECTORY_SLOT_SIZE as u64) {
                return Err(Error::Range);
            }
            MAX_DIRECTORY_SIZE
        } else {
            MAX_FILE_SIZE
        };
        if self.size > maximum {
            return Err(Error::Range);
        }
        if usize::from(self.ext_count) > MAX_INDIRECT_EXTENTS
            || (self.ext_block == 0) != (self.ext_count == 0)
            || (self.ext_block != 0
                && (count != MAX_INLINE_EXTENTS
                    || inode_id >= BUSINESS_INODE_COUNT
                    || !is_business_block(self.ext_block)))
        {
            return Err(Error::Extent);
        }
        if self.extents[count..]
            .iter()
            .any(|&extent| extent != Extent::EMPTY)
        {
            return Err(Error::Reserved);
        }
        let required = self.size.div_ceil(BLOCK_SIZE as u64);
        let mut logical_end = 0_u32;
        for (index, extent) in self.extents[..count].iter().enumerate() {
            if extent.logical_start != logical_end
                || extent.block_count == 0
                || if inode_id < BUSINESS_INODE_COUNT {
                    !is_business_block(extent.physical_start)
                } else {
                    !(DATA_START..FIRST_BUSINESS_BLOCK).contains(&extent.physical_start)
                }
            {
                return Err(Error::Extent);
            }
            logical_end = logical_end
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            let physical_end = extent
                .physical_start
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            if physical_end
                > if inode_id < BUSINESS_INODE_COUNT {
                    TOTAL_BLOCKS
                } else {
                    FIRST_BUSINESS_BLOCK
                }
                || (self.ext_block != 0
                    && (extent.physical_start..physical_end).contains(&self.ext_block))
            {
                return Err(Error::Extent);
            }
            for previous in &self.extents[..index] {
                // Previous ranges already passed checked_add and disk bounds.
                let previous_end = previous.physical_start + previous.block_count;
                if extent.physical_start < previous_end && previous.physical_start < physical_end {
                    return Err(Error::Extent);
                }
            }
        }
        if (self.ext_count == 0 && u64::from(logical_end) != required)
            || (self.ext_count != 0
                && (u64::from(logical_end) >= required
                    || u64::from(logical_end) + u64::from(self.ext_count) > required))
        {
            return Err(Error::Extent);
        }
        Ok(())
    }

    pub fn encode(&self, inode_id: u32, bytes: &mut [u8]) -> Result<(), Error> {
        check_len(bytes, INODE_SIZE)?;
        self.validate(inode_id)?;
        bytes.fill(0);
        put32(bytes, 0, INODE_MAGIC);
        put16(
            bytes,
            4,
            match self.kind {
                InodeKind::Free => 0,
                InodeKind::File => 1,
                InodeKind::Directory => 2,
            },
        );
        put64(bytes, 8, self.generation);
        put64(bytes, 16, self.size);
        put64(bytes, 24, self.durable_write_seq);
        put16(bytes, 32, self.extent_count);
        put32(bytes, 36, self.parent_inode);
        put64(bytes, 40, self.parent_generation);
        for (index, extent) in self.extents.iter().enumerate() {
            let offset = 48 + index * 12;
            put32(bytes, offset, extent.logical_start);
            put32(bytes, offset + 4, extent.physical_start);
            put32(bytes, offset + 8, extent.block_count);
        }
        put32(bytes, 240, self.ext_block);
        put16(bytes, 244, self.ext_count);
        write_checksum(bytes, 252);
        Ok(())
    }

    pub fn decode(inode_id: u32, bytes: &[u8]) -> Result<Self, Error> {
        check_len(bytes, INODE_SIZE)?;
        check_checksum(bytes, 252)?;
        if u32_at(bytes, 0) != INODE_MAGIC {
            return Err(Error::Magic);
        }
        zeros(&bytes[6..8])?;
        zeros(&bytes[34..36])?;
        zeros(&bytes[246..252])?;
        let kind = match u16_at(bytes, 4) {
            0 => InodeKind::Free,
            1 => InodeKind::File,
            2 => InodeKind::Directory,
            _ => return Err(Error::InodeType),
        };
        let mut extents = [Extent::EMPTY; 16];
        for (index, extent) in extents.iter_mut().enumerate() {
            let offset = 48 + index * 12;
            *extent = Extent {
                logical_start: u32_at(bytes, offset),
                physical_start: u32_at(bytes, offset + 4),
                block_count: u32_at(bytes, offset + 8),
            };
        }
        let value = Self {
            kind,
            generation: u64_at(bytes, 8),
            size: u64_at(bytes, 16),
            durable_write_seq: u64_at(bytes, 24),
            extent_count: u16_at(bytes, 32),
            parent_inode: u32_at(bytes, 36),
            parent_generation: u64_at(bytes, 40),
            extents,
            ext_block: u32_at(bytes, 240),
            ext_count: u16_at(bytes, 244),
        };
        value.validate(inode_id)?;
        Ok(value)
    }
}

/// One immutable indirect extent page. Its identity is bound to the inode
/// generation; `validate_for` also checks the complete inline+indirect mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentBlock {
    pub inode_id: u32,
    pub inode_generation: u64,
    pub count: u16,
    pub extents: [Extent; MAX_INDIRECT_EXTENTS],
}

impl ExtentBlock {
    pub const fn empty(inode_id: u32, inode_generation: u64) -> Self {
        Self {
            inode_id,
            inode_generation,
            count: 0,
            extents: [Extent::EMPTY; MAX_INDIRECT_EXTENTS],
        }
    }

    /// Extract one entry without copying the 338-entry page into a second
    /// buffer. Call `validate_bytes_for` once before iterating a mapping; this
    /// accessor checks the exact page length and the entry/count bounds only.
    pub fn extent_from_bytes(bytes: &[u8], index: usize) -> Result<Extent, Error> {
        check_len(bytes, BLOCK_SIZE)?;
        let count = usize::from(u16_at(bytes, 12));
        if count == 0 || count > MAX_INDIRECT_EXTENTS || index >= count {
            return Err(Error::Extent);
        }
        let offset = 32 + index * 12;
        Ok(Extent {
            logical_start: u32_at(bytes, offset),
            physical_start: u32_at(bytes, offset + 4),
            block_count: u32_at(bytes, offset + 8),
        })
    }

    /// Borrowed equivalent of `decode(bytes)?.validate_for(inode_id, inode)`.
    /// It validates every byte and the complete inline+indirect mapping while
    /// using only one entry at a time, for the bounded streaming GC workspace.
    pub fn validate_bytes_for(bytes: &[u8], inode_id: u32, inode: &Inode) -> Result<(), Error> {
        check_len(bytes, BLOCK_SIZE)?;
        check_checksum(bytes, 4092)?;
        if u32_at(bytes, 0) != EXTENT_MAGIC {
            return Err(Error::Magic);
        }
        if u16_at(bytes, 4) != 2 {
            return Err(Error::Version);
        }
        if u16_at(bytes, 6) != 32 {
            return Err(Error::Layout);
        }
        zeros(&bytes[14..16])?;
        zeros(&bytes[24..32])?;
        let count = usize::from(u16_at(bytes, 12));
        if count == 0 || count > MAX_INDIRECT_EXTENTS {
            return Err(Error::Extent);
        }
        zeros(&bytes[32 + count * 12..4092])?;
        inode.validate(inode_id)?;
        if inode_id >= BUSINESS_INODE_COUNT
            || u32_at(bytes, 8) != inode_id
            || u64_at(bytes, 16) != inode.generation
            || count != usize::from(inode.ext_count)
            || inode.ext_block == 0
        {
            return Err(Error::Identity);
        }
        let last = inode.extents[MAX_INLINE_EXTENTS - 1];
        let mut logical_end = last.logical_start + last.block_count;
        for index in 0..count {
            let extent = Self::extent_from_bytes(bytes, index)?;
            if extent.logical_start != logical_end
                || extent.block_count == 0
                || !is_business_block(extent.physical_start)
            {
                return Err(Error::Extent);
            }
            logical_end = logical_end
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            let end = extent
                .physical_start
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            if end > TOTAL_BLOCKS
                || (extent.physical_start..end).contains(&inode.ext_block)
                || inode.extents.iter().any(|inline| {
                    extent.physical_start < inline.physical_start + inline.block_count
                        && inline.physical_start < end
                })
            {
                return Err(Error::Extent);
            }
            for previous in 0..index {
                let previous = Self::extent_from_bytes(bytes, previous)?;
                if extent.physical_start < previous.physical_start + previous.block_count
                    && previous.physical_start < end
                {
                    return Err(Error::Extent);
                }
            }
        }
        if u64::from(logical_end) != inode.size.div_ceil(BLOCK_SIZE as u64) {
            return Err(Error::Extent);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.inode_id >= BUSINESS_INODE_COUNT || self.inode_generation == 0 {
            return Err(Error::Identity);
        }
        let count = usize::from(self.count);
        if count == 0 || count > MAX_INDIRECT_EXTENTS {
            return Err(Error::Extent);
        }
        if self.extents[count..]
            .iter()
            .any(|extent| *extent != Extent::EMPTY)
        {
            return Err(Error::Reserved);
        }
        let mut logical_end = self.extents[0].logical_start;
        if logical_end < MAX_INLINE_EXTENTS as u32 {
            return Err(Error::Extent);
        }
        for (index, extent) in self.extents[..count].iter().enumerate() {
            if extent.logical_start != logical_end
                || extent.block_count == 0
                || !is_business_block(extent.physical_start)
            {
                return Err(Error::Extent);
            }
            logical_end = logical_end
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            let end = extent
                .physical_start
                .checked_add(extent.block_count)
                .ok_or(Error::Extent)?;
            if end > TOTAL_BLOCKS || u64::from(logical_end) > MAX_FILE_SIZE / BLOCK_SIZE as u64 {
                return Err(Error::Extent);
            }
            if self.extents[..index].iter().any(|previous| {
                extent.physical_start < previous.physical_start + previous.block_count
                    && previous.physical_start < end
            }) {
                return Err(Error::Extent);
            }
        }
        Ok(())
    }

    pub fn validate_for(&self, inode_id: u32, inode: &Inode) -> Result<(), Error> {
        self.validate()?;
        inode.validate(inode_id)?;
        if self.inode_id != inode_id
            || self.inode_generation != inode.generation
            || self.count != inode.ext_count
            || inode.ext_block == 0
        {
            return Err(Error::Identity);
        }
        let inline_last = inode.extents[MAX_INLINE_EXTENTS - 1];
        if self.extents[0].logical_start != inline_last.logical_start + inline_last.block_count {
            return Err(Error::Extent);
        }
        let last = self.extents[usize::from(self.count) - 1];
        if u64::from(last.logical_start + last.block_count)
            != inode.size.div_ceil(BLOCK_SIZE as u64)
        {
            return Err(Error::Extent);
        }
        for extent in &self.extents[..usize::from(self.count)] {
            let end = extent.physical_start + extent.block_count;
            if (extent.physical_start..end).contains(&inode.ext_block)
                || inode.extents.iter().any(|inline| {
                    extent.physical_start < inline.physical_start + inline.block_count
                        && inline.physical_start < end
                })
            {
                return Err(Error::Extent);
            }
        }
        Ok(())
    }

    pub fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        check_len(bytes, BLOCK_SIZE)?;
        self.validate()?;
        bytes.fill(0);
        put32(bytes, 0, EXTENT_MAGIC);
        put16(bytes, 4, 2);
        put16(bytes, 6, 32);
        put32(bytes, 8, self.inode_id);
        put16(bytes, 12, self.count);
        put64(bytes, 16, self.inode_generation);
        for (index, extent) in self.extents[..usize::from(self.count)].iter().enumerate() {
            let offset = 32 + index * 12;
            put32(bytes, offset, extent.logical_start);
            put32(bytes, offset + 4, extent.physical_start);
            put32(bytes, offset + 8, extent.block_count);
        }
        write_checksum(bytes, 4092);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        check_len(bytes, BLOCK_SIZE)?;
        check_checksum(bytes, 4092)?;
        if u32_at(bytes, 0) != EXTENT_MAGIC {
            return Err(Error::Magic);
        }
        if u16_at(bytes, 4) != 2 {
            return Err(Error::Version);
        }
        if u16_at(bytes, 6) != 32 {
            return Err(Error::Layout);
        }
        zeros(&bytes[14..16])?;
        zeros(&bytes[24..32])?;
        let count = u16_at(bytes, 12);
        if usize::from(count) > MAX_INDIRECT_EXTENTS {
            return Err(Error::Extent);
        }
        zeros(&bytes[32 + usize::from(count) * 12..4092])?;
        let mut value = Self::empty(u32_at(bytes, 8), u64_at(bytes, 16));
        value.count = count;
        for (index, extent) in value.extents[..usize::from(count)].iter_mut().enumerate() {
            let offset = 32 + index * 12;
            *extent = Extent {
                logical_start: u32_at(bytes, offset),
                physical_start: u32_at(bytes, offset + 4),
                block_count: u32_at(bytes, offset + 8),
            };
        }
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry<'a> {
    pub inode_id: u32,
    pub inode_generation: u64,
    pub name: &'a str,
}

impl<'a> DirectoryEntry<'a> {
    pub const EMPTY: Self = Self {
        inode_id: u32::MAX,
        inode_generation: 0,
        name: "",
    };

    fn validate(&self) -> Result<(), Error> {
        if self.inode_id == u32::MAX {
            return if *self == Self::EMPTY {
                Ok(())
            } else {
                Err(Error::Layout)
            };
        }
        if self.inode_id >= INODE_COUNT || self.inode_generation == 0 {
            return Err(Error::Identity);
        }
        if self.name.is_empty()
            || self.name.len() > 63
            || self.name == "."
            || self.name == ".."
            || self
                .name
                .as_bytes()
                .iter()
                .any(|&byte| byte == 0 || byte == b'/')
        {
            return Err(Error::Name);
        }
        Ok(())
    }

    pub fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        check_len(bytes, DIRECTORY_SLOT_SIZE)?;
        self.validate()?;
        bytes.fill(0);
        put32(bytes, 0, self.inode_id);
        put16(bytes, 4, self.name.len() as u16);
        put64(bytes, 8, self.inode_generation);
        bytes[16..16 + self.name.len()].copy_from_slice(self.name.as_bytes());
        write_checksum(bytes, 124);
        Ok(())
    }

    /// The name borrows the record's exact UTF-8 bytes; no normalization or
    /// case folding is performed. Duplicate names and referenced inode state
    /// must be checked by the filesystem-wide validator.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        check_len(bytes, DIRECTORY_SLOT_SIZE)?;
        check_checksum(bytes, 124)?;
        zeros(&bytes[6..8])?;
        let length = usize::from(u16_at(bytes, 4));
        if length > 63 {
            return Err(Error::Name);
        }
        zeros(&bytes[16 + length..124])?;
        let name = core::str::from_utf8(&bytes[16..16 + length]).map_err(|_| Error::Name)?;
        let value = Self {
            inode_id: u32_at(bytes, 0),
            inode_generation: u64_at(bytes, 8),
            name,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogPayload<'a> {
    Begin {
        redo_count: u32,
    },
    Redo {
        home_block: u64,
        index: u32,
        count: u32,
        after_image: &'a [u8],
    },
    Commit {
        begin_lsn: u64,
        last_redo_lsn: u64,
        redo_count: u32,
        ordered_digest: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub txid: u64,
    pub lsn: u64,
    pub log_epoch: u64,
    pub payload: LogPayload<'a>,
}

fn check_count(count: u32) -> Result<(), Error> {
    if !(1..=MAX_REDOS).contains(&count) {
        Err(Error::Payload)
    } else {
        Ok(())
    }
}

impl<'a> Record<'a> {
    fn validate(&self) -> Result<(), Error> {
        if self.txid == 0 || self.lsn == 0 || self.log_epoch == 0 {
            return Err(Error::Counter);
        }
        match self.payload {
            LogPayload::Begin { redo_count } => {
                check_count(redo_count)?;
                self.lsn
                    .checked_add(u64::from(redo_count) + 1)
                    .ok_or(Error::Counter)?;
            }
            LogPayload::Redo {
                home_block,
                index,
                count,
                after_image,
            } => {
                check_count(count)?;
                if index >= count
                    || !(u64::from(BITMAP_START)..u64::from(FIRST_BUSINESS_BLOCK))
                        .contains(&home_block)
                {
                    return Err(Error::Range);
                }
                check_len(after_image, BLOCK_SIZE)?;
                let begin = self
                    .lsn
                    .checked_sub(u64::from(index) + 1)
                    .ok_or(Error::Counter)?;
                if begin == 0 {
                    return Err(Error::Counter);
                }
                begin
                    .checked_add(u64::from(count) + 1)
                    .ok_or(Error::Counter)?;
            }
            LogPayload::Commit {
                begin_lsn,
                last_redo_lsn,
                redo_count,
                ..
            } => {
                check_count(redo_count)?;
                if begin_lsn == 0
                    || begin_lsn.checked_add(u64::from(redo_count)) != Some(last_redo_lsn)
                    || last_redo_lsn.checked_add(1) != Some(self.lsn)
                {
                    return Err(Error::Counter);
                }
            }
        }
        Ok(())
    }

    /// Includes mandatory zero alignment padding. This does not validate fields.
    pub const fn encoded_len(&self) -> usize {
        match self.payload {
            LogPayload::Redo { .. } => 2 * BLOCK_SIZE,
            _ => BLOCK_SIZE,
        }
    }

    pub fn encode(&self, bytes: &mut [u8]) -> Result<(), Error> {
        check_len(bytes, self.encoded_len())?;
        self.validate()?;
        bytes.fill(0);
        put32(bytes, 0, LOG_MAGIC);
        put16(bytes, 4, 1);
        put64(bytes, 16, self.txid);
        put64(bytes, 24, self.lsn);
        put64(bytes, 32, self.log_epoch);
        let length = match self.payload {
            LogPayload::Begin { redo_count } => {
                put16(bytes, 6, 1);
                put32(bytes, 64, redo_count);
                put64(bytes, 72, u64::from(redo_count) * BLOCK_SIZE as u64);
                80
            }
            LogPayload::Redo {
                home_block,
                index,
                count,
                after_image,
            } => {
                put16(bytes, 6, 2);
                put64(bytes, 40, home_block);
                put32(bytes, 48, index);
                put32(bytes, 52, count);
                bytes[64..64 + BLOCK_SIZE].copy_from_slice(after_image);
                64 + BLOCK_SIZE
            }
            LogPayload::Commit {
                begin_lsn,
                last_redo_lsn,
                redo_count,
                ordered_digest,
            } => {
                put16(bytes, 6, 3);
                put64(bytes, 64, self.txid);
                put64(bytes, 72, begin_lsn);
                put64(bytes, 80, last_redo_lsn);
                put32(bytes, 88, redo_count);
                bytes[96..128].copy_from_slice(&ordered_digest);
                128
            }
        };
        put32(bytes, 8, length as u32);
        let crc = crc32c(&bytes[64..length]);
        put32(bytes, 12, crc);
        write_checksum(&mut bytes[..LOG_HEADER_SIZE], 56);
        Ok(())
    }

    /// Decode exactly one padded record, borrowing a REDO image in place.
    /// A journal scanner must independently check epoch/txid/LSN continuity,
    /// distinct home blocks, count agreement across records and ordered digest.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != BLOCK_SIZE && bytes.len() != 2 * BLOCK_SIZE {
            return Err(Error::Length);
        }
        check_checksum(&bytes[..LOG_HEADER_SIZE], 56)?;
        if u32_at(bytes, 0) != LOG_MAGIC {
            return Err(Error::Magic);
        }
        if u16_at(bytes, 4) != 1 {
            return Err(Error::Version);
        }
        zeros(&bytes[60..64])?;
        let kind = u16_at(bytes, 6);
        let (length, padded) = match kind {
            1 => (80, BLOCK_SIZE),
            2 => (64 + BLOCK_SIZE, 2 * BLOCK_SIZE),
            3 => (128, BLOCK_SIZE),
            _ => return Err(Error::LogType),
        };
        if bytes.len() != padded || u32_at(bytes, 8) != length as u32 {
            return Err(Error::Length);
        }
        if u32_at(bytes, 12) != crc32c(&bytes[64..length]) {
            return Err(Error::Checksum);
        }
        zeros(&bytes[length..])?;
        let txid = u64_at(bytes, 16);
        if kind != 2 {
            zeros(&bytes[40..56])?;
        }
        let payload = match kind {
            1 => {
                zeros(&bytes[68..72])?;
                let redo_count = u32_at(bytes, 64);
                if u64_at(bytes, 72) != u64::from(redo_count) * BLOCK_SIZE as u64 {
                    return Err(Error::Payload);
                }
                LogPayload::Begin { redo_count }
            }
            2 => LogPayload::Redo {
                home_block: u64_at(bytes, 40),
                index: u32_at(bytes, 48),
                count: u32_at(bytes, 52),
                after_image: &bytes[64..64 + BLOCK_SIZE],
            },
            _ => {
                if u64_at(bytes, 64) != txid {
                    return Err(Error::Identity);
                }
                zeros(&bytes[92..96])?;
                let mut ordered_digest = [0; 32];
                ordered_digest.copy_from_slice(&bytes[96..128]);
                LogPayload::Commit {
                    begin_lsn: u64_at(bytes, 72),
                    last_redo_lsn: u64_at(bytes, 80),
                    redo_count: u32_at(bytes, 88),
                    ordered_digest,
                }
            }
        };
        let value = Self {
            txid,
            lsn: u64_at(bytes, 24),
            log_epoch: u64_at(bytes, 32),
            payload,
        };
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod checksum_tests {
    use super::{checksum, crc32c};

    fn bitwise_reference(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for &byte in bytes {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0x82f6_3b78
                };
            }
        }
        !crc
    }

    #[test]
    fn table_crc_matches_independent_bitwise_golden_and_page_lengths() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b""), 0);
        let bytes: [u8; 8192] = core::array::from_fn(|i| (i.wrapping_mul(131) ^ (i >> 3)) as u8);
        for length in (0..=512).chain([1023, 1024, 1025, 4095, 4096, 4097, 8191, 8192]) {
            assert_eq!(
                crc32c(&bytes[..length]),
                bitwise_reference(&bytes[..length])
            );
        }
    }

    #[test]
    fn zeroed_checksum_field_matches_independent_bitwise_crc() {
        let bytes: [u8; 8192] = core::array::from_fn(|i| (i.wrapping_mul(73) ^ (i >> 5)) as u8);
        let mut zeroed = bytes;
        for length in [4, 16, 64, 128, 256, 512, 4096, 8192] {
            for offset in [0, (length - 4) / 2, length - 4] {
                zeroed[..length].copy_from_slice(&bytes[..length]);
                zeroed[offset..offset + 4].fill(0);
                assert_eq!(
                    checksum(&bytes[..length], offset),
                    bitwise_reference(&zeroed[..length])
                );
            }
        }
    }
}
