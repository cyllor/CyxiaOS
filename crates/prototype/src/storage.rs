//! Fixed disk-format codecs for the v1.3 functional profile, sections 9.2–9.2.1.
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
pub const DATA_START: u32 = 4118;
pub const INODE_COUNT: u32 = 256;
pub const INODE_SIZE: usize = 256;
pub const DIRECTORY_SLOT_SIZE: usize = 128;
pub const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;
pub const MAX_DIRECTORY_SIZE: u64 = 256 * DIRECTORY_SLOT_SIZE as u64;
pub const MAX_REDOS: u32 = 128;
pub const LOG_HEADER_SIZE: usize = 64;
const SUPERBLOCK_MAGIC: u32 = 0x4359_4653;
const INODE_MAGIC: u32 = 0x4359_494e;
const LOG_MAGIC: u32 = 0x4359_4c47;

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

fn crc_byte(mut crc: u32, byte: u8) -> u32 {
    crc ^= u32::from(byte);
    for _ in 0..8 {
        crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
    }
    crc
}

/// Reflected CRC32C (Castagnoli), with initial and final XOR of 0xffffffff.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = crc_byte(crc, byte);
    }
    !crc
}

fn checksum(bytes: &[u8], offset: usize) -> u32 {
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
        put16(bytes, 4, 1);
        put16(bytes, 6, 80);
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
        write_checksum(bytes, 76);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        check_len(bytes, BLOCK_SIZE)?;
        check_checksum(bytes, 76)?;
        if u32_at(bytes, 0) != SUPERBLOCK_MAGIC {
            return Err(Error::Magic);
        }
        if u16_at(bytes, 4) != 1 {
            return Err(Error::Version);
        }
        if u16_at(bytes, 6) != 80
            || u32_at(bytes, 8) != BLOCK_SIZE as u32
            || u32_at(bytes, 12) != TOTAL_BLOCKS
            || u32_at(bytes, 56) != BITMAP_START
            || u32_at(bytes, 60) != INODE_START
            || u32_at(bytes, 64) != DATA_START
            || u32_at(bytes, 68) != INODE_COUNT
            || u32_at(bytes, 72) != 0
        {
            return Err(Error::Layout);
        }
        zeros(&bytes[80..])?;
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
                || self.size != 0
                || self.durable_write_seq != 0
                || count != 0
                || self.parent_inode != 0
                || self.parent_generation != 0
                || self.extents != [Extent::EMPTY; 16]
            {
                return Err(Error::Layout);
            }
            return Ok(());
        }
        if self.parent_inode >= INODE_COUNT || self.parent_generation == 0 {
            return Err(Error::Identity);
        }
        if inode_id == 0 {
            if self.kind != InodeKind::Directory
                || self.generation != 1
                || self.parent_inode != 0
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
                || extent.physical_start < DATA_START
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
            if physical_end > TOTAL_BLOCKS {
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
        if u64::from(logical_end) != required {
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
        zeros(&bytes[240..252])?;
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
        };
        value.validate(inode_id)?;
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
                    || !(u64::from(BITMAP_START)..u64::from(TOTAL_BLOCKS)).contains(&home_block)
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
