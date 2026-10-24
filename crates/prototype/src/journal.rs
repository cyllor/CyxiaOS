//! Bounded, synchronous redo journal for the v1.3 512 MiB disk format.
//!
//! The caller serializes this service and supplies the 8 KiB scratch buffer.
//! A successful write is only a device completion; only `flush` establishes
//! durability. Every I/O error poisons the instance because a failed operation
//! may have reached media. Remount scans disk evidence, never a saved flush flag.
//! Filesystem-wide inode/bitmap ownership checks belong to the file service.

use crate::storage::{
    self, BITMAP_START, BLOCK_SIZE, DATA_START, Extent, INODE_COUNT, INODE_SIZE, INODE_START,
    Inode, InodeKind, LogPayload, MAX_REDOS, Record, Superblock, TOTAL_BLOCKS,
};
use sha2::{Digest, Sha256};

pub type Scratch = [u8; 2 * BLOCK_SIZE];
const LOG_START: u32 = 2;
const LOG_END: u32 = BITMAP_START;
const INDEX_CAPACITY: usize = 2048;

/// Implementations must reject unnegotiated/unsupported flush, wait for each
/// completion, and retain in-flight DMA ownership after uncertain errors.
pub trait BlockDevice {
    type Error;
    fn block_count(&self) -> u32;
    fn read_block(&mut self, block: u32, output: &mut [u8; BLOCK_SIZE]) -> Result<(), Self::Error>;
    fn write_block(&mut self, block: u32, bytes: &[u8; BLOCK_SIZE]) -> Result<(), Self::Error>;
    fn flush(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    Format(storage::Error),
    WrongCapacity,
    NotBlank,
    Invalid,
    Corrupt,
    NoSpace,
    Counter,
    Poisoned,
}

#[derive(Clone, Copy, Debug)]
pub struct AfterImage<'a> {
    pub home_block: u32,
    pub bytes: &'a [u8; BLOCK_SIZE],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionKey {
    pub fs_uuid: [u8; 16],
    pub log_epoch: u64,
    pub txid: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    pub key: TransactionKey,
    pub commit_lsn: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub committed_transactions: u32,
    pub replayed_blocks: u32,
    pub discarded_tail: bool,
    pub checkpoint: Superblock,
}

#[derive(Clone, Copy)]
struct IndexEntry {
    home: u32,
    record: u32,
}
impl IndexEntry {
    const EMPTY: Self = Self { home: 0, record: 0 };
}

/// At most 2048 REDOs fit in the finite log, hence this fixed index is sufficient
/// even if every committed REDO targets a different home block. Mutable access
/// is the single-writer publication boundary: readers cannot observe half a commit.
pub struct Journal {
    superblock: Superblock,
    active_superblock: u32,
    next_block: u32,
    next_lsn: u64,
    next_txid: u64,
    last_commit_lsn: u64,
    entries: [IndexEntry; INDEX_CAPACITY],
    used: usize,
    writable: bool,
}

impl Default for Journal {
    fn default() -> Self {
        Self::new()
    }
}

impl Journal {
    /// Constant initializer suitable for caller-owned static memory.
    pub const fn new() -> Self {
        Self {
            superblock: Superblock {
                fs_uuid: [0; 16],
                generation: 0,
                checkpoint_lsn: 0,
                log_epoch: 0,
            },
            active_superblock: 0,
            next_block: LOG_START,
            next_lsn: 1,
            next_txid: 1,
            last_commit_lsn: 0,
            entries: [IndexEntry::EMPTY; INDEX_CAPACITY],
            used: 0,
            writable: false,
        }
    }
    pub fn superblock(&self) -> Superblock {
        self.superblock
    }
    pub fn last_commit_lsn(&self) -> u64 {
        self.last_commit_lsn
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    pub fn remaining_log_blocks(&self) -> u32 {
        LOG_END - self.next_block
    }

    /// Recovery first validates the complete accepted prefix, then writes each
    /// latest home image once. It always starts a fresh durable epoch before
    /// admitting a new transaction, including an empty-log mount.
    pub fn mount<D: BlockDevice>(
        &mut self,
        device: &mut D,
        scratch: &mut Scratch,
    ) -> Result<Recovery, Error<D::Error>> {
        self.writable = false;
        self.used = 0;
        if device.block_count() != TOTAL_BLOCKS {
            return Err(Error::WrongCapacity);
        }
        read_half(device, 0, scratch, 0)?;
        read_half(device, 1, scratch, 1)?;
        let selected = storage::select_superblock(&scratch[..BLOCK_SIZE], &scratch[BLOCK_SIZE..])
            .map_err(Error::Format)?;
        self.active_superblock = if Superblock::decode(&scratch[..BLOCK_SIZE]) == Ok(selected) {
            0
        } else {
            1
        };
        self.superblock = selected;
        self.last_commit_lsn = selected.checkpoint_lsn;
        self.next_block = LOG_START;
        self.next_lsn = selected
            .checkpoint_lsn
            .checked_add(1)
            .ok_or(Error::Counter)?;
        self.next_txid = 1;
        let mut transactions = 0;
        let mut discarded_tail = false;
        let mut previous_txid = 0;
        while self.next_block < LOG_END {
            let begin_block = self.next_block;
            let begin_lsn = self.next_lsn;
            let length = read_record(device, begin_block, scratch)?;
            let record = Record::decode(&scratch[..length]);
            let (txid, count) = match record {
                Ok(Record {
                    txid,
                    lsn,
                    log_epoch,
                    payload: LogPayload::Begin { redo_count },
                }) if lsn == begin_lsn
                    && log_epoch == selected.log_epoch
                    && txid > previous_txid =>
                {
                    (txid, redo_count)
                }
                _ => {
                    discarded_tail = tail_present(&scratch[..BLOCK_SIZE], selected.log_epoch);
                    reject_later_commit(
                        device,
                        begin_block,
                        selected.log_epoch,
                        begin_lsn,
                        scratch,
                    )?;
                    break;
                }
            };
            let commit_lsn = begin_lsn
                .checked_add(u64::from(count) + 1)
                .ok_or(Error::Counter)?;
            let mut pending = [IndexEntry::EMPTY; MAX_REDOS as usize];
            let mut digest = Sha256::new();
            let mut cursor = begin_block + 1;
            let mut valid = true;
            for index in 0..count {
                if cursor >= LOG_END {
                    valid = false;
                    break;
                }
                let length = read_record(device, cursor, scratch)?;
                match Record::decode(&scratch[..length]) {
                    Ok(Record {
                        txid: found_txid,
                        lsn,
                        log_epoch,
                        payload:
                            LogPayload::Redo {
                                home_block,
                                index: found_index,
                                count: found_count,
                                after_image,
                            },
                    }) if found_txid == txid
                        && lsn == begin_lsn + u64::from(index) + 1
                        && log_epoch == selected.log_epoch
                        && found_index == index
                        && found_count == count
                        && !pending[..index as usize]
                            .iter()
                            .any(|entry| u64::from(entry.home) == home_block) =>
                    {
                        pending[index as usize] = IndexEntry {
                            home: home_block as u32,
                            record: cursor,
                        };
                        digest.update(home_block.to_le_bytes());
                        digest.update(after_image);
                    }
                    _ => {
                        valid = false;
                        break;
                    }
                }
                cursor += 2;
            }
            if valid && cursor < LOG_END {
                let length = read_record(device, cursor, scratch)?;
                let expected: [u8; 32] = digest.finalize().into();
                valid = matches!(Record::decode(&scratch[..length]), Ok(Record { txid: found_txid, lsn, log_epoch,
                    payload: LogPayload::Commit { begin_lsn: found_begin, last_redo_lsn, redo_count, ordered_digest } })
                    if found_txid == txid && lsn == commit_lsn && log_epoch == selected.log_epoch && found_begin == begin_lsn
                    && last_redo_lsn == commit_lsn - 1 && redo_count == count && ordered_digest == expected);
            } else {
                valid = false;
            }
            if !valid {
                discarded_tail = true;
                reject_later_commit(device, begin_block, selected.log_epoch, begin_lsn, scratch)?;
                break;
            }
            for entry in &pending[..count as usize] {
                self.publish(*entry)?;
            }
            transactions += 1;
            previous_txid = txid;
            self.last_commit_lsn = commit_lsn;
            self.next_lsn = commit_lsn.checked_add(1).ok_or(Error::Counter)?;
            self.next_block = cursor + 1;
        }
        let replayed_blocks = self.used as u32;
        // checkpoint_inner does not require writable: recovery is the only
        // operation allowed to reach this stage from an unopened instance.
        self.checkpoint_inner(device, scratch)?;
        self.writable = true;
        Ok(Recovery {
            committed_transactions: transactions,
            replayed_blocks,
            discarded_tail,
            checkpoint: self.superblock,
        })
    }

    pub fn commit<D: BlockDevice>(
        &mut self,
        device: &mut D,
        changes: &[AfterImage<'_>],
        scratch: &mut Scratch,
    ) -> Result<CommitReceipt, Error<D::Error>> {
        if !self.writable {
            return Err(Error::Poisoned);
        }
        if changes.is_empty() || changes.len() > MAX_REDOS as usize {
            return Err(Error::Invalid);
        }
        for (index, change) in changes.iter().enumerate() {
            if !(BITMAP_START..TOTAL_BLOCKS).contains(&change.home_block)
                || changes[..index]
                    .iter()
                    .any(|previous| previous.home_block == change.home_block)
            {
                return Err(Error::Invalid);
            }
        }
        let needed = 2 + 2 * changes.len() as u32;
        if needed > self.remaining_log_blocks() {
            return Err(Error::NoSpace);
        }
        let additions = changes
            .iter()
            .filter(|change| {
                !self.entries[..self.used]
                    .iter()
                    .any(|entry| entry.home == change.home_block)
            })
            .count();
        if self.used + additions > INDEX_CAPACITY {
            return Err(Error::NoSpace);
        }
        let count = changes.len() as u32;
        let commit_lsn = self
            .next_lsn
            .checked_add(u64::from(count) + 1)
            .ok_or(Error::Counter)?;
        let after_lsn = commit_lsn.checked_add(1).ok_or(Error::Counter)?;
        let after_txid = self.next_txid.checked_add(1).ok_or(Error::Counter)?;
        // Do not start a transaction that cannot later checkpoint and advance
        // to another epoch; counter exhaustion is a pre-I/O rejection.
        self.superblock
            .generation
            .checked_add(1)
            .ok_or(Error::Counter)?;
        self.superblock
            .log_epoch
            .checked_add(1)
            .ok_or(Error::Counter)?;
        let key = TransactionKey {
            fs_uuid: self.superblock.fs_uuid,
            log_epoch: self.superblock.log_epoch,
            txid: self.next_txid,
        };
        self.writable = false;
        let mut cursor = self.next_block;
        write_record(
            device,
            cursor,
            Record {
                txid: key.txid,
                lsn: self.next_lsn,
                log_epoch: key.log_epoch,
                payload: LogPayload::Begin { redo_count: count },
            },
            scratch,
        )?;
        cursor += 1;
        let mut digest = Sha256::new();
        for (index, change) in changes.iter().enumerate() {
            digest.update(u64::from(change.home_block).to_le_bytes());
            digest.update(change.bytes);
            write_record(
                device,
                cursor,
                Record {
                    txid: key.txid,
                    lsn: self.next_lsn + index as u64 + 1,
                    log_epoch: key.log_epoch,
                    payload: LogPayload::Redo {
                        home_block: u64::from(change.home_block),
                        index: index as u32,
                        count,
                        after_image: change.bytes,
                    },
                },
                scratch,
            )?;
            cursor += 2;
        }
        device.flush().map_err(Error::Io)?;
        write_record(
            device,
            cursor,
            Record {
                txid: key.txid,
                lsn: commit_lsn,
                log_epoch: key.log_epoch,
                payload: LogPayload::Commit {
                    begin_lsn: self.next_lsn,
                    last_redo_lsn: commit_lsn - 1,
                    redo_count: count,
                    ordered_digest: digest.finalize().into(),
                },
            },
            scratch,
        )?;
        device.flush().map_err(Error::Io)?;
        // All possible bounds/counter failures were rejected before BEGIN.
        for (index, change) in changes.iter().enumerate() {
            self.publish(IndexEntry {
                home: change.home_block,
                record: self.next_block + 1 + 2 * index as u32,
            })?;
        }
        self.next_block = cursor + 1;
        self.next_lsn = after_lsn;
        self.next_txid = after_txid;
        self.last_commit_lsn = commit_lsn;
        self.writable = true;
        Ok(CommitReceipt { key, commit_lsn })
    }

    /// Read the newest committed image, including data not yet checkpointed.
    pub fn read_block<D: BlockDevice>(
        &mut self,
        device: &mut D,
        home: u32,
        output: &mut [u8; BLOCK_SIZE],
        scratch: &mut Scratch,
    ) -> Result<(), Error<D::Error>> {
        if !self.writable {
            return Err(Error::Poisoned);
        }
        if !(BITMAP_START..TOTAL_BLOCKS).contains(&home) {
            return Err(Error::Invalid);
        }
        let result = if let Some(entry) = self.entries[..self.used]
            .iter()
            .find(|entry| entry.home == home)
        {
            read_image(device, *entry, self.superblock.log_epoch, output, scratch)
        } else {
            device.read_block(home, output).map_err(Error::Io)
        };
        if result.is_err() {
            self.writable = false;
        }
        result
    }

    pub fn checkpoint<D: BlockDevice>(
        &mut self,
        device: &mut D,
        scratch: &mut Scratch,
    ) -> Result<Superblock, Error<D::Error>> {
        if !self.writable {
            return Err(Error::Poisoned);
        }
        self.writable = false;
        self.checkpoint_inner(device, scratch)?;
        self.writable = true;
        Ok(self.superblock)
    }

    fn checkpoint_inner<D: BlockDevice>(
        &mut self,
        device: &mut D,
        scratch: &mut Scratch,
    ) -> Result<(), Error<D::Error>> {
        let next = Superblock {
            fs_uuid: self.superblock.fs_uuid,
            generation: self
                .superblock
                .generation
                .checked_add(1)
                .ok_or(Error::Counter)?,
            checkpoint_lsn: self.last_commit_lsn,
            log_epoch: self
                .superblock
                .log_epoch
                .checked_add(1)
                .ok_or(Error::Counter)?,
        };
        let next_lsn = next.checkpoint_lsn.checked_add(1).ok_or(Error::Counter)?;
        // Buffer re-use avoids a separate 4 KiB stack array: REDO's image is
        // moved to the first half after validation, then written as a home block.
        for entry in &self.entries[..self.used] {
            let length = read_record(device, entry.record, scratch)?;
            match Record::decode(&scratch[..length]) {
                Ok(Record {
                    log_epoch,
                    payload: LogPayload::Redo { home_block, .. },
                    ..
                }) if log_epoch == self.superblock.log_epoch
                    && home_block == u64::from(entry.home) => {}
                _ => return Err(Error::Corrupt),
            }
            scratch.copy_within(64..64 + BLOCK_SIZE, 0);
            write_half(device, entry.home, scratch, 0)?;
        }
        device.flush().map_err(Error::Io)?;
        next.encode(&mut scratch[..BLOCK_SIZE])
            .map_err(Error::Format)?;
        let inactive = 1 - self.active_superblock;
        write_half(device, inactive, scratch, 0)?;
        device.flush().map_err(Error::Io)?;
        self.superblock = next;
        self.active_superblock = inactive;
        self.used = 0;
        self.next_block = LOG_START;
        self.next_lsn = next_lsn;
        self.next_txid = 1;
        Ok(())
    }

    fn publish<E>(&mut self, entry: IndexEntry) -> Result<(), Error<E>> {
        if let Some(found) = self.entries[..self.used]
            .iter_mut()
            .find(|found| found.home == entry.home)
        {
            *found = entry;
        } else {
            if self.used == INDEX_CAPACITY {
                return Err(Error::NoSpace);
            }
            self.entries[self.used] = entry;
            self.used += 1;
        }
        Ok(())
    }
}

/// Format only a fully zero, exactly 512 MiB device. An interrupted format must
/// be handled as an invalid image; this function never erases existing content.
/// The empty root directory uses no data extents. Free slots have valid CRCs.
pub fn format<D: BlockDevice>(
    device: &mut D,
    fs_uuid: [u8; 16],
    scratch: &mut Scratch,
) -> Result<Superblock, Error<D::Error>> {
    if device.block_count() != TOTAL_BLOCKS {
        return Err(Error::WrongCapacity);
    }
    let superblock = Superblock {
        fs_uuid,
        generation: 1,
        checkpoint_lsn: 0,
        log_epoch: 1,
    };
    superblock
        .encode(&mut scratch[..BLOCK_SIZE])
        .map_err(Error::Format)?;
    for block in 0..TOTAL_BLOCKS {
        read_half(device, block, scratch, 0)?;
        if scratch[..BLOCK_SIZE].iter().any(|&byte| byte != 0) {
            return Err(Error::NotBlank);
        }
    }
    for bitmap in 0..4_u32 {
        scratch[..BLOCK_SIZE].fill(0);
        for (byte, value) in scratch[..BLOCK_SIZE].iter_mut().enumerate() {
            let first_block = bitmap * (BLOCK_SIZE as u32 * 8) + byte as u32 * 8;
            for bit in 0..8 {
                if first_block + bit < DATA_START {
                    *value |= 1 << bit;
                }
            }
        }
        write_half(device, BITMAP_START + bitmap, scratch, 0)?;
    }
    let free = Inode {
        kind: InodeKind::Free,
        generation: 1,
        size: 0,
        durable_write_seq: 0,
        extent_count: 0,
        parent_inode: 0,
        parent_generation: 0,
        extents: [Extent::EMPTY; 16],
    };
    for block in 0..16_u32 {
        scratch[..BLOCK_SIZE].fill(0);
        for slot in 0..16_u32 {
            let id = block * 16 + slot;
            let inode = if id == 0 {
                Inode {
                    kind: InodeKind::Directory,
                    parent_generation: 1,
                    ..free
                }
            } else {
                free
            };
            let offset = slot as usize * INODE_SIZE;
            inode
                .encode(id, &mut scratch[offset..offset + INODE_SIZE])
                .map_err(Error::Format)?;
        }
        write_half(device, INODE_START + block, scratch, 0)?;
    }
    debug_assert_eq!(INODE_COUNT, 256);
    device.flush().map_err(Error::Io)?;
    scratch[..BLOCK_SIZE].fill(0);
    for block in LOG_START..LOG_END {
        write_half(device, block, scratch, 0)?;
    }
    device.flush().map_err(Error::Io)?;
    superblock
        .encode(&mut scratch[..BLOCK_SIZE])
        .map_err(Error::Format)?;
    // Publish independently so either copy is a valid recovery base after a cut.
    write_half(device, 0, scratch, 0)?;
    device.flush().map_err(Error::Io)?;
    write_half(device, 1, scratch, 0)?;
    device.flush().map_err(Error::Io)?;
    Ok(superblock)
}

fn read_half<D: BlockDevice>(
    device: &mut D,
    block: u32,
    scratch: &mut Scratch,
    half: usize,
) -> Result<(), Error<D::Error>> {
    let bytes = (&mut scratch[half * BLOCK_SIZE..(half + 1) * BLOCK_SIZE])
        .try_into()
        .map_err(|_| Error::Invalid)?;
    device.read_block(block, bytes).map_err(Error::Io)
}
fn write_half<D: BlockDevice>(
    device: &mut D,
    block: u32,
    scratch: &Scratch,
    half: usize,
) -> Result<(), Error<D::Error>> {
    let bytes = (&scratch[half * BLOCK_SIZE..(half + 1) * BLOCK_SIZE])
        .try_into()
        .map_err(|_| Error::Invalid)?;
    device.write_block(block, bytes).map_err(Error::Io)
}
fn read_record<D: BlockDevice>(
    device: &mut D,
    block: u32,
    scratch: &mut Scratch,
) -> Result<usize, Error<D::Error>> {
    read_half(device, block, scratch, 0)?;
    if scratch[6..8] == 2_u16.to_le_bytes() && block + 1 < LOG_END {
        read_half(device, block + 1, scratch, 1)?;
        Ok(2 * BLOCK_SIZE)
    } else {
        Ok(BLOCK_SIZE)
    }
}
fn write_record<D: BlockDevice>(
    device: &mut D,
    block: u32,
    record: Record<'_>,
    scratch: &mut Scratch,
) -> Result<(), Error<D::Error>> {
    let length = record.encoded_len();
    record
        .encode(&mut scratch[..length])
        .map_err(Error::Format)?;
    write_half(device, block, scratch, 0)?;
    if length > BLOCK_SIZE {
        write_half(device, block + 1, scratch, 1)?;
    }
    Ok(())
}
fn read_image<D: BlockDevice>(
    device: &mut D,
    entry: IndexEntry,
    epoch: u64,
    output: &mut [u8; BLOCK_SIZE],
    scratch: &mut Scratch,
) -> Result<(), Error<D::Error>> {
    let length = read_record(device, entry.record, scratch)?;
    match Record::decode(&scratch[..length]) {
        Ok(Record {
            log_epoch,
            payload:
                LogPayload::Redo {
                    home_block,
                    after_image,
                    ..
                },
            ..
        }) if log_epoch == epoch && home_block == u64::from(entry.home) => {
            output.copy_from_slice(after_image);
            Ok(())
        }
        _ => Err(Error::Corrupt),
    }
}
fn tail_present(first: &[u8], epoch: u64) -> bool {
    first.iter().any(|&byte| byte != 0) && first[32..40] == epoch.to_le_bytes()
}
/// Search every remaining aligned block, including a damaged transaction's
/// candidate COMMIT. A valid later current-epoch COMMIT proves this is not an
/// ignorable incomplete tail. Old-epoch residual bytes are never replayed.
fn reject_later_commit<D: BlockDevice>(
    device: &mut D,
    start: u32,
    epoch: u64,
    minimum_lsn: u64,
    scratch: &mut Scratch,
) -> Result<(), Error<D::Error>> {
    for block in start..LOG_END {
        read_half(device, block, scratch, 0)?;
        if matches!(Record::decode(&scratch[..BLOCK_SIZE]), Ok(Record {
            log_epoch, lsn, payload: LogPayload::Commit { .. }, ..
        }) if log_epoch == epoch && lsn >= minimum_lsn)
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}
