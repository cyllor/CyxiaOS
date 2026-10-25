//! Ordinary bounded files on the same redo journal as BootEpoch and contracts.
//! Mutable journal/disk ownership is borrowed per operation, never duplicated.
use super::{Action, Error, ObjectKey, PolicyStamp};
use crate::journal::{self, AfterImage, BlockDevice, Journal, Scratch};
use crate::storage::{
    BITMAP_START, BLOCK_SIZE, DATA_START, DirectoryEntry, Extent, INODE_START, Inode, InodeKind,
    MAX_FILE_SIZE, TOTAL_BLOCKS,
};
mod validation;
pub use validation::validate_volume;

pub const MAX_PATH: usize = 512;
pub const MAX_IO: usize = 65536;
pub const FIRST_ORDINARY_INODE: usize = 4;
pub const FIRST_ORDINARY_BLOCK: u32 =
    crate::cluster::volume::START + 2 * crate::cluster::volume::FILE_BLOCKS;
const MAP_BYTES: usize = TOTAL_BLOCKS as usize / 8;
const TX_CAPACITY: usize = 40;
pub const BACKGROUND_RESERVATION_BYTES: u64 = (2 + 2 * TX_CAPACITY as u64) * BLOCK_SIZE as u64;
const EMPTY_INODE: Inode = Inode {
    kind: InodeKind::Free,
    generation: 1,
    size: 0,
    durable_write_seq: 0,
    extent_count: 0,
    parent_inode: 0,
    parent_generation: 0,
    extents: [Extent::EMPTY; 16],
};
fn journal_error<E>(error: journal::Error<E>) -> Error {
    match error {
        journal::Error::NoSpace => Error::Capacity,
        journal::Error::Counter => Error::Overflow,
        journal::Error::Io(_) | journal::Error::Poisoned => Error::Io,
        _ => Error::Format,
    }
}
fn physical(inode: &Inode, logical: u32) -> Result<u32, Error> {
    inode.extents[..usize::from(inode.extent_count)]
        .iter()
        .find(|e| logical >= e.logical_start && logical - e.logical_start < e.block_count)
        .map(|e| e.physical_start + logical - e.logical_start)
        .ok_or(Error::Range)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Directory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    slot: u16,
    generation: u64,
}
#[derive(Clone, Copy)]
struct Open {
    inode: usize,
    object_generation: u64,
    generation: u64,
    mode: OpenMode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    pub object: ObjectKey,
    pub kind: InodeKind,
    pub size: u64,
    pub write_seq: u64,
    pub durable_write_seq: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    pub object: ObjectKey,
    pub kind: InodeKind,
    pub name: [u8; 63],
    pub name_len: u8,
    pub next_cookie: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncReceipt {
    pub object: ObjectKey,
    pub write_seq: u64,
    pub transactions: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushReceipt {
    pub object: ObjectKey,
    pub pages: u16,
    pub durable_write_seq: u64,
    pub transaction: journal::TransactionKey,
    pub commit_lsn: u64,
    pub policy_version: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub dirty_pages: u32,
    pub readahead_pages: u64,
    pub readahead_hits: u64,
    pub flushed_pages: u64,
    pub last_read_version: u64,
    pub last_flush_version: u64,
}
#[derive(Clone, Copy)]
struct Cache {
    valid: bool,
    dirty: bool,
    pinned: bool,
    prefetched: bool,
    inode: usize,
    logical: u32,
    physical: u32,
}
impl Cache {
    const EMPTY: Self = Self {
        valid: false,
        dirty: false,
        pinned: false,
        prefetched: false,
        inode: 0,
        logical: 0,
        physical: 0,
    };
}
#[repr(C, align(4096))]
#[derive(Clone, Copy)]
struct CachePage([u8; BLOCK_SIZE]);

pub struct FileSystem<const CACHE: usize = 64> {
    ready: bool,
    failed: bool,
    inodes: [Inode; 256],
    bitmap: [u8; MAP_BYTES],
    write_seq: [u64; 256],
    handles: [Option<Open>; 64],
    handle_generation: u64,
    cache: [Cache; CACHE],
    resident: usize,
    pages: [CachePage; CACHE],
    cache_budget: usize,
    reclaim_batch: usize,
    cache_baseline: (usize, usize),
    cache_selected: (usize, usize),
    cache_stamp: PolicyStamp,
    cache_policy_active: bool,
    reclaim_cursor: usize,
    evict_cursor: usize,
    tx: [[u8; BLOCK_SIZE]; TX_CAPACITY],
    homes: [u32; TX_CAPACITY],
    tx_count: usize,
    stamp: PolicyStamp,
    readahead: u16,
    flush_pages: u16,
    metrics: Metrics,
}
impl<const C: usize> Default for FileSystem<C> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const C: usize> FileSystem<C> {
    pub const fn new() -> Self {
        Self {
            ready: false,
            failed: false,
            inodes: [EMPTY_INODE; 256],
            bitmap: [0; MAP_BYTES],
            write_seq: [0; 256],
            handles: [None; 64],
            handle_generation: 0,
            cache: [Cache::EMPTY; C],
            resident: 0,
            pages: [CachePage([0; BLOCK_SIZE]); C],
            cache_budget: if C < 256 { C } else { 256 },
            reclaim_batch: 16,
            cache_baseline: (if C < 256 { C } else { 256 }, 16),
            cache_selected: (if C < 256 { C } else { 256 }, 16),
            cache_stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            cache_policy_active: false,
            reclaim_cursor: 0,
            evict_cursor: 0,
            tx: [[0; BLOCK_SIZE]; TX_CAPACITY],
            homes: [0; TX_CAPACITY],
            tx_count: 0,
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            readahead: 0,
            flush_pages: 4,
            metrics: Metrics {
                read_bytes: 0,
                write_bytes: 0,
                cache_hits: 0,
                cache_misses: 0,
                dirty_pages: 0,
                readahead_pages: 0,
                readahead_hits: 0,
                flushed_pages: 0,
                last_read_version: 0,
                last_flush_version: 0,
            },
        }
    }
    fn check(&self) -> Result<(), Error> {
        if !self.ready {
            Err(Error::NotReady)
        } else if self.failed {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
    fn check_journal(&mut self, j: &Journal) -> Result<(), Error> {
        self.check()?;
        if !j.is_writable() {
            self.failed = true;
            return Err(Error::Io);
        }
        Ok(())
    }
    pub fn mount<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        if self.ready {
            return Err(Error::Busy);
        }
        if !(64..=4096).contains(&C) {
            return Err(Error::Capacity);
        }
        validation::load_and_validate(
            &mut self.inodes,
            &mut self.bitmap,
            j,
            d,
            s,
            (&mut self.tx[..4]).try_into().unwrap(),
        )?;
        if self.inodes[1].kind == InodeKind::Free {
            return Err(Error::NotReady);
        }
        for i in 0..256 {
            self.write_seq[i] = self.inodes[i].durable_write_seq;
        }
        self.ready = true;
        Ok(())
    }
    pub fn metrics(&self) -> Metrics {
        self.metrics
    }
    pub fn apply(&mut self, action: Action, stamp: PolicyStamp, now: u64) -> Result<(), Error> {
        self.check()?;
        action.validate()?;
        let Action::Filesystem { readahead, flush } = action else {
            return Err(Error::Schema);
        };
        self.stamp.accepts(stamp, now)?;
        if self.stamp == stamp && (self.readahead != readahead || self.flush_pages != flush) {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.readahead = readahead;
        self.flush_pages = flush;
        Ok(())
    }
    pub fn current_action(&self, now: u64) -> Action {
        if self.stamp.live(now) {
            Action::Filesystem {
                readahead: self.readahead,
                flush: self.flush_pages,
            }
        } else {
            Action::Filesystem {
                readahead: 0,
                flush: 4,
            }
        }
    }
    pub fn policy_deadline_ns(&self) -> u64 {
        self.stamp.installed_until_ns
    }
    pub fn cache_usage(&self) -> [usize; 4] {
        [
            self.resident,
            self.metrics.dirty_pages as usize,
            self.cache_budget,
            C,
        ]
    }
    /// A control-plane reader cannot perform the owner's TTL transition. Until
    /// that owner actually closes expired admission, do not report baseline as
    /// if it had already been installed or release any charged cache pages.
    pub fn cache_partition_status(&self, now: u64) -> Result<[usize; 4], Error> {
        if self.cache_policy_active && !self.cache_stamp.live(now) {
            return Err(Error::Busy);
        }
        Ok(self.cache_usage())
    }
    pub fn cache_partition_deadline_ns(&self) -> Option<u64> {
        self.cache_policy_active
            .then_some(self.cache_stamp.installed_until_ns)
    }
    /// Actual page-aligned backing, excluding inode and cache metadata storage.
    pub fn cache_backing(&self) -> (usize, usize) {
        (self.pages.as_ptr() as usize, C * BLOCK_SIZE)
    }
    pub fn set_cache_partition(&mut self, pages: usize, batch: usize) -> Result<(), Error> {
        if pages == 0 || pages > C || batch == 0 || batch > 64 {
            return Err(Error::Capacity);
        }
        self.cache_budget = pages;
        self.reclaim_batch = batch;
        self.cache_baseline = (pages, batch);
        self.cache_policy_active = false;
        Ok(())
    }
    pub fn set_cache_partition_expiring(
        &mut self,
        pages: usize,
        batch: usize,
        stamp: PolicyStamp,
        now: u64,
    ) -> Result<(), Error> {
        if pages == 0 || pages > C || batch == 0 || batch > 64 {
            return Err(Error::Capacity);
        }
        self.cache_stamp.accepts(stamp, now)?;
        self.refresh_cache_partition(now);
        if self.cache_stamp == stamp {
            return if self.cache_selected == (pages, batch) {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        self.cache_stamp = stamp;
        self.cache_selected = (pages, batch);
        self.cache_policy_active = true;
        self.cache_budget = pages;
        self.reclaim_batch = batch;
        Ok(())
    }
    /// Close expired new admission at the cache owner's gate. Existing dirty
    /// and referenced pages remain charged; only bounded clean reclaim frees them.
    pub fn refresh_cache_partition(&mut self, now: u64) {
        if self.cache_policy_active && !self.cache_stamp.live(now) {
            self.cache_policy_active = false;
            (self.cache_budget, self.reclaim_batch) = self.cache_baseline;
        }
    }
    pub fn set_cache_budget(&mut self, pages: usize) -> Result<(), Error> {
        self.set_cache_partition(pages, 64)?;
        while self.cache_usage()[0] > pages && self.reclaim_cache() != 0 {}
        Ok(())
    }
    pub fn reclaim_cache(&mut self) -> usize {
        let mut resident = self.cache_usage()[0];
        let mut freed = 0;
        for _ in 0..C {
            if resident <= self.cache_budget || freed == self.reclaim_batch {
                break;
            }
            let at = self.reclaim_cursor;
            self.reclaim_cursor = (at + 1) % C;
            let page = &mut self.cache[at];
            if page.valid && !page.dirty && !page.pinned {
                *page = Cache::EMPTY;
                self.resident -= 1;
                resident -= 1;
                freed += 1;
            }
        }
        freed
    }
    /// Drop a bounded part of one durable object's clean cache. This is an
    /// explicit owner operation used when restoring a cold workload image;
    /// it never flushes, discards dirty data, releases pins, or changes policy.
    /// The caller retains `cursor` and must complete the scan before claiming
    /// that the object's cache is empty. A blocked cell is retried in place.
    pub fn discard_clean_object_cache(
        &mut self,
        object: ObjectKey,
        cursor: usize,
        maximum: usize,
    ) -> Result<usize, Error> {
        self.stat_object(object)?;
        if cursor > C || maximum == 0 || maximum > 64 {
            return Err(Error::Range);
        }
        let inode = usize::try_from(object.id).map_err(|_| Error::Range)?;
        let end = cursor.saturating_add(maximum).min(C);
        for at in cursor..end {
            let page = &mut self.cache[at];
            if page.valid && page.inode == inode {
                if page.dirty || page.pinned {
                    return Err(Error::Busy);
                }
                *page = Cache::EMPTY;
                self.resident = self.resident.checked_sub(1).ok_or(Error::Conflict)?;
            }
        }
        Ok(end)
    }
    fn allocated(&self, block: u32) -> bool {
        self.bitmap[block as usize / 8] & (1 << (block % 8)) != 0
    }
    fn set_allocated(&mut self, block: u32, allocated: bool) {
        let byte = &mut self.bitmap[block as usize / 8];
        let mask = 1 << (block % 8);
        if allocated {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    fn free_block(&self, excluded: &[u32]) -> Result<u32, Error> {
        (FIRST_ORDINARY_BLOCK..TOTAL_BLOCKS)
            .find(|b| !self.allocated(*b) && !excluded.contains(b))
            .ok_or(Error::Capacity)
    }
    fn append_block(inode: &mut Inode, block: u32) -> Result<(), Error> {
        let count = usize::from(inode.extent_count);
        let logical = inode.extents[..count].iter().map(|e| e.block_count).sum();
        if count > 0
            && inode.extents[count - 1].physical_start + inode.extents[count - 1].block_count
                == block
        {
            inode.extents[count - 1].block_count += 1;
            return Ok(());
        }
        if count == 16 {
            return Err(Error::Capacity);
        }
        inode.extents[count] = Extent {
            logical_start: logical,
            physical_start: block,
            block_count: 1,
        };
        inode.extent_count += 1;
        Ok(())
    }
    fn begin_tx(&mut self) {
        self.tx_count = 0;
    }
    fn tx_load<D: BlockDevice>(
        &mut self,
        home: u32,
        zero: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        if let Some(at) = self.homes[..self.tx_count].iter().position(|&v| v == home) {
            return Ok(at);
        }
        if self.tx_count == TX_CAPACITY {
            return Err(Error::Capacity);
        }
        let at = self.tx_count;
        if zero {
            self.tx[at].fill(0);
        } else {
            j.read_block(d, home, &mut self.tx[at], s)
                .map_err(journal_error)?;
        }
        self.homes[at] = home;
        self.tx_count += 1;
        Ok(at)
    }
    fn tx_inode<D: BlockDevice>(
        &mut self,
        id: usize,
        inode: Inode,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        let at = self.tx_load(INODE_START + id as u32 / 16, false, j, d, s)?;
        inode
            .encode(
                id as u32,
                &mut self.tx[at][id % 16 * 256..id % 16 * 256 + 256],
            )
            .map_err(|_| Error::Format)
    }
    fn tx_bit<D: BlockDevice>(
        &mut self,
        block: u32,
        allocated: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        let at = self.tx_load(BITMAP_START + block / 32768, false, j, d, s)?;
        let byte = &mut self.tx[at][block as usize / 8 % BLOCK_SIZE];
        if allocated {
            *byte |= 1 << (block % 8);
        } else {
            *byte &= !(1 << (block % 8));
        }
        Ok(())
    }
    fn commit<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<journal::CommitReceipt, Error> {
        if j.remaining_log_blocks() < 2 + 2 * self.tx_count as u32
            && let Err(e) = j.checkpoint(d, s)
        {
            self.failed = true;
            return Err(journal_error(e));
        }
        let mut images = [AfterImage {
            home_block: 0,
            bytes: &self.tx[0],
        }; TX_CAPACITY];
        for (i, image) in images[..self.tx_count].iter_mut().enumerate() {
            *image = AfterImage {
                home_block: self.homes[i],
                bytes: &self.tx[i],
            };
        }
        match j.commit(d, &images[..self.tx_count], s) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.failed = !j.is_writable();
                Err(journal_error(e))
            }
        }
    }
    fn refresh_reserved<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.check_journal(j)?;
        j.read_block(d, INODE_START, &mut self.tx[0], s)
            .map_err(journal_error)?;
        for id in 0..4 {
            self.inodes[id] = Inode::decode(id as u32, &self.tx[0][id * 256..id * 256 + 256])
                .map_err(|_| Error::Format)?;
            self.write_seq[id] = self.inodes[id].durable_write_seq;
        }
        // The cluster allocator cannot touch ordinary data. Merge its current
        // reservation bits without discarding any ordinary dirty reservations.
        j.read_block(d, BITMAP_START, &mut self.tx[0], s)
            .map_err(journal_error)?;
        for block in DATA_START..FIRST_ORDINARY_BLOCK {
            self.set_allocated(
                block,
                self.tx[0][block as usize / 8] & (1 << (block % 8)) != 0,
            );
        }
        Ok(())
    }
    fn path(path: &str) -> Result<(), Error> {
        if !path.starts_with('/') || path.len() > MAX_PATH || path.as_bytes().contains(&0) {
            return Err(Error::Range);
        }
        for part in path.split('/').filter(|s| !s.is_empty()) {
            if part.len() > 63 || part == "." || part == ".." {
                return Err(Error::Format);
            }
        }
        Ok(())
    }
    fn entry<D: BlockDevice>(
        &mut self,
        id: usize,
        index: usize,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<Entry>, Error> {
        let inode = self.inodes[id];
        if inode.kind != InodeKind::Directory {
            return Err(Error::NotDirectory);
        }
        if index >= inode.size as usize / 128 {
            return Ok(None);
        }
        j.read_block(d, physical(&inode, index as u32 / 32)?, &mut self.tx[0], s)
            .map_err(journal_error)?;
        let e = DirectoryEntry::decode(&self.tx[0][index % 32 * 128..index % 32 * 128 + 128])
            .map_err(|_| Error::Format)?;
        if e == DirectoryEntry::EMPTY {
            return Ok(None);
        }
        let target = self.inodes[e.inode_id as usize];
        if target.kind == InodeKind::Free || target.generation != e.inode_generation {
            return Err(Error::Stale);
        }
        let mut name = [0; 63];
        name[..e.name.len()].copy_from_slice(e.name.as_bytes());
        Ok(Some(Entry {
            object: ObjectKey {
                id: u64::from(e.inode_id),
                generation: e.inode_generation,
            },
            kind: target.kind,
            name,
            name_len: e.name.len() as u8,
            next_cookie: index as u16 + 1,
        }))
    }
    fn lookup<D: BlockDevice>(
        &mut self,
        id: usize,
        name: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<(usize, usize)>, Error> {
        if self.inodes[id].kind != InodeKind::Directory {
            return Err(Error::NotDirectory);
        }
        for index in 0..self.inodes[id].size as usize / 128 {
            if let Some(e) = self.entry(id, index, j, d, s)?
                && e.name[..usize::from(e.name_len)] == *name.as_bytes()
            {
                return Ok(Some((e.object.id as usize, index)));
            }
        }
        Ok(None)
    }
    fn resolve<D: BlockDevice>(
        &mut self,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        Self::path(path)?;
        let mut id = 0;
        for part in path.split('/').filter(|v| !v.is_empty()) {
            id = self.lookup(id, part, j, d, s)?.ok_or(Error::NotFound)?.0;
        }
        Ok(id)
    }
    fn parent<'a, D: BlockDevice>(
        &mut self,
        path: &'a str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(usize, &'a str), Error> {
        Self::path(path)?;
        let path = path.trim_end_matches('/');
        let (prefix, name) = path.rsplit_once('/').ok_or(Error::Format)?;
        if name.is_empty() {
            return Err(Error::Exists);
        }
        let parent = self.resolve(if prefix.is_empty() { "/" } else { prefix }, j, d, s)?;
        if self.inodes[parent].kind != InodeKind::Directory {
            return Err(Error::NotDirectory);
        }
        if parent == 0 && (name == ".cyxia-boot" || crate::cluster::volume::NAMES.contains(&name)) {
            return Err(Error::Auth);
        }
        Ok((parent, name))
    }
    fn create_kind<D: BlockDevice>(
        &mut self,
        path: &str,
        kind: InodeKind,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<ObjectKey, Error> {
        self.refresh_reserved(j, d, s)?;
        let (parent, name) = self.parent(path, j, d, s)?;
        if self.lookup(parent, name, j, d, s)?.is_some() {
            return Err(Error::Exists);
        }
        let id = (FIRST_ORDINARY_INODE..256)
            .find(|&i| {
                self.inodes[i].kind == InodeKind::Free && self.inodes[i].generation != u64::MAX
            })
            .ok_or(Error::Capacity)?;
        let mut parent_inode = self.inodes[parent];
        let first = if parent == 0 { 3 } else { 0 };
        let old_slots = parent_inode.size as usize / 128;
        let mut index = old_slots.max(first);
        for slot in first..old_slots {
            if self.entry(parent, slot, j, d, s)?.is_none() {
                index = slot;
                break;
            }
        }
        if index >= 256 {
            return Err(Error::Capacity);
        }
        let inode = Inode {
            kind,
            generation: self.inodes[id].generation + 1,
            parent_inode: parent as u32,
            parent_generation: parent_inode.generation,
            ..EMPTY_INODE
        };
        let new_size = parent_inode.size.max((index + 1) as u64 * 128);
        let mut allocated = None;
        if new_size.div_ceil(BLOCK_SIZE as u64) > parent_inode.size.div_ceil(BLOCK_SIZE as u64) {
            let block = self.free_block(&[])?;
            Self::append_block(&mut parent_inode, block)?;
            allocated = Some(block);
        }
        parent_inode.size = new_size;
        parent_inode.durable_write_seq = parent_inode
            .durable_write_seq
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.begin_tx();
        let home = physical(&parent_inode, index as u32 / 32)?;
        let at = self.tx_load(home, allocated == Some(home), j, d, s)?;
        for slot in old_slots..index {
            DirectoryEntry::EMPTY
                .encode(&mut self.tx[at][slot % 32 * 128..slot % 32 * 128 + 128])
                .map_err(|_| Error::Format)?;
        }
        DirectoryEntry {
            inode_id: id as u32,
            inode_generation: inode.generation,
            name,
        }
        .encode(&mut self.tx[at][index % 32 * 128..index % 32 * 128 + 128])
        .map_err(|_| Error::Format)?;
        if let Some(block) = allocated {
            self.tx_bit(block, true, j, d, s)?;
        }
        self.tx_inode(parent, parent_inode, j, d, s)?;
        self.tx_inode(id, inode, j, d, s)?;
        self.commit(j, d, s)?;
        if let Some(block) = allocated {
            self.set_allocated(block, true);
        }
        self.inodes[parent] = parent_inode;
        self.write_seq[parent] = parent_inode.durable_write_seq;
        self.inodes[id] = inode;
        self.write_seq[id] = 0;
        Ok(ObjectKey {
            id: id as u64,
            generation: inode.generation,
        })
    }
    pub fn create<D: BlockDevice>(
        &mut self,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<ObjectKey, Error> {
        self.create_kind(path, InodeKind::File, j, d, s)
    }
    pub fn mkdir<D: BlockDevice>(
        &mut self,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<ObjectKey, Error> {
        self.create_kind(path, InodeKind::Directory, j, d, s)
    }
    pub fn stat_object(&self, key: ObjectKey) -> Result<Stat, Error> {
        self.check()?;
        let id = usize::try_from(key.id).map_err(|_| Error::Stale)?;
        let inode = self
            .inodes
            .get(id)
            .filter(|i| i.kind != InodeKind::Free && i.generation == key.generation)
            .ok_or(Error::Stale)?;
        if (1..4).contains(&id) {
            return Err(Error::Auth);
        }
        Ok(Stat {
            object: key,
            kind: inode.kind,
            size: inode.size,
            write_seq: self.write_seq[id],
            durable_write_seq: inode.durable_write_seq,
        })
    }
    pub fn stat<D: BlockDevice>(
        &mut self,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Stat, Error> {
        self.refresh_reserved(j, d, s)?;
        let id = self.resolve(path, j, d, s)?;
        self.stat_object(ObjectKey {
            id: id as u64,
            generation: self.inodes[id].generation,
        })
    }
    pub fn open<D: BlockDevice>(
        &mut self,
        path: &str,
        mode: OpenMode,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Handle, Error> {
        let stat = self.stat(path, j, d, s)?;
        if stat.kind == InodeKind::Directory && mode != OpenMode::Directory {
            return Err(Error::IsDirectory);
        }
        if stat.kind != InodeKind::Directory && mode == OpenMode::Directory {
            return Err(Error::NotDirectory);
        }
        let at = self
            .handles
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.handle_generation = self
            .handle_generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.handles[at] = Some(Open {
            inode: stat.object.id as usize,
            object_generation: stat.object.generation,
            generation: self.handle_generation,
            mode,
        });
        Ok(Handle {
            slot: at as u16,
            generation: self.handle_generation,
        })
    }
    fn opened(&self, h: Handle) -> Result<Open, Error> {
        self.check()?;
        self.handles
            .get(usize::from(h.slot))
            .and_then(|v| *v)
            .filter(|v| {
                v.generation == h.generation
                    && self.inodes[v.inode].generation == v.object_generation
            })
            .ok_or(Error::Stale)
    }
    pub fn handle_object(&self, h: Handle) -> Result<ObjectKey, Error> {
        let o = self.opened(h)?;
        Ok(ObjectKey {
            id: o.inode as u64,
            generation: o.object_generation,
        })
    }
    pub fn close(&mut self, h: Handle) -> Result<(), Error> {
        let slot = self
            .handles
            .get_mut(usize::from(h.slot))
            .ok_or(Error::Stale)?;
        if slot.is_none_or(|o| o.generation != h.generation) {
            return Err(Error::Stale);
        }
        *slot = None;
        Ok(())
    }
    pub fn readdir<D: BlockDevice>(
        &mut self,
        h: Handle,
        cookie: u16,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<Entry>, Error> {
        let open = self.opened(h)?;
        if open.mode != OpenMode::Directory {
            return Err(Error::NotDirectory);
        }
        self.refresh_reserved(j, d, s)?;
        for index in usize::from(cookie)..self.inodes[open.inode].size as usize / 128 {
            if let Some(e) = self.entry(open.inode, index, j, d, s)?
                && e.object.id >= FIRST_ORDINARY_INODE as u64
            {
                return Ok(Some(e));
            }
        }
        Ok(None)
    }
    fn cached(&self, id: usize, logical: u32, physical: u32) -> Option<usize> {
        self.cache.iter().position(|p| {
            p.valid && p.inode == id && p.logical == logical && p.physical == physical
        })
    }
    /// Inspect a stopped caller's actual read without loading pages or changing
    /// cache recency. Pure cache hits, EOF, and cache admission blocked by dirty
    /// debt do not advertise a DMA demand to the ordinary I/O arbiter.
    pub fn read_io_demand(
        &self,
        h: Handle,
        offset: u64,
        length: usize,
        now: u64,
        prefetch_admitted: bool,
    ) -> Result<bool, Error> {
        let open = self.opened(h)?;
        if !matches!(open.mode, OpenMode::Read | OpenMode::ReadWrite) {
            return Err(Error::Auth);
        }
        if length > MAX_IO {
            return Err(Error::Range);
        }
        let inode = self.inodes[open.inode];
        if length == 0 || offset >= inode.size {
            return Ok(false);
        }
        let end = offset + (length as u64).min(inode.size - offset);
        let first = offset / BLOCK_SIZE as u64;
        let demand_end = end.div_ceil(BLOCK_SIZE as u64);
        let extra = if prefetch_admitted && self.stamp.live(now) {
            u64::from(self.readahead)
        } else {
            0
        };
        let last = (demand_end + extra).min(inode.size.div_ceil(BLOCK_SIZE as u64));
        self.range_io_demand(open.inode, first as u32, last as u32, false)
    }
    /// Newly extended zero-filled pages are only dirty memory until writeback.
    /// A write needs foreground disk reads solely for an uncached old page.
    pub fn write_io_demand(&self, h: Handle, offset: u64, length: usize) -> Result<bool, Error> {
        let open = self.opened(h)?;
        if !matches!(open.mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(Error::Auth);
        }
        let inode = self.inodes[open.inode];
        if length > MAX_IO || offset > inode.size {
            return Err(Error::Range);
        }
        let end = offset.checked_add(length as u64).ok_or(Error::Overflow)?;
        if end > MAX_FILE_SIZE {
            return Err(Error::Range);
        }
        if length == 0 {
            return Ok(false);
        }
        self.range_io_demand(
            open.inode,
            (offset / BLOCK_SIZE as u64) as u32,
            end.div_ceil(BLOCK_SIZE as u64)
                .min(inode.size.div_ceil(BLOCK_SIZE as u64)) as u32,
            true,
        )
    }
    pub fn readdir_io_demand(&self, h: Handle) -> Result<bool, Error> {
        let open = self.opened(h)?;
        if open.mode != OpenMode::Directory {
            return Err(Error::NotDirectory);
        }
        // readdir always refreshes the reserved directory's durable metadata.
        Ok(true)
    }
    fn range_io_demand(&self, id: usize, first: u32, end: u32, write: bool) -> Result<bool, Error> {
        let count = end.saturating_sub(first);
        if count == 0 {
            return Ok(false);
        }
        // A 64KiB demand can cross 17 pages, with at most 64 prefetch pages.
        if count > 81 {
            return Err(Error::Range);
        }
        if self.resident > self.cache_budget {
            return Ok(false);
        }
        let mut available = self.resident < self.cache_budget;
        let mut present = 0u128;
        for page in &self.cache {
            let inside = page.valid && page.inode == id && (first..end).contains(&page.logical);
            if inside && physical(&self.inodes[id], page.logical)? == page.physical {
                present |= 1u128 << (page.logical - first);
            }
            // Writes pin their existing destination pages before admitting a
            // miss, so those pages cannot serve as the eviction backing.
            let evictable = page.valid && !page.dirty && !page.pinned && (!write || !inside);
            available |= evictable;
        }
        Ok(available && present != (1u128 << count) - 1)
    }
    #[allow(clippy::too_many_arguments)]
    fn page<D: BlockDevice>(
        &mut self,
        id: usize,
        logical: u32,
        home: u32,
        zero: bool,
        prefetch: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        if let Some(at) = self.cached(id, logical, home) {
            if !prefetch {
                self.metrics.cache_hits += 1;
            }
            if !prefetch && self.cache[at].prefetched {
                self.cache[at].prefetched = false;
                self.metrics.readahead_hits += 1;
            }
            return Ok(at);
        }
        if !prefetch {
            self.metrics.cache_misses += 1;
        }
        let resident = self.cache_usage()[0];
        if resident > self.cache_budget {
            return Err(Error::Again);
        }
        let at = if resident < self.cache_budget {
            self.cache.iter().position(|p| !p.valid)
        } else {
            None
        }
        .or_else(|| {
            (0..C)
                .map(|n| (self.evict_cursor + n) % C)
                .find(|&i| self.cache[i].valid && !self.cache[i].dirty && !self.cache[i].pinned)
        })
        .ok_or(Error::Again)?;
        if self.cache[at].valid {
            self.resident -= 1;
        }
        self.cache[at] = Cache::EMPTY;
        if !zero {
            j.read_block(d, home, &mut self.pages[at].0, s)
                .map_err(journal_error)?;
        } else {
            self.pages[at].0.fill(0);
        }
        self.cache[at].valid = true;
        self.resident += 1;
        self.cache[at].inode = id;
        self.cache[at].logical = logical;
        self.cache[at].physical = home;
        self.cache[at].prefetched = prefetch;
        self.evict_cursor = (at + 1) % C;
        if prefetch {
            self.metrics.readahead_pages += 1;
        }
        Ok(at)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn read<D: BlockDevice>(
        &mut self,
        h: Handle,
        offset: u64,
        out: &mut [u8],
        now: u64,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        self.read_admitted(h, offset, out, now, true, j, d, s)
    }
    /// Dependency admission is checked by the owner before borrowing the file
    /// service. A closed prerequisite suppresses only new optional prefetch;
    /// demand reads and already owned dirty/cache pages retain their progress.
    #[allow(clippy::too_many_arguments)]
    pub fn read_admitted<D: BlockDevice>(
        &mut self,
        h: Handle,
        offset: u64,
        out: &mut [u8],
        now: u64,
        prefetch_admitted: bool,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        self.check_journal(j)?;
        let open = self.opened(h)?;
        if !matches!(open.mode, OpenMode::Read | OpenMode::ReadWrite) {
            return Err(Error::Auth);
        }
        if out.len() > MAX_IO {
            return Err(Error::Range);
        }
        let inode = self.inodes[open.inode];
        if offset >= inode.size || out.is_empty() {
            return Ok(0);
        }
        let len = out.len().min((inode.size - offset) as usize);
        let mut done = 0;
        while done < len {
            let pos = offset as usize + done;
            let logical = (pos / BLOCK_SIZE) as u32;
            let home = physical(&inode, logical)?;
            let at = self.page(open.inode, logical, home, false, false, j, d, s)?;
            let n = (BLOCK_SIZE - pos % BLOCK_SIZE).min(len - done);
            out[done..done + n]
                .copy_from_slice(&self.pages[at].0[pos % BLOCK_SIZE..pos % BLOCK_SIZE + n]);
            done += n;
        }
        self.metrics.read_bytes = self.metrics.read_bytes.saturating_add(done as u64);
        let first = (offset + done as u64).div_ceil(BLOCK_SIZE as u64) as u32;
        let count = if prefetch_admitted && self.stamp.live(now) {
            self.readahead
        } else {
            0
        };
        if prefetch_admitted && self.stamp.live(now) {
            self.metrics.last_read_version = self.stamp.version;
        }
        for logical in
            first..(first + u32::from(count)).min(inode.size.div_ceil(BLOCK_SIZE as u64) as u32)
        {
            let home = physical(&inode, logical)?;
            match self.page(open.inode, logical, home, false, true, j, d, s) {
                Ok(_) => (),
                Err(Error::Again) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }
    pub fn read_cache_page<D: BlockDevice>(
        &mut self,
        key: ObjectKey,
        page: u64,
        out: &mut [u8; BLOCK_SIZE],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.check_journal(j)?;
        let stat = self.stat_object(key)?;
        if stat.kind != InodeKind::File {
            return Err(Error::IsDirectory);
        }
        let offset = page.checked_mul(BLOCK_SIZE as u64).ok_or(Error::Range)?;
        if offset >= stat.size {
            return Err(Error::Range);
        }
        let home = physical(&self.inodes[key.id as usize], page as u32)?;
        if let Some(at) = self.cached(key.id as usize, page as u32, home) {
            self.metrics.cache_hits += 1;
            out.copy_from_slice(&self.pages[at].0);
        } else {
            self.metrics.cache_misses += 1;
            j.read_block(d, home, out, s).map_err(journal_error)?;
        }
        let length = (stat.size - offset).min(BLOCK_SIZE as u64) as usize;
        out[length..].fill(0);
        Ok(())
    }
    pub fn write<D: BlockDevice>(
        &mut self,
        h: Handle,
        offset: u64,
        data: &[u8],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<usize, Error> {
        self.check_journal(j)?;
        let open = self.opened(h)?;
        if !matches!(open.mode, OpenMode::Write | OpenMode::ReadWrite) {
            return Err(Error::Auth);
        }
        let id = open.inode;
        let original = self.inodes[id];
        if data.len() > MAX_IO || offset > original.size {
            return Err(Error::Range);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::Overflow)?;
        if end > MAX_FILE_SIZE {
            return Err(Error::Range);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let seq = self.write_seq[id].checked_add(1).ok_or(Error::Overflow)?;
        let mut inode = original;
        let mut blocks = [0u32; 17];
        let mut count = 0;
        for _ in original.size.div_ceil(BLOCK_SIZE as u64)..end.div_ceil(BLOCK_SIZE as u64) {
            let block = self.free_block(&blocks[..count])?;
            Self::append_block(&mut inode, block)?;
            blocks[count] = block;
            count += 1;
        }
        inode.size = original.size.max(end);
        inode.validate(id as u32).map_err(|_| Error::Format)?;
        let first = offset as u32 / BLOCK_SIZE as u32;
        let last = (end - 1) as u32 / BLOCK_SIZE as u32;
        for logical in first..=last {
            let home = physical(&inode, logical)?;
            if let Some(at) = self.cached(id, logical, home) {
                self.cache[at].pinned = true;
            }
        }
        let prepared = (|| {
            for logical in first..=last {
                let home = physical(&inode, logical)?;
                let at = self.page(
                    id,
                    logical,
                    home,
                    blocks[..count].contains(&home),
                    false,
                    j,
                    d,
                    s,
                )?;
                self.cache[at].pinned = true;
            }
            Ok::<(), Error>(())
        })();
        if let Err(e) = prepared {
            for p in &mut self.cache {
                p.pinned = false;
                if p.valid && p.inode == id && blocks[..count].contains(&p.physical) {
                    *p = Cache::EMPTY;
                    self.resident -= 1;
                }
            }
            return Err(e);
        }
        let mut done = 0;
        while done < data.len() {
            let pos = offset as usize + done;
            let logical = (pos / BLOCK_SIZE) as u32;
            let at = self
                .cached(id, logical, physical(&inode, logical)?)
                .ok_or(Error::Conflict)?;
            let n = (BLOCK_SIZE - pos % BLOCK_SIZE).min(data.len() - done);
            self.pages[at].0[pos % BLOCK_SIZE..pos % BLOCK_SIZE + n]
                .copy_from_slice(&data[done..done + n]);
            if !self.cache[at].dirty {
                self.cache[at].dirty = true;
                self.metrics.dirty_pages += 1;
            }
            done += n;
        }
        for p in &mut self.cache {
            p.pinned = false;
        }
        for block in &blocks[..count] {
            self.set_allocated(*block, true);
        }
        self.inodes[id] = inode;
        self.write_seq[id] = seq;
        self.metrics.write_bytes = self.metrics.write_bytes.saturating_add(done as u64);
        Ok(done)
    }
    fn prefix(inode: Inode, size: u64) -> Inode {
        let mut result = inode;
        result.size = size;
        result.extents = [Extent::EMPTY; 16];
        result.extent_count = 0;
        let mut left = size.div_ceil(BLOCK_SIZE as u64) as u32;
        for extent in &inode.extents[..usize::from(inode.extent_count)] {
            if left == 0 {
                break;
            }
            let mut e = *extent;
            e.block_count = e.block_count.min(left);
            result.extents[usize::from(result.extent_count)] = e;
            result.extent_count += 1;
            left -= e.block_count;
        }
        result
    }
    fn flush_inode<D: BlockDevice>(
        &mut self,
        id: usize,
        limit: usize,
        version: u64,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<FlushReceipt>, Error> {
        self.check()?;
        let mut selected = [0usize; 32];
        let mut count = 0;
        let mut after = None;
        while count < limit.min(32) {
            let next = self
                .cache
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    p.valid && p.dirty && p.inode == id && after.is_none_or(|n| p.logical > n)
                })
                .min_by_key(|(_, p)| p.logical)
                .map(|(i, _)| i);
            let Some(at) = next else {
                break;
            };
            after = Some(self.cache[at].logical);
            selected[count] = at;
            count += 1;
        }
        if count == 0 {
            return Ok(None);
        }
        self.begin_tx();
        let inode_at = self.tx_load(INODE_START + id as u32 / 16, false, j, d, s)?;
        let old = Inode::decode(
            id as u32,
            &self.tx[inode_at][id % 16 * 256..id % 16 * 256 + 256],
        )
        .map_err(|_| Error::Format)?;
        let size = old.size.max(
            self.inodes[id]
                .size
                .min((u64::from(after.unwrap()) + 1) * BLOCK_SIZE as u64),
        );
        let mut published = Self::prefix(self.inodes[id], size);
        let remaining = self
            .cache
            .iter()
            .filter(|p| p.valid && p.dirty && p.inode == id)
            .count()
            - count;
        published.durable_write_seq = if remaining == 0 {
            self.write_seq[id]
        } else {
            old.durable_write_seq
        };
        for &at in &selected[..count] {
            let slot = self.tx_load(self.cache[at].physical, true, j, d, s)?;
            self.tx[slot].copy_from_slice(&self.pages[at].0);
        }
        for logical in
            old.size.div_ceil(BLOCK_SIZE as u64) as u32..size.div_ceil(BLOCK_SIZE as u64) as u32
        {
            self.tx_bit(physical(&published, logical)?, true, j, d, s)?;
        }
        self.tx_inode(id, published, j, d, s)?;
        let receipt = self.commit(j, d, s)?;
        for &at in &selected[..count] {
            self.cache[at].dirty = false;
            self.metrics.dirty_pages -= 1;
        }
        self.inodes[id].durable_write_seq = published.durable_write_seq;
        self.metrics.flushed_pages += count as u64;
        self.metrics.last_flush_version = self.metrics.last_flush_version.max(version);
        Ok(Some(FlushReceipt {
            object: ObjectKey {
                id: id as u64,
                generation: published.generation,
            },
            pages: count as u16,
            durable_write_seq: published.durable_write_seq,
            transaction: receipt.key,
            commit_lsn: receipt.commit_lsn,
            policy_version: version,
        }))
    }
    pub fn fsync<D: BlockDevice>(
        &mut self,
        h: Handle,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<SyncReceipt, Error> {
        self.check_journal(j)?;
        let open = self.opened(h)?;
        if open.mode == OpenMode::Directory {
            return Err(Error::IsDirectory);
        }
        let seq = self.write_seq[open.inode];
        let mut transactions = 0;
        while self.flush_inode(open.inode, 32, 0, j, d, s)?.is_some() {
            transactions += 1;
        }
        if self.inodes[open.inode].durable_write_seq < seq {
            return Err(Error::Io);
        }
        Ok(SyncReceipt {
            object: ObjectKey {
                id: open.inode as u64,
                generation: open.object_generation,
            },
            write_seq: seq,
            transactions,
        })
    }
    pub fn background_flush<D: BlockDevice>(
        &mut self,
        now: u64,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<FlushReceipt>, Error> {
        self.check_journal(j)?;
        let Some(id) = self
            .cache
            .iter()
            .find(|p| p.valid && p.dirty)
            .map(|p| p.inode)
        else {
            return Ok(None);
        };
        let (limit, version) = if self.stamp.live(now) {
            (self.flush_pages as usize, self.stamp.version)
        } else {
            (4, 0)
        };
        self.flush_inode(id, limit, version, j, d, s)
    }
    /// Required cache reclamation uses the protected progress path. It cannot
    /// be stopped by an optional writeback policy or earn that policy a receipt.
    pub fn reclaim_flush_one<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Option<FlushReceipt>, Error> {
        self.check_journal(j)?;
        if self.resident <= self.cache_budget {
            return Ok(None);
        }
        let Some(id) = self
            .cache
            .iter()
            .find(|p| p.valid && p.dirty)
            .map(|p| p.inode)
        else {
            return Ok(None);
        };
        self.flush_inode(id, 32, 0, j, d, s)
    }
    pub fn unlink<D: BlockDevice>(
        &mut self,
        path: &str,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(), Error> {
        self.refresh_reserved(j, d, s)?;
        let (parent, name) = self.parent(path, j, d, s)?;
        let (id, index) = self.lookup(parent, name, j, d, s)?.ok_or(Error::NotFound)?;
        if id < FIRST_ORDINARY_INODE {
            return Err(Error::Auth);
        }
        if self.handles.iter().flatten().any(|h| h.inode == id) {
            return Err(Error::Busy);
        }
        let inode = self.inodes[id];
        if inode.kind == InodeKind::Directory {
            for n in 0..inode.size as usize / 128 {
                if self.entry(id, n, j, d, s)?.is_some() {
                    return Err(Error::NotEmpty);
                }
            }
        }
        let mut parent_inode = self.inodes[parent];
        parent_inode.durable_write_seq = parent_inode
            .durable_write_seq
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.begin_tx();
        let at = self.tx_load(physical(&parent_inode, index as u32 / 32)?, false, j, d, s)?;
        DirectoryEntry::EMPTY
            .encode(&mut self.tx[at][index % 32 * 128..index % 32 * 128 + 128])
            .map_err(|_| Error::Format)?;
        for extent in &inode.extents[..usize::from(inode.extent_count)] {
            for block in extent.physical_start..extent.physical_start + extent.block_count {
                self.tx_bit(block, false, j, d, s)?;
            }
        }
        self.tx_inode(parent, parent_inode, j, d, s)?;
        let free = Inode {
            generation: inode.generation,
            ..EMPTY_INODE
        };
        self.tx_inode(id, free, j, d, s)?;
        self.commit(j, d, s)?;
        for extent in &inode.extents[..usize::from(inode.extent_count)] {
            for block in extent.physical_start..extent.physical_start + extent.block_count {
                self.set_allocated(block, false);
            }
        }
        for page in &mut self.cache {
            if page.valid && page.inode == id {
                if page.dirty {
                    self.metrics.dirty_pages -= 1;
                }
                *page = Cache::EMPTY;
                self.resident -= 1;
            }
        }
        self.inodes[parent] = parent_inode;
        self.write_seq[parent] = parent_inode.durable_write_seq;
        self.inodes[id] = free;
        self.write_seq[id] = 0;
        Ok(())
    }
}
