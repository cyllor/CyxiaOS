//! Business blocks are immutable once published. Dirty pages own new blocks;
//! only fixed management pages enter redo. Old allocations remain until GC.
use super::*;

pub(super) const FILE_BLOCKS: usize = MAX_FILE_SIZE as usize / BLOCK_SIZE;
pub(super) type BlockMap = [u32; FILE_BLOCKS];

pub(super) fn load_map<D: BlockDevice>(
    id: usize,
    inode: &Inode,
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    out: &mut BlockMap,
) -> Result<(), Error> {
    out.fill(0);
    let mut append = |e: &Extent| -> Result<(), Error> {
        let start = e.logical_start as usize;
        let end = start
            .checked_add(e.block_count as usize)
            .ok_or(Error::Format)?;
        if end > FILE_BLOCKS {
            return Err(Error::Format);
        }
        for (n, cell) in out[start..end].iter_mut().enumerate() {
            if *cell != 0 {
                return Err(Error::Conflict);
            }
            *cell = e
                .physical_start
                .checked_add(n as u32)
                .ok_or(Error::Format)?;
        }
        Ok(())
    };
    for e in &inode.extents[..usize::from(inode.extent_count)] {
        append(e)?;
    }
    if inode.ext_block != 0 {
        // Borrow the existing I/O scratch. A decoded extent array and another
        // block-sized local would otherwise compound the caller's map stack.
        let page = j
            .read_block_scratch(d, inode.ext_block, s)
            .map_err(journal_error)?;
        ExtentBlock::validate_bytes_for(page, id as u32, inode).map_err(|_| Error::Format)?;
        for index in 0..usize::from(inode.ext_count) {
            let extent = ExtentBlock::extent_from_bytes(page, index).map_err(|_| Error::Format)?;
            append(&extent)?;
        }
    }
    let count = inode.size.div_ceil(BLOCK_SIZE as u64) as usize;
    if out[..count].contains(&0) || out[count..].iter().any(|&b| b != 0) {
        return Err(Error::Format);
    }
    Ok(())
}

pub(super) fn extent_count(map: &[u32]) -> usize {
    let mut previous = 0;
    let mut count = 0;
    for &block in map {
        if block == 0 {
            return usize::MAX;
        }
        if previous == 0 || previous + 1 != block {
            count += 1;
        }
        previous = block;
    }
    count
}

pub(super) fn mapped_inode(
    id: usize,
    mut inode: Inode,
    size: u64,
    map: &BlockMap,
    indirect_home: u32,
) -> Result<(Inode, Option<ExtentBlock>), Error> {
    inode.size = size;
    inode.extents.fill(Extent::EMPTY);
    inode.extent_count = 0;
    inode.ext_block = 0;
    inode.ext_count = 0;
    let blocks = size.div_ceil(BLOCK_SIZE as u64) as usize;
    let mut indirect = ExtentBlock::empty(id as u32, inode.generation);
    let mut logical = 0;
    let mut count = 0;
    while logical < blocks {
        let home = map[logical];
        if !(FIRST_BUSINESS_BLOCK..TOTAL_BLOCKS).contains(&home) {
            return Err(Error::Format);
        }
        let mut n = 1;
        while logical + n < blocks && map[logical + n] == home + n as u32 {
            n += 1;
        }
        let extent = Extent {
            logical_start: logical as u32,
            physical_start: home,
            block_count: n as u32,
        };
        if count < 16 {
            inode.extents[count] = extent;
            inode.extent_count += 1;
        } else if count < MAX_EXTENTS {
            indirect.extents[count - 16] = extent;
            indirect.count += 1;
        } else {
            return Err(Error::Capacity);
        }
        count += 1;
        logical += n;
    }
    if count > 16 {
        if !(FIRST_BUSINESS_BLOCK..TOTAL_BLOCKS).contains(&indirect_home) {
            return Err(Error::Capacity);
        }
        inode.ext_block = indirect_home;
        inode.ext_count = indirect.count;
        indirect
            .validate_for(id as u32, &inode)
            .map_err(|_| Error::Format)?;
    }
    inode.validate(id as u32).map_err(|_| Error::Format)?;
    Ok((inode, (count > 16).then_some(indirect)))
}

impl<const C: usize> FileSystem<C> {
    pub(super) fn reserve_block<D: BlockDevice>(
        &mut self,
        excluded: &[u32],
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<u32, Error> {
        match self.free_block(excluded) {
            Ok(block) => Ok(block),
            Err(Error::Capacity) => {
                self.snapshots
                    .fault_freeze(j, d, s, &mut self.tx)
                    .map_err(snapshots::snapshot_error)?;
                Err(Error::Capacity)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn committed_inode<D: BlockDevice>(
        &mut self,
        id: usize,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<Inode, Error> {
        let _ = (j, d, s);
        let mut inode = self.inodes[id];
        inode.size = self.committed_size[id];
        Ok(inode)
    }
    pub(super) fn live_physical<D: BlockDevice>(
        &mut self,
        id: usize,
        logical: u32,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<u32, Error> {
        if let Some(page) = self
            .cache
            .iter()
            .find(|p| p.valid && p.inode == id && p.logical == logical)
        {
            return Ok(page.physical);
        }
        let inode = self.inodes[id];
        if let Ok(home) = physical(&inode, logical) {
            return Ok(home);
        }
        if inode.ext_block == 0 {
            return Err(Error::Range);
        }
        let page = j
            .read_block_scratch(d, inode.ext_block, s)
            .map_err(journal_error)?;
        let mut committed = inode;
        committed.size = self.committed_size[id];
        let integrity = (|| {
            ExtentBlock::validate_bytes_for(page, id as u32, &committed)
                .map_err(|_| Error::Format)?;
            for index in 0..usize::from(committed.ext_count) {
                let extent =
                    ExtentBlock::extent_from_bytes(page, index).map_err(|_| Error::Format)?;
                if logical >= extent.logical_start
                    && logical - extent.logical_start < extent.block_count
                {
                    return Ok(extent.physical_start + logical - extent.logical_start);
                }
            }
            Err(Error::Range)
        })();
        self.guard_integrity(integrity, j, d, s)
    }

    pub(super) fn cow_directory<D: BlockDevice>(
        &mut self,
        parent: usize,
        index: usize,
        entry: DirectoryEntry<'_>,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
    ) -> Result<(Inode, u32), Error> {
        let old = self.inodes[parent];
        let home = self.reserve_block(&[], j, d, s)?;
        let logical = index as u32 / 32;
        let mut map = [0; FILE_BLOCKS];
        load_map(parent, &old, j, d, s, &mut map)?;
        let at = self.tx_load(home, true, j, d, s)?;
        if map[logical as usize] != 0 {
            j.read_block(d, map[logical as usize], &mut self.tx[at], s)
                .map_err(journal_error)?;
        } else {
            // An empty directory slot has a canonical CRC, not an all-zero image.
            for slot in self.tx[at].chunks_exact_mut(128) {
                DirectoryEntry::EMPTY
                    .encode(slot)
                    .map_err(|_| Error::Format)?;
            }
        }
        entry
            .encode(&mut self.tx[at][index % 32 * 128..(index % 32 + 1) * 128])
            .map_err(|_| Error::Format)?;
        let new_size = old.size.max((index + 1) as u64 * 128);
        let valid =
            (new_size - u64::from(logical) * BLOCK_SIZE as u64).min(BLOCK_SIZE as u64) as usize;
        self.tx[at][valid..].fill(0);
        map[logical as usize] = home;
        let mut parent_inode = old;
        parent_inode.durable_write_seq = old
            .durable_write_seq
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let (parent_inode, indirect) = mapped_inode(
            parent,
            parent_inode,
            old.size.max((index + 1) as u64 * 128),
            &map,
            0,
        )?;
        if indirect.is_some() {
            return Err(Error::Format);
        } // A directory has at most eight blocks.
        self.tx_bit(home, true, j, d, s)?;
        self.tx_inode(parent, parent_inode, j, d, s)?;
        Ok((parent_inode, home))
    }
}
