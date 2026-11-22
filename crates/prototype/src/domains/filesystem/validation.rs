//! Streaming namespace validation. A collector supplies exactly 48 KiB:
//! 16 KiB mark, 16 KiB per-view ownership, and 16 KiB inode/name scan scratch.
//! Inodes are decoded from the committed logical view one at a time. The
//! journal's existing 8 KiB I/O scratch is reused, never a second inode table.
use super::*;
use crate::storage::{BOOT_BLOCK, CLUSTER_INODES, REQUEST_INODE, SNAPSHOT_REQUEST_START};

pub const GC_SCRATCH_BYTES: usize = 48 * 1024;

pub fn validate_volume<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    work: &mut [[u8; BLOCK_SIZE]; 4],
) -> Result<(), Error> {
    let mut bitmap = [0; MAP_BYTES];
    for map in 0..4 {
        let page = j
            .read_block_scratch(d, BITMAP_START + map as u32, s)
            .map_err(journal_error)?;
        bitmap[map * BLOCK_SIZE..(map + 1) * BLOCK_SIZE].copy_from_slice(page);
    }
    validate_system(&bitmap, j, d, s)?;
    let mut owners = [0; MAP_BYTES];
    validate_disk_tree(INODE_START, &bitmap, None, &mut owners, work, j, d, s)
}

pub(super) fn read_inode<D: BlockDevice>(
    first: u32,
    id: usize,
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
) -> Result<Inode, Error> {
    if id >= 256 {
        return Err(Error::Format);
    }
    let page = j
        .read_block_scratch(d, first + id as u32 / 16, s)
        .map_err(journal_error)?;
    Inode::decode(id as u32, &page[id % 16 * 256..(id % 16 + 1) * 256]).map_err(|_| Error::Format)
}

pub(super) fn load_table<D: BlockDevice>(
    inodes: &mut [Inode; 256],
    first: u32,
    pages: usize,
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    page: &mut [u8; BLOCK_SIZE],
) -> Result<(), Error> {
    for table in 0..pages {
        j.read_block(d, first + table as u32, page, s)
            .map_err(journal_error)?;
        for slot in 0..16 {
            let id = table * 16 + slot;
            inodes[id] = Inode::decode(id as u32, &page[slot * 256..(slot + 1) * 256])
                .map_err(|_| Error::Format)?;
        }
    }
    Ok(())
}

pub(super) fn load_and_validate<D: BlockDevice>(
    inodes: &mut [Inode; 256],
    bitmap: &mut [u8; MAP_BYTES],
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    work: &mut [[u8; BLOCK_SIZE]; 4],
) -> Result<(), Error> {
    load_table(inodes, INODE_START, 16, j, d, s, &mut work[0])?;
    for map in 0..4 {
        let page = j
            .read_block_scratch(d, BITMAP_START + map as u32, s)
            .map_err(journal_error)?;
        bitmap[map * BLOCK_SIZE..(map + 1) * BLOCK_SIZE].copy_from_slice(page);
    }
    validate_system(bitmap, j, d, s)?;
    let mut owners = [0; MAP_BYTES];
    validate_disk_tree(INODE_START, bitmap, None, &mut owners, work, j, d, s)
}

fn single(inode: &Inode, kind: InodeKind, size: u64, home: u32, count: u32) -> bool {
    inode.kind == kind
        && inode.size == size
        && inode.extent_count == 1
        && inode.ext_count == 0
        && inode.extents[0]
            == (Extent {
                logical_start: 0,
                physical_start: home,
                block_count: count,
            })
}
fn validate_system<D: BlockDevice>(
    bitmap: &[u8; MAP_BYTES],
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
) -> Result<(), Error> {
    for block in 0..FIRST_BUSINESS_BLOCK {
        if bitmap[block as usize / 8] & (1 << (block % 8)) == 0 {
            return Err(Error::Conflict);
        }
    }
    let root = read_inode(INODE_START, SYSTEM_ROOT_INODE as usize, j, d, s)?;
    let boot = read_inode(INODE_START, BOOT_INODE as usize, j, d, s)?;
    let requests = read_inode(INODE_START, REQUEST_INODE as usize, j, d, s)?;
    if !single(&root, InodeKind::Directory, 512, DATA_START, 1)
        || !single(&boot, InodeKind::File, 64, BOOT_BLOCK, 1)
        || !single(
            &requests,
            InodeKind::File,
            65536,
            SNAPSHOT_REQUEST_START,
            16,
        )
    {
        return Err(Error::Conflict);
    }
    for (file, &id) in CLUSTER_INODES.iter().enumerate() {
        if !crate::cluster::volume::valid_file(
            file,
            &read_inode(INODE_START, id as usize, j, d, s)?,
        ) {
            return Err(Error::Conflict);
        }
    }
    for id in REQUEST_INODE as usize + 1..256 {
        if read_inode(INODE_START, id, j, d, s)?.kind != InodeKind::Free {
            return Err(Error::Conflict);
        }
    }
    let ids = [
        BOOT_INODE,
        CLUSTER_INODES[0],
        CLUSTER_INODES[1],
        REQUEST_INODE,
    ];
    let names = [
        ".cyxia-boot",
        crate::cluster::volume::NAMES[0],
        crate::cluster::volume::NAMES[1],
        ".cyxia-snapshot-requests",
    ];
    for n in 0..4 {
        let inode = read_inode(INODE_START, ids[n] as usize, j, d, s)?;
        let page = j
            .read_block_scratch(d, DATA_START, s)
            .map_err(journal_error)?;
        let e = DirectoryEntry::decode(&page[n * 128..(n + 1) * 128]).map_err(|_| Error::Format)?;
        if e.inode_id != ids[n]
            || e.inode_generation != inode.generation
            || e.name != names[n]
            || inode.parent_inode != SYSTEM_ROOT_INODE
            || inode.parent_generation != 1
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn own(block: u32, bitmap: &[u8; MAP_BYTES], owners: &mut [u8; MAP_BYTES]) -> Result<(), Error> {
    if !(FIRST_BUSINESS_BLOCK..TOTAL_BLOCKS).contains(&block) {
        return Err(Error::Conflict);
    }
    let byte = block as usize / 8;
    let mask = 1 << (block % 8);
    if owners[byte] & mask != 0 || bitmap[byte] & mask == 0 {
        return Err(Error::Conflict);
    }
    owners[byte] |= mask;
    Ok(())
}

/// Validate one business tree with no allocation proportional to inode count.
/// Unique ownership is checked independently for each view; valid historical
/// sharing is accumulated into the optional union mark. Allocated garbage is
/// retained until collection proves it unreachable from every protected root.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_disk_tree<D: BlockDevice>(
    inode_first: u32,
    bitmap: &[u8; MAP_BYTES],
    mark: Option<&mut [u8; MAP_BYTES]>,
    owners: &mut [u8; MAP_BYTES],
    scan: &mut [[u8; BLOCK_SIZE]; 4],
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
) -> Result<(), Error> {
    owners.fill(0);
    for block in 0..FIRST_BUSINESS_BLOCK {
        owners[block as usize / 8] |= 1 << (block % 8);
    }
    let mut references = [0u16; BUSINESS_INODE_COUNT as usize];
    let mut cached_inode_page = None;
    for id in 0..BUSINESS_INODE_COUNT as usize {
        // Reuse one scan page until a directory needs the complete name bank.
        // In particular, free inode slots must not trigger 16 repeated disk
        // reads of the same metadata page in the native paid service path.
        let home = inode_first + id as u32 / 16;
        if cached_inode_page != Some(home) {
            j.read_block(d, home, &mut scan[0], s)
                .map_err(journal_error)?;
            cached_inode_page = Some(home);
        }
        let inode = Inode::decode(id as u32, &scan[0][id % 16 * 256..(id % 16 + 1) * 256])
            .map_err(|_| Error::Format)?;
        if id == 0 && inode.kind != InodeKind::Directory {
            return Err(Error::Conflict);
        }
        if inode.kind == InodeKind::Free {
            continue;
        }
        let mut last = 0;
        for extent in &inode.extents[..usize::from(inode.extent_count)] {
            for block in extent.physical_start..extent.physical_start + extent.block_count {
                own(block, bitmap, owners)?;
                last = block;
            }
        }
        if inode.ext_block != 0 {
            own(inode.ext_block, bitmap, owners)?;
            let page = j
                .read_block_scratch(d, inode.ext_block, s)
                .map_err(journal_error)?;
            ExtentBlock::validate_bytes_for(page, id as u32, &inode).map_err(|_| Error::Format)?;
            for index in 0..usize::from(inode.ext_count) {
                let extent =
                    ExtentBlock::extent_from_bytes(page, index).map_err(|_| Error::Format)?;
                for block in extent.physical_start..extent.physical_start + extent.block_count {
                    own(block, bitmap, owners)?;
                    last = block;
                }
            }
        }
        let tail = inode.size as usize % BLOCK_SIZE;
        if tail != 0 {
            let page = j.read_block_scratch(d, last, s).map_err(journal_error)?;
            if page[tail..].iter().any(|&byte| byte != 0) {
                return Err(Error::Format);
            }
        }
        if id != 0 {
            let mut child = inode;
            let mut reached_root = false;
            for _ in 0..BUSINESS_INODE_COUNT {
                let parent_id = child.parent_inode as usize;
                if parent_id >= BUSINESS_INODE_COUNT as usize {
                    return Err(Error::Conflict);
                }
                let parent = read_inode(inode_first, parent_id, j, d, s)?;
                if parent.kind != InodeKind::Directory
                    || parent.generation != child.parent_generation
                {
                    return Err(Error::Stale);
                }
                if parent_id == 0 {
                    reached_root = true;
                    break;
                }
                if parent_id == id {
                    return Err(Error::Conflict);
                }
                child = parent;
            }
            if !reached_root {
                return Err(Error::Conflict);
            }
        }
        if inode.kind != InodeKind::Directory || inode.size == 0 {
            continue;
        }
        cached_inode_page = None;
        let names = scan.as_flattened_mut();
        names.fill(0);
        for index in 0..inode.size as usize / 128 {
            let page = j
                .read_block_scratch(d, physical(&inode, index as u32 / 32)?, s)
                .map_err(journal_error)?;
            let entry = DirectoryEntry::decode(&page[index % 32 * 128..(index % 32 + 1) * 128])
                .map_err(|_| Error::Format)?;
            if entry == DirectoryEntry::EMPTY {
                continue;
            }
            let target_id = entry.inode_id as usize;
            let generation = entry.inode_generation;
            if target_id == 0 || target_id >= BUSINESS_INODE_COUNT as usize {
                return Err(Error::Conflict);
            }
            let bytes = entry.name.as_bytes();
            for old in 0..index {
                if usize::from(names[old * 64]) == bytes.len()
                    && names[old * 64 + 1..old * 64 + 1 + bytes.len()] == *bytes
                {
                    return Err(Error::Exists);
                }
            }
            names[index * 64] = bytes.len() as u8;
            names[index * 64 + 1..index * 64 + 1 + bytes.len()].copy_from_slice(bytes);
            let target = read_inode(inode_first, target_id, j, d, s)?;
            if target.kind == InodeKind::Free
                || target.generation != generation
                || target.parent_inode as usize != id
                || target.parent_generation != inode.generation
            {
                return Err(Error::Stale);
            }
            references[target_id] = references[target_id]
                .checked_add(1)
                .ok_or(Error::Overflow)?;
        }
    }
    // The final reference audit is another sequential page pass. Keep full
    // inode decoding and every reference check, without a second inode table.
    for first in (0..BUSINESS_INODE_COUNT as usize).step_by(16) {
        j.read_block(d, inode_first + first as u32 / 16, &mut scan[0], s)
            .map_err(journal_error)?;
        for slot in 0..16 {
            let id = first + slot;
            let inode = Inode::decode(id as u32, &scan[0][slot * 256..(slot + 1) * 256])
                .map_err(|_| Error::Format)?;
            if id != 0 && references[id] != u16::from(inode.kind != InodeKind::Free) {
                return Err(Error::Conflict);
            }
        }
    }
    if let Some(mark) = mark {
        for (target, &source) in mark.iter_mut().zip(owners.iter()) {
            *target |= source;
        }
    }
    Ok(())
}
