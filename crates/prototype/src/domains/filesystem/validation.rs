use super::*;

pub fn validate_volume<D: BlockDevice>(
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    work: &mut [[u8; BLOCK_SIZE]; 4],
) -> Result<(), Error> {
    let mut inodes = [EMPTY_INODE; 256];
    let mut bitmap = [0; MAP_BYTES];
    load_and_validate(&mut inodes, &mut bitmap, j, d, s, work)
}

pub(super) fn load_and_validate<D: BlockDevice>(
    inodes: &mut [Inode; 256],
    bitmap: &mut [u8; MAP_BYTES],
    j: &mut Journal,
    d: &mut D,
    s: &mut Scratch,
    work: &mut [[u8; BLOCK_SIZE]; 4],
) -> Result<(), Error> {
    for table in 0..16 {
        j.read_block(d, INODE_START + table as u32, &mut work[0], s)
            .map_err(journal_error)?;
        for slot in 0..16 {
            let id = table * 16 + slot;
            inodes[id] = Inode::decode(id as u32, &work[0][slot * 256..slot * 256 + 256])
                .map_err(|_| Error::Format)?;
        }
    }
    for map in 0..4 {
        j.read_block(d, BITMAP_START + map as u32, &mut work[0], s)
            .map_err(journal_error)?;
        bitmap[map * BLOCK_SIZE..(map + 1) * BLOCK_SIZE].copy_from_slice(&work[0]);
    }
    let mut owners = [0u8; MAP_BYTES];
    for block in 0..DATA_START {
        owners[block as usize / 8] |= 1 << (block % 8);
    }
    for (id, inode) in inodes.iter().enumerate() {
        if inode.kind == InodeKind::Free {
            continue;
        }
        if id == 1
            && (inode.kind != InodeKind::File
                || inode.size != 64
                || inode.extent_count != 1
                || inode.extents[0]
                    != (Extent {
                        logical_start: 0,
                        physical_start: DATA_START + 1,
                        block_count: 1,
                    }))
        {
            return Err(Error::Conflict);
        }
        if (2..=3).contains(&id) && !crate::cluster::volume::valid_file(id - 2, inode) {
            return Err(Error::Conflict);
        }
        if id == 0
            && inode.size > 0
            && (inode.extent_count == 0
                || inode.extents[0].physical_start != DATA_START
                || inode.extents[0].block_count != 1)
        {
            return Err(Error::Conflict);
        }
        for extent in &inode.extents[..usize::from(inode.extent_count)] {
            for block in extent.physical_start..extent.physical_start + extent.block_count {
                if (id >= FIRST_ORDINARY_INODE || (id == 0 && block != DATA_START))
                    && block < FIRST_ORDINARY_BLOCK
                {
                    return Err(Error::Conflict);
                }
                let byte = &mut owners[block as usize / 8];
                let mask = 1 << (block % 8);
                if *byte & mask != 0 {
                    return Err(Error::Conflict);
                }
                *byte |= mask;
            }
        }
        if id != 0 {
            let parent = &inodes[inode.parent_inode as usize];
            if parent.kind != InodeKind::Directory || parent.generation != inode.parent_generation {
                return Err(Error::Stale);
            }
            let mut ancestor = inode.parent_inode as usize;
            for step in 0..256 {
                if ancestor == 0 {
                    break;
                }
                if ancestor == id || step == 255 {
                    return Err(Error::Conflict);
                }
                let next = inodes[ancestor];
                let parent = inodes[next.parent_inode as usize];
                if parent.kind != InodeKind::Directory
                    || parent.generation != next.parent_generation
                {
                    return Err(Error::Stale);
                }
                ancestor = next.parent_inode as usize;
            }
        }
    }
    if owners != *bitmap {
        return Err(Error::Conflict);
    }
    if inodes[1].kind == InodeKind::Free && inodes[0].size != 0 {
        return Err(Error::Conflict);
    }
    let mut references = [0u16; 256];
    let mut names = [[0u8; 63]; 256];
    let mut lengths = [0u8; 256];
    for (parent, inode) in inodes.iter().enumerate() {
        if inode.kind != InodeKind::Directory {
            continue;
        }
        lengths.fill(0);
        let slots = inode.size as usize / 128;
        for index in 0..slots {
            if index % 32 == 0 {
                j.read_block(d, physical(inode, index as u32 / 32)?, &mut work[0], s)
                    .map_err(journal_error)?;
            }
            let entry = DirectoryEntry::decode(&work[0][index % 32 * 128..index % 32 * 128 + 128])
                .map_err(|_| Error::Format)?;
            if entry == DirectoryEntry::EMPTY {
                continue;
            }
            let id = entry.inode_id as usize;
            let target = inodes[id];
            if id == 0
                || target.kind == InodeKind::Free
                || target.generation != entry.inode_generation
                || target.parent_inode as usize != parent
                || target.parent_generation != inode.generation
            {
                return Err(Error::Stale);
            }
            if id < FIRST_ORDINARY_INODE {
                let expected = if id == 1 {
                    ".cyxia-boot"
                } else {
                    crate::cluster::volume::NAMES[id - 2]
                };
                if parent != 0 || index != id - 1 || entry.name != expected {
                    return Err(Error::Conflict);
                }
            } else if parent == 0 && index < 3 {
                return Err(Error::Conflict);
            }
            let bytes = entry.name.as_bytes();
            for old in 0..index {
                if usize::from(lengths[old]) == bytes.len() && names[old][..bytes.len()] == *bytes {
                    return Err(Error::Exists);
                }
            }
            names[index][..bytes.len()].copy_from_slice(bytes);
            lengths[index] = bytes.len() as u8;
            references[id] = references[id].checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    for id in 1..256 {
        if references[id] != u16::from(inodes[id].kind != InodeKind::Free) {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
