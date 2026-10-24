//! Two ordinary contiguous growing files reserve sixteen MiB. Append and inode,
//! allocation and directory publication share one journal transaction.
use crate::{
    journal::{self, AfterImage, BlockDevice, Journal, Scratch},
    storage::{
        self, BITMAP_START, BLOCK_SIZE, DATA_START, DirectoryEntry, Extent, INODE_START, Inode,
        InodeKind,
    },
};
pub type VolumeScratch = [[u8; 4096]; 16];
pub const NAMES: [&str; 2] = [".cyxia-cluster-a", ".cyxia-cluster-b"];
pub const FILE_BLOCKS: u32 = 2048;
pub const START: u32 = DATA_START + 2;
pub const CLOSE_RESERVE: u64 = 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Layout,
    Capacity,
    Journal(journal::Error<E>),
    Format(storage::Error),
}
pub struct Volume {
    sizes: [u64; 2],
}
#[derive(Clone, Copy, Default)]
pub struct Cursor {
    file: usize,
    offset: u64,
}
impl Cursor {
    pub const fn new() -> Self {
        Self { file: 0, offset: 0 }
    }
}
impl Volume {
    pub fn open<D: BlockDevice>(
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        w: &mut VolumeScratch,
    ) -> Result<Self, Error<D::Error>> {
        j.read_block(d, INODE_START, &mut w[0], s)
            .map_err(Error::Journal)?;
        let mut sizes = [0; 2];
        for (i, size) in sizes.iter_mut().enumerate() {
            let id = i + 2;
            let f =
                Inode::decode(id as u32, &w[0][id * 256..id * 256 + 256]).map_err(Error::Format)?;
            if f.kind == InodeKind::Free {
                continue;
            }
            if !valid_file(i, &f) {
                return Err(Error::Layout);
            }
            *size = f.size;
        }
        Ok(Self { sizes })
    }
    pub fn used(&self) -> u64 {
        self.sizes[0] + self.sizes[1]
    }
    pub fn append<D: BlockDevice>(
        &mut self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        w: &mut VolumeScratch,
        body: &[u8],
        closing: bool,
    ) -> Result<(), Error<D::Error>> {
        if body.is_empty() || body.len() > super::MAX_EFFECT {
            return Err(Error::Capacity);
        }
        let len = 16 + body.len();
        if !closing && self.used() + len as u64 > 16 * 1024 * 1024 - CLOSE_RESERVE {
            return Err(Error::Capacity);
        }
        let file = if self.sizes[0] + len as u64 <= 8 * 1024 * 1024 && self.sizes[1] == 0 {
            0
        } else {
            1
        };
        let old = self.sizes[file];
        let new = old.checked_add(len as u64).ok_or(Error::Capacity)?;
        if new > 8 * 1024 * 1024 || (!closing && file == 1 && new > 8 * 1024 * 1024 - CLOSE_RESERVE)
        {
            return Err(Error::Capacity);
        }
        let first = old as usize / BLOCK_SIZE;
        let last = (new as usize - 1) / BLOCK_SIZE;
        let count = last - first + 1;
        if count > 12 {
            return Err(Error::Capacity);
        }
        for i in 0..count {
            if (first + i) as u64 * (BLOCK_SIZE as u64) < old {
                j.read_block(
                    d,
                    START + file as u32 * FILE_BLOCKS + (first + i) as u32,
                    &mut w[i],
                    s,
                )
                .map_err(Error::Journal)?;
            } else {
                w[i].fill(0)
            }
        }
        let mut header = [0; 16];
        header[..4].copy_from_slice(b"CXV1");
        header[4..8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        header[8..12].copy_from_slice(&storage::crc32c(body).to_le_bytes());
        let crc = storage::crc32c(&header[..12]);
        header[12..16].copy_from_slice(&crc.to_le_bytes());
        for (i, byte) in header.iter().chain(body).enumerate() {
            let at = old as usize % BLOCK_SIZE + i;
            w[at / BLOCK_SIZE][at % BLOCK_SIZE] = *byte;
        }
        j.read_block(d, INODE_START, &mut w[12], s)
            .map_err(Error::Journal)?;
        j.read_block(d, BITMAP_START, &mut w[13], s)
            .map_err(Error::Journal)?;
        j.read_block(d, DATA_START, &mut w[14], s)
            .map_err(Error::Journal)?;
        let id = (file + 2) as u32;
        let at = id as usize * 256;
        let mut inode = Inode::decode(id, &w[12][at..at + 256]).map_err(Error::Format)?;
        let fresh = inode.kind == InodeKind::Free;
        if (!fresh && (!valid_file(file, &inode) || inode.size != old)) || (fresh && old != 0) {
            return Err(Error::Layout);
        }
        inode.kind = InodeKind::File;
        inode.parent_inode = 0;
        inode.parent_generation = 1;
        inode.size = new;
        inode.durable_write_seq = inode
            .durable_write_seq
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        inode.extent_count = 1;
        inode.extents[0] = Extent {
            logical_start: 0,
            physical_start: START + file as u32 * FILE_BLOCKS,
            block_count: new.div_ceil(BLOCK_SIZE as u64) as u32,
        };
        inode
            .encode(id, &mut w[12][at..at + 256])
            .map_err(Error::Format)?;
        for block in old.div_ceil(BLOCK_SIZE as u64) as u32..inode.extents[0].block_count {
            let n = START + file as u32 * FILE_BLOCKS + block;
            let index = n as usize / 8;
            if w[13][index] & (1 << (n % 8)) != 0 {
                return Err(Error::Layout);
            }
            w[13][index] |= 1 << (n % 8);
        }
        if fresh {
            let mut root = Inode::decode(0, &w[12][..256]).map_err(Error::Format)?;
            if root.size != (file as u64 + 1) * 128 {
                return Err(Error::Layout);
            }
            root.size += 128;
            root.durable_write_seq = root
                .durable_write_seq
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            root.encode(0, &mut w[12][..256]).map_err(Error::Format)?;
            DirectoryEntry {
                inode_id: id,
                inode_generation: inode.generation,
                name: NAMES[file],
            }
            .encode(&mut w[14][(file + 1) * 128..(file + 2) * 128])
            .map_err(Error::Format)?;
        }
        let mut images = [AfterImage {
            home_block: INODE_START,
            bytes: &w[12],
        }; 15];
        for i in 0..count {
            images[i] = AfterImage {
                home_block: START + file as u32 * FILE_BLOCKS + (first + i) as u32,
                bytes: &w[i],
            };
        }
        images[count] = AfterImage {
            home_block: INODE_START,
            bytes: &w[12],
        };
        images[count + 1] = AfterImage {
            home_block: BITMAP_START,
            bytes: &w[13],
        };
        images[count + 2] = AfterImage {
            home_block: DATA_START,
            bytes: &w[14],
        };
        let needed = (count as u32 + 3) * 2 + 2;
        if j.remaining_log_blocks() < needed {
            j.checkpoint(d, s).map_err(Error::Journal)?;
        }
        j.commit(d, &images[..count + 3], s)
            .map_err(Error::Journal)?;
        self.sizes[file] = new;
        Ok(())
    }
    pub fn next<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        w: &mut VolumeScratch,
        c: &mut Cursor,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error<D::Error>> {
        while c.file < 2 && c.offset == self.sizes[c.file] {
            c.file += 1;
            c.offset = 0;
        }
        if c.file >= 2 {
            return Ok(None);
        }
        let mut header = [0; 16];
        self.read(j, d, s, &mut w[0], c.file, c.offset, &mut header)?;
        let len = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if &header[..4] != b"CXV1"
            || storage::crc32c(&header[..12])
                != u32::from_le_bytes(header[12..16].try_into().unwrap())
            || len == 0
            || len > super::MAX_EFFECT
            || len > out.len()
            || c.offset + 16 + len as u64 > self.sizes[c.file]
        {
            return Err(Error::Layout);
        }
        self.read(j, d, s, &mut w[0], c.file, c.offset + 16, &mut out[..len])?;
        if storage::crc32c(&out[..len]) != u32::from_le_bytes(header[8..12].try_into().unwrap()) {
            return Err(Error::Layout);
        }
        c.offset += 16 + len as u64;
        Ok(Some(len))
    }
    fn read<D: BlockDevice>(
        &self,
        j: &mut Journal,
        d: &mut D,
        s: &mut Scratch,
        w: &mut [u8; 4096],
        file: usize,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        let mut done = 0;
        while done < out.len() {
            let at = offset as usize + done;
            j.read_block(
                d,
                START + file as u32 * FILE_BLOCKS + (at / 4096) as u32,
                w,
                s,
            )
            .map_err(Error::Journal)?;
            let n = (4096 - at % 4096).min(out.len() - done);
            out[done..done + n].copy_from_slice(&w[at % 4096..at % 4096 + n]);
            done += n;
        }
        Ok(())
    }
}
pub(crate) fn valid_file(i: usize, f: &Inode) -> bool {
    f.kind == InodeKind::File
        && f.size > 0
        && f.size <= 8 * 1024 * 1024
        && f.parent_inode == 0
        && f.parent_generation == 1
        && f.extent_count == 1
        && f.extents[0]
            == (Extent {
                logical_start: 0,
                physical_start: START + i as u32 * FILE_BLOCKS,
                block_count: f.size.div_ceil(BLOCK_SIZE as u64) as u32,
            })
}
