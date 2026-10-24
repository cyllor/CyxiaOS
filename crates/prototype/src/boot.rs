//! Durable boot counter in an ordinary, allocated root file.
//!
//! This minimal provisioner accepts a fresh filesystem or its own existing
//! `.cyxia-boot`, reserved cluster files and globally validated ordinary files. The boot owner
//! constructs one `BootSession` and passes the returned identity to restarted
//! services; they must never allocate another epoch within the same boot.
use crate::{
    journal::{AfterImage, BlockDevice, Journal, Scratch},
    storage::{
        self, BITMAP_START, BLOCK_SIZE, DATA_START, DirectoryEntry, Extent, INODE_START, Inode,
        InodeKind,
    },
};

const NAME: &str = ".cyxia-boot";
const MAGIC: &[u8; 8] = b"CYXBOOT1";
pub type BootScratch = [[u8; BLOCK_SIZE]; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootIdentity {
    pub filesystem: [u8; 16],
    pub epoch: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    AlreadyAttempted,
    Layout,
    Exhausted,
    Format(storage::Error),
    Journal(crate::journal::Error<E>),
}

/// One instance belongs to boot orchestration, never to a restartable service.
pub struct BootSession {
    attempted: bool,
}
impl Default for BootSession {
    fn default() -> Self {
        Self::new()
    }
}
impl BootSession {
    pub const fn new() -> Self {
        Self { attempted: false }
    }

    pub fn allocate<D: BlockDevice>(
        &mut self,
        journal: &mut Journal,
        device: &mut D,
        scratch: &mut Scratch,
        work: &mut BootScratch,
    ) -> Result<BootIdentity, Error<D::Error>> {
        if self.attempted {
            return Err(Error::AlreadyAttempted);
        }
        // Any failed durability operation may already have committed. A caller
        // must recover at the next boot, never retry this boot's allocation.
        self.attempted = true;
        if !journal.is_writable() {
            return Err(Error::Layout);
        }
        crate::domains::filesystem::validate_volume(journal, device, scratch, work)
            .map_err(|_| Error::Layout)?;
        let uuid = journal.superblock().fs_uuid;
        journal
            .read_block(device, INODE_START, &mut work[0], scratch)
            .map_err(Error::Journal)?;
        journal
            .read_block(device, BITMAP_START, &mut work[1], scratch)
            .map_err(Error::Journal)?;
        let mut root = Inode::decode(0, &work[0][..256]).map_err(Error::Format)?;
        let mut file = Inode::decode(1, &work[0][256..512]).map_err(Error::Format)?;
        let fresh = root.size == 0;
        let mut cluster_files = 0usize;
        let mut cluster_blocks = [0u32; 2];
        for (i, blocks) in cluster_blocks.iter_mut().enumerate() {
            let id = i + 2;
            let inode = Inode::decode(id as u32, &work[0][id * 256..id * 256 + 256])
                .map_err(Error::Format)?;
            if inode.kind != InodeKind::Free {
                if fresh || cluster_files != i || !crate::cluster::volume::valid_file(i, &inode) {
                    return Err(Error::Layout);
                }
                *blocks = inode.extents[0].block_count;
                cluster_files += 1;
            }
        }
        let epoch;
        if fresh {
            if root.extent_count != 0 || file.kind != InodeKind::Free {
                return Err(Error::Layout);
            }
            for block in [DATA_START, DATA_START + 1] {
                if bit(&work[1], block) {
                    return Err(Error::Layout);
                }
                work[1][block as usize / 8] |= 1 << (block % 8);
            }
            root.size = 128;
            root.extent_count = 1;
            root.extents[0] = Extent {
                logical_start: 0,
                physical_start: DATA_START,
                block_count: 1,
            };
            file.kind = InodeKind::File;
            file.size = 64;
            file.extent_count = 1;
            file.parent_inode = 0;
            file.parent_generation = 1;
            file.extents[0] = Extent {
                logical_start: 0,
                physical_start: DATA_START + 1,
                block_count: 1,
            };
            work[2].fill(0);
            DirectoryEntry {
                inode_id: 1,
                inode_generation: file.generation,
                name: NAME,
            }
            .encode(&mut work[2][..128])
            .map_err(Error::Format)?;
            epoch = 1;
        } else {
            if root.size < (1 + cluster_files as u64) * 128
                || root.extent_count == 0
                || root.extents[0]
                    != (Extent {
                        logical_start: 0,
                        physical_start: DATA_START,
                        block_count: 1,
                    })
                || file.kind != InodeKind::File
                || file.size != 64
                || file.extent_count != 1
                || file.extents[0]
                    != (Extent {
                        logical_start: 0,
                        physical_start: DATA_START + 1,
                        block_count: 1,
                    })
                || file.parent_inode != 0
                || file.parent_generation != root.generation
                || !bit(&work[1], DATA_START)
                || !bit(&work[1], DATA_START + 1)
            {
                return Err(Error::Layout);
            }
            journal
                .read_block(device, DATA_START, &mut work[2], scratch)
                .map_err(Error::Journal)?;
            if DirectoryEntry::decode(&work[2][..128]).map_err(Error::Format)?
                != (DirectoryEntry {
                    inode_id: 1,
                    inode_generation: file.generation,
                    name: NAME,
                })
            {
                return Err(Error::Layout);
            }
            for i in 0..cluster_files {
                let id = i + 2;
                let inode = Inode::decode(id as u32, &work[0][id * 256..id * 256 + 256])
                    .map_err(Error::Format)?;
                if DirectoryEntry::decode(&work[2][(i + 1) * 128..(i + 2) * 128])
                    .map_err(Error::Format)?
                    != (DirectoryEntry {
                        inode_id: id as u32,
                        inode_generation: inode.generation,
                        name: crate::cluster::volume::NAMES[i],
                    })
                {
                    return Err(Error::Layout);
                }
            }
            journal
                .read_block(device, DATA_START + 1, &mut work[3], scratch)
                .map_err(Error::Journal)?;
            let bytes = &work[3];
            if &bytes[..8] != MAGIC
                || bytes[8..24] != uuid
                || bytes[36..].iter().any(|&x| x != 0)
                || storage::crc32c(&bytes[..32])
                    != u32::from_le_bytes(bytes[32..36].try_into().unwrap())
            {
                return Err(Error::Layout);
            }
            let previous = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
            if previous == 0 || file.durable_write_seq != previous {
                return Err(Error::Layout);
            }
            epoch = previous.checked_add(1).ok_or(Error::Exhausted)?;
        }
        file.durable_write_seq = epoch;
        if fresh {
            root.durable_write_seq = root
                .durable_write_seq
                .checked_add(1)
                .ok_or(Error::Exhausted)?;
        }
        root.encode(0, &mut work[0][..256]).map_err(Error::Format)?;
        file.encode(1, &mut work[0][256..512])
            .map_err(Error::Format)?;
        work[3].fill(0);
        work[3][..8].copy_from_slice(MAGIC);
        work[3][8..24].copy_from_slice(&uuid);
        work[3][24..32].copy_from_slice(&epoch.to_le_bytes());
        let crc = storage::crc32c(&work[3][..32]);
        work[3][32..36].copy_from_slice(&crc.to_le_bytes());
        let images = [
            AfterImage {
                home_block: INODE_START,
                bytes: &work[0],
            },
            AfterImage {
                home_block: DATA_START + 1,
                bytes: &work[3],
            },
            AfterImage {
                home_block: BITMAP_START,
                bytes: &work[1],
            },
            AfterImage {
                home_block: DATA_START,
                bytes: &work[2],
            },
        ];
        journal
            .commit(device, &images[..if fresh { 4 } else { 2 }], scratch)
            .map_err(Error::Journal)?;
        Ok(BootIdentity {
            filesystem: uuid,
            epoch,
        })
    }
}

fn bit(bytes: &[u8; BLOCK_SIZE], block: u32) -> bool {
    bytes[block as usize / 8] & (1 << (block % 8)) != 0
}
