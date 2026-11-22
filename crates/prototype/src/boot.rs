//! Durable boot counter in a preallocated, non-revertible system object.
//!
//! The formatter creates `.cyxia-boot` under the separate system root. The boot owner
//! constructs one `BootSession` and passes the returned identity to restarted
//! services; they must never allocate another epoch within the same boot.
use crate::{
    journal::{AfterImage, BlockDevice, Journal, Scratch},
    storage::{
        self, BITMAP_START, BLOCK_SIZE, BOOT_BLOCK, BOOT_INODE, DirectoryEntry, Extent,
        INODE_START, Inode, InodeKind, SYSTEM_ROOT_BLOCK, SYSTEM_ROOT_INODE,
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
        let inode_block = INODE_START + SYSTEM_ROOT_INODE / 16;
        journal
            .read_block(device, inode_block, &mut work[0], scratch)
            .map_err(Error::Journal)?;
        journal
            .read_block(device, BITMAP_START, &mut work[1], scratch)
            .map_err(Error::Journal)?;
        let root = Inode::decode(SYSTEM_ROOT_INODE, &work[0][..256]).map_err(Error::Format)?;
        let mut file = Inode::decode(BOOT_INODE, &work[0][256..512]).map_err(Error::Format)?;
        if root.size != 4 * 128
            || root.extent_count != 1
            || root.extents[0]
                != (Extent {
                    logical_start: 0,
                    physical_start: SYSTEM_ROOT_BLOCK,
                    block_count: 1,
                })
            || file.kind != InodeKind::File
            || file.size != 64
            || file.extent_count != 1
            || file.extents[0]
                != (Extent {
                    logical_start: 0,
                    physical_start: BOOT_BLOCK,
                    block_count: 1,
                })
            || file.parent_inode != SYSTEM_ROOT_INODE
            || file.parent_generation != root.generation
            || !bit(&work[1], SYSTEM_ROOT_BLOCK)
            || !bit(&work[1], BOOT_BLOCK)
        {
            return Err(Error::Layout);
        }
        journal
            .read_block(device, SYSTEM_ROOT_BLOCK, &mut work[2], scratch)
            .map_err(Error::Journal)?;
        if DirectoryEntry::decode(&work[2][..128]).map_err(Error::Format)?
            != (DirectoryEntry {
                inode_id: BOOT_INODE,
                inode_generation: file.generation,
                name: NAME,
            })
        {
            return Err(Error::Layout);
        }
        journal
            .read_block(device, BOOT_BLOCK, &mut work[3], scratch)
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
        if file.durable_write_seq != previous {
            return Err(Error::Layout);
        }
        let epoch = previous.checked_add(1).ok_or(Error::Exhausted)?;
        file.durable_write_seq = epoch;
        file.encode(BOOT_INODE, &mut work[0][256..512])
            .map_err(Error::Format)?;
        work[3][24..32].copy_from_slice(&epoch.to_le_bytes());
        let crc = storage::crc32c(&work[3][..32]);
        work[3][32..36].copy_from_slice(&crc.to_le_bytes());
        journal
            .commit(
                device,
                &[
                    AfterImage {
                        home_block: inode_block,
                        bytes: &work[0],
                    },
                    AfterImage {
                        home_block: BOOT_BLOCK,
                        bytes: &work[3],
                    },
                ],
                scratch,
            )
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
