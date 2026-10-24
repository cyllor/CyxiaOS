use cyxia_prototype::{
    boot::{BootSession, Error as BootError},
    journal::{self, BlockDevice, Journal},
    storage::{BLOCK_SIZE, DATA_START, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;
#[derive(Default)]
struct Disk {
    durable: BTreeMap<u32, Box<[u8; BLOCK_SIZE]>>,
    pending: BTreeMap<u32, Box<[u8; BLOCK_SIZE]>>,
    fail_flush: bool,
    lose_flush_response: Option<u32>,
}
impl Disk {
    fn crash(&mut self) {
        self.pending.clear();
        self.fail_flush = false;
    }
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, n: u32, b: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        if let Some(bytes) = self.pending.get(&n).or_else(|| self.durable.get(&n)) {
            b.copy_from_slice(bytes.as_ref());
        } else {
            b.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, n: u32, b: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        self.pending.insert(n, Box::new(*b));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        if self.fail_flush {
            return Err(());
        }
        self.durable.append(&mut self.pending);
        if let Some(left) = self.lose_flush_response.as_mut() {
            *left -= 1;
            if *left == 0 {
                self.lose_flush_response = None;
                return Err(());
            }
        }
        Ok(())
    }
}
fn fixture() -> (Disk, Journal) {
    let mut disk = Disk::default();
    journal::format(&mut disk, [7; 16], &mut [0; 8192]).unwrap();
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut [0; 8192]).unwrap();
    (disk, journal)
}
#[test]
fn boot_counter_recovers_from_journal_without_home_checkpoint() {
    let (mut disk, mut journal) = fixture();
    let first = BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    assert_eq!(first.epoch, 1);
    assert_eq!(first.filesystem, [7; 16]);
    assert!(!disk.durable.contains_key(&(DATA_START + 1)));
    disk.crash();
    let mut journal = Journal::new();
    let recovery = journal.mount(&mut disk, &mut [0; 8192]).unwrap();
    assert_eq!(recovery.committed_transactions, 1);
    assert_eq!(recovery.replayed_blocks, 4);
    let second = BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    assert_eq!(second.epoch, 2);
    assert_eq!(second.filesystem, first.filesystem);
}
#[test]
fn boot_owner_cannot_allocate_again_for_a_service_restart() {
    let (mut disk, mut journal) = fixture();
    let mut session = BootSession::new();
    session
        .allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    assert_eq!(
        session.allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4]
        ),
        Err(BootError::AlreadyAttempted)
    );
}
#[test]
fn uncertain_flush_prevents_any_new_authority_this_boot() {
    let (mut disk, mut journal) = fixture();
    let mut session = BootSession::new();
    disk.fail_flush = true;
    assert!(
        session
            .allocate(
                &mut journal,
                &mut disk,
                &mut [0; 8192],
                &mut [[0; BLOCK_SIZE]; 4]
            )
            .is_err()
    );
    assert!(!journal.is_writable());
    assert_eq!(
        session.allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4]
        ),
        Err(BootError::AlreadyAttempted)
    );
    disk.crash();
    let mut recovered = Journal::new();
    recovered.mount(&mut disk, &mut [0; 8192]).unwrap();
    assert_eq!(
        BootSession::new()
            .allocate(
                &mut recovered,
                &mut disk,
                &mut [0; 8192],
                &mut [[0; BLOCK_SIZE]; 4]
            )
            .unwrap()
            .epoch,
        1
    );
}
#[test]
fn corrupted_boot_body_is_never_reset_to_one() {
    let (mut disk, mut journal) = fixture();
    BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    journal.checkpoint(&mut disk, &mut [0; 8192]).unwrap();
    disk.durable.get_mut(&(DATA_START + 1)).unwrap()[24] ^= 1;
    let mut recovered = Journal::new();
    recovered.mount(&mut disk, &mut [0; 8192]).unwrap();
    assert_eq!(
        BootSession::new().allocate(
            &mut recovered,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4]
        ),
        Err(BootError::Layout)
    );
}

#[test]
fn lost_second_flush_response_preserves_unknown_and_recovers_committed_epoch() {
    let (mut disk, mut journal) = fixture();
    disk.lose_flush_response = Some(2);
    let mut owner = BootSession::new();
    assert!(
        owner
            .allocate(
                &mut journal,
                &mut disk,
                &mut [0; 8192],
                &mut [[0; BLOCK_SIZE]; 4]
            )
            .is_err()
    );
    assert!(!journal.is_writable());
    assert_eq!(
        owner.allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4]
        ),
        Err(BootError::AlreadyAttempted)
    );
    disk.crash();
    let mut recovered = Journal::new();
    assert_eq!(
        recovered
            .mount(&mut disk, &mut [0; 8192])
            .unwrap()
            .committed_transactions,
        1
    );
    assert_eq!(
        BootSession::new()
            .allocate(
                &mut recovered,
                &mut disk,
                &mut [0; 8192],
                &mut [[0; BLOCK_SIZE]; 4]
            )
            .unwrap()
            .epoch,
        2
    );
}

#[test]
fn counter_exhaustion_never_wraps_or_mutates_storage() {
    use cyxia_prototype::storage::{INODE_START, Inode, crc32c};
    let (mut disk, mut journal) = fixture();
    BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    journal.checkpoint(&mut disk, &mut [0; 8192]).unwrap();
    let table = disk.durable.get_mut(&INODE_START).unwrap();
    let mut inode = Inode::decode(1, &table[256..512]).unwrap();
    inode.durable_write_seq = u64::MAX;
    inode.encode(1, &mut table[256..512]).unwrap();
    let body = disk.durable.get_mut(&(DATA_START + 1)).unwrap();
    body[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    let crc = crc32c(&body[..32]);
    body[32..36].copy_from_slice(&crc.to_le_bytes());
    let mut recovered = Journal::new();
    recovered.mount(&mut disk, &mut [0; 8192]).unwrap();
    let before = disk.durable.clone();
    assert_eq!(
        BootSession::new().allocate(
            &mut recovered,
            &mut disk,
            &mut [0; 8192],
            &mut [[0; BLOCK_SIZE]; 4]
        ),
        Err(BootError::Exhausted)
    );
    assert!(disk.pending.is_empty());
    assert_eq!(disk.durable, before);
}

#[test]
fn bitmap_mismatch_and_orphan_inode_do_not_allocate_boot_authority() {
    use cyxia_prototype::storage::{BITMAP_START, INODE_START, Inode, InodeKind};
    for orphan in [false, true] {
        let (mut disk, mut journal) = fixture();
        if orphan {
            let table = disk.durable.get_mut(&INODE_START).unwrap();
            let mut inode = Inode::decode(2, &table[512..768]).unwrap();
            inode.kind = InodeKind::File;
            inode.parent_generation = 1;
            inode.encode(2, &mut table[512..768]).unwrap();
        } else {
            disk.durable.get_mut(&BITMAP_START).unwrap()[1024] = 1;
        }
        assert_eq!(
            BootSession::new().allocate(
                &mut journal,
                &mut disk,
                &mut [0; 8192],
                &mut [[0; BLOCK_SIZE]; 4]
            ),
            Err(BootError::Layout)
        );
        assert!(disk.pending.is_empty());
    }
}
