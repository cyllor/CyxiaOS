use cyxia_prototype::journal::{self, AfterImage, BlockDevice, Error, Journal, Scratch};
use cyxia_prototype::storage::{
    self, BITMAP_START, BLOCK_SIZE, DATA_START, INODE_START, Inode, InodeKind, LogPayload, Record,
    Superblock, TOTAL_BLOCKS,
};
use std::collections::BTreeMap;

type Block = [u8; BLOCK_SIZE];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Injected,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Write(u32),
    Flush,
}
#[derive(Clone, Copy)]
enum Cut {
    Before(usize),
    After(usize),
}
#[derive(Clone, Default)]
struct Disk {
    stable: BTreeMap<u32, Box<Block>>,
    pending: BTreeMap<u32, Option<Box<Block>>>,
    operations: Vec<Operation>,
    cut: Option<Cut>,
    reads: usize,
    capacity: u32,
}
impl Disk {
    fn blank() -> Self {
        Self {
            capacity: TOTAL_BLOCKS,
            ..Self::default()
        }
    }
    fn before(&mut self, operation: Operation) -> Result<(), Fault> {
        self.operations.push(operation);
        if matches!(self.cut, Some(Cut::Before(n)) if self.operations.len() == n) {
            Err(Fault::Injected)
        } else {
            Ok(())
        }
    }
    fn after(&self) -> Result<(), Fault> {
        if matches!(self.cut, Some(Cut::After(n)) if self.operations.len() == n) {
            Err(Fault::Injected)
        } else {
            Ok(())
        }
    }
    fn power_cut(&mut self) {
        // Pending completed writes are explicitly discarded. Restart alone is
        // not the fault model; only successful FLUSH survives this cut.
        self.pending.clear();
        self.cut = None;
        self.operations.clear();
    }
    fn home(&self, block: u32) -> Block {
        self.stable.get(&block).map_or([0; BLOCK_SIZE], |v| **v)
    }
    fn corrupt(&mut self, block: u32, offset: usize) {
        self.stable.get_mut(&block).unwrap()[offset] ^= 1;
    }
}
impl BlockDevice for Disk {
    type Error = Fault;
    fn block_count(&self) -> u32 {
        self.capacity
    }
    fn read_block(&mut self, block: u32, output: &mut Block) -> Result<(), Fault> {
        assert!(block < TOTAL_BLOCKS);
        self.reads += 1;
        match self.pending.get(&block) {
            Some(Some(bytes)) => output.copy_from_slice(&bytes[..]),
            Some(None) => output.fill(0),
            None => output.copy_from_slice(&self.home(block)),
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &Block) -> Result<(), Fault> {
        assert!(block < TOTAL_BLOCKS);
        self.before(Operation::Write(block))?;
        self.pending.insert(
            block,
            if bytes.iter().all(|&x| x == 0) {
                None
            } else {
                Some(Box::new(*bytes))
            },
        );
        self.after()
    }
    fn flush(&mut self) -> Result<(), Fault> {
        self.before(Operation::Flush)?;
        for (block, bytes) in std::mem::take(&mut self.pending) {
            match bytes {
                Some(bytes) => {
                    self.stable.insert(block, bytes);
                }
                None => {
                    self.stable.remove(&block);
                }
            }
        }
        self.after()
    }
}
fn scratch() -> Scratch {
    [0; 2 * BLOCK_SIZE]
}
fn formatted() -> Disk {
    let mut disk = Disk::blank();
    journal::format(&mut disk, [0x42; 16], &mut scratch()).unwrap();
    disk.operations.clear();
    disk.reads = 0;
    disk
}
fn mounted() -> (Disk, Journal) {
    let mut disk = formatted();
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut scratch()).unwrap();
    disk.operations.clear();
    (disk, journal)
}
fn read(journal: &mut Journal, disk: &mut Disk, home: u32) -> Block {
    let mut out = [0; BLOCK_SIZE];
    journal
        .read_block(disk, home, &mut out, &mut scratch())
        .unwrap();
    out
}
fn commit(journal: &mut Journal, disk: &mut Disk, home: u32, byte: u8) -> journal::CommitReceipt {
    journal
        .commit(
            disk,
            &[AfterImage {
                home_block: home,
                bytes: &[byte; BLOCK_SIZE],
            }],
            &mut scratch(),
        )
        .unwrap()
}

#[test]
fn formatter_checks_every_block_and_publishes_valid_initial_metadata() {
    let mut disk = Disk::blank();
    let sb = journal::format(&mut disk, [7; 16], &mut scratch()).unwrap();
    assert_eq!(disk.reads, TOTAL_BLOCKS as usize);
    assert_eq!(Superblock::decode(&disk.home(0)).unwrap(), sb);
    assert_eq!(Superblock::decode(&disk.home(1)).unwrap(), sb);
    for block in 0..TOTAL_BLOCKS {
        let bitmap = disk.home(BITMAP_START + block / (BLOCK_SIZE as u32 * 8));
        let allocated =
            bitmap[(block % (BLOCK_SIZE as u32 * 8) / 8) as usize] & (1 << (block % 8)) != 0;
        assert_eq!(allocated, block < DATA_START);
    }
    for id in 0..256 {
        let bytes = disk.home(INODE_START + id / 16);
        let slot = (id % 16) as usize * 256;
        let inode = Inode::decode(id, &bytes[slot..slot + 256]).unwrap();
        assert_eq!(
            inode.kind,
            if id == 0 {
                InodeKind::Directory
            } else {
                InodeKind::Free
            }
        );
    }
    assert_eq!(
        &disk.operations[disk.operations.len() - 4..],
        &[
            Operation::Write(0),
            Operation::Flush,
            Operation::Write(1),
            Operation::Flush
        ]
    );
}

#[test]
fn formatter_rejects_any_content_size_and_bad_uuid_before_writing() {
    for target in [0, 1, DATA_START, TOTAL_BLOCKS - 1] {
        let mut disk = Disk::blank();
        disk.stable.insert(target, Box::new([1; BLOCK_SIZE]));
        assert_eq!(
            journal::format(&mut disk, [7; 16], &mut scratch()),
            Err(Error::NotBlank)
        );
        assert!(disk.operations.is_empty());
    }
    let mut disk = Disk::blank();
    disk.capacity -= 1;
    assert_eq!(
        journal::format(&mut disk, [7; 16], &mut scratch()),
        Err(Error::WrongCapacity)
    );
    let mut disk = Disk::blank();
    assert!(matches!(
        journal::format(&mut disk, [0; 16], &mut scratch()),
        Err(Error::Format(_))
    ));
    assert!(disk.operations.is_empty());
}

#[test]
fn durable_commit_is_visible_from_log_before_checkpoint_and_uses_exact_flush_order() {
    let (mut disk, mut journal) = mounted();
    let receipt = commit(&mut journal, &mut disk, DATA_START, 0xa5);
    assert_eq!(receipt.key.log_epoch, 2);
    assert_eq!(receipt.key.txid, 1);
    assert_eq!(receipt.commit_lsn, 3);
    assert_eq!(disk.home(DATA_START), [0; BLOCK_SIZE]);
    assert_eq!(
        read(&mut journal, &mut disk, DATA_START),
        [0xa5; BLOCK_SIZE]
    );
    assert_eq!(
        disk.operations,
        [
            Operation::Write(2),
            Operation::Write(3),
            Operation::Write(4),
            Operation::Flush,
            Operation::Write(5),
            Operation::Flush
        ]
    );
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    assert_eq!(disk.home(DATA_START), [0xa5; BLOCK_SIZE]);
    assert_eq!(journal.superblock().checkpoint_lsn, 3);
    assert_eq!(journal.superblock().log_epoch, 3);
}

#[test]
fn mount_always_advances_epoch_and_complete_key_never_reuses_same_identity() {
    let (mut disk, mut journal) = mounted();
    let a = commit(&mut journal, &mut disk, DATA_START, 1);
    disk.power_cut();
    let recovery = journal.mount(&mut disk, &mut scratch()).unwrap();
    assert_eq!(recovery.committed_transactions, 1);
    assert_eq!(recovery.replayed_blocks, 1);
    assert_eq!(disk.home(DATA_START), [1; BLOCK_SIZE]);
    let b = commit(&mut journal, &mut disk, DATA_START, 2);
    assert_eq!(a.key.txid, b.key.txid);
    assert_ne!(a.key, b.key);
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    let epoch = journal.superblock().log_epoch;
    let recovery = journal.mount(&mut disk, &mut scratch()).unwrap();
    assert_eq!(recovery.committed_transactions, 0);
    assert_eq!(journal.superblock().log_epoch, epoch + 1);
    assert_eq!(disk.home(DATA_START), [2; BLOCK_SIZE]);
}

#[test]
fn invalid_transactions_make_no_writes_or_publication_and_do_not_poison() {
    let (mut disk, mut journal) = mounted();
    let data = [1; BLOCK_SIZE];
    let duplicate = [AfterImage {
        home_block: DATA_START,
        bytes: &data,
    }; 2];
    assert_eq!(
        journal.commit(&mut disk, &[], &mut scratch()),
        Err(Error::Invalid)
    );
    assert_eq!(
        journal.commit(&mut disk, &duplicate, &mut scratch()),
        Err(Error::Invalid)
    );
    for home in [0, 1, BITMAP_START - 1, TOTAL_BLOCKS, u32::MAX] {
        assert_eq!(
            journal.commit(
                &mut disk,
                &[AfterImage {
                    home_block: home,
                    bytes: &data
                }],
                &mut scratch()
            ),
            Err(Error::Invalid)
        );
    }
    assert!(disk.operations.is_empty());
    assert!(journal.is_writable());
    assert_eq!(journal.last_commit_lsn(), 0);
}

#[test]
fn checkpoint_coalesces_multiple_versions_and_writes_each_home_once() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 1);
    commit(&mut journal, &mut disk, DATA_START + 1, 2);
    commit(&mut journal, &mut disk, DATA_START, 3);
    disk.operations.clear();
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    assert_eq!(
        disk.operations,
        [
            Operation::Write(DATA_START),
            Operation::Write(DATA_START + 1),
            Operation::Flush,
            Operation::Write(0),
            Operation::Flush
        ]
    );
    assert_eq!(disk.home(DATA_START), [3; BLOCK_SIZE]);
    assert_eq!(disk.home(DATA_START + 1), [2; BLOCK_SIZE]);
}

#[test]
fn every_commit_write_and_flush_boundary_loses_unflushed_data_without_false_success() {
    for after in [false, true] {
        for point in 1..=6 {
            let (mut disk, mut journal) = mounted();
            disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            assert_eq!(
                journal.commit(
                    &mut disk,
                    &[AfterImage {
                        home_block: DATA_START,
                        bytes: &[9; BLOCK_SIZE]
                    }],
                    &mut scratch()
                ),
                Err(Error::Io(Fault::Injected)),
                "after={after} point={point}"
            );
            assert!(!journal.is_writable());
            assert_eq!(
                journal.checkpoint(&mut disk, &mut scratch()),
                Err(Error::Poisoned)
            );
            assert_eq!(disk.home(DATA_START), [0; BLOCK_SIZE]);
            disk.power_cut();
            journal.mount(&mut disk, &mut scratch()).unwrap();
            let expected = if after && point == 6 { 9 } else { 0 };
            assert_eq!(
                read(&mut journal, &mut disk, DATA_START),
                [expected; BLOCK_SIZE],
                "after={after} point={point}"
            );
        }
    }
}

#[test]
fn every_checkpoint_write_and_flush_boundary_recovers_acknowledged_commit() {
    for after in [false, true] {
        for point in 1..=4 {
            let (mut disk, mut journal) = mounted();
            commit(&mut journal, &mut disk, DATA_START, 8);
            disk.operations.clear();
            disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            assert_eq!(
                journal.checkpoint(&mut disk, &mut scratch()),
                Err(Error::Io(Fault::Injected))
            );
            assert!(!journal.is_writable());
            disk.power_cut();
            journal.mount(&mut disk, &mut scratch()).unwrap();
            assert_eq!(
                read(&mut journal, &mut disk, DATA_START),
                [8; BLOCK_SIZE],
                "after={after} point={point}"
            );
        }
    }
}

#[test]
fn torn_redo_and_digest_corruption_with_valid_commit_fail_closed_without_home_writes() {
    for (block, offset) in [(3, 100), (4, 0), (3, 40)] {
        let (mut disk, mut journal) = mounted();
        commit(&mut journal, &mut disk, DATA_START, 7);
        disk.corrupt(block, offset);
        disk.operations.clear();
        assert_eq!(
            journal.mount(&mut disk, &mut scratch()),
            Err(Error::Corrupt)
        );
        assert!(disk.operations.is_empty());
        assert!(!journal.is_writable());
    }
    // A fully CRC-valid COMMIT with the wrong SHA-256 digest must also fail.
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 7);
    let mut commit_bytes = disk.home(5);
    let mut record = Record::decode(&commit_bytes).unwrap();
    if let LogPayload::Commit {
        ref mut ordered_digest,
        ..
    } = record.payload
    {
        ordered_digest[0] ^= 1;
    }
    let record_owned = Record {
        txid: record.txid,
        lsn: record.lsn,
        log_epoch: record.log_epoch,
        payload: record.payload,
    };
    let mut encoded = [0; BLOCK_SIZE];
    record_owned.encode(&mut encoded).unwrap();
    commit_bytes.copy_from_slice(&encoded);
    disk.stable.insert(5, Box::new(commit_bytes));
    disk.operations.clear();
    assert_eq!(
        journal.mount(&mut disk, &mut scratch()),
        Err(Error::Corrupt)
    );
    assert!(disk.operations.is_empty());
}

#[test]
fn corrupt_middle_commit_with_later_commit_is_not_silently_dropped() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 1);
    commit(&mut journal, &mut disk, DATA_START + 1, 2);
    disk.corrupt(5, 120);
    disk.operations.clear();
    assert_eq!(
        journal.mount(&mut disk, &mut scratch()),
        Err(Error::Corrupt)
    );
    assert!(disk.operations.is_empty());
}

#[test]
fn truncated_last_commit_does_not_replay_its_uncommitted_redo() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 1);
    commit(&mut journal, &mut disk, DATA_START, 2);
    disk.stable.remove(&9); // second transaction's complete COMMIT was lost/torn.
    let recovery = journal.mount(&mut disk, &mut scratch()).unwrap();
    assert_eq!(recovery.committed_transactions, 1);
    assert!(recovery.discarded_tail);
    assert_eq!(disk.home(DATA_START), [1; BLOCK_SIZE]);
}

#[test]
fn maximum_transaction_and_log_full_reject_before_mutation_then_checkpoint_reuses() {
    let (mut disk, mut journal) = mounted();
    let bytes = [4; BLOCK_SIZE];
    let changes: Vec<_> = (0..128)
        .map(|i| AfterImage {
            home_block: DATA_START + i,
            bytes: &bytes,
        })
        .collect();
    for _ in 0..15 {
        journal.commit(&mut disk, &changes, &mut scratch()).unwrap();
    }
    assert_eq!(journal.remaining_log_blocks(), 226);
    disk.operations.clear();
    assert_eq!(
        journal.commit(&mut disk, &changes, &mut scratch()),
        Err(Error::NoSpace)
    );
    assert!(disk.operations.is_empty());
    assert!(journal.is_writable());
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    assert_eq!(journal.remaining_log_blocks(), 4096);
    journal.commit(&mut disk, &changes, &mut scratch()).unwrap();
}

#[test]
fn old_epoch_residue_never_replays_and_conflicting_superblocks_reject() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 1);
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    // The old complete log still exists, but selected epoch makes it inert.
    assert_eq!(
        journal
            .mount(&mut disk, &mut scratch())
            .unwrap()
            .committed_transactions,
        0
    );
    let mut forged = journal.superblock();
    forged.fs_uuid = [0x99; 16];
    let mut bytes = [0; BLOCK_SIZE];
    forged.encode(&mut bytes).unwrap();
    disk.stable.insert(1, Box::new(bytes));
    disk.operations.clear();
    assert_eq!(
        journal.mount(&mut disk, &mut scratch()),
        Err(Error::Format(storage::Error::Conflict))
    );
    assert!(disk.operations.is_empty());
}

#[test]
fn ordered_digest_matches_independent_python_sha256_golden() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 0xa5);
    let bytes = disk.home(5);
    let record = Record::decode(&bytes).unwrap();
    let LogPayload::Commit { ordered_digest, .. } = record.payload else {
        panic!("not COMMIT")
    };
    // hashlib.sha256((4118).to_bytes(8,'little') + bytes([0xa5])*4096)
    assert_eq!(
        ordered_digest,
        [
            0x59, 0x17, 0xbc, 0xb9, 0xfa, 0x23, 0x56, 0x5f, 0x39, 0x05, 0xda, 0x91, 0x7b, 0x7e,
            0x53, 0xe0, 0x67, 0x9f, 0x71, 0x3d, 0xb8, 0x22, 0x76, 0x13, 0x04, 0xd9, 0x70, 0x39,
            0x0e, 0x33, 0x59, 0x99
        ]
    );
}

fn rewrite_record(disk: &mut Disk, block: u32, edit: impl FnOnce(&mut Record<'_>)) {
    let mut bytes = Vec::from(disk.home(block));
    if bytes[6..8] == 2_u16.to_le_bytes() {
        bytes.extend_from_slice(&disk.home(block + 1));
    }
    let mut record = Record::decode(&bytes).unwrap();
    edit(&mut record);
    let mut encoded = vec![0; record.encoded_len()];
    record.encode(&mut encoded).unwrap();
    for (index, chunk) in encoded.chunks_exact(BLOCK_SIZE).enumerate() {
        disk.stable
            .insert(block + index as u32, Box::new(chunk.try_into().unwrap()));
    }
}

#[test]
fn valid_crc_but_wrong_txid_lsn_or_duplicate_home_is_rejected() {
    for variant in 0..3 {
        let (mut disk, mut journal) = mounted();
        journal
            .commit(
                &mut disk,
                &[
                    AfterImage {
                        home_block: DATA_START,
                        bytes: &[1; BLOCK_SIZE],
                    },
                    AfterImage {
                        home_block: DATA_START + 1,
                        bytes: &[2; BLOCK_SIZE],
                    },
                ],
                &mut scratch(),
            )
            .unwrap();
        rewrite_record(&mut disk, 5, |record| match variant {
            0 => record.txid += 1,
            1 => record.lsn += 1,
            _ => {
                if let LogPayload::Redo {
                    ref mut home_block, ..
                } = record.payload
                {
                    *home_block = u64::from(DATA_START);
                }
            }
        });
        disk.operations.clear();
        assert_eq!(
            journal.mount(&mut disk, &mut scratch()),
            Err(Error::Corrupt)
        );
        assert!(disk.operations.is_empty());
    }
}

#[test]
fn full_log_at_exact_boundary_recovers_every_distinct_home_and_never_overwrites_in_use_log() {
    let (mut disk, mut journal) = mounted();
    for offset in 0..1024 {
        commit(
            &mut journal,
            &mut disk,
            DATA_START + offset,
            (offset % 251 + 1) as u8,
        );
    }
    assert_eq!(journal.remaining_log_blocks(), 0);
    disk.operations.clear();
    assert_eq!(
        journal.commit(
            &mut disk,
            &[AfterImage {
                home_block: DATA_START + 1024,
                bytes: &[1; BLOCK_SIZE]
            }],
            &mut scratch()
        ),
        Err(Error::NoSpace)
    );
    assert!(disk.operations.is_empty());
    disk.power_cut();
    let recovery = journal.mount(&mut disk, &mut scratch()).unwrap();
    assert_eq!(recovery.committed_transactions, 1024);
    assert_eq!(recovery.replayed_blocks, 1024);
    for offset in 0..1024 {
        assert_eq!(
            disk.home(DATA_START + offset),
            [(offset % 251 + 1) as u8; BLOCK_SIZE]
        );
    }
}

#[test]
fn interrupted_format_never_publishes_before_metadata_and_log_flush() {
    for after in [false, true] {
        for point in [1, 20, 21, 22, 4117, 4118, 4119, 4120, 4121, 4122] {
            let mut disk = Disk::blank();
            disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            assert_eq!(
                journal::format(&mut disk, [0x42; 16], &mut scratch()),
                Err(Error::Io(Fault::Injected))
            );
            disk.power_cut();
            let has_published = disk.stable.contains_key(&0);
            assert_eq!(has_published, point > 4120 || (point == 4120 && after));
            let mut journal = Journal::new();
            let result = journal.mount(&mut disk, &mut scratch());
            if has_published {
                result.unwrap();
                let block = disk.home(INODE_START);
                assert_eq!(
                    Inode::decode(0, &block[..256]).unwrap().kind,
                    InodeKind::Directory
                );
            } else {
                assert!(matches!(result, Err(Error::Format(_))));
                if !disk.stable.is_empty() {
                    assert_eq!(
                        journal::format(&mut disk, [0x43; 16], &mut scratch()),
                        Err(Error::NotBlank)
                    );
                }
            }
        }
    }
}

#[test]
fn generation_epoch_and_lsn_exhaustion_are_rejected_before_io() {
    for field in 0..3 {
        let mut disk = formatted();
        let mut sb = Superblock::decode(&disk.home(0)).unwrap();
        match field {
            0 => sb.generation = u64::MAX,
            1 => sb.log_epoch = u64::MAX,
            _ => sb.checkpoint_lsn = u64::MAX,
        }
        let mut bytes = [0; BLOCK_SIZE];
        sb.encode(&mut bytes).unwrap();
        disk.stable.insert(0, Box::new(bytes));
        disk.stable.insert(1, Box::new(bytes));
        let mut journal = Journal::new();
        assert_eq!(
            journal.mount(&mut disk, &mut scratch()),
            Err(Error::Counter)
        );
        assert!(disk.operations.is_empty());
    }
    let mut disk = formatted();
    let mut sb = Superblock::decode(&disk.home(0)).unwrap();
    sb.checkpoint_lsn = u64::MAX - 3;
    let mut bytes = [0; BLOCK_SIZE];
    sb.encode(&mut bytes).unwrap();
    disk.stable.insert(0, Box::new(bytes));
    disk.stable.insert(1, Box::new(bytes));
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut scratch()).unwrap();
    disk.operations.clear();
    assert_eq!(
        journal.commit(
            &mut disk,
            &[AfterImage {
                home_block: DATA_START,
                bytes: &[1; BLOCK_SIZE]
            }],
            &mut scratch()
        ),
        Err(Error::Counter)
    );
    assert!(disk.operations.is_empty());
}
