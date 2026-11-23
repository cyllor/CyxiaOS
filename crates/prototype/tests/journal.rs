use cyxia_prototype::journal::{self, AfterImage, BlockDevice, Error, Journal, Scratch};
use cyxia_prototype::storage::{
    self, BITMAP_START, BLOCK_SIZE, CLUSTER_START as DATA_START, FIRST_BUSINESS_BLOCK, INODE_START,
    Inode, InodeKind, LogPayload, Record, Superblock, TOTAL_BLOCKS,
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
    reservations: Vec<u64>,
    endings: Vec<bool>,
    reject_reservation: bool,
    fail_flush: Option<usize>,
    fail_read: Option<u32>,
    cpu_progress_calls: usize,
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
        if matches!(self.cut, Some(Cut::Before(n)) if self.operations.len() == n)
            || (operation == Operation::Flush
                && self.fail_flush
                    == Some(
                        self.operations
                            .iter()
                            .filter(|op| **op == Operation::Flush)
                            .count(),
                    ))
        {
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
        self.fail_flush = None;
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
        if self.fail_read == Some(block) {
            return Err(Fault::Injected);
        }
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
    fn transaction_begin(&mut self, bytes: u64) -> Result<(), Fault> {
        if self.reject_reservation {
            return Err(Fault::Injected);
        }
        self.reservations.push(bytes);
        Ok(())
    }
    fn transaction_end(&mut self, success: bool) {
        self.endings.push(success);
    }
    fn cpu_progress(&mut self) {
        self.cpu_progress_calls += 1;
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

fn independent_image(disk: &Disk, label: &str, script: &str) -> String {
    use std::io::{Seek, SeekFrom, Write};
    let path =
        std::env::temp_dir().join(format!("cyxia-checker-{label}-{}.raw", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.set_len(u64::from(TOTAL_BLOCKS) * BLOCK_SIZE as u64)
        .unwrap();
    for (block, bytes) in &disk.stable {
        file.seek(SeekFrom::Start(u64::from(*block) * BLOCK_SIZE as u64))
            .unwrap();
        file.write_all(&bytes[..]).unwrap();
    }
    drop(file);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = std::process::Command::new("python3")
        .current_dir(root)
        .args(["-c", script])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
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
        assert_eq!(allocated, block < FIRST_BUSINESS_BLOCK);
    }
    for id in 0..256 {
        let bytes = disk.home(INODE_START + id / 16);
        let slot = (id % 16) as usize * 256;
        let inode = Inode::decode(id, &bytes[slot..slot + 256]).unwrap();
        assert_eq!(
            inode.kind,
            if id == 0 || id == storage::SYSTEM_ROOT_INODE {
                InodeKind::Directory
            } else if (storage::BOOT_INODE..=storage::REQUEST_INODE).contains(&id) {
                InodeKind::File
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
fn every_recovery_write_and_flush_boundary_preserves_the_latest_committed_prefix() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 1);
    commit(&mut journal, &mut disk, DATA_START + 1, 2);
    let acknowledged = commit(&mut journal, &mut disk, DATA_START, 3);
    assert_eq!(acknowledged.commit_lsn, 9);

    // The next REDO reaches durable media, but its COMMIT has no completed
    // FLUSH. Recovery must retain the preceding version of this same home.
    disk.operations.clear();
    disk.cut = Some(Cut::Before(6));
    assert_eq!(
        journal.commit(
            &mut disk,
            &[AfterImage {
                home_block: DATA_START,
                bytes: &[4; BLOCK_SIZE],
            }],
            &mut scratch(),
        ),
        Err(Error::Io(Fault::Injected))
    );
    disk.power_cut();

    let mut successful = disk.clone();
    let recovered = Journal::new()
        .mount(&mut successful, &mut scratch())
        .unwrap();
    assert_eq!(recovered.committed_transactions, 3);
    assert_eq!(recovered.replayed_blocks, 2);
    assert!(recovered.discarded_tail);
    let operations = successful.operations;
    assert_eq!(
        operations,
        [
            Operation::Write(DATA_START),
            Operation::Write(DATA_START + 1),
            Operation::Flush,
            Operation::Write(0),
            Operation::Flush,
        ]
    );
    for after in [false, true] {
        for point in 1..=operations.len() {
            let mut interrupted = disk.clone();
            interrupted.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            let mut recovery = Journal::new();
            assert_eq!(
                recovery.mount(&mut interrupted, &mut scratch()),
                Err(Error::Io(Fault::Injected)),
                "after={after} point={point} operation={:?}",
                operations[point - 1]
            );
            assert!(!recovery.is_writable());
            assert_eq!(interrupted.operations, operations[..point]);

            // A second power loss discards recovery's own unflushed home or
            // superblock writes. A fresh owner must independently recover.
            interrupted.power_cut();
            let mut recovered = Journal::new();
            recovered.mount(&mut interrupted, &mut scratch()).unwrap();
            assert_eq!(recovered.last_commit_lsn(), 9);
            assert_eq!(
                read(&mut recovered, &mut interrupted, DATA_START),
                [3; BLOCK_SIZE]
            );
            assert_eq!(
                read(&mut recovered, &mut interrupted, DATA_START + 1),
                [2; BLOCK_SIZE]
            );
            let next = commit(&mut recovered, &mut interrupted, DATA_START + 2, 5);
            assert!(next.key.log_epoch > acknowledged.key.log_epoch);
            assert_eq!(next.commit_lsn, 12);
        }
    }
}

#[test]
fn every_recovery_write_and_flush_boundary_preserves_acknowledged_fsync_sequence() {
    use cyxia_prototype::{
        boot::BootSession,
        domains::filesystem::{FileSystem, OpenMode, validate_volume},
    };

    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (mut disk, mut journal) = mounted();
            BootSession::new()
                .allocate(
                    &mut journal,
                    &mut disk,
                    &mut scratch(),
                    &mut [[0; BLOCK_SIZE]; 4],
                )
                .unwrap();
            let key = {
                let mut fs = FileSystem::<64>::new();
                fs.mount(&mut journal, &mut disk, &mut scratch()).unwrap();
                fs.initialize_business(&mut journal, &mut disk, &mut scratch())
                    .unwrap();
                let key = fs
                    .create("/durable", &mut journal, &mut disk, &mut scratch())
                    .unwrap();
                let handle = fs
                    .open(
                        "/durable",
                        OpenMode::ReadWrite,
                        &mut journal,
                        &mut disk,
                        &mut scratch(),
                    )
                    .unwrap();
                for (byte, sequence) in [(0x11, 1), (0x22, 2)] {
                    fs.write(
                        handle,
                        0,
                        &[byte; BLOCK_SIZE],
                        &mut journal,
                        &mut disk,
                        &mut scratch(),
                    )
                    .unwrap();
                    let receipt = fs
                        .fsync(handle, &mut journal, &mut disk, &mut scratch())
                        .unwrap();
                    assert_eq!(receipt.object, key);
                    assert_eq!(receipt.write_seq, sequence);
                }
                fs.write(
                    handle,
                    0,
                    &[0x33; BLOCK_SIZE],
                    &mut journal,
                    &mut disk,
                    &mut scratch(),
                )
                .unwrap();
                let stat = fs.stat_object(key).unwrap();
                assert_eq!((stat.write_seq, stat.durable_write_seq), (3, 2));
                key
            };
            let acknowledged_lsn = journal.last_commit_lsn();
            disk.power_cut();
            let mut successful = disk.clone();
            let recovery = Journal::new()
                .mount(&mut successful, &mut scratch())
                .unwrap();
            assert!(recovery.committed_transactions > 1);
            assert!(recovery.replayed_blocks > 1);
            let operations = successful.operations;
            for after in [false, true] {
                for point in 1..=operations.len() {
                    let mut interrupted = disk.clone();
                    interrupted.cut = Some(if after {
                        Cut::After(point)
                    } else {
                        Cut::Before(point)
                    });
                    let mut first_recovery = Journal::new();
                    assert_eq!(
                        first_recovery.mount(&mut interrupted, &mut scratch()),
                        Err(Error::Io(Fault::Injected)),
                        "after={after} point={point} operation={:?}",
                        operations[point - 1]
                    );
                    assert!(!first_recovery.is_writable());
                    assert_eq!(interrupted.operations, operations[..point]);
                    interrupted.power_cut();
                    let mut recovered = Journal::new();
                    recovered.mount(&mut interrupted, &mut scratch()).unwrap();
                    assert_eq!(recovered.last_commit_lsn(), acknowledged_lsn);
                    validate_volume(
                        &mut recovered,
                        &mut interrupted,
                        &mut scratch(),
                        &mut [[0; BLOCK_SIZE]; 4],
                    )
                    .unwrap();
                    let mut fs = FileSystem::<64>::new();
                    fs.mount(&mut recovered, &mut interrupted, &mut scratch())
                        .unwrap();
                    let stat = fs
                        .stat("/durable", &mut recovered, &mut interrupted, &mut scratch())
                        .unwrap();
                    assert_eq!(stat.object, key);
                    assert_eq!(
                        (stat.size, stat.write_seq, stat.durable_write_seq),
                        (4096, 2, 2)
                    );
                    let reader = fs
                        .open(
                            "/durable",
                            OpenMode::Read,
                            &mut recovered,
                            &mut interrupted,
                            &mut scratch(),
                        )
                        .unwrap();
                    let mut bytes = [0; BLOCK_SIZE];
                    assert_eq!(
                        fs.read(
                            reader,
                            0,
                            &mut bytes,
                            0,
                            &mut recovered,
                            &mut interrupted,
                            &mut scratch()
                        )
                        .unwrap(),
                        BLOCK_SIZE
                    );
                    assert_eq!(bytes, [0x22; BLOCK_SIZE]);
                    fs.close(reader).unwrap();
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn independent_checker_keeps_real_boot_prefix_when_final_commit_did_not_flush() {
    use cyxia_prototype::boot::BootSession;

    let (mut disk, mut journal) = mounted();
    BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut scratch(),
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    let acknowledged_lsn = journal.last_commit_lsn();
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    disk.operations.clear();
    // The next BootEpoch updates two home blocks. Its BEGIN and REDOs are
    // flushed, but the final COMMIT's FLUSH is interrupted before durability.
    disk.cut = Some(Cut::Before(8));
    assert!(
        BootSession::new()
            .allocate(
                &mut journal,
                &mut disk,
                &mut scratch(),
                &mut [[0; BLOCK_SIZE]; 4]
            )
            .is_err()
    );
    assert_eq!(disk.operations[7], Operation::Flush);
    disk.power_cut();

    let result = independent_image(
        &disk,
        "boot-prefix",
        "import sys; from pathlib import Path; sys.path.insert(0, 'tools'); from check_v2_filesystem import inspect; r=inspect(Path(sys.argv[1])); print(r['boot_epoch'], r['last_commit_lsn'], r['committed_transactions'], r['discarded_tail'])",
    );
    assert_eq!(result, format!("1 {acknowledged_lsn} 0 True"));
}

#[test]
fn independent_checker_reads_real_ordinary_fsync_prefix_and_ignores_uncommitted_newer_data() {
    use cyxia_prototype::{
        boot::BootSession,
        domains::filesystem::{FileSystem, OpenMode},
    };
    std::thread::Builder::new().stack_size(8 * 1024 * 1024).spawn(|| {
        let (mut disk, mut journal) = mounted();
        BootSession::new().allocate(&mut journal, &mut disk, &mut scratch(), &mut [[0; BLOCK_SIZE]; 4]).unwrap();
        let mut files = FileSystem::<64>::new();
        files.mount(&mut journal, &mut disk, &mut scratch()).unwrap();
        files.initialize_business(&mut journal, &mut disk, &mut scratch()).unwrap();
        files.mkdir("/a10", &mut journal, &mut disk, &mut scratch()).unwrap();
        let object = files.create("/a10/value", &mut journal, &mut disk, &mut scratch()).unwrap();
        assert!(object.id > 0 && object.id < u64::from(storage::BUSINESS_INODE_COUNT));
        let handle = files.open("/a10/value", OpenMode::ReadWrite, &mut journal, &mut disk, &mut scratch()).unwrap();
        for (byte, sequence) in [(0x11, 1), (0x22, 2)] {
            files.write(handle, 0, &[byte; BLOCK_SIZE], &mut journal, &mut disk, &mut scratch()).unwrap();
            assert_eq!(files.fsync(handle, &mut journal, &mut disk, &mut scratch()).unwrap().write_seq, sequence);
        }
        let acknowledged_lsn = journal.last_commit_lsn();
        files.write(handle, 0, &[0x33; BLOCK_SIZE], &mut journal, &mut disk, &mut scratch()).unwrap();
        disk.operations.clear(); disk.fail_flush = Some(2);
        assert!(files.fsync(handle, &mut journal, &mut disk, &mut scratch()).is_err());
        assert_eq!(disk.operations.last(), Some(&Operation::Flush));
        assert_eq!(disk.operations.iter().filter(|op| **op == Operation::Flush).count(), 2);
        disk.power_cut();
        let result = independent_image(&disk, "ordinary-prefix", "import sys,hashlib; from pathlib import Path; sys.path.insert(0, 'tools'); from check_v2_filesystem import inspect; r=inspect(Path(sys.argv[1])); v=r['files']['/a10/value']; print(r['boot_epoch'], r['last_commit_lsn'], r['committed_transactions']>0, r['discarded_tail'], v['inode'], v['generation'], v['size'], v['durable_write_seq'], v['sha256']==hashlib.sha256(bytes([0x22])*4096).hexdigest())");
        assert_eq!(result, format!("1 {acknowledged_lsn} True True {} {} 4096 2 True", object.id, object.generation));
    }).unwrap().join().unwrap();
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
    // hashlib.sha256((4242).to_bytes(8,'little') + bytes([0xa5])*4096)
    assert_eq!(
        ordered_digest,
        [
            0x7d, 0xe8, 0x45, 0xba, 0xb6, 0x1c, 0x84, 0x6d, 0x0f, 0x58, 0x93, 0x10, 0x7e, 0xe1,
            0xf2, 0xc1, 0xad, 0xf2, 0x87, 0x9c, 0x5f, 0x96, 0x46, 0xfd, 0x6c, 0x97, 0x0d, 0x7d,
            0xa3, 0x0b, 0x18, 0xca
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
    let mut reference = Disk::blank();
    journal::format(&mut reference, [0x42; 16], &mut scratch()).unwrap();
    let operations = reference.operations;
    let first_publish_flush = operations
        .iter()
        .position(|op| *op == Operation::Write(0))
        .unwrap()
        + 2;
    let mut boundaries = vec![1, 20, 21];
    for (index, operation) in operations.iter().enumerate() {
        if *operation == Operation::Flush {
            boundaries.extend([index.max(1), index + 1, (index + 2).min(operations.len())]);
        }
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    for after in [false, true] {
        for &point in &boundaries {
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
            assert_eq!(
                has_published,
                point > first_publish_flush || (point == first_publish_flush && after)
            );
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

fn allocated_bit(bytes: &Block, block: u32) -> bool {
    let local = block as usize % (BLOCK_SIZE * 8);
    bytes[local / 8] & (1 << (local % 8)) != 0
}
fn set_bit(bytes: &mut Block, block: u32) {
    let local = block as usize % (BLOCK_SIZE * 8);
    bytes[local / 8] |= 1 << (local % 8);
}

#[test]
fn ordered_cow_reserves_complete_write_set_and_publishes_only_after_two_flushes() {
    let (mut disk, mut journal) = mounted();
    let target = FIRST_BUSINESS_BLOCK;
    let mut bitmap = read(&mut journal, &mut disk, BITMAP_START);
    set_bit(&mut bitmap, target);
    let data = [0x72; BLOCK_SIZE];
    let expected = journal.peek_next_commit(1).unwrap();
    let receipt = journal
        .commit_ordered(
            &mut disk,
            &[AfterImage {
                home_block: target,
                bytes: &data,
            }],
            &[AfterImage {
                home_block: BITMAP_START,
                bytes: &bitmap,
            }],
            &mut scratch(),
        )
        .unwrap();
    assert_eq!(receipt, expected);
    assert_eq!(disk.reservations, [5 * BLOCK_SIZE as u64]);
    assert_eq!(disk.endings, [true]);
    assert_eq!(
        disk.operations,
        [
            Operation::Write(target),
            Operation::Write(2),
            Operation::Write(3),
            Operation::Write(4),
            Operation::Flush,
            Operation::Write(5),
            Operation::Flush
        ]
    );
    assert_eq!(disk.home(target), data);
    assert!(!allocated_bit(&disk.home(BITMAP_START), target));
    assert!(allocated_bit(
        &read(&mut journal, &mut disk, BITMAP_START),
        target
    ));
    disk.operations.clear();
    journal.checkpoint(&mut disk, &mut scratch()).unwrap();
    assert!(!disk.operations.contains(&Operation::Write(target)));
    assert!(allocated_bit(&disk.home(BITMAP_START), target));
}

#[test]
fn ordered_cow_rejects_allocated_duplicate_unpublished_and_unreserved_targets_before_writes() {
    let (mut disk, mut journal) = mounted();
    let target = FIRST_BUSINESS_BLOCK;
    let original = read(&mut journal, &mut disk, BITMAP_START);
    let mut bitmap = original;
    set_bit(&mut bitmap, target);
    let data = [1; BLOCK_SIZE];
    let ordered = AfterImage {
        home_block: target,
        bytes: &data,
    };
    let metadata = AfterImage {
        home_block: BITMAP_START,
        bytes: &bitmap,
    };
    for (data_set, metadata_set) in [
        (vec![ordered, ordered], vec![metadata]),
        (vec![ordered], vec![]),
        (
            vec![ordered],
            vec![AfterImage {
                home_block: BITMAP_START,
                bytes: &original,
            }],
        ),
        (
            vec![AfterImage {
                home_block: DATA_START,
                bytes: &data,
            }],
            vec![metadata],
        ),
        (vec![], vec![ordered]),
        (vec![ordered; storage::MAX_ORDERED + 1], vec![metadata]),
    ] {
        assert_eq!(
            journal.commit_ordered(&mut disk, &data_set, &metadata_set, &mut scratch()),
            Err(Error::Invalid)
        );
        assert!(journal.is_writable());
        assert!(disk.operations.is_empty());
        assert!(disk.reservations.is_empty());
    }
    disk.reject_reservation = true;
    assert_eq!(
        journal.commit_ordered(&mut disk, &[ordered], &[metadata], &mut scratch()),
        Err(Error::Io(Fault::Injected))
    );
    assert!(journal.is_writable());
    assert!(disk.operations.is_empty());
    assert!(disk.endings.is_empty());
    disk.reject_reservation = false;
    journal
        .commit_ordered(&mut disk, &[ordered], &[metadata], &mut scratch())
        .unwrap();
    disk.operations.clear();
    // The bitmap home remains free until checkpoint: only the committed overlay
    // prevents an illegal second write into the immutable, already allocated block.
    assert!(!allocated_bit(&disk.home(BITMAP_START), target));
    assert_eq!(
        journal.commit_ordered(&mut disk, &[ordered], &[metadata], &mut scratch()),
        Err(Error::Invalid)
    );
    assert!(disk.operations.is_empty());
    assert!(journal.is_writable());
}

#[test]
fn every_ordered_cow_write_and_flush_cut_preserves_old_data_and_never_publishes_unflushed_bytes() {
    let (mut original, mut journal) = mounted();
    let old = FIRST_BUSINESS_BLOCK;
    let target = old + 1;
    let mut bitmap = read(&mut journal, &mut original, BITMAP_START);
    set_bit(&mut bitmap, old);
    journal
        .commit_ordered(
            &mut original,
            &[AfterImage {
                home_block: old,
                bytes: &[0x31; BLOCK_SIZE],
            }],
            &[AfterImage {
                home_block: BITMAP_START,
                bytes: &bitmap,
            }],
            &mut scratch(),
        )
        .unwrap();
    journal.checkpoint(&mut original, &mut scratch()).unwrap();
    set_bit(&mut bitmap, target);
    for after in [false, true] {
        for point in 1..=7 {
            let mut disk = original.clone();
            disk.power_cut();
            let mut live = Journal::new();
            live.mount(&mut disk, &mut scratch()).unwrap();
            disk.operations.clear();
            disk.cut = Some(if after {
                Cut::After(point)
            } else {
                Cut::Before(point)
            });
            assert_eq!(
                live.commit_ordered(
                    &mut disk,
                    &[AfterImage {
                        home_block: target,
                        bytes: &[0x62; BLOCK_SIZE]
                    }],
                    &[AfterImage {
                        home_block: BITMAP_START,
                        bytes: &bitmap
                    }],
                    &mut scratch()
                ),
                Err(Error::Io(Fault::Injected)),
                "after={after}, point={point}"
            );
            assert!(!live.is_writable());
            assert_eq!(disk.endings.last(), Some(&false));
            disk.power_cut();
            let mut recovered = Journal::new();
            recovered.mount(&mut disk, &mut scratch()).unwrap();
            assert_eq!(disk.home(old), [0x31; BLOCK_SIZE]);
            let published = allocated_bit(&read(&mut recovered, &mut disk, BITMAP_START), target);
            assert_eq!(
                published,
                after && point == 7,
                "after={after}, point={point}"
            );
            if published {
                assert_eq!(disk.home(target), [0x62; BLOCK_SIZE]);
            }
        }
    }
}

#[test]
fn valid_crc_business_redo_with_a_durable_commit_is_middle_corruption() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 9);
    // Bypass the encoder to emulate a corrupted on-disk destination, retaining
    // valid record CRCs. A later valid COMMIT prevents tail-discard recovery.
    let header = disk.stable.get_mut(&3).unwrap();
    header[40..48].copy_from_slice(&u64::from(FIRST_BUSINESS_BLOCK).to_le_bytes());
    header[56..60].fill(0);
    let crc = storage::crc32c(&header[..64]);
    header[56..60].copy_from_slice(&crc.to_le_bytes());
    disk.power_cut();
    assert_eq!(
        Journal::new().mount(&mut disk, &mut scratch()),
        Err(Error::Corrupt)
    );
    assert!(disk.operations.is_empty());
    assert_eq!(disk.home(FIRST_BUSINESS_BLOCK), [0; BLOCK_SIZE]);
}

#[test]
fn maximum_ordered_batch_spans_all_four_bitmaps_without_business_redo() {
    let (mut disk, mut journal) = mounted();
    let mut maps = [[0; BLOCK_SIZE]; 4];
    let mut targets = Vec::new();
    for (index, map) in maps.iter_mut().enumerate() {
        *map = read(&mut journal, &mut disk, BITMAP_START + index as u32);
        let first = if index == 0 {
            FIRST_BUSINESS_BLOCK
        } else {
            index as u32 * 32768
        };
        for offset in 0..32 {
            let block = first + offset;
            set_bit(map, block);
            targets.push(block);
        }
    }
    let bytes = [0x85; BLOCK_SIZE];
    let ordered: Vec<_> = targets
        .iter()
        .map(|block| AfterImage {
            home_block: *block,
            bytes: &bytes,
        })
        .collect();
    let changes: Vec<_> = maps
        .iter()
        .enumerate()
        .map(|(index, bytes)| AfterImage {
            home_block: BITMAP_START + index as u32,
            bytes,
        })
        .collect();
    assert_eq!(ordered.len(), storage::MAX_ORDERED);
    journal
        .commit_ordered(&mut disk, &ordered, &changes, &mut scratch())
        .unwrap();
    assert_eq!(disk.reservations, [138 * BLOCK_SIZE as u64]);
    disk.power_cut();
    let mut recovered = Journal::new();
    let report = recovered.mount(&mut disk, &mut scratch()).unwrap();
    assert_eq!(report.replayed_blocks, 4);
    for block in targets {
        assert_eq!(disk.home(block), bytes);
        assert!(allocated_bit(
            &disk.home(BITMAP_START + block / 32768),
            block
        ));
        assert!(!disk.operations.contains(&Operation::Write(block)));
    }
}

#[test]
fn scratch_read_uses_latest_redo_and_rejects_wrong_record_identity() {
    let (mut disk, mut journal) = mounted();
    commit(&mut journal, &mut disk, DATA_START, 0x45);
    let mut work = scratch();
    assert_eq!(
        journal
            .read_block_scratch(&mut disk, DATA_START, &mut work)
            .unwrap(),
        &[0x45; BLOCK_SIZE]
    );
    rewrite_record(&mut disk, 3, |record| record.log_epoch += 1);
    assert_eq!(
        journal.read_block_scratch(&mut disk, DATA_START, &mut work),
        Err(Error::Corrupt)
    );
    assert!(!journal.is_writable());
}

#[test]
fn immutable_business_read_needs_no_redo_buffer_and_rejects_mutable_homes() {
    let (mut disk, mut journal) = mounted();
    disk.stable
        .insert(FIRST_BUSINESS_BLOCK, Box::new([0x7a; BLOCK_SIZE]));
    let mut block = [0; BLOCK_SIZE];
    assert_eq!(
        journal.read_business_block(&mut disk, DATA_START, &mut block),
        Err(Error::Invalid)
    );
    assert!(journal.is_writable());
    journal
        .read_business_block(&mut disk, FIRST_BUSINESS_BLOCK, &mut block)
        .unwrap();
    assert_eq!(block, [0x7a; BLOCK_SIZE]);
    assert_eq!(
        journal
            .read_block_scratch(&mut disk, FIRST_BUSINESS_BLOCK, &mut scratch())
            .unwrap(),
        &[0x7a; BLOCK_SIZE]
    );
}

fn progress_read(
    journal: &mut Journal,
    disk: &mut Disk,
    use_scratch: bool,
    home: u32,
) -> Result<Block, Error<Fault>> {
    if use_scratch {
        journal
            .read_block_scratch(disk, home, &mut scratch())
            .copied()
    } else {
        let mut out = [0; BLOCK_SIZE];
        journal.read_block(disk, home, &mut out, &mut scratch())?;
        Ok(out)
    }
}

#[test]
fn cpu_progress_follows_successful_direct_and_validated_redo_reads() {
    for use_scratch in [false, true] {
        let (mut disk, mut journal) = mounted();
        disk.cpu_progress_calls = 0;
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, DATA_START).unwrap(),
            [0; BLOCK_SIZE]
        );
        assert_eq!(disk.cpu_progress_calls, 1);
        commit(&mut journal, &mut disk, DATA_START, 0x59);
        let before = disk.cpu_progress_calls;
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, DATA_START).unwrap(),
            [0x59; BLOCK_SIZE]
        );
        assert_eq!(disk.cpu_progress_calls, before + 1);
        rewrite_record(&mut disk, 3, |record| record.log_epoch += 1);
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, DATA_START),
            Err(Error::Corrupt)
        );
        assert_eq!(disk.cpu_progress_calls, before + 1);
        assert!(!journal.is_writable());
    }
}

#[test]
fn invalid_unknown_io_and_corrupt_crc_reads_never_publish_cpu_progress() {
    for use_scratch in [false, true] {
        let (mut disk, mut journal) = mounted();
        disk.cpu_progress_calls = 0;
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, 0),
            Err(Error::Invalid)
        );
        assert_eq!(disk.cpu_progress_calls, 0);
        assert!(journal.is_writable());
        disk.fail_read = Some(DATA_START);
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, DATA_START),
            Err(Error::Io(Fault::Injected))
        );
        assert_eq!(disk.cpu_progress_calls, 0);
        assert!(!journal.is_writable());

        let (mut disk, mut journal) = mounted();
        commit(&mut journal, &mut disk, DATA_START, 0x66);
        disk.cpu_progress_calls = 0;
        disk.corrupt(3, 64);
        assert_eq!(
            progress_read(&mut journal, &mut disk, use_scratch, DATA_START),
            Err(Error::Corrupt)
        );
        assert_eq!(disk.cpu_progress_calls, 0);
        assert!(!journal.is_writable());
    }
}

#[test]
fn v019_sec_f01_direct_filesystem_rejects_ambiguous_path_without_disk_effect() {
    use cyxia_prototype::{
        boot::BootSession,
        domains::{Error as DomainError, filesystem::FileSystem},
    };
    // Keep the fixed-size native-shaped filesystem and journal off the small
    // default host-test thread stack. No fake capability or AI is involved.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let (mut disk, mut journal) = mounted();
            BootSession::new()
                .allocate(
                    &mut journal,
                    &mut disk,
                    &mut scratch(),
                    &mut [[0; BLOCK_SIZE]; 4],
                )
                .unwrap();
            let mut files = FileSystem::<64>::new();
            files.mount(&mut journal, &mut disk, &mut scratch()).unwrap();
            files.initialize_business(&mut journal, &mut disk, &mut scratch())
                .unwrap();
            let durable_before = journal.last_commit_lsn();
            disk.operations.clear();
            for invalid in [
                "//a", "/a//b", "/a/", "/./a", "/a/../b", "/a/.", "/a/..",
            ] {
                assert_eq!(
                    files.create(invalid, &mut journal, &mut disk, &mut scratch()),
                    Err(DomainError::Format),
                    "ambiguous path {invalid:?}"
                );
                assert_eq!(journal.last_commit_lsn(), durable_before);
                assert!(disk.operations.is_empty(), "path {invalid:?} had disk side effects");
            }
            assert_eq!(
                files.create("/a\0b", &mut journal, &mut disk, &mut scratch()),
                Err(DomainError::Range),
            );
            let excessive = format!("/{}", "a".repeat(512));
            assert_eq!(
                files.create(&excessive, &mut journal, &mut disk, &mut scratch()),
                Err(DomainError::Range),
            );
            assert!(journal.is_writable());
            assert!(disk.operations.is_empty());
            // Valid ordinary creation still goes through the existing redo,
            // bitmap, inode and flush protocol after the guard.
            files.create("/valid", &mut journal, &mut disk, &mut scratch())
                .unwrap();
            assert!(journal.last_commit_lsn() > durable_before);
        })
        .unwrap()
        .join()
        .unwrap();
}
