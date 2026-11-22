//! Independent audit regressions for CoW admission, indirect mappings and I/O
//! custody. The device models unflushed writes separately from durable media.
use cyxia_prototype::{
    boot::BootSession,
    domains::{
        Error,
        filesystem::{FileSystem, Handle, OpenMode},
    },
    journal::{self, BlockDevice, Journal},
    snapshot::{self, FileReqKey, Request},
    storage::{BLOCK_SIZE, FIRST_BUSINESS_BLOCK, INODE_START, Inode, MAX_EXTENTS, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

type Block = [u8; BLOCK_SIZE];
#[derive(Clone, Default)]
struct Disk {
    stable: BTreeMap<u32, Box<Block>>,
    pending: BTreeMap<u32, Option<Box<Block>>>,
    writes: usize,
    reads: usize,
    fail_read: Option<u32>,
    unknown_io: bool,
    quiescence_checks: usize,
}
impl Disk {
    fn crash(&mut self) {
        self.pending.clear();
        self.fail_read = None;
        // A modeled full power cut stops the old device, unlike merely making
        // another Journal/FileSystem object in this same boot.
        self.unknown_io = false;
    }
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, out: &mut Block) -> Result<(), ()> {
        self.reads += 1;
        if self.fail_read == Some(block) {
            self.unknown_io = true;
            return Err(());
        }
        match self.pending.get(&block) {
            Some(Some(bytes)) => out.copy_from_slice(&bytes[..]),
            Some(None) => out.fill(0),
            None => out.copy_from_slice(
                self.stable
                    .get(&block)
                    .map_or(&[0; BLOCK_SIZE], |bytes| &**bytes),
            ),
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &Block) -> Result<(), ()> {
        self.writes += 1;
        self.pending.insert(
            block,
            if bytes.iter().all(|byte| *byte == 0) {
                None
            } else {
                Some(Box::new(*bytes))
            },
        );
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        for (block, value) in std::mem::take(&mut self.pending) {
            if let Some(bytes) = value {
                self.stable.insert(block, bytes);
            } else {
                self.stable.remove(&block);
            }
        }
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), ()> {
        self.quiescence_checks += 1;
        if self.unknown_io { Err(()) } else { Ok(()) }
    }
}
fn large(task: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(task)
        .unwrap()
        .join()
        .unwrap();
}
fn fixture() -> (Disk, Journal, FileSystem<64>) {
    let mut d = Disk::default();
    let mut j = Journal::new();
    let mut s = [0; 8192];
    journal::format(&mut d, [0x64; 16], &mut s).unwrap();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; BLOCK_SIZE]; 4])
        .unwrap();
    let mut fs = FileSystem::new();
    fs.mount(&mut j, &mut d, &mut s).unwrap();
    fs.initialize_business(&mut j, &mut d, &mut s).unwrap();
    (d, j, fs)
}

#[test]
fn empty_business_validation_reads_metadata_pages_without_per_inode_io() {
    large(|| {
        let (mut disk, mut journal, _fs) = fixture();
        let mut scratch = [0; 8192];
        journal.checkpoint(&mut disk, &mut scratch).unwrap();
        let before = disk.reads;
        cyxia_prototype::domains::filesystem::validate_volume(
            &mut journal,
            &mut disk,
            &mut scratch,
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
        let reads = disk.reads - before;
        // Includes system-capacity and directory identity checks as well as
        // both complete business-inode passes. Per-inode I/O alone would
        // require more than 400 reads, stalling the native paid service path.
        assert!(reads <= 96, "empty volume validation used {reads} reads");
    });
}

fn open_file(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk, path: &str) -> Handle {
    fs.create(path, j, d, &mut [0; 8192]).unwrap();
    fs.open(path, OpenMode::ReadWrite, j, d, &mut [0; 8192])
        .unwrap()
}
fn inode(fs: &FileSystem<64>, j: &mut Journal, d: &mut Disk, h: Handle) -> Inode {
    let id = fs.handle_object(h).unwrap().id as u32;
    let mut s = [0; 8192];
    let page = j
        .read_block_scratch(d, INODE_START + id / 16, &mut s)
        .unwrap();
    Inode::decode(
        id,
        &page[id as usize % 16 * 256..(id as usize % 16 + 1) * 256],
    )
    .unwrap()
}
fn assert_byte(
    fs: &mut FileSystem<64>,
    j: &mut Journal,
    d: &mut Disk,
    h: Handle,
    block: usize,
    value: u8,
) {
    let mut bytes = [0; BLOCK_SIZE];
    assert_eq!(
        fs.read(
            h,
            (block * BLOCK_SIZE) as u64,
            &mut bytes,
            0,
            j,
            d,
            &mut [0; 8192]
        )
        .unwrap(),
        BLOCK_SIZE
    );
    assert_eq!(bytes, [value; BLOCK_SIZE], "logical block {block}");
}

#[test]
fn complete_354_extent_mapping_survives_cow_partial_flush_snapshot_gc_and_reboot() {
    large(|| {
        let (mut d, mut j, mut fs) = fixture();
        let a = open_file(&mut fs, &mut j, &mut d, "/fragmented");
        let b = open_file(&mut fs, &mut j, &mut d, "/spacer");
        // Interleave durable allocations so each data block occupies a distinct
        // extent. Each append still enters through normal admission and fsync.
        for logical in 0..MAX_EXTENTS {
            fs.write(
                a,
                (logical * BLOCK_SIZE) as u64,
                &[(logical % 251 + 1) as u8; BLOCK_SIZE],
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
            fs.fsync(a, &mut j, &mut d, &mut [0; 8192]).unwrap();
            fs.write(b, 0, &[0xee; BLOCK_SIZE], &mut j, &mut d, &mut [0; 8192])
                .unwrap();
            fs.fsync(b, &mut j, &mut d, &mut [0; 8192]).unwrap();
        }
        let full = inode(&fs, &mut j, &mut d, a);
        assert_eq!((full.extent_count, full.ext_count), (16, 338));
        assert!(full.ext_block >= FIRST_BUSINESS_BLOCK);
        let old_seq = fs
            .stat_object(fs.handle_object(a).unwrap())
            .unwrap()
            .write_seq;
        let old_lsn = j.last_commit_lsn();
        assert_eq!(
            fs.write(
                a,
                (MAX_EXTENTS * BLOCK_SIZE) as u64,
                &[0xff; BLOCK_SIZE],
                &mut j,
                &mut d,
                &mut [0; 8192]
            ),
            Err(Error::Capacity)
        );
        assert_eq!(j.last_commit_lsn(), old_lsn);
        assert_eq!(
            fs.stat_object(fs.handle_object(a).unwrap())
                .unwrap()
                .write_seq,
            old_seq
        );
        let request = Request {
            key: FileReqKey {
                fs_uuid: fs.snapshot_uuid().unwrap(),
                client_slot: 0,
                client_generation: 1,
                request_seq: 1,
            },
            expected_live_view_epoch: fs.live_view_epoch(),
        };
        let mut payload = [0; 16];
        payload[..8].copy_from_slice(&3600_u64.to_le_bytes());
        payload[8..12].copy_from_slice(&2_u32.to_le_bytes());
        payload[12..].copy_from_slice(&1_u32.to_le_bytes());
        let captured = fs
            .snapshot_execute(
                request,
                snapshot::OP_CREATE,
                &payload,
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        let historical = fs
            .snapshot_open(
                captured.snapshot_key,
                "/fragmented",
                "/",
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        for logical in [0, 17, 200, 353] {
            fs.write(
                a,
                (logical * BLOCK_SIZE) as u64,
                &[0xab; BLOCK_SIZE],
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        }
        fs.set_writeback_baseline(4).unwrap();
        assert_eq!(
            fs.background_flush(0, &mut j, &mut d, &mut [0; 8192])
                .unwrap()
                .unwrap()
                .pages,
            4
        );
        for logical in [0, 17, 200, 353] {
            assert_byte(&mut fs, &mut j, &mut d, a, logical, 0xab);
            assert_byte(
                &mut fs,
                &mut j,
                &mut d,
                historical,
                logical,
                (logical % 251 + 1) as u8,
            );
        }
        fs.collect_garbage(&mut j, &mut d, &mut [0; 8192]).unwrap();
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut [0; 8192]).unwrap();
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut [0; 8192]).unwrap();
        let a = fs
            .open(
                "/fragmented",
                OpenMode::Read,
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        let historical = fs
            .snapshot_open(
                captured.snapshot_key,
                "/fragmented",
                "/",
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        for logical in [0, 17, 200, 353] {
            assert_byte(&mut fs, &mut j, &mut d, a, logical, 0xab);
            assert_byte(
                &mut fs,
                &mut j,
                &mut d,
                historical,
                logical,
                (logical % 251 + 1) as u8,
            );
        }
    });
}

#[test]
fn failed_cache_admission_keeps_previously_accepted_bytes_and_reservations_usable() {
    large(|| {
        let (mut d, mut j, mut fs) = fixture();
        let a = open_file(&mut fs, &mut j, &mut d, "/a");
        let b = open_file(&mut fs, &mut j, &mut d, "/b");
        for batch in 0..3 {
            fs.write(
                a,
                batch * 65536,
                &[0x31; 65536],
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
        }
        fs.write(b, 0, &[0x72; 65536], &mut j, &mut d, &mut [0; 8192])
            .unwrap();
        let before = fs.stat_object(fs.handle_object(a).unwrap()).unwrap();
        assert_eq!(
            fs.write(
                a,
                48 * BLOCK_SIZE as u64 - 1,
                &[0xfe, 0xfd],
                &mut j,
                &mut d,
                &mut [0; 8192]
            ),
            Err(Error::Again)
        );
        let after = fs.stat_object(fs.handle_object(a).unwrap()).unwrap();
        assert_eq!(
            (after.size, after.write_seq),
            (before.size, before.write_seq)
        );
        let mut byte = [0];
        fs.read(
            a,
            before.size - 1,
            &mut byte,
            0,
            &mut j,
            &mut d,
            &mut [0; 8192],
        )
        .unwrap();
        assert_eq!(byte, [0x31]);
        fs.fsync(a, &mut j, &mut d, &mut [0; 8192]).unwrap();
        fs.fsync(b, &mut j, &mut d, &mut [0; 8192]).unwrap();
        fs.collect_garbage(&mut j, &mut d, &mut [0; 8192]).unwrap();
        assert_byte(&mut fs, &mut j, &mut d, a, 47, 0x31);
        assert_byte(&mut fs, &mut j, &mut d, b, 15, 0x72);
    });
}

#[test]
fn unknown_read_custody_blocks_gc_and_same_boot_journal_reinitialization() {
    large(|| {
        let (mut d, mut j, mut fs) = fixture();
        let h = open_file(&mut fs, &mut j, &mut d, "/data");
        fs.write(h, 0, &[0x58; BLOCK_SIZE], &mut j, &mut d, &mut [0; 8192])
            .unwrap();
        fs.fsync(h, &mut j, &mut d, &mut [0; 8192]).unwrap();
        let node = inode(&fs, &mut j, &mut d, h);
        let object = fs.handle_object(h).unwrap();
        fs.discard_clean_object_cache(object, 0, 64).unwrap();
        d.fail_read = Some(node.extents[0].physical_start);
        assert_eq!(
            fs.read(
                h,
                0,
                &mut [0; BLOCK_SIZE],
                0,
                &mut j,
                &mut d,
                &mut [0; 8192]
            ),
            Err(Error::Io)
        );
        assert!(!j.is_writable());
        let writes = d.writes;
        assert_eq!(
            fs.collect_garbage(&mut j, &mut d, &mut [0; 8192]),
            Err(Error::Io)
        );
        assert_eq!(d.writes, writes);
        d.fail_read = None;
        let reads = d.reads;
        assert!(Journal::new().mount(&mut d, &mut [0; 8192]).is_err());
        assert_eq!(
            d.reads, reads,
            "unknown DMA must block before media recovery"
        );
    });
}

#[test]
fn gc_requires_device_quiescence_even_if_no_journal_call_reported_an_error() {
    large(|| {
        let (mut d, mut j, mut fs) = fixture();
        d.unknown_io = true;
        let writes = d.writes;
        assert_eq!(
            fs.collect_garbage(&mut j, &mut d, &mut [0; 8192]),
            Err(Error::Io)
        );
        assert!(!j.is_writable());
        assert_eq!(d.writes, writes);
    });
}

#[test]
fn live_indirect_read_rejects_crc_valid_mapping_that_disagrees_with_its_inode() {
    large(|| {
        let (mut d, mut j, mut fs) = fixture();
        let file = open_file(&mut fs, &mut j, &mut d, "/indirect");
        let spacer = open_file(&mut fs, &mut j, &mut d, "/spacer");
        for logical in 0..18 {
            fs.write(
                file,
                (logical * BLOCK_SIZE) as u64,
                &[logical as u8; BLOCK_SIZE],
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
            fs.fsync(file, &mut j, &mut d, &mut [0; 8192]).unwrap();
            fs.write(
                spacer,
                0,
                &[0xee; BLOCK_SIZE],
                &mut j,
                &mut d,
                &mut [0; 8192],
            )
            .unwrap();
            fs.fsync(spacer, &mut j, &mut d, &mut [0; 8192]).unwrap();
        }
        let node = inode(&fs, &mut j, &mut d, file);
        assert_eq!(node.ext_count, 2);
        let object = fs.handle_object(file).unwrap();
        fs.discard_clean_object_cache(object, 0, 64).unwrap();
        let page = d.stable.get_mut(&node.ext_block).unwrap();
        // Retain valid page CRC, identity and local contiguous ranges, but shift
        // the whole indirect suffix past the inline prefix and published EOF.
        for index in 0..2 {
            let offset = 32 + index * 12;
            let logical = u32::from_le_bytes(page[offset..offset + 4].try_into().unwrap());
            page[offset..offset + 4].copy_from_slice(&(logical + 1).to_le_bytes());
        }
        page[4092..].fill(0);
        let checksum = cyxia_prototype::storage::crc32c(&page[..]);
        page[4092..].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(
            fs.read(
                file,
                17 * BLOCK_SIZE as u64,
                &mut [0; BLOCK_SIZE],
                0,
                &mut j,
                &mut d,
                &mut [0; 8192]
            ),
            Err(Error::Format)
        );
    });
}
