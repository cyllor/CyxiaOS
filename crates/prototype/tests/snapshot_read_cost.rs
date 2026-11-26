//! Deterministic device-read bounds for snapshot capture and historical lookup.
use cyxia_prototype::{
    boot::BootSession,
    domains::{
        Error,
        filesystem::{FileSystem, OpenMode},
    },
    journal::{self, BlockDevice, Journal},
    snapshot::{self, FileReqKey, Request, RequestState, SlotClass, SnapshotKey},
    storage::{BLOCK_SIZE, DIRECTORY_SLOT_SIZE, DirectoryEntry, INODE_SIZE, Inode, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

#[derive(Default)]
struct Disk {
    blocks: BTreeMap<u32, [u8; BLOCK_SIZE]>,
    reads: usize,
}

impl BlockDevice for Disk {
    type Error = ();

    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }

    fn read_block(&mut self, block: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        self.reads += 1;
        *out = self.blocks.get(&block).copied().unwrap_or([0; BLOCK_SIZE]);
        Ok(())
    }

    fn write_block(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        self.blocks.insert(block, *data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

fn large(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

fn blank() -> (Disk, Journal, FileSystem<64>) {
    let mut disk = Disk::default();
    let mut journal = Journal::new();
    let mut scratch = [0; 8192];
    journal::format(&mut disk, [0x28; 16], &mut scratch).unwrap();
    journal.mount(&mut disk, &mut scratch).unwrap();
    BootSession::new()
        .allocate(
            &mut journal,
            &mut disk,
            &mut scratch,
            &mut [[0; BLOCK_SIZE]; 4],
        )
        .unwrap();
    let mut fs = FileSystem::new();
    fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
    fs.initialize_business(&mut journal, &mut disk, &mut scratch)
        .unwrap();
    (disk, journal, fs)
}

fn create_snapshot(fs: &mut FileSystem<64>, journal: &mut Journal, disk: &mut Disk) -> SnapshotKey {
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
    payload[..8].copy_from_slice(&3600u64.to_le_bytes());
    payload[8..12].copy_from_slice(&(SlotClass::OnDemand as u32).to_le_bytes());
    payload[12..].copy_from_slice(&1u32.to_le_bytes());
    let record = fs
        .snapshot_execute(
            request,
            snapshot::OP_CREATE,
            &payload,
            journal,
            disk,
            &mut [0; 8192],
        )
        .unwrap();
    assert_eq!(record.state, RequestState::Done);
    record.snapshot_key
}

const ENTRIES: usize = 200;

fn capture_reads(nested: bool) -> usize {
    let (mut disk, mut journal, mut fs) = blank();
    let mut scratch = [0; 8192];
    let mut path = String::new();
    for index in 0..ENTRIES {
        if nested {
            path.push_str("/a");
        } else {
            path = format!("/d{index}");
        }
        fs.mkdir(&path, &mut journal, &mut disk, &mut scratch)
            .unwrap();
    }
    disk.reads = 0;
    create_snapshot(&mut fs, &mut journal, &mut disk);
    disk.reads
}

#[test]
fn capture_validation_cost_does_not_scale_with_tree_depth() {
    large(|| {
        let nested = capture_reads(true);
        let flat = capture_reads(false);
        println!("capture device reads: nested={nested}, flat={flat}");
        assert!(
            nested <= 2 * flat,
            "nested capture used {nested} reads, flat used {flat}"
        );
    });
}

#[test]
fn history_lookup_reads_pages_once_and_returns_historical_bytes() {
    large(|| {
        let (mut disk, mut journal, mut fs) = blank();
        let mut scratch = [0; 8192];
        fs.mkdir("/big", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        for index in 0..ENTRIES {
            fs.create(
                &format!("/big/f{index}"),
                &mut journal,
                &mut disk,
                &mut scratch,
            )
            .unwrap();
        }
        let last = format!("/big/f{}", ENTRIES - 1);
        let live = fs
            .open(
                &last,
                OpenMode::Write,
                &mut journal,
                &mut disk,
                &mut scratch,
            )
            .unwrap();
        fs.write(live, 0, b"before", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        let key = create_snapshot(&mut fs, &mut journal, &mut disk);
        fs.write(live, 0, b"after!", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        fs.fsync(live, &mut journal, &mut disk, &mut scratch)
            .unwrap();
        fs.close(live).unwrap();

        disk.reads = 0;
        let history = fs
            .snapshot_open(key, &last, "/", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        let reads = disk.reads;
        println!("history open device reads: last of {ENTRIES} used {reads}");
        let mut data = [0; 6];
        assert_eq!(
            fs.read(
                history,
                0,
                &mut data,
                0,
                &mut journal,
                &mut disk,
                &mut scratch
            )
            .unwrap(),
            data.len()
        );
        assert_eq!(&data, b"before");
        fs.close(history).unwrap();
        assert!(reads <= 64, "history open used {reads} reads");
    });
}

#[test]
fn history_lookup_rejects_stale_generation_in_an_earlier_entry() {
    large(|| {
        let (mut disk, mut journal, mut fs) = blank();
        let mut scratch = [0; 8192];
        let directory = fs
            .mkdir("/big", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        fs.create("/big/first", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        fs.create("/big/last", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        let key = create_snapshot(&mut fs, &mut journal, &mut disk);
        journal.checkpoint(&mut disk, &mut scratch).unwrap();

        let root = fs.snapshot_entries().unwrap()[key.slot as usize].inode_first_block;
        let id = directory.id as usize;
        let inodes_per_page = BLOCK_SIZE / INODE_SIZE;
        let inode_page = &disk.blocks[&(root + (id / inodes_per_page) as u32)];
        let offset = id % inodes_per_page * INODE_SIZE;
        let inode = Inode::decode(id as u32, &inode_page[offset..offset + INODE_SIZE]).unwrap();
        let page = disk
            .blocks
            .get_mut(&inode.extents[0].physical_start)
            .unwrap();
        let slot = &mut page[..DIRECTORY_SLOT_SIZE];
        let first = DirectoryEntry::decode(slot).unwrap();
        assert_eq!(first.name, "first");
        DirectoryEntry {
            inode_id: first.inode_id,
            inode_generation: first.inode_generation + 1,
            name: "first",
        }
        .encode(slot)
        .unwrap();
        assert_eq!(
            fs.snapshot_open(key, "/big/last", "/", &mut journal, &mut disk, &mut scratch),
            Err(Error::Stale)
        );
    });
}
