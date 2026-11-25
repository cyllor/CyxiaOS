//! Device-read cost of snapshot capture and historical path resolution.
//! Reads are counted on an in-memory device so the bounds are deterministic.
use cyxia_prototype::{
    boot::BootSession,
    domains::filesystem::FileSystem,
    journal::{self, BlockDevice, Journal},
    snapshot::{self, FileReqKey, Request, RequestState},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
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

fn large(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

fn blank() -> (Disk, Journal, FileSystem<64>) {
    let mut d = Disk::default();
    let mut j = Journal::new();
    let mut s = [0; 8192];
    journal::format(&mut d, [0x28; 16], &mut s).unwrap();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; BLOCK_SIZE]; 4])
        .unwrap();
    let mut fs = FileSystem::new();
    fs.mount(&mut j, &mut d, &mut s).unwrap();
    fs.initialize_business(&mut j, &mut d, &mut s).unwrap();
    (d, j, fs)
}

fn create_snapshot(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk) -> snapshot::RequestRecord {
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
    payload[8..12].copy_from_slice(&2u32.to_le_bytes());
    payload[12..].copy_from_slice(&1u32.to_le_bytes());
    let record = fs
        .snapshot_execute(request, snapshot::OP_CREATE, &payload, j, d, &mut [0; 8192])
        .unwrap();
    assert_eq!(record.state, RequestState::Done);
    record
}

/// Reads spent by one snapshot create over a tree built by `build`.
fn capture_reads(build: impl FnOnce(&mut FileSystem<64>, &mut Journal, &mut Disk)) -> usize {
    let (mut d, mut j, mut fs) = blank();
    build(&mut fs, &mut j, &mut d);
    d.reads = 0;
    create_snapshot(&mut fs, &mut j, &mut d);
    d.reads
}

const DIRS: usize = 200;

fn nested(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk) {
    let mut path = String::new();
    for _ in 0..DIRS {
        path.push_str("/a");
        fs.mkdir(&path, j, d, &mut [0; 8192]).unwrap();
    }
}

fn flat(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk) {
    for index in 0..DIRS {
        fs.mkdir(&format!("/d{index}"), j, d, &mut [0; 8192]).unwrap();
    }
}

/// Parent-chain validation must not scale with depth times inode count:
/// a 200-deep tree may cost at most twice a flat tree of the same size.
/// Before memoizing verified ancestors this was 41,646 vs 1,273 reads.
#[test]
fn capture_validation_cost_does_not_scale_with_tree_depth() {
    large(|| {
        let deep = capture_reads(nested);
        let wide = capture_reads(flat);
        assert!(
            deep <= 2 * wide,
            "nested capture used {deep} reads, flat used {wide}"
        );
    });
}

/// Historical lookup reads each directory page once and only the matching
/// target inode. Before this bound the last of 200 entries cost 641 reads.
#[test]
fn history_lookup_reads_only_directory_pages_and_the_matching_inode() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        fs.mkdir("/big", &mut j, &mut d, &mut [0; 8192]).unwrap();
        for index in 0..DIRS {
            fs.create(&format!("/big/f{index}"), &mut j, &mut d, &mut [0; 8192])
                .unwrap();
        }
        let record = create_snapshot(&mut fs, &mut j, &mut d);
        d.reads = 0;
        let last = format!("/big/f{}", DIRS - 1);
        let handle = fs
            .snapshot_open(record.snapshot_key, &last, "/", &mut j, &mut d, &mut [0; 8192])
            .unwrap();
        let history = d.reads;
        fs.close(handle).unwrap();
        assert!(history <= 64, "history open used {history} reads");
    });
}

#[test]
fn report_capture_and_history_read_costs() {
    large(|| {
        let deep = capture_reads(nested);
        let wide = capture_reads(flat);
        let (mut d, mut j, mut fs) = blank();
        fs.mkdir("/big", &mut j, &mut d, &mut [0; 8192]).unwrap();
        for index in 0..DIRS {
            fs.create(&format!("/big/f{index}"), &mut j, &mut d, &mut [0; 8192])
                .unwrap();
        }
        let record = create_snapshot(&mut fs, &mut j, &mut d);
        d.reads = 0;
        let last = format!("/big/f{}", DIRS - 1);
        let handle = fs
            .snapshot_open(record.snapshot_key, &last, "/", &mut j, &mut d, &mut [0; 8192])
            .unwrap();
        let history = d.reads;
        fs.close(handle).unwrap();
        println!("COST capture_nested={deep} capture_flat={wide} history_open_last_of_{DIRS}={history}");
    });
}
