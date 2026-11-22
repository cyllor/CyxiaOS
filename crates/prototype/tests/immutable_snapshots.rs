//! Actual journal/filesystem integration, using a volatile/stable block device.
//! Every injected power cut discards writes not covered by a successful flush.
use cyxia_prototype::{
    boot::BootSession,
    cluster::volume::{Cursor, Volume},
    domains::{
        Error,
        filesystem::{FileSystem, Handle, OpenMode},
    },
    journal::{self, BlockDevice, Journal},
    snapshot::{self, FileReqKey, Gate, Request, RequestRecord, RequestState, SnapshotKey, State},
    storage::{BLOCK_SIZE, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
struct Disk {
    stable: BTreeMap<u32, [u8; BLOCK_SIZE]>,
    pending: BTreeMap<u32, [u8; BLOCK_SIZE]>,
    events: usize,
    fail: Option<(usize, bool)>,
}
impl Disk {
    fn edge(&mut self, after: bool) -> Result<(), ()> {
        if !after {
            self.events += 1;
        }
        if self.fail == Some((self.events, after)) {
            Err(())
        } else {
            Ok(())
        }
    }
    fn crash(&mut self) {
        self.pending.clear();
        self.fail = None;
        self.events = 0;
    }
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, out: &mut [u8; BLOCK_SIZE]) -> Result<(), ()> {
        *out = self
            .pending
            .get(&block)
            .or_else(|| self.stable.get(&block))
            .copied()
            .unwrap_or([0; BLOCK_SIZE]);
        Ok(())
    }
    fn write_block(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), ()> {
        self.edge(false)?;
        self.pending.insert(block, *data);
        self.edge(true)
    }
    fn flush(&mut self) -> Result<(), ()> {
        self.edge(false)?;
        self.stable.append(&mut self.pending);
        self.edge(true)
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
    journal::format(&mut d, [0x18; 16], &mut s).unwrap();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; BLOCK_SIZE]; 4])
        .unwrap();
    let mut fs = FileSystem::new();
    fs.mount(&mut j, &mut d, &mut s).unwrap();
    assert_eq!(
        fs.snapshot_control().unwrap().business_write_gate,
        Gate::Frozen
    );
    assert_eq!(
        fs.create("/before-protection", &mut j, &mut d, &mut s),
        Err(Error::ReadOnly)
    );
    fs.initialize_business(&mut j, &mut d, &mut s).unwrap();
    assert_eq!(
        fs.snapshot_entries()
            .unwrap()
            .iter()
            .filter(|e| e.state == State::Active)
            .count(),
        2
    );
    (d, j, fs)
}
fn remount(d: &mut Disk) -> (Journal, FileSystem<64>) {
    d.crash();
    let mut j = Journal::new();
    let mut s = [0; 8192];
    j.mount(d, &mut s).unwrap();
    let mut fs = FileSystem::new();
    fs.mount(&mut j, d, &mut s).unwrap();
    (j, fs)
}
fn request(fs: &FileSystem<64>, slot: u32, seq: u64, epoch: bool) -> Request {
    Request {
        key: FileReqKey {
            fs_uuid: fs.snapshot_uuid().unwrap(),
            client_slot: slot,
            client_generation: 1,
            request_seq: seq,
        },
        expected_live_view_epoch: if epoch { fs.live_view_epoch() } else { 0 },
    }
}
fn create_payload(seconds: u64) -> [u8; 16] {
    let mut p = [0; 16];
    p[..8].copy_from_slice(&seconds.to_le_bytes());
    p[8..12].copy_from_slice(&2u32.to_le_bytes());
    p[12..].copy_from_slice(&1u32.to_le_bytes());
    p
}
fn capture(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk, seq: u64) -> RequestRecord {
    let r = request(fs, 0, seq, true);
    fs.snapshot_execute(
        r,
        snapshot::OP_CREATE,
        &create_payload(3600),
        j,
        d,
        &mut [0; 8192],
    )
    .unwrap()
}
fn key_bytes(key: SnapshotKey) -> [u8; 40] {
    let mut b = [0; 40];
    key.encode(&mut b).unwrap();
    b
}
fn restore_payload(key: SnapshotKey, mode: u32) -> [u8; 48] {
    let mut p = [0; 48];
    p[..40].copy_from_slice(&key_bytes(key));
    p[40..44].copy_from_slice(&mode.to_le_bytes());
    p
}
fn read(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk, h: Handle) -> Vec<u8> {
    let mut bytes = [0; 65536];
    let n = fs.read(h, 0, &mut bytes, 0, j, d, &mut [0; 8192]).unwrap();
    bytes[..n].to_vec()
}
fn read_path(fs: &mut FileSystem<64>, j: &mut Journal, d: &mut Disk, path: &str) -> Vec<u8> {
    let h = fs.open(path, OpenMode::Read, j, d, &mut [0; 8192]).unwrap();
    let result = read(fs, j, d, h);
    fs.close(h).unwrap();
    result
}
fn write_file(
    fs: &mut FileSystem<64>,
    j: &mut Journal,
    d: &mut Disk,
    path: &str,
    bytes: &[u8],
) -> Handle {
    fs.create(path, j, d, &mut [0; 8192]).unwrap();
    let h = fs
        .open(path, OpenMode::ReadWrite, j, d, &mut [0; 8192])
        .unwrap();
    fs.write(h, 0, bytes, j, d, &mut [0; 8192]).unwrap();
    h
}

#[test]
fn historical_data_and_directories_survive_cow_unlink_inode_reuse_checkpoint_and_reboot() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        fs.mkdir("/documents", &mut j, &mut d, &mut s).unwrap();
        let h = write_file(&mut fs, &mut j, &mut d, "/documents/report", b"original");
        // Creation drains accepted writes and captures their committed image.
        let first = capture(&mut fs, &mut j, &mut d, 1);
        assert_eq!(first.state, RequestState::Done);
        let hist = fs
            .snapshot_open(
                first.snapshot_key,
                "/documents/report",
                "/documents",
                &mut j,
                &mut d,
                &mut s,
            )
            .unwrap();
        assert_eq!(
            fs.write(hist, 0, b"bad", &mut j, &mut d, &mut s),
            Err(Error::ReadOnly)
        );
        assert_eq!(fs.fsync(hist, &mut j, &mut d, &mut s), Err(Error::ReadOnly));
        fs.write(h, 0, b"modified", &mut j, &mut d, &mut s).unwrap();
        fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
        fs.close(h).unwrap();
        assert_eq!(read(&mut fs, &mut j, &mut d, hist), b"original");
        fs.unlink("/documents/report", &mut j, &mut d, &mut s)
            .unwrap();
        let h = write_file(&mut fs, &mut j, &mut d, "/documents/reused", b"new name");
        fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
        fs.close(h).unwrap();
        let dir = fs
            .snapshot_open(
                first.snapshot_key,
                "/documents",
                "/documents",
                &mut j,
                &mut d,
                &mut s,
            )
            .unwrap();
        let e = fs.readdir(dir, 0, &mut j, &mut d, &mut s).unwrap().unwrap();
        assert_eq!(&e.name[..usize::from(e.name_len)], b"report");
        fs.close(dir).unwrap();
        fs.close(hist).unwrap();
        j.checkpoint(&mut d, &mut s).unwrap();
        let (mut j, mut fs) = remount(&mut d);
        let h = fs
            .snapshot_open(
                first.snapshot_key,
                "/documents/report",
                "/documents",
                &mut j,
                &mut d,
                &mut s,
            )
            .unwrap();
        assert_eq!(read(&mut fs, &mut j, &mut d, h), b"original");
        assert_eq!(
            read_path(&mut fs, &mut j, &mut d, "/documents/reused"),
            b"new name"
        );
        assert_eq!(
            fs.snapshot_open(
                first.snapshot_key,
                "/documents/report",
                "/absent",
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Auth)
        );
        assert_eq!(
            fs.snapshot_open(
                first.snapshot_key,
                "/absent/file",
                "/absent",
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::NotFound)
        );
    });
}

#[test]
fn restore_changes_only_business_epoch_and_preserves_system_contracts_and_old_history() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        let h = write_file(&mut fs, &mut j, &mut d, "/file", b"version1");
        let saved = capture(&mut fs, &mut j, &mut d, 1);
        let historical = fs
            .snapshot_open(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, b"version2", &mut j, &mut d, &mut s).unwrap();
        let mut work = [[0; BLOCK_SIZE]; 16];
        let mut volume = Volume::open(&mut j, &mut d, &mut s, &mut work).unwrap();
        volume
            .append(
                &mut j,
                &mut d,
                &mut s,
                &mut work,
                b"nonrollback-contract",
                false,
            )
            .unwrap();
        let r = request(&fs, 15, 2, true);
        let restored = fs
            .snapshot_execute(
                r,
                snapshot::OP_RESTORE,
                &restore_payload(saved.snapshot_key, 1),
                &mut j,
                &mut d,
                &mut s,
            )
            .unwrap();
        assert_eq!(restored.state, RequestState::Done);
        assert_eq!(fs.live_view_epoch(), 2);
        assert_eq!(
            fs.read(h, 0, &mut [0; 8], 0, &mut j, &mut d, &mut s),
            Err(Error::Stale)
        );
        assert_eq!(read(&mut fs, &mut j, &mut d, historical), b"version1");
        assert_eq!(read_path(&mut fs, &mut j, &mut d, "/file"), b"version1");
        assert_eq!(
            fs.create("/blocked", &mut j, &mut d, &mut s),
            Err(Error::ReadOnly)
        );
        let mut out = [0; 64];
        assert_eq!(
            volume
                .next(
                    &mut j,
                    &mut d,
                    &mut s,
                    &mut work,
                    &mut Cursor::new(),
                    &mut out
                )
                .unwrap(),
            Some(20)
        );
        assert_eq!(&out[..20], b"nonrollback-contract");
        // History lookup precedes the now-stale expected epoch.
        assert_eq!(
            fs.snapshot_execute(
                r,
                snapshot::OP_RESTORE,
                &restore_payload(saved.snapshot_key, 1),
                &mut j,
                &mut d,
                &mut s
            )
            .unwrap(),
            restored
        );
        fs.snapshot_ack(r.key, restored.result_digest, &mut j, &mut d, &mut s)
            .unwrap();
        let mut open = [0; 48];
        open[..8].copy_from_slice(
            &fs.snapshot_control()
                .unwrap()
                .protection_generation
                .to_le_bytes(),
        );
        r.key.encode(&mut open[8..44]).unwrap();
        let r = request(&fs, 15, 3, true);
        fs.snapshot_execute(r, snapshot::OP_OPEN_WRITES, &open, &mut j, &mut d, &mut s)
            .unwrap();
        fs.create("/open", &mut j, &mut d, &mut s).unwrap();
        let epoch = BootSession::new()
            .allocate(&mut j, &mut d, &mut s, &mut [[0; BLOCK_SIZE]; 4])
            .unwrap()
            .epoch;
        assert_eq!(epoch, 2);
        let (mut j, mut fs) = remount(&mut d);
        assert_eq!(fs.live_view_epoch(), 2);
        assert_eq!(read_path(&mut fs, &mut j, &mut d, "/file"), b"version1");
    });
}

#[test]
fn retention_pinned_reads_gc_and_slot_reuse_are_independent() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        let h = write_file(&mut fs, &mut j, &mut d, "/file", b"protected");
        let first = capture(&mut fs, &mut j, &mut d, 1);
        fs.close(h).unwrap();
        fs.unlink("/file", &mut j, &mut d, &mut s).unwrap();
        let history = fs
            .snapshot_open(first.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
            .unwrap();
        let r = request(&fs, 0, 2, false);
        let payload = key_bytes(first.snapshot_key);
        assert_eq!(
            fs.snapshot_execute(r, snapshot::OP_DELETE, &payload, &mut j, &mut d, &mut s),
            Err(Error::Auth)
        );
        fs.collect_garbage(&mut j, &mut d, &mut s).unwrap();
        assert_eq!(read(&mut fs, &mut j, &mut d, history), b"protected");
        fs.snapshot_maintenance(0, &mut j, &mut d, &mut s).unwrap();
        fs.snapshot_maintenance(3600 * snapshot::SECOND_NS, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(
            fs.snapshot_execute(r, snapshot::OP_DELETE, &payload, &mut j, &mut d, &mut s),
            Err(Error::Busy)
        );
        fs.close(history).unwrap();
        let deleted = fs
            .snapshot_execute(r, snapshot::OP_DELETE, &payload, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(deleted.state, RequestState::Done);
        assert_eq!(fs.snapshot_entries().unwrap()[6].state, State::Deleting);
        assert_eq!(
            fs.snapshot_open(first.snapshot_key, "/file", "/", &mut j, &mut d, &mut s),
            Err(Error::Stale)
        );
        assert!(fs.collect_garbage(&mut j, &mut d, &mut s).unwrap() >= 2);
        assert_eq!(fs.snapshot_entries().unwrap()[6].state, State::Free);
        let next = capture(&mut fs, &mut j, &mut d, 3);
        assert_eq!(next.snapshot_key.slot, 6);
        assert!(next.snapshot_key.snapshot_id > first.snapshot_key.snapshot_id);
        assert!(next.snapshot_key.slot_generation > first.snapshot_key.slot_generation);
        assert_eq!(
            fs.snapshot_execute(r, snapshot::OP_DELETE, &payload, &mut j, &mut d, &mut s)
                .unwrap(),
            deleted
        );
    });
}

#[test]
fn request_retries_conflicts_ack_and_protection_generation_are_persistent() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        let saved = capture(&mut fs, &mut j, &mut d, 1);
        let r = request(&fs, 0, 1, true);
        assert_eq!(
            fs.snapshot_execute(
                r,
                snapshot::OP_CREATE,
                &create_payload(3600),
                &mut j,
                &mut d,
                &mut s
            )
            .unwrap(),
            saved
        );
        assert_eq!(
            fs.snapshot_execute(
                r,
                snapshot::OP_CREATE,
                &create_payload(7200),
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Conflict)
        );
        fs.snapshot_ack(r.key, saved.result_digest, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(
            fs.snapshot_execute(
                r,
                snapshot::OP_CREATE,
                &create_payload(3600),
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Stale)
        );
        let generation = fs.snapshot_control().unwrap().protection_generation;
        let mut payload = [0; 16];
        payload[..8].copy_from_slice(&generation.to_le_bytes());
        let r = request(&fs, 15, 2, false);
        let frozen = fs
            .snapshot_execute(r, snapshot::OP_FREEZE_SET, &payload, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(
            fs.snapshot_control().unwrap().protection_generation,
            generation + 1
        );
        assert_eq!(
            fs.snapshot_execute(r, snapshot::OP_FREEZE_SET, &payload, &mut j, &mut d, &mut s)
                .unwrap(),
            frozen
        );
        let next = request(&fs, 15, 3, false);
        assert_eq!(
            fs.snapshot_execute(
                next,
                snapshot::OP_FREEZE_CLEAR,
                &generation.to_le_bytes(),
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Stale)
        );
        // Freeze disallows root removal, not proven unreachable CoW cleanup.
        fs.collect_garbage(&mut j, &mut d, &mut s).unwrap();
        let (mut j, mut fs) = remount(&mut d);
        fs.initialize_business(&mut j, &mut d, &mut s).unwrap();
        assert_eq!(
            fs.snapshot_control().unwrap().business_write_gate,
            Gate::Frozen
        );
        assert!(fs.snapshot_control().unwrap().cleanup_freeze);
        assert_eq!(
            fs.snapshot_query_request(r.key, &mut j, &mut d, &mut s)
                .unwrap(),
            frozen
        );
    });
}

fn prepared_base() -> (Disk, SnapshotKey) {
    let (mut d, mut j, mut fs) = blank();
    let mut s = [0; 8192];
    let h = write_file(&mut fs, &mut j, &mut d, "/file", b"before");
    let snapshot = capture(&mut fs, &mut j, &mut d, 1).snapshot_key;
    fs.close(h).unwrap();
    j.checkpoint(&mut d, &mut s).unwrap();
    d.crash();
    (d, snapshot)
}
#[test]
fn snapshot_publish_is_atomic_at_every_write_and_flush_power_cut() {
    large(|| {
        let (base, original) = prepared_base();
        let run = |mut d: Disk, fault: Option<(usize, bool)>| {
            let (mut j, mut fs) = remount(&mut d);
            let mut s = [0; 8192];
            let h = fs
                .open("/file", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
                .unwrap();
            fs.write(h, 0, b"after!", &mut j, &mut d, &mut s).unwrap();
            let r = request(&fs, 0, 2, true);
            d.events = 0;
            d.fail = fault;
            let result = fs.snapshot_execute(
                r,
                snapshot::OP_CREATE,
                &create_payload(3600),
                &mut j,
                &mut d,
                &mut s,
            );
            let events = d.events;
            let (mut j, mut fs) = remount(&mut d);
            let h = fs
                .snapshot_open(original, "/file", "/", &mut j, &mut d, &mut s)
                .unwrap();
            assert_eq!(read(&mut fs, &mut j, &mut d, h), b"before");
            match fs.snapshot_query_request(r.key, &mut j, &mut d, &mut s) {
                Ok(record) if record.state == RequestState::Done => {
                    let h = fs
                        .snapshot_open(record.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
                        .unwrap();
                    assert_eq!(read(&mut fs, &mut j, &mut d, h), b"after!");
                    assert_eq!(
                        fs.snapshot_execute(
                            r,
                            snapshot::OP_CREATE,
                            &create_payload(3600),
                            &mut j,
                            &mut d,
                            &mut s
                        )
                        .unwrap(),
                        record
                    );
                }
                Ok(record) => {
                    assert_eq!(record.state, RequestState::Incomplete);
                    assert_eq!(fs.snapshot_entries().unwrap()[7].state, State::Free);
                }
                Err(Error::Stale) => {
                    assert!(result.is_err());
                    assert_eq!(fs.snapshot_entries().unwrap()[7].state, State::Free);
                }
                other => panic!("unexpected recovery: {other:?}"),
            }
            if result.is_ok() {
                assert_eq!(fs.snapshot_entries().unwrap()[7].state, State::Active);
            }
            events
        };
        let events = run(base.clone(), None);
        assert!(events > 40);
        for event in 1..=events {
            for after in [false, true] {
                run(base.clone(), Some((event, after)));
            }
        }
    });
}

#[test]
fn restore_power_cuts_publish_whole_business_table_and_keep_write_gate_closed() {
    large(|| {
        let (mut base, original) = prepared_base();
        let (mut j, mut fs) = remount(&mut base);
        let mut s = [0; 8192];
        let h = fs
            .open("/file", OpenMode::ReadWrite, &mut j, &mut base, &mut s)
            .unwrap();
        fs.write(h, 0, b"after!", &mut j, &mut base, &mut s)
            .unwrap();
        fs.fsync(h, &mut j, &mut base, &mut s).unwrap();
        j.checkpoint(&mut base, &mut s).unwrap();
        base.crash();
        let run = |mut d: Disk, fault: Option<(usize, bool)>| {
            let (mut j, mut fs) = remount(&mut d);
            let mut s = [0; 8192];
            let r = request(&fs, 15, 2, true);
            d.events = 0;
            d.fail = fault;
            let result = fs.snapshot_execute(
                r,
                snapshot::OP_RESTORE,
                &restore_payload(original, 2),
                &mut j,
                &mut d,
                &mut s,
            );
            let events = d.events;
            let (mut j, mut fs) = remount(&mut d);
            let bytes = read_path(&mut fs, &mut j, &mut d, "/file");
            match fs.snapshot_query_request(r.key, &mut j, &mut d, &mut s) {
                Ok(record) if record.state == RequestState::Done => {
                    assert_eq!(bytes, b"before");
                    assert_eq!(fs.live_view_epoch(), 2);
                    assert_eq!(
                        fs.snapshot_control().unwrap().business_write_gate,
                        Gate::Frozen
                    );
                }
                Ok(record) => {
                    assert_eq!(record.state, RequestState::Incomplete);
                    assert_eq!(bytes, b"after!");
                    assert_eq!(fs.live_view_epoch(), 1);
                    assert_eq!(
                        fs.snapshot_control().unwrap().business_write_gate,
                        Gate::Frozen
                    );
                }
                Err(Error::Stale) => {
                    assert!(result.is_err());
                    assert_eq!(bytes, b"after!");
                    assert_eq!(fs.live_view_epoch(), 1);
                }
                other => panic!("unexpected recovery: {other:?}"),
            }
            events
        };
        let events = run(base.clone(), None);
        assert!(events > 30);
        for event in 1..=events {
            for after in [false, true] {
                run(base.clone(), Some((event, after)));
            }
        }
    });
}

#[test]
fn gc_power_cuts_between_both_checkpoints_never_reuse_a_protected_root() {
    large(|| {
        let (mut base, original) = prepared_base();
        let (mut j, mut fs) = remount(&mut base);
        let mut s = [0; 8192];
        fs.unlink("/file", &mut j, &mut base, &mut s).unwrap();
        fs.snapshot_maintenance(0, &mut j, &mut base, &mut s)
            .unwrap();
        fs.snapshot_maintenance(3600 * snapshot::SECOND_NS, &mut j, &mut base, &mut s)
            .unwrap();
        let r = request(&fs, 0, 2, false);
        fs.snapshot_execute(
            r,
            snapshot::OP_DELETE,
            &key_bytes(original),
            &mut j,
            &mut base,
            &mut s,
        )
        .unwrap();
        j.checkpoint(&mut base, &mut s).unwrap();
        base.crash();
        let run = |mut d: Disk, fault: Option<(usize, bool)>| {
            let (mut j, mut fs) = remount(&mut d);
            let mut s = [0; 8192];
            d.events = 0;
            d.fail = fault;
            let result = fs.collect_garbage(&mut j, &mut d, &mut s);
            let events = d.events;
            let (mut j, mut fs) = remount(&mut d);
            assert_eq!(
                fs.snapshot_open(original, "/file", "/", &mut j, &mut d, &mut s),
                Err(Error::Stale)
            );
            fs.collect_garbage(&mut j, &mut d, &mut s).unwrap();
            assert_eq!(fs.snapshot_entries().unwrap()[6].state, State::Free);
            let h = write_file(&mut fs, &mut j, &mut d, "/reused", b"safe-new-data");
            fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
            for slot in [0, 3] {
                let e = fs.snapshot_entries().unwrap()[slot];
                let k = e.key(fs.snapshot_uuid().unwrap(), slot);
                let root = fs
                    .snapshot_open(k, "/", "/", &mut j, &mut d, &mut s)
                    .unwrap();
                assert_eq!(fs.readdir(root, 0, &mut j, &mut d, &mut s).unwrap(), None);
            }
            if result.is_ok() {
                assert!(events > 0);
            }
            events
        };
        let events = run(base.clone(), None);
        assert!(events > 20);
        for event in 1..=events {
            for after in [false, true] {
                run(base.clone(), Some((event, after)));
            }
        }
    });
}

#[test]
fn history_quota_cannot_consume_recovery_handles_or_frozen_views() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        let h = write_file(&mut fs, &mut j, &mut d, "/file", b"snapshot");
        let saved = capture(&mut fs, &mut j, &mut d, 1);
        fs.close(h).unwrap();
        let mut ordinary = Vec::new();
        for _ in 0..56 {
            ordinary.push(
                fs.snapshot_open(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
                    .unwrap(),
            );
        }
        assert_eq!(
            fs.snapshot_open(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s),
            Err(Error::Again)
        );
        let mut recovery = Vec::new();
        for _ in 0..8 {
            recovery.push(
                fs.snapshot_open_recovery(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
                    .unwrap(),
            );
        }
        assert_eq!(
            fs.snapshot_open_recovery(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s),
            Err(Error::Again)
        );
        assert_eq!(fs.snapshot_root_refs(6).unwrap(), 64);
        for h in ordinary.into_iter().chain(recovery) {
            assert_eq!(read(&mut fs, &mut j, &mut d, h), b"snapshot");
            fs.close(h).unwrap();
        }
        assert_eq!(fs.snapshot_root_refs(6).unwrap(), 0);
    });
}

#[test]
fn maximum_dirty_page_barrier_flushes_4096_pages_without_discarding_accepted_bytes() {
    std::thread::Builder::new().stack_size(128 * 1024 * 1024).spawn(|| {
        let mut d = Disk::default(); let mut j = Journal::new(); let mut s = [0; 8192];
        journal::format(&mut d, [0x18; 16], &mut s).unwrap(); j.mount(&mut d, &mut s).unwrap();
        BootSession::new().allocate(&mut j, &mut d, &mut s, &mut [[0; BLOCK_SIZE]; 4]).unwrap();
        let mut fs = Box::new(FileSystem::<4096>::new()); fs.mount(&mut j, &mut d, &mut s).unwrap(); fs.initialize_business(&mut j, &mut d, &mut s).unwrap(); fs.set_cache_budget(4096).unwrap();
        let mut handles = Vec::new();
        for file in 0..2 {
            let path = format!("/large-{file}"); fs.create(&path, &mut j, &mut d, &mut s).unwrap();
            let h = fs.open(&path, OpenMode::ReadWrite, &mut j, &mut d, &mut s).unwrap(); handles.push(h);
            for part in 0..128u64 { fs.write(h, part * 65536, &[file as u8 + 0x40; 65536], &mut j, &mut d, &mut s).unwrap(); }
        }
        assert_eq!(fs.metrics().dirty_pages, 4096);
        let request = Request { key: FileReqKey { fs_uuid: fs.snapshot_uuid().unwrap(), client_slot: 0, client_generation: 1, request_seq: 1 }, expected_live_view_epoch: 1 };
        let before = d.events; let started = std::time::Instant::now();
        let saved = fs.snapshot_execute(request, snapshot::OP_CREATE, &create_payload(3600), &mut j, &mut d, &mut s).unwrap();
        eprintln!("snapshot host maximum-dirty: pages=4096, events={}, elapsed_ms={}, gc_scratch_bytes={}", d.events - before, started.elapsed().as_millis(), cyxia_prototype::domains::filesystem::GC_SCRATCH_BYTES);
        assert_eq!(saved.state, RequestState::Done); assert_eq!(fs.metrics().dirty_pages, 0);
        for (file, h) in handles.into_iter().enumerate() {
            let receipt = fs.fsync(h, &mut j, &mut d, &mut s).unwrap(); assert_eq!(receipt.write_seq, 128); assert_eq!(receipt.transactions, 0); assert_eq!(receipt.live_view_epoch, 1);
            let hist = fs.snapshot_open(saved.snapshot_key, &format!("/large-{file}"), "/", &mut j, &mut d, &mut s).unwrap();
            for offset in [0, 4 * 1024 * 1024, 8 * 1024 * 1024 - 4096] {
                let mut bytes = [0; BLOCK_SIZE]; assert_eq!(fs.read(hist, offset, &mut bytes, 0, &mut j, &mut d, &mut s).unwrap(), BLOCK_SIZE); assert_eq!(bytes, [file as u8 + 0x40; BLOCK_SIZE]);
            }
        }
    }).unwrap().join().unwrap();
}

#[test]
fn observed_snapshot_corruption_freezes_cleanup_and_cannot_be_cleared_without_revalidation() {
    large(|| {
        let (mut d, mut j, mut fs) = blank();
        let mut s = [0; 8192];
        let h = write_file(&mut fs, &mut j, &mut d, "/file", b"protected");
        let saved = capture(&mut fs, &mut j, &mut d, 1);
        fs.close(h).unwrap();
        j.checkpoint(&mut d, &mut s).unwrap();
        let descriptor = fs.snapshot_entries().unwrap()[6].descriptor_block;
        let valid_page = d.stable[&descriptor];
        d.stable.get_mut(&descriptor).unwrap()[100] ^= 0x80;
        assert_eq!(
            fs.snapshot_open(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s),
            Err(Error::Format)
        );
        let control = fs.snapshot_control().unwrap();
        assert!(control.cleanup_freeze);
        assert_eq!(control.business_write_gate, Gate::Frozen);
        assert_eq!(fs.snapshot_entries().unwrap()[6].state, State::Active);
        assert_eq!(
            fs.create("/denied", &mut j, &mut d, &mut s),
            Err(Error::ReadOnly)
        );
        let r = request(&fs, 15, 2, false);
        assert_eq!(
            fs.snapshot_execute(
                r,
                snapshot::OP_FREEZE_CLEAR,
                &control.protection_generation.to_le_bytes(),
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Format)
        );
        assert!(fs.snapshot_control().unwrap().cleanup_freeze);
        // Simulate a verified offline repair of the damaged page. No mutation
        // capability or snapshot-delete operation can perform this repair.
        d.stable.insert(descriptor, valid_page);
        fs.snapshot_execute(
            r,
            snapshot::OP_FREEZE_CLEAR,
            &control.protection_generation.to_le_bytes(),
            &mut j,
            &mut d,
            &mut s,
        )
        .unwrap();
        assert!(!fs.snapshot_control().unwrap().cleanup_freeze);
        assert_eq!(
            fs.snapshot_control().unwrap().business_write_gate,
            Gate::Frozen
        );
        let history = fs
            .snapshot_open(saved.snapshot_key, "/file", "/", &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(read(&mut fs, &mut j, &mut d, history), b"protected");
    });
}
