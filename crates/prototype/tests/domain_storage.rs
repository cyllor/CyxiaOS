use cyxia_prototype::{
    boot::BootSession,
    cluster::volume::{Cursor, Volume},
    domains::{
        Action, Error, ObjectKey, PolicyStamp,
        filesystem::{FIRST_ORDINARY_BLOCK, FileSystem, OpenMode, validate_volume},
        io::{Class, ORDINARY_BYTES, Request, Scheduler, Submission},
    },
    journal::{self, AfterImage, BlockDevice, Journal},
    storage::{INODE_START, Inode, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

#[test]
fn byte_grant_owns_real_credits_without_a_fake_completion() {
    let mut io = Scheduler::new(16, 16);
    io.recovery_reserve(2, 2).unwrap();
    let first = Request {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        class: Class::Background,
        bytes: 512,
        pages: 2,
        descriptors: 2,
    };
    let recovery = io
        .enqueue(
            Request {
                class: Class::Recovery,
                ..first
            },
            0,
        )
        .unwrap();
    io.cancel(recovery).unwrap();
    let stamp = PolicyStamp::new(1, 1, 1).unwrap();
    io.apply(Action::IoShare(100), stamp, 1).unwrap();
    assert_eq!(
        io.apply(Action::IoShare(750), stamp, 1),
        Err(Error::Conflict)
    );
    assert_eq!(io.reserve_admission(first, 4096, 1, 1), Err(Error::Again));
    assert_eq!(io.usage().ordinary_credits, 0);
    let grant = io.reserve_admission(first, 4096, 1, 100_000_000).unwrap();
    assert_eq!(grant.policy_version, 1);
    assert_eq!(io.reserved_bytes(), 4096);
    assert_eq!(
        (
            io.usage().submit_credits,
            io.usage().ordinary_credits,
            io.usage().pages,
            io.usage().descriptors
        ),
        (1, 1, 2, 2)
    );
    assert_eq!(
        (
            io.stats().submitted,
            io.stats().completed,
            io.usage().background_bytes
        ),
        (0, 0, 0)
    );
    assert_eq!(
        io.complete(grant.ticket, Ok(()), 100_000_001),
        Err(Error::Conflict)
    );
    assert_eq!(
        io.enqueue(Request { pages: 13, ..first }, 100_000_001),
        Err(Error::Again)
    );
    let recovery = io
        .enqueue(
            Request {
                class: Class::Recovery,
                ..first
            },
            100_000_001,
        )
        .unwrap();
    io.cancel(recovery).unwrap();
    io.cancel_admission(grant).unwrap();
    assert_eq!(io.reserved_bytes(), 0);
    assert_eq!(
        (
            io.usage().submit_credits,
            io.usage().ordinary_credits,
            io.usage().pages
        ),
        (0, 0, 0)
    );
}

#[test]
fn granted_slot_becomes_the_real_first_request_and_unknown_retains_it() {
    let mut io = Scheduler::new(16, 16);
    let first = Request {
        object: ObjectKey {
            id: 1,
            generation: 1,
        },
        class: Class::Background,
        bytes: 512,
        pages: 2,
        descriptors: 2,
    };
    io.apply(Action::IoShare(250), PolicyStamp::new(7, 0, 0).unwrap(), 0)
        .unwrap();
    let grant = io.reserve_admission(first, 4096, 7, 0).unwrap();
    io.begin_admission(grant, 1024).unwrap();
    let a = io.activate_admission(grant, first, 1).unwrap();
    assert_eq!(a, grant.ticket);
    assert_eq!(io.reserved_slots(), 0);
    assert_eq!(
        io.dispatch(1, |_, _| true, |_, _| Submission::Unknown)
            .unwrap(),
        Some(a)
    );
    assert_eq!(io.cancel_admission(grant), Err(Error::Busy));
    assert_eq!(io.finish_transaction(grant.permit), Err(Error::Busy));
    let b = io.enqueue_transaction(first, grant.permit, 2).unwrap();
    assert_eq!(
        io.dispatch(2, |_, _| true, |_, _| Submission::Accepted)
            .unwrap(),
        Some(b)
    );
    assert_eq!(io.reserved_bytes(), 0);
    io.complete(b, Ok(()), 3).unwrap();
    assert_eq!(io.acknowledge(b).unwrap().policy_version, 7);
    assert_eq!(io.usage().ordinary_credits, 1);
    io.complete(a, Ok(()), 4).unwrap();
    assert_eq!(io.acknowledge(a).unwrap().policy_version, 7);
    io.finish_transaction(grant.permit).unwrap();
    assert_eq!((io.stats().submitted, io.stats().completed), (2, 2));
    assert_eq!((io.usage().ordinary_credits, io.usage().pages), (0, 0));
}

#[test]
fn expired_cache_partition_closes_admission_and_required_writeback_drains_dirty_debt() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.set_cache_partition(4, 2).unwrap();
        let stamp = PolicyStamp::new(1, 0, 0).unwrap();
        fs.set_cache_partition_expiring(32, 4, stamp, 0).unwrap();
        fs.create("/debt", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/debt", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, &[3; 65536], &mut j, &mut d, &mut s).unwrap();
        fs.refresh_cache_partition(10_000_000_000);
        assert_eq!(fs.cache_usage(), [16, 16, 4, 64]);
        fs.set_cache_partition_expiring(32, 4, stamp, 10_000_000_000)
            .unwrap();
        assert_eq!(fs.cache_usage()[2], 4); // an exact retry does not renew TTL
        assert_eq!(
            fs.write(h, 65536, &[1; 4096], &mut j, &mut d, &mut s),
            Err(Error::Again)
        );
        let mut out = [0; 16];
        fs.read(h, 0, &mut out, 10_000_000_000, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(out, [3; 16]);
        let receipt = fs
            .reclaim_flush_one(&mut j, &mut d, &mut s)
            .unwrap()
            .unwrap();
        assert_eq!((receipt.pages, receipt.policy_version), (16, 0));
        assert_eq!(fs.metrics().last_flush_version, 0);
        assert_eq!(fs.reclaim_cache(), 2);
        assert_eq!(fs.cache_usage(), [14, 0, 4, 64]);
    });
}

#[test]
fn control_reads_do_not_perform_cache_expiry_or_release_actual_dirty_occupancy() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.set_cache_partition(4, 2).unwrap();
        let stamp = PolicyStamp::new(1, 0, 0).unwrap();
        fs.set_cache_partition_expiring(32, 4, stamp, 0).unwrap();
        fs.create("/snapshot-debt", &mut j, &mut d, &mut s).unwrap();
        let handle = fs
            .open(
                "/snapshot-debt",
                OpenMode::ReadWrite,
                &mut j,
                &mut d,
                &mut s,
            )
            .unwrap();
        fs.write(handle, 0, &[0x4a; 65536], &mut j, &mut d, &mut s)
            .unwrap();
        let usage = fs.cache_usage();
        let disk_counts = (d.reads, d.writes, d.flushes);
        assert_eq!(
            fs.cache_partition_deadline_ns(),
            Some(stamp.installed_until_ns)
        );
        assert_eq!(
            fs.cache_partition_status(stamp.installed_until_ns - 1),
            Ok(usage)
        );
        for _ in 0..4 {
            assert_eq!(
                fs.cache_partition_status(stamp.installed_until_ns),
                Err(Error::Busy)
            );
        }
        assert_eq!(fs.cache_usage(), usage);
        assert_eq!((d.reads, d.writes, d.flushes), disk_counts);
        // Only the actual CPU0/cache-owner transition can publish baseline.
        fs.refresh_cache_partition(stamp.installed_until_ns);
        assert_eq!(fs.cache_partition_deadline_ns(), None);
        assert_eq!(
            fs.cache_partition_status(stamp.installed_until_ns),
            Ok([16, 16, 4, 64])
        );
        assert_eq!((d.reads, d.writes, d.flushes), disk_counts);
    });
}

#[test]
fn io_control_view_has_a_window_deadline_and_never_grants_resources() {
    let mut io = Scheduler::new(16, 16);
    let stamp = PolicyStamp::new(1, 5, 5).unwrap();
    io.apply(Action::IoShare(750), stamp, 5).unwrap();
    let initial = io.usage();
    for now in [5, 10, 99_999_999] {
        assert_eq!(io.current_action(now), Action::IoShare(750));
        assert_eq!(io.control_view_until_ns(now), Ok(100_000_000));
        assert_eq!(io.reserved_bytes(), 0);
        assert_eq!(io.reserved_slots(), 0);
        assert_eq!(io.usage(), initial);
    }
    assert_eq!(
        io.control_view_until_ns(10_000_000_000),
        Ok(stamp.installed_until_ns)
    );
    assert_eq!(
        io.current_action(stamp.installed_until_ns),
        Action::IoShare(250)
    );
    assert_eq!(io.control_view_until_ns(u64::MAX), Err(Error::Overflow));
    assert_eq!((io.stats().submitted, io.stats().completed), (0, 0));
    assert_eq!(io.usage(), initial);
}

#[derive(Default)]
struct Disk {
    durable: BTreeMap<u32, Box<[u8; 4096]>>,
    pending: BTreeMap<u32, Box<[u8; 4096]>>,
    reads: u64,
    writes: u64,
    flushes: u64,
    lose_flush: Option<u32>,
}
impl Disk {
    fn crash(&mut self) {
        self.pending.clear();
        self.lose_flush = None;
    }
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, n: u32, out: &mut [u8; 4096]) -> Result<(), ()> {
        self.reads += 1;
        if let Some(b) = self.pending.get(&n).or_else(|| self.durable.get(&n)) {
            out.copy_from_slice(b.as_ref());
        } else {
            out.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, n: u32, data: &[u8; 4096]) -> Result<(), ()> {
        self.writes += 1;
        self.pending.insert(n, Box::new(*data));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        self.flushes += 1;
        self.durable.append(&mut self.pending);
        if let Some(left) = self.lose_flush.as_mut() {
            *left -= 1;
            if *left == 0 {
                self.lose_flush = None;
                return Err(());
            }
        }
        Ok(())
    }
}
fn fixture() -> (Disk, Journal) {
    let mut d = Disk::default();
    let mut s = [0; 8192];
    journal::format(&mut d, [7; 16], &mut s).unwrap();
    let mut j = Journal::new();
    j.mount(&mut d, &mut s).unwrap();
    BootSession::new()
        .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
        .unwrap();
    (d, j)
}
fn large(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn ordinary_crud_fsync_reboot_and_generation_custody() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.mkdir("/data", &mut j, &mut d, &mut s).unwrap();
        let key = fs.create("/data/a", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/data/a", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(
            fs.write(h, 1, b"hole", &mut j, &mut d, &mut s),
            Err(Error::Range)
        );
        fs.write(h, 0, b"accepted", &mut j, &mut d, &mut s).unwrap();
        let stat = fs.stat_object(key).unwrap();
        assert_eq!((stat.write_seq, stat.durable_write_seq), (1, 0));
        assert_eq!(
            fs.unlink("/data/a", &mut j, &mut d, &mut s),
            Err(Error::Busy)
        );
        assert_eq!(
            fs.unlink("/data", &mut j, &mut d, &mut s),
            Err(Error::NotEmpty)
        );
        assert_eq!(fs.fsync(h, &mut j, &mut d, &mut s).unwrap().write_seq, 1);
        fs.close(h).unwrap();
        assert_eq!(fs.close(h), Err(Error::Stale));
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut s).unwrap();
        assert_eq!(
            BootSession::new()
                .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
                .unwrap()
                .epoch,
            2
        );
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/data/a", OpenMode::Read, &mut j, &mut d, &mut s)
            .unwrap();
        let mut out = [0; 16];
        assert_eq!(
            fs.read(h, 0, &mut out, 0, &mut j, &mut d, &mut s).unwrap(),
            8
        );
        assert_eq!(&out[..8], b"accepted");
        assert_eq!(
            fs.write(h, 0, b"x", &mut j, &mut d, &mut s),
            Err(Error::Auth)
        );
        fs.close(h).unwrap();
        let dir = fs
            .open("/data", OpenMode::Directory, &mut j, &mut d, &mut s)
            .unwrap();
        let entry = fs.readdir(dir, 0, &mut j, &mut d, &mut s).unwrap().unwrap();
        assert_eq!(entry.object, key);
        assert_eq!(&entry.name[..entry.name_len as usize], b"a");
        assert!(
            fs.readdir(dir, entry.next_cookie, &mut j, &mut d, &mut s)
                .unwrap()
                .is_none()
        );
        fs.close(dir).unwrap();
        fs.unlink("/data/a", &mut j, &mut d, &mut s).unwrap();
        let next = fs.create("/data/b", &mut j, &mut d, &mut s).unwrap();
        assert_eq!(next.id, key.id);
        assert!(next.generation > key.generation);
        assert_eq!(fs.stat_object(key), Err(Error::Stale));
        validate_volume(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4]).unwrap();
    });
}

#[test]
fn accepted_write_is_not_durability_and_unknown_second_flush_never_replies_success() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.create("/a", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/a", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, b"lost", &mut j, &mut d, &mut s).unwrap();
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut s).unwrap();
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        assert_eq!(fs.stat("/a", &mut j, &mut d, &mut s).unwrap().size, 0);
        let h = fs
            .open("/a", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, b"durable but reply lost", &mut j, &mut d, &mut s)
            .unwrap();
        d.lose_flush = Some(2);
        assert_eq!(fs.fsync(h, &mut j, &mut d, &mut s), Err(Error::Io));
        assert_eq!(fs.write(h, 0, b"x", &mut j, &mut d, &mut s), Err(Error::Io));
        fs.close(h).unwrap();
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut s).unwrap();
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let stat = fs.stat("/a", &mut j, &mut d, &mut s).unwrap();
        assert_eq!((stat.size, stat.durable_write_seq), (22, 1));
    });
}

#[test]
fn partial_background_commit_exposes_only_initialized_prefix() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.create("/prefix", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/prefix", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, &[0x5a; 65536], &mut j, &mut d, &mut s)
            .unwrap();
        let r = fs
            .background_flush(0, &mut j, &mut d, &mut s)
            .unwrap()
            .unwrap();
        assert_eq!((r.pages, r.durable_write_seq), (4, 0));
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut s).unwrap();
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let stat = fs.stat("/prefix", &mut j, &mut d, &mut s).unwrap();
        assert_eq!((stat.size, stat.durable_write_seq), (16384, 0));
        let h = fs
            .open("/prefix", OpenMode::Read, &mut j, &mut d, &mut s)
            .unwrap();
        let mut out = [0; 65536];
        assert_eq!(
            fs.read(h, 0, &mut out, 0, &mut j, &mut d, &mut s).unwrap(),
            16384
        );
        assert!(out[..16384].iter().all(|b| *b == 0x5a));
        validate_volume(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4]).unwrap();
    });
}

#[test]
fn ordinary_and_reserved_cluster_files_share_metadata_without_overwriting_slots() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        for i in 0..40 {
            fs.create(&format!("/f{i}"), &mut j, &mut d, &mut s)
                .unwrap();
        }
        let mut w = [[0; 4096]; 16];
        let mut volume = Volume::open(&mut j, &mut d, &mut s, &mut w).unwrap();
        volume
            .append(&mut j, &mut d, &mut s, &mut w, b"contract", false)
            .unwrap();
        fs.create("/later", &mut j, &mut d, &mut s).unwrap();
        for i in 0..40 {
            fs.stat(&format!("/f{i}"), &mut j, &mut d, &mut s).unwrap();
        }
        assert_eq!(
            fs.open("/.cyxia-cluster-a", OpenMode::Read, &mut j, &mut d, &mut s),
            Err(Error::Auth)
        );
        let mut cursor = Cursor::new();
        let mut body = [0; 64];
        assert_eq!(
            volume
                .next(&mut j, &mut d, &mut s, &mut w, &mut cursor, &mut body)
                .unwrap(),
            Some(8)
        );
        assert_eq!(&body[..8], b"contract");
        d.crash();
        let mut j = Journal::new();
        j.mount(&mut d, &mut s).unwrap();
        assert_eq!(
            BootSession::new()
                .allocate(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4])
                .unwrap()
                .epoch,
            2
        );
    });
}

#[test]
fn selected_readahead_and_writeback_versions_execute_real_io() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.create("/a", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/a", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        fs.write(h, 0, &[9; 65536], &mut j, &mut d, &mut s).unwrap();
        fs.apply(
            Action::Filesystem {
                readahead: 0,
                flush: 4,
            },
            PolicyStamp::new(1, 0, 0).unwrap(),
            0,
        )
        .unwrap();
        let r = fs
            .background_flush(0, &mut j, &mut d, &mut s)
            .unwrap()
            .unwrap();
        assert_eq!((r.pages, r.policy_version), (4, 1));
        fs.apply(
            Action::Filesystem {
                readahead: 2,
                flush: 8,
            },
            PolicyStamp::new(2, 1, 1).unwrap(),
            1,
        )
        .unwrap();
        let r = fs
            .background_flush(1, &mut j, &mut d, &mut s)
            .unwrap()
            .unwrap();
        assert_eq!((r.pages, r.policy_version), (8, 2));
        fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
        j.checkpoint(&mut d, &mut s).unwrap();
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/a", OpenMode::Read, &mut j, &mut d, &mut s)
            .unwrap();
        fs.apply(
            Action::Filesystem {
                readahead: 8,
                flush: 16,
            },
            PolicyStamp::new(3, 2, 2).unwrap(),
            2,
        )
        .unwrap();
        let mut out = [0; 4096];
        // A pending prerequisite closes only new optional use. Demand data
        // remains readable, while the blocked policy earns no read receipt.
        fs.read_admitted(h, 10 * 4096, &mut out, 2, false, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(out, [9; 4096]);
        assert_eq!(fs.metrics().readahead_pages, 0);
        assert_eq!(fs.metrics().last_read_version, 0);
        let before = d.reads;
        fs.read(h, 0, &mut out, 2, &mut j, &mut d, &mut s).unwrap();
        assert!(d.reads >= before + 9);
        assert_eq!(fs.metrics().readahead_pages, 8);
        let before = d.reads;
        fs.read(h, 4096, &mut out, 3, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(fs.metrics().readahead_hits, 1);
        assert_eq!(fs.metrics().last_read_version, 3);
        assert_eq!(d.reads, before + 1);
    });
}

#[test]
fn cache_shrink_is_bounded_and_never_discards_dirty_data() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        let (base, bytes) = fs.cache_backing();
        assert_eq!(base % 4096, 0);
        assert_eq!(bytes, 64 * 4096);
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.create("/cache", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/cache", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        for n in 0..3 {
            fs.write(h, n * 65536, &[42; 65536], &mut j, &mut d, &mut s)
                .unwrap();
        }
        fs.set_cache_partition(8, 4).unwrap();
        assert_eq!(fs.reclaim_cache(), 0);
        assert_eq!(fs.cache_usage(), [48, 48, 8, 64]);
        assert_eq!(
            fs.write(h, 3 * 65536, &[1; 4096], &mut j, &mut d, &mut s),
            Err(Error::Again)
        );
        fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
        for remaining in (8..48).step_by(4).rev() {
            assert_eq!(fs.reclaim_cache(), 4);
            assert_eq!(fs.cache_usage()[0], remaining);
        }
        assert_eq!(fs.reclaim_cache(), 0);
        let key = fs.handle_object(h).unwrap();
        let before = fs.cache_usage();
        let mut page = [0; 4096];
        fs.read_cache_page(key, 0, &mut page, &mut j, &mut d, &mut s)
            .unwrap();
        assert_eq!(page, [42; 4096]);
        assert_eq!(fs.cache_usage(), before);
        assert_eq!(
            fs.read_cache_page(
                ObjectKey {
                    generation: key.generation + 1,
                    ..key
                },
                0,
                &mut page,
                &mut j,
                &mut d,
                &mut s
            ),
            Err(Error::Stale)
        );
    });
}

#[test]
fn foreground_demand_distinguishes_disk_misses_from_cached_and_zero_filled_work() {
    large(|| {
        let (mut disk, mut journal) = fixture();
        let mut scratch = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
        fs.create("/demand", &mut journal, &mut disk, &mut scratch)
            .unwrap();
        let h = fs
            .open(
                "/demand",
                OpenMode::ReadWrite,
                &mut journal,
                &mut disk,
                &mut scratch,
            )
            .unwrap();
        let before = (disk.reads, disk.writes, disk.flushes);
        assert!(!fs.write_io_demand(h, 0, 16 * 1024).unwrap());
        fs.write(h, 0, &[7; 16 * 1024], &mut journal, &mut disk, &mut scratch)
            .unwrap();
        assert_eq!((disk.reads, disk.writes, disk.flushes), before);
        assert!(!fs.read_io_demand(h, 0, 4096, 0, false).unwrap());
        assert!(!fs.write_io_demand(h, 0, 4096).unwrap());
        fs.fsync(h, &mut journal, &mut disk, &mut scratch).unwrap();
        journal.checkpoint(&mut disk, &mut scratch).unwrap();

        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
        let h = fs
            .open(
                "/demand",
                OpenMode::ReadWrite,
                &mut journal,
                &mut disk,
                &mut scratch,
            )
            .unwrap();
        let before = (disk.reads, disk.writes, disk.flushes, fs.cache_usage());
        assert!(fs.read_io_demand(h, 0, 4096, 0, false).unwrap());
        assert!(fs.write_io_demand(h, 0, 4096).unwrap());
        assert!(!fs.read_io_demand(h, 0, 0, 0, false).unwrap());
        assert!(!fs.read_io_demand(h, 16 * 1024, 1, 0, false).unwrap());
        assert_eq!(
            (disk.reads, disk.writes, disk.flushes, fs.cache_usage()),
            before
        );
        fs.read_admitted(
            h,
            0,
            &mut [0; 4096],
            0,
            false,
            &mut journal,
            &mut disk,
            &mut scratch,
        )
        .unwrap();
        assert!(disk.reads > before.0);
        assert!(!fs.read_io_demand(h, 0, 4096, 0, false).unwrap());
        assert!(!fs.write_io_demand(h, 0, 4096).unwrap());

        fs.apply(
            Action::Filesystem {
                readahead: 2,
                flush: 8,
            },
            PolicyStamp::new(1, 1, 1).unwrap(),
            1,
        )
        .unwrap();
        assert!(fs.read_io_demand(h, 0, 4096, 1, true).unwrap());
        assert!(!fs.read_io_demand(h, 0, 4096, 1, false).unwrap());
        let before = disk.reads;
        fs.read(
            h,
            0,
            &mut [0; 4096],
            1,
            &mut journal,
            &mut disk,
            &mut scratch,
        )
        .unwrap();
        assert_eq!(disk.reads, before + 2);
        assert!(!fs.read_io_demand(h, 0, 4096, 1, true).unwrap());
        fs.set_cache_partition(1, 1).unwrap();
        assert!(!fs.read_io_demand(h, 3 * 4096, 4096, 1, false).unwrap());
        let before = disk.reads;
        assert_eq!(
            fs.read_admitted(
                h,
                3 * 4096,
                &mut [0; 4096],
                1,
                false,
                &mut journal,
                &mut disk,
                &mut scratch
            ),
            Err(Error::Again)
        );
        assert_eq!(disk.reads, before);
        fs.close(h).unwrap();
        assert_eq!(fs.read_io_demand(h, 0, 1, 1, false), Err(Error::Stale));
    });
}

#[test]
fn replay_cold_reset_requires_real_durability_and_preserves_other_objects() {
    large(|| {
        let (mut disk, mut journal) = fixture();
        let mut scratch = [0; 8192]; let mut fs = FileSystem::<64>::new();
        fs.mount(&mut journal, &mut disk, &mut scratch).unwrap();
        let object = fs.create("/replay", &mut journal, &mut disk, &mut scratch).unwrap();
        let other = fs.create("/ordinary", &mut journal, &mut disk, &mut scratch).unwrap();
        let h = fs.open("/replay", OpenMode::ReadWrite, &mut journal, &mut disk, &mut scratch).unwrap();
        let o = fs.open("/ordinary", OpenMode::ReadWrite, &mut journal, &mut disk, &mut scratch).unwrap();
        fs.write(h, 0, &[17; 8192], &mut journal, &mut disk, &mut scratch).unwrap();
        fs.write(o, 0, &[91; 4096], &mut journal, &mut disk, &mut scratch).unwrap();
        assert_eq!(fs.discard_clean_object_cache(object, 0, 64), Err(Error::Busy));
        assert_eq!(fs.metrics().dirty_pages, 3);
        let receipt = fs.fsync(h, &mut journal, &mut disk, &mut scratch).unwrap();
        assert_eq!(fs.stat_object(object).unwrap().durable_write_seq, receipt.write_seq);
        let before = fs.cache_usage();
        let mut cursor = 0;
        while cursor != 64 { cursor = fs.discard_clean_object_cache(object, cursor, 3).unwrap(); }
        assert_eq!(fs.cache_usage()[0], before[0] - 2);
        assert_eq!(fs.metrics().dirty_pages, 1);
        let mut bytes = [0; 8192]; let reads = disk.reads;
        fs.read(o, 0, &mut bytes[..4096], 0, &mut journal, &mut disk, &mut scratch).unwrap();
        assert_eq!(&bytes[..4096], &[91; 4096]); assert_eq!(disk.reads, reads);
        fs.read(h, 0, &mut bytes, 0, &mut journal, &mut disk, &mut scratch).unwrap();
        assert_eq!(bytes, [17; 8192]); assert!(disk.reads > reads);
        assert_eq!(fs.metrics().last_read_version, 0);
        assert_eq!(fs.metrics().last_flush_version, 0);
        assert_eq!(fs.stat_object(other).unwrap().durable_write_seq, 0);
        assert_eq!(fs.discard_clean_object_cache(ObjectKey { generation: object.generation + 1, ..object }, 0, 1), Err(Error::Stale));
        assert_eq!(fs.discard_clean_object_cache(object, 65, 1), Err(Error::Range));
        assert_eq!(fs.discard_clean_object_cache(object, 0, 0), Err(Error::Range));
    });
}

#[test]
fn allocation_limits_and_full_volume_owner_validation_are_enforced() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let a = fs.create("/a", &mut j, &mut d, &mut s).unwrap();
        let b = fs.create("/b", &mut j, &mut d, &mut s).unwrap();
        for path in ["/a", "/b"] {
            let h = fs
                .open(path, OpenMode::ReadWrite, &mut j, &mut d, &mut s)
                .unwrap();
            fs.write(h, 0, &[1; 4096], &mut j, &mut d, &mut s).unwrap();
            fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
            fs.close(h).unwrap();
        }
        let mut block = [0; 4096];
        let home = INODE_START + a.id as u32 / 16;
        j.read_block(&mut d, home, &mut block, &mut s).unwrap();
        let at = a.id as usize % 16 * 256;
        let source = Inode::decode(a.id as u32, &block[at..at + 256]).unwrap();
        assert!(source.extents[0].physical_start >= FIRST_ORDINARY_BLOCK);
        let at = b.id as usize % 16 * 256;
        let mut alias = Inode::decode(b.id as u32, &block[at..at + 256]).unwrap();
        alias.extents[0].physical_start = source.extents[0].physical_start;
        alias.encode(b.id as u32, &mut block[at..at + 256]).unwrap();
        j.commit(
            &mut d,
            &[AfterImage {
                home_block: home,
                bytes: &block,
            }],
            &mut s,
        )
        .unwrap();
        assert_eq!(
            validate_volume(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4]),
            Err(Error::Conflict)
        );
    });
}

#[test]
fn all_ordinary_inode_slots_and_eight_mib_file_are_real() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        fs.create("/full", &mut j, &mut d, &mut s).unwrap();
        let h = fs
            .open("/full", OpenMode::ReadWrite, &mut j, &mut d, &mut s)
            .unwrap();
        for n in 0..128 {
            fs.write(h, n * 65536, &[0x79; 65536], &mut j, &mut d, &mut s)
                .unwrap();
            fs.fsync(h, &mut j, &mut d, &mut s).unwrap();
        }
        assert_eq!(
            fs.write(h, 8 * 1024 * 1024, b"x", &mut j, &mut d, &mut s),
            Err(Error::Range)
        );
        let mut last = [0; 4096];
        assert_eq!(
            fs.read(
                h,
                8 * 1024 * 1024 - 4096,
                &mut last,
                0,
                &mut j,
                &mut d,
                &mut s
            )
            .unwrap(),
            4096
        );
        assert_eq!(last, [0x79; 4096]);
        fs.close(h).unwrap();
        for i in 1..252 {
            fs.create(&format!("/f{i:03}"), &mut j, &mut d, &mut s)
                .unwrap();
        }
        assert_eq!(
            fs.create("/over", &mut j, &mut d, &mut s),
            Err(Error::Capacity)
        );
        validate_volume(&mut j, &mut d, &mut s, &mut [[0; 4096]; 4]).unwrap();
    });
}

#[test]
fn absolute_utf8_paths_have_real_512_byte_bound() {
    large(|| {
        let (mut d, mut j) = fixture();
        let mut s = [0; 8192];
        let mut fs = FileSystem::<64>::new();
        fs.mount(&mut j, &mut d, &mut s).unwrap();
        let mut path = String::new();
        for _ in 0..7 {
            path.push('/');
            path.push_str(&"a".repeat(63));
            fs.mkdir(&path, &mut j, &mut d, &mut s).unwrap();
        }
        let max = path.clone() + "/" + &"b".repeat(63);
        assert_eq!(max.len(), 512);
        fs.create(&max, &mut j, &mut d, &mut s).unwrap();
        assert_eq!(
            fs.stat(&(max + "x"), &mut j, &mut d, &mut s),
            Err(Error::Range)
        );
        assert_eq!(
            fs.create("relative", &mut j, &mut d, &mut s),
            Err(Error::Range)
        );
        assert_eq!(
            fs.create("/../x", &mut j, &mut d, &mut s),
            Err(Error::Format)
        );
    });
}

fn req(id: u64, class: Class) -> Request {
    Request {
        object: ObjectKey { id, generation: 1 },
        class,
        bytes: 65536,
        pages: 1,
        descriptors: 1,
    }
}
#[test]
fn byte_shares_borrow_only_idle_capacity_and_recovery_credits_are_independent() {
    let mut io = Scheduler::new(512, 512);
    io.apply(Action::IoShare(250), PolicyStamp::new(1, 0, 0).unwrap(), 0)
        .unwrap();
    for n in 0..64 {
        io.enqueue(
            req(
                n,
                if n < 44 {
                    Class::Foreground
                } else {
                    Class::Background
                },
            ),
            0,
        )
        .unwrap();
    }
    assert_eq!(
        io.enqueue(req(100, Class::Foreground), 0),
        Err(Error::Again)
    );
    let recovery = io.enqueue(req(101, Class::Recovery), 0).unwrap();
    for n in 0..65 {
        let t = io
            .dispatch(0, |_, _| true, |_, _| Submission::Accepted)
            .unwrap()
            .unwrap();
        if n == 0 {
            assert_eq!(t, recovery);
        }
        io.complete(t, Ok(()), 1).unwrap();
        io.acknowledge(t).unwrap();
    }
    let u = io.usage();
    assert_eq!(u.foreground_bytes + u.background_bytes, ORDINARY_BYTES);
    assert_eq!(u.background_bytes, 20 * 65536);
    assert_eq!(u.borrowed_background_bytes, 4 * 65536);
    assert_eq!(u.recovery_bytes, 65536);
    assert_eq!(
        (
            u.pages,
            u.descriptors,
            u.ordinary_credits,
            u.recovery_credits
        ),
        (0, 0, 0, 0)
    );
    io.enqueue(req(102, Class::Foreground), 2).unwrap();
    assert_eq!(
        io.dispatch(2, |_, _| true, |_, _| panic!("quota exhausted"))
            .unwrap(),
        None
    );
}

#[test]
fn deferred_or_unknown_io_never_fakes_completion_or_reuses_dma() {
    let mut io = Scheduler::new(8, 8);
    io.recovery_reserve(2, 2).unwrap();
    let t = io.enqueue(req(1, Class::Background), 0).unwrap();
    assert_eq!(
        io.dispatch(0, |_, _| true, |_, _| Submission::Deferred)
            .unwrap(),
        None
    );
    assert_eq!(io.usage().background_bytes, 0);
    assert_eq!(
        io.dispatch(0, |_, _| true, |_, _| Submission::Unknown)
            .unwrap(),
        Some(t)
    );
    assert_eq!(io.cancel(t), Err(Error::Busy));
    assert_eq!(io.acknowledge(t), Err(Error::Busy));
    assert_eq!(
        io.dispatch(1, |_, _| true, |_, _| panic!("no replay of unknown"))
            .unwrap(),
        None
    );
    io.complete(t, Err(Error::Io), 20_000_000_000).unwrap();
    assert_eq!(io.usage().pages, 1);
    assert_eq!(io.acknowledge(t).unwrap().result, Err(Error::Io));
    assert_eq!(io.usage().pages, 0);
    assert_eq!(io.complete(t, Ok(()), 20_000_000_001), Err(Error::Stale));
}

#[test]
fn transaction_escrow_precedes_begin_and_keeps_original_version_until_real_completion() {
    let mut io = Scheduler::new(256, 256);
    io.apply(Action::IoShare(750), PolicyStamp::new(1, 0, 0).unwrap(), 0)
        .unwrap();
    let permit = io
        .reserve_transaction(Class::Background, ORDINARY_BYTES, 0)
        .unwrap();
    assert_eq!(io.usage().background_bytes, 0);
    let fg = io
        .enqueue(
            Request {
                bytes: 512,
                ..req(999, Class::Foreground)
            },
            0,
        )
        .unwrap();
    io.apply(
        Action::IoShare(100),
        PolicyStamp::new(2, 200_000_000, 200_000_000).unwrap(),
        200_000_000,
    )
    .unwrap();
    for n in 0..64 {
        let t = io
            .enqueue_transaction(req(n, Class::Background), permit, 200_000_000)
            .unwrap();
        assert_eq!(
            io.dispatch(200_000_000, |_, _| true, |_, _| Submission::Accepted)
                .unwrap(),
            Some(t)
        );
        io.complete(t, Ok(()), 200_000_001).unwrap();
        assert_eq!(io.acknowledge(t).unwrap().policy_version, 1);
    }
    io.finish_transaction(permit).unwrap();
    assert_eq!(io.reserved_bytes(), 0);
    assert_eq!(
        io.dispatch(200_000_002, |_, _| true, |_, _| Submission::Accepted)
            .unwrap(),
        None
    );
    assert_eq!(
        io.dispatch(300_000_000, |_, _| true, |_, _| Submission::Accepted)
            .unwrap(),
        Some(fg)
    );
}

#[test]
fn recovery_and_zero_byte_completion_cannot_acknowledge_ordinary_byte_policy() {
    let mut io = Scheduler::new(16, 16);
    io.apply(Action::IoShare(750), PolicyStamp::new(7, 0, 0).unwrap(), 0)
        .unwrap();
    for (id, class, bytes, version) in [
        (1, Class::Recovery, 512, 0),
        (2, Class::Foreground, 0, 0),
        (3, Class::Foreground, 512, 7),
        (4, Class::Background, 512, 7),
    ] {
        let t = io
            .enqueue(
                Request {
                    bytes,
                    ..req(id, class)
                },
                0,
            )
            .unwrap();
        io.dispatch(0, |_, _| true, |_, _| Submission::Accepted)
            .unwrap();
        io.complete(t, Ok(()), 1).unwrap();
        assert_eq!(io.acknowledge(t).unwrap().policy_version, version);
    }
    assert_eq!(
        (
            io.usage().recovery_bytes,
            io.usage().foreground_bytes,
            io.usage().background_bytes
        ),
        (512, 512, 512)
    );
}

#[test]
fn expiration_inside_a_byte_window_preserves_spent_bytes_and_inflight_version() {
    let mut io = Scheduler::new(16, 16);
    let stamp = PolicyStamp::new(7, 1, 1).unwrap();
    io.apply(Action::IoShare(750), stamp, 1).unwrap();
    let before = 10_000_000_000;
    let first = io.enqueue(req(1, Class::Background), before).unwrap();
    io.dispatch(before, |_, _| true, |_, _| Submission::Accepted)
        .unwrap();
    let after = stamp.installed_until_ns;
    let second = io.enqueue(req(2, Class::Background), after).unwrap();
    assert_eq!(io.current_action(after), Action::IoShare(250));
    assert_eq!(io.usage().background_bytes, 65536);
    io.dispatch(after, |_, _| true, |_, _| Submission::Accepted)
        .unwrap();
    io.complete(first, Ok(()), after).unwrap();
    io.complete(second, Ok(()), after).unwrap();
    assert_eq!(io.acknowledge(first).unwrap().policy_version, 7);
    assert_eq!(io.acknowledge(second).unwrap().policy_version, 0);
    assert_eq!(io.usage().background_bytes, 131072);
}
