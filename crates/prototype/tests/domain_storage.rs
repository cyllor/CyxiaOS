use cyxia_prototype::{
    boot::BootSession,
    cluster::volume::{Cursor, Volume},
    domains::{
        Action, Error, ObjectKey, PolicyStamp,
        filesystem::{FIRST_ORDINARY_BLOCK, FileSystem, OpenMode, validate_volume},
        io::{Class, ORDINARY_BYTES, Request, Scheduler, Submission},
    },
    journal::{self, AfterImage, BlockDevice, Journal},
    storage::{BLOCK_SIZE, INODE_START, Inode, TOTAL_BLOCKS},
};
use std::collections::BTreeMap;

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
        let before = d.reads;
        let mut out = [0; 4096];
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
