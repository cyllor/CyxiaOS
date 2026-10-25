//! Production reset/abort owner over the actual journal-backed FileSystem.
//! Host storage and rejected-call fixtures do not create native replay labels.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::{
    boot::BootSession,
    domains::{
        Error, ObjectKey,
        filesystem::{FileSystem, Handle, OpenMode, Stat, SyncReceipt},
    },
    journal::{self, BlockDevice, Journal},
    storage::TOTAL_BLOCKS,
};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Disk {
    durable: BTreeMap<u32, Box<[u8; 4096]>>,
    pending: BTreeMap<u32, Box<[u8; 4096]>>,
    flushes: usize,
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, out: &mut [u8; 4096]) -> Result<(), ()> {
        if let Some(bytes) = self
            .pending
            .get(&block)
            .or_else(|| self.durable.get(&block))
        {
            out.copy_from_slice(bytes.as_ref());
        } else {
            out.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &[u8; 4096]) -> Result<(), ()> {
        self.pending.insert(block, Box::new(*bytes));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        self.flushes += 1;
        self.durable.append(&mut self.pending);
        Ok(())
    }
}
struct Backend {
    files: FileSystem<64>,
    disk: Disk,
    journal: Journal,
    scratch: [u8; 8192],
    closes: usize,
}
static BACKEND: Mutex<Option<Box<Backend>>> = Mutex::new(None);
static REJECT_WRITE: AtomicBool = AtomicBool::new(false);
static BLOCK_SYNC: AtomicBool = AtomicBool::new(false);
static CLOCK: AtomicU64 = AtomicU64::new(1_000_000_000);
struct Board;
impl Board {
    fn now_ns(&self) -> u64 {
        CLOCK.fetch_add(1000, Ordering::AcqRel)
    }
}
fn owner() -> Result<(), Error> {
    Ok(())
}
fn backend<T>(f: impl FnOnce(&mut Backend) -> Result<T, Error>) -> Result<T, Error> {
    let mut state = BACKEND.lock().unwrap();
    f(state.as_mut().ok_or(Error::NotReady)?)
}
fn with_files<T>(f: impl FnOnce(&mut FileSystem<64>) -> Result<T, Error>) -> Result<T, Error> {
    backend(|s| f(&mut s.files))
}
fn create(path: &str, _: &mut dyn FnMut()) -> Result<ObjectKey, Error> {
    backend(|s| {
        s.files
            .create(path, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
fn stat(path: &str, _: &mut dyn FnMut()) -> Result<Stat, Error> {
    backend(|s| {
        s.files
            .stat(path, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
fn open(path: &str, mode: OpenMode, _: &mut dyn FnMut()) -> Result<Handle, Error> {
    backend(|s| {
        s.files
            .open(path, mode, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
fn close(handle: Handle) -> Result<(), Error> {
    backend(|s| {
        s.files.close(handle)?;
        s.closes += 1;
        Ok(())
    })
}
fn read(handle: Handle, offset: u64, out: &mut [u8], _: &mut dyn FnMut()) -> Result<usize, Error> {
    backend(|s| {
        s.files.read(
            handle,
            offset,
            out,
            Board.now_ns(),
            &mut s.journal,
            &mut s.disk,
            &mut s.scratch,
        )
    })
}
fn write(handle: Handle, offset: u64, data: &[u8], _: &mut dyn FnMut()) -> Result<usize, Error> {
    // Explicitly rejected before the real filesystem accepts this call.
    if REJECT_WRITE.swap(false, Ordering::AcqRel) {
        return Err(Error::Io);
    }
    backend(|s| {
        s.files.write(
            handle,
            offset,
            data,
            &mut s.journal,
            &mut s.disk,
            &mut s.scratch,
        )
    })
}
fn fsync(handle: Handle, _: &mut dyn FnMut()) -> Result<SyncReceipt, Error> {
    if BLOCK_SYNC.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    backend(|s| {
        s.files
            .fsync(handle, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
#[path = "../../../kernel/src/domain_storage/replay.rs"]
mod replay;

#[test]
fn interrupted_reset_keeps_dirty_custody_until_real_fsync_close_and_can_retry_the_prefix() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let mut disk = Disk::default();
            let mut scratch = [0; 8192];
            journal::format(&mut disk, [7; 16], &mut scratch).unwrap();
            let mut journal = Journal::new();
            journal.mount(&mut disk, &mut scratch).unwrap();
            BootSession::new()
                .allocate(&mut journal, &mut disk, &mut scratch, &mut [[0; 4096]; 4])
                .unwrap();
            let mut files = FileSystem::<64>::new();
            files.mount(&mut journal, &mut disk, &mut scratch).unwrap();
            *BACKEND.lock().unwrap() = Some(Box::new(Backend {
                files,
                disk,
                journal,
                scratch,
                closes: 0,
            }));
            let mut progress = || {};
            assert_eq!(replay::prepare(73).unwrap(), None);
            replay::step(&mut progress).unwrap(); // Actual create/open.
            replay::step(&mut progress).unwrap(); // Actual accepted 32 KiB write.
            assert!(with_files(|f| Ok(f.metrics().dirty_pages)).unwrap() > 0);
            let original = stat("/native-replay-data", &mut progress).unwrap();
            assert_eq!(original.size, 32768);
            assert!(original.write_seq > original.durable_write_seq);
            REJECT_WRITE.store(true, Ordering::Release);
            assert_eq!(replay::step(&mut progress), Err(Error::Io));
            assert_eq!(replay::prepare(73), Err(Error::Io));
            assert!(!replay::needs_io());
            assert!(!replay::abort_prepared().unwrap());
            assert!(replay::needs_io());
            BLOCK_SYNC.store(true, Ordering::Release);
            assert_eq!(replay::step(&mut progress), Err(Error::Busy));
            CLOCK.fetch_add(20_000_000_000, Ordering::AcqRel);
            assert!(!replay::abort_prepared().unwrap());
            assert_eq!(replay::release_prepared(), Err(Error::Busy));
            assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 0);
            BLOCK_SYNC.store(false, Ordering::Release);
            let old_flushes = backend(|s| Ok(s.disk.flushes)).unwrap();
            replay::step(&mut progress).unwrap(); // Real journal fsync.
            assert!(backend(|s| Ok(s.disk.flushes)).unwrap() > old_flushes);
            assert_eq!(with_files(|f| Ok(f.metrics().dirty_pages)).unwrap(), 0);
            assert!(!replay::abort_prepared().unwrap()); // Actual handle still live.
            replay::step(&mut progress).unwrap(); // Actual close.
            assert!(replay::abort_prepared().unwrap());
            assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 1);
            let durable = stat("/native-replay-data", &mut progress).unwrap();
            assert_eq!(durable.object, original.object);
            assert_eq!(durable.write_seq, durable.durable_write_seq);
            replay::release_prepared().unwrap();

            // A retained, durable prefix from a failed reset is a legitimate new
            // reset input. It is never mistaken for a complete initial image.
            assert_eq!(replay::prepare(74).unwrap(), None);
            replay::step(&mut progress).unwrap();
            replay::step(&mut progress).unwrap();
            assert_eq!(replay::prepare(74).unwrap(), None);
            assert!(!replay::abort_prepared().unwrap());
            replay::step(&mut progress).unwrap();
            replay::step(&mut progress).unwrap();
            assert!(replay::abort_prepared().unwrap());
            replay::release_prepared().unwrap();
            let handle = open("/native-replay-data", OpenMode::Read, &mut progress).unwrap();
            let mut word = [0; 8];
            assert_eq!(read(handle, 0, &mut word, &mut progress).unwrap(), 8);
            assert_eq!(u64::from_le_bytes(word), 74u64.rotate_left(17));
            close(handle).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
