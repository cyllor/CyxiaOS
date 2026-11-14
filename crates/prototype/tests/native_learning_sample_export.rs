//! Production outbound serialization and durable writer over real host journal/FS.
//! Explicit synthetic replay/owner host fixtures: never native training evidence.
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
fn backend<T>(f: impl FnOnce(&mut Backend) -> Result<T, Error>) -> Result<T, Error> {
    let mut state = BACKEND.lock().unwrap();
    f(state.as_mut().ok_or(Error::NotReady)?)
}
pub fn create(path: &str, _: &mut dyn FnMut()) -> Result<ObjectKey, Error> {
    backend(|s| {
        s.files
            .create(path, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
pub fn stat(path: &str, _: &mut dyn FnMut()) -> Result<Stat, Error> {
    backend(|s| {
        s.files
            .stat(path, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
pub fn open(path: &str, mode: OpenMode, _: &mut dyn FnMut()) -> Result<Handle, Error> {
    backend(|s| {
        s.files
            .open(path, mode, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}
pub fn close(handle: Handle) -> Result<(), Error> {
    backend(|s| {
        s.files.close(handle)?;
        s.closes += 1;
        Ok(())
    })
}
pub fn read(
    handle: Handle,
    offset: u64,
    out: &mut [u8],
    _: &mut dyn FnMut(),
) -> Result<usize, Error> {
    let n = backend(|s| {
        s.files.read(
            handle,
            offset,
            out,
            Board.now_ns(),
            &mut s.journal,
            &mut s.disk,
            &mut s.scratch,
        )
    })?;
    if CORRUPT_READ.swap(false, Ordering::AcqRel) && n > 0 {
        out[0] ^= 1;
    }
    Ok(n)
}
pub fn write(
    handle: Handle,
    offset: u64,
    data: &[u8],
    _: &mut dyn FnMut(),
) -> Result<usize, Error> {
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
pub fn fsync(handle: Handle, _: &mut dyn FnMut()) -> Result<SyncReceipt, Error> {
    if BLOCK_SYNC.load(Ordering::Acquire) {
        return Err(Error::Busy);
    }
    backend(|s| {
        s.files
            .fsync(handle, &mut s.journal, &mut s.disk, &mut s.scratch)
    })
}

static CORRUPT_READ: AtomicBool = AtomicBool::new(false);
pub mod domain_storage {
    pub use super::{close, create, fsync, open, read, stat, write};
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    Training,
    Validation,
}
#[path = "../../../kernel/src/runtime/learning/learning_replay/sample_witness.rs"]
mod sample_witness;
#[path = "support/learning.rs"]
mod support;
/// Archive Export identities below are host fixtures, not durable native capabilities.
pub mod archive {
    use super::*;
    use cyxia_prototype::learning::capture::RunKey;
    #[derive(Clone, Copy)]
    pub struct Export {
        pub trial: u64,
    }
    impl Export {
        pub fn key(self) -> RunKey {
            RunKey {
                boot_epoch: 7,
                trial_id: self.trial,
                generation: 3,
            }
        }
        pub fn object(self) -> ObjectKey {
            ObjectKey {
                id: self.trial,
                generation: 4,
            }
        }
        pub fn offset(self) -> u64 {
            4096
        }
        pub fn bytes(self) -> usize {
            8192
        }
        pub fn digest(self) -> [u8; 32] {
            [self.trial as u8; 32]
        }
    }
}
#[path = "../../../kernel/src/runtime/learning/learning_replay/sample_export.rs"]
mod sample_export;
fn reset() {
    BLOCK_SYNC.store(false, Ordering::Release);
    CORRUPT_READ.store(false, Ordering::Release);
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
}
fn with_witness(f: impl FnOnce(sample_witness::Witness, archive::Export, archive::Export)) {
    use cyxia_prototype::learning::reward::{self, ReplayKind, RewardWorkspace};
    support::with_trials(
        support::FAMILIES[1],
        1,
        1,
        Default::default(),
        |candidate, baseline| {
            let mut workspace = RewardWorkspace::new();
            let b = reward::verify_replay(
                baseline,
                ReplayKind::Baseline,
                &support::TestAuthority,
                &mut workspace,
            )?;
            let c = reward::verify_replay(
                candidate,
                ReplayKind::Candidate,
                &support::TestAuthority,
                &mut workspace,
            )?;
            let sample = reward::pair_verified(&c, &b)?;
            let witness = sample_witness::Witness::from_stored(&sample, &c, &b, Split::Training, 8);
            assert_eq!(witness.0.len(), 1024);
            assert_eq!(&witness.0[32..40], &b.trial_id().to_le_bytes());
            assert_eq!(&witness.0[40..48], &c.trial_id().to_le_bytes());
            assert_eq!(&witness.0[48..80], &b.evidence_hash());
            assert_eq!(&witness.0[80..112], &c.evidence_hash());
            assert_eq!(&witness.0[784..816], &sample.evidence_hash());
            assert!(witness.0[816..].iter().all(|v| *v == 0));
            f(
                witness,
                archive::Export {
                    trial: b.trial_id(),
                },
                archive::Export {
                    trial: c.trial_id(),
                },
            );
            Ok(())
        },
    )
    .unwrap();
}
#[test]
fn actual_getters_and_durable_readback_are_required() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            reset();
            with_witness(|w, b, c| {
                let mut writer = sample_export::Archive::new(w, b, c).unwrap();
                let mut progress = || {};
                BLOCK_SYNC.store(true, Ordering::Release);
                let mut blocked = false;
                for _ in 0..32 {
                    match writer.step(&mut progress) {
                        Err(Error::Busy) => {
                            blocked = true;
                            break;
                        }
                        Ok(_) => assert!(!writer.done()),
                        Err(e) => panic!("unexpected {e:?}"),
                    }
                }
                assert!(blocked);
                assert!(!writer.done());
                BLOCK_SYNC.store(false, Ordering::Release);
                for _ in 0..32 {
                    writer.step(&mut progress).unwrap();
                    if writer.done() {
                        break;
                    }
                }
                assert!(writer.done());
                assert!(!writer.step(&mut progress).unwrap());
                assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 1);
                let h = open("/ls-0000000000000007", OpenMode::Read, &mut progress).unwrap();
                let mut bytes = [0; 2048];
                assert_eq!(read(h, 0, &mut bytes, &mut progress).unwrap(), 2048);
                close(h).unwrap();
                use sha2::{Digest, Sha256};
                assert_eq!(<[u8; 32]>::from(Sha256::digest(bytes)), writer.digest());
                assert_eq!(
                    <[u8; 32]>::from(Sha256::digest(&bytes[32..1056])),
                    bytes[1056..1088]
                );
            });
            // Same epoch one-pair bank cannot silently append/overwrite another label.
            with_witness(|w, b, c| {
                let mut writer = sample_export::Archive::new(w, b, c).unwrap();
                assert_eq!(writer.step(&mut || {}), Err(Error::Conflict));
                assert!(!writer.done());
            });
            reset();
            with_witness(|w, b, c| {
                let mut writer = sample_export::Archive::new(w, b, c).unwrap();
                let mut progress = || {};
                BLOCK_SYNC.store(true, Ordering::Release);
                while writer.step(&mut progress) != Err(Error::Busy) {
                    assert!(!writer.done());
                }
                BLOCK_SYNC.store(false, Ordering::Release);
                writer.step(&mut progress).unwrap(); // fsync success enters Read
                CORRUPT_READ.store(true, Ordering::Release);
                let mut failed = false;
                for _ in 0..16 {
                    if writer.step(&mut progress) == Err(Error::Io) {
                        failed = true;
                        break;
                    }
                }
                assert!(failed);
                assert!(!writer.done());
                assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 0); // failed proof retains handle
            });
            with_witness(|w, b, mut c| {
                c.trial += 100;
                assert!(matches!(
                    sample_export::Archive::new(w, b, c),
                    Err(Error::Conflict)
                ));
            });
        })
        .unwrap()
        .join()
        .unwrap();
}
