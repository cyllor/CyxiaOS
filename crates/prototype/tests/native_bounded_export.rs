#![allow(dead_code)]
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
static REJECT_CLOSE: AtomicBool = AtomicBool::new(false);
pub fn close(handle: Handle) -> Result<(), Error> {
    if REJECT_CLOSE.load(Ordering::Acquire) {
        return Err(Error::Io);
    }
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
static FAIL_SYNC_IO: AtomicBool = AtomicBool::new(false);
pub fn fsync(handle: Handle, _: &mut dyn FnMut()) -> Result<SyncReceipt, Error> {
    if FAIL_SYNC_IO.swap(false, Ordering::AcqRel) {
        return Err(Error::Io);
    }
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
#[path = "../../../kernel/src/learning_replay/sample_witness.rs"]
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
#[path = "../../../kernel/src/learning_replay/sample_export.rs"]
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
            // This host fixture uses native-order trial IDs before the real
            // production verifier/canonical hashing, never edits a witness.
            fn trial_id<'a>(
                t: &cyxia_prototype::learning::reward::Trial<'a>,
                id: u64,
            ) -> cyxia_prototype::learning::reward::Trial<'a> {
                use cyxia_prototype::learning::reward::Trial;
                Trial {
                    id,
                    family: t.family,
                    group: t.group,
                    frozen_other_domains: t.frozen_other_domains,
                    schemas: t.schemas,
                    local_node: t.local_node,
                    controlled_nodes: t.controlled_nodes,
                    observation_ns: t.observation_ns,
                    observation_end_ns: t.observation_end_ns,
                    warmed_from_ns: t.warmed_from_ns,
                    closing_ns: t.closing_ns,
                    requests: t.requests,
                    adoptions: t.adoptions,
                    coverage: t.coverage,
                    cpu: t.cpu,
                    baseline: t.baseline,
                    joint_policy: t.joint_policy,
                    correct: t.correct,
                    frozen: t.frozen,
                    closing: t.closing,
                    ordinary_warmup_cpu_ns: t.ordinary_warmup_cpu_ns,
                    later_workload_cpu_ns: t.later_workload_cpu_ns,
                    peak_workspace_bytes: t.peak_workspace_bytes,
                }
            }
            let candidate = trial_id(candidate, 2);
            let baseline = trial_id(baseline, 1);
            let mut workspace = RewardWorkspace::new();
            let b = reward::verify_replay(
                &baseline,
                ReplayKind::Baseline,
                &support::TestAuthority,
                &mut workspace,
            )?;
            let c = reward::verify_replay(
                &candidate,
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

#[path = "../../../kernel/src/learning_replay/bounded_data.rs"]
mod bounded_data;
#[path = "../../../kernel/src/learning_replay/bounded_export.rs"]
mod bounded_export;
#[test]
fn bounded_sample_ledger_uses_real_durable_readback_and_retains_failed_close() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            use bounded_data::{Ledger, Reference, Release};
            let make = |w: &sample_witness::Witness, b: archive::Export, c: archive::Export| {
                let mut l = Ledger::new();
                for (e, kind, hash) in [(b, 2, &w.0[48..80]), (c, 1, &w.0[80..112])] {
                    let k = e.key();
                    l.admit(k.trial_id, k.trial_id, k.boot_epoch, kind, 100)
                        .unwrap();
                    l.capture(k.trial_id, k.generation).unwrap();
                    l.verified(k.trial_id, hash.try_into().unwrap()).unwrap();
                    let o = e.object();
                    l.journal(
                        k.trial_id,
                        0,
                        Reference {
                            key: [k.boot_epoch, k.trial_id, k.generation],
                            object: [o.id, o.generation],
                            offset: e.offset(),
                            bytes: e.bytes() as u64,
                            digest: e.digest(),
                        },
                    )
                    .unwrap();
                    for r in [
                        Release::Capture,
                        Release::History,
                        Release::Work,
                        Release::Root,
                        Release::Permit,
                    ] {
                        l.release(k.trial_id, r).unwrap();
                    }
                }
                l.store(&w.0).unwrap();
                assert!(l.supplement(Some(&w.0), [0, 2, 2], 41, false).is_err());
                l.supplement(Some(&w.0), [0, 2, 2], 41, true).unwrap()
            };
            reset();
            with_witness(|w, b, c| {
                let bytes = make(&w, b, c);
                let mut a = bounded_export::Archive::new(bytes, 7).unwrap();
                BLOCK_SYNC.store(true, Ordering::Release);
                while a.step(&mut || {}) != Err(Error::Busy) {
                    assert!(!a.done());
                }
                BLOCK_SYNC.store(false, Ordering::Release);
                for _ in 0..64 {
                    a.step(&mut || {}).unwrap();
                    if a.done() {
                        break;
                    }
                }
                assert!(a.done());
                assert_eq!(a.bytes(), &bytes);
                assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 1);
                assert_eq!(stat("/ld-0000000000000007", &mut || {}).unwrap().size, 4096);
            });
            reset();
            with_witness(|w, b, c| {
                let mut a = bounded_export::Archive::new(make(&w, b, c), 7).unwrap();
                BLOCK_SYNC.store(true, Ordering::Release);
                while a.step(&mut || {}) != Err(Error::Busy) {}
                BLOCK_SYNC.store(false, Ordering::Release);
                a.step(&mut || {}).unwrap();
                CORRUPT_READ.store(true, Ordering::Release);
                let mut bad = false;
                for _ in 0..32 {
                    if a.step(&mut || {}) == Err(Error::Io) {
                        bad = true;
                        break;
                    }
                }
                assert!(bad && !a.done());
                assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 0);
            });
            reset();
            with_witness(|w, b, c| {
                let mut a = bounded_export::Archive::new(make(&w, b, c), 7).unwrap();
                REJECT_CLOSE.store(true, Ordering::Release);
                let mut bad = false;
                for _ in 0..64 {
                    if a.step(&mut || {}) == Err(Error::Io) {
                        bad = true;
                        break;
                    }
                }
                assert!(bad && !a.done());
                assert_eq!(backend(|s| Ok(s.closes)).unwrap(), 0);
                REJECT_CLOSE.store(false, Ordering::Release);
                a.step(&mut || {}).unwrap();
                assert!(a.done());
            });
            // Host-only negative-custody payload; no Trial/AcceptedSample is
            // decoded from it. Drive the actual production writer over real FS
            // errors, then feed its observed durable object/range/hash to the
            // same production ledger callbacks as owner::service_io.
            for stage in 0..3 {
                reset();
                let mut ledger = Ledger::new();
                ledger.admit(1, 1, 7, 2, 100).unwrap();
                ledger.capture(1, 3).unwrap();
                ledger.error(1, 10, 123).unwrap();
                ledger.excluded(1, 17).unwrap();
                let mut writer = bounded_export::Archive::new([0xa5; 4096], 7).unwrap();
                match stage {
                    0 => REJECT_WRITE.store(true, Ordering::Release),
                    1 => FAIL_SYNC_IO.store(true, Ordering::Release),
                    _ => REJECT_CLOSE.store(true, Ordering::Release),
                }
                let mut fault = false;
                for _ in 0..64 {
                    if writer.step(&mut || {}) == Err(Error::Io) {
                        ledger.observe_incoming(1, Error::Io, 200, 10).unwrap();
                        fault = true;
                        break;
                    }
                }
                assert!(fault && !writer.done());
                assert!(!ledger.may_continue());
                assert!(!ledger.references_closed());
                assert_eq!(ledger.row(0)[5], 10);
                assert_eq!(ledger.row(0)[55], 18);
                REJECT_CLOSE.store(false, Ordering::Release);
                for _ in 0..64 {
                    writer.step(&mut || {}).unwrap();
                    if writer.done() {
                        break;
                    }
                }
                assert!(writer.done());
                let object = writer.object().unwrap();
                ledger
                    .journal(
                        1,
                        0,
                        Reference {
                            key: [7, 1, 3],
                            object: [object.id, object.generation],
                            offset: 0,
                            bytes: 4096,
                            digest: writer.digest(),
                        },
                    )
                    .unwrap();
                for release in [
                    Release::Capture,
                    Release::History,
                    Release::Work,
                    Release::Root,
                    Release::Permit,
                ] {
                    ledger.release(1, release).unwrap();
                }
                assert!(ledger.references_closed());
                assert!(!ledger.can_admit());
                assert!(!ledger.retryable());
                assert_eq!(ledger.hard_stop(), [1, 18, 200, 10]);
                assert!(ledger.store(&[0; 1024]).is_err());
                assert!(!ledger.stored());
                let final_bytes = ledger.supplement(None, [1, 0, 1], 41, true).unwrap();
                assert!(ledger.snapshot_current(&final_bytes));
                assert_eq!(ledger.row(0)[5], 10);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
