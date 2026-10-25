//! Host execution of the production late-evidence Archive state machine.
//! The filesystem uses an explicit in-memory block device with injected API
//! failures. Fixture signing keys are unrelated to native node identities.
use cyxia_peer_billing as wire;
use cyxia_prototype::{
    boot::BootSession,
    domains::{
        Error, ObjectKey,
        filesystem::{FileSystem, Handle, OpenMode, Stat, SyncReceipt},
    },
    journal::{self, BlockDevice, Journal},
    learning::{Family, ReplayGroup, capture::RunKey},
    policy::{PlanId, Snapshot},
    storage::TOTAL_BLOCKS,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};

#[path = "../../../kernel/src/learning_replay/archive_packet.rs"]
mod archive_packet;
#[path = "../../../kernel/src/learning_replay/late_archive.rs"]
mod late_archive;

static SERIAL: Mutex<()> = Mutex::new(());
#[derive(Default)]
struct Disk(BTreeMap<u32, Box<[u8; 4096]>>);
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, block: u32, out: &mut [u8; 4096]) -> Result<(), ()> {
        if let Some(bytes) = self.0.get(&block) {
            out.copy_from_slice(bytes.as_ref());
        } else {
            out.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, block: u32, bytes: &[u8; 4096]) -> Result<(), ()> {
        self.0.insert(block, Box::new(*bytes));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
struct Backend {
    files: FileSystem<64>,
    disk: Disk,
    journal: Journal,
    scratch: [u8; 8192],
    path: String,
    short_write: bool,
    fail_sync: bool,
    corrupt_read: bool,
    close_busy: usize,
    writes: Vec<(u64, usize, usize)>,
    reads: usize,
    sync_calls: usize,
    synced: usize,
    close_calls: usize,
    closed: usize,
}
static BACKEND: Mutex<Option<Box<Backend>>> = Mutex::new(None);
fn backend<T>(f: impl FnOnce(&mut Backend) -> Result<T, Error>) -> Result<T, Error> {
    let mut owner = BACKEND.lock().unwrap();
    f(owner.as_mut().ok_or(Error::NotReady)?)
}
fn reset_files() {
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
        path: String::new(),
        short_write: false,
        fail_sync: false,
        corrupt_read: false,
        close_busy: 0,
        writes: Vec::new(),
        reads: 0,
        sync_calls: 0,
        synced: 0,
        close_calls: 0,
        closed: 0,
    }));
}
pub mod domain_storage {
    use super::*;
    pub fn stat(path: &str, _: &mut dyn FnMut()) -> Result<Stat, Error> {
        backend(|s| {
            s.files
                .stat(path, &mut s.journal, &mut s.disk, &mut s.scratch)
        })
    }
    pub fn create(path: &str, _: &mut dyn FnMut()) -> Result<ObjectKey, Error> {
        backend(|s| {
            let object = s
                .files
                .create(path, &mut s.journal, &mut s.disk, &mut s.scratch)?;
            s.path = path.into();
            Ok(object)
        })
    }
    pub fn open(path: &str, mode: OpenMode, _: &mut dyn FnMut()) -> Result<Handle, Error> {
        backend(|s| {
            s.files
                .open(path, mode, &mut s.journal, &mut s.disk, &mut s.scratch)
        })
    }
    pub fn write(
        handle: Handle,
        offset: u64,
        bytes: &[u8],
        _: &mut dyn FnMut(),
    ) -> Result<usize, Error> {
        backend(|s| {
            let n = if std::mem::take(&mut s.short_write) {
                bytes.len() / 2
            } else {
                bytes.len()
            };
            let actual = s.files.write(
                handle,
                offset,
                &bytes[..n],
                &mut s.journal,
                &mut s.disk,
                &mut s.scratch,
            )?;
            s.writes.push((offset, bytes.len(), actual));
            Ok(actual)
        })
    }
    pub fn fsync(handle: Handle, _: &mut dyn FnMut()) -> Result<SyncReceipt, Error> {
        backend(|s| {
            s.sync_calls += 1;
            if std::mem::take(&mut s.fail_sync) {
                return Err(Error::Io);
            }
            let receipt = s
                .files
                .fsync(handle, &mut s.journal, &mut s.disk, &mut s.scratch)?;
            s.synced += 1;
            Ok(receipt)
        })
    }
    pub fn read(
        handle: Handle,
        offset: u64,
        bytes: &mut [u8],
        _: &mut dyn FnMut(),
    ) -> Result<usize, Error> {
        backend(|s| {
            assert!(s.synced != 0, "readback preceded successful fsync");
            let n = s.files.read(
                handle,
                offset,
                bytes,
                1_000_000_000,
                &mut s.journal,
                &mut s.disk,
                &mut s.scratch,
            )?;
            if s.corrupt_read && n != 0 {
                bytes[0] ^= 1;
            }
            s.reads += 1;
            Ok(n)
        })
    }
    pub fn close(handle: Handle) -> Result<(), Error> {
        backend(|s| {
            s.close_calls += 1;
            if s.close_busy != 0 {
                s.close_busy -= 1;
                return Err(Error::Busy);
            }
            s.files.close(handle)?;
            s.closed += 1;
            Ok(())
        })
    }
}

pub mod peer_replay {
    use super::*;
    /// Explicit test facade for the protected native receipt. Construction
    /// below requires the real signed packet to decode and match all facts.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct LateFailureReceipt {
        binding: wire::Binding,
        failure: wire::Failure,
        packet_hash: [u8; 32],
        packet_bytes: usize,
        sequence: u64,
        closing_ns: u64,
    }
    impl LateFailureReceipt {
        pub fn key(self) -> RunKey {
            self.binding.run
        }
        pub fn binding(self) -> wire::Binding {
            self.binding
        }
        pub fn failure(self) -> wire::Failure {
            self.failure
        }
        pub fn packet_hash(self) -> [u8; 32] {
            self.packet_hash
        }
        pub fn packet_bytes(self) -> usize {
            self.packet_bytes
        }
        pub fn sequence(self) -> u64 {
            self.sequence
        }
        pub fn closing_ns(self) -> u64 {
            self.closing_ns
        }
    }
    static RETAINED: Mutex<Option<(LateFailureReceipt, Vec<u8>)>> = Mutex::new(None);
    pub fn install(packet: &[u8], binding: wire::Binding, closing_ns: u64) -> LateFailureReceipt {
        let (reader, _) = keys();
        let authenticated = reader
            .decode(
                packet,
                binding.participant.node,
                binding.origin,
                Some(binding.session),
            )
            .unwrap();
        assert_eq!(authenticated.header.kind, wire::ROOT_FAILED);
        let body = wire::RootFailure::decode(authenticated.body).unwrap();
        assert_eq!(body.binding, binding);
        let receipt = LateFailureReceipt {
            binding,
            failure: body.failure,
            packet_hash: Sha256::digest(packet).into(),
            packet_bytes: packet.len(),
            sequence: authenticated.header.sequence,
            closing_ns,
        };
        *RETAINED.lock().unwrap() = Some((receipt, packet.to_vec()));
        receipt
    }
    pub fn late_failure(run: RunKey) -> Result<Option<LateFailureReceipt>, Error> {
        let retained = RETAINED.lock().unwrap();
        match retained.as_ref() {
            Some((receipt, _)) if receipt.key() == run => Ok(Some(*receipt)),
            Some(_) => Err(Error::Stale),
            None => Ok(None),
        }
    }
    pub fn copy_late_packet(
        receipt: LateFailureReceipt,
        offset: usize,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let retained = RETAINED.lock().unwrap();
        let (original, packet) = retained.as_ref().ok_or(Error::NotReady)?;
        if *original != receipt {
            return Err(Error::Stale);
        }
        if out.len() > 256 || offset > packet.len() {
            return Err(Error::Range);
        }
        let n = out.len().min(packet.len() - offset);
        out[..n].copy_from_slice(&packet[offset..offset + n]);
        Ok(n)
    }
    pub fn corrupt_packet() {
        RETAINED.lock().unwrap().as_mut().unwrap().1[200] ^= 1;
    }
}
fn keys() -> (wire::Keys, wire::Keys) {
    let a = SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes();
    let b = SigningKey::from_bytes(&[72; 32]).verifying_key().to_bytes();
    (
        wire::Keys::new(&[71; 32], &a, &b).unwrap(),
        wire::Keys::new(&[72; 32], &b, &a).unwrap(),
    )
}
fn fixture(closing_ns: u64) -> (peer_replay::LateFailureReceipt, Vec<u8>) {
    let binding = wire::Binding {
        origin: wire::Endpoint {
            node: [3; 32],
            boot: 4,
        },
        participant: wire::Endpoint {
            node: [5; 32],
            boot: 6,
        },
        session: [7; 32],
        run: RunKey {
            boot_epoch: 4,
            trial_id: 8,
            generation: 9,
        },
        family: Family {
            domain: 10,
            kind: 1,
        },
        baseline: false,
        owner: ObjectKey {
            id: 11,
            generation: 1,
        },
        target: ObjectKey {
            id: 10,
            generation: 1,
        },
        group: ReplayGroup {
            seed: 81,
            workload: [12; 32],
            initial_image: [13; 32],
        },
        frozen_scope_hash: [14; 32],
    };
    let failure = wire::Failure {
        root_token: 17,
        error: Error::Busy as u64 + 1,
        observed_ns: 20_000_000_030,
        publication: Some(wire::FailedPublication {
            id: PlanId {
                boot_epoch: 6,
                controller_epoch: 3,
                plan_seq: 8,
            },
            snapshot: Snapshot {
                sequence: 10,
                taken_ns: 20_000_000_000,
                ledger_generation: 7,
                core_generation: 3,
            },
            target: binding.target,
            plan_hash: [88; 32],
            received_ns: 20_000_000_010,
            observed_ns: 20_000_000_030,
            wall_deadline_ns: 20_050_000_000,
        }),
    };
    let (_, writer) = keys();
    let mut body = [0; wire::ROOT_FAILURE_BYTES];
    wire::RootFailure { binding, failure }
        .encode(&mut body)
        .unwrap();
    let mut packet = [0; wire::PACKET_BYTES];
    let n = writer
        .encode(
            wire::Header {
                kind: wire::ROOT_FAILED,
                sequence: 99,
                source: binding.participant,
                destination: binding.origin,
                session: binding.session,
            },
            &body,
            &mut packet,
        )
        .unwrap();
    assert_eq!(n, wire::ROOT_FAILURE_PACKET_BYTES);
    assert_eq!(n, 640);
    (
        peer_replay::install(&packet[..n], binding, closing_ns),
        packet[..n].to_vec(),
    )
}
fn no_export(archive: &late_archive::Archive) {
    assert!(!archive.done());
    assert!(matches!(archive.export(), Err(Error::Busy)));
}
fn until_error(archive: &mut late_archive::Archive, expected: Error) {
    for _ in 0..64 {
        no_export(archive);
        match archive.step(&mut || {}) {
            Err(error) => {
                assert_eq!(error, expected);
                no_export(archive);
                return;
            }
            Ok(true) => (),
            Ok(false) => panic!("archive completed before the injected failure"),
        }
    }
    panic!("injected archive failure was never exercised");
}
fn on_host(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let _serial = SERIAL.lock().unwrap();
            reset_files();
            body();
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn short_write_failed_sync_and_busy_close_retain_original_archive_until_complete() {
    on_host(|| {
        let (receipt, packet) = fixture(20_000_000_000);
        let mut archive = late_archive::Archive::new(receipt, 3).unwrap();
        no_export(&archive);
        backend(|s| {
            s.short_write = true;
            Ok(())
        })
        .unwrap();
        until_error(&mut archive, Error::Io);
        assert_eq!(backend(|s| Ok(s.writes.clone())).unwrap(), [(0, 256, 128)]);
        backend(|s| {
            s.fail_sync = true;
            Ok(())
        })
        .unwrap();
        until_error(&mut archive, Error::Io);
        backend(|s| {
            assert_eq!(&s.writes[..2], &[(0, 256, 128), (0, 256, 256)]);
            assert_eq!((s.sync_calls, s.synced, s.reads, s.closed), (1, 0, 0, 0));
            s.close_busy = 2;
            Ok(())
        })
        .unwrap();
        until_error(&mut archive, Error::Busy);
        let counts = backend(|s| Ok((s.writes.len(), s.reads, s.sync_calls))).unwrap();
        assert!(counts.1 > 0);
        assert_eq!(archive.step(&mut || {}), Err(Error::Busy));
        no_export(&archive);
        assert_eq!(archive.step(&mut || {}), Ok(true));
        assert!(archive.done());
        assert_eq!(archive.step(&mut || {}), Ok(false));
        let export = archive.export().unwrap();
        let duplicate = archive.export().unwrap();
        assert_eq!(export.receipt(), receipt);
        assert_eq!(
            (
                duplicate.receipt(),
                duplicate.object(),
                duplicate.offset(),
                duplicate.bytes(),
                duplicate.digest()
            ),
            (
                receipt,
                export.object(),
                export.offset(),
                export.bytes(),
                export.digest()
            )
        );
        let bytes = backend(|s| {
            assert_eq!((s.writes.len(), s.reads, s.sync_calls), counts);
            assert_eq!((s.synced, s.close_calls, s.closed), (1, 3, 1));
            let stat = s
                .files
                .stat(&s.path, &mut s.journal, &mut s.disk, &mut s.scratch)?;
            assert_eq!(
                (stat.object, stat.write_seq),
                (export.object(), stat.durable_write_seq)
            );
            let h = s.files.open(
                &s.path,
                OpenMode::Read,
                &mut s.journal,
                &mut s.disk,
                &mut s.scratch,
            )?;
            let mut bytes = vec![0; export.bytes()];
            assert_eq!(
                s.files.read(
                    h,
                    export.offset(),
                    &mut bytes,
                    1_000_000_000,
                    &mut s.journal,
                    &mut s.disk,
                    &mut s.scratch
                )?,
                bytes.len()
            );
            s.files.close(h)?;
            Ok(bytes)
        })
        .unwrap();
        assert_eq!(export.bytes(), 256 + packet.len().div_ceil(256) * 256);
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), export.digest());
        assert_eq!(&bytes[256..256 + packet.len()], &packet);
        assert!(bytes[256 + packet.len()..].iter().all(|b| *b == 0));
        let (reader, _) = keys();
        let b = receipt.binding();
        let restored = reader
            .decode(
                &bytes[256..256 + packet.len()],
                b.participant.node,
                b.origin,
                Some(b.session),
            )
            .unwrap();
        assert_eq!(
            wire::RootFailure::decode(restored.body).unwrap(),
            wire::RootFailure {
                binding: b,
                failure: receipt.failure(),
            }
        );
    });
}

#[test]
fn corrupt_readback_requires_a_complete_exact_retry_before_export() {
    on_host(|| {
        let (receipt, _) = fixture(20_000_000_000);
        let mut archive = late_archive::Archive::new(receipt, 0).unwrap();
        backend(|s| {
            s.corrupt_read = true;
            Ok(())
        })
        .unwrap();
        until_error(&mut archive, Error::Io);
        let counts = backend(|s| {
            s.corrupt_read = false;
            assert_eq!((s.synced, s.reads, s.closed), (1, 4, 0));
            Ok((s.writes.len(), s.sync_calls))
        })
        .unwrap();
        // A transient read fault can be retried, but the entire original
        // durable range must be verified again before close may run.
        for _ in 0..4 {
            assert_eq!(archive.step(&mut || {}), Ok(true));
            no_export(&archive);
        }
        assert_eq!(archive.step(&mut || {}), Ok(true));
        no_export(&archive);
        backend(|s| {
            assert_eq!((s.writes.len(), s.sync_calls), counts);
            assert_eq!((s.reads, s.closed), (8, 0));
            Ok(())
        })
        .unwrap();
        assert_eq!(archive.step(&mut || {}), Ok(true));
        assert_eq!(archive.export().unwrap().receipt(), receipt);
    });
}

#[test]
fn original_signed_packet_hash_and_strict_post_seal_time_are_required() {
    on_host(|| {
        let (receipt, _) = fixture(20_000_000_030);
        assert!(matches!(
            late_archive::Archive::new(receipt, 0),
            Err(Error::Stale)
        ));
        let (receipt, _) = fixture(20_000_000_000);
        let mut archive = late_archive::Archive::new(receipt, 0).unwrap();
        peer_replay::corrupt_packet();
        until_error(&mut archive, Error::Io);
        backend(|s| {
            assert_eq!((s.synced, s.closed), (1, 0));
            Ok(())
        })
        .unwrap();
        // The whole-file hash alone matches these written bytes. The second,
        // independent signed-packet hash must still reject every read retry.
        until_error(&mut archive, Error::Io);
        backend(|s| {
            assert_eq!((s.synced, s.closed), (1, 0));
            Ok(())
        })
        .unwrap();
    });
}
