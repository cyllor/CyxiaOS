//! Host regression for the production CPU0 STORE broker. Journal, Volume and
//! Engine are real; only the block device, CPU slot and progress hook are host
//! substitutes. This is not native boot or physical-device evidence.
#![cfg(feature = "cluster-engine")]

extern crate self as cyxia_arch_aarch64;
pub mod cpu {
    pub fn slot() -> usize {
        0
    }
}

use cyxia_prototype::{
    boot::BootSession,
    cluster::{
        volume::{Cursor, START, Volume, VolumeScratch},
        wire::{Config, Proof},
        *,
    },
    journal::{self, BlockDevice, Journal},
    storage::TOTAL_BLOCKS,
};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap, sync::Mutex};

// The production broker is CPU0-owned static state. Serialize every test that
// includes it, while allowing the rest of the workspace to run concurrently.
static CPU0: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Disk {
    stable: BTreeMap<u32, Box<[u8; 4096]>>,
    pending: BTreeMap<u32, Box<[u8; 4096]>>,
    reads: usize,
    fail_flush: bool,
}
impl BlockDevice for Disk {
    type Error = ();
    fn block_count(&self) -> u32 {
        TOTAL_BLOCKS
    }
    fn read_block(&mut self, n: u32, b: &mut [u8; 4096]) -> Result<(), ()> {
        self.reads += 1;
        if let Some(a) = self.pending.get(&n).or(self.stable.get(&n)) {
            *b = **a;
        } else {
            b.fill(0);
        }
        Ok(())
    }
    fn write_block(&mut self, n: u32, b: &[u8; 4096]) -> Result<(), ()> {
        self.pending.insert(n, Box::new(*b));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), ()> {
        if self.fail_flush {
            return Err(());
        }
        self.stable.append(&mut self.pending);
        Ok(())
    }
}

struct Store {
    journal: Journal,
    disk: Disk,
    scratch: [u8; 8192],
}
thread_local! {
    static STORE: RefCell<Option<Store>> = const { RefCell::new(None) };
}
mod prototype_storage {
    use super::*;
    pub(crate) fn with_journal<R>(
        f: impl FnOnce(&mut Journal, &mut Disk, &mut [u8; 8192]) -> R,
    ) -> R {
        STORE.with(|cell| {
            let mut value = cell.borrow_mut();
            let Store {
                journal,
                disk,
                scratch,
            } = value.as_mut().unwrap();
            f(journal, disk, scratch)
        })
    }
    pub(crate) fn with_progress<R>(
        _progress: &mut dyn FnMut(),
        f: impl FnOnce(&mut Journal, &mut Disk, &mut [u8; 8192]) -> R,
    ) -> R {
        with_journal(f)
    }
}
#[path = "../../../kernel/src/runtime/cluster/unified_store.rs"]
mod unified_store;

fn initialize() {
    let mut disk = Disk::default();
    let mut scratch = [0; 8192];
    journal::format(&mut disk, [7; 16], &mut scratch).unwrap();
    let mut journal = Journal::new();
    journal.mount(&mut disk, &mut scratch).unwrap();
    BootSession::new()
        .allocate(&mut journal, &mut disk, &mut scratch, &mut [[0; 4096]; 4])
        .unwrap();
    STORE.with(|cell| {
        *cell.borrow_mut() = Some(Store {
            journal,
            disk,
            scratch,
        });
    });
    unified_store::init();
}

fn identity(node: u8) -> Vec<u8> {
    let mut out = b"CXID2".to_vec();
    out.extend_from_slice(&[7; 16]);
    out.extend_from_slice(&[node; 32]);
    out.extend_from_slice(&[2; 32]);
    out
}

fn append(key: u64, body: &[u8]) -> (u64, usize, u64) {
    let mut result = (3, 0, 0);
    for (index, chunk) in body.chunks(4096).enumerate() {
        let offset = index * 4096;
        let phase = u64::from(offset + chunk.len() == body.len());
        let mut payload = [0; 4096];
        payload[..chunk.len()].copy_from_slice(chunk);
        result = unified_store::request(
            true,
            key,
            body.len() as u64,
            phase,
            offset as u64,
            &mut payload,
            chunk.len(),
            &mut || {},
        );
        if result.0 != 0 {
            break;
        }
    }
    result
}

fn read(key: u64, offset: usize, len: usize) -> ((u64, usize, u64), Vec<u8>) {
    let mut payload = [0; 4096];
    let result = unified_store::request(
        false,
        key,
        0,
        0,
        offset as u64,
        &mut payload,
        len,
        &mut || {},
    );
    (result, payload[..result.1].to_vec())
}

// Same deterministic signature fixture as cluster_engine.rs. We test legal
// journal histories and IO work, not cryptographic security.
struct TestCrypto([u8; 32]);
fn signature(node: [u8; 32], body: &[u8]) -> [u8; 64] {
    let mut hash = Sha256::new();
    hash.update(node);
    hash.update(body);
    let digest = hash.finalize();
    let mut out = [0; 64];
    out[..32].copy_from_slice(&digest);
    out[32..].copy_from_slice(&digest);
    out
}
impl Crypto for TestCrypto {
    fn sha256(&self, body: &[u8]) -> [u8; 32] {
        Sha256::digest(body).into()
    }
    fn sign(&self, body: &[u8]) -> [u8; 64] {
        signature(self.0, body)
    }
    fn verify(&self, node: &[u8; 32], body: &[u8], sig: &[u8; 64]) -> bool {
        signature(*node, body) == *sig
    }
}
fn commit(engine: &mut Engine<TestCrypto>, effect: Effect) -> Vec<u8> {
    let bytes = effect.bytes.clone();
    engine.complete(effect.id, Durability::Committed).unwrap();
    bytes
}
fn history(cycles: usize) -> Vec<Vec<u8>> {
    let mut a = Engine::new([1; 32], [2; 32], 1, TestCrypto([1; 32])).unwrap();
    let mut b = Engine::new([2; 32], [1; 32], 1, TestCrypto([2; 32])).unwrap();
    let mut log = vec![identity(1)];
    let effect = a.begin_formation([3; 32]).unwrap();
    log.push(commit(&mut a, effect));
    let effect = b.begin_formation([4; 32]).unwrap();
    commit(&mut b, effect);
    let config = Config {
        trust_domain: [5; 32],
        nodes: [[1; 32], [2; 32]],
        counters: [1, 1],
        nonces: [[3; 32], [4; 32]],
        schema: [6; 32],
        policy: [7; 32],
        epoch: 1,
    };
    let effect = a.confirm(config, 0).unwrap();
    log.push(commit(&mut a, effect));
    let effect = b.confirm(config, 0).unwrap();
    commit(&mut b, effect);
    let proof = Proof {
        config,
        formation: a.formation_for(&config),
        signatures: [a.signature().unwrap(), b.signature().unwrap()],
    };
    let effect = a.bind(proof).unwrap();
    log.push(commit(&mut a, effect));
    let effect = b.bind(proof).unwrap();
    commit(&mut b, effect);
    for engine in [&mut a, &mut b] {
        engine.hello(1, [8; 32]).unwrap();
        engine.reconcile(&[]).unwrap();
        engine.send_ready().unwrap();
        engine.peer_ready(1, [8; 32], engine.cluster()).unwrap();
    }
    for index in 0..cycles {
        let terms = Terms {
            id: (index as u128 + 1).to_le_bytes(),
            cpu_milli: 100,
            memory_pages: 8,
            runtime_ms: 100,
            package_hash: [10; 32],
            input_hash: a.crypto.sha256(b"input"),
        };
        let hash = a.request_hash_for(&terms, a.local, a.peer);
        let effect = a.record_request(terms, hash).unwrap();
        log.push(commit(&mut a, effect));
        let effect = a.cancel_request(terms.id).unwrap();
        log.push(commit(&mut a, effect));
    }
    let mut recovered = Engine::new([1; 32], [2; 32], 2, TestCrypto([1; 32])).unwrap();
    for record in &log[1..] {
        recovered.recover_event(record).unwrap();
    }
    log
}

#[test]
fn sequential_recovery_preserves_records_with_linear_disk_reads() {
    let _cpu = CPU0.lock().unwrap_or_else(|e| e.into_inner());
    let mut previous = None;
    for cycles in [16, 32, 64] {
        initialize();
        let log = history(cycles);
        for (index, record) in log.iter().enumerate() {
            assert_eq!(append(index as u64, record).0, 0);
        }
        prototype_storage::with_journal(|journal, disk, scratch| {
            *journal = Journal::new();
            journal.mount(disk, scratch).unwrap();
        });
        unified_store::init();
        prototype_storage::with_journal(|_, disk, _| disk.reads = 0);
        for (index, record) in log.iter().enumerate() {
            let (status, bytes) = read(index as u64 + 1, 0, 4096);
            assert_eq!(status, (0, record.len(), record.len() as u64));
            assert_eq!(&bytes, record);
        }
        assert_eq!(read(log.len() as u64 + 1, 0, 4096).0, (4, 0, 0));
        let broker_reads = prototype_storage::with_journal(|_, disk, _| disk.reads);
        let reference_reads = prototype_storage::with_journal(|journal, disk, scratch| {
            disk.reads = 0;
            let mut work: Box<VolumeScratch> = Box::new([[0; 4096]; 16]);
            let volume = Volume::open(journal, disk, scratch, &mut work).unwrap();
            let mut cursor = Cursor::new();
            let mut payload = [0; MAX_EFFECT];
            for record in &log {
                let len = volume
                    .next(journal, disk, scratch, &mut work, &mut cursor, &mut payload)
                    .unwrap()
                    .unwrap();
                assert_eq!(&payload[..len], record);
            }
            assert_eq!(
                volume
                    .next(journal, disk, scratch, &mut work, &mut cursor, &mut payload)
                    .unwrap(),
                None
            );
            disk.reads
        });
        println!(
            "records={} broker_reads={broker_reads} reference_reads={reference_reads}",
            log.len()
        );
        // Short legal records need at most four block reads each, including
        // crossing a 4 KiB boundary. A prefix rescan violates this bound.
        assert!(broker_reads <= log.len() * 4, "recovery rescanned prefixes");
        assert!(broker_reads <= reference_reads + 2);
        if let Some(smaller) = previous {
            assert!(
                broker_reads <= smaller * 3,
                "doubling history must not quadruple IO"
            );
        }
        previous = Some(broker_reads);
    }
}

#[test]
fn eof_append_fragments_and_random_reads_preserve_cursor_contents() {
    let _cpu = CPU0.lock().unwrap_or_else(|e| e.into_inner());
    initialize();
    assert_eq!(read(1, 0, 4096).0, (4, 0, 0));
    let id = identity(1);
    assert_eq!(append(0, &id).0, 0);
    assert_eq!(read(1, 0, 4096).1, id);
    assert_eq!(read(2, 0, 4096).0, (4, 0, 0));
    let body: Vec<u8> = (0..9000).map(|index| (index % 251) as u8).collect();
    assert_eq!(append(1, &body).0, 0);
    for offset in [0, 4096, 8192, 17, 9000] {
        let (status, bytes) = read(2, offset, 4096);
        let end = (offset + 4096).min(body.len());
        assert_eq!(status, (0, end - offset, 9000));
        assert_eq!(bytes, body[offset..end]);
    }
    assert_eq!(read(2, 9001, 4096).0, (3, 0, 0));
    assert_eq!(read(0, 0, 4096).0, (3, 0, 0));
    assert_eq!(read(u64::MAX, 0, 4096).0, (4, 0, 0));
    assert_eq!(read(1, 0, 4096).1, id);
    assert_eq!(read(2, 5000, 100).1, body[5000..5100]);
    assert_eq!(read(3, 0, 4096).0, (4, 0, 0));
    assert_eq!(append(2, b"tail").0, 0);
    assert_eq!(read(3, 0, 4096), ((0, 4, 4), b"tail".to_vec()));
}

#[test]
fn reinitialization_discards_previous_volume_cache_and_partial_write() {
    let _cpu = CPU0.lock().unwrap_or_else(|e| e.into_inner());
    initialize();
    assert_eq!(append(0, &identity(1)).0, 0);
    assert_eq!(read(1, 0, 4096).1, identity(1));
    let mut payload = [9; 4096];
    assert_eq!(
        unified_store::request(true, 8, 5000, 0, 0, &mut payload, 4096, &mut || {}).0,
        0
    );
    initialize();
    assert_eq!(
        unified_store::request(true, 8, 5000, 1, 4096, &mut payload, 904, &mut || {}).0,
        3
    );
    assert_eq!(read(1, 0, 4096).0, (4, 0, 0));
    assert_eq!(append(0, &identity(3)).0, 0);
    assert_eq!(read(1, 0, 4096).1, identity(3));
}

#[test]
fn corrupt_record_fails_closed_until_valid_volume_reinitialization() {
    let _cpu = CPU0.lock().unwrap_or_else(|e| e.into_inner());
    initialize();
    assert_eq!(append(0, &identity(1)).0, 0);
    prototype_storage::with_journal(|journal, disk, scratch| {
        journal.checkpoint(disk, scratch).unwrap();
        // Change payload only: volume CRC must detect the corruption.
        disk.stable.get_mut(&START).unwrap()[16] ^= 1;
    });
    assert_eq!(read(1, 0, 4096).0, (3, 0, 0));
    assert_eq!(append(1, b"cannot append after a read failure").0, 3);
    initialize();
    assert_eq!(append(0, &identity(1)).0, 0);
    assert_eq!(read(1, 0, 4096).1, identity(1));
}

#[test]
fn failed_append_does_not_publish_a_record_or_continue_reads() {
    let _cpu = CPU0.lock().unwrap_or_else(|e| e.into_inner());
    initialize();
    assert_eq!(append(0, &identity(1)).0, 0);
    assert_eq!(read(1, 0, 4096).1, identity(1));
    prototype_storage::with_journal(|_, disk, _| disk.fail_flush = true);
    assert_eq!(append(1, b"uncommitted").0, 3);
    assert_eq!(read(2, 0, 4096).0, (3, 0, 0));
}
