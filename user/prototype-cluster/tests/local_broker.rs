//! Drive the actual EL1 request table with a controllable admission boundary.
//! These doubles do not claim native task creation; they prove no second call
//! crosses that boundary after UNKNOWN, conflicting replay, or table pressure.
extern crate self as cyxia_arch_aarch64;
extern crate self as sha2;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use cyxia_prototype::domains::{Error, ObjectKey, tasks::SpawnState};
pub mod cpu {
    pub fn slot() -> usize {
        0
    }
}
pub struct Sha256;
pub trait Digest {
    fn digest(bytes: &[u8]) -> [u8; 32];
}
impl Digest for Sha256 {
    fn digest(bytes: &[u8]) -> [u8; 32] {
        ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .try_into()
            .unwrap()
    }
}
static NOW: AtomicU64 = AtomicU64::new(1_000_000_000);
static SUBMITS: AtomicU64 = AtomicU64::new(0);
static SUBMIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static SUBMIT_TRANSIENT: AtomicU64 = AtomicU64::new(0);
static SUBMIT_PERMANENT: AtomicBool = AtomicBool::new(false);
static ACCEPTED_FAILED: AtomicBool = AtomicBool::new(false);
static CREATED: AtomicBool = AtomicBool::new(false);
static CLAIMS: AtomicU64 = AtomicU64::new(0);
static CLAIM_BUSY: AtomicBool = AtomicBool::new(false);
static CLAIMED_SPAWN: AtomicU64 = AtomicU64::new(0);
static RESULT_READS: AtomicU64 = AtomicU64::new(0);
static EXIT_READY: AtomicBool = AtomicBool::new(false);
static EXIT_VALUE: AtomicU64 = AtomicU64::new(0);
static EXIT_FINISHED: AtomicU64 = AtomicU64::new(0);
static ACK_BUSY: AtomicBool = AtomicBool::new(false);
static ACK_CALLS: AtomicU64 = AtomicU64::new(0);
static ACKS: AtomicU64 = AtomicU64::new(0);
static FAILURE_BINDS: AtomicU64 = AtomicU64::new(0);
mod domain_network {
    pub mod replay {
        use super::super::*;
        pub fn claim_local(key: ObjectKey, spawn_id: u64) -> Result<(), Error> {
            assert_ne!(key.id, 0);
            assert_eq!(key.generation, 1);
            assert_ne!(spawn_id, 0);
            CLAIMS.fetch_add(1, Ordering::AcqRel);
            if CLAIM_BUSY.swap(false, Ordering::AcqRel) { return Err(Error::Busy); }
            CLAIMED_SPAWN.store(spawn_id, Ordering::Release);
            Ok(())
        }
    }
}
mod domain_platform {
    pub fn now_ns() -> u64 {
        super::NOW.load(super::Ordering::Acquire)
    }
}
mod domain_tasks {
    use super::*;
    pub fn bind_local_failure_request(id: u64, key: ObjectKey, deadline: u64) {
        assert_eq!(key, ObjectKey { id: if id == 1 { 4097 } else { id }, generation: 1 });
        assert_eq!(deadline, if id == 1 { 61_000_000_000 } else { 160_000_000_000 },
            "a diagnostic binding retains the original Entry deadline, including after expiry");
        FAILURE_BINDS.fetch_add(1, Ordering::AcqRel);
    }
    pub fn submit_local(id: u64, input: &[u8], deadline: u64) -> Result<SpawnState, Error> {
        assert!(id != 0 && !input.is_empty() && deadline > NOW.load(Ordering::Acquire));
        assert_eq!(CLAIMED_SPAWN.load(Ordering::Acquire), id, "claim must precede actual constructor admission");
        SUBMIT_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
        match SUBMIT_TRANSIENT.swap(0, Ordering::AcqRel) {
            1 => return Err(Error::Busy),
            2 => return Err(Error::Again),
            3 => return Err(Error::NotReady),
            _ => (),
        }
        if SUBMIT_PERMANENT.swap(false, Ordering::AcqRel) { return Err(Error::Auth); }
        SUBMITS.fetch_add(1, Ordering::AcqRel);
        Ok(if ACCEPTED_FAILED.swap(false, Ordering::AcqRel) {
            SpawnState::Failed(Error::Again)
        } else { SpawnState::Unknown })
    }
    pub fn query_local(id: u64) -> Result<SpawnState, Error> {
        Ok(if CREATED.load(Ordering::Acquire) {
            SpawnState::Created(ObjectKey {
                id: id + 500,
                generation: 1,
            })
        } else {
            SpawnState::Unknown
        })
    }
    pub fn local_result(id: u64) -> Result<Option<(u64, u64)>, Error> {
        assert_eq!(id, 1);
        RESULT_READS.fetch_add(1, Ordering::AcqRel);
        Ok(if CREATED.load(Ordering::Acquire) && EXIT_READY.load(Ordering::Acquire) {
            Some((EXIT_VALUE.load(Ordering::Acquire), EXIT_FINISHED.load(Ordering::Acquire)))
        } else { None })
    }
    pub fn acknowledge_local_result(id: u64) -> Result<(), Error> {
        assert_eq!(id, 1);
        assert!(CREATED.load(Ordering::Acquire) && EXIT_READY.load(Ordering::Acquire));
        assert!(RESULT_READS.load(Ordering::Acquire) > 0);
        ACK_CALLS.fetch_add(1, Ordering::AcqRel);
        if ACK_BUSY.swap(false, Ordering::AcqRel) { return Err(Error::Busy); }
        EXIT_READY.store(false, Ordering::Release);
        ACKS.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
#[path = "../../../kernel/src/local_placement.rs"]
mod local_placement;
fn submit(key: u64, generation: u64) -> ([u8; 4096], usize) {
    let mut b = [0; 4096];
    let deadline = NOW.load(Ordering::Acquire) / 1_000_000 + 60_000;
    for (at, value) in [
        (0, key),
        (8, generation),
        (16, deadline),
        (24, 100),
        (32, 16),
        (104, 8),
    ] {
        b[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    b[112..120].copy_from_slice(&7u64.to_le_bytes());
    let hash = Sha256::digest(&b[112..120]);
    b[40..72].copy_from_slice(&hash);
    b[72..104].fill(9);
    (b, 120)
}
#[test]
fn actual_local_receipt_table_never_reenters_constructor_or_evicts_unknown() {
    let (mut original, n) = submit(4097, 1);
    let frozen = original;
    CLAIM_BUSY.store(true, Ordering::Release);
    assert_eq!(local_placement::request(11, &mut original, n, [9; 32]), (1, 0, 0));
    assert_eq!(SUBMITS.load(Ordering::Acquire), 0);
    for error in 1..=3 {
        SUBMIT_TRANSIENT.store(error, Ordering::Release);
        let mut retry = frozen;
        assert_eq!(local_placement::request(11, &mut retry, n, [9; 32]), (1, 0, 0),
            "an explicit pre-admission transient error cannot become a terminal rejection");
        assert_eq!(SUBMITS.load(Ordering::Acquire), 0);
    }
    original = frozen;
    assert_eq!(
        local_placement::request(11, &mut original, n, [9; 32]),
        (0, 24, 0)
    );
    assert_eq!(u64::from_le_bytes(original[..8].try_into().unwrap()), 3);
    for _ in 0..5 {
        let mut retry = frozen;
        assert_eq!(
            local_placement::request(11, &mut retry, n, [9; 32]),
            (0, 24, 0)
        );
    }
    assert_eq!(SUBMITS.load(Ordering::Acquire), 1);
    assert_eq!(SUBMIT_ATTEMPTS.load(Ordering::Acquire), 4);
    assert_eq!(CLAIMS.load(Ordering::Acquire), 5, "only proven pre-admission retries may reclaim; UNKNOWN must only query");
    let mut conflicting = frozen;
    conflicting[16] ^= 1;
    assert_eq!(
        local_placement::request(11, &mut conflicting, n, [9; 32]),
        (3, 0, 0)
    );
    let mut query = [0; 4096];
    query[..16].copy_from_slice(&frozen[..16]);
    query[16..48].copy_from_slice(&frozen[40..72]);
    let frozen_query = query;
    assert_eq!(local_placement::request(27, &mut query, 48, [9; 32]), (1, 0, 0));
    assert_eq!(ACKS.load(Ordering::Acquire), 0, "UNKNOWN has no exit receipt to acknowledge");
    CREATED.store(true, Ordering::Release);
    assert_eq!(
        local_placement::request(12, &mut query, 48, [9; 32]),
        (0, 24, 0)
    );
    assert_eq!(u64::from_le_bytes(query[..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(query[8..16].try_into().unwrap()), 501);
    let mut query = frozen_query;
    assert_eq!(local_placement::request(27, &mut query, 48, [9; 32]), (1, 0, 0));
    assert_eq!(ACK_CALLS.load(Ordering::Acquire), 0, "Created alone is not task completion");
    EXIT_VALUE.store(7, Ordering::Release);
    EXIT_FINISHED.store(1_001_000_000, Ordering::Release);
    EXIT_READY.store(true, Ordering::Release);
    ACK_BUSY.store(true, Ordering::Release);
    let mut query = frozen_query;
    assert_eq!(local_placement::request(27, &mut query, 48, [9; 32]), (1, 0, 0));
    assert_eq!(RESULT_READS.load(Ordering::Acquire), 3);
    assert_eq!(ACK_CALLS.load(Ordering::Acquire), 1);
    assert_eq!(ACKS.load(Ordering::Acquire), 0);
    assert!(EXIT_READY.load(Ordering::Acquire), "failed ack cannot release the original exit slot");
    // The exact first result is now retained by the production broker table.
    // Mutating the fixture makes an accidental re-read after Busy detectable.
    EXIT_VALUE.store(999, Ordering::Release);
    EXIT_FINISHED.store(9_999_000_000, Ordering::Release);
    for _ in 0..4 {
        let mut query = frozen_query;
        assert_eq!(local_placement::request(27, &mut query, 48, [9; 32]), (0, 16, 0));
        assert_eq!(u64::from_le_bytes(query[..8].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(query[8..16].try_into().unwrap()), 1_001_000_000);
    }
    assert_eq!(RESULT_READS.load(Ordering::Acquire), 3, "ack retry and lost broker replies use retained result bytes");
    assert_eq!(ACK_CALLS.load(Ordering::Acquire), 2);
    assert_eq!(ACKS.load(Ordering::Acquire), 1);
    assert!(!EXIT_READY.load(Ordering::Acquire));
    assert_eq!(SUBMITS.load(Ordering::Acquire), 1);
    NOW.store(100_000_000_000, Ordering::Release);
    let mut retry = frozen;
    assert_eq!(
        local_placement::request(11, &mut retry, n, [9; 32]),
        (0, 24, 0)
    );
    assert_eq!(SUBMITS.load(Ordering::Acquire), 1);
    CREATED.store(false, Ordering::Release);
    for key in 2..=256 {
        if key == 255 { SUBMIT_PERMANENT.store(true, Ordering::Release); }
        if key == 256 { ACCEPTED_FAILED.store(true, Ordering::Release); }
        let (mut b, n) = submit(key, 1);
        let frozen = b;
        assert_eq!(local_placement::request(11, &mut b, n, [9; 32]), (0, 24, 0));
        if key >= 255 {
            assert_eq!(u64::from_le_bytes(b[..8].try_into().unwrap()), 2);
            let attempts = SUBMIT_ATTEMPTS.load(Ordering::Acquire);
            let mut retry = frozen;
            assert_eq!(local_placement::request(11, &mut retry, n, [9; 32]), (0, 24, 0));
            assert_eq!(u64::from_le_bytes(retry[..8].try_into().unwrap()), 2);
            assert_eq!(SUBMIT_ATTEMPTS.load(Ordering::Acquire), attempts,
                "permanent errors and an already accepted Failed(Again) remain terminal");
        }
    }
    let (mut full, n) = submit(257, 1);
    let attempts = SUBMIT_ATTEMPTS.load(Ordering::Acquire);
    let bindings = FAILURE_BINDS.load(Ordering::Acquire);
    assert_eq!(
        local_placement::request(11, &mut full, n, [9; 32]),
        (5, 0, 0),
        "a permanently full receipt table rejects only a new, unaccepted identity"
    );
    assert_eq!(FAILURE_BINDS.load(Ordering::Acquire), bindings,
        "a rejected new identity cannot replace a retained failure's request binding");
    assert_eq!(SUBMITS.load(Ordering::Acquire), 255);
    let mut retained = frozen;
    assert_eq!(local_placement::request(11, &mut retained, 120, [9; 32]), (0, 24, 0));
    assert_eq!(u64::from_le_bytes(retained[..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(retained[8..16].try_into().unwrap()), 501);
    let (mut unknown, n) = submit(2, 1);
    assert_eq!(local_placement::request(11, &mut unknown, n, [9; 32]), (0, 24, 0));
    assert_eq!(u64::from_le_bytes(unknown[..8].try_into().unwrap()), 3);
    assert_eq!(SUBMIT_ATTEMPTS.load(Ordering::Acquire), attempts,
        "full capacity never replaces old successful or UNKNOWN custody");
    let (mut absent, _) = submit(1, 2);
    absent[16..48].copy_from_slice(&frozen[40..72]);
    assert_eq!(
        local_placement::request(12, &mut absent, 48, [9; 32]),
        (4, 0, 0)
    );
    assert_eq!(SUBMITS.load(Ordering::Acquire), 255);
}
