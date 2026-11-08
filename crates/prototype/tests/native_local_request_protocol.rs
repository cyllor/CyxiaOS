//! Actual CPU0 local-request ABI with controlled task-owner outcomes.
//! These protocol checks do not create native execution or completion proof.
extern crate self as cyxia_arch_aarch64;
pub mod cpu {
    pub fn slot() -> usize {
        0
    }
}
mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(100_000_000);
    pub fn now_ns() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    pub fn at(value: u64) {
        NOW.store(value, Ordering::Relaxed);
    }
}
mod domain_network {
    pub mod replay {
        pub fn claim_local(
            _: cyxia_prototype::domains::ObjectKey,
            _: u64,
        ) -> Result<(), cyxia_prototype::domains::Error> {
            Ok(())
        }
    }
}
mod domain_tasks {
    use core::sync::atomic::{AtomicU64, Ordering};
    use cyxia_prototype::domains::{Error, ObjectKey, tasks::SpawnState};
    static SUBMIT: AtomicU64 = AtomicU64::new(0);
    static QUERY: AtomicU64 = AtomicU64::new(0);
    pub static CALLS: AtomicU64 = AtomicU64::new(0);
    pub fn responses(submit: u64, query: u64) {
        SUBMIT.store(submit, Ordering::Relaxed);
        QUERY.store(query, Ordering::Relaxed);
    }
    fn state(value: u64) -> Result<SpawnState, Error> {
        match value {
            0 => Err(Error::Busy),
            1 => Ok(SpawnState::Queued),
            2 => Ok(SpawnState::Created(ObjectKey {
                id: 4097,
                generation: 17,
            })),
            _ => Ok(SpawnState::Unknown),
        }
    }
    pub fn submit_local(_: u64, _: &[u8], _: u64) -> Result<SpawnState, Error> {
        CALLS.fetch_add(1, Ordering::Relaxed);
        state(SUBMIT.load(Ordering::Relaxed))
    }
    pub fn query_local(_: u64) -> Result<SpawnState, Error> {
        state(QUERY.load(Ordering::Relaxed))
    }
    pub fn bind_local_failure_request(_: u64, _: ObjectKey, _: u64) {}
    pub fn local_result(_: u64) -> Result<Option<(u64, u64)>, Error> {
        Ok(Some((9, 200_000_000)))
    }
    pub fn acknowledge_local_result(_: u64) -> Result<(), Error> {
        Ok(())
    }
}
#[path = "../../../kernel/src/local_placement.rs"]
mod local;

use core::sync::atomic::Ordering;
use sha2::{Digest, Sha256};

const PACKAGE: [u8; 32] = [7; 32];
fn submission(id: u64) -> [u8; 4096] {
    let mut bytes = [0; 4096];
    for (word, value) in [id, 1, 1000, 100, 16].into_iter().enumerate() {
        bytes[word * 8..word * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    let input = 9u64.to_le_bytes();
    bytes[40..72].copy_from_slice(&Sha256::digest(input));
    bytes[72..104].copy_from_slice(&PACKAGE);
    bytes[104..112].copy_from_slice(&8u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&input);
    bytes
}
fn query(id: u64) -> [u8; 4096] {
    let mut bytes = submission(id);
    bytes[16..48].copy_from_slice(&Sha256::digest(9u64.to_le_bytes()));
    bytes
}
fn phase(phase: u64, bytes: &mut [u8; 4096]) -> (u64, usize, u64) {
    local::request(phase, bytes, if phase == 11 { 120 } else { 48 }, PACKAGE)
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[test]
fn actual_local_abi_preserves_queued_and_unknown_custody_and_explicit_retry() {
    domain_tasks::responses(1, 1);
    let mut request = submission(4097);
    assert_eq!(phase(11, &mut request), (0, 24, 0));
    assert_eq!(word(&request, 0), 0); // real Queued ABI, not Created
    let capture = local::diagnostic::LOCAL_REQUEST_EVIDENCE.snapshot();
    assert_eq!(&capture[8..12], &[4097, 1, 1, 11]);
    assert_eq!(capture[8 + 8], 0); // actual retained Queued
    assert_eq!(&capture[8 + 21..8 + 26], &[1, 0, 11, 0, 0]);
    for _ in 0..3 {
        let mut request = query(4097);
        assert_eq!(phase(12, &mut request), (0, 24, 0));
        assert_eq!(word(&request, 0), 0);
    }
    assert_eq!(domain_tasks::CALLS.load(Ordering::Relaxed), 1);
    let capture = local::diagnostic::LOCAL_REQUEST_EVIDENCE.snapshot();
    assert_eq!(&capture[8 + 18..8 + 23], &[1, 3, 0, 1, 3]);
    assert_eq!(&capture[8 + 23..8 + 26], &[12, 0, 0]);
    domain_tasks::responses(1, 2);
    let mut request = query(4097);
    assert_eq!(phase(12, &mut request), (0, 24, 0));
    assert_eq!(
        [word(&request, 0), word(&request, 8), word(&request, 16)],
        [1, 4097, 17]
    );
    let mut request = query(4097);
    assert_eq!(phase(27, &mut request), (0, 16, 0));
    assert_eq!(word(&request, 0), 9);

    domain_tasks::responses(0, 0);
    assert_eq!(phase(11, &mut submission(4098)), (1, 0, 0));
    let capture = local::diagnostic::LOCAL_REQUEST_EVIDENCE.snapshot();
    let row = 8 + 32;
    assert_eq!(&capture[row + 8..row + 13], &[3, 0, 0, 0, 1]);
    assert_eq!(
        capture[row + 25],
        cyxia_prototype::domains::Error::Busy as u64 + 1
    );
    assert_eq!(phase(12, &mut query(4098)), (1, 0, 0));
    assert_eq!(domain_tasks::CALLS.load(Ordering::Relaxed), 2);
    domain_tasks::responses(2, 2);
    assert_eq!(phase(11, &mut submission(4098)), (0, 24, 0));
    assert_eq!(domain_tasks::CALLS.load(Ordering::Relaxed), 3);

    domain_tasks::responses(3, 3);
    assert_eq!(phase(11, &mut submission(4099)), (0, 24, 0));
    domain_platform::at(2_000_000_000);
    let mut request = query(4099);
    assert_eq!(phase(12, &mut request), (0, 24, 0));
    assert_eq!(word(&request, 0), 3); // expiry cannot erase UNKNOWN
    let calls = domain_tasks::CALLS.load(Ordering::Relaxed);
    assert_eq!(phase(11, &mut submission(4099)), (0, 24, 0));
    assert_eq!(domain_tasks::CALLS.load(Ordering::Relaxed), calls);
}
