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
static CREATED: AtomicBool = AtomicBool::new(false);
mod domain_platform {
    pub fn now_ns() -> u64 {
        super::NOW.load(super::Ordering::Acquire)
    }
}
mod domain_tasks {
    use super::*;
    pub fn submit_local(id: u64, input: &[u8], deadline: u64) -> Result<SpawnState, Error> {
        assert!(id != 0 && !input.is_empty() && deadline > NOW.load(Ordering::Acquire));
        SUBMITS.fetch_add(1, Ordering::AcqRel);
        Ok(SpawnState::Unknown)
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
    let (mut original, n) = submit(1, 1);
    let frozen = original;
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
    let mut conflicting = frozen;
    conflicting[16] ^= 1;
    assert_eq!(
        local_placement::request(11, &mut conflicting, n, [9; 32]),
        (3, 0, 0)
    );
    let mut query = [0; 4096];
    query[..16].copy_from_slice(&frozen[..16]);
    query[16..48].copy_from_slice(&frozen[40..72]);
    CREATED.store(true, Ordering::Release);
    assert_eq!(
        local_placement::request(12, &mut query, 48, [9; 32]),
        (0, 24, 0)
    );
    assert_eq!(u64::from_le_bytes(query[..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(query[8..16].try_into().unwrap()), 501);
    NOW.store(100_000_000_000, Ordering::Release);
    let mut retry = frozen;
    assert_eq!(
        local_placement::request(11, &mut retry, n, [9; 32]),
        (0, 24, 0)
    );
    assert_eq!(SUBMITS.load(Ordering::Acquire), 1);
    CREATED.store(false, Ordering::Release);
    for key in 2..=256 {
        let (mut b, n) = submit(key, 1);
        assert_eq!(local_placement::request(11, &mut b, n, [9; 32]), (0, 24, 0));
    }
    let (mut full, n) = submit(257, 1);
    assert_eq!(
        local_placement::request(11, &mut full, n, [9; 32]),
        (1, 0, 0)
    );
    assert_eq!(SUBMITS.load(Ordering::Acquire), 256);
    let (mut absent, _) = submit(1, 2);
    absent[16..48].copy_from_slice(&frozen[40..72]);
    assert_eq!(
        local_placement::request(12, &mut absent, 48, [9; 32]),
        (4, 0, 0)
    );
    assert_eq!(SUBMITS.load(Ordering::Acquire), 256);
}
