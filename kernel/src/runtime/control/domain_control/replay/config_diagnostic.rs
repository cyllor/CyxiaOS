//! The original owner result at the first frozen-configuration mismatch.
//! Diagnostics neither permit changed configurations nor replace observations.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{Action, Error, ObjectKey},
    learning::Family,
    policy::Snapshot,
};

pub(super) const MAGIC: u64 = 0x4359_5243_4647_3133;
#[derive(Clone, Copy)]
pub(super) struct Context {
    pub phase: u64,
    pub cursor: u64,
    pub count: u64,
    pub token: u64,
    pub boot: u64,
    pub trial: u64,
    pub kind: u64,
    pub first: Option<Snapshot>,
    pub ledger: u64,
    pub core: u64,
    pub fault: Option<Error>,
}
/// 0 seqlock, 1 magic, 2 schema, 3 original root phase+1, 4 config cursor,
/// 5/6 family, 7/8 target, 9..13 expected Action::order(), 13..17 actual
/// Action::order(), 17 actual-present, 18 original owner error+1, 19 observed
/// time, 20 token, 21 boot, 22 trial, 23 candidate=1/baseline=2/spectator=0,
/// 24/25 first sequence/time, 26/27 current ledger/core, 28 config count,
/// 29 already-retained fault+1, 30/31 first ledger/core. Absent current action
/// remains absent even when the expected baseline is the real OfferCpu(0).
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 32]);
impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 32])
    }
    pub(super) fn retain(&self, words: [u64; 32]) -> bool {
        if self.0[0]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        for (slot, value) in self.0.iter().zip(words).skip(1) {
            slot.store(value, Ordering::Relaxed);
        }
        self.0[0].store(2, Ordering::Release);
        true
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> [u64; 32] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
#[unsafe(no_mangle)]
pub static REPLAY_CONFIG_EVIDENCE: Evidence = Evidence::new();
const _: () = assert!(core::mem::size_of::<Evidence>() == 256);

pub(super) fn words(
    context: Context,
    family: Family,
    target: ObjectKey,
    expected: Action,
    actual: Result<Action, Error>,
    observed_ns: u64,
) -> [u64; 32] {
    let mut words = [0; 32];
    words[1] = MAGIC;
    words[2] = 1;
    words[3] = context.phase;
    words[4] = context.cursor;
    words[5] = u64::from(family.domain);
    words[6] = u64::from(family.kind);
    words[7] = target.id;
    words[8] = target.generation;
    let (domain, kind, a, b) = expected.order();
    words[9..13].copy_from_slice(&[u64::from(domain), u64::from(kind), a, b]);
    match actual {
        Ok(action) => {
            let (domain, kind, a, b) = action.order();
            words[13..17].copy_from_slice(&[u64::from(domain), u64::from(kind), a, b]);
            words[17] = 1;
        }
        Err(error) => words[18] = error as u64 + 1,
    }
    words[19] = observed_ns;
    words[20] = context.token;
    words[21] = context.boot;
    words[22] = context.trial;
    words[23] = context.kind;
    if let Some(first) = context.first {
        words[24] = first.sequence;
        words[25] = first.taken_ns;
        words[30] = first.ledger_generation;
        words[31] = first.core_generation;
    }
    words[26] = context.ledger;
    words[27] = context.core;
    words[28] = context.count;
    words[29] = context.fault.map_or(0, |e| e as u64 + 1);
    words
}
pub(super) fn record(
    context: Context,
    family: Family,
    target: ObjectKey,
    expected: Action,
    actual: Result<Action, Error>,
    observed_ns: u64,
) {
    REPLAY_CONFIG_EVIDENCE.retain(words(
        context,
        family,
        target,
        expected,
        actual,
        observed_ns,
    ));
}
