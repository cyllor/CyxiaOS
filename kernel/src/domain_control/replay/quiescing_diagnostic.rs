//! [DEBUG-v15-replay-gate] Latest bounded root::poll gate observation.
//! Diagnostic only. Copied while the original control gate is held; never
//! performs owner queries, reads a fresh clock or changes replay authority.
use core::sync::atomic::{AtomicU64, Ordering};
const MAGIC: u64 = 0x4359_5155_4945_3031;
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 64]);
#[unsafe(no_mangle)]
pub static REPLAY_QUIESCING_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 64]);
const _: () = assert!(core::mem::size_of::<Evidence>() == 512);

/// Payload word offsets (bank offset = 8 + payload offset):
/// 0 boot,1 token,2 trial,3/4 family,5/6 target,7 original phase,
/// 8 stage(1 job,2 execution,3 live stamp,4 partial scan,5 fixture wait,
/// 6 scanning entered,7 fixture error),9 existing predicate time,10 cursor
/// before,11 scan end,12 cursor after,13 slot+1,14 reason(1 nonterminal,
/// 2 APPLIED unobserved,4 live lease),15..20 ApplyId,21..23 stamp,
/// 24 state(0 pending,1 applied,2 failed,3 unknown),25 error+1,26 observed,
/// 27 started,28 one-shot,29..31 action domain/kind/desired job,
/// 32 first-entry time,33 owner-observed time,34 published,
/// 35 job present,36 sequence,37 controller,38 CPU,39 started,
/// 40 completion present,41 fixture ready evaluated,42 fixture ready,
/// 43 fixture error+1. All remaining words reserved zero.
pub(super) struct Event(pub [u64; 56]);
impl Event {
    pub fn new() -> Self {
        Self([0; 56])
    }
    pub fn publish(&self) {
        let b = &REPLAY_QUIESCING_EVIDENCE.0;
        // All callers retain the same root/control gate. This is a latest
        // observation bank, not a complete event history or first-failure latch.
        let old = b[0].load(Ordering::Relaxed);
        b[0].store(old + 1, Ordering::Release);
        b[1].store(MAGIC, Ordering::Relaxed);
        b[2].store(1, Ordering::Relaxed);
        b[3].store(64, Ordering::Relaxed);
        b[4].fetch_add(1, Ordering::Relaxed);
        for (slot, value) in b[8..].iter().zip(self.0) {
            slot.store(value, Ordering::Relaxed);
        }
        b[0].store(old + 2, Ordering::Release);
    }
}
#[cfg(test)]
pub(super) fn snapshot() -> [u64; 64] {
    core::array::from_fn(|i| REPLAY_QUIESCING_EVIDENCE.0[i].load(Ordering::Acquire))
}
