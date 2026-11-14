//! [DEBUG-v15-session] Bounded actual EL1 phase-9 observations, not authority.
//! CPU0 alone calls this within the original paid broker segment. No new SVC,
//! clock substitution, pending-operation release or session renewal is added.
use core::sync::atomic::{AtomicU64, Ordering};

const MAGIC: u64 = 0x4359_5853_4143_5431;
#[repr(C, align(64))]
struct Evidence([AtomicU64; 104]);
const fn initial() -> Evidence {
    let mut words = [const { AtomicU64::new(0) }; 104];
    words[0] = AtomicU64::new(MAGIC);
    words[1] = AtomicU64::new(2);
    words[2] = AtomicU64::new(104);
    words[3] = AtomicU64::new(24);
    Evidence(words)
}
#[used]
#[unsafe(no_mangle)]
static SESSION_ACTIVITY_EVIDENCE: Evidence = initial();
// CPU0's current OP_TASK only: entry, network completion, paid credit acquired.
static BROKER_TIMING: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
pub(super) fn broker_timing(times: [u64; 3]) {
    for (word, value) in BROKER_TIMING.iter().zip(times) {
        word.store(value, Ordering::Relaxed);
    }
}

pub(super) struct Observation {
    pub boot: u64,
    pub token: u64,
    pub requested_epoch: u64,
    pub live_epoch: u64,
    pub connected: bool,
    pub fresh_ms: u64,
    pub before: [u64; 4],
    pub after: [u64; 4],
    pub status: u64,
    // 0 success, 1 transport/epoch guard, 2 Invalid, 3 NotReady, 255 other.
    pub reason: u64,
}

fn write(slot: usize, ordinal: u64, sample: &Observation, first: bool) {
    let row = &SESSION_ACTIVITY_EVIDENCE.0[8 + slot * 24..8 + (slot + 1) * 24];
    let previous = row[0].load(Ordering::Acquire);
    if first && previous != 0 {
        return;
    }
    let Some(sequence) = previous.checked_add(2) else {
        return;
    };
    row[0].store(sequence - 1, Ordering::Release);
    let values = [
        ordinal,
        sample.boot,
        sample.token,
        sample.requested_epoch,
        sample.live_epoch,
        u64::from(sample.connected),
        sample.fresh_ms,
        sample.before[0],
        sample.before[1],
        sample.before[2],
        sample.before[3],
        sample.status,
        sample.reason,
        sample.after[0],
        sample.after[1],
        sample.after[2],
        sample.after[3],
    ];
    for (word, value) in row[1..18].iter().zip(values) {
        word.store(value, Ordering::Relaxed);
    }
    for (word, time) in row[18..21].iter().zip(&BROKER_TIMING) {
        word.store(time.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    row[0].store(sequence, Ordering::Release);
}

pub(super) fn record(sample: Observation) {
    let ordinal = SESSION_ACTIVITY_EVIDENCE.0[4].fetch_add(1, Ordering::Relaxed) + 1;
    if sample.token == 1 && sample.status == 0 {
        write(0, ordinal, &sample, true);
    }
    if sample.token == 3 {
        SESSION_ACTIVITY_EVIDENCE.0[5].fetch_add(1, Ordering::Relaxed);
        let index = if sample.status == 0 { 7 } else { 6 };
        SESSION_ACTIVITY_EVIDENCE.0[index].fetch_add(1, Ordering::Relaxed);
        if sample.status != 0 {
            write(1, ordinal, &sample, true);
        }
        write(2, ordinal, &sample, false);
    }
    write(3, ordinal, &sample, false);
}

#[cfg(test)]
pub(super) fn snapshot() -> [u64; 104] {
    core::array::from_fn(|i| SESSION_ACTIVITY_EVIDENCE.0[i].load(Ordering::Acquire))
}
