//! Latest terminal EL0 loop timing, published after teardown. This bank never
//! describes the current active session.
use core::sync::atomic::{AtomicU64, Ordering, fence};

pub const MAGIC: u64 = 0x4359_5254_4c4f_4f31;
pub const RECORD_WORDS: usize = 32;

#[repr(C, align(64))]
pub struct Evidence {
    words: [AtomicU64; 64],
}
const _: () = assert!(core::mem::size_of::<Evidence>() == 512);

#[used]
#[unsafe(no_mangle)]
pub static RUNTIME_LOOP_EVIDENCE: Evidence = Evidence {
    words: [const { AtomicU64::new(0) }; 64],
};

fn interval(record: &[u64; RECORD_WORDS], at: usize) -> bool {
    let (duration, started, finished) = (record[at], record[at + 1], record[at + 2]);
    duration == 0 && started == 0 && finished == 0
        || record[3] <= started
            && started <= finished
            && finished <= record[28]
            && duration == finished - started
}

fn valid(record: &[u64; RECORD_WORDS], connection: u64) -> bool {
    record[0] == 1
        && record[1] == connection
        && record[2] > 0
        && record[3] > 0
        && record[3] <= record[4]
        && record[4] <= record[5]
        && record[5] <= record[28]
        && interval(record, 6)
        && interval(record, 9)
        && interval(record, 12)
        && interval(record, 15)
        && interval(record, 18)
        && interval(record, 21)
        && interval(record, 24)
        && (record[27] == 0 || record[3] <= record[27] && record[27] <= record[28])
        && (1..=16).contains(&record[29])
        && record[31] == 0
}

/// CPU0 is the sole writer. Word 0 is an odd/even publication sequence;
/// stopped readers accept only an unchanged, nonzero even snapshot.
pub fn retain(record: &[u64; RECORD_WORDS], boot: u64, generation: u64, connection: u64) -> bool {
    if boot == 0 || generation == 0 || connection == 0 || !valid(record, connection) {
        return false;
    }
    let current = RUNTIME_LOOP_EVIDENCE.words[0].load(Ordering::Acquire);
    let Some(next) = current.checked_add(2) else {
        return false;
    };
    let Some(reports) = RUNTIME_LOOP_EVIDENCE.words[3]
        .load(Ordering::Relaxed)
        .checked_add(1)
    else {
        return false;
    };
    if current & 1 != 0 {
        return false;
    }
    RUNTIME_LOOP_EVIDENCE.words[0].store(current + 1, Ordering::Release);
    fence(Ordering::Release);
    for (index, value) in [MAGIC, 1, reports, boot, generation, connection, 0]
        .into_iter()
        .enumerate()
    {
        RUNTIME_LOOP_EVIDENCE.words[index + 1].store(value, Ordering::Relaxed);
    }
    for (saved, value) in RUNTIME_LOOP_EVIDENCE.words[8..40].iter().zip(record) {
        saved.store(*value, Ordering::Relaxed);
    }
    fence(Ordering::Release);
    RUNTIME_LOOP_EVIDENCE.words[0].store(next, Ordering::Release);
    true
}

#[cfg(test)]
pub fn snapshot() -> [u64; 64] {
    core::array::from_fn(|i| RUNTIME_LOOP_EVIDENCE.words[i].load(Ordering::Acquire))
}
