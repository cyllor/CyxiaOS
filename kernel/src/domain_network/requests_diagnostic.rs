//! [DEBUG-v15-placement] Bounded observations of the real application queue.
//! No payload bytes, admission authority or completion facts originate here.
use core::sync::atomic::{AtomicU64, Ordering};

const ROWS: usize = 32;
const ROW_WORDS: usize = 24;
const HEADER: usize = 8;
const MAGIC: u64 = 0x4359_4150_5051_3031;

#[derive(Clone, Copy)]
#[repr(u64)]
pub(super) enum Stage {
    Submit = 1,
    Next = 2,
    Acknowledge = 3,
    Status = 4,
    Finish = 5,
    Reserve = 6,
    Release = 7,
    Cancel = 8,
}

/// One row per last observed request index modulo 32. Replacing a diagnostic
/// row never evicts the actual queue receipt. Words 15..23 are stage counters.
/// Header: seqlock, magic, schema, rows, row words, publications, replacements,
/// reserved. Row: request id/gen, actor id/gen, sequence, submitted ns, observed
/// ns, stage, reserved, state, target id/gen, completion outcome/finished ns,
/// flags(available/cancelled/completed), 8 stage counters, last state-change ns.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; HEADER + ROWS * ROW_WORDS]);

impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; HEADER + ROWS * ROW_WORDS])
    }

    pub(super) fn record(&self, index: usize, stage: Stage, mut facts: [u64; 15]) {
        let sequence = self.0[0].load(Ordering::Relaxed);
        if sequence & 1 != 0 || sequence > u64::MAX - 2 {
            return;
        }
        // The real queue has one CPU0 owner. Contended host-test writers may
        // omit a diagnostic observation; they must never block real custody.
        if self.0[0]
            .compare_exchange(sequence, sequence + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let at = HEADER + (index % ROWS) * ROW_WORDS;
        let same = self.0[at].load(Ordering::Relaxed) == facts[0]
            && self.0[at + 1].load(Ordering::Relaxed) == facts[1];
        let state_changed = !same
            || self.0[at + 9].load(Ordering::Relaxed) != facts[9]
            || self.0[at + 10].load(Ordering::Relaxed) != facts[10]
            || self.0[at + 11].load(Ordering::Relaxed) != facts[11]
            || self.0[at + 12].load(Ordering::Relaxed) != facts[12]
            || self.0[at + 14].load(Ordering::Relaxed) != facts[14];
        if !same {
            if self.0[at].load(Ordering::Relaxed) != 0 {
                self.0[6].fetch_add(1, Ordering::Relaxed);
            }
            for slot in &self.0[at..at + ROW_WORDS] {
                slot.store(0, Ordering::Relaxed);
            }
        }
        facts[7] = stage as u64;
        for (slot, value) in self.0[at..at + 15].iter().zip(facts) {
            slot.store(value, Ordering::Relaxed);
        }
        let count = &self.0[at + 14 + stage as usize];
        count.store(
            count.load(Ordering::Relaxed).saturating_add(1),
            Ordering::Relaxed,
        );
        if state_changed {
            self.0[at + 23].store(facts[6], Ordering::Relaxed);
        }
        for (slot, value) in
            self.0[1..6]
                .iter()
                .zip([MAGIC, 1, ROWS as u64, ROW_WORDS as u64, sequence / 2 + 1])
        {
            slot.store(value, Ordering::Relaxed);
        }
        self.0[0].store(sequence + 2, Ordering::Release);
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> [u64; HEADER + ROWS * ROW_WORDS] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}

#[used]
#[unsafe(no_mangle)]
pub static APPLICATION_REQUEST_EVIDENCE: Evidence = Evidence::new();

const _: () = assert!(core::mem::size_of::<Evidence>() == 6208);
