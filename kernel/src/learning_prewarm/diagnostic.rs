//! First-cause observation only; never grants evidence or changes warm custody.
use core::sync::atomic::{AtomicU64, Ordering};
pub const MAGIC: u64 = 0x4359_5057_4641_3136;
/// 0 seqlock,1 magic,2 schema1,3 site(1 pendingDrop,2 finishAuth,3 fullRing,
/// 4 freezeLost),4 originalError+1 (0 for Drop with no returned Error),
/// 5 bank(u64::MAX when absent),6 observedCPU,7 attemptSession,8 currentSession,
/// 9 first,10 last,11 earliest,12 observedClock(0 if not read by original check),
/// 13 head,14 tail,15 capacity,16 oldLast,17 cutoff,18 open,19 active,20 lost,
/// 21 completed,22 lastCompleted,23 frozenFirst,24 started,25 finishAttempted,
/// 26 flags(bit0 clock observed,bit1 ring operands original,bit2 oldLast original,
/// bit3 currentSession observed),
/// 27 boot,28 trial,29 captureGeneration;30..31 reserved0.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 32]);
impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 32])
    }
    pub fn record(&self, words: &[u64; 32]) {
        if self.0[0]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        for (slot, value) in self.0.iter().zip(words).skip(1) {
            slot.store(*value, Ordering::Relaxed);
        }
        self.0[0].store(2, Ordering::Release);
    }
    #[cfg(test)]
    pub fn snapshot(&self) -> [u64; 32] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
#[used]
#[unsafe(no_mangle)]
pub static LEARNING_PREWARM_FIRST_FAILURE: Evidence = Evidence::new();
pub const BYTES: usize = core::mem::size_of::<Evidence>();
const _: () = assert!(BYTES == 256);
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_capacity_operands_are_first_cause_and_never_overwritten() {
        let bank = Evidence::new();
        assert_eq!(bank.snapshot(), [0; 32]);
        let mut words = [0; 32];
        words[1] = MAGIC;
        words[2] = 1;
        words[3] = 3;
        words[4] = 5;
        words[5] = 1;
        words[6] = 1;
        words[7] = 9;
        words[8] = 9;
        words[9] = 2_100_000_000;
        words[10] = 2_100_001_000;
        words[13] = 256;
        words[14] = 0;
        words[15] = 256;
        words[16] = 1_100_001_000;
        words[17] = 1_100_001_000;
        words[18] = 1;
        words[19] = 1;
        words[20] = 1;
        words[26] = 15;
        bank.record(&words);
        let original = bank.snapshot();
        assert_eq!(original[0], 2);
        assert_eq!(&original[1..], &words[1..]);
        words[3] = 1;
        words[4] = 0;
        words[18] = 0;
        bank.record(&words);
        assert_eq!(bank.snapshot(), original);
    }
}
