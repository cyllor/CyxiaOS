//! Bounded positive observations only. No snapshot grants replay authority.
use core::sync::atomic::{AtomicU64, Ordering};
pub const MAGIC: u64 = 0x4359505750523136;
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 128]);
#[used]
#[unsafe(no_mangle)]
pub static CORESET_PREWARM_PROGRESS: Evidence = Evidence([const { AtomicU64::new(0) }; 128]);
pub const BYTES: usize = core::mem::size_of::<Evidence>();
const _: () = assert!(BYTES == 1024);
pub fn publish(words: &[u64; 128]) {
    CORESET_PREWARM_PROGRESS.0[0].fetch_add(1, Ordering::AcqRel);
    for (i, value) in words.iter().enumerate().skip(1) {
        CORESET_PREWARM_PROGRESS.0[i].store(*value, Ordering::Relaxed);
    }
    CORESET_PREWARM_PROGRESS.0[0].fetch_add(1, Ordering::Release);
}
