//! Outbound sequence fence. Only the actual C1 billing owner acknowledges it
//! after settling both original credits; it grants no work or label authority.
use core::sync::atomic::{AtomicU64, Ordering};
pub struct Fence {
    current: AtomicU64,
    settled: AtomicU64,
}
impl Fence {
    pub const fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
            settled: AtomicU64::new(0),
        }
    }
    pub fn begin(&self, sequence: u64) {
        self.current.store(sequence, Ordering::Release);
    }
    pub fn ticket(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }
    pub fn acknowledge(&self, sequence: u64) {
        self.settled.store(sequence, Ordering::Release);
    }
    pub fn settled(&self, ticket: u64) -> bool {
        ticket != 0 && self.settled.load(Ordering::Acquire) >= ticket
    }
}
