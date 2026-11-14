//! Fixed-memory, single-producer IRQ timing histogram. Every completed handler
//! contributes; interrupt frequency never evicts a sample. Integer microsecond
//! bins yield the exact nearest-rank p99 at that stated clock precision. If the
//! p99 lies beyond the represented 4095 us, report it unavailable rather than
//! substituting a bucket edge or a fabricated duration.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};

const MICROSECOND_BINS: usize = 4096;
const BINS: usize = MICROSECOND_BINS + 1;

pub struct Histogram {
    sequence: AtomicU64,
    count: AtomicU64,
    ticks: AtomicU64,
    bins: [AtomicU64; BINS],
    invalid: AtomicBool,
}
pub struct Snapshot {
    count: u64,
    ticks: u64,
    bins: [u64; BINS],
}
pub struct Delta {
    pub count: u64,
    pub ticks: u64,
    pub p99_us: Option<u64>,
}

impl Histogram {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            count: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            bins: [const { AtomicU64::new(0) }; BINS],
            invalid: AtomicBool::new(false),
        }
    }
    /// The source is masked before this call and cannot have a second active
    /// handler. A violated producer contract or arithmetic overflow invalidates
    /// measurements; neither case is hidden by wrapping or dropping a sample.
    pub fn record(&self, ticks: u64, frequency: u64) {
        if frequency == 0 {
            self.invalid.store(true, Ordering::Release);
            return;
        }
        let sequence = self.sequence.load(Ordering::Relaxed);
        if sequence & 1 != 0 || sequence > u64::MAX - 2 {
            self.invalid.store(true, Ordering::Release);
            return;
        }
        if self
            .sequence
            .compare_exchange(sequence, sequence + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            self.invalid.store(true, Ordering::Release);
            return;
        }
        let us = (u128::from(ticks) * 1_000_000).div_ceil(u128::from(frequency));
        let bucket = us.min(MICROSECOND_BINS as u128) as usize;
        let next = self
            .count
            .load(Ordering::Relaxed)
            .checked_add(1)
            .zip(self.ticks.load(Ordering::Relaxed).checked_add(ticks))
            .zip(self.bins[bucket].load(Ordering::Relaxed).checked_add(1));
        if let Some(((count, total), bin)) = next {
            self.count.store(count, Ordering::Relaxed);
            self.ticks.store(total, Ordering::Relaxed);
            self.bins[bucket].store(bin, Ordering::Relaxed);
        } else {
            self.invalid.store(true, Ordering::Release);
        }
        self.sequence.store(sequence + 2, Ordering::Release);
    }
    /// The foreground reader never spins waiting for an IRQ producer. The
    /// atomic payload and sequence check also cover a producer on CPU3.
    pub fn snapshot(&self, out: &mut Snapshot) -> bool {
        for _ in 0..3 {
            let sequence = self.sequence.load(Ordering::Acquire);
            if sequence & 1 != 0 || self.invalid.load(Ordering::Acquire) {
                continue;
            }
            out.count = self.count.load(Ordering::Relaxed);
            out.ticks = self.ticks.load(Ordering::Relaxed);
            for (out, bin) in out.bins.iter_mut().zip(&self.bins) {
                *out = bin.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if self.sequence.load(Ordering::Relaxed) == sequence
                && !self.invalid.load(Ordering::Acquire)
            {
                return true;
            }
        }
        false
    }
}
impl Snapshot {
    pub const fn new() -> Self {
        Self {
            count: 0,
            ticks: 0,
            bins: [0; BINS],
        }
    }
    /// Copy directly into fixed storage, avoiding a 32KiB temporary on a native
    /// CPU's bounded kernel stack.
    pub fn copy_from(&mut self, other: &Self) {
        self.count = other.count;
        self.ticks = other.ticks;
        self.bins.copy_from_slice(&other.bins);
    }
    pub fn since(&self, previous: &Self) -> Option<Delta> {
        let count = self.count.checked_sub(previous.count)?;
        let ticks = self.ticks.checked_sub(previous.ticks)?;
        let rank = (u128::from(count) * 99).div_ceil(100);
        let mut cumulative = 0u128;
        let mut p99_us = None;
        for (i, (current, old)) in self.bins.iter().zip(&previous.bins).enumerate() {
            cumulative += u128::from(current.checked_sub(*old)?);
            if count != 0 && cumulative >= rank && p99_us.is_none() && i < MICROSECOND_BINS {
                p99_us = Some(i as u64);
            }
        }
        (cumulative == u128::from(count)).then_some(Delta {
            count,
            ticks,
            p99_us,
        })
    }
}
