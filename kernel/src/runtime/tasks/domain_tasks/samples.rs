//! Bounded recent task latency observations.
use cyxia_prototype::domains::Error;

#[derive(Clone, Copy)]
pub(super) struct Samples {
    values: [u64; 64],
    count: usize,
    next: usize,
}
impl Samples {
    pub(super) const EMPTY: Self = Self {
        values: [0; 64],
        count: 0,
        next: 0,
    };
    pub(super) fn add(&mut self, value: u64) {
        self.values[self.next] = value;
        self.next = (self.next + 1) % 64;
        self.count = (self.count + 1).min(64);
    }
    pub(super) fn p99(&self) -> Result<u64, Error> {
        if self.count == 0 {
            return Err(Error::NotReady);
        }
        // With 1..=64 samples, nearest-rank ceil(99*n/100) is exactly n.
        // A linear maximum is the exact percentile, without copying/sorting
        // the ring during a mandatory control evaluation.
        Ok(*self.values[..self.count].iter().max().unwrap())
    }
}
