//! Bounded contiguous-run ownership state machine for whole-image executable
//! backing. Unlike [`crate::frames::FramePool`], which hands out independent
//! pages, each allocation here is a physically contiguous run: the static
//! loader builds the initial stack through one base-relative slice and the
//! supervisor resolves image pages against a single run base. Clearing and
//! revocation must succeed before a run is released for reuse.
//!
//! Free space is recomputed from the occupied set on every allocation, so gaps
//! coalesce implicitly and no separate free list can drift out of sync. The
//! live-run table is bounded by `N`; both a full table and an exhausted address
//! window are distinct, reported failures rather than silent overcommit.
use super::frames::{FrameError, FrameSnapshot};
use cyxia_contracts::TaskId;

#[derive(Debug, Clone, Copy)]
struct Run {
    base: u64,
    pages: usize,
    owner: TaskId,
}

#[derive(Debug)]
pub struct ContigFramePool<const N: usize> {
    base: u64,
    capacity: usize,
    runs: [Option<Run>; N],
}

impl<const N: usize> ContigFramePool<N> {
    /// `base` is an exclusively reserved, page-aligned physical range of
    /// `capacity` pages. The caller must have retired every other claim to it.
    pub fn new(base: u64, capacity: usize) -> Result<Self, FrameError> {
        if base == 0 || !base.is_multiple_of(4096) || capacity == 0 || N == 0 {
            return Err(FrameError::Invalid);
        }
        let bytes = (capacity as u64).checked_mul(4096).ok_or(FrameError::Capacity)?;
        if base.checked_add(bytes).is_none() {
            return Err(FrameError::Capacity);
        }
        Ok(Self { base, capacity, runs: [None; N] })
    }

    pub fn snapshot(&self) -> FrameSnapshot {
        let used: usize = self.runs.iter().filter_map(|r| *r).map(|r| r.pages).sum();
        FrameSnapshot { capacity: self.capacity, free: self.capacity - used, used }
    }

    /// First-fit contiguous run owned by `owner`. Returns the physical base.
    pub fn allocate(&mut self, pages: usize, owner: TaskId) -> Result<u64, FrameError> {
        if pages == 0 || pages > self.capacity {
            return Err(FrameError::Invalid);
        }
        let slot = self.runs.iter().position(|r| r.is_none()).ok_or(FrameError::Capacity)?;
        let mut occupied: [(u64, u64); N] = [(0, 0); N];
        let mut count = 0;
        for run in self.runs.iter().filter_map(|r| *r) {
            occupied[count] = (run.base, run.base + run.pages as u64 * 4096);
            count += 1;
        }
        occupied[..count].sort_unstable_by_key(|&(base, _)| base);
        let need = pages as u64 * 4096;
        let end = self.base + self.capacity as u64 * 4096;
        let mut cursor = self.base;
        let mut chosen = None;
        for &(start, stop) in &occupied[..count] {
            if start >= cursor.saturating_add(need) {
                chosen = Some(cursor);
                break;
            }
            cursor = cursor.max(stop);
        }
        if chosen.is_none() && end >= cursor.saturating_add(need) {
            chosen = Some(cursor);
        }
        let base = chosen.ok_or(FrameError::Exhausted)?;
        self.runs[slot] = Some(Run { base, pages, owner });
        Ok(base)
    }

    /// Release exactly the run identified by `base`/`pages` after its mappings
    /// were retired and its contents cleared. A mismatched owner is rejected
    /// without freeing anything; an unknown identity is stale.
    pub fn release(&mut self, base: u64, pages: usize, owner: TaskId) -> Result<(), FrameError> {
        for run in self.runs.iter_mut() {
            if let Some(r) = run
                && r.base == base && r.pages == pages {
                if r.owner != owner {
                    return Err(FrameError::Owner);
                }
                *run = None;
                return Ok(());
            }
        }
        Err(FrameError::Stale)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(n: u32) -> TaskId {
        TaskId::new(n).unwrap()
    }

    #[test]
    fn sequential_allocation_charges_contiguous_runs_and_reports_capacity() {
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 16, free: 16, used: 0 });
        assert_eq!(pool.allocate(4, owner(1)).unwrap(), 0x1000);
        assert_eq!(pool.allocate(4, owner(2)).unwrap(), 0x5000);
        assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 16, free: 8, used: 8 });
        assert_eq!(pool.allocate(8, owner(3)).unwrap(), 0x9000);
        assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 16, free: 0, used: 16 });
        assert_eq!(pool.allocate(1, owner(4)), Err(FrameError::Exhausted));
    }

    #[test]
    fn first_fit_reuses_a_released_gap_before_extending_the_window() {
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        let a = pool.allocate(4, owner(1)).unwrap();
        let b = pool.allocate(4, owner(2)).unwrap();
        let _c = pool.allocate(4, owner(3)).unwrap();
        assert_eq!((a, b), (0x1000, 0x5000));
        pool.release(b, 4, owner(2)).unwrap();
        // The freed 4-page gap at 0x5000 is reused instead of opening 0xd000.
        assert_eq!(pool.allocate(2, owner(4)).unwrap(), 0x5000);
        assert_eq!(pool.allocate(2, owner(5)).unwrap(), 0x7000);
        assert_eq!(pool.snapshot().used, 12);
    }

    #[test]
    fn adjacent_releases_coalesce_into_a_larger_usable_gap() {
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        let a = pool.allocate(4, owner(1)).unwrap();
        let b = pool.allocate(4, owner(2)).unwrap();
        let _c = pool.allocate(8, owner(3)).unwrap();
        pool.release(a, 4, owner(1)).unwrap();
        pool.release(b, 4, owner(2)).unwrap();
        // Neither 4-page hole alone fits 8 pages; the coalesced gap does.
        assert_eq!(pool.allocate(8, owner(4)).unwrap(), 0x1000);
        assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 16, free: 0, used: 16 });
    }

    #[test]
    fn live_run_table_bounds_allocation_even_when_pages_remain() {
        let mut pool = ContigFramePool::<2>::new(0x1000, 64).unwrap();
        pool.allocate(1, owner(1)).unwrap();
        pool.allocate(1, owner(2)).unwrap();
        assert_eq!(pool.allocate(1, owner(3)), Err(FrameError::Capacity));
        assert_eq!(pool.snapshot().free, 62);
    }

    #[test]
    fn release_checks_owner_and_identity_and_is_not_idempotent() {
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        let base = pool.allocate(4, owner(1)).unwrap();
        assert_eq!(pool.release(base, 4, owner(2)), Err(FrameError::Owner));
        assert_eq!(pool.snapshot().used, 4);
        assert_eq!(pool.release(base + 4096, 4, owner(1)), Err(FrameError::Stale));
        assert_eq!(pool.release(base, 8, owner(1)), Err(FrameError::Stale));
        pool.release(base, 4, owner(1)).unwrap();
        assert_eq!(pool.snapshot().used, 0);
        assert_eq!(pool.release(base, 4, owner(1)), Err(FrameError::Stale));
    }

    #[test]
    fn forged_release_does_not_free_another_owners_run() {
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        let a = pool.allocate(4, owner(1)).unwrap();
        let b = pool.allocate(4, owner(2)).unwrap();
        assert_eq!(pool.release(a, 4, owner(2)), Err(FrameError::Owner));
        assert_eq!(pool.release(b, 4, owner(1)), Err(FrameError::Owner));
        assert_eq!(pool.snapshot(), FrameSnapshot { capacity: 16, free: 8, used: 8 });
    }

    #[test]
    fn invalid_geometry_and_requests_are_rejected() {
        assert_eq!(ContigFramePool::<4>::new(0, 16).unwrap_err(), FrameError::Invalid);
        assert_eq!(ContigFramePool::<4>::new(0x1001, 16).unwrap_err(), FrameError::Invalid);
        assert_eq!(ContigFramePool::<4>::new(0x1000, 0).unwrap_err(), FrameError::Invalid);
        assert_eq!(ContigFramePool::<0>::new(0x1000, 16).unwrap_err(), FrameError::Invalid);
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        assert_eq!(pool.allocate(0, owner(1)), Err(FrameError::Invalid));
        assert_eq!(pool.allocate(17, owner(1)), Err(FrameError::Invalid));
        assert_eq!(pool.allocate(16, owner(1)).unwrap(), 0x1000);
    }
}
