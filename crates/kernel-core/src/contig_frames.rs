//! Bounded contiguous-run ownership state machine for whole-image executable
//! backing. Unlike [`crate::frames::FramePool`], which hands out independent
//! pages, each allocation here is a physically contiguous run: the static
//! loader builds the initial stack through one base-relative slice and the
//! supervisor resolves image pages against a single run base. Clearing and
//! revocation must succeed before a run is released for reuse.
//!
//! The occupied prefix is kept sorted by physical base, followed by empty
//! slots. First-fit allocation and release are bounded O(N) operations without
//! an allocation-time sorting scratch array. Gaps coalesce implicitly; no
//! separate free list can drift out of sync. A full live-run table and an
//! exhausted address window remain distinct failures.
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
        let bytes = (capacity as u64)
            .checked_mul(4096)
            .ok_or(FrameError::Capacity)?;
        if base.checked_add(bytes).is_none() {
            return Err(FrameError::Capacity);
        }
        Ok(Self {
            base,
            capacity,
            runs: [None; N],
        })
    }

    pub fn snapshot(&self) -> FrameSnapshot {
        let used: usize = self.runs.iter().filter_map(|r| *r).map(|r| r.pages).sum();
        FrameSnapshot {
            capacity: self.capacity,
            free: self.capacity - used,
            used,
        }
    }

    /// First-fit contiguous run owned by `owner`. Returns the physical base.
    pub fn allocate(&mut self, pages: usize, owner: TaskId) -> Result<u64, FrameError> {
        if pages == 0 || pages > self.capacity {
            return Err(FrameError::Invalid);
        }
        let count = self
            .runs
            .iter()
            .position(Option::is_none)
            .ok_or(FrameError::Capacity)?;
        let need = pages as u64 * 4096;
        let end = self.base + self.capacity as u64 * 4096;
        let mut cursor = self.base;
        let mut insertion = 0;
        for run in self.runs[..count].iter().flatten() {
            if run.base.saturating_sub(cursor) >= need {
                break;
            }
            cursor = run.base + run.pages as u64 * 4096;
            insertion += 1;
        }
        if end.saturating_sub(cursor) < need {
            return Err(FrameError::Exhausted);
        }
        // Publish only after a complete gap has been found. Preserve the sorted
        // occupied prefix and the empty tail; ownership and first-fit stay exact.
        self.runs.copy_within(insertion..count, insertion + 1);
        self.runs[insertion] = Some(Run {
            base: cursor,
            pages,
            owner,
        });
        Ok(cursor)
    }

    /// Release exactly the run identified by `base`/`pages` after its mappings
    /// were retired and its contents cleared. A mismatched owner is rejected
    /// without freeing anything; an unknown identity is stale.
    pub fn release(&mut self, base: u64, pages: usize, owner: TaskId) -> Result<(), FrameError> {
        let count = self.runs.iter().position(Option::is_none).unwrap_or(N);
        for index in 0..count {
            if let Some(r) = self.runs[index]
                && r.base == base
                && r.pages == pages
            {
                if r.owner != owner {
                    return Err(FrameError::Owner);
                }
                self.runs.copy_within(index + 1..count, index);
                self.runs[count - 1] = None;
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
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 16,
                free: 16,
                used: 0
            }
        );
        assert_eq!(pool.allocate(4, owner(1)).unwrap(), 0x1000);
        assert_eq!(pool.allocate(4, owner(2)).unwrap(), 0x5000);
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 16,
                free: 8,
                used: 8
            }
        );
        assert_eq!(pool.allocate(8, owner(3)).unwrap(), 0x9000);
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 16,
                free: 0,
                used: 16
            }
        );
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
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 16,
                free: 0,
                used: 16
            }
        );
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
        assert_eq!(
            pool.release(base + 4096, 4, owner(1)),
            Err(FrameError::Stale)
        );
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
        assert_eq!(
            pool.snapshot(),
            FrameSnapshot {
                capacity: 16,
                free: 8,
                used: 8
            }
        );
    }

    #[test]
    fn first_fit_matches_page_bitmap_for_every_eight_page_fragmentation() {
        for used_mask in 0u16..=255 {
            for pages in 1usize..=8 {
                let mut pool = ContigFramePool::<8>::new(0x1000, 8).unwrap();
                for page in 0..8 {
                    assert_eq!(
                        pool.allocate(1, owner(page as u32 + 1)).unwrap(),
                        0x1000 + page as u64 * 4096
                    );
                }
                for page in 0..8 {
                    if used_mask & (1 << page) == 0 {
                        pool.release(0x1000 + page as u64 * 4096, 1, owner(page as u32 + 1))
                            .unwrap();
                    }
                }
                let bits = (1u16 << pages) - 1;
                let expected = if used_mask == 255 {
                    Err(FrameError::Capacity)
                } else {
                    (0..=8 - pages)
                        .find(|&start| used_mask & (bits << start) == 0)
                        .map(|start| 0x1000 + start as u64 * 4096)
                        .ok_or(FrameError::Exhausted)
                };
                assert_eq!(pool.allocate(pages, owner(99)), expected);
                let used =
                    used_mask.count_ones() as usize + if expected.is_ok() { pages } else { 0 };
                assert_eq!(
                    pool.snapshot(),
                    FrameSnapshot {
                        capacity: 8,
                        free: 8 - used,
                        used,
                    }
                );
            }
        }
    }

    #[test]
    fn first_fit_near_address_limit_preserves_exhaustion_and_ownership() {
        let base = u64::MAX - 0x4fff;
        let mut pool = ContigFramePool::<4>::new(base, 4).unwrap();
        let a = pool.allocate(3, owner(1)).unwrap();
        let b = pool.allocate(1, owner(2)).unwrap();
        assert_eq!((a, b), (base, base + 3 * 4096));
        assert_eq!(pool.allocate(1, owner(3)), Err(FrameError::Exhausted));
        assert_eq!(pool.release(a, 3, owner(2)), Err(FrameError::Owner));
        assert_eq!(pool.snapshot().used, 4);
        pool.release(a, 3, owner(1)).unwrap();
        assert_eq!(pool.allocate(3, owner(3)), Ok(base));
        assert_eq!(pool.snapshot().free, 0);
    }

    #[test]
    fn invalid_geometry_and_requests_are_rejected() {
        assert_eq!(
            ContigFramePool::<4>::new(0, 16).unwrap_err(),
            FrameError::Invalid
        );
        assert_eq!(
            ContigFramePool::<4>::new(0x1001, 16).unwrap_err(),
            FrameError::Invalid
        );
        assert_eq!(
            ContigFramePool::<4>::new(0x1000, 0).unwrap_err(),
            FrameError::Invalid
        );
        assert_eq!(
            ContigFramePool::<0>::new(0x1000, 16).unwrap_err(),
            FrameError::Invalid
        );
        let mut pool = ContigFramePool::<4>::new(0x1000, 16).unwrap();
        assert_eq!(pool.allocate(0, owner(1)), Err(FrameError::Invalid));
        assert_eq!(pool.allocate(17, owner(1)), Err(FrameError::Invalid));
        assert_eq!(pool.allocate(16, owner(1)).unwrap(), 0x1000);
    }
}
