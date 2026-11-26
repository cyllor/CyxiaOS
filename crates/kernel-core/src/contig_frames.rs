//! Bounded contiguous-run ownership state machine for whole-image executable
//! backing. Unlike [`crate::frames::FramePool`], which hands out independent
//! pages, each allocation here is a physically contiguous run: the static
//! loader builds the initial stack through one base-relative slice and the
//! supervisor resolves image pages against a single run base. Clearing and
//! revocation must succeed before a run is released for reuse.
//!
//! Small tables retain the original sparse slots and sort a bounded local
//! interval list for first-fit. Larger tables use an ordered occupied prefix
//! and avoid sorting scratch. Both keep one authoritative ownership table;
//! gaps coalesce implicitly. A full table and an exhausted address window
//! remain distinct failures. The compile-time cutoff is measurement-driven
//! and provisional until the expanded same-runner size sweep is verified.
use super::frames::{FrameError, FrameSnapshot};
use cyxia_contracts::TaskId;

// Wave 9 measured regressions at 17..27, mixed results at 28..30, and
// gains at 31/32/64. Prefer the historical sparse path through 30 to
// avoid sacrificing dense workloads for small fragmentation-only gains.
// This host-derived cutoff is provisional pending target measurements.
const SMALL_RUN_LIMIT: usize = 30;

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
        if N <= SMALL_RUN_LIMIT {
            let slot = self
                .runs
                .iter()
                .position(|r| r.is_none())
                .ok_or(FrameError::Capacity)?;
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
            return Ok(base);
        }
        let count = self.runs.partition_point(Option::is_some);
        if count == N {
            return Err(FrameError::Capacity);
        }
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
        if N <= SMALL_RUN_LIMIT {
            for run in self.runs.iter_mut() {
                if let Some(r) = run
                    && r.base == base
                    && r.pages == pages
                {
                    if r.owner != owner {
                        return Err(FrameError::Owner);
                    }
                    *run = None;
                    return Ok(());
                }
            }
            return Err(FrameError::Stale);
        }
        // Nonempty runs have unique increasing bases; empty slots compare
        // after every valid base. The handle identity still includes pages
        // and owner, and a failed lookup never mutates the occupied prefix.
        let index = self
            .runs
            .binary_search_by(|r| r.map_or(core::cmp::Ordering::Greater, |r| r.base.cmp(&base)))
            .map_err(|_| FrameError::Stale)?;
        let run = self.runs[index].ok_or(FrameError::Stale)?;
        if run.pages != pages {
            return Err(FrameError::Stale);
        }
        if run.owner != owner {
            return Err(FrameError::Owner);
        }
        let count = self.runs.partition_point(Option::is_some);
        self.runs.copy_within(index + 1..count, index);
        self.runs[count - 1] = None;
        Ok(())
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
    fn wave7_exact_release_lookup_preserves_error_order_and_sorted_reuse() {
        let mut pool = ContigFramePool::<16>::new(0x1000, 32).unwrap();
        let mut bases = [0u64; 16];
        for (i, base) in bases.iter_mut().enumerate() {
            *base = pool.allocate(2, owner(i as u32 + 1)).unwrap();
        }
        assert_eq!(pool.allocate(1, owner(99)), Err(FrameError::Capacity));
        for i in (0..16).rev().step_by(2) {
            assert_eq!(pool.release(bases[i], 1, owner(99)), Err(FrameError::Stale));
            assert_eq!(pool.release(bases[i], 2, owner(99)), Err(FrameError::Owner));
            pool.release(bases[i], 2, owner(i as u32 + 1)).unwrap();
            assert_eq!(
                pool.release(bases[i], 2, owner(i as u32 + 1)),
                Err(FrameError::Stale)
            );
        }
        for &base in bases.iter().skip(1).step_by(2) {
            assert_eq!(pool.allocate(2, owner(99)), Ok(base));
        }
        assert_eq!(pool.snapshot().used, 32);
        assert_eq!(pool.allocate(1, owner(99)), Err(FrameError::Capacity));
    }

    fn exercise_capacity<const N: usize>() {
        let capacity = 3 * N;
        let base = u64::MAX - 4095 - capacity as u64 * 4096;
        let mut pool = ContigFramePool::<N>::new(base, capacity).unwrap();
        let mut addresses = [0; N];
        for (i, address) in addresses.iter_mut().enumerate() {
            *address = pool.allocate(3, owner(i as u32 + 1)).unwrap();
            assert_eq!(*address, base + i as u64 * 12288);
        }
        assert_eq!(pool.allocate(1, owner(99)), Err(FrameError::Capacity));
        for i in (1..N).rev().filter(|i| i % 2 != 0) {
            let address = addresses[i];
            assert_eq!(pool.release(address, 2, owner(99)), Err(FrameError::Stale));
            assert_eq!(pool.release(address, 3, owner(99)), Err(FrameError::Owner));
            pool.release(address, 3, owner(i as u32 + 1)).unwrap();
        }
        assert_eq!(pool.allocate(4, owner(99)), Err(FrameError::Exhausted));
        for &address in addresses.iter().skip(1).step_by(2) {
            assert_eq!(pool.allocate(3, owner(99)), Ok(address));
        }
        assert_eq!(pool.snapshot().free, 0);
        for (i, address) in addresses.into_iter().enumerate() {
            let who = if i % 2 == 0 { i as u32 + 1 } else { 99 };
            pool.release(address, 3, owner(who)).unwrap();
        }
        assert_eq!(pool.snapshot().used, 0);
        assert_eq!(pool.allocate(capacity, owner(99)), Ok(base));
    }

    #[test]
    fn wave8_small_large_boundary_preserves_first_fit_and_ownership() {
        exercise_capacity::<4>();
        exercise_capacity::<8>();
        exercise_capacity::<9>();
        exercise_capacity::<16>();
        exercise_capacity::<17>();
        exercise_capacity::<24>();
        exercise_capacity::<28>();
        exercise_capacity::<30>();
        exercise_capacity::<31>();
        exercise_capacity::<32>();
        exercise_capacity::<64>();
    }

    fn exercise_randomized<const N: usize>(base: u64) {
        let capacity = 3 * N;
        let mut pool = ContigFramePool::<N>::new(base, capacity).unwrap();
        let mut live: [Option<(usize, usize, TaskId)>; N] = [None; N];
        let mut seed = 0x9a62_c15bu32 ^ N as u32;
        let mut next = || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            (seed >> 16) as usize
        };
        for step in 0..2048 {
            let op = next() % 5;
            let count = live.iter().flatten().count();
            let who = owner((next() % 11 + 1) as u32);
            if op < 2 {
                let pages = if next() % 12 == 0 {
                    capacity + 1
                } else {
                    next() % 9
                };
                let expected = if pages == 0 || pages > capacity {
                    Err(FrameError::Invalid)
                } else if count == N {
                    Err(FrameError::Capacity)
                } else {
                    let mut used = [false; 192];
                    for &(at, len, _) in live.iter().flatten() {
                        used[at..at + len].fill(true);
                    }
                    (0..=capacity - pages)
                        .find(|&at| used[at..at + pages].iter().all(|bit| !bit))
                        .map(|at| base + at as u64 * 4096)
                        .ok_or(FrameError::Exhausted)
                };
                assert_eq!(pool.allocate(pages, who), expected, "N={N} step={step}");
                if let Ok(address) = expected {
                    let at = ((address - base) / 4096) as usize;
                    let slot = live.iter_mut().find(|r| r.is_none()).unwrap();
                    *slot = Some((at, pages, who));
                }
            } else {
                let mut request = (next() % capacity, next() % 6 + 1, who);
                if op < 4
                    && let Some(&entry) = live.iter().flatten().nth(next() % count.max(1))
                {
                    request = entry;
                    if op == 3 {
                        request.2 = if entry.2 == owner(1) {
                            owner(2)
                        } else {
                            owner(1)
                        };
                    }
                }
                let (at, pages, who) = request;
                let address = base + at as u64 * 4096;
                let slot = live
                    .iter()
                    .position(|r| r.is_some_and(|(start, len, _)| start == at && len == pages));
                let expected = match slot {
                    None => Err(FrameError::Stale),
                    Some(i) if live[i].unwrap().2 != who => Err(FrameError::Owner),
                    Some(_) => Ok(()),
                };
                assert_eq!(
                    pool.release(address, pages, who),
                    expected,
                    "N={N} step={step}"
                );
                if expected.is_ok() {
                    live[slot.unwrap()] = None;
                }
            }
            let used: usize = live.iter().flatten().map(|r| r.1).sum();
            assert_eq!(
                pool.snapshot(),
                FrameSnapshot {
                    capacity,
                    used,
                    free: capacity - used,
                }
            );
        }
        for (at, pages, who) in live.into_iter().flatten() {
            pool.release(base + at as u64 * 4096, pages, who).unwrap();
        }
        assert_eq!(pool.snapshot().free, capacity);
    }

    #[test]
    fn wave10_randomized_public_allocator_matches_independent_occupancy() {
        fn both<const N: usize>() {
            exercise_randomized::<N>(4096);
            exercise_randomized::<N>(u64::MAX - 4095 - 3 * N as u64 * 4096);
        }
        both::<1>();
        both::<2>();
        both::<4>();
        both::<8>();
        both::<9>();
        both::<16>();
        both::<17>();
        both::<20>();
        both::<24>();
        both::<28>();
        both::<30>();
        both::<31>();
        both::<32>();
        both::<64>();
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
