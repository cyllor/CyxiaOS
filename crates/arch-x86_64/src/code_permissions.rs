//! Transactional direct-map permissions. The owner retains frames on every
//! failure; only completed hardware fences authorize a stable permission state.
use crate::space::{Error, PAGE_BYTES};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    StableWritable = 0,
    Transition = 1,
    StableSealed = 2,
}
impl Phase {
    /// Old aliases may always be removed, including during a failed transition.
    /// No new alias is published while the physical permission is uncertain.
    pub fn permits_mapping(self, new: u64) -> bool {
        if new == 0 {
            return true;
        }
        if new & !7 != 0 || new & 1 == 0 || new & 6 == 6 {
            return false;
        }
        match self {
            Self::StableWritable => new & 4 == 0,
            Self::StableSealed => new & 2 == 0,
            Self::Transition => false,
        }
    }
}

/// Two bits per physical page. Writers still serialize the whole transaction;
/// atomic fields also make a phase read indivisible for architectural guards.
pub struct PhaseTable<const WORDS: usize> {
    words: [AtomicU64; WORDS],
}
impl<const WORDS: usize> Default for PhaseTable<WORDS> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const WORDS: usize> PhaseTable<WORDS> {
    pub const fn new() -> Self {
        Self { words: [const { AtomicU64::new(0) }; WORDS] }
    }
    /// Whether this page has phase storage, without reading its current phase.
    pub const fn contains_page(&self, page: usize) -> bool {
        page / 32 < self.words.len()
    }
    pub fn get(&self, page: usize) -> Option<Phase> {
        let word = self.words.get(page / 32)?.load(Ordering::Acquire);
        Some(match (word >> (page % 32 * 2)) & 3 {
            0 => Phase::StableWritable,
            2 => Phase::StableSealed,
            // Reserved/corrupted encoding is never treated as writable or RX.
            _ => Phase::Transition,
        })
    }
    pub fn set(&self, page: usize, phase: Phase) -> Result<(), Error> {
        let word = self.words.get(page / 32).ok_or(Error::Address)?;
        let shift = page % 32 * 2;
        word.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
            Some((old & !(3 << shift)) | ((phase as u64) << shift))
        }).expect("unconditional phase update");
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Pages {
    start: u64,
    end: u64,
}
impl Pages {
    pub fn new(start: u64, bytes: usize, limit: u64) -> Result<Self, Error> {
        let end = start.checked_add(bytes as u64).ok_or(Error::Address)?;
        if start == 0 || !start.is_multiple_of(PAGE_BYTES) || bytes == 0
            || !(bytes as u64).is_multiple_of(PAGE_BYTES) || end > limit
        {
            return Err(Error::Address);
        }
        Ok(Self { start, end })
    }
    pub fn iter(self) -> impl Iterator<Item = u64> {
        (self.start..self.end).step_by(PAGE_BYTES as usize)
    }
}

pub trait Backend {
    fn phase(&self, physical: u64) -> Phase;
    /// The prevalidated range must fit the board's phase table. Recording a
    /// phase is infallible; it never performs or substitutes for a hardware fence.
    fn record(&mut self, physical: u64, phase: Phase);
    fn aliases(&self, physical: u64) -> (u64, u64); // total, writable
    fn set_writable(&mut self, physical: u64, writable: bool) -> Result<(), Error>;
    fn synchronize(&mut self) -> Result<(), Error>;
}

/// The caller owns the frames, stopped all users, and holds the alias writer
/// lock through this operation. A failure preserves Transition for the entire
/// range; callers must neither publish it nor infer writable zeroing permission.
pub fn seal(pages: Pages, backend: &mut impl Backend) -> Result<(), Error> {
    for page in pages.iter() {
        if backend.aliases(page).1 != 0 {
            return Err(Error::Permissions);
        }
    }
    if pages.iter().all(|page| backend.phase(page) == Phase::StableSealed) {
        return Ok(());
    }
    for page in pages.iter() {
        backend.record(page, Phase::Transition);
    }
    for page in pages.iter() {
        backend.set_writable(page, false)?;
    }
    backend.synchronize()?;
    for page in pages.iter() {
        backend.record(page, Phase::StableSealed);
    }
    Ok(())
}

/// No old alias may remain. First prove old execution translations retired,
/// then grant direct-map write access, then prove the new permissions visible.
/// Both fences are mandatory; retrying a Transition repeats the full protocol.
pub fn unseal(pages: Pages, backend: &mut impl Backend) -> Result<(), Error> {
    for page in pages.iter() {
        if backend.aliases(page).0 != 0 {
            return Err(Error::Active);
        }
    }
    if pages.iter().all(|page| backend.phase(page) == Phase::StableWritable) {
        return Ok(());
    }
    for page in pages.iter() {
        backend.record(page, Phase::Transition);
    }
    backend.synchronize()?;
    for page in pages.iter() {
        backend.set_writable(page, true)?;
    }
    backend.synchronize()?;
    for page in pages.iter() {
        backend.record(page, Phase::StableWritable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    struct Hardware {
        phases: [Phase; 3],
        pte_write: [bool; 3],
        local_write: [bool; 3],
        peer_write: [bool; 3],
        aliases: [(u64, u64); 3],
        call: usize,
        fail: Option<usize>,
        events: Vec<(char, usize)>,
    }
    impl Hardware {
        fn new(phase: Phase) -> Self {
            let writable = phase == Phase::StableWritable;
            Self { phases: [phase; 3], pte_write: [writable; 3],
                   local_write: [writable; 3], peer_write: [writable; 3],
                   aliases: [(0, 0); 3], call: 0, fail: None, events: Vec::new() }
        }
        fn operation(&mut self) -> Result<(), Error> {
            self.call += 1;
            if self.fail == Some(self.call) { Err(Error::Timeout) } else { Ok(()) }
        }
        fn zero_eligible(&self) -> bool {
            self.phases.iter().all(|p| *p == Phase::StableWritable)
                && self.local_write.iter().all(|p| *p)
                && self.peer_write.iter().all(|p| *p)
        }
    }
    fn index(page: u64) -> usize { (page / PAGE_BYTES - 1) as usize }
    fn pages() -> Pages { Pages::new(PAGE_BYTES, 3 * PAGE_BYTES as usize, 4 * PAGE_BYTES).unwrap() }
    impl Backend for Hardware {
        fn phase(&self, physical: u64) -> Phase { self.phases[index(physical)] }
        fn record(&mut self, physical: u64, phase: Phase) { self.phases[index(physical)] = phase; }
        fn aliases(&self, physical: u64) -> (u64, u64) { self.aliases[index(physical)] }
        fn set_writable(&mut self, physical: u64, writable: bool) -> Result<(), Error> {
            self.events.push((if writable { 'W' } else { 'R' }, index(physical)));
            self.operation()?;
            self.pte_write[index(physical)] = writable;
            Ok(())
        }
        fn synchronize(&mut self) -> Result<(), Error> {
            self.events.push(('F', 0));
            // Actual synchronize_tlb flushes the local CR3 before an IPI or
            // remote-ACK error. A failed fence cannot certify the peers.
            self.local_write = self.pte_write;
            self.operation()?;
            self.peer_write = self.pte_write;
            Ok(())
        }
    }

    #[test]
    fn packed_states_boundaries_and_invalid_encoding_fail_closed() {
        let table = PhaseTable::<2>::new();
        for page in [0, 31, 32, 63] {
            for phase in [Phase::Transition, Phase::StableSealed, Phase::StableWritable] {
                table.set(page, phase).unwrap();
                assert_eq!(table.get(page), Some(phase));
            }
        }
        assert_eq!(table.get(64), None);
        assert_eq!(table.set(64, Phase::StableSealed), Err(Error::Address));
        table.words[0].store(3, Ordering::Release);
        assert_eq!(table.get(0), Some(Phase::Transition));
        assert_eq!(table.get(1), Some(Phase::StableWritable));
    }

    #[test]
    fn invalid_ranges_are_rejected_before_any_transaction() {
        for (start, bytes, limit) in [(0, 4096, 8192), (4097, 4096, 16384),
                (4096, 0, 8192), (4096, 4097, 16384), (4096, 8192, 8192),
                (u64::MAX - 4095, 4096, u64::MAX)] {
            assert!(Pages::new(start, bytes, limit).is_err());
        }
    }

    #[test]
    fn transition_blocks_new_aliases_but_allows_old_alias_removal() {
        for phase in [Phase::StableWritable, Phase::Transition, Phase::StableSealed] {
            assert!(phase.permits_mapping(0));
            assert!(!phase.permits_mapping(7));
            assert!(!phase.permits_mapping(8));
        }
        for flags in [1, 3, 5] { assert!(!Phase::Transition.permits_mapping(flags)); }
        assert!(Phase::StableWritable.permits_mapping(3));
        assert!(!Phase::StableWritable.permits_mapping(5));
        assert!(Phase::StableSealed.permits_mapping(5));
        assert!(!Phase::StableSealed.permits_mapping(3));
    }

    #[test]
    fn full_range_alias_preflight_precedes_every_mutation() {
        let mut hw = Hardware::new(Phase::StableWritable);
        hw.aliases[2] = (1, 1);
        assert_eq!(seal(pages(), &mut hw), Err(Error::Permissions));
        assert!(hw.events.is_empty());
        assert_eq!(hw.phases, [Phase::StableWritable; 3]);
        let mut hw = Hardware::new(Phase::StableSealed);
        hw.aliases[2] = (1, 0);
        assert_eq!(unseal(pages(), &mut hw), Err(Error::Active));
        assert!(hw.events.is_empty());
        assert_eq!(hw.phases, [Phase::StableSealed; 3]);
    }

    #[test]
    fn every_seal_failure_remains_quarantined_and_can_retry() {
        for fail in 1..=4 { // Each of three PTE writes and the real fence.
            let mut hw = Hardware::new(Phase::StableWritable);
            hw.fail = Some(fail);
            assert_eq!(seal(pages(), &mut hw), Err(Error::Timeout));
            assert_eq!(hw.phases, [Phase::Transition; 3]);
            assert!(!hw.zero_eligible());
            assert!(hw.phases.iter().all(|p| !p.permits_mapping(5) && !p.permits_mapping(3)));
            hw.fail = None;
            seal(pages(), &mut hw).unwrap();
            assert_eq!(hw.phases, [Phase::StableSealed; 3]);
            assert_eq!(hw.local_write, [false; 3]);
            assert_eq!(hw.peer_write, [false; 3]);
        }
    }

    #[test]
    fn failed_seal_requires_real_writable_recovery_before_zero() {
        let mut hw = Hardware::new(Phase::StableWritable);
        hw.fail = Some(4);
        assert_eq!(seal(pages(), &mut hw), Err(Error::Timeout));
        assert_eq!(hw.local_write, [false; 3]);
        assert_eq!(hw.peer_write, [true; 3]);
        assert!(!hw.zero_eligible());
        hw.fail = None;
        let before = hw.events.len();
        unseal(pages(), &mut hw).unwrap();
        assert_eq!(&hw.events[before..], &[('F', 0), ('W', 0), ('W', 1), ('W', 2), ('F', 0)]);
        assert!(hw.zero_eligible());
    }

    #[test]
    fn every_unseal_failure_blocks_rx_and_zero_until_complete_retry() {
        for fail in 1..=5 { // Retirement fence, three PTEs, publication fence.
            let mut hw = Hardware::new(Phase::StableSealed);
            hw.fail = Some(fail);
            assert_eq!(unseal(pages(), &mut hw), Err(Error::Timeout));
            assert_eq!(hw.phases, [Phase::Transition; 3]);
            assert!(!hw.zero_eligible());
            assert!(hw.phases.iter().all(|p| !p.permits_mapping(5) && !p.permits_mapping(3)));
            hw.fail = None;
            unseal(pages(), &mut hw).unwrap();
            assert!(hw.zero_eligible());
        }
    }

    #[test]
    fn failed_final_writable_fence_can_reseal_without_exposing_wx() {
        let mut hw = Hardware::new(Phase::StableSealed);
        hw.fail = Some(5);
        assert_eq!(unseal(pages(), &mut hw), Err(Error::Timeout));
        assert_eq!(hw.pte_write, [true; 3]);
        assert!(!hw.phases[0].permits_mapping(5));
        hw.fail = None;
        seal(pages(), &mut hw).unwrap();
        assert_eq!(hw.phases, [Phase::StableSealed; 3]);
        assert_eq!(hw.pte_write, [false; 3]);
        assert_eq!(hw.peer_write, [false; 3]);
    }

    #[test]
    fn cache_hit_requires_every_page_to_be_stable() {
        let mut hw = Hardware::new(Phase::StableSealed);
        seal(pages(), &mut hw).unwrap();
        assert_eq!(hw.call, 0);
        hw.phases[2] = Phase::Transition;
        hw.pte_write[2] = true;
        hw.peer_write[2] = true;
        seal(pages(), &mut hw).unwrap();
        assert_eq!(hw.call, 4);
        assert_eq!(hw.peer_write, [false; 3]);
        unseal(pages(), &mut hw).unwrap();
        let calls = hw.call;
        unseal(pages(), &mut hw).unwrap();
        assert_eq!(hw.call, calls);
    }
}
