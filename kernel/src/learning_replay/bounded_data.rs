//! Bounded observational custody ledger. Only real native writer/owner events
//! feed these transitions; this module has no replay/label authority.
use cyxia_prototype::domains::Error;
pub const MAX_ATTEMPTS: usize = 6;
pub const ROW_WORDS: usize = 56;
pub const SUPPLEMENT_BYTES: usize = 4096;
pub const EVIDENCE_BYTES: usize = 8192;
pub const MAGIC: u64 = 0x4359_4244_4154_3136;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference {
    pub key: [u64; 3],
    pub object: [u64; 2],
    pub offset: u64,
    pub bytes: u64,
    pub digest: [u8; 32],
}
impl Reference {
    pub fn words(self) -> [u64; 12] {
        let mut w = [0; 12];
        w[..3].copy_from_slice(&self.key);
        w[3..5].copy_from_slice(&self.object);
        w[5] = self.offset;
        w[6] = self.bytes;
        for (i, c) in self.digest.chunks_exact(8).enumerate() {
            w[7 + i] = u64::from_le_bytes(c.try_into().unwrap());
        }
        w
    }
    fn valid(self) -> bool {
        self.key[0] != 0
            && self.key[1] != 0
            && self.object[0] != 0
            && self.object[1] != 0
            && self.bytes != 0
            && self.offset.checked_add(self.bytes).is_some()
            && self.digest != [0; 32]
    }
    fn from_words(w: &[u64]) -> Self {
        let mut digest = [0; 32];
        for (i, v) in w[7..11].iter().enumerate() {
            digest[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
        }
        Self {
            key: [w[0], w[1], w[2]],
            object: [w[3], w[4]],
            offset: w[5],
            bytes: w[6],
            digest,
        }
    }
}
#[derive(Clone, Copy)]
#[repr(u64)]
pub enum Release {
    Work = 1,
    Root = 2,
    Permit = 4,
    Capture = 8,
    History = 16,
}
pub fn is_hard(error: Error) -> bool {
    !matches!(
        error,
        Error::Busy | Error::Again | Error::NotReady | Error::Expired
    )
}
/// First incoming hard fault survives a failed owner try-lock. A partially
/// published latch blocks protected transitions until its original operands exist.
pub struct HardPending([core::sync::atomic::AtomicU64; 3]);
impl HardPending {
    pub const fn new() -> Self {
        Self([const { core::sync::atomic::AtomicU64::new(0) }; 3])
    }
    pub fn record(&self, error: Error, observed: u64) {
        use core::sync::atomic::Ordering;
        if !is_hard(error)
            || self.0[0]
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        self.0[1].store(error as u64 + 1, Ordering::Relaxed);
        self.0[2].store(observed, Ordering::Relaxed);
        self.0[0].store(2, Ordering::Release);
    }
    pub fn snapshot(&self) -> Result<Option<(u64, u64)>, Error> {
        use core::sync::atomic::Ordering;
        match self.0[0].load(Ordering::Acquire) {
            0 => Ok(None),
            2 => Ok(Some((
                self.0[1].load(Ordering::Relaxed),
                self.0[2].load(Ordering::Relaxed),
            ))),
            _ => Err(Error::Busy),
        }
    }
}
pub struct Ledger {
    rows: [[u64; ROW_WORDS]; MAX_ATTEMPTS],
    count: usize,
    stored: bool,
    selected: [u64; 2],
    valid_selection: bool,
    hard_stop: [u64; 4],
}
impl Ledger {
    pub const fn new() -> Self {
        Self {
            rows: [[0; ROW_WORDS]; MAX_ATTEMPTS],
            count: 0,
            stored: false,
            selected: [0; 2],
            valid_selection: false,
            hard_stop: [0; 4],
        }
    }
    pub fn last_trial(&self) -> u64 {
        self.count.checked_sub(1).map_or(0, |i| self.rows[i][0])
    }
    pub fn hard_stop(&self) -> [u64; 4] {
        self.hard_stop
    }
    pub fn observe_incoming(
        &mut self,
        trial: u64,
        error: Error,
        observed: u64,
        phase: u64,
    ) -> Result<(), Error> {
        if !is_hard(error) {
            return Ok(());
        }
        self.observe_hard_code(trial, error as u64 + 1, observed, phase)
    }
    pub fn observe_hard_code(
        &mut self,
        trial: u64,
        code: u64,
        observed: u64,
        phase: u64,
    ) -> Result<(), Error> {
        let i = self.index(trial)?;
        if !(1..=20).contains(&code) || matches!(code, 8 | 10 | 11 | 20) || observed == 0 {
            return Err(Error::Range);
        }
        if self.rows[i][55] == 0 {
            self.rows[i][55] = code;
        }
        if self.hard_stop[0] == 0 {
            self.hard_stop = [
                trial,
                code,
                observed,
                phase | (u64::from(self.stored) << 63),
            ];
        }
        Ok(())
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn stored(&self) -> bool {
        self.stored
    }
    pub fn may_continue(&self) -> bool {
        !self.stored && self.count < MAX_ATTEMPTS && self.retryable()
    }
    pub fn can_admit(&self) -> bool {
        !self.stored
            && self.retryable()
            && self.count < MAX_ATTEMPTS
            && self.rows[..self.count].iter().all(|r| {
                r[11] == 1 || (r[7] == 2 && r[8] == 29 && r[9] == 31 && r[16] != 0 && r[52] != 0)
            })
    }
    pub fn exhausted(&self) -> bool {
        !self.stored && self.count == MAX_ATTEMPTS
    }
    pub fn row(&self, i: usize) -> &[u64; ROW_WORDS] {
        &self.rows[i]
    }
    fn index(&self, trial: u64) -> Result<usize, Error> {
        self.rows[..self.count]
            .iter()
            .position(|r| r[0] == trial)
            .ok_or(Error::Stale)
    }
    pub fn admit(
        &mut self,
        trial: u64,
        prep: u64,
        boot: u64,
        kind: u64,
        started: u64,
    ) -> Result<(), Error> {
        if !self.can_admit() {
            return Err(Error::Capacity);
        }
        if trial == 0
            || prep == 0
            || boot == 0
            || started == 0
            || !matches!(kind, 1 | 2)
            || self.rows[..self.count]
                .iter()
                .any(|r| r[0] >= trial || r[1] == prep || r[2] != boot)
        {
            return Err(Error::Stale);
        }
        let r = &mut self.rows[self.count];
        r[0] = trial;
        r[1] = prep;
        r[2] = boot;
        r[3] = kind;
        r[9] = 7;
        r[53] = started;
        self.count += 1;
        Ok(())
    }
    pub fn root(&mut self, trial: u64, token: u64) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if token == 0 || r[52] != 0 && r[52] != token {
            return Err(Error::Stale);
        }
        r[52] = token;
        Ok(())
    }
    pub fn capture(&mut self, trial: u64, generation: u64) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if generation == 0 || r[4] != 0 && r[4] != generation {
            return Err(Error::Stale);
        }
        r[4] = generation;
        r[9] = 31;
        Ok(())
    }
    pub fn error(&mut self, trial: u64, domain: u64, failed: u64) -> Result<(), Error> {
        let i = self.index(trial)?;
        if self.stored && matches!(self.rows[i][7], 3 | 4) {
            return Ok(());
        }
        let r = &mut self.rows[i];
        if domain == 0 || failed == 0 {
            return Err(Error::Range);
        }
        if r[5] != 0 {
            return if r[5] == domain {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        r[5] = domain;
        r[54] = failed;
        Ok(())
    }
    pub fn excluded(&mut self, trial: u64, learning: u64) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if learning == 0 || r[6] != 0 && r[6] != learning {
            return Err(Error::Conflict);
        }
        r[6] = learning;
        r[7] = 1;
        Ok(())
    }
    pub fn verified(&mut self, trial: u64, hash: [u8; 32]) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if hash == [0; 32] || r[6] != 0 {
            return Err(Error::Conflict);
        }
        for (j, c) in hash.chunks_exact(8).enumerate() {
            let v = u64::from_le_bytes(c.try_into().unwrap());
            if r[12 + j] != 0 && r[12 + j] != v {
                return Err(Error::Conflict);
            }
            r[12 + j] = v;
        }
        if !matches!(r[7], 3 | 4) {
            r[7] = if r[3] == 2 { 2 } else { 0 };
        }
        Ok(())
    }
    pub fn journal(&mut self, trial: u64, kind: usize, reference: Reference) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if kind > 2
            || !reference.valid()
            || reference.key[..2] != [r[2], trial]
            || kind == 1 && reference.key[2] != 0
            || kind != 1 && reference.key[2] != r[4]
            || kind == 0 && r[28] != 0
            || kind == 1 && r[16] != 0
        {
            return Err(Error::Conflict);
        }
        let at = 16 + kind * 12;
        let w = reference.words();
        if r[at] != 0 {
            return if r[at..at + 12] == w {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        r[at..at + 12].copy_from_slice(&w);
        r[10] += 1;
        Self::refresh(r);
        Ok(())
    }
    fn refresh(r: &mut [u64; ROW_WORDS]) {
        r[11] = u64::from(r[8] & r[9] == r[9] && r[10] > 0 && (r[16] != 0 || r[28] != 0));
    }
    pub fn release(&mut self, trial: u64, release: Release) -> Result<(), Error> {
        let i = self.index(trial)?;
        let r = &mut self.rows[i];
        if r[9] & (release as u64) == 0 {
            return Err(Error::Conflict);
        }
        r[8] |= release as u64;
        Self::refresh(r);
        Ok(())
    }
    /// Real Root release closes the retained baseline chain, not a synthetic
    /// per-attempt physical-credit acknowledgement.
    pub fn release_root_chain(&mut self) {
        for r in &mut self.rows[..self.count] {
            r[8] |= Release::Root as u64;
            Self::refresh(r);
        }
    }
    pub fn references_closed(&self) -> bool {
        self.count > 0 && self.rows[..self.count].iter().all(|r| r[11] == 1)
    }
    pub fn closed(&self) -> usize {
        self.rows[..self.count]
            .iter()
            .filter(|r| r[11] == 1)
            .count()
    }
    pub fn journals(&self) -> usize {
        self.rows[..self.count].iter().map(|r| r[10] as usize).sum()
    }
    pub fn retryable(&self) -> bool {
        self.hard_stop[0] == 0
            && self.rows[..self.count].iter().all(|r| {
                matches!(r[5], 0 | 8 | 10 | 11 | 20)
                    && matches!(r[6], 0 | 7 | 16 | 17)
                    && (r[7] != 1 || r[6] != 0)
            })
    }
    pub fn supersede(&mut self) -> Result<(), Error> {
        if self.stored {
            return Err(Error::Conflict);
        }
        for r in &mut self.rows[..self.count] {
            if r[7] == 2 {
                r[7] = 5;
            }
        }
        Ok(())
    }
    /// Called immediately after actual accept/store. Latch first, even on a
    /// contradictory downstream observation, so no later error can admit trials.
    pub fn store(&mut self, w: &[u8; 1024]) -> Result<(), Error> {
        if self.stored || self.hard_stop[0] != 0 {
            return Err(Error::Conflict);
        }
        self.stored = true;
        let b = u64::from_le_bytes(w[32..40].try_into().unwrap());
        let c = u64::from_le_bytes(w[40..48].try_into().unwrap());
        self.selected = [b, c];
        let bi = self.index(b)?;
        let ci = self.index(c)?;
        if bi == ci
            || self.rows[bi][3] != 2
            || self.rows[ci][3] != 1
            || self.rows[bi][7] != 2
            || self.rows[ci][6] != 0
            || self.rows[bi][5] != 0
            || self.rows[ci][5] != 0
        {
            return Err(Error::Conflict);
        }
        for (i, hash) in [(bi, &w[48..80]), (ci, &w[80..112])] {
            for (j, chunk) in hash.chunks_exact(8).enumerate() {
                if self.rows[i][12 + j] != u64::from_le_bytes(chunk.try_into().unwrap()) {
                    return Err(Error::Conflict);
                }
            }
        }
        self.rows[bi][7] = 3;
        self.rows[ci][7] = 4;
        self.valid_selection = true;
        Ok(())
    }
    pub fn selected_trials(&self) -> [u64; 2] {
        self.selected
    }
    pub fn selected(&self) -> Result<[Reference; 2], Error> {
        if !self.stored || !self.valid_selection {
            return Err(Error::NotReady);
        }
        let mut out = [Reference {
            key: [0; 3],
            object: [0; 2],
            offset: 0,
            bytes: 0,
            digest: [0; 32],
        }; 2];
        for (i, t) in self.selected.iter().enumerate() {
            let r = &self.rows[self.index(*t)?];
            if r[16] == 0 || r[6] != 0 || r[5] != 0 || r[40] != 0 {
                return Err(Error::NotReady);
            }
            out[i] = Reference::from_words(&r[16..28]);
        }
        Ok(out)
    }
    pub fn snapshot_current(&self, bytes: &[u8; SUPPLEMENT_BYTES]) -> bool {
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()) == 2
            && (0..4).all(|i| {
                u64::from_le_bytes(bytes[4064 + 8 * i..4072 + 8 * i].try_into().unwrap())
                    == self.hard_stop[i]
            })
    }
    pub fn supplement(
        &self,
        witness: Option<&[u8; 1024]>,
        counters: [u64; 3],
        ticket: u64,
        ack: bool,
    ) -> Result<[u8; SUPPLEMENT_BYTES], Error> {
        if !self.references_closed() || ticket == 0 || !ack || self.stored != witness.is_some() {
            return Err(Error::NotReady);
        }
        let selected = if self.stored {
            Some(self.selected()?)
        } else {
            None
        };
        let mut words = [0u64; SUPPLEMENT_BYTES / 8];
        words[..15].copy_from_slice(&[
            MAGIC,
            2,
            2,
            self.count as u64,
            6,
            u64::from(self.stored),
            self.selected[0],
            self.selected[1],
            self.closed() as u64,
            counters[0],
            counters[1],
            counters[2],
            ticket,
            1,
            u64::from(self.stored),
        ]);
        self.rows_words(&mut words[16..352]);
        words[508..512].copy_from_slice(&self.hard_stop);
        let mut bytes = [0; SUPPLEMENT_BYTES];
        for (i, w) in words.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        if let Some(w) = witness {
            use sha2::{Digest, Sha256};
            bytes[2816..3840].copy_from_slice(w);
            bytes[3840..3872].copy_from_slice(&Sha256::digest(w));
        }
        if let Some(refs) = selected {
            for (i, r) in refs.into_iter().enumerate() {
                for (j, w) in r.words().iter().enumerate() {
                    let at = 3872 + i * 96 + j * 8;
                    bytes[at..at + 8].copy_from_slice(&w.to_le_bytes());
                }
            }
        }
        Ok(bytes)
    }
    pub fn rows_words(&self, out: &mut [u64]) {
        assert_eq!(out.len(), MAX_ATTEMPTS * ROW_WORDS);
        for (i, r) in self.rows.iter().enumerate() {
            out[i * ROW_WORDS..(i + 1) * ROW_WORDS].copy_from_slice(r);
        }
    }
}
const _: () =
    assert!(128 + MAX_ATTEMPTS * ROW_WORDS * 8 + 1024 + 32 + 192 + 32 == SUPPLEMENT_BYTES);

#[cfg(test)]
mod hard_pending_tests {
    use super::*;
    #[test]
    fn pending_hard_fault_survives_owner_lock_failure_and_preserves_first_operands() {
        let pending = HardPending::new();
        assert_eq!(pending.snapshot(), Ok(None));
        pending.record(Error::Busy, 99);
        assert_eq!(pending.snapshot(), Ok(None));
        // There is deliberately no owner gate in this first monotone capture.
        pending.record(Error::Io, 200);
        pending.record(Error::Auth, 201);
        assert_eq!(pending.snapshot(), Ok(Some((18, 200))));
    }
    #[test]
    fn partial_publication_is_busy_and_cannot_be_used_as_no_fault() {
        use core::sync::atomic::Ordering;
        let pending = HardPending::new();
        pending.0[0].store(1, Ordering::Release);
        assert_eq!(pending.snapshot(), Err(Error::Busy));
    }
}
