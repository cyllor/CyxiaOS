//! Fixed protected last-operation diagnostics. No payload bytes or verdicts.
//!
//! Header: magic/version/sequence/reserved/errors, then reserved words.
//! Rows 8..24 and 24..40 retain current and previous completed operations:
//! sequence/start_tick/end_tick/state followed by twelve ABI result fields.
//! Word 63 is a publication seqlock. This diagnostic bank cannot prove a full
//! trace or durable acceptance and never substitutes for the A10 capture.
//! Words 40..46 retain credit attempts: count/tick/owner/generation/status/error.
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(64))]
pub struct Capture {
    pub words: [u64; 63],
    pub publication: AtomicU64,
}
const _: () = assert!(core::mem::size_of::<Capture>() == 512);

impl Capture {
    pub const fn new() -> Self {
        let mut words = [0; 63];
        words[0] = 0x4359_4649_4c45_4431;
        words[1] = 1;
        Self {
            words,
            publication: AtomicU64::new(0),
        }
    }

    fn error(&mut self) {
        self.publication.fetch_add(1, Ordering::AcqRel);
        self.words[4] = self.words[4].saturating_add(1);
        self.publication.fetch_add(1, Ordering::Release);
    }

    pub fn credit_attempt(
        &mut self,
        now: u64,
        owner: u64,
        generation: u64,
        status: u64,
        error: u64,
    ) {
        self.publication.fetch_add(1, Ordering::AcqRel);
        let count = self.words[40].saturating_add(1);
        self.words[40..46].copy_from_slice(&[count, now, owner, generation, status, error]);
        self.publication.fetch_add(1, Ordering::Release);
    }

    pub fn begin(&mut self, now: u64, fields: &[u64; 12]) -> Option<u64> {
        let Some(sequence) = self.words[2].checked_add(1) else {
            self.error();
            return None;
        };
        if self.words[11] == 1 || now < self.words[10] {
            self.error();
            return None;
        }
        self.publication.fetch_add(1, Ordering::AcqRel);
        if self.words[11] == 2 {
            self.words.copy_within(8..24, 24);
        }
        self.words[2] = sequence;
        self.words[8..12].copy_from_slice(&[sequence, now, 0, 1]);
        self.words[12..24].copy_from_slice(fields);
        self.publication.fetch_add(1, Ordering::Release);
        Some(sequence)
    }

    pub fn finish(&mut self, sequence: u64, now: u64, fields: &[u64; 12]) -> bool {
        if sequence != self.words[8]
            || self.words[11] != 1
            || now < self.words[9]
            || self.words[12..16] != fields[..4]
        {
            self.error();
            return false;
        }
        self.publication.fetch_add(1, Ordering::AcqRel);
        self.words[10] = now;
        self.words[12..24].copy_from_slice(fields);
        self.words[11] = 2;
        self.publication.fetch_add(1, Ordering::Release);
        true
    }
}
