//! CPU0-only diagnostics for the first observed pending baseline cycle.
//! No payload, authority or acceptance verdict. The host reads stopped banks.
//! Header: magic/version/state(0 idle,1 collecting,2 closed), first/last ns,
//! opportunities, denied, bodies, successes, errors, pending settlements,
//! closed ns, maximum opportunity gap, its start/end ns, invalid-ticket count.
//! First attempt is words16..32; words32..112 retain the last five attempts.
//! Row: sequence, callsite, opportunity/start/end/return ns, result(0 pending,
//! 1 no body,2 Ok(false),3 Ok(true),4 Err), error+1, prior credit kind/pending,
//! body reservation/kind, final credit kind/pending, body CPU ns, failure mask.
//! Version2: words112..127 retain first failures in five categories as triples
//! (ns, attempt, detail): gate, settlement, admission, revalidation, authority.
//! Gate/authority detail: error+1, prior credit kind<<8, pending<<16.
//! Settlement: error+1, retained active<<8, pending<<9, credit kind<<16.
//! Admission/revalidation: reason, error+1<<8, copied scalar context<<16.
//! Word127 is the publication seqlock. It freezes after the first cycle closes.
//! An opportunity may offer two separately billed pieces: the replay body and
//! one bounded queued admission. This ticket, body timings and final credit
//! fields describe only the replay piece and close before admission begins.
use super::Error;
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(64))]
struct Capture {
    words: [u64; 127],
    publication: AtomicU64,
}
const _: () = assert!(core::mem::size_of::<Capture>() == 1024);
#[used]
#[unsafe(no_mangle)]
static mut BASELINE_SERVICE_EVIDENCE: Capture = Capture {
    words: {
        let mut words = [0; 127];
        words[0] = 0x4359_4241_5345_5331;
        words[1] = 2;
        words
    },
    publication: AtomicU64::new(0),
};
// Diagnostic scope only; CPU0 is the sole writer. No mutable bank borrow is
// retained across service_step or another owner call. Current call sites do
// not recursively enter the helper. Other CPUs never mutate this bank.
static CURRENT_ATTEMPT: AtomicU64 = AtomicU64::new(0);

impl Capture {
    fn row(&self, sequence: u64) -> usize {
        32 + ((sequence - 1) % 5) as usize * 16
    }
    fn update(&mut self, sequence: u64, body: impl FnOnce(&mut [u64])) {
        let offset = self.row(sequence);
        self.publication.fetch_add(1, Ordering::AcqRel);
        if self.words[offset] == sequence {
            body(&mut self.words[offset..offset + 16]);
            if sequence == 1 {
                self.words.copy_within(offset..offset + 16, 16);
            }
        } else {
            self.words[15] = self.words[15].saturating_add(1);
        }
        self.publication.fetch_add(1, Ordering::Release);
    }
}
pub(super) fn opportunity(hint: bool, site: u64, kind: u64, pending: bool) -> Option<u64> {
    debug_assert_eq!(super::cpu::slot(), 0);
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_SERVICE_EVIDENCE) };
    if capture.words[2] == 2 || !hint && capture.words[2] == 0 {
        return None;
    }
    let now = super::now_ns();
    capture.publication.fetch_add(1, Ordering::AcqRel);
    if !hint {
        CURRENT_ATTEMPT.store(0, Ordering::Release);
        capture.words[2] = 2;
        capture.words[11] = now;
        capture.publication.fetch_add(1, Ordering::Release);
        return None;
    }
    let sequence = capture.words[5].saturating_add(1);
    if sequence == 1 {
        capture.words[2] = 1;
        capture.words[3] = now;
    } else if now.saturating_sub(capture.words[4]) > capture.words[12] {
        capture.words[12] = now.saturating_sub(capture.words[4]);
        capture.words[13] = capture.words[4];
        capture.words[14] = now;
    }
    capture.words[4] = now;
    capture.words[5] = sequence;
    let offset = capture.row(sequence);
    capture.words[offset..offset + 16].fill(0);
    capture.words[offset..offset + 3].copy_from_slice(&[sequence, site, now]);
    capture.words[offset + 8] = kind;
    capture.words[offset + 9] = u64::from(pending);
    capture.publication.fetch_add(1, Ordering::Release);
    CURRENT_ATTEMPT.store(sequence, Ordering::Release);
    Some(sequence)
}
pub(super) fn failure(category: usize, detail: u64) {
    if super::cpu::slot() != 0 || !(1..=5).contains(&category) {
        return;
    }
    let sequence = CURRENT_ATTEMPT.load(Ordering::Acquire);
    if sequence == 0 {
        return;
    }
    let now = super::now_ns();
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_SERVICE_EVIDENCE) };
    if capture.words[2] != 1 {
        return;
    }
    capture.publication.fetch_add(1, Ordering::AcqRel);
    let offset = capture.row(sequence);
    if capture.words[offset] == sequence {
        capture.words[offset + 15] |= 1 << (category - 1);
        if sequence == 1 {
            capture.words.copy_within(offset..offset + 16, 16);
        }
    } else {
        capture.words[15] = capture.words[15].saturating_add(1);
    }
    let first = 112 + (category - 1) * 3;
    if capture.words[first] == 0 {
        capture.words[first..first + 3].copy_from_slice(&[now, sequence, detail]);
    }
    capture.publication.fetch_add(1, Ordering::Release);
}
pub(super) fn body_start(ticket: Option<u64>, reserved: u64, kind: u64) {
    if let Some(sequence) = ticket {
        let now = super::now_ns();
        let capture = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_SERVICE_EVIDENCE) };
        capture.update(sequence, |row| {
            row[3] = now;
            row[10] = reserved;
            row[11] = kind;
        });
    }
}
pub(super) fn body_finish(ticket: Option<u64>, result: &Result<bool, Error>, cpu_ns: u64) {
    if let Some(sequence) = ticket {
        let now = super::now_ns();
        let capture = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_SERVICE_EVIDENCE) };
        capture.update(sequence, |row| {
            row[4] = now;
            row[6] = match result {
                Ok(false) => 2,
                Ok(true) => 3,
                Err(_) => 4,
            };
            row[7] = result.as_ref().err().map_or(0, |error| *error as u64 + 1);
            row[14] = cpu_ns;
        });
    }
}
pub(super) fn finish(ticket: Option<u64>, entered: bool, kind: u64, pending: bool) {
    if let Some(sequence) = ticket {
        let now = super::now_ns();
        let capture = unsafe { &mut *core::ptr::addr_of_mut!(BASELINE_SERVICE_EVIDENCE) };
        capture.publication.fetch_add(1, Ordering::AcqRel);
        let offset = capture.row(sequence);
        if capture.words[offset] != sequence {
            capture.words[15] = capture.words[15].saturating_add(1);
        } else {
            capture.words[offset + 5] = now;
            if !entered {
                capture.words[offset + 6] = 1;
            }
            capture.words[offset + 12] = kind;
            capture.words[offset + 13] = u64::from(pending);
            if sequence == 1 {
                capture.words.copy_within(offset..offset + 16, 16);
            }
            let result = capture.words[offset + 6];
            let counter = if !entered {
                6
            } else if result == 4 {
                9
            } else {
                8
            };
            capture.words[counter] = capture.words[counter].saturating_add(1);
            if entered {
                capture.words[7] = capture.words[7].saturating_add(1);
            }
            if pending {
                capture.words[10] = capture.words[10].saturating_add(1);
            }
        }
        capture.publication.fetch_add(1, Ordering::Release);
        CURRENT_ATTEMPT.store(0, Ordering::Release);
    }
}
