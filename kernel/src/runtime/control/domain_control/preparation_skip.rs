//! Durable reasons for ordinary preparation turns that stop before encoding.
//!
//! `domain_control::with` owns the sole writer through its `CLAIMED` gate.
//! Each family row is independently release-published so a stopped snapshot
//! retains cumulative reasons even when later preparation turns use another
//! family or CPU.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering, fence},
};
use cyxia_prototype::domains::{Error, ObjectKey};

pub(crate) const FAMILY_CAPACITY: usize = 18;
pub(crate) const REASON_CAPACITY: usize = 16;
const HEADER_WORDS: usize = 8;
const ROW_WORDS: usize = 13;
const BANK_WORDS: usize = 256;
const MAGIC: u64 = 0x4359_5053_4b49_5031;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub(crate) enum Reason {
    TargetAbsent = 1,
    CanaryBlocked = 2,
    ReplayBlocked = 3,
    ReplayFirstRetry = 4,
    ModelGateBlocked = 5,
    SpecialPreparationUnavailable = 6,
    CurrentUnavailable = 7,
    ObservationUnavailable = 8,
    ReplacementBlocked = 9,
    DependencyUnavailable = 10,
    LegalOptionsUnavailable = 11,
    CurrentIllegal = 12,
    ActionReplayFiltered = 13,
    ActionStabilityFiltered = 14,
    TargetFeaturesUnavailable = 15,
    NoCandidate = 16,
}

#[repr(C)]
struct Row {
    // Odd means an update is in progress; nonzero even values are complete.
    publication: AtomicU64,
    // domain, kind, total, last reason, last error, target id, target
    // generation, wall start, then four packed u16 per-reason counters.
    payload: UnsafeCell<[u64; ROW_WORDS - 1]>,
}
unsafe impl Sync for Row {}
impl Row {
    const fn new() -> Self {
        Self {
            publication: AtomicU64::new(0),
            payload: UnsafeCell::new([0; ROW_WORDS - 1]),
        }
    }

    fn load(&self, offset: usize) -> u64 {
        // The global control gate guarantees one writer. Volatile accesses
        // retain the bank in a stopped guest image without atomic RMW helpers.
        unsafe { self.payload.get().cast::<u64>().add(offset).read_volatile() }
    }

    fn store(&self, offset: usize, value: u64) {
        unsafe {
            self.payload
                .get()
                .cast::<u64>()
                .add(offset)
                .write_volatile(value);
        }
    }
}

#[repr(C, align(64))]
struct Evidence {
    header: [u64; HEADER_WORDS],
    rows: [Row; FAMILY_CAPACITY],
    padding: [u64; BANK_WORDS - HEADER_WORDS - FAMILY_CAPACITY * ROW_WORDS],
}
unsafe impl Sync for Evidence {}

#[used]
#[unsafe(no_mangle)]
static DOMAIN_PREPARATION_SKIP_EVIDENCE: Evidence = Evidence {
    header: [
        // magic, schema, row words, family capacity, reason capacity,
        // highest assigned reason code, reserved, reserved
        MAGIC,
        1,
        ROW_WORDS as u64,
        FAMILY_CAPACITY as u64,
        REASON_CAPACITY as u64,
        16,
        0,
        0,
    ],
    rows: [const { Row::new() }; FAMILY_CAPACITY],
    padding: [0; BANK_WORDS - HEADER_WORDS - FAMILY_CAPACITY * ROW_WORDS],
};

const _: () = assert!(core::mem::size_of::<Row>() == ROW_WORDS * 8);
const _: () = assert!(core::mem::size_of::<Evidence>() == BANK_WORDS * 8);

pub(crate) fn record(
    family: usize,
    domain: u16,
    kind: u16,
    target: Option<ObjectKey>,
    wall_started: u64,
    reason: Reason,
    error: Option<Error>,
) {
    let Some(row) = DOMAIN_PREPARATION_SKIP_EVIDENCE.rows.get(family) else {
        return;
    };
    let sequence = row.publication.load(Ordering::Relaxed) & !1;
    let odd = sequence.wrapping_add(1);
    row.publication.store(odd, Ordering::Release);
    fence(Ordering::Release);

    let total = row.load(2).saturating_add(1);
    let reason_index = reason as usize - 1;
    let packed_offset = 8 + reason_index / 4;
    let shift = (reason_index % 4) * 16;
    let packed = row.load(packed_offset);
    let count = ((packed >> shift) & 0xffff) as u16;
    let next_count = count.saturating_add(1);
    let next_packed = (packed & !(0xffff << shift)) | (u64::from(next_count) << shift);
    let target = target.unwrap_or_default();

    for (offset, value) in [
        u64::from(domain),
        u64::from(kind),
        total,
        reason as u64,
        error.map_or(0, error_code),
        target.id,
        target.generation,
        wall_started,
    ]
    .into_iter()
    .enumerate()
    {
        row.store(offset, value);
    }
    row.store(packed_offset, next_packed);
    fence(Ordering::Release);
    row.publication
        .store(odd.wrapping_add(1), Ordering::Release);
}

fn error_code(error: Error) -> u64 {
    match error {
        Error::Format => 1,
        Error::Auth => 2,
        Error::Schema => 3,
        Error::Stale => 4,
        Error::Capacity => 5,
        Error::Budget => 6,
        Error::Conflict => 7,
        Error::Expired => 8,
        Error::Unsupported => 9,
        Error::Busy => 10,
        Error::Again => 11,
        Error::NotFound => 12,
        Error::Exists => 13,
        Error::NotDirectory => 14,
        Error::IsDirectory => 15,
        Error::NotEmpty => 16,
        Error::Range => 17,
        Error::Io => 18,
        Error::Overflow => 19,
        Error::NotReady => 20,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words() -> [u64; BANK_WORDS] {
        core::array::from_fn(|index| unsafe {
            core::ptr::addr_of!(DOMAIN_PREPARATION_SKIP_EVIDENCE)
                .cast::<u64>()
                .add(index)
                .read_volatile()
        })
    }

    fn row(words: &[u64; BANK_WORDS], family: usize) -> &[u64] {
        let start = HEADER_WORDS + family * ROW_WORDS;
        &words[start..start + ROW_WORDS]
    }

    #[test]
    fn fixed_layout_describes_the_decoder_contract() {
        let words = words();
        assert_eq!(core::mem::size_of::<Evidence>(), 2048);
        assert_eq!(&words[..8], &[MAGIC, 1, 13, 18, 16, 16, 0, 0]);
    }

    #[test]
    fn latest_reason_and_each_reason_count_survive_later_updates() {
        let target = ObjectKey {
            id: 0x5352_5643,
            generation: 1,
        };
        record(
            8,
            8,
            1,
            Some(target),
            41,
            Reason::ObservationUnavailable,
            Some(Error::NotReady),
        );
        record(
            8,
            8,
            1,
            Some(target),
            42,
            Reason::DependencyUnavailable,
            Some(Error::Conflict),
        );
        record(5, 5, 1, None, 43, Reason::TargetAbsent, None);
        let words = words();
        let d8 = row(&words, 8);
        assert_ne!(d8[0], 0);
        assert_eq!(d8[0] & 1, 0);
        assert_eq!(&d8[1..9], &[8, 1, 2, 10, 7, target.id, 1, 42]);
        assert_eq!((d8[10] >> 48) & 0xffff, 1); // observation reason 8
        assert_eq!((d8[11] >> 16) & 0xffff, 1); // dependency reason 10
        let d5 = row(&words, 5);
        assert_eq!(&d5[1..9], &[5, 1, 1, 1, 0, 0, 0, 43]);
    }

    #[test]
    fn per_reason_counter_saturates_without_wrapping() {
        for _ in 0..=u16::MAX {
            record(7, 7, 1, None, 9, Reason::ReplayBlocked, None);
        }
        let words = words();
        let d7 = row(&words, 7);
        assert_eq!(d7[3], u64::from(u16::MAX) + 1);
        assert_eq!((d7[9] >> 32) & 0xffff, u64::from(u16::MAX));
        assert_eq!(d7[0] & 1, 0);
    }
}
