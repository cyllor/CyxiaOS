//! Bounded custody of completed, origin-CPU-validated native segments.
//! Each slot owns the original producer lease, never a reconstructed interval.
use super::*;
use core::{
    mem::{MaybeUninit, size_of},
    sync::atomic::AtomicU8,
};

pub(super) const CAPACITY: usize = 16;
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;
const READING: u8 = 3;
struct Slot {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<OwnerAttempt>>,
}
// A slot's state transfers exclusive ownership even across an IRQ nesting
// point. No borrowed reference to its private token escapes the claimed slot.
unsafe impl Sync for Slot {}
static SLOTS: [Slot; CAPACITY] = [const {
    Slot {
        state: AtomicU8::new(EMPTY),
        value: UnsafeCell::new(MaybeUninit::uninit()),
    }
}; CAPACITY];
static CURSOR: AtomicUsize = AtomicUsize::new(0);
static DRAINING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
#[repr(u64)]
pub(super) enum Loss {
    Unfinished = 1,
    CollectorBusy,
    ClassifierUnknown,
    PeerBusy,
    InvalidCompletion,
    UnknownSource,
    Excluded,
    Detached,
    Full,
    Other,
}
/// First actual loss: 0 seqlock, 1 magic, 2 total losses, 3 generation,
/// 4/5 original owner, 6 class, 7 actual core, 8 reason, 9/10 retained
/// start/end, 11 observed time, 12 measured-present, 13 origin-validated,
/// 14 attempt mode, 15 ingress word. Words 16..25 count reasons 1..10;
/// 26 retained, 27 drained, 28 current retained slots, 29/30/31 collector /
/// classifier / peer temporary replies. Capacity is exactly 16. The first
/// record is immutable; independent counters may advance after that record.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 32]);
#[unsafe(no_mangle)]
pub static REPLAY_CAPTURE_EVIDENCE: Evidence = Evidence([const { AtomicU64::new(0) }; 32]);
pub(super) const OWNED_BYTES: usize = size_of::<[Slot; CAPACITY]>()
    + size_of::<AtomicUsize>()
    + size_of::<AtomicBool>()
    + size_of::<Evidence>();
const _: () = assert!(size_of::<Evidence>() == 256);

fn counter(index: usize) {
    REPLAY_CAPTURE_EVIDENCE.0[index].fetch_add(1, Ordering::AcqRel);
}
pub(super) fn temporary(reason: Retry) {
    counter(match reason {
        Retry::Collector => 29,
        Retry::Classifier => 30,
        Retry::Peer => 31,
    });
}
pub(super) fn loss(reason: Loss, attempt: &OwnerAttempt) {
    let bank = &REPLAY_CAPTURE_EVIDENCE.0;
    counter(2);
    counter(15 + reason as usize);
    if bank[0]
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let (first, last) = attempt.measured.unwrap_or((0, 0));
    for (index, value) in [
        (1, 0x4359_4341_5054_3133),
        (3, attempt.generation),
        (4, attempt.owner.id),
        (5, attempt.owner.generation),
        (6, attempt.class as u64),
        (7, u64::from(attempt.core)),
        (8, reason as u64),
        (9, first),
        (10, last),
        (11, now_ns()),
        (12, u64::from(attempt.measured.is_some())),
        (13, u64::from(attempt.validated)),
        (14, attempt.mode as u64),
        (15, INGRESS.load(Ordering::Acquire)),
    ] {
        bank[index].store(value, Ordering::Relaxed);
    }
    bank[0].store(2, Ordering::Release);
}

/// Claim a cell before moving anything. A full bank leaves the original
/// intact so its real loss is accounted exactly once, without recursion.
pub(super) fn retain(original: &mut OwnerAttempt) -> bool {
    debug_assert!(original.pending && original.validated && original.retry.is_some());
    for slot in &SLOTS {
        if slot
            .state
            .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        let retained = OwnerAttempt {
            lease: original.lease.take(),
            owner: original.owner,
            class: original.class,
            generation: original.generation,
            core: original.core,
            measured: original.measured,
            validated: original.validated,
            invalid: original.invalid,
            retry: original.retry.take(),
            resolved: original.resolved,
            outside: original.outside,
            source_checked: original.source_checked,
            mode: original.mode,
            pending: true,
            #[cfg(not(test))]
            peer: original.peer.take(),
        };
        original.pending = false;
        unsafe {
            (*slot.value.get()).write(retained);
        }
        counter(26);
        counter(28);
        slot.state.store(READY, Ordering::Release);
        return true;
    }
    false
}
pub(super) fn pending() -> bool {
    SLOTS
        .iter()
        .any(|slot| slot.state.load(Ordering::Acquire) != EMPTY)
}
/// Existing paid owner turns perform at most `limit` attempts. There is no
/// spinning, heap allocation, timestamp refresh or recursive drain.
pub(super) fn drain(limit: usize) -> bool {
    if DRAINING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return !pending();
    }
    struct DrainGuard;
    impl Drop for DrainGuard {
        fn drop(&mut self) {
            DRAINING.store(false, Ordering::Release);
        }
    }
    let _guard = DrainGuard;
    let start = CURSOR.fetch_add(1, Ordering::Relaxed) % CAPACITY;
    let mut attempted = 0;
    for offset in 0..CAPACITY {
        if attempted == limit {
            break;
        }
        let slot = &SLOTS[(start + offset) % CAPACITY];
        if slot
            .state
            .compare_exchange(READY, READING, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        attempted += 1;
        let mut value = unsafe { (*slot.value.get()).assume_init_read() };
        let (first, last) = value.measured.expect("retained native exit has real times");
        let result = finish_attempt(&mut value, first, last);
        if result == Err(Error::Busy) && value.pending && value.validated && value.retry.is_some() {
            unsafe {
                (*slot.value.get()).write(value);
            }
            slot.state.store(READY, Ordering::Release);
        } else {
            value.retry = None;
            drop(value);
            counter(27);
            REPLAY_CAPTURE_EVIDENCE.0[28].fetch_sub(1, Ordering::AcqRel);
            slot.state.store(EMPTY, Ordering::Release);
        }
    }
    !pending()
}
#[cfg(test)]
pub(super) fn snapshot() -> [u64; 32] {
    core::array::from_fn(|i| REPLAY_CAPTURE_EVIDENCE.0[i].load(Ordering::Acquire))
}
