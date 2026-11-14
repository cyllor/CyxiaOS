//! CPU0-only stopped-snapshot diagnostics, written inside paid owner pieces.
//! This is neither a trace nor an acceptance receipt. No live Rust reader.
//! Words 0/1: magic/version; 2: paid phases; 3..14: per-phase counts;
//! 14: vector observations; 15: observed ns; 16/17: task; 18: vector id;
//! 19/20: original vector start/deadline; 21/22: needed/ready leases;
//! 23/24: lease/step error + 1 (zero means no error);
//! 25/26: item/pending counts; 27..30: cumulative service statistics
//! (items, IPC calls, completed, errors); 31: current batch policy.
//! Word 63 is the publication seqlock. Other words are reserved.
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(64))]
struct Capture {
    words: [u64; 63],
    publication: AtomicU64,
}
const _: () = assert!(core::mem::size_of::<Capture>() == 512);

#[used]
#[unsafe(no_mangle)]
static mut TASK_VECTOR_EVIDENCE: Capture = Capture {
    words: {
        let mut words = [0; 63];
        words[0] = 0x4359_5645_4354_5231;
        words[1] = 1;
        words
    },
    publication: AtomicU64::new(0),
};

pub(super) fn phase(phase: u8) {
    let phase = usize::from(phase);
    debug_assert_eq!(super::cpu::slot(), 0);
    debug_assert!(phase < 11);
    // Only the CPU0 service pump calls these functions, without reentry and
    // while holding the task gate. The host reads only a stopped snapshot.
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(TASK_VECTOR_EVIDENCE) };
    capture.publication.fetch_add(1, Ordering::AcqRel);
    capture.words[2] = capture.words[2].saturating_add(1);
    capture.words[3 + phase] = capture.words[3 + phase].saturating_add(1);
    capture.publication.fetch_add(1, Ordering::Release);
}

pub(super) fn vector(fields: [u64; 17]) {
    debug_assert_eq!(super::cpu::slot(), 0);
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(TASK_VECTOR_EVIDENCE) };
    capture.publication.fetch_add(1, Ordering::AcqRel);
    capture.words[14] = capture.words[14].saturating_add(1);
    capture.words[15..32].copy_from_slice(&fields);
    capture.publication.fetch_add(1, Ordering::Release);
}
