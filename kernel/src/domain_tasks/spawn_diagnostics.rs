//! Last ordinary client spawn-query result, without input/payload bytes.
//! All writers hold the task gate, including deferred CPU0 syscall handling;
//! the host reads stopped snapshots only. This never authorizes admission.
//! 0 magic; 1 version; 2 queries; 3 observed ns; 4/5 caller; 6 request id;
//! 7 state (0 queued,1 created,2 failed,3 unknown,4 cancelled,5 query error);
//! 8/9 created task or domain error+1/zero. Word31 is the seqlock.
//! Version2 adds first pre-rollback construction failure: word10 latched;
//! 11 time;12 stage;13 error+1;14 request;15/16 caller;17/18 candidate task;
//! 19 deadline;20 stage entry;21 CPU;22 target committed ns;23 thread count;
//! 24 eligible slots;25/26 ordinary/progress free pages;27/28 CPU2/3 committed;
//! 29/30 business/healthy masks. Query updates never replace these facts.
use super::{Error, ObjectKey, SpawnState};
use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(64))]
struct Capture {
    words: [u64; 31],
    publication: AtomicU64,
}
const _: () = assert!(core::mem::size_of::<Capture>() == 256);
#[used]
#[unsafe(no_mangle)]
static mut TASK_SPAWN_EVIDENCE: Capture = Capture {
    words: {
        let mut words = [0; 31];
        words[0] = 0x4359_5350_4157_4e31;
        words[1] = 2;
        words
    },
    publication: AtomicU64::new(0),
};

pub(super) fn construction_failure(fields: [u64; 20]) {
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(TASK_SPAWN_EVIDENCE) };
    if capture.words[10] != 0 {
        return;
    }
    capture.publication.fetch_add(1, Ordering::AcqRel);
    capture.words[11..31].copy_from_slice(&fields);
    capture.words[10] = 1;
    capture.publication.fetch_add(1, Ordering::Release);
}

pub(super) fn query(
    caller: ObjectKey,
    request: u64,
    result: &Result<SpawnState, Error>,
    observed_ns: u64,
) {
    let (state, value, generation) = match *result {
        Ok(SpawnState::Queued) => (0, 0, 0),
        Ok(SpawnState::Created(key)) => (1, key.id, key.generation),
        Ok(SpawnState::Failed(error)) => (2, error as u64 + 1, 0),
        Ok(SpawnState::Unknown) => (3, 0, 0),
        Ok(SpawnState::Cancelled) => (4, 0, 0),
        Err(error) => (5, error as u64 + 1, 0),
    };
    let capture = unsafe { &mut *core::ptr::addr_of_mut!(TASK_SPAWN_EVIDENCE) };
    capture.publication.fetch_add(1, Ordering::AcqRel);
    capture.words[2] = capture.words[2].saturating_add(1);
    capture.words[3..10].copy_from_slice(&[
        observed_ns,
        caller.id,
        caller.generation,
        request,
        state,
        value,
        generation,
    ]);
    capture.publication.fetch_add(1, Ordering::Release);
}
