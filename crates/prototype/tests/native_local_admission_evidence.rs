//! The diagnostic records real scheduler refusals without granting a retry or
//! changing admission. Original request identity is bound only after the
//! kernel broker observes the same spawn/deadline result.
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_tasks/local_evidence.rs"]
mod evidence;
use cyxia_prototype::domains::{
    Error, ObjectKey, WINDOW_NS,
    tasks::{CpuLayout, RunState, Scheduler, ThreadSpec},
};

fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn layout() -> CpuLayout {
    CpuLayout {
        business_mask: 13,
        healthy_mask: 15,
        generation: 1,
    }
}
fn local(id: u64) -> ThreadSpec {
    ThreadSpec {
        key: key(id),
        group: key(5),
        cpu: 3,
        allowed_mask: 12,
        minimum_ns: 10_000_000,
        budget_ns: 10_000_000,
    }
}
fn event(error: Error, observed_ns: u64) -> evidence::Event {
    evidence::Event {
        stage: 23,
        error,
        observed_ns,
        spawn_id: 7,
        deadline_ns: 60_000_000_000,
        task: key(0x1001),
        cpu: 3,
        group: key(5),
        layout: layout(),
        entered_ns: observed_ns - 100,
    }
}

#[test]
fn actual_window_minimum_refusal_keeps_original_error_time_and_exact_request_binding() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(5)).unwrap();
    let refused_at = 95_000_000;
    let error = scheduler
        .admit(local(0x1001), layout(), refused_at)
        .unwrap_err();
    assert_eq!(error, Error::Budget);
    assert_eq!(scheduler.thread_count(), 0, "refusal creates no thread");
    let record = evidence::Evidence::new();
    record.retain(evidence::Failure::capture(
        event(error, refused_at),
        &scheduler,
    ));
    let original = record.words();
    assert_eq!(
        original[3..7],
        [23, Error::Budget as u64 + 1, refused_at, 7]
    );
    assert_eq!(original[18..22], [0, 0, 0, 5_000_000]);
    assert_eq!(original[30], 0);

    record.bind_request(8, key(4097), 60_000_000_000);
    record.bind_request(7, key(4097), 60_000_000_001);
    record.bind_request(7, ObjectKey::default(), 60_000_000_000);
    assert_eq!(record.words(), original);
    record.bind_request(7, key(4097), 60_000_000_000);
    let bound = record.words();
    assert_eq!(bound[7..10], [4097, 1, 60_000_000_000]);
    assert_eq!(bound[30], 1);
    assert_eq!(bound[3..7], original[3..7]);

    // A later legal admission and failure never overwrite the first refusal.
    scheduler.admit(local(0x1001), layout(), WINDOW_NS).unwrap();
    let later = scheduler
        .admit(local(0x1001), layout(), WINDOW_NS + 1)
        .unwrap_err();
    assert_eq!(later, Error::Exists);
    record.retain(evidence::Failure::capture(
        event(later, WINDOW_NS + 1),
        &scheduler,
    ));
    record.bind_request(7, key(4100), 60_000_000_000);
    assert_eq!(record.words(), bound);
    assert_eq!(core::mem::size_of::<evidence::Evidence>(), 256);
}

#[test]
fn actual_old_window_credit_is_retained_as_busy_without_fabricating_budget_or_completion() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(5)).unwrap();
    scheduler.admit(local(0x1000), layout(), 0).unwrap();
    let active = scheduler
        .dispatch(3, layout(), 99_000_000, 1_000_000)
        .unwrap()
        .unwrap();
    let refused_at = WINDOW_NS + 1;
    let error = scheduler
        .admit(local(0x1001), layout(), refused_at)
        .unwrap_err();
    assert_eq!(error, Error::Busy);
    let record = evidence::Evidence::new();
    record.retain(evidence::Failure::capture(
        event(error, refused_at),
        &scheduler,
    ));
    let words = record.words();
    assert_eq!(words[4], Error::Busy as u64 + 1);
    assert_eq!(
        words[22..28],
        [
            active.sequence,
            active.thread.id,
            active.thread.generation,
            active.window,
            active.started_ns,
            active.reserved_ns
        ]
    );
    assert_eq!((words[20], words[31]), (9_000_000, 9_000_000));
    assert_eq!(
        scheduler.active(3),
        Some(active),
        "diagnostics cannot retire actual credit"
    );
    scheduler
        .complete(active, 1_000_000, RunState::Blocked, WINDOW_NS)
        .unwrap();
    assert_eq!(
        record.words(),
        words,
        "later settlement cannot rewrite the failure context"
    );
}
