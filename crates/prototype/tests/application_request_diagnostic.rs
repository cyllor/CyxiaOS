//! Observe actual queue boundaries, without minting native completion evidence.
mod domain_platform {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(100);
    pub fn now_ns() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    pub fn at(now: u64) {
        NOW.store(now, Ordering::Relaxed);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_network/requests.rs"]
mod requests;

use cyxia_prototype::domains::ObjectKey;
use requests::{Queue, wire};

#[test]
fn real_queue_submission_handoff_unknown_and_completion_are_distinguishable() {
    let actor = ObjectKey {
        id: 44,
        generation: 8,
    };
    let mut queue = Queue::<4>::new();
    queue.initialize(7).unwrap();
    let mut input = [0u8; 32];
    for (slot, value) in input.chunks_exact_mut(8).zip(1u64..=4) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
    let key = queue.submit(actor, 1, &input, 100).unwrap();
    let snapshot = requests::diagnostic::APPLICATION_REQUEST_EVIDENCE.snapshot();
    assert_eq!(&snapshot[8..13], &[4097, 7, 44, 8, 1]);
    assert_eq!(snapshot[8 + 9], wire::QUEUED);
    assert_eq!(snapshot[8 + 15], 1); // actual successful submit
    assert_eq!(snapshot[8 + 16], 0); // no service handoff yet

    domain_platform::at(200);
    let mut payload = [0u8; 4096];
    let bytes = queue.next(&mut payload).unwrap();
    let copied = wire::Submission::decode(&payload[..bytes]).unwrap();
    assert_eq!(copied.key, key);
    assert_eq!(copied.input, input);
    queue
        .acknowledge(wire::Status {
            key,
            state: wire::UNKNOWN,
            target: ObjectKey::default(),
        })
        .unwrap();
    assert_eq!(queue.status(actor, key).unwrap(), [wire::UNKNOWN, 0, 0]);
    let snapshot = requests::diagnostic::APPLICATION_REQUEST_EVIDENCE.snapshot();
    assert_eq!(&snapshot[8 + 15..8 + 19], &[1, 1, 1, 1]);
    assert_eq!(snapshot[8 + 12], 0); // UNKNOWN never fabricates completion
    assert!(queue.completion(actor, key).unwrap().is_none());

    domain_platform::at(300);
    let target = ObjectKey {
        id: 55,
        generation: 9,
    };
    queue
        .acknowledge(wire::Status {
            key,
            state: wire::LOCAL,
            target,
        })
        .unwrap();
    queue
        .finish(
            wire::Completion {
                key,
                outcome: 1,
                target,
                value: 10,
                finished_ns: 250,
                closed: 1,
            },
            300,
        )
        .unwrap();
    let snapshot = requests::diagnostic::APPLICATION_REQUEST_EVIDENCE.snapshot();
    assert_eq!(snapshot[0], 2 * snapshot[5]);
    assert_eq!(snapshot[8 + 9], wire::LOCAL);
    assert_eq!(&snapshot[8 + 10..8 + 14], &[55, 9, 1, 250]);
    assert_eq!(snapshot[8 + 19], 1); // actual admitted completion only
    assert_eq!(queue.completion(actor, key).unwrap().unwrap().value, 10);
}
