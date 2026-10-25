//! Drive the real bounded mailbox and copied service protocol independently of
//! an emulator. Executor status remains authoritative; time cannot settle it.
mod domain_platform {
    pub fn now_ns() -> u64 {
        1
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/domain_network/requests.rs"]
mod requests;
use cyxia_prototype::domains::{Error, ObjectKey};
use requests::{Queue, wire};
const ACTOR: ObjectKey = ObjectKey {
    id: 44,
    generation: 8,
};

#[test]
fn caller_identity_payload_and_original_clock_survive_lost_handoff_ack() {
    let mut q = Queue::<4>::new();
    q.initialize(7).unwrap();
    let input = [9; 32];
    let key = q.submit(ACTOR, 3, &input, 123).unwrap();
    assert_eq!(key.generation, 7);
    assert_eq!(q.submit(ACTOR, 3, &input, 999), Ok(key));
    assert_eq!(q.submit(ACTOR, 3, &[8; 32], 999), Err(Error::Conflict));
    assert_eq!(q.submit(ACTOR, 2, &input, 999), Err(Error::Stale));
    assert_eq!(
        q.status(
            ObjectKey {
                generation: 9,
                ..ACTOR
            },
            key
        ),
        Err(Error::Auth)
    );
    assert_eq!(
        q.status(
            ACTOR,
            ObjectKey {
                generation: 8,
                ..key
            }
        ),
        Err(Error::Stale)
    );
    let mut bytes = [0; 4096];
    for _ in 0..3 {
        let size = q.next(&mut bytes).unwrap();
        let value = wire::Submission::decode(&bytes[..size]).unwrap();
        assert_eq!(value.key, key);
        assert_eq!(value.actor, ACTOR);
        assert_eq!(value.sequence, 3);
        assert_eq!(
            value.submitted_ns, 123,
            "retry cannot renew four-second deadline"
        );
        assert_eq!(value.input, input);
        assert_eq!(q.status(ACTOR, key), Ok([wire::QUEUED, 0, 0]));
    }
    q.acknowledge(wire::Status {
        key,
        state: wire::UNKNOWN,
        target: ObjectKey::default(),
    })
    .unwrap();
    assert_eq!(q.next(&mut bytes), Err(Error::Again));
    assert_eq!(q.status(ACTOR, key), Ok([wire::UNKNOWN, 0, 0]));
    q.acknowledge(wire::Status {
        key,
        state: wire::PENDING,
        target: ObjectKey::default(),
    })
    .unwrap();
    assert_eq!(q.status(ACTOR, key), Ok([wire::UNKNOWN, 0, 0]));
    let terminal = wire::Status {
        key,
        state: wire::REMOTE,
        target: ObjectKey {
            id: 91,
            generation: 12,
        },
    };
    q.acknowledge(terminal).unwrap();
    q.acknowledge(terminal).unwrap();
    assert_eq!(q.status(ACTOR, key), Ok([wire::REMOTE, 91, 12]));
    assert_eq!(
        q.acknowledge(wire::Status {
            state: wire::LOCAL,
            ..terminal
        }),
        Err(Error::Conflict)
    );
    assert_eq!(q.submit(ACTOR, 3, &input, u64::MAX), Ok(key));
    assert_eq!(q.initialize(8), Err(Error::Stale));
}

#[test]
fn all_thirty_two_unknown_obligations_block_new_work_but_terminal_releases_one_slot() {
    let mut q = Queue::<33>::new();
    q.initialize(1).unwrap();
    let mut keys = Vec::new();
    for n in 1..=32 {
        let key = q.submit(ACTOR, n, &n.to_le_bytes(), n).unwrap();
        q.acknowledge(wire::Status {
            key,
            state: wire::UNKNOWN,
            target: ObjectKey::default(),
        })
        .unwrap();
        keys.push(key);
    }
    assert_eq!(q.submit(ACTOR, 33, &[0; 8], 999), Err(Error::Capacity));
    assert_eq!(q.submit(ACTOR, 1, &1u64.to_le_bytes(), 999), Ok(keys[0]));
    q.acknowledge(wire::Status {
        key: keys[9],
        state: wire::LOCAL,
        target: ObjectKey {
            id: 90,
            generation: 5,
        },
    })
    .unwrap();
    let fresh = q.submit(ACTOR, 33, &[0; 8], 999).unwrap();
    assert_ne!(fresh, keys[9]);
    q.acknowledge(wire::Status {
        key: fresh,
        state: wire::REJECTED,
        target: ObjectKey {
            id: 11,
            generation: 0,
        },
    })
    .unwrap();
    assert_eq!(
        q.submit(ACTOR, 34, &[0; 8], 1000),
        Err(Error::Capacity),
        "retained identity table never evicts an old key"
    );
    assert_eq!(q.status(ACTOR, keys[9]), Ok([wire::LOCAL, 90, 5]));
}

#[test]
fn copied_protocol_rejects_truncation_and_unbacked_terminal_identity() {
    let mut q = Queue::<2>::new();
    q.initialize(1).unwrap();
    assert_eq!(q.submit(ACTOR, 1, &[0; 7], 0), Err(Error::Range));
    let key = q.submit(ACTOR, 1, &[0; 8], 0).unwrap();
    assert_eq!(q.next(&mut [0; 8]), Err(Error::Capacity));
    let mut bytes = [0; 4096];
    let n = q.next(&mut bytes).unwrap();
    assert!(wire::Submission::decode(&bytes[..n - 1]).is_err());
    assert_eq!(
        q.acknowledge(wire::Status {
            key,
            state: wire::REMOTE,
            target: ObjectKey::default()
        }),
        Err(Error::Format)
    );
    assert_eq!(q.status(ACTOR, key), Ok([wire::QUEUED, 0, 0]));
}

#[test]
fn frozen_request_cannot_escape_before_release_or_finish_at_custody_only() {
    let mut q = Queue::<4>::new();
    q.initialize(7).unwrap();
    let input: Vec<u8> = [3u64, 5, 7]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let key = q.reserve(ACTOR, 1, &input, 100).unwrap();
    let mut bytes = [0; 4096];
    assert_eq!(
        q.next(&mut bytes),
        Err(Error::Again),
        "pre-owned payload is not yet arrived"
    );
    let custody = wire::Status {
        key,
        state: wire::LOCAL,
        target: ObjectKey {
            id: 90,
            generation: 2,
        },
    };
    assert_eq!(q.acknowledge(custody), Err(Error::Auth));
    assert_eq!(q.release(ACTOR, key, 200, 199), Err(Error::Again));
    q.release(ACTOR, key, 200, 220).unwrap();
    q.release(ACTOR, key, 200, 900).unwrap();
    assert_eq!(q.release(ACTOR, key, 900, 900), Err(Error::Conflict));
    let n = q.next(&mut bytes).unwrap();
    assert_eq!(
        wire::Submission::decode(&bytes[..n]).unwrap().submitted_ns,
        200
    );
    let done = wire::Completion {
        key,
        outcome: 1,
        target: custody.target,
        value: 15,
        finished_ns: 300,
        closed: 1,
    };
    assert_eq!(
        q.finish(done, 300),
        Err(Error::Conflict),
        "a result without actual admission is not custody"
    );
    q.acknowledge(custody).unwrap();
    assert_eq!(
        q.completion(ACTOR, key),
        Ok(None),
        "Created is not an exited correct task"
    );
    assert_eq!(
        q.finish(wire::Completion { value: 14, ..done }, 300),
        Err(Error::Conflict)
    );
    assert_eq!(
        q.finish(wire::Completion { closed: 0, ..done }, 300),
        Err(Error::Conflict)
    );
    assert_eq!(q.finish(done, 299), Err(Error::Conflict));
    q.finish(done, 300).unwrap();
    q.finish(done, u64::MAX).unwrap();
    assert_eq!(
        q.finish(
            wire::Completion {
                finished_ns: 301,
                ..done
            },
            999
        ),
        Err(Error::Conflict)
    );
    assert_eq!(q.completion(ACTOR, key), Ok(Some(done)));
}

#[test]
fn cancellation_retires_only_unreleased_payload_and_never_manufactures_completion() {
    let mut q = Queue::<35>::new();
    q.initialize(7).unwrap();
    let mut keys = Vec::new();
    for seq in 1..=32 {
        keys.push(q.reserve(ACTOR, seq, &seq.to_le_bytes(), 100).unwrap());
    }
    assert_eq!(q.reserve(ACTOR, 33, &[0; 8], 101), Err(Error::Capacity));
    let held = keys[0];
    assert_eq!(
        q.cancel_reserved(
            ObjectKey {
                generation: 9,
                ..ACTOR
            },
            held,
            200
        ),
        Err(Error::Auth)
    );
    assert_eq!(q.cancel_reserved(ACTOR, held, 99), Err(Error::Busy));
    assert_eq!(q.cancel_reserved(ACTOR, held, 200), Ok(200));
    assert_eq!(
        q.cancel_reserved(ACTOR, held, u64::MAX),
        Ok(200),
        "retry preserves actual original cancellation time"
    );
    assert_eq!(q.completion(ACTOR, held), Ok(None));
    assert_eq!(q.status(ACTOR, held), Err(Error::Stale));
    assert_eq!(q.release(ACTOR, held, 100, 300), Err(Error::Stale));
    assert_eq!(
        q.reserve(ACTOR, 1, &1u64.to_le_bytes(), 300),
        Err(Error::Stale)
    );
    let new = q.reserve(ACTOR, 33, &[0; 8], 300).unwrap();
    assert_ne!(new, held);
    assert_eq!(
        q.reserve(ACTOR, 34, &[0; 8], 301),
        Err(Error::Capacity),
        "idempotent cancel frees exactly one custody slot"
    );
    let released = keys[1];
    q.release(ACTOR, released, 400, 400).unwrap();
    assert_eq!(q.cancel_reserved(ACTOR, released, 500), Err(Error::Busy));
    q.acknowledge(wire::Status {
        key: released,
        state: wire::UNKNOWN,
        target: ObjectKey::default(),
    })
    .unwrap();
    assert_eq!(
        q.cancel_reserved(ACTOR, released, u64::MAX),
        Err(Error::Busy),
        "time cannot discard unknown side effects"
    );
    assert_eq!(q.status(ACTOR, released), Ok([wire::UNKNOWN, 0, 0]));
    let mut bytes = [0; 4096];
    assert_eq!(q.next(&mut bytes), Err(Error::Again));
}
