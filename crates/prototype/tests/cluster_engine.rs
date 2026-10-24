#![cfg(feature = "cluster-engine")]
use cyxia_prototype::cluster::{
    wire::{Config, Proof},
    *,
};
use sha2::{Digest, Sha256};
struct TestCrypto([u8; 32]);
impl Crypto for TestCrypto {
    fn sha256(&self, b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }
    fn sign(&self, b: &[u8]) -> [u8; 64] {
        sig(self.0, b)
    }
    fn verify(&self, n: &[u8; 32], b: &[u8], s: &[u8; 64]) -> bool {
        sig(*n, b) == *s
    }
}
fn sig(n: [u8; 32], b: &[u8]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(n);
    h.update(b);
    let d = h.finalize();
    let mut s = [0; 64];
    s[..32].copy_from_slice(&d);
    s[32..].copy_from_slice(&d);
    s
}
fn commit(e: &mut Engine<TestCrypto>, x: Effect) -> Vec<u8> {
    let b = x.bytes.clone();
    e.complete(x.id, Durability::Committed).unwrap();
    b
}
fn pair() -> (Engine<TestCrypto>, Engine<TestCrypto>, Vec<Vec<u8>>) {
    let mut a = Engine::new([1; 32], [2; 32], 1, TestCrypto([1; 32])).unwrap();
    let mut b = Engine::new([2; 32], [1; 32], 1, TestCrypto([2; 32])).unwrap();
    let mut history = vec![];
    let e = a.begin_formation([3; 32]).unwrap();
    history.push(commit(&mut a, e));
    let e = b.begin_formation([4; 32]).unwrap();
    commit(&mut b, e);
    let c = Config {
        trust_domain: [5; 32],
        nodes: [[1; 32], [2; 32]],
        counters: [1, 1],
        nonces: [[3; 32], [4; 32]],
        schema: [6; 32],
        policy: [7; 32],
        epoch: 1,
    };
    let e = a.confirm(c, 0).unwrap();
    history.push(commit(&mut a, e));
    let e = b.confirm(c, 0).unwrap();
    commit(&mut b, e);
    let p = Proof {
        config: c,
        formation: a.formation_for(&c),
        signatures: [a.signature().unwrap(), b.signature().unwrap()],
    };
    let e = a.bind(p).unwrap();
    history.push(commit(&mut a, e));
    let e = b.bind(p).unwrap();
    commit(&mut b, e);
    for e in [&mut a, &mut b] {
        e.hello(1, [8; 32]).unwrap();
        e.reconcile(&[]).unwrap();
        e.send_ready().unwrap();
        e.peer_ready(1, [8; 32], e.cluster()).unwrap();
    }
    (a, b, history)
}
fn terms(e: &Engine<TestCrypto>) -> Terms {
    Terms {
        id: [9; 16],
        cpu_milli: 100,
        memory_pages: 8,
        runtime_ms: 100,
        package_hash: [10; 32],
        input_hash: e.crypto.sha256(b"input"),
    }
}
fn grant(a: &mut Engine<TestCrypto>) -> ([u8; 16], [u8; 32]) {
    let t = terms(a);
    let h = a.request_hash(&t);
    a.prepare(t, h, [11; 16], 0, 2000).unwrap();
    let e = a.commit(t.id, [11; 16], h, 0).unwrap();
    assert_eq!(a.contracts[0].state, ContractState::GrantPending);
    commit(a, e);
    (t.id, h)
}
#[test]
fn formation_publish_waits_for_durability_and_unknown_io_freezes() {
    let mut a = Engine::new([1; 32], [2; 32], 1, TestCrypto([1; 32])).unwrap();
    let e = a.begin_formation([3; 32]).unwrap();
    assert_eq!(a.formation_counter, 0);
    assert_eq!(a.complete(e.id, Durability::Unknown), Err(Error::UnknownIo));
    assert!(matches!(a.begin_formation([4; 32]), Err(Error::UnknownIo)));
    assert!(!a.ready());
}
#[test]
fn unique_execution_final_gate_and_reboot_started_becomes_lost() {
    let (mut a, _, _) = pair();
    let (id, h) = grant(&mut a);
    let key = TaskKey {
        cluster: a.cluster(),
        contract: id,
        task: [12; 16],
        attempt: 1,
    };
    let e = a.activate(key, h, b"input", 1, 1, 1).unwrap();
    commit(&mut a, e);
    assert!(a.enqueue(key, 1, 1, 2).is_ok());
    assert!(a.enqueue(key, 1, 1, 2).is_err());
    assert!(a.activate(key, h, b"input", 1, 1, 2).is_err());
    let (mut original, _, mut log) = pair();
    let t = terms(&original);
    let h = original.request_hash(&t);
    original.prepare(t, h, [11; 16], 0, 2000).unwrap();
    let e = original.commit(t.id, [11; 16], h, 0).unwrap();
    log.push(commit(&mut original, e));
    let e = original.activate(key, h, b"input", 1, 1, 1).unwrap();
    log.push(commit(&mut original, e));
    let mut recovered = Engine::new([1; 32], [2; 32], 2, TestCrypto([1; 32])).unwrap();
    for event in log {
        recovered.recover_event(&event).unwrap();
    }
    assert!(!recovered.ready());
    let e = recovered.recovery_loss().unwrap().unwrap();
    commit(&mut recovered, e);
    assert_eq!(recovered.results[0].state, TaskState::Lost);
    assert!(recovered.enqueue(key, 2, 1, 2).is_err());
}
#[test]
fn isolation_and_deadline_are_rechecked_after_started_intent() {
    let (mut a, _, _) = pair();
    let (id, h) = grant(&mut a);
    let key = TaskKey {
        cluster: a.cluster(),
        contract: id,
        task: [12; 16],
        attempt: 1,
    };
    let e = a.activate(key, h, b"input", 1, 1, 1).unwrap();
    commit(&mut a, e);
    assert_eq!(a.enqueue(key, 1, 1, 100).unwrap_err(), Error::Expired);
    a.isolate();
    assert_eq!(a.enqueue(key, 1, 1, 2).unwrap_err(), Error::Isolated);
    assert_eq!(a.results[0].state, TaskState::Started);
}
#[test]
fn recipient_persists_before_ack_owner_persists_tombstone_before_free() {
    let (mut owner, mut recipient, _) = pair();
    let (id, h) = grant(&mut owner);
    let key = TaskKey {
        cluster: owner.cluster(),
        contract: id,
        task: [12; 16],
        attempt: 1,
    };
    let e = owner.activate(key, h, b"input", 1, 1, 1).unwrap();
    commit(&mut owner, e);
    owner.enqueue(key, 1, 1, 2).unwrap();
    let e = owner.finish(key, TaskState::Done, b"result").unwrap();
    assert_eq!(owner.results[0].state, TaskState::Started);
    commit(&mut owner, e);
    let hash = owner.results[0].result_hash;
    let terms = owner.contracts[0].terms;
    let e = recipient.record_request(terms, h).unwrap();
    commit(&mut recipient, e);
    let e = recipient.observe_grant(terms, h, [11; 16], 1, 1).unwrap();
    commit(&mut recipient, e);
    let e = recipient
        .record_request_task(key, terms.input_hash)
        .unwrap();
    commit(&mut recipient, e);
    let e = recipient
        .receive_result(
            key,
            TaskState::Done,
            owner.crypto.sha256(b"input"),
            b"result",
            hash,
        )
        .unwrap();
    assert!(recipient.ack_ready(key).is_err());
    commit(&mut recipient, e);
    assert_eq!(recipient.ack_ready(key).unwrap(), hash);
    let e = owner.ack_result(key, hash).unwrap();
    assert_eq!(owner.results[0].body, b"result");
    commit(&mut owner, e);
    assert!(owner.results.is_empty());
    assert!(owner.ack_result(key, [0; 32]).is_err());
}
#[test]
fn sign_leave_cannot_bypass_live_obligations() {
    let (mut a, _, _) = pair();
    grant(&mut a);
    let e = a.leave().unwrap();
    commit(&mut a, e);
    let mut record = [0; 184];
    record[..32].copy_from_slice(&a.cluster());
    assert!(a.sign_leave(&record).is_err());
}
#[test]
fn malformed_event_cannot_publish_partial_member_state() {
    let (mut a, _, log) = pair();
    let mut new = Engine::new([1; 32], [2; 32], 2, TestCrypto([1; 32])).unwrap();
    new.recover_event(&log[0]).unwrap();
    let mut bad = log[1].clone();
    bad.push(0);
    assert!(new.recover_event(&bad).is_err());
    assert_eq!(new.member, Member::Standalone);
    let mut forged = log[2].clone();
    forged[4..12].copy_from_slice(&1u64.to_le_bytes());
    let mut empty = Engine::new([1; 32], [2; 32], 2, TestCrypto([1; 32])).unwrap();
    assert!(empty.recover_event(&forged).is_err());
    a.isolate();
}
#[test]
fn reservations_enforce_combined_cpu_and_expired_uncommitted_slots_recycle() {
    let (mut a, _, _) = pair();
    let mut t = terms(&a);
    t.cpu_milli = 600;
    let h = a.request_hash(&t);
    a.prepare(t, h, [11; 16], 0, 10).unwrap();
    t.id = [10; 16];
    t.cpu_milli = 400;
    let h = a.request_hash(&t);
    assert_eq!(a.prepare(t, h, [12; 16], 0, 10), Err(Error::Capacity));
    assert!(a.prepare(t, h, [12; 16], 11, 10).is_ok());
    assert_eq!(a.contracts.len(), 1);
}
#[test]
fn closed_unactivated_contracts_recycle_active_slots_but_reject_old_id() {
    let (mut a, _, _) = pair();
    for id in 1u8..=40 {
        let mut t = terms(&a);
        t.id = [id; 16];
        let h = a.request_hash(&t);
        a.prepare(t, h, [id; 16], 0, 2000).unwrap();
        let e = a.commit(t.id, [id; 16], h, 0).unwrap();
        commit(&mut a, e);
        let e = a.close(t.id, true).unwrap();
        commit(&mut a, e);
    }
    assert!(a.contracts.is_empty());
    let mut t = terms(&a);
    t.id = [1; 16];
    let h = a.request_hash(&t);
    assert_eq!(a.prepare(t, h, [1; 16], 0, 2000), Err(Error::Conflict));
}
#[test]
fn leave_signature_covers_actual_local_obligation_digest() {
    let (mut a, _, _) = pair();
    let e = a.leave().unwrap();
    commit(&mut a, e);
    let record = a.leave_record([1; 16], [[0; 32]; 2]);
    assert!(record.is_err());
}
#[test]
fn acknowledged_owner_result_releases_active_result_slot_but_keeps_hash_tombstone() {
    let (mut a, _, _) = pair();
    let (id, h) = grant(&mut a);
    let key = TaskKey {
        cluster: a.cluster(),
        contract: id,
        task: [12; 16],
        attempt: 1,
    };
    let e = a.activate(key, h, b"input", 1, 1, 1).unwrap();
    commit(&mut a, e);
    a.enqueue(key, 1, 1, 2).unwrap();
    let e = a.finish(key, TaskState::Done, b"result").unwrap();
    commit(&mut a, e);
    let hash = a.results[0].result_hash;
    let e = a.ack_result(key, hash).unwrap();
    commit(&mut a, e);
    assert!(a.results.is_empty());
    assert!(a.ack_result(key, hash).is_ok());
}
#[test]
fn capacity_rejection_rolls_back_only_volatile_pending_grant() {
    let (mut a, _, _) = pair();
    let t = terms(&a);
    let h = a.request_hash(&t);
    a.prepare(t, h, [11; 16], 0, 2000).unwrap();
    let e = a.commit(t.id, [11; 16], h, 0).unwrap();
    assert_eq!(a.complete(e.id, Durability::Rejected), Err(Error::Capacity));
    assert_eq!(a.contracts[0].state, ContractState::Prepared);
    assert!(a.ready());
    assert!(a.commit(t.id, [11; 16], h, 1).is_ok());
}
#[test]
fn session_headers_reject_replay_boot_mismatch_and_active_clone() {
    let (mut a, _, _) = pair();
    let h = cyxia_prototype::cluster::wire::Header {
        kind: 16,
        body_len: 0,
        sequence: 1,
        request: [1; 16],
        cluster: a.cluster(),
        epoch: 1,
        sender_boot: 1,
        receiver_boot: 1,
    };
    a.accept_header(&h).unwrap();
    assert_eq!(a.accept_header(&h), Err(Error::Replay));
    let mut stale = h;
    stale.sequence = 2;
    stale.receiver_boot = 2;
    assert_eq!(a.accept_header(&stale), Err(Error::Replay));
    assert_eq!(a.hello(2, [9; 32]), Err(Error::Conflict));
    assert!(!a.ready());
}
#[test]
fn recipient_rejects_unknown_contract_wrong_input_and_unexpected_task() {
    let (mut owner, mut recipient, _) = pair();
    let (id, h) = grant(&mut owner);
    let key = TaskKey {
        cluster: owner.cluster(),
        contract: id,
        task: [12; 16],
        attempt: 1,
    };
    let input_hash = owner.crypto.sha256(b"input");
    let result_hash = owner.crypto.sha256(b"result");
    assert!(
        recipient
            .receive_result(key, TaskState::Done, input_hash, b"result", result_hash)
            .is_err()
    );
    let terms = owner.contracts[0].terms;
    let e = recipient.record_request(terms, h).unwrap();
    commit(&mut recipient, e);
    let e = recipient.observe_grant(terms, h, [11; 16], 1, 1).unwrap();
    commit(&mut recipient, e);
    let e = recipient.record_request_task(key, input_hash).unwrap();
    commit(&mut recipient, e);
    assert!(
        recipient
            .receive_result(key, TaskState::Done, [99; 32], b"result", result_hash)
            .is_err()
    );
    let mut other = key;
    other.task = [13; 16];
    assert!(
        recipient
            .receive_result(other, TaskState::Done, input_hash, b"result", result_hash)
            .is_err()
    );
    let e = recipient
        .receive_result(key, TaskState::Done, input_hash, b"result", result_hash)
        .unwrap();
    commit(&mut recipient, e);
    let e = recipient.close(id, true).unwrap();
    commit(&mut recipient, e);
    assert!(
        recipient
            .receive_result(key, TaskState::Done, input_hash, b"result", result_hash)
            .is_ok()
    );
}
#[test]
fn full_recipient_capacity_accepts_identical_retry_but_rejects_new_129th_result() {
    let (mut owner, mut recipient, _) = pair();
    let mut first = None;
    let hash = owner.crypto.sha256(b"r");
    for id in 1u8..=129 {
        let mut t = terms(&owner);
        t.id = [id; 16];
        let request_hash = owner.request_hash(&t);
        owner.prepare(t, request_hash, [id; 16], 0, 2000).unwrap();
        let e = owner.commit(t.id, [id; 16], request_hash, 0).unwrap();
        commit(&mut owner, e);
        let e = recipient.record_request(t, request_hash).unwrap();
        commit(&mut recipient, e);
        let e = recipient
            .observe_grant(t, request_hash, [id; 16], 1, 1)
            .unwrap();
        commit(&mut recipient, e);
        let key = TaskKey {
            cluster: owner.cluster(),
            contract: t.id,
            task: [id; 16],
            attempt: 1,
        };
        let e = recipient.record_request_task(key, t.input_hash).unwrap();
        commit(&mut recipient, e);
        if id == 129 {
            assert!(matches!(
                recipient.receive_result(key, TaskState::Done, t.input_hash, b"r", hash),
                Err(Error::Capacity)
            ));
            break;
        }
        if id == 1 {
            first = Some((key, t.input_hash));
        }
        let e = recipient
            .receive_result(key, TaskState::Done, t.input_hash, b"r", hash)
            .unwrap();
        commit(&mut recipient, e);
        let e = owner.close(t.id, true).unwrap();
        commit(&mut owner, e);
        let e = recipient.close(t.id, true).unwrap();
        commit(&mut recipient, e);
    }
    assert_eq!(recipient.results.len(), 128);
    let (key, input_hash) = first.unwrap();
    let e = recipient
        .receive_result(key, TaskState::Done, input_hash, b"r", hash)
        .unwrap();
    commit(&mut recipient, e);
    assert_eq!(recipient.results.len(), 128);
    assert_eq!(recipient.ack_ready(key), Ok(hash));
}
