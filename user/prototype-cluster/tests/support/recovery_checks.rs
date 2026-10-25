use super::*;
fn completed() -> (Driver, Driver) {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 0);
    a.connect([31; 32], 0).unwrap();
    crate::select(1, 0);
    b.connect([32; 32], 0).unwrap();
    crate::pump(&mut a, &mut b, 0, crate::closed_both);
    (a, b)
}
#[test]
fn historical_close_cannot_release_another_contracts_prepared_kernel_token() {
    let (mut a, mut b) = completed();
    let (owner, index) = if a.engine.local > b.engine.local {
        (&mut a, 0)
    } else {
        (&mut b, 1)
    };
    crate::select(index, 100);
    let old = owner.engine.statuses()[0].contract;
    let terms = Terms {
        id: [251; 16],
        cpu_milli: 100,
        memory_pages: 16,
        runtime_ms: 60000,
        package_hash: [42; 32],
        input_hash: owner.engine.crypto.sha256(&[]),
    };
    let hash = owner.engine.request_hash(&terms);
    owner
        .engine
        .prepare(terms, hash, [9; 16], 100, 2000)
        .unwrap();
    owner.kernel_token = Some(77);
    owner.kernel_contract = Some(terms.id);
    crate::CTX.with(|c| {
        let mut c = c.borrow_mut();
        c.nodes[index].reserved = true;
        c.nodes[index].task_state = 1;
    });
    let header = Header {
        kind: 22,
        body_len: 16,
        sequence: 10000,
        request: [99; 16],
        cluster: owner.engine.cluster(),
        epoch: 1,
        sender_boot: 1,
        receiver_boot: 1,
    };
    owner.handle(header, &old, 101).unwrap();
    assert_eq!(owner.kernel_token, Some(77));
    assert_eq!(owner.kernel_contract, Some(terms.id));
    assert!(crate::CTX.with(|c| c.borrow().nodes[index].reserved));
    assert!(
        owner
            .engine
            .contracts
            .iter()
            .any(|c| c.terms.id == terms.id && c.state == cluster::ContractState::Prepared)
    );
}
#[test]
fn complete_snapshot_pages_reconcile_more_than_32_retained_contracts() {
    let (mut a, mut b) = completed();
    let (owner, recipient, oi, ri) = if a.engine.local > b.engine.local {
        (&mut a, &mut b, 0, 1)
    } else {
        (&mut b, &mut a, 1, 0)
    };
    for id in 100u8..140 {
        let t = Terms {
            id: [id; 16],
            cpu_milli: 100,
            memory_pages: 16,
            runtime_ms: 60000,
            package_hash: [42; 32],
            input_hash: owner.engine.crypto.sha256(&[]),
        };
        let hash = owner.engine.request_hash(&t);
        crate::select(oi, 100);
        owner.engine.prepare(t, hash, [id; 16], 100, 2000).unwrap();
        let e = owner.engine.commit(t.id, [id; 16], hash, 100).unwrap();
        persist(&mut owner.engine, e).unwrap();
        crate::select(ri, 100);
        let e = recipient.engine.record_request(t, hash).unwrap();
        persist(&mut recipient.engine, e).unwrap();
        let e = recipient
            .engine
            .observe_grant(t, hash, [id; 16], 1, 1)
            .unwrap();
        persist(&mut recipient.engine, e).unwrap();
        crate::select(oi, 100);
        let e = owner.engine.close(t.id, true).unwrap();
        persist(&mut owner.engine, e).unwrap();
        crate::select(ri, 100);
        let e = recipient.engine.close(t.id, true).unwrap();
        persist(&mut recipient.engine, e).unwrap();
    }
    assert_eq!(a.engine.statuses().len(), 41);
    assert_eq!(b.engine.statuses().len(), 41);
    crate::select(0, 200);
    a.disconnect();
    a.connect([41; 32], 200).unwrap();
    crate::select(1, 200);
    b.disconnect();
    b.connect([42; 32], 200).unwrap();
    crate::pump(&mut a, &mut b, 200, || {
        crate::CTX.with(|c| {
            c.borrow()
                .nodes
                .iter()
                .all(|n| n.traces.iter().filter(|&&e| e == 0x212).count() >= 2)
        })
    });
    assert!(a.engine.ready() && b.engine.ready());
}
#[test]
fn transient_reservation_entropy_failure_allocates_no_kernel_token_and_next_prepare_works() {
    let (mut a, mut b) = completed();
    let (owner, index) = if a.engine.local > b.engine.local {
        (&mut a, 0)
    } else {
        (&mut b, 1)
    };
    crate::select(index, 100);
    let t = Terms {
        id: [251; 16],
        cpu_milli: 100,
        memory_pages: 16,
        runtime_ms: 60000,
        package_hash: [42; 32],
        input_hash: owner.engine.crypto.sha256(&[]),
    };
    let hash = owner.engine.request_hash(&t);
    let mut body = terms_bytes(t);
    body.extend_from_slice(&hash);
    body.extend_from_slice(&owner.engine.boot.to_le_bytes());
    let mut header = Header {
        kind: 17,
        body_len: body.len() as u32,
        sequence: 10000,
        request: [99; 16],
        cluster: owner.engine.cluster(),
        epoch: 1,
        sender_boot: 1,
        receiver_boot: 1,
    };
    crate::CTX.with(|c| c.borrow_mut().nodes[index].fail_nonce_once = true);
    assert!(owner.handle(header, &body, 100).is_err());
    assert!(owner.kernel_token.is_none());
    assert!(!crate::CTX.with(|c| c.borrow().nodes[index].reserved));
    header.sequence += 1;
    header.request = [100; 16];
    owner.handle(header, &body, 101).unwrap();
    assert!(owner.kernel_token.is_some());
    assert!(crate::CTX.with(|c| c.borrow().nodes[index].reserved));
}
