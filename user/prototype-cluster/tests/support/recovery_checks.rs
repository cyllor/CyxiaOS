use super::*;
#[test]
fn same_boot_service_restart_recovers_started_task_without_a_second_enqueue() {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 0);
    a.connect([31; 32], 0).unwrap();
    crate::select(1, 0);
    b.connect([32; 32], 0).unwrap();
    crate::pump(&mut a, &mut b, 0, || crate::has_trace(0x214));
    let owner = crate::CTX.with(|c| c.borrow().nodes.iter().position(|n| n.starts == 1).unwrap());
    let key = if owner == 0 { a.task_key } else { b.task_key }.unwrap();
    drop(a);
    drop(b);
    // The service alone is reconstructed. The kernel and BootEpoch survive.
    let (mut a, mut b) = crate::setup(1);
    crate::select(owner, 500);
    let driver = if owner == 0 { &mut a } else { &mut b };
    driver.offline_tick(500).unwrap();
    let result = driver.engine.results.iter().find(|r| r.key == key).unwrap();
    assert_eq!(result.state, TaskState::Done);
    assert_eq!(result.body, 10i64.to_le_bytes());
    assert_eq!(crate::CTX.with(|c| c.borrow().nodes[owner].starts), 1);
    assert!(
        driver.outgoing().is_empty(),
        "offline recovery must not grant a session"
    );
}

#[test]
fn same_boot_service_restart_reconnects_and_closes_the_original_kernel_custody() {
    let (a, b, owner, _) = started();
    drop((a, b));
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 100);
    a.connect([41; 32], 100).unwrap();
    crate::select(1, 100);
    b.connect([42; 32], 100).unwrap();
    crate::pump(&mut a, &mut b, 100, crate::closed_both);
    assert!(a.engine.contracts.is_empty() && b.engine.contracts.is_empty());
    crate::CTX.with(|c| {
        let c = c.borrow();
        assert_eq!(c.nodes[owner].starts, 1);
        assert!(!c.nodes[owner].reserved);
    });
}

#[test]
fn same_boot_service_restart_closes_granted_but_unstarted_work_without_dispatch() {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 0);
    a.connect([31; 32], 0).unwrap();
    crate::select(1, 0);
    b.connect([32; 32], 0).unwrap();
    crate::pump(&mut a, &mut b, 0, || crate::has_trace(0x213));
    drop((a, b));
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 100);
    a.connect([41; 32], 100).unwrap();
    crate::select(1, 100);
    b.connect([42; 32], 100).unwrap();
    crate::pump(&mut a, &mut b, 100, crate::closed_both);
    crate::CTX.with(|c| {
        for node in &c.borrow().nodes {
            assert_eq!(node.starts, 0);
            assert!(!node.reserved);
        }
    });
}

fn started() -> (Driver, Driver, usize, TaskKey) {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 0);
    a.connect([31; 32], 0).unwrap();
    crate::select(1, 0);
    b.connect([32; 32], 0).unwrap();
    crate::pump(&mut a, &mut b, 0, || crate::has_trace(0x214));
    let owner = crate::CTX.with(|c| c.borrow().nodes.iter().position(|n| n.starts == 1).unwrap());
    let key = if owner == 0 { a.task_key } else { b.task_key }.unwrap();
    (a, b, owner, key)
}

#[test]
fn same_boot_recovery_waits_for_live_work_and_persists_kernel_failure_without_restarting() {
    let (a, b, owner, key) = started();
    drop((a, b));
    crate::CTX.with(|c| c.borrow_mut().nodes[owner].task_pending = true);
    let (mut a, mut b) = crate::setup(1);
    crate::select(owner, 100);
    let driver = if owner == 0 { &mut a } else { &mut b };
    driver.offline_tick(100).unwrap();
    assert_eq!(driver.engine.results[0].state, TaskState::Started);
    crate::CTX.with(|c| {
        let mut c = c.borrow_mut();
        c.nodes[owner].task_pending = false;
        c.nodes[owner].fail_task = true;
    });
    driver.offline_tick(200).unwrap();
    assert_eq!(
        driver
            .engine
            .results
            .iter()
            .find(|r| r.key == key)
            .unwrap()
            .state,
        TaskState::Failed
    );
    assert_eq!(crate::CTX.with(|c| c.borrow().nodes[owner].starts), 1);
}

#[test]
fn missing_or_mismatched_kernel_custody_stays_started_without_rerun_or_release() {
    for mutation in 0..6 {
        let (a, b, owner, key) = started();
        drop((a, b));
        crate::CTX.with(|c| {
            let mut c = c.borrow_mut();
            if mutation == 5 {
                c.nodes[owner].custody = None;
            } else {
                c.nodes[owner].custody.as_mut().unwrap()[[0, 8, 40, 72, 88][mutation]] ^= 1;
            }
        });
        let (mut a, mut b) = crate::setup(1);
        crate::select(owner, 100);
        let driver = if owner == 0 { &mut a } else { &mut b };
        driver.offline_tick(100).unwrap();
        assert_eq!(
            driver
                .engine
                .results
                .iter()
                .find(|r| r.key == key)
                .unwrap()
                .state,
            TaskState::Started
        );
        assert!(!driver.engine.ready());
        assert!(driver.kernel_token.is_none());
        crate::CTX.with(|c| {
            let c = c.borrow();
            assert_eq!(c.nodes[owner].starts, 1);
            assert!(c.nodes[owner].reserved);
        });
    }
}

#[test]
fn durable_started_before_kernel_admission_is_cancelled_without_execution() {
    let (a, b, owner, key) = started();
    drop((a, b));
    // Crash cut after durable STARTED, before the actual kernel START operation.
    crate::CTX.with(|c| {
        let mut c = c.borrow_mut();
        let n = &mut c.nodes[owner];
        n.starts = 0;
        n.custody_admitted = false;
        n.task_state = 1;
    });
    let (a, b) = crate::setup(1);
    let driver = if owner == 0 { &a } else { &b };
    assert_eq!(
        driver
            .engine
            .results
            .iter()
            .find(|r| r.key == key)
            .unwrap()
            .state,
        TaskState::Cancelled
    );
    assert_eq!(crate::CTX.with(|c| c.borrow().nodes[owner].starts), 0);
    assert!(!driver.engine.ready());
}

#[test]
fn service_restart_releases_volatile_prepare_without_creating_a_grant() {
    crate::CTX.with(|c| *c.borrow_mut() = crate::Context::default());
    let (mut a, mut b) = crate::setup(1);
    crate::select(0, 0);
    a.connect([31; 32], 0).unwrap();
    crate::select(1, 0);
    b.connect([32; 32], 0).unwrap();
    crate::pump(&mut a, &mut b, 0, || crate::has_trace(0x220));
    let owner = crate::CTX.with(|c| c.borrow().nodes.iter().position(|n| n.reserved).unwrap());
    drop((a, b));
    let (a, b) = crate::setup(1);
    let driver = if owner == 0 { &a } else { &b };
    assert!(driver.engine.contracts.is_empty());
    assert!(driver.kernel_token.is_none());
    crate::CTX.with(|c| {
        let c = c.borrow();
        assert!(!c.nodes[owner].reserved);
        assert_eq!(c.nodes[owner].starts, 0);
    });
}

#[test]
fn service_restart_releases_custody_after_durable_close_before_kernel_release() {
    let (mut a, mut b, owner, key) = started();
    crate::select(owner, 100);
    let driver = if owner == 0 { &mut a } else { &mut b };
    driver.offline_tick(100).unwrap();
    let hash = driver
        .engine
        .results
        .iter()
        .find(|r| r.key == key)
        .unwrap()
        .result_hash;
    let effect = driver.engine.ack_result(key, hash).unwrap();
    persist(&mut driver.engine, effect).unwrap();
    let effect = driver.engine.close(key.contract, true).unwrap();
    persist(&mut driver.engine, effect).unwrap();
    drop((a, b));
    crate::CTX.with(|c| c.borrow_mut().nodes[owner].fail_release_once = true);
    let (mut a, mut b) = crate::setup(1);
    assert!(crate::CTX.with(|c| c.borrow().nodes[owner].reserved));
    crate::select(owner, 200);
    let driver = if owner == 0 { &mut a } else { &mut b };
    driver.offline_tick(200).unwrap();
    assert!(driver.engine.contracts.is_empty());
    assert!(!crate::CTX.with(|c| c.borrow().nodes[owner].reserved));
    assert_eq!(crate::CTX.with(|c| c.borrow().nodes[owner].starts), 1);
}

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
