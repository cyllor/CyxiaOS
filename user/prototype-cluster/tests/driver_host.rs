extern crate alloc;
use cyxia_cluster_transport::tls::IdentitySigner;
use ring::signature::KeyPair;
use std::cell::RefCell;
#[path = "../src/driver.rs"]
mod driver;
#[path = "../src/runtime.rs"]
mod runtime;
#[path = "../../../kernel/src/unified_store/identity.rs"]
mod store_identity;
#[derive(Default)]
struct Node {
    records: Vec<Vec<u8>>,
    staging: Vec<u8>,
    traces: Vec<u64>,
    exit_records: Vec<Vec<u64>>,
    input: Vec<u8>,
    starts: usize,
    reserved: bool,
    entropy: u8,
    fail_task: bool,
    task_state: u64,
    custody: Option<[u8; 120]>,
    custody_admitted: bool,
    task_pending: bool,
    fail_release_once: bool,
    expire_after_stage: bool,
    fail_nonce_once: bool,
    domains: cyxia_prototype_cluster::abi::DomainInput,
    local_submits: usize,
    local_attempts: usize,
    local_again: usize,
    local_requests: Vec<([u8; 16], [u8; 32])>,
    application_requests: Vec<Vec<u8>>,
    application_status: Vec<cyxia_prototype_cluster::application::Status>,
    lose_application_commit: bool,
    lose_application_ack: bool,
    fail_terminal_application_status_once: bool,
    local_results: Vec<([u8; 16], u64, u64)>,
    application_completions: Vec<cyxia_prototype_cluster::application::Completion>,
    replay_requests: Vec<cyxia_prototype_cluster::replay_work::Work>,
    replay_results: Vec<[u8; 72]>,
    bind_busy: bool,
    bind_calls: usize,
    transport_epoch: u64,
    authority: Option<cyxia_kernel_core::control_plane::task_admission::Authority>,
    session_calls: Vec<(u64, u64, Result<(), cyxia_kernel_core::control_plane::Error>)>,
    // Controlled native admission wait: phase9 token, fresh time, live, epoch.
    session_wait: Option<(u64, u64, bool, u64)>,
}
#[derive(Default)]
struct Context {
    node: usize,
    now: u64,
    nodes: [Node; 2],
}
thread_local! {static CTX:RefCell<Context>=RefCell::new(Context::default());}
mod broker {
    use super::*;
    use cyxia_prototype_cluster::abi::*;
    pub fn clock_ns() -> u64 {
        CTX.with(|c| c.borrow().now * 1_000_000)
    }
    pub fn domains() -> DomainInput {
        CTX.with(|c| {
            let c = c.borrow();
            c.nodes[c.node].domains
        })
    }
    pub fn request(
        op: u64,
        input: &[u8],
        out: &mut [u8],
        offset: u64,
        args: [u64; 3],
    ) -> Result<(usize, u64), u64> {
        CTX.with(|cx| {
            let mut cx = cx.borrow_mut();
            let i = cx.node;
            let now = cx.now;
            let n = &mut cx.nodes[i];
            match op {
                OP_TRACE if args[0] == 0x24f && input.len() == 192 => {
                    n.exit_records.push(input.chunks_exact(8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap())).collect());
                    Ok((0, 0))
                }
                OP_STORE_GET => {
                    let b = n.records.get(args[0] as usize - 1).ok_or(NOT_FOUND)?;
                    let off = offset as usize;
                    if off >= b.len() {
                        return Err(FAILED);
                    }
                    let len = out.len().min(b.len() - off);
                    out[..len].copy_from_slice(&b[off..off + len]);
                    Ok((len, b.len() as u64))
                }
                OP_STORE_PUT => {
                    let off = offset as usize;
                    if off == 0 {
                        n.staging = vec![0; args[1] as usize]
                    }
                    n.staging[off..off + input.len()].copy_from_slice(input);
                    if args[2] == 1 {
                        let b = core::mem::take(&mut n.staging);
                        let used = n.records.iter().map(|r| 16 + r.len() as u64).sum();
                        if !store_identity::append_allowed(args[0], used, &b) {
                            return Err(FAILED);
                        }
                        let lose = n.lose_application_commit
                            && b.starts_with(cyxia_prototype_cluster::application_journal::MAGIC);
                        n.records.push(b);
                        if lose {
                            n.lose_application_commit = false;
                            return Err(FAILED);
                        }
                    }
                    Ok((input.len(), args[0]))
                }
                OP_TASK => match args[0] {
                    10 => {
                        for (i, value) in [
                            if n.reserved { 0u64 } else { 100 },
                            if n.reserved { 0 } else { 16 },
                            1,
                            1,
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            out[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
                        }
                        Ok((32, 0))
                    }
                    11 => {
                        n.local_attempts += 1;
                        let key: [u8; 16] = input[..16].try_into().unwrap();
                        let hash: [u8; 32] = input[40..72].try_into().unwrap();
                        assert!(n.records.iter().filter_map(|record|
                            cyxia_prototype_cluster::domain_placement::decode(record).ok())
                            .any(|record| matches!(record,
                                cyxia_prototype_cluster::domain_placement::Record::Intent(intent, _)
                                if intent.request.key.id.to_le_bytes() == key[..8]
                                    && intent.request.key.generation.to_le_bytes() == key[8..]
                                    && intent.request.payload_hash == hash)),
                            "LOCAL admission preceded its durable intent");
                        if n.local_again != 0 {
                            n.local_again -= 1;
                            return Err(AGAIN);
                        }
                        if let Some(old) = n.local_requests.iter().find(|old| old.0 == key) {
                            if *old != (key, hash) {
                                return Err(FAILED);
                            }
                        } else {
                            n.local_requests.push((key, hash));
                            n.local_submits += 1;
                        }
                        for (i, value) in [1u64, 51, 1].into_iter().enumerate() {
                            out[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
                        }
                        Ok((24, 0))
                    }
                    12 => {
                        let key = input[..16].try_into().unwrap();
                        let hash = input[16..48].try_into().unwrap();
                        if !n.local_requests.contains(&(key, hash)) {
                            return Err(NOT_FOUND);
                        }
                        for (i, value) in [1u64, 51, 1].into_iter().enumerate() {
                            out[i * 8..i * 8 + 8].copy_from_slice(&value.to_le_bytes());
                        }
                        Ok((24, 0))
                    }
                    13 => {
                        let bytes = n.application_requests.first().ok_or(AGAIN)?;
                        out[..bytes.len()].copy_from_slice(bytes);
                        Ok((bytes.len(), 0))
                    }
                    14 => {
                        use cyxia_prototype_cluster::{application as wire, application_journal};
                        let status = wire::Status::decode(input).map_err(|_| FAILED)?;
                        if status.state != wire::REJECTED {
                            assert!(n.records.iter().filter_map(|r| application_journal::Record::decode(r).ok())
                                .any(|record| record.key == status.key), "handoff preceded its durable input");
                        }
                        if n.lose_application_ack {
                            n.lose_application_ack = false;
                            return Err(AGAIN);
                        }
                        if status.terminal() && n.fail_terminal_application_status_once {
                            n.fail_terminal_application_status_once = false;
                            return Err(FAILED);
                        }
                        n.application_requests.retain(|r| wire::Submission::decode(r).unwrap().key != status.key);
                        if let Some(old) = n.application_status.iter_mut().find(|old| old.key == status.key) {
                            *old = status;
                        } else {
                            n.application_status.push(status);
                        }
                        Ok((0, 0))
                    }
                    25 => {
                        let work = n.replay_requests.first().ok_or(AGAIN)?;
                        out[..72].copy_from_slice(&work.encode()); Ok((72, 0))
                    }
                    26 => {
                        if input.len() != 72 { return Err(FAILED); }
                        let work = n.replay_requests.first().ok_or(NOT_FOUND)?;
                        let word = |i| u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
                        assert_eq!([word(0), word(8), word(16), word(24)],
                            [work.run.boot_epoch, work.run.trial_id, work.run.generation, work.id]);
                        n.replay_results.push(input.try_into().unwrap()); n.replay_requests.remove(0); Ok((0, 0))
                    }
                    27 => {
                        let key: [u8; 16] = input.get(..16).ok_or(FAILED)?.try_into().unwrap();
                        let (_, value, finished) = n.local_results.iter().find(|v| v.0 == key).ok_or(AGAIN)?;
                        out[..8].copy_from_slice(&value.to_le_bytes()); out[8..16].copy_from_slice(&finished.to_le_bytes()); Ok((16, 0))
                    }
                    28 => {
                        let value = cyxia_prototype_cluster::application::Completion::decode(input).map_err(|_| FAILED)?;
                        if let Some(old) = n.application_completions.iter().find(|v| v.key == value.key) { assert_eq!(*old, value); }
                        else { n.application_completions.push(value); }
                        Ok((0, 0))
                    }
                    29 => Ok((0, 0)),
                    30 => {
                        n.bind_calls += 1;
                        if n.bind_busy { Err(AGAIN) } else { Err(NOT_FOUND) }
                    }
                    TASK_LOOKUP_CUSTODY => {
                        if !n.reserved || n.custody.as_ref().map(|key| &key[..]) != Some(input) {
                            return Err(NOT_FOUND);
                        }
                        out[..8].copy_from_slice(&n.task_state.to_le_bytes());
                        out[8..16].copy_from_slice(&u64::from(n.custody_admitted).to_le_bytes());
                        Ok((16, 1))
                    }
                    TASK_CUSTODY_INVENTORY => {
                        let key = n.custody.as_ref().filter(|key| n.reserved
                            && input[..8] == key[..8] && input[8..40] == key[40..72]).ok_or(NOT_FOUND)?;
                        out[..120].copy_from_slice(key);
                        out[120..128].copy_from_slice(&n.task_state.to_le_bytes());
                        out[128..136].copy_from_slice(&u64::from(n.custody_admitted).to_le_bytes());
                        Ok((136, 1))
                    }
                    0 | TASK_RESERVE_CUSTODY => {
                        if n.reserved {
                            return Err(AGAIN);
                        }
                        n.custody = if args[0] == TASK_RESERVE_CUSTODY {
                            assert_eq!(input.len(), 224);
                            Some(input[104..].try_into().unwrap())
                        } else { None };
                        n.custody_admitted = false;
                        n.reserved = true;
                        n.task_state = 1;
                        Ok((0, 1))
                    }
                    1 => {
                        if args[2] == 0 {
                            n.input.clear()
                        }
                        n.input.extend_from_slice(input);
                        Ok((0, 1))
                    }
                    2 => {
                        assert!(!n.custody_admitted, "task was admitted twice");
                        n.custody_admitted = true;
                        n.starts += 1;
                        n.task_state = 2;
                        Ok((0, 1))
                    }
                    3 => {
                        if n.task_pending { return Err(AGAIN); }
                        if n.fail_task {
                            n.task_state = 5;
                            return Err(FAILED);
                        }
                        n.task_state = 4;
                        let sum = n
                            .input
                            .chunks_exact(8)
                            .map(|b| i64::from_le_bytes(b.try_into().unwrap()))
                            .sum::<i64>();
                        out[..8].copy_from_slice(&sum.to_le_bytes());
                        Ok((8, 1))
                    }
                    4 => {
                        if n.fail_release_once { n.fail_release_once = false; return Err(AGAIN); }
                        n.reserved = false;
                        n.custody = None;
                        Ok((0, 1))
                    }
                    5 => {
                        if matches!(n.task_state, 1 | 2 | 3) { n.task_state = 5; }
                        Ok((0, 0))
                    }
                    8 => {
                        if matches!(n.task_state, 1 | 4 | 5) {
                            Ok((0, n.task_state))
                        } else {
                            Err(AGAIN)
                        }
                    }
                    9 if n.authority.is_some() => {
                        let (now, connected, epoch) = match n.session_wait {
                            Some((token, now, live, epoch)) if token == args[1] => {
                                n.session_wait = None;
                                (now, live, epoch)
                            }
                            _ => (now, true, n.transport_epoch.max(1)),
                        };
                        let authority = n.authority.as_mut().unwrap();
                        if args[1] != 0 && (!connected || args[2] != epoch) {
                            authority.disconnect(); return Err(FAILED);
                        }
                        let result = if args[1] == 3 { authority.activity(epoch, now) }
                            else { authority.session(epoch, args[1], now) };
                        n.session_calls.push((args[1], now, result));
                        if result.is_err() { eprintln!("real Authority session calls: {:?}", n.session_calls); }
                        result.map(|()| (0, 0)).map_err(|_| FAILED)
                    }
                    7 | 9 => Ok((0, 0)),
                    6 => {
                        out[..32].fill(42);
                        Ok((32, 0))
                    }
                    _ => Err(FAILED),
                },
                _ => Err(FAILED),
            }
        })
    }
    pub fn entropy(out: &mut [u8]) -> Result<(), u64> {
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let i = c.node;
            if out.len() == 16 && c.nodes[i].fail_nonce_once {
                c.nodes[i].fail_nonce_once = false;
                return Err(cyxia_prototype_cluster::abi::FAILED);
            }
            c.nodes[i].entropy += 1;
            out.fill(c.nodes[i].entropy + 10 * i as u8);
            Ok(())
        })
    }
    pub fn poll() -> Result<(bool, u64), u64> {
        Ok((true, CTX.with(|c| { let c = c.borrow(); c.nodes[c.node].transport_epoch.max(1) })))
    }
    pub fn service_generation() -> u64 { 7 }
    pub fn time() -> Option<(u64, u64)> {
        Some(CTX.with(|c| {
            let c = c.borrow();
            let n = &c.nodes[c.node];
            (
                c.now
                    + if n.expire_after_stage && !n.input.is_empty() {
                        60001
                    } else {
                        0
                    },
                1_700_000_000,
            )
        }))
    }
    pub fn trace(e: u64) {
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let i = c.node;
            c.nodes[i].traces.push(e)
        })
    }
}
fn identity(seed: u8) -> (IdentitySigner, [u8; 32], [u8; 32]) {
    let seed = [seed; 32];
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
    let mut der = vec![
        0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
    ];
    der.extend_from_slice(&seed);
    let signer = IdentitySigner::new(&der, public).unwrap();
    let node = ring::digest::digest(&ring::digest::SHA256, &public)
        .as_ref()
        .try_into()
        .unwrap();
    (signer, public, node)
}
fn select(i: usize, now: u64) {
    CTX.with(|c| {
        let mut c = c.borrow_mut();
        c.node = i;
        c.now = now;
    })
}
fn native_setup(boot: u64) -> (driver::Driver, driver::Driver) {
    use cyxia_prototype::domains::platform::PlacementQueue;
    let (sa, pa, na) = identity(1);
    let (sb, pb, nb) = identity(2);
    select(0, 0);
    let a = driver::Driver::new_native(
        boot,
        [1; 16],
        na,
        nb,
        sa,
        pb,
        Box::leak(Box::new(PlacementQueue::new())),
    )
    .unwrap();
    select(1, 0);
    let b = driver::Driver::new_native(
        boot,
        [2; 16],
        nb,
        na,
        sb,
        pa,
        Box::leak(Box::new(PlacementQueue::new())),
    )
    .unwrap();
    (a, b)
}
fn native_pair_turn(a: &mut driver::Driver, b: &mut driver::Driver, now: u64) {
    for (i, d) in [(0, &mut *a), (1, &mut *b)] {
        select(i, now); d.domain_tick(now * 1_000_000).unwrap(); d.tick(now).unwrap();
    }
    for from in 0..2 {
        let (source, target) = if from == 0 { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
        let bytes = source.outgoing().to_vec();
        if !bytes.is_empty() { source.consume_outgoing(bytes.len()); select(1 - from, now);
            assert_eq!(target.ingest(&bytes, now), Ok(bytes.len())); }
    }
}
fn connect_native(a: &mut driver::Driver, b: &mut driver::Driver) {
    select(0, 0); a.connect([51; 32], 0).unwrap(); select(1, 0); b.connect([52; 32], 0).unwrap();
}
fn replay_work(family: u16, id: u64) -> cyxia_prototype_cluster::replay_work::Work {
    cyxia_prototype_cluster::replay_work::Work { run: cyxia_prototype::learning::capture::RunKey { boot_epoch: 1, trial_id: 44, generation: 8 },
        id, family, kind: 1, arrived_ns: 0, deadline_ns: 9_000_000_000, seed: 7 }
}

#[test]
fn more_than_32_real_replay_remote_tasks_close_and_retire_only_persisted_started_proofs() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::abi::*;
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1);
        CTX.with(|c| { let mut c = c.borrow_mut();
            c.nodes[0].replay_requests = (1..=40).map(|id| replay_work(16, id)).collect();
            c.nodes[0].bind_busy = true;
            for n in &mut c.nodes { n.domains.offer = PolicyWire { version: 1, snapshot_ns: 0,
                installed_until_ns: 10_000_000_000, value: 250, plan_seq: 1, controller_epoch: 1, action_index: 0 }; }
        });
        connect_native(&mut a, &mut b);
        for at in 0..500 { native_pair_turn(&mut a, &mut b, at); }
        CTX.with(|c| { let mut c = c.borrow_mut();
            assert!(c.nodes[0].bind_calls > 0);
            assert_eq!(c.nodes[1].starts, 0, "unconfirmed signed binding cannot cause START");
            assert!(c.nodes[0].replay_results.is_empty());
            c.nodes[0].bind_busy = false;
        });
        for at in 500..8000 {
            native_pair_turn(&mut a, &mut b, at);
            if CTX.with(|c| c.borrow().nodes[0].replay_results.len() == 40) { break; }
        }
        CTX.with(|c| { let c = c.borrow(); let origin = &c.nodes[0];
            assert_eq!(origin.replay_results.len(), 40);
            assert_eq!(c.nodes[1].starts, 40, "one actual kernel admission per retained work identity");
            for (i, result) in origin.replay_results.iter().enumerate() {
                let word = |at| u64::from_le_bytes(result[at..at + 8].try_into().unwrap());
                assert_eq!(word(24), i as u64 + 1); assert_eq!(word(32), 1);
                assert_ne!(word(40), 0); assert_ne!(word(48), 0); assert!(word(64) >= word(56));
            }
            assert!(!c.nodes[1].reserved, "correct result is insufficient until the original contract closes");
        });
    }).unwrap().join().unwrap();
}

#[test]
fn application_custody_does_not_publish_completion_until_actual_local_result_and_close() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::abi::*;
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, _) = native_setup(1); enqueue_application(0, 1, 0);
        select(0, 0); a.domain_tick(0).unwrap();
        CTX.with(|c| { let mut c = c.borrow_mut(); let p = &mut c.nodes[0].domains;
            p.placement = PolicyWire { version: 1, snapshot_ns: 1_000_000, installed_until_ns: 0,
                value: 0, plan_seq: 1, controller_epoch: 1, action_index: 0 };
            p.placement_request_id = 4097; p.placement_request_generation = 1;
        });
        for at in 1..20 { select(0, at); a.domain_tick(at * 1_000_000).unwrap(); }
        CTX.with(|c| { let mut c = c.borrow_mut(); let n = &mut c.nodes[0];
            assert_eq!(n.application_status[0].state, cyxia_prototype_cluster::application::LOCAL);
            assert!(n.application_completions.is_empty(), "Created has no terminal EL0 result");
            assert_eq!(n.local_submits, 1);
            n.local_results.push((n.local_requests[0].0, 26, 20_000_000));
        });
        for at in 20..25 { select(0, at); a.domain_tick(at * 1_000_000).unwrap(); }
        CTX.with(|c| { let c = c.borrow(); let n = &c.nodes[0];
            assert_eq!(n.application_completions.len(), 1); let value = n.application_completions[0];
            assert_eq!((value.outcome, value.value, value.finished_ns, value.closed), (1, 26, 20_000_000, 1));
            assert_eq!(n.local_submits, 1);
        });
    }).unwrap().join().unwrap();
}

#[test]
fn status_replay_waits_for_its_ordinary_correlated_snapshot_not_membership_heartbeats() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype::cluster::wire::Header;
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1); connect_native(&mut a, &mut b);
        for at in 0..100 { native_pair_turn(&mut a, &mut b, at); }
        CTX.with(|c| c.borrow_mut().nodes[0].replay_requests.push(replay_work(10, 1)));
        for at in 100..110 {
            select(0, at); a.domain_tick(at * 1_000_000).unwrap(); a.tick(at).unwrap();
            let bytes = a.outgoing().to_vec(); a.consume_outgoing(bytes.len());
            select(1, at); if !bytes.is_empty() { b.ingest(&bytes, at).unwrap(); }
            b.domain_tick(at * 1_000_000).unwrap(); b.tick(at).unwrap();
        }
        let bytes = b.outgoing().to_vec(); let mut offset = 0; let mut matched = false;
        while offset < bytes.len() { let h = Header::decode(&bytes[offset..offset + 96]).unwrap();
            if h.kind == 0x8031 { matched = true; assert!(!cyxia_prototype_cluster::domain_ingress::reserved_rpc(h.kind)); }
            offset += 96 + h.body_len as usize;
        }
        assert!(matched); CTX.with(|c| assert!(c.borrow().nodes[0].replay_results.is_empty()));
        b.consume_outgoing(bytes.len()); select(0, 110); a.ingest(&bytes, 110).unwrap();
        for at in 111..120 { native_pair_turn(&mut a, &mut b, at); }
        CTX.with(|c| { let c = c.borrow(); assert_eq!(c.nodes[0].replay_results.len(), 1);
            assert_eq!(u64::from_le_bytes(c.nodes[0].replay_results[0][32..40].try_into().unwrap()), 1); });
    }).unwrap().join().unwrap();
}

#[test]
fn reconnect_work_requires_new_authenticated_epoch_and_retains_unknown_past_deadline() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1); connect_native(&mut a, &mut b);
        for at in 0..100 { native_pair_turn(&mut a, &mut b, at); }
        CTX.with(|c| c.borrow_mut().nodes[0].replay_requests.push(replay_work(12, 1)));
        native_pair_turn(&mut a, &mut b, 100);
        assert!(!a.replay_wants_reconnect(0));
        assert!(a.replay_wants_reconnect(1)); assert!(!a.replay_wants_reconnect(1));
        select(0, 101); a.disconnect(); select(1, 101); b.disconnect();
        for at in [200, 1000, 9500] {
            select(0, at); a.offline_tick(at).unwrap();
            a.replay_authenticated(1, at * 1_000_000); a.replay_authenticated(0, at * 1_000_000);
            CTX.with(|c| assert!(c.borrow().nodes[0].replay_results.is_empty(),
                "elapsed time, disconnect and the old authenticated epoch cannot settle reauthentication"));
        }
        CTX.with(|c| { let mut c = c.borrow_mut(); for n in &mut c.nodes { n.transport_epoch = 2; } });
        select(0, 9501); a.connect([61; 32], 9501).unwrap();
        select(1, 9501); b.connect([62; 32], 9501).unwrap();
        // Runtime reaches this callback only after the real TLS handshake and
        // TlsIngress accepted the newly authenticated identity. The separate
        // domain_transport tests exercise that actual TLS/ingress boundary.
        select(0, 9501); a.replay_authenticated(2, 9_501_000_000);
        for at in 9501..9520 { native_pair_turn(&mut a, &mut b, at); }
        CTX.with(|c| { let c = c.borrow(); let results = &c.nodes[0].replay_results;
            assert_eq!(results.len(), 1);
            let value = |at| u64::from_le_bytes(results[0][at..at + 8].try_into().unwrap());
            assert_eq!((value(24), value(32), value(48), value(64)), (1, 1, 2, 9_501_000_000));
        });
    }).unwrap().join().unwrap();
}
fn enqueue_application(node: usize, sequence: u64, submitted_ns: u64) -> Vec<u8> {
    use cyxia_prototype::domains::ObjectKey;
    use cyxia_prototype_cluster::application::Submission;
    let input: Vec<_> = [3i64, 5, 7, 11].into_iter().flat_map(i64::to_le_bytes).collect();
    let submission = Submission { actor: ObjectKey { id: 81 + node as u64, generation: 3 },
        sequence, key: ObjectKey { id: 4096 + sequence, generation: 1 }, submitted_ns,
        input: &input };
    let mut bytes = vec![0; 4096];
    let n = submission.encode(&mut bytes).unwrap();
    bytes.truncate(n);
    CTX.with(|c| c.borrow_mut().nodes[node].application_requests.push(bytes.clone()));
    bytes
}

#[test]
fn application_handoff_lost_commit_and_ack_keep_one_durable_local_execution() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::{abi::*, application as wire, application_journal};
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, b) = native_setup(1);
        let original = enqueue_application(0, 1, 0);
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            c.nodes[0].lose_application_commit = true;
            c.nodes[0].lose_application_ack = true;
        });
        for now in 0..5 {
            select(0, now);
            a.domain_tick(now * 1_000_000).unwrap();
        }
        CTX.with(|c| {
            let c = c.borrow();
            let n = &c.nodes[0];
            assert_eq!(n.local_submits, 0);
            assert_eq!(n.application_status[0].state, wire::PENDING);
            let records: Vec<_> = n.records.iter().filter_map(|b| application_journal::Record::decode(b).ok()).collect();
            assert_eq!(records.len(), 1, "lost commit reply cannot reappend the original application");
            assert_eq!(records[0].actor.id, 81);
            assert_eq!(records[0].sequence, 1);
            assert_eq!(records[0].key.generation, 1);
        });
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let d = &mut c.nodes[0].domains;
            d.placement = PolicyWire { version: 2, snapshot_ns: 2_000_000_000,
                installed_until_ns: 0, value: 0, plan_seq: 2, controller_epoch: 1, action_index: 0 };
            d.placement_request_id = 4097;
            d.placement_request_generation = 1;
        });
        select(0, 2000);
        a.domain_tick(2_000_000_000).unwrap();
        let receipt = a.domain_feedback(2_000_000_000).placement;
        assert_eq!((receipt.outcome, receipt.actual), (DOMAIN_APPLIED, 0));
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            let n = &mut c.nodes[0];
            assert_eq!(n.application_status[0].state, wire::LOCAL);
            assert_ne!(n.application_status[0].target.id, 0);
            assert_eq!(n.local_submits, 1);
            n.application_requests.push(original);
        });
        select(0, 2001);
        a.domain_tick(2_001_000_000).unwrap();
        drop(a); drop(b);
        let (mut recovered, _) = native_setup(2);
        select(0, 0);
        recovered.domain_tick(0).unwrap();
        CTX.with(|c| {
            let c = c.borrow();
            assert_eq!(c.nodes[0].local_submits, 1, "duplicate transport or reboot must only query custody");
            assert_eq!(c.nodes[0].records.iter().filter(|b| b.starts_with(application_journal::MAGIC)).count(), 1);
        });
    }).unwrap().join().unwrap();
}

#[test]
fn non_retryable_status_reply_keeps_native_custody_and_retries_the_same_real_result() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::{abi::*, application as wire, application_journal};
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, _) = native_setup(1);
        let original = enqueue_application(0, 1, 0);
        select(0, 0); a.domain_tick(0).unwrap();
        assert_eq!(a.domain_feedback(0).pending_placements, 1);
        CTX.with(|c| {
            let mut c = c.borrow_mut(); let n = &mut c.nodes[0];
            assert_eq!(n.application_status[0].state, wire::PENDING);
            n.domains.placement = PolicyWire { version: 1, snapshot_ns: 1_000_000,
                installed_until_ns: 0, value: 0, plan_seq: 1, controller_epoch: 1, action_index: 0 };
            n.domains.placement_request_id = 4097; n.domains.placement_request_generation = 1;
            // The terminal value exists only after native.queue.poll inside
            // domain_tick has taken NativeDomains out of the Driver.
            n.fail_terminal_application_status_once = true;
        });
        select(0, 1); assert_eq!(a.domain_tick(1_000_000), Err(()));
        let retained = a.domain_feedback(1_000_000).placement;
        assert_eq!((retained.version, retained.outcome, retained.actual), (1, DOMAIN_APPLIED, 0));
        CTX.with(|c| {
            let mut c = c.borrow_mut(); let n = &mut c.nodes[0];
            assert_eq!(n.local_submits, 1); assert!(!n.fail_terminal_application_status_once);
            assert_eq!(n.application_status[0].state, wire::PENDING);
            assert!(n.application_completions.is_empty());
            n.local_results.push((n.local_requests[0].0, 26, 2_000_000));
            n.application_requests.push(original);
        });
        for at in 2..7 { select(0, at); a.domain_tick(at * 1_000_000).unwrap(); }
        CTX.with(|c| {
            let c = c.borrow(); let n = &c.nodes[0];
            assert_eq!(n.local_submits, 1, "retained execution is reconciled, never re-submitted");
            assert_eq!(n.records.iter().filter(|r| r.starts_with(application_journal::MAGIC)).count(), 1);
            assert_eq!(n.application_status[0].state, wire::LOCAL);
            assert_eq!(n.application_completions.len(), 1);
            let result = n.application_completions[0];
            assert_eq!((result.key.id, result.outcome, result.value, result.finished_ns, result.closed), (4097, 1, 26, 2_000_000, 1));
        });
    }).unwrap().join().unwrap();
}

#[test]
fn application_deadline_starts_at_submission_not_delayed_service_handoff() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::application as wire;
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, _) = native_setup(1);
        enqueue_application(0, 1, 0);
        select(0, 3999);
        a.domain_tick(3_999_000_000).unwrap();
        CTX.with(|c| assert_eq!(c.borrow().nodes[0].local_submits, 0));
        assert_eq!(a.domain_feedback(3_999_000_000).waiting[0].queued_us, 3_999_000);
        select(0, 4000);
        a.domain_tick(4_000_000_000).unwrap();
        CTX.with(|c| {
            let c = c.borrow();
            assert_eq!(c.nodes[0].local_submits, 1);
            assert_eq!(c.nodes[0].application_status[0].state, wire::LOCAL);
        });
        assert_eq!(a.domain_feedback(4_000_000_000).placement_fallbacks, 1);
    }).unwrap().join().unwrap();
}

#[test]
fn four_ordinary_requests_fall_back_without_policy_after_durable_native_store_handoff() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype::domains::platform::{PlacementChoice, PlacementOutcome};
        use cyxia_prototype_cluster::{application as wire, application_journal, domain_placement};
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1);
        let mut originals = [Vec::new(), Vec::new()];
        for (node, submissions) in originals.iter_mut().enumerate() {
            for sequence in 1..=4 {
                submissions.push(enqueue_application(node, sequence, 1_000_000_000));
            }
        }
        for at in 1000..1004 {
            for (node, driver) in [(0, &mut a), (1, &mut b)] {
                select(node, at);
                driver.domain_tick(at * 1_000_000).unwrap();
            }
        }
        for (node, driver) in [(0, &mut a), (1, &mut b)] {
            select(node, 4999);
            driver.domain_tick(4_999_000_000).unwrap();
            let feedback = driver.domain_feedback(4_999_000_000);
            assert_eq!(feedback.pending_placements, 4, "all original inputs reached the queue");
            assert_eq!(feedback.placement.version, 0, "no model policy was installed");
            for waiting in &feedback.waiting[..4] {
                assert_eq!(waiting.queued_us, 3_999_000);
            }
        }
        CTX.with(|c| {
            let c = c.borrow();
            for n in &c.nodes {
                assert_eq!(n.local_submits, 0, "fallback cannot run before its original 4 s deadline");
                assert!(n.application_requests.is_empty());
                assert_eq!(n.application_status.len(), 4);
                assert!(n.application_status.iter().all(|s| s.state == wire::PENDING));
                let inputs: Vec<_> = n.records.iter()
                    .filter_map(|r| application_journal::Record::decode(r).ok()).collect();
                assert_eq!(inputs.len(), 4);
                assert!(inputs.iter().all(|r| r.submitted_ns == 1_000_000_000));
                assert!(!n.records.iter().any(|r| r.starts_with(domain_placement::MAGIC)));
            }
        });
        for at in 5000..5010 {
            for (node, driver) in [(0, &mut a), (1, &mut b)] {
                select(node, at);
                driver.domain_tick(at * 1_000_000).unwrap();
            }
        }
        for driver in [&a, &b] {
            let feedback = driver.domain_feedback(5_009_000_000);
            assert_eq!((feedback.pending_placements, feedback.placement_fallbacks), (0, 4));
            assert_eq!(feedback.placement.version, 0);
        }
        CTX.with(|c| {
            let c = c.borrow();
            for n in &c.nodes {
                assert_eq!(n.local_submits, 4);
                assert_eq!(n.local_requests.len(), 4);
                assert!(n.application_status.iter().all(|s| s.state == wire::LOCAL
                    && s.target.id != 0 && s.target.generation != 0));
                assert!(n.application_completions.is_empty(), "custody is not a fabricated task exit");
                let records: Vec<_> = n.records.iter()
                    .filter_map(|r| domain_placement::decode(r).ok()).collect();
                assert_eq!(records.len(), 8, "one durable intent and receipt per original request");
                for sequence in 1..=4 {
                    let id = 4096 + sequence;
                    assert_eq!(records.iter().filter(|r| matches!(r,
                        domain_placement::Record::Intent(i, _)
                            if i.request.key.id == id && i.apply.is_none()
                                && i.choice == PlacementChoice::Local
                                && i.decided_ns == 5_000_000_000)).count(), 1);
                    assert_eq!(records.iter().filter(|r| matches!(r,
                        domain_placement::Record::Receipt(i, PlacementOutcome::Local(_))
                            if i.request.key.id == id && i.apply.is_none())).count(), 1);
                }
            }
        });
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            for (node, submissions) in originals.into_iter().enumerate() {
                c.nodes[node].application_requests.extend(submissions);
            }
        });
        for at in 5100..5110 {
            for (node, driver) in [(0, &mut a), (1, &mut b)] {
                select(node, at);
                driver.domain_tick(at * 1_000_000).unwrap();
            }
        }
        drop(a);
        drop(b);
        let (mut a, mut b) = native_setup(2);
        for (node, driver) in [(0, &mut a), (1, &mut b)] {
            select(node, 0);
            driver.domain_tick(0).unwrap();
        }
        CTX.with(|c| {
            let c = c.borrow();
            for n in &c.nodes {
                assert_eq!(n.local_submits, 4, "recovery queries the same custody instead of resubmitting");
                assert!(n.application_requests.is_empty());
                assert_eq!(n.records.iter().filter(|r| r.starts_with(application_journal::MAGIC)).count(), 4);
                assert_eq!(n.records.iter().filter(|r| r.starts_with(domain_placement::MAGIC)).count(), 8);
            }
        });
    }).unwrap().join().unwrap();
}
#[test]
fn local_pre_admission_busy_retries_one_durable_intent_but_recovery_never_readmits() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype_cluster::{application as wire, domain_placement as journal};
        use cyxia_prototype::domains::platform::PlacementOutcome;
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1);
        for node in 0..2 { enqueue_application(node, 1, 1_000_000_000); }
        for (node, driver) in [(0, &mut a), (1, &mut b)] {
            select(node, 1000);
            driver.domain_tick(1_000_000_000).unwrap();
        }
        CTX.with(|c| { let mut c = c.borrow_mut(); for n in &mut c.nodes { n.local_again = 3; } });
        for at in 5000..5003 {
            for (node, driver) in [(0, &mut a), (1, &mut b)] {
                select(node, at); driver.domain_tick(at * 1_000_000).unwrap();
            }
            CTX.with(|c| {
                let c = c.borrow();
                for n in &c.nodes {
                    assert_eq!(n.local_submits, 0);
                    assert_eq!(n.application_status[0].state, wire::UNKNOWN,
                        "a broker's explicit no-custody AGAIN must not become REJECTED");
                    assert_eq!(n.records.iter().filter_map(|r| journal::decode(r).ok())
                        .filter(|r| matches!(r, journal::Record::Intent(_, _))).count(), 1);
                    assert!(!n.records.iter().filter_map(|r| journal::decode(r).ok())
                        .any(|r| matches!(r, journal::Record::Receipt(_, _))));
                }
            });
        }
        // Node 0 now accepts once. Node 1 reboots while its persisted intent
        // has no known admission result; recovery must query, never resubmit.
        select(0, 5003); a.domain_tick(5_003_000_000).unwrap();
        CTX.with(|c| {
            let c = c.borrow(); let n = &c.nodes[0];
            assert_eq!((n.local_attempts, n.local_submits), (4, 1));
            assert_eq!(n.application_status[0].state, wire::LOCAL);
            let records: Vec<_> = n.records.iter().filter_map(|r| journal::decode(r).ok()).collect();
            assert_eq!(records.len(), 2);
            for record in records {
                let intent = match record {
                    journal::Record::Intent(intent, _) => intent,
                    journal::Record::Receipt(intent, PlacementOutcome::Local(_)) => intent,
                    _ => panic!("unexpected terminal rejection"),
                };
                assert_eq!(intent.decided_ns, 5_000_000_000);
                assert_eq!(intent.request.key.id, 4097);
            }
        });
        drop(a); drop(b);
        let (mut a, mut b) = native_setup(2);
        for at in 0..4 {
            for (node, driver) in [(0, &mut a), (1, &mut b)] {
                select(node, at); driver.domain_tick(at * 1_000_000).unwrap();
            }
        }
        CTX.with(|c| {
            let c = c.borrow();
            assert_eq!((c.nodes[0].local_attempts, c.nodes[0].local_submits), (4, 1));
            assert_eq!((c.nodes[1].local_attempts, c.nodes[1].local_submits), (3, 0));
            assert_eq!(c.nodes[1].application_status[0].state, wire::UNKNOWN);
        });
    }).unwrap().join().unwrap();
}

#[test]
fn native_local_fallback_is_durable_and_reboot_does_not_submit_again() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            CTX.with(|c| *c.borrow_mut() = Context::default());
            let (mut a, mut b) = native_setup(1);
            for ms in [0u64, 3999, 4000, 4001, 5000] {
                select(0, ms);
                a.domain_tick(ms * 1_000_000).unwrap();
                select(1, ms);
                b.domain_tick(ms * 1_000_000).unwrap();
            }
            CTX.with(|c| {
                let c = c.borrow();
                assert_eq!(c.nodes.iter().map(|n| n.local_submits).sum::<usize>(), 1);
                assert_eq!(
                    c.nodes
                        .iter()
                        .flat_map(|n| &n.records)
                        .filter(|b| b.starts_with(b"CXDP2"))
                        .count(),
                    2
                );
            });
            assert_eq!(
                a.domain_feedback(5_000_000_000).pending_placements
                    + b.domain_feedback(5_000_000_000).pending_placements,
                0
            );
            drop(a);
            drop(b);
            let (mut a, mut b) = native_setup(2);
            select(0, 0);
            a.domain_tick(0).unwrap();
            select(1, 0);
            b.domain_tick(0).unwrap();
            CTX.with(|c| {
                assert_eq!(
                    c.borrow()
                        .nodes
                        .iter()
                        .map(|n| n.local_submits)
                        .sum::<usize>(),
                    1
                )
            });
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn native_peer_selection_uses_real_quote_and_actual_started_custody() {
    native_peer_selection(false, false, false);
}
#[test]
fn native_peer_selection_rejects_leased_policy_before_a_fresh_zero_lease_invocation() {
    native_peer_selection(true, false, false);
}
#[test]
fn application_remote_selection_delivers_actual_started_contract_to_original_caller() {
    native_peer_selection(false, true, false);
}
#[test]
fn stopping_new_quotes_preserves_an_unexpired_real_issued_quote_for_started_custody() {
    native_peer_selection(false, true, true);
}
#[test]
fn real_driver_sends_busy_after_stop_and_only_new_offer_version_resumes_quotes() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        use cyxia_prototype::{cluster::wire::Header, domains::Action};
        use cyxia_prototype_cluster::{abi::*, domain_placement::QuoteWire};
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = native_setup(1);
        CTX.with(|c| { for n in &mut c.borrow_mut().nodes {
            n.domains.offer = PolicyWire { version: 1, snapshot_ns: 0,
                installed_until_ns: 10_000_000_000, value: 100, plan_seq: 1,
                controller_epoch: 1, action_index: 0 };
        }});
        select(0, 0); a.connect([31; 32], 0).unwrap();
        select(1, 0); b.connect([32; 32], 0).unwrap();
        let mut positive_before = 0;
        let mut busy = 0;
        let mut positive_after = 0;
        let mut actual_stop = None;
        for now in 0u64..600 {
            if now == 150 {
                CTX.with(|c| c.borrow_mut().nodes[0].domains.quote_stop = QuoteStopWire {
                    boot_epoch: 1, replay_id: 21, owner_id: 42, owner_generation: 1,
                    sequence: 1, issued_ns: now * 1_000_000 });
            }
            if now == 350 {
                CTX.with(|c| {
                    let mut c = c.borrow_mut();
                    let p = &mut c.nodes[0].domains.offer;
                    p.version = 2; p.plan_seq = 2; p.snapshot_ns = now * 1_000_000;
                    p.installed_until_ns = p.snapshot_ns + 10_000_000_000;
                });
            }
            for (i, driver) in [(0, &mut a), (1, &mut b)] {
                select(i, now);
                driver.domain_tick(now * 1_000_000).unwrap();
                driver.tick(now).unwrap();
            }
            let f = a.domain_feedback(now * 1_000_000);
            if now == 150 { actual_stop = Some(f.quote_stop); }
            if now >= 150 {
                assert_eq!(f.quote_stop, actual_stop.unwrap(), "polling and resumption preserve exact historical receipt");
                assert_eq!(f.quote_stop.outcome, DOMAIN_APPLIED);
                assert_eq!(f.quotes_stopped, u64::from(now < 350));
            }
            for from in 0..2 {
                let (src, dst) = if from == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
                let data = src.outgoing().to_vec();
                let mut at = 0;
                while at < data.len() {
                    let h = Header::decode(&data[at..at + 96]).unwrap();
                    let end = at + 96 + h.body_len as usize;
                    if from == 0 && h.kind == 0x8010 {
                        let q = QuoteWire::decode(&data[at + 96..end]).unwrap();
                        if now < 150 { assert_eq!(q.status, 0); positive_before += 1; }
                        else if now < 350 {
                            assert_eq!(q.status, 1, "actual QUOTE reply must say Busy while stopped");
                            assert_eq!((q.cpu_milli, q.memory_pages, q.remaining_ms, q.offer_seq), (0, 0, 0, 0));
                            busy += 1;
                        } else { assert_eq!(q.status, 0); positive_after += 1; }
                    }
                    at = end;
                }
                if !data.is_empty() {
                    src.consume_outgoing(data.len());
                    select(1 - from, now);
                    assert_eq!(dst.ingest(&data, now), Ok(data.len()));
                }
            }
        }
        assert!(positive_before > 0 && busy > 0 && positive_after > 0);
        assert_eq!(a.domain_feedback(600_000_000).offer.version, 2);
        assert_eq!(a.domain_feedback(600_000_000).offer.outcome, DOMAIN_APPLIED);
        assert!(Action::OfferCpu(0).validate().is_err());
    }).unwrap().join().unwrap();
}
fn native_peer_selection(reject_nonzero_lease: bool, application: bool, stop_quotes: bool) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            use cyxia_prototype_cluster::abi::*;
            CTX.with(|c| *c.borrow_mut() = Context::default());
            let (mut a, mut b) = native_setup(1);
            if application {
                enqueue_application(0, 1, 0);
                enqueue_application(1, 1, 0);
            }
            CTX.with(|c| {
                for n in &mut c.borrow_mut().nodes {
                    n.domains.offer = PolicyWire {
                        version: 1,
                        snapshot_ns: 0,
                        installed_until_ns: 10_000_000_000,
                        value: 250,
                        plan_seq: 1,
                        controller_epoch: 1,
                        action_index: 0,
                    };
                }
            });
            select(0, 0);
            a.connect([31; 32], 0).unwrap();
            select(1, 0);
            b.connect([32; 32], 0).unwrap();
            let mut selected = None;
            let mut rejected_turns = 0;
            for now in 0u64..2000 {
                for (i, driver) in [(0, &mut a), (1, &mut b)] {
                    select(i, now);
                    driver.domain_tick(now * 1_000_000).unwrap();
                    driver.tick(now).unwrap();
                    let f = driver.domain_feedback(now * 1_000_000);
                    if selected.is_none() && f.waiting[0].peer_ready == 1 {
                        assert_eq!(f.peer_cpu_milli, 100);
                        assert_eq!(f.peer_memory_pages, 16);
                        CTX.with(|c| {
                            let mut c = c.borrow_mut();
                            let d = &mut c.nodes[i].domains;
                            d.placement = PolicyWire {
                                version: 2,
                                snapshot_ns: now * 1_000_000,
                                // A placement is one invocation, so its wire
                                // lease is zero even though the offer is leased.
                                installed_until_ns: if reject_nonzero_lease {
                                    now * 1_000_000 + 10_000_000_000
                                } else {
                                    0
                                },
                                value: 1,
                                plan_seq: 2,
                                controller_epoch: 1,
                                action_index: 0,
                            };
                            d.placement_request_id = f.waiting[0].request_id;
                            d.placement_request_generation = f.waiting[0].request_generation;
                            if stop_quotes {
                                c.nodes[1 - i].domains.quote_stop = QuoteStopWire { boot_epoch: 1,
                                    replay_id: 19, owner_id: 42, owner_generation: 1, sequence: 1,
                                    issued_ns: now * 1_000_000 };
                            }
                        });
                        selected = Some(i);
                    } else if reject_nonzero_lease && selected == Some(i) && rejected_turns < 3 {
                        assert_eq!(f.placement.version, 2);
                        assert_eq!(f.placement.plan_seq, 2);
                        assert_eq!(f.placement.outcome, DOMAIN_REJECTED);
                        assert!(f.waiting.iter().any(|request| {
                            request.request_id == f.placement.request_id
                                && request.request_generation == f.placement.request_generation
                        }));
                        CTX.with(|c| {
                            let c = c.borrow();
                            // Drive the real queue and both protocol endpoints
                            // for repeated rejected turns: no task may acquire
                            // execution custody, including through LOCAL fallback.
                            assert!(c.nodes.iter().all(|n| !n.reserved));
                            assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 0);
                            assert_eq!(c.nodes.iter().map(|n| n.local_submits).sum::<usize>(), 0);
                            assert!(
                                !c.nodes.iter().flat_map(|n| &n.records)
                                    .any(|record| record.starts_with(b"CXDP2"))
                            );
                        });
                        rejected_turns += 1;
                        if rejected_turns == 3 {
                            CTX.with(|c| {
                                let mut c = c.borrow_mut();
                                let p = &mut c.nodes[i].domains.placement;
                                p.version = 3;
                                p.plan_seq = 3;
                                p.snapshot_ns = now * 1_000_000;
                                p.installed_until_ns = 0;
                            });
                        }
                    }
                }
                for from in 0..2 {
                    let (src, dst) = if from == 0 {
                        (&mut a, &mut b)
                    } else {
                        (&mut b, &mut a)
                    };
                    let n = src.outgoing().len().min(251);
                    if n > 0 {
                        let data = src.outgoing()[..n].to_vec();
                        src.consume_outgoing(n);
                        select(1 - from, now);
                        assert_eq!(dst.ingest(&data, now), Ok(n), "turn {now} from {from}");
                    }
                }
                if selected.is_some_and(|i| {
                    [
                        a.domain_feedback(now * 1_000_000),
                        b.domain_feedback(now * 1_000_000),
                    ][i]
                        .placement
                        .outcome
                        == DOMAIN_APPLIED
                }) {
                    break;
                }
            }
            let i = selected.expect("a capacity-backed peer quote must become eligible");
            let feedback = [
                a.domain_feedback(2_000_000_000),
                b.domain_feedback(2_000_000_000),
            ];
            assert_eq!(rejected_turns, if reject_nonzero_lease { 3 } else { 0 });
            assert_eq!(
                feedback[i].placement.version,
                if reject_nonzero_lease { 3 } else { 2 }
            );
            assert_eq!(feedback[i].placement.plan_seq, feedback[i].placement.version);
            assert_eq!(feedback[i].placement.outcome, DOMAIN_APPLIED);
            assert_eq!(feedback[i].placement.actual, 1);
            assert_eq!(feedback[1 - i].offer.outcome, DOMAIN_APPLIED);
            assert_eq!(feedback[1 - i].offer.actual, 100);
            if stop_quotes {
                assert_eq!(feedback[1 - i].quote_stop.outcome, DOMAIN_APPLIED);
                assert_eq!(feedback[1 - i].quote_stop.command.replay_id, 19);
                assert_eq!(feedback[1 - i].quotes_stopped, 1);
            }
            CTX.with(|c| {
                let c = c.borrow();
                assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 1);
                assert_eq!(c.nodes.iter().map(|n| n.local_submits).sum::<usize>(), 0);
                if application {
                    use cyxia_prototype_cluster::application as wire;
                    let outcome = c.nodes[i].application_status.iter().find(|s| s.key.id == 4097).unwrap();
                    assert_eq!(outcome.state, wire::REMOTE);
                    assert_ne!(outcome.target.id, 0);
                    assert_ne!(outcome.target.generation, 0);
                    assert_eq!(outcome.key.generation, 1);
                }
            });
        })
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn real_signed_two_driver_streams_form_and_persist_unique_result_custody() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (sa, pa, na) = identity(1);
    let (sb, pb, nb) = identity(2);
    select(0, 0);
    let mut a = driver::Driver::new(1, [1; 16], na, nb, sa, pb).unwrap();
    select(1, 0);
    let mut b = driver::Driver::new(1, [2; 16], nb, na, sb, pa).unwrap();
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    for step in 0..2000 {
        let now = step as u64;
        select(0, now);
        a.tick(now).unwrap();
        select(1, now);
        b.tick(now).unwrap();
        for from in 0..2 {
            let (src, dst) = if from == 0 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            let n = src.outgoing().len().min(1 + step % 47);
            if n != 0 {
                let bytes = src.outgoing()[..n].to_vec();
                src.consume_outgoing(n);
                select(1 - from, now);
                assert_eq!(
                    dst.ingest(&bytes, now),
                    Ok(n),
                    "step {step}, from {from}, traces {:?}",
                    CTX.with(|c| [
                        c.borrow().nodes[0].traces.clone(),
                        c.borrow().nodes[1].traces.clone()
                    ])
                );
            }
        }
        let closed = CTX.with(|c| c.borrow().nodes.iter().all(|n| n.traces.contains(&0x219)));
        if closed {
            break;
        }
    }
    CTX.with(|c| {
        let c = c.borrow();
        assert!(
            c.nodes.iter().all(|n| n.traces.contains(&0x211)
                && n.traces.contains(&0x212)
                && n.traces.contains(&0x219)),
            "traces {:?} {:?}",
            c.nodes[0].traces,
            c.nodes[1].traces
        );
        assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 1);
        assert!(c.nodes.iter().any(|n| n.traces.contains(&0x216)));
        assert!(c.nodes.iter().any(|n| n.traces.contains(&0x217)));
        assert!(c.nodes.iter().all(|n| n.records.len() >= 5));
    });
}
fn setup(boot: u64) -> (driver::Driver, driver::Driver) {
    let (sa, _, na) = identity(1);
    let (sb, _, nb) = identity(2);
    let (_, pa, _) = identity(1);
    let (_, pb, _) = identity(2);
    select(0, 0);
    let a = driver::Driver::new(boot, [1; 16], na, nb, sa, pb).unwrap();
    select(1, 0);
    let b = driver::Driver::new(boot, [2; 16], nb, na, sb, pa).unwrap();
    (a, b)
}
fn has_trace(code: u64) -> bool {
    CTX.with(|c| c.borrow().nodes.iter().any(|n| n.traces.contains(&code)))
}
fn pump(a: &mut driver::Driver, b: &mut driver::Driver, base: u64, until: impl Fn() -> bool) {
    for step in 0..3000 {
        let now = base + step as u64;
        select(0, now);
        a.tick(now).unwrap();
        select(1, now);
        b.tick(now).unwrap();
        if until() {
            return;
        }
        for from in 0..2 {
            let (src, dst) = if from == 0 {
                (&mut *a, &mut *b)
            } else {
                (&mut *b, &mut *a)
            };
            let n = src.outgoing().len().min(97);
            if n > 0 {
                let bytes = src.outgoing()[..n].to_vec();
                src.consume_outgoing(n);
                select(1 - from, now);
                assert_eq!(
                    dst.ingest(&bytes, now),
                    Ok(n),
                    "base {base},step {step},from {from}, traces {:?}, exits {:?}",
                    CTX.with(|c| [
                        c.borrow().nodes[0].traces.clone(),
                        c.borrow().nodes[1].traces.clone()
                    ]),
                    CTX.with(|c| [c.borrow().nodes[0].exit_records.clone(), c.borrow().nodes[1].exit_records.clone()])
                );
            }
            if until() {
                return;
            }
        }
    }
    panic!(
        "pump timeout traces {:?}",
        CTX.with(|c| [
            c.borrow().nodes[0].traces.clone(),
            c.borrow().nodes[1].traces.clone()
        ])
    );
}
fn closed_both() -> bool {
    CTX.with(|c| c.borrow().nodes.iter().all(|n| n.traces.contains(&0x219)))
}

// These helpers transport genuine production frames. Only the transport's
// delivery order/chunk size and broker storage/clock boundary are controlled.
fn session_frames(d: &mut driver::Driver) -> Vec<Vec<u8>> {
    use cyxia_prototype::cluster::wire::Header;
    let bytes = d.outgoing().to_vec();
    d.consume_outgoing(bytes.len());
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let h = Header::decode(&bytes[at..at + 96]).unwrap();
        let end = at + 96 + h.body_len as usize;
        frames.push(bytes[at..end].to_vec());
        at = end;
    }
    frames
}

fn deliver_session_frames(
    d: &mut driver::Driver,
    node: usize,
    frames: &[Vec<u8>],
    now: u64,
    chunk: usize,
) {
    use cyxia_prototype::cluster::wire::Header;
    select(node, now);
    for frame in frames {
        let h = Header::decode(&frame[..96]).unwrap();
        for bytes in frame.chunks(chunk) {
            assert_eq!(
                d.ingest(bytes, now),
                Ok(bytes.len()),
                "node {node} rejected genuine kind {} sequence {} at {now}ms",
                h.kind,
                h.sequence
            );
        }
        if h.kind == 2 {
            assert_eq!(
                frame[96], 1,
                "heartbeat must not perform proofless reconciliation"
            );
        }
    }
}

fn durable_member_proof(node: usize) -> Option<Vec<u8>> {
    CTX.with(|c| {
        c.borrow().nodes[node]
            .records
            .iter()
            .rev()
            .find(|b| b.len() > 13 && b.starts_with(b"CXE1") && b[12] == 3)
            .map(|b| b[13..].to_vec())
    })
}

fn session_ready_both() -> bool {
    CTX.with(|c| c.borrow().nodes.iter().all(|n| n.traces.contains(&0x212)))
}

fn real_authority_pair() -> (driver::Driver, driver::Driver) {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        for n in &mut c.borrow_mut().nodes {
            n.authority = Some(cyxia_kernel_core::control_plane::task_admission::Authority::new());
        }
    });
    let (mut a, mut b) = native_setup(1);
    connect_native(&mut a, &mut b);
    (a, b)
}

#[test]
fn invalid_or_incomplete_rpc_and_outbound_ticks_do_not_renew_authority() {
    use cyxia_prototype::cluster::wire::Header;
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        for mutation in 0..15 {
            let (mut a, mut b) = real_authority_pair();
            let ha = session_frames(&mut a);
            let hb = session_frames(&mut b);
            deliver_session_frames(&mut b, 1, &ha, 400, 97);
            deliver_session_frames(&mut a, 0, &hb, 400, 97);
            let mut frame = ha[0].clone();
            let mut h = Header::decode(&frame[..96]).unwrap();
            h.sequence = 10;
            h.receiver_boot = 1;
            match mutation {
                0 => frame[96] ^= 1,
                1 => frame[128] ^= 1,
                2 => frame[160] ^= 1,
                3 => frame[168] ^= 1,
                4 => frame[176] ^= 1,
                5 => frame[208] = 1,
                6 => h.receiver_boot = 0,
                7 => h.sender_boot = 2,
                8 => h.cluster = [9; 32],
                9 => h.epoch = 1,
                10 => h.kind = 0x8001,
                11 => h.sequence = 1,
                12 => h.kind = 2,
                _ => {},
            }
            frame[..96].copy_from_slice(&h.encode());
            select(1, 1000);
            if mutation < 13 {
                assert_eq!(b.ingest(&frame, 1000), Err(()));
            } else if mutation == 13 {
                assert_eq!(b.ingest(&frame[..frame.len() - 1], 1000), Ok(frame.len() - 1));
            } else {
                b.tick(1000).unwrap();
                assert!(!b.outgoing().is_empty());
                b.consume_outgoing(b.outgoing().len());
                b.ingest(&[], 1000).unwrap();
            }
            CTX.with(|c| {
                let mut c = c.borrow_mut();
                assert!(c.nodes[1].authority.as_mut().unwrap().session(1, 2, 1900).is_err(),
                    "invalid/partial/outbound activity renewed authority: {mutation}");
                assert!(!c.nodes[1].traces.contains(&0x212));
            });
        }
    }).unwrap().join().unwrap();
}

// Both Drivers construct READY only after real signatures, durable BOUND and
// reconciliation. Hold it at the transport boundary, never mutate Engine state.
fn queued_real_ready(a: &mut driver::Driver, b: &mut driver::Driver) -> [Vec<Vec<u8>>; 2] {
    use cyxia_prototype::cluster::wire::Header;
    let mut held: [Vec<Vec<u8>>; 2] = Default::default();
    for _ in 0..12 {
        let frames = [session_frames(a), session_frames(b)];
        for (node, d) in [(0, &mut *a), (1, &mut *b)] {
            for frame in &frames[1 - node] {
                if !held[node].is_empty() || Header::decode(&frame[..96]).unwrap().kind == 6 {
                    held[node].push(frame.clone());
                } else { deliver_session_frames(d, node, &[frame.clone()], 0, 97); }
            }
        }
        if held.iter().all(|frames| !frames.is_empty()) { return held; }
    }
    panic!("genuine READY was never queued");
}

#[test]
fn stale_or_wrong_session_ready_and_changed_native_admission_never_publish_ready() {
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        for case in 0..7 {
            let (mut a, mut b) = real_authority_pair();
            let mut held = queued_real_ready(&mut a, &mut b);
            assert!(durable_member_proof(0).is_some());
            assert!(!session_ready_both());
            let now = if case == 0 { 1500 } else if case == 1 { 1501 } else { 1000 };
            if case == 2 { held[0][0][96] ^= 1; }
            CTX.with(|c| c.borrow_mut().nodes[0].session_wait = match case {
                3 => Some((3, 1500, true, 1)),
                4 => Some((3, 1000, false, 1)),
                5 => Some((3, 1000, true, 2)),
                6 => Some((2, 2500, true, 1)),
                _ => None,
            });
            select(0, now);
            assert_eq!(a.ingest(&held[0][0], now), Err(()), "case {case}");
            CTX.with(|c| {
                let mut c = c.borrow_mut();
                let n = &mut c.nodes[0];
                assert!(!n.traces.contains(&0x212), "failed promotion published READY");
                assert!(n.authority.as_mut().unwrap().session(1, 2, 2500).is_err());
            });
        }
    }).unwrap().join().unwrap();
}

// Missing accepted-RPC renewal expires real kernel authority despite each
// authenticated inter-message gap being shorter than the 1500ms deadline.
#[test]
fn live_authenticated_formation_over_1500ms_reaches_real_authority_ready() {
    use cyxia_kernel_core::control_plane::task_admission::Terms;
    std::thread::Builder::new().stack_size(16 * 1024 * 1024).spawn(|| {
        let (mut a, mut b) = real_authority_pair();
        for now in (400..=8000).step_by(400) {
            for (node, d) in [(0, &mut a), (1, &mut b)] {
                select(node, now);
                d.tick(now).unwrap();
            }
            let frames = [session_frames(&mut a), session_frames(&mut b)];
            for (node, d) in [(0, &mut a), (1, &mut b)] {
                CTX.with(|c| {
                    let mut c = c.borrow_mut();
                    let n = &mut c.nodes[node];
                    if !n.traces.contains(&0x212) {
                        assert!(n.authority.as_mut().unwrap().reserve(Terms {
                            cpu_milli: 100, memory_pages: 16, runtime_ms: 50,
                            contract: [1; 16], input_hash: [2; 32], package_hash: [3; 32],
                        }, [3; 32], now).is_err(), "pre-READY resource admission");
                    }
                });
                deliver_session_frames(d, node, &frames[1 - node], now, 97);
            }
            if session_ready_both() {
                assert!(now > 1500);
                let proof = durable_member_proof(0).expect("durable BOUND precedes READY");
                assert_eq!(durable_member_proof(1), Some(proof));
                CTX.with(|c| {
                    for n in &mut c.borrow_mut().nodes {
                        let authority = n.authority.as_mut().unwrap();
                        let token = authority.reserve(Terms {
                            cpu_milli: 100, memory_pages: 16, runtime_ms: 50,
                            contract: [1; 16], input_hash: [2; 32], package_hash: [3; 32],
                        }, [3; 32], now).expect("current-session READY grants real resource authority");
                        authority.release(token).unwrap();
                    }
                });
                let status_before = CTX.with(|c| core::array::from_fn::<_, 2, _>(|i|
                    c.borrow().nodes[i].traces.iter().filter(|e| **e == 0x10002).count()));
                for later in [now + 400, now + 800] {
                    native_pair_turn(&mut a, &mut b, later);
                }
                CTX.with(|c| {
                    for (i, n) in c.borrow().nodes.iter().enumerate() {
                        assert!(n.traces.iter().filter(|e| **e == 0x10002).count() > status_before[i],
                            "fixture did not deliver post-READY STATUS");
                        assert_eq!(n.traces.iter().filter(|e| **e == 0x212).count(), 1,
                            "ordinary accepted STATUS repeated native READY");
                    }
                });
                return;
            }
        }
        panic!("mutual READY never reached");
    }).unwrap().join().unwrap();
}

#[test]
fn forming_hello_heartbeat_only_refreshes_liveness_and_checks_frozen_identity() {
    use cyxia_prototype::cluster::wire::Header;
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            // Each malformed frame gets a fresh real session; rejected headers may
            // tear down the connection, so never rely on accepting one afterwards.
            for mutation in 0..14 {
                CTX.with(|c| *c.borrow_mut() = Context::default());
                let (mut a, mut b) = native_setup(1);
                connect_native(&mut a, &mut b);
                let ha = session_frames(&mut a);
                let hb = session_frames(&mut b);
                deliver_session_frames(&mut b, 1, &ha, 0, 97);
                deliver_session_frames(&mut a, 0, &hb, 0, 97);
                let mut frame = ha[0].clone();
                let mut h = Header::decode(&frame[..96]).unwrap();
                h.sequence = 10;
                h.receiver_boot = 1;
                match mutation {
                    1 => frame[96] ^= 1,  // NodeID
                    2 => frame[128] ^= 1, // challenge
                    3 => frame[160] ^= 1, // formation counter
                    4 => frame[168] ^= 1, // frozen epoch
                    5 => frame[176] ^= 1, // nonce
                    6 => frame[208] = 1,  // member
                    7 => h.receiver_boot = 0,
                    8 => h.sender_boot = 2,
                    9 => h.cluster = [9; 32],
                    10 => h.epoch = 1,
                    11 => h.kind = 0x8001,
                    12 => h.sequence = 1,
                    13 => h.kind = 2,
                    _ => {}
                }
                frame[..96].copy_from_slice(&h.encode());
                let before = CTX.with(|c| c.borrow().nodes[1].records.clone());
                let queued = b.outgoing().to_vec();
                select(1, 1000);
                if mutation == 0 {
                    assert_eq!(
                        b.ingest(&frame, 1000),
                        Ok(frame.len()),
                        "immutable forming HELLO is a liveness-only heartbeat"
                    );
                    assert_eq!(
                        b.outgoing(),
                        queued,
                        "heartbeat must not restart negotiation or send READY"
                    );
                    assert_eq!(CTX.with(|c| c.borrow().nodes[1].records.clone()), before);
                    assert!(!session_ready_both());
                    assert!(durable_member_proof(1).is_none());
                    select(1, 2499);
                    b.tick(2499).unwrap();
                    select(1, 2500);
                    assert_eq!(b.tick(2500), Err(()), "1500ms isolation is unchanged");
                } else {
                    assert_eq!(
                        b.ingest(&frame, 1000),
                        Err(()),
                        "mutation {mutation} must fail"
                    );
                    assert_eq!(CTX.with(|c| c.borrow().nodes[1].records.clone()), before);
                }
                CTX.with(|c| {
                    assert_eq!(c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>(), 0)
                });
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn delayed_formation_crosses_heartbeat_without_proofless_reconciliation() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            for first in [0, 1] {
                for hold_confirm in [false, true] {
                    CTX.with(|c| *c.borrow_mut() = Context::default());
                    let (mut a, mut b) = native_setup(1);
                    CTX.with(|c| {
                        c.borrow_mut().nodes[0]
                            .replay_requests
                            .push(replay_work(16, 1))
                    });
                    connect_native(&mut a, &mut b);
                    let hello_a = session_frames(&mut a);
                    let hello_b = session_frames(&mut b);
                    deliver_session_frames(&mut b, 1, &hello_a, 0, 97);
                    deliver_session_frames(&mut a, 0, &hello_b, 0, 97);
                    // Hold the genuine NEGOTIATE and every following frame in FIFO.
                    let mut held = [session_frames(&mut a), session_frames(&mut b)];
                    if hold_confirm {
                        let proposer = usize::from(held[0].is_empty());
                        let d = if proposer == 0 { &mut b } else { &mut a };
                        deliver_session_frames(d, 1 - proposer, &held[proposer], 0, 97);
                        held[proposer].clear();
                        held[1 - proposer].extend(session_frames(d));
                    }
                    for now in [499, 500, 999, 1000] {
                        for (node, d) in [(0, &mut a), (1, &mut b)] {
                            select(node, now);
                            d.tick(now).unwrap();
                            let frames = session_frames(d);
                            if now == 500 || now == 1000 {
                                assert!(
                                    !frames.is_empty(),
                                    "node {node} owes a 500ms forming heartbeat"
                                );
                            } else {
                                assert!(frames.is_empty(), "heartbeat must respect 500ms cadence");
                            }
                            held[node].extend(frames);
                        }
                    }
                    assert!(!session_ready_both());
                    CTX.with(|c| {
                        assert_eq!(c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>(), 0)
                    });
                    for from in [first, 1 - first] {
                        let d = if from == 0 { &mut b } else { &mut a };
                        deliver_session_frames(d, 1 - from, &held[from], 1100, 97);
                    }
                    pump(&mut a, &mut b, 1101, session_ready_both);
                    let proof =
                        durable_member_proof(0).expect("BOUND proof persisted before READY");
                    assert_eq!(durable_member_proof(1), Some(proof));
                    CTX.with(|c| {
                        assert!(c.borrow().nodes.iter().all(|n| n.exit_records.is_empty()))
                    });
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn forming_heartbeat_does_not_repeat_before_peer_hello_or_accept_initial_bound_or_leaving() {
    use cyxia_prototype::cluster::wire::Header;
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            CTX.with(|c| *c.borrow_mut() = Context::default());
            let (mut a, mut b) = native_setup(1);
            connect_native(&mut a, &mut b);
            session_frames(&mut a);
            for now in [500, 1000, 1499] {
                select(0, now);
                a.tick(now).unwrap();
                assert!(
                    a.outgoing().is_empty(),
                    "receiver boot is unknown until peer HELLO"
                );
            }
            select(0, 1500);
            assert_eq!(a.tick(1500), Err(()));
            for leaving in [false, true] {
                CTX.with(|c| *c.borrow_mut() = Context::default());
                let (mut a, mut b) = native_setup(1);
                connect_native(&mut a, &mut b);
                pump(&mut a, &mut b, 0, session_ready_both);
                if leaving {
                    select(0, 100);
                    a.begin_leave([7; 16]).unwrap();
                }
                drop(a);
                drop(b);
                let (mut a, mut b) = native_setup(2);
                connect_native(&mut a, &mut b);
                let hello = session_frames(&mut a);
                assert_eq!(hello[0][208], if leaving { 3 } else { 2 });
                deliver_session_frames(&mut b, 1, &hello, 0, 97);
                let mut repeat = hello[0].clone();
                let mut h = Header::decode(&repeat[..96]).unwrap();
                h.sequence = 2;
                h.receiver_boot = 2;
                h.cluster = [0; 32];
                h.epoch = 0;
                repeat[..96].copy_from_slice(&h.encode());
                select(1, 500);
                assert_eq!(
                    b.ingest(&repeat, 500),
                    Err(()),
                    "initial BOUND/LEAVING cannot claim forming heartbeat"
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn bound_confirmed_reconnect_sends_proof_before_status() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            for first in [0, 1] {
                for chunk in [97, usize::MAX] {
                    CTX.with(|c| *c.borrow_mut() = Context::default());
                    let (mut a, mut b) = native_setup(1);
                    connect_native(&mut a, &mut b);
                    pump(&mut a, &mut b, 0, || has_trace(0x211));
                    let bound = usize::from(durable_member_proof(0).is_none());
                    let proof = durable_member_proof(bound).unwrap();
                    assert!(durable_member_proof(1 - bound).is_none());
                    CTX.with(|c| {
                        assert!(
                            c.borrow().nodes[1 - bound]
                                .records
                                .iter()
                                .any(|b| b.starts_with(b"CXE1") && b[12] == 2),
                            "peer is durably CONFIRMED"
                        )
                    });
                    drop(a);
                    drop(b);
                    CTX.with(|c| {
                        for n in &mut c.borrow_mut().nodes {
                            n.traces.clear();
                        }
                    });
                    // Recover the real engine from the original persistent journals.
                    let (mut a, mut b) = native_setup(2);
                    connect_native(&mut a, &mut b);
                    let hello = [session_frames(&mut a), session_frames(&mut b)];
                    for from in [first, 1 - first] {
                        let d = if from == 0 { &mut b } else { &mut a };
                        deliver_session_frames(d, 1 - from, &hello[from], 0, chunk);
                    }
                    let responses = [session_frames(&mut a), session_frames(&mut b)];
                    for from in [first, 1 - first] {
                        let d = if from == 0 { &mut b } else { &mut a };
                        deliver_session_frames(d, 1 - from, &responses[from], 1, chunk);
                    }
                    let kinds: Vec<_> = responses[bound]
                        .iter()
                        .map(|f| {
                            cyxia_prototype::cluster::wire::Header::decode(&f[..96])
                                .unwrap()
                                .kind
                        })
                        .collect();
                    assert_eq!(
                        kinds.first(),
                        Some(&5),
                        "durable PROOF must precede reconciliation STATUS"
                    );
                    assert_eq!(durable_member_proof(1 - bound), Some(proof.clone()));
                    assert!(!session_ready_both(), "proof alone cannot establish READY");
                    CTX.with(|c| {
                        assert_eq!(c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>(), 0)
                    });
                    pump(&mut a, &mut b, 2, session_ready_both);
                    assert_eq!(durable_member_proof(bound), Some(proof.clone()));
                    assert_eq!(durable_member_proof(1 - bound), Some(proof));
                }
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn recovered_ack_response_closes_only_the_exact_persisted_terminal_result() {
    use cyxia_prototype::cluster::wire::Header;
    for mutation in 0..5 {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = setup(1);
        select(0, 0);
        a.connect([31; 32], 0).unwrap();
        select(1, 0);
        b.connect([32; 32], 0).unwrap();
        pump(&mut a, &mut b, 0, closed_both);
        drop(a);
        drop(b);
        let (mut a, mut b) = setup(2);
        select(0, 0);
        a.connect([41; 32], 0).unwrap();
        select(1, 0);
        b.connect([42; 32], 0).unwrap();
        let mut checked = false;
        'delivery: for now in 0..100 {
            for from in 0..2 {
                let (src, dst) = if from == 0 {
                    (&mut a, &mut b)
                } else {
                    (&mut b, &mut a)
                };
                for mut frame in session_frames(src) {
                    let mut h = Header::decode(&frame[..96]).unwrap();
                    if h.kind != 0x8015 {
                        deliver_session_frames(dst, 1 - from, &[frame], now, 97);
                        continue;
                    }
                    let contract = frame[128..144].to_vec();
                    match mutation {
                        1 => frame[128] ^= 1, // another contract/key
                        2 => frame[168] ^= 1, // terminal hash
                        3 => {
                            frame.pop();
                            h.body_len -= 1;
                        }
                        4 => {
                            frame.push(0);
                            h.body_len += 1;
                        }
                        _ => {}
                    }
                    frame[..96].copy_from_slice(&h.encode());
                    let queued = dst.outgoing().to_vec();
                    let records = CTX.with(|c| c.borrow().nodes[1 - from].records.clone());
                    select(1 - from, now);
                    if mutation == 0 {
                        assert_eq!(
                            dst.ingest(&frame, now),
                            Ok(frame.len()),
                            "recovered ACK response uses durable result, not transient task_key"
                        );
                        let close = &dst.outgoing()[queued.len()..];
                        assert_eq!(Header::decode(&close[..96]).unwrap().kind, 22);
                        assert_eq!(&close[96..], contract);
                    } else {
                        assert_eq!(
                            dst.ingest(&frame, now),
                            Err(()),
                            "invalid recovered ACK mutation {mutation}"
                        );
                        assert_eq!(
                            dst.outgoing(),
                            queued,
                            "invalid ACK cannot emit unrelated CLOSE"
                        );
                    }
                    assert_eq!(
                        CTX.with(|c| c.borrow().nodes[1 - from].records.clone()),
                        records,
                        "ACK response alone must not release or forget durable custody"
                    );
                    CTX.with(|c| {
                        assert_eq!(c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>(), 1)
                    });
                    checked = true;
                    break 'delivery;
                }
            }
        }
        assert!(checked, "real recovery never generated ACK_RESULT response");
    }
}

#[test]
fn bound_pair_reconnect_drains_recovery_after_ready_in_both_fifo_orders() {
    for first in [0, 1] {
        for chunk in [97, usize::MAX] {
            CTX.with(|c| *c.borrow_mut() = Context::default());
            let (mut a, mut b) = setup(1);
            select(0, 0);
            a.connect([31; 32], 0).unwrap();
            select(1, 0);
            b.connect([32; 32], 0).unwrap();
            pump(&mut a, &mut b, 0, closed_both);
            let proof = durable_member_proof(0).unwrap();
            assert_eq!(durable_member_proof(1), Some(proof.clone()));
            drop(a);
            drop(b);
            CTX.with(|c| {
                for n in &mut c.borrow_mut().nodes {
                    n.traces.clear();
                }
            });
            let (mut a, mut b) = setup(2);
            select(0, 0);
            a.connect([41; 32], 0).unwrap();
            select(1, 0);
            b.connect([42; 32], 0).unwrap();
            // Keep consuming after READY, including retransmitted ACK/CLOSE and
            // the next periodic STATUS. READY alone must not hide queued errors.
            for now in 0..600 {
                select(0, now);
                a.tick(now).unwrap();
                select(1, now);
                b.tick(now).unwrap();
                for from in [first, 1 - first] {
                    let (src, dst) = if from == 0 {
                        (&mut a, &mut b)
                    } else {
                        (&mut b, &mut a)
                    };
                    deliver_session_frames(dst, 1 - from, &session_frames(src), now, chunk);
                }
            }
            assert!(session_ready_both());
            assert_eq!(durable_member_proof(0), Some(proof.clone()));
            assert_eq!(durable_member_proof(1), Some(proof));
            CTX.with(|c| {
                let c = c.borrow();
                assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 1);
                assert!(c.nodes.iter().all(|n| n.exit_records.is_empty()));
            });
        }
    }
}

#[test]
fn session_exit_idle_timeout_retains_original_identity_before_disconnect() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0); a.connect([31; 32], 0).unwrap();
    select(1, 0); b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    select(0, 10_000);
    assert_eq!(a.tick(10_000), Err(()));
    assert!(a.take_exit_reported(), "runtime must suppress duplicate reporting");
    assert!(!a.take_exit_reported());
    assert!(a.outgoing().is_empty(), "timeout still tears down authority");
    CTX.with(|c| {
        let c = c.borrow();
        let records = &c.nodes[0].exit_records;
        assert_eq!(records.len(), 1, "real idle timeout must retain its original branch");
        let r = &records[0];
        assert_eq!(&r[..8], &[1, 1, 7, 1, 10_000, 12, 0x4001, 5]);
        assert_eq!(r[8], 2, "bound membership before isolate");
        assert_eq!(r[9], 15, "TLS authenticated, active, sent READY, ready");
        assert_eq!(r[11], 1, "peer boot before disconnect clears it");
        assert!(r[19..23].iter().any(|&v| v != 0));
    });
}

#[test]
fn session_exit_failed_ready_retains_message_context_without_body() {
    use cyxia_prototype::cluster::wire::Header;
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0); a.connect([31; 32], 0).unwrap();
    select(1, 0); b.connect([32; 32], 0).unwrap();
    // Exchange HELLO and formation until a genuine READY is queued, then
    // corrupt only its session binding. All headers/signatures remain real.
    for now in 0..1000 {
        for from in 0..2 {
            let (src, dst) = if from == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
            let bytes = src.outgoing().to_vec();
            if bytes.is_empty() { continue; }
            src.consume_outgoing(bytes.len());
            let mut at = 0;
            while at < bytes.len() {
                let h = Header::decode(&bytes[at..at + 96]).unwrap();
                let end = at + 96 + h.body_len as usize;
                let mut frame = bytes[at..end].to_vec();
                select(1 - from, now);
                if h.kind == 6 {
                    frame[96] ^= 1;
                    assert_eq!(dst.ingest(&frame, now), Err(()));
                    CTX.with(|c| {
                        let c = c.borrow();
                        let records = &c.nodes[1 - from].exit_records;
                        assert_eq!(records.len(), 1, "failed READY must retain original validation branch");
                        let r = &records[0];
                        assert_eq!(&r[5..8], &[10, 0x4002, 4]);
                        assert_eq!(&r[12..17], &[6, h.sequence, 1, 1, 32]);
                        assert!(!c.nodes[1 - from].traces.contains(&0x212));
                        assert_eq!(r[23], 0);
                    });
                    return;
                }
                assert_eq!(dst.ingest(&frame, now), Ok(frame.len()));
                at = end;
            }
        }
    }
    panic!("real drivers never produced READY");
}

#[test]
fn session_exit_replayed_real_header_keeps_original_engine_result() {
    use cyxia_prototype::cluster::wire::Header;
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0); a.connect([31; 32], 0).unwrap();
    select(1, 0); b.connect([32; 32], 0).unwrap();
    for now in 0..1000 {
        for from in 0..2 {
            let (src, dst) = if from == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
            let bytes = src.outgoing().to_vec();
            if bytes.is_empty() { continue; }
            src.consume_outgoing(bytes.len());
            let mut at = 0;
            while at < bytes.len() {
                let h = Header::decode(&bytes[at..at + 96]).unwrap();
                let end = at + 96 + h.body_len as usize;
                let frame = &bytes[at..end];
                select(1 - from, now);
                assert_eq!(dst.ingest(frame, now), Ok(frame.len()));
                if h.kind != 1 {
                    assert_eq!(dst.ingest(frame, now), Err(()));
                    CTX.with(|c| {
                        let c = c.borrow();
                        let r = &c.nodes[1 - from].exit_records[0];
                        assert_eq!(&r[5..8], &[10, 0x5009, 3]);
                        assert_eq!(&r[12..17], &[h.kind as u64, h.sequence, 1, 1, h.body_len as u64]);
                        assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 0);
                    });
                    return;
                }
                at = end;
            }
        }
    }
    panic!("real drivers never produced a formation frame");
}
#[test]
fn reconnect_at_each_custody_boundary_never_reexecutes() {
    for cut in [0x220, 0x213, 0x214, 0x215, 0x216, 0x217] {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = setup(1);
        select(0, 0);
        a.connect([31; 32], 0).unwrap();
        select(1, 0);
        b.connect([32; 32], 0).unwrap();
        pump(&mut a, &mut b, 0, || has_trace(cut));
        select(0, 100);
        a.disconnect();
        a.offline_tick(100).unwrap();
        select(1, 100);
        b.disconnect();
        b.offline_tick(100).unwrap();
        select(0, 101);
        a.connect([41; 32], 101).unwrap();
        select(1, 101);
        b.connect([42; 32], 101).unwrap();
        if cut == 0x220 {
            pump(&mut a, &mut b, 101, || {
                CTX.with(|c| {
                    c.borrow()
                        .nodes
                        .iter()
                        .all(|n| n.traces.iter().filter(|&&e| e == 0x212).count() >= 2)
                })
            });
        } else {
            pump(&mut a, &mut b, 101, closed_both);
        }
        let starts = CTX.with(|c| c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>());
        assert!(starts <= 1, "cut {cut:x}: {starts}");
        if cut >= 0x214 && cut != 0x220 {
            assert_eq!(starts, 1, "cut {cut:x}");
        }
    }
}
#[test]
fn closed_disk_reboot_reconciles_without_duplicate_execution() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    drop(a);
    drop(b);
    let (mut a, mut b) = setup(2);
    select(0, 0);
    a.connect([41; 32], 0).unwrap();
    select(1, 0);
    b.connect([42; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, || {
        CTX.with(|c| {
            c.borrow()
                .nodes
                .iter()
                .all(|n| n.traces.iter().filter(|&&e| e == 0x212).count() >= 2)
        })
    });
    CTX.with(|c| assert_eq!(c.borrow().nodes.iter().map(|n| n.starts).sum::<usize>(), 1));
}
#[test]
fn double_signed_leave_proof_is_persisted_before_unlock() {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        for n in &mut c.borrow_mut().nodes {
            n.authority = Some(cyxia_kernel_core::control_plane::task_admission::Authority::new());
        }
    });
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    select(0, 500);
    a.begin_leave([7; 16]).unwrap();
    pump(&mut a, &mut b, 500, || {
        CTX.with(|c| c.borrow().nodes.iter().all(|n| n.traces.contains(&0x221)))
    });
    let records = CTX.with(|c| {
        [
            c.borrow().nodes[0].records.clone(),
            c.borrow().nodes[1].records.clone(),
        ]
    });
    for records in records {
        assert!(records.iter().any(|b| b.len() == 325 && b[12] == 8));
    }
    CTX.with(|c| {
        for n in &mut c.borrow_mut().nodes {
            assert_eq!(n.session_calls.last().unwrap().0, 0, "completed leave renewed authority");
            assert!(n.authority.as_mut().unwrap().session(1, 2, 1000).is_err());
        }
    });
}
#[test]
fn worker_failure_is_durable_and_acknowledged_without_fake_done_output() {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        c.borrow_mut().nodes[0].fail_task = true;
        c.borrow_mut().nodes[1].fail_task = true;
    });
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    CTX.with(|c| {
        let c = c.borrow();
        assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 1);
        assert!(
            c.nodes
                .iter()
                .flat_map(|n| &n.records)
                .any(|b| b.len() > 86 && b[12] == 5 && b[85] == 2)
        );
    });
}
#[test]
fn changing_provisioned_identity_on_existing_volume_is_rejected_without_writes() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (_a, _b) = setup(1);
    let (sa, _, na) = identity(1);
    let (_, pb, nb) = identity(2);
    select(0, 0);
    let before = CTX.with(|c| c.borrow().nodes[0].records.len());
    assert!(driver::Driver::new(2, [99; 16], na, nb, sa, pb).is_err());
    assert_eq!(CTX.with(|c| c.borrow().nodes[0].records.len()), before);
}
#[test]
fn expired_final_gate_after_started_intent_persists_cancelled_without_execution() {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        c.borrow_mut().nodes[0].expire_after_stage = true;
        c.borrow_mut().nodes[1].expire_after_stage = true;
    });
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    CTX.with(|c| {
        let c = c.borrow();
        assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 0);
        assert!(
            c.nodes
                .iter()
                .flat_map(|n| &n.records)
                .any(|b| b.len() > 86 && b[12] == 5 && b[85] == 3)
        );
    });
}
#[test]
fn asymmetric_confirm_reboot_reuses_frozen_formation_lock() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, || has_trace(0x210));
    drop(a);
    drop(b);
    let (mut a, mut b) = setup(2);
    select(0, 0);
    a.connect([41; 32], 0).unwrap();
    select(1, 0);
    b.connect([42; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    CTX.with(|c| {
        let c = c.borrow();
        for n in &c.nodes {
            assert_eq!(
                n.records
                    .iter()
                    .filter(|b| b.len() > 13 && &b[..4] == b"CXE1" && b[12] == 1)
                    .count(),
                1
            );
        }
        assert_eq!(c.nodes.iter().map(|n| n.starts).sum::<usize>(), 1);
    });
}
#[test]
fn leave_reboots_after_one_signature_or_dropped_final_proof_finish_same_record() {
    for proof_cut in [false, true] {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = setup(1);
        select(0, 0);
        a.connect([31; 32], 0).unwrap();
        select(1, 0);
        b.connect([32; 32], 0).unwrap();
        pump(&mut a, &mut b, 0, closed_both);
        select(0, 500);
        a.begin_leave([7; 16]).unwrap();
        pump(&mut a, &mut b, 500, || {
            if proof_cut {
                has_trace(0x221)
            } else {
                CTX.with(|c| {
                    c.borrow()
                        .nodes
                        .iter()
                        .flat_map(|n| &n.records)
                        .any(|b| b.len() > 13 && b[12] == 13)
                })
            }
        });
        drop(a);
        drop(b);
        let (mut a, mut b) = setup(2);
        select(0, 0);
        a.connect([41; 32], 0).unwrap();
        select(1, 0);
        b.connect([42; 32], 0).unwrap();
        pump(&mut a, &mut b, 0, || {
            CTX.with(|c| c.borrow().nodes.iter().all(|n| n.traces.contains(&0x221)))
        });
        CTX.with(|c| {
            let c = c.borrow();
            for n in &c.nodes {
                let proof = n
                    .records
                    .iter()
                    .rev()
                    .find(|b| b.len() > 13 && b[12] == 8)
                    .unwrap();
                assert_eq!(&proof[53..69], &[7; 16]);
            }
        });
    }
}

#[test]
fn no_entropy_or_tcp_still_persists_real_driver_completion_without_authority() {
    for connected in [false, true] {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let (mut a, mut b) = setup(1);
        select(0, 0);
        a.connect([31; 32], 0).unwrap();
        select(1, 0);
        b.connect([32; 32], 0).unwrap();
        pump(&mut a, &mut b, 0, || has_trace(0x214));
        let owner = CTX.with(|c| c.borrow().nodes.iter().position(|n| n.starts == 1).unwrap());
        select(owner, 500);
        let driver = if owner == 0 { &mut a } else { &mut b };
        driver.disconnect();
        let before = CTX.with(|c| c.borrow().nodes[owner].records.len());
        let attempts = std::cell::Cell::new(0);
        let result = runtime::advance_network(
            driver,
            500,
            || connected.then_some(1),
            || {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(cyxia_cluster_transport::tls::Error::Entropy)
            },
        );
        assert!(
            matches!(
                result,
                Ok(runtime::NetworkTurn::Offline) | Ok(runtime::NetworkTurn::EntropyUnavailable)
            ),
            "missing entropy isolates network, not custody: {result:?}"
        );
        CTX.with(|c| {
            let c = c.borrow();
            let n = &c.nodes[owner];
            assert_eq!(
                n.records.len(),
                before + 1,
                "actual durable terminal must be persisted offline"
            );
            let terminal = n.records.last().unwrap();
            assert_eq!(terminal[12], 5);
            assert_eq!(terminal[13 + 72], 1);
            assert!(n.traces.contains(&0x215));
            assert_eq!(n.starts, 1);
        });
        assert_eq!(attempts.get(), usize::from(connected));
        assert!(
            driver.outgoing().is_empty(),
            "no HELLO, READY or new authority while entropy is absent"
        );
    }
}

#[test]
fn completed_history_recovers_without_entropy_and_remains_unchanged_offline() {
    CTX.with(|c| *c.borrow_mut() = Context::default());
    let (mut a, mut b) = setup(1);
    select(0, 0);
    a.connect([31; 32], 0).unwrap();
    select(1, 0);
    b.connect([32; 32], 0).unwrap();
    pump(&mut a, &mut b, 0, closed_both);
    drop(a);
    drop(b);
    let records = CTX.with(|c| {
        [
            c.borrow().nodes[0].records.clone(),
            c.borrow().nodes[1].records.clone(),
        ]
    });
    let starts = CTX.with(|c| [c.borrow().nodes[0].starts, c.borrow().nodes[1].starts]);
    let (mut a, mut b) = setup(2);
    for (index, driver) in [&mut a, &mut b].into_iter().enumerate() {
        select(index, 500);
        for connected in [false, true] {
            let result = runtime::advance_network(
                driver,
                500,
                || connected.then_some(1),
                || Err::<(), _>(cyxia_cluster_transport::tls::Error::Entropy),
            );
            assert!(matches!(
                result,
                Ok(runtime::NetworkTurn::Offline) | Ok(runtime::NetworkTurn::EntropyUnavailable)
            ));
            assert!(driver.outgoing().is_empty());
        }
    }
    CTX.with(|c| {
        let c = c.borrow();
        for index in 0..2 {
            assert_eq!(c.nodes[index].records, records[index]);
            assert_eq!(c.nodes[index].starts, starts[index]);
        }
    });
}
