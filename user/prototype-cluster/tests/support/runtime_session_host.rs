//! Real TLS + production runtime turn + Driver/Authority replay. Only the
//! external broker clock, byte transport, entropy and durable storage are owned
//! by the existing deterministic host broker.
use super::*;
use cyxia_cluster_transport::tls::{Buffers, Pairing, node_id, public_key};
use cyxia_kernel_core::control_plane::task_admission::Authority;
use cyxia_prototype::{domains::Error as DomainError, domains::platform::PlacementQueue};
use cyxia_prototype_cluster::domain_ingress::{TlsEgress, TlsIngress};
use cyxia_prototype_cluster::session_exit::SessionExitReason;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct Clock;
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            1_800_000_000,
        )))
    }
}

fn fixtures() -> [(&'static [u8], &'static [u8]); 2] {
    let mut f = [
        (
            &include_bytes!("../../../../crates/cluster-transport/tests/fixtures/a-test-cert.der")
                [..],
            &include_bytes!("../../../../crates/cluster-transport/tests/fixtures/a-test-key.der")[..],
        ),
        (
            &include_bytes!("../../../../crates/cluster-transport/tests/fixtures/b-test-cert.der")
                [..],
            &include_bytes!("../../../../crates/cluster-transport/tests/fixtures/b-test-key.der")[..],
        ),
    ];
    f.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    f
}

fn replay(
    io_delay_ms: u64,
    fragment: usize,
    again_every: usize,
    delay_ops: &[u64],
    delay_task: Option<u64>,
) -> Result<(), (usize, SessionExitReason, u64)> {
    replay_with_goal(
        io_delay_ms,
        fragment,
        again_every,
        delay_ops,
        delay_task,
        false,
    )
}

fn replay_with_goal(
    io_delay_ms: u64,
    fragment: usize,
    again_every: usize,
    delay_ops: &[u64],
    delay_task: Option<u64>,
    first_hello_only: bool,
) -> Result<(), (usize, SessionExitReason, u64)> {
    replay_goal(
        io_delay_ms,
        fragment,
        again_every,
        delay_ops,
        delay_task,
        first_hello_only,
        false,
    )
}

fn replay_goal(
    io_delay_ms: u64,
    fragment: usize,
    again_every: usize,
    delay_ops: &[u64],
    delay_task: Option<u64>,
    first_hello_only: bool,
    remote_ordinary: bool,
) -> Result<(), (usize, SessionExitReason, u64)> {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        for n in &mut c.borrow_mut().nodes {
            n.authority = Some(Authority::new());
            if remote_ordinary {
                n.strict_authority = true;
                n.domains.offer = cyxia_prototype_cluster::abi::PolicyWire {
                    version: 1,
                    snapshot_ns: 0,
                    installed_until_ns: 10_000_000_000,
                    value: 250,
                    plan_seq: 1,
                    controller_epoch: 1,
                    action_index: 0,
                };
            }
            n.tcp_fragment = fragment;
            n.tcp_again_every = again_every;
            n.io_delay_ops = delay_ops.to_vec();
            n.io_delay_task = delay_task;
        }
    });
    let f = fixtures();
    let ids = f.map(|(cert, _)| node_id(&CertificateDer::from(cert)).unwrap());
    let publics = f.map(|(cert, _)| public_key(&CertificateDer::from(cert)).unwrap());
    let make = |node: usize| {
        select(node, 0);
        driver::Driver::new_native(
            1,
            [1 + node as u8; 16],
            ids[node],
            ids[1 - node],
            IdentitySigner::new(f[node].1, publics[node]).unwrap(),
            publics[1 - node],
            Box::leak(Box::new(PlacementQueue::new())),
        )
        .unwrap()
    };
    let mut a = make(0);
    let mut b = make(1);
    if remote_ordinary {
        enqueue_application(0, 1, 0);
        enqueue_application(1, 1, 0);
    }
    let mut selected = false;
    let pairings = [0, 1].map(|node| {
        Pairing::new(
            CertificateDer::from(f[node].0),
            PrivatePkcs8KeyDer::from(f[node].1).into(),
            ids[1 - node],
            Arc::new(Clock),
        )
        .unwrap()
    });
    let mut ingress = [TlsIngress::new(0).unwrap(), TlsIngress::new(0).unwrap()];
    let [at, bt] = [0, 1].map(|node| {
        ingress[node]
            .begin_at([10, 42, 0, 1 + node as u8], 0, || Ok::<_, DomainError>(()))
            .unwrap()
            .0
    });
    let mut buffers = [Buffers::new(), Buffers::new()];
    let [ab, bb] = &mut buffers;
    let mut sa = pairings[0].client(ab, 0).unwrap();
    let mut sb = pairings[1].server(bb, 0).unwrap();
    let mut states = [
        runtime::SessionState::new(1, at),
        runtime::SessionState::new(1, bt),
    ];
    let mut egress = [TlsEgress::new(1).unwrap(), TlsEgress::new(1).unwrap()];
    let mut input = [0u8; cyxia_prototype_cluster::abi::PAYLOAD];
    for _ in 0..20_000 {
        for node in 0..2 {
            let now = CTX.with(|c| c.borrow().now) + 1;
            select(node, now);
            if sa.authenticated_peer().is_some() && sb.authenticated_peer().is_some() {
                CTX.with(|c| c.borrow_mut().nodes[node].io_delay_ms = io_delay_ms);
            }
            let (d, s) = if node == 0 {
                (&mut a, &mut sa)
            } else {
                (&mut b, &mut sb)
            };
            let verdict = runtime::session_turn(
                d,
                s,
                &mut ingress[node],
                &mut egress[node],
                &mut input,
                &mut states[node],
            );
            if let Err((reason, status)) = verdict {
                return Err((node, reason, status));
            }
        }
        if remote_ordinary && session_ready_both() && !selected {
            let now = CTX.with(|c| c.borrow().now);
            let f = a.domain_feedback(now * 1_000_000);
            if f.waiting[0].peer_ready == 1 {
                CTX.with(|c| {
                    let mut c = c.borrow_mut();
                    let d = &mut c.nodes[0].domains;
                    // A controlled legal D16 invocation exercises the real
                    // execution chain; it is not evidence of model selection.
                    d.placement = cyxia_prototype_cluster::abi::PolicyWire {
                        version: 2,
                        snapshot_ns: now * 1_000_000,
                        installed_until_ns: 0,
                        value: 1,
                        plan_seq: 2,
                        controller_epoch: 1,
                        action_index: 0,
                    };
                    d.placement_request_id = f.waiting[0].request_id;
                    d.placement_request_generation = f.waiting[0].request_generation;
                });
                selected = true;
            }
        }
        if remote_ordinary
            && CTX.with(|c| {
                c.borrow().nodes[0]
                    .application_status
                    .iter()
                    .any(|s| s.state == cyxia_prototype_cluster::application::REMOTE)
            })
        {
            CTX.with(|c| {
                let c = c.borrow();
                assert!(selected);
                assert!(durable_member_proof(0).is_some());
                assert_eq!(durable_member_proof(0), durable_member_proof(1));
                assert_eq!(c.nodes.each_ref().map(|n| n.starts), [0, 1]);
                assert_eq!(c.nodes.each_ref().map(|n| n.local_submits), [0, 0]);
                assert_eq!(
                    (c.nodes[1].strict_reserves, c.nodes[1].strict_grants),
                    (1, 1)
                );
                assert!(
                    c.nodes[0]
                        .records
                        .iter()
                        .filter_map(|r| cyxia_prototype_cluster::domain_placement::decode(r).ok())
                        .any(|r| matches!(
                            r,
                            cyxia_prototype_cluster::domain_placement::Record::Receipt(
                                _,
                                cyxia_prototype::domains::platform::PlacementOutcome::Peer { .. }
                            )
                        ))
                );
            });
            return Ok(());
        }
        if first_hello_only
            && CTX.with(|c| {
                c.borrow().nodes.iter().all(|n| {
                    n.session_calls
                        .iter()
                        .any(|(token, _, result)| *token == 3 && result.is_ok())
                })
            })
        {
            return Ok(());
        }
        if !remote_ordinary && session_ready_both() {
            assert_eq!(durable_member_proof(0), durable_member_proof(1));
            return Ok(());
        }
    }
    panic!(
        "real TLS/runtime pair did not reach requested READY or ordinary remote STARTED custody"
    );
}

#[test]
fn first_authenticated_hello_reaches_both_authorities_with_bounded_broker_work() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| replay_with_goal(100, 4096, 0, &[], None, true).unwrap())
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn real_tls_runtime_fragmented_again_reaches_durable_ready() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| replay(0, 71, 5, &[], None).unwrap())
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn real_tls_runtime_bounded_broker_work_preserves_protocol_progress() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| replay(10, 4096, 0, &[], None).unwrap())
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn real_tls_runtime_expired_activity_retains_original_broker_error() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let (node, reason, status) = replay(100, 4096, 0, &[], None).unwrap_err();
            assert_eq!(
                (reason, status),
                (SessionExitReason::PlaintextIngest, 0x4000)
            );
            CTX.with(|c| {
                let c = c.borrow();
                let n = &c.nodes[node];
                assert!(matches!(n.session_calls.last(), Some((3, _, Err(_)))));
                let record = n
                    .exit_records
                    .last()
                    .expect("actual Driver retained the exit");
                assert_eq!(
                    record[6],
                    0x3000 + cyxia_prototype_cluster::abi::FAILED,
                    "the original broker rejection was collapsed into a generic unit error"
                );
                assert_eq!(
                    record[7], 9,
                    "activity admission must not be reported as message handling"
                );
                assert!(
                    !n.traces.contains(&0x212),
                    "expired authority reached READY"
                );
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[derive(Clone, Copy)]
enum SetupFailure {
    StoreRejected,
    ReplacedEpoch,
}

fn initial_hello_case(
    start_ms: u64,
    later_ms: Option<u64>,
    preparation_ms: u64,
    failure: Option<SetupFailure>,
) -> Result<(), (SessionExitReason, u64)> {
    CTX.with(|c| {
        *c.borrow_mut() = Context::default();
        for n in &mut c.borrow_mut().nodes {
            n.authority = Some(Authority::new());
            n.diagnostic_generation = Some(1);
        }
    });
    let f = fixtures();
    let ids = f.map(|(cert, _)| node_id(&CertificateDer::from(cert)).unwrap());
    let publics = f.map(|(cert, _)| public_key(&CertificateDer::from(cert)).unwrap());
    let make = |node: usize| {
        select(node, 0);
        driver::Driver::new_native(
            1,
            [1 + node as u8; 16],
            ids[node],
            ids[1 - node],
            IdentitySigner::new(f[node].1, publics[node]).unwrap(),
            publics[1 - node],
            Box::leak(Box::new(PlacementQueue::new())),
        )
        .unwrap()
    };
    let mut a = make(0);
    let mut b = make(1);
    let pairings = [0, 1].map(|node| {
        Pairing::new(
            CertificateDer::from(f[node].0),
            PrivatePkcs8KeyDer::from(f[node].1).into(),
            ids[1 - node],
            Arc::new(Clock),
        )
        .unwrap()
    });
    let mut buffers = [Buffers::new(), Buffers::new()];
    let [ab, bb] = &mut buffers;
    let mut sa = pairings[0].client(ab, 0).unwrap();
    let mut sb = pairings[1].server(bb, 0).unwrap();
    for _ in 0..100 {
        sa.pump(0).unwrap();
        sb.pump(0).unwrap();
        for direction in 0..2 {
            let (src, dst) = if direction == 0 {
                (&mut sa, &mut sb)
            } else {
                (&mut sb, &mut sa)
            };
            let bytes = src.pending_tls();
            let n = dst.receive_tls(bytes).unwrap();
            src.consume_tls(n).unwrap();
        }
        if sa.authenticated_peer().is_some()
            && sb.authenticated_peer().is_some()
            && sa.pending_tls().is_empty()
            && sb.pending_tls().is_empty()
        {
            break;
        }
    }
    assert!(sa.authenticated_peer().is_some() && sb.authenticated_peer().is_some());
    let mut ingress = [TlsIngress::new(0).unwrap(), TlsIngress::new(0).unwrap()];
    let [at, bt] = [0, 1].map(|node| {
        ingress[node]
            .begin_at([10, 42, 0, node as u8 + 1], 0, || Ok::<_, DomainError>(()))
            .unwrap()
            .0
    });
    let mut states = [
        runtime::SessionState::new(1, at),
        runtime::SessionState::new(1, bt),
    ];
    let mut egress = [TlsEgress::new(1).unwrap(), TlsEgress::new(1).unwrap()];
    let mut input = [0; cyxia_prototype_cluster::abi::PAYLOAD];
    for node in 0..2 {
        select(node, start_ms.max(CTX.with(|c| c.borrow().now)));
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            c.nodes[node].io_delay_ms = preparation_ms;
            c.nodes[node].io_delay_ops = vec![cyxia_prototype_cluster::abi::OP_STORE_PUT];
            if node == 0 {
                match failure {
                    Some(SetupFailure::StoreRejected) => c.nodes[node].reject_store_next = true,
                    Some(SetupFailure::ReplacedEpoch) => {
                        c.nodes[node].session_wait = Some((1, 900, true, 2))
                    }
                    None => (),
                }
            }
        });
        let (driver, session) = if node == 0 {
            (&mut a, &mut sa)
        } else {
            (&mut b, &mut sb)
        };
        runtime::session_turn(
            driver,
            session,
            &mut ingress[node],
            &mut egress[node],
            &mut input,
            &mut states[node],
        )?;
    }
    // Native r2 records caller-sampled ingest time, not an independent
    // EL1 completion timestamp. Reproduce that public context exactly.
    select(0, later_ms.unwrap_or_else(|| CTX.with(|c| c.borrow().now)));
    runtime::session_turn(
        &mut a,
        &mut sa,
        &mut ingress[0],
        &mut egress[0],
        &mut input,
        &mut states[0],
    )
}

#[test]
fn native_r2_first_hello_activity_failure_replays_exact_public_context() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            assert_eq!(
                initial_hello_case(11211, Some(12950), 0, None),
                Err((SessionExitReason::PlaintextIngest, 0x4000))
            );
            CTX.with(|c| {
                let c = c.borrow();
                let n = &c.nodes[0];
                let record = n.exit_records.last().unwrap();
                assert_eq!(&record[..8], &[2, 1, 1, 1, 12950, 10, 0x3003, 9]);
                assert_eq!(record[10], 11211);
                assert_eq!(&record[12..17], &[1, 1, 1, 0, 113]);
                assert!(matches!(n.session_calls.last(), Some((3, 12950, Err(_)))));
                assert!(!n.traces.contains(&0x212));
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn durable_connection_preparation_precedes_initial_authority_liveness() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            // Each node's cold formation write takes 900 ms. The write is setup,
            // not a reason to consume the first live authority's receive interval.
            let result = initial_hello_case(0, None, 900, None);
            assert_eq!(
                result,
                Ok(()),
                "timely first HELLO failed after cold durable setup"
            );
            CTX.with(|c| {
                let c = c.borrow();
                let calls = &c.nodes[0].session_calls;
                assert!(matches!(calls.last(), Some((3, 1800, Ok(())))));
                assert_eq!(calls.iter().filter(|(level, _, _)| *level == 1).count(), 1);
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn failed_preparation_or_replaced_epoch_cannot_transmit_hello_or_open_authority() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            for failure in [SetupFailure::StoreRejected, SetupFailure::ReplacedEpoch] {
                assert_eq!(
                    initial_hello_case(0, None, 900, Some(failure)),
                    Err((SessionExitReason::EnterAuthenticated, 0x2012))
                );
                CTX.with(|c| {
                    let mut c = c.borrow_mut();
                    let n = &mut c.nodes[0];
                    assert_eq!(
                        n.tcp_writes, 0,
                        "HELLO left before local authority admission"
                    );
                    assert!(
                        !n.session_calls
                            .iter()
                            .any(|(level, _, result)| *level == 1 && result.is_ok())
                    );
                    assert!(!n.traces.contains(&0x212));
                    assert!(n.authority.as_mut().unwrap().session(1, 2, 1800).is_err());
                });
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

// Coverage enhancement: this path was GREEN before any production fix. The
// legal peer policy is controlled; no native or current-model verdict follows.
#[test]
fn real_tls_runtime_ordinary_peer_choice_reaches_actual_started_custody() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            replay_goal(0, 71, 5, &[], None, false, true).unwrap();
        })
        .unwrap()
        .join()
        .unwrap();
}
