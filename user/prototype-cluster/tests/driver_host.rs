extern crate alloc;
use cyxia_cluster_transport::tls::IdentitySigner;
use ring::signature::KeyPair;
use std::cell::RefCell;
#[path = "../src/driver.rs"]
mod driver;
#[path = "../src/runtime.rs"]
mod runtime;
#[derive(Default)]
struct Node {
    records: Vec<Vec<u8>>,
    staging: Vec<u8>,
    traces: Vec<u64>,
    input: Vec<u8>,
    starts: usize,
    reserved: bool,
    entropy: u8,
    fail_task: bool,
    task_state: u64,
    expire_after_stage: bool,
    fail_nonce_once: bool,
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
            let n = &mut cx.nodes[i];
            match op {
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
                        n.records.push(b);
                    }
                    Ok((input.len(), args[0]))
                }
                OP_TASK => match args[0] {
                    0 => {
                        if n.reserved {
                            return Err(AGAIN);
                        }
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
                        n.starts += 1;
                        n.task_state = 2;
                        Ok((0, 1))
                    }
                    3 => {
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
                        n.reserved = false;
                        Ok((0, 1))
                    }
                    5 => {
                        n.task_state = 5;
                        Ok((0, 0))
                    }
                    8 => {
                        if matches!(n.task_state, 1 | 4 | 5) {
                            Ok((0, n.task_state))
                        } else {
                            Err(AGAIN)
                        }
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
        Ok((true, 1))
    }
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
                    "base {base},step {step},from {from}, traces {:?}",
                    CTX.with(|c| [
                        c.borrow().nodes[0].traces.clone(),
                        c.borrow().nodes[1].traces.clone()
                    ])
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
