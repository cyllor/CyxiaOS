// Reconnect regression: production driver and real TLS, with in-memory sockets.
// Reuse the production Driver plus the repository's broker/journal fixture.
use super::*;

mod recheck {
    use super::*;
    use cyxia_cluster_transport::tls::{Buffers, Pairing, node_id, public_key};
    use cyxia_prototype::cluster::wire::Header;
    use cyxia_prototype::domains::{Error as DomainError, platform::PlacementQueue};
    use cyxia_prototype_cluster::domain_ingress::{RpcOutbox, TlsEgress, TlsTransport};
    use rustls::{
        pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
        time_provider::TimeProvider,
    };
    use std::{collections::VecDeque, sync::Arc, time::Duration};

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
                &include_bytes!(
                    "../../../../crates/cluster-transport/tests/fixtures/a-test-cert.der"
                )[..],
                &include_bytes!(
                    "../../../../crates/cluster-transport/tests/fixtures/a-test-key.der"
                )[..],
            ),
            (
                &include_bytes!(
                    "../../../../crates/cluster-transport/tests/fixtures/b-test-cert.der"
                )[..],
                &include_bytes!(
                    "../../../../crates/cluster-transport/tests/fixtures/b-test-key.der"
                )[..],
            ),
        ];
        f.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
        f
    }
    fn setup_fixture_drivers() -> [driver::Driver; 2] {
        let f = fixtures();
        core::array::from_fn(|i| {
            select(i, 0);
            let own = CertificateDer::from(f[i].0);
            let peer = CertificateDer::from(f[1 - i].0);
            driver::Driver::new_native(
                1,
                [1 + i as u8; 16],
                node_id(&own).unwrap(),
                node_id(&peer).unwrap(),
                IdentitySigner::new(f[i].1, public_key(&own).unwrap()).unwrap(),
                public_key(&peer).unwrap(),
                Box::leak(Box::new(PlacementQueue::new())),
            )
            .unwrap()
        })
    }
    fn pairings() -> [Pairing; 2] {
        let f = fixtures();
        core::array::from_fn(|i| {
            Pairing::new(
                CertificateDer::from(f[i].0),
                PrivatePkcs8KeyDer::from(f[i].1).into(),
                node_id(&CertificateDer::from(f[1 - i].0)).unwrap(),
                Arc::new(Clock),
            )
            .unwrap()
        })
    }
    fn complete_history(count: u64) -> [driver::Driver; 2] {
        CTX.with(|c| *c.borrow_mut() = Context::default());
        let mut drivers = setup_fixture_drivers();
        CTX.with(|c| {
            let mut c = c.borrow_mut();
            c.nodes[0].replay_requests = (1..=count).map(|id| replay_work(16, id)).collect();
            for n in &mut c.nodes {
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
        });
        let [a, b] = &mut drivers;
        connect_native(a, b);
        for now in 0..8000 {
            native_pair_turn(a, b, now);
            if CTX.with(|c| c.borrow().nodes[0].replay_results.len() == count as usize) {
                break;
            }
        }
        CTX.with(|c| {
            let c = c.borrow();
            assert_eq!(c.nodes[0].replay_results.len(), count as usize);
            assert_eq!(c.nodes[1].starts, count as usize);
            assert!(c.nodes.iter().all(|n| !n.reserved));
        });
        drivers
    }
    fn clear_connection_evidence() {
        CTX.with(|c| {
            for n in &mut c.borrow_mut().nodes {
                n.traces.clear();
                n.exit_records.clear();
            }
        });
    }
    struct Socket<'a> {
        bytes: &'a mut VecDeque<u8>,
        write_limit: usize,
    }
    impl TlsTransport for Socket<'_> {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, DomainError> {
            let n = bytes.len().min(self.write_limit);
            self.bytes.extend(bytes[..n].iter().copied());
            Ok(n)
        }
    }
    struct AuditedOutbox<'a> {
        driver: &'a mut driver::Driver,
        frames: &'a mut Vec<u16>,
    }
    impl RpcOutbox for AuditedOutbox<'_> {
        fn outgoing(&self) -> &[u8] {
            self.driver.outgoing()
        }
        fn consume(&mut self, n: usize) {
            // Every reconnect frame in this fixture fits the 16 KiB TLS buffer.
            // Record actual transfer of frame custody to TLS, not queued sends.
            let h = Header::decode(&self.driver.outgoing()[..96]).unwrap();
            assert_eq!(n, 96 + h.body_len as usize);
            self.frames.push(h.kind);
            self.driver.consume_outgoing(n);
        }
    }
    #[derive(Debug)]
    struct Outcome {
        phase: &'static str,
        node: usize,
        at: u64,
        first_kind: Option<u16>,
        incoming_bytes: usize,
        queued: usize,
        ready: [bool; 2],
        tls_connected: [bool; 2],
        frames_sent: [Vec<u16>; 2],
    }
    fn ready_flags() -> [bool; 2] {
        CTX.with(|c| core::array::from_fn(|i| c.borrow().nodes[i].traces.contains(&0x212)))
    }
    // Match runtime.rs: domain_tick -> socket receive -> TLS pump -> connect
    // -> ingest -> driver.tick -> TlsEgress. Any ingest/tick error returns
    // BEFORE egress and tears down that endpoint, as the real runtime does.
    fn run_real_tls(
        drivers: &mut [driver::Driver; 2],
        first: usize,
        fragment: usize,
        stagger_server: bool,
        start: u64,
    ) -> Outcome {
        for (i, d) in drivers.iter_mut().enumerate() {
            select(i, start);
            d.disconnect();
        }
        clear_connection_evidence();
        let [client, server] = pairings();
        let mut left = Buffers::new();
        let mut right = Buffers::new();
        let mut sessions = [
            client.client(&mut left, start).unwrap(),
            server.server(&mut right, start).unwrap(),
        ];
        let mut egress = [TlsEgress::new(1).unwrap(), TlsEgress::new(1).unwrap()];
        let mut sockets: [VecDeque<u8>; 2] = core::array::from_fn(|_| VecDeque::new());
        let mut connected = [false; 2];
        let mut frames: [Vec<u16>; 2] = core::array::from_fn(|_| Vec::new());
        let mut ready_at = None;
        let history_count = CTX.with(|c| {
            c.borrow().nodes[0]
                .records
                .iter()
                .filter(|b| b.starts_with(b"CXE1") && b.get(12) == Some(&5))
                .count()
        });
        for step in 0..16000u64 {
            let now = start + step / 4;
            for i in [first, 1 - first] {
                if stagger_server && i == 1 && step < 40 {
                    continue;
                }
                select(i, now);
                let mut fail = None;
                let d = &mut drivers[i];
                let s = &mut sessions[i];
                if d.domain_tick(now * 1_000_000).is_err() {
                    fail = Some(("domain_tick", None, 0));
                }
                if fail.is_none() {
                    let n = s
                        .receive_capacity()
                        .min(cyxia_prototype_cluster::abi::PAYLOAD)
                        .min(fragment)
                        .min(sockets[i].len());
                    if n != 0 {
                        let bytes: Vec<u8> = sockets[i].drain(..n).collect();
                        assert_eq!(s.receive_tls(&bytes).unwrap(), n);
                    }
                    s.pump(now).unwrap();
                    if s.authenticated_peer().is_some() && !connected[i] {
                        d.connect([91 + i as u8; 32], now).unwrap();
                        connected[i] = true;
                    }
                    if connected[i] {
                        if !s.plaintext().is_empty() {
                            let n = s.plaintext().len();
                            let kind = if n >= 96 {
                                Header::decode(&s.plaintext()[..96]).ok().map(|h| h.kind)
                            } else {
                                None
                            };
                            match d.ingest(s.plaintext(), now) {
                                Ok(got) => {
                                    assert_eq!(got, n);
                                    s.consume_plaintext(got).unwrap();
                                }
                                Err(()) => fail = Some(("ingest", kind, n)),
                            }
                        }
                        if fail.is_none() && d.tick(now).is_err() {
                            fail = Some(("tick", None, 0));
                        }
                    }
                }
                if let Some((phase, kind, n)) = fail {
                    let out = Outcome {
                        phase,
                        node: i,
                        at: now - start,
                        first_kind: kind,
                        incoming_bytes: n,
                        queued: d.queued_frames(),
                        ready: ready_flags(),
                        tls_connected: connected,
                        frames_sent: frames,
                    };
                    d.disconnect();
                    s.abort();
                    return out;
                }
                let mut outbox = AuditedOutbox {
                    driver: d,
                    frames: &mut frames[i],
                };
                let mut socket = Socket {
                    bytes: &mut sockets[1 - i],
                    write_limit: fragment,
                };
                egress[i]
                    .service_at(s, &mut outbox, now * 1_000_000, &mut socket)
                    .unwrap();
            }
            if ready_flags() == [true, true] {
                let since = *ready_at.get_or_insert(now);
                // Exercise closure replies and another periodic STATUS, not
                // merely the HELLO ingest or the first READY transition.
                if now - since >= 650
                    && frames[0].iter().filter(|&&k| k == 21).count() >= history_count
                    && frames[1].iter().filter(|&&k| k == 0x8016).count() >= history_count * 2
                {
                    return Outcome {
                        phase: "ready_stable",
                        node: 0,
                        at: now - start,
                        first_kind: None,
                        incoming_bytes: 0,
                        queued: drivers[0].queued_frames(),
                        ready: ready_flags(),
                        tls_connected: connected,
                        frames_sent: frames,
                    };
                }
            }
        }
        Outcome {
            phase: "timeout",
            node: 0,
            at: 4000,
            first_kind: None,
            incoming_bytes: 0,
            queued: drivers[0].queued_frames(),
            ready: ready_flags(),
            tls_connected: connected,
            frames_sent: frames,
        }
    }
    fn summarize(
        count: u64,
        rebuild: bool,
        first: usize,
        fragment: usize,
        stagger: bool,
        trial: usize,
        out: &Outcome,
    ) {
        let closures: [usize; 2] = core::array::from_fn(|i| {
            out.frames_sent[i]
                .iter()
                .filter(|&&k| matches!(k & 0x7fff, 21 | 22))
                .count()
        });
        eprintln!(
            "RECHECK_TLS count={count} rebuild={rebuild} first={first} fragment={fragment} stagger={stagger} trial={trial} phase={} node={} at_ms={} first_kind={:?} plaintext={} queued={} ready={:?} authenticated={:?} sent_closure_frames={:?} sent_frames={:?}",
            out.phase,
            out.node,
            out.at,
            out.first_kind,
            out.incoming_bytes,
            out.queued,
            out.ready,
            out.tls_connected,
            closures,
            out.frames_sent
        );
    }
    #[test]
    fn recheck_real_tls_runtime_order_and_final_ready_matrix() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                for count in [15, 16, 32] {
                    for rebuild in [false, true] {
                        for first in [0, 1] {
                            for fragment in [7, 4096] {
                                let mut d = complete_history(count);
                                if rebuild {
                                    drop(d);
                                    d = setup_fixture_drivers();
                                }
                                let out = run_real_tls(&mut d, first, fragment, first == 1, 9000);
                                summarize(count, rebuild, first, fragment, first == 1, 0, &out);
                                assert_eq!(out.phase, "ready_stable");
                                assert!(
                                    out.frames_sent[0].iter().filter(|&&k| k == 21).count()
                                        >= count as usize
                                );
                                CTX.with(|c| {
                                    assert_eq!(c.borrow().nodes[1].starts, count as usize)
                                });
                            }
                        }
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn recheck_one_hello_fragmentation_without_batched_rpc_input() {
        std::thread::Builder::new().stack_size(16*1024*1024).spawn(|| {
            for count in [15,16,32] { for chunk in [1,97,207] {
                let mut d=complete_history(count);
                for (i,driver) in d.iter_mut().enumerate() { select(i,9000); driver.connect([101+i as u8;32],9000).unwrap(); }
                let mut hello=Vec::new();
                for (i,driver) in d.iter_mut().enumerate() {
                    let h=Header::decode(&driver.outgoing()[..96]).unwrap();
                    assert_eq!(h.kind,1);
                    let bytes=driver.outgoing()[..96+h.body_len as usize].to_vec();
                    driver.consume_outgoing(bytes.len());
                    if i==1 { hello=bytes; }
                }
                let mut final_result=Ok(0); let mut advanced=0;
                for piece in hello.chunks(chunk) {
                    select(0,9000);
                    final_result=d[0].ingest(piece,9000);
                    advanced+=piece.len();
                    if advanced<hello.len() { assert_eq!(final_result,Ok(piece.len()));
                        assert!(d[0].outgoing().is_empty(),"partial HELLO must not manufacture closure work"); }
                }
                eprintln!("RECHECK_SINGLE_HELLO count={count} chunk={chunk} input={} result={final_result:?} queued={}",hello.len(),d[0].queued_frames());
                assert!(final_result.is_ok());
                assert!(d[0].queued_frames() < 32);
            }}
        }).unwrap().join().unwrap();
    }
    #[test]
    fn recheck_repeated_real_tls_retries_preserve_the_blocking_history() {
        std::thread::Builder::new().stack_size(16*1024*1024).spawn(|| {
            let mut d=complete_history(16);
            let history=CTX.with(|c| c.borrow().nodes[0].records.clone());
            let terminal_records:Vec<_>=history.iter().filter(|b| b.starts_with(b"CXE1")
                && b.get(12)==Some(&5)).cloned().collect();
            assert_eq!(terminal_records.len(),16);
            for trial in 0..3 {
                if trial==1 { drop(d); d=setup_fixture_drivers(); }
                let out=run_real_tls(&mut d,trial%2,if trial==2 {7}else{4096},trial==1,9000+trial as u64*5000);
                summarize(16,trial==1,trial%2,if trial==2 {7}else{4096},trial==1,trial,&out);
                assert_eq!(out.phase,"ready_stable");
                let after=CTX.with(|c| c.borrow().nodes[0].records.clone());
                assert!(after.starts_with(&history),"durable history must remain intact");
                // Local fallback may append its own independent placement
                // receipt while the cluster is offline. Only the retained
                // result custody and absence of a completed leave matter here.
                assert_eq!(after.iter().filter(|b| b.starts_with(b"CXE1")
                    && b.get(12)==Some(&5)).cloned().collect::<Vec<_>>(),terminal_records);
                assert!(!after.iter().any(|b| b.starts_with(b"CXE1") && b.get(12)==Some(&8)));
                eprintln!("RECHECK_RETRY_HISTORY trial={trial} results={} original_records={} retained_records={} added_records={}",
                    terminal_records.len(),history.len(),after.len(),after.len()-history.len());
            }
        }).unwrap().join().unwrap();
    }
}
