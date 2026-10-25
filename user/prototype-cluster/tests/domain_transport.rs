use cyxia_cluster_transport::tls::{Buffers, Pairing, Session, node_id};
use cyxia_prototype::cluster::wire::Header;
use cyxia_prototype::domains::{
    Error, ObjectKey,
    tasks::{Ipc, IpcBackend, IpcOperation, Message},
};
use cyxia_prototype_cluster::{abi::*, domain_ingress::*};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
use std::{cell::Cell, sync::Arc, time::Duration};
#[derive(Debug)]
struct Clock;
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(
            1_800_000_000,
        )))
    }
}
fn pairings() -> [Pairing; 2] {
    let mut fixtures = [
        (
            &include_bytes!("../../../crates/cluster-transport/tests/fixtures/a-test-cert.der")[..],
            &include_bytes!("../../../crates/cluster-transport/tests/fixtures/a-test-key.der")[..],
        ),
        (
            &include_bytes!("../../../crates/cluster-transport/tests/fixtures/b-test-cert.der")[..],
            &include_bytes!("../../../crates/cluster-transport/tests/fixtures/b-test-key.der")[..],
        ),
    ];
    fixtures.sort_by_key(|(certificate, _)| node_id(&CertificateDer::from(*certificate)).unwrap());
    core::array::from_fn(|i| {
        Pairing::new(
            CertificateDer::from(fixtures[i].0),
            PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
            node_id(&CertificateDer::from(fixtures[1 - i].0)).unwrap(),
            Arc::new(Clock),
        )
        .unwrap()
    })
}
fn transfer(a: &mut Session<'_>, b: &mut Session<'_>) {
    let count = a.pending_tls().len().min(37);
    if count != 0 {
        let n = b.receive_tls(&a.pending_tls()[..count]).unwrap();
        a.consume_tls(n).unwrap();
    }
}
fn handshake(a: &mut Session<'_>, b: &mut Session<'_>) {
    handshake_at(a, b, 0)
}
fn handshake_at(a: &mut Session<'_>, b: &mut Session<'_>, now: u64) {
    for _ in 0..20000 {
        a.pump(now).unwrap();
        b.pump(now).unwrap();
        transfer(a, b);
        transfer(b, a);
        if a.authenticated_peer().is_some()
            && b.authenticated_peer().is_some()
            && a.pending_tls().is_empty()
            && b.pending_tls().is_empty()
        {
            return;
        }
    }
    panic!("TLS handshake failed to complete");
}
#[test]
fn delayed_real_handshake_adopts_exact_rate_and_recovery_does_not_adopt_a_new_policy() {
    let mut ingress = TlsIngress::new(0).unwrap();
    ingress.install(policy(8), 0).unwrap();
    assert_eq!(ingress.receipt.outcome, DOMAIN_PENDING);
    ingress.observe(2500).unwrap();
    assert_eq!(ingress.receipt.outcome, DOMAIN_PENDING, "installation and elapsed time are not execution");
    let (ticket, [client, server]) = ingress.begin([10, 0, 0, 1], 3000, || Ok(pairings())).unwrap();
    let mut left = Buffers::new();
    let mut right = Buffers::new();
    let mut a = client.client(&mut left, 3000).unwrap();
    let mut b = server.server(&mut right, 3000).unwrap();
    handshake_at(&mut a, &mut b, 3000);
    assert!(a.authenticated_peer().is_some() && b.authenticated_peer().is_some());
    ingress.finish(ticket, true, 3000).unwrap();
    let adopted = ingress.receipt;
    assert_eq!(adopted.outcome, DOMAIN_APPLIED);
    assert_eq!(adopted.actual, 8);
    assert_eq!((adopted.version, adopted.plan_seq, adopted.controller_epoch, adopted.action_index), (1, 19, 7, 2));
    let session = ObjectKey { id: 9, generation: 3 };
    let (reserved, ()) = ingress.enter_authenticated_at(session, 3_000_000_000, || Ok(())).unwrap();
    let mut next = policy(4);
    next.version = 2;
    next.plan_seq = 20;
    next.snapshot_ns = 4_000_000_000;
    next.installed_until_ns = 14_000_000_000;
    ingress.install_at(next, 4_000_000_000).unwrap();
    ingress.leave_authenticated_at(session, reserved, 4_000_000_001).unwrap();
    assert_eq!(ingress.receipt.outcome, DOMAIN_PENDING, "authenticated recovery cannot stand in for an unauthenticated admission");
    let (next_ticket, ()) = ingress.begin_at([10, 0, 0, 1], 4_000_000_002, || Ok(())).unwrap();
    assert_eq!(ingress.receipt.outcome, DOMAIN_APPLIED);
    assert_eq!((ingress.receipt.version, ingress.receipt.plan_seq, ingress.receipt.actual), (2, 20, 4));
    ingress.finish_at(next_ticket, true, 4_000_000_003).unwrap();
}
fn policy(value: u64) -> PolicyWire {
    PolicyWire {
        version: 1,
        snapshot_ns: 0,
        installed_until_ns: 10_000_000_000,
        value,
        plan_seq: 19,
        controller_epoch: 7,
        action_index: 2,
    }
}
#[test]
fn native_ingress_debits_before_real_pairing_creation_and_reports_window_rates() {
    let constructed = Cell::new(0);
    let mut ingress = TlsIngress::new(0).unwrap();
    ingress.install(policy(4), 0).unwrap();
    for _ in 0..4 {
        let (ticket, pairings) = ingress
            .begin([10, 0, 0, 1], 0, || {
                constructed.set(constructed.get() + 1);
                Ok(pairings())
            })
            .unwrap();
        drop(pairings);
        ingress.finish(ticket, false, 0).unwrap();
    }
    assert!(matches!(
        ingress.begin([10, 0, 0, 1], 0, || {
            constructed.set(constructed.get() + 1);
            Ok(pairings())
        }),
        Err(Error::Again)
    ));
    assert_eq!(constructed.get(), 4);
    assert_eq!(ingress.observe(999).unwrap(), None);
    assert_eq!(ingress.observe(1000).unwrap(), Some([5, 4, 0, 1]));
    assert_eq!(ingress.receipt.outcome, DOMAIN_APPLIED);
    assert_eq!(ingress.receipt.actual, 4);
    assert_eq!(
        (
            ingress.receipt.plan_seq,
            ingress.receipt.controller_epoch,
            ingress.receipt.action_index
        ),
        (19, 7, 2)
    );
    assert_eq!(
        (
            ingress.receipt.request_id,
            ingress.receipt.request_generation
        ),
        (UNAUTH_SERVICE_ID, 1)
    );
}
#[test]
fn fractional_millisecond_leases_do_not_reject_fresh_policy_or_rewrite_applied_receipts() {
    let mut wire = policy(4);
    wire.snapshot_ns = 500_000;
    wire.installed_until_ns += 500_000;
    let mut ingress = TlsIngress::new(0).unwrap();
    ingress.install_at(wire, 600_000).unwrap();
    let (ticket, ()) = ingress.begin_at([10, 0, 0, 1], 600_000, || Ok(())).unwrap();
    ingress.finish_at(ticket, true, 600_001).unwrap();
    let applied = ingress.receipt;
    assert_eq!(applied.outcome, DOMAIN_APPLIED);
    let (ticket, ()) = ingress
        .begin_at([10, 0, 0, 1], wire.installed_until_ns, || Ok(()))
        .unwrap();
    assert_eq!(
        ingress
            .security
            .effective_rate(wire.installed_until_ns)
            .unwrap(),
        16
    );
    assert_eq!(
        ingress.receipt, applied,
        "expiry changes new admission, not a settled apply receipt"
    );
    ingress
        .finish_at(ticket, true, wire.installed_until_ns)
        .unwrap();
    ingress
        .install_at(wire, wire.installed_until_ns + 1)
        .unwrap();
    assert_eq!(
        ingress
            .security
            .effective_rate(wire.installed_until_ns + 1)
            .unwrap(),
        16,
        "repeating a policy version never renews its TTL"
    );
    let mut unused = TlsIngress::new(0).unwrap();
    unused.install_at(wire, 600_000).unwrap();
    let (ticket, ()) = unused
        .begin_at([10, 0, 0, 2], wire.installed_until_ns, || Ok(()))
        .unwrap();
    assert_eq!(unused.receipt.outcome, DOMAIN_EXPIRED);
    assert_eq!(unused.receipt.actual, 16);
    unused
        .finish_at(ticket, true, wire.installed_until_ns)
        .unwrap();
}
struct Outbox {
    bytes: Vec<u8>,
    offset: usize,
}
impl RpcOutbox for Outbox {
    fn outgoing(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
    fn consume(&mut self, bytes: usize) {
        self.offset += bytes;
    }
}
struct Link<'a, 'b> {
    peer: &'a mut Session<'b>,
    blocked: bool,
    classes: &'a Cell<(u64, u64)>,
}
impl Link<'_, '_> {
    fn send(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if self.blocked {
            return Err(Error::Again);
        }
        self.peer
            .receive_tls(&bytes[..bytes.len().min(337)])
            .map_err(|_| Error::Io)
    }
}
impl TlsTransport for Link<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let count = self.send(bytes)?;
        let (ordinary, reserved) = self.classes.get();
        self.classes
            .set((ordinary + u64::from(count != 0), reserved));
        Ok(count)
    }
    fn write_reserved(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let count = self.send(bytes)?;
        let (ordinary, reserved) = self.classes.get();
        self.classes
            .set((ordinary, reserved + u64::from(count != 0)));
        Ok(count)
    }
}
fn frame(kind: u16, sequence: u64, bytes: usize) -> Vec<u8> {
    let header = Header {
        kind,
        body_len: bytes as u32,
        sequence,
        request: [1; 16],
        cluster: [2; 32],
        epoch: 1,
        sender_boot: 1,
        receiver_boot: 1,
    };
    let mut output = header.encode().to_vec();
    output.extend(vec![sequence as u8; bytes]);
    output
}
#[test]
fn native_egress_preserves_tls_suffix_and_sequence_while_separating_control_credits() {
    let [small, large] = pairings();
    let mut small_buffers = Box::new(Buffers::new());
    let mut large_buffers = Box::new(Buffers::new());
    let mut a = small.client(&mut small_buffers, 0).unwrap();
    let mut b = large.server(&mut large_buffers, 0).unwrap();
    handshake(&mut a, &mut b);
    let mut expected = frame(16, 1, 10000);
    expected.extend(frame(2, 2, 100));
    let mut outbox = Outbox {
        bytes: expected.clone(),
        offset: 0,
    };
    let mut egress = TlsEgress::new(1).unwrap();
    egress.install(policy(1), 0).unwrap();
    let classes = Cell::new((0, 0));
    let first = egress
        .service(
            &mut a,
            &mut outbox,
            0,
            &mut Link {
                peer: &mut b,
                blocked: true,
                classes: &classes,
            },
        )
        .unwrap();
    assert_eq!((first.ordinary, first.reserved), (0, 0));
    assert!(
        !a.pending_tls().is_empty(),
        "backpressure retains encrypted bytes already accepted from outbox"
    );
    assert_eq!(egress.receipt.outcome, DOMAIN_PENDING);
    let mut received = Vec::new();
    let mut saw_reserved = false;
    for now in 1..1000 {
        let round = egress
            .service(
                &mut a,
                &mut outbox,
                now,
                &mut Link {
                    peer: &mut b,
                    blocked: false,
                    classes: &classes,
                },
            )
            .unwrap();
        assert!(round.ordinary <= 1 && round.reserved <= 4);
        saw_reserved |= round.reserved != 0;
        b.pump(now).unwrap();
        received.extend_from_slice(b.plaintext());
        let count = b.plaintext().len();
        b.consume_plaintext(count).unwrap();
        if received.len() == expected.len() {
            break;
        }
    }
    assert_eq!(
        received, expected,
        "RPC frames retain authenticated TCP sequence order"
    );
    assert!(saw_reserved);
    assert_eq!(egress.receipt.outcome, DOMAIN_APPLIED);
    assert_eq!(egress.receipt.actual, 1);
    assert_eq!(egress.receipt.request_id, TX_SERVICE_ID);
    assert!(egress.counts().0 > 1 && egress.counts().1 > 0);
    assert_eq!(
        classes.get(),
        egress.counts(),
        "ordinary and reserved writes reach distinct transport methods"
    );
    let applied = egress.receipt;
    let mut after_expiry = Outbox {
        bytes: frame(16, 3, 2000),
        offset: 0,
    };
    let expired = egress
        .service_at(
            &mut a,
            &mut after_expiry,
            10_000_000_000,
            &mut Link {
                peer: &mut b,
                blocked: false,
                classes: &classes,
            },
        )
        .unwrap();
    assert_eq!(expired.policy_version, 0);
    assert_eq!(
        expired.ordinary, 4,
        "the expired batch1 policy falls back to actual batch4 sends"
    );
    assert_eq!(
        egress.receipt, applied,
        "expiry preserves the settled execution receipt"
    );
    let mut rejected = policy(8);
    rejected.version = 2;
    rejected.plan_seq = 20;
    assert!(egress.install_at(rejected, 10_000_000_001).is_err());
    let failed = egress.receipt;
    assert_eq!((failed.version, failed.outcome), (2, DOMAIN_REJECTED));
    egress
        .service_at(
            &mut a,
            &mut after_expiry,
            10_000_000_002,
            &mut Link {
                peer: &mut b,
                blocked: true,
                classes: &classes,
            },
        )
        .unwrap();
    assert_eq!(
        egress.receipt, failed,
        "old work cannot overwrite a newer proposal's rejection"
    );
}

const NETWORK_OWNER: ObjectKey = ObjectKey {
    id: 100,
    generation: 1,
};
struct IpcPeer<'a, 'b> {
    peer: &'a mut Session<'b>,
    endpoint: ObjectKey,
}
impl IpcBackend<256> for IpcPeer<'_, '_> {
    fn authorize(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        _: IpcOperation,
    ) -> Result<(), Error> {
        if actor == NETWORK_OWNER && endpoint == self.endpoint {
            Ok(())
        } else {
            Err(Error::Auth)
        }
    }
    fn notify(&mut self, actor: ObjectKey, endpoint: ObjectKey) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)
    }
    fn deliver(
        &mut self,
        actor: ObjectKey,
        endpoint: ObjectKey,
        message: &Message<256>,
    ) -> Result<(), Error> {
        self.authorize(actor, endpoint, IpcOperation::Receive)?;
        let count = self
            .peer
            .receive_tls(&message.bytes[..message.len])
            .map_err(|_| Error::Io)?;
        assert_eq!(
            count, message.len,
            "the test receiver has capacity for a complete IPC message"
        );
        Ok(())
    }
}
struct QueuedLink<'a, 'b> {
    peer: &'a mut Session<'b>,
    ipc: Ipc<256>,
    endpoint: ObjectKey,
    sequence: u64,
    now_ns: u64,
    drain_enabled: bool,
    blocked_reserved: u64,
    sent_reserved: u64,
}
impl QueuedLink<'_, '_> {
    fn depth(&self) -> usize {
        self.ipc.stats(self.endpoint).unwrap().depth
    }
    fn drain(&mut self) -> Result<usize, Error> {
        if !self.drain_enabled {
            return Ok(0);
        }
        self.ipc.receive_batch(
            NETWORK_OWNER,
            self.endpoint,
            self.now_ns,
            &mut IpcPeer {
                peer: self.peer,
                endpoint: self.endpoint,
            },
        )
    }
}
impl TlsTransport for QueuedLink<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        let count = bytes.len().min(256);
        self.sequence += 1;
        self.ipc.send(
            NETWORK_OWNER,
            self.endpoint,
            self.sequence,
            &bytes[..count],
            self.now_ns,
            &mut IpcPeer {
                peer: self.peer,
                endpoint: self.endpoint,
            },
        )?;
        Ok(count)
    }
    fn write_reserved(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.drain()?;
        if self.depth() != 0 {
            self.blocked_reserved += 1;
            return Err(Error::Again);
        }
        let count = self.peer.receive_tls(bytes).map_err(|_| Error::Io)?;
        self.sent_reserved += u64::from(count != 0);
        Ok(count)
    }
}
#[test]
fn reserved_ciphertext_waits_for_real_ipc_prefix_and_bounded_drain() {
    // Native keeps this fixed queue in static storage. The host thread needs
    // enough stack to construct that same pool without changing its bounds.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let [small, large] = pairings();
            let mut small_buffers = Box::new(Buffers::new());
            let mut large_buffers = Box::new(Buffers::new());
            let mut a = small.client(&mut small_buffers, 0).unwrap();
            let mut b = large.server(&mut large_buffers, 0).unwrap();
            handshake(&mut a, &mut b);
            let mut expected = frame(16, 1, 3000);
            expected.extend(frame(2, 2, 100));
            let mut outbox = Outbox {
                bytes: expected.clone(),
                offset: 0,
            };
            let mut egress = TlsEgress::new(1).unwrap();
            egress.install(policy(16), 0).unwrap();
            let mut ipc = Ipc::new();
            let endpoint = ipc.open(NETWORK_OWNER, false).unwrap();
            let mut link = QueuedLink {
                peer: &mut b,
                ipc,
                endpoint,
                sequence: 0,
                now_ns: 0,
                drain_enabled: false,
                blocked_reserved: 0,
                sent_reserved: 0,
            };
            let first = egress.service(&mut a, &mut outbox, 0, &mut link).unwrap();
            assert!(first.ordinary > 4 && link.depth() > 4);
            assert_eq!(first.reserved, 0);
            let depth = link.depth();
            let blocked = egress.service(&mut a, &mut outbox, 1, &mut link).unwrap();
            assert_eq!((blocked.ordinary, blocked.reserved), (0, 0));
            assert_eq!(link.sent_reserved, 0);
            assert!(link.blocked_reserved > 0);
            assert_eq!(
                link.depth(),
                depth,
                "blocked TCP leaves every queued prefix message owned by IPC"
            );
            let suffix = a.pending_tls().to_vec();
            assert!(!suffix.is_empty());
            egress.service(&mut a, &mut outbox, 2, &mut link).unwrap();
            assert_eq!(
                a.pending_tls(),
                suffix,
                "AGAIN retains the exact reserved TLS record"
            );
            assert!(link.peer.plaintext().is_empty());
            link.drain_enabled = true;
            egress.service(&mut a, &mut outbox, 3, &mut link).unwrap();
            assert_eq!(
                link.depth(),
                depth - 4,
                "one drain obeys the actual IPC batch4 baseline"
            );
            assert_eq!(
                link.sent_reserved, 0,
                "a partial drain never allows reserved ciphertext to overtake"
            );
            let mut received = Vec::new();
            for now in 4..100 {
                link.now_ns = now * 1_000_000;
                egress.service(&mut a, &mut outbox, now, &mut link).unwrap();
                link.peer.pump(now).unwrap();
                received.extend_from_slice(link.peer.plaintext());
                let count = link.peer.plaintext().len();
                link.peer.consume_plaintext(count).unwrap();
                if received.len() == expected.len() {
                    break;
                }
            }
            assert_eq!(link.depth(), 0);
            assert!(link.sent_reserved > 0);
            assert_eq!(
                received, expected,
                "mutual TLS verifies ordered delivery across both admission paths"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
