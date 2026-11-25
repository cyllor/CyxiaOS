//! Host tests for the SEC-N service adapter. Test identities and ephemeral
//! secrets only; a mock socket never stands in for real TCP/VirtIO/DMA proof.
extern crate std;
use super::*;
use crate::tls::{Buffers, Pairing, Session, node_id};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
use std::sync::Arc;
use std::vec::Vec;

#[derive(Debug)]
struct Time;
impl rustls::time_provider::TimeProvider for Time {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
            1_800_000_000,
        )))
    }
}
fn local_pairings() -> [Pairing; 2] {
    let mut fixtures = [
        (
            &include_bytes!("../tests/fixtures/a-test-cert.der")[..],
            &include_bytes!("../tests/fixtures/a-test-key.der")[..],
        ),
        (
            &include_bytes!("../tests/fixtures/b-test-cert.der")[..],
            &include_bytes!("../tests/fixtures/b-test-key.der")[..],
        ),
    ];
    fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
    core::array::from_fn(|i| {
        Pairing::new_local_echo(
            CertificateDer::from(fixtures[i].0),
            PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
            node_id(&CertificateDer::from(fixtures[1 - i].0)).unwrap(),
            Arc::new(Time),
        )
        .unwrap()
    })
}
fn transfer(a: &mut Session<'_>, b: &mut Session<'_>) {
    let n = b.receive_tls(a.pending_tls()).unwrap();
    a.consume_tls(n).unwrap();
}
fn handshake(a: &mut Session<'_>, b: &mut Session<'_>) {
    for _ in 0..100 {
        a.pump(0).unwrap();
        b.pump(0).unwrap();
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
    panic!("handshake did not complete");
}
fn echo_frame(seq: u64, payload: [u8; 4]) -> [u8; 20] {
    let mut frame = [0u8; 20];
    frame[..2].copy_from_slice(&1u16.to_le_bytes());
    frame[2..4].copy_from_slice(&1u16.to_le_bytes());
    frame[4..8].copy_from_slice(&4u32.to_le_bytes());
    frame[8..16].copy_from_slice(&seq.to_le_bytes());
    frame[16..20].copy_from_slice(&payload);
    frame
}

/// Bidirectional byte pipe with bounded partial IO. It is a mock transport, not
/// a device: it never asserts TX quiescence (default fail-closed false).
struct Pipe {
    to_server: Vec<u8>,
    server_read: usize,
    from_server: Vec<u8>,
    chunk: usize,
}
impl Pipe {
    fn new(chunk: usize) -> Self {
        Self {
            to_server: Vec::new(),
            server_read: 0,
            from_server: Vec::new(),
            chunk,
        }
    }
}
impl NativeSocket for Pipe {
    fn poll_native(&mut self, _: u64) -> Result<(), SocketError> {
        Ok(())
    }
    fn read_ciphertext(&mut self, out: &mut [u8]) -> Result<usize, SocketError> {
        if self.server_read == self.to_server.len() {
            return Err(SocketError::Again);
        }
        let n = out
            .len()
            .min(self.chunk)
            .min(self.to_server.len() - self.server_read);
        out[..n].copy_from_slice(&self.to_server[self.server_read..self.server_read + n]);
        self.server_read += n;
        Ok(n)
    }
    fn queue_ciphertext(&mut self, bytes: &[u8]) -> Result<usize, SocketError> {
        let n = self.chunk.min(bytes.len());
        self.from_server.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
}

/// Mock retirement-evidence socket: asserts quiescence only when the test has
/// set BOTH the TCP-closed and NIC-done flags. It is still a host mock — it
/// never stands in for real VirtIO used-ring/DMA evidence in production.
struct EvidenceSocket {
    closed: bool,
    nic_done: bool,
}
impl NativeSocket for EvidenceSocket {
    fn terminal_tx_quiescent(&self) -> bool {
        self.closed && self.nic_done
    }
    fn poll_native(&mut self, _: u64) -> Result<(), SocketError> {
        Ok(())
    }
    fn read_ciphertext(&mut self, _: &mut [u8]) -> Result<usize, SocketError> {
        Err(SocketError::Again)
    }
    fn queue_ciphertext(&mut self, _: &[u8]) -> Result<usize, SocketError> {
        Err(SocketError::Again)
    }
}

/// Drive a real pinned handshake to completion through the service's bounded
/// `handshake_turn`, interleaving a live client on the other side of the pipe.
/// Every turn is charged to the exact live pending lease.
fn drive_handshake(
    service: &mut Service,
    pipe: &mut Pipe,
    ticket: PendingTicket,
    server: &mut Session<'_>,
    client: &mut Session<'_>,
    scratch: &mut [u8],
) -> u64 {
    for now in 1..=400u64 {
        client.pump(now).unwrap();
        let out = client.pending_tls().to_vec();
        client.consume_tls(out.len()).unwrap();
        pipe.to_server.extend_from_slice(&out);
        let done = service
            .handshake_turn(pipe, ticket, server, scratch, now)
            .unwrap();
        let incoming = core::mem::take(&mut pipe.from_server);
        if !incoming.is_empty() {
            client.receive_tls(&incoming).unwrap();
        }
        if done && client.authenticated_peer().is_some() {
            return now;
        }
    }
    panic!("service handshake did not complete");
}

#[test]
fn service_handshake_turn_completes_a_real_pinned_session_over_native_socket() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    assert_eq!(service.pending_count(), 1);
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    let mut pipe = Pipe::new(64);
    let mut scratch = [0u8; 4096];
    drive_handshake(
        &mut service,
        &mut pipe,
        ticket,
        &mut server,
        &mut client,
        &mut scratch,
    );
    assert!(server.local_echo_proof().is_some());
    assert!(client.authenticated_peer().is_some());
    let active = service.authenticate(ticket, &server).unwrap();
    assert_eq!(service.active_count(), 1);
    assert_eq!(service.pending_count(), 0);
    let _ = active;
}

#[test]
fn service_echo_turn_round_trips_a_readonly_frame_and_retires_only_on_evidence() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    let mut pipe = Pipe::new(7);
    let mut scratch = [0u8; 4096];
    let mut now = drive_handshake(
        &mut service,
        &mut pipe,
        ticket,
        &mut server,
        &mut client,
        &mut scratch,
    );
    let active = service.authenticate(ticket, &server).unwrap();

    let frame = echo_frame(13, [9, 8, 7, 6]);
    client.send_plaintext(&frame).unwrap();
    now += 1;
    client.pump(now).unwrap();
    let encrypted = client.pending_tls().to_vec();
    client.consume_tls(encrypted.len()).unwrap();
    pipe.to_server.extend_from_slice(&encrypted);

    let mut echoes = 0;
    for _ in 0..240 {
        now += 1;
        let progress = service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
        echoes += usize::from(progress.echo_queued != 0);
        let outgoing = core::mem::take(&mut pipe.from_server);
        if !outgoing.is_empty() {
            client.receive_tls(&outgoing).unwrap();
        }
        client.pump(now).unwrap();
        if echoes != 0 && !server.has_pending_plaintext() && server.pending_tls().is_empty() {
            break;
        }
    }
    assert_eq!(echoes, 1, "partial records never generate two replies");
    assert_eq!(client.plaintext(), frame.as_slice());

    // The mock pipe cannot certify device quiescence: retirement must fail
    // closed even though TLS output is drained. No fabricated completion.
    assert!(matches!(
        service.finish(&pipe, active, &server),
        Err(Error::Native(native_tcp::Error::Admission(
            AdmissionError::Busy
        )))
    ));
    assert_eq!(service.active_count(), 1);
}

#[test]
fn service_finish_requires_device_quiescence_and_exact_session() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    handshake(&mut client, &mut server);
    let ticket = service.admit(7, 0, 16).unwrap();
    let active = service.authenticate(ticket, &server).unwrap();

    let mut socket = EvidenceSocket {
        closed: false,
        nic_done: false,
    };
    assert!(service.finish(&socket, active, &server).is_err());
    socket.closed = true;
    assert!(service.finish(&socket, active, &server).is_err());
    socket.nic_done = true;
    // A different TLS session cannot retire this connection's credit.
    let mut other_buf = Buffers::new();
    let other = service.session(&mut other_buf, 0).unwrap();
    assert!(matches!(
        service.finish(&socket, active, &other),
        Err(Error::Native(native_tcp::Error::Admission(
            AdmissionError::Unauthenticated
        )))
    ));
    assert_eq!(service.active_count(), 1);
    service.finish(&socket, active, &server).unwrap();
    assert_eq!(service.active_count(), 0);
    assert!(service.finish(&socket, active, &server).is_err());
}

#[test]
fn service_restart_retains_outstanding_credit() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    handshake(&mut client, &mut server);
    let ticket = service.admit(7, 0, 16).unwrap();
    let active = service.authenticate(ticket, &server).unwrap();
    service.begin_restart();
    assert!(service.restarting());
    assert!(service.finish_restart().is_err());
    assert_eq!(service.active_count(), 1);
    // A restart cannot admit new work.
    assert!(service.admit(8, 1, 16).is_err());
    let _ = active;
}

#[test]
fn service_rejects_unauthenticated_and_replayed_sessions() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    let mut server_buf = Buffers::new();
    let server = service.session(&mut server_buf, 0).unwrap();
    // No handshake yet: no proof, so authentication must fail closed.
    assert!(matches!(
        service.authenticate(ticket, &server),
        Err(Error::Admission(AdmissionError::Unauthenticated))
    ));
    assert_eq!(service.pending_count(), 0);
    let _ = client_pairing;
}

#[test]
fn service_socket_boundary_accepts_the_virtio_backed_native_tcp() {
    use crate::device::{Error as DeviceError, MTU, Port};
    use crate::tcp::Tcp;
    fn requires_native_socket<S: NativeSocket>() {}
    // Compile-time proof: the real VirtIO-backed native TCP type satisfies the
    // service's socket boundary (VirtioLink -> VirtioPort -> Tcp -> Service).
    requires_native_socket::<Tcp<'static, DummyPort>>();
    struct DummyPort;
    impl Port for DummyPort {
        fn send(&mut self, _: &[u8]) -> Result<(), DeviceError> {
            Ok(())
        }
        fn receive(&mut self, _: &mut [u8; MTU]) -> Result<Option<usize>, DeviceError> {
            Ok(None)
        }
    }
    // An unsupported port must not manufacture a TX quiescence witness.
    assert!(!DummyPort.tx_quiescent());
}

#[test]
fn service_handshake_ticket_generation_mismatch_gets_no_device_work() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let old = service.admit(7, 0, 16).unwrap();
    service.reject(old).unwrap();
    let fresh = service.admit(7, 1_000_000_000, 16).unwrap();
    assert_ne!(old, fresh);
    let mut server_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut pipe = Pipe::new(64);
    let mut scratch = [0u8; 4096];
    // ABA: the replayed old-generation ticket is refused before any socket
    // work and can never spend the fresh lease's handshake budget.
    let error = service
        .handshake_turn(&mut pipe, old, &mut server, &mut scratch, 0)
        .unwrap_err();
    assert!(matches!(error, Error::Admission(AdmissionError::Stale)));
    assert_eq!(error.disposition(), Disposition::FailClosed);
    assert_eq!(service.handshake_turns_used(old), None);
    assert_eq!(service.handshake_turns_used(fresh), Some(0));
    // The fresh generation drives the real handshake to completion.
    let mut client_buf = Buffers::new();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    drive_handshake(
        &mut service,
        &mut pipe,
        fresh,
        &mut server,
        &mut client,
        &mut scratch,
    );
    let active = service.authenticate(fresh, &server).unwrap();
    // The consumed pending generation cannot authenticate a second time.
    assert!(matches!(
        service.authenticate(fresh, &server),
        Err(Error::Admission(AdmissionError::Stale))
    ));
    assert_eq!(service.active_count(), 1);
    let _ = active;
}

#[test]
fn service_handshake_turn_budget_is_bounded_and_fails_closed() {
    let [_client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    let mut server_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    // Empty pipe: the peer never sends handshake bytes. A frozen clock must
    // not allow an unbounded handshake spin; the turn budget is the backstop.
    let mut pipe = Pipe::new(64);
    let mut scratch = [0u8; 4096];
    for _ in 0..HANDSHAKE_TURN_BUDGET {
        assert!(
            !service
                .handshake_turn(&mut pipe, ticket, &mut server, &mut scratch, 0)
                .unwrap()
        );
    }
    assert_eq!(
        service.handshake_turns_used(ticket),
        Some(HANDSHAKE_TURN_BUDGET)
    );
    let error = service
        .handshake_turn(&mut pipe, ticket, &mut server, &mut scratch, 0)
        .unwrap_err();
    assert!(matches!(error, Error::Budget));
    assert_eq!(error.disposition(), Disposition::FailClosed);
    // Exhaustion ends only this failed handshake: its pending credit is
    // released, the session is aborted, and no active credit or device
    // completion claim is created.
    assert_eq!(service.pending_count(), 0);
    assert_eq!(service.active_count(), 0);
    assert!(server.authenticated_peer().is_none());
    assert_eq!(service.handshake_turns_used(ticket), None);
    // A fresh lease starts with its own full budget: no cross-lease debt or
    // inheritance, and the service is not poisoned by the refusal.
    let fresh = service.admit(7, 1_000_000_000, 16).unwrap();
    assert_eq!(service.handshake_turns_used(fresh), Some(0));
    service.reject(fresh).unwrap();
}

#[test]
fn service_echo_stall_budget_retains_credit_until_real_evidence() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    let mut pipe = Pipe::new(64);
    let mut scratch = [0u8; 4096];
    let mut now = drive_handshake(
        &mut service,
        &mut pipe,
        ticket,
        &mut server,
        &mut client,
        &mut scratch,
    );
    let active = service.authenticate(ticket, &server).unwrap();
    assert_eq!(service.echo_stall_turns(active), Some(0));
    // No traffic: every turn is zero-progress. The stall budget bounds the
    // unproductive spin without any clock input.
    for _ in 0..ECHO_STALL_TURN_BUDGET - 1 {
        now += 1;
        let progress = service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
        assert_eq!(progress, Progress::default());
    }
    now += 1;
    let error = service
        .turn(&mut pipe, active, &mut server, &mut scratch, now)
        .unwrap_err();
    assert!(matches!(error, Error::Budget));
    assert_eq!(error.disposition(), Disposition::FailClosed);
    // Budget exhaustion is NOT device completion: the active credit stays
    // retained and the connection is draining.
    assert_eq!(service.active_count(), 1);
    assert_eq!(
        service.echo_stall_turns(active),
        Some(ECHO_STALL_TURN_BUDGET)
    );
    // Further turns fail closed without doing device work.
    assert!(matches!(
        service.turn(&mut pipe, active, &mut server, &mut scratch, now + 1),
        Err(Error::Budget)
    ));
    // The mock pipe cannot prove quiescence: retirement still fails closed.
    assert!(service.finish(&pipe, active, &server).is_err());
    assert_eq!(service.active_count(), 1);
    // Only the evidence-gated path retires the credit and its budget entry.
    let socket = EvidenceSocket {
        closed: true,
        nic_done: true,
    };
    service.finish(&socket, active, &server).unwrap();
    assert_eq!(service.active_count(), 0);
    assert_eq!(service.echo_stall_turns(active), None);
    // A replayed retired ticket gets no work and fails closed.
    assert!(matches!(
        service.turn(&mut pipe, active, &mut server, &mut scratch, now + 2),
        Err(Error::Admission(AdmissionError::Stale))
    ));
}

#[test]
fn service_echo_progress_resets_the_stall_budget() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 0, 16).unwrap();
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    let mut pipe = Pipe::new(64);
    let mut scratch = [0u8; 4096];
    let mut now = drive_handshake(
        &mut service,
        &mut pipe,
        ticket,
        &mut server,
        &mut client,
        &mut scratch,
    );
    let active = service.authenticate(ticket, &server).unwrap();
    // Charge stall turns, then let one real Echo dispatch reset the counter.
    for _ in 0..16 {
        now += 1;
        service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
    }
    assert_eq!(service.echo_stall_turns(active), Some(16));
    let frame = echo_frame(21, [1, 2, 3, 4]);
    client.send_plaintext(&frame).unwrap();
    now += 1;
    client.pump(now).unwrap();
    let encrypted = client.pending_tls().to_vec();
    client.consume_tls(encrypted.len()).unwrap();
    pipe.to_server.extend_from_slice(&encrypted);
    now += 1;
    let progress = service
        .turn(&mut pipe, active, &mut server, &mut scratch, now)
        .unwrap();
    assert!(progress.echo_queued != 0);
    assert_eq!(service.echo_stall_turns(active), Some(0));
    // Stall again: the budget counts consecutive stalls, not lifetime turns,
    // so a productive long-lived connection is never capped.
    for _ in 0..16 {
        now += 1;
        service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
    }
    assert_eq!(service.echo_stall_turns(active), Some(16));
    // Drain the outstanding reply through the bounded turn path, then retire
    // only on evidence.
    for _ in 0..8 {
        now += 1;
        service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
        let outgoing = core::mem::take(&mut pipe.from_server);
        if !outgoing.is_empty() {
            client.receive_tls(&outgoing).unwrap();
        }
        client.pump(now).unwrap();
        if !server.has_pending_plaintext() && server.pending_tls().is_empty() {
            break;
        }
    }
    assert_eq!(client.plaintext(), frame.as_slice());
    let socket = EvidenceSocket {
        closed: true,
        nic_done: true,
    };
    service.finish(&socket, active, &server).unwrap();
    assert_eq!(service.active_count(), 0);
}

#[test]
fn service_finish_requires_tls_drain_even_with_device_quiescence() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    handshake(&mut client, &mut server);
    let ticket = service.admit(7, 0, 16).unwrap();
    let active = service.authenticate(ticket, &server).unwrap();
    // Dispatch one real Echo reply; the tiny pipe chunk leaves part of the
    // ciphertext still owned by TLS after the turn.
    let frame = echo_frame(5, [4, 3, 2, 1]);
    client.send_plaintext(&frame).unwrap();
    client.pump(1).unwrap();
    let encrypted = client.pending_tls().to_vec();
    client.consume_tls(encrypted.len()).unwrap();
    let mut pipe = Pipe::new(7);
    pipe.to_server.extend_from_slice(&encrypted);
    let mut scratch = [0u8; 4096];
    // The 7-byte chunk fragments the request record across turns; drive the
    // bounded turn path until the complete frame dispatches exactly once.
    let mut now = 2u64;
    let mut dispatched = false;
    for _ in 0..32 {
        let progress = service
            .turn(&mut pipe, active, &mut server, &mut scratch, now)
            .unwrap();
        if progress.echo_queued != 0 {
            dispatched = true;
            break;
        }
        now += 1;
    }
    assert!(dispatched);
    // The same tiny chunk leaves part of the reply ciphertext TLS-owned.
    assert!(!server.pending_tls().is_empty());
    let socket = EvidenceSocket {
        closed: true,
        nic_done: true,
    };
    // Device quiescent, but the reply is still TLS-owned egress debt: normal
    // retirement must fail closed even with a fully quiescent device.
    assert!(matches!(
        service.finish(&socket, active, &server),
        Err(Error::Native(native_tcp::Error::Admission(
            AdmissionError::Busy
        )))
    ));
    assert_eq!(service.active_count(), 1);
    // Reconcile the TLS debt: the mock TCP accepts the remaining ciphertext.
    let remaining = server.pending_tls().len();
    server.consume_tls(remaining).unwrap();
    assert!(!server.has_pending_plaintext());
    service.finish(&socket, active, &server).unwrap();
    assert_eq!(service.active_count(), 0);
}

#[test]
fn service_restart_retains_credit_and_rejects_replayed_generations() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let mut server_buf = Buffers::new();
    let mut client_buf = Buffers::new();
    let mut server = service.session(&mut server_buf, 0).unwrap();
    let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
    handshake(&mut client, &mut server);
    let ticket = service.admit(7, 0, 16).unwrap();
    let active = service.authenticate(ticket, &server).unwrap();
    let pending = service.admit(8, 0, 16).unwrap();

    service.begin_restart();
    assert!(service.restarting());
    // No new admission during restart: transient backpressure, not a reset.
    let error = service.admit(9, 1_000_000_000, 16).unwrap_err();
    assert!(matches!(error, Error::Admission(AdmissionError::Busy)));
    assert_eq!(error.disposition(), Disposition::Backpressure);
    // Restart cannot complete while any credit is outstanding.
    assert!(matches!(
        service.finish_restart(),
        Err(Error::Admission(AdmissionError::Busy))
    ));
    // The outstanding pending lease is releasable exactly once, even during
    // restart; a replayed reject is stale.
    service.reject(pending).unwrap();
    assert!(matches!(
        service.reject(pending),
        Err(Error::Admission(AdmissionError::Stale))
    ));
    assert!(service.finish_restart().is_err());
    assert_eq!(service.active_count(), 1);
    // The active credit survives restart and retires only through evidence.
    let socket = EvidenceSocket {
        closed: true,
        nic_done: true,
    };
    service.finish(&socket, active, &server).unwrap();
    service.finish_restart().unwrap();
    assert!(!service.restarting());
    // Pre-restart generations are permanently stale after retirement.
    assert!(matches!(
        service.finish(&socket, active, &server),
        Err(Error::Native(native_tcp::Error::Admission(
            AdmissionError::Stale
        )))
    ));
    assert!(matches!(
        service.authenticate(ticket, &server),
        Err(Error::Admission(AdmissionError::Stale))
    ));
    assert_eq!(service.echo_stall_turns(active), None);
    assert_eq!(service.handshake_turns_used(ticket), None);
    // A restarted service admits fresh generations; source rate debt is not
    // replenished by the restart itself.
    let fresh = service.admit(7, 1_000_000_000, 16).unwrap();
    assert_ne!(fresh, ticket);
    service.reject(fresh).unwrap();
}

#[test]
fn service_error_disposition_maps_the_fail_closed_taxonomy() {
    use crate::tls::Error as TlsError;
    // Transient backpressure: the same owned work may retry on a later turn.
    for error in [
        Error::Admission(AdmissionError::Capacity),
        Error::Admission(AdmissionError::RateLimited),
        Error::Admission(AdmissionError::Busy),
        Error::Native(native_tcp::Error::Socket(SocketError::Again)),
        Error::Native(native_tcp::Error::Admission(AdmissionError::Busy)),
        Error::Tls(TlsError::WouldBlock),
    ] {
        assert_eq!(error.disposition(), Disposition::Backpressure);
    }
    // Permanent fail-closed: never retry the same identity; credit and UNKNOWN
    // device custody stay retained until real evidence reconciles them.
    for error in [
        Error::Budget,
        Error::Admission(AdmissionError::Invalid),
        Error::Admission(AdmissionError::Stale),
        Error::Admission(AdmissionError::Unauthenticated),
        Error::Admission(AdmissionError::Duplicate),
        Error::Admission(AdmissionError::Exhausted),
        Error::Native(native_tcp::Error::Socket(SocketError::Closed)),
        Error::Native(native_tcp::Error::Socket(SocketError::Device)),
        Error::Native(native_tcp::Error::Tls),
        Error::Native(native_tcp::Error::Admission(AdmissionError::Stale)),
        Error::Tls(TlsError::Closed),
        Error::Tls(TlsError::Timeout),
        Error::Tls(TlsError::Clock),
    ] {
        assert_eq!(error.disposition(), Disposition::FailClosed);
    }
    // Live refusals carry the same dispositions: a rewound trusted clock is
    // permanent fail-closed, an empty token bucket is transient backpressure.
    let [_client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let ticket = service.admit(7, 1_000_000_000, 16).unwrap();
    service.reject(ticket).unwrap();
    let rewind = service.admit(7, 0, 16).unwrap_err();
    assert!(matches!(rewind, Error::Admission(AdmissionError::Invalid)));
    assert_eq!(rewind.disposition(), Disposition::FailClosed);
    let [_client_pairing, server_pairing] = local_pairings();
    let mut gate = Service::new(server_pairing);
    for ip in 1..=4 {
        let t = gate.admit(ip, 0, 4).unwrap();
        gate.reject(t).unwrap();
    }
    let limited = gate.admit(5, 0, 4).unwrap_err();
    assert!(matches!(
        limited,
        Error::Admission(AdmissionError::RateLimited)
    ));
    assert_eq!(limited.disposition(), Disposition::Backpressure);
}

#[test]
fn service_reconnect_after_retirement_is_a_fresh_generation_not_a_replay() {
    let [client_pairing, server_pairing] = local_pairings();
    let mut service = Service::new(server_pairing);
    let socket = EvidenceSocket {
        closed: true,
        nic_done: true,
    };
    let mut first_active = None;
    for round in 0..2u64 {
        let mut server_buf = Buffers::new();
        let mut client_buf = Buffers::new();
        let mut server = service.session(&mut server_buf, 0).unwrap();
        let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
        handshake(&mut client, &mut server);
        let ticket = service.admit(7, round * 1_000_000_000, 16).unwrap();
        let active = service.authenticate(ticket, &server).unwrap();
        if let Some(old) = first_active {
            assert_ne!(old, active);
            // The retired generation reuses the slot but can never retire or
            // impersonate the new session: exact generation match is required.
            assert!(matches!(
                service.finish(&socket, old, &server),
                Err(Error::Native(native_tcp::Error::Admission(
                    AdmissionError::Stale
                )))
            ));
            assert_eq!(service.active_count(), 1);
        }
        service.finish(&socket, active, &server).unwrap();
        first_active = Some(active);
    }
    assert_eq!(service.active_count(), 0);
}
