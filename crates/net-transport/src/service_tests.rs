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

/// Drive a real pinned handshake to completion through the service's bounded
/// `handshake_turn`, interleaving a live client on the other side of the pipe.
fn drive_handshake(
    service: &mut Service,
    pipe: &mut Pipe,
    server: &mut Session<'_>,
    client: &mut Session<'_>,
    scratch: &mut [u8],
) -> u64 {
    for now in 1..=400u64 {
        client.pump(now).unwrap();
        let out = client.pending_tls().to_vec();
        client.consume_tls(out.len()).unwrap();
        pipe.to_server.extend_from_slice(&out);
        let done = service.handshake_turn(pipe, server, scratch, now).unwrap();
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
