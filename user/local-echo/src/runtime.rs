//! V0.19 single-node read-only Echo EL0 service candidate.
//!
//! Uses only kernel-owned native TCP broker calls; no member discovery,
//! remote task execution, mutable filesystem, strategy publication or AI.
//! On fault it fails closed until the kernel can prove actual NIC/DMA reset
//! and restart. This candidate is intentionally NOT installed as the current
//! production service by default.
use crate::broker;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::time::Duration;
use cyxia_net_transport::{
    admission::Admission,
    native_tcp::{self, NativeSocket, SocketError},
    tls::{Buffers, LocalEchoVerifier, Session, node_id},
};
use rustls::{
    Error as TlsError, SignatureAlgorithm, SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer, UnixTime},
    server::ParsedCertificate,
    sign::{Signer, SigningKey},
    time_provider::TimeProvider,
};

#[derive(Debug)]
struct VerifierKey(SubjectPublicKeyInfoDer<'static>);

impl SigningKey for VerifierKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(CertificateVerify) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.0.as_ref()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

#[derive(Debug)]
struct CertificateVerify;

impl Signer for CertificateVerify {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, TlsError> {
        // rustls constructs this message from the current transcript. The
        // signer receives just the SHA-256 hash and reconstructs the context.
        let hash = cyxia_contracts::tls_signer::certificate_verify_hash(message)
            .ok_or_else(|| TlsError::General("wrong CertificateVerify context".into()))?;
        broker::certificate_verify(&hash)
            .map(|signature| signature.to_vec())
            .map_err(|_| TlsError::General("CertificateVerify authorization refused".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
#[derive(Debug)]
struct Clock;
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        broker::unix_seconds().map(|secs| UnixTime::since_unix_epoch(Duration::from_secs(secs)))
    }
}
struct BrokerSocket {
    generation: u64,
    source: u32,
    terminal: bool,
}
impl NativeSocket for BrokerSocket {
    fn terminal_tx_quiescent(&self) -> bool {
        self.terminal
    }
    fn poll_native(&mut self, _now_ms: u64) -> Result<(), SocketError> {
        match broker::poll() {
            Ok((true, generation, ip, _)) if generation == self.generation && ip == self.source => {
                Ok(())
            }
            Ok(_) => Err(SocketError::Closed),
            Err(broker::Error::Again) => Err(SocketError::Again),
            Err(_) => Err(SocketError::Device),
        }
    }
    fn read_ciphertext(&mut self, out: &mut [u8]) -> Result<usize, SocketError> {
        match broker::read(out) {
            Ok(0) | Err(broker::Error::Again) => Err(SocketError::Again),
            Ok(n) => Ok(n),
            Err(broker::Error::Closed) => Err(SocketError::Closed),
            Err(_) => Err(SocketError::Device),
        }
    }
    fn queue_ciphertext(&mut self, bytes: &[u8]) -> Result<usize, SocketError> {
        let chunk = &bytes[..bytes.len().min(cyxia_local_echo::broker_surface::PAYLOAD)];
        match broker::write_ciphertext(chunk) {
            Ok(n) => Ok(n),
            Err(broker::Error::Again) => Err(SocketError::Again),
            Err(broker::Error::Closed) => Err(SocketError::Closed),
            Err(_) => Err(SocketError::Device),
        }
    }
}
fn send_pending(socket: &mut BrokerSocket, tls: &mut Session<'_>) -> Result<(), ()> {
    let pending = tls.pending_tls();
    if pending.is_empty() {
        return Ok(());
    }
    let accepted = match socket.queue_ciphertext(pending) {
        Ok(n) if n <= pending.len() => n,
        Err(SocketError::Again) => 0,
        _ => return Err(()),
    };
    tls.consume_tls(accepted).map_err(|_| ())?;
    Ok(())
}
fn handshake(
    socket: &mut BrokerSocket,
    tls: &mut Session<'_>,
    scratch: &mut [u8],
) -> Result<(), ()> {
    // The broker bounds each entry and the total number of calls. End the
    // handshake by elapsed monotonic time, independent of empty-poll speed.
    loop {
        let now = broker::now().map_err(|_| ())?;
        socket.poll_native(now).map_err(|_| ())?;
        send_pending(socket, tls)?;
        let capacity = tls.receive_capacity().min(scratch.len());
        if capacity != 0 {
            match socket.read_ciphertext(&mut scratch[..capacity]) {
                Ok(n) if n <= capacity => {
                    if tls.receive_tls(&scratch[..n]).map_err(|_| ())? != n {
                        return Err(());
                    }
                }
                Err(SocketError::Again) => {}
                _ => return Err(()),
            }
        }
        tls.pump(now).map_err(|_| ())?;
        send_pending(socket, tls)?;
        if tls.local_echo_proof().is_some() {
            return Ok(());
        }
        broker::yield_cpu();
    }
}
pub fn run() -> ! {
    let certificate =
        CertificateDer::from(&include_bytes!(concat!(env!("OUT_DIR"), "/cert.der"))[..]);
    let peer: [u8; 32] = *include_bytes!(concat!(env!("OUT_DIR"), "/peer.pin"));
    let Some((kernel_local, kernel_peer)) = broker::boot_identity() else {
        broker::park();
    };
    if node_id(&certificate).ok() != Some(kernel_local) || kernel_peer != peer {
        broker::park();
    }
    let public_key = ParsedCertificate::try_from(&certificate)
        .unwrap_or_else(|_| broker::park())
        .subject_public_key_info();
    let mut gate = Admission::new();
    let mut buffers = Buffers::new();
    let mut scratch = [0u8; cyxia_local_echo::broker_surface::PAYLOAD];
    loop {
        let now = broker::now().unwrap_or_else(|_| broker::park());
        let (connected, generation, source, normal_close) =
            broker::poll().unwrap_or_else(|_| broker::park());
        if !connected {
            broker::yield_cpu();
            continue;
        }
        if generation == 0 || source == 0 {
            broker::park();
        }
        // The broker currently exposes monotonic milliseconds. Preserve that
        // precision instead of truncating to whole seconds; full native ns
        // clock/ABI migration remains a separate acceptance requirement.
        let admission_ns = now.checked_mul(1_000_000).unwrap_or_else(|| broker::park());
        let ticket = gate
            .begin_ns(source, admission_ns, 16)
            .unwrap_or_else(|_| broker::park());
        broker::admission_granted(ticket, generation, source).unwrap_or_else(|_| broker::park());
        let pairing = LocalEchoVerifier::new(
            certificate.clone(),
            Arc::new(VerifierKey(public_key.clone())),
            peer,
            Arc::new(Clock),
        )
        .unwrap_or_else(|_| broker::park());
        // V0.19 Echo is a passive server; no cluster peer auto-dial. This
        // native profile requires a kernel-owned listener and pinned client.
        let mut session = pairing
            .server(&mut buffers, now)
            .unwrap_or_else(|_| broker::park());
        let mut socket = BrokerSocket {
            generation,
            source,
            terminal: false,
        };
        if handshake(&mut socket, &mut session, &mut scratch).is_err() {
            let _ = gate.reject(ticket);
            gate.begin_restart();
            broker::park();
        }
        let active = gate
            .authenticate(ticket, &session)
            .unwrap_or_else(|_| broker::park());
        broker::tls_authenticated(&active, generation, source).unwrap_or_else(|_| broker::park());
        if normal_close {
            session
                .enable_normal_close()
                .unwrap_or_else(|_| broker::park());
        }
        loop {
            let now = broker::now().unwrap_or_else(|_| broker::park());
            if native_tcp::turn(
                &mut socket,
                &mut gate,
                active,
                &mut session,
                &mut scratch,
                now,
            )
            .is_err()
            {
                // UNKNOWN TLS or NIC ownership may still exist. No automatic
                // credit release/reconnect until a protected reset authority
                // can prove all outstanding descriptors have stopped.
                gate.begin_restart();
                session.abort();
                broker::park();
            }
            if session.normal_close_complete() {
                // Timers only stop the attempt. Retirement requires a positive
                // kernel witness for the current generation and a finished ledger entry.
                let deadline = now.checked_add(5_000).unwrap_or_else(|| broker::park());
                loop {
                    if !matches!(broker::now(), Ok(t) if t < deadline) {
                        gate.begin_restart();
                        broker::park();
                    }
                    match broker::poll_normal_close(generation, source) {
                        Ok(()) => break,
                        Err(broker::Error::Again) => broker::yield_cpu(),
                        Err(_) => {
                            gate.begin_restart();
                            broker::park();
                        }
                    }
                }
                socket.terminal = true;
                native_tcp::finish_session(&socket, &mut gate, active, &session)
                    .unwrap_or_else(|_| broker::park());
                broker::admission_retired(generation, source).unwrap_or_else(|_| broker::park());
                broker::park();
            }
            broker::yield_cpu();
        }
    }
}
