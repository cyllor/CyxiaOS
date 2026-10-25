//! Real rustls TLS 1.3 with mutually pinned Ed25519 public keys. This optional
//! module needs a quota-backed allocator and a platform CSPRNG. The isolated
//! user/prototype-cluster service supplies these with a narrow EL1 broker.
extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use ring::digest;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError,
    ServerConfig, SignatureScheme,
    client::{
        Resumption, UnbufferedClientConnection,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{
        ParsedCertificate, UnbufferedServerConnection,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    time_provider::TimeProvider,
    unbuffered::{ConnectionState, UnbufferedStatus},
};

pub const RECORD_BUFFER: usize = 32768;
pub const PLAINTEXT_BUFFER: usize = 16384;
pub const MAX_CERTIFICATE: usize = 4096;
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 3, 0x21, 0];

#[derive(Debug)]
pub enum Error {
    Identity,
    Entropy,
    Time,
    Clock,
    Timeout,
    Protocol(TlsError),
    Buffer,
    WouldBlock,
    Handshake,
    Closed,
    Direction,
}

/// Ed25519 public-key fingerprint, not a certificate signature or a claim of
/// measured boot. Parse the certificate with rustls-webpki before inspecting
/// its canonical RFC 8410 SubjectPublicKeyInfo.
pub fn node_id(certificate: &CertificateDer<'_>) -> Result<[u8; 32], Error> {
    if certificate.as_ref().len() > MAX_CERTIFICATE {
        return Err(Error::Identity);
    }
    let parsed = ParsedCertificate::try_from(certificate).map_err(|_| Error::Identity)?;
    let spki = parsed.subject_public_key_info();
    let bytes = spki.as_ref();
    if bytes.len() != 44 || bytes[..12] != ED25519_SPKI_PREFIX {
        return Err(Error::Identity);
    }
    let hash = digest::digest(&digest::SHA256, &bytes[12..]);
    Ok(core::array::from_fn(|i| hash.as_ref()[i]))
}

#[derive(Debug)]
struct Pin {
    node: [u8; 32],
    provider: Arc<CryptoProvider>,
}
impl Pin {
    fn certificate(
        &self,
        cert: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), TlsError> {
        if !intermediates.is_empty() || node_id(cert).ok() != Some(self.node) {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(())
    }
    fn signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if signed.scheme != SignatureScheme::ED25519 {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        self.certificate(cert, &[])?;
        verify_tls13_signature(
            msg,
            cert,
            signed,
            &self.provider.signature_verification_algorithms,
        )
    }
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        ocsp: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.certificate(cert, chain)?;
        if !ocsp.is_empty() {
            return Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.signature(msg, cert, signed)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
impl ClientCertVerifier for Pin {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.certificate(cert, chain)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.signature(msg, cert, signed)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// No API accepts "already authenticated" or a boolean trust override. Both
/// directions always verify a fixed public-key pin and a real Ed25519 TLS
/// CertificateVerify signature. Certificate validity dates are intentionally
/// not Web-PKI authority in this closed pairing model (§10.2).
pub struct Pairing {
    local: [u8; 32],
    peer: [u8; 32],
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    time: Arc<dyn TimeProvider>,
}
impl Pairing {
    pub fn new(
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        peer: [u8; 32],
        time: Arc<dyn TimeProvider>,
    ) -> Result<Self, Error> {
        Self::configure(
            certificate,
            key,
            peer,
            time,
            rustls::crypto::ring::default_provider(),
        )
    }

    fn configure(
        certificate: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        peer: [u8; 32],
        time: Arc<dyn TimeProvider>,
        mut provider: CryptoProvider,
    ) -> Result<Self, Error> {
        if time.current_time().is_none() {
            return Err(Error::Time);
        }
        let local = node_id(&certificate)?;
        if local == peer || peer == [0; 32] {
            return Err(Error::Identity);
        }
        provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
        let mut probe = [0; 32];
        let entropy = provider.secure_random.fill(&mut probe);
        probe.fill(0);
        entropy.map_err(|_| Error::Entropy)?;
        let provider = Arc::new(provider);
        // Unlike from_der's permissive Unknown case, require demonstrable
        // equality of the provisioned Ed25519 certificate and private key.
        let certified = rustls::sign::CertifiedKey::from_der(
            vec![certificate.clone()],
            key.clone_key(),
            &provider,
        )
        .map_err(Error::Protocol)?;
        certified.keys_match().map_err(Error::Protocol)?;
        let pin = Arc::new(Pin {
            node: peer,
            provider: provider.clone(),
        });
        let mut client = ClientConfig::builder_with_details(provider.clone(), time.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(Error::Protocol)?
            .dangerous()
            .with_custom_certificate_verifier(pin.clone())
            .with_client_auth_cert(vec![certificate.clone()], key.clone_key())
            .map_err(Error::Protocol)?;
        client.resumption = Resumption::disabled();
        client.enable_early_data = false;
        client.enable_sni = false;
        client.max_fragment_size = Some(4096);
        client.alpn_protocols = vec![b"cyxia-cluster/1".to_vec()];
        let mut server = ServerConfig::builder_with_details(provider, time.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(Error::Protocol)?
            .with_client_cert_verifier(pin)
            .with_single_cert(vec![certificate], key)
            .map_err(Error::Protocol)?;
        server.send_tls13_tickets = 0;
        server.max_early_data_size = 0;
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.max_fragment_size = Some(4096);
        server.alpn_protocols = vec![b"cyxia-cluster/1".to_vec()];
        Ok(Self {
            local,
            peer,
            client: Arc::new(client),
            server: Arc::new(server),
            time,
        })
    }

    /// Only the smaller NodeID initiates the primary connection. Every new
    /// rustls connection generates a new X25519 KeyShare; resumption is off.
    pub fn client<'a>(&self, buffers: &'a mut Buffers, now_ms: u64) -> Result<Session<'a>, Error> {
        if self.local >= self.peer {
            return Err(Error::Direction);
        }
        let name = ServerName::try_from("paired.cyxia.invalid").map_err(|_| Error::Identity)?;
        let connection =
            UnbufferedClientConnection::new(self.client.clone(), name).map_err(Error::Protocol)?;
        Session::new(
            Connection::Client(connection),
            buffers,
            self.peer,
            self.time.clone(),
            now_ms,
        )
    }
    pub fn server<'a>(&self, buffers: &'a mut Buffers, now_ms: u64) -> Result<Session<'a>, Error> {
        if self.local <= self.peer {
            return Err(Error::Direction);
        }
        let connection =
            UnbufferedServerConnection::new(self.server.clone()).map_err(Error::Protocol)?;
        Session::new(
            Connection::Server(connection),
            buffers,
            self.peer,
            self.time.clone(),
            now_ms,
        )
    }
    pub fn local_node(&self) -> [u8; 32] {
        self.local
    }
}

pub struct Buffers {
    input: Box<[u8; RECORD_BUFFER]>,
    output: Box<[u8; RECORD_BUFFER]>,
    received: Box<[u8; PLAINTEXT_BUFFER]>,
    sending: Box<[u8; PLAINTEXT_BUFFER]>,
}
impl Buffers {
    pub fn new() -> Self {
        // Box::new([0; N]) can materialize N bytes in the caller's permanent
        // frame. The native service's never-returning run frame was 120400 B,
        // leaving insufficient space for a real TLS key-schedule call. Vec's
        // repeated-byte constructor initializes the allocator-owned region
        // directly; the checked boxed-slice conversion moves only a pointer.
        fn zeros<const N: usize>() -> Box<[u8; N]> {
            vec![0u8; N]
                .into_boxed_slice()
                .try_into()
                .unwrap_or_else(|_| unreachable!("fixed buffer length"))
        }
        Self {
            input: zeros(),
            output: zeros(),
            received: zeros(),
            sending: zeros(),
        }
    }
}
impl Default for Buffers {
    fn default() -> Self {
        Self::new()
    }
}

enum Connection {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}
pub struct Session<'a> {
    connection: Connection,
    buffers: &'a mut Buffers,
    input: usize,
    output: usize,
    received: usize,
    sending: usize,
    peer: [u8; 32],
    authenticated: bool,
    failed: bool,
    time: Arc<dyn TimeProvider>,
    last_ms: u64,
    handshake_deadline: u64,
}
struct Step {
    discard: usize,
    output: usize,
    received: usize,
    sent: bool,
    authenticated: bool,
}

impl<'a> Session<'a> {
    fn new(
        connection: Connection,
        buffers: &'a mut Buffers,
        peer: [u8; 32],
        time: Arc<dyn TimeProvider>,
        now_ms: u64,
    ) -> Result<Self, Error> {
        let handshake_deadline = now_ms.checked_add(5000).ok_or(Error::Clock)?;
        buffers.input.fill(0);
        buffers.output.fill(0);
        buffers.received.fill(0);
        buffers.sending.fill(0);
        Ok(Self {
            connection,
            buffers,
            input: 0,
            output: 0,
            received: 0,
            sending: 0,
            peer,
            authenticated: false,
            failed: false,
            time,
            last_ms: now_ms,
            handshake_deadline,
        })
    }
    pub fn authenticated_peer(&self) -> Option<[u8; 32]> {
        if self.authenticated && !self.failed {
            Some(self.peer)
        } else {
            None
        }
    }
    pub fn receive_tls(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        let count = bytes.len().min(RECORD_BUFFER - self.input);
        if count == 0 && !bytes.is_empty() {
            return Err(Error::WouldBlock);
        }
        self.buffers.input[self.input..self.input + count].copy_from_slice(&bytes[..count]);
        self.input += count;
        Ok(count)
    }
    /// Pending ciphertext remains immutable until the TCP stream accepted it.
    pub fn pending_tls(&self) -> &[u8] {
        &self.buffers.output[..self.output]
    }
    pub fn consume_tls(&mut self, count: usize) -> Result<(), Error> {
        if count > self.output {
            return Err(Error::Buffer);
        }
        self.buffers.output.copy_within(count..self.output, 0);
        self.buffers.output[self.output - count..self.output].fill(0);
        self.output -= count;
        Ok(())
    }
    pub fn send_plaintext(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if !self.authenticated {
            return Err(Error::Handshake);
        }
        if self.sending != 0 {
            return Err(Error::WouldBlock);
        }
        if bytes.len() > PLAINTEXT_BUFFER {
            return Err(Error::Buffer);
        }
        self.buffers.sending[..bytes.len()].copy_from_slice(bytes);
        self.sending = bytes.len();
        Ok(())
    }
    pub fn plaintext(&self) -> &[u8] {
        if self.failed {
            &[]
        } else {
            &self.buffers.received[..self.received]
        }
    }
    pub fn consume_plaintext(&mut self, count: usize) -> Result<(), Error> {
        if count > self.received {
            return Err(Error::Buffer);
        }
        self.buffers.received.copy_within(count..self.received, 0);
        self.buffers.received[self.received - count..self.received].fill(0);
        self.received -= count;
        Ok(())
    }
    /// One bounded rustls state transition; no socket wait. TLS itself enforces
    /// record sequence/key usage and processes authenticated KeyUpdate messages.
    pub fn pump(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        if now_ms < self.last_ms {
            self.fail();
            return Err(Error::Clock);
        }
        self.last_ms = now_ms;
        if !self.authenticated && now_ms >= self.handshake_deadline {
            self.fail();
            return Err(Error::Timeout);
        }
        if self.time.current_time().is_none() {
            self.fail();
            return Err(Error::Time);
        }
        if self.output != 0 || self.received != 0 {
            return Ok(());
        }
        let incoming = &mut self.buffers.input[..self.input];
        let result = match &mut self.connection {
            Connection::Client(c) => step(
                c.process_tls_records(incoming),
                &mut self.buffers.output[..],
                &mut self.buffers.received[..],
                &self.buffers.sending[..self.sending],
            ),
            Connection::Server(c) => step(
                c.process_tls_records(incoming),
                &mut self.buffers.output[..],
                &mut self.buffers.received[..],
                &self.buffers.sending[..self.sending],
            ),
        };
        let progress = match result {
            Ok(s) => s,
            Err(e) => {
                self.fail();
                return Err(e);
            }
        };
        if progress.discard > self.input {
            self.fail();
            return Err(Error::Buffer);
        }
        // rustls retains incomplete handshake spans in caller storage. Never
        // deadlock on a valid-length but over-quota fragmented handshake.
        if self.input == RECORD_BUFFER
            && progress.discard == 0
            && progress.output == 0
            && progress.received == 0
        {
            self.fail();
            return Err(Error::Buffer);
        }
        self.buffers
            .input
            .copy_within(progress.discard..self.input, 0);
        self.buffers.input[self.input - progress.discard..self.input].fill(0);
        self.input -= progress.discard;
        self.output = progress.output;
        self.received = progress.received;
        if progress.sent {
            self.buffers.sending[..self.sending].fill(0);
            self.sending = 0;
        }
        self.authenticated |= progress.authenticated;
        Ok(())
    }
    /// TCP EOF, reset, timeout, or transport failure invalidates the live TLS
    /// proof. A reconnect must construct a new session and redo reconciliation.
    pub fn abort(&mut self) {
        self.fail();
    }
    fn fail(&mut self) {
        self.failed = true;
        self.authenticated = false;
        self.buffers.input.fill(0);
        self.buffers.output.fill(0);
        self.buffers.received.fill(0);
        self.buffers.sending.fill(0);
        self.input = 0;
        self.output = 0;
        self.received = 0;
        self.sending = 0;
    }
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        self.fail();
    }
}

fn step<T>(
    status: UnbufferedStatus<'_, '_, T>,
    output: &mut [u8],
    received: &mut [u8],
    sending: &[u8],
) -> Result<Step, Error> {
    let mut result = Step {
        discard: status.discard,
        output: 0,
        received: 0,
        sent: false,
        authenticated: false,
    };
    match status.state.map_err(Error::Protocol)? {
        ConnectionState::EncodeTlsData(mut state) => {
            result.output = state.encode(output).map_err(|_| Error::Buffer)?
        }
        ConnectionState::TransmitTlsData(state) => state.done(),
        ConnectionState::BlockedHandshake => {}
        ConnectionState::WriteTraffic(mut state) => {
            result.authenticated = true;
            if !sending.is_empty() {
                result.output = state.encrypt(sending, output).map_err(|_| Error::Buffer)?;
                result.sent = true;
            }
        }
        ConnectionState::ReadTraffic(mut state) => {
            result.authenticated = true;
            if let Some(record) = state.next_record() {
                let record = record.map_err(Error::Protocol)?;
                if record.payload.len() > received.len() {
                    return Err(Error::Buffer);
                }
                received[..record.payload.len()].copy_from_slice(record.payload);
                result.received = record.payload.len();
                result.discard += record.discard;
            }
        }
        ConnectionState::Closed | ConnectionState::PeerClosed => return Err(Error::Closed),
        ConnectionState::ReadEarlyData(_) => return Err(Error::Handshake),
        _ => return Err(Error::Handshake),
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        crypto::{GetRandomFailed, SecureRandom},
        pki_types::PrivatePkcs8KeyDer,
    };
    #[derive(Debug)]
    struct MissingEntropy;
    impl SecureRandom for MissingEntropy {
        fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
            Err(GetRandomFailed)
        }
    }
    #[derive(Debug)]
    struct Time;
    impl TimeProvider for Time {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
                1,
            )))
        }
    }
    #[test]
    fn entropy_failure_prevents_pairing_construction() {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.secure_random = &MissingEntropy;
        let result = Pairing::configure(
            CertificateDer::from(&include_bytes!("../tests/fixtures/a-test-cert.der")[..]),
            PrivatePkcs8KeyDer::from(&include_bytes!("../tests/fixtures/a-test-key.der")[..])
                .into(),
            [1; 32],
            Arc::new(Time),
            provider,
        );
        assert!(matches!(result, Err(Error::Entropy)));
    }
}

/// Canonical RFC8410 Ed25519 public key, validated by webpki first.
pub fn public_key(certificate: &CertificateDer<'_>) -> Result<[u8; 32], Error> {
    if certificate.as_ref().len() > MAX_CERTIFICATE {
        return Err(Error::Identity);
    }
    let parsed = ParsedCertificate::try_from(certificate).map_err(|_| Error::Identity)?;
    let spki = parsed.subject_public_key_info();
    let bytes = spki.as_ref();
    if bytes.len() != 44 || bytes[..12] != ED25519_SPKI_PREFIX {
        return Err(Error::Identity);
    }
    Ok(core::array::from_fn(|i| bytes[i + 12]))
}
/// Own key only; peer verification takes a public key and its NodeID pin.
pub struct IdentitySigner(ring::signature::Ed25519KeyPair);
impl IdentitySigner {
    pub fn new(key: &[u8], public: [u8; 32]) -> Result<Self, Error> {
        use ring::signature::KeyPair;
        let key = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key)
            .map_err(|_| Error::Identity)?;
        if key.public_key().as_ref() != public {
            return Err(Error::Identity);
        }
        Ok(Self(key))
    }
    pub fn public_key(&self) -> [u8; 32] {
        use ring::signature::KeyPair;
        core::array::from_fn(|i| self.0.public_key().as_ref()[i])
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.0.sign(message);
        core::array::from_fn(|i| signature.as_ref()[i])
    }
    pub fn verify(
        public: &[u8; 32],
        node: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        digest::digest(&digest::SHA256, public).as_ref() == node
            && ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
                .verify(message, signature)
                .is_ok()
    }
}
