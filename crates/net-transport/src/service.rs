//! SEC-N native service adapter: bounded kernel-side glue binding the sole
//! authoritative [`Admission`] connection-credit ledger, the [`NativeSocket`]
//! trait and pinned TLS session generation ([`Pairing`]).
//!
//! This is the reusable service core a future EL1 Echo broker (or the EL0
//! `user/local-echo` guest) drives. It is deliberately PREP, not production
//! wiring: it owns no device, no boot/dispatch path and no execution grant, and
//! it never fabricates a completion witness. Normal credit retirement goes only
//! through [`native_tcp::finish_session`], which demands real TCP/VirtIO TX
//! quiescence plus a drained, generation-pinned TLS session.
//!
//! # VirtIO net-driver trait boundary
//!
//! The socket side is generic over [`NativeSocket`]; the trusted native driver
//! plugs in through the existing chain, never through this adapter directly:
//!
//! ```text
//! driver-virtio Net/BatchedNet : VirtioLink   (device.rs)
//!   -> device::VirtioPort      : Port         (device.rs)
//!   -> tcp::Tcp<'_, P>         : NativeSocket (local_echo_tcp.rs)
//!   -> service::Service::turn / handshake_turn / finish
//! ```
//!
//! A peer cannot manufacture admission tickets, TLS proofs or privileged
//! completion events; source IPv4, clock and rate policy are supplied by the
//! trusted native owner, never by peer plaintext or AI advice.
//!
//! # Target split (why this module is `tls`-gated)
//!
//! rustls/ring require AArch64 NEON, so this module compiles for the EL0 guest
//! target `aarch64-unknown-none` (FP/SIMD) and for host tests. The EL1 kernel
//! stays `aarch64-unknown-none-softfloat`; its `sec-n-native` feature pulls only
//! the `smoltcp` device/tcp stack and must not add NEON to the soft-float ABI
//! (docs/implementation/v19-security-six-tracks.md). The boot-chain dispatch
//! that actually deploys the guest is a separate, still-open gate.
#![forbid(unsafe_code)]
use crate::{
    admission::{ActiveTicket, Admission, Error as AdmissionError, PendingTicket},
    native_tcp::{self, NativeSocket, Progress, SocketError},
    tls::{self, Buffers, Pairing, Session},
};

/// Unified service error. Preserves the authoritative admission / TLS / native
/// socket distinction; it carries no capability and no completion claim.
#[derive(Debug)]
pub enum Error {
    Admission(AdmissionError),
    Tls(tls::Error),
    Native(native_tcp::Error),
}
impl From<AdmissionError> for Error {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}
impl From<tls::Error> for Error {
    fn from(error: tls::Error) -> Self {
        Self::Tls(error)
    }
}
impl From<native_tcp::Error> for Error {
    fn from(error: native_tcp::Error) -> Self {
        Self::Native(error)
    }
}

/// One bounded native read-only Echo service instance. Owns the single
/// authoritative ledger and the pinned pairing; the caller owns the socket, the
/// TLS buffers and the trusted clock/source inputs.
pub struct Service {
    admission: Admission,
    pairing: Pairing,
}
impl Service {
    /// Bind an already-provisioned pinned pairing. No certificate, private key
    /// or peer identity is ever taken from a wire request.
    pub fn new(pairing: Pairing) -> Self {
        Self {
            admission: Admission::new(),
            pairing,
        }
    }
    pub fn local_node(&self) -> [u8; 32] {
        self.pairing.local_node()
    }
    pub fn pending_count(&self) -> usize {
        self.admission.pending_count()
    }
    pub fn active_count(&self) -> usize {
        self.admission.active_count()
    }
    pub fn restarting(&self) -> bool {
        self.admission.restarting()
    }

    /// Admit a pending handshake lease. `ip`, `now_ns` and `rate` come from the
    /// trusted native TCP owner / local clock / configuration, never the peer.
    pub fn admit(&mut self, ip: u32, now_ns: u64, rate: u16) -> Result<PendingTicket, Error> {
        self.admission
            .begin_ns(ip, now_ns, rate)
            .map_err(Into::into)
    }

    /// Generate a fresh pinned passive-server TLS session bound to caller-owned
    /// buffers. The read-only Echo service is a server; there is intentionally
    /// no client auto-dial / cluster peer discovery path here.
    pub fn session<'a>(&self, buffers: &'a mut Buffers, now_ms: u64) -> Result<Session<'a>, Error> {
        self.pairing.server(buffers, now_ms).map_err(Into::into)
    }

    /// One bounded pre-authentication handshake step over the native socket:
    /// at most one device poll, one ciphertext read, one TLS pump and two queue
    /// attempts. Returns `true` only when a real pinned `cyxia-echo/1` session
    /// proof exists. Incomplete records retain exact ownership for a later turn.
    pub fn handshake_turn<S: NativeSocket>(
        &mut self,
        socket: &mut S,
        tls: &mut Session<'_>,
        scratch: &mut [u8],
        now_ms: u64,
    ) -> Result<bool, Error> {
        if let Err(error) = socket.poll_native(now_ms) {
            if error != SocketError::Again {
                tls.abort();
                return Err(Error::Native(native_tcp::Error::Socket(error)));
            }
        }
        flush(socket, tls)?;
        let capacity = tls.receive_capacity().min(scratch.len());
        if capacity != 0 {
            match socket.read_ciphertext(&mut scratch[..capacity]) {
                Ok(0) | Err(SocketError::Again) => {}
                Ok(n) if n <= capacity => {
                    let accepted = tls
                        .receive_tls(&scratch[..n])
                        .map_err(|_| Error::Native(native_tcp::Error::Tls))?;
                    if accepted != n {
                        return Err(Error::Native(native_tcp::Error::Tls));
                    }
                }
                Ok(_) => {
                    return Err(Error::Native(native_tcp::Error::Socket(
                        SocketError::Device,
                    )));
                }
                Err(error) => {
                    tls.abort();
                    return Err(Error::Native(native_tcp::Error::Socket(error)));
                }
            }
        }
        tls.pump(now_ms)
            .map_err(|_| Error::Native(native_tcp::Error::Tls))?;
        flush(socket, tls)?;
        Ok(tls.local_echo_proof().is_some())
    }

    /// Promote a finished, pinned handshake to an active read-only admission.
    /// A same-IP reconnect or replayed TLS identity is not that session.
    pub fn authenticate(
        &mut self,
        ticket: PendingTicket,
        tls: &Session<'_>,
    ) -> Result<ActiveTicket, Error> {
        self.admission.authenticate(ticket, tls).map_err(Into::into)
    }

    /// End a failed/aborted handshake, releasing only its own pending lease.
    pub fn reject(&mut self, ticket: PendingTicket) -> Result<(), Error> {
        self.admission.reject(ticket).map_err(Into::into)
    }

    /// One bounded authenticated Echo turn (delegates to the authoritative
    /// native bridge). Success is a plaintext enqueue, NOT network egress or
    /// DMA completion.
    pub fn turn<S: NativeSocket>(
        &mut self,
        socket: &mut S,
        active: ActiveTicket,
        tls: &mut Session<'_>,
        scratch: &mut [u8],
        now_ms: u64,
    ) -> Result<Progress, Error> {
        native_tcp::turn(socket, &mut self.admission, active, tls, scratch, now_ms)
            .map_err(Into::into)
    }

    /// Normal retirement gate. Requires verified TCP/VirtIO TX quiescence and a
    /// drained, generation-pinned TLS session before any credit is released.
    /// No model, timeout or socket reset can substitute for device completion.
    pub fn finish<S: NativeSocket>(
        &mut self,
        socket: &S,
        active: ActiveTicket,
        tls: &Session<'_>,
    ) -> Result<(), Error> {
        native_tcp::finish_session(socket, &mut self.admission, active, tls).map_err(Into::into)
    }

    /// Stop new admission but retain every outstanding token across restart.
    pub fn begin_restart(&mut self) {
        self.admission.begin_restart();
    }
    /// Complete a restart only once no pending/active credit remains; it never
    /// replenishes exhausted bursts or reuses stale generations.
    pub fn finish_restart(&mut self) -> Result<(), Error> {
        self.admission.finish_restart().map_err(Into::into)
    }
}

/// Queue only actual pending TLS ciphertext into the native send queue, one
/// bounded attempt. A queued count is not a TCP ACK, used-ring or DMA proof.
fn flush<S: NativeSocket>(socket: &mut S, tls: &mut Session<'_>) -> Result<(), Error> {
    let pending = tls.pending_tls();
    if pending.is_empty() {
        return Ok(());
    }
    let queued = match socket.queue_ciphertext(pending) {
        Ok(n) => n,
        Err(SocketError::Again) => 0,
        Err(error) => return Err(Error::Native(native_tcp::Error::Socket(error))),
    };
    if queued > pending.len() {
        return Err(Error::Native(native_tcp::Error::Socket(
            SocketError::Device,
        )));
    }
    tls.consume_tls(queued)
        .map_err(|_| Error::Native(native_tcp::Error::Tls))?;
    Ok(())
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
