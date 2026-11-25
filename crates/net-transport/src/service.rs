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
//! # Bounded per-connection turn budgets
//!
//! Every individual turn is already bounded (one device poll, one ciphertext
//! read, one TLS pump, two queue attempts). The budgets below additionally
//! bound the *aggregate* work a caller may spend on one connection, so no
//! caller loop can spin unboundedly on a stalled or hostile peer:
//!
//! - [`HANDSHAKE_TURN_BUDGET`]: total `handshake_turn` calls per pending
//!   lease, independent of the clock. A frozen or rewound trusted clock can
//!   never extend a handshake past this bound (rustls' own
//!   `HANDSHAKE_TIMEOUT_MS` remains the time-based gate). Exhaustion ends the
//!   failed handshake: the TLS session is aborted and only that lease's
//!   pending credit is released via `Admission::reject`. No active credit or
//!   device debt is created or released by a handshake budget refusal.
//! - [`ECHO_STALL_TURN_BUDGET`]: consecutive *zero-progress* authenticated
//!   `turn` calls (no ciphertext received, no ciphertext queued, no Echo
//!   dispatch). Any real progress resets the counter, so a legitimately
//!   active long-lived Echo connection is never killed by a lifetime cap.
//!   This is a clock-independent idle backstop against unproductive spinning;
//!   the trusted idle-timeout policy (`IDLE_TIMEOUT_SECS`) stays the authority
//!   for *when* to close. Exhaustion marks the connection draining and refuses
//!   further turns, but RETAINS the active credit: retirement still requires
//!   [`Service::finish`] with real TCP/VirtIO/TLS evidence.
//!
//! Budget state is keyed by the exact opaque ticket (slot + generation), so a
//! replayed or stale ticket cannot spend, reset or inherit another
//! connection's budget.
//!
//! # Error taxonomy (fail-closed semantics)
//!
//! [`Error::disposition`] classifies every failure into the two dispositions
//! the SEC-N design allows:
//!
//! - [`Disposition::Backpressure`]: transient refusal (queue full, token
//!   bucket empty, TLS/socket `Again`, drain/restart in progress). The exact
//!   same owned work may be attempted again on a later bounded turn. No
//!   credit is created, released or transferred by a backpressure refusal.
//! - [`Disposition::FailClosed`]: permanent refusal for this ticket, session
//!   generation or device state (stale/replayed generation, unauthenticated
//!   or duplicate TLS proof, malformed trusted input, serial exhaustion,
//!   socket closed/device fault, dead TLS session, exhausted turn budget).
//!   The same identity must never be retried. Outstanding credit and UNKNOWN
//!   device custody remain retained; only the evidence-gated
//!   [`native_tcp::finish_session`] path (or a protected platform reset
//!   authority reconciling real completions) may release them. A fail-closed
//!   error never auto-reconnects and never substitutes a timeout, a model
//!   suggestion or a socket reset for device completion.
//!
//! # EL1 boot-dispatch integration contract (OPEN dispatch; T4 device skeleton provided)
//!
//! Deploying this core is a separate, still-open gate. The T4 device-wiring
//! skeleton supplies the REAL VirtIO-net adapter chain (item 1 below) and a
//! kernel init API, but the protected EL1 boot dispatch that deploys it is still
//! unwired. The future EL1 boot dispatch must supply ALL of the following from
//! protected kernel state; this adapter instantiates none of it and accepts none
//! of it from a peer, a wire frame or AI advice:
//!
//! 1. **VirtIO net driver handle.** Ownership of the real
//!    `driver-virtio::net::Net`/`BatchedNet` (`VirtioLink`) MMIO/IRQ/DMA
//!    custody, wrapped as `device::VirtioPort` (`Port`) and driven through
//!    `tcp::Tcp<'_, P>` (`NativeSocket` via `local_echo_tcp`). The dispatch
//!    must reconcile real used-ring TX receipts
//!    (`BatchedNet::poll_tx_receipt` / `acknowledge_tx`, exact
//!    token+generation) so `tx_quiescent` can become true;
//!    `Tcp::terminal_tx_quiescent` additionally requires TCP `State::Closed`
//!    and an empty TCP send queue. The trait's fail-closed default `false`
//!    must never be overridden by a mock, a timeout or a plain socket reset.
//!    The T4 device-wiring skeleton now PROVIDES this real-device chain:
//!    `virtio_custody::CustodyNet` (receipt custody over `BatchedNet`),
//!    `virtio_custody::CustodyPort` (`Port`), and the `tls`-gated
//!    `virtio_custody::VirtioNativeSocket` (`NativeSocket` with the real
//!    `terminal_tx_quiescent` witness). The kernel-side bring-up is
//!    `kernel/src/platform/virt/net_device.rs::init` (CPU0-only, pinned DMA,
//!    `sec-n-native`-gated), returning the real `BatchedNet` for T1 to wrap.
//!    T1 must still supply the protected dispatch that calls `init`, owns the
//!    handle for the service lifetime, and drives the per-turn reconciliation.
//! 2. **Identity material.** The provisioned local Ed25519 certificate,
//!    PKCS#8 private key and peer NodeID pin, reconciled against the
//!    protected shared page (`boot_identity`: kernel-local == `node_id(cert)`
//!    and kernel-peer == provisioned pin) BEFORE `Pairing::new_local_echo`.
//!    The `user/local-echo` build-time fixtures are CI type-check material
//!    only, never production credentials. No certificate, key or peer
//!    identity is ever taken from a wire request.
//! 3. **Clock source.** A trusted monotonic millisecond clock for
//!    `turn`/`handshake_turn`/`Session::pump` (rewind fails closed), a
//!    monotonic nanosecond clock for `admit` (`begin_ns` rejects rewind), and
//!    a wall-clock `rustls::time_provider::TimeProvider` for the TLS engine.
//!    All three come from the EL1 broker/platform, never from the peer.
//! 4. **Source address and rate policy.** The actual source IPv4 from the
//!    trusted native TCP endpoint and a configured rate in {4, 8, 16, 32};
//!    never fields decoded from peer plaintext.
//! 5. **Reset/restart authority.** A protected reliable-device-reset and
//!    completion-reconciliation path for UNKNOWN NIC/DMA custody.
//!    `begin_restart`/`finish_restart` retain every outstanding token across
//!    a service restart; a restart never replenishes exhausted bursts, reuses
//!    stale generations or silently drops unknown completions.
//! 6. **EL0 execution substrate.** A quota-backed allocator and platform
//!    CSPRNG for rustls/ring, plus the restricted SVC broker allowlist. TLS
//!    stays in the EL0 guest (`aarch64-unknown-none`, FP/SIMD); the EL1
//!    kernel stays `aarch64-unknown-none-softfloat` and must never pull
//!    ring/rustls NEON into the soft-float ABI.
//!
//! Until that dispatch exists and is proven in the protected object, this
//! module remains host-testable PREP: G2/G3/G4 native acceptance is NOT
//! upgraded by anything in this file
//! (docs/implementation/v19-security-six-tracks.md).
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
    admission::{ACTIVE, ActiveTicket, Admission, Error as AdmissionError, PENDING, PendingTicket},
    native_tcp::{self, NativeSocket, Progress, SocketError},
    tls::{self, Buffers, Pairing, Session},
};

/// Total bounded `handshake_turn` calls allowed per pending lease, independent
/// of the clock. Matches the cooperative handshake bound of the EL0
/// `user/local-echo` candidate. Exhaustion aborts the session and rejects only
/// that lease's pending credit; it never touches active credit or device debt.
pub const HANDSHAKE_TURN_BUDGET: u32 = 8192;
/// Consecutive zero-progress authenticated `turn` calls allowed before the
/// connection is marked draining and further turns fail closed. Any real
/// progress (received ciphertext, queued ciphertext or an Echo dispatch)
/// resets the counter. Clock-independent idle backstop; the trusted
/// `IDLE_TIMEOUT_SECS` policy remains the authority for when to close.
pub const ECHO_STALL_TURN_BUDGET: u32 = 256;

/// Unified service error. Preserves the authoritative admission / TLS / native
/// socket distinction; it carries no capability and no completion claim.
#[derive(Debug)]
pub enum Error {
    Admission(AdmissionError),
    Tls(tls::Error),
    Native(native_tcp::Error),
    /// The connection's bounded turn budget is exhausted. Fail-closed: no
    /// further turns are served for this ticket. Handshake exhaustion rejects
    /// only the pending lease; Echo exhaustion retains the active credit until
    /// the evidence-gated `finish` path reconciles real device completion.
    Budget,
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

/// The two fail-closed dispositions the SEC-N design allows for a service
/// failure. See the module-level "Error taxonomy" section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Transient refusal: the exact same owned work may be attempted again on
    /// a later bounded turn once the blocking condition (queue space, token
    /// refill, TLS drain, restart completion) is reconciled. No credit is
    /// created, released or transferred.
    Backpressure,
    /// Permanent refusal for this ticket/session generation/device state. The
    /// same identity must never be retried; outstanding credit and UNKNOWN
    /// device custody stay retained until real completion evidence (or a
    /// protected reset authority) reconciles them. Never auto-reconnects.
    FailClosed,
}
impl Error {
    /// Classify this failure into the design's fail-closed semantics. This is
    /// a pure decision aid for the trusted caller; it grants no capability and
    /// releases no credit.
    pub fn disposition(&self) -> Disposition {
        match self {
            Self::Budget => Disposition::FailClosed,
            Self::Admission(error) => admission_disposition(*error),
            Self::Native(native_tcp::Error::Admission(error)) => admission_disposition(*error),
            Self::Native(native_tcp::Error::Socket(SocketError::Again)) => {
                Disposition::Backpressure
            }
            // Closed/Device socket faults and dead TLS sessions are permanent
            // for this connection; retirement still needs the evidence gate.
            Self::Native(_) => Disposition::FailClosed,
            Self::Tls(tls::Error::WouldBlock) => Disposition::Backpressure,
            Self::Tls(_) => Disposition::FailClosed,
        }
    }
}
fn admission_disposition(error: AdmissionError) -> Disposition {
    match error {
        // Full tables, empty token buckets and in-progress drain/restart are
        // transient: retry only after the blocking condition is reconciled.
        AdmissionError::Capacity | AdmissionError::RateLimited | AdmissionError::Busy => {
            Disposition::Backpressure
        }
        // Stale/replayed generations, unauthenticated or duplicate proofs,
        // malformed trusted inputs and exhausted serials never recover.
        _ => Disposition::FailClosed,
    }
}

/// One bounded native read-only Echo service instance. Owns the single
/// authoritative ledger, the pinned pairing and the per-connection turn-budget
/// accounting; the caller owns the socket, the TLS buffers and the trusted
/// clock/source inputs.
pub struct Service {
    admission: Admission,
    pairing: Pairing,
    handshake_turns: [Option<(PendingTicket, u32)>; PENDING],
    echo_stall: [Option<(ActiveTicket, u32)>; ACTIVE],
}
impl Service {
    /// Bind an already-provisioned pinned pairing. No certificate, private key
    /// or peer identity is ever taken from a wire request.
    pub fn new(pairing: Pairing) -> Self {
        Self {
            admission: Admission::new(),
            pairing,
            handshake_turns: [None; PENDING],
            echo_stall: [None; ACTIVE],
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
    /// Handshake turns already spent by this exact pending lease, or `None`
    /// when the lease is not live (rejected, authenticated or replayed).
    pub fn handshake_turns_used(&self, ticket: PendingTicket) -> Option<u32> {
        self.handshake_turns
            .iter()
            .flatten()
            .find(|(t, _)| *t == ticket)
            .map(|(_, used)| *used)
    }
    /// Consecutive zero-progress turns currently charged to this exact active
    /// ticket, or `None` when the ticket is not live.
    pub fn echo_stall_turns(&self, ticket: ActiveTicket) -> Option<u32> {
        self.echo_stall
            .iter()
            .flatten()
            .find(|(t, _)| *t == ticket)
            .map(|(_, stall)| *stall)
    }

    /// Admit a pending handshake lease. `ip`, `now_ns` and `rate` come from the
    /// trusted native TCP owner / local clock / configuration, never the peer.
    /// A successful admission starts a fresh bounded handshake turn budget.
    pub fn admit(&mut self, ip: u32, now_ns: u64, rate: u16) -> Result<PendingTicket, Error> {
        let ticket = self.admission.begin_ns(ip, now_ns, rate)?;
        if let Some(slot) = self.handshake_turns.iter().position(Option::is_none) {
            self.handshake_turns[slot] = Some((ticket, 0));
        } else {
            // Defensive only: the budget table mirrors the ledger's PENDING
            // capacity, so a live lease always has a slot. Fail closed rather
            // than panic, releasing only the lease just created.
            let _ = self.admission.reject(ticket);
            return Err(Error::Admission(AdmissionError::Capacity));
        }
        Ok(ticket)
    }

    /// Generate a fresh pinned passive-server TLS session bound to caller-owned
    /// buffers. The read-only Echo service is a server; there is intentionally
    /// no client auto-dial / cluster peer discovery path here.
    pub fn session<'a>(&self, buffers: &'a mut Buffers, now_ms: u64) -> Result<Session<'a>, Error> {
        self.pairing.server(buffers, now_ms).map_err(Into::into)
    }

    /// One bounded pre-authentication handshake step over the native socket,
    /// charged to the exact live pending lease: at most one device poll, one
    /// ciphertext read, one TLS pump and two queue attempts, and at most
    /// [`HANDSHAKE_TURN_BUDGET`] total calls per lease. A stale/replayed ticket
    /// gets no device work at all. Returns `true` only when a real pinned
    /// `cyxia-echo/1` session proof exists. Incomplete records retain exact
    /// ownership for a later turn. Budget exhaustion aborts the session and
    /// rejects only this lease's pending credit (fail-closed, no device claim).
    pub fn handshake_turn<S: NativeSocket>(
        &mut self,
        socket: &mut S,
        ticket: PendingTicket,
        tls: &mut Session<'_>,
        scratch: &mut [u8],
        now_ms: u64,
    ) -> Result<bool, Error> {
        let at = self
            .handshake_turns
            .iter()
            .position(|e| e.is_some_and(|(t, _)| t == ticket))
            .ok_or(Error::Admission(AdmissionError::Stale))?;
        let used = self.handshake_turns[at].map(|(_, used)| used).unwrap_or(0);
        if used >= HANDSHAKE_TURN_BUDGET {
            tls.abort();
            let _ = self.admission.reject(ticket);
            self.handshake_turns[at] = None;
            return Err(Error::Budget);
        }
        self.handshake_turns[at] = Some((ticket, used + 1));
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
    /// A same-IP reconnect or replayed TLS identity is not that session. The
    /// pending lease (and its handshake budget) is consumed on every outcome;
    /// success starts a fresh zero-progress stall budget for the active ticket.
    pub fn authenticate(
        &mut self,
        ticket: PendingTicket,
        tls: &Session<'_>,
    ) -> Result<ActiveTicket, Error> {
        let result = self.admission.authenticate(ticket, tls);
        // The ledger consumes the pending lease on success and auto-rejects it
        // on every refusal; the budget entry must not outlive the lease.
        if let Some(at) = self
            .handshake_turns
            .iter()
            .position(|e| e.is_some_and(|(t, _)| t == ticket))
        {
            self.handshake_turns[at] = None;
        }
        let active = result?;
        if let Some(slot) = self.echo_stall.iter().position(Option::is_none) {
            self.echo_stall[slot] = Some((active, 0));
        } else {
            // Defensive only: the stall table mirrors the ledger's ACTIVE
            // capacity. Fail closed with the credit retained and draining
            // rather than panic; retirement still needs the evidence gate.
            let _ = self.admission.begin_drain(active);
            return Err(Error::Budget);
        }
        Ok(active)
    }

    /// End a failed/aborted handshake, releasing only its own pending lease
    /// and discarding exactly that lease's handshake budget.
    pub fn reject(&mut self, ticket: PendingTicket) -> Result<(), Error> {
        if let Some(at) = self
            .handshake_turns
            .iter()
            .position(|e| e.is_some_and(|(t, _)| t == ticket))
        {
            self.handshake_turns[at] = None;
        }
        self.admission.reject(ticket).map_err(Into::into)
    }

    /// One bounded authenticated Echo turn (delegates to the authoritative
    /// native bridge), charged to the exact live active ticket. Success is a
    /// plaintext enqueue, NOT network egress or DMA completion. Consecutive
    /// zero-progress turns are bounded by [`ECHO_STALL_TURN_BUDGET`]; any real
    /// progress resets the counter. Exhaustion marks the connection draining
    /// and fails closed while RETAINING the active credit for the evidence
    /// gate. A stale/replayed ticket gets no device work at all.
    pub fn turn<S: NativeSocket>(
        &mut self,
        socket: &mut S,
        active: ActiveTicket,
        tls: &mut Session<'_>,
        scratch: &mut [u8],
        now_ms: u64,
    ) -> Result<Progress, Error> {
        let at = self
            .echo_stall
            .iter()
            .position(|e| e.is_some_and(|(t, _)| t == active))
            .ok_or(Error::Admission(AdmissionError::Stale))?;
        let stall = self.echo_stall[at].map(|(_, stall)| stall).unwrap_or(0);
        if stall >= ECHO_STALL_TURN_BUDGET {
            return Err(Error::Budget);
        }
        let progress = native_tcp::turn(socket, &mut self.admission, active, tls, scratch, now_ms)?;
        let next = if progress == Progress::default() {
            stall + 1
        } else {
            0
        };
        self.echo_stall[at] = Some((active, next));
        if next >= ECHO_STALL_TURN_BUDGET {
            // Stop application work on this connection but retain the credit;
            // only the evidence-gated finish path may release it.
            let _ = self.admission.begin_drain(active);
            return Err(Error::Budget);
        }
        Ok(progress)
    }

    /// Normal retirement gate. Requires verified TCP/VirtIO TX quiescence and a
    /// drained, generation-pinned TLS session before any credit is released.
    /// No model, timeout or socket reset can substitute for device completion.
    /// Success discards exactly this ticket's stall budget; failure retains it.
    pub fn finish<S: NativeSocket>(
        &mut self,
        socket: &S,
        active: ActiveTicket,
        tls: &Session<'_>,
    ) -> Result<(), Error> {
        native_tcp::finish_session(socket, &mut self.admission, active, tls)?;
        if let Some(at) = self
            .echo_stall
            .iter()
            .position(|e| e.is_some_and(|(t, _)| t == active))
        {
            self.echo_stall[at] = None;
        }
        Ok(())
    }

    /// Stop new admission but retain every outstanding token across restart.
    /// Per-connection budget entries are retained with their credits.
    pub fn begin_restart(&mut self) {
        self.admission.begin_restart();
    }
    /// Complete a restart only once no pending/active credit remains; it never
    /// replenishes exhausted bursts or reuses stale generations.
    pub fn finish_restart(&mut self) -> Result<(), Error> {
        self.admission.finish_restart()?;
        // The ledger is empty by the check above; clear any residual budget
        // state so a restarted service starts from exact zero accounting.
        self.handshake_turns = [None; PENDING];
        self.echo_stall = [None; ACTIVE];
        Ok(())
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
