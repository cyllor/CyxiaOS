//! A single statically provisioned TCP stream over native Ethernet/ARP/IPv4.
//! Its plaintext bytes must be consumed only by the TLS engine.
//!
//! This stream is discovery-free: the peer is pinned by `Config` at
//! construction. The legacy CXD1 paired-node cluster discovery machinery was
//! relocated to the excluded cluster-transport crate, which drives this
//! stream through the public open-peer/phase/accessor API below.
use crate::device::{Ethernet, Port};
use cyxia_driver_virtio::DiagnosticStage as Stage;
mod observe;
pub use observe::Observation;
use observe::ObservedPort;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage},
    socket::tcp::{Socket, SocketBuffer},
    time::{Duration, Instant},
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

pub use smoltcp::iface::SocketStorage as Storage;
pub use smoltcp::socket::tcp::State;
pub const BUFFER_SIZE: usize = 32768;
/// The application heartbeat detects a failed member much earlier; this bound
/// only prevents an otherwise healthy native TLS/control session from being
/// recycled while TCG is servicing other exact-credit roles.
pub const IDLE_TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Clock,
    Device,
    Socket,
    Closed,
    Peer,
    WouldBlock,
}

/// Retire only the failed TCP generation after a bounded backoff. The caller
/// retains the same pinned device owner; a poisoned device remains failed.
pub fn reconnect_due(
    state: Result<State, Error>,
    elapsed_ms: u64,
    entropy_available: bool,
) -> bool {
    entropy_available
        && elapsed_ms >= 1000
        && matches!(
            state,
            Ok(State::Closed)
                | Err(Error::Clock | Error::Device | Error::Socket | Error::Closed | Error::Peer)
        )
}

#[derive(Clone, Copy)]
pub struct Config {
    pub mac: [u8; 6],
    pub local: [u8; 4],
    pub peer: [u8; 4],
    pub prefix_len: u8,
    pub local_port: u16,
    pub peer_port: u16,
    /// Fresh seed obtained from the guest CSPRNG, never from the clock/NodeID.
    pub random_seed: u64,
}

/// The caller owns fixed buffers and socket storage for this stream's lifetime.
/// Dropping this object never frees the NIC's pinned DMA storage.
pub struct Tcp<'a, P> {
    device: Ethernet<ObservedPort<P>>,
    interface: Interface,
    sockets: SocketSet<'a>,
    socket: SocketHandle,
    config: Config,
    last_ms: u64,
    failed: bool,
    passive_fin_acked: bool,
}

impl<'a, P: Port> Tcp<'a, P> {
    pub fn new(
        port: P,
        config: Config,
        now_ms: u64,
        rx: &'a mut [u8; BUFFER_SIZE],
        tx: &'a mut [u8; BUFFER_SIZE],
        storage: &'a mut [SocketStorage<'a>; 1],
    ) -> Result<Self, Error> {
        Self::new_inner(port, config, now_ms, rx, tx, storage, false)
    }

    /// Construct with the peer left open: `config.peer` must be all-zero and
    /// `config.peer_port` zero, and the caller pins the real endpoint later
    /// via [`Self::select_peer`]. The legacy cluster facade uses this for its
    /// hint-selected stream; the single-machine profile always uses
    /// [`Self::new`] with a fixed peer. The caller owns enough socket storage
    /// for every socket it adds through [`Self::sockets_mut`].
    pub fn new_with_open_peer(
        port: P,
        config: Config,
        now_ms: u64,
        rx: &'a mut [u8; BUFFER_SIZE],
        tx: &'a mut [u8; BUFFER_SIZE],
        storage: &'a mut [SocketStorage<'a>],
    ) -> Result<Self, Error> {
        Self::new_inner(port, config, now_ms, rx, tx, storage, true)
    }

    fn new_inner(
        port: P,
        config: Config,
        now_ms: u64,
        rx: &'a mut [u8; BUFFER_SIZE],
        tx: &'a mut [u8; BUFFER_SIZE],
        storage: &'a mut [SocketStorage<'a>],
        open_peer: bool,
    ) -> Result<Self, Error> {
        let mac = EthernetAddress(config.mac);
        let local = Ipv4Address::from(config.local);
        let peer = Ipv4Address::from(config.peer);
        let unicast = |ip: [u8; 4]| (1..=223).contains(&ip[0]) && ip[0] != 127;
        if !mac.is_unicast()
            || config.mac == [0; 6]
            || !unicast(config.local)
            || (!open_peer && (!unicast(config.peer) || local == peer))
            || (open_peer && (config.peer != [0; 4] || config.peer_port != 0))
            || !(1..=30).contains(&config.prefix_len)
            || config.local_port == 0
            || (!open_peer && config.peer_port == 0)
            || config.random_seed == 0
            || now_ms > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        let cidr = IpCidr::new(IpAddress::Ipv4(local), config.prefix_len);
        if !open_peer && !cidr.contains_addr(&IpAddress::Ipv4(peer)) {
            return Err(Error::Configuration);
        }
        let host_mask = u32::MAX >> config.prefix_len;
        for address in [Some(config.local), (!open_peer).then_some(config.peer)]
            .into_iter()
            .flatten()
        {
            let host = u32::from_be_bytes(address) & host_mask;
            if host == 0 || host == host_mask {
                return Err(Error::Configuration);
            }
        }
        let mut device = Ethernet::new(ObservedPort::new(port, config, now_ms));
        let mut iface_config = InterfaceConfig::new(mac.into());
        iface_config.random_seed = config.random_seed;
        let mut interface = Interface::new(
            iface_config,
            &mut device,
            Instant::from_millis(now_ms as i64),
        );
        interface.update_ip_addrs(|ips| {
            let _ = ips.push(cidr);
        });
        let mut sockets = SocketSet::new(&mut storage[..]);
        let mut socket = Socket::new(
            SocketBuffer::new(&mut rx[..]),
            SocketBuffer::new(&mut tx[..]),
        );
        socket.set_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS)));
        socket.set_ack_delay(None);
        socket.set_nagle_enabled(false);
        let handle = sockets.add(socket);
        Ok(Self {
            device,
            interface,
            sockets,
            socket: handle,
            config,
            last_ms: now_ms,
            failed: false,
            passive_fin_acked: false,
        })
    }

    pub fn listen(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.passive_fin_acked = false;
        self.sockets
            .get_mut::<Socket>(self.socket)
            .listen((Ipv4Address::from(self.config.local), self.config.local_port))
            .map_err(|_| Error::Socket)
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.passive_fin_acked = false;
        self.sockets
            .get_mut::<Socket>(self.socket)
            .connect(
                self.interface.context(),
                (Ipv4Address::from(self.config.peer), self.config.peer_port),
                (Ipv4Address::from(self.config.local), self.config.local_port),
            )
            .map_err(|_| Error::Socket)
    }

    /// A failed stream never resumes; every operation fails closed.
    pub fn healthy(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    /// The socket set of this stream's bounded device turn. The legacy
    /// cluster facade adds its auxiliary UDP socket here; a single-machine
    /// stream only ever holds the one TCP socket created at construction.
    /// The caller must have reserved enough storage for every added socket.
    pub fn sockets_mut(&mut self) -> &mut SocketSet<'a> {
        &mut self.sockets
    }

    /// Re-pin the peer endpoint after construction with an open peer. The
    /// caller owns endpoint validation; [`Self::poll`] still verifies the
    /// live remote endpoint against the pinned peer and aborts on mismatch.
    /// The observation layer re-pins with the same config so RTT/retransmit
    /// sampling follows the selected endpoint.
    pub fn select_peer(&mut self, peer: [u8; 4], peer_port: u16) {
        self.config.peer = peer;
        self.config.peer_port = peer_port;
        self.device.port_mut().select_peer(self.config);
    }

    /// The configured peer IPv4, if one is pinned. An open-peer stream
    /// reports `None` until a peer is selected.
    pub fn peer_ipv4(&self) -> Option<[u8; 4]> {
        if self.config.peer == [0; 4] {
            None
        } else {
            Some(self.config.peer)
        }
    }

    /// Read-only access to the caller-owned port beneath the observation
    /// layer. The legacy cluster facade reads its wire counters here.
    pub fn port(&self) -> &P {
        self.device.port().inner()
    }

    /// Mutable access to the caller-owned port beneath the observation
    /// layer, for turn-clock bookkeeping only; protocol work must still go
    /// through the poll phases so device credit boundaries stay intact.
    pub fn port_mut(&mut self) -> &mut P {
        self.device.port_mut().inner_mut()
    }

    /// Read the actual socket state without advancing timers or consuming any
    /// device work. A scheduler turn with no CPU credit is not a disconnect.
    pub fn state(&self) -> Result<State, Error> {
        self.healthy()?;
        Ok(self.sockets.get::<Socket>(self.socket).state())
    }

    /// One ingress frame, bounded egress, no blocking network wait. The timer
    /// must be the same boot's monotonic clock, including reconnects.
    pub fn poll(&mut self, now_ms: u64) -> Result<State, Error> {
        let mut checkpoint = || {};
        self.poll_with_checkpoints(now_ms, &mut checkpoint)
    }

    /// The same protocol turn as [`Self::poll`], with explicit safe points
    /// between independently bounded NIC, ingress and egress pieces. The
    /// callback runs only while no smoltcp/device borrow or protocol update is
    /// in flight, so a native scheduler may settle one CPU reservation and
    /// obtain the next without keeping a device or socket lock across that
    /// wait. A no-op callback preserves the ordinary host/test behaviour.
    pub fn poll_with_checkpoints(
        &mut self,
        now_ms: u64,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<State, Error> {
        self.poll_ingress_phase(now_ms, checkpoint)?;
        self.poll_egress_phase(now_ms, checkpoint)
    }

    /// First half of one protocol turn: health/clock preflight, the bounded
    /// NIC service and flush, and at most one ingress frame with its socket
    /// state update. Ends at a safe point with no borrow in flight. The
    /// caller MUST complete the same turn with [`Self::poll_egress_phase`]
    /// at the same `now_ms`; the legacy cluster facade inserts its auxiliary
    /// UDP socket work between the two phases. A failed preflight poisons
    /// the stream exactly as a whole-turn poll does.
    pub fn poll_ingress_phase(
        &mut self,
        now_ms: u64,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<(), Error> {
        self.device.port().diagnostic_stage(Stage::TcpHealth as u64);
        self.healthy()?;
        checkpoint();
        self.device.port().diagnostic_stage(Stage::TcpClock as u64);
        if now_ms < self.last_ms || now_ms > i64::MAX as u64 {
            self.device.port().diagnostic_stage(Stage::TcpAbort as u64);
            self.abort();
            return Err(Error::Clock);
        }
        self.last_ms = now_ms;
        checkpoint();
        self.device.port().diagnostic_stage(Stage::TcpTime as u64);
        self.device.port_mut().set_time(now_ms);
        // Preflight state is complete and no device/socket borrow is live.
        // Give the first cold NIC service operation its own native credit.
        checkpoint();
        if self.device.service_with_checkpoint(checkpoint).is_err() {
            self.device.port().diagnostic_stage(Stage::TcpAbort as u64);
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();
        self.device.port().diagnostic_stage(Stage::TcpFlush as u64);
        if self.device.port_mut().flush().is_err() {
            self.device.port().diagnostic_stage(Stage::TcpAbort as u64);
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();

        self.device
            .port()
            .diagnostic_stage(Stage::TcpSocketSnapshot as u64);
        let now = Instant::from_millis(now_ms as i64);
        let before = self.sockets.get::<Socket>(self.socket);
        let queued = before.send_queue();
        let state = before.state();
        // Parsing one received frame can include ARP/IP/TCP state transitions.
        // It receives its own exact physical-credit segment and completes all
        // borrows before the following safe point.
        checkpoint();
        self.device
            .port()
            .diagnostic_stage(Stage::TcpIngress as u64);
        let ingress = self
            .interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        checkpoint();
        self.device
            .port()
            .diagnostic_stage(Stage::TcpIngressResult as u64);
        let after = self.sockets.get::<Socket>(self.socket);
        if ingress != smoltcp::iface::PollIngressSingleResult::None {
            if state == State::LastAck && after.state() == State::Closed {
                self.passive_fin_acked = self.device.port().final_ack_matches();
            }
            self.device.port_mut().ingress_processed(
                after.send_queue() < queued
                    || (matches!(state, State::SynSent | State::SynReceived)
                        && after.state() == State::Established),
            );
        }
        checkpoint();
        Ok(())
    }

    /// Second half of one protocol turn: the bounded egress burst, the final
    /// staged-TX flush and the remote-endpoint verification. Requires a
    /// successful [`Self::poll_ingress_phase`] at the same `now_ms` in the
    /// same turn; it does not repeat the preflight, NIC service or ingress.
    pub fn poll_egress_phase(
        &mut self,
        now_ms: u64,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<State, Error> {
        let now = Instant::from_millis(now_ms as i64);
        // A hardware multichain port can accept multiple independent frames.
        // Keep the logical burst, but expose a safe scheduler checkpoint after
        // every complete descriptor-chain attempt. This prevents a batch from
        // being billed as one non-preemptible native CPU segment.
        for _ in 0..self.device.port().burst_capacity().clamp(1, 8) {
            self.device.port().diagnostic_stage(Stage::TcpEgress as u64);
            let egress = self
                .interface
                .poll_egress(now, &mut self.device, &mut self.sockets);
            if self.device.service_with_checkpoint(checkpoint).is_err() {
                self.device.port().diagnostic_stage(Stage::TcpAbort as u64);
                self.abort();
                return Err(Error::Device);
            }
            checkpoint();
            // An idle socket or a retained backpressured frame cannot make
            // progress by repeating the same poll in this paid CPU turn.
            // The staged TX is serviced above and flushed below; retry on the
            // next turn, preserving its bytes and normal retransmit timers.
            if egress == smoltcp::iface::PollResult::None {
                break;
            }
        }
        self.device.port().diagnostic_stage(Stage::TcpFlush as u64);
        if self.device.port_mut().flush().is_err() {
            self.device.port().diagnostic_stage(Stage::TcpAbort as u64);
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();
        self.device
            .port()
            .diagnostic_stage(Stage::TcpRemoteState as u64);
        let socket = self.sockets.get::<Socket>(self.socket);
        if let Some(endpoint) = socket.remote_endpoint()
            && (endpoint.addr != IpAddress::Ipv4(Ipv4Address::from(self.config.peer))
                || endpoint.port != self.config.peer_port)
        {
            self.abort();
            return Err(Error::Peer);
        }
        self.state()
    }

    /// These are encrypted TLS record bytes, never an authenticated RPC API.
    pub fn send_tls(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.healthy()?;
        let socket = self.sockets.get_mut::<Socket>(self.socket);
        if !socket.may_send() {
            return Err(Error::Closed);
        }
        if !socket.can_send() {
            return Err(Error::WouldBlock);
        }
        socket.send_slice(bytes).map_err(|_| Error::Socket)
    }

    /// All-or-nothing enqueue for an IPC message. Insufficient socket capacity
    /// has no side effects, allowing the real IPC head to remain queued.
    pub fn send_exact(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.healthy()?;
        let socket = self.sockets.get::<Socket>(self.socket);
        if !socket.may_send() {
            return Err(Error::Closed);
        }
        if bytes.len() > socket.send_capacity().saturating_sub(socket.send_queue()) {
            return Err(Error::WouldBlock);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        if self.send_tls(bytes)? != bytes.len() {
            // A violated socket capacity contract must never duplicate a prefix.
            self.abort();
            return Err(Error::Socket);
        }
        Ok(())
    }

    /// A closed native TCP socket with empty send queue and verified absence
    /// of outstanding VirtIO transmit descriptor leases. This is NOT proof
    /// that the remote endpoint consumed or acknowledged application bytes.
    pub fn terminal_tx_quiescent(&self) -> bool {
        let socket = self.sockets.get::<Socket>(self.socket);
        socket.state() == State::Closed
            && socket.send_queue() == 0
            && self.device.port().tx_quiescent()
    }

    /// Drive a passive TCP close after both authenticated TLS alerts. A peer FIN
    /// moves the socket into CloseWait. Only an accepted ACK of our *transmitted*
    /// FIN can establish the LastAck -> Closed witness. A timer or RST cannot.
    pub fn poll_passive_close(&mut self, now_ms: u64) -> Result<bool, Error> {
        self.poll(now_ms)?;
        self.finish_passive_close()
    }

    /// Report normal retirement after the scheduler has driven the socket
    /// and NIC for this turn. A successful true result requires its final ACK.
    pub fn finish_passive_close(&mut self) -> Result<bool, Error> {
        let state = self.state()?;
        let socket = self.sockets.get_mut::<Socket>(self.socket);
        if socket.recv_queue() != 0 {
            return Err(Error::Socket);
        }
        match state {
            State::Established | State::LastAck => Ok(false),
            State::CloseWait => {
                socket.close();
                Ok(false)
            }
            State::Closed if self.passive_fin_acked => {
                Ok(self.device.tx_staging_empty() && self.terminal_tx_quiescent())
            }
            _ => Err(Error::Closed),
        }
    }

    /// Reset the observed socket identity and listen for a new allowed peer.
    /// Require the completed old FIN and quiescent TX before any reuse.
    pub fn relisten_open_after_close(&mut self) -> Result<(), Error> {
        if self.state()? != State::Closed || !self.finish_passive_close()? {
            return Err(Error::WouldBlock);
        }
        self.relisten_open()
    }

    /// The trusted TLS verifier rejected a pending handshake. Queue a TCP
    /// reset and allow subsequent reactor turns to retire the native TX work.
    pub fn abort_rejected(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.sockets.get_mut::<Socket>(self.socket).abort();
        Ok(())
    }

    /// Require the aborted socket to release its endpoint, the transport's
    /// staged reset to have drained, and the NIC's TX leases to be quiescent.
    /// A reset carries no authenticated normal-close claim.
    pub fn relisten_open_after_rejection(&mut self) -> Result<bool, Error> {
        if self.state()? != State::Closed
            || self.remote().is_some()
            || !self.device.tx_staging_empty()
            || !self.device.port().tx_quiescent()
        {
            return Ok(false);
        }
        self.relisten_open()?;
        Ok(true)
    }

    fn relisten_open(&mut self) -> Result<(), Error> {
        self.config.peer = [0; 4];
        self.config.peer_port = 0;
        self.device.port_mut().reset_peer(self.config);
        self.listen()
    }

    pub fn observation(&self) -> Observation {
        let socket = self.sockets.get::<Socket>(self.socket);
        let active =
            !self.failed && matches!(socket.state(), State::Established | State::CloseWait);
        self.device.port().observation(socket.send_queue(), active)
    }

    pub fn receive_tls(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
        self.healthy()?;
        let socket = self.sockets.get_mut::<Socket>(self.socket);
        if !socket.can_recv() {
            return Err(if socket.may_recv() {
                Error::WouldBlock
            } else {
                Error::Closed
            });
        }
        socket.recv_slice(bytes).map_err(|_| Error::Socket)
    }

    pub fn remote(&self) -> Option<IpEndpoint> {
        self.sockets.get::<Socket>(self.socket).remote_endpoint()
    }
    /// Send a TCP reset before retiring this stream. The NIC queues remain
    /// pinned and are never reclaimed; a new socket needs fresh storage/seed.
    pub fn close(&mut self, now_ms: u64) {
        self.sockets.get_mut::<Socket>(self.socket).abort();
        if !self.failed && now_ms >= self.last_ms && now_ms <= i64::MAX as u64 {
            self.interface.poll_egress(
                Instant::from_millis(now_ms as i64),
                &mut self.device,
                &mut self.sockets,
            );
            let _ = self.device.service();
            let _ = self.device.port_mut().flush();
        }
        self.failed = true;
    }
    pub fn abort(&mut self) {
        self.sockets.get_mut::<Socket>(self.socket).abort();
        self.failed = true;
    }
}

#[cfg(test)]
mod close_tests;
