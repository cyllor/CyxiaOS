//! Legacy CXD1 paired-node discovery driven over the single-machine native
//! TCP stream's public API. Relocated from the active net-transport crate:
//! V0.20 is single-machine, so the cluster discovery wire and its UDP socket
//! integration live only in this legacy facade. The selected endpoint remains
//! pinned for this transport's entire lifetime; UDP hints are processed by the
//! same bounded NIC/socket turn as TCP.
use crate::device::{Error as PortError, MTU, Port};
use crate::discovery::{self, Attempt, Discovery, PacketMetadata};
use cyxia_net_transport::tcp::Tcp as NetTcp;
use cyxia_net_transport::tcp::{BUFFER_SIZE, Config, Error, State, Storage};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{PacketBuffer, SendError, Socket as UdpSocket};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, UdpPacket,
};

pub struct DiscoveryConfig {
    pub local_node: [u8; 32],
    pub peer_node: [u8; 32],
}
pub struct DiscoveryBuffers<'a> {
    pub rx_meta: &'a mut [PacketMetadata; 4],
    pub tx_meta: &'a mut [PacketMetadata; 4],
    pub rx: &'a mut [u8; 1024],
    pub tx: &'a mut [u8; 1024],
}
#[derive(Clone, Copy)]
pub struct DiscoverySnapshot {
    pub counters: discovery::Counters,
    pub candidates: usize,
    pub attempts: usize,
    pub selected: Option<Attempt>,
    pub selected_ms: u64,
    pub candidate_ms: u64,
    pub sent: u64,
    pub sent_ms: u64,
    pub sent_nonce: [u8; 16],
    pub next_ms: u64,
    pub local_node: [u8; 32],
    pub peer_node: [u8; 32],
    pub local_ip: [u8; 4],
    pub local_port: u16,
}

/// Counters of CXD1 announcements actually accepted by the real device. This
/// port wrapper rides inside the stream's observation wrapper, so it sees the
/// exact frames the NIC accepted; it never invents a sample. Relocated from
/// net-transport's observation layer together with the discovery wire.
pub struct DiscoveryPort<P> {
    inner: P,
    local: [u8; 4],
    now: u64,
    pub(super) sent: u64,
    pub(super) sent_ms: u64,
    pub(super) nonce: [u8; 16],
}
impl<P> DiscoveryPort<P> {
    fn new(inner: P, local: [u8; 4], now: u64) -> Self {
        Self {
            inner,
            local,
            now,
            sent: 0,
            sent_ms: 0,
            nonce: [0; 16],
        }
    }
    /// The owning stream advances this clock once per protocol turn, at the
    /// same point the observation layer samples its own clock.
    pub(super) fn set_now(&mut self, now: u64) {
        self.now = now;
    }
}
impl<P: Port> Port for DiscoveryPort<P> {
    fn diagnostic_stage(&self, stage: u64) {
        self.inner.diagnostic_stage(stage);
    }
    fn flush(&mut self) -> Result<(), PortError> {
        self.inner.flush()
    }
    fn burst_capacity(&self) -> usize {
        self.inner.burst_capacity()
    }
    fn tx_quiescent(&self) -> bool {
        self.inner.tx_quiescent()
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), PortError> {
        self.inner.send(frame)?;
        // Count only packets actually accepted by the device, not socket
        // preparation/queueing. PCAP remains the independent wire evidence.
        if let Ok(ethernet) = EthernetFrame::new_checked(frame)
            && ethernet.ethertype() == EthernetProtocol::Ipv4
            && let Ok(ip) = Ipv4Packet::new_checked(ethernet.payload())
            && ip.next_header() == IpProtocol::Udp
            && ip.src_addr().octets() == self.local
            && let Ok(udp) = UdpPacket::new_checked(ip.payload())
            && udp.src_port() == discovery::PORT
            && udp.dst_port() == discovery::PORT
            && let Ok(message) = discovery::Message::decode(udp.payload())
        {
            self.sent = self.sent.saturating_add(1);
            self.sent_ms = self.now;
            self.nonce = message.nonce;
        }
        Ok(())
    }
    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, PortError> {
        self.inner.receive(frame)
    }
    fn receive_with_checkpoint(
        &mut self,
        frame: &mut [u8; MTU],
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, PortError> {
        // Preserve the inner port's custody-safe scheduling boundaries.
        self.inner.receive_with_checkpoint(frame, checkpoint)
    }
}

/// A single-machine native TCP stream plus the legacy CXD1 UDP discovery
/// socket sharing its bounded device turn. The stream is constructed with an
/// open (zero) peer; only an actually received hint pins the TCP endpoint.
pub struct DiscoveringTcp<'a, P> {
    tcp: NetTcp<'a, DiscoveryPort<P>>,
    udp: SocketHandle,
    state: Discovery,
    config: Config,
    initiator: bool,
    armed: bool,
    attempt: Option<Attempt>,
    pending: Option<[u8; discovery::WIRE_BYTES]>,
    identity: DiscoveryConfig,
    selected_ms: u64,
    candidate_ms: u64,
}
impl<'a, P: Port> DiscoveringTcp<'a, P> {
    pub fn new(
        port: P,
        config: Config,
        now: u64,
        rx: &'a mut [u8; BUFFER_SIZE],
        tx: &'a mut [u8; BUFFER_SIZE],
        storage: &'a mut [Storage<'a>; 2],
        identity: DiscoveryConfig,
        buffers: DiscoveryBuffers<'a>,
    ) -> Result<Self, Error> {
        let state = Discovery::new(
            identity.local_node,
            identity.peer_node,
            config.local,
            config.prefix_len,
            config.local_port,
            now,
        )
        .map_err(|_| Error::Configuration)?;
        let mut tcp = NetTcp::new_with_open_peer(
            DiscoveryPort::new(port, config.local, now),
            config,
            now,
            rx,
            tx,
            storage,
        )?;
        let mut udp = UdpSocket::new(
            PacketBuffer::new(&mut buffers.rx_meta[..], &mut buffers.rx[..]),
            PacketBuffer::new(&mut buffers.tx_meta[..], &mut buffers.tx[..]),
        );
        udp.bind(discovery::PORT).map_err(|_| Error::Socket)?;
        let udp = tcp.sockets_mut().add(udp);
        Ok(Self {
            tcp,
            udp,
            state,
            config,
            initiator: identity.local_node < identity.peer_node,
            armed: false,
            attempt: None,
            pending: None,
            identity,
            selected_ms: 0,
            candidate_ms: 0,
        })
    }

    pub fn listen(&mut self) -> Result<(), Error> {
        self.tcp.healthy()?;
        if self.initiator {
            return Err(Error::Configuration);
        }
        self.armed = true;
        Ok(())
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        self.tcp.healthy()?;
        if !self.initiator {
            return Err(Error::Configuration);
        }
        self.armed = true;
        Ok(())
    }

    pub fn state(&self) -> Result<State, Error> {
        let state = self.tcp.state()?;
        // Waiting for an unauthenticated hint is a live listener lifecycle,
        // never an established transport or a failed TCP generation.
        if self.armed && self.attempt.is_none() {
            return Ok(State::Listen);
        }
        Ok(state)
    }

    pub fn poll(&mut self, now_ms: u64) -> Result<State, Error> {
        self.poll_with_checkpoints(now_ms, &mut || {})
    }

    pub fn poll_with_checkpoints(
        &mut self,
        now_ms: u64,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<State, Error> {
        self.tcp.port_mut().set_now(now_ms);
        self.tcp.poll_ingress_phase(now_ms, checkpoint)?;
        self.discovery_turn(now_ms)?;
        checkpoint();
        let state = self.tcp.poll_egress_phase(now_ms, checkpoint)?;
        if self.armed && self.attempt.is_none() {
            return Ok(State::Listen);
        }
        Ok(state)
    }

    pub fn discovery_schedule(&self) -> Option<discovery::AnnouncementSchedule> {
        Some(self.state.announcement_schedule())
    }

    pub fn resume_discovery_schedule(
        &mut self,
        schedule: discovery::AnnouncementSchedule,
        now: u64,
    ) -> Result<(), Error> {
        self.state
            .resume_announcements(schedule, now)
            .map_err(|error| {
                if error == discovery::Error::Clock {
                    Error::Clock
                } else {
                    Error::Configuration
                }
            })
    }

    pub fn discovery_due(&mut self, now: u64) -> Result<bool, Error> {
        self.state
            .due(now)
            .map(|due| due && self.pending.is_none())
            .map_err(|_| Error::Clock)
    }

    /// A distinct CSPRNG nonce is supplied by the guest for each datagram.
    /// Full UDP TX storage retains this packet; it is never regenerated on AGAIN.
    pub fn prepare_discovery(&mut self, now: u64, nonce: [u8; 16]) -> Result<(), Error> {
        self.tcp.healthy()?;
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let packet = self
            .state
            .announce(now, nonce)
            .and_then(|m| m.encode())
            .map_err(|_| Error::Configuration)?;
        self.pending = Some(packet);
        Ok(())
    }

    pub fn peer_ipv4(&self) -> Option<[u8; 4]> {
        self.tcp.peer_ipv4()
    }

    pub fn discovery_snapshot(&self) -> Option<DiscoverySnapshot> {
        let port = self.tcp.port();
        Some(DiscoverySnapshot {
            counters: self.state.counters,
            candidates: self.state.candidates(),
            attempts: self.state.pending_auth(),
            selected: self.attempt,
            selected_ms: self.selected_ms,
            candidate_ms: self.candidate_ms,
            sent: port.sent,
            sent_ms: port.sent_ms,
            sent_nonce: port.nonce,
            next_ms: self.state.next_announcement_ms(),
            local_node: self.identity.local_node,
            peer_node: self.identity.peer_node,
            local_ip: self.config.local,
            local_port: self.config.local_port,
        })
    }

    pub fn send_tls(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.tcp.send_tls(bytes)
    }

    pub fn send_exact(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.tcp.send_exact(bytes)
    }

    pub fn receive_tls(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
        self.tcp.receive_tls(bytes)
    }

    pub fn terminal_tx_quiescent(&self) -> bool {
        self.tcp.terminal_tx_quiescent()
    }

    pub fn observation(&self) -> cyxia_net_transport::tcp::Observation {
        self.tcp.observation()
    }

    pub fn remote(&self) -> Option<smoltcp::wire::IpEndpoint> {
        self.tcp.remote()
    }

    pub fn close(&mut self, now_ms: u64) {
        self.tcp.close(now_ms);
    }

    pub fn abort(&mut self) {
        self.tcp.abort();
    }

    fn discovery_turn(&mut self, now: u64) -> Result<(), Error> {
        let socket = self.tcp.sockets_mut().get_mut::<UdpSocket>(self.udp);
        // A turn receives at most one Ethernet frame. Consume at most one
        // discovery packet as well; invalid datagrams never select a target.
        if let Ok((packet, meta)) = socket.recv() {
            let IpAddress::Ipv4(source) = meta.endpoint.addr;
            if meta.endpoint.port == discovery::PORT {
                let _ = self.state.receive(source.octets(), packet, now);
            }
        }
        if let Some(packet) = self.pending.as_ref() {
            let mask = u32::MAX >> self.config.prefix_len;
            let broadcast =
                Ipv4Address::from((u32::from_be_bytes(self.config.local) | mask).to_be_bytes());
            match socket.send_slice(packet, (broadcast, discovery::PORT)) {
                Ok(()) => self.pending = None,
                Err(SendError::BufferFull) => {}
                Err(_) => return Err(Error::Socket),
            }
        }
        if self.armed && self.attempt.is_none() {
            match self.state.begin_auth(now) {
                Ok(attempt) => {
                    self.selected_ms = now;
                    self.candidate_ms = self
                        .state
                        .selected_candidate()
                        .map(|c| c.received_ms)
                        .unwrap_or(0);
                    self.tcp.select_peer(attempt.ipv4, attempt.port);
                    self.attempt = Some(attempt);
                    if self.initiator {
                        self.tcp.connect()?
                    } else {
                        self.tcp.listen()?
                    }
                }
                Err(discovery::Error::NotFound | discovery::Error::Expired) => {}
                Err(_) => return Err(Error::Peer),
            }
        }
        Ok(())
    }
}
