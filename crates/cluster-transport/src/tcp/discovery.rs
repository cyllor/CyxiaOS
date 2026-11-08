//! UDP hints are processed by the same bounded NIC/socket turn as TCP. The
//! selected endpoint remains pinned for this transport's entire lifetime.
use super::*;
use crate::discovery::{self, Attempt, Discovery, PacketMetadata};
use smoltcp::socket::udp::{PacketBuffer, Socket as UdpSocket};
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
pub(super) struct Socket {
    state: Discovery,
    udp: SocketHandle,
    pub(super) initiator: bool,
    pub(super) armed: bool,
    pub(super) attempt: Option<Attempt>,
    pending: Option<[u8; discovery::WIRE_BYTES]>,
    identity: DiscoveryConfig,
    selected_ms: u64,
    candidate_ms: u64,
}
impl<'a, P: Port> Tcp<'a, P> {
    pub fn discovery_schedule(&self) -> Option<discovery::AnnouncementSchedule> {
        self.discovery
            .as_ref()
            .map(|d| d.state.announcement_schedule())
    }
    pub fn resume_discovery_schedule(
        &mut self,
        schedule: discovery::AnnouncementSchedule,
        now: u64,
    ) -> Result<(), Error> {
        self.discovery
            .as_mut()
            .ok_or(Error::Configuration)?
            .state
            .resume_announcements(schedule, now)
            .map_err(|error| {
                if error == discovery::Error::Clock {
                    Error::Clock
                } else {
                    Error::Configuration
                }
            })
    }
    pub fn new_discovering(
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
        let mut tcp = Self::new_inner(port, config, now, rx, tx, storage, true)?;
        let mut udp = UdpSocket::new(
            PacketBuffer::new(&mut buffers.rx_meta[..], &mut buffers.rx[..]),
            PacketBuffer::new(&mut buffers.tx_meta[..], &mut buffers.tx[..]),
        );
        udp.bind(discovery::PORT).map_err(|_| Error::Socket)?;
        let udp = tcp.sockets.add(udp);
        tcp.discovery = Some(Socket {
            state,
            udp,
            initiator: identity.local_node < identity.peer_node,
            armed: false,
            attempt: None,
            pending: None,
            identity,
            selected_ms: 0,
            candidate_ms: 0,
        });
        Ok(tcp)
    }
    pub fn discovery_due(&mut self, now: u64) -> Result<bool, Error> {
        let Some(d) = self.discovery.as_mut() else {
            return Ok(false);
        };
        d.state
            .due(now)
            .map(|due| due && d.pending.is_none())
            .map_err(|_| Error::Clock)
    }
    /// A distinct CSPRNG nonce is supplied by the guest for each datagram.
    /// Full UDP TX storage retains this packet; it is never regenerated on AGAIN.
    pub fn prepare_discovery(&mut self, now: u64, nonce: [u8; 16]) -> Result<(), Error> {
        self.healthy()?;
        let d = self.discovery.as_mut().ok_or(Error::Configuration)?;
        if d.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let packet = d
            .state
            .announce(now, nonce)
            .and_then(|m| m.encode())
            .map_err(|_| Error::Configuration)?;
        d.pending = Some(packet);
        Ok(())
    }
    pub fn peer_ipv4(&self) -> Option<[u8; 4]> {
        if self.config.peer == [0; 4] {
            None
        } else {
            Some(self.config.peer)
        }
    }
    pub fn discovery_snapshot(&self) -> Option<DiscoverySnapshot> {
        let d = self.discovery.as_ref()?;
        let port = self.device.port();
        Some(DiscoverySnapshot {
            counters: d.state.counters,
            candidates: d.state.candidates(),
            attempts: d.state.pending_auth(),
            selected: d.attempt,
            selected_ms: d.selected_ms,
            candidate_ms: d.candidate_ms,
            sent: port.discovery_sent,
            sent_ms: port.discovery_sent_ms,
            sent_nonce: port.discovery_nonce,
            next_ms: d.state.next_announcement_ms(),
            local_node: d.identity.local_node,
            peer_node: d.identity.peer_node,
            local_ip: self.config.local,
            local_port: self.config.local_port,
        })
    }
    pub(super) fn discovery_turn(&mut self, now: u64) -> Result<(), Error> {
        let Some(d) = self.discovery.as_mut() else {
            return Ok(());
        };
        let socket = self.sockets.get_mut::<UdpSocket>(d.udp);
        // A turn receives at most one Ethernet frame. Consume at most one
        // discovery packet as well; invalid datagrams never select a target.
        if let Ok((packet, meta)) = socket.recv() {
            let IpAddress::Ipv4(source) = meta.endpoint.addr;
            if meta.endpoint.port == discovery::PORT {
                let _ = d.state.receive(source.octets(), packet, now);
            }
        }
        if let Some(packet) = d.pending.as_ref() {
            let mask = u32::MAX >> self.config.prefix_len;
            let broadcast =
                Ipv4Address::from((u32::from_be_bytes(self.config.local) | mask).to_be_bytes());
            match socket.send_slice(packet, (broadcast, discovery::PORT)) {
                Ok(()) => d.pending = None,
                Err(smoltcp::socket::udp::SendError::BufferFull) => {}
                Err(_) => return Err(Error::Socket),
            }
        }
        if d.armed && d.attempt.is_none() {
            match d.state.begin_auth(now) {
                Ok(attempt) => {
                    d.selected_ms = now;
                    d.candidate_ms = d
                        .state
                        .selected_candidate()
                        .map(|c| c.received_ms)
                        .unwrap_or(0);
                    self.config.peer = attempt.ipv4;
                    self.config.peer_port = attempt.port;
                    d.attempt = Some(attempt);
                    self.device.port_mut().select_peer(self.config);
                    if d.initiator {
                        self.connect_raw()?
                    } else {
                        self.listen_raw()?
                    }
                }
                Err(discovery::Error::NotFound | discovery::Error::Expired) => {}
                Err(_) => return Err(Error::Peer),
            }
        }
        Ok(())
    }
}
