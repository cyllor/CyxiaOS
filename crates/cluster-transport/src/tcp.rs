//! A single statically provisioned TCP stream over native Ethernet/ARP/IPv4.
//! Its plaintext bytes must be consumed only by the TLS engine.
use crate::device::{Ethernet, Port};
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
        let mac = EthernetAddress(config.mac);
        let local = Ipv4Address::from(config.local);
        let peer = Ipv4Address::from(config.peer);
        let unicast = |ip: [u8; 4]| (1..=223).contains(&ip[0]) && ip[0] != 127;
        if !mac.is_unicast()
            || config.mac == [0; 6]
            || !unicast(config.local)
            || !unicast(config.peer)
            || local == peer
            || !(1..=30).contains(&config.prefix_len)
            || config.local_port == 0
            || config.peer_port == 0
            || config.random_seed == 0
            || now_ms > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        let cidr = IpCidr::new(IpAddress::Ipv4(local), config.prefix_len);
        if !cidr.contains_addr(&IpAddress::Ipv4(peer)) {
            return Err(Error::Configuration);
        }
        let host_mask = u32::MAX >> config.prefix_len;
        for address in [config.local, config.peer] {
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
        socket.set_timeout(Some(Duration::from_secs(10)));
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
        })
    }

    pub fn listen(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.sockets
            .get_mut::<Socket>(self.socket)
            .listen((Ipv4Address::from(self.config.local), self.config.local_port))
            .map_err(|_| Error::Socket)
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        self.healthy()?;
        self.sockets
            .get_mut::<Socket>(self.socket)
            .connect(
                self.interface.context(),
                (Ipv4Address::from(self.config.peer), self.config.peer_port),
                (Ipv4Address::from(self.config.local), self.config.local_port),
            )
            .map_err(|_| Error::Socket)
    }

    fn healthy(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
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
        self.healthy()?;
        if now_ms < self.last_ms || now_ms > i64::MAX as u64 {
            self.abort();
            return Err(Error::Clock);
        }
        self.last_ms = now_ms;
        self.device.port_mut().set_time(now_ms);
        // Preflight state is complete and no device/socket borrow is live.
        // Give the first cold NIC service operation its own native credit.
        checkpoint();
        if self.device.service_with_checkpoint(checkpoint).is_err() {
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();
        if self.device.port_mut().flush().is_err() {
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();

        let now = Instant::from_millis(now_ms as i64);
        let before = self.sockets.get::<Socket>(self.socket);
        let queued = before.send_queue();
        let state = before.state();
        let ingress = self
            .interface
            .poll_ingress_single(now, &mut self.device, &mut self.sockets);
        let after = self.sockets.get::<Socket>(self.socket);
        if ingress != smoltcp::iface::PollIngressSingleResult::None {
            self.device.port_mut().ingress_processed(
                after.send_queue() < queued
                    || (matches!(state, State::SynSent | State::SynReceived)
                        && after.state() == State::Established),
            );
        }
        checkpoint();

        // A hardware multichain port can accept multiple independent frames.
        // Keep the logical burst, but expose a safe scheduler checkpoint after
        // every complete descriptor-chain attempt. This prevents a batch from
        // being billed as one non-preemptible native CPU segment.
        for _ in 0..self.device.port().burst_capacity().clamp(1, 8) {
            let egress = self
                .interface
                .poll_egress(now, &mut self.device, &mut self.sockets);
            if self.device.service_with_checkpoint(checkpoint).is_err() {
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
        if self.device.port_mut().flush().is_err() {
            self.abort();
            return Err(Error::Device);
        }
        checkpoint();
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
