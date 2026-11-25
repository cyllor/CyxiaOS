//! Legacy cluster TCP surface. The bounded single-machine stream itself lives
//! in cyxia-net-transport (discovery-free); this module adds the relocated
//! CXD1 paired-node discovery machinery as an opt-in wrapper. `Tcp` keeps the
//! historical facade shape: `new` constructs the plain fixed-peer stream,
//! `new_discovering` constructs the legacy hint-selected stream. TCP
//! connectivity is never a cluster admission proof.
use crate::device::Port;
use cyxia_net_transport::tcp::Tcp as NetTcp;
pub use cyxia_net_transport::tcp::{
    BUFFER_SIZE, Config, Error, IDLE_TIMEOUT_SECS, Observation, State, Storage, reconnect_due,
};
mod discovering;
pub use discovering::{DiscoveringTcp, DiscoveryBuffers, DiscoveryConfig, DiscoverySnapshot};

/// The historical facade stream type. `Plain` is exactly the single-machine
/// net-transport stream; `Discovering` adds the legacy CXD1 UDP hint turn.
pub enum Tcp<'a, P> {
    Plain(NetTcp<'a, P>),
    Discovering(DiscoveringTcp<'a, P>),
}

impl<'a, P: Port> Tcp<'a, P> {
    pub fn new(
        port: P,
        config: Config,
        now_ms: u64,
        rx: &'a mut [u8; BUFFER_SIZE],
        tx: &'a mut [u8; BUFFER_SIZE],
        storage: &'a mut [Storage<'a>; 1],
    ) -> Result<Self, Error> {
        Ok(Self::Plain(NetTcp::new(
            port, config, now_ms, rx, tx, storage,
        )?))
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
        Ok(Self::Discovering(DiscoveringTcp::new(
            port, config, now, rx, tx, storage, identity, buffers,
        )?))
    }

    pub fn listen(&mut self) -> Result<(), Error> {
        match self {
            Self::Plain(tcp) => tcp.listen(),
            Self::Discovering(tcp) => tcp.listen(),
        }
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        match self {
            Self::Plain(tcp) => tcp.connect(),
            Self::Discovering(tcp) => tcp.connect(),
        }
    }

    pub fn state(&self) -> Result<State, Error> {
        match self {
            Self::Plain(tcp) => tcp.state(),
            Self::Discovering(tcp) => tcp.state(),
        }
    }

    pub fn poll(&mut self, now_ms: u64) -> Result<State, Error> {
        match self {
            Self::Plain(tcp) => tcp.poll(now_ms),
            Self::Discovering(tcp) => tcp.poll(now_ms),
        }
    }

    pub fn poll_with_checkpoints(
        &mut self,
        now_ms: u64,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<State, Error> {
        match self {
            Self::Plain(tcp) => tcp.poll_with_checkpoints(now_ms, checkpoint),
            Self::Discovering(tcp) => tcp.poll_with_checkpoints(now_ms, checkpoint),
        }
    }

    pub fn send_tls(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        match self {
            Self::Plain(tcp) => tcp.send_tls(bytes),
            Self::Discovering(tcp) => tcp.send_tls(bytes),
        }
    }

    pub fn send_exact(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Plain(tcp) => tcp.send_exact(bytes),
            Self::Discovering(tcp) => tcp.send_exact(bytes),
        }
    }

    pub fn receive_tls(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Plain(tcp) => tcp.receive_tls(bytes),
            Self::Discovering(tcp) => tcp.receive_tls(bytes),
        }
    }

    pub fn terminal_tx_quiescent(&self) -> bool {
        match self {
            Self::Plain(tcp) => tcp.terminal_tx_quiescent(),
            Self::Discovering(tcp) => tcp.terminal_tx_quiescent(),
        }
    }

    pub fn observation(&self) -> Observation {
        match self {
            Self::Plain(tcp) => tcp.observation(),
            Self::Discovering(tcp) => tcp.observation(),
        }
    }

    pub fn remote(&self) -> Option<smoltcp::wire::IpEndpoint> {
        match self {
            Self::Plain(tcp) => tcp.remote(),
            Self::Discovering(tcp) => tcp.remote(),
        }
    }

    pub fn close(&mut self, now_ms: u64) {
        match self {
            Self::Plain(tcp) => tcp.close(now_ms),
            Self::Discovering(tcp) => tcp.close(now_ms),
        }
    }

    pub fn abort(&mut self) {
        match self {
            Self::Plain(tcp) => tcp.abort(),
            Self::Discovering(tcp) => tcp.abort(),
        }
    }

    pub fn peer_ipv4(&self) -> Option<[u8; 4]> {
        match self {
            Self::Plain(tcp) => tcp.peer_ipv4(),
            Self::Discovering(tcp) => tcp.peer_ipv4(),
        }
    }

    pub fn discovery_schedule(&self) -> Option<crate::discovery::AnnouncementSchedule> {
        match self {
            Self::Plain(_) => None,
            Self::Discovering(tcp) => tcp.discovery_schedule(),
        }
    }

    pub fn resume_discovery_schedule(
        &mut self,
        schedule: crate::discovery::AnnouncementSchedule,
        now: u64,
    ) -> Result<(), Error> {
        match self {
            Self::Plain(_) => Err(Error::Configuration),
            Self::Discovering(tcp) => tcp.resume_discovery_schedule(schedule, now),
        }
    }

    pub fn discovery_due(&mut self, now: u64) -> Result<bool, Error> {
        match self {
            Self::Plain(_) => Ok(false),
            Self::Discovering(tcp) => tcp.discovery_due(now),
        }
    }

    pub fn prepare_discovery(&mut self, now: u64, nonce: [u8; 16]) -> Result<(), Error> {
        match self {
            Self::Plain(tcp) => {
                tcp.healthy()?;
                Err(Error::Configuration)
            }
            Self::Discovering(tcp) => tcp.prepare_discovery(now, nonce),
        }
    }

    pub fn discovery_snapshot(&self) -> Option<DiscoverySnapshot> {
        match self {
            Self::Plain(_) => None,
            Self::Discovering(tcp) => tcp.discovery_snapshot(),
        }
    }
}
