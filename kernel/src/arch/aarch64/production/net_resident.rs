//! Authorized, polling SEC-N service. CPU0 prepares it under Recovery and
//! transfers the stopped owner exclusively to the fixed business CPU.
use super::{
    super::sec_n_broker::{
        self, BootIdentity,
        ingress::Parser,
        resident::{Progress, Verifier},
        signer::Signer,
    },
    net_entropy::Entropy,
};
use crate::{ExceptionFrame, net_device, virtio_platform::Board};
use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicU64, Ordering},
};
use cyxia_arch_aarch64::cpu;
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::{Error, net::BatchedNet};
use cyxia_net_transport::{
    device::{self, MTU, Port, VirtioPort},
    tcp::{self, BUFFER_SIZE, Config, State, Storage, Tcp},
};

pub(crate) const CPU: usize = sec_n_broker::resident::CPU;
const DEPART_MARGIN_NS: u64 = 500_000;
const RESET_DRAIN_NS: u64 = 1_000_000_000;

#[unsafe(link_section = ".bss.sec_n")]
static mut TCP_RX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
#[unsafe(link_section = ".bss.sec_n")]
static mut TCP_TX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
#[unsafe(link_section = ".bss.sec_n")]
static mut SOCKET: MaybeUninit<[Storage<'static>; 1]> = MaybeUninit::uninit();

// [epoch, key gen, phase, accepted, authenticated, retired, parser reads,
//  fault, last rejected-and-drained connection, parser admissions, parser expirations].
// The host can read this device-independent witness while the guest is stopped.
#[used]
#[unsafe(no_mangle)]
static V020_RESIDENT_NET_EVIDENCE: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];

const PREPARED: u64 = 1;
const LISTENING: u64 = 2;
const CONNECTED: u64 = 3;
const CLOSED: u64 = 4;
const SCRUBBED: u64 = 5;

#[derive(Clone, Copy)]
enum Connection {
    Listening,
    Active,
    Rejecting(u64),
}

fn record(index: usize, value: u64) {
    V020_RESIDENT_NET_EVIDENCE[index].store(value, Ordering::Release);
}

struct Ingress {
    nic: VirtioPort<'static, Board, BatchedNet>,
    parser: Parser,
    deadline_ns: u64,
    available: bool,
}

impl Port for Ingress {
    fn send(&mut self, frame: &[u8]) -> Result<(), device::Error> {
        self.nic.send(frame)
    }

    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, device::Error> {
        if !self.available || sec_n_broker::now_ns() >= self.deadline_ns {
            return Ok(None);
        }
        self.available = false;
        if !self.parser.has_pending() {
            let Some(length) = self.nic.receive(frame)? else {
                return Ok(None);
            };
            self.parser
                .stage_frame(frame.get(..length).ok_or(device::Error::Frame)?)?;
        }
        self.parser.poll_frame(frame, self.deadline_ns)
    }

    fn flush(&mut self) -> Result<(), device::Error> {
        self.nic.flush()
    }

    fn tx_quiescent(&self) -> bool {
        self.nic.tx_quiescent()
    }
}

type Stream = Tcp<'static, Ingress>;

/// The broker handles pending TLS ciphertext only. The paid network turn
/// advances the device separately and leaves the socket in trusted custody.
struct Ciphertext<'a>(&'a mut Stream);

impl Ciphertext<'_> {
    fn normal_close(&mut self) -> Result<bool, device::Error> {
        self.0.finish_passive_close().map_err(tcp_error)
    }
}

impl Port for Ciphertext<'_> {
    fn send(&mut self, bytes: &[u8]) -> Result<(), device::Error> {
        if !sec_n_broker::admits_next_transmit() {
            return Err(device::Error::WouldBlock);
        }
        self.0.send_exact(bytes).map_err(tcp_error)
    }

    fn receive(&mut self, out: &mut [u8; MTU]) -> Result<Option<usize>, device::Error> {
        self.receive_up_to(out, MTU)
    }

    fn receive_up_to(
        &mut self,
        out: &mut [u8; MTU],
        limit: usize,
    ) -> Result<Option<usize>, device::Error> {
        match self.0.receive_tls(&mut out[..limit.min(MTU)]) {
            Ok(0) | Err(tcp::Error::WouldBlock) => Ok(None),
            Ok(len) => Ok(Some(len)),
            Err(e) => Err(tcp_error(e)),
        }
    }

    fn tx_quiescent(&self) -> bool {
        self.0.terminal_tx_quiescent()
    }
}

fn tcp_error(error: tcp::Error) -> device::Error {
    match error {
        tcp::Error::WouldBlock => device::Error::WouldBlock,
        _ => device::Error::Device,
    }
}

pub(super) struct Resident {
    stream: Stream,
    verifier: Verifier,
    signer: Option<Signer<'static>>,
    entropy: Entropy,
    peer: [u8; 4],
    epoch: u64,
    connection: Connection,
}

impl Resident {
    pub(super) fn start(
        info: &BootInfo,
        identity: BootIdentity<'static>,
        mut entropy: Entropy,
        checkpoint: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Self, Error> {
        if cpu::registered_slot() != Some(0) || crate::clock::seconds().is_none() {
            return Err(Error::Response);
        }
        let listener = identity.listener();
        let mut bytes = [0; 8];
        entropy.fill_tcp_seed(&mut bytes)?;
        let seed = u64::from_le_bytes(bytes) | 1;
        zeroize::Zeroize::zeroize(&mut bytes);
        checkpoint()?;
        let device =
            net_device::open_resident(info, identity.boot_epoch(), listener.mac, checkpoint)?;
        checkpoint()?;
        let parser = Parser::load_image(
            identity.ingress_image(),
            listener.mac,
            listener.local_ipv4,
            listener.peer_ipv4,
            listener.listen_port,
        );
        checkpoint()?;
        let verifier = Verifier::load(identity, checkpoint)?;
        // SAFETY: the unique device claim also grants the single boot owner
        // of the TCP buffers. This sole mutable borrow follows the driver.
        let (rx, tx, sockets) = unsafe {
            (
                &mut *core::ptr::addr_of_mut!(TCP_RX),
                &mut *core::ptr::addr_of_mut!(TCP_TX),
                (&mut *core::ptr::addr_of_mut!(SOCKET)).write([Storage::EMPTY]),
            )
        };
        let config = Config {
            mac: listener.mac,
            local: listener.local_ipv4,
            peer: [0; 4],
            prefix_len: listener.prefix_len,
            local_port: listener.listen_port,
            peer_port: 0,
            random_seed: seed,
        };
        let mut stream = Tcp::new_with_open_peer(
            Ingress {
                nic: VirtioPort {
                    net: device,
                    platform: &Board,
                },
                parser,
                deadline_ns: 0,
                available: false,
            },
            config,
            sec_n_broker::now_ms(),
            rx,
            tx,
            sockets,
        )
        .map_err(|_| Error::Response)?;
        stream.listen().map_err(|_| Error::Response)?;
        // The approved Signer image receives the key immediately before the
        // owner is ready to hand off. No later initialization touches EL0.
        checkpoint()?;
        let signer = Signer::load_deployed(identity, identity.signer_image())
            .map_err(|_| Error::Response)?;
        record(0, identity.boot_epoch());
        record(1, identity.tls().key_generation);
        record(2, PREPARED);
        Ok(Self {
            stream,
            verifier,
            signer: Some(signer),
            entropy,
            peer: listener.peer_ipv4,
            epoch: 0,
            connection: Connection::Listening,
        })
    }

    /// One prepaid device or private-EL0 turn, bounded by the owner deadline.
    pub(super) fn step(&mut self, deadline_ns: u64) -> Result<(), Error> {
        if cpu::registered_slot() != Some(CPU) {
            return Err(Error::Response);
        }
        if sec_n_broker::now_ns() >= deadline_ns.saturating_sub(DEPART_MARGIN_NS) {
            return Ok(());
        }
        if self.signer.is_none() {
            if self.verifier.scrub_step() {
                record(2, SCRUBBED);
                return Err(Error::Device);
            }
            return Ok(());
        }
        let result = self.turn(deadline_ns);
        if let Err(error) = result {
            record(7, error as u64 + 1);
            self.stop();
        }
        Ok(())
    }

    fn turn(&mut self, deadline_ns: u64) -> Result<(), Error> {
        if !matches!(self.connection, Connection::Rejecting(_)) && !self.entropy.maintain()? {
            return Ok(());
        }
        // Poll one submitted TX completion even when the network is idle.
        let port = self.stream.port_mut();
        port.nic.net.poll_tx(&Board)?;
        port.deadline_ns = deadline_ns.saturating_sub(DEPART_MARGIN_NS);
        port.available = true;
        let time = sec_n_broker::now_ms();
        self.stream
            .poll_ingress_phase(time, &mut || {})
            .map_err(|_| Error::Device)?;
        if self.stream.peer_ipv4().is_none()
            && let Some(peer) = self.stream.remote()
        {
            match core::net::SocketAddr::from(peer) {
                core::net::SocketAddr::V4(peer)
                    if peer.ip().octets() == self.peer && peer.port() != 0 =>
                {
                    self.stream.select_peer(self.peer, peer.port());
                }
                _ => return Err(Error::Response),
            }
        }
        let socket = self
            .stream
            .poll_egress_phase(time, &mut || {})
            .map_err(|_| Error::Device)?;
        let (checked, accepted, expired) = self.stream.port().parser.counts();
        record(6, checked);
        record(9, accepted);
        record(10, expired);
        match self.connection {
            Connection::Rejecting(expiry) => {
                if sec_n_broker::now_ns() >= expiry {
                    return Err(Error::Timeout);
                }
                if self
                    .stream
                    .relisten_open_after_rejection()
                    .map_err(|_| Error::Response)?
                {
                    if !self
                        .signer
                        .as_mut()
                        .ok_or(Error::Response)?
                        .reject(self.epoch)
                    {
                        return Err(Error::Response);
                    }
                    self.connection = Connection::Listening;
                    record(8, self.epoch);
                    record(2, LISTENING);
                }
                return Ok(());
            }
            Connection::Listening => {
                record(2, LISTENING);
                if super::recovery::audit_degraded() {
                    return Ok(());
                }
                #[cfg(cyxia_business_package)]
                if super::signed_control::publications_fenced() {
                    return Ok(());
                }
                if socket != State::Established {
                    return Ok(());
                }
                if self.stream.peer_ipv4() != Some(self.peer) {
                    return Err(Error::Response);
                }
                self.epoch = self.epoch.checked_add(1).ok_or(Error::Exhausted)?;
                self.verifier.begin(
                    self.epoch,
                    u32::from_be_bytes(self.peer),
                    sec_n_broker::now_ns(),
                );
                self.connection = Connection::Active;
                record(3, self.epoch);
                record(2, CONNECTED);
                return Ok(());
            }
            Connection::Active => {}
        }
        let signer = self.signer.as_mut().ok_or(Error::Response)?;
        let result = self.verifier.run(
            &mut Ciphertext(&mut self.stream),
            &mut |out| self.entropy.fill(out),
            Ciphertext::normal_close,
            signer,
            deadline_ns,
        );
        if self.verifier.authenticated(self.epoch) {
            record(4, self.epoch);
        }
        match result {
            Ok(Progress::Retired) => {
                if !signer.retire(self.epoch) {
                    return Err(Error::Response);
                }
                self.stream
                    .relisten_open_after_close()
                    .map_err(|_| Error::Response)?;
                self.connection = Connection::Listening;
                record(5, self.epoch);
                record(2, LISTENING);
            }
            Ok(Progress::Rejected) => {
                self.stream.abort_rejected().map_err(|_| Error::Response)?;
                let expiry = sec_n_broker::now_ns()
                    .checked_add(RESET_DRAIN_NS)
                    .ok_or(Error::Exhausted)?;
                self.connection = Connection::Rejecting(expiry);
            }
            Ok(Progress::Pending) => {}
            Err(stop) => {
                record(7, stop.code);
                self.stop();
            }
        }
        Ok(())
    }

    pub(super) fn stop(&mut self) {
        // Stop new DMA and revoke the isolated verifier before wiping its
        // backing. Retain the queue memory and all outstanding leases.
        if let Some(signer) = self.signer.take() {
            self.stream.abort();
            let port = self.stream.port_mut();
            port.parser.discard_frame();
            port.nic.net.fence_native(&Board);
            self.verifier.revoke();
            signer.discard();
            self.entropy.close();
            record(2, CLOSED);
        }
    }
}

pub(crate) fn verify_resident_trap(slot: usize, frame: &ExceptionFrame, kind: u64) -> bool {
    sec_n_broker::resident::verify_trap(slot, frame, kind)
}
