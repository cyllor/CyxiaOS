//! V0.20 wave 11: SEC-N real VirtIO-net + TCP to the EL0 local-echo guest in the
//! production boot (evidence words 138..142).
//!
//! After the advice chain, CPU0 brings up the REAL `driver-virtio` BatchedNet
//! (`net_device::init`), runs the smoltcp `tcp::Tcp` stream as a passive listener
//! on 10.0.2.15:7 (static IPv4, /24), and accepts one connection from the QEMU
//! user-net gateway 10.0.2.2 on whatever source port it presents (open-peer
//! accept: the peer port is pinned with `select_peer` on the first SYN). The
//! established byte stream is then relayed to the cross-compiled local-echo EL0
//! guest through the shared SVC 0x43 broker (`sec_n_broker`). Admission stays in
//! the guest (its own `net-transport::admission::Admission`); this module never
//! touches a rate limiter.
//!
//! HONEST SCOPE (do not read more into the words below):
//! * Polling only: IRQs stay masked at EL1, the accept loop is bounded by
//!   `NET_POLL_TURNS` turns paced at `TURN_PACE_MS`, every guest entry is
//!   bounded by the private timer backstop, and the relay by `GUEST_SVC_BUDGET`
//!   SVCs. A guest that does not park ends the relay (`V020_W11_NET_GUEST_END`
//!   a=902/900/901); a remote peer can never halt the boot.
//! * READ is length-aware (never dequeues more than the guest asked for); a
//!   closed/reset/failed stream reaches the guest as EOF + disconnected POLL.
//! * The authenticated test profile seeds separate TCP-ISN and TLS DRBG
//!   domains from the pinned VirtIO RNG. Missing or failed entropy closes
//!   authentication. The transport-only probe has its own fixture source.
//! * Word 140 counts the admission receipt issued by the guest and accepted by
//!   the broker for this connection epoch and pinned peer IPv4.
//! * Word 142 stays zero. The authenticated verifier observes Echo with its
//!   independent pinned TLS peer and combines that result with this evidence.
//! * Word 176 counts a normally retired guest Admission credit in the opt-in
//!   authenticated profile. RX pools and queue memory stay pinned after return.
//! * No device => `V020_W11_NET_ABSENT`, words 138..142 stay 0, boot continues.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * TCP_RX / TCP_TX (static mut) are covered by the FrameMeta Arena registration
//!   for the pinned `.bss.sec_n` section. Their only `&mut` is created once in
//!   `open_stream`, guarded by the SERVED swap, on CPU0 after the business CPUs
//!   stopped; the `Tcp` borrowing them is dropped before `serve` returns.
//! * SERVED (atomic): CPU0 only; makes `open_stream` (the buffer borrow) one-shot.
//! * net_device.rs manages dynamic descriptor custody for its pinned DMA pools;
//!   the guest frame pool and broker page by sec_n_broker.rs.

use super::super::{report, sec_n_broker};
use super::evidence;
use crate::net_device::{self, NetDevice};
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_arch_aarch64::timer;
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::net::BatchedNet;
use cyxia_driver_virtio::reset::{RESET_PROOF_BYTES, ResetProof};
use cyxia_net_transport::device::{self, Port, VirtioPort};
use cyxia_net_transport::tcp::{self, BUFFER_SIZE, Config, State, Storage, Tcp};

#[cfg(feature = "v020-production-authenticated-net")]
#[path = "net_entropy.rs"]
mod net_entropy;

/// Upper bound of accept turns on CPU0.
const NET_POLL_TURNS: u32 = 20_000;
/// Minimum spacing between accept turns (bounds the accept window to ~20 s).
const TURN_PACE_MS: u64 = 1;
/// Bounded SVC budget for the guest relay run (the fixture's proven bound).
const GUEST_SVC_BUDGET: u64 = 200_000;
const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const PREFIX_LEN: u8 = 24;
const LISTEN_PORT: u16 = 7;
const TCP_SEED_BYTES: usize = 8;
/// QEMU user-net gateway; must equal the guest's trusted source observation.
const PEER_IP: [u8; 4] = [10, 0, 2, 2];

type Stream<'a> = Tcp<'a, VirtioPort<'a, Board, BatchedNet>>;

#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut TCP_RX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
#[cfg_attr(feature = "v020-production", unsafe(link_section = ".bss.sec_n"))]
static mut TCP_TX: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static SERVED: AtomicBool = AtomicBool::new(false);

/// Result of the one-shot SEC-N service run (evidence words 138..141).
#[derive(Clone, Copy, Default)]
pub(super) struct NetOutcome {
    pub(super) device: bool,
    pub(super) tcp_established: bool,
    pub(super) leases: u64,
    pub(super) relayed_bytes: u64,
    #[cfg(feature = "v020-production-authenticated-net")]
    rng_bytes: u64,
    #[cfg(feature = "v020-production-authenticated-net")]
    pub(super) retired: u64,
}

/// Byte-stream adapter: the broker's READ/WRITE become TCP payload receive/send
/// on the established stream; every operation first runs one bounded TCP turn.
struct StreamPort<'s, 'a> {
    tcp: &'s mut Stream<'a>,
}
impl StreamPort<'_, '_> {
    #[cfg(feature = "v020-production-authenticated-net")]
    fn poll_normal_close(&mut self) -> Result<bool, device::Error> {
        // An idle port only reaps a TX completion when explicitly polled.
        // BatchedNet::poll_tx checks a used entry and acknowledges its exact token.
        self.tcp
            .port_mut()
            .net
            .poll_tx(&Board)
            .map_err(|_| device::Error::Device)?;
        self.tcp
            .poll_passive_close(sec_n_broker::now_ms())
            .map_err(|_| device::Error::Device)
    }
    fn turn(&mut self) {
        // A failed turn poisons the stream: the following receive/send then
        // returns Closed, which the broker surfaces to the guest as EOF.
        let _ = self.tcp.poll(sec_n_broker::now_ms());
    }
}
impl Port for StreamPort<'_, '_> {
    fn send(&mut self, bytes: &[u8]) -> Result<(), device::Error> {
        self.turn();
        match self.tcp.send_exact(bytes) {
            Ok(()) => Ok(()),
            Err(tcp::Error::WouldBlock) => Err(device::Error::WouldBlock),
            Err(_) => Err(device::Error::Device),
        }
    }
    fn receive(&mut self, frame: &mut [u8; device::MTU]) -> Result<Option<usize>, device::Error> {
        self.receive_up_to(frame, device::MTU)
    }
    /// Byte stream: dequeue at most `limit` bytes; the unread suffix stays in
    /// the smoltcp RX buffer for the next READ. Closed/reset/failed => Device.
    fn receive_up_to(
        &mut self,
        frame: &mut [u8; device::MTU],
        limit: usize,
    ) -> Result<Option<usize>, device::Error> {
        self.turn();
        match self.tcp.receive_tls(&mut frame[..limit.min(device::MTU)]) {
            Ok(0) | Err(tcp::Error::WouldBlock) => Ok(None),
            Ok(n) => Ok(Some(n)),
            Err(_) => Err(device::Error::Device),
        }
    }
    fn tx_quiescent(&self) -> bool {
        self.tcp.terminal_tx_quiescent()
    }
}

fn pace() {
    let ticks = (timer::frequency() / 1000).max(1) * TURN_PACE_MS;
    let until = timer::ticks().saturating_add(ticks);
    while timer::ticks() < until {
        core::hint::spin_loop();
    }
}

/// Pin the first remote endpoint if it is the gateway; abort any other source.
fn pin_peer(stream: &mut Stream<'_>) -> bool {
    if stream.peer_ipv4().is_some() {
        return true;
    }
    let Some(remote) = stream.remote() else {
        return true;
    };
    match core::net::SocketAddr::from(remote) {
        core::net::SocketAddr::V4(v4) if v4.ip().octets() == PEER_IP => {
            stream.select_peer(PEER_IP, v4.port());
            true
        }
        _ => {
            stream.abort();
            false
        }
    }
}

/// Why the bounded accept ended without a connection (serial reason code).
#[derive(Clone, Copy)]
enum AcceptFailure {
    /// No peer reached Established within NET_POLL_TURNS turns.
    Timeout = 1,
    /// A TCP/device turn failed (stream poisoned).
    Stream = 2,
    /// A non-gateway source was aborted.
    Peer = 3,
}

/// Bounded polling accept: Ok once the pinned peer is Established.
fn accept(stream: &mut Stream<'_>) -> Result<(u32, u64), AcceptFailure> {
    for _ in 0..NET_POLL_TURNS {
        let now = sec_n_broker::now_ms();
        stream
            .poll_ingress_phase(now, &mut || {})
            .map_err(|_| AcceptFailure::Stream)?;
        if !pin_peer(stream) {
            return Err(AcceptFailure::Peer);
        }
        match stream.poll_egress_phase(now, &mut || {}) {
            Ok(State::Established) => {
                return stream
                    .peer_ipv4()
                    .map(|ip| (u32::from_be_bytes(ip), sec_n_broker::now_ns()))
                    .ok_or(AcceptFailure::Peer);
            }
            Ok(_) => pace(),
            Err(_) => return Err(AcceptFailure::Stream),
        }
    }
    Err(AcceptFailure::Timeout)
}

/// Build the listening stream over the device. One-shot: the SERVED swap is
/// the only gate to the static stream buffers.
fn open_stream<'a>(
    dev: &'a mut NetDevice,
    storage: &'a mut [Storage<'a>; 1],
    random_seed: u64,
) -> Option<Stream<'a>> {
    if SERVED.swap(true, Ordering::AcqRel) {
        return None;
    }
    let config = Config {
        mac: dev.net.mac(),
        local: LOCAL_IP,
        peer: [0; 4],
        prefix_len: PREFIX_LEN,
        local_port: LISTEN_PORT,
        peer_port: 0,
        random_seed,
    };
    let port = VirtioPort {
        net: &mut dev.net,
        platform: &Board,
    };
    // SAFETY: one-shot (SERVED swap above) on CPU0; these are the only
    // references ever formed to the stream buffers (see module header).
    let (rx, tx) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(TCP_RX),
            &mut *core::ptr::addr_of_mut!(TCP_TX),
        )
    };
    let mut stream =
        Tcp::new_with_open_peer(port, config, sec_n_broker::now_ms(), rx, tx, storage).ok()?;
    stream.listen().ok()?;
    Some(stream)
}

/// Relay the established stream to a fresh local-echo guest until it parks.
/// A guest that does not park (budget, fault) ends the relay; it never halts
/// the production boot.
fn relay(
    stream: &mut Stream<'_>,
    identity: sec_n_broker::BootIdentity,
    source: u32,
    accepted_ns: u64,
    entropy: &mut sec_n_broker::EntropyFill<'_>,
) -> Result<u64, sec_n_broker::GuestStop> {
    let layout = sec_n_broker::load_guest();
    report(
        "V020_W11_NET_GUEST",
        layout.entry,
        layout.used_frames as u64,
        sec_n_broker::GUEST_ELF.len() as u64,
    );
    sec_n_broker::reset_guest_data(&layout);
    sec_n_broker::stage_connection(
        identity,
        sec_n_broker::LOCAL_NODE,
        true,
        1,
        source,
        accepted_ns,
    );
    let mut port = StreamPort { tcp: stream };
    #[cfg(feature = "v020-production-authenticated-net")]
    {
        let mut signer = sec_n_broker::signer::Signer::load(identity);
        sec_n_broker::run_guest(
            &layout,
            &mut port,
            entropy,
            GUEST_SVC_BUDGET,
            Some(StreamPort::poll_normal_close),
            Some(&mut signer),
        )
    }
    #[cfg(not(feature = "v020-production-authenticated-net"))]
    {
        sec_n_broker::try_run_until_park(&layout, &mut port, entropy, GUEST_SVC_BUDGET)
    }
}

/// One-shot SEC-N service run on CPU0 (after the advice chain).
pub(super) fn serve(info: &BootInfo, identity: sec_n_broker::BootIdentity) -> NetOutcome {
    // net_device::init is itself one-shot (CLAIMED) and CPU0-only.
    let mut dev = match net_device::init(info) {
        Ok(dev) => dev,
        Err(error) => {
            super::super::super::log(b"V020_W11_NET_ABSENT device=0 tcp_echo=0\n");
            report(
                "V020_W11_NET_INIT_ERROR",
                error as u64,
                info.virtio_count as u64,
                0,
            );
            return NetOutcome::default();
        }
    };
    let outcome = serve_attached_network(info, &mut dev, identity);
    // The stream and its polling port have been dropped. The exclusive
    // device owner freezes both queues before attempting the MMIO reset.
    match dev.stop(identity.boot_epoch) {
        Ok(proofs) => {
            for proof in proofs {
                emit_reset_proof(proof);
            }
        }
        Err(error) => report("V020_SEC_D_NET_RESET_UNCONFIRMED", error as u64, 0, 0),
    }
    outcome
}

fn emit_reset_proof(proof: ResetProof) {
    const PREFIX: &[u8] = b"V020_SEC_D_NET_RESET_PROOF ";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = [0; PREFIX.len() + 2 * RESET_PROOF_BYTES + 1];
    text[..PREFIX.len()].copy_from_slice(PREFIX);
    for (slot, byte) in text[PREFIX.len()..].chunks_exact_mut(2).zip(proof.encode()) {
        slot[0] = HEX[usize::from(byte >> 4)];
        slot[1] = HEX[usize::from(byte & 0xf)];
    }
    text[PREFIX.len() + 2 * RESET_PROOF_BYTES] = b'\n';
    // The console consumer reassembles bytes in sequence. CPU0 owns this
    // writer, and each fragment fits the native payload limit.
    for fragment in text.chunks(96) {
        super::super::super::log(fragment);
    }
}

fn serve_attached_network(
    #[cfg_attr(
        not(feature = "v020-production-authenticated-net"),
        allow(unused_variables)
    )]
    info: &BootInfo,
    dev: &mut NetDevice,
    identity: sec_n_broker::BootIdentity,
) -> NetOutcome {
    #[cfg(feature = "v020-production-authenticated-net")]
    let mut rng = match net_entropy::Entropy::attach(info, identity.boot_epoch) {
        Ok(rng) => rng,
        Err(error) => {
            report("V020_W12_NET_ENTROPY_UNAVAILABLE", error as u64, 0, 0);
            return NetOutcome {
                device: true,
                ..NetOutcome::default()
            };
        }
    };
    let mut seed = [0u8; TCP_SEED_BYTES];
    #[cfg(feature = "v020-production-authenticated-net")]
    let seeded = rng.fill_tcp_seed(&mut seed).is_ok();
    #[cfg(not(feature = "v020-production-authenticated-net"))]
    let seeded = sec_n_broker::fixture_entropy(&mut seed);
    if !seeded {
        report("V020_W12_NET_ENTROPY_UNAVAILABLE", 0, 0, 0);
        return NetOutcome {
            device: true,
            ..NetOutcome::default()
        };
    }
    #[cfg(feature = "v020-production-authenticated-net")]
    let mut entropy = |out: &mut [u8]| rng.fill(out);
    #[cfg(not(feature = "v020-production-authenticated-net"))]
    let mut entropy = sec_n_broker::fixture_entropy;
    let outcome = serve_stream(dev, identity, u64::from_le_bytes(seed) | 1, &mut entropy);
    #[cfg(feature = "v020-production-authenticated-net")]
    let outcome = {
        let rng_bytes = rng.supplied - TCP_SEED_BYTES as u64;
        report(
            "V020_W12_NET_ENTROPY",
            TCP_SEED_BYTES as u64,
            rng_bytes,
            u64::from(rng.failed),
        );
        report(
            "V020_SEC_N_DRBG",
            rng.key_epoch(),
            rng.raw_samples(),
            rng_bytes,
        );
        NetOutcome {
            rng_bytes,
            ..outcome
        }
    };
    outcome
}

fn serve_stream(
    dev: &mut NetDevice,
    identity: sec_n_broker::BootIdentity,
    random_seed: u64,
    entropy: &mut sec_n_broker::EntropyFill<'_>,
) -> NetOutcome {
    // The outer owner resets the stopped device after this port returns.
    let mut storage = [Storage::EMPTY];
    let Some(mut stream) = open_stream(dev, &mut storage, random_seed) else {
        report("V020_W11_NET_STREAM_ERROR", 0, 0, 0);
        return NetOutcome {
            device: true,
            ..NetOutcome::default()
        };
    };
    report("V020_W11_NET_LISTEN", u64::from(LISTEN_PORT), 0, 0);
    let (source, accepted_ns) = match accept(&mut stream) {
        Ok(accepted) => accepted,
        Err(failure) => {
            stream.abort();
            report(
                "V020_W11_NET_NO_PEER",
                failure as u64,
                u64::from(NET_POLL_TURNS),
                0,
            );
            return NetOutcome {
                device: true,
                ..NetOutcome::default()
            };
        }
    };
    let (dispatched, stop_code) = match relay(&mut stream, identity, source, accepted_ns, entropy) {
        Ok(dispatched) => (dispatched, 0),
        Err(stop) => (stop.dispatched, stop.code),
    };
    #[cfg(feature = "v020-production-authenticated-net")]
    let retired = stop_code == 0 && sec_n_broker::retired();
    #[cfg(not(feature = "v020-production-authenticated-net"))]
    let retired = false;
    if !retired {
        stream.close(sec_n_broker::now_ms());
    }
    // a = 0 parked / 900 fault / 901 foreign SVC / 902 budget; b = closed-stream
    // events surfaced to the guest as EOF.
    report(
        "V020_W11_NET_GUEST_END",
        stop_code,
        sec_n_broker::stream_closed(),
        0,
    );
    let receipt = sec_n_broker::admission_receipt();
    if let Some((epoch, peer)) = receipt {
        report("V020_W11_NET_ADMISSION", epoch, u64::from(peer), 1);
        #[cfg(feature = "v020-production-authenticated-net")]
        if retired {
            report("V020_W13_NET_RETIRE", epoch, u64::from(peer), 1);
        }
    }
    let outcome = NetOutcome {
        device: true,
        tcp_established: true,
        leases: u64::from(receipt.is_some()),
        // The stream does not own the entropy source. serve() replaces this
        // initial value with the actual guest delivery count before publish.
        #[cfg(feature = "v020-production-authenticated-net")]
        rng_bytes: 0,
        #[cfg(feature = "v020-production-authenticated-net")]
        retired: u64::from(retired),
        relayed_bytes: sec_n_broker::relayed_bytes(),
    };
    report(
        "V020_W11_NET_RELAY",
        dispatched,
        outcome.leases,
        outcome.relayed_bytes,
    );
    outcome
}

/// Evidence seal: words 138..142 (CPU0, after the page was zeroed).
pub(super) fn publish(outcome: &NetOutcome) {
    evidence::put(evidence::W11_REAL_NET_DEVICE, u64::from(outcome.device));
    // tcp_to_local_echo: a real TCP connection was established AND its bytes
    // reached the guest through 0x43 READ.
    evidence::put(
        evidence::W11_TCP_TO_LOCAL_ECHO,
        u64::from(outcome.tcp_established && outcome.relayed_bytes > 0),
    );
    evidence::put(evidence::W11_ADMISSION_LEASES, outcome.leases);
    #[cfg(feature = "v020-production-authenticated-net")]
    evidence::put(evidence::W12_SEC_N_RNG_BYTES, outcome.rng_bytes);
    #[cfg(feature = "v020-production-authenticated-net")]
    evidence::put(evidence::W13_NET_RETIREMENTS, outcome.retired);
    evidence::put(evidence::W11_ECHO_BYTES, outcome.relayed_bytes);
    // The authenticated Echo verdict requires the independent host transcript.
    evidence::put(evidence::W11_TLS_ECHO_TURN_VERIFIED, 0);
}
