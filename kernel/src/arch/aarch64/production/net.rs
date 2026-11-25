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
//!   `NET_POLL_TURNS` turns paced at `TURN_PACE_MS`, and every guest entry is
//!   bounded by the private timer backstop inside `run_until_park`.
//! * Entropy for the guest's rustls session and the smoltcp seed is the
//!   deterministic FIXTURE PRNG (`sec_n_broker::fixture_entropy`), NOT a
//!   production CSPRNG; this is acceptable only because no TLS session completes.
//! * Word 140 (leases) is INFERRED from the broker trace (connected POLL then
//!   ENTROPY), not reported by the guest.
//! * Word 142 `tls_echo_turn_verified` is written 0 by design: the host peer is
//!   not a pinned TLS client, so no authenticated Echo turn happens.
//! * No device => `V020_W11_NET_ABSENT`, words 138..142 stay 0, boot continues.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline SEC-BUF: minimal trusted boundaries).
//! * TCP_RX / TCP_TX (static mut, `.bss.sec_n` link section, NOT
//!   FrameMeta-registered this wave): the only `&mut` to them is created once in
//!   `open_stream`, guarded by the SERVED swap, on CPU0 after the business CPUs
//!   stopped; the `Tcp` borrowing them is dropped before `serve` returns.
//! * SERVED (atomic): CPU0 only; makes `open_stream` (the buffer borrow) one-shot.
//! * The pinned VirtIO-net DMA pools are owned and registered by net_device.rs;
//!   the guest frame pool and broker page by sec_n_broker.rs.

use super::super::{report, sec_n_broker};
use super::evidence;
use crate::net_device::{self, NetDevice};
use crate::virtio_platform::Board;
use core::sync::atomic::{AtomicBool, Ordering};
use cyxia_arch_aarch64::timer;
use cyxia_contracts::BootInfo;
use cyxia_driver_virtio::net::BatchedNet;
use cyxia_net_transport::device::{self, Port, VirtioPort};
use cyxia_net_transport::tcp::{self, BUFFER_SIZE, Config, State, Storage, Tcp};

/// Upper bound of accept turns on CPU0.
const NET_POLL_TURNS: u32 = 20_000;
/// Minimum spacing between accept turns (bounds the accept window to ~20 s).
const TURN_PACE_MS: u64 = 1;
/// Bounded SVC budget for the guest relay run (the fixture's proven bound).
const GUEST_SVC_BUDGET: u64 = 200_000;
/// Largest ingress chunk handed to the guest per 0x43 READ (≤ its request).
const RELAY_CHUNK: usize = 1024;
const LOCAL_IP: [u8; 4] = [10, 0, 2, 15];
const PREFIX_LEN: u8 = 24;
const LISTEN_PORT: u16 = 7;
/// QEMU user-net gateway; must equal the guest's trusted source observation.
const PEER_IP: [u8; 4] = [10, 0, 2, 2];
const _: () = assert!(u32::from_be_bytes(PEER_IP) == sec_n_broker::SOURCE_IP);

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
}

/// Byte-stream adapter: the broker's READ/WRITE become TCP payload receive/send
/// on the established stream; every operation first runs one bounded TCP turn.
struct StreamPort<'s, 'a> {
    tcp: &'s mut Stream<'a>,
}
impl StreamPort<'_, '_> {
    fn turn(&mut self) {
        // A failed turn poisons the stream; later operations then fail closed.
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
        self.turn();
        match self.tcp.receive_tls(&mut frame[..RELAY_CHUNK]) {
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

/// Bounded polling accept: returns true once the pinned peer is Established.
fn accept(stream: &mut Stream<'_>) -> bool {
    for _ in 0..NET_POLL_TURNS {
        let now = sec_n_broker::now_ms();
        if stream.poll_ingress_phase(now, &mut || {}).is_err() || !pin_peer(stream) {
            return false;
        }
        match stream.poll_egress_phase(now, &mut || {}) {
            Ok(State::Established) => return true,
            Ok(_) => pace(),
            Err(_) => return false,
        }
    }
    false
}

/// Build the listening stream over the device. One-shot: the SERVED swap is
/// the only gate to the static stream buffers.
fn open_stream<'a>(
    dev: &'a mut NetDevice,
    storage: &'a mut [Storage<'a>; 1],
) -> Option<Stream<'a>> {
    if SERVED.swap(true, Ordering::AcqRel) {
        return None;
    }
    let mut seed = [0u8; 8];
    sec_n_broker::fixture_entropy(&mut seed);
    let config = Config {
        mac: dev.net.mac(),
        local: LOCAL_IP,
        peer: [0; 4],
        prefix_len: PREFIX_LEN,
        local_port: LISTEN_PORT,
        peer_port: 0,
        random_seed: u64::from_le_bytes(seed) | 1,
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
fn relay(stream: &mut Stream<'_>) -> u64 {
    let layout = sec_n_broker::load_guest();
    report(
        "V020_W11_NET_GUEST",
        layout.entry,
        layout.used_frames as u64,
        sec_n_broker::GUEST_ELF.len() as u64,
    );
    sec_n_broker::reset_guest_data(&layout);
    sec_n_broker::stage_shared(sec_n_broker::LOCAL_NODE, true, 1);
    let mut port = StreamPort { tcp: stream };
    sec_n_broker::run_until_park(&layout, &mut port, GUEST_SVC_BUDGET)
}

/// One-shot SEC-N service run on CPU0 (after the advice chain).
pub(super) fn serve(info: &BootInfo) -> NetOutcome {
    // net_device::init is itself one-shot (CLAIMED) and CPU0-only.
    let mut dev = match net_device::init(info) {
        Ok(dev) => dev,
        Err(error) => {
            super::super::super::log(b"V020_W11_NET_ABSENT device=0 tcp_echo=0\n");
            report("V020_W11_NET_INIT_ERROR", error as u64, info.virtio_count as u64, 0);
            return NetOutcome::default();
        }
    };
    // Dropping `dev` at return never releases the pinned DMA pools or resets
    // the device (net_device.rs contract).
    let mut storage = [Storage::EMPTY];
    let Some(mut stream) = open_stream(&mut dev, &mut storage) else {
        return NetOutcome {
            device: true,
            ..NetOutcome::default()
        };
    };
    report("V020_W11_NET_LISTEN", u64::from(LISTEN_PORT), 0, 0);
    if !accept(&mut stream) {
        stream.abort();
        report("V020_W11_NET_NO_PEER", u64::from(NET_POLL_TURNS), 0, 0);
        return NetOutcome {
            device: true,
            ..NetOutcome::default()
        };
    }
    let dispatched = relay(&mut stream);
    stream.close(sec_n_broker::now_ms());
    let outcome = NetOutcome {
        device: true,
        tcp_established: true,
        leases: sec_n_broker::inferred_leases(),
        relayed_bytes: sec_n_broker::relayed_bytes(),
    };
    report("V020_W11_NET_RELAY", dispatched, outcome.leases, outcome.relayed_bytes);
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
    evidence::put(evidence::W11_ECHO_BYTES, outcome.relayed_bytes);
    // By design: no pinned TLS peer, so no authenticated Echo turn is verified.
    evidence::put(evidence::W11_TLS_ECHO_TURN_VERIFIED, 0);
}
