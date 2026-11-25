//! V0.19.9 SEC-N native Echo *deployment* fixture (fixture scope, NOT production).
//!
//! This is the gated boot-dispatch that wave-7/wave-8 left OPEN: it actually
//! loads the cross-compiled `user/local-echo` EL0 image into its own private
//! TTBR0 address space, reconciles the protected boot identity, and services the
//! guest's restricted SVC 0x43 broker (ENTROPY/TIME/POLL/READ/WRITE/CLOSE/YIELD)
//! from a bounded kernel-owned port. The guest itself runs the REAL authoritative
//! `cyxia_net_transport::admission::Admission` ledger and a REAL rustls TLS 1.3
//! passive-server session; the EL1 kernel stays `aarch64-unknown-none-softfloat`
//! and never compiles rustls/ring (the `tls` feature is EL0-only by design).
//!
//! HONEST SCOPE / GAP DOCUMENTATION (read before trusting any word below):
//! * The socket side is a bounded TRAIT-LEVEL mock [`Port`] (a loopback stub that
//!   accepts egress and never delivers ingress ciphertext), NOT a real VirtIO-net
//!   device. The broker simulates the TCP connection generation/state so the guest
//!   reaches its real Admission + TLS handshake, then stalls ingress. Real
//!   `driver-virtio::net` MMIO/IRQ/DMA custody, a real smoltcp `Tcp` endpoint and a
//!   real pinned TLS peer are the REMAINING device gap. Because there is no real
//!   peer, the positive authenticated Echo turn and the evidence-gated
//!   `finish_session` retirement are NOT exercised here and are NOT claimed.
//! * What IS proven natively on CPU0 EL0 traps:
//!     - the real guest ELF is loaded (own TTBR0/identity) and executes;
//!     - boot-identity reconciliation fails closed on a wrong local node pin;
//!     - a real `Admission::begin_ns` pending lease is created and then released
//!       via `reject` when the bounded 8192-turn handshake budget is exhausted
//!       (stalled peer), after which the guest `begin_restart` + parks;
//!     - a stale connection generation fails closed mid-handshake;
//!     - the device boundary refuses to certify TX quiescence (fail-closed
//!       `Port::tx_quiescent == false`), so no `finish`/credit retirement can be
//!       authorized — matching the guest's hardcoded-false `BrokerSocket`.
//! * The fixture entropy source is a deterministic fixture PRNG, NOT a production
//!   platform CSPRNG; it is sufficient only because no real cryptographic session
//!   completes here.
//! * production_deployment=false, real_device_wiring=false,
//!   tls_echo_turn_verified=false, finish_retirement_verified=false.
//!
//! UNSAFE BOUNDARY REGISTRATION (baseline 安 0.6 SEC-BUF). Global invariant: run()
//! asserts cpu::slot()==0 and the whole chain executes synchronously in that single
//! CPU0 turn loop; no IRQ handler, DMA or secondary CPU touches these statics. The
//! EL0 entry mechanism (user::enter_immutable) is arch-aarch64's registered
//! boundary; this module only calls it.
//! * The guest loader, shared-page helpers and the SVC 0x43 broker live in
//!   sec_n_broker.rs (registered there); this module owns only the mock port,
//!   its TX counter and the four negative phases.
//! * LoopbackPort / TX_BYTES (static mut): CPU0-only bounded egress counter,
//!   reset by `stage` before every phase.
//! * SMP_EVIDENCE shared reference: a static of AtomicU64; atomic interior
//!   mutability, completion seal stored last with Release.
use super::sec_n_broker::{
    self, FRAME_CAP, GUEST_ELF, IMAGE_BASE_VA, LOCAL_NODE, OP_CLOSE, OP_ENTROPY, OP_POLL, OP_WRITE,
    OP_YIELD, op_count, reset_guest_data, run_until_park,
};
use super::*;
use cyxia_net_transport::device::{self, Port};
use sha2::{Digest, Sha256};

const MAGIC: u64 = 0x4359_5853_4543_4e31; // "CYXSECN1"

// CPU0-only mock-port egress accounting.
static mut TX_BYTES: u64 = 0;

/// Bounded trait-level loopback port. It accepts egress into a bounded counter and
/// never delivers ingress ciphertext (stall), and it can NEVER certify TX
/// quiescence (fail-closed default). This is the documented mock device boundary;
/// real VirtIO-net DMA/used-ring custody is the remaining gap.
struct LoopbackPort;
impl Port for LoopbackPort {
    fn send(&mut self, frame: &[u8]) -> Result<(), device::Error> {
        if frame.len() > device::MTU {
            return Err(device::Error::Frame);
        }
        unsafe {
            TX_BYTES += frame.len() as u64;
        }
        Ok(())
    }
    fn receive(&mut self, _frame: &mut [u8; device::MTU]) -> Result<Option<usize>, device::Error> {
        Ok(None) // bounded stall: no ingress ciphertext is ever manufactured.
    }
    fn tx_quiescent(&self) -> bool {
        false // fail-closed: an unknown/mock port cannot certify DMA cessation.
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}
fn lo(d: &[u8; 32]) -> u64 {
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

/// Stage the shared page for a fresh phase and reset the mock egress counter.
fn stage(local: [u8; 32], connected: bool, conn_epoch: u64) {
    sec_n_broker::stage_shared(local, connected, conn_epoch);
    unsafe { TX_BYTES = 0 };
}

pub(super) fn run(info: &BootInfo) -> ! {
    assert_eq!(
        cpu::slot(),
        0,
        "only boot CPU0 owns the SEC-N deployment fixture"
    );
    assert_eq!(ONLINE.load(Ordering::Acquire), 15);
    let _ = info;
    report("V0199_SEC_N_STAGE", 1, GUEST_ELF.len() as u64, 0);
    let image_digest = sha(GUEST_ELF);

    // Load the real guest ELF into its own private TTBR0 (own identity space).
    let layout = sec_n_broker::load_guest();
    assert!(layout.entry >= IMAGE_BASE_VA && layout.used_frames <= FRAME_CAP);
    report(
        "V0199_SEC_N_LOAD",
        layout.entry,
        layout.used_frames as u64,
        lo(&image_digest),
    );

    // Wait for bounded business progress on CPU1-3, then enable the CPU0 PPI.
    wait(|| (1..REQUIRED).all(|slot| PROGRESS[slot * 2].load(Ordering::Acquire) >= 2));
    gic()
        .enable(TIMER_IRQ.load(Ordering::Acquire) as u32)
        .expect("CPU0 timer PPI");

    let mut port = LoopbackPort;

    // (1) NEGATIVE: wrong kernel-local node pin => the guest fails closed at the
    // boot-identity reconciliation (CLOSE + park), never admitting a connection.
    reset_guest_data(&layout);
    stage([0u8; 32], true, 1); // wrong local node, valid page identity.
    sec_n_broker::set_stall_after_poll(0);
    let d1 = run_until_park(&layout, &mut port, 4096);
    assert!(
        sec_n_broker::close_seen(),
        "identity mismatch must park (CLOSE)"
    );
    assert_eq!(
        op_count(OP_POLL),
        0,
        "identity mismatch must never poll a connection"
    );
    assert_eq!(
        op_count(OP_ENTROPY),
        0,
        "identity mismatch must never reach TLS"
    );
    report(
        "V0199_SEC_N_NEG_IDENTITY",
        d1,
        op_count(OP_CLOSE),
        op_count(OP_POLL),
    );
    let c1 = sec_n_broker::op_counts(); // snapshot before the next phase resets counters.

    // (2) NEGATIVE: real Admission begin_ns + real TLS session, but the stalled
    // mock port exhausts the bounded 8192-turn handshake budget => reject +
    // begin_restart + park. This exercises the REAL authoritative ledger lease.
    reset_guest_data(&layout);
    stage(LOCAL_NODE, true, 1);
    sec_n_broker::set_stall_after_poll(0);
    let d2 = run_until_park(&layout, &mut port, 200_000);
    assert!(
        sec_n_broker::close_seen(),
        "budget exhaustion must park (CLOSE)"
    );
    assert!(
        op_count(OP_POLL) >= 8192,
        "handshake must spend the bounded turn budget"
    );
    assert!(
        op_count(OP_ENTROPY) > 0,
        "a real TLS session must have requested entropy"
    );
    assert_eq!(
        op_count(OP_WRITE),
        0,
        "a passive server sends nothing before ClientHello"
    );
    report(
        "V0199_SEC_N_NEG_BUDGET",
        d2,
        op_count(OP_POLL),
        op_count(OP_ENTROPY),
    );
    let c2 = sec_n_broker::op_counts();
    let tx2 = unsafe { TX_BYTES };

    // (3) NEGATIVE: stale connection generation mid-handshake => the guest's
    // generation-bound socket fails closed well before the turn budget.
    reset_guest_data(&layout);
    stage(LOCAL_NODE, true, 1);
    sec_n_broker::set_stall_after_poll(200);
    let d3 = run_until_park(&layout, &mut port, 200_000);
    assert!(
        sec_n_broker::close_seen(),
        "stale generation must park (CLOSE)"
    );
    assert!(
        op_count(OP_POLL) < 8192,
        "stale generation must abort before the budget"
    );
    assert!(
        op_count(OP_POLL) >= 200,
        "stale generation must be observed mid-handshake"
    );
    report(
        "V0199_SEC_N_NEG_STALE",
        d3,
        op_count(OP_POLL),
        sec_n_broker::conn_epoch(),
    );
    let c3 = sec_n_broker::op_counts();
    let epoch3 = sec_n_broker::conn_epoch();

    // (4) NEGATIVE: finish without quiescence. The device boundary refuses to
    // certify TX quiescence (fail-closed default), so no finish/credit retirement
    // can be authorized. Assert the refusal was actually observed at CLOSE.
    assert!(
        !port.tx_quiescent(),
        "mock port must never certify TX quiescence"
    );
    assert!(
        sec_n_broker::quiescence_refused() >= 3,
        "every CLOSE must refuse quiescence"
    );
    report(
        "V0199_SEC_N_NEG_FINISH",
        sec_n_broker::quiescence_refused(),
        unsafe { TX_BYTES },
        0,
    );

    // Business CPUs kept running; deterministic cleanup.
    for slot in 1..REQUIRED {
        assert!(PROGRESS[slot * 2].load(Ordering::Acquire) >= 2);
        assert_eq!(PROGRESS[slot * 2 + 1].load(Ordering::Acquire), 0);
    }
    for gate in GATES.iter().take(REQUIRED).skip(1) {
        close_gate(gate);
    }
    wait(|| (1..REQUIRED).all(|slot| GATES[slot].quiescent()));
    QUIT.store(true, Ordering::Release);
    wait(|| STOPPED.load(Ordering::Acquire) == 14);
    check_failures();
    for slot in 1..REQUIRED {
        report(
            "V0199_SEC_N_BUSINESS",
            slot as u64,
            PROGRESS[slot * 2].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        );
    }

    // QMP-readable evidence page.
    let words = unsafe { &*core::ptr::addr_of!(SMP_EVIDENCE) };
    for w in words.words.iter() {
        w.store(0, Ordering::Relaxed);
    }
    let summary = [
        MAGIC,
        1,
        0, // completion seal set last
        15,
        1,
        14,
        GUEST_ELF.len() as u64,
        layout.entry,
        layout.used_frames as u64,
        lo(&image_digest),
        d1,
        d2,
        d3,
        sec_n_broker::quiescence_refused(),
        4, // four fail-closed negatives
        0, // tls_echo_turn_verified = false (mock port, no real peer)
    ];
    for (i, v) in summary.into_iter().enumerate() {
        words.words[i].store(v, Ordering::Relaxed);
    }
    // Per-negative rows: [dispatches, polls, entropy, close, yield_run, tx, epoch, 0].
    let rows: [[u64; 8]; 3] = [
        [
            d1,
            c1[OP_POLL as usize],
            c1[OP_ENTROPY as usize],
            c1[OP_CLOSE as usize],
            c1[OP_YIELD as usize],
            0,
            1,
            0,
        ],
        [
            d2,
            c2[OP_POLL as usize],
            c2[OP_ENTROPY as usize],
            c2[OP_CLOSE as usize],
            c2[OP_YIELD as usize],
            tx2,
            1,
            0,
        ],
        [
            d3,
            c3[OP_POLL as usize],
            c3[OP_ENTROPY as usize],
            c3[OP_CLOSE as usize],
            c3[OP_YIELD as usize],
            0,
            epoch3,
            0,
        ],
    ];
    for (r, row) in rows.into_iter().enumerate() {
        for (c, v) in row.into_iter().enumerate() {
            words.words[16 + r * 8 + c].store(v, Ordering::Relaxed);
        }
    }
    for slot in 1..REQUIRED {
        let at = 48 + (slot - 1) * 4;
        for (off, v) in [
            AFFINITIES[slot].load(Ordering::Acquire),
            PROGRESS[slot * 2].load(Ordering::Acquire),
            PROGRESS[slot * 2 + 1].load(Ordering::Acquire),
            IRQS[slot].load(Ordering::Acquire),
        ]
        .into_iter()
        .enumerate()
        {
            words.words[at + off].store(v, Ordering::Relaxed);
        }
    }
    words.words[2].store(1, Ordering::Release);
    // Framed UART payloads are bounded to 96 bytes (transport::encode); keep both
    // markers within that bound or they are silently dropped.
    super::super::log(b"V0199_SEC_N_SCOPE production=false device=false echo_turn=false finish=false mock_port=true\n");
    super::super::log(b"V0199_SEC_N_FIXTURE_PASS cpus=4 deploy=el0-echo negatives=identity,budget,stale,quiescence\n");
    super::super::halt()
}
