//! T4 real VirtIO-net adapter host tests with a MOCK MMIO device.
//!
//! These verify the custody/evidence logic of the production adapter against the
//! REAL `driver-virtio::net::BatchedNet` driver code driven by a fake MMIO device
//! (the same emulation pattern as the driver's own unit tests). The real
//! MMIO/IRQ/DMA hardware path is exercised only in a native fixture; nothing here
//! fabricates a completion witness. This is a separate integration-test crate, so
//! the fake `Platform`/volatile device emulation may use `unsafe` even though the
//! library itself is `#![forbid(unsafe_code)]`.
use core::{
    cell::{Cell, RefCell, UnsafeCell},
    ptr::{read_volatile, write_volatile},
};
use cyxia_driver_virtio::{
    Error as DriverError, Platform, Transport,
    net::{BatchedNet, TxReceipt},
    queue::{BatchMemory, Token},
};
use cyxia_net_transport::{
    device::VirtioPort,
    tcp::{BUFFER_SIZE, Config, Storage, Tcp},
    virtio_custody::{CustodyNet, VirtioNativeSocket},
};
use std::boxed::Box;

// ---- fake MMIO device -------------------------------------------------------

#[repr(C, align(4096))]
struct Page(UnsafeCell<[u8; 4096]>);
impl Page {
    fn new() -> Self {
        Self(UnsafeCell::new([0; 4096]))
    }
    fn addr(&self) -> usize {
        self.0.get() as usize
    }
    unsafe fn put32(&self, off: usize, v: u32) {
        unsafe { write_volatile((self.addr() + off) as *mut u32, v.to_le()) }
    }
    unsafe fn get32(&self, off: usize) -> u32 {
        unsafe { u32::from_le(read_volatile((self.addr() + off) as *const u32)) }
    }
    unsafe fn put8(&self, off: usize, v: u8) {
        unsafe { write_volatile((self.addr() + off) as *mut u8, v) }
    }
}

struct Host {
    mmio: &'static Page,
    features: u64,
    selected: Cell<u32>,
    ready: RefCell<[u32; 2]>,
    clock: Cell<u64>,
}
// SAFETY: tests serialize a fake device with driver accesses to pinned pages.
// DMA is emulated only through volatile accesses at valid descriptor addresses.
unsafe impl Platform for Host {
    fn physical(&self, address: usize, _: usize) -> Result<u64, DriverError> {
        Ok(address as u64)
    }
    unsafe fn sync(&self, _: usize, _: usize) {}
    fn barrier(&self) {
        let m = self.mmio;
        unsafe {
            let selector = m.get32(0x14);
            m.put32(
                0x10,
                if selector == 0 {
                    self.features as u32
                } else {
                    (self.features >> 32) as u32
                },
            );
            let selected = m.get32(0x30);
            if selected < 2 {
                if selected != self.selected.get() {
                    self.ready.borrow_mut()[self.selected.get() as usize] = m.get32(0x44);
                    self.selected.set(selected);
                    m.put32(0x44, self.ready.borrow()[selected as usize]);
                }
                m.put32(0x34, 16);
            }
        }
    }
    fn now_ms(&self) -> u64 {
        self.clock.get() / 1_000_000
    }
    fn now_ns(&self) -> u64 {
        self.clock.get()
    }
}

/// Bring up a real BatchedNet against the fake device, wrapped in custody.
/// Returns the custody owner, the fake platform and the TX DMA base address.
fn fixture() -> (CustodyNet, Host, usize) {
    let mmio = Box::leak(Box::new(Page::new()));
    unsafe {
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 1);
        mmio.put32(0x34, 16);
        mmio.put32(0x50, u32::MAX);
        for (i, b) in [2u8, 0, 0, 0, 0, 1].iter().enumerate() {
            mmio.put8(0x100 + i, *b);
        }
    }
    let host = Host {
        mmio,
        features: (1 << 32) | (1 << 5) | (1 << 0),
        selected: Cell::new(0),
        ready: RefCell::new([0; 2]),
        clock: Cell::new(0),
    };
    let transport = unsafe { Transport::attach(mmio.addr(), 4096).unwrap() };
    let rx = Box::leak(Box::new(BatchMemory::zeroed()));
    let tx = Box::leak(Box::new(BatchMemory::zeroed()));
    let tx_base = tx as *mut _ as usize;
    let net = BatchedNet::initialize(transport, rx, tx, &host).unwrap();
    (CustodyNet::new(net), host, tx_base)
}

/// Emulate the device completing ONE outstanding TX chain: read the published
/// head descriptor from the avail ring and write a validated used-ring entry
/// (TX writable length is zero). This is real used-ring evidence, not a mock flag.
unsafe fn complete_tx(base: usize) {
    unsafe {
        let avail = base + 4096;
        let used = base + 8192;
        let a = u16::from_le(read_volatile((avail + 2) as *const u16));
        let u = u16::from_le(read_volatile((used + 2) as *const u16));
        if a == u {
            return;
        }
        let head = u16::from_le(read_volatile(
            (avail + 4 + usize::from(u % 16) * 2) as *const u16,
        ));
        let at = used + 4 + usize::from(u % 16) * 8;
        write_volatile(at as *mut u32, u32::from(head).to_le());
        write_volatile((at + 4) as *mut u32, 0u32.to_le());
        write_volatile((used + 2) as *mut u16, u.wrapping_add(1).to_le());
    }
}

fn tcp_config() -> Config {
    Config {
        mac: [2, 0, 0, 0, 0, 1],
        local: [10, 0, 0, 1],
        peer: [10, 0, 0, 2],
        prefix_len: 24,
        local_port: 40001,
        peer_port: 8443,
        random_seed: 7,
    }
}

// ---- custody / evidence logic ----------------------------------------------

#[test]
fn custody_initially_quiescent_with_no_transmit() {
    let (c, _h, _tx) = fixture();
    assert!(c.tx_quiescent());
    assert_eq!(c.held_receipt(), None);
    assert_eq!(c.reconciled_count(), 0);
}

#[test]
fn custody_quiescent_requires_real_completion_and_exact_reconcile() {
    let (mut c, h, tx) = fixture();
    c.send_queued(&[0x33; 64], &h).unwrap();
    c.flush_tx(&h).unwrap();
    assert!(!c.tx_quiescent(), "in-flight TX forbids quiescence");
    // Silent device: no completion, never quiescent.
    assert_eq!(c.poll_receipt(&h).unwrap(), None);
    assert!(!c.tx_quiescent());
    // Real used-ring completion appears; the receipt is retained.
    unsafe { complete_tx(tx) };
    let receipt = c.poll_receipt(&h).unwrap().unwrap();
    assert_eq!(c.held_receipt(), Some(receipt));
    assert!(!c.tx_quiescent(), "a held receipt forbids quiescence");
    // Exact-token reconciliation releases the descriptor.
    assert!(c.reconcile(&h).unwrap());
    assert!(c.tx_quiescent());
    assert_eq!(c.reconciled_count(), 1);
    assert_eq!(c.last_reconciled_version(), receipt.version);
    assert_eq!(c.held_receipt(), None);
}

#[test]
fn custody_wrong_generation_ack_is_refused_and_retains_custody() {
    let (mut c, h, tx) = fixture();
    c.send_queued(&[0x31; 64], &h).unwrap();
    unsafe { complete_tx(tx) };
    let receipt = c.poll_receipt(&h).unwrap().unwrap();
    let stale = TxReceipt {
        token: Token {
            generation: receipt.token.generation + 1,
            ..receipt.token
        },
        ..receipt
    };
    assert_eq!(
        c.inner_mut().acknowledge_tx(stale, &h),
        Err(DriverError::Response)
    );
    assert!(!c.tx_quiescent());
    assert_eq!(c.held_receipt(), Some(receipt));
    // The exact receipt still reconciles.
    assert!(c.reconcile(&h).unwrap());
    assert!(c.tx_quiescent());
}

#[test]
fn custody_silent_device_never_certifies_quiescence() {
    let (mut c, h, _tx) = fixture();
    c.send_queued(&[0x2d; 64], &h).unwrap();
    for _ in 0..16 {
        assert_eq!(c.poll_receipt(&h).unwrap(), None);
        assert!(!c.reconcile(&h).unwrap());
        assert!(!c.tx_quiescent());
    }
}

#[test]
fn custody_reconcile_without_receipt_is_a_noop() {
    let (mut c, h, _tx) = fixture();
    assert!(!c.reconcile(&h).unwrap());
    assert!(c.tx_quiescent());
    assert_eq!(c.reconciled_count(), 0);
}

#[test]
fn custody_second_poll_before_reconcile_is_busy() {
    let (mut c, h, tx) = fixture();
    c.send_queued(&[0x41; 64], &h).unwrap();
    unsafe { complete_tx(tx) };
    assert!(c.poll_receipt(&h).unwrap().is_some());
    assert_eq!(c.poll_receipt(&h), Err(DriverError::Busy));
    assert!(c.reconcile(&h).unwrap());
    assert!(c.tx_quiescent());
}

// ---- terminal quiescence flows through the real TCP/port chain --------------

#[test]
fn terminal_quiescence_flows_real_device_evidence_through_tcp() {
    let (mut custody, host, tx) = fixture();
    let rx = Box::leak(Box::new([0u8; BUFFER_SIZE]));
    let txbuf = Box::leak(Box::new([0u8; BUFFER_SIZE]));
    let storage = Box::leak(Box::new([Storage::EMPTY; 1]));
    let port = VirtioPort {
        net: &mut custody,
        platform: &host,
    };
    let mut tcp = Tcp::new(port, tcp_config(), 0, rx, txbuf, storage).unwrap();
    tcp.listen().unwrap();
    // TCP not Closed: not terminal even though the device is idle.
    assert!(!tcp.terminal_tx_quiescent());
    // Publish a real outstanding TX chain through the custody port.
    {
        let p = tcp.port_mut();
        p.net.send_queued(&[0x55; 64], p.platform).unwrap();
    }
    tcp.close(1);
    // TCP Closed + empty send queue, but the device still has an in-flight TX.
    assert!(!tcp.terminal_tx_quiescent());
    // Real completion + exact reconciliation through the port.
    unsafe { complete_tx(tx) };
    {
        let p = tcp.port_mut();
        assert!(p.net.poll_receipt(p.platform).unwrap().is_some());
        assert!(p.net.reconcile(p.platform).unwrap());
    }
    assert!(tcp.terminal_tx_quiescent());
}

// ---- Service finish gate accepts REAL device evidence -----------------------

#[cfg(feature = "tls")]
mod service_evidence {
    use super::*;
    use cyxia_net_transport::{
        admission::Error as AdmissionError,
        native_tcp::{self, NativeSocket},
        service::{Error as ServiceError, Service},
        tls::{Buffers, Pairing, Session, node_id},
    };
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
    use std::sync::Arc;

    #[derive(Debug)]
    struct Time;
    impl rustls::time_provider::TimeProvider for Time {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
                1_800_000_000,
            )))
        }
    }
    fn local_pairings() -> [Pairing; 2] {
        let mut fixtures = [
            (
                &include_bytes!("fixtures/a-test-cert.der")[..],
                &include_bytes!("fixtures/a-test-key.der")[..],
            ),
            (
                &include_bytes!("fixtures/b-test-cert.der")[..],
                &include_bytes!("fixtures/b-test-key.der")[..],
            ),
        ];
        fixtures.sort_by_key(|(cert, _)| node_id(&CertificateDer::from(*cert)).unwrap());
        core::array::from_fn(|i| {
            Pairing::new_local_echo(
                CertificateDer::from(fixtures[i].0),
                PrivatePkcs8KeyDer::from(fixtures[i].1).into(),
                node_id(&CertificateDer::from(fixtures[1 - i].0)).unwrap(),
                Arc::new(Time),
            )
            .unwrap()
        })
    }
    fn transfer(a: &mut Session<'_>, b: &mut Session<'_>) {
        let n = b.receive_tls(a.pending_tls()).unwrap();
        a.consume_tls(n).unwrap();
    }
    fn handshake(a: &mut Session<'_>, b: &mut Session<'_>) {
        for _ in 0..100 {
            a.pump(0).unwrap();
            b.pump(0).unwrap();
            transfer(a, b);
            transfer(b, a);
            if a.authenticated_peer().is_some()
                && b.authenticated_peer().is_some()
                && a.pending_tls().is_empty()
                && b.pending_tls().is_empty()
            {
                return;
            }
        }
        panic!("handshake did not complete");
    }

    /// The Service retirement gate accepts a REAL BatchedNet-backed quiescence
    /// witness (not the fixture's mock EvidenceSocket) and refuses it while a real
    /// TX chain is still in flight. No fabricated completion.
    #[test]
    fn service_finish_retires_only_on_real_device_quiescence() {
        let [client_pairing, server_pairing] = local_pairings();
        let mut service = Service::new(server_pairing);
        let ticket = service.admit(7, 0, 16).unwrap();
        let mut server_buf = Buffers::new();
        let mut client_buf = Buffers::new();
        let mut server = service.session(&mut server_buf, 0).unwrap();
        let mut client = client_pairing.client(&mut client_buf, 0).unwrap();
        handshake(&mut client, &mut server);
        let active = service.authenticate(ticket, &server).unwrap();
        assert_eq!(service.active_count(), 1);

        // Real device adapter: TCP closed, but an outstanding TX keeps it live.
        let (mut custody, host, tx) = fixture();
        let rx = Box::leak(Box::new([0u8; BUFFER_SIZE]));
        let txbuf = Box::leak(Box::new([0u8; BUFFER_SIZE]));
        let storage = Box::leak(Box::new([Storage::EMPTY; 1]));
        let port = VirtioPort {
            net: &mut custody,
            platform: &host,
        };
        let mut tcp = Tcp::new(port, tcp_config(), 0, rx, txbuf, storage).unwrap();
        tcp.listen().unwrap();
        {
            let p = tcp.port_mut();
            p.net.send_queued(&[0x55; 64], p.platform).unwrap();
        }
        tcp.close(1);
        let mut adapter = VirtioNativeSocket::new(tcp);
        assert!(!adapter.terminal_tx_quiescent());
        // Retirement refused: real device not quiescent. Credit retained.
        assert!(matches!(
            service.finish(&adapter, active, &server),
            Err(ServiceError::Native(native_tcp::Error::Admission(
                AdmissionError::Busy
            )))
        ));
        assert_eq!(service.active_count(), 1);
        // Real used-ring completion + exact reconciliation.
        unsafe { complete_tx(tx) };
        {
            let p = adapter.tcp_mut().port_mut();
            assert!(p.net.poll_receipt(p.platform).unwrap().is_some());
        }
        assert!(adapter.reconcile_tx().unwrap());
        assert!(adapter.terminal_tx_quiescent());
        // Now the evidence gate accepts the real witness and retires the credit.
        service.finish(&adapter, active, &server).unwrap();
        assert_eq!(service.active_count(), 0);
    }
}
