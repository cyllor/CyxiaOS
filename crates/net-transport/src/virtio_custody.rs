//! Real VirtIO-net-backed SEC-N production adapter (T4 device-wiring skeleton).
//!
//! This replaces the trait-level mock `Port` used by the deployment fixture with
//! the actual `driver-virtio::net::BatchedNet` driver for the production path. It
//! is a *skeleton*: it provides the real device evidence chain and a clean init
//! surface, but the protected EL1 boot-dispatch that deploys it (identity, clock,
//! rate policy, reset authority, EL0 substrate) remains T1's open gate. Nothing
//! here fabricates a completion witness.
//!
//! # Evidence chain
//!
//! ```text
//! driver-virtio BatchedNet            (real MMIO/IRQ/DMA, used-ring validation)
//!   -> CustodyNet                     (TX receipt custody: poll_receipt/reconcile)
//!   -> device::VirtioPort<'_, P, _>   (Port)
//!   -> tcp::Tcp<'_, _>                (terminal_tx_quiescent: TCP Closed + empty
//!                                      send queue + port.tx_quiescent)
//!   -> VirtioNativeSocket             (NativeSocket, tls-gated EL0/host boundary)
//!   -> service::Service::finish       (evidence-gated credit retirement)
//! ```
//!
//! [`CustodyNet`] drives TX completions ONLY through the driver's custody API
//! (`BatchedNet::poll_tx_receipt` / `acknowledge_tx`, exact token+generation). A
//! polled completion is *retained* until the trusted owner reconciles it; while a
//! receipt is held, or any descriptor is still in flight, `tx_quiescent` is false.
//! A silent or poisoned device can never certify quiescence by timeout or reset.
//!
//! The generic `impl<P: Port> NativeSocket for Tcp<'_, P>` (local_echo_tcp) keeps
//! the fail-closed `terminal_tx_quiescent == false` default so an unknown/mock
//! port cannot manufacture a witness. Only this concrete real-device adapter
//! overrides it, delegating to the real `Tcp::terminal_tx_quiescent`.
#![forbid(unsafe_code)]
use crate::device::{VirtioLink, VirtioPort};
use cyxia_driver_virtio::{
    Error as DriverError, Platform, Transport,
    net::{BatchedNet, TxReceipt},
    queue::BatchMemory,
};

/// TX receipt custody wrapper around the real [`BatchedNet`] driver.
///
/// Custody invariant: `held` mirrors the driver's single retained
/// `completed_tx`. A receipt is acquired only from a validated device used-ring
/// entry (`poll_receipt`) and released only by acknowledging that exact
/// token+generation (`reconcile`). No other path releases a descriptor or
/// advances the reconciled-version accounting.
pub struct CustodyNet {
    net: BatchedNet,
    held: Option<TxReceipt>,
    reconciled: u64,
    last_reconciled_version: u64,
}

impl CustodyNet {
    /// Wrap an already-initialized real device.
    pub fn new(net: BatchedNet) -> Self {
        Self {
            net,
            held: None,
            reconciled: 0,
            last_reconciled_version: 0,
        }
    }

    /// Initialize the real driver against pinned DMA pages and wrap it.
    pub fn initialize(
        t: Transport,
        rx: &'static mut BatchMemory,
        tx: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, DriverError> {
        Ok(Self::new(BatchedNet::initialize(t, rx, tx, p)?))
    }

    /// Poll one verified device TX completion and retain its exact receipt.
    /// A second poll before reconciliation returns `Busy` (the driver still
    /// holds the completion); a silent device returns `None` and never waits.
    pub fn poll_receipt(&mut self, p: &impl Platform) -> Result<Option<TxReceipt>, DriverError> {
        let receipt = self.net.poll_tx_receipt(p)?;
        if receipt.is_some() {
            self.held = receipt;
        }
        Ok(receipt)
    }

    /// Reconcile the held receipt with its exact token+generation, releasing the
    /// DMA descriptor. Returns whether a receipt was reconciled. A mismatched or
    /// stale receipt is refused by the driver and custody is retained.
    pub fn reconcile(&mut self, p: &impl Platform) -> Result<bool, DriverError> {
        let Some(receipt) = self.held else {
            return Ok(false);
        };
        // On error the driver still holds the completion; keep `held` consistent.
        self.net.acknowledge_tx(receipt, p)?;
        self.held = None;
        self.reconciled = self.reconciled.saturating_add(1);
        self.last_reconciled_version = self.last_reconciled_version.max(receipt.version);
        Ok(true)
    }

    /// Conservative device TX settle witness: no held receipt AND the real
    /// driver reports every used-ring completion validated and acknowledged with
    /// nothing in flight. A poisoned device or pending/UNKNOWN TX forbids it.
    pub fn tx_quiescent(&self) -> bool {
        self.held.is_none() && self.net.tx_quiescent()
    }

    /// The exact receipt currently retained, if any.
    pub fn held_receipt(&self) -> Option<TxReceipt> {
        self.held
    }
    /// Count of exact-token reconciliations performed by this owner.
    pub fn reconciled_count(&self) -> u64 {
        self.reconciled
    }
    /// Highest policy version reconciled from a real device completion.
    pub fn last_reconciled_version(&self) -> u64 {
        self.last_reconciled_version
    }

    pub fn mac(&self) -> [u8; 6] {
        self.net.mac()
    }
    pub fn capacity(&self) -> usize {
        self.net.capacity()
    }
    pub fn send_queued(&mut self, frame: &[u8], p: &impl Platform) -> Result<(), DriverError> {
        self.net.send_queued(frame, p)
    }
    pub fn flush_tx(&mut self, p: &impl Platform) -> Result<(), DriverError> {
        self.net.flush_tx(p)
    }
    pub fn receive(
        &mut self,
        out: &mut [u8],
        p: &impl Platform,
    ) -> Result<Option<usize>, DriverError> {
        self.net.receive(out, p)
    }
    pub fn receive_with_checkpoint(
        &mut self,
        out: &mut [u8],
        p: &impl Platform,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, DriverError> {
        self.net.receive_with_checkpoint(out, p, checkpoint)
    }
    /// Read-only access to the real driver (diagnostics only; protocol work must
    /// go through the custody API so receipt accounting stays intact).
    pub fn inner(&self) -> &BatchedNet {
        &self.net
    }
    pub fn inner_mut(&mut self) -> &mut BatchedNet {
        &mut self.net
    }
}

/// Custody-mode link: each bounded TX turn reconciles the previously held exact
/// receipt, then retains the next verified completion. The terminal receipt is
/// released by an explicit [`CustodyNet::reconcile`] sweep (the native socket
/// adapter performs it each turn), so quiescence is never certified while a
/// completion is still held.
impl VirtioLink for CustodyNet {
    fn tx_quiescent(&self) -> bool {
        CustodyNet::tx_quiescent(self)
    }
    fn transmit(&mut self, f: &[u8], p: &impl Platform) -> Result<(), DriverError> {
        self.send_queued(f, p)
    }
    fn poll_transmit(&mut self, p: &impl Platform) -> Result<bool, DriverError> {
        self.reconcile(p)?;
        Ok(self.poll_receipt(p)?.is_some())
    }
    fn receive_frame(
        &mut self,
        o: &mut [u8],
        p: &impl Platform,
    ) -> Result<Option<usize>, DriverError> {
        self.receive(o, p)
    }
    fn receive_frame_with_checkpoint(
        &mut self,
        o: &mut [u8],
        p: &impl Platform,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, DriverError> {
        self.receive_with_checkpoint(o, p, checkpoint)
    }
    fn finish_turn(&mut self, p: &impl Platform) -> Result<(), DriverError> {
        self.flush_tx(p)
    }
    fn burst_capacity(&self) -> usize {
        self.capacity()
    }
}

/// A real VirtIO-net-backed [`crate::device::Port`] with TX receipt custody.
pub type CustodyPort<'a, P> = VirtioPort<'a, P, CustodyNet>;

/// Real-device [`crate::native_tcp::NativeSocket`] adapter (EL0/host boundary).
///
/// Wraps a `Tcp` over a custody-mode VirtIO port and surfaces the REAL
/// `terminal_tx_quiescent` witness (TCP Closed + empty send queue + verified
/// device TX quiescence). The trait's fail-closed default is never overridden by
/// a mock, a timeout or a plain socket reset.
#[cfg(feature = "tls")]
mod native {
    use super::{CustodyNet, VirtioPort};
    use crate::{
        native_tcp::{NativeSocket, SocketError},
        tcp::{self, Tcp},
    };
    use cyxia_driver_virtio::Platform;

    pub struct VirtioNativeSocket<'a, 'd, P: Platform> {
        tcp: Tcp<'a, VirtioPort<'d, P, CustodyNet>>,
    }

    impl<'a, 'd, P: Platform> VirtioNativeSocket<'a, 'd, P> {
        pub fn new(tcp: Tcp<'a, VirtioPort<'d, P, CustodyNet>>) -> Self {
            Self { tcp }
        }
        pub fn tcp(&self) -> &Tcp<'a, VirtioPort<'d, P, CustodyNet>> {
            &self.tcp
        }
        pub fn tcp_mut(&mut self) -> &mut Tcp<'a, VirtioPort<'d, P, CustodyNet>> {
            &mut self.tcp
        }
        /// Reconcile any outstanding TX receipt with its exact device evidence.
        /// The trusted native owner calls this each bounded turn so a verified
        /// completion can retire; it never fabricates a completion.
        pub fn reconcile_tx(&mut self) -> Result<bool, SocketError> {
            let port = self.tcp.port_mut();
            port.net
                .reconcile(port.platform)
                .map_err(|_| SocketError::Device)
        }
    }

    fn map_error(error: tcp::Error) -> SocketError {
        match error {
            tcp::Error::WouldBlock => SocketError::Again,
            tcp::Error::Closed => SocketError::Closed,
            _ => SocketError::Device,
        }
    }

    impl<P: Platform> NativeSocket for VirtioNativeSocket<'_, '_, P> {
        fn terminal_tx_quiescent(&self) -> bool {
            self.tcp.terminal_tx_quiescent()
        }
        fn poll_native(&mut self, now_ms: u64) -> Result<(), SocketError> {
            let state = self.tcp.poll(now_ms).map_err(map_error)?;
            self.reconcile_tx()?;
            if state == tcp::State::Closed {
                Err(SocketError::Closed)
            } else {
                Ok(())
            }
        }
        fn read_ciphertext(&mut self, out: &mut [u8]) -> Result<usize, SocketError> {
            self.tcp.receive_tls(out).map_err(map_error)
        }
        fn queue_ciphertext(&mut self, bytes: &[u8]) -> Result<usize, SocketError> {
            self.tcp.send_tls(bytes).map_err(map_error)
        }
    }
}
#[cfg(feature = "tls")]
pub use native::VirtioNativeSocket;
