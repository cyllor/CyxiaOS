//! Bounded bridge between a polling NIC and smoltcp. One pending frame each
//! way; backpressure never overwrites DMA or a staged TCP packet.
use cyxia_driver_virtio::{
    Error as DriverError, Platform,
    net::{BatchedNet, Net},
};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

pub const MTU: usize = 1514;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WouldBlock,
    Device,
    Frame,
}

/// Serialized owner of an Ethernet device. Success from send means queued,
/// never that the peer received it. No host socket or protocol proxy is used.
pub trait Port {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error>;
    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, Error>;
    fn receive_with_checkpoint(
        &mut self,
        frame: &mut [u8; MTU],
        _checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, Error> {
        self.receive(frame)
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn burst_capacity(&self) -> usize {
        1
    }
}

pub trait VirtioLink {
    fn transmit(&mut self, frame: &[u8], p: &impl Platform) -> Result<(), DriverError>;
    fn poll_transmit(&mut self, p: &impl Platform) -> Result<bool, DriverError>;
    fn receive_frame(
        &mut self,
        out: &mut [u8],
        p: &impl Platform,
    ) -> Result<Option<usize>, DriverError>;
    fn receive_frame_with_checkpoint(
        &mut self,
        out: &mut [u8],
        p: &impl Platform,
        _checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, DriverError> {
        self.receive_frame(out, p)
    }
    fn finish_turn(&mut self, p: &impl Platform) -> Result<(), DriverError>;
    fn burst_capacity(&self) -> usize;
}
impl VirtioLink for Net {
    fn transmit(&mut self, f: &[u8], p: &impl Platform) -> Result<(), DriverError> {
        self.send(f, p)
    }
    fn poll_transmit(&mut self, p: &impl Platform) -> Result<bool, DriverError> {
        self.poll_tx(p)
    }
    fn receive_frame(
        &mut self,
        o: &mut [u8],
        p: &impl Platform,
    ) -> Result<Option<usize>, DriverError> {
        self.receive(o, p)
    }
    fn finish_turn(&mut self, _: &impl Platform) -> Result<(), DriverError> {
        Ok(())
    }
    fn burst_capacity(&self) -> usize {
        1
    }
}
impl VirtioLink for BatchedNet {
    fn transmit(&mut self, f: &[u8], p: &impl Platform) -> Result<(), DriverError> {
        self.send_queued(f, p)
    }
    fn poll_transmit(&mut self, p: &impl Platform) -> Result<bool, DriverError> {
        self.poll_tx(p)
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
pub struct VirtioPort<'a, P, N = Net> {
    pub net: &'a mut N,
    pub platform: &'a P,
}

impl<P: Platform, N: VirtioLink> Port for VirtioPort<'_, P, N> {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.net
            .poll_transmit(self.platform)
            .map_err(|_| Error::Device)?;
        self.net
            .transmit(frame, self.platform)
            .map_err(|e| match e {
                DriverError::Busy => Error::WouldBlock,
                _ => Error::Device,
            })
    }

    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, Error> {
        self.net
            .receive_frame(frame, self.platform)
            .map_err(|_| Error::Device)
    }
    fn receive_with_checkpoint(
        &mut self,
        frame: &mut [u8; MTU],
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, Error> {
        self.net
            .receive_frame_with_checkpoint(frame, self.platform, checkpoint)
            .map_err(|_| Error::Device)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.net
            .finish_turn(self.platform)
            .map_err(|_| Error::Device)
    }
    fn burst_capacity(&self) -> usize {
        self.net.burst_capacity()
    }
}

struct Slot {
    bytes: [u8; MTU],
    len: usize,
}

impl Slot {
    const fn new() -> Self {
        Self {
            bytes: [0; MTU],
            len: 0,
        }
    }
}

pub struct Ethernet<P> {
    port: P,
    rx: Slot,
    tx: Slot,
    failed: bool,
}

impl<P: Port> Ethernet<P> {
    pub(crate) fn port(&self) -> &P {
        &self.port
    }
    pub(crate) fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    pub fn new(port: P) -> Self {
        Self {
            port,
            rx: Slot::new(),
            tx: Slot::new(),
            failed: false,
        }
    }

    /// At most one TX and one RX operation; an idle or backpressured NIC does
    /// not spin. A fatal error poisons the adapter until externally reset.
    pub fn service(&mut self) -> Result<(), Error> {
        self.service_with_checkpoint(&mut || {})
    }

    /// The same bounded device turn with scheduler-safe boundaries after the
    /// TX completion check and, when supported by the port, between complete
    /// RX custody transitions. At every boundary no borrowed frame escapes,
    /// so the caller may settle the current CPU reservation before continuing.
    pub fn service_with_checkpoint(&mut self, checkpoint: &mut dyn FnMut()) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        let result = self.service_inner(checkpoint);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn service_inner(&mut self, checkpoint: &mut dyn FnMut()) -> Result<(), Error> {
        if self.tx.len != 0 {
            match self.port.send(&self.tx.bytes[..self.tx.len]) {
                Ok(()) => self.tx.len = 0,
                Err(Error::WouldBlock) => {}
                Err(e) => return Err(e),
            }
        }
        checkpoint();
        if self.rx.len == 0
            && let Some(len) = self
                .port
                .receive_with_checkpoint(&mut self.rx.bytes, checkpoint)?
        {
            if !(14..=MTU).contains(&len) {
                return Err(Error::Frame);
            }
            self.rx.len = len;
        }
        Ok(())
    }
}

pub struct Receive<'a> {
    slot: &'a mut Slot,
}
pub struct Transmit<'a> {
    slot: &'a mut Slot,
}

impl RxToken for Receive<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let len = core::mem::replace(&mut self.slot.len, 0);
        f(&self.slot.bytes[..len])
    }
}

impl TxToken for Transmit<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // smoltcp's Device contract bounds len by max_transmission_unit.
        let result = f(&mut self.slot.bytes[..len]);
        self.slot.len = len;
        result
    }
}

impl<P: Port> Device for Ethernet<P> {
    type RxToken<'a>
        = Receive<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = Transmit<'a>
    where
        Self: 'a;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.failed || self.rx.len == 0 || self.tx.len != 0 {
            return None;
        }
        Some((
            Receive { slot: &mut self.rx },
            Transmit { slot: &mut self.tx },
        ))
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        if self.failed || self.tx.len != 0 {
            return None;
        }
        Some(Transmit { slot: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU;
        caps.max_burst_size = Some(self.port.burst_capacity());
        caps
    }
}
