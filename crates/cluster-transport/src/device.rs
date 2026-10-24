//! Bounded bridge between a polling NIC and smoltcp. One pending frame each
//! way; backpressure never overwrites DMA or a staged TCP packet.
use cyxia_driver_virtio::{Error as DriverError, Platform, net::Net};
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
}

pub struct VirtioPort<'a, P> {
    pub net: &'a mut Net,
    pub platform: &'a P,
}

impl<P: Platform> Port for VirtioPort<'_, P> {
    fn send(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.net.poll_tx(self.platform).map_err(|_| Error::Device)?;
        self.net.send(frame, self.platform).map_err(|e| match e {
            DriverError::Busy => Error::WouldBlock,
            _ => Error::Device,
        })
    }

    fn receive(&mut self, frame: &mut [u8; MTU]) -> Result<Option<usize>, Error> {
        self.net
            .receive(frame, self.platform)
            .map_err(|_| Error::Device)
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
        if self.failed {
            return Err(Error::Device);
        }
        let result = self.service_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn service_inner(&mut self) -> Result<(), Error> {
        if self.tx.len != 0 {
            match self.port.send(&self.tx.bytes[..self.tx.len]) {
                Ok(()) => self.tx.len = 0,
                Err(Error::WouldBlock) => {}
                Err(e) => return Err(e),
            }
        }
        if self.rx.len == 0
            && let Some(len) = self.port.receive(&mut self.rx.bytes)?
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
        caps.max_burst_size = Some(1);
        caps
    }
}
