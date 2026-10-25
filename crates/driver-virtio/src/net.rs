//! Bounded modern VirtIO-MMIO Ethernet driver (one RX and one TX credit).
use crate::{Error, Platform, QueueMemory, Transport};
mod batched;
pub use batched::BatchedNet;

pub const MAX_FRAME: usize = 1514;
const HEADER: usize = 12;
const BUFFER: usize = HEADER + MAX_FRAME;

struct Ring {
    memory: &'static mut QueueMemory,
    available: u16,
    used: u16,
    id: u16,
    pending: bool,
    buffer_pa: u64,
}

impl Ring {
    fn configure(
        t: &mut Transport,
        memory: &'static mut QueueMemory,
        index: u32,
        platform: &impl Platform,
    ) -> Result<Self, Error> {
        t.write(0x30, index);
        platform.barrier();
        if t.read(0x44) != 0 || t.read(0x34) < 8 {
            return Err(Error::Queue);
        }
        let size = core::mem::size_of::<QueueMemory>();
        let pa = platform.physical(memory as *mut _ as usize, size)?;
        if !pa.is_multiple_of(4096) || pa.checked_add(size as u64).is_none() {
            return Err(Error::Address);
        }
        memory.desc.clear();
        memory.avail.clear();
        memory.used.clear();
        memory.request.clear();
        memory.response.clear();
        memory.avail.put16(0, 1); // Polling, NO_INTERRUPT.
        unsafe { platform.sync(memory as *mut _ as usize, size) };
        t.write(0x38, 8);
        t.address(0x80, pa);
        t.address(0x90, pa + 4096);
        t.address(0xa0, pa + 8192);
        platform.barrier();
        t.write(0x44, 1);
        platform.barrier();
        if t.read(0x44) != 1 {
            return Err(Error::Queue);
        }
        Ok(Self {
            memory,
            available: 0,
            used: 0,
            id: 0,
            pending: false,
            buffer_pa: pa + if index == 0 { 16384 } else { 12288 },
        })
    }

    /// Caller holds exclusive CPU ownership of the packet page until publication.
    /// A single readable TX or writable RX descriptor; no artificial response.
    fn post(&mut self, rx: bool, length: usize, p: &impl Platform) {
        debug_assert!(!self.pending);
        self.id = self.available % 8;
        let at = usize::from(self.id) * 16;
        self.memory.desc.put64(at, self.buffer_pa);
        self.memory.desc.put32(at + 8, length as u32);
        self.memory.desc.put16(at + 12, if rx { 2 } else { 0 });
        self.memory.desc.put16(at + 14, 0);
        let buffer = if rx {
            &self.memory.response
        } else {
            &self.memory.request
        };
        // SAFETY: packet/descriptor storage is pinned and CPU-owned. After the
        // avail publication it is not touched again until a validated used entry.
        unsafe {
            p.sync(buffer.address(), 4096);
            p.sync(self.memory.desc.address(), 4096);
        }
        self.memory
            .avail
            .put16(4 + usize::from(self.available % 8) * 2, self.id);
        self.available = self.available.wrapping_add(1);
        p.barrier();
        self.memory.avail.put16(2, self.available);
        unsafe { p.sync(self.memory.avail.address(), 4096) };
        p.barrier();
        self.pending = true;
    }

    fn poll(&mut self, rx: bool, p: &impl Platform) -> Result<Option<usize>, Error> {
        // SAFETY: used is device-owned, pinned storage. Synchronize before reads.
        unsafe { p.sync(self.memory.used.address(), 4096) };
        p.barrier();
        let end = self.memory.used.get16(2);
        if end == self.used {
            return Ok(None);
        }
        let at = 4 + usize::from(self.used % 8) * 8;
        // used.idx is the device's publication field. Acquire after observing
        // it, before reading ID/length. A pre-index invalidate alone is not
        // enough on non-coherent machines: speculative entry reads may have
        // repopulated an old cache line (slot 7 even straddles two 64B lines).
        p.barrier();
        // SAFETY: this bounded entry belongs to the pinned device-owned used
        // page; invalidate its complete ID+length after the publication acquire.
        unsafe { p.sync(self.memory.used.address() + at, 8) };
        p.barrier();
        let length = self.memory.used.get32(at + 4) as usize;
        if !self.pending
            || end.wrapping_sub(self.used) != 1
            || self.memory.used.get32(at) != u32::from(self.id)
            || (rx && !(HEADER + 14..=BUFFER).contains(&length))
            || (!rx && length != 0)
        {
            return Err(Error::Queue);
        }
        self.used = end;
        self.pending = false;
        Ok(Some(length))
    }
}

/// One serialized owner, permanently pinned DMA pages, polling only. Drop and
/// any error do not release the supplied static pages or reset the device:
/// FAILED is not proof that DMA has stopped. Recovery needs an external reset
/// and verified quiescence before those pages can ever be reclaimed.
pub struct Net {
    transport: Transport,
    rx: Ring,
    tx: Ring,
    mac: [u8; 6],
    received: Option<usize>,
    failed: bool,
}

impl Net {
    pub fn initialize(
        mut transport: Transport,
        rx: &'static mut QueueMemory,
        tx: &'static mut QueueMemory,
        platform: &impl Platform,
    ) -> Result<Self, Error> {
        if transport.device_id() != 1 {
            return Err(Error::Device);
        }
        let configuration = Self::configure(&mut transport, rx, tx, platform);
        let (mac, rx, tx) = match configuration {
            Ok(config) => config,
            Err(e) => {
                transport.fail();
                platform.barrier();
                return Err(e);
            }
        };
        let mut net = Self {
            transport,
            rx,
            tx,
            mac,
            received: None,
            failed: false,
        };
        // Populate before DRIVER_OK, but do not notify until DRIVER_OK. Both
        // queues retain their own packet page on success and every error path.
        net.rx.post(true, BUFFER, platform);
        if let Err(e) = net.transport.start(platform) {
            net.fail(platform);
            return Err(e);
        }
        net.transport.write(0x50, 0);
        Ok(net)
    }

    fn configure(
        t: &mut Transport,
        rx: &'static mut QueueMemory,
        tx: &'static mut QueueMemory,
        p: &impl Platform,
    ) -> Result<([u8; 6], Ring, Ring), Error> {
        Self::negotiate(t, p)?;
        let mac = Self::read_mac(t, p)?;
        let rx = Ring::configure(t, rx, 0, p)?;
        let tx = Ring::configure(t, tx, 1, p)?;
        Ok((mac, rx, tx))
    }

    fn negotiate(t: &mut Transport, p: &impl Platform) -> Result<(), Error> {
        let result = (|| {
            t.write(0x70, 0);
            p.barrier();
            let start = p.now_ms();
            while t.read(0x70) != 0 {
                if p.now_ms().wrapping_sub(start) >= 100 {
                    return Err(Error::Timeout);
                }
                core::hint::spin_loop();
            }
            t.write(0x70, 3);
            t.write(0x14, 0);
            p.barrier();
            let low_features = t.read(0x10);
            if low_features & 32 == 0 {
                return Err(Error::Features);
            }
            t.write(0x14, 1);
            p.barrier();
            if t.read(0x10) & 1 == 0 {
                return Err(Error::Features);
            }
            // Optional MRG_RXBUF makes modern devices publish num_buffers.
            // Only one MTU-sized RX buffer is posted; multi-buffer packets are
            // still outside this bounded profile and are rejected. No checksum,
            // GSO/control/MQ/event-index/indirect features are accepted.
            t.write(0x24, 0);
            t.write(0x20, 32 | (low_features & (1 << 15)));
            p.barrier();
            t.write(0x24, 1);
            t.write(0x20, 1);
            p.barrier();
            t.write(0x70, 3 | 8);
            p.barrier();
            if t.read(0x70) & (8 | 64 | 128) != 8 {
                return Err(Error::Features);
            }
            Ok(())
        })();
        if result.is_err() {
            t.fail();
            p.barrier();
        }
        result
    }

    fn read_mac(t: &Transport, p: &impl Platform) -> Result<[u8; 6], Error> {
        for _ in 0..8 {
            let generation = t.read(0xfc);
            p.barrier();
            let mut mac = [0; 6];
            for (i, byte) in mac.iter_mut().enumerate() {
                // SAFETY: Transport validates a mapped >=0x200-byte resource.
                *byte = unsafe { core::ptr::read_volatile((t.base + 0x100 + i) as *const u8) };
            }
            p.barrier();
            if generation == t.read(0xfc) {
                return if mac[0] & 1 == 0 && mac != [0; 6] {
                    Ok(mac)
                } else {
                    Err(Error::Response)
                };
            }
        }
        Err(Error::Device)
    }

    fn fail(&mut self, p: &impl Platform) {
        self.failed = true;
        self.transport.fail();
        p.barrier();
    }

    fn healthy(&mut self, p: &impl Platform) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if self.transport.read(0x70) != 15 {
            self.fail(p);
            return Err(Error::Device);
        }
        Ok(())
    }

    fn completion(&mut self, rx: bool, p: &impl Platform) -> Result<Option<usize>, Error> {
        self.healthy(p)?;
        let result = if rx {
            self.rx.poll(true, p)
        } else {
            self.tx.poll(false, p)
        };
        if result.is_err() {
            self.fail(p);
        }
        if matches!(result, Ok(Some(_))) {
            let irq = self.transport.read(0x60);
            self.transport.write(0x64, irq & 3);
        }
        result
    }
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    /// Publish one complete Ethernet frame (14..=1514 bytes, without FCS).
    /// Ok means queued, not delivered; Busy never changes the in-flight packet.
    pub fn send(&mut self, frame: &[u8], platform: &impl Platform) -> Result<(), Error> {
        self.healthy(platform)?;
        if self.tx.pending {
            return Err(Error::Busy);
        }
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(Error::Address);
        }
        // Even an idle ring must reject unsolicited/replayed used records before
        // a new descriptor is exposed, rather than treating them as its result.
        self.completion(false, platform)?;
        for i in 0..HEADER {
            self.tx.memory.request.put8(i, 0);
        }
        for (i, byte) in frame.iter().enumerate() {
            self.tx.memory.request.put8(HEADER + i, *byte);
        }
        self.tx.post(false, HEADER + frame.len(), platform);
        self.transport.write(0x50, 1);
        Ok(())
    }
    /// Poll once: true consumes one TX completion and returns its single credit.
    /// A silent device retains ownership indefinitely; this method never waits.
    pub fn poll_tx(&mut self, platform: &impl Platform) -> Result<bool, Error> {
        Ok(self.completion(false, platform)?.is_some())
    }
    /// Poll once and validate a received packet, retaining it until receive.
    /// A quiet network is normal and has no RX timeout. No buffer is rearmed here.
    pub fn poll_rx(&mut self, platform: &impl Platform) -> Result<bool, Error> {
        if let Some(length) = self.completion(true, platform)? {
            // SAFETY: a validated used record has returned the single RX buffer.
            unsafe { platform.sync(self.rx.memory.response.address(), 4096) };
            platform.barrier();
            let m = &self.rx.memory.response;
            // Modern virtio_net_hdr always includes num_buffers, even without
            // MRG_RXBUF. This single-buffer MTU profile accepts exactly one;
            // without MRG_RXBUF the device must also report exactly one.
            let header = m.get16(0);
            let flags = header as u8;
            let gso_type = (header >> 8) as u8;
            // §5.1.6.4.2 requires ignoring unknown flag bits. The recognized
            // NEEDS_CSUM, DATA_VALID and RSC_INFO features are not negotiated.
            if flags & (1 | 2 | 4) != 0 || gso_type != 0 || m.get16(10) != 1 {
                self.fail(platform);
                return Err(Error::Response);
            }
            self.received = Some(length - HEADER);
        }
        Ok(self.received.is_some())
    }
    /// Copy a validated frame, consume its RX credit, and post the next buffer.
    /// A short output returns Address and retains the complete packet for retry.
    pub fn receive(
        &mut self,
        output: &mut [u8],
        platform: &impl Platform,
    ) -> Result<Option<usize>, Error> {
        self.poll_rx(platform)?;
        let Some(length) = self.received else {
            return Ok(None);
        };
        if output.len() < length {
            return Err(Error::Address);
        }
        for (i, byte) in output[..length].iter_mut().enumerate() {
            // SAFETY: CPU owns the completed RX page, and length was bounded by
            // the advertised descriptor capacity before any packet was exposed.
            *byte = unsafe {
                core::ptr::read_volatile(
                    (self.rx.memory.response.address() + HEADER + i) as *const u8,
                )
            };
        }
        self.received = None;
        self.rx.post(true, BUFFER, platform);
        self.transport.write(0x50, 0);
        Ok(Some(length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Page;
    use core::{
        cell::Cell,
        ptr::{read_volatile, write_volatile},
    };
    use std::{boxed::Box, cell::RefCell, vec::Vec};

    struct Host {
        mmio: &'static Page,
        features: u64,
        selected: Cell<u32>,
        ready: RefCell<[u32; 2]>,
        negotiated: RefCell<Vec<(u32, u32)>>,
        queue_desc: RefCell<[u64; 2]>,
        reject_features: bool,
        tx_max: u32,
        bad_dma: bool,
        unstable_mac: bool,
        saw_driver_ok: Cell<bool>,
        early_notify: Cell<bool>,
        clock: Cell<u64>,
    }
    // SAFETY: tests serialize a fake device with driver accesses to pinned pages.
    // DMA is emulated only through volatile accesses at valid descriptor addresses.
    unsafe impl Platform for Host {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64 + u64::from(self.bad_dma))
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn now_ms(&self) -> u64 {
            self.clock.get()
        }
        fn barrier(&self) {
            let m = self.mmio;
            if !self.saw_driver_ok.get() && m.get32(0x50) != u32::MAX {
                self.early_notify.set(true);
            }
            if m.get32(0x70) == 15 {
                self.saw_driver_ok.set(true);
            }
            if self.unstable_mac {
                m.put32(0xfc, m.get32(0xfc).wrapping_add(1));
            }
            let selector = m.get32(0x14);
            m.put32(
                0x10,
                if selector == 0 {
                    self.features as u32
                } else {
                    (self.features >> 32) as u32
                },
            );
            if m.get32(0x70) == 3 {
                self.negotiated
                    .borrow_mut()
                    .push((m.get32(0x24), m.get32(0x20)));
            }
            if self.reject_features && m.get32(0x70) & 8 != 0 {
                m.put32(0x70, m.get32(0x70) & !8);
            }
            let selected = m.get32(0x30);
            if selected < 2 {
                if selected != self.selected.get() {
                    self.ready.borrow_mut()[self.selected.get() as usize] = m.get32(0x44);
                    self.selected.set(selected);
                    m.put32(0x44, self.ready.borrow()[selected as usize]);
                }
                m.put32(0x34, if selected == 1 { self.tx_max } else { 8 });
                if m.get32(0x44) == 1 {
                    self.queue_desc.borrow_mut()[selected as usize] =
                        u64::from(m.get32(0x80)) | (u64::from(m.get32(0x84)) << 32);
                }
            }
        }
    }
    fn host(features: u64) -> Host {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 1);
        mmio.put32(0x34, 8);
        mmio.put32(0x50, u32::MAX);
        for (i, b) in [2, 0x11, 0x22, 0x33, 0x44, 0x55].iter().enumerate() {
            mmio.put8(0x100 + i, *b);
        }
        Host {
            mmio,
            features,
            selected: Cell::new(0),
            ready: RefCell::new([0; 2]),
            negotiated: RefCell::new(Vec::new()),
            queue_desc: RefCell::new([0; 2]),
            reject_features: false,
            tx_max: 8,
            bad_dma: false,
            unstable_mac: false,
            saw_driver_ok: Cell::new(false),
            early_notify: Cell::new(false),
            clock: Cell::new(0),
        }
    }
    fn initialize(h: &Host) -> Result<Net, Error> {
        let t = unsafe { Transport::attach(h.mmio.address(), 4096).unwrap() };
        Net::initialize(
            t,
            Box::leak(Box::new(QueueMemory::zeroed())),
            Box::leak(Box::new(QueueMemory::zeroed())),
            h,
        )
    }
    fn fixture() -> (Net, Host) {
        let h = host((1 << 32) | (1 << 5) | (1 << 15) | (1 << 0));
        let n = initialize(&h).unwrap();
        (n, h)
    }
    fn complete(r: &Ring, id: u32, length: u32, advance: u16) {
        let at = 4 + usize::from(r.used % 8) * 8;
        r.memory.used.put32(at, id);
        r.memory.used.put32(at + 4, length);
        r.memory.used.put16(2, r.used.wrapping_add(advance));
    }
    fn packet(n: &Net, flags: u8, gso: u8, buffers: u16, frame: &[u8]) {
        // Device follows the address in the actual posted RX descriptor.
        let d = n.rx.memory.desc.address() + usize::from(n.rx.id) * 16;
        let address = u64::from_le(unsafe { read_volatile(d as *const u64) }) as usize;
        for i in 0..12 {
            unsafe {
                write_volatile((address + i) as *mut u8, 0);
            }
        }
        unsafe {
            write_volatile(address as *mut u8, flags);
            write_volatile((address + 1) as *mut u8, gso);
            write_volatile((address + 10) as *mut u16, buffers.to_le());
            for (i, b) in frame.iter().enumerate() {
                write_volatile((address + 12 + i) as *mut u8, *b);
            }
        }
        complete(&n.rx, u32::from(n.rx.id), (12 + frame.len()) as u32, 1);
    }

    #[test]
    fn initializes_two_real_rings_with_mac_version_one_and_optional_mergeable() {
        let (n, h) = fixture();
        assert_eq!(n.mac(), [2, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert!(h.negotiated.borrow().contains(&(0, 32 | (1 << 15))));
        assert!(h.negotiated.borrow().contains(&(1, 1)));
        assert_eq!(
            *h.queue_desc.borrow(),
            [
                n.rx.memory.desc.address() as u64,
                n.tx.memory.desc.address() as u64
            ]
        );
        assert_eq!(h.mmio.get32(0x70), 15);
        assert_eq!(n.rx.memory.desc.get32(8), 1526);
        assert_eq!(n.rx.memory.desc.get16(12), 2);
        assert_eq!(n.rx.memory.avail.get16(2), 1);
        assert_eq!(n.tx.memory.avail.get16(2), 0);
        assert!(
            !h.early_notify.get(),
            "buffer notification before DRIVER_OK"
        );
    }
    #[test]
    fn initialization_failure_sets_failed_even_after_one_queue_was_configured() {
        for fault in 0..4 {
            let mut h = host((1 << 32) | 32);
            let expected = match fault {
                0 => {
                    h.tx_max = 0;
                    Error::Queue
                }
                1 => {
                    h.bad_dma = true;
                    Error::Address
                }
                2 => {
                    h.mmio.put8(0x100, 1);
                    Error::Response
                }
                _ => {
                    h.unstable_mac = true;
                    Error::Device
                }
            };
            assert!(matches!(initialize(&h), Err(e) if e == expected));
            assert_ne!(h.mmio.get32(0x70) & 128, 0);
            assert!(!h.saw_driver_ok.get());
        }
    }
    #[test]
    fn unexpected_status_reset_poisoned_without_republishing_owned_dma() {
        for status in [0, 3, 11, 15 | 64] {
            let (mut n, h) = fixture();
            n.send(&[0x55; 14], &h).unwrap();
            h.mmio.put32(0x70, status);
            assert_eq!(n.poll_tx(&h), Err(Error::Device));
            assert_eq!(n.poll_rx(&h), Err(Error::Device));
            assert_eq!(n.send(&[0x99; 14], &h), Err(Error::Device));
            assert_eq!(n.tx.memory.avail.get16(2), 1);
            assert_eq!(n.tx.memory.request.get16(12), 0x5555);
        }
    }
    #[test]
    fn split_ring_indices_wrap_without_replaying_or_losing_rx_tx_credits() {
        let (mut n, h) = fixture();
        n.tx.available = u16::MAX;
        n.tx.used = u16::MAX;
        n.tx.memory.used.put16(2, u16::MAX);
        n.send(&[0x55; 14], &h).unwrap();
        assert_eq!(n.tx.memory.avail.get16(2), 0);
        assert_eq!(n.tx.memory.avail.get16(18), 7);
        complete(&n.tx, 7, 0, 1);
        assert_eq!(n.poll_tx(&h), Ok(true));
        n.send(&[0x99; 14], &h).unwrap();
        assert_eq!(n.tx.memory.avail.get16(2), 1);
        complete(&n.tx, 0, 0, 1);
        assert_eq!(n.poll_tx(&h), Ok(true));
        n.rx.used = u16::MAX;
        packet(&n, 0, 0, 1, &[0xaa; 14]);
        assert_eq!(n.receive(&mut [0; 14], &h), Ok(Some(14)));
        assert_eq!(n.rx.used, 0);
    }
    #[test]
    fn rejects_wrong_device_missing_features_and_rejected_negotiation() {
        for features in [0, 1 << 32, 1 << 5] {
            let h = host(features);
            assert!(matches!(initialize(&h), Err(Error::Features)));
            assert_eq!(*h.queue_desc.borrow(), [0; 2]);
        }
        let h = host((1 << 32) | 32);
        h.mmio.put32(8, 2);
        assert!(matches!(initialize(&h), Err(Error::Device)));
        let mut h = host((1 << 32) | 32);
        h.reject_features = true;
        assert!(matches!(initialize(&h), Err(Error::Features)));
    }
    #[test]
    fn mergeable_feature_is_optional_but_only_one_buffer_frame_is_supported() {
        for offered in [0, 1 << 15] {
            let h = host((1 << 32) | 32 | offered | 1 | (1 << 7));
            let mut n = initialize(&h).unwrap();
            assert!(h.negotiated.borrow().contains(&(0, 32 | offered as u32)));
            assert_eq!(n.rx.memory.desc.get32(8), 1526);
            assert_eq!(n.rx.memory.avail.get16(2), 1);
            packet(&n, 0, 0, 1, &[0xa5; 1514]);
            let mut output = [0; 1514];
            assert_eq!(n.receive(&mut output, &h), Ok(Some(1514)));
            assert_eq!(output, [0xa5; 1514]);
            packet(&n, 0, 0, 2, &[0x55; 14]);
            assert_eq!(n.receive(&mut output, &h), Err(Error::Response));
            assert_eq!(output, [0xa5; 1514]);
            assert_eq!(n.rx.memory.avail.get16(2), 2);
            assert_eq!(n.send(&[0; 14], &h), Err(Error::Device));
        }
    }
    #[test]
    fn transmit_is_read_only_twelve_byte_header_and_busy_preserves_dma() {
        let (mut n, h) = fixture();
        let frame = [0xab; 14];
        n.send(&frame, &h).unwrap();
        assert_eq!(n.tx.memory.desc.get32(8), 26);
        assert_eq!(n.tx.memory.desc.get16(12), 0);
        // Follow the readable descriptor as a device would, catching a wrong
        // packet DMA address rather than only checking the CPU staging page.
        let address =
            u64::from_le(unsafe { read_volatile(n.tx.memory.desc.address() as *const u64) })
                as usize;
        for i in 0..26 {
            assert_eq!(
                unsafe { read_volatile((address + i) as *const u8) },
                if i < 12 { 0 } else { 0xab }
            );
        }
        assert_eq!(n.send(&[0xcd; 14], &h), Err(Error::Busy));
        assert_eq!(n.tx.memory.avail.get16(2), 1);
        assert_eq!(n.tx.memory.request.get16(12), 0xabab);
        assert_eq!(n.poll_tx(&h), Ok(false));
        complete(&n.tx, 0, 0, 1);
        assert_eq!(n.poll_tx(&h), Ok(true));
        assert_eq!(n.poll_tx(&h), Ok(false));
        n.send(&frame, &h).unwrap();
        assert_eq!(n.tx.memory.avail.get16(6), 1);
        complete(&n.tx, 1, 0, 1);
        assert_eq!(n.poll_tx(&h), Ok(true));
    }
    #[test]
    fn receives_frame_without_header_then_rearms_and_retains_on_short_output() {
        let (mut n, h) = fixture();
        assert_eq!(n.receive(&mut [0; 1514], &h), Ok(None));
        packet(&n, 0, 0, 1, &[0xa5; 14]);
        assert_eq!(n.poll_rx(&h), Ok(true));
        assert_eq!(n.rx.memory.avail.get16(2), 1);
        assert_eq!(n.receive(&mut [0xaa; 13], &h), Err(Error::Address));
        assert_eq!(n.rx.memory.avail.get16(2), 1);
        let mut output = [0xcc; 20];
        assert_eq!(n.receive(&mut output, &h), Ok(Some(14)));
        assert_eq!(&output[..14], &[0xa5; 14]);
        assert_eq!(&output[14..], &[0xcc; 6]);
        assert_eq!(n.rx.memory.avail.get16(2), 2);
        assert_eq!(n.rx.memory.avail.get16(6), 1);
        packet(&n, 0, 0, 1, &[0x5a; 1514]);
        assert_eq!(n.receive(&mut [0; 1514], &h), Ok(Some(1514)));
        assert_eq!(n.receive(&mut [0; 1514], &h), Ok(None));
    }
    #[test]
    fn silent_receive_never_times_out_or_reposts_owned_buffer() {
        let (mut n, h) = fixture();
        h.clock.set(u64::MAX);
        for _ in 0..16 {
            assert_eq!(n.poll_rx(&h), Ok(false));
        }
        assert_eq!(n.rx.memory.avail.get16(2), 1);
        n.send(&[0; 1514], &h).unwrap();
    }
    struct CachedUsed<'a> {
        host: &'a Host,
        used: &'a Page,
        phase: Cell<u8>,
    }
    // SAFETY: same pinned test DMA storage as Host. This adapter maintains a
    // CPU-visible shadow of a device completion on two 64-byte cache lines.
    unsafe impl Platform for CachedUsed<'_> {
        fn physical(&self, address: usize, len: usize) -> Result<u64, Error> {
            self.host.physical(address, len)
        }
        unsafe fn sync(&self, address: usize, len: usize) {
            let entry = self.used.address() + 60;
            if address <= entry && address.saturating_add(len) >= entry + 8 {
                match self.phase.get() {
                    0 => self.phase.set(1), // First invalidate precedes publication.
                    3 => self.phase.set(4), // Invalidate again after acquiring idx.
                    _ => {}
                }
            }
        }
        fn now_ms(&self) -> u64 {
            self.host.now_ms()
        }
        fn barrier(&self) {
            self.host.barrier();
            match self.phase.get() {
                1 => {
                    // Device publishes idx after the initial invalidate. The
                    // entry's second cache line still contains speculative old
                    // length=0 until a post-publication acquire+invalidate.
                    self.used.put16(2, 8);
                    self.phase.set(2);
                }
                2 => self.phase.set(3),
                4 => {
                    self.used.put32(60, 7);
                    self.used.put32(64, 26);
                    self.phase.set(5);
                }
                _ => {}
            }
        }
    }
    #[test]
    fn acquires_used_index_then_invalidates_split_cache_line_entry() {
        let (mut n, h) = fixture();
        for _ in 0..7 {
            packet(&n, 0, 0, 1, &[0x55; 14]);
            assert_eq!(n.receive(&mut [0; 14], &h), Ok(Some(14)));
        }
        packet(&n, 0, 0, 1, &[0xa5; 14]);
        n.rx.memory.used.put16(2, 7);
        n.rx.memory.used.put32(60, 7);
        n.rx.memory.used.put32(64, 0); // Stale cache line, valid ID on first line.
        // Borrow the page through its stable raw pointer, just as device DMA
        // stays independent of the driver's exclusive queue owner.
        let used = &n.rx.memory.used as *const Page;
        let cached = CachedUsed {
            host: &h,
            used: unsafe { &*used },
            phase: Cell::new(0),
        };
        let mut output = [0; 14];
        assert_eq!(n.receive(&mut output, &cached), Ok(Some(14)));
        assert_eq!(output, [0xa5; 14]);
        assert_eq!(cached.phase.get(), 5);
        assert_eq!(n.rx.memory.avail.get16(2), 9);
    }
    #[test]
    fn unknown_receive_flags_do_not_prevent_frame_delivery_or_next_transmit() {
        for flags in [8, 16, 32, 64, 128, 248] {
            let (mut n, h) = fixture();
            packet(&n, flags, 0, 1, &[0xa5; 14]);
            let mut output = [0; 14];
            assert_eq!(n.receive(&mut output, &h), Ok(Some(14)));
            assert_eq!(output, [0xa5; 14]);
            assert_eq!(n.rx.memory.avail.get16(2), 2);
            assert_eq!(n.send(&[0; 14], &h), Ok(()));
        }
    }
    #[test]
    fn rejects_malformed_used_records_without_reusing_dma() {
        for (rx, id, len, advance) in [
            (true, 8, 26, 1),
            (true, 0, 25, 1),
            (true, 0, 1527, 1),
            (true, 0, 26, 2),
            (false, 8, 0, 1),
            (false, 0, 1, 1),
            (false, 0, 0, 2),
        ] {
            let (mut n, h) = fixture();
            n.send(&[0x55; 14], &h).unwrap();
            complete(if rx { &n.rx } else { &n.tx }, id, len, advance);
            let mut output = [0xaa; 1514];
            let result = if rx {
                n.receive(&mut output, &h).map(|_| false)
            } else {
                n.poll_tx(&h)
            };
            assert_eq!(result, Err(Error::Queue));
            assert_eq!(output, [0xaa; 1514]);
            assert_eq!(n.send(&[0x99; 14], &h), Err(Error::Device));
            assert_eq!(n.rx.memory.avail.get16(2), 1);
            assert_eq!(n.tx.memory.avail.get16(2), 1);
            assert_eq!(n.tx.memory.request.get16(12), 0x5555);
            assert_ne!(h.mmio.get32(0x70) & 128, 0);
        }
    }
    #[test]
    fn rejects_offloads_and_merged_receive_before_exposing_frame() {
        for (flags, gso, buffers) in [
            (1, 0, 1),
            (2, 0, 1),
            (4, 0, 1),
            (0x81, 0, 1),
            (0x82, 0, 1),
            (0x84, 0, 1),
            (0, 1, 1),
            (0, 0, 0),
            (0, 0, 2),
        ] {
            let (mut n, h) = fixture();
            packet(&n, flags, gso, buffers, &[0x5a; 14]);
            let mut output = [0xaa; 1514];
            assert_eq!(n.receive(&mut output, &h), Err(Error::Response));
            assert_eq!(output, [0xaa; 1514]);
            assert_eq!(n.rx.memory.avail.get16(2), 1);
            assert_eq!(n.poll_rx(&h), Err(Error::Device));
        }
    }
    #[test]
    fn replayed_completion_is_rejected_while_idle_or_after_rearm() {
        let (mut n, h) = fixture();
        n.send(&[0; 14], &h).unwrap();
        complete(&n.tx, 0, 0, 1);
        assert_eq!(n.poll_tx(&h), Ok(true));
        complete(&n.tx, 0, 0, 1);
        assert_eq!(n.send(&[1; 14], &h), Err(Error::Queue));
        assert_eq!(n.tx.memory.avail.get16(2), 1);
        let (mut n, h) = fixture();
        packet(&n, 0, 0, 1, &[0; 14]);
        n.receive(&mut [0; 14], &h).unwrap();
        complete(&n.rx, 0, 26, 1);
        assert_eq!(n.poll_rx(&h), Err(Error::Queue));
        assert_eq!(n.rx.memory.avail.get16(2), 2);
    }
    #[test]
    fn frame_bounds_and_device_fault_do_not_overwrite_transmit() {
        let (mut n, h) = fixture();
        assert_eq!(n.send(&[0; 13], &h), Err(Error::Address));
        assert_eq!(n.send(&[0; 1515], &h), Err(Error::Address));
        assert_eq!(n.tx.memory.avail.get16(2), 0);
        n.send(&[0x55; 14], &h).unwrap();
        h.mmio.put32(0x70, 15 | 64);
        assert_eq!(n.poll_tx(&h), Err(Error::Device));
        assert_eq!(n.receive(&mut [0; 1514], &h), Err(Error::Device));
        assert_eq!(n.send(&[0xaa; 14], &h), Err(Error::Device));
        assert_eq!(n.tx.memory.request.get16(12), 0x5555);
    }
}
