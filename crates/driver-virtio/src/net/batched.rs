//! Eight independently owned RX and TX buffers, with private TX publication.
use super::{BUFFER, HEADER, MAX_FRAME, Net};
use crate::{
    DiagnosticStage as Stage, Error, Platform, Transport,
    queue::{BatchMemory, BatchQueue, NotifyFeedback, NotifyRequest, NotifyStats, Token},
};
pub struct BatchedNet {
    transport: Transport,
    rx: BatchQueue,
    tx: BatchQueue,
    mac: [u8; 6],
    received: Option<(Token, usize)>,
    packet: [u8; BUFFER],
    failed: bool,
    last_completed: u64,
    hooks: Option<(NotifyRequest, NotifyFeedback)>,
    command_version: u64,
}
impl BatchedNet {
    pub fn initialize(
        mut t: Transport,
        rx: &'static mut BatchMemory,
        tx: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        if t.device_id() != 1 {
            return Err(Error::Device);
        }
        Net::negotiate(&mut t, p)?;
        let mac = Net::read_mac(&t, p)?;
        let rx = BatchQueue::configure(&mut t, rx, 0, p)?;
        let tx = BatchQueue::configure(&mut t, tx, 1, p)?;
        t.start(p)?;
        let mut net = Self {
            transport: t,
            rx,
            tx,
            mac,
            received: None,
            packet: [0; BUFFER],
            failed: false,
            last_completed: 0,
            hooks: None,
            command_version: 0,
        };
        for _ in 0..net.rx.capacity() {
            net.rx
                .enqueue(&mut net.transport, &[], BUFFER, false, true, p)?;
        }
        Ok(net)
    }
    pub fn set_notify_hooks(&mut self, request: NotifyRequest, feedback: NotifyFeedback) {
        self.hooks = Some((request, feedback));
    }
    fn report(&self, p: &impl Platform, polled: bool) {
        if let Some((_, report)) = self.hooks {
            report(self.notify_stats(), p.now_ns(), polled);
        }
    }
    fn healthy(&mut self, p: &impl Platform) -> Result<(), Error> {
        if let Some((request, _)) = self.hooks
            && let Some(c) = request(p.now_ns())
            && c.version != self.command_version
        {
            self.set_notify_policy(c.batch, c.version, c.until_ns, p.now_ns())?;
            self.command_version = c.version;
        }
        if self.failed {
            return Err(Error::Device);
        }
        if self.transport.check().is_err() {
            self.fail(p);
            return Err(Error::Device);
        }
        Ok(())
    }
    fn fail(&mut self, p: &impl Platform) {
        self.failed = true;
        self.rx.poison(&mut self.transport, p);
        self.tx.poison(&mut self.transport, p);
        self.report(p, false);
    }
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
    pub fn capacity(&self) -> usize {
        self.tx.capacity().min(self.rx.capacity())
    }
    pub fn notify_stats(&self) -> NotifyStats {
        let mut t = self.tx.stats();
        let r = self.rx.stats();
        t.published = t.published.saturating_add(r.published);
        t.completed = t.completed.saturating_add(r.completed);
        t.doorbells = t.doorbells.saturating_add(r.doorbells);
        t.pending += r.pending;
        t.inflight += r.inflight;
        t.max_batch = t.max_batch.max(r.max_batch);
        t.descriptors += r.descriptors;
        t.errors = t.errors.max(r.errors);
        t.pending_version = t.pending_version.max(r.pending_version);
        t.last_completed_version = self.last_completed;
        t
    }
    pub fn current_batch(&self, now: u64) -> u8 {
        self.tx.current_batch(now)
    }
    pub fn set_notify_policy(
        &mut self,
        batch: u8,
        version: u64,
        until: u64,
        now: u64,
    ) -> Result<(), Error> {
        if usize::from(batch) > self.capacity() {
            return Err(Error::Exhausted);
        }
        self.tx.install(batch, version, until, now)?;
        self.rx.install(batch, version, until, now)
    }
    pub fn set_completion_interrupts(&mut self, enabled: bool, p: &impl Platform) {
        self.rx.set_completion_interrupts(enabled, p);
        self.tx.set_completion_interrupts(enabled, p);
    }
    fn submit(&mut self, frame: &[u8], isolated: bool, p: &impl Platform) -> Result<(), Error> {
        self.healthy(p)?;
        if !(14..=MAX_FRAME).contains(&frame.len()) {
            return Err(Error::Address);
        }
        let mut bytes = [0; BUFFER];
        bytes[HEADER..HEADER + frame.len()].copy_from_slice(frame);
        match self.tx.enqueue(
            &mut self.transport,
            &bytes[..HEADER + frame.len()],
            0,
            false,
            isolated,
            p,
        ) {
            Ok(_) => {
                self.report(p, false);
                Ok(())
            }
            Err(e) => {
                if !matches!(e, Error::Busy | Error::Address) {
                    self.fail(p);
                }
                Err(e)
            }
        }
    }
    /// Independent synchronous/isolated caller: notify immediately.
    pub fn send(&mut self, frame: &[u8], p: &impl Platform) -> Result<(), Error> {
        self.submit(frame, true, p)
    }
    /// Producer must finish its bounded turn with flush_tx, also polled at 50us.
    pub fn send_queued(&mut self, frame: &[u8], p: &impl Platform) -> Result<(), Error> {
        self.submit(frame, false, p)
    }
    pub fn flush_tx(&mut self, p: &impl Platform) -> Result<(), Error> {
        self.healthy(p)?;
        let r = self.tx.drain(&mut self.transport, p);
        self.report(p, false);
        r
    }
    pub fn poll_tx(&mut self, p: &impl Platform) -> Result<bool, Error> {
        self.healthy(p)?;
        match self.tx.poll(&mut self.transport, &mut [], p) {
            Ok(Some(c)) => {
                self.tx.release(c.token)?;
                self.last_completed = self.last_completed.max(c.version);
                self.report(p, true);
                Ok(true)
            }
            Ok(None) => {
                self.report(p, true);
                Ok(false)
            }
            Err(e) => {
                self.fail(p);
                Err(e)
            }
        }
    }
    pub fn poll_rx(&mut self, p: &impl Platform) -> Result<bool, Error> {
        self.poll_rx_with_checkpoint(p, &mut || {})
    }
    fn poll_rx_with_checkpoint(
        &mut self,
        p: &impl Platform,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<bool, Error> {
        p.diagnostic_stage(Stage::NetRxPoll as u64);
        self.healthy(p)?;
        if self.received.is_some() {
            return Ok(true);
        }
        let c =
            match self
                .rx
                .poll_with_checkpoint(&mut self.transport, &mut self.packet, p, checkpoint)
            {
                Ok(Some(c)) => c,
                Ok(None) => {
                    self.report(p, true);
                    return Ok(false);
                }
                Err(e) => {
                    self.fail(p);
                    return Err(e);
                }
            };
        p.diagnostic_stage(Stage::NetRxHeader as u64);
        let flags = self.packet[0];
        let gso = self.packet[1];
        let buffers = u16::from_le_bytes([self.packet[10], self.packet[11]]);
        if !(HEADER + 14..=BUFFER).contains(&c.len) || flags & 7 != 0 || gso != 0 || buffers != 1 {
            self.fail(p);
            return Err(Error::Response);
        }
        self.received = Some((c.token, c.len - HEADER));
        self.last_completed = self.last_completed.max(c.version);
        self.report(p, true);
        Ok(true)
    }
    pub fn receive(&mut self, out: &mut [u8], p: &impl Platform) -> Result<Option<usize>, Error> {
        self.receive_with_checkpoint(out, p, &mut || {})
    }
    /// Poll, copy and release/rearm are distinct custody transitions. The
    /// callback is invoked only after a complete transition while no slice
    /// into pinned DMA memory escapes this owner.
    pub fn receive_with_checkpoint(
        &mut self,
        out: &mut [u8],
        p: &impl Platform,
        checkpoint: &mut dyn FnMut(),
    ) -> Result<Option<usize>, Error> {
        self.poll_rx_with_checkpoint(p, checkpoint)?;
        checkpoint();
        p.diagnostic_stage(Stage::NetRxDelivery as u64);
        let Some((token, len)) = self.received else {
            return Ok(None);
        };
        if out.len() < len {
            return Err(Error::Address);
        }
        p.diagnostic_stage(Stage::NetRxCopy as u64);
        out[..len].copy_from_slice(&self.packet[HEADER..HEADER + len]);
        checkpoint();
        p.diagnostic_stage(Stage::NetRxRearm as u64);
        self.rx.release(token)?;
        self.received = None;
        self.rx
            .enqueue(&mut self.transport, &[], BUFFER, false, true, p)?;
        self.report(p, false);
        Ok(Some(len))
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
    use std::boxed::Box;
    struct Host(Cell<u64>);
    unsafe impl Platform for Host {
        fn physical(&self, a: usize, _: usize) -> Result<u64, Error> {
            Ok(a as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {}
        fn now_ms(&self) -> u64 {
            self.0.get() / 1_000_000
        }
        fn now_ns(&self) -> u64 {
            self.0.get()
        }
    }
    fn fixture() -> (BatchedNet, Host, usize, usize) {
        let p = Host(Cell::new(0));
        let m = Box::leak(Box::new(Page::zeroed()));
        m.put32(0, 0x74726976);
        m.put32(4, 2);
        m.put32(8, 1);
        m.put32(0x34, 16);
        m.put32(0x70, 15);
        let mut t = unsafe { Transport::attach(m.address(), 4096).unwrap() };
        let a = Box::leak(Box::new(BatchMemory::zeroed()));
        let ap = a as *mut _ as usize;
        let rx = BatchQueue::configure(&mut t, a, 0, &p).unwrap();
        m.put32(0x44, 0);
        let b = Box::leak(Box::new(BatchMemory::zeroed()));
        let bp = b as *mut _ as usize;
        let tx = BatchQueue::configure(&mut t, b, 1, &p).unwrap();
        let mut n = BatchedNet {
            transport: t,
            rx,
            tx,
            mac: [2, 0, 0, 0, 0, 1],
            received: None,
            packet: [0; BUFFER],
            failed: false,
            last_completed: 0,
            hooks: None,
            command_version: 0,
        };
        for _ in 0..n.rx.capacity() {
            n.rx.enqueue(&mut n.transport, &[], BUFFER, false, true, &p)
                .unwrap();
        }
        (n, p, ap, bp)
    }
    unsafe fn used(base: usize, id: u16, len: u32) {
        unsafe {
            let u = base + 8192;
            let n = u16::from_le(read_volatile((u + 2) as *const u16));
            let a = u + 4 + usize::from(n % 16) * 8;
            write_volatile(a as *mut u32, u32::from(id).to_le());
            write_volatile((a + 4) as *mut u32, len.to_le());
            write_volatile((u + 2) as *mut u16, n.wrapping_add(1).to_le());
        }
    }
    #[test]
    fn tx_publication_is_real_bounded_and_tracks_completed_version() {
        let (mut n, p, _, tx) = fixture();
        n.set_notify_policy(4, 10, 1_000_000, 0).unwrap();
        for _ in 0..3 {
            n.send_queued(&[0x33; 64], &p).unwrap();
        }
        assert_eq!(n.tx.stats().published, 0);
        n.send_queued(&[0x55; 64], &p).unwrap();
        assert_eq!(n.tx.stats().published, 4);
        assert_eq!(n.tx.stats().doorbells, 1);
        unsafe {
            used(tx, 4, 0);
        }
        assert!(n.poll_tx(&p).unwrap());
        assert_eq!(n.notify_stats().last_completed_version, 10);
        n.send(&[0x77; 64], &p).unwrap();
        assert_eq!(n.tx.stats().published, 5);
    }
    #[test]
    fn rx_short_consumer_holds_completed_buffer_until_consumption() {
        let (mut n, p, rx, _) = fixture();
        unsafe {
            let response = u64::from_le(read_volatile(rx as *const u64)) as usize;
            for i in 0..76 {
                write_volatile((response + i) as *mut u8, if i < 12 { 0 } else { 0x62 });
            }
            write_volatile((response + 10) as *mut u16, 1u16.to_le());
            used(rx, 0, 76);
        }
        assert_eq!(n.receive(&mut [0; 12], &p), Err(Error::Address));
        assert_eq!(n.rx.free(), 0);
        let mut frame = [0; 64];
        assert_eq!(n.receive(&mut frame, &p), Ok(Some(64)));
        assert_eq!(frame, [0x62; 64]);
        assert_eq!(n.rx.free(), 0);
        assert_eq!(n.rx.stats().published, 9);
    }
}
