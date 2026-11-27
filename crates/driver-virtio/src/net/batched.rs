//! Eight independently owned RX and TX buffers, with private TX publication.
use super::{BUFFER, HEADER, MAX_FRAME, Net};
use crate::{
    DiagnosticStage as Stage, Error, Platform, Transport,
    queue::{
        BatchMemory, BatchQueue, MAX_CHAINS, NotifyFeedback, NotifyRequest, NotifyStats,
        RetainedChain, Token,
    },
    reset::{DeviceState, ResetProof},
};
/// Exactly one device-verified TX used-ring completion retained by the
/// dedicated native adapter until its protected upper owner acknowledges.
/// This is a DMA-chain completion, NOT a remote TCP ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxReceipt {
    pub token: Token,
    pub version: u64,
}
pub struct BatchedNet {
    transport: Transport,
    rx: BatchQueue,
    tx: BatchQueue,
    mac: [u8; 6],
    strict_features: bool,
    received: Option<(Token, usize)>,
    completed_tx: Option<TxReceipt>,
    state: DeviceState,
    last_completed: u64,
    hooks: Option<(NotifyRequest, NotifyFeedback)>,
    command_version: u64,
}
impl BatchedNet {
    pub fn initialize(
        t: Transport,
        rx: &'static mut BatchMemory,
        tx: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::initialize_inner(t, rx, tx, None, p)
    }

    /// Admit the V0.20 native net profile with only MAC and VERSION_1,
    /// and check the deployment MAC before advertising any DMA descriptors.
    pub fn initialize_native(
        t: Transport,
        rx: &'static mut BatchMemory,
        tx: &'static mut BatchMemory,
        expected_mac: [u8; 6],
        p: &impl Platform,
    ) -> Result<Self, Error> {
        Self::initialize_inner(t, rx, tx, Some(expected_mac), p)
    }

    fn initialize_inner(
        mut t: Transport,
        rx: &'static mut BatchMemory,
        tx: &'static mut BatchMemory,
        expected_mac: Option<[u8; 6]>,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        if t.device_id() != 1 {
            return Err(Error::Device);
        }
        let strict_features = expected_mac.is_some();
        Net::negotiate(&mut t, p, !strict_features)?;
        let configured =
            (|t: &mut Transport, rx: &'static mut BatchMemory, tx: &'static mut BatchMemory| {
                let mac = Net::read_mac(t, p)?;
                if expected_mac.is_some_and(|expected| expected != mac) {
                    return Err(Error::Device);
                }
                let rx = BatchQueue::configure(t, rx, 0, p)?;
                let tx = BatchQueue::configure(t, tx, 1, p)?;
                t.start(p)?;
                Ok((mac, rx, tx))
            })(&mut t, rx, tx);
        let (mac, rx, tx) = match configured {
            Ok(configured) => configured,
            Err(error) => {
                t.fail();
                p.barrier();
                return Err(error);
            }
        };
        let mut net = Self {
            transport: t,
            rx,
            tx,
            mac,
            strict_features,
            received: None,
            completed_tx: None,
            state: DeviceState::Live,
            last_completed: 0,
            hooks: None,
            command_version: 0,
        };
        for _ in 0..net.rx.capacity() {
            if let Err(error) = net
                .rx
                .enqueue(&mut net.transport, &[], BUFFER, false, true, p)
            {
                net.fail(p);
                return Err(error);
            }
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
        if self.state != DeviceState::Live {
            return Err(Error::Device);
        }
        if let Some((request, _)) = self.hooks
            && let Some(c) = request(p.now_ns())
            && c.version != self.command_version
        {
            self.set_notify_policy(c.batch, c.version, c.until_ns, p.now_ns())?;
            self.command_version = c.version;
        }
        if self.transport.check().is_err() {
            self.fail(p);
            return Err(Error::Device);
        }
        Ok(())
    }
    fn fail(&mut self, p: &impl Platform) {
        self.state = DeviceState::Failed;
        self.rx.poison(&mut self.transport, p);
        self.tx.poison(&mut self.transport, p);
        self.report(p, false);
    }
    /// Permanently stop this one-shot native NIC owner. The caller retains
    /// this outcome for retries. RX/TX buffers and credits stay in custody.
    pub fn stop_native(
        &mut self,
        boot_epoch: u64,
        platform: &impl Platform,
    ) -> Result<[ResetProof; 2], Error> {
        if !self.strict_features {
            return Err(Error::Unsupported);
        }
        if boot_epoch == 0 {
            return Err(Error::Address);
        }
        if self.state == DeviceState::ResetAttempted {
            return Err(Error::Busy);
        }
        self.state = DeviceState::ResetAttempted;
        self.rx.fence();
        self.tx.fence();
        self.transport
            .observe_mmio_reset(1, &[0, 1], platform)
            .map(|observed| {
                [0, 1].map(|id| ResetProof::for_first_generation(boot_epoch, 1, id, observed))
            })
    }
    /// Return RX and TX custody in queue-ID order after the terminal reset
    /// attempt. A published chain has no verified completion at this point.
    pub fn stopped_chains(&self) -> Option<[[Option<RetainedChain>; MAX_CHAINS]; 2]> {
        (self.state == DeviceState::ResetAttempted)
            .then(|| [self.rx.retained_chains(), self.tx.retained_chains()])
    }
    /// Conservative device TX settle witness, only after every used-ring
    /// completion was validated and every matching token acknowledged.
    /// Pending/UNKNOWN TX or a held receipt forbids normal credit retirement.
    pub fn tx_quiescent(&self) -> bool {
        self.state == DeviceState::Live && self.completed_tx.is_none() && self.tx.is_quiescent()
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
    /// Opt-in SEC-D completion custody: return the exact slot generation and
    /// policy version from a verified VirtIO used-ring entry while retaining
    /// the pinned chain. A second poll cannot bypass its owner's ACK.
    pub fn poll_tx_receipt(&mut self, p: &impl Platform) -> Result<Option<TxReceipt>, Error> {
        self.healthy(p)?;
        if self.completed_tx.is_some() {
            return Err(Error::Busy);
        }
        match self.tx.poll(&mut self.transport, &mut [], p) {
            Ok(Some(c)) => {
                let receipt = TxReceipt {
                    token: c.token,
                    version: c.version,
                };
                self.completed_tx = Some(receipt);
                self.report(p, true);
                Ok(Some(receipt))
            }
            Ok(None) => {
                self.report(p, true);
                Ok(None)
            }
            Err(e) => {
                self.fail(p);
                Err(e)
            }
        }
    }
    /// Only the exact, driver-issued completed TX token may retire the DMA
    /// descriptor. A stale/reused generation or arbitrary caller notification
    /// does not release another chain or advance completed policy versions.
    pub fn acknowledge_tx(&mut self, receipt: TxReceipt, p: &impl Platform) -> Result<(), Error> {
        if self.completed_tx != Some(receipt) {
            return Err(Error::Response);
        }
        self.healthy(p)?;
        self.tx.release(receipt.token)?;
        self.completed_tx = None;
        self.last_completed = self.last_completed.max(receipt.version);
        self.report(p, true);
        Ok(())
    }
    /// Historical port compatibility: the trusted native VirtIO owner may
    /// directly ACK the exact completion in the same serialized driver turn.
    /// New security consumers can use poll_tx_receipt + acknowledge_tx instead.
    pub fn poll_tx(&mut self, p: &impl Platform) -> Result<bool, Error> {
        match self.poll_tx_receipt(p)? {
            Some(receipt) => {
                self.acknowledge_tx(receipt, p)?;
                Ok(true)
            }
            None => Ok(false),
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
        let c = match self
            .rx
            .poll_in_place_with_checkpoint(&mut self.transport, p, checkpoint)
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
        let valid = (HEADER + 14..=BUFFER).contains(&c.len)
            && self.rx.completed_response(c.token).is_ok_and(|page| {
                let [flags, gso] = page.get16(0).to_le_bytes();
                let buffers = page.get16(10);
                // QEMU 10.2's non-mergeable receive path leaves num_buffers
                // unwritten. The zero-initialized field then stays zero.
                // In this profile the device still gets one bounded descriptor.
                flags & 7 == 0
                    && gso == 0
                    && (buffers == 1 || (self.strict_features && buffers == 0))
            });
        if !valid {
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
        self.rx
            .completed_response(token)?
            .copy_range_to(HEADER, &mut out[..len]);
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
            strict_features: false,
            received: None,
            completed_tx: None,
            state: DeviceState::Live,
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
    fn device_receive(base: usize, id: u16, head: [u8; 12], frame: &[u8], len: u32) {
        let descriptor = base + usize::from(id) * 16;
        unsafe {
            let response = u64::from_le(read_volatile(descriptor as *const u64)) as usize;
            for (i, byte) in head.into_iter().chain(frame.iter().copied()).enumerate() {
                write_volatile((response + i) as *mut u8, byte);
            }
            used(base, id, len);
        }
    }
    const GOOD_HEADER: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];

    #[test]
    fn native_rx_accepts_one_frame_when_qemu_leaves_buffer_count_unwritten() {
        let (mut net, platform, rx, _) = fixture();
        net.strict_features = true;
        device_receive(rx, 0, [0; HEADER], &[0x5a; 64], 76);
        let mut out = [0; 64];
        assert_eq!(net.receive(&mut out, &platform), Ok(Some(64)));
        assert_eq!(out, [0x5a; 64]);
    }

    #[test]
    fn rx_owner_fits_below_one_receive_buffer() {
        assert!(
            core::mem::size_of::<BatchedNet>() < BUFFER,
            "the RX owner still reserves space for a staged packet"
        );
    }

    #[test]
    fn rx_copies_exact_frame_into_unaligned_output() {
        #[repr(align(8))]
        struct Aligned([u8; 1516]);

        let (mut n, p, rx, _) = fixture();
        let frame: [u8; 1514] = core::array::from_fn(|i| i.wrapping_mul(17) as u8);
        for len in [14, 19, 64, 1514] {
            let mut header = GOOD_HEADER;
            header[0] = 0x80;
            device_receive(rx, 0, header, &frame[..len], (12 + len) as u32);
            assert_eq!(n.poll_rx(&p), Ok(true));
            let mut storage = Aligned([0xa5; 1516]);
            let out = &mut storage.0;
            assert_eq!(n.receive(&mut out[1..], &p), Ok(Some(len)));
            assert_eq!(&out[1..len + 1], &frame[..len]);
            assert_eq!(out[0], 0xa5);
            assert!(out[len + 1..].iter().all(|&byte| byte == 0xa5));
        }
    }

    #[test]
    fn rx_rejects_malformed_completions_without_delivery_or_rearm() {
        for (flags, gso, buffers, len, error) in [
            (0, 0, 1u16, 0, Error::Response),
            (0, 0, 1, 25, Error::Response),
            (0, 0, 1, 1527, Error::Queue),
            (1, 0, 1, 26, Error::Response),
            (2, 0, 1, 26, Error::Response),
            (4, 0, 1, 26, Error::Response),
            (0, 1, 1, 26, Error::Response),
            (0, 0, 0, 26, Error::Response),
            (0, 0, 2, 26, Error::Response),
            (0, 0, 256, 26, Error::Response),
        ] {
            let (mut n, p, rx, _) = fixture();
            let mut header = GOOD_HEADER;
            header[0] = flags;
            header[1] = gso;
            header[10..].copy_from_slice(&buffers.to_le_bytes());
            device_receive(rx, 0, header, &[0x62; 14], len);
            let mut out = [0xa5; 64];
            assert_eq!(n.receive(&mut out, &p), Err(error));
            assert_eq!(out, [0xa5; 64]);
            assert_eq!(n.notify_stats().published, 8);
            assert_eq!(n.notify_stats().errors, 1);
            assert_eq!(n.poll_rx(&p), Err(Error::Device));
        }
    }

    #[test]
    fn rx_accepts_another_completion_during_delivery_checkpoint() {
        let (mut n, p, rx, _) = fixture();
        device_receive(rx, 4, GOOD_HEADER, &[0x44; 64], 76);
        let mut checkpoints = 0;
        let mut out = [0; 64];
        assert_eq!(
            n.receive_with_checkpoint(&mut out, &p, &mut || {
                checkpoints += 1;
                let avail = unsafe { read_volatile((rx + 4098) as *const u16) };
                assert_eq!(u16::from_le(avail), 8, "published before rearm");
                if checkpoints == 10 {
                    device_receive(rx, 0, GOOD_HEADER, &[0x22; 64], 76);
                }
            }),
            Ok(Some(64))
        );
        assert_eq!(checkpoints, 10);
        assert_eq!(out, [0x44; 64]);
        assert_eq!(n.notify_stats().completed, 1);
        assert_eq!(n.notify_stats().published, 9);
        assert_eq!(n.receive(&mut out, &p), Ok(Some(64)));
        assert_eq!(out, [0x22; 64]);
        assert_eq!(n.notify_stats().completed, 2);
        assert_eq!(n.notify_stats().published, 10);
        assert_eq!(n.receive(&mut out, &p), Ok(None));
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
    fn v019_sec_d_tx_completion_retains_dma_until_exact_generation_ack() {
        let (mut n, p, _, tx) = fixture();
        n.send(&[0x31; 64], &p).unwrap();
        unsafe {
            used(tx, 0, 0);
        }
        let receipt = n.poll_tx_receipt(&p).unwrap().unwrap();
        assert_eq!(n.tx.free(), n.tx.capacity() - 1);
        assert_eq!(n.poll_tx_receipt(&p), Err(Error::Busy));
        assert_eq!(n.poll_tx(&p), Err(Error::Busy));
        assert_eq!(
            n.acknowledge_tx(
                TxReceipt {
                    token: Token {
                        generation: receipt.token.generation + 1,
                        ..receipt.token
                    },
                    ..receipt
                },
                &p
            ),
            Err(Error::Response)
        );
        assert_eq!(n.tx.free(), n.tx.capacity() - 1);
        assert_eq!(n.notify_stats().last_completed_version, 0);
        n.acknowledge_tx(receipt, &p).unwrap();
        assert_eq!(n.tx.free(), n.tx.capacity());
        assert_eq!(n.acknowledge_tx(receipt, &p), Err(Error::Response));
        n.send(&[0x32; 64], &p).unwrap();
        // Reusing a freed slot cannot make the old completion valid again.
        assert_eq!(n.acknowledge_tx(receipt, &p), Err(Error::Response));
    }
    #[test]
    fn v019_sec_d_tx_quiescent_requires_used_ring_and_matching_ack() {
        let (mut n, p, _, tx) = fixture();
        assert!(n.tx_quiescent());
        n.send(&[0x2d; 64], &p).unwrap();
        assert!(!n.tx_quiescent());
        unsafe { used(tx, 0, 0) };
        let receipt = n.poll_tx_receipt(&p).unwrap().unwrap();
        assert!(!n.tx_quiescent());
        n.acknowledge_tx(receipt, &p).unwrap();
        assert!(n.tx_quiescent());
    }
    #[test]
    fn rx_short_consumer_holds_completed_buffer_until_consumption() {
        let (mut n, p, rx, _) = fixture();
        device_receive(rx, 0, GOOD_HEADER, &[0x62; 64], 76);
        let mut short = [0xa5; 12];
        assert_eq!(n.receive(&mut short, &p), Err(Error::Address));
        assert_eq!(short, [0xa5; 12]);
        assert_eq!(n.rx.free(), 0);
        assert_eq!(n.rx.stats().completed, 1);
        assert_eq!(n.rx.stats().published, 8);
        let mut frame = [0; 64];
        assert_eq!(n.receive(&mut frame, &p), Ok(Some(64)));
        assert_eq!(frame, [0x62; 64]);
        assert_eq!(n.rx.free(), 0);
        assert_eq!(n.rx.stats().published, 9);
    }
}
