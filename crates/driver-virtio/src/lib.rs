#![no_std]
//! Modern VirtIO MMIO/PCI, one outstanding split-ring chain per queue.
//! No allocator, interrupts, indirect descriptors, packed rings or legacy transport.
use core::{
    cell::UnsafeCell,
    ptr::{read_volatile, write_volatile},
};

pub mod block;
pub mod gpu;
pub mod input_buffer;
pub mod net;
pub mod queue;
pub mod reset;
pub mod rng;
pub mod snapshot;

/// Read-only operation labels. A marker is never a scheduler checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum DiagnosticStage {
    TcpHealth = 1,
    TcpClock,
    TcpTime,
    EthernetTx,
    EthernetRx,
    NetRxPoll,
    NetRxHeader,
    NetRxDelivery,
    NetRxCopy,
    NetRxRearm,
    QueueStatus,
    QueueFlush,
    QueueUsedSync,
    QueueIdleAck,
    QueueElementSync,
    QueueDecode,
    QueueValidate,
    QueuePayloadSync,
    QueueCopyPublish,
    QueueCompletionAck,
    TcpFlush,
    TcpSocketSnapshot,
    TcpIngress,
    TcpIngressResult,
    TcpEgress,
    TcpRemoteState,
    IpcDrain,
    TcpAbort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Address,
    Unsupported,
    Features,
    Queue,
    Busy,
    Timeout,
    Device,
    Response,
    Exhausted,
}

/// Platform implementation must provide DMA visibility and ordered MMIO access.
/// # Safety
/// A successful physical translation identifies the complete contiguous pinned
/// memory region for its lifetime. Cache maintenance and barriers must cover
/// CPU/device ownership transitions.
pub unsafe trait Platform {
    /// Copy a scalar diagnostic only; implementations must not schedule,
    /// borrow a device/owner, read clocks or alter DMA custody here.
    fn diagnostic_stage(&self, _stage: u64) {}
    fn physical(&self, address: usize, len: usize) -> Result<u64, Error>;
    /// Authorize the exact split-ring and bounce-page range for this queue
    /// before publishing any DMA address. The assignment survives a failed
    /// configuration, an abandoned queue, and all resets for this backing.
    fn admit_queue_dma(
        &self,
        _transport: usize,
        _device: u32,
        _index: u32,
        _pa: u64,
        _len: usize,
    ) -> Result<(), Error> {
        Ok(())
    }
    /// Synchronize an exclusively owned DMA region before CPU access or after writes.
    /// # Safety
    /// Address/length must denote mapped, pinned storage owned by the caller.
    unsafe fn sync(&self, address: usize, len: usize);
    fn barrier(&self);
    fn now_ms(&self) -> u64;
    /// A board with a finer clock overrides this for the 50us publication cap.
    fn now_ns(&self) -> u64 {
        self.now_ms().saturating_mul(1_000_000)
    }
}

#[repr(C, align(4096))]
struct Page(UnsafeCell<[u8; 4096]>);
impl Page {
    const fn zeroed() -> Self {
        Self(UnsafeCell::new([0; 4096]))
    }
    fn address(&self) -> usize {
        self.0.get() as usize
    }
    fn clear(&mut self) {
        self.clear_prefix(4096);
    }
    fn clear_prefix(&self, bytes: usize) {
        debug_assert!(bytes <= 4096);
        let wide = bytes & !7;
        for offset in (0..wide).step_by(8) {
            self.put64(offset, 0);
        }
        for offset in wide..bytes {
            self.put8(offset, 0);
        }
    }
    fn copy_prefix_to(&self, out: &mut [u8], bytes: usize) {
        self.copy_range_to(0, &mut out[..bytes]);
    }
    fn copy_range_to(&self, offset: usize, out: &mut [u8]) {
        assert!(offset <= 4096 && out.len() <= 4096 - offset);
        let address = self.address() + offset;
        // The source must be aligned for wide volatile reads. Peel off any
        // leading bytes, then handle the aligned words and trailing bytes.
        let prefix = (offset.next_multiple_of(8) - offset).min(out.len());
        let (head, rest) = out.split_at_mut(prefix);
        for (i, byte) in head.iter_mut().enumerate() {
            *byte = unsafe { read_volatile((address + i) as *const u8) };
        }
        let address = address + prefix;
        let wide = rest.len() & !7;
        for i in (0..wide).step_by(8) {
            // DMA ownership has already transferred to the CPU. Preserve
            // volatile device-memory reads while avoiding one translated
            // helper per byte for maximum-MTU responses. The destination may
            // be unaligned, hence the explicit unaligned ordinary store.
            let value = unsafe { read_volatile((address + i) as *const u64) };
            unsafe { core::ptr::write_unaligned(rest.as_mut_ptr().add(i).cast::<u64>(), value) };
        }
        for (i, byte) in rest[wide..].iter_mut().enumerate() {
            *byte = unsafe { read_volatile((address + wide + i) as *const u8) };
        }
    }
    /// Mirror of `copy_prefix_to` for the request direction. A maximum-MTU
    /// frame or a sector payload otherwise pays one translated volatile helper
    /// per byte; the device page is 8-aligned at every wide offset.
    fn copy_prefix_from(&self, offset: usize, bytes: &[u8]) {
        debug_assert!(offset + bytes.len() <= 4096);
        let mut at = 0;
        // Wide volatile stores must stay 8-aligned for architectures that trap
        // unaligned device accesses, so emit the leading bytes individually.
        while at < bytes.len() && !(offset + at).is_multiple_of(8) {
            self.put8(offset + at, bytes[at]);
            at += 1;
        }
        let wide = (bytes.len() - at) & !7;
        for step in (0..wide).step_by(8) {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[at + step..at + step + 8]);
            self.put64(offset + at + step, u64::from_le_bytes(chunk));
        }
        for (index, &byte) in bytes.iter().enumerate().skip(at + wide) {
            self.put8(offset + index, byte);
        }
    }
    fn put8(&self, offset: usize, value: u8) {
        // SAFETY: every caller bounds offsets to this page; volatile accesses are
        // serialized by Queue's exclusive CPU owner and descriptor ownership.
        unsafe { write_volatile((self.address() + offset) as *mut u8, value) }
    }
    fn put16(&self, offset: usize, value: u16) {
        unsafe { write_volatile((self.address() + offset) as *mut u16, value.to_le()) }
    }
    fn put32(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.address() + offset) as *mut u32, value.to_le()) }
    }
    fn put64(&self, offset: usize, value: u64) {
        unsafe { write_volatile((self.address() + offset) as *mut u64, value.to_le()) }
    }
    fn get8(&self, offset: usize) -> u8 {
        debug_assert!(offset < 4096);
        unsafe { read_volatile((self.address() + offset) as *const u8) }
    }
    fn get16(&self, offset: usize) -> u16 {
        u16::from_le(unsafe { read_volatile((self.address() + offset) as *const u16) })
    }
    fn get32(&self, offset: usize) -> u32 {
        u32::from_le(unsafe { read_volatile((self.address() + offset) as *const u32) })
    }
}

#[repr(C, align(4096))]
pub struct QueueMemory {
    desc: Page,
    avail: Page,
    used: Page,
    request: Page,
    response: Page,
}
impl QueueMemory {
    pub const fn zeroed() -> Self {
        Self {
            desc: Page::zeroed(),
            avail: Page::zeroed(),
            used: Page::zeroed(),
            request: Page::zeroed(),
            response: Page::zeroed(),
        }
    }
}

mod transport;
pub use transport::{MappedRegion, PciRegions, Transport};
/// DMA buffers are permanently reserved, including after timeout or Drop.
/// This deliberately quarantines failed devices instead of reusing in-flight pages.
pub struct Queue {
    memory: &'static mut QueueMemory,
    dma_base: u64,
    notification: transport::Notification,
    size: u16,
    available: u16,
    used: u16,
    writable: u32,
    pending: bool,
    poisoned: bool,
}
impl Queue {
    pub fn configure(
        transport: &mut Transport,
        memory: &'static mut QueueMemory,
        index: u32,
        platform: &impl Platform,
    ) -> Result<Self, Error> {
        transport.select_queue(index)?;
        let maximum = transport.queue_max_size();
        if transport.queue_enabled() || maximum < 8 {
            return Err(Error::Queue);
        }
        // Input reports consume one descriptor per event. Use up to 64 of the
        // existing pinned slots so a short motion burst is not silently lost.
        // Request/response devices retain their original eight-entry ring.
        let queue_size = if transport.device_id() == 18 {
            let limit = maximum.min(64);
            1u32 << (31 - limit.leading_zeros())
        } else {
            8
        };
        let notification = transport.queue_notification(index)?;
        let size = core::mem::size_of::<QueueMemory>();
        let pa = platform.physical(memory as *mut _ as usize, size)?;
        if !pa.is_multiple_of(4096) || pa.checked_add(size as u64).is_none() {
            return Err(Error::Address);
        }
        platform.admit_queue_dma(transport.owner(), transport.device_id(), index, pa, size)?;
        memory.desc.clear();
        memory.avail.clear();
        memory.used.clear();
        memory.request.clear();
        memory.response.clear();
        memory.avail.put16(0, 1); // Polling: NO_INTERRUPT, still acknowledge delivered IRQ status.
        unsafe {
            platform.sync(memory as *mut _ as usize, size);
        }
        transport.set_queue_size(queue_size)?;
        transport.set_queue_addresses(pa, pa + 4096, pa + 8192);
        platform.barrier();
        transport.enable_queue();
        Ok(Self {
            memory,
            dma_base: pa,
            notification,
            size: queue_size as u16,
            available: 0,
            used: 0,
            writable: 0,
            pending: false,
            poisoned: false,
        })
    }
    /// No device completion can exist when the single-chain queue is idle.
    /// A stale used element must not be accepted as the next submission.
    /// The physical DMA pool stays quarantined if a device violates this.
    fn validate_idle_used(
        &mut self,
        transport: &mut Transport,
        platform: &impl Platform,
    ) -> Result<(), Error> {
        unsafe { platform.sync(self.memory.used.address(), 4) };
        platform.barrier();
        if self.memory.used.get16(2) != self.used {
            self.poisoned = true;
            transport.fail();
            platform.barrier();
            return Err(Error::Queue);
        }
        Ok(())
    }

    pub fn submit(
        &mut self,
        transport: &mut Transport,
        request: &[u8],
        writable: usize,
        platform: &impl Platform,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        if self.pending {
            return Err(Error::Busy);
        }
        if request.len() > 4096 || !(1..=4096).contains(&writable) {
            return Err(Error::Address);
        }
        transport.check()?;
        self.validate_idle_used(transport, platform)?;
        let m = &self.memory;
        let response_pa = self.dma_base + core::mem::offset_of!(QueueMemory, response) as u64;
        let request_pa = self.dma_base + core::mem::offset_of!(QueueMemory, request) as u64;
        m.request.copy_prefix_from(0, request);
        let response_descriptor = if request.is_empty() { 0 } else { 16 };
        if !request.is_empty() {
            m.desc.put64(0, request_pa);
            m.desc.put32(8, request.len() as u32);
            m.desc.put16(12, 1);
            m.desc.put16(14, 1);
        }
        m.desc.put64(response_descriptor, response_pa);
        m.desc.put32(response_descriptor + 8, writable as u32);
        m.desc.put16(response_descriptor + 12, 2);
        m.desc.put16(response_descriptor + 14, 0);
        // The device cannot touch request/response until the available index is published.
        unsafe {
            platform.sync(m.request.address(), 4096);
            platform.sync(m.response.address(), 4096);
            platform.sync(m.desc.address(), 4096);
        }
        m.avail
            .put16(4 + usize::from(self.available % self.size) * 2, 0);
        self.available = self.available.wrapping_add(1);
        platform.barrier();
        m.avail.put16(2, self.available);
        unsafe {
            platform.sync(m.avail.address(), 4096);
        }
        platform.barrier();
        self.writable = writable as u32;
        self.pending = true;
        if let Err(error) = transport.notify(self.notification) {
            self.poisoned = true;
            transport.fail();
            return Err(error);
        }
        Ok(())
    }
    pub fn poll(
        &mut self,
        transport: &mut Transport,
        output: &mut [u8],
        platform: &impl Platform,
    ) -> Result<Option<usize>, Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        if !self.pending {
            self.validate_idle_used(transport, platform)?;
            return Ok(None);
        }
        if output.len() < self.writable as usize {
            return Err(Error::Address);
        }
        transport.check()?;
        let m = &self.memory;
        unsafe {
            platform.sync(m.used.address(), 4096);
        }
        platform.barrier();
        let index = m.used.get16(2);
        if index == self.used {
            return Ok(None);
        }
        // Acquire the published used index before reading the used element.
        // A pre-index cache invalidation can race the device's final writes.
        platform.barrier();
        unsafe {
            platform.sync(m.used.address(), 4096);
        }
        platform.barrier();
        let at = 4 + usize::from(self.used % self.size) * 8;
        let length = m.used.get32(at + 4);
        if index.wrapping_sub(self.used) != 1 || m.used.get32(at) != 0 || length > self.writable {
            self.poisoned = true;
            transport.fail();
            return Err(Error::Queue);
        }
        unsafe {
            platform.sync(m.response.address(), 4096);
        }
        platform.barrier();
        m.response.copy_prefix_to(output, length as usize);
        transport.acknowledge_interrupt();
        self.used = index;
        self.pending = false;
        Ok(Some(length as usize))
    }
    pub fn transact(
        &mut self,
        transport: &mut Transport,
        request: &[u8],
        output: &mut [u8],
        platform: &impl Platform,
    ) -> Result<usize, Error> {
        self.submit(transport, request, output.len(), platform)?;
        let start = platform.now_ms();
        loop {
            if let Some(len) = self.poll(transport, output, platform)? {
                return Ok(len);
            }
            if platform.now_ms().wrapping_sub(start) >= 250 {
                self.poisoned = true;
                transport.fail();
                return Err(Error::Timeout);
            }
            core::hint::spin_loop();
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u16,
    pub value: i32,
}
const _: () = assert!(core::mem::size_of::<InputEvent>() == 8);
const _: () = assert!(core::mem::offset_of!(InputEvent, kind) == 0);
const _: () = assert!(core::mem::offset_of!(InputEvent, code) == 2);
const _: () = assert!(core::mem::offset_of!(InputEvent, value) == 4);

/// Bounded independently posted event buffers: one keyboard/mouse report may
/// contain multiple events plus SYN_REPORT, so a single posted buffer is invalid.
pub struct EventQueue {
    queue: Queue,
}
impl EventQueue {
    pub fn prime(
        mut queue: Queue,
        transport: &mut Transport,
        platform: &impl Platform,
    ) -> Result<Self, Error> {
        if queue.pending || queue.poisoned || queue.available != 0 {
            return Err(Error::Busy);
        }
        if queue.size < 8 || queue.size > 64 || !queue.size.is_power_of_two() {
            return Err(Error::Queue);
        }
        let pa = queue.dma_base + core::mem::offset_of!(QueueMemory, response) as u64;
        for slot in 0..usize::from(queue.size) {
            queue.memory.desc.put64(slot * 16, pa + slot as u64 * 8);
            queue.memory.desc.put32(slot * 16 + 8, 8);
            queue.memory.desc.put16(slot * 16 + 12, 2);
            queue.memory.desc.put16(slot * 16 + 14, 0);
            queue.memory.avail.put16(4 + slot * 2, slot as u16);
        }
        unsafe {
            platform.sync(queue.memory.desc.address(), 4096);
            platform.sync(queue.memory.response.address(), 4096);
        }
        platform.barrier();
        queue.memory.avail.put16(2, queue.size);
        unsafe {
            platform.sync(queue.memory.avail.address(), 4096);
        }
        platform.barrier();
        queue.available = queue.size;
        if let Err(error) = transport.notify(queue.notification) {
            // The handle is dropped, but its static DMA pages remain pinned.
            transport.fail();
            return Err(error);
        }
        Ok(Self { queue })
    }
    pub fn poll(
        &mut self,
        transport: &mut Transport,
        platform: &impl Platform,
    ) -> Result<Option<InputEvent>, Error> {
        let q = &mut self.queue;
        if q.poisoned {
            return Err(Error::Device);
        }
        transport.check()?;
        unsafe {
            platform.sync(q.memory.used.address(), 4096);
        }
        platform.barrier();
        let end = q.memory.used.get16(2);
        if end == q.used {
            return Ok(None);
        }
        // As above, invalidate elements again after acquiring the device's index.
        platform.barrier();
        unsafe {
            platform.sync(q.memory.used.address(), 4096);
        }
        platform.barrier();
        // Snapshot the entire currently completed batch before re-posting any
        // ID. Otherwise a duplicate used ID could be mistaken for a fresh event.
        let count = end.wrapping_sub(q.used) as usize;
        if count > usize::from(q.size) {
            q.poisoned = true;
            transport.fail();
            return Err(Error::Queue);
        }
        let mut seen = [false; 64];
        let mut first_slot = 0;
        for n in 0..count {
            let offset = 4 + usize::from(q.used.wrapping_add(n as u16) % q.size) * 8;
            let id = q.memory.used.get32(offset) as usize;
            if id >= usize::from(q.size) || seen[id] || q.memory.used.get32(offset + 4) != 8 {
                q.poisoned = true;
                transport.fail();
                return Err(Error::Queue);
            }
            if n == 0 {
                first_slot = id;
            }
            seen[id] = true;
        }
        let slot = first_slot;
        unsafe {
            platform.sync(q.memory.response.address(), 4096);
        }
        platform.barrier();
        let event = InputEvent {
            kind: q.memory.response.get16(slot * 8),
            code: q.memory.response.get16(slot * 8 + 2),
            value: q.memory.response.get32(slot * 8 + 4) as i32,
        };
        q.used = q.used.wrapping_add(1);
        q.memory
            .avail
            .put16(4 + usize::from(q.available % q.size) * 2, slot as u16);
        q.available = q.available.wrapping_add(1);
        platform.barrier();
        q.memory.avail.put16(2, q.available);
        unsafe {
            platform.sync(q.memory.avail.address(), 4096);
        }
        platform.barrier();
        if let Err(error) = transport.notify(q.notification) {
            q.poisoned = true;
            transport.fail();
            return Err(error);
        }
        transport.acknowledge_interrupt();
        Ok(Some(event))
    }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    struct Host;
    // SAFETY: tests use stable boxed storage and manually emulate device writes;
    // no DMA hardware or concurrent accesses exist in these tests.
    unsafe impl Platform for Host {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {}
        fn now_ms(&self) -> u64 {
            0
        }
    }

    #[test]
    fn queue_dma_denial_leaves_device_addresses_unpublished() {
        use core::cell::Cell;

        struct RejectDma(Cell<Option<(usize, u32, u32, u64, usize)>>);
        // SAFETY: the test uses pinned boxed memory and no DMA hardware.
        unsafe impl Platform for RejectDma {
            fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
                Ok(address as u64)
            }
            fn admit_queue_dma(
                &self,
                transport: usize,
                device: u32,
                index: u32,
                pa: u64,
                len: usize,
            ) -> Result<(), Error> {
                self.0.set(Some((transport, device, index, pa, len)));
                Err(Error::Address)
            }
            unsafe fn sync(&self, _: usize, _: usize) {}
            fn barrier(&self) {}
            fn now_ms(&self) -> u64 {
                0
            }
        }

        for batched in [true, false] {
            let platform = RejectDma(Cell::new(None));
            let mmio = Box::leak(Box::new(Page::zeroed()));
            mmio.put32(0, 0x74726976);
            mmio.put32(4, 2);
            mmio.put32(8, 2);
            mmio.put32(0x34, 16);
            let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
            let (result, pa, len) = if batched {
                let memory = Box::leak(Box::new(queue::BatchMemory::zeroed()));
                let pa = memory as *mut _ as u64;
                let result = queue::BatchQueue::configure(&mut transport, memory, 0, &platform);
                (result.err(), pa, size_of::<queue::BatchMemory>())
            } else {
                let memory = Box::leak(Box::new(QueueMemory::zeroed()));
                let pa = memory as *mut _ as u64;
                let result = Queue::configure(&mut transport, memory, 0, &platform);
                (result.err(), pa, size_of::<QueueMemory>())
            };
            assert_eq!(result, Some(Error::Address), "batched={batched}");
            assert_eq!(platform.0.get(), Some((mmio.address(), 2, 0, pa, len)));
            for offset in [0x38, 0x44, 0x80, 0x84, 0x90, 0x94, 0xa0, 0xa4] {
                assert_eq!(mmio.get32(offset), 0);
            }
        }
    }

    #[test]
    fn terminal_mmio_reset_refuses_changed_device_before_writing() {
        let mmio = Box::new(Page::zeroed());
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 4);
        mmio.put32(0x70, 15);
        let region = MappedRegion {
            base: mmio.address(),
            len: 4096,
        };
        // SAFETY: the mock has no other owner and is never resumed.
        assert_eq!(
            unsafe { Transport::terminal_mmio_reset(region, 2, &[0], &Host) },
            Err(Error::Device)
        );
        assert_eq!(mmio.get32(0x70), 15);
    }

    #[test]
    fn terminal_mmio_reset_cannot_certify_a_ready_queue_with_a_frozen_clock() {
        let mmio = Box::new(Page::zeroed());
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 2);
        mmio.put32(0x44, 1);
        mmio.put32(0x70, 15);
        let region = MappedRegion {
            base: mmio.address(),
            len: 4096,
        };
        // SAFETY: the mock has no other owner and is never resumed.
        assert_eq!(
            unsafe { Transport::terminal_mmio_reset(region, 2, &[0], &Host) },
            Err(Error::Timeout)
        );
        assert_eq!(mmio.get32(0x70), 0);
        assert_eq!(mmio.get32(0x44), 1);
    }

    /// Wide request stores must stay byte-exact, including the unaligned head
    /// and tail runs used by the 12-byte virtio-net header offset.
    #[test]
    fn wide_request_copies_preserve_bytes_at_unaligned_offsets() {
        let page = Box::leak(Box::new(Page::zeroed()));
        let mut source = [0u8; 300];
        for (index, byte) in source.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        let mut back = std::vec![0u8; 4096];
        for offset in [0usize, 1, 7, 12] {
            for len in [0usize, 1, 7, 8, 9, 15, 16, 300] {
                page.clear_prefix(4096);
                page.copy_prefix_from(offset, &source[..len]);
                page.copy_prefix_to(&mut back, 4096);
                assert_eq!(
                    &back[offset..offset + len],
                    &source[..len],
                    "offset={offset} len={len}"
                );
                assert!(
                    back[..offset].iter().all(|v| *v == 0),
                    "wrote before offset"
                );
                assert!(
                    back[offset + len..].iter().all(|v| *v == 0),
                    "wrote past the prefix"
                );
            }
        }
    }

    fn fixture() -> (Transport, Queue) {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(0x34, 8);
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let queue = Queue::configure(
            &mut transport,
            Box::leak(Box::new(QueueMemory::zeroed())),
            0,
            &Host,
        )
        .unwrap();
        (transport, queue)
    }
    #[test]
    fn busy_chain_and_completion() {
        let (mut t, mut q) = fixture();
        q.submit(&mut t, b"request", 8, &Host).unwrap();
        assert_eq!(q.submit(&mut t, b"second", 8, &Host), Err(Error::Busy));
        q.memory.response.put32(0, 0x12345678);
        q.memory.used.put32(4, 0);
        q.memory.used.put32(8, 4);
        q.memory.used.put16(2, 1);
        let mut output = [0; 8];
        assert_eq!(q.poll(&mut t, &mut output, &Host), Ok(Some(4)));
        assert_eq!(&output[..4], &0x12345678u32.to_le_bytes());
        assert_eq!(q.poll(&mut t, &mut output, &Host), Ok(None));
    }
    #[test]
    fn single_chain_unsolicited_or_duplicate_completion_cannot_authorize_reuse() {
        for prior_completion in [false, true] {
            let (mut t, mut q) = fixture();
            if prior_completion {
                q.submit(&mut t, b"first", 8, &Host).unwrap();
                q.memory.used.put32(4, 0);
                q.memory.used.put32(8, 8);
                q.memory.used.put16(2, 1);
                assert_eq!(q.poll(&mut t, &mut [0; 8], &Host), Ok(Some(8)));
            }
            let index = q.used;
            let before = q.available;
            let at = 4 + usize::from(index % q.size) * 8;
            q.memory.used.put32(at, 0);
            q.memory.used.put32(at + 4, 8);
            q.memory.used.put16(2, index.wrapping_add(1));
            assert_eq!(q.submit(&mut t, b"next", 8, &Host), Err(Error::Queue));
            assert_eq!(q.available, before);
            assert_eq!(q.memory.avail.get16(2), before);
            assert!(!q.pending);
            assert_eq!(q.poll(&mut t, &mut [0; 8], &Host), Err(Error::Device));
        }
    }
    #[test]
    fn idle_poll_quarantines_unsolicited_used_index() {
        let (mut t, mut q) = fixture();
        q.memory.used.put16(2, 1);
        assert_eq!(q.poll(&mut t, &mut [0; 8], &Host), Err(Error::Queue));
        assert_eq!(q.submit(&mut t, b"x", 8, &Host), Err(Error::Device));
    }
    #[test]
    fn single_chain_wide_copy_preserves_odd_length_and_output_tail() {
        let (mut t, mut q) = fixture();
        q.submit(&mut t, b"x", 32, &Host).unwrap();
        for i in 0..19 {
            q.memory.response.put8(i, (i as u8).wrapping_mul(13));
        }
        q.memory.used.put32(4, 0);
        q.memory.used.put32(8, 19);
        q.memory.used.put16(2, 1);
        let mut out = [0xcc; 32];
        assert_eq!(q.poll(&mut t, &mut out, &Host), Ok(Some(19)));
        for (i, b) in out[..19].iter().enumerate() {
            assert_eq!(*b, (i as u8).wrapping_mul(13));
        }
        assert!(out[19..].iter().all(|b| *b == 0xcc));
    }

    #[test]
    fn completion_metadata_is_resynchronized_after_index_acquire() {
        use core::cell::Cell;
        struct Cached {
            used: usize,
            synchronizations: Cell<usize>,
        }
        // SAFETY: synchronous single-threaded emulation of pinned queue memory.
        unsafe impl Platform for Cached {
            fn physical(&self, p: usize, _: usize) -> Result<u64, Error> {
                Ok(p as u64)
            }
            unsafe fn sync(&self, p: usize, _: usize) {
                if p == self.used {
                    let count = self.synchronizations.get() + 1;
                    self.synchronizations.set(count);
                    if count == 2 {
                        // Device metadata becomes visible only on post-index sync.
                        unsafe {
                            core::ptr::write_volatile((p + 8) as *mut u32, 4_u32.to_le());
                        }
                    }
                }
            }
            fn barrier(&self) {}
            fn now_ms(&self) -> u64 {
                0
            }
        }
        let (mut t, mut q) = fixture();
        q.submit(&mut t, b"request", 8, &Host).unwrap();
        q.memory.response.put32(0, 0x12345678);
        q.memory.used.put32(8, 999); // stale cache line before index publication
        q.memory.used.put16(2, 1);
        let host = Cached {
            used: q.memory.used.address(),
            synchronizations: Cell::new(0),
        };
        let mut output = [0; 8];
        assert_eq!(q.poll(&mut t, &mut output, &host), Ok(Some(4)));
        assert_eq!(&output[..4], &0x12345678_u32.to_le_bytes());
        assert_eq!(host.synchronizations.get(), 2);
    }
    #[test]
    fn invalid_used_length_quarantines_queue() {
        let (mut t, mut q) = fixture();
        q.submit(&mut t, b"x", 8, &Host).unwrap();
        q.memory.used.put32(8, 9);
        q.memory.used.put16(2, 1);
        assert_eq!(q.poll(&mut t, &mut [0; 8], &Host), Err(Error::Queue));
        assert_eq!(q.submit(&mut t, b"x", 8, &Host), Err(Error::Device));
    }
    #[test]
    fn event_report_can_have_multiple_buffers() {
        let (mut t, q) = fixture();
        let mut e = EventQueue::prime(q, &mut t, &Host).unwrap();
        for slot in 0..2 {
            e.queue.memory.used.put32(4 + slot * 8, slot as u32);
            e.queue.memory.used.put32(8 + slot * 8, 8);
        }
        e.queue.memory.response.put16(0, 1);
        e.queue.memory.response.put16(2, 30);
        e.queue.memory.response.put32(4, 1);
        e.queue.memory.used.put16(2, 2);
        assert_eq!(
            e.poll(&mut t, &Host),
            Ok(Some(InputEvent {
                kind: 1,
                code: 30,
                value: 1
            }))
        );
        assert_eq!(
            e.poll(&mut t, &Host),
            Ok(Some(InputEvent {
                kind: 0,
                code: 0,
                value: 0
            }))
        );
        assert_eq!(e.poll(&mut t, &Host), Ok(None));
    }
    #[test]
    fn pointer_burst_retains_all_motion_when_device_has_more_ring_capacity() {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 18); // Actual VirtIO input device, not a request/response queue.
        mmio.put32(0x34, 128);
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let memory = Box::leak(Box::new(QueueMemory::zeroed()));
        let queue = Queue::configure(&mut transport, memory, 0, &Host).unwrap();
        let mut events = EventQueue::prime(queue, &mut transport, &Host).unwrap();
        // Real input devices cannot retain host reports without posted buffers.
        // The device boundary writes only the buffers this driver advertised.
        let posted = events.queue.memory.avail.get16(2) as usize;
        let delivered = posted.min(24 * 2);
        for index in 0..delivered {
            let slot = events.queue.memory.avail.get16(4 + index * 2) as usize;
            events
                .queue
                .memory
                .response
                .put16(slot * 8, if index % 2 == 0 { 2 } else { 0 });
            events.queue.memory.response.put16(slot * 8 + 2, 0);
            events
                .queue
                .memory
                .response
                .put32(slot * 8 + 4, if index % 2 == 0 { 8 } else { 0 });
            events.queue.memory.used.put32(4 + index * 8, slot as u32);
            events.queue.memory.used.put32(8 + index * 8, 8);
        }
        events.queue.memory.used.put16(2, delivered as u16);
        let mut delta = 0;
        let mut reports = 0;
        while let Some(event) = events.poll(&mut transport, &Host).unwrap() {
            if event.kind == 2 {
                delta += event.value;
            }
            if event.kind == 0 && event.code == 0 {
                reports += 1;
            }
        }
        assert_eq!(
            delta, 192,
            "driver lost motion before the software input buffer"
        );
        assert_eq!(reports, 24);
        assert_eq!(core::mem::size_of::<QueueMemory>(), 5 * 4096);
    }
    fn input_fixture(maximum: u32) -> (Transport, EventQueue, &'static Page) {
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 18);
        mmio.put32(0x34, maximum);
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let queue = Queue::configure(
            &mut transport,
            Box::leak(Box::new(QueueMemory::zeroed())),
            0,
            &Host,
        )
        .unwrap();
        let events = EventQueue::prime(queue, &mut transport, &Host).unwrap();
        (transport, events, mmio)
    }
    #[test]
    fn input_ring_respects_device_limits_without_growing_dma_storage() {
        for (maximum, expected) in [(8, 8), (12, 8), (16, 16), (31, 16), (64, 64), (128, 64)] {
            let (_, queue, mmio) = input_fixture(maximum);
            assert_eq!(mmio.get32(0x38), expected);
            assert_eq!(queue.queue.memory.avail.get16(2), expected as u16);
        }
        let (mut t, mut q) = fixture();
        q.submit(&mut t, b"gpu-like request", 8, &Host).unwrap();
        assert_eq!(q.size, 8);
        assert_eq!(core::mem::size_of::<QueueMemory>(), 20_480);
    }
    #[test]
    fn large_input_ring_still_rejects_duplicate_ids_bad_lengths_and_overruns() {
        for scenario in 0..4 {
            let (mut t, mut e, _) = input_fixture(64);
            let published = e.queue.available;
            e.queue
                .memory
                .used
                .put32(4, if scenario == 0 { 64 } else { 63 });
            e.queue
                .memory
                .used
                .put32(8, if scenario == 1 { 9 } else { 8 });
            e.queue.memory.used.put32(12, 63);
            e.queue.memory.used.put32(16, 8);
            e.queue.memory.used.put16(
                2,
                match scenario {
                    2 => 2,
                    3 => 65,
                    _ => 1,
                },
            );
            assert_eq!(e.poll(&mut t, &Host), Err(Error::Queue));
            assert_eq!(
                e.queue.available, published,
                "invalid device metadata reposted a buffer"
            );
            assert_eq!(e.poll(&mut t, &Host), Err(Error::Device));
        }
    }
    #[test]
    fn large_input_ring_keeps_signed_values_and_wraps_16_bit_indices() {
        let (mut t, mut e, _) = input_fixture(64);
        e.queue.used = u16::MAX;
        e.queue.available = 63;
        e.queue.memory.used.put32(4 + 63 * 8, 63);
        e.queue.memory.used.put32(8 + 63 * 8, 8);
        e.queue.memory.used.put16(2, 0);
        e.queue.memory.response.put16(63 * 8, 2);
        e.queue.memory.response.put32(63 * 8 + 4, (-7i32) as u32);
        assert_eq!(
            e.poll(&mut t, &Host),
            Ok(Some(InputEvent {
                kind: 2,
                code: 0,
                value: -7
            }))
        );
        assert_eq!(e.queue.used, 0);
        assert_eq!(e.queue.available, 64);
        assert_eq!(e.poll(&mut t, &Host), Ok(None));
    }
    #[test]
    fn duplicate_event_id_fails_before_repost() {
        let (mut t, q) = fixture();
        let mut e = EventQueue::prime(q, &mut t, &Host).unwrap();
        e.queue.memory.used.put32(8, 8);
        e.queue.memory.used.put32(16, 8);
        e.queue.memory.used.put16(2, 2);
        assert_eq!(e.poll(&mut t, &Host), Err(Error::Queue));
    }
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    use core::cell::Cell;
    use std::boxed::Box;
    struct Clock(Cell<u64>);
    // SAFETY: boxed test memory is stable, with no concurrent device accesses.
    unsafe impl Platform for Clock {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {}
        fn now_ms(&self) -> u64 {
            let now = self.0.get();
            self.0.set(now + 100);
            now
        }
    }
    fn fixture() -> (Transport, Queue, Clock) {
        let clock = Clock(Cell::new(0));
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(0x34, 8);
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let queue = Queue::configure(
            &mut transport,
            Box::leak(Box::new(QueueMemory::zeroed())),
            0,
            &clock,
        )
        .unwrap();
        (transport, queue, clock)
    }
    #[test]
    fn timeout_prevents_reuse() {
        let (mut t, mut q, c) = fixture();
        assert_eq!(
            q.transact(&mut t, b"x", &mut [0; 8], &c),
            Err(Error::Timeout)
        );
        assert_eq!(q.submit(&mut t, b"again", 8, &c), Err(Error::Device));
    }
    #[test]
    fn malformed_head_and_index_are_rejected() {
        for (head, index) in [(1, 1), (0, 2), (u32::MAX, 1)] {
            let (mut t, mut q, c) = fixture();
            q.submit(&mut t, b"x", 8, &c).unwrap();
            q.memory.used.put32(4, head);
            q.memory.used.put32(8, 8);
            q.memory.used.put16(2, index);
            assert_eq!(q.poll(&mut t, &mut [0; 8], &c), Err(Error::Queue));
        }
    }
    #[test]
    fn ring_index_wrap_keeps_descriptor_ownership() {
        let (mut t, mut q, c) = fixture();
        q.available = u16::MAX;
        q.used = u16::MAX;
        q.memory.used.put16(2, u16::MAX); // device and driver agree before publication
        q.submit(&mut t, b"x", 8, &c).unwrap();
        q.memory.used.put32(4 + 7 * 8, 0);
        q.memory.used.put32(8 + 7 * 8, 8);
        q.memory.used.put16(2, 0);
        assert_eq!(q.poll(&mut t, &mut [0; 8], &c), Ok(Some(8)));
        assert_eq!(q.available, 0);
        assert_eq!(q.used, 0);
    }
    #[test]
    fn input_out_of_range_id_does_not_read_outside_pool() {
        let (mut t, q, c) = fixture();
        let mut events = EventQueue::prime(q, &mut t, &c).unwrap();
        events.queue.memory.used.put32(4, u32::MAX);
        events.queue.memory.used.put32(8, 8);
        events.queue.memory.used.put16(2, 1);
        assert_eq!(events.poll(&mut t, &c), Err(Error::Queue));
    }
    #[test]
    fn invalid_mmio_and_unnegotiated_version_rejected() {
        let mmio = Box::new(Page::zeroed());
        assert!(matches!(
            unsafe { Transport::attach(mmio.address(), 4) },
            Err(Error::Address)
        ));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 1);
        assert!(matches!(
            unsafe { Transport::attach(mmio.address(), 4096) },
            Err(Error::Unsupported)
        ));
        mmio.put32(4, 2);
        let mut t = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        assert_eq!(t.negotiate(&Clock(Cell::new(0))), Err(Error::Features));
    }
}
