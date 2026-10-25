#![no_std]
//! Modern VirtIO MMIO, one outstanding split-ring chain per queue.
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
pub mod rng;
pub mod snapshot;

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
/// DMA addresses must identify the supplied pinned memory for its complete lifetime;
/// cache maintenance and barriers must cover CPU/device ownership transitions.
pub unsafe trait Platform {
    fn physical(&self, address: usize, len: usize) -> Result<u64, Error>;
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
        for index in 0..4096 {
            self.put8(index, 0);
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

pub struct Transport {
    base: usize,
}
impl Transport {
    /// # Safety
    /// `base..base+len` must be an exclusively owned, mapped Device-memory
    /// VirtIO MMIO resource. Caller serializes all queue/configuration access.
    pub unsafe fn attach(base: usize, len: usize) -> Result<Self, Error> {
        if !base.is_multiple_of(4) || len < 0x200 || base.checked_add(len).is_none() {
            return Err(Error::Address);
        }
        let s = Self { base };
        if s.read(0) != 0x74726976 || s.read(4) != 2 {
            return Err(Error::Unsupported);
        }
        Ok(s)
    }
    fn read(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }
    fn write(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }
    pub fn device_id(&self) -> u32 {
        self.read(8)
    }
    pub fn negotiate(&mut self, platform: &impl Platform) -> Result<(), Error> {
        self.write(0x70, 0);
        platform.barrier();
        let start = platform.now_ms();
        while self.read(0x70) != 0 {
            if platform.now_ms().wrapping_sub(start) >= 100 {
                return Err(Error::Timeout);
            }
        }
        self.write(0x70, 1 | 2);
        self.write(0x14, 1);
        if self.read(0x10) & 1 == 0 {
            self.fail();
            return Err(Error::Features);
        }
        self.write(0x24, 0);
        self.write(0x20, 0);
        self.write(0x24, 1);
        self.write(0x20, 1); // VERSION_1 only
        self.write(0x70, 1 | 2 | 8);
        platform.barrier();
        if self.read(0x70) & (8 | 64 | 128) != 8 {
            self.fail();
            return Err(Error::Features);
        }
        Ok(())
    }
    pub fn start(&mut self, platform: &impl Platform) -> Result<(), Error> {
        self.write(0x70, 1 | 2 | 8 | 4);
        platform.barrier();
        if self.read(0x70) != 15 {
            self.fail();
            return Err(Error::Device);
        }
        Ok(())
    }
    pub fn fail(&mut self) {
        self.write(0x70, self.read(0x70) | 128);
    }
    fn check(&self) -> Result<(), Error> {
        if self.read(0x70) & (64 | 128) != 0 {
            Err(Error::Device)
        } else {
            Ok(())
        }
    }
    fn address(&self, offset: usize, value: u64) {
        self.write(offset, value as u32);
        self.write(offset + 4, (value >> 32) as u32);
    }
}

/// DMA buffers are permanently reserved, including after timeout or Drop.
/// This deliberately quarantines failed devices instead of reusing in-flight pages.
pub struct Queue {
    memory: &'static mut QueueMemory,
    index: u32,
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
        transport.write(0x30, index);
        if transport.read(0x44) != 0 || transport.read(0x34) < 8 {
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
        memory.avail.put16(0, 1); // Polling: NO_INTERRUPT, still acknowledge delivered IRQ status.
        unsafe {
            platform.sync(memory as *mut _ as usize, size);
        }
        transport.write(0x38, 8);
        transport.address(0x80, pa);
        transport.address(0x90, pa + 4096);
        transport.address(0xa0, pa + 8192);
        platform.barrier();
        transport.write(0x44, 1);
        Ok(Self {
            memory,
            index,
            available: 0,
            used: 0,
            writable: 0,
            pending: false,
            poisoned: false,
        })
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
        let m = &self.memory;
        let response_pa = platform.physical(m.response.address(), 4096)?;
        let request_pa = platform.physical(m.request.address(), 4096)?;
        for (i, byte) in request.iter().enumerate() {
            m.request.put8(i, *byte);
        }
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
        m.avail.put16(4 + usize::from(self.available % 8) * 2, 0);
        self.available = self.available.wrapping_add(1);
        platform.barrier();
        m.avail.put16(2, self.available);
        unsafe {
            platform.sync(m.avail.address(), 4096);
        }
        platform.barrier();
        transport.write(0x50, self.index);
        self.writable = writable as u32;
        self.pending = true;
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
        let at = 4 + usize::from(self.used % 8) * 8;
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
        for (i, byte) in output[..length as usize].iter_mut().enumerate() {
            *byte = unsafe { read_volatile((m.response.address() + i) as *const u8) };
        }
        let irq = transport.read(0x60);
        transport.write(0x64, irq & 3);
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

/// Eight independently posted event buffers: one keyboard/mouse report may
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
        let pa = platform.physical(queue.memory.response.address(), 4096)?;
        for slot in 0..8 {
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
        queue.memory.avail.put16(2, 8);
        unsafe {
            platform.sync(queue.memory.avail.address(), 4096);
        }
        platform.barrier();
        transport.write(0x50, queue.index);
        queue.available = 8;
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
        if count > 8 {
            q.poisoned = true;
            transport.fail();
            return Err(Error::Queue);
        }
        let mut seen = [false; 8];
        let mut first_slot = 0;
        for n in 0..count {
            let offset = 4 + usize::from(q.used.wrapping_add(n as u16) % 8) * 8;
            let id = q.memory.used.get32(offset) as usize;
            if id >= 8 || seen[id] || q.memory.used.get32(offset + 4) != 8 {
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
            .put16(4 + usize::from(q.available % 8) * 2, slot as u16);
        q.available = q.available.wrapping_add(1);
        platform.barrier();
        q.memory.avail.put16(2, q.available);
        unsafe {
            platform.sync(q.memory.avail.address(), 4096);
        }
        platform.barrier();
        transport.write(0x50, q.index);
        let irq = transport.read(0x60);
        transport.write(0x64, irq & 3);
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
