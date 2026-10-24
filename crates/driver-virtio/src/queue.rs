//! Independent pinned split-ring chains, with one publication per bounded batch.
//! Prepared chains are private; published/unknown chains are never cancelled.
use crate::{Error, Page, Platform, Transport};

pub const MAX_CHAINS: usize = 8;
pub const MAX_DELAY_NS: u64 = 50_000;
#[repr(C, align(4096))]
pub struct BatchMemory {
    desc: Page,
    avail: Page,
    used: Page,
    request: [Page; MAX_CHAINS],
    response: [Page; MAX_CHAINS],
}
impl BatchMemory {
    pub const fn zeroed() -> Self {
        Self {
            desc: Page::zeroed(),
            avail: Page::zeroed(),
            used: Page::zeroed(),
            request: [const { Page::zeroed() }; MAX_CHAINS],
            response: [const { Page::zeroed() }; MAX_CHAINS],
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Token {
    pub slot: u8,
    pub generation: u64,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum State {
    Free,
    Private,
    Published,
    Complete,
}
#[derive(Clone, Copy)]
struct Slot {
    state: State,
    generation: u64,
    writable: u32,
    descriptors: u16,
    version: u64,
    started: u64,
}
const EMPTY: Slot = Slot {
    state: State::Free,
    generation: 0,
    writable: 0,
    descriptors: 0,
    version: 0,
    started: 0,
};
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NotifyStats {
    pub published: u64,
    pub completed: u64,
    pub doorbells: u64,
    pub max_batch: u8,
    pub pending: u8,
    pub inflight: u8,
    pub descriptors: u16,
    pub errors: u64,
    /// Highest policy version whose private, DMA, or completion custody is live.
    pub pending_version: u64,
    pub last_published_version: u64,
    pub last_completed_version: u64,
}
#[derive(Clone, Copy)]
pub struct NotifyPolicy {
    pub batch: u8,
    pub version: u64,
    pub until_ns: u64,
}
pub type NotifyRequest = fn(u64) -> Option<NotifyPolicy>;
pub type NotifyFeedback = fn(NotifyStats, u64, bool);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    pub token: Token,
    pub len: usize,
    pub version: u64,
    pub latency_ns: u64,
}

pub struct BatchQueue {
    memory: &'static mut BatchMemory,
    index: u32,
    size: u16,
    available: u16,
    used: u16,
    slots: [Slot; MAX_CHAINS],
    private: [Option<Token>; MAX_CHAINS],
    count: usize,
    first: u64,
    batch: u8,
    version: u64,
    until: u64,
    frozen_batch: u8,
    frozen_version: u64,
    stats: NotifyStats,
    poisoned: bool,
}
impl BatchQueue {
    pub fn configure(
        t: &mut Transport,
        memory: &'static mut BatchMemory,
        index: u32,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        t.write(0x30, index);
        p.barrier();
        let max = t.read(0x34);
        if t.read(0x44) != 0 || max < 2 {
            return Err(Error::Queue);
        }
        let size = if max >= 16 {
            16
        } else if max >= 8 {
            8
        } else if max >= 4 {
            4
        } else {
            2
        };
        let bytes = core::mem::size_of::<BatchMemory>();
        let pa = p.physical(memory as *mut _ as usize, bytes)?;
        if !pa.is_multiple_of(4096) || pa.checked_add(bytes as u64).is_none() {
            return Err(Error::Address);
        }
        memory.desc.clear();
        memory.avail.clear();
        memory.used.clear();
        for v in &mut memory.request {
            v.clear();
        }
        for v in &mut memory.response {
            v.clear();
        }
        memory.avail.put16(0, 1);
        unsafe { p.sync(memory as *mut _ as usize, bytes) };
        t.write(0x38, size);
        t.address(0x80, pa);
        t.address(0x90, pa + 4096);
        t.address(0xa0, pa + 8192);
        p.barrier();
        t.write(0x44, 1);
        p.barrier();
        if t.read(0x44) != 1 {
            return Err(Error::Queue);
        }
        Ok(Self {
            memory,
            index,
            size: size as u16,
            available: 0,
            used: 0,
            slots: [EMPTY; MAX_CHAINS],
            private: [None; MAX_CHAINS],
            count: 0,
            first: 0,
            batch: 1,
            version: 0,
            until: 0,
            frozen_batch: 1,
            frozen_version: 0,
            stats: NotifyStats::default(),
            poisoned: false,
        })
    }
    pub fn capacity(&self) -> usize {
        usize::from(self.size / 2)
    }
    pub fn free(&self) -> usize {
        self.slots[..self.capacity()]
            .iter()
            .filter(|s| s.state == State::Free && s.generation != u64::MAX)
            .count()
    }
    pub fn stats(&self) -> NotifyStats {
        let mut s = self.stats;
        s.pending = self.count as u8;
        s.inflight = self
            .slots
            .iter()
            .filter(|s| s.state == State::Published)
            .count() as u8;
        s.descriptors = self
            .slots
            .iter()
            .filter(|v| v.state != State::Free)
            .map(|v| v.descriptors)
            .sum();
        s.pending_version = self
            .slots
            .iter()
            .filter(|v| v.state != State::Free)
            .map(|v| v.version)
            .max()
            .unwrap_or(0);
        s
    }
    pub fn current_batch(&self, now: u64) -> u8 {
        if now < self.until { self.batch } else { 1 }
    }
    pub fn install(&mut self, batch: u8, version: u64, until: u64, now: u64) -> Result<(), Error> {
        if !matches!(batch, 1 | 2 | 4 | 8) || usize::from(batch) > self.capacity() {
            return Err(Error::Exhausted);
        }
        if version == 0 || until <= now {
            return Err(Error::Address);
        }
        if version < self.version {
            return Err(Error::Response);
        }
        if version == self.version && (batch != self.batch || until != self.until) {
            return Err(Error::Response);
        }
        self.batch = batch;
        self.version = version;
        self.until = until;
        Ok(())
    }
    pub fn set_completion_interrupts(&mut self, enabled: bool, p: &impl Platform) {
        self.memory.avail.put16(0, if enabled { 0 } else { 1 });
        unsafe { p.sync(self.memory.avail.address(), 4096) };
        p.barrier();
    }
    pub fn poison(&mut self, t: &mut Transport, p: &impl Platform) {
        if !self.poisoned {
            self.stats.errors = self.stats.errors.saturating_add(1);
        }
        self.poisoned = true;
        t.fail();
        p.barrier();
    }
    fn slot(&self, t: Token) -> Result<&Slot, Error> {
        self.slots
            .get(usize::from(t.slot))
            .filter(|s| s.state != State::Free && s.generation == t.generation)
            .ok_or(Error::Response)
    }
    fn validate_returned(&mut self, t: &mut Transport, p: &impl Platform) -> Result<(), Error> {
        unsafe { p.sync(self.memory.used.address(), 4096) };
        p.barrier();
        let end = self.memory.used.get16(2);
        let delta = end.wrapping_sub(self.used);
        if delta == 0 {
            return Ok(());
        }
        p.barrier();
        unsafe { p.sync(self.memory.used.address(), 4096) };
        p.barrier();
        let owned = self
            .slots
            .iter()
            .filter(|s| s.state == State::Published)
            .count();
        let mut seen = 0u16;
        if usize::from(delta) > owned {
            self.poison(t, p);
            return Err(Error::Queue);
        }
        for n in 0..delta {
            let at = 4 + usize::from(self.used.wrapping_add(n) % self.size) * 8;
            let id = self.memory.used.get32(at);
            let len = self.memory.used.get32(at + 4);
            if id % 2 != 0 || id >= u32::from(self.size) {
                self.poison(t, p);
                return Err(Error::Queue);
            }
            let index = id as usize / 2;
            if seen & (1 << index) != 0
                || self.slots[index].state != State::Published
                || len > self.slots[index].writable
            {
                self.poison(t, p);
                return Err(Error::Queue);
            }
            seen |= 1 << index;
        }
        Ok(())
    }
    pub fn enqueue(
        &mut self,
        t: &mut Transport,
        request: &[u8],
        writable: usize,
        synchronous: bool,
        isolated: bool,
        p: &impl Platform,
    ) -> Result<Token, Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        if t.read(0x70) != 15 {
            self.poison(t, p);
            return Err(Error::Device);
        }
        if request.len() > 4096 || writable > 4096 || (request.is_empty() && writable == 0) {
            return Err(Error::Address);
        }
        // A stale used head must be rejected before its descriptor can become
        // live again under a new generation, including across partial drains.
        self.validate_returned(t, p)?;
        self.flush_due(t, p)?;
        let at = self.slots[..self.capacity()]
            .iter()
            .position(|s| s.state == State::Free && s.generation != u64::MAX)
            .ok_or(Error::Busy)?;
        let m = &self.memory;
        let request_pa = p.physical(m.request[at].address(), 4096)?;
        let response_pa = p.physical(m.response[at].address(), 4096)?;
        for (i, b) in request.iter().enumerate() {
            m.request[at].put8(i, *b);
        }
        for i in 0..writable {
            m.response[at].put8(i, 0xff);
        }
        let head = at * 2;
        let desc = head * 16;
        if !request.is_empty() {
            m.desc.put64(desc, request_pa);
            m.desc.put32(desc + 8, request.len() as u32);
            m.desc.put16(desc + 12, if writable == 0 { 0 } else { 1 });
            m.desc.put16(desc + 14, (head + 1) as u16);
        }
        if writable != 0 {
            let d = desc + if request.is_empty() { 0 } else { 16 };
            m.desc.put64(d, response_pa);
            m.desc.put32(d + 8, writable as u32);
            m.desc.put16(d + 12, 2);
            m.desc.put16(d + 14, 0);
        }
        unsafe {
            p.sync(m.request[at].address(), 4096);
            p.sync(m.response[at].address(), 4096);
            p.sync(m.desc.address(), 4096)
        };
        let now = p.now_ns();
        if self.count == 0 {
            self.first = now;
            self.frozen_batch = self.current_batch(now);
            self.frozen_version = if now < self.until { self.version } else { 0 };
        }
        self.slots[at].generation += 1;
        let token = Token {
            slot: at as u8,
            generation: self.slots[at].generation,
        };
        self.slots[at] = Slot {
            state: State::Private,
            generation: token.generation,
            writable: writable as u32,
            descriptors: u16::from(!request.is_empty()) + u16::from(writable != 0),
            version: self.frozen_version,
            started: now,
        };
        self.private[self.count] = Some(token);
        self.count += 1;
        if synchronous
            || isolated
            || self.count >= usize::from(self.frozen_batch)
            || now.saturating_sub(self.first) >= MAX_DELAY_NS
        {
            self.drain(t, p)?;
        }
        Ok(token)
    }
    pub fn flush_due(&mut self, t: &mut Transport, p: &impl Platform) -> Result<(), Error> {
        if self.count != 0 && p.now_ns().saturating_sub(self.first) >= MAX_DELAY_NS {
            self.drain(t, p)?;
        }
        Ok(())
    }
    /// End of a producer turn: publish a partial batch, never wait for its peers.
    pub fn drain(&mut self, t: &mut Transport, p: &impl Platform) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        if self.count == 0 {
            return Ok(());
        }
        if t.read(0x70) != 15 {
            self.poison(t, p);
            return Err(Error::Device);
        }
        let count = self.count;
        for i in 0..count {
            let token = self.private[i].unwrap();
            let s = &mut self.slots[usize::from(token.slot)];
            if s.state != State::Private || s.generation != token.generation {
                self.poison(t, p);
                return Err(Error::Queue);
            }
            self.memory.avail.put16(
                4 + usize::from(self.available % self.size) * 2,
                u16::from(token.slot) * 2,
            );
            self.available = self.available.wrapping_add(1);
            s.state = State::Published;
        }
        // Publish complete ring elements before the release of avail.idx.
        unsafe { p.sync(self.memory.avail.address(), 4096) };
        p.barrier();
        self.memory.avail.put16(2, self.available);
        unsafe { p.sync(self.memory.avail.address(), 4096) };
        p.barrier();
        unsafe { p.sync(self.memory.used.address(), 4096) };
        p.barrier();
        if self.memory.used.get16(0) & 1 == 0 {
            t.write(0x50, self.index);
            p.barrier();
            self.stats.doorbells = self.stats.doorbells.saturating_add(1);
        }
        self.stats.published = self.stats.published.saturating_add(count as u64);
        self.stats.max_batch = self.stats.max_batch.max(count as u8);
        self.stats.last_published_version = self.frozen_version;
        self.private.fill(None);
        self.count = 0;
        Ok(())
    }
    /// Consume one validated used record. DMA custody remains until release.
    pub fn poll(
        &mut self,
        t: &mut Transport,
        out: &mut [u8],
        p: &impl Platform,
    ) -> Result<Option<Completion>, Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        if t.read(0x70) != 15 {
            self.poison(t, p);
            return Err(Error::Device);
        }
        self.flush_due(t, p)?;
        unsafe { p.sync(self.memory.used.address(), 4096) };
        p.barrier();
        let end = self.memory.used.get16(2);
        if end == self.used {
            let irq = t.read(0x60);
            t.write(0x64, irq & 3);
            p.barrier();
            return Ok(None);
        }
        p.barrier();
        let at = 4 + usize::from(self.used % self.size) * 8;
        unsafe { p.sync(self.memory.used.address() + at, 8) };
        p.barrier();
        let id = self.memory.used.get32(at);
        let len = self.memory.used.get32(at + 4);
        let owned = self
            .slots
            .iter()
            .filter(|s| s.state == State::Published)
            .count();
        if usize::from(end.wrapping_sub(self.used)) > owned
            || id % 2 != 0
            || id >= u32::from(self.size)
        {
            self.poison(t, p);
            return Err(Error::Queue);
        }
        let index = id as usize / 2;
        let s = self.slots[index];
        if s.state != State::Published || len > s.writable {
            self.poison(t, p);
            return Err(Error::Queue);
        }
        if out.len() < len as usize {
            return Err(Error::Address);
        }
        unsafe { p.sync(self.memory.response[index].address(), 4096) };
        p.barrier();
        for (i, b) in out[..len as usize].iter_mut().enumerate() {
            *b = unsafe {
                core::ptr::read_volatile((self.memory.response[index].address() + i) as *const u8)
            };
        }
        self.slots[index].state = State::Complete;
        self.used = self.used.wrapping_add(1);
        self.stats.completed = self.stats.completed.saturating_add(1);
        self.stats.last_completed_version = self.stats.last_completed_version.max(s.version);
        let irq = t.read(0x60);
        t.write(0x64, irq & 3);
        p.barrier();
        Ok(Some(Completion {
            token: Token {
                slot: index as u8,
                generation: s.generation,
            },
            len: len as usize,
            version: s.version,
            latency_ns: p.now_ns().saturating_sub(s.started),
        }))
    }
    pub fn release(&mut self, token: Token) -> Result<(), Error> {
        if self.slot(token)?.state != State::Complete {
            return Err(Error::Busy);
        }
        let at = usize::from(token.slot);
        for i in 0..4096 {
            self.memory.request[at].put8(i, 0);
            self.memory.response[at].put8(i, 0);
        }
        self.slots[at].state = State::Free;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
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
    fn fixture(max: u32) -> (BatchQueue, Transport, Host) {
        let p = Host(Cell::new(0));
        let m = Box::leak(Box::new(Page::zeroed()));
        m.put32(0, 0x74726976);
        m.put32(4, 2);
        m.put32(8, 2);
        m.put32(0x34, max);
        m.put32(0x70, 15);
        let mut t = unsafe { Transport::attach(m.address(), 4096).unwrap() };
        let q = BatchQueue::configure(&mut t, Box::leak(Box::new(BatchMemory::zeroed())), 0, &p)
            .unwrap();
        (q, t, p)
    }
    fn used(q: &mut BatchQueue, id: u32, len: u32) {
        let index = q.memory.used.get16(2);
        let at = 4 + usize::from(index % q.size) * 8;
        q.memory.used.put32(at, id);
        q.memory.used.put32(at + 4, len);
        q.memory.used.put16(2, index.wrapping_add(1));
    }
    #[test]
    fn four_chains_one_publish_and_out_of_order_custody() {
        let (mut q, mut t, p) = fixture(16);
        q.install(4, 7, 1_000_000, 0).unwrap();
        let mut tokens = [Token {
            slot: 0,
            generation: 0,
        }; 4];
        for (i, v) in tokens.iter_mut().enumerate() {
            *v = q.enqueue(&mut t, &[i as u8], 1, false, false, &p).unwrap();
            assert_eq!(q.memory.avail.get16(2), if i == 3 { 4 } else { 0 });
        }
        assert_eq!(q.stats().doorbells, 1);
        assert_eq!(q.stats().last_completed_version, 0);
        assert_eq!(q.free(), 4);
        used(&mut q, 6, 1);
        used(&mut q, 0, 1);
        let c = q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap();
        assert_eq!(c.token, tokens[3]);
        assert_eq!(c.version, 7);
        assert_eq!(q.free(), 4);
        q.release(c.token).unwrap();
        assert_eq!(q.free(), 5);
        assert_eq!(q.release(tokens[1]), Err(Error::Busy));
        assert_eq!(
            q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap().token,
            tokens[0]
        );
    }
    #[test]
    fn first_deadline_sync_and_isolated_never_wait_for_threshold() {
        let (mut q, mut t, p) = fixture(16);
        q.install(8, 1, 1_000_000, 0).unwrap();
        q.enqueue(&mut t, &[1], 1, false, false, &p).unwrap();
        p.0.set(49_999);
        q.flush_due(&mut t, &p).unwrap();
        assert_eq!(q.stats().published, 0);
        p.0.set(50_000);
        q.flush_due(&mut t, &p).unwrap();
        assert_eq!(q.stats().published, 1);
        q.enqueue(&mut t, &[2], 1, true, false, &p).unwrap();
        q.enqueue(&mut t, &[3], 1, false, true, &p).unwrap();
        assert_eq!(q.stats().published, 3);
        assert_eq!(q.stats().doorbells, 3);
    }
    #[test]
    fn version_is_frozen_at_actual_batch_and_completion_not_install() {
        let (mut q, mut t, p) = fixture(16);
        q.install(4, 3, 100_000, 0).unwrap();
        q.enqueue(&mut t, &[1], 1, false, false, &p).unwrap();
        q.install(8, 4, 200_000, 0).unwrap();
        q.drain(&mut t, &p).unwrap();
        used(&mut q, 0, 1);
        assert_eq!(q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap().version, 3);
        p.0.set(300_000);
        q.enqueue(&mut t, &[1], 1, false, false, &p).unwrap();
        used(&mut q, 2, 1);
        assert_eq!(q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap().version, 0);
    }
    #[test]
    fn exact_capacity_and_malformed_used_quarantine() {
        let (mut q, mut t, p) = fixture(8);
        assert_eq!(q.capacity(), 4);
        assert_eq!(q.install(8, 1, 1_000_000, 0), Err(Error::Exhausted));
        for _ in 0..4 {
            q.enqueue(&mut t, &[1], 1, false, true, &p).unwrap();
        }
        assert_eq!(
            q.enqueue(&mut t, &[1], 1, false, true, &p),
            Err(Error::Busy)
        );
        used(&mut q, 3, 1);
        assert_eq!(q.poll(&mut t, &mut [0; 1], &p), Err(Error::Queue));
        assert_eq!(q.free(), 0);
        assert_eq!(
            q.release(Token {
                slot: 0,
                generation: 1
            }),
            Err(Error::Busy)
        );
    }
    #[test]
    fn no_notify_suppression_does_not_skip_publication() {
        let (mut q, mut t, p) = fixture(16);
        q.memory.used.put16(0, 1);
        q.enqueue(&mut t, &[1], 1, true, false, &p).unwrap();
        assert_eq!(q.stats().published, 1);
        assert_eq!(q.stats().doorbells, 0);
    }
    #[test]
    fn older_out_of_order_completion_cannot_erase_a_newer_execution_receipt() {
        let (mut q, mut t, p) = fixture(16);
        q.install(1, 3, 1_000_000, 0).unwrap();
        q.enqueue(&mut t, &[1], 1, true, false, &p).unwrap();
        q.install(1, 4, 1_000_000, 0).unwrap();
        q.enqueue(&mut t, &[2], 1, true, false, &p).unwrap();
        used(&mut q, 2, 1);
        used(&mut q, 0, 1);
        let newer = q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap();
        assert_eq!(newer.version, 4);
        q.release(newer.token).unwrap();
        let older = q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap();
        assert_eq!(older.version, 3);
        assert_eq!(q.stats().last_completed_version, 4);
        assert_eq!(q.stats().pending_version, 3);
        q.release(older.token).unwrap();
        assert_eq!(q.stats().pending_version, 0);
    }
    #[test]
    fn queued_duplicate_used_head_cannot_become_valid_after_slot_reuse() {
        let (mut q, mut t, p) = fixture(16);
        q.enqueue(&mut t, &[1], 1, true, false, &p).unwrap();
        q.enqueue(&mut t, &[2], 1, true, false, &p).unwrap();
        used(&mut q, 0, 1);
        used(&mut q, 0, 1);
        let c = q.poll(&mut t, &mut [0; 1], &p).unwrap().unwrap();
        q.release(c.token).unwrap();
        assert_eq!(
            q.enqueue(&mut t, &[3], 1, true, false, &p),
            Err(Error::Queue)
        );
        assert_eq!(q.stats().published, 2);
    }
    #[test]
    fn unsolicited_used_head_is_rejected_before_first_publication() {
        let (mut q, mut t, p) = fixture(16);
        used(&mut q, 0, 1);
        assert_eq!(
            q.enqueue(&mut t, &[1], 1, true, false, &p),
            Err(Error::Queue)
        );
        assert_eq!(q.stats().published, 0);
    }
}
