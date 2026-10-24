//! Multi-request block owner. Returned buffers remain pinned until acknowledge.
use super::{FLUSH, Operation, READ_ONLY, SECTOR_BYTES};
use crate::{
    Error, Platform, Transport,
    queue::{BatchMemory, BatchQueue, MAX_CHAINS, NotifyStats, Token},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCompletion {
    pub token: Token,
    pub operation: Operation,
    pub notify_version: u64,
    pub latency_ns: u64,
}
pub struct BatchedBlock {
    transport: Transport,
    queue: BatchQueue,
    sectors: u64,
    read_only: bool,
    pending: [Option<(Token, Operation, u64)>; MAX_CHAINS],
    failed: bool,
    last_completed: u64,
}
impl BatchedBlock {
    pub fn attach(
        mut t: Transport,
        memory: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        if t.device_id() != 2 {
            return Err(Error::Device);
        }
        t.write(0x70, 0);
        p.barrier();
        let start = p.now_ms();
        while t.read(0x70) != 0 {
            if p.now_ms().wrapping_sub(start) >= 100 {
                return Err(Error::Timeout);
            }
        }
        t.write(0x70, 3);
        t.write(0x14, 1);
        p.barrier();
        let modern = t.read(0x10) & 1 != 0;
        t.write(0x14, 0);
        p.barrier();
        let features = t.read(0x10);
        if !modern || features & FLUSH == 0 {
            t.fail();
            return Err(Error::Features);
        }
        t.write(0x24, 0);
        t.write(0x20, features & (FLUSH | READ_ONLY));
        t.write(0x24, 1);
        t.write(0x20, 1);
        t.write(0x70, 11);
        p.barrier();
        if t.read(0x70) & (8 | 64 | 128) != 8 {
            t.fail();
            return Err(Error::Features);
        }
        let mut sectors = None;
        for _ in 0..8 {
            let before = t.read(0xfc);
            let lo = t.read(0x100);
            let hi = t.read(0x104);
            p.barrier();
            if t.read(0xfc) == before {
                sectors = Some(u64::from(lo) | (u64::from(hi) << 32));
                break;
            }
        }
        let sectors = sectors.filter(|n| *n != 0).ok_or(Error::Device)?;
        let queue = BatchQueue::configure(&mut t, memory, 0, p)?;
        t.start(p)?;
        Ok(Self {
            transport: t,
            queue,
            sectors,
            read_only: features & READ_ONLY != 0,
            pending: [None; MAX_CHAINS],
            failed: false,
            last_completed: 0,
        })
    }
    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }
    pub fn free(&self) -> usize {
        self.queue.free()
    }
    pub fn notify_stats(&self) -> NotifyStats {
        let mut s = self.queue.stats();
        s.last_completed_version = self.last_completed;
        s
    }
    pub fn current_batch(&self, now: u64) -> u8 {
        self.queue.current_batch(now)
    }
    pub fn set_notify_policy(
        &mut self,
        batch: u8,
        version: u64,
        until: u64,
        now: u64,
    ) -> Result<(), Error> {
        self.queue.install(batch, version, until, now)
    }
    pub fn set_completion_interrupts(&mut self, enabled: bool, p: &impl Platform) {
        self.queue.set_completion_interrupts(enabled, p);
    }
    fn fail(&mut self, p: &impl Platform) {
        self.failed = true;
        self.queue.poison(&mut self.transport, p);
    }
    pub fn begin(
        &mut self,
        operation: Operation,
        data: &[u8; SECTOR_BYTES],
        synchronous: bool,
        isolated: bool,
        p: &impl Platform,
    ) -> Result<Token, Error> {
        if self.failed {
            return Err(Error::Device);
        }
        let (kind, sector) = match operation {
            Operation::Read(s) => (0u32, s),
            Operation::Write(s) if !self.read_only => (1, s),
            Operation::Write(_) => return Err(Error::Unsupported),
            Operation::Flush => (4, 0),
        };
        if kind != 4 && sector >= self.sectors {
            return Err(Error::Address);
        }
        let mut request = [0; 16 + SECTOR_BYTES];
        request[..4].copy_from_slice(&kind.to_le_bytes());
        request[8..16].copy_from_slice(&sector.to_le_bytes());
        let len = if kind == 1 {
            request[16..].copy_from_slice(data);
            request.len()
        } else {
            16
        };
        let writable = if kind == 0 { 513 } else { 1 };
        let token = match self.queue.enqueue(
            &mut self.transport,
            &request[..len],
            writable,
            synchronous || kind == 4,
            isolated,
            p,
        ) {
            Ok(token) => token,
            Err(e) => {
                if !matches!(e, Error::Busy | Error::Address) {
                    self.fail(p);
                }
                return Err(e);
            }
        };
        self.pending[usize::from(token.slot)] = Some((token, operation, p.now_ms()));
        Ok(token)
    }
    pub fn drain(&mut self, p: &impl Platform) -> Result<(), Error> {
        self.queue.drain(&mut self.transport, p)
    }
    pub fn poll(
        &mut self,
        out: &mut [u8; SECTOR_BYTES],
        p: &impl Platform,
    ) -> Result<Option<BlockCompletion>, Error> {
        if self.failed {
            return Err(Error::Device);
        }
        let mut bytes = [0; 513];
        let completion = match self.queue.poll(&mut self.transport, &mut bytes, p) {
            Ok(c) => c,
            Err(e) => {
                self.fail(p);
                return Err(e);
            }
        };
        if let Some(c) = completion {
            let Some((token, operation, _)) = self.pending[usize::from(c.token.slot)] else {
                self.fail(p);
                return Err(Error::Queue);
            };
            let expected = if matches!(operation, Operation::Read(_)) {
                513
            } else {
                1
            };
            if token != c.token || c.len != expected || bytes[expected - 1] != 0 {
                self.fail(p);
                return Err(Error::Response);
            }
            if expected == 513 {
                out.copy_from_slice(&bytes[..512]);
            }
            self.pending[usize::from(token.slot)] = None;
            self.last_completed = self.last_completed.max(c.version);
            return Ok(Some(BlockCompletion {
                token,
                operation,
                notify_version: c.version,
                latency_ns: c.latency_ns,
            }));
        }
        if self
            .pending
            .iter()
            .flatten()
            .any(|(_, _, start)| p.now_ms().wrapping_sub(*start) >= 250)
        {
            self.fail(p);
            return Err(Error::Timeout);
        }
        Ok(None)
    }
    pub fn acknowledge(&mut self, token: Token) -> Result<(), Error> {
        self.queue.release(token)
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
    struct Host {
        clock: Cell<u64>,
    }
    unsafe impl Platform for Host {
        fn physical(&self, a: usize, _: usize) -> Result<u64, Error> {
            Ok(a as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {}
        fn now_ms(&self) -> u64 {
            self.clock.get() / 1_000_000
        }
        fn now_ns(&self) -> u64 {
            self.clock.get()
        }
    }
    fn fixture() -> (BatchedBlock, Host, usize) {
        let p = Host {
            clock: Cell::new(0),
        };
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 2);
        mmio.put32(0x34, 16);
        mmio.put32(0x70, 15);
        let mut t = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let m = Box::leak(Box::new(BatchMemory::zeroed()));
        let base = m as *mut _ as usize;
        let q = BatchQueue::configure(&mut t, m, 0, &p).unwrap();
        (
            BatchedBlock {
                transport: t,
                queue: q,
                sectors: 4096,
                read_only: false,
                pending: [None; 8],
                failed: false,
                last_completed: 0,
            },
            p,
            base,
        )
    }
    unsafe fn complete(base: usize, slot: u8, read: bool, status: u8) {
        unsafe {
            let desc = base + usize::from(slot) * 32 + 16;
            let response = u64::from_le(read_volatile(desc as *const u64)) as usize;
            if read {
                for i in 0..512 {
                    write_volatile((response + i) as *mut u8, 0x5a);
                }
            }
            write_volatile((response + if read { 512 } else { 0 }) as *mut u8, status);
            let used = base + 8192;
            let n = u16::from_le(read_volatile((used + 2) as *const u16));
            let at = used + 4 + usize::from(n % 16) * 8;
            write_volatile(at as *mut u32, u32::from(slot * 2).to_le());
            write_volatile(
                (at + 4) as *mut u32,
                (if read { 513u32 } else { 1u32 }).to_le(),
            );
            write_volatile((used + 2) as *mut u16, n.wrapping_add(1).to_le());
        }
    }
    #[test]
    fn real_four_sector_batch_retains_buffers_through_ack() {
        let (mut b, p, m) = fixture();
        b.set_notify_policy(4, 9, 1_000_000, 0).unwrap();
        let mut ts = [Token {
            slot: 0,
            generation: 0,
        }; 4];
        for (i, t) in ts.iter_mut().enumerate() {
            *t = b
                .begin(Operation::Read(i as u64), &[0; 512], false, false, &p)
                .unwrap();
        }
        assert_eq!(b.notify_stats().doorbells, 1);
        assert_eq!(b.notify_stats().last_completed_version, 0);
        unsafe {
            complete(m, ts[2].slot, true, 0);
        }
        let mut out = [0; 512];
        let c = b.poll(&mut out, &p).unwrap().unwrap();
        assert_eq!(c.operation, Operation::Read(2));
        assert_eq!(out, [0x5a; 512]);
        assert_eq!(b.free(), 4);
        assert_eq!(c.notify_version, 9);
        b.acknowledge(c.token).unwrap();
        assert_eq!(b.free(), 5);
    }
    #[test]
    fn invalid_device_status_never_releases_or_acknowledges_policy() {
        let (mut b, p, m) = fixture();
        b.set_notify_policy(1, 2, 1_000_000, 0).unwrap();
        let token = b
            .begin(Operation::Write(0), &[7; 512], true, false, &p)
            .unwrap();
        unsafe {
            complete(m, token.slot, false, 1);
        }
        assert_eq!(b.poll(&mut [0; 512], &p), Err(Error::Response));
        assert_eq!(b.notify_stats().last_completed_version, 0);
        assert_eq!(b.free(), 7);
    }
}
