//! Independent entropy requests retain DMA credit through byte consumption.
use crate::{
    Error, Platform, Transport,
    queue::{
        BatchMemory, BatchQueue, MAX_CHAINS, NotifyFeedback, NotifyRequest, NotifyStats, Token,
    },
};
pub struct BatchedRng {
    transport: Transport,
    queue: BatchQueue,
    pending: [Option<(Token, u64)>; MAX_CHAINS],
    ready: [Option<(Token, usize, usize)>; MAX_CHAINS],
    pool: [[u8; 256]; MAX_CHAINS],
    failed: bool,
    last_completed: u64,
    hooks: Option<(NotifyRequest, NotifyFeedback)>,
    command_version: u64,
}
impl BatchedRng {
    pub fn attach(
        mut t: Transport,
        memory: &'static mut BatchMemory,
        p: &impl Platform,
    ) -> Result<Self, Error> {
        if t.device_id() != 4 {
            return Err(Error::Device);
        }
        t.negotiate(p)?;
        let q = BatchQueue::configure(&mut t, memory, 0, p)?;
        t.start(p)?;
        Ok(Self {
            transport: t,
            queue: q,
            pending: [None; MAX_CHAINS],
            ready: [None; MAX_CHAINS],
            pool: [[0; 256]; MAX_CHAINS],
            failed: false,
            last_completed: 0,
            hooks: None,
            command_version: 0,
        })
    }
    pub fn set_notify_hooks(&mut self, request: NotifyRequest, feedback: NotifyFeedback) {
        self.hooks = Some((request, feedback));
    }
    fn report(&self, p: &impl Platform, polled: bool) {
        if let Some((_, report)) = self.hooks {
            report(self.notify_stats(), p.now_ns(), polled);
        }
    }
    pub fn capacity(&self) -> usize {
        self.queue.capacity()
    }
    pub fn current_batch(&self, now: u64) -> u8 {
        self.queue.current_batch(now)
    }
    pub fn notify_stats(&self) -> NotifyStats {
        let mut s = self.queue.stats();
        s.last_completed_version = self.last_completed;
        s
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
        for pool in &mut self.pool {
            pool.fill(0);
        }
        self.ready.fill(None);
        self.report(p, false);
    }
    pub fn prefetch(&mut self, p: &impl Platform) -> Result<(), Error> {
        if let Some((request, _)) = self.hooks {
            if let Some(c) = request(p.now_ns()) {
                if c.version != self.command_version {
                    self.set_notify_policy(c.batch, c.version, c.until_ns, p.now_ns())?;
                    self.command_version = c.version;
                }
            }
        }
        if self.failed {
            return Err(Error::Device);
        }
        // Fixed-capacity prefetch waves are independent of the D11 policy.
        // Consume one wave before posting its successor: D11 changes only how
        // these already required chains are published, not the entropy quota.
        if self.pending.iter().any(Option::is_some) || self.ready.iter().any(Option::is_some) {
            return Ok(());
        }
        let count = self.queue.free();
        for _ in 0..count {
            let token = match self
                .queue
                .enqueue(&mut self.transport, &[], 256, false, false, p)
            {
                Ok(t) => t,
                Err(e) => {
                    self.fail(p);
                    return Err(e);
                }
            };
            self.pending[usize::from(token.slot)] = Some((token, p.now_ms()));
        }
        let r = self.queue.drain(&mut self.transport, p);
        self.report(p, false);
        r
    }
    fn collect(&mut self, p: &impl Platform) -> Result<(), Error> {
        for _ in 0..self.capacity() {
            let mut out = [0; 256];
            let c = match self.queue.poll(&mut self.transport, &mut out, p) {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    self.fail(p);
                    return Err(e);
                }
            };
            let at = usize::from(c.token.slot);
            if c.len == 0
                || !self.pending[at].is_some_and(|(t, _)| t == c.token)
                || self.ready[at].is_some()
            {
                self.fail(p);
                return Err(Error::Response);
            }
            self.pending[at] = None;
            self.pool[at][..c.len].copy_from_slice(&out[..c.len]);
            out.fill(0);
            self.ready[at] = Some((c.token, 0, c.len));
            self.last_completed = self.last_completed.max(c.version);
        }
        // A completed prefetch remains valid however late its next consumer.
        if self
            .pending
            .iter()
            .flatten()
            .any(|(_, start)| p.now_ms().wrapping_sub(*start) >= 250)
        {
            self.fail(p);
            return Err(Error::Timeout);
        }
        self.report(p, true);
        Ok(())
    }
    pub fn try_fill(&mut self, out: &mut [u8], p: &impl Platform) -> Result<usize, Error> {
        if out.len() > 256 {
            return Err(Error::Address);
        }
        if self.failed {
            return Err(Error::Device);
        }
        if out.is_empty() {
            return Ok(0);
        }
        self.prefetch(p)?;
        self.collect(p)?;
        let mut done = 0;
        for at in 0..self.capacity() {
            let Some((token, offset, available)) = self.ready[at] else {
                continue;
            };
            let n = (out.len() - done).min(available);
            out[done..done + n].copy_from_slice(&self.pool[at][offset..offset + n]);
            self.pool[at][offset..offset + n].fill(0);
            done += n;
            if n == available {
                self.ready[at] = None;
                self.queue.release(token)?;
            } else {
                self.ready[at] = Some((token, offset + n, available - n));
            }
            if done == out.len() {
                break;
            }
        }
        self.report(p, false);
        Ok(done)
    }
    pub fn fill(&mut self, out: &mut [u8], p: &impl Platform) -> Result<(), Error> {
        if out.len() > 256 {
            return Err(Error::Address);
        }
        let mut staged = [0; 256];
        let mut done = 0;
        let start = p.now_ms();
        while done < out.len() {
            if p.now_ms().wrapping_sub(start) >= 250 {
                self.fail(p);
                staged.fill(0);
                return Err(Error::Timeout);
            }
            match self.try_fill(&mut staged[done..out.len()], p) {
                Ok(n) => done += n,
                Err(e) => {
                    staged.fill(0);
                    return Err(e);
                }
            }
            core::hint::spin_loop();
        }
        out.copy_from_slice(&staged[..done]);
        staged.fill(0);
        Ok(())
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
    fn fixture() -> (BatchedRng, Host, usize) {
        let p = Host(Cell::new(0));
        let m = Box::leak(Box::new(Page::zeroed()));
        m.put32(0, 0x74726976);
        m.put32(4, 2);
        m.put32(8, 4);
        m.put32(0x34, 16);
        m.put32(0x70, 15);
        let mut t = unsafe { Transport::attach(m.address(), 4096).unwrap() };
        let memory = Box::leak(Box::new(BatchMemory::zeroed()));
        let base = memory as *mut _ as usize;
        let q = BatchQueue::configure(&mut t, memory, 0, &p).unwrap();
        (
            BatchedRng {
                transport: t,
                queue: q,
                pending: [None; 8],
                ready: [None; 8],
                pool: [[0; 256]; 8],
                failed: false,
                last_completed: 0,
                hooks: None,
                command_version: 0,
            },
            p,
            base,
        )
    }
    unsafe fn all_complete(base: usize) {
        unsafe {
            for slot in 0..8 {
                let addr = u64::from_le(read_volatile((base + slot * 32) as *const u64)) as usize;
                for i in 0..256 {
                    write_volatile((addr + i) as *mut u8, (slot * 17 + i) as u8);
                }
                let used = base + 8192 + 4 + slot * 8;
                write_volatile(used as *mut u32, ((slot * 2) as u32).to_le());
                write_volatile((used + 4) as *mut u32, 256u32.to_le());
            }
            write_volatile((base + 8192 + 2) as *mut u16, 8u16.to_le());
        }
    }
    #[test]
    fn eight_entropy_chains_publish_once_and_hold_until_consumed() {
        let (mut r, p, m) = fixture();
        r.set_notify_policy(8, 4, 1_000_000, 0).unwrap();
        r.prefetch(&p).unwrap();
        assert_eq!(r.notify_stats().doorbells, 1);
        assert_eq!(r.queue.free(), 0);
        unsafe {
            all_complete(m);
        }
        p.0.set(1_000_000_000);
        let mut a = [0; 64];
        assert_eq!(r.try_fill(&mut a, &p), Ok(64));
        assert_eq!(a[63], 63);
        assert_eq!(r.queue.free(), 0);
        assert_eq!(r.notify_stats().last_completed_version, 4);
        let mut b = [0; 192];
        assert_eq!(r.try_fill(&mut b, &p), Ok(192));
        assert_eq!(b[0], 64);
        assert_eq!(r.queue.free(), 1);
        assert_eq!(r.pool[0], [0; 256]);
    }
    #[test]
    fn silent_device_retains_all_dma_and_never_fills_output() {
        let (mut r, p, _) = fixture();
        r.set_notify_policy(8, 1, 1_000_000_000, 0).unwrap();
        r.prefetch(&p).unwrap();
        p.0.set(250_000_000);
        let mut out = [0xaa; 32];
        assert_eq!(r.try_fill(&mut out, &p), Err(Error::Timeout));
        assert_eq!(out, [0xaa; 32]);
        assert_eq!(r.queue.free(), 0);
    }
}
