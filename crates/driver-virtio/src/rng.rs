//! VirtIO entropy source. No invented seed or deterministic fallback.
use crate::{Error, Platform, Queue, Transport};
pub struct Rng {
    transport: Transport,
    queue: Queue,
    failed: bool,
    pool: [u8; 256],
    offset: usize,
    available: usize,
    pending: bool,
    pending_since: u64,
}

impl Rng {
    pub fn new(transport: Transport, queue: Queue) -> Result<Self, Error> {
        if transport.device_id() != 4 {
            return Err(Error::Device);
        }
        Ok(Self {
            transport,
            queue,
            failed: false,
            pool: [0; 256],
            offset: 0,
            available: 0,
            pending: false,
            pending_since: 0,
        })
    }

    fn fail(&mut self, platform: &impl Platform) {
        self.failed = true;
        self.queue.poisoned = true;
        self.transport.fail();
        self.pool.fill(0);
        self.available = 0;
        platform.barrier();
    }

    /// Submit one bounded entropy request without waiting for the device.
    /// Only one DMA request can be outstanding; unread bytes are never replaced.
    pub fn prefetch(&mut self, platform: &impl Platform) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if self.pending || self.available != 0 {
            return Ok(());
        }
        if let Err(error) = self
            .queue
            .submit(&mut self.transport, &[], self.pool.len(), platform)
        {
            self.fail(platform);
            return Err(error);
        }
        self.pending_since = platform.now_ms();
        self.pending = true;
        Ok(())
    }

    /// Poll once and consume available entropy. Ok(0) means not ready, never
    /// repeated/zero-filled entropy. Partial reads are allowed; each consumed
    /// byte is erased and cannot be returned to another caller.
    pub fn try_fill(&mut self, out: &mut [u8], platform: &impl Platform) -> Result<usize, Error> {
        if out.len() > 256 {
            return Err(Error::Address);
        }
        if self.failed {
            return Err(Error::Device);
        }
        if out.is_empty() {
            return Ok(0);
        }
        self.prefetch(platform)?;
        if self.pending {
            // A prefetch may have completed long before its next consumer.
            // Accept an observed completion; time out only a still-silent
            // device. There is no blocking loop or interrupt-side pool access.
            match self
                .queue
                .poll(&mut self.transport, &mut self.pool, platform)
            {
                Ok(Some(count)) if count > 0 => {
                    self.pending = false;
                    self.offset = 0;
                    self.available = count;
                }
                Ok(None) if platform.now_ms().wrapping_sub(self.pending_since) < 250 => {
                    return Ok(0);
                }
                response => {
                    let error = match response {
                        Ok(None) => Error::Timeout,
                        Ok(Some(_)) => Error::Response,
                        Err(error) => error,
                    };
                    self.fail(platform);
                    return Err(error);
                }
            }
        }
        let count = out.len().min(self.available);
        out[..count].copy_from_slice(&self.pool[self.offset..self.offset + count]);
        self.pool[self.offset..self.offset + count].fill(0);
        self.offset += count;
        self.available -= count;
        Ok(count)
    }
    /// Single serialized foreground reader; DMA queue storage remains pinned
    /// even after a failure. On error no partially filled output is exposed.
    /// The complete fill has one 250 ms deadline, including partial responses.
    pub fn fill(&mut self, out: &mut [u8], platform: &impl Platform) -> Result<(), Error> {
        if out.len() > 256 {
            return Err(Error::Address);
        }
        if self.failed {
            return Err(Error::Device);
        }
        if out.is_empty() {
            return Ok(());
        }
        if self.pending || self.available != 0 {
            let start = platform.now_ms();
            let mut staged = [0; 256];
            let mut done = 0;
            let result = (|| {
                while done < out.len() {
                    if platform.now_ms().wrapping_sub(start) >= 250 {
                        return Err(Error::Timeout);
                    }
                    done += self.try_fill(&mut staged[done..out.len()], platform)?;
                    if platform.now_ms().wrapping_sub(start) >= 250 {
                        return Err(Error::Timeout);
                    }
                    core::hint::spin_loop();
                }
                Ok(())
            })();
            if let Err(error) = result {
                self.fail(platform);
                staged.fill(0);
                return Err(error);
            }
            out.copy_from_slice(&staged[..done]);
            staged.fill(0);
            return Ok(());
        }
        let mut bytes = [0u8; 256];
        let mut done = 0;
        let start = platform.now_ms();
        let result = (|| {
            while done < out.len() {
                if platform.now_ms().wrapping_sub(start) >= 250 {
                    return Err(Error::Timeout);
                }
                self.queue
                    .submit(&mut self.transport, &[], out.len() - done, platform)?;
                let received = loop {
                    if platform.now_ms().wrapping_sub(start) >= 250 {
                        return Err(Error::Timeout);
                    }
                    let response = self.queue.poll(
                        &mut self.transport,
                        &mut bytes[done..out.len()],
                        platform,
                    )?;
                    // Completion observed after the deadline is not success.
                    if platform.now_ms().wrapping_sub(start) >= 250 {
                        return Err(Error::Timeout);
                    }
                    match response {
                        Some(0) => return Err(Error::Response),
                        Some(count) => break count,
                        None => core::hint::spin_loop(),
                    }
                };
                done += received;
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.fail(platform);
            bytes.fill(0);
            return Err(error);
        }
        out.copy_from_slice(&bytes[..done]);
        bytes.fill(0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Page, QueueMemory};
    use core::{
        cell::Cell,
        ptr::{read_volatile, write_volatile},
    };
    use std::boxed::Box;

    struct Host {
        desc: usize,
        avail: usize,
        used: usize,
        response: usize,
        completed: Cell<u16>,
        clock: Cell<u64>,
        step: u64,
        chunks: &'static [usize],
    }

    // SAFETY: all fake MMIO and DMA storage is aligned, pinned, and accessed
    // synchronously on this test thread. There is no actual DMA or concurrency.
    unsafe impl Platform for Host {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn now_ms(&self) -> u64 {
            let now = self.clock.get();
            self.clock.set(now.wrapping_add(self.step));
            now
        }
        fn barrier(&self) {
            if self.avail == 0 {
                return;
            }
            // SAFETY: addresses refer to the permanently pinned QueueMemory's
            // UnsafeCell pages and only this fake device mutates used/response.
            unsafe {
                let available = u16::from_le(read_volatile((self.avail + 2) as *const u16));
                let completed = self.completed.get();
                if available == completed {
                    return;
                }
                let Some(&count) = self.chunks.get(usize::from(completed)) else {
                    return;
                };
                let writable = u32::from_le(read_volatile((self.desc + 8) as *const u32)) as usize;
                for i in 0..count.min(writable) {
                    write_volatile((self.response + i) as *mut u8, completed as u8 + 1);
                }
                let slot = usize::from(completed % 8);
                write_volatile((self.used + 4 + slot * 8) as *mut u32, 0);
                write_volatile(
                    (self.used + 8 + slot * 8) as *mut u32,
                    (count as u32).to_le(),
                );
                write_volatile((self.used + 2) as *mut u16, available.to_le());
                self.completed.set(available);
            }
        }
    }

    fn fixture(chunks: &'static [usize], step: u64) -> (Rng, Host) {
        let mut host = Host {
            desc: 0,
            avail: 0,
            used: 0,
            response: 0,
            completed: Cell::new(0),
            clock: Cell::new(0),
            step,
            chunks,
        };
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 4);
        mmio.put32(0x34, 8);
        mmio.put32(0x70, 15);
        // SAFETY: fixture MMIO remains pinned for the entire test.
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let queue = Queue::configure(
            &mut transport,
            Box::leak(Box::new(QueueMemory::zeroed())),
            0,
            &host,
        )
        .unwrap();
        host.desc = queue.memory.desc.address();
        host.avail = queue.memory.avail.address();
        host.used = queue.memory.used.address();
        host.response = queue.memory.response.address();
        (Rng::new(transport, queue).unwrap(), host)
    }

    #[test]
    fn nonblocking_prefetch_returns_only_completed_unconsumed_bytes() {
        let (mut rng, mut host) = fixture(&[], 0);
        rng.prefetch(&host).unwrap();
        let mut out = [0xaa; 8];
        assert_eq!(rng.try_fill(&mut out, &host), Ok(0));
        assert_eq!(out, [0xaa; 8]);
        assert_eq!(host.completed.get(), 0);
        host.chunks = &[16, 3];
        assert_eq!(rng.try_fill(&mut out, &host), Ok(8));
        assert_eq!(out, [1; 8]);
        assert_eq!(rng.try_fill(&mut out, &host), Ok(8));
        assert_eq!(host.completed.get(), 1);
        assert!(rng.pool.iter().all(|byte| *byte == 0));
        assert_eq!(rng.try_fill(&mut out, &host), Ok(3));
        assert_eq!(out, [2, 2, 2, 1, 1, 1, 1, 1]);
        assert_eq!(host.completed.get(), 2);
        assert_eq!(rng.try_fill(&mut out, &host), Ok(0));
    }

    #[test]
    fn blocking_and_nonblocking_readers_share_one_pool_without_replay() {
        let (mut rng, host) = fixture(&[16, 16], 1);
        rng.prefetch(&host).unwrap();
        let mut out = [0; 20];
        rng.fill(&mut out, &host).unwrap();
        assert_eq!(&out[..16], &[1; 16]);
        assert_eq!(&out[16..], &[2; 4]);
        let mut rest = [0xaa; 16];
        assert_eq!(rng.try_fill(&mut rest, &host), Ok(12));
        assert_eq!(&rest[..12], &[2; 12]);
        assert_eq!(&rest[12..], &[0xaa; 4]);
        assert!(rng.pool.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn silent_prefetch_fails_after_deadline_without_mutating_output() {
        let (mut rng, host) = fixture(&[], 0);
        rng.prefetch(&host).unwrap();
        let mut out = [0xaa; 8];
        assert_eq!(rng.try_fill(&mut out, &host), Ok(0));
        host.clock.set(250);
        assert_eq!(rng.try_fill(&mut out, &host), Err(Error::Timeout));
        assert_eq!(out, [0xaa; 8]);
        assert_eq!(rng.try_fill(&mut out, &host), Err(Error::Device));
    }

    #[test]
    fn partial_success_fills_all_bytes_before_publishing() {
        let (mut rng, host) = fixture(&[3, 2, 3], 1);
        let mut out = [0xaa; 8];
        assert_eq!(rng.fill(&mut out, &host), Ok(()));
        assert_eq!(out, [1, 1, 1, 2, 2, 3, 3, 3]);
        assert_eq!(host.completed.get(), 3);
    }

    #[test]
    fn partial_then_timeout_never_publishes_or_reuses_queue() {
        let (mut rng, host) = fixture(&[3], 10);
        let mut out = [0xaa; 8];
        assert_eq!(rng.fill(&mut out, &host), Err(Error::Timeout));
        assert_eq!(out, [0xaa; 8]);
        assert_eq!(rng.fill(&mut out, &host), Err(Error::Device));
        assert_eq!(host.completed.get(), 1);
    }

    #[test]
    fn total_deadline_is_not_restarted_for_each_partial_completion() {
        let (mut rng, host) = fixture(&[1; 16], 30);
        let mut out = [0xaa; 16];
        assert_eq!(rng.fill(&mut out, &host), Err(Error::Timeout));
        assert_eq!(out, [0xaa; 16]);
        assert!(host.completed.get() < 16);
    }

    #[test]
    fn malformed_zero_length_and_silent_device_fail_atomically() {
        for (chunks, error) in [
            (&[0][..], Error::Response),
            (&[9][..], Error::Queue),
            (&[][..], Error::Timeout),
        ] {
            let (mut rng, host) = fixture(chunks, 10);
            let mut out = [0xaa; 8];
            assert_eq!(rng.fill(&mut out, &host), Err(error));
            assert_eq!(out, [0xaa; 8]);
            assert_eq!(rng.fill(&mut out, &host), Err(Error::Device));
        }
    }

    #[test]
    fn length_limit_and_empty_request_do_not_consume_entropy() {
        let (mut rng, host) = fixture(&[8], 1);
        assert_eq!(rng.fill(&mut [0xaa; 257], &host), Err(Error::Address));
        assert_eq!(rng.fill(&mut [], &host), Ok(()));
        assert_eq!(host.completed.get(), 0);
        assert_eq!(rng.fill(&mut [0; 8], &host), Ok(()));
    }
}
