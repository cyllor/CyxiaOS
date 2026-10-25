//! Modern VirtIO 1.2 block requests. One 512-byte request may be in flight.
//! Queue DMA pages stay pinned after any error; only successful FLUSH is durable.
use crate::{Error, Platform, Queue, QueueMemory, Transport};
mod batched;
pub use batched::{BatchedBlock, BlockCompletion};

pub const SECTOR_BYTES: usize = 512;
const FLUSH: u32 = 1 << 9;
const READ_ONLY: u32 = 1 << 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Read(u64),
    Write(u64),
    Flush,
}

pub struct Block {
    transport: Transport,
    queue: Queue,
    sectors: u64,
    read_only: bool,
    pending: Option<(Operation, u64)>,
    failed: bool,
}

impl Block {
    pub fn attach(
        mut transport: Transport,
        memory: &'static mut QueueMemory,
        platform: &impl Platform,
    ) -> Result<Self, Error> {
        if transport.device_id() != 2 {
            return Err(Error::Device);
        }
        transport.write(0x70, 0);
        platform.barrier();
        let start = platform.now_ms();
        while transport.read(0x70) != 0 {
            if platform.now_ms().wrapping_sub(start) >= 100 {
                return Err(Error::Timeout);
            }
        }
        transport.write(0x70, 3);
        transport.write(0x14, 1);
        let modern = transport.read(0x10) & 1 != 0;
        transport.write(0x14, 0);
        let features = transport.read(0x10);
        if !modern || features & FLUSH == 0 {
            transport.fail();
            return Err(Error::Features);
        }
        transport.write(0x24, 0);
        transport.write(0x20, features & (FLUSH | READ_ONLY));
        transport.write(0x24, 1);
        transport.write(0x20, 1);
        transport.write(0x70, 11);
        platform.barrier();
        if transport.read(0x70) & (8 | 64 | 128) != 8 {
            transport.fail();
            return Err(Error::Features);
        }
        let mut sectors = None;
        for _ in 0..8 {
            let before = transport.read(0xfc);
            let low = transport.read(0x100);
            let high = transport.read(0x104);
            platform.barrier();
            if transport.read(0xfc) == before {
                sectors = Some(u64::from(low) | (u64::from(high) << 32));
                break;
            }
        }
        let sectors = sectors.filter(|n| *n != 0).ok_or(Error::Device)?;
        let queue = Queue::configure(&mut transport, memory, 0, platform)?;
        transport.start(platform)?;
        Ok(Self {
            transport,
            queue,
            sectors,
            read_only: features & READ_ONLY != 0,
            pending: None,
            failed: false,
        })
    }

    pub fn sectors(&self) -> u64 {
        self.sectors
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }
    pub fn begin(
        &mut self,
        operation: Operation,
        data: &[u8; SECTOR_BYTES],
        platform: &impl Platform,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::Device);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let (kind, sector) = match operation {
            Operation::Read(sector) => (0u32, sector),
            Operation::Write(sector) if !self.read_only => (1, sector),
            Operation::Write(_) => return Err(Error::Unsupported),
            Operation::Flush => (4, 0),
        };
        if kind != 4 && sector >= self.sectors {
            return Err(Error::Address);
        }
        // Modern VirtIO permits combined device-readable header/data and
        // device-writable data/status descriptors. No legacy ANY_LAYOUT claim.
        let mut request = [0u8; 16 + SECTOR_BYTES];
        request[..4].copy_from_slice(&kind.to_le_bytes());
        request[8..16].copy_from_slice(&sector.to_le_bytes());
        let request_len = if kind == 1 {
            request[16..].copy_from_slice(data);
            request.len()
        } else {
            16
        };
        let response_len = if kind == 0 { SECTOR_BYTES + 1 } else { 1 };
        // Poison the status byte so a short or missing device response cannot
        // inherit a previous successful status from the reused pinned page.
        self.queue.memory.response.put8(response_len - 1, 0xff);
        self.queue.submit(
            &mut self.transport,
            &request[..request_len],
            response_len,
            platform,
        )?;
        self.pending = Some((operation, platform.now_ms()));
        Ok(())
    }

    pub fn poll(
        &mut self,
        output: &mut [u8; SECTOR_BYTES],
        platform: &impl Platform,
    ) -> Result<Option<Operation>, Error> {
        if self.failed {
            return Err(Error::Device);
        }
        let Some((operation, start)) = self.pending else {
            return Ok(None);
        };
        let mut bytes = [0u8; SECTOR_BYTES + 1];
        let result = (|| {
            if platform.now_ms().wrapping_sub(start) >= 250 {
                return Err(Error::Timeout);
            }
            let Some(length) = self.queue.poll(&mut self.transport, &mut bytes, platform)? else {
                return Ok(None);
            };
            if platform.now_ms().wrapping_sub(start) >= 250 {
                return Err(Error::Timeout);
            }
            let expected = if matches!(operation, Operation::Read(_)) {
                513
            } else {
                1
            };
            if length != expected || bytes[expected - 1] != 0 {
                return Err(Error::Response);
            }
            if matches!(operation, Operation::Read(_)) {
                output.copy_from_slice(&bytes[..SECTOR_BYTES]);
            }
            Ok(Some(operation))
        })();
        match result {
            Ok(Some(_)) => self.pending = None,
            Err(_) => {
                self.failed = true;
                self.queue.poisoned = true;
                self.transport.fail();
                platform.barrier();
            }
            _ => {}
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Page;
    use core::cell::Cell;
    use std::boxed::Box;
    struct Host(Cell<u64>);
    // SAFETY: all MMIO/DMA storage is pinned and synchronously emulated.
    unsafe impl Platform for Host {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn barrier(&self) {}
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }
    fn fixture() -> (Block, Host) {
        let host = Host(Cell::new(0));
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 2);
        mmio.put32(0x34, 8);
        mmio.put32(0x70, 15);
        let mut transport = unsafe { Transport::attach(mmio.address(), 4096).unwrap() };
        let queue = Queue::configure(
            &mut transport,
            Box::leak(Box::new(QueueMemory::zeroed())),
            0,
            &host,
        )
        .unwrap();
        (
            Block {
                transport,
                queue,
                sectors: 4096,
                read_only: false,
                pending: None,
                failed: false,
            },
            host,
        )
    }
    fn complete(b: &mut Block, length: u32, status: u8) {
        let offset = if matches!(b.pending, Some((Operation::Read(_), _))) {
            512
        } else {
            0
        };
        for i in 0..offset {
            b.queue.memory.response.put8(i, i as u8);
        }
        b.queue.memory.response.put8(offset, status);
        let at = 4 + usize::from(b.queue.used % 8) * 8;
        b.queue.memory.used.put32(at, 0);
        b.queue.memory.used.put32(at + 4, length);
        b.queue.memory.used.put16(2, b.queue.used.wrapping_add(1));
    }
    #[test]
    fn read_write_flush_use_real_wire_layout_and_completion() {
        let (mut b, h) = fixture();
        let mut out = [0xaa; 512];
        b.begin(Operation::Read(7), &[0; 512], &h).unwrap();
        assert_eq!(b.begin(Operation::Flush, &[0; 512], &h), Err(Error::Busy));
        assert_eq!(b.queue.memory.request.get32(0), 0);
        assert_eq!(b.queue.memory.request.get32(8), 7);
        complete(&mut b, 513, 0);
        assert_eq!(b.poll(&mut out, &h), Ok(Some(Operation::Read(7))));
        assert_eq!(out[300], 44);
        b.begin(Operation::Write(8), &[0x37; 512], &h).unwrap();
        assert_eq!(b.queue.memory.request.get32(0), 1);
        assert_eq!(b.queue.memory.request.get32(16), 0x37373737);
        complete(&mut b, 1, 0);
        assert_eq!(b.poll(&mut out, &h), Ok(Some(Operation::Write(8))));
        b.begin(Operation::Flush, &[0; 512], &h).unwrap();
        assert_eq!(b.queue.memory.request.get32(0), 4);
        assert_eq!(b.queue.memory.request.get32(8), 0);
        assert_eq!(b.queue.memory.desc.get32(8), 16);
        complete(&mut b, 1, 0);
        assert_eq!(b.poll(&mut out, &h), Ok(Some(Operation::Flush)));
    }
    #[test]
    fn failure_never_publishes_read_or_reuses_dma() {
        for (length, status, timeout) in [(513, 1, false), (512, 0, false), (513, 0, true)] {
            let (mut b, h) = fixture();
            let mut out = [0xaa; 512];
            b.begin(Operation::Read(0), &[0; 512], &h).unwrap();
            complete(&mut b, length, status);
            if timeout {
                h.0.set(250);
            }
            assert!(b.poll(&mut out, &h).is_err());
            assert_eq!(out, [0xaa; 512]);
            assert_eq!(b.begin(Operation::Flush, &[0; 512], &h), Err(Error::Device));
        }
    }
    #[test]
    fn out_of_range_and_readonly_requests_never_publish() {
        let (mut b, h) = fixture();
        assert_eq!(
            b.begin(Operation::Read(4096), &[0; 512], &h),
            Err(Error::Address)
        );
        b.read_only = true;
        assert_eq!(
            b.begin(Operation::Write(0), &[0; 512], &h),
            Err(Error::Unsupported)
        );
        assert_eq!(b.queue.available, 0);
    }
}
