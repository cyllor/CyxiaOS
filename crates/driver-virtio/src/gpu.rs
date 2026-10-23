//! VirtIO 2D control messages; all commands use fences and validate the response.
use crate::{Error, Platform, Queue, Transport};

pub const WIDTH: usize = 1024;
pub const HEIGHT: usize = 768;
pub const FRAME_BYTES: usize = WIDTH * HEIGHT * 4;

#[derive(Clone, Copy)]
enum State {
    Empty,
    Ready {
        backing: usize,
    },
    Pending {
        backing: usize,
        phase: Phase,
        started: u64,
    },
    Quarantined,
}
#[derive(Clone, Copy)]
enum Phase {
    Transfer,
    Flush,
}

/// One permanently attached 2D backing store and one control queue. Runtime
/// updates submit/poll without waiting; initialization may use synchronous I/O.
/// Dropping this object does not reset the device or release its DMA storage.
pub struct Gpu {
    transport: Transport,
    queue: Queue,
    fence: u64,
    state: State,
}
impl Gpu {
    pub fn new(transport: Transport, queue: Queue) -> Result<Self, Error> {
        if transport.device_id() != 16 {
            return Err(Error::Device);
        }
        Ok(Self {
            transport,
            queue,
            fence: 0,
            state: State::Empty,
        })
    }
    fn quarantine(&mut self, platform: &impl Platform) {
        self.state = State::Quarantined;
        self.transport.fail();
        platform.barrier();
    }
    fn prepare_request(
        &mut self,
        kind: u32,
        body: &[u8],
        platform: &impl Platform,
    ) -> Result<([u8; 256], usize), Error> {
        if matches!(self.state, State::Quarantined) {
            return Err(Error::Device);
        }
        if body.len() > 232 {
            return Err(Error::Address);
        }
        let Some(fence) = self.fence.checked_add(1) else {
            self.quarantine(platform);
            return Err(Error::Exhausted);
        };
        self.fence = fence;
        let mut request = [0; 256];
        put32(&mut request, 0, kind);
        put32(&mut request, 4, 1);
        request[8..16].copy_from_slice(&self.fence.to_le_bytes());
        request[24..24 + body.len()].copy_from_slice(body);
        Ok((request, 24 + body.len()))
    }
    fn command(
        &mut self,
        kind: u32,
        body: &[u8],
        reply_kind: u32,
        platform: &impl Platform,
    ) -> Result<(), Error> {
        let (request, length) = self.prepare_request(kind, body, platform)?;
        let mut response = [0; 408];
        let result = self
            .queue
            .transact(
                &mut self.transport,
                &request[..length],
                &mut response,
                platform,
            )
            .and_then(|count| validate_response(&response[..count], reply_kind, self.fence));
        if result.is_err() {
            // Queue completion alone does not establish GPU completion: a
            // missing or stale fence must quarantine backing just like timeout.
            self.quarantine(platform);
        }
        result
    }
    fn submit_command(
        &mut self,
        kind: u32,
        body: &[u8],
        platform: &impl Platform,
    ) -> Result<(), Error> {
        let (request, length) = self.prepare_request(kind, body, platform)?;
        let result = self
            .queue
            .submit(&mut self.transport, &request[..length], 408, platform);
        if result.is_err() {
            self.quarantine(platform);
        }
        result
    }
    /// Attach and display a fixed 1024x768 B8G8R8X8_UNORM backing store once.
    /// Subsequent frames use [`Self::submit_update`] / [`Self::poll_update`],
    /// without replacing the backing.
    /// A successful return means transfer, scanout and flush fences completed.
    ///
    /// # Safety
    /// `backing..backing+FRAME_BYTES` must be initialized writable RAM, pinned,
    /// mapped and physically contiguous for the lifetime of the device,
    /// including after errors or dropping `Gpu`. Ownership is exclusively given
    /// to this object: no CPU, device, alias or interrupt may access these bytes
    /// outside the temporary render borrow supplied by `submit_update`. Platform cache
    /// operations must cover the complete backing without touching other owners.
    /// Errors after commands have been submitted require permanent quarantine;
    /// setting FAILED alone does not prove that DMA has stopped.
    pub unsafe fn show(&mut self, backing: usize, platform: &impl Platform) -> Result<(), Error> {
        match self.state {
            State::Ready { .. } | State::Pending { .. } => return Err(Error::Busy),
            State::Quarantined => return Err(Error::Device),
            State::Empty => {}
        }
        if backing == 0
            || !backing.is_multiple_of(4096)
            || backing.checked_add(FRAME_BYTES).is_none()
        {
            return Err(Error::Address);
        }
        let pa = platform.physical(backing, FRAME_BYTES)?;
        if !pa.is_multiple_of(4096) || pa.checked_add(FRAME_BYTES as u64).is_none() {
            return Err(Error::Address);
        }
        self.command(0x100, &[], 0x1101, platform)?;
        let mut create = [0; 16];
        put32(&mut create, 0, 1);
        put32(&mut create, 4, 2); // B8G8R8X8_UNORM
        put32(&mut create, 8, WIDTH as u32);
        put32(&mut create, 12, HEIGHT as u32);
        self.command(0x101, &create, 0x1100, platform)?;
        let mut attach = [0; 24];
        put32(&mut attach, 0, 1);
        put32(&mut attach, 4, 1);
        attach[8..16].copy_from_slice(&pa.to_le_bytes());
        put32(&mut attach, 16, FRAME_BYTES as u32);
        self.command(0x106, &attach, 0x1100, platform)?;
        self.transfer(backing, platform)?;
        let mut scanout = [0; 24];
        rectangle(&mut scanout);
        put32(&mut scanout, 20, 1);
        self.command(0x103, &scanout, 0x1100, platform)?;
        self.flush(platform)?;
        self.state = State::Ready { backing };
        Ok(())
    }

    /// Synchronous diagnostic wrapper. Runtime services should instead submit
    /// once and poll from their foreground event loop so other tasks can run.
    pub fn update(
        &mut self,
        render: impl FnOnce(&mut [u32]),
        platform: &impl Platform,
    ) -> Result<(), Error> {
        self.submit_update(render, platform)?;
        while !self.poll_update(platform)? {
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Render and queue a complete frame without waiting for device completion.
    /// The callback's borrow ends before cache synchronization and DMA. Call
    /// [`Self::poll_update`] to receive completion of both transfer and flush.
    ///
    /// The callback is never called before initialization or after a device
    /// error, or while a previous update is pending (`Error::Busy`). Every
    /// submission/response failure permanently disables rendering through this
    /// object. The backing remains reserved even if this is dropped.
    pub fn submit_update(
        &mut self,
        render: impl FnOnce(&mut [u32]),
        platform: &impl Platform,
    ) -> Result<(), Error> {
        let backing = match self.state {
            State::Ready { backing } => backing,
            State::Pending { .. } => return Err(Error::Busy),
            State::Empty | State::Quarantined => return Err(Error::Device),
        };
        if let Err(error) = self.transport.check() {
            self.quarantine(platform);
            return Err(error);
        }
        // SAFETY: show permanently transfers exclusive access to aligned,
        // initialized RAM. All earlier transfer commands completed with matching
        // fences. The callback cannot retain this short-lived mutable borrow.
        // VirtIO 2D scans out its host resource; guest backing is read by transfer.
        render(unsafe { core::slice::from_raw_parts_mut(backing as *mut u32, WIDTH * HEIGHT) });
        self.sync_frame(backing, platform);
        let started = platform.now_ms();
        self.submit_command(0x105, &transfer_body(), platform)?;
        self.state = State::Pending {
            backing,
            phase: Phase::Transfer,
            started,
        };
        Ok(())
    }

    /// Inspect at most one queued response. `true` is emitted once, only after
    /// the matching FLUSH fence completes; `false` means idle or still pending.
    /// No loop waits on the device. A pending command expires 250 ms after its
    /// submission when next polled. The caller should poll regularly for timely
    /// completion and timeout delivery. Success does not promise vblank or an
    /// atomic presentation on the display.
    pub fn poll_update(&mut self, platform: &impl Platform) -> Result<bool, Error> {
        let (backing, phase, started) = match self.state {
            State::Pending {
                backing,
                phase,
                started,
            } => (backing, phase, started),
            State::Quarantined => return Err(Error::Device),
            State::Empty | State::Ready { .. } => return Ok(false),
        };
        let mut response = [0; 408];
        let count = match self
            .queue
            .poll(&mut self.transport, &mut response, platform)
        {
            Ok(Some(count)) => count,
            Ok(None) => {
                if platform.now_ms().wrapping_sub(started) >= 250 {
                    self.quarantine(platform);
                    return Err(Error::Timeout);
                }
                return Ok(false);
            }
            Err(error) => {
                self.quarantine(platform);
                return Err(error);
            }
        };
        if let Err(error) = validate_response(&response[..count], 0x1100, self.fence) {
            self.quarantine(platform);
            return Err(error);
        }
        match phase {
            Phase::Transfer => {
                let started = platform.now_ms();
                self.submit_command(0x104, &flush_body(), platform)?;
                self.state = State::Pending {
                    backing,
                    phase: Phase::Flush,
                    started,
                };
                Ok(false)
            }
            Phase::Flush => {
                self.state = State::Ready { backing };
                Ok(true)
            }
        }
    }

    fn sync_frame(&self, backing: usize, platform: &impl Platform) {
        // SAFETY: show established permanent exclusive ownership of this
        // complete backing, and the caller's CPU writes have now finished.
        unsafe {
            platform.sync(backing, FRAME_BYTES);
        }
        platform.barrier();
    }
    fn transfer(&mut self, backing: usize, platform: &impl Platform) -> Result<(), Error> {
        self.sync_frame(backing, platform);
        self.command(0x105, &transfer_body(), 0x1100, platform)
    }
    fn flush(&mut self, platform: &impl Platform) -> Result<(), Error> {
        self.command(0x104, &flush_body(), 0x1100, platform)
    }
}
fn transfer_body() -> [u8; 32] {
    let mut transfer = [0; 32];
    rectangle(&mut transfer);
    put32(&mut transfer, 24, 1);
    transfer
}
fn flush_body() -> [u8; 24] {
    let mut flush = [0; 24];
    rectangle(&mut flush);
    put32(&mut flush, 16, 1);
    flush
}
fn rectangle(bytes: &mut [u8]) {
    put32(bytes, 8, WIDTH as u32);
    put32(bytes, 12, HEIGHT as u32);
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn validate_response(bytes: &[u8], kind: u32, fence: u64) -> Result<(), Error> {
    if bytes.len() < 24
        || bytes[..4] != kind.to_le_bytes()
        || bytes[4..8] != 1u32.to_le_bytes()
        || bytes[8..16] != fence.to_le_bytes()
    {
        return Err(Error::Response);
    }
    if kind == 0x1101 && (bytes.len() < 408 || bytes[40..44] != 1u32.to_le_bytes()) {
        return Err(Error::Response);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Page, QueueMemory};
    use core::cell::{Cell, RefCell};
    use core::ptr::{read_volatile, write_volatile};
    use std::{boxed::Box, vec::Vec};

    struct Host {
        desc: usize,
        avail: usize,
        used: usize,
        request: usize,
        response: usize,
        completed: Cell<u16>,
        clock: Cell<u64>,
        commands: RefCell<Vec<Vec<u8>>>,
        frames: RefCell<Vec<(u32, u32)>>,
        frame: usize,
        fail_at: Cell<Option<usize>>,
        stale_fence: bool,
    }
    // SAFETY: the fake device uses leaked, aligned memory and volatile accesses
    // on this thread. No real DMA or concurrent access occurs in these tests.
    unsafe impl Platform for Host {
        fn physical(&self, address: usize, _: usize) -> Result<u64, Error> {
            Ok(address as u64)
        }
        unsafe fn sync(&self, _: usize, _: usize) {}
        fn now_ms(&self) -> u64 {
            let now = self.clock.get();
            self.clock.set(now + 100);
            now
        }
        fn barrier(&self) {
            if self.avail == 0 {
                return;
            }
            // SAFETY: these addresses are obtained from the permanently pinned
            // queue's UnsafeCell storage. Commands are handled synchronously.
            unsafe {
                let available = u16::from_le(read_volatile((self.avail + 2) as *const u16));
                if available == self.completed.get() {
                    return;
                }
                let ordinal = self.commands.borrow().len();
                if self.fail_at.get() == Some(ordinal) && !self.stale_fence {
                    return;
                }
                let len = u32::from_le(read_volatile((self.desc + 8) as *const u32)) as usize;
                let request: Vec<_> = (0..len)
                    .map(|offset| read_volatile((self.request + offset) as *const u8))
                    .collect();
                let kind = u32::from_le_bytes(request[..4].try_into().unwrap());
                if kind == 0x105 {
                    self.frames.borrow_mut().push((
                        read_volatile(self.frame as *const u32),
                        read_volatile((self.frame + FRAME_BYTES - 4) as *const u32),
                    ));
                }
                let mut reply = [0; 408];
                put32(&mut reply, 0, if kind == 0x100 { 0x1101 } else { 0x1100 });
                put32(&mut reply, 4, 1);
                reply[8..16].copy_from_slice(&request[8..16]);
                if self.fail_at.get() == Some(ordinal) {
                    reply[8] ^= 1;
                }
                let len = if kind == 0x100 { 408 } else { 24 };
                put32(&mut reply, 40, 1);
                for (offset, byte) in reply[..len].iter().enumerate() {
                    write_volatile((self.response + offset) as *mut u8, *byte);
                }
                let slot = usize::from(self.completed.get() % 8);
                write_volatile((self.used + 4 + slot * 8) as *mut u32, 0);
                write_volatile((self.used + 8 + slot * 8) as *mut u32, (len as u32).to_le());
                write_volatile((self.used + 2) as *mut u16, available.to_le());
                self.completed.set(available);
                self.commands.borrow_mut().push(request);
            }
        }
    }
    fn fixture() -> (Gpu, Host) {
        let frame = unsafe {
            std::alloc::alloc_zeroed(
                std::alloc::Layout::from_size_align(FRAME_BYTES, 4096).unwrap(),
            )
        } as usize;
        assert_ne!(frame, 0);
        let mut host = Host {
            desc: 0,
            avail: 0,
            used: 0,
            request: 0,
            response: 0,
            completed: Cell::new(0),
            clock: Cell::new(0),
            commands: RefCell::new(Vec::new()),
            frames: RefCell::new(Vec::new()),
            frame,
            fail_at: Cell::new(None),
            stale_fence: false,
        };
        let mmio = Box::leak(Box::new(Page::zeroed()));
        mmio.put32(0, 0x74726976);
        mmio.put32(4, 2);
        mmio.put32(8, 16);
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
        host.desc = queue.memory.desc.address();
        host.avail = queue.memory.avail.address();
        host.used = queue.memory.used.address();
        host.request = queue.memory.request.address();
        host.response = queue.memory.response.address();
        (Gpu::new(transport, queue).unwrap(), host)
    }

    #[test]
    fn updates_reuse_backing_and_complete_both_fences() {
        let (mut gpu, host) = fixture();
        unsafe { gpu.show(host.frame, &host).unwrap() };
        for pixel in [0x123456, 0xabcdef] {
            gpu.update(
                |pixels| {
                    assert_eq!(pixels.len(), WIDTH * HEIGHT);
                    pixels[0] = pixel;
                    pixels[WIDTH * HEIGHT - 1] = pixel;
                },
                &host,
            )
            .unwrap();
        }
        assert_eq!(
            &*host.frames.borrow(),
            &[(0, 0), (0x123456, 0x123456), (0xabcdef, 0xabcdef)]
        );
        let commands = host.commands.borrow();
        assert_eq!(commands.len(), 10);
        for (index, command) in commands.iter().enumerate() {
            assert_eq!(&command[4..8], &1u32.to_le_bytes());
            assert_eq!(&command[8..16], &((index + 1) as u64).to_le_bytes());
        }
        for index in [6, 8] {
            let transfer = &commands[index];
            assert_eq!(&transfer[..4], &0x105u32.to_le_bytes());
            assert_eq!(transfer.len(), 56);
            assert_eq!(&transfer[24..32], &[0; 8]);
            assert_eq!(&transfer[32..36], &(WIDTH as u32).to_le_bytes());
            assert_eq!(&transfer[36..40], &(HEIGHT as u32).to_le_bytes());
            assert_eq!(&transfer[40..48], &[0; 8]);
            assert_eq!(&transfer[48..52], &1u32.to_le_bytes());
            assert_eq!(&commands[index + 1][..4], &0x104u32.to_le_bytes());
        }
    }

    #[test]
    fn asynchronous_submission_holds_backing_until_flush_fence() {
        let (mut gpu, host) = fixture();
        unsafe { gpu.show(host.frame, &host).unwrap() };
        assert_eq!(gpu.poll_update(&host), Ok(false));
        gpu.submit_update(|pixels| pixels[0] = 0x123456, &host)
            .unwrap();
        assert_eq!(host.commands.borrow().len(), 7);
        assert_eq!(
            gpu.submit_update(|_| panic!("transfer owns backing"), &host),
            Err(Error::Busy)
        );
        assert_eq!(gpu.poll_update(&host), Ok(false));
        assert_eq!(host.commands.borrow().len(), 8);
        assert_eq!(
            gpu.submit_update(|_| panic!("flush still pending"), &host),
            Err(Error::Busy)
        );
        assert_eq!(gpu.poll_update(&host), Ok(true));
        assert_eq!(gpu.poll_update(&host), Ok(false));
        gpu.submit_update(|pixels| pixels[0] = 0xabcdef, &host)
            .unwrap();
        assert_eq!(gpu.poll_update(&host), Ok(false));
        assert_eq!(gpu.poll_update(&host), Ok(true));
        assert_eq!(
            &*host.frames.borrow(),
            &[(0, 0), (0x123456, 0), (0xabcdef, 0)]
        );
    }

    #[test]
    fn pending_poll_returns_without_waiting_and_timeout_still_quarantines() {
        for command in [6, 7] {
            let (mut gpu, host) = fixture();
            unsafe { gpu.show(host.frame, &host).unwrap() };
            host.fail_at.set(Some(command));
            gpu.submit_update(|_| {}, &host).unwrap();
            if command == 7 {
                assert_eq!(gpu.poll_update(&host), Ok(false));
            }
            let before = host.clock.get();
            assert_eq!(gpu.poll_update(&host), Ok(false));
            // One deadline check, not the busy loop of Queue::transact.
            assert_eq!(host.clock.get() - before, 100);
            assert_eq!(gpu.poll_update(&host), Ok(false));
            assert_eq!(gpu.poll_update(&host), Err(Error::Timeout));
            assert_eq!(
                gpu.submit_update(|_| panic!("timed out backing"), &host),
                Err(Error::Device)
            );
            assert_eq!(gpu.poll_update(&host), Err(Error::Device));
        }
    }

    #[test]
    fn asynchronous_bad_fence_never_yields_a_success_completion() {
        for command in [6, 7] {
            let (mut gpu, mut host) = fixture();
            unsafe { gpu.show(host.frame, &host).unwrap() };
            host.stale_fence = true;
            host.fail_at.set(Some(command));
            gpu.submit_update(|_| {}, &host).unwrap();
            if command == 7 {
                assert_eq!(gpu.poll_update(&host), Ok(false));
            }
            assert_eq!(gpu.poll_update(&host), Err(Error::Response));
            assert_eq!(
                gpu.submit_update(|_| panic!("uncertain DMA fence"), &host),
                Err(Error::Device)
            );
        }
    }

    #[test]
    fn cannot_render_before_initialization_or_replace_live_backing() {
        let (mut gpu, host) = fixture();
        assert_eq!(
            gpu.update(|_| panic!("uninitialized render"), &host),
            Err(Error::Device)
        );
        unsafe { gpu.show(host.frame, &host).unwrap() };
        assert_eq!(unsafe { gpu.show(host.frame, &host) }, Err(Error::Busy));
        assert_eq!(host.commands.borrow().len(), 6);
    }

    #[test]
    fn transfer_or_flush_timeout_quarantines_frame_and_prevents_render() {
        for failed_command in [6, 7] {
            let (mut gpu, host) = fixture();
            unsafe { gpu.show(host.frame, &host).unwrap() };
            host.fail_at.set(Some(failed_command));
            assert_eq!(
                gpu.update(|pixels| pixels[0] = 1, &host),
                Err(Error::Timeout)
            );
            assert_eq!(
                gpu.update(|_| panic!("quarantined render"), &host),
                Err(Error::Device)
            );
            assert_eq!(unsafe { gpu.show(host.frame, &host) }, Err(Error::Device));
        }
    }

    #[test]
    fn stale_fence_quarantines_even_when_queue_completed() {
        let (mut gpu, mut host) = fixture();
        unsafe { gpu.show(host.frame, &host).unwrap() };
        host.stale_fence = true;
        host.fail_at.set(Some(6));
        assert_eq!(gpu.update(|_| {}, &host), Err(Error::Response));
        assert_eq!(
            gpu.update(|_| panic!("stale fence render"), &host),
            Err(Error::Device)
        );
    }

    #[test]
    fn every_initialization_timeout_prevents_retry_and_render() {
        for failed_command in 0..6 {
            let (mut gpu, host) = fixture();
            host.fail_at.set(Some(failed_command));
            assert_eq!(unsafe { gpu.show(host.frame, &host) }, Err(Error::Timeout));
            assert_eq!(unsafe { gpu.show(host.frame, &host) }, Err(Error::Device));
            assert_eq!(
                gpu.update(|_| panic!("incomplete initialization render"), &host),
                Err(Error::Device)
            );
            assert_eq!(host.commands.borrow().len(), failed_command);
        }
    }

    #[test]
    fn device_fault_prevents_cpu_borrow_and_fence_counter_never_wraps() {
        let (mut gpu, host) = fixture();
        unsafe { gpu.show(host.frame, &host).unwrap() };
        gpu.transport.write(0x70, 15 | 64);
        assert_eq!(
            gpu.update(|_| panic!("faulted device render"), &host),
            Err(Error::Device)
        );
        let (mut gpu, host) = fixture();
        unsafe { gpu.show(host.frame, &host).unwrap() };
        gpu.fence = u64::MAX;
        assert_eq!(gpu.update(|_| {}, &host), Err(Error::Exhausted));
        assert_eq!(host.commands.borrow().len(), 6);
        assert_eq!(
            gpu.update(|_| panic!("exhausted fence render"), &host),
            Err(Error::Device)
        );
    }
    #[test]
    fn rejects_truncated_wrong_kind_and_stale_fence() {
        let mut reply = [0; 24];
        put32(&mut reply, 0, 0x1100);
        put32(&mut reply, 4, 1);
        reply[8..16].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(validate_response(&reply, 0x1100, 7), Ok(()));
        assert_eq!(
            validate_response(&reply[..23], 0x1100, 7),
            Err(Error::Response)
        );
        assert_eq!(validate_response(&reply, 0x1100, 8), Err(Error::Response));
        assert_eq!(validate_response(&reply, 0x1101, 7), Err(Error::Response));
        put32(&mut reply, 4, 0);
        assert_eq!(validate_response(&reply, 0x1100, 7), Err(Error::Response));
    }
}
