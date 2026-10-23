//! Linux event/stream-message subset needed by the real Wayland event loop.
//! Bounded SCM_RIGHTS uses real shared open descriptions; unsupported object
//! types and message flags fail before any stream byte is consumed.
use super::{Errno, Runner, Wait, fd};
use cyxia_posix::{OPEN_MAX, epoll};

impl Runner {
    pub(super) fn nanosleep(
        &mut self,
        clock: u64,
        flags: u64,
        request: u64,
        remaining: u64,
    ) -> Result<u64, Errno> {
        if clock > 1 || flags > 1 {
            return Err(Errno::Inval);
        }
        // CLOCK_REALTIME absolute deadlines require tracking RTC changes while
        // parked. Until that service exists, only MONOTONIC absolute is offered.
        if clock == 0 && flags == 1 {
            return Err(Errno::Nosys);
        }
        let mut bytes = [0u8; 16];
        self.copy_from(request, &mut bytes)?;
        let seconds = i64::from_le_bytes(bytes[..8].try_into().unwrap());
        let ns = i64::from_le_bytes(bytes[8..].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000_000).contains(&ns) {
            return Err(Errno::Inval);
        }
        let requested_ns = (seconds as u64)
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(ns as u64))
            .ok_or(Errno::Overflow)?;
        let now = super::now_ns();
        let deadline_ns = if flags == 1 {
            requested_ns
        } else {
            now.checked_add(requested_ns).ok_or(Errno::Overflow)?
        };
        let remaining = if flags == 1 { 0 } else { remaining };
        if remaining != 0 {
            self.validate(remaining, 16, true)?;
        }
        if now < deadline_ns {
            self.block(Wait::Nanosleep {
                until: deadline_ns.div_ceil(1_000_000),
                deadline_ns,
                remaining,
            });
        }
        Ok(0)
    }

    pub(super) fn sleep_interrupted(&mut self) -> Result<(), Errno> {
        if let Some(Wait::Nanosleep {
            deadline_ns,
            remaining,
            ..
        }) = self.thread.waiting
            && remaining != 0
        {
            let left = deadline_ns.saturating_sub(super::now_ns());
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(left / 1_000_000_000).to_le_bytes());
            bytes[8..].copy_from_slice(&(left % 1_000_000_000).to_le_bytes());
            self.copy_to(remaining, &bytes)?;
        }
        Ok(())
    }

    fn source_readiness(source: epoll::Source) -> Result<u32, Errno> {
        Ok(match source {
            epoll::Source::Local { read, write } => u32::from(read) | (u32::from(write) << 2),
            epoll::Source::Timer { deadline } => {
                u32::from(deadline.is_some_and(|deadline| super::now_ns() >= deadline))
            }
            epoll::Source::Socket { owner, handle } => {
                let ready = super::unix::with(|s| s.poll(owner, super::unix::handle(handle)))?;
                u32::from(ready.readable)
                    | (u32::from(ready.writable) << 2)
                    | if ready.hangup { epoll::HUP } else { 0 }
                    | if ready.read_hangup { epoll::RDHUP } else { 0 }
            }
            epoll::Source::Pipe { owner, handle } => {
                u32::from(super::pipes::with(|p| p.poll(owner, handle))?)
            }
            epoll::Source::Pty { owner, handle } => {
                u32::from(super::pty::with(|p| p.poll(owner, handle))?)
            }
        })
    }

    fn epoll_readiness(&self, epfd: i32) -> Result<[u32; OPEN_MAX], Errno> {
        let descriptors = self.process.epoll_sources(epfd)?;
        let mut readiness = [0u32; OPEN_MAX];
        for (i, descriptor) in descriptors.into_iter().enumerate() {
            if let Some(descriptor) = descriptor {
                readiness[i] = Self::source_readiness(descriptor)?;
            }
        }
        Ok(readiness)
    }

    pub(super) fn epoll_readable(&mut self, epfd: i32) -> Result<bool, Errno> {
        let readiness = self.epoll_readiness(epfd)?;
        self.process.epoll_readable(epfd, &readiness)
    }

    pub(super) fn epoll_control(
        &mut self,
        epfd: u64,
        operation: u64,
        target: u64,
        address: u64,
    ) -> Result<u64, Errno> {
        let operation = u32::try_from(operation).map_err(|_| Errno::Inval)?;
        let mut event = epoll::Event::default();
        if operation != 2 {
            let mut bytes = [0u8; 16]; // AArch64 epoll_data_t is 8-byte aligned.
            self.copy_from(address, &mut bytes)?;
            event.events = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            event.data = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        }
        if operation == 1
            && let Some(raw) = self.process.socket(fd(target)?)?
        {
            // This bounded stream implementation supports connected sockets
            // and listeners. Reject an unconnected watch at registration, not
            // later when it would poison a wait for other ready descriptors.
            super::unix::with(|s| {
                s.poll(
                    self.process.backend_owner(fd(target)?)?,
                    super::unix::handle(raw),
                )
            })?;
        }
        self.process
            .epoll_ctl(fd(epfd)?, operation, fd(target)?, event)?;
        Ok(0)
    }

    pub(super) fn epoll_result(
        &mut self,
        epfd: i32,
        address: u64,
        count: usize,
    ) -> Result<usize, Errno> {
        let count = count.min(OPEN_MAX);
        if count == 0 {
            return Err(Errno::Inval);
        }
        self.validate(address, count * 16, true)?;
        let readiness = self.epoll_readiness(epfd)?;
        let mut events = [epoll::Event::default(); OPEN_MAX];
        let size = self
            .process
            .epoll_collect(epfd, &readiness, &mut events[..count])?;
        let mut encoded = [0u8; OPEN_MAX * 16];
        for (event, bytes) in events[..size].iter().zip(encoded.chunks_exact_mut(16)) {
            bytes[..4].copy_from_slice(&event.events.to_le_bytes());
            bytes[8..16].copy_from_slice(&event.data.to_le_bytes());
        }
        self.copy_to(address, &encoded[..size * 16])?;
        Ok(size)
    }

    pub(super) fn epoll_wait(
        &mut self,
        epfd: u64,
        address: u64,
        count: u64,
        timeout: u64,
        mask: u64,
        _mask_size: u64,
    ) -> Result<u64, Errno> {
        if mask != 0 {
            return Err(Errno::Nosys);
        }
        let count = usize::try_from(count as i32)
            .ok()
            .filter(|n| *n > 0)
            .ok_or(Errno::Inval)?
            .min(OPEN_MAX);
        let descriptor = fd(epfd)?;
        let until = if (timeout as i32) < 0 {
            u64::MAX
        } else {
            super::now()
                .saturating_add(u64::from(timeout as u32))
                .saturating_add(u64::from(timeout != 0))
        };
        let ready = self.epoll_result(descriptor, address, count)?;
        if ready == 0 && super::now() < until {
            let identity = self.process.epoll_identity(descriptor)?;
            self.block(Wait::Epoll {
                descriptor,
                identity,
                address,
                count,
                until,
            });
        }
        Ok(ready as u64)
    }

    pub(super) fn socket_message(
        &mut self,
        fs: &mut cyxia_ai_fs::FileSystem,
        descriptor: u64,
        address: u64,
        flags: u64,
        writing: bool,
    ) -> Result<u64, Errno> {
        const DONTWAIT: u64 = 0x40;
        const NOSIGNAL: u64 = 0x4000;
        const CMSG_CLOEXEC: u64 = 0x4000_0000;
        let supported = DONTWAIT | if writing { NOSIGNAL } else { CMSG_CLOEXEC };
        if flags & !supported != 0 {
            return Err(Errno::Nosys);
        }
        let descriptor = fd(descriptor)?;
        let handle = self.socket_handle(descriptor)?;
        let mut header = [0u8; 56];
        self.copy_from(address, &mut header)?;
        if !writing {
            self.validate(address, header.len(), true)?;
        }
        let field = |start| u64::from_le_bytes(header[start..start + 8].try_into().unwrap());
        let name = field(0);
        let name_length = u32::from_le_bytes(header[8..12].try_into().unwrap());
        let vector_address = field(16);
        let vector_count = usize::try_from(field(24))
            .ok()
            .filter(|n| *n <= 16)
            .ok_or(Errno::Inval)?;
        let control = field(32);
        let control_length = usize::try_from(field(40)).map_err(|_| Errno::Inval)?;
        let mut rights = [-1; cyxia_posix::ancillary::MAX_RIGHTS];
        let mut rights_count = 0;
        if writing && control_length != 0 {
            // Eight one-FD headers are the largest supported representation.
            let mut wire = [0u8; 8 * 24];
            if control_length > wire.len() {
                return Err(Errno::Inval);
            }
            self.copy_from(control, &mut wire[..control_length])?;
            (rights, rights_count) =
                cyxia_posix::ancillary::parse_control(&wire[..control_length])?;
            if rights_count != 0 {
                self.process.validate_rights(&rights[..rights_count])?;
            }
        }
        if writing && name != 0 && name_length != 0 {
            return Err(Errno::Nosys);
        }
        // On connected streams recvmsg accepts a source-address output buffer.
        // This subset returns no address (msg_namelen = 0), so it never accesses
        // the optional buffer. In particular, do not reject rustix's ordinary
        // sockaddr_storage request or fabricate peer address bytes.
        if !writing && control_length != 0 {
            self.validate(control, control_length, true)?;
        }
        let mut vectors = [0u8; 16 * 16];
        self.copy_from(vector_address, &mut vectors[..vector_count * 16])?;
        let mut total = 0usize;
        for vector in vectors[..vector_count * 16].chunks_exact(16) {
            let pointer = u64::from_le_bytes(vector[..8].try_into().unwrap());
            let length = super::count(u64::from_le_bytes(vector[8..].try_into().unwrap()))?;
            self.validate(pointer, length, !writing)?;
            total = total
                .checked_add(length)
                .filter(|n| *n <= isize::MAX as usize)
                .ok_or(Errno::Inval)?;
        }
        // The stream may return a short prefix. Gather once, so a multi-iovec
        // send never partially commits before checking subsequent addresses.
        let mut bytes = [0u8; 1024];
        let capacity = total.min(bytes.len());
        let mut copied = 0;
        if writing {
            for vector in vectors[..vector_count * 16].chunks_exact(16) {
                let pointer = u64::from_le_bytes(vector[..8].try_into().unwrap());
                let length = (u64::from_le_bytes(vector[8..].try_into().unwrap()) as usize)
                    .min(capacity - copied);
                self.copy_from(pointer, &mut bytes[copied..copied + length])?;
                copied += length;
                if copied == capacity {
                    break;
                }
            }
        }
        let owner = self.process.backend_owner(descriptor)?;
        let mut received = None;
        let result = if writing {
            if rights_count != 0 {
                super::unix::write_rights(
                    fs,
                    &self.process,
                    owner,
                    handle,
                    &bytes[..capacity],
                    &rights[..rights_count],
                )
            } else {
                super::unix::with(|s| {
                    s.write(owner, super::unix::handle(handle), &bytes[..capacity])
                })
            }
        } else {
            super::unix::with(|s| {
                s.read_message(owner, super::unix::handle(handle), &mut bytes[..capacity])
            })
            .and_then(|(n, ticket)| {
                if let Some(ticket) = ticket {
                    let limit = if control_length >= 20 {
                        (control_length - 16) / 4
                    } else {
                        0
                    };
                    let out = self.process.receive_rights(
                        fs,
                        ticket,
                        limit,
                        flags & CMSG_CLOEXEC != 0,
                    )?;
                    for item in out.released {
                        super::objects::release(fs, item)?;
                    }
                    super::unix::receipt_release(out.original_count, false);
                    received = Some(out);
                }
                Ok(n)
            })
        };
        if writing && result == Err(Errno::Pipe) && flags & NOSIGNAL == 0 {
            self.queue_signal(13, cyxia_posix::signal::Info::EMPTY, false)?;
        }
        if !writing && let Ok(n) = result {
            copied = 0;
            for vector in vectors[..vector_count * 16].chunks_exact(16) {
                let pointer = u64::from_le_bytes(vector[..8].try_into().unwrap());
                let length =
                    (u64::from_le_bytes(vector[8..].try_into().unwrap()) as usize).min(n - copied);
                self.copy_to(pointer, &bytes[copied..copied + length])?;
                copied += length;
                if copied == n {
                    break;
                }
            }
            header[8..12].fill(0); // No source address for this connected stream subset.
            header[40..48].fill(0);
            header[48..52].fill(0);
            if let Some(out) = received {
                if out.truncated {
                    header[48..52].copy_from_slice(&8u32.to_le_bytes());
                } // MSG_CTRUNC
                if out.count != 0 {
                    let length = 16 + out.count * 4;
                    let space = ((length + 7) & !7).min(control_length);
                    let mut wire = [0u8; 48];
                    wire[..8].copy_from_slice(&(length as u64).to_le_bytes());
                    wire[8..12].copy_from_slice(&1i32.to_le_bytes());
                    wire[12..16].copy_from_slice(&1i32.to_le_bytes());
                    for (chunk, fd) in wire[16..length].chunks_exact_mut(4).zip(out.fds) {
                        chunk.copy_from_slice(&fd.to_le_bytes());
                    }
                    self.copy_to(control, &wire[..space])?;
                    header[40..48].copy_from_slice(&(space as u64).to_le_bytes());
                }
            }
            self.copy_to(address, &header)?;
        }
        // Ancillary sends currently have one nonblocking commit attempt, even
        // on a blocking socket. Replaying this SVC would re-resolve source FD
        // numbers after another thread could close/reuse them. A future blocking
        // implementation must retain the staged ticket in thread wait state and
        // cancel it on every signal/exit path; never silently resend replacements.
        if flags & DONTWAIT != 0 || (writing && rights_count != 0) {
            result.map(|n| n as u64)
        } else {
            self.socket_wait(descriptor, writing, descriptor as u64, result)
        }
    }
}
