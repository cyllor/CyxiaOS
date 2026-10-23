//! Initial Linux AArch64 syscall personality for explicitly selected static ELF.
//! Native SVC numbers remain a separate personality. Unsupported calls fail;
//! successful musl probes do not imply general Linux binary compatibility.
use super::{Errno, FileSystem, GrantLedger, LocalIpc, Output, Runner, UserState, count, fd};
#[cfg(feature = "graphics")]
static mut DRAW: [u32; 16384] = [0; 16384];

#[cfg(feature = "graphics")]
fn display_error(error: cyxia_driver_virtio::Error) -> Errno {
    match error {
        cyxia_driver_virtio::Error::Address => Errno::Inval,
        cyxia_driver_virtio::Error::Device => Errno::Nodev,
        cyxia_driver_virtio::Error::Busy => Errno::Again,
        _ => Errno::Io,
    }
}

impl Runner {
    fn descriptor_flags(&self, descriptor: i32) -> Result<u32, Errno> {
        self.process.flags(descriptor)
    }
    fn set_descriptor_flags(&mut self, descriptor: i32, flags: u32) -> Result<(), Errno> {
        self.process.set_flags(descriptor, flags)
    }
    fn asset_mode(path: cyxia_ai_fs::Path) -> u16 {
        if super::PORTED.iter().any(|(_, p, _)| *p == path.as_str()) {
            0o555
        } else {
            0o444
        }
    }
    fn readonly_asset(&self, path: cyxia_ai_fs::Path) -> Option<(u64, &'static [u8])> {
        super::ROOT_FILES
            .iter()
            .enumerate()
            .find(|(_, (p, _))| *p == path.as_str())
            .map(|(i, (_, bytes))| (0x10000 + i as u64, *bytes))
    }
    fn path_stat(&self, fs: &FileSystem, path: &str) -> Result<cyxia_posix::FileInfo, Errno> {
        self.resolved_stat(fs, self.process.resolved_path(fs, path)?)
    }
    fn resolved_stat(
        &self,
        fs: &FileSystem,
        path: cyxia_ai_fs::Path,
    ) -> Result<cyxia_posix::FileInfo, Errno> {
        if let Some((inode, bytes)) = self.readonly_asset(path) {
            return Ok(cyxia_posix::FileInfo {
                inode,
                size: bytes.len() as u64,
                mode: 0o100000 | u32::from(Self::asset_mode(path)),
                links: 1,
            });
        }
        self.process.stat_resolved(fs, path)
    }
    fn copy_stat(&mut self, address: u64, info: cyxia_posix::FileInfo) -> Result<u64, Errno> {
        let mut bytes = [0u8; 128];
        bytes[..8].copy_from_slice(&1u64.to_le_bytes()); // Single RAM/rootfs device.
        bytes[8..16].copy_from_slice(&info.inode.to_le_bytes());
        bytes[16..20].copy_from_slice(&info.mode.to_le_bytes());
        bytes[20..24].copy_from_slice(&info.links.to_le_bytes());
        bytes[48..56].copy_from_slice(&info.size.to_le_bytes());
        bytes[56..60].copy_from_slice(&4096u32.to_le_bytes());
        bytes[64..72].copy_from_slice(&info.size.div_ceil(512).to_le_bytes());
        // Files have no wall-clock timestamps until an RTC service exists.
        self.copy_to(address, &bytes)?;
        Ok(0)
    }
    fn descriptor_stat(
        &self,
        fs: &FileSystem,
        descriptor: i32,
    ) -> Result<cyxia_posix::FileInfo, Errno> {
        if self.process.memfd(descriptor)?.is_some() {
            self.memfd_info(descriptor)
        } else {
            self.process.fstat(fs, descriptor)
        }
    }
    pub(super) fn poll_result(&mut self, address: u64, count: usize) -> Result<usize, Errno> {
        let mut bytes = [0u8; cyxia_posix::OPEN_MAX * 8];
        if count > cyxia_posix::OPEN_MAX {
            return Err(Errno::Inval);
        }
        self.validate(address, count * 8, true)?;
        self.copy_from(address, &mut bytes[..count * 8])?;
        let mut ready_count = 0;
        for record in bytes[..count * 8].chunks_exact_mut(8) {
            let descriptor = i32::from_le_bytes(record[..4].try_into().map_err(|_| Errno::Inval)?);
            let events = u16::from_le_bytes(record[4..6].try_into().map_err(|_| Errno::Inval)?);
            let available = if descriptor < 0 {
                0
            } else {
                match self.process.socket(descriptor) {
                    Ok(Some(raw)) => {
                        let owner = self.process.backend_owner(descriptor)?;
                        let ready = super::unix::with(|s| s.poll(owner, super::unix::handle(raw)))?;
                        u16::from(ready.readable)
                            | (u16::from(ready.writable) << 2)
                            | (u16::from(ready.hangup) << 4)
                            | (u16::from(ready.read_hangup) << 13)
                    }
                    Ok(None) => {
                        let owner = self.process.backend_owner(descriptor)?;
                        if let Some(raw) = self.process.pipe(descriptor)? {
                            super::pipes::with(|p| p.poll(owner, raw))?
                        } else if let Some(raw) = self.process.pty(descriptor)? {
                            super::pty::with(|p| p.poll(owner, raw))?
                        } else if self.process.is_timerfd(descriptor)? {
                            u16::from(self.process.timerfd_ready(descriptor, super::now_ns())?)
                        } else if self.process.is_epoll(descriptor)? {
                            u16::from(self.epoll_readable(descriptor)?)
                        } else {
                            let (read, write) = self.process.local_readiness(descriptor)?;
                            u16::from(read) | (u16::from(write) << 2)
                        }
                    }
                    Err(Errno::Badf) => 0x20,
                    Err(error) => return Err(error),
                }
            };
            let revents = (available & events) | (available & 0x38);
            record[6..8].copy_from_slice(&revents.to_le_bytes());
            ready_count += usize::from(revents != 0);
        }
        self.copy_to(address, &bytes[..count * 8])?;
        Ok(ready_count)
    }
    fn relative_deadline(&self, address: u64) -> Result<u64, Errno> {
        let mut timespec = [0u8; 16];
        self.copy_from(address, &mut timespec)?;
        let sec = i64::from_le_bytes(timespec[..8].try_into().map_err(|_| Errno::Inval)?);
        let ns = i64::from_le_bytes(timespec[8..].try_into().map_err(|_| Errno::Inval)?);
        if sec < 0 || !(0..1_000_000_000).contains(&ns) {
            return Err(Errno::Inval);
        }
        (sec as u64)
            .checked_mul(1000)
            .and_then(|ms| ms.checked_add((ns as u64).div_ceil(1_000_000)))
            // now() floors the clock. Positive relative waits must not expire
            // almost one millisecond early within the current timer tick.
            .and_then(|ms| ms.checked_add(u64::from(sec != 0 || ns != 0)))
            .and_then(|ms| super::now().checked_add(ms))
            .ok_or(Errno::Overflow)
    }
    pub(super) fn socket_handle(&self, descriptor: i32) -> Result<u64, Errno> {
        self.process.socket(descriptor)?.ok_or(Errno::Inval)
    }
    fn linux_read(
        &mut self,
        fs: &mut FileSystem,
        descriptor: i32,
        bytes: &mut [u8],
    ) -> Result<usize, Errno> {
        let owner = self.process.backend_owner(descriptor)?;
        if self.process.is_timerfd(descriptor)? {
            self.process
                .timerfd_read(descriptor, super::now_ns(), bytes)
        } else if self.process.memfd(descriptor)?.is_some() {
            self.read_memfd(descriptor, bytes)
        } else if let Some(raw) = self.process.socket(descriptor)? {
            super::unix::read(fs, owner, raw, bytes)
        } else if let Some(raw) = self.process.pipe(descriptor)? {
            super::pipes::with(|p| p.read(owner, raw, bytes))
        } else if let Some(raw) = self.process.pty(descriptor)? {
            super::pty::with(|p| p.read(owner, raw, bytes))
        } else {
            self.process.read(fs, descriptor, bytes)
        }
    }
    fn linux_write(
        &mut self,
        fs: &mut FileSystem,
        descriptor: i32,
        bytes: &[u8],
    ) -> Result<usize, Errno> {
        let owner = self.process.backend_owner(descriptor)?;
        if self.process.memfd(descriptor)?.is_some() {
            self.write_memfd(descriptor, bytes)
        } else if let Some(raw) = self.process.socket(descriptor)? {
            let result = super::unix::with(|s| s.write(owner, super::unix::handle(raw), bytes));
            if result == Err(Errno::Pipe) {
                self.queue_signal(13, cyxia_posix::signal::Info::EMPTY, false)?;
            }
            result
        } else if self.process.pipe(descriptor)?.is_some() {
            self.pipe_write(descriptor, bytes, bytes.len())
        } else if let Some(raw) = self.process.pty(descriptor)? {
            super::pty::with(|p| p.write(owner, raw, bytes))
        } else {
            self.process.write(fs, &mut Output, descriptor, bytes)
        }
    }
    fn pipe_write(
        &mut self,
        descriptor: i32,
        bytes: &[u8],
        requested: usize,
    ) -> Result<usize, Errno> {
        let raw = self.process.pipe(descriptor)?.ok_or(Errno::Badf)?;
        let owner = self.process.backend_owner(descriptor)?;
        let result = super::pipes::with(|p| p.write_prefix(owner, raw, bytes, requested));
        if result == Err(Errno::Pipe) {
            self.queue_signal(
                13,
                cyxia_posix::signal::Info {
                    sender_pid: self.status.pid,
                    ..cyxia_posix::signal::Info::EMPTY
                },
                false,
            )?;
        }
        result
    }
    fn linux_close(&mut self, fs: &mut FileSystem, descriptor: i32) -> Result<(), Errno> {
        let released = self.process.close(fs, descriptor)?;
        super::objects::release(fs, released)
    }
    fn install_socket(&mut self, fs: &mut FileSystem, raw: u64, flags: u32) -> Result<i32, Errno> {
        match self.process.install_socket(raw, flags) {
            Ok(fd) => Ok(fd),
            Err(error) => {
                let _ = super::unix::close(fs, self.status.pid, raw);
                Err(error)
            }
        }
    }
    fn vector_io(
        &mut self,
        fs: &mut FileSystem,
        descriptor: i32,
        vector_address: u64,
        vector_count: u64,
        writing: bool,
    ) -> Result<usize, Errno> {
        let mut bytes = [0u8; 1024];
        // Validate every vector before the first side effect.
        let vectors = usize::try_from(vector_count)
            .ok()
            .filter(|n| *n <= 16)
            .ok_or(Errno::Inval)?;
        let mut encoded = [0u8; 256];
        self.copy_from(vector_address, &mut encoded[..vectors * 16])?;
        let mut total = 0usize;
        for vector in encoded[..vectors * 16].chunks_exact(16) {
            let address = u64::from_le_bytes(vector[..8].try_into().map_err(|_| Errno::Inval)?);
            let n = count(u64::from_le_bytes(
                vector[8..].try_into().map_err(|_| Errno::Inval)?,
            ))?;
            self.validate(address, n, !writing)?;
            total = total
                .checked_add(n)
                .filter(|n| *n <= isize::MAX as usize)
                .ok_or(Errno::Inval)?;
        }
        if writing && self.process.pipe(descriptor)?.is_some() {
            // One writev of <= PIPE_BUF must remain atomic across all iovecs.
            let mut pipe_bytes = [0u8; cyxia_posix::pipe::PIPE_BUF];
            let mut copied = 0;
            for vector in encoded[..vectors * 16].chunks_exact(16) {
                let address = u64::from_le_bytes(vector[..8].try_into().map_err(|_| Errno::Inval)?);
                let n = count(u64::from_le_bytes(
                    vector[8..].try_into().map_err(|_| Errno::Inval)?,
                ))?
                .min(pipe_bytes.len() - copied);
                if n != 0 {
                    self.copy_from(address, &mut pipe_bytes[copied..copied + n])?;
                    copied += n;
                }
                if copied == pipe_bytes.len() {
                    break;
                }
            }
            return self.pipe_write(descriptor, &pipe_bytes[..copied], total);
        }
        // eventfd read_iter scatters one u64; legacy writev invokes a separate
        // exact-eight-byte write for each vector, with normal partial success.
        if self.process.is_eventfd(descriptor)? || self.process.is_timerfd(descriptor)? {
            if total == 0 {
                return Ok(0);
            }
            if writing {
                if self.process.is_timerfd(descriptor)? {
                    return Err(Errno::Inval);
                }
                let mut done = 0;
                for vector in encoded[..vectors * 16].chunks_exact(16) {
                    let address =
                        u64::from_le_bytes(vector[..8].try_into().map_err(|_| Errno::Inval)?);
                    let n = count(u64::from_le_bytes(
                        vector[8..].try_into().map_err(|_| Errno::Inval)?,
                    ))?;
                    if n == 0 && done > 0 {
                        continue;
                    }
                    let result = if n == 8 {
                        self.copy_from(address, &mut bytes[..8])?;
                        self.linux_write(fs, descriptor, &bytes[..8])
                    } else {
                        Err(Errno::Inval)
                    };
                    match result {
                        Ok(n) => done += n,
                        Err(_) if done > 0 => break,
                        Err(e) => return Err(e),
                    }
                }
                return Ok(done);
            }
            if total < 8 {
                return Err(Errno::Inval);
            }
            let mut position = 0;
            self.linux_read(fs, descriptor, &mut bytes[..8])?;
            for vector in encoded[..vectors * 16].chunks_exact(16) {
                let address = u64::from_le_bytes(vector[..8].try_into().map_err(|_| Errno::Inval)?);
                let n = count(u64::from_le_bytes(
                    vector[8..].try_into().map_err(|_| Errno::Inval)?,
                ))?
                .min(8 - position);
                if n == 0 {
                    continue;
                }
                self.copy_to(address, &bytes[position..position + n])?;
                position += n;
                if position == 8 {
                    break;
                }
            }
            return Ok(8);
        }
        // Validate even when iovcnt=0; no bytes are consumed here.
        if writing {
            self.linux_write(fs, descriptor, &[])?;
        } else {
            self.linux_read(fs, descriptor, &mut [])?;
        }
        let mut done = 0usize;
        for vector in encoded[..vectors * 16].chunks_exact(16) {
            let address = u64::from_le_bytes(vector[..8].try_into().map_err(|_| Errno::Inval)?);
            let n = count(u64::from_le_bytes(
                vector[8..].try_into().map_err(|_| Errno::Inval)?,
            ))?;
            if n == 0 {
                continue;
            }
            let chunk = n.min(bytes.len());
            let result = if writing {
                self.copy_from(address, &mut bytes[..chunk])?;
                self.linux_write(fs, descriptor, &bytes[..chunk])
            } else {
                self.linux_read(fs, descriptor, &mut bytes[..chunk])
            };
            match result {
                Ok(written) => {
                    if !writing {
                        self.copy_to(address, &bytes[..written])?;
                    }
                    done += written;
                    if written < n {
                        break;
                    }
                }
                Err(_) if done > 0 => break,
                Err(error) => return Err(error),
            }
            if done >= 1024 {
                break;
            }
        }
        Ok(done)
    }
    fn socket_address_capacity(&self, address: u64, length: u64) -> Result<usize, Errno> {
        let mut encoded = [0; 4];
        self.copy_from(length, &mut encoded)?;
        self.validate(length, 4, true)?;
        let capacity = u32::from_le_bytes(encoded) as usize;
        self.validate(address, capacity.min(110), true)?;
        Ok(capacity)
    }
    fn copy_socket_address(
        &mut self,
        address: u64,
        length: u64,
        capacity: usize,
        handle: u64,
        owner: u32,
        peer: bool,
    ) -> Result<(), Errno> {
        let (wire, len) =
            super::unix::with(|s| s.socket_name(owner, super::unix::handle(handle), peer))?;
        self.copy_to(address, &wire[..len.min(capacity)])?;
        self.copy_to(length, &(len as u32).to_le_bytes())
    }
    fn socket_address(
        &self,
        fs: &FileSystem,
        address: u64,
        len: u64,
        create: bool,
    ) -> Result<([u8; 108], usize), Errno> {
        let len = count(len)?;
        if !(3..=110).contains(&len) {
            return Err(Errno::Inval);
        }
        let mut bytes = [0u8; 110];
        self.copy_from(address, &mut bytes[..len])?;
        if bytes[..2] != [1, 0] {
            return Err(Errno::Inval);
        }
        let mut name = [0u8; 108];
        if bytes[2] == 0 {
            name[..len - 2].copy_from_slice(&bytes[2..len]);
            return Ok((name, len - 2));
        }
        let end = bytes[2..len]
            .iter()
            .position(|b| *b == 0)
            .map_or(len, |i| i + 2);
        let path = core::str::from_utf8(&bytes[2..end]).map_err(|_| Errno::Inval)?;
        let resolved = self.process.socket_path(fs, path, create)?;
        let path = resolved.as_str().as_bytes();
        name[..path.len()].copy_from_slice(path);
        Ok((name, path.len()))
    }
    pub(super) fn socket_wait(
        &mut self,
        descriptor: i32,
        write: bool,
        original_a: u64,
        result: Result<usize, Errno>,
    ) -> Result<u64, Errno> {
        if result == Err(Errno::Again)
            && self.descriptor_flags(descriptor)? & cyxia_posix::O_NONBLOCK == 0
        {
            let identity = self.process.description_identity(descriptor)?;
            let socket = self.process.socket(descriptor)?;
            let pc = self.thread.context.pc.checked_sub(4).ok_or(Errno::Fault)?;
            self.thread.context.pc = pc;
            self.thread.retry_syscall = true;
            self.thread.retry_descriptor = Some((descriptor, identity));
            let wait = if let Some(raw) = socket {
                super::Wait::Unix {
                    handle: raw,
                    descriptor,
                    write,
                }
            } else if self.process.is_timerfd(descriptor)? {
                super::Wait::TimerRead {
                    descriptor,
                    identity,
                }
            } else {
                super::Wait::Retry(super::now().saturating_add(1))
            };
            self.block(wait);
            return Ok(original_a); // Retry the identical SVC after identity validation.
        }
        self.thread.retry_syscall = false;
        self.thread.retry_descriptor = None;
        result.map(|n| n as u64)
    }
    pub(super) fn linux_syscall(
        &mut self,
        fs: &mut FileSystem,
        ledger: &mut GrantLedger,
        ipc: &mut LocalIpc,
    ) -> Result<u64, Errno> {
        let [a, b, c, d, e, f] = core::array::from_fn(|i| self.thread.context.regs[i]);
        let mut bytes = [0u8; 1024];
        match self.thread.context.regs[8] {
            20 => self
                .process
                .epoll_create(u32::try_from(a).map_err(|_| Errno::Inval)?)
                .map(|fd| fd as u64),
            21 => self.epoll_control(a, b, c, d),
            22 => self.epoll_wait(a, b, c, d, e, f),
            85 => self
                .process
                .timerfd_create(a as i32, u32::try_from(b).map_err(|_| Errno::Inval)?)
                .map(|fd| fd as u64),
            86 => self.timerfd_settime(a, b, c, d),
            87 => self.timerfd_gettime(a, b),
            211 | 212 => self.socket_message(fs, a, b, c, self.thread.context.regs[8] == 211),
            0x43595810 => self.request_spawn(a),
            0x43595820 => super::super::storage::start_checkpoint(fs),
            0x43595821 => super::super::storage::checkpoint_complete(a),
            260 => self.request_wait(a, b, c, d),
            173 => Ok(self.status.parent_pid as u64),
            19 => self
                .process
                .eventfd(a as u32, u32::try_from(b).map_err(|_| Errno::Inval)?)
                .map(|v| v as u64),
            59 => {
                let flags = u32::try_from(b).map_err(|_| Errno::Inval)?;
                if flags & !(cyxia_posix::O_NONBLOCK | cyxia_posix::O_CLOEXEC) != 0 {
                    return Err(Errno::Inval);
                }
                self.validate(a, 8, true)?;
                let handles = super::pipes::pair(self.status.pid)?;
                for handle in handles {
                    super::pipes::with(|p| {
                        p.set_flags(self.status.pid, handle, flags & !cyxia_posix::O_CLOEXEC)
                    })?;
                }
                let descriptors = match self.process.install_pipe(handles, flags) {
                    Ok(fds) => fds,
                    Err(error) => {
                        for handle in handles {
                            super::pipes::with(|p| p.close(self.status.pid, handle))?;
                        }
                        return Err(error);
                    }
                };
                bytes[..4].copy_from_slice(&descriptors[0].to_le_bytes());
                bytes[4..8].copy_from_slice(&descriptors[1].to_le_bytes());
                self.copy_to(a, &bytes[..8])?;
                Ok(0)
            }
            61 => {
                let size = count(c)?.min(bytes.len());
                self.validate(b, size, true)?;
                let n = self
                    .process
                    .getdents(fs, fd(a)?, super::ROOT_FILES, &mut bytes[..size])?;
                self.copy_to(b, &bytes[..n])?;
                Ok(n as u64)
            }
            17 => {
                let capacity = count(b)?.min(bytes.len());
                self.validate(a, capacity, true)?;
                let n = self.process.getcwd(&mut bytes[..capacity])?;
                self.copy_to(a, &bytes[..n])?;
                Ok(n as u64)
            }
            49 => {
                let mut path = [0u8; 96];
                let n = self.path(a, &mut path)?;
                self.process.chdir(
                    fs,
                    core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?,
                )?;
                Ok(0)
            }
            98 => self.futex(a, b, c, d, e, self.thread.context.regs[5]),
            220 => self.clone_thread(a, b, c, d, e),
            38 => self.rename_at(fs, a as i32, b, c as i32, d, 0),
            276 => self.rename_at(fs, a as i32, b, c as i32, d, e),
            160 => {
                let mut fields = [0u8; 390];
                for (field, value) in fields.chunks_exact_mut(65).zip([
                    "CyxiaOS",
                    "cyxia",
                    "0.1",
                    "native ARM kernel",
                    "aarch64",
                    "",
                ]) {
                    field[..value.len()].copy_from_slice(value.as_bytes());
                }
                self.copy_to(a, &fields)?;
                Ok(0)
            }
            166 => Ok(self.process.umask(a as u16) as u64),
            52 => self.process.fchmod(fs, fd(a)?, b as u16).map(|_| 0),
            53 => {
                let mut path = [0u8; 96];
                let n = self.path(b, &mut path)?;
                let path = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                if a as i64 != -100 && !path.starts_with('/') {
                    return Err(Errno::Badf);
                }
                self.process.chmod(fs, path, c as u16)?;
                Ok(0)
            }
            204 | 205 => {
                let handle = self.socket_handle(fd(a)?)?;
                let capacity = self.socket_address_capacity(b, c)?;
                self.copy_socket_address(
                    b,
                    c,
                    capacity,
                    handle,
                    self.process.backend_owner(fd(a)?)?,
                    self.thread.context.regs[8] == 205,
                )?;
                Ok(0)
            }
            209 => {
                let handle = self.socket_handle(fd(a)?)?;
                if b != 1 {
                    return Err(Errno::Nosys);
                }
                self.copy_from(e, &mut bytes[..4])?;
                let capacity = u32::from_le_bytes(bytes[..4].try_into().expect("socklen")) as usize;
                self.validate(e, 4, true)?;
                let size = match c {
                    3 => {
                        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
                        4
                    } // SOCK_STREAM
                    4 => {
                        bytes[..4].fill(0);
                        4
                    } // synchronous connect has no pending error
                    7 | 8 => {
                        bytes[..4].copy_from_slice(
                            &(cyxia_posix::unix::BUFFER_BYTES as u32).to_le_bytes(),
                        );
                        4
                    }
                    17 => {
                        let capability_owner = self.process.backend_owner(fd(a)?)?;
                        let owner = super::unix::with(|s| {
                            s.peer_owner(capability_owner, super::unix::handle(handle))
                        })?;
                        bytes[..4].copy_from_slice(&owner.to_le_bytes());
                        bytes[4..12].fill(0);
                        12
                    }
                    _ => return Err(Errno::Nosys),
                };
                let size = capacity.min(size);
                self.validate(d, size, true)?;
                self.copy_to(d, &bytes[..size])?;
                self.copy_to(e, &(size as u32).to_le_bytes())?;
                Ok(0)
            }
            210 => {
                let handle = self.socket_handle(fd(a)?)?;
                let owner = self.process.backend_owner(fd(a)?)?;
                super::unix::shutdown(fs, owner, handle, b)?;
                Ok(0)
            }
            208 => {
                self.socket_handle(fd(a)?)?;
                // SO_REUSEADDR has no effect on pathname AF_UNIX sockets.
                if b != 1 || c != 2 || e != 4 {
                    return Err(Errno::Nosys);
                }
                self.copy_from(d, &mut bytes[..4])?;
                Ok(0)
            }
            79 => {
                // AT_NO_AUTOMOUNT is a real no-op: this namespace has no
                // automount points. GLib passes it when falling back from statx.
                if d & !(0x100 | 0x800 | 0x1000) != 0 {
                    return Err(Errno::Inval);
                }
                let mut path = [0u8; 96];
                let n = self.path(b, &mut path)?;
                if n == 0 && d & 0x1000 != 0 {
                    if a as i32 != -100 {
                        return self.copy_stat(c, self.descriptor_stat(fs, fd(a)?)?);
                    }
                    return self.copy_stat(c, self.process.stat_empty_at(fs, a as i32)?);
                }
                let path = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                let resolved = self.process.path_at(fs, a as i32, path)?;
                self.copy_stat(c, self.resolved_stat(fs, resolved)?)
            }
            80 => self.copy_stat(b, self.descriptor_stat(fs, fd(a)?)?),
            46 => self.memfd_resize(fd(a)?, b),
            279 => self.memfd_create(a, b),
            48 => {
                let mut path = [0u8; 96];
                let n = self.path(b, &mut path)?;
                let path = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                if a as i64 != -100 && !path.starts_with('/') {
                    return Err(Errno::Badf);
                }
                if c & !7 != 0 {
                    return Err(Errno::Inval);
                }
                let info = self.path_stat(fs, path)?;
                if ((info.mode >> 6) & c as u32) != c as u32 {
                    return Err(Errno::Access);
                }
                Ok(0)
            }
            163 | 261 => {
                let (resource, new, old) = if self.thread.context.regs[8] == 163 {
                    (a, 0, b)
                } else {
                    if a != 0 && a != self.status.pid as u64 {
                        return Err(Errno::Noent);
                    }
                    (b, c, d)
                };
                if resource > 15 {
                    return Err(Errno::Inval);
                }
                let limit = match resource {
                    3 => (super::super::exec_memory::STACK_PAGES * 4096) as u64,
                    4 => 0,
                    6 => 3,
                    7 => cyxia_posix::OPEN_MAX as u64,
                    11 => 64,
                    _ => u64::MAX,
                };
                bytes[..8].copy_from_slice(&limit.to_le_bytes());
                bytes[8..16].copy_from_slice(&limit.to_le_bytes());
                if new != 0 {
                    let mut proposed = [0u8; 16];
                    self.copy_from(new, &mut proposed)?;
                    // Limit mutation is not implemented; only a true no-op is accepted.
                    if proposed != bytes[..16] {
                        return Err(Errno::Perm);
                    }
                }
                if old != 0 {
                    self.copy_to(old, &bytes[..16])?;
                }
                Ok(0)
            }
            132 => self.signal_stack(a, b),
            134 => self.signal_action(a, b, c, d),
            135 => self.signal_mask(a, b, c, d),
            139 => match self.signal_return() {
                Ok(value) => Ok(value),
                Err(_) => {
                    self.finish(fs, ledger, ipc, UserState::Fault, 139);
                    Ok(0)
                }
            },
            129..=131 => self.send_signal(self.thread.context.regs[8], a, b, c),
            154 => {
                if a != 0 && a != self.status.pid as u64 {
                    return Err(Errno::Noent);
                }
                if b != 0 && b != self.status.pid as u64 {
                    return Err(Errno::Perm);
                }
                Ok(0) // Each boot-launched process owns its own initial group.
            }
            155 | 156 => {
                if a == 0 || a == self.status.pid as u64 {
                    Ok(self.status.pid as u64)
                } else {
                    Err(Errno::Noent)
                }
            }
            73 => {
                // ppoll with a null temporary signal mask. Readiness and wait
                // registration are serialized, so there is no lost-wakeup gap.
                if d != 0 {
                    return Err(Errno::Nosys);
                }
                let count = count(b)?;
                let until = if c == 0 {
                    u64::MAX
                } else {
                    self.relative_deadline(c)?
                };
                let ready = self.poll_result(a, count)?;
                if ready == 0 && super::now() < until {
                    self.block(super::Wait::Poll {
                        address: a,
                        count,
                        until,
                    });
                }
                Ok(ready as u64)
            }
            101 => self.nanosleep(1, 0, a, b),
            115 => self.nanosleep(a, b, c, d),
            23 => self.process.dup(fd(a)?).map(|n| n as u64),
            24 => {
                let (old, new) = (fd(a)?, fd(b)?);
                if old == new || c & !(cyxia_posix::O_CLOEXEC as u64) != 0 {
                    return Err(Errno::Inval);
                }
                self.process.flags(old)?;
                if new as usize >= cyxia_posix::OPEN_MAX {
                    return Err(Errno::Badf);
                }
                if self.process.flags(new).is_ok() {
                    self.linux_close(fs, new)?;
                }
                let (_, released) = self.process.dup2(fs, old, new)?;
                super::objects::release(fs, released)?;
                self.process.set_close_on_exec(new, c != 0)?;
                Ok(new as u64)
            }
            25 => match b {
                0 | 1030 => self
                    .process
                    .dup_from(
                        fd(a)?,
                        i32::try_from(c).map_err(|_| Errno::Inval)?,
                        b == 1030,
                    )
                    .map(|n| n as u64),
                1 => self.process.close_on_exec(fd(a)?).map(u64::from),
                2 if c <= 1 => self.process.set_close_on_exec(fd(a)?, c != 0).map(|_| 0),
                3 => self.descriptor_flags(fd(a)?).map(u64::from),
                4 => self
                    .set_descriptor_flags(
                        fd(a)?,
                        u32::try_from(c).map_err(|_| Errno::Inval)? & !0x20000,
                    )
                    .map(|_| 0),
                1032 if self.process.pipe(fd(a)?)?.is_some() => {
                    Ok(cyxia_posix::pipe::CAPACITY as u64)
                }
                1033 | 1034 => self.memfd_control(fd(a)?, b, c),
                _ => Err(Errno::Inval),
            },
            198 | 199 => {
                let flags = u32::try_from(b).map_err(|_| Errno::Inval)?;
                if a != 1
                    || c != 0
                    || flags & !(1 | cyxia_posix::O_NONBLOCK | cyxia_posix::O_CLOEXEC) != 0
                    || flags & 1 == 0
                {
                    return Err(Errno::Nosys);
                }
                let flags = flags & !1;
                if self.thread.context.regs[8] == 198 {
                    let handle = super::unix::admit(1, 0, 0, |s| s.socket(self.status.pid))?;
                    self.install_socket(fs, handle.raw(), flags)
                        .map(|n| n as u64)
                } else {
                    self.validate(d, 8, true)?;
                    let handles = super::unix::admit(2, 1, 0, |s| s.socketpair(self.status.pid))?;
                    let left = match self.install_socket(fs, handles[0].raw(), flags) {
                        Ok(fd) => fd,
                        Err(error) => {
                            let _ = super::unix::close(fs, self.status.pid, handles[1].raw());
                            return Err(error);
                        }
                    };
                    let right = match self.install_socket(fs, handles[1].raw(), flags) {
                        Ok(fd) => fd,
                        Err(error) => {
                            self.linux_close(fs, left)?;
                            return Err(error);
                        }
                    };
                    bytes[..4].copy_from_slice(&left.to_le_bytes());
                    bytes[4..8].copy_from_slice(&right.to_le_bytes());
                    self.copy_to(d, &bytes[..8])?;
                    Ok(0)
                }
            }
            200 | 203 => {
                let raw = self.socket_handle(fd(a)?)?;
                let owner = self.process.backend_owner(fd(a)?)?;
                let binding = self.thread.context.regs[8] == 200;
                let (path, len) = self.socket_address(fs, b, c, binding)?;
                if binding {
                    super::unix::admit(0, 0, 1, |s| {
                        s.bind(owner, super::unix::handle(raw), &path[..len])
                    })?;
                } else {
                    super::unix::admit(1, 1, 0, |s| {
                        s.connect_for(
                            owner,
                            super::unix::handle(raw),
                            &path[..len],
                            self.status.pid,
                        )
                    })?;
                }
                Ok(0)
            }
            201 => {
                let raw = self.socket_handle(fd(a)?)?;
                let owner = self.process.backend_owner(fd(a)?)?;
                // Linux clamps large backlog values; zero still permits a pending connection.
                super::unix::with(|s| {
                    s.listen_for(
                        owner,
                        super::unix::handle(raw),
                        count(b)?.clamp(1, 8),
                        self.status.pid,
                    )
                })?;
                Ok(0)
            }
            202 | 242 => {
                let flags = if self.thread.context.regs[8] == 242 {
                    u32::try_from(d).map_err(|_| Errno::Inval)?
                } else {
                    0
                };
                if flags & !(cyxia_posix::O_NONBLOCK | cyxia_posix::O_CLOEXEC) != 0 {
                    return Err(Errno::Inval);
                }
                let raw = self.socket_handle(fd(a)?)?;
                let owner = self.process.backend_owner(fd(a)?)?;
                let capacity = if b != 0 {
                    self.socket_address_capacity(b, c)?
                } else {
                    0
                };
                match super::unix::with(|s| {
                    s.accept_for(owner, super::unix::handle(raw), self.status.pid)
                }) {
                    Ok(handle) => {
                        if b != 0 {
                            self.copy_socket_address(
                                b,
                                c,
                                capacity,
                                handle.raw(),
                                self.status.pid,
                                true,
                            )?;
                        }
                        self.install_socket(fs, handle.raw(), flags)
                            .map(|n| n as u64)
                    }
                    Err(error) => self.socket_wait(fd(a)?, false, a, Err(error)),
                }
            }
            // Explicit CyxiaOS extensions used by the native X.Org DDX. These
            // numbers are deliberately separate from the Linux syscall ABI.
            #[cfg(feature = "graphics")]
            0x43595801 => {
                let (width, height) = super::super::graphics::info().map_err(display_error)?;
                let fields = [width, height, width * 4, 1, 65536, 1];
                for (field, chunk) in fields.iter().zip(bytes[..24].chunks_exact_mut(4)) {
                    chunk.copy_from_slice(&field.to_le_bytes());
                }
                self.copy_to(a, &bytes[..24])?;
                Ok(0)
            }
            #[cfg(feature = "graphics")]
            0x43595802 => {
                let (x, y, width, height) = (count(a)?, count(b)?, count(c)?, count(d)?);
                let n = width
                    .checked_mul(height)
                    .filter(|n| *n > 0 && *n <= 16384)
                    .ok_or(Errno::Inval)?;
                if f != (n * 4) as u64 {
                    return Err(Errno::Inval);
                }
                self.validate(e, n * 4, false)?;
                // CPU0 foreground serializes these calls; IRQs never access
                // DRAW. The display service copies into its own pending buffer
                // before returning; it retains no reference to this buffer.
                let pixels = unsafe { &mut *core::ptr::addr_of_mut!(DRAW) };
                for (index, chunk) in pixels[..n].chunks_mut(256).enumerate() {
                    self.copy_from(e + (index * 1024) as u64, &mut bytes[..chunk.len() * 4])?;
                    for (pixel, raw) in chunk.iter_mut().zip(bytes.chunks_exact(4)) {
                        *pixel = u32::from_le_bytes(raw.try_into().map_err(|_| Errno::Inval)?);
                    }
                }
                super::super::graphics::begin_blit(
                    self.status.pid,
                    x,
                    y,
                    width,
                    height,
                    &pixels[..n],
                )
                .map_err(display_error)?;
                self.block(super::Wait::Display);
                Ok(0)
            }
            #[cfg(feature = "graphics")]
            0x43595803 => {
                let count = count(b)?;
                if count == 0 || count > 32 {
                    return Err(Errno::Inval);
                }
                self.validate(a, count * 8, true)?;
                let mut events = [cyxia_driver_virtio::InputEvent {
                    kind: 0,
                    code: 0,
                    value: 0,
                }; 32];
                let n = super::super::graphics::read_events(&mut events[..count])
                    .map_err(display_error)?;
                for (event, chunk) in events[..n].iter().zip(bytes.chunks_exact_mut(8)) {
                    chunk[..2].copy_from_slice(&event.kind.to_le_bytes());
                    chunk[2..4].copy_from_slice(&event.code.to_le_bytes());
                    chunk[4..8].copy_from_slice(&event.value.to_le_bytes());
                }
                self.copy_to(a, &bytes[..n * 8])?;
                Ok(n as u64)
            }
            #[cfg(feature = "graphics")]
            0x43595804 => {
                self.validate(a, 96, true)?;
                let mut keys = [0u8; 96];
                super::super::graphics::key_state(&mut keys);
                self.copy_to(a, &keys)?;
                Ok(0)
            }
            #[cfg(not(feature = "graphics"))]
            0x43595801..=0x43595804 => Err(Errno::Nodev),
            56 => {
                // openat resolves relative names against a real directory FD.
                let mut path = [0u8; 96];
                let n = self.path(b, &mut path)?;
                let path = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                let flags = u32::try_from(c).map_err(|_| Errno::Inval)?;
                // AArch64 O_LARGEFILE is redundant with our 64-bit offsets. All
                // other unknown open flags remain rejected by Process::open.
                let flags = flags & !0x20000;
                if path == "/dev/ptmx" || path.starts_with("/dev/pts/") {
                    return self.pty_open(path, flags).map(|fd| fd as u64);
                }
                let resolved = self.process.path_at(fs, a as i32, path)?;
                if let Some((inode, bytes)) = self.readonly_asset(resolved) {
                    return self
                        .process
                        .open_readonly_mode(inode, bytes, flags, Self::asset_mode(resolved))
                        .map(|fd| fd as u64);
                }
                self.process
                    .open_resolved(fs, resolved, flags, d as u16)
                    .map(|fd| fd as u64)
            }
            34 | 35 => {
                let mut path = [0u8; 96];
                let n = self.path(b, &mut path)?;
                let path = core::str::from_utf8(&path[..n]).map_err(|_| Errno::Inval)?;
                if a as i64 != -100 && !path.starts_with('/') {
                    return Err(Errno::Badf);
                }
                if self.thread.context.regs[8] == 34 {
                    self.process.mkdir(fs, path, c as u16)?;
                } else if c == 0x200 {
                    self.process.rmdir(fs, path)?;
                } else if c == 0 {
                    // Both namespaces resolve through the same real parent
                    // permission checks. Socket unlink preserves live streams.
                    if let Ok(p) = self.process.socket_path(fs, path, true)
                        && super::unix::with(|s| s.unlink(p.as_str().as_bytes())).is_ok()
                    {
                        return Ok(0);
                    }
                    self.process.unlink(fs, path)?;
                } else {
                    return Err(Errno::Inval);
                }
                Ok(0)
            }
            57 => self.linux_close(fs, fd(a)?).map(|_| 0),
            62 => {
                let descriptor = fd(a)?;
                let whence = u32::try_from(c).map_err(|_| Errno::Inval)?;
                if self.process.memfd(descriptor)?.is_some() {
                    self.seek_memfd(descriptor, b as i64, whence)
                } else {
                    self.process.lseek(fs, descriptor, b as i64, whence)
                }
            }
            63 | 207 => {
                if self.thread.context.regs[8] == 207 {
                    self.socket_handle(fd(a)?)?;
                    if d & !64 != 0 || e != 0 {
                        return Err(Errno::Nosys);
                    }
                }
                let n = count(c)?;
                self.validate(b, n, true)?;
                let result = self.linux_read(fs, fd(a)?, &mut bytes[..n.min(1024)]);
                if let Ok(n) = result {
                    self.copy_to(b, &bytes[..n])?;
                }
                if self.thread.context.regs[8] == 207 && d & 64 != 0 {
                    result.map(|n| n as u64)
                } else {
                    self.socket_wait(fd(a)?, false, a, result)
                }
            }
            67 | 68 => {
                let writing = self.thread.context.regs[8] == 68;
                let descriptor = fd(a)?;
                let offset = usize::try_from(d as i64).map_err(|_| Errno::Inval)?;
                let requested = count(c)?;
                self.validate(b, requested, !writing)?;
                let size = requested.min(bytes.len());
                if writing {
                    self.copy_from(b, &mut bytes[..size])?;
                    self.write_memfd_at(descriptor, offset, &bytes[..size])
                        .map(|n| n as u64)
                } else {
                    let n = self.read_memfd_at(descriptor, offset, &mut bytes[..size])?;
                    self.copy_to(b, &bytes[..n])?;
                    Ok(n as u64)
                }
            }
            206 => {
                // Connected AF_UNIX streams: Rust std's send(MSG_NOSIGNAL)
                // reaches sendto with no destination. Do not accept datagram
                // destinations or silently ignore unsupported message flags.
                const DONTWAIT: u64 = 0x40;
                const NOSIGNAL: u64 = 0x4000;
                if d & !(DONTWAIT | NOSIGNAL) != 0 || e != 0 {
                    return Err(Errno::Nosys);
                }
                let descriptor = fd(a)?;
                let handle = self.socket_handle(descriptor)?;
                let owner = self.process.backend_owner(descriptor)?;
                let requested = count(c)?;
                self.validate(b, requested, false)?;
                let copied = requested.min(bytes.len());
                self.copy_from(b, &mut bytes[..copied])?;
                let result = super::unix::with(|s| {
                    s.write(owner, super::unix::handle(handle), &bytes[..copied])
                });
                if result == Err(Errno::Pipe) && d & NOSIGNAL == 0 {
                    self.queue_signal(13, cyxia_posix::signal::Info::EMPTY, false)?;
                }
                if d & DONTWAIT != 0 {
                    result.map(|n| n as u64)
                } else {
                    self.socket_wait(descriptor, true, a, result)
                }
            }
            64 => {
                let n = count(c)?;
                self.validate(b, n, false)?;
                if self.process.pipe(fd(a)?)?.is_some() {
                    let mut pipe_bytes = [0u8; cyxia_posix::pipe::PIPE_BUF];
                    let copied = n.min(pipe_bytes.len());
                    self.copy_from(b, &mut pipe_bytes[..copied])?;
                    let result = self.pipe_write(fd(a)?, &pipe_bytes[..copied], n);
                    return self.socket_wait(fd(a)?, true, a, result);
                }
                let n = n.min(1024);
                self.copy_from(b, &mut bytes[..n])?;
                let result = self.linux_write(fs, fd(a)?, &bytes[..n]);
                self.socket_wait(fd(a)?, true, a, result)
            }
            65 | 66 => {
                let writing = self.thread.context.regs[8] == 66;
                let result = self.vector_io(fs, fd(a)?, b, c, writing);
                self.socket_wait(fd(a)?, writing, a, result)
            }
            93 => {
                self.thread_exit(fs, ledger, ipc, (a & 255) as u32);
                Ok(0)
            }
            94 => {
                self.finish(fs, ledger, ipc, UserState::Exited, (a & 255) as u32);
                Ok(0)
            }
            96 => {
                self.thread.clear_tid = a;
                Ok(self.thread.tid as u64)
            }
            172 => Ok(self.status.pid as u64),
            178 => Ok(self.thread.tid as u64),
            174..=177 => Ok(0), // The implemented file domain has one root UID/GID.
            148 | 150 => {
                // getresuid/getresgid: this file domain has one root identity.
                // Linux writes each 32-bit result in order, so an EFAULT on a
                // later pointer preserves the earlier successfully copied IDs.
                for address in [a, b, c] {
                    self.copy_to(address, &0u32.to_le_bytes())?;
                }
                Ok(0)
            }
            124 => Ok(0), // sched_yield; dispatch loop hands control back to AI.
            214 => Ok(0), // No brk arena. musl's real allocator takes its mmap path.
            222 => {
                let len = count(b)?;
                if d & 0x20 == 0 {
                    // Non-fixed file mappings only. Private mappings require
                    // a fully immutable memfd and allocate a real private copy.
                    // The address remains a hint; each arena chooses its VA.
                    if !matches!(d, 1 | 2) || len == 0 || c > 3 || c == 2 {
                        return Err(Errno::Inval);
                    }
                    if d == 2 {
                        return self.map_private_sealed(fd(e)?, f, len, c as u8);
                    }
                    return self.map_shared(fd(e)?, f, len, c as u8);
                }
                if len == 0
                    || c > 3
                    || c == 2
                    || d & !(0x22 | 0x4000 | 0x20000) != 0
                    || d & 0x22 != 0x22
                    || e as i64 != -1
                    || f != 0
                {
                    return Err(Errno::Inval);
                }
                let pages = len.checked_add(4095).ok_or(Errno::Nomem)? / 4096;
                // Linux MAP_STACK (0x20000) is a compatibility hint/no-op.
                // `a` is only a hint without MAP_FIXED; this arena chooses an
                // available VA, as permitted by mmap's non-fixed contract.
                let result = self.heap.allocate_protected(pages, c as u8);
                if result.is_err() {
                    super::super::log(b"MMAP_DENIED requested_pages,free_pages MECHANISM\n");
                    super::super::hex(pages as u64);
                    super::super::hex(self.heap.free() as u64);
                }
                result
            }
            215 => {
                let len = count(b)?;
                if len == 0 || !a.is_multiple_of(4096) {
                    return Err(Errno::Inval);
                }
                let pages = len.checked_add(4095).ok_or(Errno::Inval)? / 4096;
                if (super::shared_memory::BASE..super::shared_memory::END).contains(&a) {
                    return self.unmap_shared(a, pages).map(|_| 0);
                }
                // First-stage ABI explicitly supports whole allocations only.
                self.heap.unmap(a, pages).map(|_| 0)
            }
            226 => {
                if c > 7 {
                    return Err(Errno::Inval);
                }
                let len = count(b)?;
                if (super::shared_memory::BASE..super::shared_memory::END).contains(&a) {
                    self.protect_shared(a, len, c as u8)?;
                } else if (cyxia_posix::vm::BASE..cyxia_posix::vm::END).contains(&a) {
                    self.heap.protect(a, len, c as u8)?;
                } else {
                    self.executable.protect(a, len, c)?;
                }
                Ok(0)
            }
            113 => {
                let ns = match a {
                    0 => super::super::clock::realtime_seconds()? * 1_000_000_000,
                    1 => {
                        cyxia_kernel_core::time::ticks_to_ns(
                            cyxia_arch_aarch64::timer::ticks(),
                            cyxia_arch_aarch64::timer::frequency(),
                        )
                        .map_err(|_| Errno::Io)?
                        .0
                    }
                    _ => return Err(Errno::Inval),
                };
                bytes[..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
                bytes[8..16].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
                self.copy_to(b, &bytes[..16])?;
                Ok(0)
            }
            114 => {
                let (sec, ns) = match a {
                    0 => {
                        super::super::clock::realtime_seconds()?;
                        (1u64, 0u64)
                    }
                    1 => (
                        0,
                        1_000_000_000u64.div_ceil(cyxia_arch_aarch64::timer::frequency()),
                    ),
                    _ => return Err(Errno::Inval),
                };
                if b != 0 {
                    bytes[..8].copy_from_slice(&sec.to_le_bytes());
                    bytes[8..16].copy_from_slice(&ns.to_le_bytes());
                    self.copy_to(b, &bytes[..16])?;
                }
                Ok(0)
            }
            169 => {
                if a != 0 {
                    let seconds = super::super::clock::realtime_seconds()?;
                    bytes[..8].copy_from_slice(&seconds.to_le_bytes());
                    bytes[8..16].fill(0);
                    self.copy_to(a, &bytes[..16])?;
                }
                if b != 0 {
                    self.copy_to(b, &[0u8; 8])?;
                }
                Ok(0)
            }
            278 => {
                if c & !1 != 0 {
                    return Err(Errno::Inval);
                }
                let len = count(b)?.min(256);
                self.validate(a, len, true)?;
                if len != 0 {
                    // GRND_NONBLOCK uses only completed real device bytes.
                    // GRND_INSECURE remains unsupported: a finite entropy pool
                    // cannot promise unlimited reads without seed waiting.
                    let n = super::super::entropy::read(&mut bytes[..len], c != 0)?;
                    self.copy_to(a, &bytes[..n])?;
                    return Ok(n as u64);
                }
                Ok(len as u64)
            }
            29 => {
                if let Some(raw) = self.process.pty(fd(a)?)? {
                    self.pty_ioctl(raw, self.process.backend_owner(fd(a)?)?, b, c)
                } else if b == 0x541b
                    && let Some(raw) = self.process.pipe(fd(a)?)?
                {
                    self.validate(c, 4, true)?;
                    let owner = self.process.backend_owner(fd(a)?)?;
                    let pending = super::pipes::with(|p| p.pending(owner, raw))?;
                    self.copy_to(c, &(pending as u32).to_le_bytes())?;
                    Ok(0)
                } else {
                    Err(Errno::Notty)
                }
            }
            number => {
                super::super::log(b"LINUX_ABI_UNSUPPORTED MECHANISM\n");
                super::super::hex(number);
                Err(Errno::Nosys)
            }
        }
    }
}
