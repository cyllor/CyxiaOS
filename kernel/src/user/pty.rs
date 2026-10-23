//! CPU0 foreground PTY pool. IRQ and DMA never access this storage.
use cyxia_posix::{Errno, pty::Ptys};

static mut PTYS: Ptys = Ptys::new();

pub(super) fn with<T>(f: impl FnOnce(&mut Ptys) -> Result<T, Errno>) -> Result<T, Errno> {
    // SAFETY: the supervisor serializes foreground calls; no borrowed pool
    // reference may escape the callback, and IRQ handlers do not touch PTYS.
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(PTYS) };
    let result = f(pool);
    super::objects::table().observe_backend(|source| {
        let cyxia_posix::epoll::Source::Pty { owner, handle } = source else {
            return None;
        };
        Some((
            u32::from(pool.poll(owner, handle).ok()?),
            pool.wake_mask(owner, handle).unwrap_or(0),
        ))
    });
    pool.clear_wakes();
    result
}
pub(super) fn open_master(owner: u32, flags: u32) -> Result<u64, Errno> {
    let mut attempt = cyxia_ai_runtime::accounting::Attempt::default();
    let result = (|| {
        let free = with(|p| Ok(p.free()))?;
        // Fixed backing is BOOTSTRAP; this model grants only logical occupancy.
        attempt.proposed(8193);
        let (allowed, model) =
            cyxia_ai_runtime::user_memory_policy(free as u32, 1).map_err(|_| Errno::Io)?;
        attempt.decided(allowed, model);
        if !allowed {
            return Err(Errno::Again);
        }
        with(|p| p.open_master(owner, flags))
    })();
    super::ai::admission(super::ai::Domain::Pty, attempt, &result);
    if result.is_ok() {
        super::super::log(b"PTY_ADMISSION AI_DIRECT model=8193 committed=true\n");
    }
    result
}

pub(super) fn release_actor(actor: u32) {
    let _ = with(|p| {
        p.release_actor(actor);
        Ok(())
    });
}
pub(super) fn take_signal() -> Option<(u32, u8)> {
    with(|p| Ok(p.take_signal())).ok().flatten()
}

impl super::Runner {
    fn install_pty(&mut self, handle: u64, flags: u32) -> Result<i32, Errno> {
        match self.process.install_pty(
            handle,
            flags & (cyxia_posix::O_NONBLOCK | cyxia_posix::O_CLOEXEC),
        ) {
            Ok(fd) => Ok(fd),
            Err(error) => {
                let _ = with(|p| p.close(self.status.pid, handle));
                Err(error)
            }
        }
    }
    fn pty_flags(flags: u32) -> Result<(), Errno> {
        if flags & 3 != cyxia_posix::O_RDWR
            || flags & !(3 | 0x100 | cyxia_posix::O_NONBLOCK | cyxia_posix::O_CLOEXEC) != 0
        {
            return Err(Errno::Inval);
        }
        Ok(())
    }
    pub(super) fn pty_open(&mut self, path: &str, flags: u32) -> Result<i32, Errno> {
        Self::pty_flags(flags)?;
        let nonblock = flags & cyxia_posix::O_NONBLOCK;
        let handle = if path == "/dev/ptmx" {
            open_master(self.status.pid, nonblock)?
        } else {
            let n = path.strip_prefix("/dev/pts/").ok_or(Errno::Noent)?;
            if n.len() != 1 || !n.as_bytes()[0].is_ascii_digit() {
                return Err(Errno::Noent);
            }
            with(|p| {
                p.open_slave(
                    self.status.pid,
                    usize::from(n.as_bytes()[0] - b'0'),
                    nonblock,
                )
            })?
        };
        self.install_pty(handle, flags)
    }
    pub(super) fn pty_ioctl(
        &mut self,
        handle: u64,
        backend_owner: u32,
        request: u64,
        address: u64,
    ) -> Result<u64, Errno> {
        // Linux ioctl takes an unsigned 32-bit command. Musl's int request
        // prototype may sign-extend _IOR values into the AArch64 register.
        let request = u64::from(request as u32);
        let owner = backend_owner;
        match request {
            0x80045430 => {
                self.validate(address, 4, true)?;
                let n = with(|p| p.number(owner, handle))?;
                self.copy_to(address, &(n as u32).to_le_bytes())?;
                Ok(0)
            }
            0x40045431 => {
                let mut bytes = [0; 4];
                self.copy_from(address, &mut bytes)?;
                let value = u32::from_le_bytes(bytes);
                if value > 1 {
                    return Err(Errno::Inval);
                }
                with(|p| p.lock(owner, handle, value == 1))?;
                Ok(0)
            }
            0x5441 => {
                let flags = u32::try_from(address).map_err(|_| Errno::Inval)?;
                Self::pty_flags(flags)?;
                let n = with(|p| p.number(owner, handle))?;
                let slave =
                    with(|p| p.open_slave(self.status.pid, n, flags & cyxia_posix::O_NONBLOCK))?;
                self.install_pty(slave, flags).map(|fd| fd as u64)
            }
            0x5401 => {
                self.validate(address, 36, true)?;
                let t = with(|p| p.termios(owner, handle))?;
                let mut bytes = [0; 36];
                for (i, field) in [t.input, t.output, t.control, t.local]
                    .into_iter()
                    .enumerate()
                {
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&field.to_le_bytes());
                }
                bytes[17..].copy_from_slice(&t.cc);
                self.copy_to(address, &bytes)?;
                Ok(0)
            }
            0x5402..=0x5404 => {
                let mut bytes = [0; 36];
                self.copy_from(address, &mut bytes)?;
                if bytes[16] != 0 {
                    return Err(Errno::Inval);
                }
                let mut fields = [0; 4];
                for (field, b) in fields.iter_mut().zip(bytes[..16].chunks_exact(4)) {
                    *field = u32::from_le_bytes(b.try_into().map_err(|_| Errno::Inval)?);
                }
                let mut cc = [0; 19];
                cc.copy_from_slice(&bytes[17..]);
                let t = cyxia_posix::pty::Termios {
                    input: fields[0],
                    output: fields[1],
                    control: fields[2],
                    local: fields[3],
                    cc,
                };
                with(|p| p.set_termios(owner, handle, t, request == 0x5404, request != 0x5402))?;
                Ok(0)
            }
            0x540b => {
                with(|p| p.flush(owner, handle, address))?;
                Ok(0)
            }
            0x540e => {
                if address != 0 {
                    return Err(Errno::Perm);
                }
                with(|p| p.controlling_for(owner, handle, self.status.pid))?;
                Ok(0)
            }
            0x540f => {
                self.validate(address, 4, true)?;
                let pid = with(|p| p.foreground(owner, handle))?;
                self.copy_to(address, &pid.to_le_bytes())?;
                Ok(0)
            }
            0x5410 => {
                let mut bytes = [0; 4];
                self.copy_from(address, &mut bytes)?;
                if u32::from_le_bytes(bytes) != self.status.pid {
                    return Err(Errno::Perm);
                }
                with(|p| p.controlling_for(owner, handle, self.status.pid))?;
                Ok(0)
            }
            0x5411 | 0x541b => {
                self.validate(address, 4, true)?;
                let n = with(|p| {
                    if request == 0x541b {
                        p.pending(owner, handle)
                    } else {
                        p.output_pending(owner, handle)
                    }
                })?;
                self.copy_to(address, &(n as u32).to_le_bytes())?;
                Ok(0)
            }
            0x5413 => {
                self.validate(address, 8, true)?;
                let size = with(|p| p.winsize(owner, handle))?;
                let mut bytes = [0; 8];
                for (v, b) in size.iter().zip(bytes.chunks_exact_mut(2)) {
                    b.copy_from_slice(&v.to_le_bytes());
                }
                self.copy_to(address, &bytes)?;
                Ok(0)
            }
            0x5414 => {
                let mut bytes = [0; 8];
                self.copy_from(address, &mut bytes)?;
                let mut size = [0; 4];
                for (v, b) in size.iter_mut().zip(bytes.chunks_exact(2)) {
                    *v = u16::from_le_bytes([b[0], b[1]]);
                }
                with(|p| p.set_winsize(owner, handle, size))?;
                Ok(0)
            }
            _ => Err(Errno::Notty),
        }
    }
}
