#![no_std]
#![forbid(unsafe_code)]
//! Bounded, single-UID POSIX file API subset. No architecture or raw user pointers.
pub mod ancillary;
mod directory;
pub mod open_description;
pub mod shared_memory;
use open_description::Handle;
pub use open_description::{OpenDescriptions, Released};
pub mod epoll;
pub mod executable;
pub mod image;
pub mod ipc;
pub mod pipe;
pub mod pty;
pub mod signal;
pub mod spawn;
pub mod timerfd;
pub mod unix;
pub mod usermem;
pub mod vm;
use cyxia_ai_fs::{Error, FileSystem, Inode, Kind, Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    Perm = 1,
    Noent = 2,
    Srch = 3,
    Intr = 4,
    Io = 5,
    Badf = 9,
    Child = 10,
    Again = 11,
    Nomem = 12,
    TooBig = 7,
    Access = 13,
    Fault = 14,
    Busy = 16,
    Exist = 17,
    Nodev = 19,
    Notdir = 20,
    Isdir = 21,
    Inval = 22,
    Mfile = 24,
    Notty = 25,
    Fbig = 27,
    Nospc = 28,
    Spipe = 29,
    Rofs = 30,
    Pipe = 32,
    Range = 34,
    Nametoolong = 36,
    Nosys = 38,
    Notempty = 39,
    Overflow = 75,
    Addrinuse = 98,
    Nobufs = 105,
    Isconn = 106,
    Notconn = 107,
    Connrefused = 111,
    Timedout = 110,
}
impl From<Error> for Errno {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => Self::Noent,
            Error::Exists => Self::Exist,
            Error::NotDirectory => Self::Notdir,
            Error::IsDirectory => Self::Isdir,
            Error::NotEmpty => Self::Notempty,
            Error::TooLong => Self::Nametoolong,
            Error::TooLarge => Self::Fbig,
            Error::Full | Error::AiDenied => Self::Nospc,
            Error::InvalidPath => Self::Inval,
            Error::Stale => Self::Badf,
            Error::Exhausted => Self::Overflow,
            Error::InvalidDecision
            | Error::NeedSamples
            | Error::CandidateRejected
            | Error::NoCandidate => Self::Io,
        }
    }
}
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0x40;
pub const O_EXCL: u32 = 0x80;
pub const O_TRUNC: u32 = 0x200;
pub const O_APPEND: u32 = 0x400;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_DIRECTORY: u32 = 0x4000; // Linux AArch64 ABI.
pub const O_NOFOLLOW: u32 = 0x8000;
pub const OPEN_MAX: usize = 16;
#[derive(Clone, Copy)]
enum Object {
    File(Inode),
    Directory { inode: Option<Inode>, path: Path },
    Null,
    Output,
    Socket(u64),
    Pipe(u64),
    Pty(u64),
    Memfd(u64),
    Event { counter: u64, semaphore: bool },
    Timer(timerfd::Timer),
    Epoll(usize),
    ReadOnly(u64, &'static [u8], u16),
}
#[derive(Clone, Copy)]
struct Description {
    object: Object,
    offset: u64,
    flags: u32,
}
pub trait Console {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileInfo {
    pub inode: u64,
    pub size: u64,
    pub mode: u32,
    pub links: u32,
}
/// A process owns descriptor table entries; the shared store owns descriptions.
/// Drop is deliberately not implicit: callers must close_all with the filesystem
/// and execute the returned backend releases before reusing a process slot.
pub struct Process<'a> {
    fds: [Option<Handle>; OPEN_MAX],
    objects: &'a OpenDescriptions,
    owner: u32,
    cwd: Path,
    mask: u16,
    cloexec: [bool; OPEN_MAX],
}
impl<'a> Process<'a> {
    pub fn fchmod(&mut self, fs: &mut FileSystem, fd: i32, mode: u16) -> Result<(), Errno> {
        match self.objects.get(self.description(fd)?)?.object {
            Object::File(h) | Object::Directory { inode: Some(h), .. } => {
                fs.set_inode_mode(h, mode).map_err(Into::into)
            }
            _ => Err(Errno::Access),
        }
    }
    pub fn chmod(&mut self, fs: &mut FileSystem, path: &str, mode: u16) -> Result<(), Errno> {
        fs.set_mode(self.path(fs, path)?, mode).map_err(Into::into)
    }
    pub fn resolved_path(&self, fs: &FileSystem, path: &str) -> Result<Path, Errno> {
        self.path(fs, path)
    }
    pub fn stat(&self, fs: &FileSystem, path: &str) -> Result<FileInfo, Errno> {
        let path = self.path(fs, path)?;
        self.stat_resolved(fs, path)
    }
    /// Inspect a path immediately after `path_at` or `resolved_path` authorized
    /// its traversal. Do not restart at root: a directory FD is the lookup base.
    pub fn stat_resolved(&self, fs: &FileSystem, path: Path) -> Result<FileInfo, Errno> {
        let info = fs.stat(path)?;
        Ok(FileInfo {
            inode: fs.identity(path)?,
            size: info.len as u64,
            mode: info.mode as u32
                | if info.kind == Kind::Directory {
                    0o40000
                } else {
                    0o100000
                },
            links: 1,
        })
    }
    /// Linux AT_EMPTY_PATH refers to the descriptor itself, or the current
    /// directory for AT_FDCWD, without requiring directory search permission.
    pub fn stat_empty_at(&self, fs: &FileSystem, fd: i32) -> Result<FileInfo, Errno> {
        if fd == -100 {
            self.stat_resolved(fs, self.cwd)
        } else {
            self.fstat(fs, fd)
        }
    }
    pub fn fstat(&self, fs: &FileSystem, fd: i32) -> Result<FileInfo, Errno> {
        let d = self.objects.get(self.description(fd)?)?;
        Ok(match d.object {
            Object::Directory { inode, .. } => {
                let (id, mode, linked) = if let Some(h) = inode {
                    let (id, _, mode, linked) = fs.inode_info(h)?;
                    (id + 1, mode, linked)
                } else {
                    (1, 0o755, true)
                };
                FileInfo {
                    inode: id,
                    size: 0,
                    mode: 0o40000 | u32::from(mode),
                    links: u32::from(linked),
                }
            }
            Object::File(h) => {
                let (inode, size, mode, linked) = fs.inode_info(h)?;
                FileInfo {
                    inode: inode + 1,
                    size: size as u64,
                    mode: mode as u32 | 0o100000,
                    links: u32::from(linked),
                }
            }
            Object::ReadOnly(inode, bytes, mode) => FileInfo {
                inode,
                size: bytes.len() as u64,
                mode: 0o100000 | u32::from(mode),
                links: 1,
            },
            Object::Memfd(_) => return Err(Errno::Nosys),
            Object::Socket(inode) => FileInfo {
                inode,
                size: 0,
                mode: 0o140600,
                links: 1,
            },
            Object::Event { .. } | Object::Timer(_) | Object::Epoll(_) => FileInfo {
                inode: 0,
                size: 0,
                mode: 0o600,
                links: 1,
            },
            Object::Pipe(handle) => FileInfo {
                inode: handle & !1,
                size: 0,
                mode: 0o10600,
                links: 1,
            },
            Object::Pty(handle) => FileInfo {
                inode: handle,
                size: 0,
                mode: 0o20600,
                links: 1,
            },
            Object::Null | Object::Output => FileInfo {
                inode: 0,
                size: 0,
                mode: 0o20600,
                links: 1,
            },
        })
    }
    pub fn open_readonly(
        &mut self,
        inode: u64,
        bytes: &'static [u8],
        flags: u32,
    ) -> Result<i32, Errno> {
        self.open_readonly_mode(inode, bytes, flags, 0o444)
    }
    pub fn open_readonly_mode(
        &mut self,
        inode: u64,
        bytes: &'static [u8],
        flags: u32,
        mode: u16,
    ) -> Result<i32, Errno> {
        if mode & !0o555 != 0 {
            return Err(Errno::Inval);
        }
        if flags & (3 | O_TRUNC | O_CREAT) != 0 {
            return Err(Errno::Access);
        }
        if flags & O_DIRECTORY != 0 {
            return Err(Errno::Notdir);
        }
        if flags & !(O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW) != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::ReadOnly(inode, bytes, mode),
                offset: 0,
                flags: flags & !O_CLOEXEC,
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub const fn empty(objects: &'a OpenDescriptions, owner: u32) -> Self {
        Self {
            fds: [None; OPEN_MAX],
            objects,
            owner,
            cwd: Path::ROOT,
            mask: 0o022,
            cloexec: [false; OPEN_MAX],
        }
    }
    pub fn new(objects: &'a OpenDescriptions, owner: u32) -> Result<Self, Errno> {
        let mut process = Self::empty(objects, owner);
        // Preflight the complete stdio set; construction cannot leak a prefix.
        let slots = objects.free_slots::<3>()?;
        for (fd, slot) in slots.into_iter().enumerate() {
            objects.create(
                slot,
                owner,
                Description {
                    object: if fd == 0 {
                        Object::Null
                    } else {
                        Object::Output
                    },
                    offset: 0,
                    flags: if fd == 0 { O_RDONLY } else { O_WRONLY },
                },
            )?;
            process.fds[fd] = Some(slot);
        }
        Ok(process)
    }
    /// Stable identity of the shared open description, not the numeric FD or
    /// backend endpoint. Observation does not retain a lifetime reference.
    pub fn description_identity(&self, fd: i32) -> Result<u64, Errno> {
        let handle = self.description(fd)?;
        self.objects.references(handle)?;
        Ok(handle.identity())
    }
    /// The bounded retry ABI cancels with EBADF when a parked call's FD now
    /// names another OFD. A dup alias of the same OFD remains the same identity.
    pub fn validate_description_identity(&self, fd: i32, identity: u64) -> Result<(), Errno> {
        if self.description_identity(fd)? == identity {
            Ok(())
        } else {
            Err(Errno::Badf)
        }
    }
    pub fn backend_owner(&self, fd: i32) -> Result<u32, Errno> {
        self.objects.owner(self.description(fd)?)
    }
    pub fn umask(&mut self, mask: u16) -> u16 {
        let old = self.mask;
        self.mask = mask & 0o777;
        old
    }
    fn description(&self, fd: i32) -> Result<Handle, Errno> {
        self.fds
            .get(fd as usize)
            .copied()
            .flatten()
            .ok_or(Errno::Badf)
    }
    fn free_fd(&self) -> Result<usize, Errno> {
        self.fds
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Mfile)
    }
    /// Install an already authorized socket into the same descriptor namespace
    /// as files. The supervisor retains endpoint lifetime/owner responsibility.
    pub fn install_socket(&mut self, handle: u64, flags: u32) -> Result<i32, Errno> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::Socket(handle),
                offset: 0,
                flags: O_RDWR | (flags & O_NONBLOCK),
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub fn socket(&self, fd: i32) -> Result<Option<u64>, Errno> {
        let d = self.objects.get(self.description(fd)?)?;
        Ok(match d.object {
            Object::Socket(h) => Some(h),
            _ => None,
        })
    }
    /// Install an admitted read/write pair atomically. The supervisor owns
    /// endpoint lifetimes and closes them only on the final descriptor reference.
    pub fn install_pipe(&mut self, handles: [u64; 2], flags: u32) -> Result<[i32; 2], Errno> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        let mut fds = self.fds.iter().enumerate().filter(|(_, v)| v.is_none());
        let read_fd = fds.next().ok_or(Errno::Mfile)?.0;
        let write_fd = fds.next().ok_or(Errno::Mfile)?.0;
        let [read_slot, write_slot] = self.objects.free_slots::<2>()?;
        for (fd, slot, handle, access) in [
            (read_fd, read_slot, handles[0], O_RDONLY),
            (write_fd, write_slot, handles[1], O_WRONLY),
        ] {
            self.objects.create(
                slot,
                self.owner,
                Description {
                    object: Object::Pipe(handle),
                    offset: 0,
                    flags: access | (flags & O_NONBLOCK),
                },
            )?;
            self.fds[fd] = Some(slot);
            self.cloexec[fd] = flags & O_CLOEXEC != 0;
        }
        Ok([read_fd as i32, write_fd as i32])
    }
    pub fn pipe(&self, fd: i32) -> Result<Option<u64>, Errno> {
        let d = self.objects.get(self.description(fd)?)?;
        Ok(match d.object {
            Object::Pipe(handle) => Some(handle),
            _ => None,
        })
    }
    /// The supervisor owns PTY admission and endpoint lifetime, as for pipes.
    pub fn install_pty(&mut self, handle: u64, flags: u32) -> Result<i32, Errno> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::Pty(handle),
                offset: 0,
                flags: O_RDWR | (flags & O_NONBLOCK),
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub fn pty(&self, fd: i32) -> Result<Option<u64>, Errno> {
        Ok(match self.objects.get(self.description(fd)?)?.object {
            Object::Pty(handle) => Some(handle),
            _ => None,
        })
    }
    /// One admitted shared backing reference belongs to this new description.
    pub fn install_memfd(&mut self, handle: u64, flags: u32) -> Result<i32, Errno> {
        if flags & !O_CLOEXEC != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::Memfd(handle),
                offset: 0,
                flags: O_RDWR,
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub fn memfd(&self, fd: i32) -> Result<Option<u64>, Errno> {
        Ok(match self.objects.get(self.description(fd)?)?.object {
            Object::Memfd(h) => Some(h),
            _ => None,
        })
    }
    pub fn memfd_position(&self, fd: i32, writing: bool) -> Result<(u64, u64, u32), Errno> {
        let d = self.objects.get(self.description(fd)?)?;
        let Object::Memfd(handle) = d.object else {
            return Err(Errno::Inval);
        };
        if (writing && d.flags & 3 == O_RDONLY) || (!writing && d.flags & 3 == O_WRONLY) {
            return Err(Errno::Badf);
        }
        Ok((handle, d.offset, d.flags))
    }
    pub fn set_memfd_position(&mut self, fd: i32, offset: u64) -> Result<(), Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        if !matches!(d.object, Object::Memfd(_)) {
            return Err(Errno::Inval);
        }
        self.objects.update(slot, Description { offset, ..d })
    }
    /// Bounded event counters share their open description across dup().
    /// The descriptor admission limit also bounds event storage; no allocation.
    pub fn eventfd(&mut self, initial: u32, flags: u32) -> Result<i32, Errno> {
        if flags & !(1 | O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::Event {
                    counter: u64::from(initial),
                    semaphore: flags & 1 != 0,
                },
                offset: 0,
                flags: O_RDWR | (flags & O_NONBLOCK),
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    /// Read/write readiness for local objects; socket readiness is supervisor owned.
    pub fn local_readiness(&self, fd: i32) -> Result<(bool, bool), Errno> {
        let d = self.objects.get(self.description(fd)?)?;
        Ok(match d.object {
            Object::Event { counter, .. } => (counter != 0, counter < u64::MAX - 1),
            Object::Socket(_)
            | Object::Pipe(_)
            | Object::Pty(_)
            | Object::Epoll(_)
            | Object::Timer(_) => {
                return Err(Errno::Inval);
            }
            _ => (d.flags & 3 != O_WRONLY, d.flags & 3 != O_RDONLY),
        })
    }
    pub fn is_eventfd(&self, fd: i32) -> Result<bool, Errno> {
        Ok(matches!(
            self.objects.get(self.description(fd)?)?.object,
            Object::Event { .. }
        ))
    }
    pub fn last_reference(&self, fd: i32) -> Result<bool, Errno> {
        Ok(self.objects.references(self.description(fd)?)? == 1)
    }
    pub fn flags(&self, fd: i32) -> Result<u32, Errno> {
        Ok(self.objects.get(self.description(fd)?)?.flags)
    }
    pub fn set_flags(&mut self, fd: i32, flags: u32) -> Result<(), Errno> {
        if flags & !(3 | O_APPEND | O_NONBLOCK) != 0 {
            return Err(Errno::Inval);
        }
        let slot = self.description(fd)?;
        let mut d = self.objects.get(slot)?;
        d.flags = (d.flags & !(O_APPEND | O_NONBLOCK)) | (flags & (O_APPEND | O_NONBLOCK));
        self.objects.update(slot, d)?;
        Ok(())
    }
    pub fn close_on_exec(&self, fd: i32) -> Result<bool, Errno> {
        self.description(fd)?;
        Ok(self.cloexec[fd as usize])
    }
    pub fn set_close_on_exec(&mut self, fd: i32, close: bool) -> Result<(), Errno> {
        self.description(fd)?;
        self.cloexec[fd as usize] = close;
        Ok(())
    }
    pub fn dup_from(&mut self, fd: i32, start: i32, cloexec: bool) -> Result<i32, Errno> {
        let slot = self.description(fd)?;
        let start = usize::try_from(start)
            .ok()
            .filter(|n| *n < OPEN_MAX)
            .ok_or(Errno::Inval)?;
        let new = (start..OPEN_MAX)
            .find(|i| self.fds[*i].is_none())
            .ok_or(Errno::Mfile)?;
        self.objects.retain(slot)?;
        self.fds[new] = Some(slot);
        self.cloexec[new] = cloexec;
        Ok(new as i32)
    }
    /// Resolve and authorize a pathname for a local socket. The supervisor
    /// handles the socket namespace; this enforces real directory permissions.
    pub fn socket_path(&self, fs: &FileSystem, path: &str, create: bool) -> Result<Path, Errno> {
        let p = self.path(fs, path)?;
        if create {
            self.change_parent(fs, p)?;
        }
        if fs.stat(p).is_ok() {
            return Err(Errno::Addrinuse);
        }
        Ok(p)
    }
    /// Walk each component before interpreting '..'; lexical collapse alone is incorrect.
    fn path(&self, fs: &FileSystem, s: &str) -> Result<Path, Errno> {
        self.path_from(fs, self.cwd, s)
    }
    fn path_from(&self, fs: &FileSystem, base: Path, s: &str) -> Result<Path, Errno> {
        if s.is_empty() {
            return Err(Errno::Noent);
        }
        if s.len() >= cyxia_ai_fs::PATH_BYTES {
            return Err(Errno::Nametoolong);
        }
        let mut p = if s.starts_with('/') { Path::ROOT } else { base };
        for component in s.split('/').filter(|c| !c.is_empty()) {
            let parent = fs.stat(p)?;
            if parent.kind != Kind::Directory {
                return Err(Errno::Notdir);
            }
            if parent.mode & 0o100 == 0 {
                return Err(Errno::Access);
            }
            p = Path::resolve(p, component)?;
        }
        if s.ends_with('/') && fs.stat(p)?.kind != Kind::Directory {
            return Err(Errno::Notdir);
        }
        Ok(p)
    }
    pub fn path_at(&self, fs: &FileSystem, fd: i32, path: &str) -> Result<Path, Errno> {
        if fd == -100 || path.starts_with('/') {
            return self.path(fs, path);
        }
        self.path_from(fs, self.directory_path(fs, fd)?, path)
    }
    fn directory_path(&self, fs: &FileSystem, fd: i32) -> Result<Path, Errno> {
        match self.objects.get(self.description(fd)?)?.object {
            Object::Directory { inode, path } => {
                if let Some(h) = inode
                    && !fs.inode_info(h)?.3
                {
                    return Err(Errno::Noent);
                }
                Ok(path)
            }
            _ => Err(Errno::Notdir),
        }
    }
    fn change_parent(&self, fs: &FileSystem, p: Path) -> Result<(), Errno> {
        let e = fs.stat(p.parent())?;
        if e.kind != Kind::Directory {
            return Err(Errno::Notdir);
        }
        if e.mode & 0o300 != 0o300 {
            return Err(Errno::Access);
        }
        Ok(())
    }
    pub fn open(
        &mut self,
        fs: &mut FileSystem,
        path: &str,
        flags: u32,
        mode: u16,
    ) -> Result<i32, Errno> {
        let path = self.path(fs, path)?;
        self.open_resolved(fs, path, flags, mode)
    }
    /// Open immediately after `path_at` or `resolved_path` authorized traversal.
    /// The final file and creation-parent permissions are still checked here.
    pub fn open_resolved(
        &mut self,
        fs: &mut FileSystem,
        p: Path,
        flags: u32,
        mode: u16,
    ) -> Result<i32, Errno> {
        let known = 3
            | O_CREAT
            | O_EXCL
            | O_TRUNC
            | O_APPEND
            | O_NONBLOCK
            | O_CLOEXEC
            | O_DIRECTORY
            | O_NOFOLLOW;
        if flags & !known != 0 || flags & 3 == 3 || flags & O_TRUNC != 0 && flags & 3 == O_RDONLY {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        if let Ok(info) = fs.stat(p)
            && info.kind == Kind::Directory
        {
            if flags & (3 | O_CREAT | O_TRUNC) != 0 {
                return Err(Errno::Isdir);
            }
            if info.mode & 0o400 == 0 {
                return Err(Errno::Access);
            }
            let inode = fs.pin_directory(p)?;
            self.objects.create(
                slot,
                self.owner,
                Description {
                    object: Object::Directory { inode, path: p },
                    offset: 0,
                    flags: flags & !O_CLOEXEC,
                },
            )?;
            self.fds[fd] = Some(slot);
            self.cloexec[fd] = flags & O_CLOEXEC != 0;
            return Ok(fd as i32);
        }
        if flags & O_DIRECTORY != 0 {
            fs.stat(p)?;
            return Err(Errno::Notdir);
        }
        match fs.stat(p) {
            Ok(e) => {
                if flags & (O_CREAT | O_EXCL) == O_CREAT | O_EXCL {
                    return Err(Errno::Exist);
                }
                if e.kind != Kind::File {
                    return Err(Errno::Isdir);
                }
                let required = match flags & 3 {
                    O_RDONLY => 0o400,
                    O_WRONLY => 0o200,
                    _ => 0o600,
                };
                if e.mode & required != required {
                    return Err(Errno::Access);
                }
                if flags & O_TRUNC != 0 {
                    fs.write(p, b"", false)?;
                }
            }
            Err(Error::NotFound) if flags & O_CREAT != 0 => {
                self.change_parent(fs, p)?;
                fs.write(p, b"", false)?;
                fs.set_mode(p, mode & !self.mask)?;
            }
            Err(e) => return Err(e.into()),
        }
        let inode = fs.pin(p)?;
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::File(inode),
                offset: 0,
                flags: flags & !O_CLOEXEC,
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    /// Return a backend release only when the final shared OFD reference dies.
    /// The supervisor must execute it before publishing another user transition.
    pub fn close(&mut self, fs: &mut FileSystem, fd: i32) -> Result<Option<Released>, Errno> {
        let slot = self.description(fd)?;
        let released = self.objects.release(fs, slot)?;
        self.fds[fd as usize] = None;
        self.cloexec[fd as usize] = false;
        Ok(released)
    }
    pub fn close_all(
        &mut self,
        fs: &mut FileSystem,
    ) -> Result<[Option<Released>; OPEN_MAX], Errno> {
        let mut released = [None; OPEN_MAX];
        for (fd, out) in released.iter_mut().enumerate() {
            if self.fds[fd].is_some() {
                *out = self.close(fs, fd as i32)?;
            }
        }
        Ok(released)
    }
    pub fn dup(&mut self, fd: i32) -> Result<i32, Errno> {
        self.dup_from(fd, 0, false)
    }
    pub fn dup2(
        &mut self,
        fs: &mut FileSystem,
        old: i32,
        new: i32,
    ) -> Result<(i32, Option<Released>), Errno> {
        let slot = self.description(old)?;
        if new < 0 || new as usize >= OPEN_MAX {
            return Err(Errno::Badf);
        }
        if old == new {
            return Ok((new, None));
        }
        // Reserve the extra reference before closing the destination. Any
        // representational overflow therefore leaves the destination unchanged.
        self.objects.retain(slot)?;
        let released = if self.fds[new as usize].is_some() {
            match self.close(fs, new) {
                Ok(released) => released,
                Err(error) => {
                    self.objects.release(fs, slot)?;
                    return Err(error);
                }
            }
        } else {
            None
        };
        self.fds[new as usize] = Some(slot);
        self.cloexec[new as usize] = false;
        Ok((new, released))
    }
    pub fn read(&mut self, fs: &mut FileSystem, fd: i32, out: &mut [u8]) -> Result<usize, Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        if d.flags & 3 == O_WRONLY {
            return Err(Errno::Badf);
        }
        let n = match d.object {
            Object::Directory { .. } => return Err(Errno::Isdir),
            Object::File(h) => fs.read_at(
                h,
                usize::try_from(d.offset).map_err(|_| Errno::Overflow)?,
                out,
            )?,
            Object::Null => 0,
            Object::Output => return Err(Errno::Badf),
            Object::Epoll(_) => return Err(Errno::Inval),
            Object::Socket(_)
            | Object::Pipe(_)
            | Object::Pty(_)
            | Object::Memfd(_)
            | Object::Timer(_) => {
                return Err(Errno::Nosys);
            }
            Object::Event { counter, semaphore } => {
                if out.len() < 8 {
                    return Err(Errno::Inval);
                }
                if counter == 0 {
                    return Err(Errno::Again);
                }
                let value = if semaphore { 1 } else { counter };
                out[..8].copy_from_slice(&value.to_le_bytes());
                self.objects.update(
                    slot,
                    Description {
                        object: Object::Event {
                            counter: counter - value,
                            semaphore,
                        },
                        ..d
                    },
                )?;
                self.objects.observe_local(
                    slot,
                    (u32::from(counter != value) * epoll::IN) | epoll::OUT,
                    epoll::OUT,
                );
                return Ok(8);
            }
            Object::ReadOnly(_, bytes, _) => {
                let offset = usize::try_from(d.offset)
                    .map_err(|_| Errno::Overflow)?
                    .min(bytes.len());
                let n = out.len().min(bytes.len() - offset);
                out[..n].copy_from_slice(&bytes[offset..offset + n]);
                n
            }
        };
        self.objects.update(
            slot,
            Description {
                offset: d.offset + n as u64,
                ..d
            },
        )?;
        Ok(n)
    }
    pub fn write(
        &mut self,
        fs: &mut FileSystem,
        io: &mut impl Console,
        fd: i32,
        data: &[u8],
    ) -> Result<usize, Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        if d.flags & 3 == O_RDONLY {
            return Err(Errno::Badf);
        }
        if data.is_empty() && !matches!(d.object, Object::Event { .. } | Object::Timer(_)) {
            return Ok(0);
        }
        let mut offset = d.offset;
        let n = match d.object {
            Object::Directory { .. } => return Err(Errno::Isdir),
            Object::File(h) => {
                if d.flags & O_APPEND != 0 {
                    offset = fs.inode_len(h)? as u64;
                }
                fs.write_at(h, usize::try_from(offset).map_err(|_| Errno::Fbig)?, data)?
            }
            Object::Null => data.len(),
            Object::Output => io.write(data)?,
            Object::Epoll(_) | Object::Timer(_) => return Err(Errno::Inval),
            Object::Socket(_) | Object::Pipe(_) | Object::Pty(_) | Object::Memfd(_) => {
                return Err(Errno::Nosys);
            }
            Object::Event { counter, semaphore } => {
                if data.len() != 8 {
                    return Err(Errno::Inval);
                }
                let value = u64::from_le_bytes(data[..8].try_into().map_err(|_| Errno::Inval)?);
                if value == u64::MAX {
                    return Err(Errno::Inval);
                }
                let next = counter
                    .checked_add(value)
                    .filter(|v| *v < u64::MAX)
                    .ok_or(Errno::Again)?;
                self.objects.update(
                    slot,
                    Description {
                        object: Object::Event {
                            counter: next,
                            semaphore,
                        },
                        ..d
                    },
                )?;
                self.objects.observe_local(
                    slot,
                    (u32::from(next != 0) * epoll::IN)
                        | (u32::from(next < u64::MAX - 1) * epoll::OUT),
                    epoll::IN,
                );
                return Ok(8);
            }
            Object::ReadOnly(_, _, _) => return Err(Errno::Access),
        };
        if n > data.len() {
            return Err(Errno::Io);
        }
        self.objects.update(
            slot,
            Description {
                offset: offset + n as u64,
                ..d
            },
        )?;
        Ok(n)
    }
    pub fn lseek(
        &mut self,
        fs: &FileSystem,
        fd: i32,
        offset: i64,
        whence: u32,
    ) -> Result<u64, Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        let length = match d.object {
            Object::Directory { .. } if whence == 0 && offset >= 0 => 0,
            Object::File(h) => fs.inode_len(h)? as u64,
            Object::ReadOnly(_, bytes, _) => bytes.len() as u64,
            _ => return Err(Errno::Spipe),
        };
        let base = match whence {
            0 => 0,
            1 => d.offset,
            2 => length,
            _ => return Err(Errno::Inval),
        };
        let next = (base as i64).checked_add(offset).ok_or(Errno::Overflow)?;
        if next < 0 {
            return Err(Errno::Inval);
        }
        self.objects.update(
            slot,
            Description {
                offset: next as u64,
                ..d
            },
        )?;
        Ok(next as u64)
    }
    pub fn unlink(&mut self, fs: &mut FileSystem, path: &str) -> Result<(), Errno> {
        let p = self.path(fs, path)?;
        self.change_parent(fs, p)?;
        fs.remove(p, false)?;
        Ok(())
    }
    /// Both paths must first be resolved through path_at/resolved_path. Keeping
    /// this step separate lets the syscall layer reject immutable boot assets.
    pub fn rename_file_resolved(
        &self,
        fs: &mut FileSystem,
        from: Path,
        to: Path,
        no_replace: bool,
    ) -> Result<(), Errno> {
        self.change_parent(fs, from)?;
        self.change_parent(fs, to)?;
        fs.rename_file(from, to, no_replace)?;
        Ok(())
    }
    pub fn mkdir(&mut self, fs: &mut FileSystem, path: &str, mode: u16) -> Result<(), Errno> {
        // Creating a directory permits a trailing slash.
        if !path.is_empty() && path.bytes().all(|b| b == b'/') {
            return Err(Errno::Exist);
        }
        let p = self.path(fs, path.trim_end_matches('/'))?;
        self.change_parent(fs, p)?;
        fs.mkdir(p)?;
        fs.set_mode(p, mode & !self.mask)?;
        Ok(())
    }
    pub fn rmdir(&mut self, fs: &mut FileSystem, path: &str) -> Result<(), Errno> {
        if path.split('/').rfind(|c| !c.is_empty()) == Some(".") {
            return Err(Errno::Inval);
        }
        let p = self.path(fs, path)?;
        if p == Path::ROOT || p == self.cwd {
            return Err(Errno::Busy);
        }
        self.change_parent(fs, p)?;
        fs.remove(p, true)?;
        Ok(())
    }
    pub fn chdir(&mut self, fs: &FileSystem, path: &str) -> Result<(), Errno> {
        let p = self.path(fs, path)?;
        let e = fs.stat(p)?;
        if e.kind != Kind::Directory {
            return Err(Errno::Notdir);
        }
        if e.mode & 0o100 == 0 {
            return Err(Errno::Access);
        }
        self.cwd = p;
        Ok(())
    }
    pub fn getcwd(&self, out: &mut [u8]) -> Result<usize, Errno> {
        let b = self.cwd.as_str().as_bytes();
        if out.len() <= b.len() {
            return Err(Errno::Range);
        }
        out[..b.len()].copy_from_slice(b);
        out[b.len()] = 0;
        Ok(b.len() + 1)
    }
}
#[cfg(test)]
mod tests;

/// Supervisor requests; the shell cannot supply a program address or arbitrary image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserRequest {
    Run(&'static str),
    Spawn(&'static str),
    Execute(&'static str),
    Pair,
    Kill(Option<u32>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserState {
    Idle,
    Running,
    Waiting,
    Exited,
    Fault,
    Timeout,
    Killed,
}
impl UserState {
    pub fn active(self) -> bool {
        matches!(self, Self::Running | Self::Waiting)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct UserStatus {
    pub pid: u32,
    pub parent_pid: u32,
    pub exit_signal: u32,
    pub state: UserState,
    pub code: u32,
    pub syscalls: u64,
    pub preemptions: u64,
    pub ai_slices: u64,
    pub cpu_model: u64,
    pub last_slice_ms: u64,
    pub esr: u64,
    pub far: u64,
    pub free_pages: u32,
    pub rank_model: u64,
    pub ai_selections: u64,
    pub guard_selections: u64,
    pub thread_count: u32,
    pub thread_peak: u32,
    pub thread_memory_model: u64,
    pub thread_admissions: u64,
    pub thread_denials: u64,
    pub thread_rank_model: u64,
    pub thread_ai_selections: u64,
    pub thread_guard_selections: u64,
    pub ipc_sent: u64,
    pub ipc_received: u64,
    pub waits: u64,
    pub wakeups: u64,
    pub heap_pages: u32,
    pub heap_free: u32,
    pub heap_model: u64,
    pub image_pages: u32,
    pub image_free: u32,
}
impl UserStatus {
    pub const EMPTY: Self = Self {
        pid: 0,
        parent_pid: 0,
        exit_signal: 0,
        state: UserState::Idle,
        code: 0,
        syscalls: 0,
        preemptions: 0,
        ai_slices: 0,
        cpu_model: 0,
        last_slice_ms: 0,
        esr: 0,
        far: 0,
        free_pages: usermem::POOL_PAGES,
        rank_model: 0,
        ai_selections: 0,
        guard_selections: 0,
        thread_count: 0,
        thread_peak: 0,
        thread_memory_model: 0,
        thread_admissions: 0,
        thread_denials: 0,
        thread_rank_model: 0,
        thread_ai_selections: 0,
        thread_guard_selections: 0,
        ipc_sent: 0,
        ipc_received: 0,
        waits: 0,
        wakeups: 0,
        heap_pages: 0,
        heap_free: vm::PAGE_COUNT as u32,
        heap_model: 0,
        image_pages: 0,
        image_free: 0,
    };
}
