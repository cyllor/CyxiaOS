// SPDX-License-Identifier: MPL-2.0
//! Cyxia isolated static-image spawn. This does not implement fork or pre_exec.
use std::{
    collections::BTreeMap,
    ffi::{CString, OsString},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, process::ExitStatusExt},
    },
    pin::Pin,
    process::ExitStatus,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf, unix::AsyncFd};

const SPAWN: libc::c_long = 0x43595810;
const MAX_FDS: usize = 64;
const MAX_VECTOR: usize = 32;
const MAX_STRINGS: usize = 4096;
const MAX_PATH: usize = 95;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping {
    source: i32,
    target: i32,
}

#[repr(C)]
struct Request {
    size: u32,
    flags: u32,
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
    cwd: *const libc::c_char,
    mappings: *const Mapping,
    mapping_count: u32,
    reserved: u32,
    reserved2: u64,
}

const _: () = assert!(std::mem::size_of::<Request>() == 64);
const _: () = assert!(std::mem::size_of::<Mapping>() == 8);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| invalid("native spawn string contains NUL"))
}

fn cvt(value: libc::c_int) -> io::Result<libc::c_int> {
    if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
}

struct Input {
    args: Vec<CString>,
    env: Vec<CString>,
    paths: Vec<CString>,
}

impl Input {
    fn new(executable: &str, args: &[String], overrides: &[(String, String)]) -> io::Result<Self> {
        Self::with_environment(executable, args, overrides, std::env::vars_os())
    }

    fn with_environment(
        executable: &str,
        args: &[String],
        overrides: &[(String, String)],
        environment: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> io::Result<Self> {
        if executable.is_empty() { return Err(invalid("empty native executable")); }
        if args.len() >= MAX_VECTOR { return Err(io::Error::from_raw_os_error(libc::E2BIG)); }
        let mut merged: BTreeMap<OsString, OsString> = environment.into_iter().collect();
        for (key, value) in overrides {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(invalid("invalid native environment key"));
            }
            merged.insert(key.into(), value.into());
        }
        if merged.len() > MAX_VECTOR { return Err(io::Error::from_raw_os_error(libc::E2BIG)); }
        let paths = if executable.contains('/') {
            vec![executable.as_bytes().to_vec()]
        } else {
            let path = merged.get(std::ffi::OsStr::new("PATH"))
                .map(|value| value.as_os_str().as_bytes())
                .unwrap_or(b"/usr/local/bin:/bin:/usr/bin");
            path.split(|byte| *byte == b':').map(|directory| {
                let mut candidate = directory.to_vec();
                if !candidate.is_empty() { candidate.push(b'/'); }
                candidate.extend_from_slice(executable.as_bytes());
                candidate
            }).collect()
        };
        let paths = paths.into_iter().map(|path| cstring(&path)).collect::<io::Result<Vec<_>>>()?;
        let args = std::iter::once(executable).chain(args.iter().map(String::as_str))
            .map(|arg| cstring(arg.as_bytes())).collect::<io::Result<Vec<_>>>()?;
        let env = merged.into_iter().map(|(key, value)| {
            let key = key.as_os_str().as_bytes();
            if key.is_empty() || key.contains(&b'=') { return Err(invalid("invalid inherited environment key")); }
            let mut entry = key.to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            cstring(&entry)
        }).collect::<io::Result<Vec<_>>>()?;
        let bytes = args.iter().chain(&env).try_fold(0usize, |used, string| {
            used.checked_add(string.as_bytes_with_nul().len())
                .filter(|total| *total <= MAX_STRINGS)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))
        })?;
        debug_assert!(bytes <= MAX_STRINGS);
        Ok(Self { args, env, paths })
    }
}

fn descriptor_limit() -> io::Result<usize> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: limit is writable for the complete rlimit structure.
    cvt(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) })?;
    let limit = usize::try_from(limit.rlim_cur).map_err(|_| invalid("native fd limit overflow"))?;
    if !(3..=MAX_FDS).contains(&limit) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "native fd table exceeds supported ABI"));
    }
    Ok(limit)
}

fn fd_flags(fd: RawFd) -> io::Result<i32> {
    // SAFETY: F_GETFD has no pointer arguments and does not mutate the descriptor.
    cvt(unsafe { libc::fcntl(fd, libc::F_GETFD) })
}

fn mappings(limit: usize, forced: &[RawFd], owned: &[RawFd], stdio: [RawFd; 3]) -> io::Result<Vec<Mapping>> {
    let mut maps = Vec::with_capacity(limit);
    for (target, source) in stdio.into_iter().enumerate() {
        maps.push(Mapping { source, target: target as i32 });
    }
    for fd in 3..limit as RawFd {
        if owned.contains(&fd) { continue; }
        match fd_flags(fd) {
            Ok(flags) if flags & libc::FD_CLOEXEC == 0 || forced.contains(&fd) => {
                maps.push(Mapping { source: fd, target: fd });
            }
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::EBADF) && !forced.contains(&fd) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(maps)
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds is a writable two-element array. Each returned fd has one owner.
    cvt(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn register(fd: OwnedFd, interest: Interest) -> io::Result<AsyncFd<OwnedFd>> {
    // Only newly created parent pipe ends are changed. Opposite ends have distinct OFDs.
    let flags = cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
    cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    AsyncFd::with_interest(fd, interest)
}

pub struct ChildReader(AsyncFd<OwnedFd>);
pub struct ChildWriter(Option<AsyncFd<OwnedFd>>);

impl AsyncRead for ChildReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 { return Poll::Ready(Ok(())); }
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let result = guard.try_io(|inner| {
                let unfilled = buf.initialize_unfilled();
                loop {
                    // SAFETY: the initialized unfilled region is writable for its full length.
                    let count = unsafe { libc::read(inner.get_ref().as_raw_fd(), unfilled.as_mut_ptr().cast(), unfilled.len()) };
                    if count >= 0 { return Ok(count as usize); }
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
                }
            });
            match result {
                Ok(Ok(count)) => { buf.advance(count); return Poll::Ready(Ok(())); }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for ChildWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let Some(fd) = &self.0 else { return Poll::Ready(Err(io::Error::from_raw_os_error(libc::EPIPE))); };
        if buf.is_empty() { return Poll::Ready(Ok(0)); }
        loop {
            let mut guard = ready!(fd.poll_write_ready(cx))?;
            match guard.try_io(|inner| loop {
                // SAFETY: buf is readable for the specified length.
                let count = unsafe { libc::write(inner.get_ref().as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
                if count >= 0 { return Ok(count as usize); }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.take();
        Poll::Ready(Ok(()))
    }
}

/// A real native child and its kernel wait receipt. All managed children are killed on drop.
pub struct NativeChild {
    pub stdin: Option<ChildWriter>,
    pub stdout: Option<ChildReader>,
    pub stderr: Option<ChildReader>,
    pid: libc::pid_t,
    status: Option<ExitStatus>,
}

impl NativeChild {
    pub fn spawn(executable: &str, args: &[String], env: &[(String, String)], forced: &[RawFd]) -> io::Result<Self> {
        let input = Input::new(executable, args, env)?;
        let limit = descriptor_limit()?;
        for &fd in forced {
            if fd < 3 || fd as usize >= limit { return Err(invalid("explicit fd conflicts with stdio or exceeds native table")); }
            fd_flags(fd)?;
        }
        let (child_stdin, parent_stdin) = pipe()?;
        let (parent_stdout, child_stdout) = pipe()?;
        let (parent_stderr, child_stderr) = pipe()?;
        let owned = [child_stdin.as_raw_fd(), parent_stdin.as_raw_fd(), parent_stdout.as_raw_fd(),
            child_stdout.as_raw_fd(), parent_stderr.as_raw_fd(), child_stderr.as_raw_fd()];
        let stdio = [child_stdin.as_raw_fd(), child_stdout.as_raw_fd(), child_stderr.as_raw_fd()];
        let stdin = ChildWriter(Some(register(parent_stdin, Interest::WRITABLE)?));
        let stdout = ChildReader(register(parent_stdout, Interest::READABLE)?);
        let stderr = ChildReader(register(parent_stderr, Interest::READABLE)?);
        let maps = mappings(limit, forced, &owned, stdio)?;
        let argv = input.args.iter().map(|arg| arg.as_ptr()).chain(std::iter::once(std::ptr::null())).collect::<Vec<_>>();
        let envp = input.env.iter().map(|arg| arg.as_ptr()).chain(std::iter::once(std::ptr::null())).collect::<Vec<_>>();
        let mut denied = false;
        let mut too_long = false;
        let mut not_found = false;
        for path in &input.paths {
            // A PATH component outside the native pathname bound must not
            // prevent an earlier or later usable component from succeeding.
            if path.as_bytes().len() > MAX_PATH {
                too_long = true;
                continue;
            }
            let request = Request {
                size: 64, flags: 0, path: path.as_ptr(), argv: argv.as_ptr(), envp: envp.as_ptr(),
                cwd: std::ptr::null(), mappings: maps.as_ptr(), mapping_count: maps.len() as u32,
                reserved: 0, reserved2: 0,
            };
            // SAFETY: every request pointer remains valid throughout the synchronous syscall.
            let pid = unsafe { libc::syscall(SPAWN, &request) };
            if pid > 0 && pid <= i32::MAX as libc::c_long {
                return Ok(Self { stdin: Some(stdin), stdout: Some(stdout), stderr: Some(stderr), pid: pid as libc::pid_t, status: None });
            }
            if pid >= 0 { return Err(io::Error::other("native spawn returned invalid pid")); }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EACCES) => denied = true,
                Some(libc::ENOENT | libc::ENOTDIR) => not_found = true,
                Some(libc::ENAMETOOLONG) => too_long = true,
                _ => return Err(error),
            }
        }
        let error = if denied {
            libc::EACCES
        } else if too_long && !not_found {
            libc::ENAMETOOLONG
        } else {
            libc::ENOENT
        };
        Err(io::Error::from_raw_os_error(error))
    }

    pub fn id(&self) -> Option<u32> { self.status.is_none().then_some(self.pid as u32) }

    fn try_wait(&mut self, options: libc::c_int) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status { return Ok(Some(status)); }
        loop {
            let mut raw = 0;
            // SAFETY: raw is writable; the positive pid is the child created by this object.
            let result = unsafe { libc::waitpid(self.pid, &mut raw, options) };
            if result == self.pid {
                let status = ExitStatus::from_raw(raw);
                self.status = Some(status);
                return Ok(Some(status));
            }
            if result == 0 { return Ok(None); }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
        }
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.stdin.take();
        let mut delay_ms = 10;
        loop {
            if let Some(status) = self.try_wait(libc::WNOHANG)? { return Ok(status); }
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 2).min(100);
        }
    }

    pub async fn kill(&mut self) -> io::Result<()> {
        if self.status.is_none() {
            // SAFETY: only this object's real positive child pid is addressed.
            if unsafe { libc::kill(self.pid, libc::SIGKILL) } < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) { return Err(error); }
            }
            self.wait().await?;
        }
        Ok(())
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();
        if self.status.is_some() { return; }
        // Runtime shutdown cannot service a newly spawned asynchronous reaper.
        let killed = unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0;
        let error = (!killed).then(io::Error::last_os_error);
        let options = if killed || error.as_ref().is_some_and(|e| e.raw_os_error() == Some(libc::ESRCH)) {
            0
        } else {
            log::error!("native child {} kill-on-drop failed: {:?}", self.pid, error);
            libc::WNOHANG
        };
        if let Err(error) = self.try_wait(options) {
            if error.raw_os_error() != Some(libc::ECHILD) {
                log::error!("native child {} reap-on-drop failed: {}", self.pid, error);
            }
        }
    }
}

