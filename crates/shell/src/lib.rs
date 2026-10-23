#![no_std]
#![forbid(unsafe_code)]
use core::fmt::{self, Write};
use cyxia_ai_fs::{Error, FILE_BYTES, FileSystem, Kind, Path};
mod resources;
mod system;
const LINE_BYTES: usize = 1152;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageRequest {
    Status,
    Checkpoint,
}

pub struct Shell {
    fs: FileSystem,
    runtime: cyxia_ai_runtime::Runtime,
    cwd: Path,
    user_request: Option<cyxia_posix::UserRequest>,
    storage_request: Option<StorageRequest>,
    system_request: bool,
    user_status: cyxia_posix::UserStatus,
    user_processes: [cyxia_posix::UserStatus; cyxia_posix::usermem::MAX_PROCESSES],
    line: [u8; LINE_BYTES],
    len: usize,
    overflow: bool,
    damaged: bool,
    escape: u8,
    was_cr: bool,
}
impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}
impl Shell {
    pub const fn new() -> Self {
        Self {
            fs: FileSystem::new(),
            runtime: cyxia_ai_runtime::Runtime::new(),
            cwd: Path::ROOT,
            user_request: None,
            storage_request: None,
            system_request: false,
            user_status: cyxia_posix::UserStatus::EMPTY,
            user_processes: [cyxia_posix::UserStatus::EMPTY; cyxia_posix::usermem::MAX_PROCESSES],
            line: [0; LINE_BYTES],
            len: 0,
            overflow: false,
            damaged: false,
            escape: 0,
            was_cr: false,
        }
    }
    pub fn fs_mut(&mut self) -> &mut FileSystem {
        &mut self.fs
    }
    pub fn take_storage_request(&mut self) -> Option<StorageRequest> {
        self.storage_request.take()
    }
    /// The kernel services this read-only request at a CPU0 foreground boundary.
    pub fn take_system_request(&mut self) -> bool {
        core::mem::take(&mut self.system_request)
    }
    /// Trusted runnable work observed by the kernel; clipped to the model domain.
    /// This is load, not authorization, and never cancels already committed I/O.
    pub fn runnable_work(&self) -> usize {
        (self
            .user_processes
            .iter()
            .filter(|p| p.state == cyxia_posix::UserState::Running)
            .count()
            + self
                .runtime
                .tasks()
                .filter(|t| t.state == cyxia_ai_runtime::TaskState::Ready && !t.paused)
                .count())
        .min(8)
    }
    pub fn take_user_request(&mut self) -> Option<cyxia_posix::UserRequest> {
        self.user_request.take()
    }
    pub fn set_user_status(&mut self, status: cyxia_posix::UserStatus) {
        self.user_status = status;
    }
    pub fn set_user_processes(
        &mut self,
        processes: [cyxia_posix::UserStatus; cyxia_posix::usermem::MAX_PROCESSES],
    ) {
        self.user_processes = processes;
    }
    pub fn runtime_mut(&mut self) -> &mut cyxia_ai_runtime::Runtime {
        &mut self.runtime
    }
    pub fn banner(&self, out: &mut impl Write) -> fmt::Result {
        writeln!(out, "\r\nCyxiaOS Shell | ARM EL1 | local AI file policy\r")?;
        writeln!(
            out,
            "RAM filesystem: use storage checkpoint with a disk to save; unsaved files and learning are lost on reboot. Type help.\r"
        )?;
        self.prompt(out)
    }
    fn prompt(&self, out: &mut impl Write) -> fmt::Result {
        write!(out, "cyxia:{}> ", self.cwd.as_str())
    }
    /// Transport damage poisons the entire physical line, including its buffered tail.
    pub fn input_error(&mut self) {
        self.len = 0;
        self.escape = 0;
        self.was_cr = false;
        self.damaged = true;
    }
    pub fn input(&mut self, byte: u8, out: &mut impl Write) -> fmt::Result {
        if self.damaged {
            if byte == b'\r' || byte == b'\n' {
                self.damaged = false;
                self.overflow = false;
                self.was_cr = byte == b'\r';
                writeln!(out, "\r\nerror: damaged input; command discarded\r")?;
                self.prompt(out)?;
            }
            return Ok(());
        }
        if byte == 3 {
            self.len = 0;
            self.overflow = false;
            self.escape = 0;
            self.was_cr = false;
            write!(out, "^C\r\n")?;
            return self.prompt(out);
        }
        if byte == b'\n' && self.was_cr {
            self.was_cr = false;
            return Ok(());
        }
        self.was_cr = byte == b'\r';
        if byte == b'\r' || byte == b'\n' {
            self.escape = 0;
            write!(out, "\r\n")?;
            if self.overflow {
                writeln!(out, "error: line too long; command discarded\r")?;
            } else {
                // Copy only the bounded command buffer to separate parser and filesystem borrows.
                let line = self.line;
                match core::str::from_utf8(&line[..self.len]) {
                    Ok(s) => self.execute(s, out)?,
                    Err(_) => writeln!(out, "error: invalid UTF-8\r")?,
                }
            }
            self.len = 0;
            self.overflow = false;
            return self.prompt(out);
        }
        if self.escape != 0 {
            if self.escape == 1 && (byte == b'[' || byte == b'O') {
                self.escape = 2;
            } else if self.escape == 1 || (0x40..=0x7e).contains(&byte) {
                self.escape = 0;
            }
            return Ok(());
        }
        if byte == 27 {
            self.escape = 1;
            return Ok(());
        }
        if self.overflow {
            return Ok(());
        }
        if byte == 8 || byte == 127 {
            if self.len > 0 {
                self.len -= 1;
                while self.len > 0 && self.line[self.len] & 0xc0 == 0x80 {
                    self.len -= 1;
                }
                write!(out, "\x08 \x08")?;
            }
        } else if byte >= 32 || byte == b'\t' {
            if self.len == LINE_BYTES {
                self.overflow = true;
                write!(out, "\x07")?;
            } else {
                let byte = if byte == b'\t' { b' ' } else { byte };
                self.line[self.len] = byte;
                self.len += 1;
                // Echo complete UTF-8 sequences; do not print malformed byte fragments.
                if let Ok(s) = core::str::from_utf8(&self.line[..self.len])
                    && let Some(c) = s.chars().last()
                {
                    write!(out, "{c}")?;
                }
            }
        }
        Ok(())
    }
    pub fn execute(&mut self, line: &str, out: &mut impl Write) -> fmt::Result {
        match self.command(line, out) {
            Ok(()) => Ok(()),
            Err(CommandError::Resource(e)) => writeln!(out, "error: {e:?}\r"),
            Err(CommandError::Fs(e)) => writeln!(out, "error: {e:?}\r"),
            Err(CommandError::Usage) => writeln!(out, "error: invalid arguments; type help\r"),
            Err(CommandError::Output) => Err(fmt::Error),
        }
    }
    fn queue_user(
        &mut self,
        request: cyxia_posix::UserRequest,
        out: &mut impl Write,
    ) -> Result<(), CommandError> {
        if self.user_request.is_some() {
            writeln!(out, "error: user request busy\r")?;
        } else {
            self.user_request = Some(request);
            writeln!(out, "EL0 request queued\r")?;
        }
        Ok(())
    }
    fn command(&mut self, line: &str, out: &mut impl Write) -> Result<(), CommandError> {
        let (cmd, rest) = split(line.trim_start());
        if cmd.is_empty() {
            return Ok(());
        }
        let (arg, tail) = split(rest);
        match cmd {
            "storage" => {
                no_args(tail)?;
                let request = match arg {
                    "status" => StorageRequest::Status,
                    "checkpoint" => StorageRequest::Checkpoint,
                    _ => return Err(CommandError::Usage),
                };
                if self.storage_request.is_some() {
                    writeln!(out, "error: storage request busy\r")?;
                } else {
                    self.storage_request = Some(request);
                    writeln!(out, "STORAGE_REQUEST queued\r")?;
                }
            }
            "posix" => match arg {
                "status" => {
                    no_args(tail)?;
                    writeln!(out, "POSIX subset EL0 {:?}\r", self.user_status)?;
                }
                "list" => {
                    no_args(tail)?;
                    for process in self.user_processes.iter().filter(|p| p.pid != 0) {
                        writeln!(out, "EL0 {process:?}\r")?;
                    }
                }
                "kill" => {
                    let pid = if tail.is_empty() {
                        None
                    } else {
                        Some(
                            tail.parse::<u32>()
                                .ok()
                                .filter(|p| *p > 0)
                                .ok_or(CommandError::Usage)?,
                        )
                    };
                    self.queue_user(cyxia_posix::UserRequest::Kill(pid), out)?;
                }
                "pair" => {
                    no_args(tail)?;
                    self.queue_user(cyxia_posix::UserRequest::Pair, out)?;
                }
                "exec" => {
                    let name = match tail {
                        "probe" => "probe",
                        "xau-probe" => "xau-probe",
                        "x11-probe" => "x11-probe",
                        "x11-interactive" => "x11-interactive",
                        "x11-demo" => "x11-demo",
                        "socket-probe" => "socket-probe",
                        "signal-probe" => "signal-probe",
                        "desktop-api-probe" => "desktop-api-probe",
                        "pipe-probe" => "pipe-probe",
                        "file-probe" => "file-probe",
                        "clock-probe" => "clock-probe",
                        "event-probe" => "event-probe",
                        "timerfd-probe" => "timerfd-probe",
                        "edge-probe" => "edge-probe",
                        "rust-reactor-probe" => "rust-reactor-probe",
                        "smithay-probe" => "smithay-probe",
                        "smithay-wayland-probe" => "smithay-wayland-probe",
                        "smithay-xdg-probe" => "smithay-xdg-probe",
                        "smithay-multi-probe" => "smithay-multi-probe",
                        "smithay-interactive-probe" => "smithay-interactive-probe",
                        "smithay-resize-probe" => "smithay-resize-probe",
                        "smithay-dynamic-probe" => "smithay-dynamic-probe",
                        "smithay-dynamic-a" => "smithay-dynamic-a",
                        "smithay-dynamic-b" => "smithay-dynamic-b",
                        "smithay-dynamic-c" => "smithay-dynamic-c",
                        "smithay-dynamic-reject" => "smithay-dynamic-reject",
                        "rust-egl-probe" => "rust-egl-probe",
                        "fd-share-probe" => "fd-share-probe",
                        "scm-probe" => "scm-probe",
                        "memfd-probe" => "memfd-probe",
                        "egl-probe" => "egl-probe",
                        "egl-x11-probe" => "egl-x11-probe",
                        "rust-std-probe" => "rust-std-probe",
                        "wayland-probe" => "wayland-probe",
                        "wayland-shm-probe" => "wayland-shm-probe",
                        "xkbcommon-probe" => "xkbcommon-probe",
                        "cyxia-save" => "cyxia-save",
                        "cyxia-terminal" => "cyxia-terminal",
                        "cyxia-sh" => "cyxia-sh",
                        "pty-probe" => "pty-probe",
                        "thread-probe" => "thread-probe",
                        "glib-spawn-probe" => "glib-spawn-probe",
                        "spawn-probe" => "spawn-probe",
                        "x11-inspect" => "x11-inspect",
                        "xorg" => "xorg",
                        "twm" => "twm",
                        "openbox" => "openbox",
                        "gtk-probe" => "gtk-probe",
                        "gtk-smoke" => "gtk-smoke",
                        "pcmanfm" => "pcmanfm",
                        "pcmanfm-desktop" => "pcmanfm-desktop",
                        "pcmanfm-home" => "pcmanfm-home",
                        "lxpanel" => "lxpanel",
                        _ => return Err(CommandError::Usage),
                    };
                    self.queue_user(cyxia_posix::UserRequest::Execute(name), out)?;
                }
                "spawn" => {
                    let mode = match tail {
                        "idle" => "idle",
                        "spin" => "spin",
                        "fault" => "fault",
                        "heap" => "heap",
                        "heapfault" => "heapfault",
                        "paint" => "paint",
                        "fpu" => "fpu",
                        "heapexec" => "heapexec",
                        _ => return Err(CommandError::Usage),
                    };
                    self.queue_user(cyxia_posix::UserRequest::Spawn(mode), out)?;
                }
                "run" => {
                    let mode = match tail {
                        "demo" => "demo",
                        "preempt" => "preempt",
                        "fault" => "fault",
                        "spin" => "spin",
                        "readonly" => "readonly",
                        "execdata" => "execdata",
                        "kernel" => "kernel",
                        "guard" => "guard",
                        _ => return Err(CommandError::Usage),
                    };
                    if self.user_status.state.active() || self.user_request.is_some() {
                        writeln!(out, "error: user process busy\r")?;
                    } else {
                        self.user_request = Some(cyxia_posix::UserRequest::Run(mode));
                        writeln!(out, "EL0 launch queued: {mode}\r")?;
                    }
                }
                _ => return Err(CommandError::Usage),
            },

            "mem" | "proc" | "dev" => self.resource_command(cmd, rest, out)?,
            "ps" => {
                no_args(rest)?;
                self.resource_command("proc", "list", out)?;
            }
            "help" => {
                no_args(rest)?;
                write!(
                    out,
                    "posix run demo|preempt|fault|spin|readonly|execdata|kernel|guard | posix status|list|kill [PID]\r\nposix spawn idle|spin|fault|heap|heapfault|paint|fpu|heapexec | posix pair (native Rust IPC check)\r\nposix exec probe|xau-probe|socket-probe|signal-probe|desktop-api-probe|pipe-probe|file-probe|thread-probe|spawn-probe|glib-spawn-probe (ported/test builds)\r\nposix exec xorg|twm|openbox|x11-probe|x11-interactive|x11-demo|gtk-probe|gtk-smoke|pcmanfm|pcmanfm-home|pcmanfm-desktop|lxpanel|cyxia-save|x11-inspect (desktop profiles)\r\nmem status|alloc|free|peek|poke|list | proc spawn|list|pause|resume|kill|reap\r\ndev list|write|read|batch|requests|cancel|reap|enable|disable | ai system|resources|audit\r\nhelp | pwd | cd PATH | ls [PATH] | mkdir PATH | touch PATH\r\nwrite PATH TEXT | append PATH TEXT | cat PATH | stat PATH\r\nrm PATH | rmdir PATH | df | ai status|cache|train|apply|rollback\r\nstorage status|checkpoint (dedicated raw disk; wait for STORAGE_DURABLE)\r\nPaths: UTF-8; shell path arguments cannot contain spaces. Text is literal UTF-8 (no quotes).\r\nCatalog EL0 programs and Rust services; no shell pipelines or scripts. Ctrl+C cancels.\r\n"
                )?;
            }
            "pwd" => {
                no_args(rest)?;
                writeln!(out, "{}\r", self.cwd.as_str())?;
            }
            "df" => {
                no_args(rest)?;
                let s = self.fs.status();
                writeln!(
                    out,
                    "RAMFS nodes={}/{} bytes={} file_limit={} cache=4 persistent=no\r",
                    s.nodes,
                    cyxia_ai_fs::NODES,
                    s.bytes,
                    cyxia_ai_fs::FILE_BYTES
                )?;
            }
            "ai" => {
                no_args(tail)?;
                match arg {
                    "system" => {
                        if self.system_request {
                            return Err(cyxia_ai_runtime::Error::Busy.into());
                        }
                        self.system_request = true;
                        writeln!(out, "AI_SYSTEM_REQUEST queued\r")?;
                    }
                    "resources" => self.resource_status(out)?,
                    "audit" => self.resource_audit(out)?,
                    "status" => {
                        let s = self.fs.status();
                        writeln!(
                            out,
                            "local integer model v{} source={:?} decisions={} denied={}\r",
                            s.model.version, s.last_source, s.decisions, s.denied
                        )?;
                        writeln!(
                            out,
                            "cache hits={} misses={} weights={:?}\r",
                            s.hits, s.misses, s.model.weights
                        )?;
                        writeln!(
                            out,
                            "learning samples={}/64 trained={} candidate={} rollback={}\r",
                            s.model.samples, s.model.trained, s.model.candidate, s.model.rollback
                        )?;
                    }
                    "cache" => {
                        for e in self.fs.entries().filter(|e| e.cached) {
                            writeln!(
                                out,
                                "{} bytes={} reads={}\r",
                                e.path.as_str(),
                                e.len,
                                e.reads
                            )?;
                        }
                    }
                    "train" => {
                        self.fs.train()?;
                        writeln!(out, "candidate validated; ai apply to activate\r")?;
                    }
                    "apply" => {
                        self.fs.apply()?;
                        writeln!(out, "model activated (OPERATOR)\r")?;
                    }
                    "rollback" => {
                        self.fs.rollback()?;
                        writeln!(out, "model rolled back (OPERATOR)\r")?;
                    }
                    _ => return Err(CommandError::Usage),
                }
            }
            "ls" => {
                no_args(tail)?;
                let path = if arg.is_empty() {
                    self.cwd
                } else {
                    Path::resolve(self.cwd, arg)?
                };
                let entry = self.fs.stat(path)?;
                if entry.kind == Kind::File {
                    writeln!(out, "f {} {}\r", entry.len, path.name())?;
                } else {
                    for e in self.fs.entries().filter(|e| e.path.parent() == path) {
                        writeln!(
                            out,
                            "{} {} {}\r",
                            if e.kind == Kind::Directory { "d" } else { "f" },
                            e.len,
                            e.path.name()
                        )?;
                    }
                }
            }
            "cd" | "mkdir" | "touch" | "cat" | "stat" | "rm" | "rmdir" | "write" | "append" => {
                if arg.is_empty() {
                    return Err(CommandError::Usage);
                }
                if cmd != "write" && cmd != "append" {
                    no_args(tail)?;
                }
                let p = Path::resolve(self.cwd, arg)?;
                match cmd {
                    "cd" => {
                        if self.fs.stat(p)?.kind != Kind::Directory {
                            return Err(Error::NotDirectory.into());
                        }
                        self.cwd = p;
                    }
                    "mkdir" => self.fs.mkdir(p)?,
                    "touch" => match self.fs.stat(p) {
                        Ok(e) if e.kind == Kind::File => {}
                        Ok(_) => return Err(Error::IsDirectory.into()),
                        Err(Error::NotFound) => self.fs.write(p, b"", false)?,
                        Err(e) => return Err(e.into()),
                    },
                    "write" => self.fs.write(p, tail.as_bytes(), false)?,
                    "append" => self.fs.write(p, tail.as_bytes(), true)?,
                    "cat" => {
                        let mut buf = [0; FILE_BYTES];
                        let n = self.fs.read(p, &mut buf)?;
                        // Escape controls from file data; do not execute terminal escape sequences.
                        if let Ok(text) = core::str::from_utf8(&buf[..n]) {
                            for c in text.chars() {
                                if c == '\n' {
                                    write!(out, "\r\n")?;
                                } else if c.is_control() {
                                    write!(out, "\\u{{{:x}}}", c as u32)?;
                                } else {
                                    write!(out, "{c}")?;
                                }
                            }
                        } else {
                            for b in &buf[..n] {
                                write!(out, "\\x{b:02x}")?;
                            }
                        }
                        write!(out, "\r\n")?;
                    }
                    "stat" => {
                        let e = self.fs.stat(p)?;
                        writeln!(
                            out,
                            "{} {:?} bytes={} reads={} cached={}\r",
                            p.as_str(),
                            e.kind,
                            e.len,
                            e.reads,
                            e.cached
                        )?;
                    }
                    "rm" => self.fs.remove(p, false)?,
                    "rmdir" => {
                        let mut ancestor = self.cwd;
                        loop {
                            if p == ancestor {
                                return Err(Error::NotEmpty.into());
                            }
                            if ancestor == Path::ROOT {
                                break;
                            }
                            ancestor = ancestor.parent();
                        }
                        self.fs.remove(p, true)?;
                    }
                    _ => unreachable!(),
                }
            }
            _ => {
                writeln!(out, "error: unknown command; type help\r")?;
            }
        }
        Ok(())
    }
}
fn split(s: &str) -> (&str, &str) {
    let s = s.trim_start_matches([' ', '\t']);
    match s.find([' ', '\t']) {
        Some(i) => (&s[..i], s[i..].trim_start_matches([' ', '\t'])),
        None => (s, ""),
    }
}
enum CommandError {
    Resource(cyxia_ai_runtime::Error),
    Fs(Error),
    Usage,
    Output,
}
impl From<Error> for CommandError {
    fn from(e: Error) -> Self {
        Self::Fs(e)
    }
}
impl From<fmt::Error> for CommandError {
    fn from(_: fmt::Error) -> Self {
        Self::Output
    }
}
fn no_args(s: &str) -> Result<(), CommandError> {
    if s.trim().is_empty() {
        Ok(())
    } else {
        Err(CommandError::Usage)
    }
}
#[cfg(test)]
mod tests;

impl From<cyxia_ai_runtime::Error> for CommandError {
    fn from(e: cyxia_ai_runtime::Error) -> Self {
        Self::Resource(e)
    }
}
