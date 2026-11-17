"""Run actual shell/launch configuration bodies over explicit host facades.

This verifies request queueing, the production runtime-directory guard, and
the actual StackInput expressions used by direct and shared-spawn launches.
It does not execute an ELF or replace the guest loader, grant ledger, or IPC.
The full-OS layout and executable policy are the production Rust definitions.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from doctor import RUST_BIN, env
from native_session import idle_native_host, native_lease
from test_governance_billing_priority import function

LOCK = ROOT / "artifacts/v017-cosmic-completion-20261116/native-session.lock"


def between(source, start, end):
    first = source.index(start)
    return source[first:source.index(end, first)]


def production_program():
    shell = (ROOT / "crates/shell/src/lib.rs").read_text()
    user = (ROOT / "kernel/src/desktop/user.rs").read_text()
    spawn = (ROOT / "kernel/src/desktop/user/spawn.rs").read_text()
    runtime = (ROOT / "crates/posix/src/runtime_directory.rs").read_text()
    posix = (ROOT / "crates/posix/src/lib.rs").read_text()
    memory = (ROOT / "kernel/src/desktop/memory/exec_memory.rs").read_text()
    policy = (ROOT / "crates/ai-runtime/src/lib.rs").read_text()
    pieces = {
        "REQUEST": function(posix, "pub enum UserRequest"),
        "QUEUE": function(shell, "fn queue_user("),
        "TAKE": function(shell, "pub fn take_user_request("),
        "SPLIT": function(shell, "fn split("),
        "NO_ARGS": function(shell, "fn no_args("),
        "PARSE": between(shell, "        let (cmd, rest) = split(line.trim_start());", "        match cmd {"),
        "POSIX_ARM": function(shell, '"posix" => match arg'),
        "RUNTIME_CONSTANTS": between(runtime, "pub const DIRECTORY:", "pub fn reset_at_boot("),
        "RUNTIME_VALIDATE": function(runtime, "pub fn validate("),
        "RUNTIME_GUARD": between(user, "        let uses_session_runtime =", "        let mut random = [0u8; 16];"),
        "ARGUMENTS": between(user, "        let normal_argv:", "        let sp = match runner.executable.load("),
        "DIRECT_INPUT": function(user, "super::exec_memory::StackInput {"),
        "SPAWN_ARRAYS": between(spawn, "            let args: [&[u8]; 32] =", "            let runner = &mut self.runners[slot];"),
        "SPAWN_INPUT": function(spawn, "super::super::exec_memory::StackInput {"),
        "STACK_TYPE": function(memory, "pub struct StackInput<'a>"),
        "PAGE_COUNT": between(memory, "        let count = plan.pages().count() + STACK_PAGES;", "        attempt.proposed("),
        "MODEL_ID": re.search(r"pub const FULL_OS_EXEC_MODEL_ID[^;]+;", policy).group(),
        "MODEL": function(policy, "pub fn full_os_executable_memory_policy("),
        "WEIGHTS_PATH": json.dumps(str(ROOT / "crates/ai-runtime/src/weights.rs")),
        "LAYOUT_PATH": json.dumps(str(ROOT / "crates/contracts/src/user_layout.rs")),
    }
    program = HARNESS
    for key, value in pieces.items():
        program = program.replace("// " + key + "\n", value + "\n")
    return program, pieces


HARNESS = r'''
#![allow(dead_code, unused_mut, unused_variables)]
extern crate self as cyxia_posix;
use std::{cell::Cell, fmt::{self, Write}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// REQUEST
#[derive(Debug)]
enum CommandError { Usage, Output }
impl From<fmt::Error> for CommandError {
    fn from(_: fmt::Error) -> Self { Self::Output }
}
#[derive(Debug, Default)]
struct Status { pid: u32, state: State }
#[derive(Debug, Default)]
struct State;
impl State { fn active(&self) -> bool { false } }
#[derive(Default)]
struct Shell {
    user_request: Option<UserRequest>, user_status: Status, user_processes: [Status; 1],
}
impl Shell {
    // QUEUE
    // TAKE
    fn command(&mut self, line: &str, out: &mut impl Write) -> Result<(), CommandError> {
        // PARSE
        match cmd {
            // POSIX_ARM
            _ => return Err(CommandError::Usage),
        }
        Ok(())
    }
}
// SPLIT
// NO_ARGS

// Filesystem contents are a facade. The directory mode/type validation below
// and its position before launch preparation are the actual production bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno { Noent, Notdir, Access, Inval }
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind { Directory, File }
#[derive(Clone, Copy)]
struct Entry { kind: Kind, mode: u16 }
struct Path(&'static str);
impl Path {
    const ROOT: Self = Self("/");
    fn resolve(_: Self, value: &'static str) -> Result<Self, Errno> { Ok(Self(value)) }
}
struct FileSystem { entry: Option<Entry>, queries: Cell<usize> }
impl FileSystem {
    fn valid() -> Self { Self { entry: Some(Entry { kind: Kind::Directory, mode: 0o700 }), queries: Cell::new(0) } }
    fn stat(&self, path: Path) -> Result<Entry, Errno> {
        assert_eq!(path.0, "/run/user/0");
        self.queries.set(self.queries.get() + 1);
        self.entry.ok_or(Errno::Noent)
    }
}
pub mod runtime_directory {
    use super::{Entry, Errno, FileSystem, Kind, Path};
    // RUNTIME_CONSTANTS
    // RUNTIME_VALIDATE
}

#[derive(Debug, PartialEq, Eq)]
struct Prepared { argv: Vec<Vec<u8>>, env: Vec<Vec<u8>>, execfn: Vec<u8> }
impl Prepared {
    fn has(&self, value: &[u8]) -> bool { self.env.iter().any(|v| v == value) }
}
fn capture(input: kernel::exec_memory::StackInput<'_>) -> Prepared {
    Prepared { argv: input.argv.iter().map(|s| s.to_vec()).collect(),
        env: input.envp.iter().map(|s| s.to_vec()).collect(), execfn: input.execfn.to_vec() }
}
mod kernel {
    pub mod exec_memory {
        // STACK_TYPE
    }
    pub mod user {
        use crate::{capture, Errno, FileSystem, Prepared};
        pub fn prepare(name: &str, fs: &FileSystem) -> Result<Prepared, Errno> {
            let image_name = name;
            let path = format!("/bin/{name}");
            // RUNTIME_GUARD
            let random = [0u8; 16];
            // ARGUMENTS
            let input =
                // DIRECT_INPUT
            ;
            Ok(capture(input))
        }
        pub mod spawn {
            use crate::{capture, Prepared};
            pub struct Request {
                pub bytes: [u8; 4096], pub args: [[u16; 2]; 32], pub env: [[u16; 2]; 32],
                pub argc: usize, pub envc: usize,
            }
            pub fn prepare(request: &Request, actual_path: &str) -> Prepared {
                let random = [0u8; 16];
                // SPAWN_ARRAYS
                let input =
                    // SPAWN_INPUT
                ;
                capture(input)
            }
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error { Invalid }
#[path=
// WEIGHTS_PATH
]
mod weights;
#[path=
// LAYOUT_PATH
]
mod user_layout;
fn counted_image_pages(load_pages: usize) -> Result<usize, Errno> {
    const LAYOUT: user_layout::ImageLayout = user_layout::ImageProfile::FullOsV3.layout();
    const PAGES: usize = LAYOUT.exec_pool_pages;
    const STACK_PAGES: usize = LAYOUT.stack_pages;
    struct Permissions { read: bool }
    struct Page { permissions: Permissions }
    struct Plan { count: usize }
    impl Plan {
        fn pages(&self) -> impl Iterator<Item=Page> {
            (0..self.count).map(|_| Page { permissions: Permissions { read: true } })
        }
    }
    let plan = Plan { count: load_pages };
    // PAGE_COUNT
    Ok(count)
}
// MODEL_ID
// MODEL

#[cfg(test)]
mod notification_launch {
    use super::*;

    #[test]
    fn actual_shell_queues_exact_program_and_preserves_pending_request() {
        let mut shell = Shell::default();
        let mut output = String::new();
        shell.command("posix exec cosmic-notifications", &mut output).unwrap();
        assert_eq!(shell.take_user_request(), Some(UserRequest::Execute("cosmic-notifications")),
                   "notification command did not reach the supervisor request");
        shell.command("posix exec cosmic-comp", &mut output).unwrap();
        shell.command("posix exec cosmic-notifications", &mut output).unwrap();
        assert_eq!(shell.take_user_request(), Some(UserRequest::Execute("cosmic-comp")));
        assert!(output.contains("error: user request busy"));
        for command in ["posix exec cosmic-notifications --version", "posix exec /bin/cosmic-notifications",
                        "posix exec cosmic-notifications;", "posix exec cosmic-notifications-unknown"] {
            assert!(matches!(shell.command(command, &mut output), Err(CommandError::Usage)));
            assert!(shell.take_user_request().is_none());
        }
    }

    #[test]
    fn actual_direct_input_has_desktop_connections_and_no_invented_panel_fd() {
        let fs = FileSystem::valid();
        let input = kernel::user::prepare("cosmic-notifications", &fs).unwrap();
        assert_eq!(input.argv, [b"/bin/cosmic-notifications".to_vec()]);
        assert_eq!(input.execfn, b"/bin/cosmic-notifications");
        for value in [b"XDG_RUNTIME_DIR=/run/user/0".as_slice(),
                      b"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus", b"WAYLAND_DISPLAY=wayland-1"] {
            assert!(input.has(value), "notification did not receive a real desktop connection environment");
        }
        assert!(!input.env.iter().any(|v| v.starts_with(b"DAEMON_NOTIFICATIONS_FD=") ||
                                         v.starts_with(b"PANEL_NOTIFICATIONS_FD=") || v.starts_with(b"WAYLAND_SOCKET=")));
        assert_eq!(fs.queries.get(), 1, "notification launch skipped runtime validation");
    }

    #[test]
    fn actual_runtime_guard_rejects_missing_wrong_type_or_public_directory() {
        for (entry, error) in [(None, Errno::Noent),
                              (Some(Entry { kind: Kind::File, mode: 0o700 }), Errno::Notdir),
                              (Some(Entry { kind: Kind::Directory, mode: 0o777 }), Errno::Access)] {
            let fs = FileSystem { entry, queries: Cell::new(0) };
            assert_eq!(kernel::user::prepare("cosmic-notifications", &fs), Err(error),
                       "notification bypassed the runtime directory guard");
            assert_eq!(fs.queries.get(), 1);
        }
    }

    #[test]
    fn existing_compositor_settings_and_probe_roles_keep_their_environments() {
        let fs = FileSystem::valid();
        let settings = kernel::user::prepare("cosmic-settings-daemon", &fs).unwrap();
        assert!(settings.has(b"WAYLAND_DISPLAY=wayland-1"));
        let compositor = kernel::user::prepare("cosmic-comp", &fs).unwrap();
        assert_eq!(compositor.argv, [b"/bin/cosmic-comp".to_vec(), b"--no-xwayland".to_vec()]);
        assert!(compositor.has(b"XDG_RUNTIME_DIR=/run/user/0"));
        assert!(!compositor.env.iter().any(|v| v.starts_with(b"WAYLAND_DISPLAY=")));
        let invalid = FileSystem { entry: None, queries: Cell::new(0) };
        let probe = kernel::user::prepare("probe", &invalid).unwrap();
        assert!(probe.has(b"LANG=C") && probe.has(b"DISPLAY=:0"));
        assert_eq!(invalid.queries.get(), 0);
    }

    fn request(argv: &[Vec<u8>], env: &[Vec<u8>]) -> kernel::user::spawn::Request {
        let mut request = kernel::user::spawn::Request { bytes: [0; 4096], args: [[0; 2]; 32],
            env: [[0; 2]; 32], argc: argv.len(), envc: env.len() };
        let mut used = 0;
        for (source, slots) in [(argv, &mut request.args), (env, &mut request.env)] {
            for (value, span) in source.iter().zip(slots) {
                request.bytes[used..used + value.len()].copy_from_slice(value);
                *span = [used as u16, value.len() as u16];
                used += value.len() + 1;
            }
        }
        request
    }

    #[test]
    fn actual_shared_spawn_input_preserves_session_environment_and_optional_fds() {
        let direct = kernel::user::prepare("cosmic-notifications", &FileSystem::valid()).unwrap();
        assert_eq!(kernel::user::spawn::prepare(&request(&direct.argv, &direct.env),
                                               "/bin/cosmic-notifications"), direct,
                   "shared spawn lost the notification launch inputs");
        let env = [b"XDG_RUNTIME_DIR=/run/user/0".to_vec(), b"WAYLAND_DISPLAY=wayland-7".to_vec(),
                   b"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus".to_vec(),
                   b"DAEMON_NOTIFICATIONS_FD=11".to_vec()];
        let inherited = kernel::user::spawn::prepare(&request(&direct.argv, &env), "/bin/cosmic-notifications");
        assert_eq!(inherited.env, env, "shared spawn overwrote the real session handoff");
    }

    #[test]
    fn actual_full_os_model_counts_stack_once_and_still_rejects_unsafe_budget() {
        let layout = user_layout::ImageProfile::FullOsV3.layout();
        // The preserved 29,604,216-byte linked notification ELF has 5893 LOAD
        // pages; this is a known workload witness, not an assumed future size.
        let requested = counted_image_pages(5893).unwrap();
        assert_eq!(requested, 6405);
        assert_eq!(layout.exec_pool_pages - requested, 9979);
        assert_eq!(full_os_executable_memory_policy(layout.exec_pool_pages as u32, requested as u32),
                   Ok((true, 8197)));
        assert_eq!(full_os_executable_memory_policy(0, requested as u32), Ok((false, 8197)));
        assert_eq!(full_os_executable_memory_policy(16384, 16384), Ok((false, 8197)));
        assert_eq!(full_os_executable_memory_policy(16384, 16385), Err(Error::Invalid));
        assert_eq!(counted_image_pages(16384), Err(Errno::Inval));
    }
}
'''


class NotificationLaunch(unittest.TestCase):
    def test_actual_command_environment_guard_spawn_and_model(self):
        program, pieces = production_program()
        # These controls must compile and fail a behavioral assertion. They
        # distinguish missing command, environment, guard and spawn forwarding.
        controls = [
            (program.replace(pieces["POSIX_ARM"], pieces["POSIX_ARM"].replace(
                '                        "cosmic-notifications" => "cosmic-notifications",\n', "", 1)),
             "actual_shell_queues", "actual_shell_queues_exact_program"),
            (program.replace(pieces["DIRECT_INPUT"], pieces["DIRECT_INPUT"].replace(
                ' | "cosmic-notifications"', "", 1)),
             "actual_direct_input", "notification did not receive a real desktop connection environment"),
            (program.replace(pieces["RUNTIME_GUARD"], pieces["RUNTIME_GUARD"].replace(
                ' | "cosmic-notifications"', "", 1)),
             "actual_runtime_guard", "notification bypassed the runtime directory guard"),
            (program.replace(pieces["SPAWN_INPUT"], pieces["SPAWN_INPUT"].replace(
                "envp: &env[..request.envc]", "envp: &[]", 1)),
             "actual_shared_spawn", "shared spawn lost the notification launch inputs"),
        ]
        with tempfile.TemporaryDirectory(prefix="cyxia-notification-launch-") as temporary, native_lease(LOCK):
            idle_native_host()
            source = Path(temporary) / "launch.rs"
            binary = Path(temporary) / "launch-tests"
            for text, selection, expected_error in controls + [(program, "notification_launch::", None)]:
                if expected_error:
                    self.assertNotEqual(text, program)
                source.write_text(text)
                compiled = subprocess.run([str(RUST_BIN / "rustc"), "--edition=2024", "--test",
                                           str(source), "-o", str(binary)], cwd=ROOT, env=env(),
                                          capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
                ran = subprocess.run([str(binary), selection, "--test-threads=1"],
                                     cwd=ROOT, capture_output=True, text=True, timeout=30)
                output = ran.stdout + ran.stderr
                if expected_error:
                    self.assertNotEqual(ran.returncode, 0, output)
                    self.assertIn(expected_error, output)
                else:
                    self.assertEqual(ran.returncode, 0, output)
                    self.assertIn("6 passed; 0 failed", output)


if __name__ == "__main__":
    unittest.main()
