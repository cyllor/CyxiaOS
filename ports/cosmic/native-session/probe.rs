//! Guest regression through the actual patched launch-pad public API.
//! Compile against the patched session's exact rlibs. Register this real ELF in
//! the native catalog; invoke `session-process-probe /bin/session-process-probe` in the guest.
use launch_pad::{ProcessKey, ProcessManager, RestartMode, native_child::NativeChild, process::Process};
use std::{
    borrow::Cow,
    collections::HashSet,
    io::{Read, Write},
    os::{fd::{AsRawFd, OwnedFd}, unix::{net::UnixStream, process::ExitStatusExt}},
    time::Duration,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::mpsc};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static GRACE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

extern "C" fn grace_term(_signal: libc::c_int) {
    let delay = libc::timespec { tv_sec: 0, tv_nsec: 35_000_000 };
    // Use only async-signal-safe operations; no SA_RESTART or synthetic exit.
    unsafe {
        if libc::nanosleep(&delay, std::ptr::null_mut()) != 0 { libc::_exit(66); }
        let fd = GRACE_FD.load(std::sync::atomic::Ordering::Relaxed);
        if libc::write(fd, b"X".as_ptr().cast(), 1) != 1 { libc::_exit(67); }
        libc::_exit(23);
    }
}

fn check(ok: bool, name: &str) -> Result<()> {
    if !ok { return Err(format!("check failed: {name}").into()); }
    println!("SESSION_PROCESS CHECK name={name} result=PASS");
    Ok(())
}

fn flag(fd: i32, command: i32) -> i32 { unsafe { libc::fcntl(fd, command) } }

fn descriptors() -> usize {
    (0..64).filter(|&fd| flag(fd, libc::F_GETFD) >= 0).count()
}

fn child(mode: &str, args: &[String]) -> Result<i32> {
    match mode {
        "echo" => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            println!("OUT:{}", line.trim_end());
            eprintln!("ERR:{}", line.trim_end());
            // Let the manager consume both callback lines before the exit event.
            std::thread::sleep(Duration::from_millis(40));
            Ok(0)
        }
        "bytes" => {
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)?;
            std::io::stdout().write_all(&bytes)?;
            std::io::stdout().flush()?;
            eprintln!("BYTES:{}", bytes.len());
            Ok(0)
        }
        "exit" => Ok(args.first().ok_or("missing exit code")?.parse()?),
        "sleep" => {
            std::thread::sleep(Duration::from_millis(120));
            Ok(5)
        }
        "socket" => {
            let fd: i32 = std::env::var("PROBE_FD")?.parse()?;
            if flag(fd, libc::F_GETFD) != 0 || unsafe { libc::write(fd, b"S".as_ptr().cast(), 1) } != 1 {
                return Ok(65);
            }
            println!("SOCKET");
            std::thread::sleep(Duration::from_millis(40));
            Ok(7)
        }
        "ignore-term" => {
            // No SA_RESTART requirement: signal disposition is genuinely ignored.
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN); }
            println!("READY");
            std::io::stdout().flush()?;
            loop { std::thread::sleep(Duration::from_millis(100)); }
        }
        "grace-term" => {
            let fd = std::env::var("PROBE_GRACE_FD")?.parse()?;
            GRACE_FD.store(fd, std::sync::atomic::Ordering::Relaxed);
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = grace_term as *const () as usize;
            action.sa_flags = 0;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                || unsafe { libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) } != 0
            { return Err(std::io::Error::last_os_error().into()); }
            println!("READY");
            std::io::stdout().flush()?;
            loop { std::thread::sleep(Duration::from_millis(100)); }
        }
        "default-term" => {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = libc::SIG_DFL;
            action.sa_flags = 0;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                || unsafe { libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) } != 0
            { return Err(std::io::Error::last_os_error().into()); }
            println!("READY");
            std::io::stdout().flush()?;
            loop { std::thread::sleep(Duration::from_millis(100)); }
        }
        "inspect" => {
            let env_fd = |name: &str| -> Result<i32> { Ok(std::env::var(name)?.parse()?) };
            let ambient = env_fd("PROBE_AMBIENT_FD")?;
            let forced = env_fd("PROBE_FORCED_FD")?;
            let excluded = env_fd("PROBE_EXCLUDED_FD")?;
            if flag(ambient, libc::F_GETFD) != 0 || flag(forced, libc::F_GETFD) != 0
                || flag(excluded, libc::F_GETFD) >= 0
                || flag(ambient, libc::F_GETFL) & libc::O_NONBLOCK != 0
                || flag(forced, libc::F_GETFL) & libc::O_NONBLOCK == 0
                || (0..3).any(|fd| flag(fd, libc::F_GETFL) < 0 || flag(fd, libc::F_GETFL) & libc::O_NONBLOCK != 0)
                || std::env::var("PROBE_INHERITED")? != "ambient"
                || std::env::var("PROBE_OVERRIDE")? != "child"
                || std::env::args().next().as_deref() != Some(std::env::var("PROBE_ARGV0")?.as_str())
                || std::env::current_dir()?.as_os_str() != std::ffi::OsStr::new(&std::env::var("PROBE_CWD")?)
                || args != ["argument with spaces", "final"]
            { return Ok(61); }
            if unsafe { libc::write(ambient, b"A".as_ptr().cast(), 1) } != 1
                || unsafe { libc::write(forced, b"F".as_ptr().cast(), 1) } != 1
            { return Ok(62); }
            Ok(0)
        }
        _ => Err(format!("unknown child mode: {mode}").into()),
    }
}

fn child_args(mode: &str) -> Vec<String> { vec!["--child".into(), mode.into()] }

async fn direct_io(executable: &str) -> Result<()> {
    let baseline = descriptors();
    let mut child = NativeChild::spawn(executable, &child_args("bytes"), &[], &[])?;
    let mut stdin = child.stdin.take().ok_or("missing stdin")?;
    let mut stdout = child.stdout.take().ok_or("missing stdout")?;
    let mut stderr = child.stderr.take().ok_or("missing stderr")?;
    let bytes: Vec<u8> = (0..12000).map(|i| (i % 251) as u8).collect();
    stdin.write_all(&bytes).await?;
    stdin.shutdown().await?;
    let mut out = Vec::new();
    let mut err = String::new();
    let (read_out, read_err, status) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_string(&mut err), child.wait());
    read_out?;
    read_err?;
    check(status?.success() && out == bytes && err == "BYTES:12000\n", "real-stdio-partial-io-and-eof")?;
    check(child.id().is_none() && child.wait().await?.success(), "repeated-wait-caches-real-status")?;
    drop((stdin, stdout, stderr, child));
    check(descriptors() == baseline, "stdio-descriptors-reclaimed")
}

async fn inheritance(executable: &str) -> Result<()> {
    let (mut ambient_parent, ambient_child) = UnixStream::pair()?;
    let (mut forced_parent, forced_child) = UnixStream::pair()?;
    forced_child.set_nonblocking(true)?;
    let ambient: OwnedFd = ambient_child.into();
    let forced: OwnedFd = forced_child.into();
    let (excluded, _excluded_peer) = UnixStream::pair()?;
    let ambient_number = ambient.as_raw_fd();
    let forced_number = forced.as_raw_fd();
    if unsafe { libc::fcntl(ambient_number, libc::F_SETFD, 0) } < 0 { return Err(std::io::Error::last_os_error().into()); }
    let ambient_flags = flag(ambient_number, libc::F_GETFD);
    let forced_flags = flag(forced_number, libc::F_GETFD);
    let old_cwd = std::env::current_dir()?;
    std::fs::create_dir_all("/tmp/session-probe")?;
    std::env::set_current_dir("/tmp/session-probe")?;
    let mut args = child_args("inspect");
    args.extend(["argument with spaces".into(), "final".into()]);
    let name = std::path::Path::new(executable).file_name().ok_or("no executable name")?.to_str().ok_or("non-utf8 executable")?;
    let env = vec![
        ("PROBE_AMBIENT_FD".into(), ambient_number.to_string()),
        ("PROBE_FORCED_FD".into(), forced_number.to_string()),
        ("PROBE_EXCLUDED_FD".into(), excluded.as_raw_fd().to_string()),
        ("PROBE_CWD".into(), "/tmp/session-probe".into()),
        ("PROBE_OVERRIDE".into(), "first".into()),
        ("PROBE_OVERRIDE".into(), "child".into()),
        ("PROBE_ARGV0".into(), name.into()),
        ("PATH".into(), format!("/missing:{}", std::path::Path::new(executable).parent().ok_or("no executable parent")?.display())),
    ];
    let spawned = NativeChild::spawn(name, &args, &env, &[forced_number]);
    std::env::set_current_dir(old_cwd)?;
    let mut child = spawned?;
    check(flag(ambient_number, libc::F_GETFD) == ambient_flags && flag(forced_number, libc::F_GETFD) == forced_flags,
          "parent-cloexec-flags-unchanged")?;
    let status = child.wait().await?;
    check(status.success(), "ambient-and-forced-fds-env-path-argv-cwd")?;
    let mut a = [0];
    let mut f = [0];
    ambient_parent.read_exact(&mut a)?;
    forced_parent.read_exact(&mut f)?;
    check(a == *b"A" && f == *b"F", "inherited-sockets-connect-real-peers")
}

async fn failures_and_lifecycle(executable: &str) -> Result<()> {
    let baseline = descriptors();
    check(NativeChild::spawn(executable, &vec!["x".into(); 32], &[], &[]).err().is_some_and(|e| e.raw_os_error() == Some(libc::E2BIG)), "argv-count-rejected")?;
    check(NativeChild::spawn(executable, &["x".repeat(4096)], &[], &[]).err().is_some_and(|e| e.raw_os_error() == Some(libc::E2BIG)), "aggregate-bytes-rejected")?;
    let env = (0..33).map(|i| (format!("BOUND_{i}"), "v".into())).collect::<Vec<_>>();
    check(NativeChild::spawn(executable, &[], &env, &[]).err().is_some_and(|e| e.raw_os_error() == Some(libc::E2BIG)), "environment-count-rejected")?;
    check(NativeChild::spawn(executable, &["bad\0arg".into()], &[], &[]).is_err(), "nul-argument-rejected")?;
    check(NativeChild::spawn(executable, &[], &[], &[0]).is_err(), "stdio-explicit-fd-conflict-rejected")?;
    check(NativeChild::spawn(executable, &[], &[], &[64]).is_err(), "out-of-range-explicit-fd-rejected")?;
    for _ in 0..4 {
        check(NativeChild::spawn("/missing/session-child", &[], &[], &[]).err().is_some_and(|e| e.raw_os_error() == Some(libc::ENOENT)), "missing-image-real-error")?;
    }
    check(descriptors() == baseline, "spawn-failures-release-pipes")?;
    let mut child = NativeChild::spawn(executable, &child_args("sleep"), &[], &[])?;
    check(tokio::time::timeout(Duration::from_millis(20), child.wait()).await.is_err(), "wait-cancellation-does-not-reap")?;
    check(child.id().is_some() && child.wait().await?.code() == Some(5), "cancelled-wait-resumes-real-receipt")?;
    drop(child);
    let mut child = NativeChild::spawn(executable, &child_args("ignore-term"), &[], &[])?;
    child.kill().await?;
    check(child.wait().await?.signal() == Some(libc::SIGKILL), "kill-retains-real-signal-status")?;
    drop(child);
    let child = NativeChild::spawn(executable, &child_args("sleep"), &[], &[])?;
    let pid = child.id().ok_or("drop child missing pid")? as i32;
    drop(child);
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    check(waited == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD), "drop-kills-and-reaps-real-child")?;
    check(descriptors() == baseline, "lifecycle-descriptors-reclaimed")
}

async fn path_boundaries(executable: &str) -> Result<()> {
    let name = std::path::Path::new(executable).file_name().ok_or("no executable name")?.to_str().ok_or("non-utf8 executable")?;
    let oversized = format!("/{}", "p".repeat(100));
    let mut args = child_args("exit");
    args.push("0".into());
    let mut passed = true;
    for (path, label) in [
        (format!("/bin:{oversized}"), "path-valid-before-oversized-component"),
        (format!("{oversized}:/bin"), "path-valid-after-oversized-component"),
    ] {
        match NativeChild::spawn(name, &args, &[("PATH".into(), path)], &[]) {
            Ok(mut child) => {
                let status = child.wait().await?;
                if status.code() == Some(0) {
                    check(true, label)?;
                } else {
                    eprintln!("SESSION_PROCESS CHECK name={label} result=FAIL status={status}");
                    passed = false;
                }
            }
            Err(error) => {
                eprintln!("SESSION_PROCESS CHECK name={label} result=FAIL error={error}");
                passed = false;
            }
        }
    }
    let absolute_error = NativeChild::spawn(&oversized, &args, &[], &[]).err();
    check(absolute_error.is_some_and(|error| error.raw_os_error() == Some(libc::ENAMETOOLONG)),
          "oversized-absolute-executable-rejected")?;
    check(passed, "path-component-bounds-preserve-search-order")
}

async fn stdio_collision(executable: &str) -> Result<()> {
    let saved0 = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    let saved1 = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
    if saved0 < 0 || saved1 < 0 { return Err("cannot preserve stdio for collision test".into()); }
    let flags0 = flag(0, libc::F_GETFD);
    let flags1 = flag(1, libc::F_GETFD);
    unsafe { libc::close(0); libc::close(1); }
    let tested = async {
        let mut args = child_args("exit");
        args.push("0".into());
        let mut child = NativeChild::spawn(executable, &args, &[], &[])?;
        let status = child.wait().await?;
        drop(child);
        Ok::<bool, Box<dyn std::error::Error>>(status.success())
    }.await;
    let restored0 = unsafe { libc::dup2(saved0, 0) };
    let restored1 = unsafe { libc::dup2(saved1, 1) };
    unsafe {
        libc::fcntl(0, libc::F_SETFD, flags0);
        libc::fcntl(1, libc::F_SETFD, flags1);
        libc::close(saved0);
        libc::close(saved1);
    }
    check(restored0 == 0 && restored1 == 1 && tested?, "closed-parent-stdio-source-target-collisions")
}

#[derive(Debug)]
enum Event { Start(bool, u32), Out(String), Err(String), Exit(Option<i32>, bool) }

fn managed(executable: &str, args: Vec<String>) -> (Process, mpsc::UnboundedReceiver<Event>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let start = tx.clone();
    let out = tx.clone();
    let err = tx.clone();
    let process = Process::new().with_executable(executable).with_args(args)
        .with_on_start(move |manager, key, restarted| {
            let tx = start.clone();
            async move { tx.send(Event::Start(restarted, manager.get_pid(key).await.unwrap().unwrap())).unwrap(); }
        })
        .with_on_stdout(move |_, _, line| { let tx = out.clone(); async move { tx.send(Event::Out(line)).unwrap(); } })
        .with_on_stderr(move |_, _, line| { let tx = err.clone(); async move { tx.send(Event::Err(line)).unwrap(); } })
        .with_on_exit(move |_, _, code, restarting| { let tx = tx.clone(); async move { tx.send(Event::Exit(code, restarting)).unwrap(); } });
    (process, rx)
}

async fn event(rx: &mut mpsc::UnboundedReceiver<Event>) -> Result<Event> {
    Ok(tokio::time::timeout(Duration::from_secs(10), rx.recv()).await?.ok_or("callback channel closed")?)
}

async fn manager_io(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    manager.set_max_restarts(0).await;
    let (process, mut rx) = managed(executable, child_args("echo"));
    let key = manager.start(process).await?;
    let pid = manager.get_pid(key).await?.ok_or("manager missing pid")?;
    manager.send_message(key, Cow::Borrowed(b"manager-message\n")).await?;
    let (mut starts, mut stdout, mut stderr, mut exits) = (0, 0, 0, 0);
    for _ in 0..4 {
        match event(&mut rx).await? {
            Event::Start(false, actual) if actual == pid => starts += 1,
            Event::Out(line) if line == "OUT:manager-message" => stdout += 1,
            Event::Err(line) if line == "ERR:manager-message" => stderr += 1,
            Event::Exit(Some(0), false) => exits += 1,
            other => return Err(format!("unexpected manager event: {other:?}").into()),
        }
    }
    check((starts, stdout, stderr, exits) == (1, 1, 1, 1), "actual-manager-stdin-and-all-callbacks")?;
    manager.stop();
    Ok(())
}

async fn manager_restart(executable: &str, mode: RestartMode, name: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    manager.set_max_restarts(2).await;
    manager.set_restart_mode(mode).await;
    let mut args = child_args("exit");
    args.push("7".into());
    let (process, mut rx) = managed(executable, args);
    manager.start(process).await?;
    let mut pids = HashSet::new();
    let mut starts = Vec::new();
    let mut exits = Vec::new();
    while starts.len() < 3 || exits.len() < 3 {
        match event(&mut rx).await? {
            Event::Start(restarted, pid) => { starts.push(restarted); pids.insert(pid); }
            Event::Exit(Some(7), restarting) => exits.push(restarting),
            other => return Err(format!("unexpected restart event: {other:?}").into()),
        }
    }
    check(starts == [false, true, true] && exits == [true, true, false] && pids.len() == 3, name)?;
    manager.stop();
    Ok(())
}

async fn manager_cancel(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    let (process, mut rx) = managed(executable, child_args("ignore-term"));
    let key = manager.start(process.with_cancel_timeout(Duration::from_millis(25))).await?;
    let mut started = false;
    loop {
        match event(&mut rx).await? {
            Event::Start(false, _) => started = true,
            Event::Out(line) if line == "READY" => break,
            other => return Err(format!("unexpected cancellation startup: {other:?}").into()),
        }
    }
    manager.stop_process(key).await?;
    check(started && matches!(event(&mut rx).await?, Event::Exit(Some(137), false)), "manager-term-timeout-kill-callback")?;
    manager.stop();
    Ok(())
}

async fn manager_grace_status(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    let (mut observed, inherited) = UnixStream::pair()?;
    observed.set_nonblocking(true)?;
    let inherited: OwnedFd = inherited.into();
    let fd = inherited.as_raw_fd();
    let (process, mut rx) = managed(executable, child_args("grace-term"));
    let key = manager.start(process
        .with_env([("PROBE_GRACE_FD", fd.to_string())])
        .with_fds(move || vec![inherited])
        .with_cancel_timeout(Duration::from_millis(50))).await?;
    let mut pid = None;
    loop {
        match event(&mut rx).await? {
            Event::Start(false, actual) => pid = Some(actual),
            Event::Out(line) if line == "READY" => break,
            other => return Err(format!("unexpected grace startup: {other:?}").into()),
        }
    }
    let pid = pid.ok_or("missing grace child start callback")?;
    println!("SESSION_PROCESS grace_child_pid={pid} handler_delay_ms=35 cancel_timeout_ms=50");
    manager.stop_process(key).await?;
    let ended = event(&mut rx).await?;
    let mut byte = [0];
    let handler_completed = observed.read(&mut byte).ok() == Some(1) && byte == *b"X";
    println!("SESSION_PROCESS grace_child_pid={pid} handler_completed={handler_completed} callback={ended:?}");
    manager.stop();
    check(handler_completed && matches!(ended, Event::Exit(Some(23), false)),
          "manager-grace-timeout-race-preserves-real-exit-status")
}

async fn manager_signal_status(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    let (process, mut rx) = managed(executable, child_args("default-term"));
    let key = manager.start(process.with_cancel_timeout(Duration::from_millis(50))).await?;
    let mut pid = None;
    loop {
        match event(&mut rx).await? {
            Event::Start(false, actual) => pid = Some(actual),
            Event::Out(line) if line == "READY" => break,
            other => return Err(format!("unexpected default-TERM startup: {other:?}").into()),
        }
    }
    let pid = pid.ok_or("missing default-TERM child start callback")?;
    println!("SESSION_PROCESS default_term_child_pid={pid} expected_signal=15 cancel_timeout_ms=50");
    manager.stop_process(key).await?;
    let ended = event(&mut rx).await?;
    println!("SESSION_PROCESS default_term_child_pid={pid} callback={ended:?}");
    manager.stop();
    check(matches!(ended, Event::Exit(Some(143), false)),
          "manager-default-term-preserves-real-signal-status")
}

async fn manager_fd_refresh(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    manager.set_max_restarts(1).await;
    let (parent, child) = UnixStream::pair()?;
    let child: OwnedFd = child.into();
    let fd = child.as_raw_fd();
    let peers = std::sync::Arc::new(std::sync::Mutex::new(vec![parent]));
    let (tx, mut rx) = mpsc::unbounded_channel();
    let started = tx.clone();
    let output = tx.clone();
    let changed_peers = peers.clone();
    let process = Process::new().with_executable(executable).with_args(child_args("socket"))
        .with_env([("PROBE_FD", fd.to_string())])
        .with_fds(move || vec![child])
        .with_on_start(move |manager, key, restart| {
            let tx = started.clone();
            async move { tx.send(Event::Start(restart, manager.get_pid(key).await.unwrap().unwrap())).unwrap(); }
        })
        .with_on_stdout(move |_, _, line| { let tx = output.clone(); async move { tx.send(Event::Out(line)).unwrap(); } })
        .with_on_exit(move |mut manager, key, code, restarting| {
            let tx = tx.clone();
            let peers = changed_peers.clone();
            async move {
                if restarting {
                    let (parent, child) = UnixStream::pair().unwrap();
                    let child: OwnedFd = child.into();
                    let fd = child.as_raw_fd();
                    peers.lock().unwrap().push(parent);
                    manager.update_process_env(&key, [("PROBE_FD", fd.to_string())]).await.unwrap();
                    manager.update_process_fds(&key, move || vec![child]).await.unwrap();
                }
                tx.send(Event::Exit(code, restarting)).unwrap();
            }
        });
    manager.start(process).await?;
    let (mut starts, mut lines, mut exits) = (Vec::new(), 0, Vec::new());
    for _ in 0..6 {
        match event(&mut rx).await? {
            Event::Start(restart, _) => starts.push(restart),
            Event::Out(line) if line == "SOCKET" => lines += 1,
            Event::Exit(Some(7), restart) => exits.push(restart),
            other => return Err(format!("unexpected descriptor refresh event: {other:?}").into()),
        }
    }
    let mut connected = 0;
    for peer in peers.lock().unwrap().iter_mut() {
        let mut byte = [0];
        peer.read_exact(&mut byte)?;
        if byte == *b"S" { connected += 1; }
    }
    check(starts == [false, true] && exits == [true, false] && lines == 2 && connected == 2,
          "manager-with-fds-and-restart-fd-env-refresh")?;
    manager.stop();
    Ok(())
}

async fn manager_failed_spawn(executable: &str) -> Result<()> {
    let manager = ProcessManager::new().await;
    manager.set_max_restarts(0).await;
    let baseline = descriptors();
    for _ in 0..4 {
        check(manager.start(Process::new().with_executable("/missing/manager-child")).await.is_err(), "manager-spawn-error-propagates")?;
    }
    check(descriptors() == baseline, "manager-failed-spawn-releases-descriptors")?;
    let mut args = child_args("exit");
    args.push("0".into());
    let (process, mut rx) = managed(executable, args);
    let _: ProcessKey = manager.start(process).await?;
    let mut start = false;
    let mut exit = false;
    for _ in 0..2 {
        match event(&mut rx).await? {
            Event::Start(false, _) => start = true,
            Event::Exit(Some(0), false) => exit = true,
            other => return Err(format!("unexpected post-failure event: {other:?}").into()),
        }
    }
    check(start && exit, "manager-remains-usable-after-spawn-failure")?;
    manager.stop();
    Ok(())
}

async fn parent(executable: &str) -> Result<()> {
    manager_signal_status(executable).await?;
    manager_grace_status(executable).await?;
    direct_io(executable).await?;
    inheritance(executable).await?;
    path_boundaries(executable).await?;
    failures_and_lifecycle(executable).await?;
    stdio_collision(executable).await?;
    manager_io(executable).await?;
    manager_restart(executable, RestartMode::Delayed(Duration::from_millis(20)), "manager-delayed-restart-limit-pid-callbacks").await?;
    manager_restart(executable, RestartMode::ExponentialBackoff(Duration::from_millis(20)), "manager-backoff-restart-limit-pid-callbacks").await?;
    manager_cancel(executable).await?;
    manager_fd_refresh(executable).await?;
    manager_failed_spawn(executable).await?;
    println!("SESSION_PROCESS result=PASS scope=actual-launch-pad-native-child-and-manager");
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child") {
        match child(args.get(2).map(String::as_str).unwrap_or(""), &args[3..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => { eprintln!("SESSION_PROCESS child error: {error}"); std::process::exit(63); }
        }
    }
    let executable = args.get(1).map(String::as_str).unwrap_or("/bin/session-process-probe");
    // Single-threaded before the runtime and before any child can inspect env.
    unsafe {
        std::env::set_var("PROBE_INHERITED", "ambient");
        std::env::set_var("PROBE_OVERRIDE", "parent");
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    if let Err(error) = runtime.block_on(parent(executable)) {
        eprintln!("SESSION_PROCESS result=FAIL error={error}");
        std::process::exit(1);
    }
}
