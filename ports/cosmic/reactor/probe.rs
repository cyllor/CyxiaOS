//! Genuine, unmodified Mio on CyxiaOS's static AArch64 musl ABI.
use mio::{Events, Interest, Poll, Token, Waker, net::UnixStream, unix::SourceFd};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn check(value: bool, name: &str) -> io::Result<()> {
    if !value {
        return Err(io::Error::other(format!("check failed: {name}")));
    }
    println!("RUST_REACTOR CHECK name={name} result=PASS");
    Ok(())
}

fn quiet(poll: &mut Poll, events: &mut Events) -> io::Result<bool> {
    poll.poll(events, Some(Duration::ZERO))?;
    Ok(events.is_empty())
}

fn readable(poll: &mut Poll, events: &mut Events, token: Token) -> io::Result<bool> {
    poll.poll(events, Some(Duration::from_secs(2)))?;
    Ok(events.iter().count() == 1
        && events
            .iter()
            .all(|event| event.token() == token && event.is_readable()))
}

fn drain(stream: &mut impl Read, expected: &[u8]) -> io::Result<bool> {
    let mut bytes = [0u8; 32];
    let mut received = Vec::new();
    loop {
        match stream.read(&mut bytes) {
            Ok(0) => return Ok(false),
            Ok(count) => {
                received.extend_from_slice(&bytes[..count]);
                if received.len() > expected.len() {
                    return Ok(false);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(received == expected)
}

fn wakers(poll: &mut Poll, events: &mut Events) -> io::Result<()> {
    let waker = Arc::new(Waker::new(poll.registry(), Token(10))?);
    // Mio's Linux Waker does not drain eventfd between these calls.
    for cycle in 1..=3 {
        waker.wake()?;
        check(
            readable(poll, events, Token(10))? && quiet(poll, events)?,
            &format!("waker-cycle-{cycle}"),
        )?;
    }
    waker.wake()?;
    waker.wake()?;
    waker.wake()?;
    check(
        readable(poll, events, Token(10))? && quiet(poll, events)?,
        "waker-coalesces",
    )?;
    let other = Arc::clone(&waker);
    let thread = std::thread::Builder::new()
        .name("reactor-wake".into())
        .spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            other.wake()
        })?;
    let observed = readable(poll, events, Token(10))?;
    thread
        .join()
        .map_err(|_| io::Error::other("waker thread panicked"))??;
    check(observed && quiet(poll, events)?, "waker-thread")
}

fn sockets(poll: &mut Poll, events: &mut Events) -> io::Result<()> {
    let (mut reader, mut writer) = UnixStream::pair()?;
    poll.registry()
        .register(&mut reader, Token(20), Interest::READABLE)?;
    writer.write_all(b"ab")?;
    check(readable(poll, events, Token(20))?, "socket-first-edge")?;
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    check(
        first == *b"a" && quiet(poll, events)?,
        "socket-unread-quiet",
    )?;
    writer.write_all(b"c")?;
    check(
        readable(poll, events, Token(20))?,
        "socket-write-while-readable",
    )?;
    check(
        drain(&mut reader, b"bc")? && quiet(poll, events)?,
        "socket-drain",
    )?;
    writer.write_all(b"de")?;
    check(
        readable(poll, events, Token(20))? && drain(&mut reader, b"de")?,
        "socket-rearm-after-drain",
    )?;
    writer.write_all(b"f")?;
    poll.registry()
        .reregister(&mut reader, Token(21), Interest::READABLE)?;
    check(
        readable(poll, events, Token(21))? && drain(&mut reader, b"f")?,
        "socket-reregister-token",
    )?;
    poll.registry().deregister(&mut reader)?;
    writer.write_all(b"gh")?;
    check(quiet(poll, events)?, "socket-deregister")?;
    poll.registry()
        .register(&mut reader, Token(22), Interest::READABLE)?;
    check(
        readable(poll, events, Token(22))? && drain(&mut reader, b"gh")?,
        "socket-register-again",
    )?;
    drop(writer);
    let ready = readable(poll, events, Token(22))?;
    let closed = events.iter().all(|event| event.is_read_closed());
    check(
        ready && closed && reader.read(&mut first)? == 0,
        "socket-peer-close",
    )?;
    poll.registry().deregister(&mut reader)?;
    Ok(())
}

fn arm(timer: &File, duration: Duration) -> io::Result<()> {
    let value = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: duration.as_secs().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "timer duration exceeds time_t")
            })?,
            tv_nsec: duration.subsec_nanos().into(),
        },
    };
    // SAFETY: timer owns a live timerfd; value is initialized and readable.
    let result =
        unsafe { libc::timerfd_settime(timer.as_raw_fd(), 0, &value, std::ptr::null_mut()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn timers(poll: &mut Poll, events: &mut Events) -> io::Result<()> {
    // SAFETY: only constant flags are passed. Successful ownership is
    // transferred exactly once to File, which closes the descriptor.
    let fd = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful timerfd_create returned a new owned descriptor.
    let mut timer = unsafe { File::from_raw_fd(fd) };
    poll.registry()
        .register(&mut SourceFd(&fd), Token(30), Interest::READABLE)?;
    check(quiet(poll, events)?, "timer-create")?;
    let mut value = [0u8; 8];
    for (cycle, name) in [(1, "timer-first-expiration"), (2, "timer-rearm")] {
        let start = Instant::now();
        arm(&timer, Duration::from_millis(20))?;
        let ready = readable(poll, events, Token(30))?;
        let elapsed = start.elapsed();
        timer.read_exact(&mut value)?;
        check(
            ready
                && u64::from_ne_bytes(value) == 1
                && elapsed >= Duration::from_millis(20)
                && elapsed < Duration::from_secs(2)
                && quiet(poll, events)?,
            name,
        )?;
        println!(
            "RUST_REACTOR TIMER cycle={cycle} expirations=1 elapsed_ns={}",
            elapsed.as_nanos()
        );
    }
    arm(&timer, Duration::from_secs(1))?;
    arm(&timer, Duration::ZERO)?;
    let blocked =
        matches!(timer.read(&mut value), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    check(blocked && quiet(poll, events)?, "timer-cancel")?;
    poll.registry().deregister(&mut SourceFd(&fd))?;
    Ok(())
}

fn run() -> io::Result<()> {
    println!("RUST_REACTOR START mio=1.1.1 static=1");
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(8);
    check(true, "poll-create")?;
    let start = Instant::now();
    poll.poll(&mut events, Some(Duration::from_millis(20)))?;
    check(
        events.is_empty() && start.elapsed() >= Duration::from_millis(20),
        "empty-timeout",
    )?;
    wakers(&mut poll, &mut events)?;
    sockets(&mut poll, &mut events)?;
    timers(&mut poll, &mut events)?;
    check(quiet(&mut poll, &mut events)?, "cleanup")?;
    drop(events);
    drop(poll);
    println!("RUST_REACTOR PASS mio=1.1.1 cycles=3 cosmic_runtime=0");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("RUST_REACTOR FAIL {error}");
        std::process::exit(1);
    }
}
