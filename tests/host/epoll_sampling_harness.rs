#[cfg(test)]
use cyxia_ai_fs::{FileSystem, Path};
#[cfg(test)]
use cyxia_posix::{OPEN_MAX, inotify, timerfd};
use cyxia_posix::{Console, Errno, Process, epoll};
use std::sync::atomic::{AtomicU64, Ordering};

mod objects {
    use cyxia_posix::OpenDescriptions;

    std::thread_local! {
        static TABLE: &'static OpenDescriptions = Box::leak(Box::new(OpenDescriptions::new()));
    }

    pub(super) fn table() -> &'static OpenDescriptions {
        TABLE.with(|table| *table)
    }
}

mod unix {
    #[allow(unused_imports)]
    use cyxia_posix::{Errno, epoll, unix::{Handle, Ready, UnixSockets}};

    static mut SOCKETS: UnixSockets = UnixSockets::new();
    // UNIX_OPERATIONS
}

mod pipes {
    use cyxia_posix::{Errno, pipe::Pipes};

    static mut PIPES: Pipes = Pipes::new();
    // PIPE_OPERATIONS
}

mod pty {
    use cyxia_posix::{Errno, pty::Ptys};

    static mut PTYS: Ptys = Ptys::new();
    // PTY_OPERATIONS
}

static NOW_NS: AtomicU64 = AtomicU64::new(0);
static RAW_POLLS: AtomicU64 = AtomicU64::new(0);

fn now_ns() -> u64 { NOW_NS.load(Ordering::Relaxed) }

mod user {
    use cyxia_posix::{Errno, OPEN_MAX, Process, epoll};

    // POLL_SNAPSHOT

    pub(super) struct Runner {
        pub process: Process<'static>,
        pub records: [u8; 64],
        pub writable: bool,
        pub poll_snapshot: PollSnapshot,
    }
    impl Runner {
        // SOURCE_READINESS
        // POLL_METHODS

        fn thread_at(&self, slot: usize) -> &Self { assert_eq!(slot, 0); self }
        fn thread_at_mut(&mut self, slot: usize) -> &mut Self { assert_eq!(slot, 0); self }

        fn validate(&self, address: u64, size: usize, write: bool) -> Result<(), Errno> {
            if address != 0 || size > self.records.len() || (write && !self.writable) {
                return Err(Errno::Fault);
            }
            Ok(())
        }
        fn copy_from(&self, address: u64, bytes: &mut [u8]) -> Result<(), Errno> {
            self.validate(address, bytes.len(), false)?;
            bytes.copy_from_slice(&self.records[..bytes.len()]);
            Ok(())
        }
        fn copy_to(&mut self, address: u64, bytes: &[u8]) -> Result<(), Errno> {
            self.validate(address, bytes.len(), true)?;
            self.records[..bytes.len()].copy_from_slice(bytes);
            Ok(())
        }

        pub(super) fn sample(source: epoll::Source) -> Result<u32, Errno> {
            Self::source_readiness(source)
        }
    }
}

#[test]
fn parked_raw_poll_skips_idle_unwatched_socket_but_observes_changes() -> Result<(), Errno> {
    let owner = 21;
    let sockets = unix::with(|pool| pool.socketpair(owner))?;
    let mut process = Process::new(objects::table(), owner)?;
    let fd = process.install_socket(sockets[0].raw(), 0)?;
    let mut runner = user::Runner { process, records: [0; 64], writable: true, poll_snapshot: user::PollSnapshot::new() };
    runner.records[..4].copy_from_slice(&fd.to_le_bytes());
    runner.records[4] = epoll::IN as u8;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(0));
    RAW_POLLS.store(0, Ordering::Relaxed);
    for _ in 0..40 {
        unix::inspect(|pool| pool.poll(owner, sockets[0]))?;
        assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(0));
    }
    assert_eq!(RAW_POLLS.load(Ordering::Relaxed), 0);

    runner.records[6] = 255;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(0));
    assert_eq!(runner.records[6], 0);
    runner.writable = false;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Err(Errno::Fault));
    runner.writable = true;
    runner.records[4] = epoll::OUT as u8;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(1));
    assert_eq!(runner.records[6], epoll::OUT as u8);
    runner.records[4] = epoll::IN as u8;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(0));
    let before_timeout = RAW_POLLS.load(Ordering::Relaxed);
    assert_eq!(runner.poll_result(0, 1, None), Ok(0));
    assert_eq!(RAW_POLLS.load(Ordering::Relaxed), before_timeout + 1);

    unix::with(|pool| pool.write(owner, sockets[1], b"socket"))?;
    assert_eq!(runner.poll_result(0, 1, Some(0)), Ok(1));
    assert_eq!(runner.records[6], epoll::IN as u8);
    Ok(())
}

#[test]
fn raw_poll_retries_a_zero_sweep_that_published_epoll_readiness() -> Result<(), Errno> {
    let owner = 23;
    let mut process = Process::new(objects::table(), owner)?;
    let sockets = unix::with(|pool| pool.socketpair(owner))?;
    let socket = process.install_socket(sockets[0].raw(), 0)?;
    let ready = process.eventfd(1, 0)?;
    let epfd = process.epoll_create(0)?;
    process.epoll_ctl(epfd, 1, ready, epoll::Event { events: epoll::IN, data: 1 })?;
    let mut runner = user::Runner { process, records: [0; 64], writable: true, poll_snapshot: user::PollSnapshot::new() };
    for (i, (fd, events)) in [(socket, epoll::IN), (epfd, epoll::OUT)].into_iter().enumerate() {
        runner.records[8 * i..8 * i + 4].copy_from_slice(&fd.to_le_bytes());
        runner.records[8 * i + 4] = events as u8;
    }
    let before = runner.process.poll_readiness_epoch();
    RAW_POLLS.store(0, Ordering::Relaxed);
    assert_eq!(runner.poll_result(0, 2, Some(0)), Ok(0));
    assert_ne!(runner.process.poll_readiness_epoch(), before);
    assert_eq!(runner.poll_result(0, 2, Some(0)), Ok(0));
    assert_eq!(RAW_POLLS.load(Ordering::Relaxed), 2);
    assert_eq!(runner.poll_result(0, 2, Some(0)), Ok(0));
    assert_eq!(RAW_POLLS.load(Ordering::Relaxed), 2);
    Ok(())
}

#[test]
fn parked_raw_poll_rechecks_aliases_and_unwatched_local_and_pool_changes() -> Result<(), Errno> {
    let owner = 22;
    let objects = objects::table();
    let mut fs = FileSystem::new();
    let mut process = Process::new(objects, owner)?;
    let pipe = pipes::with(|pool| pool.pair(owner))?;
    let ends = process.install_pipe(pipe, 0)?;
    let (master, slave) = pty::with(|pool| {
        let master = pool.open_master(owner, 0)?;
        pool.lock(owner, master, false)?;
        let slave = pool.open_slave(owner, pool.number(owner, master)?, 0)?;
        Ok((master, slave))
    })?;
    let pty = process.install_pty(master, 0)?;
    let event = process.eventfd(0, 0)?;
    let ready = process.eventfd(1, 0)?;
    let notify = process.inotify_init(&fs, 0)?;
    process.inotify_add_watch(&fs, notify, "/", inotify::CREATE)?;
    let timer = process.timerfd_create(1, 0)?;
    let timer_alias = process.dup(timer)?;
    NOW_NS.store(0, Ordering::Relaxed);
    let mut runner = user::Runner { process, records: [0; 64], writable: true, poll_snapshot: user::PollSnapshot::new() };
    for (i, fd) in [ends[0], pty, event, notify, timer].into_iter().enumerate() {
        runner.records[8 * i..8 * i + 4].copy_from_slice(&fd.to_le_bytes());
        runner.records[8 * i + 4] = epoll::IN as u8;
    }
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));
    let epoch = runner.process.poll_readiness_epoch();
    assert_eq!(runner.process.dup2(&mut fs, ready, event)?, (event, None));
    assert_eq!(runner.process.poll_readiness_epoch(), epoch);
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "reused FD retained the old negative proof");
    let mut word = [0; 8];
    runner.process.read(&mut fs, event, &mut word)?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));

    runner.process.write(&mut fs, &mut Sink, ready, &1u64.to_le_bytes())?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "unwatched aliased eventfd write");
    runner.process.read(&mut fs, event, &mut word)?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));

    pipes::with(|pool| pool.write(owner, pipe[1], b"p"))?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "unwatched pipe write");
    pipes::with(|pool| pool.read(owner, pipe[0], &mut word))?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));

    pty::with(|pool| pool.write(owner, slave, b"t"))?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "unwatched PTY write");
    pty::with(|pool| pool.read(owner, master, &mut word))?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));

    fs.write(Path::resolve(Path::ROOT, "/raw-poll-created")?, b"file", false)?;
    objects.observe_filesystem(&fs);
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "unwatched inotify publication");
    runner.process.inotify_read(&fs, notify, &mut [0; 256])?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));

    runner.process.timerfd_set(timer_alias, 0, 0, timerfd::Setting { value: 20, interval: 0 })?;
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(0));
    NOW_NS.store(20, Ordering::Relaxed);
    objects.expire_timers(now_ns);
    assert_eq!(runner.poll_result(0, 5, Some(0)), Ok(1), "unwatched timer expired");
    Ok(())
}

#[test]
fn socket_readiness_query_leaves_unrelated_epoll_pending_until_sampled() -> Result<(), Errno> {
    let mut other = Process::new(objects::table(), 1)?;
    let (watched, queried) = unix::with(|sockets| {
        let pair = sockets.socketpair(1)?;
        sockets.write(1, pair[1], b"unrelated data")?;
        let query = sockets.socketpair(2)?;
        sockets.write(2, query[1], b"queried data")?;
        Ok((pair[0].raw(), query[0].raw()))
    })?;

    let fd = other.install_socket(watched, 0)?;
    let leaf = other.epoll_create(0)?;
    let root = other.epoll_create(0)?;
    other.epoll_ctl(leaf, 1, fd, epoll::Event { events: epoll::IN, data: 10 })?;
    other.epoll_ctl(root, 1, leaf, epoll::Event { events: epoll::IN | epoll::EDGE, data: 20 })?;
    let unsampled = [0; OPEN_MAX];
    assert!(!other.epoll_readable(root, &unsampled)?);

    let query = epoll::Source::Socket { owner: 2, handle: queried };
    assert_eq!(user::Runner::sample(query)?, epoll::IN | epoll::OUT);
    assert!(!other.epoll_readable(root, &unsampled)?, "socket query sampled an unrelated epoll");

    let readiness = other.epoll_sample(root, user::Runner::sample)?;
    let mut events = [epoll::Event::default(); 1];
    assert_eq!(other.epoll_collect(root, &readiness, &mut events)?, 1);
    assert_eq!(events[0], epoll::Event { events: epoll::IN, data: 20 });
    Ok(())
}

struct Sink;
impl Console for Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> { Ok(bytes.len()) }
}

fn wait_sample(process: &mut Process, root: i32) -> Result<Option<epoll::Event>, Errno> {
    let readiness = process.epoll_sample_at(root, now_ns, user::Runner::sample)?;
    let mut events = [epoll::Event::default(); 1];
    Ok((process.epoll_collect(root, &readiness, &mut events)? == 1).then_some(events[0]))
}

#[test]
fn parked_epoll_sees_real_backend_publications_and_timer_expiry() -> Result<(), Errno> {
    let owner = 31;
    let objects = objects::table();
    let mut fs = FileSystem::new();
    let mut process = Process::new(objects, owner)?;
    let sockets = unix::with(|pool| pool.socketpair(owner))?;
    let socket = process.install_socket(sockets[0].raw(), 0)?;
    let pipe = pipes::with(|pool| pool.pair(owner))?;
    let fds = process.install_pipe(pipe, 0)?;
    let (master, slave) = pty::with(|pool| {
        let master = pool.open_master(owner, 0)?;
        pool.lock(owner, master, false)?;
        let slave = pool.open_slave(owner, pool.number(owner, master)?, 0)?;
        Ok((master, slave))
    })?;
    let pty = process.install_pty(master, 0)?;
    let event = process.eventfd(0, 0)?;
    let notify = process.inotify_init(&fs, 0)?;
    process.inotify_add_watch(&fs, notify, "/", inotify::CREATE)?;
    let timer = process.timerfd_create(1, 0)?;
    let root = process.epoll_create(0)?;
    for (i, fd) in [socket, fds[0], pty, event, notify, timer].into_iter().enumerate() {
        process.epoll_ctl(root, 1, fd, epoll::Event { events: epoll::IN | epoll::EDGE, data: i as u64 })?;
    }
    NOW_NS.store(0, Ordering::Relaxed);
    process.timerfd_set(timer, 0, 0, timerfd::Setting { value: 20, interval: 0 })?;
    assert_eq!(wait_sample(&mut process, root)?, None);
    let identity = process.epoll_identity(root)?;
    let epoch = process.epoll_invalidation_epoch();
    let verify_event = |process: &mut Process, data| -> Result<(), Errno> {
        assert!(process.epoll_wait_needs_sample(root, identity, epoch)?, "missed source {data}");
        assert_eq!(wait_sample(process, root)?, Some(epoll::Event { events: epoll::IN, data }));
        assert!(!process.epoll_wait_needs_sample(root, identity, epoch)?, "read-only sampling dirtied epoch");
        Ok(())
    };

    unix::with(|pool| pool.poll(owner, sockets[0]))?;
    assert!(!process.epoll_wait_needs_sample(root, identity, epoch)?);
    unix::with(|pool| pool.write(owner, sockets[1], b"socket"))?;
    verify_event(&mut process, 0)?;
    pipes::with(|pool| pool.write(owner, pipe[1], b"pipe"))?;
    verify_event(&mut process, 1)?;
    pty::with(|pool| pool.write(owner, slave, b"pty"))?;
    verify_event(&mut process, 2)?;
    process.write(&mut fs, &mut Sink, event, &1u64.to_le_bytes())?;
    verify_event(&mut process, 3)?;
    fs.write(Path::resolve(Path::ROOT, "/epoll-created")?, b"file", false)?;
    objects.observe_filesystem(&fs);
    verify_event(&mut process, 4)?;

    NOW_NS.store(19, Ordering::Relaxed);
    objects.expire_timers(now_ns);
    assert!(!process.epoll_wait_needs_sample(root, identity, epoch)?);
    NOW_NS.store(20, Ordering::Relaxed);
    objects.expire_timers(now_ns);
    verify_event(&mut process, 5)?;
    Ok(())
}

#[test]
fn parked_epoll_rechecks_nested_controls_reused_fd_and_unresolved_backend() -> Result<(), Errno> {
    let owner = 32;
    let objects = objects::table();
    let mut fs = FileSystem::new();
    let mut process = Process::new(objects, owner)?;
    let root = process.epoll_create(0)?;
    let child = process.epoll_create(0)?;
    process.epoll_ctl(root, 1, child, epoll::Event { events: epoll::IN | epoll::EDGE, data: 5 })?;
    let identity = process.epoll_identity(root)?;
    assert_eq!(wait_sample(&mut process, root)?, None);
    let epoch = process.epoll_invalidation_epoch();
    let ready = process.eventfd(1, 0)?;
    process.epoll_ctl(child, 1, ready, epoll::Event { events: epoll::IN, data: 1 })?;
    assert!(process.epoll_wait_needs_sample(root, identity, epoch)?);
    assert_eq!(wait_sample(&mut process, root)?, Some(epoll::Event { events: epoll::IN, data: 5 }));
    process.close(&mut fs, ready)?;

    let endpoints = unix::with(|pool| pool.socketpair(owner))?;
    let socket = process.install_socket(endpoints[0].raw(), 0)?;
    process.epoll_ctl(child, 1, socket, epoll::Event { events: epoll::IN, data: 2 })?;
    assert_eq!(wait_sample(&mut process, root)?, None);
    let epoch = process.epoll_invalidation_epoch();
    // Force a stale backend capability to exercise the observer's None path.
    unix::with(|pool| pool.close(owner, endpoints[0]))?;
    assert!(process.epoll_wait_needs_sample(root, identity, epoch)?);
    assert_eq!(wait_sample(&mut process, root), Err(Errno::Badf));

    let alias = process.dup(root)?;
    process.close(&mut fs, root)?;
    assert_eq!(process.epoll_identity(alias)?, identity);
    assert_eq!(process.epoll_create(0)?, root);
    assert_eq!(process.epoll_wait_needs_sample(root, identity, epoch), Err(Errno::Badf));
    Ok(())
}
