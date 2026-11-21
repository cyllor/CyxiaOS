use cyxia_posix::{Errno, OPEN_MAX, Process, epoll};

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

fn now_ns() -> u64 {
    0
}

mod user {
    use cyxia_posix::{Errno, epoll};

    pub(super) struct Runner;
    impl Runner {
        // SOURCE_READINESS

        pub(super) fn sample(source: epoll::Source) -> Result<u32, Errno> {
            Self::source_readiness(source)
        }
    }
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
