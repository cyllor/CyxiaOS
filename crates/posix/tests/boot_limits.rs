use cyxia_ai_fs::FileSystem;
use cyxia_posix::{Errno, O_RDONLY, OpenDescriptions, Process, limits};

fn with_test_stack(test: impl FnOnce() + Send + 'static) {
    // The full session's static POSIX tables are larger than a test thread's stack.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn descriptor_and_open_description_admission_use_the_boot_envelope() {
    with_test_stack(|| {
        let objects = OpenDescriptions::new();
        objects
            .set_boot_limits(limits::ObjectProfile {
                fds_per_process: 5,
                open_descriptions: 4,
                ..limits::PROFILE
            })
            .unwrap();
        let mut fs = FileSystem::new();
        let mut first = Process::new(&objects, 1).unwrap();
        let mut second = Process::empty(&objects, 2);
        assert_eq!(first.open_readonly(10, b"data", O_RDONLY), Ok(3));
        assert_eq!(
            second.open_readonly(11, b"data", O_RDONLY),
            Err(Errno::Mfile)
        );
        assert_eq!(first.dup_from(3, 0, false), Ok(4));
        assert_eq!(first.dup_from(3, 0, false), Err(Errno::Mfile));
        assert_eq!(first.dup2(&mut fs, 3, 5), Err(Errno::Badf));
        assert_eq!(objects.snapshot().capacity, 4);
        assert_eq!(objects.snapshot().references, 5);
        assert_eq!(objects.set_boot_limits(limits::PROFILE), Err(Errno::Busy));
    });
}

#[test]
fn monitor_slots_are_reused_within_the_published_capacity() {
    with_test_stack(|| {
        let objects = OpenDescriptions::new();
        objects
            .set_boot_limits(limits::ObjectProfile {
                epoll_instances: 1,
                inotify_instances: 1,
                ..limits::PROFILE
            })
            .unwrap();
        let mut fs = FileSystem::new();
        let mut first = Process::empty(&objects, 1);
        let mut second = Process::empty(&objects, 2);
        assert_eq!(first.epoll_create(0), Ok(0));
        assert_eq!(second.epoll_create(0), Err(Errno::Mfile));
        assert_eq!(first.inotify_init(&fs, 0), Ok(1));
        assert_eq!(second.inotify_init(&fs, 0), Err(Errno::Mfile));
        first.close(&mut fs, 0).unwrap();
        first.close(&mut fs, 1).unwrap();
        assert_eq!(second.epoll_create(0), Ok(0));
        assert_eq!(second.inotify_init(&fs, 0), Ok(1));
    });
}

#[test]
fn boot_pipe_and_socket_limits_keep_creation_atomic_at_capacity() {
    use cyxia_posix::{pipe::Pipes, unix::UnixSockets};
    with_test_stack(|| {
        let mut pipes = Pipes::new();
        pipes.set_boot_limit(1).unwrap();
        let [read, write] = pipes.pair(1).unwrap();
        assert_eq!(pipes.pair(2), Err(Errno::Nospc));
        pipes.close(1, read).unwrap();
        pipes.close(1, write).unwrap();
        assert!(pipes.pair(2).is_ok());

        let mut sockets = UnixSockets::new();
        sockets.set_boot_limits(3, 1).unwrap();
        let [a, b] = sockets.socketpair(1).unwrap();
        assert_eq!(sockets.socketpair(2), Err(Errno::Nospc));
        assert_eq!(sockets.capacity().free_endpoints, 1);
        let c = sockets.socket(2).unwrap();
        assert_eq!(sockets.socket(2), Err(Errno::Nospc));
        sockets.close(1, a).unwrap();
        sockets.close(1, b).unwrap();
        sockets.close(2, c).unwrap();
        assert!(sockets.socketpair(3).is_ok());
    });
}

#[test]
fn shared_memory_uses_only_physically_reserved_slots() {
    use cyxia_posix::shared_memory::{Backings, Batch, PAGE_SIZE};
    let mut backing = Backings::new();
    backing.set_boot_limits(2, 1).unwrap();
    let mut batch = Batch::new();
    let object = backing.create(true).unwrap();
    assert_eq!(backing.create(true), Err(Errno::Mfile));
    assert_eq!(
        backing.resize(object, 3 * PAGE_SIZE, &mut batch),
        Err(Errno::Nomem)
    );
    assert_eq!(backing.free_pages(), 2);
    backing.resize(object, 2 * PAGE_SIZE, &mut batch).unwrap();
    assert_eq!(batch.iter().collect::<Vec<_>>(), [0, 1]);
    backing.close_description(object, &mut batch).unwrap();
    assert_eq!(backing.free_pages(), 2);
    assert!(backing.create(true).is_ok());
}
