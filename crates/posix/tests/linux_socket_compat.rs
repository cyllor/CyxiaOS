use cyxia_posix::{Errno, O_CLOEXEC, O_NONBLOCK, O_RDWR, OpenDescriptions, Process};

#[test]
fn linux_signed_int_backlogs_silently_use_the_bounded_queue() {
    use cyxia_posix::unix::{UnixSockets, linux_listen_backlog};
    // Rust's UnixListener passes -1. Both AArch64 sign extensions are legal;
    // syscall int arguments use the low 32 bits, not a pointer-sized count.
    for (raw, expected) in [
        (u64::MAX, 8),
        (u32::MAX as u64, 8),
        (0, 1),
        (2, 2),
        (128, 8),
        (1u64 << 32, 1),
    ] {
        assert_eq!(linux_listen_backlog(raw), expected);
        let mut sockets = UnixSockets::new();
        let server = sockets.socket(1).unwrap();
        sockets.bind(1, server, b"/wayland").unwrap();
        sockets
            .listen(1, server, linux_listen_backlog(raw))
            .unwrap();
        let client = sockets.socket(2).unwrap();
        sockets.connect(2, client, b"/wayland").unwrap();
        assert!(sockets.poll(1, server).unwrap().readable);
    }
}

#[test]
fn socket_fionbio_changes_shared_status_without_changing_cloexec_or_access() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    let fd = process.install_socket(123, O_CLOEXEC).unwrap();
    let alias = process.dup(fd).unwrap();
    process.set_socket_nonblocking(alias, -1).unwrap();
    assert_eq!(process.flags(fd).unwrap(), O_RDWR | O_NONBLOCK);
    assert_eq!(process.flags(alias), process.flags(fd));
    assert!(process.close_on_exec(fd).unwrap());
    assert!(!process.close_on_exec(alias).unwrap());
    process.set_socket_nonblocking(fd, 0).unwrap();
    assert_eq!(process.flags(alias).unwrap(), O_RDWR);
    assert!(process.close_on_exec(fd).unwrap());
    assert_eq!(process.socket(alias), Ok(Some(123)));
}

#[test]
fn socket_fionbio_rejects_other_descriptors_without_mutating_them() {
    let objects = OpenDescriptions::new();
    let mut process = Process::new(&objects, 1).unwrap();
    assert_eq!(process.set_socket_nonblocking(99, 1), Err(Errno::Badf));
    let event = process.eventfd(0, O_CLOEXEC).unwrap();
    let before = process.flags(event);
    assert_eq!(process.set_socket_nonblocking(event, 1), Err(Errno::Notty));
    assert_eq!(process.flags(event), before);
}
