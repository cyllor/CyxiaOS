use cyxia_posix::{
    Errno,
    unix::{BUFFER_BYTES, CONNECTIONS, ENDPOINTS, Handle, UnixSockets},
};

fn listener(sockets: &mut UnixSockets, owner: u32, name: &[u8], backlog: usize) -> Handle {
    let handle = sockets.socket(owner).unwrap();
    sockets.bind(owner, handle, name).unwrap();
    sockets.listen(owner, handle, backlog).unwrap();
    handle
}

#[test]
fn pathname_connection_is_full_duplex_and_ready_before_accept() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 10, b"/tmp/.X11-unix/X0", 2);
    let client = sockets.socket(20).unwrap();
    assert_eq!(sockets.accept(10, server), Err(Errno::Again));
    assert!(!sockets.poll(10, server).unwrap().readable);
    sockets.connect(20, client, b"/tmp/.X11-unix/X0").unwrap();
    assert!(sockets.poll(10, server).unwrap().readable);
    assert_eq!(sockets.write(20, client, b"X11 setup"), Ok(9));
    let accepted = sockets.accept(10, server).unwrap();
    assert!(!sockets.poll(10, server).unwrap().readable);
    let mut bytes = [0; 32];
    assert_eq!(sockets.read(10, accepted, &mut bytes), Ok(9));
    assert_eq!(&bytes[..9], b"X11 setup");
    assert_eq!(sockets.read(10, accepted, &mut bytes), Err(Errno::Again));
    assert_eq!(sockets.write(10, accepted, b"accepted"), Ok(8));
    assert_eq!(sockets.read(20, client, &mut bytes), Ok(8));
    assert_eq!(&bytes[..8], b"accepted");
}

#[test]
fn ring_wrap_short_io_and_poll_backpressure() {
    let mut sockets = UnixSockets::new();
    let [a, b] = sockets.socketpair(1).unwrap();
    let mut bytes = [0; BUFFER_BYTES];
    assert_eq!(
        sockets.write(1, a, &[3; BUFFER_BYTES + 99]),
        Ok(BUFFER_BYTES)
    );
    assert_eq!(sockets.write(1, a, b"x"), Err(Errno::Again));
    assert!(!sockets.poll(1, a).unwrap().writable);
    assert!(sockets.poll(1, b).unwrap().readable);
    assert_eq!(sockets.read(1, b, &mut bytes[..257]), Ok(257));
    assert_eq!(&bytes[..257], &[3; 257]);
    assert!(sockets.poll(1, a).unwrap().writable);
    assert_eq!(sockets.write(1, a, &[8; 300]), Ok(257));
    assert_eq!(sockets.read(1, b, &mut bytes), Ok(BUFFER_BYTES));
    assert_eq!(&bytes[..BUFFER_BYTES - 257], &[3; BUFFER_BYTES - 257]);
    assert_eq!(&bytes[BUFFER_BYTES - 257..], &[8; 257]);
    assert_eq!(sockets.read(1, b, &mut []), Ok(0));
    assert_eq!(sockets.write(1, a, &[]), Ok(0));
}

#[test]
fn eof_drains_sent_bytes_and_stale_handles_cannot_reopen() {
    let mut sockets = UnixSockets::new();
    let original = sockets.capacity();
    let [a, b] = sockets.socketpair(1).unwrap();
    assert_eq!(sockets.write(2, a, b"forged owner"), Err(Errno::Badf));
    assert_eq!(sockets.poll(1, Handle::from_raw(0)), Err(Errno::Badf));
    assert_eq!(sockets.poll(1, Handle::from_raw(0x1ff)), Err(Errno::Badf));
    sockets.write(1, a, b"last").unwrap();
    sockets.close(1, a).unwrap();
    assert_eq!(sockets.write(1, b, b"late"), Err(Errno::Pipe));
    let ready = sockets.poll(1, b).unwrap();
    assert!(ready.readable && ready.writable && ready.hangup);
    let mut bytes = [0; 8];
    assert_eq!(sockets.read(1, b, &mut bytes), Ok(4));
    assert_eq!(&bytes[..4], b"last");
    assert_eq!(sockets.read(1, b, &mut bytes), Ok(0));
    sockets.close(1, b).unwrap();
    assert_eq!(sockets.capacity(), original);
    let [c, d] = sockets.socketpair(1).unwrap();
    assert_ne!(a, c);
    assert_ne!(b, d);
    assert_eq!(sockets.read(1, a, &mut bytes), Err(Errno::Badf));
    assert_eq!(sockets.close(1, b), Err(Errno::Badf));
    assert_eq!(sockets.read(1, d, &mut bytes), Err(Errno::Again));
}

#[test]
fn backlog_failure_does_not_connect_client_or_consume_resources() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 1);
    let a = sockets.socket(2).unwrap();
    let b = sockets.socket(3).unwrap();
    sockets.connect(2, a, b"/server").unwrap();
    let before = sockets.capacity();
    assert_eq!(sockets.connect(3, b, b"/server"), Err(Errno::Again));
    assert_eq!(sockets.capacity(), before);
    assert_eq!(sockets.write(3, b, b"unconnected"), Err(Errno::Notconn));
    let accepted = sockets.accept(1, server).unwrap();
    sockets.connect(3, b, b"/server").unwrap();
    sockets.close(1, accepted).unwrap();
    assert!(sockets.accept(1, server).is_ok());
}

#[test]
fn endpoint_exhaustion_rolls_back_connect_and_socketpair() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 8);
    let client = sockets.socket(2).unwrap();
    let mut fillers = [client; ENDPOINTS - 2];
    for slot in &mut fillers {
        *slot = sockets.socket(3).unwrap();
    }
    let before = sockets.capacity();
    assert_eq!(sockets.connect(2, client, b"/server"), Err(Errno::Nospc));
    assert_eq!(sockets.socketpair(4), Err(Errno::Nospc));
    assert_eq!(sockets.capacity(), before);
    assert_eq!(sockets.accept(1, server), Err(Errno::Again));
    sockets.close(3, fillers[0]).unwrap();
    assert_eq!(sockets.socketpair(4), Err(Errno::Nospc));
    assert_eq!(sockets.capacity().free_endpoints, 1);
    sockets.connect(2, client, b"/server").unwrap();
    assert!(sockets.accept(1, server).is_ok());
}

#[test]
fn listener_close_cancels_pending_but_not_accepted_streams() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 2);
    let a = sockets.socket(2).unwrap();
    let b = sockets.socket(3).unwrap();
    sockets.connect(2, a, b"/server").unwrap();
    let accepted = sockets.accept(1, server).unwrap();
    sockets.connect(3, b, b"/server").unwrap();
    sockets.close(1, server).unwrap();
    assert!(sockets.poll(3, b).unwrap().hangup);
    assert_eq!(sockets.read(3, b, &mut [0]), Ok(0));
    assert_eq!(sockets.write(3, b, b"late"), Err(Errno::Pipe));
    assert_eq!(sockets.write(2, a, b"still connected"), Ok(15));
    let mut bytes = [0; 15];
    assert_eq!(sockets.read(1, accepted, &mut bytes), Ok(15));
    assert_eq!(&bytes, b"still connected");
}

#[test]
fn unlink_preserves_old_connections_and_rebind_targets_new_listener() {
    let mut sockets = UnixSockets::new();
    let old = listener(&mut sockets, 1, b"/server", 2);
    let first = sockets.socket(2).unwrap();
    sockets.connect(2, first, b"/server").unwrap();
    sockets.unlink(b"/server").unwrap();
    let next = sockets.socket(3).unwrap();
    assert_eq!(sockets.connect(3, next, b"/server"), Err(Errno::Noent));
    let new = listener(&mut sockets, 4, b"/server", 2);
    sockets.connect(3, next, b"/server").unwrap();
    let accepted_old = sockets.accept(1, old).unwrap();
    let accepted_new = sockets.accept(4, new).unwrap();
    sockets.close(1, old).unwrap();
    sockets.write(2, first, b"old").unwrap();
    sockets.write(3, next, b"new").unwrap();
    let mut bytes = [0; 3];
    assert_eq!(sockets.read(1, accepted_old, &mut bytes), Ok(3));
    assert_eq!(&bytes, b"old");
    assert_eq!(sockets.read(4, accepted_new, &mut bytes), Ok(3));
    assert_eq!(&bytes, b"new");
    assert_eq!(sockets.bind(2, first, b"/server"), Err(Errno::Inval));
}

#[test]
fn closed_path_remains_until_unlink_and_owner_cleanup_reclaims_streams() {
    let mut sockets = UnixSockets::new();
    let original = sockets.capacity();
    let server = listener(&mut sockets, 10, b"/server", 2);
    let client = sockets.socket(20).unwrap();
    sockets.connect(20, client, b"/server").unwrap();
    sockets.close_owner(10);
    assert_eq!(sockets.accept(10, server), Err(Errno::Badf));
    sockets.close_owner(20);
    let replacement = sockets.socket(30).unwrap();
    assert_eq!(
        sockets.bind(30, replacement, b"/server"),
        Err(Errno::Addrinuse)
    );
    assert_eq!(
        sockets.connect(30, replacement, b"/server"),
        Err(Errno::Connrefused)
    );
    sockets.unlink(b"/server").unwrap();
    assert_eq!(sockets.unlink(b"/server"), Err(Errno::Noent));
    sockets.close(30, replacement).unwrap();
    assert_eq!(sockets.capacity(), original);
}

#[test]
fn client_can_close_before_accept_and_its_queued_bytes_remain_readable() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 1);
    let client = sockets.socket(2).unwrap();
    sockets.connect(2, client, b"/server").unwrap();
    sockets.write(2, client, b"sent before close").unwrap();
    sockets.close(2, client).unwrap();
    let accepted = sockets.accept(1, server).unwrap();
    let mut bytes = [0; 32];
    assert_eq!(sockets.read(1, accepted, &mut bytes), Ok(17));
    assert_eq!(&bytes[..17], b"sent before close");
    assert_eq!(sockets.read(1, accepted, &mut bytes), Ok(0));
    assert_eq!(sockets.write(1, accepted, b"late reply"), Err(Errno::Pipe));
}

#[test]
fn malformed_names_and_invalid_lifecycle_do_not_change_capacity() {
    let mut sockets = UnixSockets::new();
    assert_eq!(sockets.socket(0), Err(Errno::Inval));
    let socket = sockets.socket(1).unwrap();
    let before = sockets.capacity();
    for path in [
        &b"relative"[..],
        b"/",
        b"/a/../b",
        b"/a//b",
        b"/a/",
        b"/a\0b",
    ] {
        assert_eq!(sockets.bind(1, socket, path), Err(Errno::Inval));
    }
    assert_eq!(
        sockets.bind(1, socket, &[b'x'; 108]),
        Err(Errno::Nametoolong)
    );
    assert_eq!(sockets.bind(1, socket, b""), Err(Errno::Noent));
    assert_eq!(sockets.listen(1, socket, 1), Err(Errno::Inval));
    assert_eq!(sockets.capacity(), before);
    sockets.bind(1, socket, b"/server").unwrap();
    assert_eq!(sockets.listen(1, socket, 0), Err(Errno::Inval));
    assert_eq!(sockets.listen(1, socket, 9), Err(Errno::Inval));
    assert_eq!(sockets.bind(1, socket, b"/twice"), Err(Errno::Inval));
    let client = sockets.socket(2).unwrap();
    assert_eq!(
        sockets.connect(2, client, b"/server"),
        Err(Errno::Connrefused)
    );
}

#[test]
fn connection_pool_exhaustion_does_not_consume_available_endpoints() {
    let mut sockets = UnixSockets::new();
    let mut peers = [Handle::from_raw(0); CONNECTIONS];
    for peer in &mut peers {
        let [a, b] = sockets.socketpair(1).unwrap();
        sockets.close(1, a).unwrap();
        *peer = b;
    }
    let server = listener(&mut sockets, 2, b"/server", 1);
    let client = sockets.socket(3).unwrap();
    let before = sockets.capacity();
    assert_eq!(before.free_connections, 0);
    assert!(before.free_endpoints >= 2);
    assert_eq!(sockets.connect(3, client, b"/server"), Err(Errno::Nospc));
    assert_eq!(sockets.socketpair(4), Err(Errno::Nospc));
    assert_eq!(sockets.capacity(), before);
    assert_eq!(sockets.accept(2, server), Err(Errno::Again));
    sockets.close(1, peers[0]).unwrap();
    sockets.connect(3, client, b"/server").unwrap();
    assert!(sockets.accept(2, server).is_ok());
}

#[test]
fn binding_pool_exhaustion_requires_explicit_unlink_and_accepts_byte_names() {
    let mut sockets = UnixSockets::new();
    for byte in 0..ENDPOINTS {
        let handle = sockets.socket(1).unwrap();
        sockets.bind(1, handle, &[b'/', b'a' + byte as u8]).unwrap();
        sockets.close(1, handle).unwrap();
    }
    let handle = sockets.socket(1).unwrap();
    let before = sockets.capacity();
    assert_eq!(sockets.bind(1, handle, b"/full"), Err(Errno::Nospc));
    assert_eq!(sockets.capacity(), before);
    sockets.unlink(b"/a").unwrap();
    let mut path = [255; 107];
    path[0] = b'/';
    sockets.bind(1, handle, &path).unwrap();
    sockets.listen(1, handle, 1).unwrap();
    let client = sockets.socket(2).unwrap();
    sockets.connect(2, client, &path).unwrap();
    assert!(sockets.accept(1, handle).is_ok());
}

#[test]
fn accept_fifo_and_backlog_changes_do_not_drop_queued_connections() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 3);
    for byte in 0..3 {
        let client = sockets.socket(2).unwrap();
        sockets.connect(2, client, b"/server").unwrap();
        sockets.write(2, client, &[byte]).unwrap();
    }
    assert_eq!(sockets.listen(1, server, 2), Err(Errno::Busy));
    sockets.listen(1, server, 8).unwrap();
    for byte in 0..3 {
        let accepted = sockets.accept(1, server).unwrap();
        let mut received = [0; 1];
        assert_eq!(sockets.read(1, accepted, &mut received), Ok(1));
        assert_eq!(received, [byte]);
    }
    assert_eq!(sockets.accept(1, server), Err(Errno::Again));
}

#[test]
fn reserved_server_handle_is_invisible_even_to_its_owner_until_accept() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 1, b"/server", 1);
    let client = sockets.socket(2).unwrap();
    sockets.connect(2, client, b"/server").unwrap();
    // Handles are generation-safe identities, not secrets. Knowing the encoding
    // must not allow a listener owner to use an endpoint before it is accepted.
    let reserved = Handle::from_raw((1 << 8) | 2);
    assert_eq!(sockets.read(1, reserved, &mut [0]), Err(Errno::Badf));
    assert_eq!(sockets.write(1, reserved, b"x"), Err(Errno::Badf));
    assert_eq!(sockets.poll(1, reserved), Err(Errno::Badf));
    assert_eq!(sockets.close(1, reserved), Err(Errno::Badf));
    let accepted = sockets.accept(1, server).unwrap();
    assert_eq!(accepted, reserved);
    assert_eq!(sockets.connect(2, client, b"/server"), Err(Errno::Isconn));
    assert_eq!(sockets.poll(2, accepted), Err(Errno::Badf));
    assert_eq!(sockets.write(1, accepted, b"now visible"), Ok(11));
}

#[test]
fn abstract_names_are_binary_distinct_and_released_at_close() {
    let mut sockets = UnixSockets::new();
    let a = listener(&mut sockets, 1, b"\0X\0a", 1);
    let b = listener(&mut sockets, 1, b"\0X\0a\0", 1);
    let client = sockets.socket(2).unwrap();
    sockets.connect(2, client, b"\0X\0a").unwrap();
    let peer = sockets.accept(1, a).unwrap();
    assert!(!sockets.poll(1, b).unwrap().readable);
    sockets.close(1, a).unwrap();
    let replacement = listener(&mut sockets, 3, b"\0X\0a", 1);
    assert_eq!(sockets.write(2, client, b"ok"), Ok(2));
    assert!(sockets.poll(1, peer).unwrap().readable);
    sockets.close(3, replacement).unwrap();
}

#[test]
fn connected_names_and_credentials_survive_unlink_and_peer_close() {
    let mut sockets = UnixSockets::new();
    let server = listener(&mut sockets, 10, b"/tmp/X0", 1);
    let client = sockets.socket(20).unwrap();
    sockets.bind(20, client, b"\0client").unwrap();
    sockets.connect(20, client, b"/tmp/X0").unwrap();
    let accepted = sockets.accept(10, server).unwrap();
    sockets.unlink(b"/tmp/X0").unwrap();
    sockets.close(10, server).unwrap();
    let (name, len) = sockets.socket_name(20, client, true).unwrap();
    assert_eq!(&name[..len], b"\x01\0/tmp/X0\0");
    let (name, len) = sockets.socket_name(10, accepted, true).unwrap();
    assert_eq!(&name[..len], b"\x01\0\0client");
    assert_eq!(sockets.peer_owner(20, client), Ok(10));
    assert_eq!(sockets.peer_owner(10, accepted), Ok(20));
    sockets.close(10, accepted).unwrap();
    assert_eq!(sockets.peer_owner(20, client), Ok(10));
    assert_eq!(sockets.peer_owner(11, client), Err(Errno::Badf));
}

#[test]
fn shutdown_half_close_delivers_eof_without_losing_reverse_stream() {
    let mut sockets = UnixSockets::new();
    let [a, b] = sockets.socketpair(1).unwrap();
    sockets.write(1, a, b"queued").unwrap();
    sockets.shutdown(1, a, 1).unwrap();
    assert_eq!(sockets.write(1, a, b"x"), Err(Errno::Pipe));
    let mut bytes = [0; 16];
    assert_eq!(sockets.read(1, b, &mut bytes), Ok(6));
    assert_eq!(sockets.read(1, b, &mut bytes), Ok(0));
    assert_eq!(sockets.write(1, b, b"reply"), Ok(5));
    assert_eq!(sockets.read(1, a, &mut bytes), Ok(5));
    assert_eq!(sockets.shutdown(1, b, 3), Err(Errno::Inval));
    sockets.shutdown(1, a, 0).unwrap();
    assert_eq!(sockets.write(1, b, b"x"), Err(Errno::Pipe));
    assert!(sockets.poll(1, a).unwrap().hangup);
    sockets.close(1, a).unwrap();
    sockets.close(1, b).unwrap();
    assert_eq!(sockets.capacity().free_connections, CONNECTIONS);
}
