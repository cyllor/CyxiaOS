use cyxia_ai_fs::FileSystem;
use cyxia_posix::{O_CLOEXEC, OpenDescriptions, Process, Released, unix::UnixSockets};

fn fixture(test: impl FnOnce() + Send + 'static) {
    // Full-OS pools are large values; this is a host fixture stack only.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

fn reclaim(
    objects: &OpenDescriptions,
    fs: &mut FileSystem,
    sockets: &mut UnixSockets,
    released: Option<Released>,
) -> cyxia_posix::ancillary::Reclaimed {
    let result = objects
        .reclaim_socket_rights(fs, sockets, released, &[], false)
        .unwrap();
    assert!(result.external.iter().all(Option::is_none));
    assert_eq!(result.receipts.iter().flatten().count(), result.messages);
    assert_eq!(
        result
            .receipts
            .iter()
            .flatten()
            .map(|r| r.references)
            .sum::<usize>(),
        result.references
    );
    assert_eq!(
        result
            .receipts
            .iter()
            .flatten()
            .filter(|r| r.cancelled)
            .count(),
        result.cancelled
    );
    result
}

#[test]
fn garbage_cycle_returns_other_pool_releases_and_per_message_receipts() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let mut pipes = cyxia_posix::pipe::Pipes::new();
        let free = pipes.free();
        let mut p = Process::empty(&objects, 1);
        let [a, b] = pair(&mut p, &mut sockets, 1);
        let [reader, writer] = pipes.pair(1).unwrap();
        let [rfd, wfd] = p.install_pipe([reader, writer], 0).unwrap();
        send(&objects, &mut sockets, &p, a, &[b, rfd]);
        close(&objects, &mut fs, &mut sockets, &mut p, rfd);
        let released = p.close(&mut fs, b).unwrap();
        let result = objects
            .reclaim_socket_rights(&mut fs, &mut sockets, released, &[], false)
            .unwrap();
        assert_eq!((result.messages, result.references), (1, 2));
        let receipt = result.receipts[0].as_ref().unwrap();
        assert_eq!(receipt.references, 2);
        assert!(!receipt.cancelled);
        assert_eq!(result.external.iter().flatten().count(), 1);
        assert_eq!(
            result.external[0],
            Some(Released::Pipe {
                owner: 1,
                handle: reader
            })
        );
        // The helper has returned the Unix borrow before entering another pool.
        pipes.close(1, reader).unwrap();
        assert_eq!(pipes.write(1, writer, b"x"), Err(cyxia_posix::Errno::Pipe));
        let released = p.close(&mut fs, wfd).unwrap();
        let result = objects
            .reclaim_socket_rights(&mut fs, &mut sockets, released, &[], false)
            .unwrap();
        assert_eq!(
            result.external[0],
            Some(Released::Pipe {
                owner: 1,
                handle: writer
            })
        );
        pipes.close(1, writer).unwrap();
        close(&objects, &mut fs, &mut sockets, &mut p, a);
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(pipes.free(), free);
    });
}

fn close(
    objects: &OpenDescriptions,
    fs: &mut FileSystem,
    sockets: &mut UnixSockets,
    process: &mut Process<'_>,
    fd: i32,
) -> cyxia_posix::ancillary::Reclaimed {
    let released = process.close(fs, fd).unwrap();
    reclaim(objects, fs, sockets, released)
}

fn pair(process: &mut Process<'_>, sockets: &mut UnixSockets, owner: u32) -> [i32; 2] {
    sockets
        .socketpair(owner)
        .unwrap()
        .map(|handle| process.install_socket(handle.raw(), 0).unwrap())
}

fn handle(process: &Process<'_>, fd: i32) -> cyxia_posix::unix::Handle {
    cyxia_posix::unix::Handle::from_raw(process.socket(fd).unwrap().unwrap())
}

fn send(
    objects: &OpenDescriptions,
    sockets: &mut UnixSockets,
    process: &Process<'_>,
    transport: i32,
    fds: &[i32],
) -> cyxia_posix::ancillary::Ticket {
    let ticket = process.stage_rights(fds).unwrap();
    assert_eq!(
        sockets.write_message(
            process.backend_owner(transport).unwrap(),
            handle(process, transport),
            b"F",
            Some(ticket)
        ),
        Ok(1)
    );
    objects.commit_rights(ticket).unwrap();
    ticket
}

#[test]
fn two_socket_cycle_is_pinned_by_an_external_queued_reference_and_then_reclaimed() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let initial = sockets.capacity();
        let mut p = Process::empty(&objects, 1);
        let [a, ap] = pair(&mut p, &mut sockets, 1);
        let [b, bp] = pair(&mut p, &mut sockets, 1);
        let [tx, rx] = pair(&mut p, &mut sockets, 1);
        send(&objects, &mut sockets, &p, ap, &[b]);
        send(&objects, &mut sockets, &p, bp, &[a]);
        send(&objects, &mut sockets, &p, tx, &[a]);
        close(&objects, &mut fs, &mut sockets, &mut p, a);
        close(&objects, &mut fs, &mut sockets, &mut p, b);
        assert_eq!(objects.snapshot().inflight_messages, 3);
        assert!(!sockets.poll(1, handle(&p, ap)).unwrap().hangup);
        // Closing the external receive queue removes the sole root of the cycle.
        let result = close(&objects, &mut fs, &mut sockets, &mut p, rx);
        assert_eq!((result.messages, result.references), (3, 3));
        assert_eq!(objects.snapshot().inflight_messages, 0);
        assert!(sockets.poll(1, handle(&p, ap)).unwrap().hangup);
        assert!(sockets.poll(1, handle(&p, bp)).unwrap().hangup);
        for fd in [ap, bp, tx] {
            close(&objects, &mut fs, &mut sockets, &mut p, fd);
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(sockets.capacity(), initial);
    });
}

#[test]
fn staged_ownership_roots_a_cycle_until_the_cancelled_send_is_released() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let mut p = Process::empty(&objects, 1);
        let [a, b] = pair(&mut p, &mut sockets, 1);
        let staged = p.stage_rights(&[b]).unwrap();
        send(&objects, &mut sockets, &p, a, &[b]);
        close(&objects, &mut fs, &mut sockets, &mut p, b);
        assert_eq!(objects.snapshot().staged_references, 1);
        assert_eq!(objects.snapshot().inflight_references, 1);
        let result = objects
            .reclaim_socket_rights(&mut fs, &mut sockets, None, &[Some(staged)], true)
            .unwrap();
        assert_eq!(
            (result.messages, result.references, result.cancelled),
            (2, 2, 1)
        );
        assert_eq!(objects.snapshot().staged_references, 0);
        assert_eq!(objects.snapshot().inflight_references, 0);
        close(&objects, &mut fs, &mut sockets, &mut p, a);
        assert_eq!(objects.snapshot().live, 0);
    });
}

#[test]
fn longest_rooted_chain_preserves_all_hops_then_drains_without_recursive_release() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let initial = sockets.capacity();
        let mut p = Process::empty(&objects, 1);
        let count = (cyxia_posix::OPEN_MAX / 2).min(cyxia_posix::ancillary::MESSAGES + 1);
        let pairs: Vec<_> = (0..count).map(|_| pair(&mut p, &mut sockets, 1)).collect();
        for i in 1..count {
            send(&objects, &mut sockets, &p, pairs[i][0], &[pairs[i - 1][1]]);
        }
        for pair in pairs.iter().take(count - 1) {
            close(&objects, &mut fs, &mut sockets, &mut p, pair[1]);
            assert_eq!(objects.snapshot().inflight_messages, count - 1);
        }
        let result = close(&objects, &mut fs, &mut sockets, &mut p, pairs[count - 1][1]);
        assert_eq!((result.messages, result.references), (count - 1, count - 1));
        for pair in pairs {
            close(&objects, &mut fs, &mut sockets, &mut p, pair[0]);
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(sockets.capacity(), initial);
    });
}

#[test]
fn pending_accept_queue_is_owned_by_the_listener_even_when_listener_is_inflight_only() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let initial = sockets.capacity();
        let mut p = Process::empty(&objects, 1);
        let listener = sockets.socket(1).unwrap();
        let listener_fd = p.install_socket(listener.raw(), 0).unwrap();
        sockets
            .bind(1, listener, b"\0pending-socket-rights")
            .unwrap();
        sockets.listen(1, listener, 1).unwrap();
        let client = sockets.socket(1).unwrap();
        let client_fd = p.install_socket(client.raw(), 0).unwrap();
        sockets
            .connect(1, client, b"\0pending-socket-rights")
            .unwrap();
        let [service, transferred] = pair(&mut p, &mut sockets, 1);
        let service_ticket = send(&objects, &mut sockets, &p, client_fd, &[transferred]);
        close(&objects, &mut fs, &mut sockets, &mut p, transferred);
        assert_eq!(objects.snapshot().inflight_messages, 1);
        let [tx, rx] = pair(&mut p, &mut sockets, 1);
        let listener_ticket = send(&objects, &mut sockets, &p, tx, &[listener_fd]);
        close(&objects, &mut fs, &mut sockets, &mut p, listener_fd);
        assert_eq!(objects.snapshot().inflight_messages, 2);
        let mut byte = [0];
        assert_eq!(
            sockets.read_message(1, handle(&p, rx), &mut byte),
            Ok((1, Some(listener_ticket)))
        );
        let new_listener = p
            .receive_rights(&mut fs, listener_ticket, 1, true)
            .unwrap()
            .fds[0];
        for fd in [tx, rx] {
            close(&objects, &mut fs, &mut sockets, &mut p, fd);
        }
        let accepted = sockets.accept(1, listener).unwrap();
        let accepted_fd = p.install_socket(accepted.raw(), 0).unwrap();
        assert_eq!(
            sockets.read_message(1, accepted, &mut byte),
            Ok((1, Some(service_ticket)))
        );
        let new_service = p
            .receive_rights(&mut fs, service_ticket, 1, true)
            .unwrap()
            .fds[0];
        assert_eq!(sockets.write(1, handle(&p, service), b"P"), Ok(1));
        assert_eq!(sockets.read(1, handle(&p, new_service), &mut byte), Ok(1));
        for fd in [new_listener, client_fd, accepted_fd, service, new_service] {
            close(&objects, &mut fs, &mut sockets, &mut p, fd);
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(sockets.capacity(), initial);
    });
}

#[test]
fn closing_listener_detaches_unaccepted_rights_before_backend_release() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let initial = sockets.capacity();
        let mut p = Process::empty(&objects, 1);
        let listener = sockets.socket(1).unwrap();
        let fd = p.install_socket(listener.raw(), 0).unwrap();
        sockets
            .bind(1, listener, b"\0cancel-pending-rights")
            .unwrap();
        sockets.listen(1, listener, 1).unwrap();
        let client = sockets.socket(1).unwrap();
        let client_fd = p.install_socket(client.raw(), 0).unwrap();
        sockets
            .connect(1, client, b"\0cancel-pending-rights")
            .unwrap();
        let [a, b] = pair(&mut p, &mut sockets, 1);
        send(&objects, &mut sockets, &p, client_fd, &[b]);
        close(&objects, &mut fs, &mut sockets, &mut p, b);
        let result = close(&objects, &mut fs, &mut sockets, &mut p, fd);
        assert_eq!((result.messages, result.references), (1, 1));
        assert_eq!(sockets.read(1, handle(&p, a), &mut [0]), Ok(0));
        for fd in [a, client_fd] {
            close(&objects, &mut fs, &mut sockets, &mut p, fd);
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(sockets.capacity(), initial);
    });
}

#[test]
fn queued_self_reference_is_collected_only_after_last_real_fd_closes() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let mut process = Process::empty(&objects, 1);
        let [a, b] = sockets.socketpair(1).unwrap();
        let a_fd = process.install_socket(a.raw(), 0).unwrap();
        let b_fd = process.install_socket(b.raw(), 0).unwrap();
        let alias = process.dup(b_fd).unwrap();
        let ep = process.epoll_create(0).unwrap();
        process
            .epoll_ctl(
                ep,
                1,
                b_fd,
                cyxia_posix::epoll::Event {
                    events: cyxia_posix::epoll::IN,
                    data: 99,
                },
            )
            .unwrap();
        let ticket = process.stage_rights(&[b_fd]).unwrap();
        assert_eq!(sockets.write_message(1, a, b"S", Some(ticket)), Ok(1));
        objects.commit_rights(ticket).unwrap();
        let released = process.close(&mut fs, b_fd).unwrap();
        let result = objects
            .reclaim_socket_rights(&mut fs, &mut sockets, released, &[], false)
            .unwrap();
        assert_eq!(result.messages, 0);
        assert_eq!(objects.snapshot().inflight_references, 1);
        let released = process.close(&mut fs, alias).unwrap();
        let result = objects
            .reclaim_socket_rights(&mut fs, &mut sockets, released, &[], false)
            .unwrap();
        assert_eq!(
            result.messages, 1,
            "a weak epoll watch must not root a socket cycle"
        );
        assert_eq!(objects.snapshot().inflight_references, 0);
        assert_eq!(objects.snapshot().watches, 0);
        assert_eq!(sockets.read(1, a, &mut [0]), Ok(0));
        for fd in [a_fd, ep] {
            let released = process.close(&mut fs, fd).unwrap();
            objects
                .reclaim_socket_rights(&mut fs, &mut sockets, released, &[], false)
                .unwrap();
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(
            sockets.capacity().free_endpoints,
            cyxia_posix::unix::ENDPOINTS
        );
    });
}

#[test]
fn identical_control_layout_accepts_eventfd_before_any_payload_commit() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut process = Process::empty(&objects, 1);
        let event = process.eventfd(7, 0).unwrap();
        let mut wire = [0u8; 24];
        wire[..8].copy_from_slice(&20u64.to_le_bytes());
        wire[8..12].copy_from_slice(&1i32.to_le_bytes());
        wire[12..16].copy_from_slice(&1i32.to_le_bytes());
        wire[16..20].copy_from_slice(&event.to_le_bytes());
        let (fds, count) = cyxia_posix::ancillary::parse_control(&wire).unwrap();
        assert_eq!(count, 1);
        let ticket = process.stage_rights(&fds[..count]).unwrap();
        let (released, count) = objects.discard_rights(&mut fs, ticket).unwrap();
        assert_eq!(count, 1);
        assert!(released.into_iter().all(|r| r.is_none()));
        assert_eq!(process.close(&mut fs, event), Ok(None));
        assert_eq!(objects.snapshot().live, 0);
    });
}

#[test]
fn connected_socket_is_pinned_until_received_after_creator_closes_it() {
    fixture(|| {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sockets = UnixSockets::new();
        let mut creator = Process::empty(&objects, 11);
        let mut receiver = Process::empty(&objects, 22);
        let [a, b] = sockets.socketpair(11).unwrap();
        let a_fd = creator.install_socket(a.raw(), 0).unwrap();
        let b_fd = creator.install_socket(b.raw(), O_CLOEXEC).unwrap();
        let [tx, rx] = sockets.socketpair(22).unwrap();
        let tx_fd = receiver.install_socket(tx.raw(), 0).unwrap();
        let rx_fd = receiver.install_socket(rx.raw(), 0).unwrap();
        let ticket = creator
            .stage_rights(&[b_fd])
            .expect("connected sockets must support SCM_RIGHTS");
        assert_eq!(sockets.write_message(22, tx, b"F", Some(ticket)), Ok(1));
        objects.commit_rights(ticket).unwrap();
        assert_eq!(creator.close(&mut fs, b_fd), Ok(None));
        let mut byte = [0];
        assert_eq!(
            sockets.read_message(22, rx, &mut byte),
            Ok((1, Some(ticket)))
        );
        let received = receiver.receive_rights(&mut fs, ticket, 1, true).unwrap();
        let fd = received.fds[0];
        assert_eq!(received.count, 1);
        assert_eq!(receiver.backend_owner(fd), Ok(11));
        assert_eq!(receiver.socket(fd), Ok(Some(b.raw())));
        assert_eq!(receiver.close_on_exec(fd), Ok(true));
        assert_eq!(sockets.write(11, a, b"Q"), Ok(1));
        assert_eq!(sockets.read(11, b, &mut byte), Ok(1));
        assert_eq!(byte, *b"Q");
        for released in [
            receiver.close(&mut fs, fd).unwrap(),
            creator.close(&mut fs, a_fd).unwrap(),
            receiver.close(&mut fs, tx_fd).unwrap(),
            receiver.close(&mut fs, rx_fd).unwrap(),
        ] {
            if let Some(Released::Socket { owner, handle }) = released {
                sockets
                    .close(owner, cyxia_posix::unix::Handle::from_raw(handle))
                    .unwrap();
            }
        }
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(objects.snapshot().inflight_references, 0);
        assert_eq!(
            sockets.capacity().free_endpoints,
            cyxia_posix::unix::ENDPOINTS
        );
    });
}
