//! Strong SCM_RIGHTS references, independent of sender descriptor tables.
//! Fixed metadata is bootstrapped. The kernel admits logical message/reference
//! occupancy before staging; this mechanism never runs policy during cleanup.
use crate::{Errno, Object, OpenDescriptions, Process, Released, open_description::Handle};
use cyxia_ai_fs::FileSystem;
pub const MAX_RIGHTS: usize = 8;
pub const MESSAGES: usize = 16;
pub const REFERENCES: usize = 64;
const EMPTY_HANDLE: Handle = Handle {
    slot: 0,
    generation: 0,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket {
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Free,
    Staged,
    Inflight,
}
#[derive(Clone, Copy)]
pub(crate) struct Slot {
    generation: u64,
    pub(crate) state: State,
    handles: [Handle; MAX_RIGHTS],
    count: usize,
}
impl Slot {
    pub(crate) const EMPTY: Self = Self {
        generation: 0,
        state: State::Free,
        handles: [EMPTY_HANDLE; MAX_RIGHTS],
        count: 0,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    pub messages: usize,
    pub references: usize,
}
/// Actual receive result. Excess references are released, never installed.
pub struct Received {
    pub fds: [i32; MAX_RIGHTS],
    pub count: usize,
    pub truncated: bool,
    pub released: [Option<Released>; MAX_RIGHTS],
    pub original_count: usize,
}
impl OpenDescriptions {
    pub fn rights_capacity(&self) -> Capacity {
        let t = self.inner.borrow();
        Capacity {
            messages: t
                .rights
                .iter()
                .filter(|s| s.state == State::Free && s.generation < u64::MAX)
                .count(),
            references: REFERENCES - t.rights.iter().map(|s| s.count).sum::<usize>(),
        }
    }
    fn rights_slot(&self, ticket: Ticket) -> Result<Slot, Errno> {
        self.inner
            .borrow()
            .rights
            .get(ticket.slot)
            .copied()
            .filter(|s| s.generation == ticket.generation && s.state != State::Free)
            .ok_or(Errno::Badf)
    }
    pub fn rights_count(&self, ticket: Ticket) -> Result<usize, Errno> {
        Ok(self.rights_slot(ticket)?.count)
    }
    /// Commit cannot allocate: the staged ticket already owns all references.
    pub fn commit_rights(&self, ticket: Ticket) -> Result<(), Errno> {
        let slot = self.rights_slot(ticket)?;
        if slot.state != State::Staged {
            return Err(Errno::Badf);
        }
        let mut t = self.inner.borrow_mut();
        for h in &slot.handles[..slot.count] {
            let entry = &mut t.entries[h.slot];
            entry.staged -= 1;
            entry.inflight += 1;
        }
        t.rights[ticket.slot].state = State::Inflight;
        Ok(())
    }
    /// Both abort and discard use the same final-release path as close(2).
    pub fn discard_rights(
        &self,
        fs: &mut FileSystem,
        ticket: Ticket,
    ) -> Result<([Option<Released>; MAX_RIGHTS], usize), Errno> {
        let slot = self.rights_slot(ticket)?;
        let kind = if slot.state == State::Staged { 1 } else { 2 };
        let mut releases = [None; MAX_RIGHTS];
        for (out, h) in releases.iter_mut().zip(&slot.handles[..slot.count]) {
            *out = self.release_kind(fs, *h, kind)?;
        }
        let mut t = self.inner.borrow_mut();
        t.rights[ticket.slot].state = State::Free;
        t.rights[ticket.slot].count = 0;
        Ok((releases, slot.count))
    }
}
impl Process<'_> {
    pub fn validate_rights(&self, descriptors: &[i32]) -> Result<(), Errno> {
        if descriptors.is_empty() || descriptors.len() > MAX_RIGHTS {
            return Err(Errno::Inval);
        }
        for fd in descriptors {
            let h = self.description(*fd)?;
            let object = self.objects.get(h)?.object;
            if !matches!(
                object,
                Object::File(_)
                    | Object::ReadOnly(..)
                    | Object::Pipe(_)
                    | Object::Event { .. }
                    | Object::Memfd(_)
            ) {
                return Err(Errno::Nosys);
            }
        }
        Ok(())
    }
    /// Validate the entire list before reserving any reference. Duplicate FDs
    /// intentionally reserve duplicate references and yield distinct received FDs.
    pub fn stage_rights(&self, descriptors: &[i32]) -> Result<Ticket, Errno> {
        self.validate_rights(descriptors)?;
        let capacity = self.objects.rights_capacity();
        if capacity.messages == 0 || capacity.references < descriptors.len() {
            return Err(Errno::Nobufs);
        }
        let mut handles = [EMPTY_HANDLE; MAX_RIGHTS];
        for (h, fd) in handles.iter_mut().zip(descriptors) {
            *h = self.description(*fd)?;
        }
        let mut t = self.objects.inner.borrow_mut();
        for h in &handles[..descriptors.len()] {
            let e = t.entry(*h)?;
            let copies = handles[..descriptors.len()]
                .iter()
                .filter(|other| *other == h)
                .count() as u16;
            e.references.checked_add(copies).ok_or(Errno::Overflow)?;
        }
        let index = t
            .rights
            .iter()
            .position(|s| s.state == State::Free && s.generation < u64::MAX)
            .ok_or(Errno::Nobufs)?;
        let generation = t.rights[index].generation + 1;
        for h in &handles[..descriptors.len()] {
            t.entries[h.slot].references += 1;
            t.entries[h.slot].staged += 1;
        }
        t.rights[index] = Slot {
            generation,
            state: State::Staged,
            handles,
            count: descriptors.len(),
        };
        Ok(Ticket {
            slot: index,
            generation,
        })
    }
    /// User output memory must be validated before this non-interleaved commit.
    /// No allocation is needed; references move directly from flight to FD slots.
    pub fn receive_rights(
        &mut self,
        fs: &mut FileSystem,
        ticket: Ticket,
        limit: usize,
        cloexec: bool,
    ) -> Result<Received, Errno> {
        let slot = self.objects.rights_slot(ticket)?;
        if slot.state != State::Inflight {
            return Err(Errno::Badf);
        }
        let count = slot
            .count
            .min(limit)
            .min(self.fds.iter().filter(|f| f.is_none()).count());
        let mut out = Received {
            fds: [-1; MAX_RIGHTS],
            count,
            truncated: count < slot.count,
            released: [None; MAX_RIGHTS],
            original_count: slot.count,
        };
        for (i, h) in slot.handles[..slot.count].iter().enumerate() {
            if i < count {
                let fd = self.free_fd()?;
                self.objects.inner.borrow_mut().entries[h.slot].inflight -= 1;
                self.fds[fd] = Some(*h);
                self.cloexec[fd] = cloexec;
                out.fds[i] = fd as i32;
            } else {
                out.released[i] = self.objects.release_kind(fs, *h, 2)?;
            }
        }
        let mut t = self.objects.inner.borrow_mut();
        t.rights[ticket.slot].state = State::Free;
        t.rights[ticket.slot].count = 0;
        Ok(out)
    }
}
/// Parse all AArch64 control headers before the caller commits payload. Only
/// SOL_SOCKET/SCM_RIGHTS is supported. Alignment padding has no semantic content.
pub fn parse_control(bytes: &[u8]) -> Result<([i32; MAX_RIGHTS], usize), Errno> {
    let mut fds = [-1; MAX_RIGHTS];
    let mut count = 0;
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(Errno::Inval);
        }
        let h = &bytes[offset..];
        let len = usize::try_from(u64::from_le_bytes(h[..8].try_into().unwrap()))
            .map_err(|_| Errno::Inval)?;
        if len < 16 || len > h.len() || (len - 16) % 4 != 0 {
            return Err(Errno::Inval);
        }
        if i32::from_le_bytes(h[8..12].try_into().unwrap()) != 1
            || i32::from_le_bytes(h[12..16].try_into().unwrap()) != 1
        {
            return Err(Errno::Nosys);
        }
        let n = (len - 16) / 4;
        if n == 0 || count + n > MAX_RIGHTS {
            return Err(Errno::Inval);
        }
        for raw in h[16..len].chunks_exact(4) {
            let fd = i32::from_le_bytes(raw.try_into().unwrap());
            if fd < 0 {
                return Err(Errno::Badf);
            }
            fds[count] = fd;
            count += 1;
        }
        let aligned = len.checked_add(7).ok_or(Errno::Inval)? & !7;
        if aligned >= h.len() {
            break;
        }
        offset = offset.checked_add(aligned).ok_or(Errno::Inval)?;
    }
    Ok((fds, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Console, O_CLOEXEC, O_CREAT, O_NONBLOCK, O_RDWR, epoll,
        unix::{BUFFER_BYTES, UnixSockets},
    };
    struct Sink;
    impl Console for Sink {
        fn write(&mut self, b: &[u8]) -> Result<usize, Errno> {
            Ok(b.len())
        }
    }
    fn discard(objects: &OpenDescriptions, fs: &mut FileSystem, ticket: Ticket) {
        let (released, _) = objects.discard_rights(fs, ticket).unwrap();
        assert!(released.iter().all(Option::is_none));
    }
    fn send(
        objects: &OpenDescriptions,
        p: &Process<'_>,
        s: &mut UnixSockets,
        peer: crate::unix::Handle,
        bytes: &[u8],
        fds: &[i32],
    ) -> Ticket {
        let ticket = p.stage_rights(fds).unwrap();
        assert_eq!(
            s.write_message(1, peer, bytes, Some(ticket)),
            Ok(bytes.len())
        );
        objects.commit_rights(ticket).unwrap();
        ticket
    }
    #[test]
    fn unlinked_file_is_pinned_by_staging_and_flight_then_shared_offset_and_cloexec() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sender = Process::new(&objects, 1).unwrap();
        let f = sender
            .open(&mut fs, "/held", O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
            .unwrap();
        sender.write(&mut fs, &mut Sink, f, b"abcdef").unwrap();
        sender.lseek(&fs, f, 0, 0).unwrap();
        let ticket = sender.stage_rights(&[f, f]).unwrap();
        sender.unlink(&mut fs, "/held").unwrap();
        sender.close_all(&mut fs).unwrap();
        assert_eq!(
            (
                objects.snapshot().fd_references,
                objects.snapshot().staged_references
            ),
            (0, 2)
        );
        objects.commit_rights(ticket).unwrap();
        assert_eq!(
            (
                objects.snapshot().staged_references,
                objects.snapshot().inflight_references
            ),
            (0, 2)
        );
        let mut receiver = Process::empty(&objects, 2);
        let got = receiver.receive_rights(&mut fs, ticket, 8, true).unwrap();
        assert_eq!(got.count, 2);
        assert!(!got.truncated);
        assert_ne!(got.fds[0], got.fds[1]);
        assert_eq!(receiver.close_on_exec(got.fds[0]), Ok(true));
        receiver.set_close_on_exec(got.fds[0], false).unwrap();
        assert_eq!(receiver.close_on_exec(got.fds[1]), Ok(true));
        receiver.set_flags(got.fds[0], O_NONBLOCK).unwrap();
        assert_eq!(receiver.flags(got.fds[0]), receiver.flags(got.fds[1]));
        let mut bytes = [0; 2];
        receiver.read(&mut fs, got.fds[0], &mut bytes).unwrap();
        assert_eq!(&bytes, b"ab");
        receiver.read(&mut fs, got.fds[1], &mut bytes).unwrap();
        assert_eq!(&bytes, b"cd");
        assert_eq!(receiver.fstat(&fs, got.fds[0]).unwrap().links, 0);
        receiver.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
        // Repeated unlink/discard must free inode slots, not only OFD slots.
        for _ in 0..64 {
            let f = sender
                .open(&mut fs, "/held", O_CREAT | O_RDWR, 0o600)
                .unwrap();
            let t = sender.stage_rights(&[f]).unwrap();
            sender.unlink(&mut fs, "/held").unwrap();
            sender.close(&mut fs, f).unwrap();
            discard(&objects, &mut fs, t);
        }
        assert_eq!(objects.snapshot().references, 0);
    }
    #[test]
    fn flight_keeps_weak_watch_until_final_discard_without_any_descriptor() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let event = p.eventfd(7, 0).unwrap();
        let ep = p.epoll_create(0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            event,
            epoll::Event {
                events: epoll::IN,
                data: 19,
            },
        )
        .unwrap();
        let t = p.stage_rights(&[event]).unwrap();
        p.close(&mut fs, event).unwrap();
        objects.commit_rights(t).unwrap();
        assert_eq!(objects.snapshot().watches, 1);
        assert!(matches!(
            p.epoll_sources(ep).unwrap()[0],
            Some(epoll::Source::Local { read: true, .. })
        ));
        discard(&objects, &mut fs, t);
        assert_eq!(objects.snapshot().watches, 0);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn all_validation_and_capacity_failures_leave_reference_classes_unchanged() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let event = p.eventfd(1, 0).unwrap();
        let socket = p.install_socket(99, 0).unwrap();
        let ep = p.epoll_create(0).unwrap();
        let pty = p.install_pty(123, 0).unwrap();
        let dir = p.open(&mut fs, "/", crate::O_DIRECTORY, 0).unwrap();
        let before = objects.snapshot();
        for unsupported in [0, socket, ep, pty, dir] {
            assert_eq!(p.stage_rights(&[event, unsupported]), Err(Errno::Nosys));
            assert_eq!(objects.snapshot(), before);
        }
        assert_eq!(p.stage_rights(&[event, 99]), Err(Errno::Badf));
        assert_eq!(p.stage_rights(&[]), Err(Errno::Inval));
        let tickets = core::array::from_fn::<_, 8, _>(|_| p.stage_rights(&[event; 8]).unwrap());
        assert_eq!(objects.rights_capacity().references, 0);
        let full = objects.snapshot();
        assert_eq!(p.stage_rights(&[event]), Err(Errno::Nobufs));
        assert_eq!(objects.snapshot(), full);
        for t in tickets {
            discard(&objects, &mut fs, t);
            assert_eq!(objects.discard_rights(&mut fs, t), Err(Errno::Badf));
        }
        assert_eq!(objects.snapshot(), before);
    }
    #[test]
    fn receive_installs_only_fit_prefix_and_never_inherits_sender_cloexec() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut sender = Process::empty(&objects, 1);
        let e = sender.eventfd(6, O_CLOEXEC).unwrap();
        let t = sender.stage_rights(&[e, e, e]).unwrap();
        objects.commit_rights(t).unwrap();
        let mut receiver = Process::empty(&objects, 2);
        for _ in 0..15 {
            receiver.eventfd(0, 0).unwrap();
        }
        let got = receiver.receive_rights(&mut fs, t, 2, false).unwrap();
        assert_eq!(got.count, 1);
        assert!(got.truncated);
        assert_eq!(receiver.close_on_exec(got.fds[0]), Ok(false));
        let mut bytes = [0; 8];
        receiver.read(&mut fs, got.fds[0], &mut bytes).unwrap();
        assert_eq!(u64::from_le_bytes(bytes), 6);
        assert_eq!(sender.read(&mut fs, e, &mut bytes), Err(Errno::Again));
        let t = sender.stage_rights(&[e, e]).unwrap();
        objects.commit_rights(t).unwrap();
        let got = receiver.receive_rights(&mut fs, t, 8, false).unwrap();
        assert_eq!(got.count, 0);
        assert!(got.truncated);
        receiver.close_all(&mut fs).unwrap();
        sender.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn barriers_short_reads_and_short_writes_deliver_each_ticket_once() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let e = p.eventfd(1, 0).unwrap();
        let mut sockets = UnixSockets::new();
        let [a, b] = sockets.socketpair(1).unwrap();
        sockets.write(1, a, b"abcd").unwrap();
        let t = send(&objects, &p, &mut sockets, a, b"efgh", &[e]);
        sockets.write(1, a, b"ijkl").unwrap();
        let mut out = [0; 32];
        assert_eq!(
            sockets.read_message(1, b, &mut out[..4]).unwrap(),
            (4, None)
        );
        assert_eq!(
            sockets.read_message(1, b, &mut out[..1]).unwrap(),
            (1, Some(t))
        );
        discard(&objects, &mut fs, t);
        assert_eq!(sockets.read_message(1, b, &mut out).unwrap(), (7, None));
        assert_eq!(&out[..7], b"fghijkl");
        sockets.write(1, a, &[0; BUFFER_BYTES - 2]).unwrap();
        let t = p.stage_rights(&[e]).unwrap();
        assert_eq!(sockets.write_message(1, a, b"1234", Some(t)), Ok(2));
        objects.commit_rights(t).unwrap();
        let mut big = [0; BUFFER_BYTES];
        assert_eq!(
            sockets.read_message(1, b, &mut big).unwrap(),
            (BUFFER_BYTES, Some(t))
        );
        discard(&objects, &mut fs, t);
        assert_eq!(&big[BUFFER_BYTES - 2..], b"12");
        sockets.close(1, a).unwrap();
        sockets.close(1, b).unwrap();
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn zero_and_eagain_write_never_publish_ticket_and_cancel_reclaims_staging() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let e = p.eventfd(1, 0).unwrap();
        let mut sockets = UnixSockets::new();
        let [a, b] = sockets.socketpair(1).unwrap();
        let t = p.stage_rights(&[e]).unwrap();
        assert_eq!(sockets.write_message(1, a, b"", Some(t)), Err(Errno::Inval));
        sockets.write(1, a, &[0; BUFFER_BYTES]).unwrap();
        assert_eq!(
            sockets.write_message(1, a, b"x", Some(t)),
            Err(Errno::Again)
        );
        assert_eq!(objects.snapshot().inflight_references, 0);
        discard(&objects, &mut fs, t);
        assert_eq!(objects.snapshot().staged_references, 0);
        sockets.close(1, a).unwrap();
        sockets.close(1, b).unwrap();
    }
    #[test]
    fn shutdown_sender_close_receiver_close_and_pending_accept_release_exactly_once() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let e = p.eventfd(1, 0).unwrap();
        let mut s = UnixSockets::new();
        let [a, b] = s.socketpair(1).unwrap();
        let t = send(&objects, &p, &mut s, a, b"data", &[e]);
        s.shutdown_with(1, a, 1, &mut |_| panic!("SHUT_WR discarded peer data"))
            .unwrap();
        s.close_with(1, a, &mut |_| panic!("sender close discarded peer data"))
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(s.read_message(1, b, &mut bytes).unwrap(), (4, Some(t)));
        discard(&objects, &mut fs, t);
        s.close(1, b).unwrap();
        let [a, b] = s.socketpair(1).unwrap();
        send(&objects, &p, &mut s, a, b"x", &[e, e]);
        let mut disposed = 0;
        s.shutdown_with(1, b, 0, &mut |t| {
            disposed += 1;
            discard(&objects, &mut fs, t);
        })
        .unwrap();
        assert_eq!(disposed, 1);
        s.close(1, a).unwrap();
        s.close(1, b).unwrap();
        let server = s.socket(1).unwrap();
        s.bind(1, server, b"/scm").unwrap();
        s.listen(1, server, 2).unwrap();
        let client = s.socket(1).unwrap();
        s.connect(1, client, b"/scm").unwrap();
        send(&objects, &p, &mut s, client, b"pending", &[e]);
        s.close_with(1, server, &mut |t| {
            disposed += 1;
            discard(&objects, &mut fs, t);
        })
        .unwrap();
        assert_eq!(disposed, 2);
        s.close(1, client).unwrap();
        assert_eq!(objects.snapshot().inflight_references, 0);
    }
    #[test]
    fn discarded_pipe_right_is_real_final_backend_close_after_creator_exit() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 7);
        let mut pipes = crate::pipe::Pipes::new();
        let raw = pipes.pair(7).unwrap();
        let fds = p.install_pipe(raw, 0).unwrap();
        let t = p.stage_rights(&fds).unwrap();
        assert!(p.close_all(&mut fs).unwrap().iter().all(Option::is_none));
        objects.commit_rights(t).unwrap();
        assert_eq!(pipes.free(), crate::pipe::PIPES - 1);
        let (released, n) = objects.discard_rights(&mut fs, t).unwrap();
        assert_eq!(n, 2);
        for r in released.into_iter().flatten() {
            let Released::Pipe { owner, handle } = r else {
                panic!("wrong release")
            };
            pipes.close(owner, handle).unwrap();
        }
        assert_eq!(pipes.free(), crate::pipe::PIPES);
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn memfd_passes_same_description_offset_and_releases_backend_only_once() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let f = p.install_memfd(123, 0).unwrap();
        p.set_memfd_position(f, 71).unwrap();
        let t = p.stage_rights(&[f, f]).unwrap();
        p.close(&mut fs, f).unwrap();
        objects.commit_rights(t).unwrap();
        let mut q = Process::empty(&objects, 2);
        let got = q.receive_rights(&mut fs, t, 8, false).unwrap();
        assert_eq!(
            q.memfd_position(got.fds[0], false).unwrap(),
            (123, 71, O_RDWR)
        );
        q.set_memfd_position(got.fds[1], 99).unwrap();
        assert_eq!(q.memfd_position(got.fds[0], false).unwrap().1, 99);
        assert_eq!(q.close(&mut fs, got.fds[0]).unwrap(), None);
        assert_eq!(
            q.close(&mut fs, got.fds[1]).unwrap(),
            Some(Released::Memfd { handle: 123 })
        );
    }
    #[test]
    fn control_parser_validates_whole_aligned_chain_before_any_staging() {
        let mut wire = [0u8; 48];
        for h in wire.chunks_exact_mut(24) {
            h[..8].copy_from_slice(&20u64.to_le_bytes());
            h[8..12].copy_from_slice(&1i32.to_le_bytes());
            h[12..16].copy_from_slice(&1i32.to_le_bytes());
            h[16..20].copy_from_slice(&4i32.to_le_bytes());
        }
        let (fds, n) = parse_control(&wire).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&fds[..n], &[4, 4]);
        assert_eq!(parse_control(&wire[..20]).unwrap().1, 1);
        wire[24 + 12..24 + 16].copy_from_slice(&2i32.to_le_bytes());
        assert_eq!(parse_control(&wire), Err(Errno::Nosys));
        wire[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(parse_control(&wire), Err(Errno::Inval));
        wire[..8].copy_from_slice(&19u64.to_le_bytes());
        assert_eq!(parse_control(&wire[..24]), Err(Errno::Inval));
        assert_eq!(parse_control(&[0; 15]), Err(Errno::Inval));
    }
    #[test]
    fn bounded_message_pool_and_receiver_close_reclaim_every_committed_ticket() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let e = p.eventfd(1, 0).unwrap();
        let mut sockets = UnixSockets::new();
        let [a, b] = sockets.socketpair(1).unwrap();
        for _ in 0..MESSAGES {
            send(&objects, &p, &mut sockets, a, b"x", &[e]);
        }
        assert_eq!(objects.rights_capacity().messages, 0);
        assert!(sockets.poll(1, a).unwrap().writable); // Bytes have space, metadata does not.
        let full = objects.snapshot();
        assert_eq!(p.stage_rights(&[e]), Err(Errno::Nobufs));
        assert_eq!(objects.snapshot(), full);
        p.close_all(&mut fs).unwrap();
        let mut n = 0;
        sockets
            .close_with(1, b, &mut |t| {
                n += 1;
                discard(&objects, &mut fs, t);
            })
            .unwrap();
        assert_eq!(n, MESSAGES);
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(objects.snapshot().inflight_messages, 0);
        assert_eq!(
            objects.rights_capacity(),
            Capacity {
                messages: MESSAGES,
                references: REFERENCES
            }
        );
        sockets.close(1, a).unwrap();
    }
    #[test]
    fn stale_tickets_cannot_commit_discard_or_receive_reused_queue_slot() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let e = p.eventfd(1, 0).unwrap();
        let stale = p.stage_rights(&[e]).unwrap();
        discard(&objects, &mut fs, stale);
        let current = p.stage_rights(&[e]).unwrap();
        assert_ne!(stale, current);
        let before = objects.snapshot();
        assert_eq!(objects.commit_rights(stale), Err(Errno::Badf));
        assert!(matches!(
            p.receive_rights(&mut fs, stale, 8, false),
            Err(Errno::Badf)
        ));
        assert_eq!(objects.discard_rights(&mut fs, stale), Err(Errno::Badf));
        assert_eq!(objects.snapshot(), before);
        objects.commit_rights(current).unwrap();
        let committed = objects.snapshot();
        assert_eq!(objects.commit_rights(current), Err(Errno::Badf));
        assert_eq!(objects.snapshot(), committed);
        discard(&objects, &mut fs, current);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
}
