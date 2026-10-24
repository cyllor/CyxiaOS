//! Shared, bounded open descriptions. The supervisor serializes access; this
//! crate stays safe and allocation-free. The 128 entries replace the existing
//! 8 admitted processes × 16 private entries, not a new resource-policy range.
use super::{Description, Errno, OPEN_MAX, Object, epoll};
use core::cell::RefCell;
use cyxia_ai_fs::FileSystem;

pub const CAPACITY: usize = super::usermem::MAX_PROCESSES * OPEN_MAX;
pub(crate) const EPOLLS: usize = super::usermem::MAX_PROCESSES * epoll::INSTANCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Handle {
    pub slot: usize,
    pub generation: u64,
}
impl Handle {
    pub(crate) fn identity(self) -> u64 {
        (self.generation << 8) | self.slot as u64
    }
}
const MAX_GENERATION: u64 = u64::MAX >> 8;

/// Final-reference cleanup, including the stable backend capability identity.
/// The resource owner is not the PID making an operation (e.g. TIOCSCTTY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Released {
    Socket { owner: u32, handle: u64 },
    Pipe { owner: u32, handle: u64 },
    Pty { owner: u32, handle: u64 },
    Memfd { handle: u64 },
}

#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub(crate) generation: u64,
    pub(crate) references: u16,
    pub(crate) staged: u16,
    pub(crate) inflight: u16,
    pub(crate) owner: u32,
    pub(crate) value: Option<Description>,
}
impl Entry {
    const EMPTY: Self = Self {
        generation: 0,
        references: 0,
        staged: 0,
        inflight: 0,
        owner: 0,
        value: None,
    };
}
pub(crate) struct Table {
    pub(crate) entries: [Entry; CAPACITY],
    pub(crate) rights: [super::ancillary::Slot; super::ancillary::MESSAGES],
    pub epolls: [epoll::Instance; EPOLLS],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub capacity: usize,
    pub live: usize,
    pub references: usize,
    pub fd_references: usize,
    pub staged_references: usize,
    pub inflight_references: usize,
    pub staged_messages: usize,
    pub inflight_messages: usize,
    pub retired: usize,
    pub epolls: usize,
    pub watches: usize,
}
pub struct OpenDescriptions {
    pub(crate) inner: RefCell<Table>,
}
impl Default for OpenDescriptions {
    fn default() -> Self {
        Self::new()
    }
}
impl OpenDescriptions {
    pub const fn new() -> Self {
        Self {
            inner: RefCell::new(Table {
                entries: [Entry::EMPTY; CAPACITY],
                rights: [super::ancillary::Slot::EMPTY; super::ancillary::MESSAGES],
                epolls: [epoll::Instance::EMPTY; EPOLLS],
            }),
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        let table = self.inner.borrow();
        Snapshot {
            capacity: CAPACITY,
            live: table.entries.iter().filter(|e| e.value.is_some()).count(),
            references: table
                .entries
                .iter()
                .map(|e| usize::from(e.references))
                .sum(),
            fd_references: table
                .entries
                .iter()
                .map(|e| usize::from(e.references - e.staged - e.inflight))
                .sum(),
            staged_references: table.entries.iter().map(|e| usize::from(e.staged)).sum(),
            inflight_references: table.entries.iter().map(|e| usize::from(e.inflight)).sum(),
            staged_messages: table
                .rights
                .iter()
                .filter(|s| s.state == super::ancillary::State::Staged)
                .count(),
            inflight_messages: table
                .rights
                .iter()
                .filter(|s| s.state == super::ancillary::State::Inflight)
                .count(),
            retired: table
                .entries
                .iter()
                .filter(|e| e.value.is_none() && e.generation == MAX_GENERATION)
                .count(),
            epolls: table.epolls.iter().filter(|e| e.used).count(),
            watches: table.epolls.iter().map(|e| e.watch_count()).sum(),
        }
    }
    pub(crate) fn free_slots<const N: usize>(&self) -> Result<[Handle; N], Errno> {
        let mut slots = [Handle {
            slot: 0,
            generation: 0,
        }; N];
        self.free_into(&mut slots)?;
        Ok(slots)
    }
    pub(crate) fn free_into(&self, slots: &mut [Handle]) -> Result<(), Errno> {
        let table = self.inner.borrow();
        let mut free = table
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.value.is_none() && e.generation < MAX_GENERATION);
        for out in slots {
            let (slot, entry) = free.next().ok_or(Errno::Mfile)?;
            *out = Handle {
                slot,
                generation: entry.generation + 1,
            };
        }
        Ok(())
    }
    pub(crate) fn create(
        &self,
        handle: Handle,
        owner: u32,
        value: Description,
    ) -> Result<(), Errno> {
        let mut table = self.inner.borrow_mut();
        let entry = table.entries.get_mut(handle.slot).ok_or(Errno::Badf)?;
        if entry.value.is_some()
            || entry.generation.checked_add(1) != Some(handle.generation)
            || handle.generation > MAX_GENERATION
        {
            return Err(Errno::Badf);
        }
        *entry = Entry {
            generation: handle.generation,
            references: 1,
            staged: 0,
            inflight: 0,
            owner,
            value: Some(value),
        };
        Ok(())
    }
    pub(crate) fn get(&self, handle: Handle) -> Result<Description, Errno> {
        let table = self.inner.borrow();
        table.entry(handle)?.value.ok_or(Errno::Badf)
    }
    pub(crate) fn owner(&self, handle: Handle) -> Result<u32, Errno> {
        Ok(self.inner.borrow().entry(handle)?.owner)
    }
    pub(crate) fn references(&self, handle: Handle) -> Result<u16, Errno> {
        Ok(self.inner.borrow().entry(handle)?.references)
    }
    pub(crate) fn update(&self, handle: Handle, description: Description) -> Result<(), Errno> {
        let mut table = self.inner.borrow_mut();
        table.entry(handle)?;
        table.entries[handle.slot].value = Some(description);
        Ok(())
    }
    pub(crate) fn retain(&self, handle: Handle) -> Result<(), Errno> {
        let mut table = self.inner.borrow_mut();
        let references = table
            .entry(handle)?
            .references
            .checked_add(1)
            .ok_or(Errno::Overflow)?;
        table.entries[handle.slot].references = references;
        Ok(())
    }
    /// Weak watches do not count as references, and are removed only on actual
    /// OFD final release (or explicit DEL / destruction of their epoll instance).
    pub(crate) fn release(
        &self,
        fs: &mut FileSystem,
        handle: Handle,
    ) -> Result<Option<Released>, Errno> {
        self.release_kind(fs, handle, 0)
    }
    pub(crate) fn release_kind(
        &self,
        fs: &mut FileSystem,
        handle: Handle,
        kind: u8,
    ) -> Result<Option<Released>, Errno> {
        let mut table = self.inner.borrow_mut();
        let entry = *table.entry(handle)?;
        let class_refs = match kind {
            0 => entry.references - entry.staged - entry.inflight,
            1 => entry.staged,
            2 => entry.inflight,
            _ => return Err(Errno::Inval),
        };
        if class_refs == 0 {
            return Err(Errno::Badf);
        }
        if entry.references == 1
            && let Object::File(inode)
            | Object::Directory {
                inode: Some(inode), ..
            } = entry.value.ok_or(Errno::Badf)?.object
        {
            fs.unpin(inode)?;
        }
        if kind == 1 {
            table.entries[handle.slot].staged -= 1;
        }
        if kind == 2 {
            table.entries[handle.slot].inflight -= 1;
        }
        if entry.references > 1 {
            table.entries[handle.slot].references -= 1;
            return Ok(None);
        }
        let description = entry.value.ok_or(Errno::Badf)?;
        if let Object::Epoll(index) = description.object {
            table.epolls[index] = epoll::Instance::EMPTY;
        }
        for instance in &mut table.epolls {
            instance.remove_description(handle);
        }
        table.entries[handle.slot].value = None;
        table.entries[handle.slot].references = 0;
        let owner = entry.owner;
        Ok(match description.object {
            Object::Socket(handle) => Some(Released::Socket { owner, handle }),
            Object::Pipe(handle) => Some(Released::Pipe { owner, handle }),
            Object::Pty(handle) => Some(Released::Pty { owner, handle }),
            Object::Memfd(handle) => Some(Released::Memfd { handle }),
            _ => None,
        })
    }
}
impl Table {
    pub(crate) fn entry(&self, handle: Handle) -> Result<&Entry, Errno> {
        self.entries
            .get(handle.slot)
            .filter(|e| e.generation == handle.generation && e.references != 0 && e.value.is_some())
            .ok_or(Errno::Badf)
    }
}

const _: () = assert!(CAPACITY <= 256);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Console, O_APPEND, O_CLOEXEC, O_CREAT, O_NONBLOCK, O_RDWR, Process, spawn::Mapping,
    };
    use cyxia_ai_fs::FileSystem;
    struct Sink;
    impl Console for Sink {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
            Ok(bytes.len())
        }
    }
    fn mapping(source: i32, target: i32) -> Mapping {
        Mapping { source, target }
    }
    fn local_ready(process: &mut Process<'_>, ep: i32) -> (usize, epoll::Event) {
        let sources = process.epoll_sources(ep).unwrap();
        let ready = core::array::from_fn(|i| match sources[i] {
            Some(epoll::Source::Local { read, write }) => u32::from(read) | (u32::from(write) << 2),
            None => 0,
            _ => panic!("expected local object"),
        });
        let mut out = [epoll::Event::default(); 1];
        (process.epoll_collect(ep, &ready, &mut out).unwrap(), out[0])
    }
    #[test]
    fn inherited_file_shares_offset_flags_and_unlinked_inode_after_creator_exit() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut parent = Process::new(&objects, 10).unwrap();
        let file = parent
            .open(&mut fs, "/shared", O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
            .unwrap();
        parent.write(&mut fs, &mut Sink, file, b"abcdef").unwrap();
        parent.lseek(&fs, file, 0, 0).unwrap();
        let mut child = parent
            .spawn_descriptors(&fs, None, &[mapping(file, 5), mapping(file, 6)], 20)
            .unwrap();
        assert_eq!(child.close_on_exec(5), Ok(false));
        child.set_close_on_exec(5, true).unwrap();
        assert_eq!(child.close_on_exec(6), Ok(false));
        child.set_flags(5, O_NONBLOCK | O_APPEND).unwrap();
        // F_GETFL exposes access/status flags, not the one-time O_CREAT request.
        assert_eq!(parent.flags(file), Ok(O_RDWR | O_NONBLOCK | O_APPEND));
        let mut bytes = [0; 2];
        parent.read(&mut fs, file, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ab");
        child.read(&mut fs, 6, &mut bytes).unwrap();
        assert_eq!(&bytes, b"cd");
        parent.unlink(&mut fs, "/shared").unwrap();
        let info = parent.fstat(&fs, file).unwrap();
        parent.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 1);
        assert_eq!(objects.snapshot().references, 2);
        assert_eq!(child.fstat(&fs, 5).unwrap(), info);
        child.read(&mut fs, 5, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ef");
        child.write(&mut fs, &mut Sink, 6, b"XY").unwrap();
        assert_eq!(child.fstat(&fs, 5).unwrap().size, 8);
        child.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(objects.snapshot().references, 0);
    }
    #[test]
    fn weak_watch_survives_no_local_fd_and_cleans_only_on_global_final_release() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut parent = Process::new(&objects, 1).unwrap();
        let ep = parent.epoll_create(0).unwrap();
        let event = parent.eventfd(1, 0).unwrap();
        parent
            .epoll_ctl(
                ep,
                1,
                event,
                epoll::Event {
                    events: epoll::IN,
                    data: 123,
                },
            )
            .unwrap();
        let mut child = parent
            .spawn_descriptors(&fs, None, &[mapping(event, 7)], 2)
            .unwrap();
        parent.close(&mut fs, event).unwrap();
        assert_eq!(parent.eventfd(0, 0).unwrap(), event);
        assert_eq!(local_ready(&mut parent, ep).1.data, 123);
        let mut value = [0; 8];
        child.read(&mut fs, 7, &mut value).unwrap();
        assert_eq!(local_ready(&mut parent, ep).0, 0);
        child
            .write(&mut fs, &mut Sink, 7, &2u64.to_le_bytes())
            .unwrap();
        assert_eq!(local_ready(&mut parent, ep).1.data, 123);
        child.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().watches, 0);
        assert_eq!(local_ready(&mut parent, ep).0, 0);
        parent.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn inherited_epoll_oneshot_is_shared_and_survives_creator_exit() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut parent = Process::new(&objects, 1).unwrap();
        let ep = parent.epoll_create(O_CLOEXEC).unwrap();
        let event = parent.eventfd(9, 0).unwrap();
        let registration = epoll::Event {
            events: epoll::IN | epoll::ONESHOT,
            data: 44,
        };
        parent.epoll_ctl(ep, 1, event, registration).unwrap();
        let mut child = parent
            .spawn_descriptors(&fs, None, &[mapping(ep, ep), mapping(event, event)], 2)
            .unwrap();
        assert_eq!(local_ready(&mut child, ep).1.data, 44);
        assert_eq!(local_ready(&mut parent, ep).0, 0);
        parent.epoll_ctl(ep, 3, event, registration).unwrap();
        parent.close_all(&mut fs).unwrap();
        assert_eq!(local_ready(&mut child, ep).1.data, 44);
        child.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().epolls, 0);
        assert_eq!(objects.snapshot().watches, 0);
        assert_eq!(objects.snapshot().references, 0);
    }
    #[test]
    fn failed_maps_and_full_global_pool_do_not_retain_or_create_files() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut processes: [Process<'_>; super::super::usermem::MAX_PROCESSES] =
            core::array::from_fn(|i| Process::new(&objects, i as u32 + 1).unwrap());
        for process in &mut processes {
            for _ in 3..OPEN_MAX {
                process.eventfd(0, 0).unwrap();
            }
        }
        let before = objects.snapshot();
        assert_eq!(before.live, CAPACITY);
        for _ in 0..20 {
            assert!(matches!(
                processes[0].spawn_descriptors(&fs, None, &[mapping(0, 0), mapping(-2, 1)], 99),
                Err(Errno::Mfile)
            ));
            assert!(matches!(
                processes[0].spawn_descriptors(&fs, None, &[mapping(0, 0), mapping(1, 0)], 99),
                Err(Errno::Inval)
            ));
            assert_eq!(objects.snapshot(), before);
        }
        // Global limit checked before path creation, even if this table has an FD.
        let mut empty = Process::empty(&objects, 99);
        assert_eq!(
            empty.open(&mut fs, "/not-created", O_CREAT | O_RDWR, 0o600),
            Err(Errno::Mfile)
        );
        assert_eq!(empty.stat(&fs, "/not-created"), Err(Errno::Noent));
        for process in &mut processes {
            process.close_all(&mut fs).unwrap();
        }
        assert_eq!(objects.snapshot().references, 0);
    }
    #[test]
    fn final_backend_release_keeps_inherited_pipe_alive_without_owner_share() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut pipes = crate::pipe::Pipes::new();
        let handles = pipes.pair(10).unwrap();
        let mut parent = Process::new(&objects, 10).unwrap();
        let [r, w] = parent.install_pipe(handles, 0).unwrap();
        let mut child = parent
            .spawn_descriptors(&fs, None, &[mapping(w, 8)], 20)
            .unwrap();
        assert_eq!(parent.close(&mut fs, w), Ok(None));
        let owner = child.backend_owner(8).unwrap();
        assert_eq!(owner, 10);
        pipes
            .write(owner, child.pipe(8).unwrap().unwrap(), b"data")
            .unwrap();
        let mut bytes = [0; 4];
        assert_eq!(pipes.read(10, handles[0], &mut bytes), Ok(4));
        assert_eq!(&bytes, b"data");
        assert_eq!(pipes.read(10, handles[0], &mut bytes), Err(Errno::Again));
        match child.close(&mut fs, 8).unwrap().unwrap() {
            Released::Pipe { owner, handle } => pipes.close(owner, handle).unwrap(),
            _ => panic!("wrong release"),
        }
        assert_eq!(pipes.read(10, handles[0], &mut bytes), Ok(0));
        match parent.close(&mut fs, r).unwrap().unwrap() {
            Released::Pipe { owner, handle } => pipes.close(owner, handle).unwrap(),
            _ => panic!("wrong release"),
        }
        parent.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
        assert_eq!(pipes.free(), crate::pipe::PIPES);
    }
    #[test]
    fn stale_handles_and_generation_exhaustion_never_alias_new_objects() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::empty(&objects, 1);
        let fd = p.eventfd(0, 0).unwrap();
        let old = p.description(fd).unwrap();
        p.close(&mut fs, fd).unwrap();
        let fresh = p.eventfd(1, 0).unwrap();
        let new = p.description(fresh).unwrap();
        assert_ne!(old, new);
        assert_eq!(objects.owner(old), Err(Errno::Badf));
        assert_eq!(objects.retain(old), Err(Errno::Badf));
        p.close_all(&mut fs).unwrap();
        objects.inner.borrow_mut().entries[0].generation = MAX_GENERATION;
        let fd = p.eventfd(2, 0).unwrap();
        assert_ne!(p.description(fd).unwrap().slot, 0);
        assert_eq!(objects.snapshot().retired, 1);
        p.close_all(&mut fs).unwrap();
    }
    #[test]
    fn retry_identity_survives_aliases_but_rejects_closed_or_replaced_fd_without_pinning() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut parent = Process::new(&objects, 10).unwrap();
        let event = parent.eventfd(0, 0).unwrap();
        let identity = parent.description_identity(event).unwrap();
        let alias = parent.dup(event).unwrap();
        let mut child = parent
            .spawn_descriptors(&fs, None, &[mapping(alias, 8)], 20)
            .unwrap();
        let before = objects.snapshot();
        assert_eq!(
            parent.validate_description_identity(alias, identity),
            Ok(())
        );
        assert_eq!(child.validate_description_identity(8, identity), Ok(()));
        assert_eq!(objects.snapshot(), before); // checking does not acquire a strong reference
        parent.close(&mut fs, event).unwrap();
        assert_eq!(
            parent.validate_description_identity(event, identity),
            Err(Errno::Badf)
        );
        let replacement = parent.eventfd(1, 0).unwrap();
        assert_eq!(replacement, event);
        assert_eq!(
            parent.validate_description_identity(replacement, identity),
            Err(Errno::Badf)
        );
        let mut byte = [0; 8];
        // Rebinding the same OFD through dup2 is allowed; unrelated ready data
        // must not be consumed by the stale blocked call before this restoration.
        parent.read(&mut fs, replacement, &mut byte).unwrap();
        assert_eq!(u64::from_le_bytes(byte), 1);
        parent.dup2(&mut fs, alias, event).unwrap();
        assert_eq!(
            parent.validate_description_identity(event, identity),
            Ok(())
        );
        assert_eq!(parent.read(&mut fs, event, &mut byte), Err(Errno::Again));
        parent.close_all(&mut fs).unwrap();
        child.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().references, 0);
    }
    #[test]
    fn retry_identity_distinguishes_backend_handles_and_all_object_kinds() {
        let objects = OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let [pipe, write] = p.install_pipe([256, 257], 0).unwrap();
        let pty = p.install_pty(512, 0).unwrap();
        let socket = p.install_socket(768, 0).unwrap();
        for fd in [pipe, write, pty, socket] {
            let identity = p.description_identity(fd).unwrap();
            let alias = p.dup(fd).unwrap();
            p.close(&mut fs, fd).unwrap();
            let replacement = p.eventfd(1, 0).unwrap();
            if replacement != fd {
                p.dup2(&mut fs, replacement, fd).unwrap();
                p.close(&mut fs, replacement).unwrap();
            }
            assert_eq!(p.is_eventfd(fd), Ok(true));
            assert_eq!(
                p.validate_description_identity(fd, identity),
                Err(Errno::Badf)
            );
            assert_eq!(p.validate_description_identity(alias, identity), Ok(()));
            p.close(&mut fs, fd).unwrap();
            p.close(&mut fs, alias).unwrap();
        }
        let a = p.install_socket(900, 0).unwrap();
        let b = p.install_socket(900, 0).unwrap();
        assert_eq!(p.socket(a), p.socket(b));
        assert_ne!(p.description_identity(a), p.description_identity(b));
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }
    #[test]
    fn socket_capability_identity_is_separate_from_connect_listen_accept_actors() {
        let mut sockets = crate::unix::UnixSockets::new();
        let listener = sockets.socket(10).unwrap();
        sockets.bind(10, listener, b"/listener").unwrap();
        sockets.listen_for(10, listener, 2, 20).unwrap();
        let client = sockets.socket(30).unwrap();
        sockets.connect_for(30, client, b"/listener", 40).unwrap();
        let accepted = sockets.accept_for(10, listener, 50).unwrap();
        assert_eq!(sockets.peer_owner(30, client), Ok(20));
        assert_eq!(sockets.peer_owner(50, accepted), Ok(40));
        assert_eq!(sockets.peer_owner(10, accepted), Err(Errno::Badf));
        sockets.close(10, listener).unwrap();
        sockets.write(50, accepted, b"X").unwrap();
        let mut byte = [0];
        assert_eq!(sockets.read(30, client, &mut byte), Ok(1));
        sockets.close(50, accepted).unwrap();
        sockets.close(30, client).unwrap();
    }
    #[test]
    fn inherited_pty_foreground_uses_caller_pid_without_changing_capability_owner() {
        let mut ptys = crate::pty::Ptys::new();
        let master = ptys.open_master(10, 0).unwrap();
        ptys.lock(10, master, false).unwrap();
        let slave = ptys
            .open_slave(10, ptys.number(10, master).unwrap(), 0)
            .unwrap();
        ptys.controlling_for(10, slave, 20).unwrap();
        assert_eq!(ptys.foreground(10, master), Ok(20));
        assert_eq!(ptys.controlling_for(10, slave, 30), Err(Errno::Perm));
        ptys.release_actor(10); // creator exits, shared OFD is still held
        ptys.write(10, master, &[3]).unwrap();
        assert_eq!(ptys.take_signal(), Some((20, 2)));
        ptys.release_actor(20);
        assert_eq!(ptys.foreground(10, master), Ok(0));
        ptys.close(10, slave).unwrap();
        ptys.close(10, master).unwrap();
    }
}
