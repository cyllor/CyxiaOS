//! Linux filesystem notifications, owned by shared open descriptions.
//! Watches hold stable inode identities without pinning files. Committed VFS
//! observations feed independent queues; a missed observation is never silence.
use crate::{Description, Errno, O_CLOEXEC, O_NONBLOCK, Object, OpenDescriptions, Process};
use cyxia_ai_fs::{
    FileSystem, Kind,
    events::{Action, Record},
};
mod queue;
use queue::{Event, Queue};

pub const INSTANCES: usize = crate::limits::PROFILE.inotify_per_owner;
pub const GLOBAL_INSTANCES: usize = crate::limits::PROFILE.inotify_instances;
pub const WATCHES: usize = 64;
pub const EVENTS: usize = 64;

pub const ACCESS: u32 = 0x1;
pub const MODIFY: u32 = 0x2;
pub const ATTRIB: u32 = 0x4;
pub const CLOSE_WRITE: u32 = 0x8;
pub const CLOSE_NOWRITE: u32 = 0x10;
pub const OPEN: u32 = 0x20;
pub const MOVED_FROM: u32 = 0x40;
pub const MOVED_TO: u32 = 0x80;
pub const CREATE: u32 = 0x100;
pub const DELETE: u32 = 0x200;
pub const DELETE_SELF: u32 = 0x400;
pub const MOVE_SELF: u32 = 0x800;
pub const ALL_EVENTS: u32 = 0xfff;
pub const UNMOUNT: u32 = 0x2000;
pub const Q_OVERFLOW: u32 = 0x4000;
pub const IGNORED: u32 = 0x8000;
pub const ONLYDIR: u32 = 0x01000000;
pub const DONT_FOLLOW: u32 = 0x02000000;
pub const EXCL_UNLINK: u32 = 0x04000000;
pub const MASK_CREATE: u32 = 0x10000000;
pub const MASK_ADD: u32 = 0x20000000;
pub const ISDIR: u32 = 0x40000000;
pub const ONESHOT: u32 = 0x80000000;

const SUPPORTED: u32 = ALL_EVENTS
    | UNMOUNT
    | Q_OVERFLOW
    | IGNORED
    | ONLYDIR
    | DONT_FOLLOW
    | EXCL_UNLINK
    | MASK_CREATE
    | MASK_ADD
    | ISDIR
    | ONESHOT;
const WATCH_MASK: u32 = ALL_EVENTS | EXCL_UNLINK | ONESHOT;

#[derive(Clone, Copy)]
struct Watch {
    inode: u64,
    wd: i32,
    mask: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct Instance {
    pub(crate) used: bool,
    pub(crate) owner: u32,
    watches: [Option<Watch>; WATCHES],
    queue: Queue,
    cursor: u64,
    // Never reuse an ID within a live instance, including while old events are
    // unread. Exhaustion rejects a new watch without changing existing ones.
    last_wd: i32,
}

impl Instance {
    pub(crate) const EMPTY: Self = Self {
        used: false,
        owner: 0,
        watches: [None; WATCHES],
        queue: Queue::EMPTY,
        cursor: 0,
        last_wd: 0,
    };

    pub(crate) fn watch_count(&self) -> usize {
        self.watches.iter().flatten().count()
    }

    pub(crate) fn queued_count(&self) -> usize {
        self.queue.len()
    }
    pub(crate) fn readable(&self) -> bool {
        self.queue.len() != 0
    }

    fn remove(&mut self, slot: usize) -> bool {
        let watch = self.watches[slot].take().expect("existing inotify watch");
        self.queue.push(Event::new(watch.wd, IGNORED, 0, ""))
    }

    /// Returns whether an actual record (including overflow) was appended.
    fn observe(&mut self, record: Record) -> bool {
        let (mask, parent, own) = match record.action {
            Action::Create => (CREATE, true, false),
            Action::Delete => (DELETE, true, false),
            Action::MoveFrom => (MOVED_FROM, true, false),
            Action::MoveTo => (MOVED_TO, true, false),
            Action::MoveSelf => (MOVE_SELF, false, true),
            Action::DeleteSelf => (DELETE_SELF, false, true),
            Action::Unlink => (ATTRIB, false, true),
            Action::Modify => (MODIFY, true, true),
            Action::Attrib => (ATTRIB, true, true),
            Action::Access => (ACCESS, true, true),
            Action::Open => (OPEN, true, true),
            Action::CloseWrite => (CLOSE_WRITE, true, true),
            Action::CloseRead => (CLOSE_NOWRITE, true, true),
        };
        // Linux's inode-only move/delete observations carry no
        // ISDIR decoration; directory entry and file activity observations do.
        let kind = if record.kind == Kind::Directory
            && !matches!(record.action, Action::MoveSelf | Action::DeleteSelf)
        {
            ISDIR
        } else {
            0
        };
        let mut changed = false;
        for slot in 0..WATCHES {
            let Some(watch) = self.watches[slot] else {
                continue;
            };
            let self_event = own && watch.inode == record.inode;
            // Root's parent identity is itself. It must not generate a second,
            // named child event for its own activity.
            let child_event = parent
                && record.parent != record.inode
                && watch.inode == record.parent
                && (record.linked || watch.mask & EXCL_UNLINK == 0);
            if !self_event && !child_event {
                continue;
            }
            let matched = watch.mask & mask != 0;
            if matched {
                let name = if child_event { record.path.name() } else { "" };
                // Rename cookies associate the two parent directory events;
                // MOVE_SELF has no associated filename/cookie in Linux.
                let cookie = if matches!(record.action, Action::MoveFrom | Action::MoveTo) {
                    record.cookie
                } else {
                    0
                };
                changed |= self
                    .queue
                    .push(Event::new(watch.wd, mask | kind, cookie, name));
            }
            if (self_event && record.action == Action::DeleteSelf)
                || (matched && watch.mask & ONESHOT != 0)
            {
                changed |= self.remove(slot);
            }
        }
        changed
    }
}

impl OpenDescriptions {
    /// Synchronize every live instance before changing watch masks or consuming
    /// events. Publish epoll notifications only after releasing the table borrow.
    pub fn observe_filesystem(&self, fs: &FileSystem) {
        let mut updates = [None; GLOBAL_INSTANCES];
        {
            let mut table = self.inner.borrow_mut();
            let mut changed = [false; GLOBAL_INSTANCES];
            for (index, instance) in table
                .inotifies
                .iter_mut()
                .enumerate()
                .filter(|(_, i)| i.used)
            {
                let lost = fs.changes_lost(instance.cursor);
                if instance.cursor == fs.change_sequence() && !lost {
                    continue;
                }
                if lost {
                    changed[index] |= instance.queue.overflow();
                }
                for record in fs.changes_after(instance.cursor) {
                    changed[index] |= instance.observe(record);
                }
                if lost {
                    // A lost DELETE_SELF must not retain a dead watch forever.
                    // Open, unlinked inodes remain alive until their last pin.
                    for slot in 0..WATCHES {
                        if instance.watches[slot].is_some_and(|w| !fs.identity_alive(w.inode)) {
                            changed[index] |= instance.remove(slot);
                        }
                    }
                }
                instance.cursor = fs.change_sequence();
            }
            for (slot, entry) in table.entries.iter().enumerate() {
                if let Some(Description {
                    object: Object::Inotify(index),
                    ..
                }) = entry.value
                    && changed[index]
                {
                    updates[index] = Some(crate::open_description::Handle {
                        slot,
                        generation: entry.generation,
                    });
                }
            }
        }
        for handle in updates.into_iter().flatten() {
            // A new queued record is a wake even when the queue was already
            // readable: nested edge-triggered epolls need that notification.
            self.observe_local(handle, crate::epoll::IN, crate::epoll::IN);
        }
    }

    pub(crate) fn inotify_readable(&self, index: usize) -> bool {
        let table = self.inner.borrow();
        table
            .inotifies
            .get(index)
            .is_some_and(|i| i.used && i.readable())
    }
}

impl Process<'_> {
    fn inotify_index(&self, fd: i32) -> Result<usize, Errno> {
        match self.objects.get(self.description(fd)?)?.object {
            Object::Inotify(index) => Ok(index),
            _ => Err(Errno::Inval),
        }
    }

    pub fn is_inotify(&self, fd: i32) -> Result<bool, Errno> {
        Ok(matches!(
            self.objects.get(self.description(fd)?)?.object,
            Object::Inotify(_)
        ))
    }

    pub fn inotify_init(&mut self, fs: &FileSystem, flags: u32) -> Result<i32, Errno> {
        self.objects.observe_filesystem(fs);
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let description = self.objects.free_slots::<1>()?[0];
        let limits = self.objects.limits();
        let index = {
            let table = self.objects.inner.borrow();
            if table
                .inotifies
                .iter()
                .filter(|i| i.used && i.owner == self.owner)
                .count()
                >= limits.inotify_per_owner
            {
                return Err(Errno::Mfile);
            }
            table
                .inotifies
                .iter()
                .take(limits.inotify_instances)
                .position(|i| !i.used)
                .ok_or(Errno::Mfile)?
        };
        self.objects.create(
            description,
            self.owner,
            Description {
                object: Object::Inotify(index),
                offset: 0,
                flags: flags & O_NONBLOCK,
            },
        )?;
        self.objects.inner.borrow_mut().inotifies[index] = Instance {
            used: true,
            owner: self.owner,
            cursor: fs.change_sequence(),
            ..Instance::EMPTY
        };
        self.fds[fd] = Some(description);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }

    pub fn inotify_add_watch(
        &mut self,
        fs: &FileSystem,
        fd: i32,
        path: &str,
        mask: u32,
    ) -> Result<i32, Errno> {
        self.objects.observe_filesystem(fs);
        if mask == 0 || mask & !SUPPORTED != 0 || mask & MASK_ADD != 0 && mask & MASK_CREATE != 0 {
            return Err(Errno::Inval);
        }
        let index = self.inotify_index(fd)?;
        let path = self.resolved_path_with_follow(fs, path, mask & DONT_FOLLOW == 0)?;
        let stat = fs.stat(path)?;
        if mask & ONLYDIR != 0 && stat.kind != Kind::Directory {
            return Err(Errno::Notdir);
        }
        if stat.mode & 0o400 == 0 {
            return Err(Errno::Access);
        }
        let inode = fs.identity(path)?;
        let mut table = self.objects.inner.borrow_mut();
        let instance = &mut table.inotifies[index];
        if let Some(watch) = instance
            .watches
            .iter_mut()
            .flatten()
            .find(|w| w.inode == inode)
        {
            if mask & MASK_CREATE != 0 {
                return Err(Errno::Exist);
            }
            watch.mask = if mask & MASK_ADD != 0 {
                watch.mask | (mask & WATCH_MASK)
            } else {
                mask & WATCH_MASK
            };
            return Ok(watch.wd);
        }
        let slot = instance
            .watches
            .iter()
            .position(Option::is_none)
            .ok_or(Errno::Nospc)?;
        let wd = instance.last_wd.checked_add(1).ok_or(Errno::Nospc)?;
        instance.watches[slot] = Some(Watch {
            inode,
            wd,
            mask: mask & WATCH_MASK,
        });
        instance.last_wd = wd;
        Ok(wd)
    }

    pub fn inotify_rm_watch(&mut self, fs: &FileSystem, fd: i32, wd: i32) -> Result<(), Errno> {
        self.objects.observe_filesystem(fs);
        let handle = self.description(fd)?;
        let index = self.inotify_index(fd)?;
        let changed = {
            let mut table = self.objects.inner.borrow_mut();
            let instance = &mut table.inotifies[index];
            let slot = instance
                .watches
                .iter()
                .position(|w| w.is_some_and(|w| w.wd == wd))
                .ok_or(Errno::Inval)?;
            instance.remove(slot)
        };
        self.objects.observe_local(
            handle,
            crate::epoll::IN,
            u32::from(changed) * crate::epoll::IN,
        );
        Ok(())
    }

    /// Empty streams report Again for the supervisor's interruptible wait path.
    /// Like Linux, a zero-length read is Again when empty and Inval otherwise.
    pub fn inotify_read(
        &mut self,
        fs: &FileSystem,
        fd: i32,
        out: &mut [u8],
    ) -> Result<usize, Errno> {
        self.objects.observe_filesystem(fs);
        let handle = self.description(fd)?;
        let index = self.inotify_index(fd)?;
        let (result, readable) = {
            let mut table = self.objects.inner.borrow_mut();
            let instance = &mut table.inotifies[index];
            (instance.queue.read(out), instance.readable())
        };
        self.objects
            .observe_local(handle, u32::from(readable) * crate::epoll::IN, 0);
        result
    }

    /// Bytes currently queued; callers synchronize the filesystem before an
    /// FIONREAD syscall, just as before readiness sampling.
    pub fn inotify_pending(&self, fd: i32) -> Result<usize, Errno> {
        let index = self.inotify_index(fd)?;
        Ok(self.objects.inner.borrow().inotifies[index].queue.bytes())
    }
}

#[cfg(test)]
mod tests;
