//! Bounded level/edge-triggered epoll in the global OFD metadata envelope.
//! Watches hold weak generational OFD identities, not reusable numeric FDs or
//! lifetime-extending references. Edge candidates come from committed backend
//! notifications and readiness transitions, not repeated scans of a ready FD.
use super::open_description::{EPOLLS, Handle, Table};
use super::{Description, Errno, O_CLOEXEC, O_RDWR, OPEN_MAX, Object, Process};
use core::num::NonZeroU16;
mod nesting;
pub(crate) use nesting::Topology;

pub const INSTANCES: usize = super::limits::PROFILE.epolls_per_owner;
pub const IN: u32 = 1;
// A valid interest even on backends that never produce priority data. It is
// retained in the watch and only returned when the backend reports this bit.
pub const PRI: u32 = 2;
pub const OUT: u32 = 4;
pub const ERR: u32 = 8;
pub const HUP: u32 = 16;
pub const RDHUP: u32 = 0x2000;
pub const ONESHOT: u32 = 1 << 30;
pub const EDGE: u32 = 1 << 31;
const SUPPORTED: u32 = IN | PRI | OUT | ERR | HUP | RDHUP | ONESHOT | EDGE;
const _: () = assert!(OPEN_MAX <= u128::BITS as usize);
const _: () = assert!(EPOLLS * OPEN_MAX <= u16::MAX as usize);

#[derive(Clone, Copy)]
struct Watch {
    fd: i32,
    description: Handle,
    events: u32,
    data: u64,
    armed: bool,
    pending: bool,
    observed: u32,
    backend: Option<Backend>,
    prev: Option<NonZeroU16>,
    next: Option<NonZeroU16>,
}
impl Watch {
    fn observe(&mut self, readiness: u32, notifications: u32) -> bool {
        let interest = (self.events | ERR | HUP) & !(ONESHOT | EDGE);
        let current = readiness & interest;
        let notified =
            self.armed && ((notifications & interest != 0) || current & !self.observed != 0);
        if notified {
            self.pending = true;
        }
        self.observed = current;
        notified && self.deliverable()
    }
    fn deliverable(&self) -> bool {
        self.armed && self.observed != 0 && (self.events & EDGE == 0 || self.pending)
    }
}

struct WatchSlots(u128);

impl Iterator for WatchSlots {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let slot = self.0.trailing_zeros() as usize;
        self.0 &= self.0 - 1;
        Some(slot)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Instance {
    pub(crate) used: bool,
    owner: u32,
    description: Option<Handle>,
    watches: [Option<Watch>; OPEN_MAX],
    occupied: u128,
    ready: u128,
    backends: [u128; 4],
    cursor: usize,
}
impl Instance {
    fn readable(&self) -> bool {
        self.ready != 0
    }
    pub(crate) const EMPTY: Self = Self {
        used: false,
        owner: 0,
        description: None,
        watches: [None; OPEN_MAX],
        occupied: 0,
        ready: 0,
        backends: [0; 4],
        cursor: 0,
    };
    fn live_slots(&self) -> WatchSlots {
        WatchSlots(self.occupied)
    }
    fn set_watch(&mut self, slot: usize, watch: Option<Watch>) {
        let bit = 1u128 << slot;
        if let Some(backend) = self.watches[slot].and_then(|watch| watch.backend) {
            self.backends[backend as usize] &= !bit;
        }
        self.watches[slot] = watch;
        if let Some(backend) = watch.and_then(|watch| watch.backend) {
            self.backends[backend as usize] |= bit;
        }
        if watch.is_some() {
            self.occupied |= bit;
        } else {
            self.occupied &= !bit;
        }
        self.refresh_ready(slot);
    }
    fn refresh_ready(&mut self, slot: usize) {
        let bit = 1u128 << slot;
        if self.watches[slot].as_ref().is_some_and(Watch::deliverable) {
            self.ready |= bit;
        } else {
            self.ready &= !bit;
        }
    }
    fn observe_watch(&mut self, slot: usize, readiness: u32, wakes: u32) -> bool {
        let notified = self.watches[slot]
            .as_mut()
            .unwrap()
            .observe(readiness, wakes);
        self.refresh_ready(slot);
        notified
    }
    pub(crate) fn watch_count(&self) -> usize {
        self.occupied.count_ones() as usize
    }
}

fn watch_indices(link: NonZeroU16) -> (usize, usize) {
    let index = usize::from(link.get() - 1);
    (index / OPEN_MAX, index % OPEN_MAX)
}

impl Table {
    fn linked_watch(&mut self, link: NonZeroU16) -> &mut Watch {
        let (index, slot) = watch_indices(link);
        self.epolls[index].watches[slot].as_mut().unwrap()
    }

    fn set_epoll_watch(&mut self, index: usize, slot: usize, mut watch: Option<Watch>) {
        let was_readable = self.epolls[index].readable();
        if let Some(old) = self.epolls[index].watches[slot] {
            if let Some(prev) = old.prev {
                self.linked_watch(prev).next = old.next;
            } else {
                self.watch_heads[old.description.slot] = old.next;
            }
            if let Some(next) = old.next {
                self.linked_watch(next).prev = old.prev;
            }
        }
        if let Some(new) = &mut watch {
            let link = NonZeroU16::new((index * OPEN_MAX + slot + 1) as u16);
            new.next = self.watch_heads[new.description.slot];
            if let Some(next) = new.next {
                self.linked_watch(next).prev = link;
            }
            self.watch_heads[new.description.slot] = link;
        }
        self.epolls[index].set_watch(slot, watch);
        self.note_epoll_readability(index, was_readable);
    }

    fn note_epoll_readability(&mut self, index: usize, was_readable: bool) {
        if self.epolls[index].readable() != was_readable {
            self.epoll_dirty |= 1 << index;
            self.publish_poll_change();
        }
    }

    pub(crate) fn observe_description(
        &mut self,
        handle: Handle,
        readiness: u32,
        notifications: u32,
    ) -> usize {
        let mut link = self.watch_heads[handle.slot];
        if link.is_none() || self.entry(handle).is_err() {
            return 0;
        }
        let mut wakes = 0;
        while let Some(current) = link {
            let (index, slot) = watch_indices(current);
            let watch = self.epolls[index].watches[slot].unwrap();
            debug_assert_eq!(watch.description, handle);
            link = watch.next;
            #[cfg(test)]
            {
                let visited = if watch.backend.is_some() {
                    &self.local_slots_visited
                } else {
                    &self.nested_watches_visited
                };
                visited.set(visited.get() + 1);
            }
            let was_readable = self.epolls[index].readable();
            if self.epolls[index].observe_watch(slot, readiness, notifications) {
                wakes |= 1 << index;
            }
            self.note_epoll_readability(index, was_readable);
        }
        wakes
    }

    pub(crate) fn clear_epoll(&mut self, index: usize) {
        for slot in self.epolls[index].live_slots() {
            self.set_epoll_watch(index, slot, None);
        }
        self.epolls[index] = Instance::EMPTY;
        self.epoll_dirty &= !(1 << index);
        self.epoll_topology.set(None);
    }

    pub(crate) fn remove_epoll_description(&mut self, handle: Handle) {
        while let Some(link) = self.watch_heads[handle.slot] {
            let (index, slot) = watch_indices(link);
            self.set_epoll_watch(index, slot, None);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub events: u32,
    pub data: u64,
}

/// Backend capability and readiness sample, never a reusable numeric FD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Local { read: bool, write: bool },
    Timer { deadline: Option<u64> },
    Socket { owner: u32, handle: u64 },
    Pipe { owner: u32, handle: u64 },
    Pty { owner: u32, handle: u64 },
}

/// Which pool answers a watch. A backend observation names its own kind so the
/// shared table can skip unrelated watches without exposing the object table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Backend {
    Local,
    Socket,
    Pipe,
    Pty,
}

fn backend_of(object: Object) -> Option<Backend> {
    Some(match object {
        Object::Epoll(_) => return None,
        Object::Socket(_) => Backend::Socket,
        Object::Pipe(_) => Backend::Pipe,
        Object::Pty(_) => Backend::Pty,
        _ => Backend::Local,
    })
}

fn source(object: Object, owner: u32) -> Result<Source, Errno> {
    Ok(match object {
        Object::Event { counter, .. } => Source::Local {
            read: counter != 0,
            write: counter < u64::MAX - 1,
        },
        Object::Timer(timer) => Source::Timer {
            deadline: timer.deadline,
        },
        Object::Socket(handle) => Source::Socket { owner, handle },
        Object::Pipe(handle) => Source::Pipe { owner, handle },
        Object::Pty(handle) => Source::Pty { owner, handle },
        _ => return Err(Errno::Inval),
    })
}

impl super::OpenDescriptions {
    /// The closure must only inspect the already borrowed backend pool. It must
    /// not call another pool or reenter this OFD table. Empty watch slots need
    /// no readiness work, even in an instance whose descriptor limit is large.
    pub fn observe_backend(
        &self,
        backend: Backend,
        mut sample: impl FnMut(Source) -> Option<(u32, u32)>,
    ) {
        let mut table = self.inner.borrow_mut();
        let mut wakes = 0;
        let mut incomplete = false;
        let mut readiness_changed = false;
        let Table {
            entries,
            epolls,
            epoll_dirty,
            #[cfg(test)]
            backend_slots_visited,
            ..
        } = &mut *table;
        for (index, instance) in epolls
            .iter_mut()
            .enumerate()
            .filter(|(_, instance)| instance.used)
        {
            let was_readable = instance.readable();
            for slot in WatchSlots(instance.backends[backend as usize]) {
                #[cfg(test)]
                backend_slots_visited.set(backend_slots_visited.get() + 1);
                let Some(watch) = instance.watches[slot].filter(|watch| watch.armed) else {
                    continue;
                };
                let entry = &entries[watch.description.slot];
                if entry.generation != watch.description.generation {
                    continue;
                }
                let Some(description) = entry.value else {
                    continue;
                };
                // A backend wake can add an edge while this epoll is
                // already readable.
                let Some((ready, notifications)) = source(description.object, entry.owner)
                    .ok()
                    .and_then(&mut sample)
                else {
                    // A backend error must be visible through the next full
                    // wait sample, even if this instance remains unreadable.
                    incomplete = true;
                    continue;
                };
                if instance.observe_watch(slot, ready, notifications) {
                    wakes |= 1 << index;
                }
            }
            if instance.readable() != was_readable {
                *epoll_dirty |= 1 << index;
                readiness_changed = true;
            }
        }
        if incomplete {
            table.epoll_invalidation_epoch = table.epoll_invalidation_epoch.saturating_add(1);
        }
        if incomplete || readiness_changed {
            table.publish_poll_change();
        }
        table.propagate_nested(wakes);
    }
    pub(crate) fn observe_local(&self, handle: Handle, readiness: u32, wakes: u32) {
        let mut table = self.inner.borrow_mut();
        if wakes != 0 {
            table.publish_poll_change();
        }
        let parents = table.observe_description(handle, readiness, wakes);
        table.propagate_nested(parents);
    }
}

impl Process<'_> {
    fn epoll_source(&self, object: Object, owner: u32) -> Result<Source, Errno> {
        if let Object::Inotify(index) = object {
            Ok(Source::Local {
                read: self.objects.inotify_readable(index),
                write: false,
            })
        } else {
            source(object, owner)
        }
    }
    fn epoll_index(&self, fd: i32) -> Result<usize, Errno> {
        match self.objects.get(self.description(fd)?)?.object {
            Object::Epoll(index) => Ok(index),
            _ => Err(Errno::Inval),
        }
    }
    pub fn is_epoll(&self, fd: i32) -> Result<bool, Errno> {
        Ok(matches!(
            self.objects.get(self.description(fd)?)?.object,
            Object::Epoll(_)
        ))
    }
    pub fn epoll_identity(&self, fd: i32) -> Result<u64, Errno> {
        self.epoll_index(fd)?;
        Ok(self.description(fd)?.identity())
    }
    /// Retain after a full wait sample returned zero. Backend publications
    /// maintain the ready bits. Committed watch changes and unresolved
    /// backend samples invalidate the proof independently of those bits.
    pub fn epoll_invalidation_epoch(&self) -> u64 {
        self.objects.inner.borrow().epoll_invalidation_epoch
    }

    /// A parked waiter may trust the published unreadable state only after
    /// the foreground has observed filesystem changes and expired due timers.
    /// Its caller must still validate the user output range and check timeout
    /// and signal priority on every wake attempt.
    pub fn epoll_wait_needs_sample(
        &self,
        fd: i32,
        identity: u64,
        epoch: u64,
    ) -> Result<bool, Errno> {
        let description = self.description(fd)?;
        if description.identity() != identity {
            return Err(Errno::Badf);
        }
        let table = self.objects.inner.borrow();
        let Object::Epoll(index) = table.entry(description)?.value.ok_or(Errno::Badf)?.object
        else {
            return Err(Errno::Badf);
        };
        Ok(table.epoll_invalidation_epoch == u64::MAX
            || table.epoll_invalidation_epoch != epoch
            || table.epoll_dirty != 0
            || table.epolls[index].readable())
    }
    pub fn epoll_create(&mut self, flags: u32) -> Result<i32, Errno> {
        if flags & !O_CLOEXEC != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let description = self.objects.free_slots::<1>()?[0];
        let limits = self.objects.limits();
        let index = {
            let table = self.objects.inner.borrow();
            if table
                .epolls
                .iter()
                .filter(|e| e.used && e.owner == self.owner)
                .count()
                >= limits.epolls_per_owner
            {
                return Err(Errno::Mfile);
            }
            table
                .epolls
                .iter()
                .take(limits.epoll_instances)
                .position(|e| !e.used)
                .ok_or(Errno::Mfile)?
        };
        self.objects.create(
            description,
            self.owner,
            Description {
                object: Object::Epoll(index),
                offset: 0,
                flags: O_RDWR,
            },
        )?;
        self.objects.inner.borrow_mut().epolls[index] = Instance {
            used: true,
            owner: self.owner,
            description: Some(description),
            ..Instance::EMPTY
        };
        self.objects.inner.borrow().epoll_topology.set(None);
        self.fds[fd] = Some(description);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub fn epoll_ctl(&mut self, epfd: i32, op: u32, fd: i32, event: Event) -> Result<(), Errno> {
        let index = self.epoll_index(epfd)?;
        let description = self.description(fd)?;
        if !matches!(op, 1..=3) {
            return Err(Errno::Inval);
        }
        if op != 2 && event.events & !SUPPORTED != 0 {
            return Err(Errno::Inval);
        }
        let target = self.objects.get(description)?.object;
        match target {
            Object::Epoll(child) if child == index => return Err(Errno::Inval),
            Object::Epoll(_) => {}
            Object::Event { .. }
            | Object::Timer(_)
            | Object::Inotify(_)
            | Object::Socket(_)
            | Object::Pipe(_)
            | Object::Pty(_) => {}
            _ => return Err(Errno::Perm),
        }
        let mut table = self.objects.inner.borrow_mut();
        let instance = &table.epolls[index];
        let existing = instance
            .watches
            .iter()
            .position(|w| w.is_some_and(|w| w.fd == fd && w.description == description));
        let slot = match (op, existing) {
            (1, Some(_)) => return Err(Errno::Exist),
            (1, None) => instance
                .watches
                .iter()
                .position(Option::is_none)
                .ok_or(Errno::Nospc)?,
            (_, None) => return Err(Errno::Noent),
            (_, Some(slot)) => slot,
        };
        if op == 1
            && let Object::Epoll(child) = target
        {
            table.epoll_topology(Some((index, child)))?;
        }
        let watch = if op == 2 {
            None
        } else {
            Some(Watch {
                fd,
                description,
                events: event.events,
                data: event.data,
                armed: true,
                pending: true, // ADD/MOD must re-poll even an already ready FD.
                observed: 0,
                backend: backend_of(target),
                prev: None,
                next: None,
            })
        };
        table.set_epoll_watch(index, slot, watch);
        table.epoll_invalidation_epoch = table.epoll_invalidation_epoch.saturating_add(1);
        table.publish_poll_change();
        let mut wakes = 0;
        if let Object::Epoll(child) = target {
            if op != 3 {
                table.epoll_topology.set(None);
            }
            if op != 2 {
                let ready = u32::from(table.epolls[child].readable()) * IN;
                let was_readable = table.epolls[index].readable();
                if table.epolls[index].observe_watch(slot, ready, 0) {
                    wakes |= 1 << index;
                }
                table.note_epoll_readability(index, was_readable);
            }
        }
        table.propagate_nested(wakes);
        Ok(())
    }
    /// Weak OFD identities resolve independently of this process's FD table.
    /// A child may retain a watched object after the registering FD was closed.
    /// Nested watches have no external backend source; use epoll_sample to
    /// refresh their descendants before collection.
    pub fn epoll_sources(&self, epfd: i32) -> Result<[Option<Source>; OPEN_MAX], Errno> {
        let index = self.epoll_index(epfd)?;
        let watches = self.objects.inner.borrow().epolls[index].watches;
        let mut sources = [None; OPEN_MAX];
        for (out, watch) in sources.iter_mut().zip(watches) {
            let Some(watch) = watch.filter(|w| w.armed) else {
                continue;
            };
            let d = self.objects.get(watch.description)?;
            let owner = self.objects.owner(watch.description)?;
            if !matches!(d.object, Object::Epoll(_)) {
                *out = Some(self.epoll_source(d.object, owner)?);
            }
        }
        Ok(sources)
    }

    /// Sample only the requested epoll's reachable children, without consuming
    /// any events. Backend callbacks run outside the OFD borrow and may publish
    /// readiness notifications, but must not mutate descriptors or watches.
    pub fn epoll_sample(
        &self,
        epfd: i32,
        sample: impl FnMut(Source) -> Result<u32, Errno>,
    ) -> Result<[u32; OPEN_MAX], Errno> {
        self.sample_epoll(self.epoll_index(epfd)?, None::<fn() -> u64>, sample)
    }

    /// Resolve timerfd readiness against one monotonic clock sample. Read the
    /// clock on the first relevant timer in the epoll graph.
    pub fn epoll_sample_at(
        &self,
        epfd: i32,
        clock: impl FnOnce() -> u64,
        sample: impl FnMut(Source) -> Result<u32, Errno>,
    ) -> Result<[u32; OPEN_MAX], Errno> {
        self.sample_epoll(self.epoll_index(epfd)?, Some(clock), sample)
    }

    fn sample_epoll(
        &self,
        root: usize,
        mut clock: Option<impl FnOnce() -> u64>,
        mut sample: impl FnMut(Source) -> Result<u32, Errno>,
    ) -> Result<[u32; OPEN_MAX], Errno> {
        let use_deadlines = clock.is_some();
        let topology = self.objects.inner.borrow().epoll_topology(None)?;
        let reachable = topology.reachable(root);
        let mut wakes = 0;
        let sampled = (|| {
            let mut result = [0; OPEN_MAX];
            for &index in &topology.order[..topology.count] {
                if reachable & (1 << index) == 0 {
                    continue;
                }
                let slots = self.objects.inner.borrow().epolls[index].live_slots();
                let mut readiness = [0; OPEN_MAX];
                for slot in slots {
                    let watch = self.objects.inner.borrow().epolls[index].watches[slot];
                    let Some(watch) = watch.filter(|w| w.armed) else {
                        continue;
                    };
                    let description = self.objects.get(watch.description)?;
                    match description.object {
                        Object::Epoll(_) => {}
                        Object::Timer(timer) if use_deadlines => {
                            if timer.deadline.is_some()
                                && let Some(read_clock) = clock.take()
                            {
                                self.objects.expire_timers(read_clock);
                            }
                            let scheduled = self
                                .objects
                                .inner
                                .borrow()
                                .timer_deadlines
                                .scheduled(watch.description.slot);
                            readiness[slot] =
                                u32::from(timer.deadline.is_some() && !scheduled) * IN;
                        }
                        object => {
                            let owner = self.objects.owner(watch.description)?;
                            readiness[slot] = sample(self.epoll_source(object, owner)?)?;
                        }
                    }
                }
                let mut table = self.objects.inner.borrow_mut();
                if table.observe_epoll(index, &mut readiness) {
                    wakes |= 1 << index;
                }
                if index == root {
                    result = readiness;
                }
            }
            Ok(result)
        })();
        // Earlier instances have already committed their observations. Publish
        // their edges even when a later backend sample fails.
        self.objects.inner.borrow_mut().propagate_nested(wakes);
        sampled
    }
    pub fn epoll_collect(
        &mut self,
        epfd: i32,
        readiness: &[u32; OPEN_MAX],
        out: &mut [Event],
    ) -> Result<usize, Errno> {
        if out.is_empty() {
            return Err(Errno::Inval);
        }
        let index = self.epoll_index(epfd)?;
        let mut table = self.objects.inner.borrow_mut();
        // Observe every watch before applying maxevents, retaining candidates
        // beyond the returned prefix. No loss and no allocation under pressure.
        let mut readiness = *readiness;
        let wakes = (table.observe_epoll(index, &mut readiness) as usize) << index;
        let instance = &mut table.epolls[index];
        let was_readable = instance.readable();
        let start = instance.cursor;
        let mut count = 0;
        for offset in 0..OPEN_MAX {
            let slot = (start + offset) % OPEN_MAX;
            let Some(watch) = &mut instance.watches[slot] else {
                continue;
            };
            let events = watch.observed;
            if events == 0 {
                watch.pending = false;
            }
            if !watch.deliverable() {
                continue;
            }
            out[count] = Event {
                events,
                data: watch.data,
            };
            watch.pending = false;
            if watch.events & ONESHOT != 0 {
                watch.armed = false;
            }
            instance.refresh_ready(slot);
            instance.cursor = (slot + 1) % OPEN_MAX;
            count += 1;
            if count == out.len() {
                break;
            }
        }
        table.note_epoll_readability(index, was_readable);
        table.propagate_nested(wakes);
        Ok(count)
    }

    /// Refresh readiness without consuming an event, advancing the fairness
    /// cursor, or disarming ONESHOT. Used by poll(2) on an epoll descriptor.
    pub fn epoll_readable(
        &mut self,
        epfd: i32,
        readiness: &[u32; OPEN_MAX],
    ) -> Result<bool, Errno> {
        let index = self.epoll_index(epfd)?;
        let mut table = self.objects.inner.borrow_mut();
        let mut readiness = *readiness;
        let wakes = (table.observe_epoll(index, &mut readiness) as usize) << index;
        let readable = table.epolls[index].readable();
        table.propagate_nested(wakes);
        Ok(readable)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use cyxia_ai_fs::FileSystem;

    struct Sink;
    impl crate::Console for Sink {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
            Ok(bytes.len())
        }
    }

    #[test]
    fn backend_observation_visits_only_live_watch_slots_after_deletion() {
        let objects = crate::OpenDescriptions::new();
        let mut fs = FileSystem::new();
        let mut owner = Process::new(&objects, 1).unwrap();
        let mut other = Process::new(&objects, 2).unwrap();
        let epfd = owner.epoll_create(0).unwrap();
        let targets: [i32; OPEN_MAX - 4] = core::array::from_fn(|slot| {
            let fd = owner.eventfd(1, 0).unwrap();
            owner
                .epoll_ctl(
                    epfd,
                    1,
                    fd,
                    Event {
                        events: IN | EDGE,
                        data: slot as u64,
                    },
                )
                .unwrap();
            fd
        });
        owner
            .epoll_ctl(epfd, 2, targets[0], Event::default())
            .unwrap();
        for &fd in &targets[1..targets.len() - 1] {
            owner.close(&mut fs, fd).unwrap();
        }
        let other_epfd = other.epoll_create(0).unwrap();
        let other_fd = other.eventfd(1, 0).unwrap();
        other
            .epoll_ctl(
                other_epfd,
                1,
                other_fd,
                Event {
                    events: IN,
                    data: 999,
                },
            )
            .unwrap();

        let source_readiness = |source| match source {
            Source::Local { read, .. } => Ok(u32::from(read) * IN),
            _ => panic!("expected a real eventfd watch"),
        };
        objects.observe_backend(Backend::Local, |source| {
            Some((source_readiness(source).unwrap(), 0))
        });
        assert_eq!(objects.inner.borrow().backend_slots_visited.get(), 2);
        let readiness = owner.epoll_sample(epfd, source_readiness).unwrap();
        let mut events = [Event::default(); 1];
        assert_eq!(
            owner.epoll_collect(epfd, &readiness, &mut events).unwrap(),
            1
        );
        assert_eq!(
            events[0],
            Event {
                events: IN,
                data: (targets.len() - 1) as u64
            }
        );
    }

    #[test]
    fn unchanged_epoll_graph_has_bounded_sampling_work() {
        // Same public sampling / backend notification / collection chain used
        // by the guest event loop, with unrelated owners sharing the OFD pool.
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut other = Process::new(&objects, 2).unwrap();
        let event = p.eventfd(1, 0).unwrap();
        let unrelated = other.eventfd(1, 0).unwrap();
        let mut root = -1;
        for _ in 0..2 {
            let ep = p.epoll_create(0).unwrap();
            root = ep;
            p.epoll_ctl(
                ep,
                1,
                event,
                Event {
                    events: IN,
                    data: 42,
                },
            )
            .unwrap();
            let ep = other.epoll_create(0).unwrap();
            other
                .epoll_ctl(
                    ep,
                    1,
                    unrelated,
                    Event {
                        events: IN,
                        data: 99,
                    },
                )
                .unwrap();
        }
        let sample = |source| match source {
            Source::Local { read, write } => Ok(u32::from(read) * IN | u32::from(write) * OUT),
            _ => panic!("unexpected backend"),
        };
        p.epoll_sample(root, sample).unwrap();
        {
            let table = objects.inner.borrow();
            table.topology_builds.set(0);
            table.nested_lookups.set(0);
        }
        let started = std::time::Instant::now();
        const ROUNDS: usize = 5000;
        for _ in 0..ROUNDS {
            let readiness = p.epoll_sample(root, sample).unwrap();
            objects.observe_backend(Backend::Local, |source| Some((sample(source).unwrap(), 0)));
            let mut events = [Event::default(); 1];
            assert_eq!(p.epoll_collect(root, &readiness, &mut events), Ok(1));
            assert_eq!(
                events[0],
                Event {
                    events: IN,
                    data: 42
                }
            );
        }
        let table = objects.inner.borrow();
        std::println!(
            "EPOLL_STABLE_GRAPH rounds={ROUNDS} elapsed_ns={} graph_builds={} nested_lookups={}",
            started.elapsed().as_nanos(),
            table.topology_builds.get(),
            table.nested_lookups.get()
        );
        assert!(
            table.topology_builds.get() <= 1,
            "unchanged graph was rebuilt on readiness sampling"
        );
        assert!(
            table.nested_lookups.get() <= ROUNDS * 4,
            "flat epolls rescanned unrelated watches for nested propagation"
        );
    }

    #[test]
    fn failed_graph_sample_publishes_committed_edges_to_shared_parents() {
        let objects = crate::OpenDescriptions::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let shared = process.epoll_create(0).unwrap();
        let other_root = process.epoll_create(0).unwrap();
        let inherited = crate::spawn::Mapping {
            source: shared,
            target: 3,
        };
        let mut other = process
            .spawn_descriptors(&FileSystem::new(), None, &[inherited], 2)
            .unwrap();
        let bad_child = other.epoll_create(0).unwrap();
        let bad_root = other.epoll_create(0).unwrap();
        let mut pipes = crate::pipe::Pipes::new();
        let [pipe, _] = other.install_pipe(pipes.pair(2).unwrap(), 0).unwrap();
        let first = process.eventfd(1, 0).unwrap();
        let second = process.eventfd(1, 0).unwrap();
        let level = Event {
            events: IN,
            data: 1,
        };
        process.epoll_ctl(shared, 1, first, level).unwrap();
        process
            .epoll_ctl(
                other_root,
                1,
                shared,
                Event {
                    events: IN | EDGE,
                    data: 1,
                },
            )
            .unwrap();
        other.epoll_ctl(bad_child, 1, pipe, level).unwrap();
        other
            .epoll_ctl(bad_root, 1, inherited.target, level)
            .unwrap();
        other.epoll_ctl(bad_root, 1, bad_child, level).unwrap();
        let sample = |source| match source {
            Source::Local { read, .. } => Ok(u32::from(read) * IN),
            Source::Pipe { .. } => Err(Errno::Io),
            _ => panic!("unexpected watch"),
        };
        let mut events = [Event::default(); 1];
        let readiness = process.epoll_sample(other_root, sample).unwrap();
        assert_eq!(
            process.epoll_collect(other_root, &readiness, &mut events),
            Ok(1)
        );
        let readiness = process.epoll_sample(other_root, sample).unwrap();
        assert_eq!(
            process.epoll_collect(other_root, &readiness, &mut events),
            Ok(0)
        );

        // Sampling this newly added watch commits a fresh edge while the
        // first watch keeps the shared child level-readable throughout.
        process
            .epoll_ctl(
                shared,
                1,
                second,
                Event {
                    events: IN,
                    data: 2,
                },
            )
            .unwrap();
        assert_eq!(other.epoll_sample(bad_root, sample), Err(Errno::Io));
        let readiness = process.epoll_sample(other_root, sample).unwrap();
        assert_eq!(
            process.epoll_collect(other_root, &readiness, &mut events),
            Ok(1)
        );
        assert_eq!(
            events[0],
            Event {
                events: IN,
                data: 1
            }
        );
    }

    #[test]
    fn nested_notifications_skip_an_unrelated_tree_even_when_it_is_readable() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut other = Process::new(&objects, 2).unwrap();
        let mut fs = FileSystem::new();
        let root = p.epoll_create(0).unwrap();
        let child = p.epoll_create(0).unwrap();
        let event = p.eventfd(0, 0).unwrap();
        p.epoll_ctl(
            root,
            1,
            child,
            Event {
                events: IN | EDGE,
                data: 10,
            },
        )
        .unwrap();
        p.epoll_ctl(
            child,
            1,
            event,
            Event {
                events: IN,
                data: 11,
            },
        )
        .unwrap();

        let unrelated = other.epoll_create(0).unwrap();
        let unrelated_child = other.epoll_create(0).unwrap();
        let unrelated_event = other.eventfd(1, 0).unwrap();
        other
            .epoll_ctl(
                unrelated,
                1,
                unrelated_child,
                Event {
                    events: IN,
                    data: 20,
                },
            )
            .unwrap();
        other
            .epoll_ctl(
                unrelated_child,
                1,
                unrelated_event,
                Event {
                    events: IN,
                    data: 21,
                },
            )
            .unwrap();
        assert_eq!(ready(&mut other, unrelated, 1)[0].events, IN);
        assert_eq!(ready(&mut p, root, 1)[0].events, 0);

        for _ in 0..2 {
            objects.inner.borrow().nested_watches_visited.set(0);
            p.write(&mut fs, &mut Sink, event, &1u64.to_le_bytes())
                .unwrap();
            assert_eq!(objects.inner.borrow().nested_watches_visited.get(), 1);
            let mut out = [Event::default(); 1];
            assert_eq!(p.epoll_collect(root, &[0; OPEN_MAX], &mut out), Ok(1));
            assert_eq!(
                out[0],
                Event {
                    events: IN,
                    data: 10
                }
            );
            assert_eq!(p.epoll_collect(root, &[0; OPEN_MAX], &mut out), Ok(0));
        }
    }

    #[test]
    fn warmed_graph_tracks_nested_changes_last_close_and_reuse() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 11,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN,
                data: 22,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 22);
        p.epoll_ctl(outer, 2, inner, Event::default()).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN,
                data: 33,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 33);
        // Closing an FD does not retire its aliased open description.
        let alias = p.dup(inner).unwrap();
        p.close(&mut fs, inner).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 33);
        p.close(&mut fs, alias).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        let replacement = p.epoll_create(0).unwrap();
        assert_eq!(replacement, inner);
        p.epoll_ctl(
            replacement,
            1,
            fd,
            Event {
                events: IN,
                data: 44,
            },
        )
        .unwrap();
        // The recycled slot must not remain reachable through an old edge.
        p.epoll_sample(outer, |_| panic!("sampled retired epoll descendant"))
            .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(
            outer,
            1,
            replacement,
            Event {
                events: IN,
                data: 55,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 55);
        assert_eq!(
            p.epoll_ctl(replacement, 1, outer, Event::default()),
            Err(Errno::Loop)
        );
        assert_eq!(ready(&mut p, outer, 1)[0].data, 55);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn deleted_nested_watch_stops_sampling_the_detached_child() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 11,
            },
        )
        .unwrap();
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN,
                data: 22,
            },
        )
        .unwrap();
        let sampled = core::cell::Cell::new(0usize);
        p.epoll_sample(outer, |_| {
            sampled.set(sampled.get() + 1);
            Ok(IN)
        })
        .unwrap();
        assert_eq!(sampled.get(), 1, "attached child backend was not sampled");
        p.epoll_ctl(outer, 2, inner, Event::default()).unwrap();
        // DEL drops the graph edge, so the detached child must leave the
        // reachable set instead of being sampled through the outer descriptor.
        p.epoll_sample(outer, |_| panic!("sampled a detached epoll descendant"))
            .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        // The child stays independently usable through its own descriptor.
        assert_eq!(ready(&mut p, inner, 1)[0].data, 11);
    }

    #[test]
    fn nested_level_is_nonconsuming_and_rejects_self_and_cycles() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 11,
            },
        )
        .unwrap();
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN,
                data: 22,
            },
        )
        .unwrap();
        for _ in 0..3 {
            assert_eq!(
                ready(&mut p, outer, 1)[0],
                Event {
                    events: IN,
                    data: 22
                }
            );
        }
        assert_eq!(
            ready(&mut p, inner, 1)[0],
            Event {
                events: IN,
                data: 11
            }
        );
        assert_eq!(
            p.epoll_ctl(inner, 1, outer, Event::default())
                .err()
                .map(|e| e as i32),
            Some(40)
        );
        let alias = p.dup(inner).unwrap();
        assert_eq!(
            p.epoll_ctl(inner, 1, alias, Event::default()),
            Err(Errno::Inval)
        );
        p.read(&mut fs, fd, &mut [0; 8]).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn nested_depth_counts_ancestors_and_disarmed_watches_across_owners() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let mut ep = [-1; 6];
        for i in 0..ep.len() {
            if i != 0 && i % INSTANCES == 0 {
                let maps: [crate::spawn::Mapping; 6] =
                    core::array::from_fn(|j| crate::spawn::Mapping {
                        source: ep[j],
                        target: ep[j],
                    });
                let child = p
                    .spawn_descriptors(&fs, None, &maps[..i], (i / INSTANCES + 1) as u32)
                    .unwrap();
                p.close_all(&mut fs).unwrap();
                p = child;
            }
            ep[i] = p.epoll_create(0).unwrap();
        }
        for i in 0..4 {
            p.epoll_ctl(
                ep[i],
                1,
                ep[i + 1],
                Event {
                    events: IN | ONESHOT,
                    data: i as u64,
                },
            )
            .unwrap();
        }
        let event = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep[4],
            1,
            event,
            Event {
                events: IN,
                data: 99,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep[0], 1)[0].events, IN);
        // The first graph edge is now disarmed, but still participates in limits.
        let before = objects.snapshot();
        assert_eq!(
            p.epoll_ctl(ep[4], 1, ep[5], Event::default()),
            Err(Errno::Loop)
        );
        assert_eq!(
            p.epoll_ctl(ep[5], 1, ep[0], Event::default()),
            Err(Errno::Loop)
        );
        assert_eq!(objects.snapshot(), before);
        p.epoll_ctl(ep[0], 2, ep[1], Event::default()).unwrap();
        p.epoll_ctl(
            ep[4],
            1,
            ep[5],
            Event {
                events: IN,
                data: 55,
            },
        )
        .unwrap();
        assert_eq!(
            p.epoll_ctl(ep[0], 1, ep[1], Event::default()),
            Err(Errno::Loop)
        );
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn nested_edges_follow_new_notifications_not_sampling_or_level_collection() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(0, 0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 1,
            },
        )
        .unwrap();
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN | EDGE,
                data: 2,
            },
        )
        .unwrap();
        for _ in 0..3 {
            p.write(&mut fs, &mut Sink, fd, &1u64.to_le_bytes())
                .unwrap();
            let sampled = sample(&p, outer);
            assert_eq!(p.epoll_readable(outer, &sampled), Ok(true));
            assert_eq!(ready(&mut p, outer, 1)[0].events, IN);
            assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
            assert_eq!(ready(&mut p, inner, 1)[0].events, IN);
            assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        }
        p.epoll_ctl(
            inner,
            3,
            fd,
            Event {
                events: IN | ONESHOT,
                data: 3,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, IN);
        assert_eq!(ready(&mut p, inner, 1)[0].data, 3);
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.write(&mut fs, &mut Sink, fd, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        // Even a disarmed edge is present for cycle detection.
        assert_eq!(
            p.epoll_ctl(inner, 1, outer, Event::default()),
            Err(Errno::Loop)
        );
        p.epoll_ctl(
            inner,
            3,
            fd,
            Event {
                events: IN,
                data: 4,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, IN);
        p.epoll_ctl(inner, 2, fd, Event::default()).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.close_all(&mut fs).unwrap();
    }

    /// A pool observation must not even call the sampler for a foreign kind.
    /// Before the kind filter the closure ran for every occupied watch and
    /// rejected the mismatched Source itself.
    #[test]
    fn backend_observation_samples_only_its_own_kind() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut pipes = crate::pipe::Pipes::new();
        let handles = pipes.pair(1).unwrap();
        let [reader, _writer] = p.install_pipe(handles, 0).unwrap();
        let event = p.eventfd(1, 0).unwrap();
        let ep = p.epoll_create(0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            reader,
            Event {
                events: IN,
                data: 1,
            },
        )
        .unwrap();
        p.epoll_ctl(
            ep,
            1,
            event,
            Event {
                events: IN,
                data: 2,
            },
        )
        .unwrap();
        let mut sampled = 0;
        objects.observe_backend(Backend::Pipe, |source| {
            let Source::Pipe { .. } = source else {
                panic!("pipe observation sampled a foreign backend");
            };
            sampled += 1;
            Some((IN, 0))
        });
        assert_eq!(sampled, 1, "the pipe watch was not observed");
        assert_eq!(objects.inner.borrow().backend_slots_visited.get(), 1);
        let mut local = 0;
        objects.observe_backend(Backend::Local, |source| {
            let Source::Local { .. } = source else {
                panic!("local observation sampled a foreign backend");
            };
            local += 1;
            Some((IN, 0))
        });
        assert_eq!(local, 1, "the local watch was not observed");
        assert_eq!(objects.inner.borrow().backend_slots_visited.get(), 2);
    }

    #[test]
    fn local_notification_visits_only_watches_of_the_committed_description() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let event = p.eventfd(0, 0).unwrap();
        let alias = p.dup(event).unwrap();
        let other = p.eventfd(0, 0).unwrap();
        let epfd = p.epoll_create(0).unwrap();
        for (fd, data) in [(event, 1), (alias, 2), (other, 3)] {
            p.epoll_ctl(
                epfd,
                1,
                fd,
                Event {
                    events: IN | EDGE,
                    data,
                },
            )
            .unwrap();
        }
        p.close(&mut fs, event).unwrap();
        p.write(&mut fs, &mut Sink, alias, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(objects.inner.borrow().local_slots_visited.get(), 2);
        let events = ready(&mut p, epfd, 3);
        assert_eq!(
            &events[..3],
            &[
                Event {
                    events: IN,
                    data: 1
                },
                Event {
                    events: IN,
                    data: 2
                },
                Event::default(),
            ]
        );
        let retired = p.description(alias).unwrap();
        p.close(&mut fs, alias).unwrap();
        let replacement = p.eventfd(0, 0).unwrap();
        let live = p.description(replacement).unwrap();
        assert_eq!(live.slot, retired.slot);
        assert_ne!(live.generation, retired.generation);
        p.epoll_ctl(
            epfd,
            1,
            replacement,
            Event {
                events: IN,
                data: 4,
            },
        )
        .unwrap();
        objects.observe_local(retired, IN, IN);
        assert_eq!(
            p.epoll_collect(epfd, &[0; OPEN_MAX], &mut [Event::default(); 1]),
            Ok(0)
        );
        p.write(&mut fs, &mut Sink, replacement, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            ready(&mut p, epfd, 2)[0],
            Event {
                events: IN,
                data: 4
            }
        );
        assert_eq!(objects.inner.borrow().local_slots_visited.get(), 3);
    }

    #[test]
    fn nested_backend_sampling_allows_notifications_and_ignores_unrelated_owners() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut other = Process::new(&objects, 2).unwrap();
        let mut fs = FileSystem::new();
        let mut pipes = crate::pipe::Pipes::new();
        let handles = pipes.pair(1).unwrap();
        let [reader, writer] = p.install_pipe(handles, 0).unwrap();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            reader,
            Event {
                events: IN,
                data: 1,
            },
        )
        .unwrap();
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN | EDGE,
                data: 2,
            },
        )
        .unwrap();
        let unrelated = other.epoll_create(0).unwrap();
        let timer = other.timerfd_create(1, 0).unwrap();
        other
            .epoll_ctl(
                unrelated,
                1,
                timer,
                Event {
                    events: IN,
                    data: 3,
                },
            )
            .unwrap();
        for _ in 0..2 {
            pipes.write(1, handles[1], b"x").unwrap();
            let readiness = p
                .epoll_sample(outer, |source| {
                    let Source::Pipe { owner, handle } = source else {
                        panic!("unrelated source sampled");
                    };
                    let ready = u32::from(pipes.poll(owner, handle)?);
                    // This is the actual backend-wrapper callback pattern. It must
                    // not encounter a held OFD borrow or lose its pending edge.
                    objects.observe_backend(Backend::Pipe, |source| match source {
                        Source::Pipe { owner, handle } => Some((
                            u32::from(pipes.poll(owner, handle).unwrap()),
                            pipes.wake_mask(owner, handle).unwrap(),
                        )),
                        _ => None,
                    });
                    Ok(ready)
                })
                .unwrap();
            pipes.clear_wakes();
            let mut events = [Event::default(); 1];
            assert_eq!(p.epoll_collect(outer, &readiness, &mut events), Ok(1));
            assert_eq!(events[0].data, 2);
            assert_eq!(p.epoll_collect(outer, &readiness, &mut events), Ok(0));
        }
        for fd in [reader, writer] {
            let Some(crate::open_description::Released::Pipe { owner, handle }) =
                p.close(&mut fs, fd).unwrap()
            else {
                panic!("pipe release");
            };
            pipes.close(owner, handle).unwrap();
        }
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.close_all(&mut fs).unwrap();
        other.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn nested_watches_follow_inherited_ofds_until_final_release_not_numeric_reuse() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 1,
            },
        )
        .unwrap();
        p.epoll_ctl(
            outer,
            1,
            inner,
            Event {
                events: IN,
                data: 2,
            },
        )
        .unwrap();
        let mapping = crate::spawn::Mapping {
            source: inner,
            target: 8,
        };
        let mut child = p.spawn_descriptors(&fs, None, &[mapping], 2).unwrap();
        p.close(&mut fs, inner).unwrap();
        assert_eq!(p.eventfd(0, 0).unwrap(), inner);
        assert_eq!(ready(&mut p, outer, 1)[0].data, 2);
        assert_eq!(ready(&mut child, 8, 1)[0].data, 1);
        child.close_all(&mut fs).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.close(&mut fs, inner).unwrap();
        assert_eq!(p.epoll_create(0).unwrap(), inner);
        p.epoll_ctl(
            inner,
            1,
            fd,
            Event {
                events: IN,
                data: 3,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
    }

    #[test]
    fn polling_priority_interest_does_not_turn_ordinary_reads_into_priority_events() {
        // polling 3.11 registers IN|HUP|ERR|PRI|ONESHOT on its eventfd.
        // Priority interest is valid even when this backend cannot produce it.
        const PRIORITY: u32 = 2;
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let ep = p.epoll_create(O_CLOEXEC).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        let polling_interest = IN | HUP | ERR | PRIORITY | ONESHOT;
        assert_eq!(
            p.epoll_ctl(
                ep,
                1,
                fd,
                Event {
                    events: polling_interest,
                    data: 41
                }
            ),
            Ok(())
        );
        let events = ready(&mut p, ep, 1);
        assert_eq!(
            events[0],
            Event {
                events: IN,
                data: 41
            }
        );
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        p.epoll_ctl(
            ep,
            3,
            fd,
            Event {
                events: PRIORITY | ONESHOT,
                data: 42,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        p.epoll_ctl(
            ep,
            3,
            fd,
            Event {
                events: polling_interest,
                data: 43,
            },
        )
        .unwrap();
        assert_eq!(
            ready(&mut p, ep, 1)[0],
            Event {
                events: IN,
                data: 43
            }
        );
        assert_eq!(
            p.epoll_ctl(
                ep,
                3,
                fd,
                Event {
                    events: 1 << 27,
                    data: 44
                }
            ),
            Err(Errno::Inval)
        );
    }

    #[test]
    fn polling_epoll_preserves_edges_oneshot_and_fairness() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let alias = p.dup(ep).unwrap();
        let a = p.eventfd(1, 0).unwrap();
        let b = p.eventfd(1, 0).unwrap();
        for (fd, data) in [(a, 10), (b, 20)] {
            p.epoll_ctl(
                ep,
                1,
                fd,
                Event {
                    events: IN | EDGE | ONESHOT,
                    data,
                },
            )
            .unwrap();
        }
        for _ in 0..3 {
            let readiness = sample(&p, ep);
            assert_eq!(p.epoll_readable(alias, &readiness), Ok(true));
        }
        assert_eq!(ready(&mut p, ep, 1)[0].data, 10);
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(true));
        assert_eq!(ready(&mut p, alias, 1)[0].data, 20);
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(alias, &readiness), Ok(false));
        p.write(&mut fs, &mut Sink, a, &1u64.to_le_bytes()).unwrap();
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(false));
        p.epoll_ctl(
            ep,
            3,
            a,
            Event {
                events: IN | EDGE,
                data: 30,
            },
        )
        .unwrap();
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(true));
        assert_eq!(ready(&mut p, ep, 1)[0].data, 30);
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(false));
        p.write(&mut fs, &mut Sink, a, &1u64.to_le_bytes()).unwrap();
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(alias, &readiness), Ok(true));
        p.read(&mut fs, a, &mut [0; 8]).unwrap();
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(false));
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
    }

    #[test]
    fn polling_epoll_level_repeats_without_consumption_and_ignores_fd_reuse() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN,
                data: 7,
            },
        )
        .unwrap();
        for _ in 0..3 {
            let readiness = sample(&p, ep);
            assert_eq!(p.epoll_readable(ep, &readiness), Ok(true));
            assert_eq!(ready(&mut p, ep, 1)[0].data, 7);
        }
        p.close(&mut fs, fd).unwrap();
        assert_eq!(p.eventfd(1, 0).unwrap(), fd);
        let readiness = sample(&p, ep);
        assert_eq!(p.epoll_readable(ep, &readiness), Ok(false));
        assert_eq!(p.epoll_readable(fd, &readiness), Err(Errno::Inval));
        assert_eq!(p.epoll_readable(-1, &readiness), Err(Errno::Badf));
    }

    #[test]
    fn edge_eventfd_repeated_writes_without_read_match_mio_waker() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(0, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN | (1 << 31),
                data: 7,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        for value in [1u64, 1, 0, 1] {
            p.write(&mut fs, &mut Sink, fd, &value.to_le_bytes())
                .unwrap();
            assert_eq!(
                ready(&mut p, ep, 1)[0],
                Event {
                    events: IN,
                    data: 7
                }
            );
            assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        }
        let mut bytes = [0; 8];
        p.read(&mut fs, fd, &mut bytes).unwrap();
        assert_eq!(u64::from_le_bytes(bytes), 3);
        p.write(&mut fs, &mut Sink, fd, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, IN);
    }

    #[test]
    fn edge_pending_fairness_oneshot_and_mod_on_already_ready_object() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let ep = p.epoll_create(0).unwrap();
        let a = p.eventfd(1, 0).unwrap();
        let b = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            a,
            Event {
                events: IN | (1 << 31),
                data: 10,
            },
        )
        .unwrap();
        p.epoll_ctl(
            ep,
            1,
            b,
            Event {
                events: IN | (1 << 31) | ONESHOT,
                data: 11,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 10);
        assert_eq!(ready(&mut p, ep, 1)[0].data, 11);
        assert_eq!(ready(&mut p, ep, 2)[0].events, 0);
        p.epoll_ctl(
            ep,
            3,
            b,
            Event {
                events: IN | (1 << 31) | ONESHOT,
                data: 12,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 12);
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
    }

    #[test]
    fn edge_consumed_before_wait_does_not_report_stale_readiness() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN | (1 << 31),
                data: 8,
            },
        )
        .unwrap();
        let alias = p.dup(fd).unwrap();
        p.read(&mut fs, alias, &mut [0; 8]).unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        p.write(&mut fs, &mut Sink, alias, &1u64.to_le_bytes())
            .unwrap();
        p.close(&mut fs, fd).unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 8);
        p.close(&mut fs, alias).unwrap();
        let reused = p.eventfd(1, 0).unwrap();
        assert_eq!(reused, fd);
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
    }

    #[test]
    fn eventfd_wakes_filter_interest_but_delivery_rechecks_full_mask() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: OUT | (1 << 31),
                data: 7,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, OUT);
        p.write(&mut fs, &mut Sink, fd, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        p.read(&mut fs, fd, &mut [0; 8]).unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, OUT);
        p.epoll_ctl(
            ep,
            3,
            fd,
            Event {
                events: IN | OUT | (1 << 31),
                data: 9,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, OUT);
        p.write(&mut fs, &mut Sink, fd, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, IN | OUT);
    }

    fn sample(process: &Process, epfd: i32) -> [u32; OPEN_MAX] {
        process
            .epoll_sample(epfd, |source| {
                Ok(match source {
                    Source::Local { read, write } => u32::from(read) | (u32::from(write) << 2),
                    _ => panic!("unexpected backend source"),
                })
            })
            .unwrap()
    }
    fn ready(process: &mut Process, epfd: i32, capacity: usize) -> [Event; OPEN_MAX] {
        let readiness = sample(process, epfd);
        let mut out = [Event::default(); OPEN_MAX];
        process
            .epoll_collect(epfd, &readiness, &mut out[..capacity])
            .unwrap();
        out
    }
    #[test]
    fn level_oneshot_rearm_and_round_robin() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let ep = p.epoll_create(O_CLOEXEC).unwrap();
        let a = p.eventfd(1, 0).unwrap();
        let b = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            a,
            Event {
                events: IN,
                data: 11,
            },
        )
        .unwrap();
        p.epoll_ctl(
            ep,
            1,
            b,
            Event {
                events: IN | ONESHOT,
                data: 22,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 11);
        assert_eq!(ready(&mut p, ep, 1)[0].data, 22);
        assert_eq!(ready(&mut p, ep, 2)[0].data, 11);
        assert_eq!(ready(&mut p, ep, 2)[1].events, 0);
        p.epoll_ctl(
            ep,
            3,
            b,
            Event {
                events: IN | ONESHOT,
                data: 33,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 33);
    }
    #[test]
    fn aliases_survive_close_but_never_follow_fd_reuse() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        let alias = p.dup(fd).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN,
                data: 123,
            },
        )
        .unwrap();
        p.close(&mut fs, fd).unwrap();
        let reused = p.eventfd(0, 0).unwrap();
        assert_eq!(fd, reused);
        assert_eq!(ready(&mut p, ep, 1)[0].data, 123);
        p.close(&mut fs, alias).unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
        p.epoll_ctl(
            ep,
            1,
            reused,
            Event {
                events: OUT,
                data: 456,
            },
        )
        .unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].data, 456);
        let dup_ep = p.dup(ep).unwrap();
        p.close(&mut fs, ep).unwrap();
        assert_eq!(ready(&mut p, dup_ep, 1)[0].data, 456);
        p.close_all(&mut fs).unwrap();
        assert_eq!(p.objects.snapshot().epolls, 0);
    }
    #[test]
    fn unsupported_modes_and_failed_ctl_do_not_mutate() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let ep = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        assert_eq!(
            p.epoll_ctl(
                ep,
                1,
                fd,
                Event {
                    events: IN | (1 << 28),
                    data: 1
                }
            ),
            Err(Errno::Inval)
        );
        assert_eq!(p.epoll_ctl(ep, 1, ep, Event::default()), Err(Errno::Inval));
        assert_eq!(p.epoll_ctl(ep, 1, 0, Event::default()), Err(Errno::Perm));
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN,
                data: 5,
            },
        )
        .unwrap();
        assert_eq!(p.epoll_ctl(ep, 1, fd, Event::default()), Err(Errno::Exist));
        assert_eq!(
            p.epoll_ctl(
                ep,
                3,
                fd,
                Event {
                    events: 1 << 28,
                    data: 9
                }
            ),
            Err(Errno::Inval)
        );
        assert_eq!(ready(&mut p, ep, 1)[0].data, 5);
        p.epoll_ctl(ep, 2, fd, Event::default()).unwrap();
        assert_eq!(ready(&mut p, ep, 1)[0].events, 0);
    }
}
