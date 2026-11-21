//! Bounded level/edge-triggered epoll in the global OFD metadata envelope.
//! Watches hold weak generational OFD identities, not reusable numeric FDs or
//! lifetime-extending references. Edge candidates come from committed backend
//! notifications and readiness transitions, not repeated scans of a ready FD.
use super::{Description, Errno, O_CLOEXEC, O_RDWR, OPEN_MAX, Object, Process};
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

#[derive(Clone, Copy)]
struct Watch {
    fd: i32,
    description: super::open_description::Handle,
    events: u32,
    data: u64,
    armed: bool,
    pending: bool,
    observed: u32,
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
    watches: [Option<Watch>; OPEN_MAX],
    occupied: u128,
    cursor: usize,
}
impl Instance {
    fn readable(&self) -> bool {
        self.live_slots()
            .any(|slot| self.watches[slot].as_ref().is_some_and(Watch::deliverable))
    }
    pub(crate) const EMPTY: Self = Self {
        used: false,
        owner: 0,
        watches: [None; OPEN_MAX],
        occupied: 0,
        cursor: 0,
    };
    fn live_slots(&self) -> WatchSlots {
        WatchSlots(self.occupied)
    }
    fn set_watch(&mut self, slot: usize, watch: Option<Watch>) {
        self.watches[slot] = watch;
        let bit = 1u128 << slot;
        if watch.is_some() {
            self.occupied |= bit;
        } else {
            self.occupied &= !bit;
        }
    }
    pub(crate) fn watch_count(&self) -> usize {
        self.watches.iter().flatten().count()
    }
    pub(crate) fn remove_description(&mut self, description: super::open_description::Handle) {
        for slot in self.live_slots() {
            if self.watches[slot].is_some_and(|watch| watch.description == description) {
                self.set_watch(slot, None);
            }
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
    pub fn observe_backend(&self, mut sample: impl FnMut(Source) -> Option<(u32, u32)>) {
        let mut table = self.inner.borrow_mut();
        let mut wakes = [false; super::open_description::EPOLLS];
        let super::open_description::Table {
            entries,
            epolls,
            #[cfg(test)]
            backend_slots_visited,
            ..
        } = &mut *table;
        for (index, instance) in epolls
            .iter_mut()
            .enumerate()
            .filter(|(_, instance)| instance.used)
        {
            for slot in instance.live_slots() {
                #[cfg(test)]
                backend_slots_visited.set(backend_slots_visited.get() + 1);
                let Some(watch) = instance.watches[slot].as_mut().filter(|watch| watch.armed) else {
                    continue;
                };
                let entry = &entries[watch.description.slot];
                if entry.generation != watch.description.generation {
                    continue;
                }
                let Some(description) = entry.value else {
                    continue;
                };
                if let Ok(source) = source(description.object, entry.owner)
                    && let Some((ready, notifications)) = sample(source)
                {
                    // A backend wake can add an event while this epoll is
                    // already readable; its ancestors still need that edge.
                    wakes[index] |= watch.observe(ready, notifications);
                }
            }
        }
        table.propagate_nested(wakes);
    }
    pub(crate) fn observe_local(
        &self,
        handle: super::open_description::Handle,
        readiness: u32,
        wakes: u32,
    ) {
        let mut table = self.inner.borrow_mut();
        let mut notifications = [false; super::open_description::EPOLLS];
        for (index, instance) in table
            .epolls
            .iter_mut()
            .enumerate()
            .filter(|(_, instance)| instance.used)
        {
            for slot in instance.live_slots() {
                if let Some(watch) = &mut instance.watches[slot]
                    && watch.description == handle
                {
                    notifications[index] |= watch.observe(readiness, wakes);
                }
            }
        }
        table.propagate_nested(notifications);
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
    pub fn epoll_create(&mut self, flags: u32) -> Result<i32, Errno> {
        if flags & !O_CLOEXEC != 0 {
            return Err(Errno::Inval);
        }
        let fd = self.free_fd()?;
        let description = self.objects.free_slots::<1>()?[0];
        let index = {
            let table = self.objects.inner.borrow();
            if table
                .epolls
                .iter()
                .filter(|e| e.used && e.owner == self.owner)
                .count()
                >= INSTANCES
            {
                return Err(Errno::Mfile);
            }
            table
                .epolls
                .iter()
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
            })
        };
        table.epolls[index].set_watch(slot, watch);
        if matches!(target, Object::Epoll(_)) && op != 3 {
            table.epoll_topology.set(None);
        }
        table.propagate_nested([false; super::open_description::EPOLLS]);
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
        mut sample: impl FnMut(Source) -> Result<u32, Errno>,
    ) -> Result<[u32; OPEN_MAX], Errno> {
        let root = self.epoll_index(epfd)?;
        let topology = self.objects.inner.borrow().epoll_topology(None)?;
        let reachable = topology.reachable(root);
        let mut result = [0; OPEN_MAX];
        let mut wakes = [false; super::open_description::EPOLLS];
        for &index in &topology.order[..topology.count] {
            if reachable & (1 << index) == 0 {
                continue;
            }
            let watches = self.objects.inner.borrow().epolls[index].watches;
            let mut readiness = [0; OPEN_MAX];
            for (slot, watch) in watches.into_iter().enumerate() {
                let Some(watch) = watch.filter(|w| w.armed) else {
                    continue;
                };
                let description = self.objects.get(watch.description)?;
                if !matches!(description.object, Object::Epoll(_)) {
                    let owner = self.objects.owner(watch.description)?;
                    readiness[slot] = sample(self.epoll_source(description.object, owner)?)?;
                }
            }
            let mut table = self.objects.inner.borrow_mut();
            wakes[index] |= table.observe_epoll(index, &mut readiness);
            if index == root {
                result = readiness;
            }
        }
        self.objects.inner.borrow_mut().propagate_nested(wakes);
        Ok(result)
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
        let mut wakes = [false; super::open_description::EPOLLS];
        let mut readiness = *readiness;
        wakes[index] = table.observe_epoll(index, &mut readiness);
        let instance = &mut table.epolls[index];
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
            instance.cursor = (slot + 1) % OPEN_MAX;
            count += 1;
            if count == out.len() {
                break;
            }
        }
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
        let mut wakes = [false; super::open_description::EPOLLS];
        let mut readiness = *readiness;
        wakes[index] = table.observe_epoll(index, &mut readiness);
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
                .epoll_ctl(epfd, 1, fd, Event { events: IN | EDGE, data: slot as u64 })
                .unwrap();
            fd
        });
        owner.epoll_ctl(epfd, 2, targets[0], Event::default()).unwrap();
        for &fd in &targets[1..targets.len() - 1] {
            owner.close(&mut fs, fd).unwrap();
        }
        let other_epfd = other.epoll_create(0).unwrap();
        let other_fd = other.eventfd(1, 0).unwrap();
        other
            .epoll_ctl(other_epfd, 1, other_fd, Event { events: IN, data: 999 })
            .unwrap();

        let source_readiness = |source| match source {
            Source::Local { read, .. } => Ok(u32::from(read) * IN),
            _ => panic!("expected a real eventfd watch"),
        };
        objects.observe_backend(|source| Some((source_readiness(source).unwrap(), 0)));
        assert_eq!(objects.inner.borrow().backend_slots_visited.get(), 2);
        let readiness = owner.epoll_sample(epfd, source_readiness).unwrap();
        let mut events = [Event::default(); 1];
        assert_eq!(owner.epoll_collect(epfd, &readiness, &mut events).unwrap(), 1);
        assert_eq!(events[0], Event { events: IN, data: (targets.len() - 1) as u64 });
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
            p.epoll_ctl(ep, 1, event, Event { events: IN, data: 42 }).unwrap();
            let ep = other.epoll_create(0).unwrap();
            other.epoll_ctl(ep, 1, unrelated, Event { events: IN, data: 99 }).unwrap();
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
            objects.observe_backend(|source| Some((sample(source).unwrap(), 0)));
            let mut events = [Event::default(); 1];
            assert_eq!(p.epoll_collect(root, &readiness, &mut events), Ok(1));
            assert_eq!(events[0], Event { events: IN, data: 42 });
        }
        let table = objects.inner.borrow();
        std::println!("EPOLL_STABLE_GRAPH rounds={ROUNDS} elapsed_ns={} graph_builds={} nested_lookups={}",
            started.elapsed().as_nanos(), table.topology_builds.get(), table.nested_lookups.get());
        assert!(table.topology_builds.get() <= 1, "unchanged graph was rebuilt on readiness sampling");
        assert!(table.nested_lookups.get() <= ROUNDS * 4,
            "flat epolls rescanned unrelated watches for nested propagation");
    }

    #[test]
    fn warmed_graph_tracks_nested_changes_last_close_and_reuse() {
        let objects = crate::OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let mut fs = FileSystem::new();
        let outer = p.epoll_create(0).unwrap();
        let inner = p.epoll_create(0).unwrap();
        let fd = p.eventfd(1, 0).unwrap();
        p.epoll_ctl(inner, 1, fd, Event { events: IN, data: 11 }).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(outer, 1, inner, Event { events: IN, data: 22 }).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 22);
        p.epoll_ctl(outer, 2, inner, Event::default()).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(outer, 1, inner, Event { events: IN, data: 33 }).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 33);
        // Closing an FD does not retire its aliased open description.
        let alias = p.dup(inner).unwrap();
        p.close(&mut fs, inner).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 33);
        p.close(&mut fs, alias).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        let replacement = p.epoll_create(0).unwrap();
        assert_eq!(replacement, inner);
        p.epoll_ctl(replacement, 1, fd, Event { events: IN, data: 44 }).unwrap();
        // The recycled slot must not remain reachable through an old edge.
        p.epoll_sample(outer, |_| panic!("sampled retired epoll descendant")).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].events, 0);
        p.epoll_ctl(outer, 1, replacement, Event { events: IN, data: 55 }).unwrap();
        assert_eq!(ready(&mut p, outer, 1)[0].data, 55);
        assert_eq!(p.epoll_ctl(replacement, 1, outer, Event::default()), Err(Errno::Loop));
        assert_eq!(ready(&mut p, outer, 1)[0].data, 55);
        p.close_all(&mut fs).unwrap();
        assert_eq!(objects.snapshot().live, 0);
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
                    objects.observe_backend(|source| match source {
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
