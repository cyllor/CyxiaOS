//! Bounded level/edge-triggered epoll in the global OFD metadata envelope.
//! Watches hold weak generational OFD identities, not reusable numeric FDs or
//! lifetime-extending references. Edge candidates come from committed backend
//! notifications and readiness transitions, not repeated scans of a ready FD.
use super::{Description, Errno, O_CLOEXEC, O_RDWR, OPEN_MAX, Object, Process};

pub const INSTANCES: usize = 2;
pub const IN: u32 = 1;
pub const OUT: u32 = 4;
pub const ERR: u32 = 8;
pub const HUP: u32 = 16;
pub const RDHUP: u32 = 0x2000;
pub const ONESHOT: u32 = 1 << 30;
pub const EDGE: u32 = 1 << 31;
const SUPPORTED: u32 = IN | OUT | ERR | HUP | RDHUP | ONESHOT | EDGE;

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
    fn observe(&mut self, readiness: u32, notifications: u32) {
        let interest = (self.events | ERR | HUP) & !(ONESHOT | EDGE);
        let current = readiness & interest;
        if self.armed && ((notifications & interest != 0) || current & !self.observed != 0) {
            self.pending = true;
        }
        self.observed = current;
    }
    fn deliverable(&self) -> bool {
        self.armed && self.observed != 0 && (self.events & EDGE == 0 || self.pending)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Instance {
    pub(crate) used: bool,
    owner: u32,
    watches: [Option<Watch>; OPEN_MAX],
    cursor: usize,
}
impl Instance {
    pub(crate) const EMPTY: Self = Self {
        used: false,
        owner: 0,
        watches: [None; OPEN_MAX],
        cursor: 0,
    };
    pub(crate) fn watch_count(&self) -> usize {
        self.watches.iter().flatten().count()
    }
    pub(crate) fn remove_description(&mut self, description: super::open_description::Handle) {
        for watch in &mut self.watches {
            if watch.is_some_and(|w| w.description == description) {
                *watch = None;
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
    /// not call another pool or reenter this OFD table. At most 256 watches.
    pub fn observe_backend(&self, mut sample: impl FnMut(Source) -> Option<(u32, u32)>) {
        let mut table = self.inner.borrow_mut();
        let super::open_description::Table {
            entries, epolls, ..
        } = &mut *table;
        for instance in epolls.iter_mut().filter(|instance| instance.used) {
            for watch in instance
                .watches
                .iter_mut()
                .flatten()
                .filter(|watch| watch.armed)
            {
                let entry = &entries[watch.description.slot];
                if entry.generation != watch.description.generation {
                    continue;
                }
                let Some(description) = entry.value else {
                    continue;
                };
                if let Ok(source) = source(description.object, entry.owner)
                    && let Some((ready, wakes)) = sample(source)
                {
                    watch.observe(ready, wakes);
                }
            }
        }
    }
    pub(crate) fn observe_local(
        &self,
        handle: super::open_description::Handle,
        readiness: u32,
        wakes: u32,
    ) {
        let mut table = self.inner.borrow_mut();
        for instance in table.epolls.iter_mut().filter(|instance| instance.used) {
            for watch in instance.watches.iter_mut().flatten() {
                if watch.description == handle {
                    watch.observe(readiness, wakes);
                }
            }
        }
    }
}

impl Process<'_> {
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
        match self.objects.get(description)?.object {
            Object::Epoll(_) => return Err(Errno::Inval),
            Object::Event { .. }
            | Object::Timer(_)
            | Object::Socket(_)
            | Object::Pipe(_)
            | Object::Pty(_) => {}
            _ => return Err(Errno::Perm),
        }
        let mut table = self.objects.inner.borrow_mut();
        let instance = &mut table.epolls[index];
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
        instance.watches[slot] = if op == 2 {
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
        Ok(())
    }
    /// Weak OFD identities resolve independently of this process's FD table.
    /// A child may retain a watched object after the registering FD was closed.
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
            *out = Some(source(d.object, owner)?);
        }
        Ok(sources)
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
        let instance = &mut table.epolls[index];
        // Observe every watch before applying maxevents, retaining candidates
        // beyond the returned prefix. No loss and no allocation under pressure.
        for (watch, &ready) in instance.watches.iter_mut().zip(readiness) {
            if let Some(watch) = watch {
                watch.observe(ready, 0);
            }
        }
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
        Ok(count)
    }

    /// Refresh readiness without consuming an event, advancing the fairness
    /// cursor, or disarming ONESHOT. Used by poll(2) on an epoll descriptor.
    /// Nested epoll registrations remain unsupported.
    pub fn epoll_readable(
        &mut self,
        epfd: i32,
        readiness: &[u32; OPEN_MAX],
    ) -> Result<bool, Errno> {
        let index = self.epoll_index(epfd)?;
        let mut table = self.objects.inner.borrow_mut();
        let instance = &mut table.epolls[index];
        let mut readable = false;
        for (watch, &ready) in instance.watches.iter_mut().zip(readiness) {
            if let Some(watch) = watch {
                watch.observe(ready, 0);
                if watch.observed == 0 {
                    watch.pending = false;
                }
                readable |= watch.deliverable();
            }
        }
        Ok(readable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyxia_ai_fs::FileSystem;

    struct Sink;
    impl crate::Console for Sink {
        fn write(&mut self, bytes: &[u8]) -> Result<usize, Errno> {
            Ok(bytes.len())
        }
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
        let sources = process.epoll_sources(epfd).unwrap();
        core::array::from_fn(|i| match sources[i] {
            Some(Source::Local { read, write }) => u32::from(read) | (u32::from(write) << 2),
            None => 0,
            _ => panic!("unexpected backend source"),
        })
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
