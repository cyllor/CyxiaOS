//! Bounded monotonic timers. Each timer belongs to its open description and
//! future expirations are ordered in a fixed-capacity deadline heap.
use super::open_description::Handle;
use super::{Description, Errno, O_CLOEXEC, O_NONBLOCK, O_RDWR, Object, Process};
mod deadlines;
pub(crate) use deadlines::Deadlines;

pub const ABSTIME: u32 = 1;

/// Nanoseconds, not an architecture-dependent userspace timespec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Setting {
    pub value: u64,
    pub interval: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct Timer {
    pub(crate) deadline: Option<u64>,
    interval: u64,
}

impl Timer {
    const fn new() -> Self {
        Self {
            deadline: None,
            interval: 0,
        }
    }
    fn ready(self, now: u64) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
    fn ticks(self, now: u64) -> u64 {
        match self.deadline {
            Some(deadline) if now >= deadline => {
                1 + (now - deadline).checked_div(self.interval).unwrap_or(0)
            }
            _ => 0,
        }
    }
    fn next(self, ticks: u64) -> Option<u64> {
        if self.interval == 0 {
            None
        } else {
            self.deadline?
                .checked_add(ticks.checked_mul(self.interval)?)
        }
    }
    fn get(self, now: u64) -> Setting {
        let ticks = self.ticks(now);
        let next = if ticks == 0 {
            self.deadline
        } else {
            self.next(ticks)
        };
        Setting {
            value: next.map_or(0, |deadline| deadline.saturating_sub(now)),
            interval: self.interval,
        }
    }
    fn set(&mut self, now: u64, flags: u32, setting: Setting) -> Result<(), Errno> {
        if flags & !ABSTIME != 0 {
            return Err(Errno::Inval);
        }
        let deadline = if setting.value == 0 {
            None
        } else if flags & ABSTIME != 0 {
            Some(setting.value)
        } else {
            Some(now.checked_add(setting.value).ok_or(Errno::Overflow)?)
        };
        *self = Self {
            deadline,
            interval: setting.interval,
        };
        Ok(())
    }
    fn read(&mut self, now: u64) -> Result<u64, Errno> {
        let ticks = self.ticks(now);
        if ticks == 0 {
            return Err(Errno::Again);
        }
        self.deadline = self.next(ticks);
        Ok(ticks)
    }
}

impl super::OpenDescriptions {
    /// Publish due timer readiness before consulting cached epoll readiness.
    pub fn expire_timers(&self, clock: impl FnOnce() -> u64) {
        if self.inner.borrow().timer_deadlines.is_empty() {
            return;
        }
        let now = clock();
        let mut table = self.inner.borrow_mut();
        let mut wakes = 0;
        let mut expired = false;
        while let Some(handle) = table.timer_deadlines.pop_due(now) {
            // The timer stays readable until read or rearm. Its original
            // deadline remains in the OFD to count missed periodic ticks.
            wakes |= table.observe_description(handle, super::epoll::IN, 0);
            expired = true;
        }
        if expired {
            table.publish_poll_change();
        }
        table.propagate_nested(wakes);
    }

    fn store_timer(
        &self,
        handle: Handle,
        description: Description,
        timer: Timer,
        now: u64,
        rearm: bool,
    ) -> Result<(), Errno> {
        let mut table = self.inner.borrow_mut();
        table.entry(handle)?;
        table.entries[handle.slot].value = Some(Description {
            object: Object::Timer(timer),
            ..description
        });
        table
            .timer_deadlines
            .set(handle, timer.deadline.filter(|&deadline| deadline > now));
        table.publish_poll_change();
        let ready = u32::from(timer.ready(now)) * super::epoll::IN;
        let notification = if rearm { ready } else { 0 };
        let wakes = table.observe_description(handle, ready, notification);
        table.propagate_nested(wakes);
        Ok(())
    }
}

impl Process<'_> {
    pub fn timerfd_create(&mut self, clock: i32, flags: u32) -> Result<i32, Errno> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno::Inval);
        }
        match clock {
            1 => {}
            // Known timerfd clocks require services this subset does not offer.
            0 | 7 | 8 | 9 => return Err(Errno::Nosys),
            _ => return Err(Errno::Inval),
        }
        let fd = self.free_fd()?;
        let slot = self.objects.free_slots::<1>()?[0];
        self.objects.create(
            slot,
            self.owner,
            Description {
                object: Object::Timer(Timer::new()),
                offset: 0,
                flags: O_RDWR | (flags & O_NONBLOCK),
            },
        )?;
        self.fds[fd] = Some(slot);
        self.cloexec[fd] = flags & O_CLOEXEC != 0;
        Ok(fd as i32)
    }
    pub fn is_timerfd(&self, fd: i32) -> Result<bool, Errno> {
        Ok(matches!(
            self.objects.get(self.description(fd)?)?.object,
            Object::Timer(_)
        ))
    }
    fn timer(&self, fd: i32) -> Result<Timer, Errno> {
        match self.objects.get(self.description(fd)?)?.object {
            Object::Timer(timer) => Ok(timer),
            _ => Err(Errno::Inval),
        }
    }
    pub fn timerfd_ready(&self, fd: i32, now: u64) -> Result<bool, Errno> {
        Ok(self.timer(fd)?.ready(now))
    }
    pub fn timerfd_get(&self, fd: i32, now: u64) -> Result<Setting, Errno> {
        Ok(self.timer(fd)?.get(now))
    }
    pub fn timerfd_set(
        &mut self,
        fd: i32,
        now: u64,
        flags: u32,
        setting: Setting,
    ) -> Result<Setting, Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        let Object::Timer(mut timer) = d.object else {
            return Err(Errno::Inval);
        };
        let previous = timer.get(now);
        timer.set(now, flags, setting)?;
        // Rearming replaces unread expirations. An already expired new timer
        // must notify edge watches even if the previous timer was also ready.
        self.objects.store_timer(slot, d, timer, now, true)?;
        Ok(previous)
    }
    pub fn timerfd_read(&mut self, fd: i32, now: u64, out: &mut [u8]) -> Result<usize, Errno> {
        let slot = self.description(fd)?;
        let d = self.objects.get(slot)?;
        let Object::Timer(mut timer) = d.object else {
            return Err(Errno::Inval);
        };
        if out.len() < 8 {
            return Err(Errno::Inval);
        }
        let ticks = timer.read(now)?;
        self.objects.store_timer(slot, d, timer, now, false)?;
        out[..8].copy_from_slice(&ticks.to_le_bytes());
        Ok(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{O_CLOEXEC, O_NONBLOCK, OpenDescriptions, Process};

    #[test]
    fn timer_epoll_samples_one_clock_and_tracks_rearm_read_and_final_close() {
        use crate::epoll::{EDGE, Event, IN};
        let objects = OpenDescriptions::new();
        let mut process = Process::new(&objects, 1).unwrap();
        let mut fs = cyxia_ai_fs::FileSystem::new();
        let epfd = process.epoll_create(0).unwrap();
        let late = process.timerfd_create(1, O_NONBLOCK).unwrap();
        let periodic = process.timerfd_create(1, O_NONBLOCK).unwrap();
        let removed = process.timerfd_create(1, O_NONBLOCK).unwrap();
        for (fd, data, value, interval) in
            [(late, 1, 40, 0), (periodic, 2, 20, 10), (removed, 3, 10, 0)]
        {
            process
                .epoll_ctl(
                    epfd,
                    1,
                    fd,
                    Event {
                        events: IN | EDGE,
                        data,
                    },
                )
                .unwrap();
            process
                .timerfd_set(fd, 0, ABSTIME, Setting { value, interval })
                .unwrap();
        }
        process
            .timerfd_set(
                late,
                0,
                ABSTIME,
                Setting {
                    value: 70,
                    interval: 0,
                },
            )
            .unwrap();
        process.close(&mut fs, removed).unwrap();
        let replacement = process.timerfd_create(1, O_NONBLOCK).unwrap();
        assert_eq!(replacement, removed);
        process
            .epoll_ctl(
                epfd,
                1,
                replacement,
                Event {
                    events: IN | EDGE,
                    data: 4,
                },
            )
            .unwrap();
        let unrelated = process.epoll_create(0).unwrap();
        process
            .epoll_sample_at(
                unrelated,
                || panic!("queried the clock for an unrelated epoll"),
                |_| panic!("sampled an unwatched timer"),
            )
            .unwrap();

        let wait = |process: &mut Process, time, expected_data: Option<u64>, clock_reads| {
            let reads = core::cell::Cell::new(0);
            let clock = || {
                reads.set(reads.get() + 1);
                time
            };
            let readiness = process
                .epoll_sample_at(epfd, clock, |_| panic!("timer escaped the deadline queue"))
                .unwrap();
            assert_eq!(reads.get(), clock_reads, "clock reads at {time}");
            let mut events = [Event::default(); 3];
            let delivered = process
                .epoll_collect(epfd, &readiness, &mut events)
                .unwrap();
            assert_eq!(
                delivered,
                usize::from(expected_data.is_some()),
                "events at {time}"
            );
            if let Some(data) = expected_data {
                assert_eq!(events[0], Event { events: IN, data });
            }
        };
        wait(&mut process, 10, None, 1);
        wait(&mut process, 45, Some(2), 1);
        let mut ticks = [0; 8];
        process.timerfd_read(periodic, 45, &mut ticks).unwrap();
        assert_eq!(u64::from_le_bytes(ticks), 3);
        wait(&mut process, 49, None, 1);
        wait(&mut process, 50, Some(2), 1);
        wait(&mut process, 70, Some(1), 1);
        process
            .timerfd_set(periodic, 70, 0, Setting::default())
            .unwrap();
        process.timerfd_read(late, 70, &mut ticks).unwrap();
        assert_eq!(u64::from_le_bytes(ticks), 1);
        wait(&mut process, 80, None, 0);
    }

    #[test]
    fn edge_past_absolute_rearm_notifies_without_consuming_previous_timer() {
        use crate::epoll::{EDGE, Event, IN, Source};
        let objects = OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let fd = p.timerfd_create(1, O_NONBLOCK).unwrap();
        let ep = p.epoll_create(0).unwrap();
        p.epoll_ctl(
            ep,
            1,
            fd,
            Event {
                events: IN | EDGE,
                data: 71,
            },
        )
        .unwrap();
        let collect = |p: &mut Process| {
            let sources = p.epoll_sources(ep).unwrap();
            let ready = core::array::from_fn(|i| match sources[i] {
                Some(Source::Timer { deadline }) => u32::from(deadline.is_some_and(|d| d <= 100)),
                None => 0,
                _ => panic!("unexpected source"),
            });
            let mut out = [Event::default()];
            p.epoll_collect(ep, &ready, &mut out).unwrap()
        };
        for value in [1, 2, 3] {
            p.timerfd_set(fd, 100, ABSTIME, Setting { value, interval: 0 })
                .unwrap();
            assert_eq!(collect(&mut p), 1);
            assert_eq!(collect(&mut p), 0);
        }
        assert_eq!(
            p.timerfd_set(fd, 100, 2, Setting::default()),
            Err(Errno::Inval)
        );
        assert_eq!(collect(&mut p), 0);
        let mut bytes = [0; 8];
        assert_eq!(p.timerfd_read(fd, 100, &mut bytes), Ok(8));
        assert_eq!(u64::from_le_bytes(bytes), 1);
        assert_eq!(collect(&mut p), 0);
    }

    #[test]
    fn periodic_read_accumulates_and_gettime_does_not_consume() {
        let mut t = Timer::new();
        t.set(
            100,
            0,
            Setting {
                value: 5,
                interval: 3,
            },
        )
        .unwrap();
        assert!(!t.ready(104));
        assert_eq!(
            t.get(114),
            Setting {
                value: 3,
                interval: 3
            }
        );
        assert_eq!(t.read(114), Ok(4));
        assert_eq!(t.read(114), Err(Errno::Again));
        assert_eq!(t.read(117), Ok(1));
    }

    #[test]
    fn oneshot_past_absolute_and_disarm_clear_unread_counts() {
        let mut t = Timer::new();
        t.set(
            100,
            ABSTIME,
            Setting {
                value: 10,
                interval: 0,
            },
        )
        .unwrap();
        assert!(t.ready(100));
        assert_eq!(t.get(100), Setting::default());
        assert_eq!(t.read(100), Ok(1));
        assert!(!t.ready(100));
        t.set(
            100,
            0,
            Setting {
                value: 1,
                interval: 2,
            },
        )
        .unwrap();
        t.set(
            105,
            0,
            Setting {
                value: 0,
                interval: 2,
            },
        )
        .unwrap();
        assert!(!t.ready(1_000));
        assert_eq!(
            t.get(1_000),
            Setting {
                value: 0,
                interval: 2
            }
        );
        assert_eq!(t.read(1_000), Err(Errno::Again));
    }

    #[test]
    fn invalid_rearm_is_atomic_and_deadline_overflow_does_not_wrap() {
        let mut t = Timer::new();
        t.set(
            10,
            0,
            Setting {
                value: 5,
                interval: 0,
            },
        )
        .unwrap();
        assert_eq!(t.set(11, 2, Setting::default()), Err(Errno::Inval));
        assert_eq!(
            t.set(
                u64::MAX,
                0,
                Setting {
                    value: 1,
                    interval: 0
                }
            ),
            Err(Errno::Overflow)
        );
        assert_eq!(t.read(15), Ok(1));
        t.set(
            0,
            ABSTIME,
            Setting {
                value: u64::MAX - 1,
                interval: 3,
            },
        )
        .unwrap();
        assert_eq!(t.read(u64::MAX), Ok(1));
        assert!(!t.ready(u64::MAX));
    }

    #[test]
    fn shared_description_read_clear_and_descriptor_flags() {
        let objects = OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        let fd = p.timerfd_create(1, O_NONBLOCK | O_CLOEXEC).unwrap();
        let alias = p.dup_from(fd, 0, false).unwrap();
        assert!(p.close_on_exec(fd).unwrap());
        assert!(!p.close_on_exec(alias).unwrap());
        assert_eq!(p.flags(alias).unwrap() & O_NONBLOCK, O_NONBLOCK);
        p.timerfd_set(
            fd,
            100,
            0,
            Setting {
                value: 10,
                interval: 10,
            },
        )
        .unwrap();
        let mut short = [0; 7];
        assert_eq!(p.timerfd_read(alias, 130, &mut short), Err(Errno::Inval));
        let mut bytes = [0; 16];
        assert_eq!(p.timerfd_read(alias, 130, &mut bytes), Ok(8));
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 3);
        assert_eq!(p.timerfd_read(fd, 130, &mut bytes), Err(Errno::Again));
        assert_eq!(p.timerfd_get(fd, 130).unwrap().value, 10);
    }

    #[test]
    fn unsupported_clock_flags_and_wrong_objects_are_rejected() {
        let objects = OpenDescriptions::new();
        let mut p = Process::new(&objects, 1).unwrap();
        assert_eq!(p.timerfd_create(0, 0), Err(Errno::Nosys));
        assert_eq!(p.timerfd_create(-1, 0), Err(Errno::Inval));
        assert_eq!(p.timerfd_create(1, 1), Err(Errno::Inval));
        let event = p.eventfd(0, 0).unwrap();
        assert_eq!(p.timerfd_get(event, 0), Err(Errno::Inval));
        assert_eq!(p.timerfd_get(-1, 0), Err(Errno::Badf));
    }
}
