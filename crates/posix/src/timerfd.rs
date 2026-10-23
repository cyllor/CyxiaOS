//! Bounded monotonic timers; elapsed time comes from the supervisor.
//! One timer lives in its existing open description. No separate queue, heap
//! allocation, background callback or reference extending epoll watch exists.
use super::{Description, Errno, O_CLOEXEC, O_NONBLOCK, O_RDWR, Object, Process};

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
        self.objects.update(
            slot,
            Description {
                object: Object::Timer(timer),
                ..d
            },
        )?;
        // Rearming replaces unread expirations. An already expired new timer
        // must notify edge watches even if the previous timer was also ready.
        let ready = u32::from(timer.ready(now));
        self.objects.observe_local(slot, ready, ready);
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
        self.objects.update(
            slot,
            Description {
                object: Object::Timer(timer),
                ..d
            },
        )?;
        self.objects
            .observe_local(slot, u32::from(timer.ready(now)), 0);
        out[..8].copy_from_slice(&ticks.to_le_bytes());
        Ok(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{O_CLOEXEC, O_NONBLOCK, OpenDescriptions, Process};

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
