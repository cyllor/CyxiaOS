use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

pub const TIMER_CAPACITY: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerClass {
    Soft,
    HardDeadline,
    Lease,
    Recovery,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerArm {
    pub key: ObjectKey,
    pub deadline_ns: u64,
    pub programmed_ns: u64,
    pub policy_version: u64,
}
pub trait TimerBackend {
    /// Err preserves the preceding hardware arm, if any.
    fn arm(&mut self, arm: TimerArm) -> Result<(), Error>;
    fn cancel(&mut self, key: ObjectKey) -> Result<(), Error>;
    /// Err has not delivered the callback; the timer remains due for retry.
    fn fire(&mut self, key: ObjectKey) -> Result<(), Error>;
}
#[derive(Clone, Copy)]
struct Timer {
    key: ObjectKey,
    class: TimerClass,
    slack: u64,
    arm: Option<TimerArm>,
}
pub struct Timers {
    entries: [Option<Timer>; TIMER_CAPACITY],
    stamp: PolicyStamp,
    coalesce_us: u16,
    now: u64,
    cursor: usize,
    pub wakeups: u64,
    pub late_ns: u64,
    soft_wakeups: u64,
    slack_overruns: u64,
}
impl Default for Timers {
    fn default() -> Self {
        Self::new()
    }
}
impl Timers {
    pub const fn new() -> Self {
        Self {
            entries: [None; TIMER_CAPACITY],
            stamp: PolicyStamp {
                version: 0,
                snapshot_ns: 0,
                installed_until_ns: 0,
            },
            coalesce_us: 0,
            now: 0,
            cursor: 0,
            wakeups: 0,
            late_ns: 0,
            soft_wakeups: 0,
            slack_overruns: 0,
        }
    }
    fn time(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Stale);
        }
        self.now = now;
        Ok(())
    }
    fn index(&self, key: ObjectKey) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|entry| entry.is_some_and(|e| e.key == key))
            .ok_or(Error::Stale)
    }
    pub fn register(
        &mut self,
        key: ObjectKey,
        class: TimerClass,
        slack_ns: u64,
    ) -> Result<(), Error> {
        if key.id == 0 || key.generation == 0 {
            return Err(Error::Format);
        }
        if class != TimerClass::Soft && slack_ns != 0 {
            return Err(Error::Auth);
        }
        if self.entries.iter().flatten().any(|e| e.key.id == key.id) {
            return Err(Error::Exists);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .ok_or(Error::Capacity)?;
        *slot = Some(Timer {
            key,
            class,
            slack: slack_ns,
            arm: None,
        });
        Ok(())
    }
    pub fn unregister(&mut self, key: ObjectKey) -> Result<(), Error> {
        let i = self.index(key)?;
        if self.entries[i].unwrap().arm.is_some() {
            return Err(Error::Busy);
        }
        self.entries[i] = None;
        Ok(())
    }
    pub fn install(&mut self, stamp: PolicyStamp, us: u16, now: u64) -> Result<(), Error> {
        Action::SoftCoalesce(us).validate()?;
        self.time(now)?;
        self.stamp.accepts(stamp, now)?;
        if stamp.version == self.stamp.version && us != self.coalesce_us {
            return Err(Error::Conflict);
        }
        self.stamp = stamp;
        self.coalesce_us = us;
        Ok(())
    }
    pub fn arm(
        &mut self,
        key: ObjectKey,
        deadline: u64,
        now: u64,
        backend: &mut impl TimerBackend,
    ) -> Result<TimerArm, Error> {
        self.time(now)?;
        let i = self.index(key)?;
        let entry = self.entries[i].unwrap();
        let live = entry.class == TimerClass::Soft && self.stamp.live(now);
        let quantum = if live {
            u64::from(self.coalesce_us) * 1000
        } else {
            0
        };
        let programmed = if deadline > now && quantum != 0 {
            let rounded = u128::from(deadline).div_ceil(u128::from(quantum)) * u128::from(quantum);
            rounded.min(u128::from(deadline.saturating_add(entry.slack))) as u64
        } else {
            deadline
        };
        let arm = TimerArm {
            key,
            deadline_ns: deadline,
            programmed_ns: programmed,
            policy_version: if live { self.stamp.version } else { 0 },
        };
        backend.arm(arm)?;
        self.entries[i].as_mut().unwrap().arm = Some(arm);
        Ok(arm)
    }
    pub fn cancel(&mut self, key: ObjectKey, backend: &mut impl TimerBackend) -> Result<(), Error> {
        let i = self.index(key)?;
        if self.entries[i].unwrap().arm.is_none() {
            return Ok(());
        }
        backend.cancel(key)?;
        self.entries[i].as_mut().unwrap().arm = None;
        Ok(())
    }
    pub fn poll(
        &mut self,
        now: u64,
        budget: usize,
        backend: &mut impl TimerBackend,
    ) -> Result<usize, Error> {
        self.time(now)?;
        let mut fired = 0;
        for _ in 0..TIMER_CAPACITY {
            if fired == budget {
                break;
            }
            let i = self.cursor;
            self.cursor = (i + 1) % TIMER_CAPACITY;
            let Some(entry) = self.entries[i] else {
                continue;
            };
            let Some(arm) = entry.arm else {
                continue;
            };
            if arm.programmed_ns > now {
                continue;
            }
            match backend.fire(entry.key) {
                Ok(()) => {}
                Err(Error::Busy | Error::Again) => continue,
                Err(e) => return Err(e),
            }
            self.entries[i].as_mut().unwrap().arm = None;
            fired += 1;
            self.wakeups = self.wakeups.saturating_add(1);
            self.late_ns = self
                .late_ns
                .saturating_add(now.saturating_sub(arm.deadline_ns));
            if entry.class == TimerClass::Soft {
                self.soft_wakeups = self.soft_wakeups.saturating_add(1);
                if now > arm.deadline_ns.saturating_add(entry.slack) {
                    self.slack_overruns = self.slack_overruns.saturating_add(1);
                }
            }
        }
        Ok(fired)
    }
    pub fn registered(&self) -> usize {
        self.entries.iter().flatten().count()
    }
    pub fn soft_observation(&self) -> (usize, u64, u64, u64) {
        let mut count = 0;
        let mut slack = u64::MAX;
        for e in self
            .entries
            .iter()
            .flatten()
            .filter(|e| e.class == TimerClass::Soft)
        {
            count += 1;
            slack = slack.min(e.slack);
        }
        (
            count,
            if count == 0 { 0 } else { slack },
            self.soft_wakeups,
            self.slack_overruns,
        )
    }
}
