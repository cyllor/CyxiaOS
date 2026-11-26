use crate::domains::{Action, Error, ObjectKey, PolicyStamp};

pub const TIMER_CAPACITY: usize = 256;
const ACTIVE_WORDS: usize = TIMER_CAPACITY.div_ceil(64);
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
    // A bit is set exactly when the corresponding entry has a hardware arm.
    active: [u64; ACTIVE_WORDS],
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
            active: [0; ACTIVE_WORDS],
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
        self.active[i / 64] |= 1u64 << (i % 64);
        Ok(arm)
    }
    pub fn cancel(&mut self, key: ObjectKey, backend: &mut impl TimerBackend) -> Result<(), Error> {
        let i = self.index(key)?;
        if self.entries[i].unwrap().arm.is_none() {
            return Ok(());
        }
        backend.cancel(key)?;
        self.entries[i].as_mut().unwrap().arm = None;
        self.active[i / 64] &= !(1u64 << (i % 64));
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
        // Traverse the same circular slot order as the linear scan. Skip
        // inactive runs without revisiting a Busy/Again timer in this poll.
        let mut remaining = TIMER_CAPACITY;
        while remaining != 0 && fired != budget {
            let offset = self.cursor % 64;
            let span = remaining.min(64 - offset).min(TIMER_CAPACITY - self.cursor);
            let bits = self.active[self.cursor / 64] >> offset;
            let skip = (bits.trailing_zeros() as usize).min(span);
            self.cursor = (self.cursor + skip) % TIMER_CAPACITY;
            remaining -= skip;
            if skip == span {
                continue;
            }
            let i = self.cursor;
            self.cursor = (i + 1) % TIMER_CAPACITY;
            remaining -= 1;
            let entry = self.entries[i].expect("active timer entry");
            let arm = entry.arm.expect("active timer arm");
            if arm.programmed_ns > now {
                continue;
            }
            match backend.fire(entry.key) {
                Ok(()) => {}
                Err(Error::Busy | Error::Again) => continue,
                Err(e) => return Err(e),
            }
            self.entries[i].as_mut().unwrap().arm = None;
            self.active[i / 64] &= !(1u64 << (i % 64));
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[derive(Default)]
    struct Backend {
        attempted: std::vec::Vec<ObjectKey>,
        arm_error: Option<Error>,
        cancel_error: Option<Error>,
        fire_error: Option<(ObjectKey, Error)>,
    }

    impl TimerBackend for Backend {
        fn arm(&mut self, _: TimerArm) -> Result<(), Error> {
            self.arm_error.map_or(Ok(()), Err)
        }

        fn cancel(&mut self, _: ObjectKey) -> Result<(), Error> {
            self.cancel_error.map_or(Ok(()), Err)
        }

        fn fire(&mut self, key: ObjectKey) -> Result<(), Error> {
            self.attempted.push(key);
            match self.fire_error {
                Some((target, error)) if target == key => Err(error),
                _ => Ok(()),
            }
        }
    }

    fn key(slot: usize) -> ObjectKey {
        ObjectKey {
            id: slot as u64 + 1,
            generation: 1,
        }
    }

    fn check_index(timers: &Timers) {
        for (i, entry) in timers.entries.iter().enumerate() {
            assert_eq!(
                timers.active[i / 64] & (1u64 << (i % 64)) != 0,
                entry.is_some_and(|e| e.arm.is_some())
            );
        }
    }

    // Frozen pre-index poll semantics, independent of the active bitmap.
    fn linear_poll(
        timers: &mut Timers,
        now: u64,
        budget: usize,
        backend: &mut Backend,
    ) -> Result<usize, Error> {
        timers.time(now)?;
        let mut fired = 0;
        for _ in 0..TIMER_CAPACITY {
            if fired == budget {
                break;
            }
            let i = timers.cursor;
            timers.cursor = (i + 1) % TIMER_CAPACITY;
            let Some(entry) = timers.entries[i] else {
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
            timers.entries[i].as_mut().unwrap().arm = None;
            fired += 1;
            timers.wakeups = timers.wakeups.saturating_add(1);
            timers.late_ns = timers
                .late_ns
                .saturating_add(now.saturating_sub(arm.deadline_ns));
            if entry.class == TimerClass::Soft {
                timers.soft_wakeups = timers.soft_wakeups.saturating_add(1);
                if now > arm.deadline_ns.saturating_add(entry.slack) {
                    timers.slack_overruns = timers.slack_overruns.saturating_add(1);
                }
            }
        }
        Ok(fired)
    }

    #[test]
    fn active_index_matches_linear_poll() {
        for cursor in [0, 1, 63, 64, 65, 127, 192, 255] {
            for dense in [false, true] {
                for budget in [0, 1, 2, 256, 300] {
                    for error in [None, Some(Error::Busy), Some(Error::Again), Some(Error::Io)] {
                        let mut indexed = Timers::new();
                        let mut reference = Timers::new();
                        let mut actual = Backend::default();
                        let mut expected = Backend::default();
                        for i in 0..TIMER_CAPACITY {
                            for (t, b) in
                                [(&mut indexed, &mut actual), (&mut reference, &mut expected)]
                            {
                                t.register(key(i), TimerClass::Soft, 2).unwrap();
                                if dense || [0, 63, 64, 127, 128, 255].contains(&i) {
                                    let deadline = if i == 64 { 20 } else { 5 };
                                    t.arm(key(i), deadline, 0, b).unwrap();
                                }
                            }
                        }
                        indexed.cursor = cursor;
                        reference.cursor = cursor;
                        actual.fire_error = error.map(|e| (key(63), e));
                        expected.fire_error = actual.fire_error;
                        for now in [10, 20, 21] {
                            assert_eq!(
                                indexed.poll(now, budget, &mut actual),
                                linear_poll(&mut reference, now, budget, &mut expected)
                            );
                            assert_eq!(actual.attempted, expected.attempted);
                            assert_eq!(indexed.cursor, reference.cursor);
                            assert_eq!(indexed.wakeups, reference.wakeups);
                            assert_eq!(indexed.late_ns, reference.late_ns);
                            assert_eq!(indexed.soft_observation(), reference.soft_observation());
                            for i in 0..TIMER_CAPACITY {
                                assert_eq!(
                                    indexed.entries[i].unwrap().arm,
                                    reference.entries[i].unwrap().arm
                                );
                            }
                            check_index(&indexed);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn active_index_preserves_failed_backend_operations_and_slot_reuse() {
        let mut timers = Timers::new();
        let mut backend = Backend::default();
        let k = key(0);
        timers.register(k, TimerClass::HardDeadline, 0).unwrap();
        backend.arm_error = Some(Error::Io);
        assert_eq!(timers.arm(k, 5, 0, &mut backend), Err(Error::Io));
        check_index(&timers);
        backend.arm_error = None;
        let original = timers.arm(k, 5, 0, &mut backend).unwrap();
        backend.arm_error = Some(Error::Io);
        assert_eq!(timers.arm(k, 9, 0, &mut backend), Err(Error::Io));
        assert_eq!(timers.entries[0].unwrap().arm, Some(original));
        backend.cancel_error = Some(Error::Busy);
        assert_eq!(timers.cancel(k, &mut backend), Err(Error::Busy));
        assert_eq!(timers.unregister(k), Err(Error::Busy));
        check_index(&timers);
        backend.cancel_error = None;
        timers.cancel(k, &mut backend).unwrap();
        timers.unregister(k).unwrap();
        let next = ObjectKey { generation: 2, ..k };
        timers.register(next, TimerClass::HardDeadline, 0).unwrap();
        assert_eq!(timers.cancel(k, &mut backend), Err(Error::Stale));
        assert_eq!(timers.poll(10, 1, &mut backend), Ok(0));
        assert!(backend.attempted.is_empty());
        backend.arm_error = None;
        timers.arm(next, 11, 10, &mut backend).unwrap();
        assert_eq!(timers.poll(9, 1, &mut backend), Err(Error::Stale));
        assert_eq!(timers.poll(11, 1, &mut backend), Ok(1));
        assert_eq!(backend.attempted, [next]);
        check_index(&timers);
    }
}
