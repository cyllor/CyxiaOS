//! Gate-admitted preparation observations only; never replay authority.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{
    domains::{ApplyId, Error, PolicyStamp},
    policy::ExecutionState,
};
pub const BYTES: usize = 6144;
pub const MAGIC: u64 = 0x4359505250473031;
pub const OUTER_GATE_UNOBSERVED: u64 = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity(pub [u64; 10]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Reason {
    AuthError = 1,
    OtherError = 2,
    JobReset = 3,
    DesiredReset = 4,
    Advance = 5,
    AlreadyReady = 6,
    ScanComplete = 7,
}
#[derive(Clone, Copy)]
pub struct Job {
    pub controller: u64,
    pub sequence: u64,
    pub cpu: u64,
    pub read_only: bool,
    pub family: Option<(u16, u16)>,
    pub target: [u64; 2],
    pub started_ns: u64,
    pub completion: bool,
}
#[derive(Clone, Copy)]
pub struct Blocker {
    pub slot: usize,
    pub reason: u64,
    pub apply: ApplyId,
    pub stamp: PolicyStamp,
    pub state: ExecutionState,
    pub started: bool,
    pub observed: bool,
    pub predicate_at: Option<u64>,
}
#[derive(Clone, Copy)]
pub struct Observation {
    pub reason: Reason,
    pub stage: u64,
    pub result: Result<bool, Error>,
    pub service_entry_ns: u64,
    pub before: usize,
    pub end: usize,
    pub after: usize,
    pub job: Option<Job>,
    pub prepared_count: usize,
    pub blocker: Option<Blocker>,
}
// Conservative additional temporary allowance: caller/callee observations,
// identity copies, retained Job metadata, snapshot construction and scalars.
// The original full stack reservation remains; this is not a measured peak.
pub const LOCAL_BYTES: usize = 3 * core::mem::size_of::<Observation>()
    + 3 * core::mem::size_of::<Identity>()
    + 2 * core::mem::size_of::<Option<Job>>()
    + 2 * core::mem::size_of::<[u64; 16]>()
    + 32 * core::mem::size_of::<u64>();
#[repr(C, align(64))]
struct Slot([AtomicU64; 128]);
impl Slot {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 128])
    }
    fn get(&self, i: usize) -> u64 {
        self.0[i].load(Ordering::Relaxed)
    }
    fn put(&self, i: usize, v: u64) {
        self.0[i].store(v, Ordering::Relaxed)
    }
    fn flag(&self, bits: u64) {
        self.put(4, self.get(4) | bits)
    }
    fn begin(&self) -> Option<u64> {
        let old = self.get(0);
        if old & 1 != 0 {
            self.flag(4);
            return None;
        }
        let Some(end) = old.checked_add(2) else {
            self.flag(1);
            return None;
        };
        self.0[0].fetch_add(1, Ordering::AcqRel);
        Some(end)
    }
    fn finish(&self, end: u64) {
        self.0[0].store(end, Ordering::Release)
    }
    fn increment(&self, i: usize) -> u64 {
        let old = self.get(i);
        let value = match old.checked_add(1) {
            Some(v) => v,
            None => {
                self.flag(1);
                u64::MAX
            }
        };
        self.put(i, value);
        value
    }
    fn snapshot_at(&self, at: usize, words: &[u64; 16]) {
        for (i, v) in words.iter().copied().enumerate() {
            self.put(at + i, v)
        }
    }
}
#[repr(C, align(64))]
pub struct Bank([Slot; 6]);
impl Bank {
    pub const fn new() -> Self {
        Self([const { Slot::new() }; 6])
    }
    /// Caller retains the original Root gate for every write, including slot selection.
    pub fn observe(&self, identity: Identity, o: Observation) {
        let mut empty = None;
        let mut found = None;
        for (i, slot) in self.0.iter().enumerate() {
            let seq = slot.get(0);
            if seq == 0 {
                if empty.is_none() {
                    empty = Some(i);
                }
                continue;
            }
            if seq & 1 != 0 {
                slot.flag(4);
                return;
            }
            if slot.get(5) == identity.0[0] && slot.get(6) == identity.0[1] {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found.or(empty) else {
            let slot = &self.0[5];
            if let Some(end) = slot.begin() {
                slot.flag(2);
                slot.finish(end);
            }
            return;
        };
        let slot = &self.0[i];
        let fresh = slot.get(0) == 0;
        let Some(end) = slot.begin() else {
            return;
        };
        if fresh {
            slot.put(1, MAGIC);
            slot.put(2, 1);
            slot.put(3, 128);
            slot.put(4, OUTER_GATE_UNOBSERVED);
            for (j, v) in identity.0.into_iter().enumerate() {
                slot.put(5 + j, v);
            }
        } else if (0..10).any(|j| slot.get(5 + j) != identity.0[j]) {
            slot.flag(4);
            slot.finish(end);
            return;
        }
        if !identity.valid() || !o.valid() {
            slot.flag(4);
            slot.finish(end);
            return;
        }
        let ordinal = slot.increment(15);
        let category = match o.reason {
            Reason::AuthError => 17,
            Reason::OtherError => 18,
            Reason::JobReset => 19,
            Reason::DesiredReset => 20,
            Reason::Advance => 21,
            Reason::AlreadyReady => 22,
            Reason::ScanComplete => 23,
        };
        slot.increment(category);
        slot.put(24, slot.get(24).max(o.before.max(o.after) as u64));
        slot.put(25, o.service_entry_ns);
        slot.put(26, o.stage);
        slot.put(27, result_word(o.result));
        slot.put(28, o.before as u64);
        slot.put(29, o.end as u64);
        slot.put(30, o.after as u64);
        let ranges: &[(usize, usize)] = match o.reason {
            Reason::AuthError => &[(32, 48)],
            Reason::JobReset => &[(64, 80)],
            Reason::DesiredReset => &[(64, 80), (96, 112)],
            _ => &[],
        };
        if !ranges.is_empty() {
            let words = o.words(ordinal);
            for &(first, last) in ranges {
                if slot.get(first) == 0 {
                    slot.snapshot_at(first, &words);
                }
                slot.snapshot_at(last, &words);
            }
        }
        slot.finish(end);
    }
    #[cfg(test)]
    pub fn snapshot(&self, slot: usize) -> [u64; 128] {
        core::array::from_fn(|i| self.0[slot].0[i].load(Ordering::Acquire))
    }
    #[cfg(test)]
    pub fn seed_counter(&self, slot: usize, index: usize, value: u64) {
        self.0[slot].0[index].store(value, Ordering::Relaxed)
    }
}
#[used]
#[unsafe(no_mangle)]
pub static REPLAY_PREPARATION_PROGRESS: Bank = Bank::new();
const _: () = assert!(core::mem::size_of::<Bank>() == BYTES);

impl Identity {
    fn valid(self) -> bool {
        self.0[..7].iter().all(|v| *v != 0) && matches!(self.0[8], 1 | 2) && self.0[9] != 0
    }
}
fn result_word(result: Result<bool, Error>) -> u64 {
    match result {
        Ok(false) => 1,
        Ok(true) => 2,
        Err(e) => 3 | ((e as u64 + 1) << 8),
    }
}
impl Observation {
    fn valid(&self) -> bool {
        if [self.before, self.end, self.after].iter().any(|v| *v > 512) {
            return false;
        }
        let branch = match self.reason {
            Reason::AuthError => self.stage == 1 && self.result.is_err(),
            Reason::OtherError => matches!(self.stage, 2 | 3) && self.result.is_err(),
            Reason::JobReset => {
                self.stage == 5
                    && self.result == Ok(false)
                    && (self.job.is_some() || self.prepared_count != 0)
                    && self.after == 0
                    && self.end == 0
            }
            Reason::DesiredReset => {
                self.stage == 6
                    && self.result == Ok(false)
                    && self.after == 0
                    && self.blocker.is_some_and(|b| {
                        matches!(b.reason, 1 | 2 | 4) && b.slot >= self.before && b.slot < self.end
                    })
            }
            Reason::Advance => {
                self.stage == 7
                    && self.result == Ok(false)
                    && self.after == self.end
                    && self.after < 512
                    && self.end == self.before + 8
            }
            Reason::AlreadyReady => {
                self.stage == 4
                    && self.result == Ok(true)
                    && self.before == self.after
                    && self.end == 0
            }
            Reason::ScanComplete => {
                self.stage == 8
                    && self.result == Ok(true)
                    && self.after == 512
                    && self.end == 512
                    && self.before + 8 == 512
            }
        };
        branch
            && (self.stage >= 4 || [self.before, self.end, self.after] == [0, 0, 0])
            && (self.reason == Reason::JobReset || (self.job.is_none() && self.prepared_count == 0))
            && (self.reason == Reason::DesiredReset || self.blocker.is_none())
    }
    fn words(self, ordinal: u64) -> [u64; 16] {
        let mut w = [0; 16];
        w[0] = ordinal;
        w[1] = self.service_entry_ns;
        let (tag, error) = match self.result {
            Ok(false) => (1, 0),
            Ok(true) => (2, 0),
            Err(e) => (3, e as u64 + 1),
        };
        w[2] = self.reason as u64
            | (self.stage << 8)
            | (tag << 16)
            | (error << 18)
            | (u64::from(self.job.is_some_and(|j| j.family.is_some())) << 26)
            | (u64::from(self.stage >= 4) << 27)
            | (u64::from(self.stage >= 6) << 28)
            | (u64::from(self.blocker.is_some()) << 29);
        w[3] = self.before as u64 | ((self.end as u64) << 10) | ((self.after as u64) << 20);
        if self.reason == Reason::JobReset {
            w[4] = u64::from(self.job.is_some());
            w[5] = self.prepared_count as u64;
            if let Some(j) = self.job {
                w[6] = j.controller;
                w[7] = j.sequence;
                w[8] = j.cpu;
                w[9] = u64::from(j.read_only);
                if let Some((d, k)) = j.family {
                    w[10] = u64::from(d);
                    w[11] = u64::from(k);
                }
                w[12] = j.target[0];
                w[13] = j.target[1];
                w[14] = j.started_ns;
                w[15] = u64::from(j.completion);
            }
        }
        if let Some(b) = self.blocker {
            w[4] = b.slot as u64 + 1;
            w[5] = b.reason;
            w[6] = b.apply.boot_epoch;
            w[7] = b.apply.controller_epoch;
            w[8] = b.apply.plan_seq;
            w[9] = b.apply.target.id;
            w[10] = b.apply.target.generation;
            w[11] = b.stamp.version;
            w[12] = b.stamp.snapshot_ns;
            w[13] = b.stamp.installed_until_ns;
            w[14] = b.predicate_at.unwrap_or(0);
            let (state, error) = match b.state {
                ExecutionState::Pending => (0, 0),
                ExecutionState::Applied => (1, 0),
                ExecutionState::Failed(e) => (2, e as u64 + 1),
                ExecutionState::Unknown => (3, 0),
            };
            w[15] = u64::from(b.apply.action_index)
                | (state << 16)
                | (error << 18)
                | (u64::from(b.started) << 26)
                | (u64::from(b.observed) << 27)
                | (u64::from(b.predicate_at.is_some()) << 28);
        }
        w
    }
}
const _: () = assert!(LOCAL_BYTES <= 4096);
