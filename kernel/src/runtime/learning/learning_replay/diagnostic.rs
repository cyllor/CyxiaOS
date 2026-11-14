//! First retained producer failure, copied from its actual call site. This
//! bank is diagnostic only; it does not participate in replay authorization.
use core::sync::atomic::{AtomicU64, Ordering};
use cyxia_prototype::{domains::Error, policy::ExecutionState};

pub(super) const MAGIC: u64 = 0x4359_524f_574e_3133;

#[derive(Clone, Copy)]
#[repr(u64)]
pub(super) enum Site {
    Entry = 1,
    Prewarm = 2,
    Prepare = 10,
    Reserve = 11,
    Freeze = 12,
    Start = 13,
    ActivateSetup = 20,
    ActivateRoot = 21,
    ActivateFault = 22,
    ActivatePublished = 23,
    ActivateBaseline = 24,
    ActivateWork = 25,
    ActivateWindows = 26,
    ActivateCommit = 27,
    RunSetup = 30,
    RunWaitingRoot = 31,
    RunWaitingFault = 32,
    RunRequest = 33,
    RunArm = 34,
    RunRequestCommit = 35,
    RunWork = 36,
    RunRoot = 37,
    RunFault = 38,
    RunBaselineCursor = 39,
    RunBaselineReceipt = 40,
    RunBaselineRecord = 41,
    RunBaselineCommit = 42,
    RunClose = 43,
    RunRenew = 44,
    Drain = 50,
    OtherPhase = 60,
}

/// Word 0 seqlock, 1 magic, 2 schema=1, 3 entry phase+1, 4 site,
/// 5 original domain error+1, 6 retained effective domain error+1,
/// 7 evidence error category, 8 nested learning error+1, 9 failure time,
/// 10 trial, 11 boot, 12 capture generation, 13 root token, 14/15 family,
/// 16 candidate=1/baseline=2, 17/18 target, 19 cursor, 20 baseline sequence,
/// 21 first, 22 observation, 23 last root phase+1, 24 retained root fault+1,
/// 25 entry flags(first_ready/activation_entered/complete/partial_start),
/// 26 request ID at entry, 27/28 last receipt plan/version, 29/30 state/error,
/// 31 service entry time. No missing value is substituted with a success.
#[repr(C, align(64))]
pub struct Evidence([AtomicU64; 32]);
impl Evidence {
    pub const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 32])
    }
    fn first(&self, words: &[u64; 32]) -> bool {
        if self.0[0]
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        for (slot, value) in self.0.iter().zip(words).skip(1) {
            slot.store(*value, Ordering::Relaxed);
        }
        self.0[0].store(2, Ordering::Release);
        true
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> [u64; 32] {
        core::array::from_fn(|i| self.0[i].load(Ordering::Acquire))
    }
}
#[unsafe(no_mangle)]
pub static REPLAY_OWNER_EVIDENCE: Evidence = Evidence::new();
const _: () = assert!(core::mem::size_of::<Evidence>() == 256);

pub(super) struct Attempt {
    pub words: [u64; 32],
}
impl Attempt {
    pub fn new(started_ns: u64) -> Self {
        let mut words = [0; 32];
        words[1] = MAGIC;
        words[2] = 1;
        words[4] = Site::Entry as u64;
        words[31] = started_ns;
        Self { words }
    }
    pub fn site(&mut self, site: Site) {
        self.words[4] = site as u64;
        self.words[7] = 0;
        self.words[8] = 0;
    }
    pub fn nested(&mut self, category: u64, error: Option<cyxia_prototype::learning::Error>) {
        self.words[7] = category;
        self.words[8] = error.map_or(0, |e| e as u64 + 1);
    }
    pub fn receipt(&mut self, receipt: Option<(u64, u64, ExecutionState)>) {
        let Some((plan, version, state)) = receipt else {
            return;
        };
        self.words[27] = plan;
        self.words[28] = version;
        let (tag, error) = match state {
            ExecutionState::Pending => (1, 0),
            ExecutionState::Applied => (2, 0),
            ExecutionState::Failed(error) => (3, error as u64 + 1),
            ExecutionState::Unknown => (4, 0),
        };
        self.words[29] = tag;
        self.words[30] = error;
    }
    pub fn retain(&mut self, original: Error, retained: Option<Error>, failed_ns: u64) {
        self.retain_in(&REPLAY_OWNER_EVIDENCE, original, retained, failed_ns);
    }
    pub(super) fn retain_in(
        &mut self,
        bank: &Evidence,
        original: Error,
        retained: Option<Error>,
        failed_ns: u64,
    ) -> bool {
        if retained.is_none() && matches!(original, Error::Busy | Error::Again | Error::NotReady) {
            return false;
        }
        self.words[5] = original as u64 + 1;
        self.words[6] = retained.unwrap_or(original) as u64 + 1;
        self.words[9] = failed_ns;
        self.words[24] = retained.map_or(0, |e| e as u64 + 1);
        bank.first(&self.words)
    }
}
