//! Passive facts from the original acceptance and publication callbacks.
use cyxia_prototype::{domains::Error, policy::SubmissionObservation};

pub(crate) const MAGIC: u64 = 0x4359_5355_424d_0001;
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AcceptStage {
    Start = 1,
    Context = 2,
    Verify = 3,
    DecodeBudget = 4,
    ReadOnlyModel = 5,
    ReadOnlyLegal = 6,
    Executor = 7,
    Submit = 8,
    Receipt = 9,
    ReadOnlyComplete = 10,
    Aborted = 11,
}
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Callback {
    AuthorizeModel = 1,
    AuthorizeBaseline = 2,
    AuthorizeRecovery = 3,
    Check = 4,
    Prepare = 5,
    Revalidate = 6,
    Publish = 7,
}
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Stage {
    Enter = 1,
    ModelBinding = 2,
    ScopeAuthority = 3,
    Context = 4,
    Family = 5,
    Legal = 6,
    Dependencies = 7,
    OldDesired = 8,
    Selection = 9,
    PrepareIndex = 10,
    PreparedCount = 11,
    Stamp = 12,
    CommitTime = 13,
    CommitDeadline = 14,
    CommitCpu = 15,
    ModelHash = 16,
    ScopeCommit = 17,
    RootPublish = 18,
    DesiredWrites = 19,
}
#[derive(Clone, Copy)]
pub(crate) struct Facts {
    enabled: bool,
    sequence: u64,
    read_only: bool,
    generations: [u64; 4],
    accept: AcceptStage,
    registry: Option<SubmissionObservation>,
    callback: u8,
    stage: u8,
    returned: u8,
    error: u64,
    calls: u64,
    cancellations: u64,
}
const _: () = assert!(core::mem::size_of::<Facts>() <= 192);
impl Facts {
    pub(crate) const fn new(
        sequence: u64,
        read_only: bool,
        generations: [u64; 4],
        enabled: bool,
    ) -> Self {
        Self {
            enabled,
            sequence,
            read_only,
            generations,
            accept: AcceptStage::Start,
            registry: None,
            callback: 0,
            stage: 0,
            returned: 0,
            error: 0,
            calls: 0,
            cancellations: 0,
        }
    }
    pub(crate) const fn disabled() -> Self {
        Self::new(0, false, [0; 4], false)
    }
    pub(crate) fn accept(&mut self, stage: AcceptStage) {
        if self.enabled {
            self.accept = stage;
        }
    }
    pub(crate) fn enter(&mut self, callback: Callback) {
        if self.enabled {
            self.callback = callback as u8;
            self.stage = Stage::Enter as u8;
            self.returned = 1;
            self.error = 0;
            self.calls = self.calls.saturating_add(1);
        }
    }
    pub(crate) fn at(&mut self, stage: Stage) {
        if self.enabled {
            self.stage = stage as u8;
        }
    }
    pub(crate) fn returned(&mut self, result: Result<(), Error>) {
        if self.enabled {
            self.returned = if result.is_ok() { 2 } else { 3 };
            self.error = result.err().map_or(0, |e| e as u64 + 1);
        }
    }
    pub(crate) fn cancelled(&mut self) {
        if self.enabled {
            self.cancellations = self.cancellations.saturating_add(1);
        }
    }
    pub(crate) fn observed(&mut self, observation: &SubmissionObservation) {
        if self.enabled {
            self.registry = Some(*observation);
        }
    }
    pub(crate) fn words(self, result: Result<u64, Error>, aborted: bool) -> [u64; 27] {
        if !self.enabled {
            return [0; 27];
        }
        let mut words = [0; 27];
        words[..6].copy_from_slice(&[
            MAGIC,
            1,
            self.accept as u64,
            u64::from(self.read_only),
            if result.is_ok() { 1 } else { 2 },
            result.err().map_or(0, |e| e as u64 + 1),
        ]);
        if let Some(o) = self.registry {
            words[6..14].copy_from_slice(&[
                1,
                o.stage as u64,
                if o.result.is_ok() { 1 } else { 2 },
                o.result.err().map_or(0, |e| e as u64 + 1),
                o.version,
                u64::from(o.preparation_started),
                u64::from(o.version != 0),
                o.published_ns,
            ]);
        }
        words[14..23].copy_from_slice(&[
            u64::from(self.callback),
            u64::from(self.stage),
            u64::from(self.returned),
            self.error,
            self.calls,
            self.cancellations,
            self.sequence,
            1 | (u64::from(!aborted) << 1),
            u64::from(aborted),
        ]);
        words[23..].copy_from_slice(&self.generations);
        words
    }
}
