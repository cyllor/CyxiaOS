//! Bounded protected-owner ingress for local replay CPU and request events.
//! Recording a trace never creates a training label. The replay/receipt owner
//! must still authenticate all nodes and the full `reward::Trial` linkage.
use super::{
    Error, Family,
    reward::{
        CpuClass, CpuCoverage, CpuInterval, MAX_CPU_INTERVALS, MAX_REQUESTS, OBSERVATION_NS,
        RequestResult, WorkRequest,
    },
};
use crate::domains::ObjectKey;
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

pub mod init;
pub use init::{CaptureInit, InitComplete, InitPiece, InitValue};

pub const MAX_SOURCES: usize = 32;
pub const MAX_OPEN: usize = 128;
static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunKey {
    pub boot_epoch: u64,
    pub trial_id: u64,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub key: RunKey,
    pub family: Family,
    pub node: [u8; 32],
    pub first_ns: u64,
    pub observation_ns: u64,
    /// Protected replay manifest: all controlled owners, requests and peers.
    pub frozen_scope_hash: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Source {
    pub owner: ObjectKey,
    pub class: CpuClass,
    pub allowed_cores: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenRequest {
    pub id: u64,
    pub owner: ObjectKey,
    pub arrived_ns: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceToken {
    instance: u64,
    index: u16,
}
#[derive(Debug)]
pub struct SpanToken {
    instance: u64,
    serial: u64,
    index: u16,
    core: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seal {
    pub key: RunKey,
    pub event_hash: [u8; 32],
    pub frozen_scope_hash: [u8; 32],
    pub closing_ns: u64,
    pub intervals: u32,
    pub requests: u32,
    pub exclusion: Option<Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub key: Option<RunKey>,
    pub intervals: usize,
    pub requests: usize,
    pub issued: usize,
    pub open: usize,
    pub closed_sources: usize,
    pub fault: Option<Error>,
    pub missing_events: u64,
    /// Raw owner-reported durations remain available even after storage fills.
    pub raw_tagged_ns: [u64; 4],
    pub ordinary_warmup_ns: u64,
    pub later_workload_ns: u64,
    pub sealed: Option<Seal>,
}
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct SourceState {
    source: Source,
    closed: bool,
    last_ns: u64,
}
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct Open {
    serial: u64,
    source: usize,
    core: u16,
    start_ns: u64,
}
#[derive(Clone, Copy)]
#[doc(hidden)]
pub struct RequestState {
    frozen: FrozenRequest,
    issued: bool,
    issued_observed_ns: u64,
    scheduled: bool,
    actual: RequestResult,
}
/// The logical release belongs to the immutable workload table. An admitted
/// scheduled request additionally records when its real queue took custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTiming {
    pub frozen: FrozenRequest,
    pub issued_observed_ns: Option<u64>,
    pub scheduled: bool,
}
const ZERO_KEY: ObjectKey = ObjectKey {
    id: 0,
    generation: 0,
};
const EMPTY_REQUEST: RequestState = RequestState {
    frozen: FrozenRequest {
        id: 0,
        owner: ZERO_KEY,
        arrived_ns: 0,
    },
    issued: false,
    issued_observed_ns: 0,
    scheduled: false,
    actual: RequestResult::Pending,
};
const EMPTY_WORK: WorkRequest = WorkRequest {
    id: 0,
    arrived_ns: 0,
    result: RequestResult::Pending,
};
const EMPTY_CPU: CpuInterval = CpuInterval {
    node: [0; 32],
    core: 0,
    start_ns: 0,
    end_ns: 0,
    class: CpuClass::Policy,
};

/// Storage is caller-owned and must be charged to its real protected pool.
/// `empty` permits in-place static construction without a large stack copy.
pub struct Capture<const I: usize, const R: usize> {
    config: Option<Config>,
    instance: u64,
    boot_epoch: u64,
    high_generation: u64,
    serial: u64,
    sources: [Option<SourceState>; MAX_SOURCES],
    source_count: usize,
    open: [Option<Open>; MAX_OPEN],
    intervals: [CpuInterval; I],
    interval_count: usize,
    request_state: [RequestState; R],
    requests: [WorkRequest; R],
    request_count: usize,
    fault: Option<Error>,
    missing: u64,
    raw: [u64; 4],
    warmup: u64,
    later: u64,
    events: Option<Sha256>,
    sealed: Option<Seal>,
}
impl<const I: usize, const R: usize> Default for Capture<I, R> {
    fn default() -> Self {
        Self::empty()
    }
}
impl<const I: usize, const R: usize> Capture<I, R> {
    pub const fn empty() -> Self {
        Self {
            config: None,
            instance: 0,
            boot_epoch: 0,
            high_generation: 0,
            serial: 0,
            sources: [None; MAX_SOURCES],
            source_count: 0,
            open: [None; MAX_OPEN],
            intervals: [EMPTY_CPU; I],
            interval_count: 0,
            request_state: [EMPTY_REQUEST; R],
            requests: [EMPTY_WORK; R],
            request_count: 0,
            fault: None,
            missing: 0,
            raw: [0; 4],
            warmup: 0,
            later: 0,
            events: None,
            sealed: None,
        }
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.taint(error);
        Err(error)
    }
    fn active(&self) -> Result<Config, Error> {
        if self.sealed.is_some() {
            return Err(Error::State);
        }
        self.config.ok_or(Error::State)
    }
    fn event(&mut self, kind: u64, values: &[u64]) {
        if let Some(hash) = self.events.as_mut() {
            hash.update(kind.to_le_bytes());
            for value in values {
                hash.update(value.to_le_bytes());
            }
        }
    }
    pub fn start(
        &mut self,
        config: Config,
        sources: &[Source],
        requests: &[FrozenRequest],
    ) -> Result<(), Error> {
        if self.config.is_some() {
            return Err(Error::Unknown);
        }
        config.family.index()?;
        let end = config
            .observation_ns
            .checked_add(OBSERVATION_NS)
            .ok_or(Error::Numeric)?;
        end.checked_add(5_000_000_000).ok_or(Error::Numeric)?;
        if I == 0
            || I > MAX_CPU_INTERVALS
            || R > MAX_REQUESTS
            || requests.len() > R
            || requests.len() < 100
            || sources.is_empty()
            || sources.len() > MAX_SOURCES
        {
            return Err(Error::Capacity);
        }
        if config.key.boot_epoch == 0
            || config.key.trial_id == 0
            || config.key.generation == 0
            || config.node == [0; 32]
            || config.frozen_scope_hash == [0; 32]
            || config.first_ns > config.observation_ns
            || config.observation_ns < 1_000_000_000
        {
            return Err(Error::Evidence);
        }
        if self.boot_epoch != 0
            && (config.key.boot_epoch != self.boot_epoch
                || config.key.generation <= self.high_generation)
        {
            return Err(Error::Stale);
        }
        let mut classes = 0u8;
        for (index, source) in sources.iter().enumerate() {
            if source.owner.id == 0
                || source.owner.generation == 0
                || source.allowed_cores == 0
                || (source.class == CpuClass::Optional && config.family.domain != 13)
                || sources[..index]
                    .iter()
                    .any(|prior| prior.owner == source.owner && prior.class == source.class)
            {
                return Err(Error::Evidence);
            }
            classes |= 1 << source.class as u8;
        }
        if classes != if config.family.domain == 13 { 15 } else { 7 } {
            return Err(Error::Evidence);
        }
        for (index, request) in requests.iter().enumerate() {
            if request.id == 0
                || request.owner.id == 0
                || request.owner.generation == 0
                || request.arrived_ns < config.observation_ns
                || request.arrived_ns >= end
                || requests[..index].iter().any(|prior| prior.id == request.id)
            {
                return Err(Error::Evidence);
            }
        }
        let instance = NEXT_CAPTURE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::Capacity)?;
        self.instance = instance;
        self.boot_epoch = config.key.boot_epoch;
        self.high_generation = config.key.generation;
        self.serial = 0;
        self.config = Some(config);
        self.source_count = sources.len();
        self.sources.fill(None);
        self.open.fill(None);
        self.interval_count = 0;
        self.request_count = requests.len();
        self.fault = None;
        self.missing = 0;
        self.raw = [0; 4];
        self.warmup = 0;
        self.later = 0;
        self.sealed = None;
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_PROTECTED_LOCAL_TRACE_1\0");
        hash.update(config.node);
        hash.update(config.frozen_scope_hash);
        self.events = Some(hash);
        self.event(
            0,
            &[
                config.key.boot_epoch,
                config.key.trial_id,
                config.key.generation,
                u64::from(config.family.domain),
                u64::from(config.family.kind),
                config.first_ns,
                config.observation_ns,
                sources.len() as u64,
                requests.len() as u64,
            ],
        );
        for (index, source) in sources.iter().enumerate() {
            self.sources[index] = Some(SourceState {
                source: *source,
                closed: false,
                last_ns: 0,
            });
            self.event(
                1,
                &[
                    index as u64,
                    source.owner.id,
                    source.owner.generation,
                    source.class as u64,
                    source.allowed_cores,
                ],
            );
        }
        for (index, request) in requests.iter().enumerate() {
            self.request_state[index] = RequestState {
                frozen: *request,
                issued: false,
                issued_observed_ns: 0,
                scheduled: false,
                actual: RequestResult::Pending,
            };
            self.requests[index] = WorkRequest {
                id: request.id,
                arrived_ns: request.arrived_ns,
                result: RequestResult::Pending,
            };
            self.event(
                2,
                &[
                    request.id,
                    request.owner.id,
                    request.owner.generation,
                    request.arrived_ns,
                ],
            );
        }
        Ok(())
    }
    pub fn source(&self, owner: ObjectKey, class: CpuClass) -> Result<SourceToken, Error> {
        self.active()?;
        let index = self.sources[..self.source_count]
            .iter()
            .position(|s| s.is_some_and(|s| s.source.owner == owner && s.source.class == class))
            .ok_or(Error::Evidence)?;
        Ok(SourceToken {
            instance: self.instance,
            index: index as u16,
        })
    }
    fn source_state(&self, token: SourceToken, core: u16) -> Result<SourceState, Error> {
        self.active()?;
        if token.instance != self.instance || usize::from(token.index) >= self.source_count {
            return Err(Error::Stale);
        }
        let state = self.sources[usize::from(token.index)].ok_or(Error::Evidence)?;
        if state.closed || core >= 64 || state.source.allowed_cores & (1u64 << core) == 0 {
            return Err(Error::State);
        }
        Ok(state)
    }
    /// One logical source cannot nest on the same physical CPU. Other tagged
    /// sources may overlap; reward::union_cpu later deduplicates P/E/O.
    pub fn begin(
        &mut self,
        token: SourceToken,
        core: u16,
        now_ns: u64,
    ) -> Result<SpanToken, Error> {
        self.source_state(token, core)?;
        if self
            .open
            .iter()
            .flatten()
            .any(|span| span.source == usize::from(token.index) && span.core == core)
        {
            return self.fail(Error::Conflict);
        }
        let Some(index) = self.open.iter().position(Option::is_none) else {
            return self.fail(Error::Capacity);
        };
        let Some(serial) = self.serial.checked_add(1) else {
            return self.fail(Error::Numeric);
        };
        self.serial = serial;
        self.open[index] = Some(Open {
            serial: self.serial,
            source: usize::from(token.index),
            core,
            start_ns: now_ns,
        });
        self.event(
            3,
            &[self.serial, u64::from(token.index), u64::from(core), now_ns],
        );
        Ok(SpanToken {
            instance: self.instance,
            serial: self.serial,
            index: index as u16,
            core,
        })
    }
    pub fn end(&mut self, token: SpanToken, core: u16, now_ns: u64) -> Result<(), Error> {
        self.active()?;
        if token.instance != self.instance
            || core != token.core
            || usize::from(token.index) >= MAX_OPEN
        {
            return Err(Error::Stale);
        }
        let span = self.open[usize::from(token.index)].ok_or(Error::Stale)?;
        if span.serial != token.serial || span.core != core {
            return Err(Error::Stale);
        }
        if now_ns < span.start_ns {
            return self.fail(Error::Evidence);
        }
        // A real exit clears only this span. Failure to retain its bytes still
        // taints the entire sample; no CPU or resource obligation is invented.
        self.open[usize::from(token.index)] = None;
        self.event(4, &[token.serial, now_ns]);
        self.record(
            SourceToken {
                instance: self.instance,
                index: span.source as u16,
            },
            core,
            span.start_ns,
            now_ns,
        )
    }
    /// Ingress for an owner which already measures its exact enter/exit pair.
    /// Native callers must supply its real physical CPU, never a budget quota.
    pub fn record(
        &mut self,
        token: SourceToken,
        core: u16,
        start_ns: u64,
        end_ns: u64,
    ) -> Result<(), Error> {
        let config = self.config.ok_or(Error::State)?;
        // A foreign/stale capability is unrelated to this run. A current
        // registered owner reporting real work on a closed source or wrong
        // CPU instead invalidates its own evidence; its raw time is retained.
        if token.instance != self.instance || usize::from(token.index) >= self.source_count {
            return Err(Error::Stale);
        }
        let state = self.sources[usize::from(token.index)].ok_or(Error::Evidence)?;
        let prohibited = self.sealed.is_some()
            || state.closed
            || core >= 64
            || state.source.allowed_cores & (1u64 << core) == 0;
        if end_ns < start_ns {
            return self.fail(Error::Evidence);
        }
        if prohibited {
            self.taint(Error::State);
        }
        let class = state.source.class;
        let Some(raw) = self.raw[class as usize].checked_add(end_ns - start_ns) else {
            return self.fail(Error::Numeric);
        };
        self.raw[class as usize] = raw;
        self.sources[usize::from(token.index)]
            .as_mut()
            .unwrap()
            .last_ns = state.last_ns.max(end_ns);
        self.event(
            5,
            &[u64::from(token.index), u64::from(core), start_ns, end_ns],
        );
        if prohibited {
            return Err(Error::State);
        }
        let observation_end = config.observation_ns + OBSERVATION_NS;
        let (begin, end) = match class {
            CpuClass::Policy | CpuClass::ExecutorAction => {
                (config.first_ns, observation_end + 5_000_000_000)
            }
            CpuClass::ExecutorWork | CpuClass::Optional => {
                // Persistent actions may need real owner demand to produce an
                // APPLIED receipt before the designated final warm second.
                // Retain that setup/warm workload separately; it is never part
                // of the ten-second reward CPU union. One-shots may also import
                // their actually pre-owned one-second warmup after activation.
                let ordinary_start = config.first_ns.min(config.observation_ns - 1_000_000_000);
                let Some(warmup) = self.warmup.checked_add(
                    end_ns
                        .min(config.observation_ns)
                        .saturating_sub(start_ns.max(ordinary_start)),
                ) else {
                    return self.fail(Error::Numeric);
                };
                let Some(later) = self
                    .later
                    .checked_add(end_ns.saturating_sub(start_ns.max(observation_end)))
                else {
                    return self.fail(Error::Numeric);
                };
                self.warmup = warmup;
                self.later = later;
                (config.observation_ns, observation_end)
            }
        };
        let interval = CpuInterval {
            node: config.node,
            core,
            start_ns: start_ns.max(begin),
            end_ns: end_ns.min(end),
            class,
        };
        let outside = match class {
            CpuClass::Policy | CpuClass::ExecutorAction => start_ns < begin || end_ns > end,
            CpuClass::ExecutorWork | CpuClass::Optional => {
                start_ns < config.first_ns.min(config.observation_ns - 1_000_000_000)
            }
        };
        if interval.start_ns < interval.end_ns {
            if let Some(last) = self
                .interval_count
                .checked_sub(1)
                .map(|i| &mut self.intervals[i])
                && last.class == class
                && last.core == core
                && last.end_ns == interval.start_ns
            {
                last.end_ns = interval.end_ns;
                if outside {
                    return self.fail(Error::Deadline);
                }
                return Ok(());
            }
            if self.interval_count == I {
                return self.fail(Error::Capacity);
            }
            self.intervals[self.interval_count] = interval;
            self.interval_count += 1;
        }
        if outside {
            return self.fail(Error::Deadline);
        }
        Ok(())
    }
    fn request_index(&self, owner: ObjectKey, id: u64) -> Result<usize, Error> {
        self.active()?;
        self.request_state[..self.request_count]
            .iter()
            .position(|r| r.frozen.id == id && r.frozen.owner == owner)
            .ok_or(Error::Evidence)
    }
    pub fn issued(&mut self, owner: ObjectKey, id: u64, actual_ns: u64) -> Result<(), Error> {
        let i = self.request_index(owner, id)?;
        if self.request_state[i].issued {
            return if !self.request_state[i].scheduled && self.requests[i].arrived_ns == actual_ns {
                Ok(())
            } else {
                self.fail(Error::Conflict)
            };
        }
        self.request_state[i].issued = true;
        self.request_state[i].issued_observed_ns = actual_ns;
        self.requests[i].arrived_ns = actual_ns;
        self.event(6, &[id, owner.id, owner.generation, actual_ns]);
        if actual_ns != self.request_state[i].frozen.arrived_ns {
            return self.fail(Error::Evidence);
        }
        Ok(())
    }
    /// Protected queue admission, not a delayed observation of a request. The
    /// caller must already own the queued workload and promise its frozen
    /// release. Processing delay is measured from that release; backdating a
    /// queue admission after the release is rejected and taints this capture.
    pub fn arm_scheduled(
        &mut self,
        owner: ObjectKey,
        id: u64,
        observed_ns: u64,
    ) -> Result<(), Error> {
        let i = self.request_index(owner, id)?;
        let state = self.request_state[i];
        if state.issued {
            return if state.scheduled && state.issued_observed_ns == observed_ns {
                Ok(())
            } else {
                self.fail(Error::Conflict)
            };
        }
        if observed_ns > state.frozen.arrived_ns {
            return self.fail(Error::Deadline);
        }
        self.request_state[i].issued = true;
        self.request_state[i].scheduled = true;
        self.request_state[i].issued_observed_ns = observed_ns;
        self.event(
            10,
            &[
                id,
                owner.id,
                owner.generation,
                state.frozen.arrived_ns,
                observed_ns,
            ],
        );
        Ok(())
    }
    pub fn result(
        &mut self,
        owner: ObjectKey,
        id: u64,
        result: RequestResult,
    ) -> Result<(), Error> {
        let i = self.request_index(owner, id)?;
        if !self.request_state[i].issued {
            return self.fail(Error::Order);
        }
        let previous = self.request_state[i].actual;
        if previous != RequestResult::Pending {
            return if previous == result {
                Ok(())
            } else {
                self.fail(Error::Conflict)
            };
        }
        let (code, at) = match result {
            RequestResult::Completed { finished_ns } => {
                if finished_ns < self.requests[i].arrived_ns {
                    return self.fail(Error::Evidence);
                }
                (1, finished_ns)
            }
            RequestResult::Rejected => (2, 0),
            RequestResult::TimedOut => (3, 0),
            RequestResult::Pending => return Ok(()),
        };
        self.request_state[i].actual = result;
        let end = self.active()?.observation_ns + OBSERVATION_NS;
        // A true completion after the fixed window is kept as raw evidence,
        // but the measured window outcome remains Pending with its penalty.
        self.requests[i].result = if at > end {
            RequestResult::Pending
        } else {
            result
        };
        self.event(7, &[id, code, at]);
        Ok(())
    }
    /// P/action owners first reconcile their policy/action operations. Work/O
    /// owners close sampling after the observation window; their unfinished
    /// workload requests keep their actual resource custody outside this log.
    /// This call is evidence of that transition, not a request to stop work.
    pub fn close_source(&mut self, token: SourceToken, now_ns: u64) -> Result<(), Error> {
        let config = self.active()?;
        if token.instance != self.instance || usize::from(token.index) >= self.source_count {
            return Err(Error::Stale);
        }
        if self
            .open
            .iter()
            .flatten()
            .any(|span| span.source == usize::from(token.index))
        {
            return Err(Error::Unknown);
        }
        let source = self.sources[usize::from(token.index)]
            .as_mut()
            .ok_or(Error::Evidence)?;
        let earliest = match source.source.class {
            CpuClass::Policy | CpuClass::ExecutorAction => config.first_ns,
            CpuClass::ExecutorWork | CpuClass::Optional => config.observation_ns + OBSERVATION_NS,
        };
        if now_ns < source.last_ns || now_ns < earliest {
            return Err(Error::Evidence);
        }
        if !source.closed {
            source.closed = true;
            source.last_ns = now_ns;
            self.event(8, &[u64::from(token.index), now_ns]);
        }
        Ok(())
    }
    /// A dropped ingress event is sticky, even if all later owners complete.
    pub fn taint(&mut self, reason: Error) {
        let first = self.fault.is_none();
        self.fault.get_or_insert(reason);
        let superseded = self.sealed.take().is_some();
        if first || superseded {
            self.event(10, &[reason as u64, u64::from(superseded)]);
        }
    }
    /// Merge collector contention losses before sealing. Known raw duration
    /// remains hashed and exportable, but absent interval boundaries can never
    /// masquerade as a complete union. A batched caller counts each loss once.
    pub fn missing_events(
        &mut self,
        class: CpuClass,
        count: u64,
        duration_ns: u64,
    ) -> Result<(), Error> {
        self.config.ok_or(Error::State)?;
        self.taint(Error::DataIncomplete);
        let Some(missing) = self.missing.checked_add(count) else {
            return self.fail(Error::Numeric);
        };
        let Some(raw) = self.raw[class as usize].checked_add(duration_ns) else {
            return self.fail(Error::Numeric);
        };
        self.missing = missing;
        self.raw[class as usize] = raw;
        self.event(11, &[class as u64, count, duration_ns]);
        Ok(())
    }
    pub fn status(&self) -> Status {
        Status {
            key: self.config.map(|c| c.key),
            intervals: self.interval_count,
            requests: self.request_count,
            issued: self.request_state[..self.request_count]
                .iter()
                .filter(|r| r.issued)
                .count(),
            open: self.open.iter().flatten().count(),
            closed_sources: self.sources[..self.source_count]
                .iter()
                .flatten()
                .filter(|s| s.closed)
                .count(),
            fault: self.fault,
            missing_events: self.missing,
            raw_tagged_ns: self.raw,
            ordinary_warmup_ns: self.warmup,
            later_workload_ns: self.later,
            sealed: self.sealed,
        }
    }
    pub fn seal(&mut self, now_ns: u64) -> Result<Seal, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        self.finish(now_ns, false)
    }
    /// Preserve an excluded run after all capture owners really closed. A
    /// frozen failed run can be exported/retired, never passed as full coverage.
    pub fn seal_incomplete(&mut self, now_ns: u64) -> Result<Seal, Error> {
        self.finish(now_ns, true)
    }
    fn finish(&mut self, now_ns: u64, incomplete: bool) -> Result<Seal, Error> {
        if let Some(seal) = self.sealed {
            return Ok(seal);
        }
        let config = self.active()?;
        if self.open.iter().any(Option::is_some) {
            return Err(Error::Unknown);
        }
        if self.sources[..self.source_count]
            .iter()
            .flatten()
            .any(|s| !s.closed)
        {
            return Err(Error::DataIncomplete);
        }
        if self.request_state[..self.request_count]
            .iter()
            .any(|r| !r.issued)
        {
            if !incomplete {
                return Err(Error::DataIncomplete);
            }
            self.fault.get_or_insert(Error::DataIncomplete);
        }
        if !incomplete && let Some(error) = self.fault {
            return Err(error);
        }
        let end = config.observation_ns + OBSERVATION_NS;
        if now_ns < end
            || self.sources[..self.source_count]
                .iter()
                .flatten()
                .any(|s| s.last_ns > now_ns)
        {
            return Err(Error::Deadline);
        }
        if now_ns > end + 5_000_000_000 {
            if !incomplete {
                return Err(Error::Deadline);
            }
            self.fault.get_or_insert(Error::Deadline);
        }
        if incomplete {
            self.fault.get_or_insert(Error::DataIncomplete);
        }
        self.event(
            9,
            &[
                now_ns,
                self.interval_count as u64,
                self.request_count as u64,
                self.raw[0],
                self.raw[1],
                self.raw[2],
                self.raw[3],
                self.warmup,
                self.later,
                self.missing,
                self.fault.map_or(0, |reason| reason as u64 + 1),
            ],
        );
        let seal = Seal {
            key: config.key,
            event_hash: self
                .events
                .as_ref()
                .ok_or(Error::State)?
                .clone()
                .finalize()
                .into(),
            frozen_scope_hash: config.frozen_scope_hash,
            closing_ns: now_ns,
            intervals: self.interval_count as u32,
            requests: self.request_count as u32,
            exclusion: self.fault,
        };
        self.sealed = Some(seal);
        Ok(seal)
    }
    pub fn coverage(&self, seal: Seal) -> Result<CpuCoverage, Error> {
        if self.sealed != Some(seal) {
            return Err(Error::Stale);
        }
        if let Some(error) = self.fault {
            return Err(error);
        }
        let config = self.config.ok_or(Error::State)?;
        let required = if config.family.domain == 13 { 7 } else { 3 };
        Ok(CpuCoverage {
            node: config.node,
            first_ns: config.first_ns,
            observation_ns: config.observation_ns,
            observation_end_ns: config.observation_ns + OBSERVATION_NS,
            closing_ns: seal.closing_ns,
            required,
            reported: required,
        })
    }
    /// Read-only raw evidence is retained on every incomplete/error path.
    pub fn intervals(&self) -> &[CpuInterval] {
        &self.intervals[..self.interval_count]
    }
    /// Reuse only the unused tail of an already sealed raw interval bank.
    /// These bytes are staging, not local evidence: they never change the
    /// local seal, event hash, interval count, coverage, or exported local view.
    /// A separate protected partner authority must authenticate them before a
    /// reward verifier may include them in a multi-node trial.
    pub fn stage_intervals(
        &mut self,
        seal: Seal,
        offset: usize,
        values: &[CpuInterval],
    ) -> Result<(), Error> {
        if self.sealed != Some(seal) {
            return Err(Error::Stale);
        }
        if values.len() > 16 {
            return Err(Error::Capacity);
        }
        let start = self
            .interval_count
            .checked_add(offset)
            .ok_or(Error::Capacity)?;
        let end = start
            .checked_add(values.len())
            .filter(|end| *end <= I)
            .ok_or(Error::Capacity)?;
        self.intervals[start..end].copy_from_slice(values);
        Ok(())
    }
    pub fn staged_intervals(&self, seal: Seal, extra: usize) -> Result<&[CpuInterval], Error> {
        if self.sealed != Some(seal) {
            return Err(Error::Stale);
        }
        let end = self
            .interval_count
            .checked_add(extra)
            .filter(|end| *end <= I)
            .ok_or(Error::Capacity)?;
        Ok(&self.intervals[..end])
    }
    pub fn requests(&self) -> &[WorkRequest] {
        &self.requests[..self.request_count]
    }
    pub fn sealed(&self) -> Option<Seal> {
        self.sealed
    }
    pub fn config(&self) -> Option<Config> {
        self.config
    }
    pub fn request_owner(&self, id: u64) -> Result<ObjectKey, Error> {
        self.active()?;
        self.request_state[..self.request_count]
            .iter()
            .find(|request| request.frozen.id == id)
            .map(|request| request.frozen.owner)
            .ok_or(Error::Evidence)
    }
    pub fn request_evidence(&self, index: usize) -> Option<(WorkRequest, Option<RequestResult>)> {
        if index >= self.request_count {
            return None;
        }
        let state = self.request_state[index];
        Some((self.requests[index], state.issued.then_some(state.actual)))
    }
    pub fn request_timing(&self, index: usize) -> Option<RequestTiming> {
        if index >= self.request_count {
            return None;
        }
        let state = self.request_state[index];
        Some(RequestTiming {
            frozen: state.frozen,
            issued_observed_ns: state.issued.then_some(state.issued_observed_ns),
            scheduled: state.scheduled,
        })
    }
    pub fn actual_result(&self, id: u64) -> Option<RequestResult> {
        self.request_state[..self.request_count]
            .iter()
            .find(|r| r.frozen.id == id && r.issued)
            .map(|r| r.actual)
    }
    /// The protected export owner calls this only after retaining the complete
    /// sealed trace. It neither cancels nor frees pending workload resources.
    pub fn retire_exported(&mut self, seal: Seal) -> Result<(), Error> {
        if self.sealed != Some(seal) {
            return Err(Error::Stale);
        }
        self.config = None;
        self.events = None;
        self.sealed = None;
        Ok(())
    }
}
