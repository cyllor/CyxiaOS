//! A real, predeclared serial workload and its immutable observation windows.
//! A request exists in this bounded queue before its release time. Slow service
//! is waiting time, never a reason to backdate a completion or omit a request.
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    learning::{
        Error,
        governance::CanaryPermit,
        reward::{RequestResult, WorkRequest},
    },
};
use sha2::{Digest, Sha256};

pub const SECOND: u64 = 1_000_000_000;
pub const PER_SECOND: usize = 100;
pub const SECONDS: usize = 30;
pub const ROWS: usize = PER_SECOND * SECONDS;
pub const PERIOD: u64 = SECOND / PER_SECOND as u64;
pub const PAYLOAD: &[u8; 8] = b"canary.\n";
const REJECTED: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Clear,
    Drain,
    Warm,
    Baseline,
    BaselineDrain,
    Ready,
    Canary,
    Closing,
    Failed,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Sample {
    // 0: not yet submitted; MAX: a known effect-free admission rejection.
    // Every other value is the exact last byte's cumulative UART watermark.
    pub end_byte: u64,
    pub finished_ns: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub written: u64,
    pub queued: usize,
    pub batch: u16,
    pub unresolved: bool,
    pub poisoned: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Due {
    pub index: usize,
    pub arrived_ns: u64,
}

pub struct State {
    pub phase: Phase,
    pub target: ObjectKey,
    pub baseline_ns: u64,
    pub permit: Option<CanaryPermit>,
    pub delivered: u16,
    pub fault: Option<Error>,
    pub generation: u64,
    cursor: usize,
    completed: usize,
    clear: usize,
    warm_ns: u64,
    pending: Option<Due>,
    last_ns: u64,
    last_written: u64,
}
impl State {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Idle,
            target: ObjectKey {
                id: 0,
                generation: 0,
            },
            baseline_ns: 0,
            permit: None,
            delivered: 0,
            fault: None,
            generation: 0,
            cursor: 0,
            completed: 0,
            clear: 0,
            warm_ns: 0,
            pending: None,
            last_ns: 0,
            last_written: 0,
        }
    }
}
#[repr(C)]
pub struct Collector {
    pub state: State,
    pub baseline: [Sample; ROWS],
    pub candidate: [Sample; ROWS],
}
impl Collector {
    pub const fn new() -> Self {
        Self {
            state: State::new(),
            baseline: [Sample {
                end_byte: 0,
                finished_ns: 0,
            }; ROWS],
            candidate: [Sample {
                end_byte: 0,
                finished_ns: 0,
            }; ROWS],
        }
    }
    pub fn reserve(&mut self, target: ObjectKey) -> Result<bool, Error> {
        if target.id == 0 || target.generation == 0 {
            return Err(Error::Evidence);
        }
        if self.state.target == target && self.state.phase == Phase::Ready {
            return Ok(true);
        }
        if !matches!(self.state.phase, Phase::Idle) {
            return if self.state.target == target && self.state.fault.is_none() {
                Ok(false)
            } else {
                Err(self.state.fault.unwrap_or(Error::Unknown))
            };
        }
        let generation = self.state.generation.checked_add(1).ok_or(Error::Numeric)?;
        self.state = State {
            target,
            phase: Phase::Clear,
            generation,
            ..State::new()
        };
        Ok(false)
    }
    pub fn blocks_active(&self) -> bool {
        matches!(
            self.state.phase,
            Phase::Clear
                | Phase::Drain
                | Phase::Warm
                | Phase::Baseline
                | Phase::BaselineDrain
                | Phase::Ready
        )
    }
    pub fn owns_output(&self) -> bool {
        self.state.phase != Phase::Idle
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.state.fault.get_or_insert(error);
        self.state.phase = Phase::Failed;
        Err(error)
    }
    fn count(&self) -> usize {
        if self.state.permit.is_some() {
            usize::from(self.state.permit.unwrap().windows / 10) * PER_SECOND
        } else {
            ROWS
        }
    }
    fn origin(&self) -> u64 {
        self.state
            .permit
            .map_or(self.state.baseline_ns, |p| p.start_ns)
    }
    fn active_rows(&self) -> &[Sample; ROWS] {
        if self.state.permit.is_some() {
            &self.candidate
        } else {
            &self.baseline
        }
    }
    fn active_rows_mut(&mut self) -> &mut [Sample; ROWS] {
        if self.state.permit.is_some() {
            &mut self.candidate
        } else {
            &mut self.baseline
        }
    }
    /// Called by the actual CPU0 owner before one ordinary pump service piece.
    /// It returns at most one already-released request, with an exact token.
    pub fn before(&mut self, now: u64, o: Observation) -> Result<Option<Due>, Error> {
        if self.state.phase == Phase::Idle {
            return Ok(None);
        }
        if now < self.state.last_ns || o.written < self.state.last_written {
            return self.fail(Error::Evidence);
        }
        self.state.last_ns = now;
        self.state.last_written = o.written;
        if o.poisoned {
            return self.fail(Error::Safety);
        }
        match self.state.phase {
            Phase::Clear => {
                let end = (self.state.clear + 64).min(ROWS);
                self.baseline[self.state.clear..end].fill(Sample::default());
                self.candidate[self.state.clear..end].fill(Sample::default());
                self.state.clear = end;
                if end == ROWS {
                    self.state.phase = Phase::Drain;
                }
                return Ok(None);
            }
            Phase::Drain => {
                // Existing desired/UNKNOWN work retains its custody. Baseline
                // begins only after it terminates and its original lease ends.
                if o.unresolved || o.queued != 0 || o.batch != 8 {
                    return Ok(None);
                }
                self.state.warm_ns = now.checked_add(SECOND).ok_or(Error::Numeric)?;
                self.state.phase = Phase::Warm;
                return Ok(None);
            }
            Phase::Warm => {
                if o.unresolved || o.queued != 0 || o.batch != 8 {
                    return self.fail(Error::Evidence);
                }
                if now < self.state.warm_ns {
                    return Ok(None);
                }
                // The bounded queue is armed before the first release. The
                // 100-ms lead permits its independent owner to witness it.
                self.state.baseline_ns = now.checked_add(100_000_000).ok_or(Error::Numeric)?;
                self.state.phase = Phase::Baseline;
                return Ok(None);
            }
            Phase::Baseline | Phase::BaselineDrain if o.batch != 8 => {
                return self.fail(Error::Evidence);
            }
            _ => {}
        }
        if !matches!(
            self.state.phase,
            Phase::Baseline | Phase::BaselineDrain | Phase::Canary | Phase::Closing
        ) {
            return Ok(None);
        }
        if self.state.pending.is_some() {
            return self.fail(Error::Unknown);
        }
        if self.state.cursor == self.count() {
            return Ok(None);
        }
        let arrived_ns = self
            .origin()
            .checked_add((self.state.cursor as u64) * PERIOD)
            .ok_or(Error::Numeric)?;
        if now < arrived_ns {
            return Ok(None);
        }
        let due = Due {
            index: self.state.cursor,
            arrived_ns,
        };
        self.state.pending = Some(due);
        Ok(Some(due))
    }
    pub fn admitted(
        &mut self,
        due: Due,
        now: u64,
        end_byte: Result<u64, DomainError>,
    ) -> Result<(), Error> {
        if self.state.pending != Some(due) || self.state.cursor != due.index || now < due.arrived_ns
        {
            return self.fail(Error::Evidence);
        }
        let mark = match end_byte {
            Ok(n) if n > self.state.last_written && n != REJECTED => n,
            Err(DomainError::Again | DomainError::Capacity) => REJECTED,
            _ => return self.fail(Error::Safety),
        };
        self.active_rows_mut()[due.index].end_byte = mark;
        self.state.cursor += 1;
        self.state.pending = None;
        Ok(())
    }
    /// Completion is derived solely from the hardware pump's monotonic byte
    /// counter. A failed/unknown write is never reported as a completed row.
    pub fn after(&mut self, now: u64, o: Observation) -> Result<(), Error> {
        if self.state.phase == Phase::Idle {
            return Ok(());
        }
        if now < self.state.last_ns || o.written < self.state.last_written || o.poisoned {
            return self.fail(Error::Evidence);
        }
        self.state.last_ns = now;
        self.state.last_written = o.written;
        if !matches!(
            self.state.phase,
            Phase::Baseline | Phase::BaselineDrain | Phase::Canary | Phase::Closing
        ) {
            return Ok(());
        }
        // No more than one admission per service piece. Eight completions is
        // enough for the largest 64-byte legal pump batch, and bounds this hook.
        for _ in 0..8 {
            let i = self.state.completed;
            if i == self.state.cursor {
                break;
            }
            let row = self.active_rows()[i];
            if row.end_byte == REJECTED {
                self.state.completed += 1;
                continue;
            }
            if row.end_byte == 0 || row.end_byte > o.written {
                break;
            }
            self.active_rows_mut()[i].finished_ns = now;
            self.state.completed += 1;
        }
        let end = self
            .origin()
            .checked_add(self.count() as u64 * PERIOD)
            .ok_or(Error::Numeric)?;
        if now >= end {
            if self.state.permit.is_none() {
                self.state.phase = Phase::BaselineDrain;
                if self.state.completed == ROWS && o.queued == 0 {
                    self.state.phase = Phase::Ready;
                }
            } else {
                self.state.phase = Phase::Closing;
            }
        }
        Ok(())
    }
    pub fn bind(&mut self, permit: CanaryPermit, now: u64) -> Result<(), Error> {
        if self.state.phase != Phase::Ready
            || self.state.fault.is_some()
            || permit.target != self.state.target
            || permit.id == 0
            || permit.active_generation == 0
            || permit.candidate_hash == [0; 32]
            || now >= permit.expires_ns
            || permit.start_ns
                < self
                    .state
                    .baseline_ns
                    .saturating_add(SECONDS as u64 * SECOND)
            || permit.windows != 100
            || permit.quota != 100
            || permit.expires_ns.checked_sub(permit.start_ns) != Some(10 * SECOND)
        {
            return Err(Error::Evidence);
        }
        self.state.permit = Some(permit);
        self.state.phase = Phase::Canary;
        self.state.cursor = 0;
        self.state.completed = 0;
        self.state.pending = None;
        self.state.delivered = 0;
        Ok(())
    }
    pub fn extend(&mut self, permit: CanaryPermit) -> Result<(), Error> {
        let old = self.state.permit.ok_or(Error::State)?;
        if self.state.phase != Phase::Canary
            || permit.id != old.id
            || permit.target != old.target
            || permit.candidate_hash != old.candidate_hash
            || permit.active_generation != old.active_generation
            || permit.start_ns != old.start_ns
            || permit.windows <= old.windows
            || permit.windows > 300
            || permit.windows % 10 != 0
            || permit.quota != permit.windows
            || permit.expires_ns.checked_sub(permit.start_ns)
                != Some(u64::from(permit.windows) * 100_000_000)
        {
            return Err(Error::Evidence);
        }
        self.state.permit = Some(permit);
        Ok(())
    }
    fn request(
        row: Sample,
        index: usize,
        source_origin: u64,
        report_origin: u64,
    ) -> Result<WorkRequest, Error> {
        let relative = index as u64 * PERIOD;
        let arrived_ns = report_origin.checked_add(relative).ok_or(Error::Numeric)?;
        let end = source_origin
            .checked_add((index / PER_SECOND + 1) as u64 * SECOND)
            .ok_or(Error::Numeric)?;
        let result = if row.end_byte == REJECTED {
            RequestResult::Rejected
        } else if row.finished_ns == 0 || row.finished_ns > end {
            RequestResult::Pending
        } else {
            RequestResult::Completed {
                finished_ns: report_origin
                    .checked_add(
                        row.finished_ns
                            .checked_sub(source_origin)
                            .ok_or(Error::Evidence)?,
                    )
                    .ok_or(Error::Numeric)?,
            }
        };
        Ok(WorkRequest {
            id: index as u64 + 1,
            arrived_ns,
            result,
        })
    }
    pub fn second(
        &self,
        permit: CanaryPermit,
        second: u16,
        now: u64,
        baseline: &mut [WorkRequest],
        candidate: &mut [WorkRequest],
    ) -> Result<(), Error> {
        if self.state.permit != Some(permit)
            || self.state.fault.is_some()
            || !matches!(self.state.phase, Phase::Canary | Phase::Closing)
            || second != self.state.delivered
            || usize::from(second) >= SECONDS
            || u64::from(second + 1) * SECOND > permit.expires_ns - permit.start_ns
            || baseline.len() != PER_SECOND
            || candidate.len() != PER_SECOND
        {
            return Err(Error::Evidence);
        }
        if now
            < permit
                .start_ns
                .checked_add(u64::from(second + 1) * SECOND)
                .ok_or(Error::Numeric)?
        {
            return Err(Error::Deadline);
        }
        for i in 0..PER_SECOND {
            let index = usize::from(second) * PER_SECOND + i;
            baseline[i] = Self::request(
                self.baseline[index],
                index,
                self.state.baseline_ns,
                permit.start_ns,
            )?;
            candidate[i] = Self::request(
                self.candidate[index],
                index,
                permit.start_ns,
                permit.start_ns,
            )?;
        }
        Ok(())
    }
    pub fn verify(
        &self,
        permit: CanaryPermit,
        second: u16,
        now: u64,
        baseline: &[WorkRequest],
        candidate: &[WorkRequest],
        digest: [u8; 32],
    ) -> Result<(), Error> {
        if self.state.permit != Some(permit)
            || self.state.fault.is_some()
            || second != self.state.delivered
            || baseline.len() != PER_SECOND
            || candidate.len() != PER_SECOND
            || usize::from(second) >= SECONDS
            || now < permit.start_ns + u64::from(second + 1) * SECOND
        {
            return Err(Error::Evidence);
        }
        for i in 0..PER_SECOND {
            let index = usize::from(second) * PER_SECOND + i;
            if baseline[i]
                != Self::request(
                    self.baseline[index],
                    index,
                    self.state.baseline_ns,
                    permit.start_ns,
                )?
                || candidate[i]
                    != Self::request(
                        self.candidate[index],
                        index,
                        permit.start_ns,
                        permit.start_ns,
                    )?
            {
                return Err(Error::Evidence);
            }
        }
        if measurement_digest(permit, second, baseline, candidate) != digest {
            return Err(Error::Evidence);
        }
        Ok(())
    }
    pub fn acknowledge(&mut self, permit: CanaryPermit, second: u16) -> Result<(), Error> {
        if self.state.permit != Some(permit) || self.state.delivered != second {
            return Err(Error::Stale);
        }
        self.state.delivered = second.checked_add(1).ok_or(Error::Numeric)?;
        Ok(())
    }
    pub fn release(&mut self, o: Observation) -> Result<(), Error> {
        if o.queued != 0 || o.unresolved || self.state.pending.is_some() {
            return Err(Error::Unknown);
        }
        // Retain raw rows until the next explicitly reserved generation.
        self.state.phase = Phase::Idle;
        self.state.permit = None;
        Ok(())
    }
}
pub fn workload_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYXIA_NATIVE_CANARY_SERIAL_1.3\0");
    h.update((PER_SECOND as u64).to_le_bytes());
    h.update((SECONDS as u64).to_le_bytes());
    h.update(PERIOD.to_le_bytes());
    h.update(PAYLOAD);
    h.finalize().into()
}
pub fn measurement_digest(
    permit: CanaryPermit,
    second: u16,
    baseline: &[WorkRequest],
    candidate: &[WorkRequest],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYXIA_CANARY_SECOND_1.3\0");
    h.update(permit.id.to_le_bytes());
    h.update(second.to_le_bytes());
    h.update((baseline.len() as u64).to_le_bytes());
    for (b, c) in baseline.iter().zip(candidate) {
        for r in [b, c] {
            h.update(r.id.to_le_bytes());
            h.update(r.arrived_ns.to_le_bytes());
            let (tag, at) = match r.result {
                RequestResult::Completed { finished_ns } => (0u64, finished_ns),
                RequestResult::Rejected => (1, 0),
                RequestResult::TimedOut => (2, 0),
                RequestResult::Pending => (3, 0),
            };
            h.update(tag.to_le_bytes());
            h.update(at.to_le_bytes());
        }
    }
    h.finalize().into()
}
