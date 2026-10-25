//! Resumable cost and latency calculations over the caller's retained,
//! immutable replay inputs. No step allocates or restarts a completed scan.
use super::{
    CostTotals, CpuClass, CpuCoverage, CpuInterval, Error, Event, Family, MAX_CPU_INTERVALS,
    MAX_REQUESTS, OBSERVATION_NS, Performance, RequestResult, RewardWorkspace, WorkRequest,
};
use core::cmp::Ordering;

// A unit is one validation, one bounded coverage lookup (at most 16 entries),
// one heap comparison/swap, one event, or one request. Heap sifts themselves
// are resumable, including at the maximum 16,384 events.
const OPERATIONS_PER_STEP: usize = 64;

#[derive(Clone, Copy)]
enum HeapPhase {
    Build,
    Child,
    Compare,
    Extract,
    Done,
}
struct HeapCursor {
    build: usize,
    end: usize,
    root: usize,
    child: usize,
    building: bool,
    phase: HeapPhase,
}
impl HeapCursor {
    const fn new(len: usize) -> Self {
        Self {
            build: len / 2,
            end: len,
            root: 0,
            child: 0,
            building: true,
            phase: HeapPhase::Build,
        }
    }
    fn sift_done(&mut self) {
        self.phase = if self.building {
            HeapPhase::Build
        } else {
            HeapPhase::Extract
        };
    }
    fn advance<T>(&mut self, values: &mut [T], compare: impl Fn(&T, &T) -> Ordering) -> bool {
        match self.phase {
            HeapPhase::Build => {
                if self.build == 0 {
                    self.phase = HeapPhase::Extract;
                } else {
                    self.build -= 1;
                    self.root = self.build;
                    self.building = true;
                    self.phase = HeapPhase::Child;
                }
            }
            HeapPhase::Child => {
                let left = self.root * 2 + 1;
                if left >= self.end {
                    self.sift_done();
                } else {
                    self.child = left;
                    if left + 1 < self.end
                        && compare(&values[left], &values[left + 1]) == Ordering::Less
                    {
                        self.child += 1;
                    }
                    self.phase = HeapPhase::Compare;
                }
            }
            HeapPhase::Compare => {
                if compare(&values[self.root], &values[self.child]) == Ordering::Less {
                    values.swap(self.root, self.child);
                    self.root = self.child;
                    self.phase = HeapPhase::Child;
                } else {
                    self.sift_done();
                }
            }
            HeapPhase::Extract => {
                if self.end <= 1 {
                    self.phase = HeapPhase::Done;
                } else {
                    self.end -= 1;
                    values.swap(0, self.end);
                    self.root = 0;
                    self.building = false;
                    self.phase = HeapPhase::Child;
                }
            }
            HeapPhase::Done => {}
        }
        matches!(self.phase, HeapPhase::Done)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CpuBinding {
    family: Family,
    intervals: usize,
    interval_count: usize,
    coverage_count: usize,
    workspace: usize,
}
#[derive(Clone, Copy)]
enum CpuPhase {
    Coverage,
    Intervals,
    Sort,
    Sweep,
    Done,
}
pub(super) struct CpuCursor {
    binding: Option<CpuBinding>,
    // Native Trial views rebuild this small value table on each paid turn.
    // Its exact contents, not the address of that temporary view, are bound.
    coverage: [CpuCoverage; 16],
    error: Option<Error>,
    phase: CpuPhase,
    at: usize,
    heap: HeapCursor,
    raw: [u64; 3],
    active: [usize; 3],
    classified: [u64; 3],
    last: Option<([u8; 32], u16, u64)>,
    total: u64,
}
impl CpuCursor {
    pub(super) const fn new() -> Self {
        Self {
            binding: None,
            coverage: [CpuCoverage {
                node: [0; 32],
                first_ns: 0,
                observation_ns: 0,
                observation_end_ns: 0,
                closing_ns: 0,
                required: 0,
                reported: 0,
            }; 16],
            error: None,
            phase: CpuPhase::Coverage,
            at: 0,
            heap: HeapCursor::new(0),
            raw: [0; 3],
            active: [0; 3],
            classified: [0; 3],
            last: None,
            total: 0,
        }
    }
    pub(super) fn step(
        &mut self,
        family: Family,
        intervals: &[CpuInterval],
        coverage: &[CpuCoverage],
        work: &mut RewardWorkspace,
    ) -> Result<bool, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let binding = CpuBinding {
            family,
            intervals: intervals.as_ptr() as usize,
            interval_count: intervals.len(),
            coverage_count: coverage.len(),
            workspace: work as *mut RewardWorkspace as usize,
        };
        let result = (|| {
            if let Some(original) = self.binding {
                if original != binding || self.coverage[..coverage.len()] != *coverage {
                    return Err(Error::Stale);
                }
            } else {
                family.index()?;
                if intervals.len() > MAX_CPU_INTERVALS || coverage.is_empty() || coverage.len() > 16
                {
                    return Err(Error::Capacity);
                }
                self.coverage[..coverage.len()].copy_from_slice(coverage);
                self.binding = Some(binding);
            }
            for _ in 0..OPERATIONS_PER_STEP {
                if self.advance(family, intervals, coverage, work)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }
    fn advance(
        &mut self,
        family: Family,
        intervals: &[CpuInterval],
        coverage: &[CpuCoverage],
        work: &mut RewardWorkspace,
    ) -> Result<bool, Error> {
        match self.phase {
            CpuPhase::Coverage => {
                if self.at == coverage.len() {
                    self.phase = CpuPhase::Intervals;
                    self.at = 0;
                } else {
                    let c = &coverage[self.at];
                    if c.node == [0; 32]
                        || c.required & !7 != 0
                        || c.required & 3 != 3
                        || c.reported & !7 != 0
                        || c.reported & c.required != c.required
                        || c.required != if family.domain == 13 { 7 } else { 3 }
                        || c.observation_end_ns.checked_sub(c.observation_ns)
                            != Some(OBSERVATION_NS)
                        || c.first_ns > c.observation_ns
                        || c.closing_ns < c.observation_end_ns
                        || c.closing_ns - c.observation_end_ns > 5_000_000_000
                        || coverage[..self.at].iter().any(|p| p.node == c.node)
                    {
                        return Err(Error::Evidence);
                    }
                    self.at += 1;
                }
            }
            CpuPhase::Intervals => {
                if self.at == intervals.len() {
                    self.heap = HeapCursor::new(intervals.len() * 2);
                    self.phase = CpuPhase::Sort;
                } else {
                    let c = &intervals[self.at];
                    let owner = coverage
                        .iter()
                        .find(|v| v.node == c.node)
                        .ok_or(Error::Evidence)?;
                    let class = c.class.union_class();
                    let (begin, end) = match c.class {
                        CpuClass::Policy | CpuClass::ExecutorAction => {
                            (owner.first_ns, owner.closing_ns)
                        }
                        CpuClass::ExecutorWork | CpuClass::Optional => {
                            (owner.observation_ns, owner.observation_end_ns)
                        }
                    };
                    if c.end_ns < c.start_ns
                        || c.start_ns < begin
                        || c.end_ns > end
                        || c.core >= 64
                        || owner.reported & (1 << class) == 0
                        || (c.class == CpuClass::Optional && family.domain != 13)
                    {
                        return Err(Error::Evidence);
                    }
                    self.raw[class] = self.raw[class]
                        .checked_add(c.end_ns - c.start_ns)
                        .ok_or(Error::Numeric)?;
                    work.events[2 * self.at] = Event {
                        at: c.start_ns,
                        interval: self.at as u16,
                        start: true,
                    };
                    work.events[2 * self.at + 1] = Event {
                        at: c.end_ns,
                        interval: self.at as u16,
                        start: false,
                    };
                    self.at += 1;
                }
            }
            CpuPhase::Sort => {
                if self
                    .heap
                    .advance(&mut work.events[..intervals.len() * 2], |a, b| {
                        let x = &intervals[usize::from(a.interval)];
                        let y = &intervals[usize::from(b.interval)];
                        x.node
                            .cmp(&y.node)
                            .then_with(|| x.core.cmp(&y.core))
                            .then_with(|| a.at.cmp(&b.at))
                            .then_with(|| (!a.start).cmp(&(!b.start)))
                    })
                {
                    self.phase = CpuPhase::Sweep;
                    self.at = 0;
                }
            }
            CpuPhase::Sweep => {
                if self.at == intervals.len() * 2 {
                    if self.active != [0; 3] {
                        return Err(Error::Evidence);
                    }
                    self.total = self.classified.iter().try_fold(0u64, |sum, value| {
                        sum.checked_add(*value).ok_or(Error::Numeric)
                    })?;
                    self.phase = CpuPhase::Done;
                } else {
                    let e = &work.events[self.at];
                    let c = &intervals[usize::from(e.interval)];
                    if let Some((node, core, at)) = self.last {
                        if (node, core) == (c.node, c.core) {
                            if let Some(class) = self.active.iter().position(|n| *n != 0) {
                                self.classified[class] = self.classified[class]
                                    .checked_add(e.at.checked_sub(at).ok_or(Error::Evidence)?)
                                    .ok_or(Error::Numeric)?;
                            }
                        } else if self.active != [0; 3] {
                            return Err(Error::Evidence);
                        }
                    }
                    let count = &mut self.active[c.class.union_class()];
                    *count = if e.start {
                        count.checked_add(1).ok_or(Error::Numeric)?
                    } else {
                        count.checked_sub(1).ok_or(Error::Evidence)?
                    };
                    self.last = Some((c.node, c.core, e.at));
                    self.at += 1;
                }
            }
            CpuPhase::Done => {}
        }
        Ok(matches!(self.phase, CpuPhase::Done))
    }
    pub(super) fn finish(&self) -> Result<CostTotals, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !matches!(self.phase, CpuPhase::Done) {
            return Err(Error::State);
        }
        Ok(CostTotals {
            union_ns: self.total,
            policy_ns: self.classified[0],
            executor_ns: self.classified[1],
            optional_ns: self.classified[2],
            raw_tagged_ns: self.raw,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PerformanceBinding {
    requests: usize,
    count: usize,
    start: u64,
    workspace: usize,
}
#[derive(Clone, Copy)]
enum PerformancePhase {
    Validate,
    SortIds,
    Unique,
    Latencies,
    SortLatencies,
    Penalties,
    Done,
}
pub(super) struct PerformanceCursor {
    binding: Option<PerformanceBinding>,
    error: Option<Error>,
    phase: PerformancePhase,
    end: u64,
    at: usize,
    completed: usize,
    counts: [u64; 4],
    actual_p99: Option<u64>,
    penalty_p99: u64,
    heap: HeapCursor,
}
impl PerformanceCursor {
    pub(super) const fn new() -> Self {
        Self {
            binding: None,
            error: None,
            phase: PerformancePhase::Validate,
            end: 0,
            at: 0,
            completed: 0,
            counts: [0; 4],
            actual_p99: None,
            penalty_p99: 0,
            heap: HeapCursor::new(0),
        }
    }
    pub(super) fn step(
        &mut self,
        requests: &[WorkRequest],
        observation_ns: u64,
        work: &mut RewardWorkspace,
    ) -> Result<bool, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let binding = PerformanceBinding {
            requests: requests.as_ptr() as usize,
            count: requests.len(),
            start: observation_ns,
            workspace: work as *mut RewardWorkspace as usize,
        };
        let result = (|| {
            if let Some(original) = self.binding {
                if original != binding {
                    return Err(Error::Stale);
                }
            } else {
                if requests.len() > MAX_REQUESTS {
                    return Err(Error::Capacity);
                }
                self.end = observation_ns
                    .checked_add(OBSERVATION_NS)
                    .ok_or(Error::Numeric)?;
                self.binding = Some(binding);
            }
            for _ in 0..OPERATIONS_PER_STEP {
                if self.advance(requests, observation_ns, work)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }
    fn advance(
        &mut self,
        requests: &[WorkRequest],
        start: u64,
        work: &mut RewardWorkspace,
    ) -> Result<bool, Error> {
        match self.phase {
            PerformancePhase::Validate => {
                if self.at == requests.len() {
                    self.heap = HeapCursor::new(requests.len());
                    self.phase = PerformancePhase::SortIds;
                } else {
                    let r = &requests[self.at];
                    if r.id == 0 || r.arrived_ns < start || r.arrived_ns >= self.end {
                        return Err(Error::Evidence);
                    }
                    let class = match r.result {
                        RequestResult::Completed { finished_ns } => {
                            if finished_ns < r.arrived_ns || finished_ns > self.end {
                                return Err(Error::Evidence);
                            }
                            0
                        }
                        RequestResult::Rejected => 1,
                        RequestResult::TimedOut => 2,
                        RequestResult::Pending => 3,
                    };
                    self.counts[class] += 1;
                    // Reuse the latency bank for a bounded duplicate-ID sort.
                    // This avoids repeating an unbounded prefix scan per row.
                    work.latencies[self.at] = r.id;
                    self.at += 1;
                }
            }
            PerformancePhase::SortIds => {
                if self
                    .heap
                    .advance(&mut work.latencies[..requests.len()], u64::cmp)
                {
                    self.at = 1;
                    self.phase = PerformancePhase::Unique;
                }
            }
            PerformancePhase::Unique => {
                if self.at >= requests.len() {
                    if requests.len() < 100 {
                        return Err(Error::DataIncomplete);
                    }
                    self.at = 0;
                    self.phase = PerformancePhase::Latencies;
                } else {
                    if work.latencies[self.at - 1] == work.latencies[self.at] {
                        return Err(Error::Evidence);
                    }
                    self.at += 1;
                }
            }
            PerformancePhase::Latencies => {
                if self.at == requests.len() {
                    if self.completed as u64 != self.counts[0] {
                        return Err(Error::Stale);
                    }
                    self.heap = HeapCursor::new(self.completed);
                    self.phase = PerformancePhase::SortLatencies;
                } else {
                    let r = &requests[self.at];
                    if let RequestResult::Completed { finished_ns } = r.result {
                        work.latencies[self.completed] = finished_ns
                            .checked_sub(r.arrived_ns)
                            .ok_or(Error::Evidence)?;
                        self.completed += 1;
                    }
                    self.at += 1;
                }
            }
            PerformancePhase::SortLatencies => {
                if self
                    .heap
                    .advance(&mut work.latencies[..self.completed], u64::cmp)
                {
                    self.actual_p99 = (self.completed != 0)
                        .then(|| work.latencies[(99 * self.completed).div_ceil(100) - 1]);
                    self.at = self.completed;
                    self.phase = PerformancePhase::Penalties;
                }
            }
            PerformancePhase::Penalties => {
                if self.at == requests.len() {
                    self.penalty_p99 = work.latencies[(99 * requests.len()).div_ceil(100) - 1];
                    self.phase = PerformancePhase::Done;
                } else {
                    // Every valid completed latency is <= OBSERVATION_NS.
                    // Appending these penalties preserves the completed sort.
                    work.latencies[self.at] = OBSERVATION_NS;
                    self.at += 1;
                }
            }
            PerformancePhase::Done => {}
        }
        Ok(matches!(self.phase, PerformancePhase::Done))
    }
    pub(super) fn finish(&self) -> Result<Performance, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !matches!(self.phase, PerformancePhase::Done) {
            return Err(Error::State);
        }
        Ok(Performance {
            emitted: self.binding.ok_or(Error::State)?.count as u64,
            completed: self.counts[0],
            rejected: self.counts[1],
            timed_out: self.counts[2],
            pending: self.counts[3],
            penalty_p99_ns: self.penalty_p99,
            actual_completed_p99_ns: self.actual_p99,
        })
    }
}

#[cfg(test)]
#[path = "tests/bounded_cost.rs"]
mod tests;
