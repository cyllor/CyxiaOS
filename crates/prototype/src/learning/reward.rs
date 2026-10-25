//! Full-cost paired replay measurements. The protected producer must attest
//! the complete canonical record; hashes alone are never execution evidence.
use super::{Error, Family, ReplayGroup, SchemaBinding, Schemas, softfloat::F64};
use crate::{
    domains::{Action, ApplyId, ObjectKey},
    features,
    model::{MODEL_BYTES, Model},
    policy::{CandidateSet, ExecutionState, Snapshot},
};
use sha2::{Digest, Sha256};

mod verified;
pub use verified::{ReplayKind, VerifiedReplay, pair_verified, verify_replay};
mod bounded;
mod bounded_cost;
pub use bounded::{IncrementalAuthority, ReplayPiece, ReplayVerification};

pub const OBSERVATION_NS: u64 = 10_000_000_000;
pub const MAX_REQUESTS: usize = 4096;
pub const MAX_CPU_INTERVALS: usize = 8192;
pub const MAX_RENEWALS: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuClass {
    Policy,
    ExecutorAction,
    ExecutorWork,
    Optional,
}
impl CpuClass {
    fn union_class(self) -> usize {
        match self {
            Self::Policy => 0,
            Self::ExecutorAction | Self::ExecutorWork => 1,
            Self::Optional => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuInterval {
    pub node: [u8; 32],
    pub core: u16,
    pub start_ns: u64,
    pub end_ns: u64,
    pub class: CpuClass,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuCoverage {
    pub node: [u8; 32],
    pub first_ns: u64,
    pub observation_ns: u64,
    pub observation_end_ns: u64,
    pub closing_ns: u64,
    /// P/E/O bits required by the frozen replay contract, including partners.
    pub required: u8,
    pub reported: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestResult {
    Completed { finished_ns: u64 },
    Rejected,
    TimedOut,
    Pending,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkRequest {
    pub id: u64,
    pub arrived_ns: u64,
    pub result: RequestResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CostTotals {
    pub union_ns: u64,
    pub policy_ns: u64,
    pub executor_ns: u64,
    pub optional_ns: u64,
    pub raw_tagged_ns: [u64; 3],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Performance {
    pub emitted: u64,
    pub completed: u64,
    pub rejected: u64,
    pub timed_out: u64,
    pub pending: u64,
    pub penalty_p99_ns: u64,
    pub actual_completed_p99_ns: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reward {
    pub candidate: Performance,
    pub baseline: Performance,
    pub candidate_cpu: CostTotals,
    pub baseline_cpu: CostTotals,
    pub raw_cost: F64,
    pub clipped_cost: F64,
    pub delta_throughput: F64,
    pub delta_latency: F64,
    pub value: F64,
}
#[derive(Clone, Copy)]
struct Event {
    at: u64,
    interval: u16,
    start: bool,
}
const EVENT: Event = Event {
    at: 0,
    interval: 0,
    start: false,
};
pub struct RewardWorkspace {
    events: [Event; MAX_CPU_INTERVALS * 2],
    latencies: [u64; MAX_REQUESTS],
}
impl Default for RewardWorkspace {
    fn default() -> Self {
        Self::new()
    }
}
impl RewardWorkspace {
    pub const fn new() -> Self {
        Self {
            events: [EVENT; MAX_CPU_INTERVALS * 2],
            latencies: [0; MAX_REQUESTS],
        }
    }
    pub(crate) fn latency_scratch(&mut self) -> &mut [u64] {
        &mut self.latencies
    }
}
const _: () = assert!(core::mem::size_of::<RewardWorkspace>() <= 1024 * 1024);

pub fn split_joint_policy(
    interval: CpuInterval,
    count: u16,
    index: u16,
) -> Result<CpuInterval, Error> {
    if interval.class != CpuClass::Policy
        || count == 0
        || count > 16
        || index >= count
        || interval.end_ns < interval.start_ns
    {
        return Err(Error::Evidence);
    }
    let length = interval.end_ns - interval.start_ns;
    let (q, r) = (length / u64::from(count), length % u64::from(count));
    let offset = q
        .checked_mul(u64::from(index))
        .and_then(|n| n.checked_add(u64::from(index).min(r)))
        .ok_or(Error::Numeric)?;
    let start = interval
        .start_ns
        .checked_add(offset)
        .ok_or(Error::Numeric)?;
    let end = start
        .checked_add(q + u64::from(u64::from(index) < r))
        .ok_or(Error::Numeric)?;
    Ok(CpuInterval {
        start_ns: start,
        end_ns: end,
        ..interval
    })
}

pub fn union_cpu(
    family: Family,
    intervals: &[CpuInterval],
    coverage: &[CpuCoverage],
    work: &mut RewardWorkspace,
) -> Result<CostTotals, Error> {
    family.index()?;
    if intervals.len() > MAX_CPU_INTERVALS || coverage.is_empty() || coverage.len() > 16 {
        return Err(Error::Capacity);
    }
    for (i, c) in coverage.iter().enumerate() {
        if c.node == [0; 32]
            || c.required & !7 != 0
            || c.required & 3 != 3
            || c.reported & !7 != 0
            || c.reported & c.required != c.required
            || c.required != if family.domain == 13 { 7 } else { 3 }
            || c.observation_end_ns.checked_sub(c.observation_ns) != Some(OBSERVATION_NS)
            || c.first_ns > c.observation_ns
            || c.closing_ns < c.observation_end_ns
            || c.closing_ns - c.observation_end_ns > 5_000_000_000
            || coverage[..i].iter().any(|p| p.node == c.node)
        {
            return Err(Error::Evidence);
        }
    }
    let mut raw = [0u64; 3];
    for (i, c) in intervals.iter().enumerate() {
        let owner = coverage
            .iter()
            .find(|v| v.node == c.node)
            .ok_or(Error::Evidence)?;
        let class = c.class.union_class();
        let (begin, end) = match c.class {
            CpuClass::Policy | CpuClass::ExecutorAction => (owner.first_ns, owner.closing_ns),
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
        raw[class] = raw[class]
            .checked_add(c.end_ns - c.start_ns)
            .ok_or(Error::Numeric)?;
        work.events[2 * i] = Event {
            at: c.start_ns,
            interval: i as u16,
            start: true,
        };
        work.events[2 * i + 1] = Event {
            at: c.end_ns,
            interval: i as u16,
            start: false,
        };
    }
    let events = &mut work.events[..intervals.len() * 2];
    events.sort_unstable_by(|a, b| {
        let x = intervals[usize::from(a.interval)];
        let y = intervals[usize::from(b.interval)];
        (x.node, x.core, a.at, !a.start).cmp(&(y.node, y.core, b.at, !b.start))
    });
    let mut active = [0usize; 3];
    let mut classified = [0u64; 3];
    let mut last = None;
    for e in events.iter() {
        let c = intervals[usize::from(e.interval)];
        if let Some((node, core, at)) = last {
            if (node, core) == (c.node, c.core) {
                if let Some(class) = active.iter().position(|n| *n != 0) {
                    classified[class] = classified[class]
                        .checked_add(e.at - at)
                        .ok_or(Error::Numeric)?;
                }
            } else if active != [0; 3] {
                return Err(Error::Evidence);
            }
        }
        let count = &mut active[c.class.union_class()];
        if e.start {
            *count = count.checked_add(1).ok_or(Error::Numeric)?;
        } else {
            *count = count.checked_sub(1).ok_or(Error::Evidence)?;
        }
        last = Some((c.node, c.core, e.at));
    }
    if active != [0; 3] {
        return Err(Error::Evidence);
    }
    let total = classified
        .iter()
        .try_fold(0u64, |a, b| a.checked_add(*b).ok_or(Error::Numeric))?;
    Ok(CostTotals {
        union_ns: total,
        policy_ns: classified[0],
        executor_ns: classified[1],
        optional_ns: classified[2],
        raw_tagged_ns: raw,
    })
}

pub fn performance(
    requests: &[WorkRequest],
    start: u64,
    work: &mut RewardWorkspace,
) -> Result<Performance, Error> {
    performance_window(requests, start, OBSERVATION_NS, work)
}
pub fn one_second_performance(
    requests: &[WorkRequest],
    start: u64,
    work: &mut RewardWorkspace,
) -> Result<Performance, Error> {
    performance_window(requests, start, 1_000_000_000, work)
}
/// Preserve even an insufficient window's actual counts and penalty values.
/// A nonempty result here is not permission to use it as a qualified sample.
pub fn inspect_one_second(
    requests: &[WorkRequest],
    start: u64,
    work: &mut RewardWorkspace,
) -> Result<Option<Performance>, Error> {
    inspect_one_second_with_latencies(requests, start, &mut work.latencies)
}
/// A bounded service owner can use only the scratch its actual frozen request
/// table needs. This shares the exact reward metric and nearest-rank rules;
/// it does not need the CPU-union sweep workspace used by full replay trials.
pub fn inspect_one_second_with_latencies(
    requests: &[WorkRequest],
    start: u64,
    latencies: &mut [u64],
) -> Result<Option<Performance>, Error> {
    inspect_window_with_latencies(requests, start, 1_000_000_000, latencies)
}
fn performance_window(
    requests: &[WorkRequest],
    start: u64,
    duration: u64,
    work: &mut RewardWorkspace,
) -> Result<Performance, Error> {
    let measured = inspect_window(requests, start, duration, work)?.ok_or(Error::DataIncomplete)?;
    if measured.emitted < 100 {
        return Err(Error::DataIncomplete);
    }
    Ok(measured)
}
fn inspect_window(
    requests: &[WorkRequest],
    start: u64,
    duration: u64,
    work: &mut RewardWorkspace,
) -> Result<Option<Performance>, Error> {
    inspect_window_with_latencies(requests, start, duration, &mut work.latencies)
}
fn inspect_window_with_latencies(
    requests: &[WorkRequest],
    start: u64,
    duration: u64,
    latencies: &mut [u64],
) -> Result<Option<Performance>, Error> {
    if requests.len() > MAX_REQUESTS || requests.len() > latencies.len() {
        return Err(Error::Capacity);
    }
    let end = start.checked_add(duration).ok_or(Error::Numeric)?;
    let mut counts = [0u64; 4];
    let mut completed = 0usize;
    for (i, r) in requests.iter().enumerate() {
        if r.id == 0
            || r.arrived_ns < start
            || r.arrived_ns >= end
            || requests[..i].iter().any(|v| v.id == r.id)
        {
            return Err(Error::Evidence);
        }
        if let RequestResult::Completed { finished_ns } = r.result {
            if finished_ns < r.arrived_ns || finished_ns > end {
                return Err(Error::Evidence);
            }
            latencies[completed] = finished_ns - r.arrived_ns;
            completed += 1;
            counts[0] += 1;
        } else {
            counts[match r.result {
                RequestResult::Rejected => 1,
                RequestResult::TimedOut => 2,
                _ => 3,
            }] += 1;
        }
    }
    if requests.is_empty() {
        return Ok(None);
    }
    latencies[..completed].sort_unstable();
    let actual = (completed != 0).then(|| latencies[(99 * completed).div_ceil(100) - 1]);
    latencies[completed..requests.len()].fill(OBSERVATION_NS);
    latencies[..requests.len()].sort_unstable();
    Ok(Some(Performance {
        emitted: requests.len() as u64,
        completed: counts[0],
        rejected: counts[1],
        timed_out: counts[2],
        pending: counts[3],
        penalty_p99_ns: latencies[(99 * requests.len()).div_ceil(100) - 1],
        actual_completed_p99_ns: actual,
    }))
}

pub struct Adoption<'a> {
    pub decision_seq: u64,
    pub apply: ApplyId,
    pub plan_version: u64,
    pub executor_generation: u64,
    pub candidates: &'a CandidateSet,
    pub model: &'a [u8; MODEL_BYTES],
    pub scores: &'a [i16],
    pub selected: u16,
    pub actual: Action,
    pub executed: ExecutionState,
    pub issued_ns: u64,
    /// Successful root PUBLISH/acceptance, independently linked by authority.
    pub accepted_ns: u64,
    pub expires_local_ns: u64,
    pub active_until_local_ns: u64,
    /// Logical frozen request id. The authority also checks its owner/TaskKey.
    pub target_request_id: Option<u64>,
    pub started_ns: u64,
    pub finished_ns: u64,
    pub installed_until_ns: u64,
    pub approved_deadline_ns: u64,
    /// The actual approved plan's ordered action identities, not just a count.
    pub concurrent: &'a [ApplyId],
    /// Complete protected root list of common CPU spans for this publication.
    pub shared_policy_intervals: &'a [CpuInterval],
}
/// A deterministic baseline can have real executor evidence without pretending
/// that a model chose it. It is never used as the candidate's training label.
pub struct BaselineAdoption {
    pub owner_boot: u64,
    pub receipt_sequence: u64,
    pub target: ObjectKey,
    pub executor_generation: u64,
    pub snapshot: Snapshot,
    pub actual: Action,
    pub executed: ExecutionState,
    pub issued_ns: u64,
    pub accepted_ns: u64,
    pub target_request_id: Option<u64>,
    pub started_ns: u64,
    pub finished_ns: u64,
    pub installed_until_ns: u64,
    pub approved_deadline_ns: u64,
}
pub struct JointPolicySplit<'a> {
    pub source: CpuInterval,
    pub actions: &'a [ApplyId],
    pub action_index: u16,
}
pub struct Trial<'a> {
    pub id: u64,
    pub family: Family,
    pub group: ReplayGroup,
    pub frozen_other_domains: [u8; 32],
    pub schemas: Schemas,
    pub local_node: [u8; 32],
    pub controlled_nodes: &'a [[u8; 32]],
    pub observation_ns: u64,
    pub observation_end_ns: u64,
    pub warmed_from_ns: u64,
    pub closing_ns: u64,
    pub requests: &'a [WorkRequest],
    pub adoptions: &'a [Adoption<'a>],
    pub coverage: &'a [CpuCoverage],
    pub cpu: &'a [CpuInterval],
    pub baseline: &'a [BaselineAdoption],
    pub joint_policy: &'a [JointPolicySplit<'a>],
    pub correct: bool,
    pub frozen: bool,
    pub closing: ExecutionState,
    pub ordinary_warmup_cpu_ns: u64,
    pub later_workload_cpu_ns: u64,
    pub peak_workspace_bytes: u64,
}
/// Implemented by the protected replay/receipt owner. Native integration must
/// authenticate every participating node and bind its collected CPU trace;
/// a caller-supplied digest without that authority cannot produce a label.
pub trait EvidenceAuthority {
    fn attest(&self, trial: &Trial<'_>, canonical_digest: [u8; 32]) -> Result<(), Error>;
}
#[derive(Clone, Debug)]
pub struct AcceptedSample {
    pub(super) family: Family,
    pub(super) group: ReplayGroup,
    pub(super) input: [i16; 64],
    pub(super) reward: Reward,
    pub(super) evidence: [u8; 32],
    pub(super) reward_schema: SchemaBinding,
    pub(super) learning_config: SchemaBinding,
    pub(super) feature_schema: SchemaBinding,
    pub(super) action_schema: SchemaBinding,
}
impl AcceptedSample {
    pub fn family(&self) -> Family {
        self.family
    }
    pub fn group(&self) -> ReplayGroup {
        self.group
    }
    pub fn input(&self) -> &[i16; 64] {
        &self.input
    }
    pub fn reward(&self) -> Reward {
        self.reward
    }
    pub fn evidence_hash(&self) -> [u8; 32] {
        self.evidence
    }
}
fn number(hash: &mut Sha256, value: u64) {
    hash.update(value.to_le_bytes());
}
fn action(hash: &mut Sha256, value: Action) -> Result<(), Error> {
    let mut b = [0; 16];
    let n = crate::policy_wire::encode_payload(value, 0, &mut b).map_err(|_| Error::Evidence)?;
    hash.update(value.domain().to_le_bytes());
    hash.update(value.kind().to_le_bytes());
    hash.update(&b[..n]);
    Ok(())
}
fn apply_id(hash: &mut Sha256, id: ApplyId) {
    for value in [
        id.boot_epoch,
        id.controller_epoch,
        id.plan_seq,
        u64::from(id.action_index),
        id.target.id,
        id.target.generation,
    ] {
        number(hash, value);
    }
}
fn terminal(s: ExecutionState) -> Result<(), Error> {
    match s {
        ExecutionState::Applied => Ok(()),
        ExecutionState::Unknown | ExecutionState::Pending => Err(Error::Unknown),
        _ => Err(Error::Evidence),
    }
}

fn verify_baseline(t: &Trial<'_>, hash: &mut Sha256) -> Result<(), Error> {
    let first = t.baseline.first().ok_or(Error::Evidence)?;
    let local = t
        .coverage
        .iter()
        .find(|c| c.node == t.local_node)
        .ok_or(Error::Evidence)?;
    let mut until = 0;
    for (index, b) in t.baseline.iter().enumerate() {
        terminal(b.executed)?;
        super::baseline::validate(b.actual)?;
        if b.owner_boot == 0
            || b.receipt_sequence == 0
            || b.executor_generation == 0
            || b.target.id == 0
            || b.target.generation == 0
            || b.owner_boot != first.owner_boot
            || b.target != first.target
            || b.actual != first.actual
            || b.actual.domain() != t.family.domain
            || b.actual.kind() != t.family.kind
            || b.snapshot.sequence == 0
            || b.snapshot.core_generation == 0
            || b.snapshot.ledger_generation == 0
            || b.snapshot.taken_ns > b.issued_ns
            || b.issued_ns > b.accepted_ns
            || b.accepted_ns > b.started_ns
            || b.finished_ns < b.started_ns
            || b.finished_ns > b.approved_deadline_ns
            || b.finished_ns > t.closing_ns
            || b.snapshot.taken_ns >= t.observation_end_ns
            || (index == 0 && local.first_ns != b.snapshot.taken_ns)
            || t.baseline[..index].iter().any(|old| {
                old.receipt_sequence == b.receipt_sequence
                    || old.snapshot.taken_ns >= b.snapshot.taken_ns
            })
        {
            return Err(Error::Evidence);
        }
        if b.actual.one_shot() {
            if t.baseline.len() != 1
                || b.issued_ns != t.observation_ns
                || b.installed_until_ns != 0
                || !b.target_request_id.is_some_and(|id| {
                    id != 0
                        && t.requests
                            .iter()
                            .any(|r| r.id == id && r.arrived_ns == b.issued_ns)
                })
            {
                return Err(Error::Evidence);
            }
            let bound = match b.actual {
                Action::ControlSet(_) => Some(200_000_000),
                Action::RecoveryRecipe(_) => Some(1_000_000_000),
                _ => None,
            };
            if bound.is_some_and(|bound| b.approved_deadline_ns - b.accepted_ns > bound) {
                return Err(Error::Deadline);
            }
        } else {
            let stopped_offer = b.actual == Action::OfferCpu(0) && b.installed_until_ns == 0;
            if b.target_request_id.is_some()
                || b.approved_deadline_ns - b.accepted_ns > 50_000_000
                || (!stopped_offer && b.finished_ns > b.installed_until_ns)
                || (index == 0
                    && (b.finished_ns > t.warmed_from_ns
                        || b.finished_ns - b.snapshot.taken_ns > 5_000_000_000))
                || (index > 0 && b.finished_ns > until)
            {
                return Err(Error::Evidence);
            }
            if stopped_offer && t.baseline.len() != 1 {
                return Err(Error::Evidence);
            }
            until = until.max(if stopped_offer {
                t.observation_end_ns
            } else {
                b.installed_until_ns
            });
        }
        for value in [
            b.owner_boot,
            b.receipt_sequence,
            b.target.id,
            b.target.generation,
            b.executor_generation,
            b.snapshot.sequence,
            b.snapshot.taken_ns,
            b.snapshot.core_generation,
            b.snapshot.ledger_generation,
            b.issued_ns,
            b.accepted_ns,
            b.target_request_id.unwrap_or(0),
            b.started_ns,
            b.finished_ns,
            b.installed_until_ns,
            b.approved_deadline_ns,
        ] {
            number(hash, value);
        }
        let mut payload = [0; 16];
        let n = super::baseline::encode(b.actual, &mut payload)?;
        hash.update(b.actual.domain().to_le_bytes());
        hash.update(b.actual.kind().to_le_bytes());
        hash.update(&payload[..n]);
    }
    if !first.actual.one_shot() && until < t.observation_end_ns {
        return Err(Error::Evidence);
    }
    Ok(())
}

fn verify_trial(
    t: &Trial<'_>,
    model_candidate: bool,
    authority: &impl EvidenceAuthority,
) -> Result<([u8; 32], [i16; 64]), Error> {
    t.family.index()?;
    t.schemas.validate()?;
    terminal(t.closing)?;
    if !t.correct && model_candidate {
        return Err(Error::Safety);
    }
    if !t.correct
        || !t.frozen
        || t.id == 0
        || t.adoptions.len() > MAX_RENEWALS
        || t.baseline.len() > MAX_RENEWALS
        || (model_candidate && (t.adoptions.is_empty() || !t.baseline.is_empty()))
        || (!model_candidate && (t.baseline.is_empty() || !t.adoptions.is_empty()))
        || t.group.workload == [0; 32]
        || t.group.initial_image == [0; 32]
        || t.frozen_other_domains == [0; 32]
        || t.observation_end_ns.checked_sub(t.observation_ns) != Some(OBSERVATION_NS)
        || t.observation_ns.checked_sub(t.warmed_from_ns) != Some(1_000_000_000)
        || t.closing_ns < t.observation_end_ns
        || t.closing_ns - t.observation_end_ns > 5_000_000_000
        || t.peak_workspace_bytes > 1024 * 1024
        || t.controlled_nodes.is_empty()
        || t.controlled_nodes.len() > 16
        || t.controlled_nodes.len() != t.coverage.len()
        || !t.controlled_nodes.contains(&t.local_node)
    {
        return Err(Error::Evidence);
    }
    for (i, node) in t.controlled_nodes.iter().enumerate() {
        if *node == [0; 32]
            || t.controlled_nodes[..i].contains(node)
            || !t.coverage.iter().any(|c| c.node == *node)
        {
            return Err(Error::Evidence);
        }
    }
    let local = t
        .coverage
        .iter()
        .find(|c| c.node == t.local_node)
        .ok_or(Error::Evidence)?;
    if local.observation_ns != t.observation_ns
        || local.observation_end_ns != t.observation_end_ns
        || local.closing_ns != t.closing_ns
    {
        return Err(Error::Evidence);
    }
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_FULL_CPU_TRIAL_1.3\0");
    hash.update([u8::from(model_candidate)]);
    for v in [
        t.id,
        t.family.domain as u64,
        t.family.kind as u64,
        t.group.seed,
        t.observation_ns,
        t.observation_end_ns,
        t.warmed_from_ns,
        t.closing_ns,
        t.ordinary_warmup_cpu_ns,
        t.later_workload_cpu_ns,
        t.peak_workspace_bytes,
    ] {
        number(&mut hash, v);
    }
    hash.update(t.group.workload);
    hash.update(t.group.initial_image);
    hash.update(t.frozen_other_domains);
    for s in [
        t.schemas.feature,
        t.schemas.action,
        t.schemas.reward,
        t.schemas.learning,
    ] {
        number(&mut hash, u64::from(s.version));
        hash.update(s.hash);
    }
    hash.update(t.local_node);
    number(&mut hash, t.controlled_nodes.len() as u64);
    for node in t.controlled_nodes {
        hash.update(node);
    }
    number(&mut hash, t.adoptions.len() as u64);
    number(&mut hash, t.baseline.len() as u64);
    number(&mut hash, t.requests.len() as u64);
    number(&mut hash, t.coverage.len() as u64);
    number(&mut hash, t.cpu.len() as u64);
    number(&mut hash, t.joint_policy.len() as u64);
    let mut input = [0i16; 64];
    let mut covered_until = 0;
    let mut previous_snapshot = 0;
    for (i, a) in t.adoptions.iter().enumerate() {
        let first = &t.adoptions[0];
        terminal(a.executed)?;
        if a.apply.boot_epoch == 0
            || a.apply.controller_epoch == 0
            || a.apply.plan_seq == 0
            || a.decision_seq == 0
            || a.plan_version == 0
            || a.executor_generation == 0
            || a.apply.target != a.candidates.target
            || a.scores.len() != a.candidates.len()
            || a.selected as usize >= a.scores.len()
            || a.actual.domain() != t.family.domain
            || a.actual.kind() != t.family.kind
            || a.actual != first.actual
            || a.candidates.model != first.candidates.model
            || a.apply.target != first.apply.target
            || a.apply.boot_epoch != first.apply.boot_epoch
            || a.finished_ns < a.started_ns
            || a.finished_ns > t.closing_ns
            || a.issued_ns < a.candidates.snapshot.taken_ns
            || a.accepted_ns < a.issued_ns
            || a.started_ns < a.accepted_ns
            || a.expires_local_ns < a.accepted_ns
            || a.expires_local_ns
                > a.candidates
                    .snapshot
                    .taken_ns
                    .checked_add(100_000_000)
                    .ok_or(Error::Numeric)?
            || a.finished_ns > a.approved_deadline_ns
            || a.candidates.snapshot.taken_ns >= t.observation_end_ns
            || a.candidates.model.schema_hash != t.schemas.feature.hash
            || Sha256::digest(a.model).as_slice() != a.candidates.model.model_hash
        {
            return Err(Error::Evidence);
        }
        if i == 0 && local.first_ns != a.candidates.snapshot.taken_ns {
            return Err(Error::Evidence);
        }
        if a.concurrent.is_empty()
            || a.concurrent.len() > 16
            || (a.actual.single_action() && a.concurrent.len() != 1)
            || a.concurrent.get(usize::from(a.apply.action_index)) != Some(&a.apply)
            || (a.concurrent.len() > 1 && a.shared_policy_intervals.is_empty())
            || a.shared_policy_intervals.len() > MAX_CPU_INTERVALS
        {
            return Err(Error::Evidence);
        }
        for (index, id) in a.concurrent.iter().enumerate() {
            if usize::from(id.action_index) != index
                || id.boot_epoch != a.apply.boot_epoch
                || id.controller_epoch != a.apply.controller_epoch
                || id.plan_seq != a.apply.plan_seq
            {
                return Err(Error::Evidence);
            }
        }
        // CandidateSet has public binding fields for its owner. Rebuild and
        // verify the cached digest so post-registration mutation is rejected.
        let first_choice = a.candidates.get(0).ok_or(Error::Evidence)?;
        let mut choices = [first_choice; 32];
        for (index, c) in a.candidates.iter().enumerate() {
            choices[index] = c;
        }
        let rebuilt = CandidateSet::new(
            a.candidates.snapshot,
            a.candidates.target,
            a.candidates.model,
            &choices[..a.candidates.len()],
            Some(first_choice.action),
        )
        .map_err(|_| Error::Evidence)?;
        if rebuilt.hash() != a.candidates.hash() {
            return Err(Error::Evidence);
        }
        if i > 0
            && (a.candidates.snapshot.taken_ns <= previous_snapshot
                || a.plan_version <= t.adoptions[i - 1].plan_version
                || a.apply.controller_epoch < t.adoptions[i - 1].apply.controller_epoch
                || (a.apply.controller_epoch == t.adoptions[i - 1].apply.controller_epoch
                    && (a.apply.plan_seq <= t.adoptions[i - 1].apply.plan_seq
                        || a.decision_seq <= t.adoptions[i - 1].decision_seq))
                || t.adoptions[..i].iter().any(|old| {
                    old.apply == a.apply
                        || (old.apply.controller_epoch == a.apply.controller_epoch
                            && old.decision_seq == a.decision_seq)
                }))
        {
            return Err(Error::Evidence);
        }
        previous_snapshot = a.candidates.snapshot.taken_ns;
        let model = Model::parse(a.model).map_err(|_| Error::Model)?;
        let mut best = 0;
        let mut best_score = i16::MIN;
        for (index, c) in a.candidates.iter().enumerate() {
            let encoded = features::encode(c.action, c.features)
                .map_err(|_| Error::Evidence)?
                .values;
            let score = model.score(&encoded);
            if a.scores[index] != score {
                return Err(Error::Evidence);
            }
            if index == 0 || score > best_score {
                best = index;
                best_score = score;
            }
            for x in encoded {
                hash.update(x.to_le_bytes());
            }
            hash.update(score.to_le_bytes());
            if i == 0 && index == a.selected as usize {
                input = encoded;
            }
        }
        if best != a.selected as usize
            || a.candidates.get(best).ok_or(Error::Evidence)?.action != a.actual
        {
            return Err(Error::Evidence);
        }
        if a.actual.one_shot() {
            if t.adoptions.len() != 1
                || a.issued_ns != t.observation_ns
                || a.installed_until_ns != 0
                || a.active_until_local_ns != 0
            {
                return Err(Error::Evidence);
            }
            if !a.target_request_id.is_some_and(|id| {
                id != 0
                    && t.requests
                        .iter()
                        .any(|r| r.id == id && r.arrived_ns == a.issued_ns)
            }) {
                return Err(Error::Evidence);
            }
            let bound = match a.actual {
                Action::ControlSet(_) => 200_000_000,
                Action::RecoveryRecipe(_) => 1_000_000_000,
                _ => a.approved_deadline_ns - a.accepted_ns,
            };
            if a.approved_deadline_ns - a.accepted_ns > bound
                || a.finished_ns - a.accepted_ns > bound
            {
                return Err(Error::Deadline);
            }
        } else {
            if a.target_request_id.is_some()
                || a.installed_until_ns
                    != a.candidates
                        .snapshot
                        .taken_ns
                        .checked_add(10_000_000_000)
                        .ok_or(Error::Numeric)?
                || a.active_until_local_ns != a.installed_until_ns
                || a.approved_deadline_ns - a.accepted_ns > 50_000_000
                || a.finished_ns > a.installed_until_ns
                || (i == 0
                    && (a.finished_ns > t.warmed_from_ns
                        || a.finished_ns.saturating_sub(a.candidates.snapshot.taken_ns)
                            > 5_000_000_000))
                || (i > 0 && a.finished_ns > covered_until)
            {
                return Err(Error::Evidence);
            }
            covered_until = covered_until.max(a.installed_until_ns);
        }
        for v in [
            a.decision_seq,
            a.apply.boot_epoch,
            a.apply.controller_epoch,
            a.apply.plan_seq,
            u64::from(a.apply.action_index),
            a.apply.target.id,
            a.apply.target.generation,
            a.plan_version,
            a.executor_generation,
            a.issued_ns,
            a.accepted_ns,
            a.expires_local_ns,
            a.active_until_local_ns,
            a.target_request_id.unwrap_or(0),
            a.started_ns,
            a.finished_ns,
            a.installed_until_ns,
            a.approved_deadline_ns,
            a.selected as u64,
            a.candidates.len() as u64,
            a.concurrent.len() as u64,
            a.shared_policy_intervals.len() as u64,
        ] {
            number(&mut hash, v);
        }
        for id in a.concurrent {
            apply_id(&mut hash, *id);
        }
        for (index, source) in a.shared_policy_intervals.iter().enumerate() {
            let coverage = t
                .coverage
                .iter()
                .find(|c| c.node == source.node)
                .ok_or(Error::Evidence)?;
            if source.class != CpuClass::Policy
                || source.end_ns <= source.start_ns
                || source.core >= 64
                || source.start_ns < coverage.first_ns
                || source.end_ns > coverage.closing_ns
                || coverage.reported & 1 == 0
                || a.shared_policy_intervals[..index].contains(source)
                || t.joint_policy
                    .iter()
                    .filter(|s| {
                        s.source == *source
                            && s.actions == a.concurrent
                            && s.action_index == a.apply.action_index
                    })
                    .count()
                    != 1
            {
                return Err(Error::Evidence);
            }
            hash.update(source.node);
            for v in [u64::from(source.core), source.start_ns, source.end_ns] {
                number(&mut hash, v);
            }
        }
        hash.update(a.candidates.hash());
        hash.update(a.candidates.model.model_hash);
        hash.update(a.candidates.model.schema_hash);
        number(&mut hash, a.candidates.model.generation);
        action(&mut hash, a.actual)?;
    }
    if let Some(first) = t.adoptions.first()
        && !first.actual.one_shot()
        && covered_until < t.observation_end_ns
    {
        return Err(Error::Evidence);
    }
    if !model_candidate {
        verify_baseline(t, &mut hash)?;
    }
    for (shared_index, shared) in t.joint_policy.iter().enumerate() {
        if shared.actions.is_empty()
            || shared.actions.len() > 16
            || usize::from(shared.action_index) >= shared.actions.len()
        {
            return Err(Error::Evidence);
        }
        let owner = shared.actions[usize::from(shared.action_index)];
        let adoption = t
            .adoptions
            .iter()
            .find(|a| a.apply == owner)
            .ok_or(Error::Evidence)?;
        if adoption.concurrent != shared.actions
            || !adoption.shared_policy_intervals.contains(&shared.source)
            || t.joint_policy[..shared_index].iter().any(|prior| {
                prior.source.node == shared.source.node
                    && prior.source.core == shared.source.core
                    && prior.source.start_ns < shared.source.end_ns
                    && shared.source.start_ns < prior.source.end_ns
            })
        {
            return Err(Error::Evidence);
        }
        let allocated = split_joint_policy(
            shared.source,
            shared.actions.len() as u16,
            shared.action_index,
        )?;
        if t.cpu.iter().filter(|c| **c == allocated).count() != 1 {
            return Err(Error::Evidence);
        }
        // A complete source span (or any other P span intersecting it) must
        // not sneak back into this action's cost alongside its allocated part.
        if t.cpu.iter().any(|c| {
            c.class == CpuClass::Policy
                && c.node == shared.source.node
                && c.core == shared.source.core
                && c.start_ns < shared.source.end_ns
                && shared.source.start_ns < c.end_ns
                && *c != allocated
        }) {
            return Err(Error::Evidence);
        }
        hash.update(shared.source.node);
        for v in [
            u64::from(shared.source.core),
            shared.source.start_ns,
            shared.source.end_ns,
            shared.actions.len() as u64,
            u64::from(shared.action_index),
        ] {
            number(&mut hash, v);
        }
        for id in shared.actions {
            apply_id(&mut hash, *id);
        }
    }
    for r in t.requests {
        number(&mut hash, r.id);
        number(&mut hash, r.arrived_ns);
        let (code, at) = match r.result {
            RequestResult::Completed { finished_ns } => (0, finished_ns),
            RequestResult::Rejected => (1, 0),
            RequestResult::TimedOut => (2, 0),
            RequestResult::Pending => (3, 0),
        };
        number(&mut hash, code);
        number(&mut hash, at);
    }
    for c in t.coverage {
        hash.update(c.node);
        for v in [
            c.first_ns,
            c.observation_ns,
            c.observation_end_ns,
            c.closing_ns,
            c.required as u64,
            c.reported as u64,
        ] {
            number(&mut hash, v);
        }
    }
    for c in t.cpu {
        hash.update(c.node);
        for v in [u64::from(c.core), c.start_ns, c.end_ns, c.class as u64] {
            number(&mut hash, v);
        }
    }
    let digest = hash.finalize().into();
    authority.attest(t, digest)?;
    Ok((digest, input))
}

/// Even an unlabelled/UNKNOWN trial retains measured cost and the reason for
/// exclusion. None of these totals releases an execution or resource obligation.
pub struct Evaluation {
    pub label: Result<AcceptedSample, Error>,
    pub candidate_cpu: Result<CostTotals, Error>,
    pub baseline_cpu: Result<CostTotals, Error>,
    pub candidate_performance: Result<Performance, Error>,
    pub baseline_performance: Result<Performance, Error>,
}
pub fn evaluate(
    candidate: &Trial<'_>,
    baseline: &Trial<'_>,
    authority: &impl EvidenceAuthority,
    work: &mut RewardWorkspace,
) -> Evaluation {
    let label = pair(candidate, baseline, authority, work);
    Evaluation {
        label,
        candidate_cpu: union_cpu(candidate.family, candidate.cpu, candidate.coverage, work),
        baseline_cpu: union_cpu(baseline.family, baseline.cpu, baseline.coverage, work),
        candidate_performance: performance(candidate.requests, candidate.observation_ns, work),
        baseline_performance: performance(baseline.requests, baseline.observation_ns, work),
    }
}

pub fn pair(
    candidate: &Trial<'_>,
    baseline: &Trial<'_>,
    authority: &impl EvidenceAuthority,
    work: &mut RewardWorkspace,
) -> Result<AcceptedSample, Error> {
    let candidate = verify_replay(candidate, ReplayKind::Candidate, authority, work)?;
    let baseline = verify_replay(baseline, ReplayKind::Baseline, authority, work)?;
    pair_verified(&candidate, &baseline)
}

fn make_sample(
    candidate: &VerifiedReplay,
    baseline: &VerifiedReplay,
) -> Result<AcceptedSample, Error> {
    let cp = candidate.performance;
    let bp = baseline.performance;
    let cc = candidate.cpu;
    let bc = baseline.cpu;
    let ten = F64::from_u64(10);
    let x = F64::from_u64(cp.completed).div(ten)?;
    let x0 = F64::from_u64(bp.completed).div(ten)?;
    let floor = F64::ONE.div(ten)?;
    let denom = if x0.compare(floor).is_lt() { floor } else { x0 };
    let dx = x.sub(x0)?.div(denom)?;
    let l = F64::from_u64(cp.penalty_p99_ns).div(F64::from_u64(1_000_000_000))?;
    let l0 = F64::from_u64(bp.penalty_p99_ns).div(F64::from_u64(1_000_000_000))?;
    let latency_floor = F64::ONE.div(F64::from_u64(1_000_000))?;
    let dl = l.sub(l0)?.div(if l0.compare(latency_floor).is_lt() {
        latency_floor
    } else {
        l0
    })?;
    let raw = F64::from_u64(cc.union_ns).div(F64::from_u64(OBSERVATION_NS))?;
    let cost = raw.clamp(F64::ZERO, F64::ONE)?;
    let four_tenths = F64::from_bits_checked(0x3fd9_9999_9999_999a)?;
    let fifth = F64::from_bits_checked(0x3fc9_9999_9999_999a)?;
    let reward = four_tenths
        .mul(dx.clamp(F64::ONE.neg(), F64::ONE)?)?
        .sub(four_tenths.mul(dl.clamp(F64::ONE.neg(), F64::ONE)?)?)?
        .sub(fifth.mul(cost)?)?;
    let mut digest = Sha256::new();
    digest.update(b"CYXIA_PAIRED_LABEL_1.3\0");
    digest.update(candidate.canonical_digest);
    digest.update(baseline.canonical_digest);
    digest.update(reward.to_bits().to_le_bytes());
    Ok(AcceptedSample {
        family: candidate.family,
        group: candidate.group,
        input: candidate.input,
        reward: Reward {
            candidate: cp,
            baseline: bp,
            candidate_cpu: cc,
            baseline_cpu: bc,
            raw_cost: raw,
            clipped_cost: cost,
            delta_throughput: dx,
            delta_latency: dl,
            value: reward,
        },
        evidence: digest.finalize().into(),
        reward_schema: candidate.schemas.reward,
        learning_config: candidate.schemas.learning,
        feature_schema: candidate.schemas.feature,
        action_schema: candidate.schemas.action,
    })
}
