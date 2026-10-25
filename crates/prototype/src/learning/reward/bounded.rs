//! Paid-turn verification of a retained, immutable native replay.
//! The synchronous verifier remains the independent canonical reference.
use super::bounded_cost::{CpuCursor, PerformanceCursor};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayPiece {
    Header,
    Adoption {
        index: usize,
    },
    Model {
        adoption: usize,
        start: usize,
        end: usize,
    },
    Candidate {
        adoption: usize,
        index: usize,
    },
    Shared {
        adoption: usize,
        index: usize,
    },
    Baseline {
        index: usize,
    },
    Joint {
        index: usize,
    },
    Requests {
        start: usize,
        end: usize,
    },
    Coverage {
        index: usize,
    },
    Cpu {
        start: usize,
        end: usize,
    },
}

/// Protected-owner authority for a retained replay. Implementations must bind
/// the actual sealed capture, immutable publication journal and model/page
/// leases, and retain them until this walk finishes or is explicitly excluded.
/// Every piece must be compared to those original owners; a supplied digest,
/// repeated pointer or caller's assertion of immutability grants no authority.
/// `None`/`false` means an actual temporary owner-lock contention. An actual
/// UNKNOWN result remains an error and can never become a retryable receipt.
pub trait IncrementalAuthority {
    fn begin(&self, trial: &Trial<'_>) -> Result<Option<[u8; 32]>, Error>;
    fn attest_piece(
        &self,
        trial: &Trial<'_>,
        binding: [u8; 32],
        piece: ReplayPiece,
    ) -> Result<bool, Error>;
    fn finish(&self, trial: &Trial<'_>, binding: [u8; 32], digest: [u8; 32])
    -> Result<bool, Error>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    id: u64,
    family: Family,
    group: ReplayGroup,
    frozen: [u8; 32],
    schemas: Schemas,
    local: [u8; 32],
    times: [u64; 7],
    sizes: [usize; 7],
    addresses: [usize; 2],
    correct: bool,
    frozen_flag: bool,
    closing: ExecutionState,
}
impl Identity {
    fn of(t: &Trial<'_>) -> Self {
        Self {
            id: t.id,
            family: t.family,
            group: t.group,
            frozen: t.frozen_other_domains,
            schemas: t.schemas,
            local: t.local_node,
            times: [
                t.observation_ns,
                t.observation_end_ns,
                t.warmed_from_ns,
                t.closing_ns,
                t.ordinary_warmup_cpu_ns,
                t.later_workload_cpu_ns,
                t.peak_workspace_bytes,
            ],
            sizes: [
                t.adoptions.len(),
                t.baseline.len(),
                t.requests.len(),
                t.coverage.len(),
                t.cpu.len(),
                t.joint_policy.len(),
                t.controlled_nodes.len(),
            ],
            addresses: [t.cpu.as_ptr() as usize, t.requests.as_ptr() as usize],
            correct: t.correct,
            frozen_flag: t.frozen,
            closing: t.closing,
        }
    }
}
/// The native owner rebuilds the small Adoption view between paid turns, but
/// its retained candidate/model/score and journal loans must remain identical.
/// Never retain or compare the temporary Adoption object's own address.
#[derive(Clone, Copy, PartialEq, Eq)]
struct AdoptionIdentity {
    sequence: [u64; 3],
    apply: ApplyId,
    actual: Action,
    executed: ExecutionState,
    selected: u16,
    times: [u64; 8],
    target_request: Option<u64>,
    snapshot: Snapshot,
    target: ObjectKey,
    model: crate::policy::ModelBinding,
    set_hash: [u8; 32],
    addresses: [usize; 5],
    sizes: [usize; 4],
}
impl AdoptionIdentity {
    fn of(a: &Adoption<'_>) -> Self {
        Self {
            sequence: [a.decision_seq, a.plan_version, a.executor_generation],
            apply: a.apply,
            actual: a.actual,
            executed: a.executed,
            selected: a.selected,
            times: [
                a.issued_ns,
                a.accepted_ns,
                a.expires_local_ns,
                a.active_until_local_ns,
                a.started_ns,
                a.finished_ns,
                a.installed_until_ns,
                a.approved_deadline_ns,
            ],
            target_request: a.target_request_id,
            snapshot: a.candidates.snapshot,
            target: a.candidates.target,
            model: a.candidates.model,
            set_hash: a.candidates.hash(),
            addresses: [
                a.candidates as *const CandidateSet as usize,
                a.model.as_ptr() as usize,
                a.scores.as_ptr() as usize,
                a.concurrent.as_ptr() as usize,
                a.shared_policy_intervals.as_ptr() as usize,
            ],
            sizes: [
                a.candidates.len(),
                a.scores.len(),
                a.concurrent.len(),
                a.shared_policy_intervals.len(),
            ],
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    Adoption,
    Model,
    Candidate,
    AdoptionTarget,
    AdoptionBody,
    Shared,
    SharedScan,
    AdoptionTail,
    Baseline,
    BaselineTarget,
    BaselineBody,
    Joint,
    JointScan,
    Requests,
    Coverage,
    Cpu,
    Performance,
    Union,
    Finish,
    Delivered,
}

/// This continuation owns only cursors, small hashes and measured aggregates.
/// It borrows no temporary Trial view across a paid turn. The caller must keep
/// its actual loans; the authority rechecks that same protected binding on
/// every step. At most 16 CPU/request rows, 256 model bytes, one model score,
/// or 64 bounded comparisons are advanced by a step.
pub struct ReplayVerification {
    kind: ReplayKind,
    phase: Phase,
    identity: Option<Identity>,
    adoption_identity: Option<AdoptionIdentity>,
    binding: Option<[u8; 32]>,
    fault: Option<Error>,
    hash: Sha256,
    model_hash: Sha256,
    schedule: Sha256,
    digest: [u8; 32],
    input: [i16; 64],
    item: usize,
    index: usize,
    scan: usize,
    matched: usize,
    found: bool,
    target_request: Option<(u64, u64)>,
    saved: Option<CpuInterval>,
    best: usize,
    best_score: i16,
    covered_until: u64,
    previous_snapshot: u64,
    baseline_until: u64,
    cpu: CpuCursor,
    performance: PerformanceCursor,
}
impl ReplayVerification {
    pub fn new(kind: ReplayKind) -> Self {
        Self {
            kind,
            phase: Phase::Header,
            identity: None,
            adoption_identity: None,
            binding: None,
            fault: None,
            hash: Sha256::new(),
            model_hash: Sha256::new(),
            schedule: Sha256::new(),
            digest: [0; 32],
            input: [0; 64],
            item: 0,
            index: 0,
            scan: 0,
            matched: 0,
            found: false,
            target_request: None,
            saved: None,
            best: 0,
            best_score: i16::MIN,
            covered_until: 0,
            previous_snapshot: 0,
            baseline_until: 0,
            cpu: CpuCursor::new(),
            performance: PerformanceCursor::new(),
        }
    }
    pub fn step(
        &mut self,
        t: &Trial<'_>,
        authority: &impl IncrementalAuthority,
        work: &mut RewardWorkspace,
    ) -> Result<Option<VerifiedReplay>, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if self.phase == Phase::Delivered {
            return Err(Error::Stale);
        }
        let result = self.advance(t, authority, work);
        if let Err(error) = result {
            self.fault = Some(error);
        }
        result
    }
    fn advance(
        &mut self,
        t: &Trial<'_>,
        authority: &impl IncrementalAuthority,
        work: &mut RewardWorkspace,
    ) -> Result<Option<VerifiedReplay>, Error> {
        let identity = Identity::of(t);
        if self.identity.is_some_and(|old| old != identity) {
            return Err(Error::Stale);
        }
        if matches!(
            self.phase,
            Phase::Model
                | Phase::Candidate
                | Phase::AdoptionTarget
                | Phase::AdoptionBody
                | Phase::Shared
                | Phase::SharedScan
                | Phase::AdoptionTail
        ) {
            let current = t.adoptions.get(self.item).ok_or(Error::Stale)?;
            if self.adoption_identity != Some(AdoptionIdentity::of(current)) {
                return Err(Error::Stale);
            }
        }
        let Some(binding) = authority.begin(t)? else {
            return Ok(None);
        };
        if binding == [0; 32] || self.binding.is_some_and(|old| old != binding) {
            return Err(Error::Stale);
        }
        self.identity = Some(identity);
        self.binding = Some(binding);
        match self.phase {
            Phase::Header => {
                if !authority.attest_piece(t, binding, ReplayPiece::Header)? {
                    return Ok(None);
                }
                self.hash = header_hash(t, self.kind == ReplayKind::Candidate)?;
                self.schedule
                    .update(b"CYXIA_FROZEN_RELATIVE_ARRIVALS_1.3\0");
                number(&mut self.schedule, t.requests.len() as u64);
                self.phase = Phase::Adoption;
            }
            Phase::Adoption => {
                if self.item == t.adoptions.len() {
                    if t.adoptions.first().is_some_and(|a| !a.actual.one_shot())
                        && self.covered_until < t.observation_end_ns
                    {
                        return Err(Error::Evidence);
                    }
                    self.index = 0;
                    self.phase = Phase::Baseline;
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Adoption { index: self.item },
                    )? {
                        return Ok(None);
                    }
                    adoption_start(t, self.item, self.previous_snapshot)?;
                    self.adoption_identity = Some(AdoptionIdentity::of(&t.adoptions[self.item]));
                    self.previous_snapshot = t.adoptions[self.item].candidates.snapshot.taken_ns;
                    self.index = 0;
                    self.model_hash = Sha256::new();
                    self.phase = Phase::Model;
                }
            }
            Phase::Model => {
                let a = &t.adoptions[self.item];
                let end = self.index.saturating_add(256).min(MODEL_BYTES);
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Model {
                        adoption: self.item,
                        start: self.index,
                        end,
                    },
                )? {
                    return Ok(None);
                }
                self.model_hash.update(&a.model[self.index..end]);
                self.index = end;
                if end == MODEL_BYTES {
                    if <[u8; 32]>::from(self.model_hash.clone().finalize())
                        != a.candidates.model.model_hash
                    {
                        return Err(Error::Evidence);
                    }
                    self.index = 0;
                    self.best = 0;
                    self.best_score = i16::MIN;
                    self.phase = Phase::Candidate;
                }
            }
            Phase::Candidate => {
                let a = &t.adoptions[self.item];
                if self.index == a.candidates.len() {
                    self.scan = 0;
                    self.found = false;
                    self.target_request = None;
                    self.phase = if a.actual.one_shot() {
                        Phase::AdoptionTarget
                    } else {
                        Phase::AdoptionBody
                    };
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Candidate {
                            adoption: self.item,
                            index: self.index,
                        },
                    )? {
                        return Ok(None);
                    }
                    let c = a.candidates.get(self.index).ok_or(Error::Evidence)?;
                    let encoded = features::encode(c.action, c.features)
                        .map_err(|_| Error::Evidence)?
                        .values;
                    let score = Model::parse(a.model)
                        .map_err(|_| Error::Model)?
                        .score(&encoded);
                    if a.scores[self.index] != score {
                        return Err(Error::Evidence);
                    }
                    if self.index == 0 || score > self.best_score {
                        self.best = self.index;
                        self.best_score = score;
                    }
                    for value in encoded {
                        self.hash.update(value.to_le_bytes());
                    }
                    self.hash.update(score.to_le_bytes());
                    if self.item == 0 && self.index == usize::from(a.selected) {
                        self.input = encoded;
                    }
                    self.index += 1;
                }
            }
            Phase::AdoptionTarget | Phase::BaselineTarget => {
                let target = if self.phase == Phase::AdoptionTarget {
                    let a = &t.adoptions[self.item];
                    (a.target_request_id, a.issued_ns)
                } else {
                    let b = &t.baseline[self.index];
                    (b.target_request_id, b.issued_ns)
                };
                let target = (
                    target.0.filter(|id| *id != 0).ok_or(Error::Evidence)?,
                    target.1,
                );
                if self.target_request.is_some_and(|old| old != target) {
                    return Err(Error::Stale);
                }
                let end = self.scan.saturating_add(16).min(t.requests.len());
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Requests {
                        start: self.scan,
                        end,
                    },
                )? {
                    return Ok(None);
                }
                // This search contributes no canonical bytes. The normal
                // Requests phase later hashes every row exactly once, in the
                // original order, after the adoption/baseline fields.
                self.target_request = Some(target);
                self.found |= t.requests[self.scan..end]
                    .iter()
                    .any(|r| r.id == target.0 && r.arrived_ns == target.1);
                self.scan = end;
                if self.found {
                    self.phase = if self.phase == Phase::AdoptionTarget {
                        Phase::AdoptionBody
                    } else {
                        Phase::BaselineBody
                    };
                } else if end == t.requests.len() {
                    return Err(Error::Evidence);
                }
            }
            Phase::AdoptionBody => {
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Adoption { index: self.item },
                )? {
                    return Ok(None);
                }
                let a = &t.adoptions[self.item];
                if a.actual.one_shot()
                    && self.target_request != a.target_request_id.map(|id| (id, a.issued_ns))
                {
                    return Err(Error::Stale);
                }
                adoption_body(
                    t,
                    self.item,
                    self.best,
                    self.found,
                    &mut self.covered_until,
                    &mut self.hash,
                )?;
                self.index = 0;
                self.phase = Phase::Shared;
            }
            Phase::Shared => {
                let a = &t.adoptions[self.item];
                if self.index == a.shared_policy_intervals.len() {
                    self.phase = Phase::AdoptionTail;
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Shared {
                            adoption: self.item,
                            index: self.index,
                        },
                    )? {
                        return Ok(None);
                    }
                    let source = a.shared_policy_intervals[self.index];
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
                    {
                        return Err(Error::Evidence);
                    }
                    self.saved = Some(source);
                    self.scan = 0;
                    self.matched = 0;
                    self.phase = Phase::SharedScan;
                }
            }
            Phase::SharedScan => {
                let a = &t.adoptions[self.item];
                let source = self.saved.ok_or(Error::State)?;
                if a.shared_policy_intervals[self.index] != source {
                    return Err(Error::Stale);
                }
                let total = self
                    .index
                    .checked_add(t.joint_policy.len())
                    .ok_or(Error::Capacity)?;
                let end = self.scan.saturating_add(64).min(total);
                for at in self.scan..end {
                    if at < self.index {
                        if a.shared_policy_intervals[at] == source {
                            return Err(Error::Evidence);
                        }
                    } else {
                        let joint = &t.joint_policy[at - self.index];
                        if joint.source == source
                            && joint.actions == a.concurrent
                            && joint.action_index == a.apply.action_index
                        {
                            self.matched += 1;
                        }
                    }
                }
                self.scan = end;
                if end == total {
                    if self.matched != 1 {
                        return Err(Error::Evidence);
                    }
                    self.hash.update(source.node);
                    for v in [u64::from(source.core), source.start_ns, source.end_ns] {
                        number(&mut self.hash, v);
                    }
                    self.index += 1;
                    self.phase = Phase::Shared;
                }
            }
            Phase::AdoptionTail => {
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Adoption { index: self.item },
                )? {
                    return Ok(None);
                }
                let a = &t.adoptions[self.item];
                self.hash.update(a.candidates.hash());
                self.hash.update(a.candidates.model.model_hash);
                self.hash.update(a.candidates.model.schema_hash);
                number(&mut self.hash, a.candidates.model.generation);
                action(&mut self.hash, a.actual)?;
                self.adoption_identity = None;
                self.item += 1;
                self.phase = Phase::Adoption;
            }
            Phase::Baseline => {
                if self.index == t.baseline.len() {
                    if t.baseline.first().is_some_and(|b| !b.actual.one_shot())
                        && self.baseline_until < t.observation_end_ns
                    {
                        return Err(Error::Evidence);
                    }
                    self.index = 0;
                    self.phase = Phase::Joint;
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Baseline { index: self.index },
                    )? {
                        return Ok(None);
                    }
                    if t.baseline[self.index].actual.one_shot() {
                        baseline_start(t, self.index)?;
                        self.scan = 0;
                        self.found = false;
                        self.target_request = None;
                        self.phase = Phase::BaselineTarget;
                    } else {
                        baseline_row(
                            t,
                            self.index,
                            false,
                            &mut self.baseline_until,
                            &mut self.hash,
                        )?;
                        self.index += 1;
                    }
                }
            }
            Phase::BaselineBody => {
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Baseline { index: self.index },
                )? {
                    return Ok(None);
                }
                let b = &t.baseline[self.index];
                if self.target_request != b.target_request_id.map(|id| (id, b.issued_ns)) {
                    return Err(Error::Stale);
                }
                baseline_row(
                    t,
                    self.index,
                    self.found,
                    &mut self.baseline_until,
                    &mut self.hash,
                )?;
                self.index += 1;
                self.phase = Phase::Baseline;
            }
            Phase::Joint => {
                if self.index == t.joint_policy.len() {
                    self.index = 0;
                    self.phase = Phase::Requests;
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Joint { index: self.index },
                    )? {
                        return Ok(None);
                    }
                    let shared = &t.joint_policy[self.index];
                    if shared.actions.is_empty()
                        || shared.actions.len() > 16
                        || usize::from(shared.action_index) >= shared.actions.len()
                    {
                        return Err(Error::Evidence);
                    }
                    let owner = shared.actions[usize::from(shared.action_index)];
                    self.item = t
                        .adoptions
                        .iter()
                        .position(|a| a.apply == owner)
                        .ok_or(Error::Evidence)?;
                    if t.adoptions[self.item].concurrent != shared.actions {
                        return Err(Error::Evidence);
                    }
                    self.saved = Some(split_joint_policy(
                        shared.source,
                        shared.actions.len() as u16,
                        shared.action_index,
                    )?);
                    self.scan = 0;
                    self.matched = 0;
                    self.found = false;
                    self.phase = Phase::JointScan;
                }
            }
            Phase::JointScan => {
                let shared = &t.joint_policy[self.index];
                let sources = t.adoptions[self.item].shared_policy_intervals;
                let allocated = self.saved.ok_or(Error::State)?;
                let prefix = sources
                    .len()
                    .checked_add(self.index)
                    .ok_or(Error::Capacity)?;
                let total = prefix.checked_add(t.cpu.len()).ok_or(Error::Capacity)?;
                let end = self.scan.saturating_add(64).min(total);
                for at in self.scan..end {
                    if at < sources.len() {
                        self.found |= sources[at] == shared.source;
                    } else if at < prefix {
                        let prior = &t.joint_policy[at - sources.len()];
                        if prior.source.node == shared.source.node
                            && prior.source.core == shared.source.core
                            && prior.source.start_ns < shared.source.end_ns
                            && shared.source.start_ns < prior.source.end_ns
                        {
                            return Err(Error::Evidence);
                        }
                    } else {
                        let c = t.cpu[at - prefix];
                        if c == allocated {
                            self.matched += 1;
                        }
                        if c.class == CpuClass::Policy
                            && c.node == shared.source.node
                            && c.core == shared.source.core
                            && c.start_ns < shared.source.end_ns
                            && shared.source.start_ns < c.end_ns
                            && c != allocated
                        {
                            return Err(Error::Evidence);
                        }
                    }
                }
                self.scan = end;
                if end == total {
                    if !self.found || self.matched != 1 {
                        return Err(Error::Evidence);
                    }
                    self.hash.update(shared.source.node);
                    for v in [
                        u64::from(shared.source.core),
                        shared.source.start_ns,
                        shared.source.end_ns,
                        shared.actions.len() as u64,
                        u64::from(shared.action_index),
                    ] {
                        number(&mut self.hash, v);
                    }
                    for id in shared.actions {
                        apply_id(&mut self.hash, *id);
                    }
                    self.index += 1;
                    self.phase = Phase::Joint;
                }
            }
            Phase::Requests => {
                let end = self.index.saturating_add(16).min(t.requests.len());
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Requests {
                        start: self.index,
                        end,
                    },
                )? {
                    return Ok(None);
                }
                for r in &t.requests[self.index..end] {
                    number(&mut self.hash, r.id);
                    number(&mut self.hash, r.arrived_ns);
                    let (code, at) = match r.result {
                        RequestResult::Completed { finished_ns } => (0, finished_ns),
                        RequestResult::Rejected => (1, 0),
                        RequestResult::TimedOut => (2, 0),
                        RequestResult::Pending => (3, 0),
                    };
                    number(&mut self.hash, code);
                    number(&mut self.hash, at);
                    number(&mut self.schedule, r.id);
                    number(
                        &mut self.schedule,
                        r.arrived_ns
                            .checked_sub(t.observation_ns)
                            .ok_or(Error::Evidence)?,
                    );
                }
                self.index = end;
                if end == t.requests.len() {
                    self.index = 0;
                    self.phase = Phase::Coverage;
                }
            }
            Phase::Coverage => {
                if self.index == t.coverage.len() {
                    self.index = 0;
                    self.phase = Phase::Cpu;
                } else {
                    if !authority.attest_piece(
                        t,
                        binding,
                        ReplayPiece::Coverage { index: self.index },
                    )? {
                        return Ok(None);
                    }
                    let c = t.coverage[self.index];
                    self.hash.update(c.node);
                    for v in [
                        c.first_ns,
                        c.observation_ns,
                        c.observation_end_ns,
                        c.closing_ns,
                        u64::from(c.required),
                        u64::from(c.reported),
                    ] {
                        number(&mut self.hash, v);
                    }
                    self.index += 1;
                }
            }
            Phase::Cpu => {
                let end = self.index.saturating_add(16).min(t.cpu.len());
                if !authority.attest_piece(
                    t,
                    binding,
                    ReplayPiece::Cpu {
                        start: self.index,
                        end,
                    },
                )? {
                    return Ok(None);
                }
                for c in &t.cpu[self.index..end] {
                    self.hash.update(c.node);
                    for v in [u64::from(c.core), c.start_ns, c.end_ns, c.class as u64] {
                        number(&mut self.hash, v);
                    }
                }
                self.index = end;
                if end == t.cpu.len() {
                    self.digest = self.hash.clone().finalize().into();
                    self.phase = Phase::Performance;
                }
            }
            Phase::Performance => {
                if self.performance.step(t.requests, t.observation_ns, work)? {
                    self.phase = Phase::Union;
                }
            }
            Phase::Union => {
                if self.cpu.step(t.family, t.cpu, t.coverage, work)? {
                    self.phase = Phase::Finish;
                }
            }
            Phase::Finish => {
                if !authority.finish(t, binding, self.digest)? {
                    return Ok(None);
                }
                let mut nodes = Sha256::new();
                nodes.update(b"CYXIA_FROZEN_REPLAY_NODES_1.3\0");
                number(&mut nodes, t.controlled_nodes.len() as u64);
                for node in t.controlled_nodes {
                    nodes.update(node);
                }
                let verified = VerifiedReplay {
                    kind: self.kind,
                    trial_id: t.id,
                    family: t.family,
                    group: t.group,
                    frozen_other_domains: t.frozen_other_domains,
                    schemas: t.schemas,
                    local_node: t.local_node,
                    controlled_nodes_hash: nodes.finalize().into(),
                    requests: t.requests.len(),
                    schedule_hash: self.schedule.clone().finalize().into(),
                    canonical_digest: self.digest,
                    input: self.input,
                    performance: self.performance.finish()?,
                    cpu: self.cpu.finish()?,
                    probe_hash: t.adoptions.first().map(|a| a.candidates.hash()),
                };
                self.phase = Phase::Delivered;
                return Ok(Some(verified));
            }
            Phase::Delivered => return Err(Error::Stale),
        }
        Ok(None)
    }
}

fn header_hash(t: &Trial<'_>, model_candidate: bool) -> Result<Sha256, Error> {
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
    Ok(hash)
}

fn adoption_start(t: &Trial<'_>, i: usize, previous_snapshot: u64) -> Result<(), Error> {
    let a = &t.adoptions[i];
    let first = &t.adoptions[0];
    let local = t
        .coverage
        .iter()
        .find(|c| c.node == t.local_node)
        .ok_or(Error::Evidence)?;
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
    // Entries are private and immutable after CandidateSet::new. Verify
    // every public binding and preserve the canonical unscoped replay rule.
    if a.candidates.canary_permit().is_some() {
        return Err(Error::Evidence);
    }
    a.candidates
        .verify_integrity()
        .map_err(|_| Error::Evidence)?;
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
    Ok(())
}

fn adoption_body(
    t: &Trial<'_>,
    i: usize,
    best: usize,
    target_found: bool,
    until: &mut u64,
    hash: &mut Sha256,
) -> Result<(), Error> {
    let a = &t.adoptions[i];
    let mut covered_until = *until;
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
        if !a
            .target_request_id
            .is_some_and(|id| id != 0 && target_found)
        {
            return Err(Error::Evidence);
        }
        let bound = match a.actual {
            Action::ControlSet(_) => 200_000_000,
            Action::RecoveryRecipe(_) => 1_000_000_000,
            _ => a.approved_deadline_ns - a.accepted_ns,
        };
        if a.approved_deadline_ns - a.accepted_ns > bound || a.finished_ns - a.accepted_ns > bound {
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
        number(hash, v);
    }
    for id in a.concurrent {
        apply_id(hash, *id);
    }
    *until = covered_until;
    Ok(())
}

fn baseline_start(t: &Trial<'_>, index: usize) -> Result<(), Error> {
    let first = t.baseline.first().ok_or(Error::Evidence)?;
    let local = t
        .coverage
        .iter()
        .find(|c| c.node == t.local_node)
        .ok_or(Error::Evidence)?;
    let b = &t.baseline[index];
    terminal(b.executed)?;
    crate::learning::baseline::validate(b.actual)?;
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
    Ok(())
}

fn baseline_row(
    t: &Trial<'_>,
    index: usize,
    target_found: bool,
    retained_until: &mut u64,
    hash: &mut Sha256,
) -> Result<(), Error> {
    baseline_start(t, index)?;
    let b = &t.baseline[index];
    let mut until = *retained_until;
    if b.actual.one_shot() {
        if t.baseline.len() != 1
            || b.issued_ns != t.observation_ns
            || b.installed_until_ns != 0
            || !b
                .target_request_id
                .is_some_and(|id| id != 0 && target_found)
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
    let n = crate::learning::baseline::encode(b.actual, &mut payload)?;
    hash.update(b.actual.domain().to_le_bytes());
    hash.update(b.actual.kind().to_le_bytes());
    hash.update(&payload[..n]);
    *retained_until = until;
    Ok(())
}
