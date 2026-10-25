//! A fully verified side of a sequential native replay. This capability lets
//! the protected owner reuse its one trace buffer after exporting the original
//! evidence, without keeping two 8192-interval traces in the learning workspace.
//! A digest, caller-supplied totals, or serialized wire row cannot construct it.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayKind {
    Candidate,
    Baseline,
}

/// Constructed only after the complete trial, protected receipts, CPU union,
/// and request outcomes have been verified. It intentionally is not Clone:
/// the replay owner retains custody until pairing or explicit exclusion.
pub struct VerifiedReplay {
    pub(super) kind: ReplayKind,
    pub(super) trial_id: u64,
    pub(super) family: Family,
    pub(super) group: ReplayGroup,
    pub(super) frozen_other_domains: [u8; 32],
    pub(super) schemas: Schemas,
    pub(super) local_node: [u8; 32],
    pub(super) controlled_nodes_hash: [u8; 32],
    pub(super) requests: usize,
    pub(super) schedule_hash: [u8; 32],
    pub(super) canonical_digest: [u8; 32],
    pub(super) input: [i16; 64],
    pub(super) performance: Performance,
    pub(super) cpu: CostTotals,
    pub(super) probe_hash: Option<[u8; 32]>,
}

impl VerifiedReplay {
    pub fn kind(&self) -> ReplayKind { self.kind }
    pub fn trial_id(&self) -> u64 { self.trial_id }
    pub fn family(&self) -> Family { self.family }
    pub fn group(&self) -> ReplayGroup { self.group }
    pub fn evidence_hash(&self) -> [u8; 32] { self.canonical_digest }
    pub fn schedule_hash(&self) -> [u8; 32] { self.schedule_hash }
    pub fn performance(&self) -> Performance { self.performance }
    pub fn cpu(&self) -> CostTotals { self.cpu }
    pub fn candidate_set_hash(&self) -> Option<[u8; 32]> { self.probe_hash }
}

/// Called while the original native capture and publication journal are still
/// retained. `attest` must check those actual owners, including frozen state,
/// every renewal, source closure, and any authenticated partner evidence.
pub fn verify_replay(
    trial: &Trial<'_>,
    kind: ReplayKind,
    authority: &impl EvidenceAuthority,
    work: &mut RewardWorkspace,
) -> Result<VerifiedReplay, Error> {
    let (canonical_digest, input) =
        verify_trial(trial, kind == ReplayKind::Candidate, authority)?;
    let performance = performance(trial.requests, trial.observation_ns, work)?;
    let cpu = union_cpu(trial.family, trial.cpu, trial.coverage, work)?;
    let mut schedule = Sha256::new();
    schedule.update(b"CYXIA_FROZEN_RELATIVE_ARRIVALS_1.3\0");
    number(&mut schedule, trial.requests.len() as u64);
    for request in trial.requests {
        number(&mut schedule, request.id);
        number(&mut schedule, request.arrived_ns.checked_sub(trial.observation_ns)
            .ok_or(Error::Evidence)?);
    }
    let mut nodes = Sha256::new();
    nodes.update(b"CYXIA_FROZEN_REPLAY_NODES_1.3\0");
    number(&mut nodes, trial.controlled_nodes.len() as u64);
    for node in trial.controlled_nodes { nodes.update(node); }
    Ok(VerifiedReplay {
        kind, trial_id: trial.id, family: trial.family, group: trial.group,
        frozen_other_domains: trial.frozen_other_domains, schemas: trial.schemas,
        local_node: trial.local_node, controlled_nodes_hash: nodes.finalize().into(),
        requests: trial.requests.len(), schedule_hash: schedule.finalize().into(),
        canonical_digest, input, performance, cpu,
        probe_hash: trial.adoptions.first().map(|v| v.candidates.hash()),
    })
}

/// Pair the two independently verified executions. Matching includes the whole
/// replay group and the ordered, relative arrival table; moving the baseline's
/// clock origin is allowed, changing an id or one arrival nanosecond is not.
pub fn pair_verified(
    candidate: &VerifiedReplay,
    baseline: &VerifiedReplay,
) -> Result<AcceptedSample, Error> {
    if candidate.kind != ReplayKind::Candidate || baseline.kind != ReplayKind::Baseline
        || candidate.group != baseline.group || candidate.family != baseline.family
        || candidate.frozen_other_domains != baseline.frozen_other_domains
        || candidate.schemas != baseline.schemas || candidate.local_node != baseline.local_node
        || candidate.controlled_nodes_hash != baseline.controlled_nodes_hash
        || candidate.requests != baseline.requests || candidate.schedule_hash != baseline.schedule_hash
    { return Err(Error::Evidence); }
    make_sample(candidate, baseline)
}
