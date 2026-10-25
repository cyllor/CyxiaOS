//! Bounded typed export of the actual publication journal. Replay owners do
//! not reconstruct candidate features or scores from current mutable state.
use super::*;
use cyxia_prototype::{features::{RawFeatures, TargetFeatures}, policy::Candidate,
    learning::reward::{CpuClass, EvidenceAuthority, RequestResult, WorkRequest}, model::MODEL_BYTES};

#[path = "incremental.rs"]
mod incremental;
pub use incremental::Incremental;

pub fn scope() -> Result<FrozenScope, Error> {
    with(|owner, _| owner.scope.ok_or(Error::NotReady))
}
/// Archive the root's read-only candidate probe with a distinct flag. These
/// rows have no PUBLISH/executor fields and cannot count as adopted samples.
#[cfg(not(test))]
pub fn record_probe(run: RunKey, proof: &crate::domain_control::replay::ValidationProbe) -> Result<(), Error> {
    if !matches!(cpu::slot(), 1 | 2) { return Err(Error::Owner); }
    let set = proof.candidates(); set.verify_integrity().map_err(|_| Error::Capture(learning::Error::Evidence))?;
    with(|owner, storage| {
        let scope = owner.scope.ok_or(Error::NotReady)?;
        if scope.key != run || owner.sealed.is_some() || scope.family != proof.family()
            || scope.target != set.target || scope.schemas.feature.hash != set.model.schema_hash
            || proof.token().boot_epoch != run.boot_epoch { return Err(Error::Stale); }
        if (0..owner.used).any(|i| u64_at(row(storage, i), 0) & PROBE != 0 && bytes32(row(storage, i), 16) == set.hash()) {
            return Ok(());
        }
        if owner.used >= DATA_RECORDS { return Err(Error::Capacity); }
        let row = row_mut(storage, owner.used); row.fill(0); put64(row, 0, PROBE);
        put64(row, 8, set.snapshot.sequence); row[16..48].copy_from_slice(&set.hash());
        put64(row, 80, set.model.generation); row[88..120].copy_from_slice(&set.model.model_hash);
        row[120..152].copy_from_slice(&set.model.schema_hash);
        for (i, value) in [set.snapshot.sequence, set.snapshot.taken_ns, set.snapshot.ledger_generation,
            set.snapshot.core_generation, set.target.id, set.target.generation].into_iter().enumerate() {
            put64(row, 152 + i * 8, value);
        }
        put16(row, 200, scope.family.domain); put16(row, 202, scope.family.kind); put16(row, 204, set.len() as u16);
        for (i, candidate) in set.iter().enumerate() { write_action(row, i, candidate.action)?; }
        let input = &mut row[INPUT..];
        put64(input, 0, u64::from_le_bytes(*b"CXPROBE1")); put64(input, 8, 3);
        for (word, value) in [(2, set.snapshot.sequence), (4, set.snapshot.taken_ns),
            (6, set.snapshot.core_generation), (7, set.snapshot.ledger_generation),
            (8, u64::from(scope.family.domain)), (9, u64::from(scope.family.kind)),
            (10, set.target.id), (11, set.target.generation), (13, set.model.generation),
            (14, run.boot_epoch), (15, set.len() as u64)] { put64(input, word * 8, value); }
        input[16 * 8..20 * 8].copy_from_slice(&set.model.model_hash);
        input[20 * 8..24 * 8].copy_from_slice(&set.hash());
        let common = set.get(0).ok_or(Error::Stale)?.features;
        for (i, value) in common.common.into_iter().chain(common.domain).enumerate() { put64(input, (24 + i) * 8, value); }
        put64(input, 40 * 8, u64::from(common.domain_present));
        for (i, candidate) in set.iter().enumerate() {
            let at = 64 + 10 * i; let mut payload = [0; 16];
            let n = policy_wire::encode_payload(candidate.action, i as u16, &mut payload)
                .map_err(|_| Error::Capture(learning::Error::Evidence))?;
            put64(input, at * 8, n as u64); input[(at + 1) * 8..(at + 3) * 8].copy_from_slice(&payload);
            let mut present = 0;
            for j in 0..4 { if let Some(value) = candidate.features.target.values[j] {
                put64(input, (at + 3 + j) * 8, value); present |= 1 << j;
            } }
            put64(input, (at + 7) * 8, present); put64(input, (at + 8) * 8, candidate.features.control_capacity.unwrap_or(0));
        }
        let mut prior = [0; 16]; let n = learning::baseline::encode(proof.current(), &mut prior)?;
        put64(input, 404 * 8, n as u64); input[405 * 8..407 * 8].copy_from_slice(&prior);
        let input_hash: [u8; 32] = Sha256::digest(&*input).into(); row[48..80].copy_from_slice(&input_hash);
        owner.used += 1; Ok(())
    })
}

/// Close recording only after all publications have terminal receipts. A
/// deadline alone cannot make an UNKNOWN journal safe to replace.
pub fn seal(seal: Seal) -> Result<(), Error> {
    if cpu::slot() != 0 { return Err(Error::Owner); }
    let actual = crate::learning_evidence::status()?.0;
    if actual.sealed != Some(seal) { return Err(Error::Stale); }
    with(|owner, storage| {
        if owner.scope.map(|s| s.key) != Some(seal.key) { return Err(Error::Stale); }
        if let Some(old) = owner.sealed { return if old == seal { Ok(()) } else { Err(Error::Stale) }; }
        for i in 0..owner.used {
            let r = row(storage, i);
            if u64_at(r, 0) & PUBLISHED != 0
                && (u64_at(r, 0) & OBSERVED == 0 || matches!(u64_at(r, 424), 0 | 2)) {
                return fail(learning::Error::Unknown);
            }
        }
        owner.sealed = Some(seal); RUN.store(0, Ordering::Release); Ok(())
    })
}

/// Called after the complete raw evidence was transferred and the capture's
/// actual service consumers have finished. It does not cancel any workload.
pub fn retire_exported(seal: Seal) -> Result<(), Error> {
    if cpu::slot() != 0 { return Err(Error::Owner); }
    with(|owner, _| {
        if owner.sealed != Some(seal) || owner.scope.map(|s| s.key) != Some(seal.key) {
            return Err(Error::Stale);
        }
        owner.scope = None; owner.checks = None; owner.sealed = None;
        owner.used = 0; owner.fault = None; Ok(())
    })
}

const EMPTY_ID: ApplyId = ApplyId { boot_epoch: 0, controller_epoch: 0, plan_seq: 0,
    action_index: 0, target: ObjectKey { id: 0, generation: 0 } };

/// One export piece is at most 256 bytes. Storage is supplied by the real
/// replay owner; a 384 KiB journal is never copied onto a kernel stack.
pub struct Record {
    run: RunKey,
    index: usize,
    cursor: usize,
    bytes: [u8; SLOT_BYTES],
    scores: [i16; 32],
    concurrent: [ApplyId; 16],
}
impl Record {
    pub const fn new(run: RunKey, index: usize) -> Self {
        Self { run, index, cursor: 0, bytes: [0; SLOT_BYTES], scores: [0; 32], concurrent: [EMPTY_ID; 16] }
    }
    /// Initialize the actual input-loan slot without first constructing a
    /// complete journal row on the native control stack.
    ///
    /// # Safety
    /// `destination` must be aligned, writable storage for one `Record`, with
    /// no outstanding references. Every field is initialized before return.
    pub unsafe fn init_at(destination: *mut Self, run: RunKey, index: usize) {
        unsafe {
            core::ptr::addr_of_mut!((*destination).run).write(run);
            core::ptr::addr_of_mut!((*destination).index).write(index);
            core::ptr::addr_of_mut!((*destination).cursor).write(0);
            core::ptr::addr_of_mut!((*destination).bytes).write_bytes(0, 1);
            core::ptr::addr_of_mut!((*destination).scores).write_bytes(0, 1);
            // ApplyId and ObjectKey contain only integers. Their all-zero
            // encoding is exactly EMPTY_ID, never an adoption or authority.
            core::ptr::addr_of_mut!((*destination).concurrent).write_bytes(0, 1);
        }
    }
    pub fn copy_piece(&mut self) -> Result<bool, Error> {
        if self.cursor == SLOT_BYTES { return Ok(false); }
        let end = (self.cursor + 256).min(SLOT_BYTES);
        let count = copy_record(self.run, self.index, self.cursor, &mut self.bytes[self.cursor..end])?;
        if count != end - self.cursor { return Err(Error::Stale); }
        self.cursor = end;
        if end == SLOT_BYTES {
            for (i, score) in self.scores.iter_mut().enumerate() { *score = u16_at(&self.bytes, 208 + i * 2) as i16; }
            for (i, id) in self.concurrent.iter_mut().enumerate() { *id = read_id(&self.bytes, CONCURRENT + i * 48); }
        }
        Ok(true)
    }
    pub fn complete(&self) -> bool { self.cursor == SLOT_BYTES }
    fn ready(&self) -> Result<&[u8], Error> {
        if !self.complete() { return Err(Error::Busy); } Ok(&self.bytes)
    }
    pub fn published(&self) -> Result<bool, Error> { Ok(u64_at(self.ready()?, 0) & PUBLISHED != 0) }
    pub fn baseline(&self) -> Result<BaselineAdoption, Error> {
        let r = self.ready()?;
        if u64_at(r, 0) & BASELINE == 0 { return Err(Error::Stale); }
        let executed = execution(r)?;
        Ok(BaselineAdoption { owner_boot: u64_at(r, 344), receipt_sequence: u64_at(r, 8),
            target: target(r), executor_generation: u64_at(r, 392), snapshot: snapshot(r), actual: action(r, 0)?,
            executed, issued_ns: u64_at(r, 352), accepted_ns: u64_at(r, 360),
            target_request_id: (u64_at(r, 440) != 0).then(|| u64_at(r, 440)),
            started_ns: u64_at(r, 400), finished_ns: u64_at(r, 416),
            installed_until_ns: u64_at(r, 376), approved_deadline_ns: u64_at(r, 384) })
    }
    pub fn candidates(&self) -> Result<CandidateSet, Error> {
        let r = self.ready()?;
        if u64_at(r, 0) & (PROPOSED | PROBE) == 0 { return Err(Error::Stale); }
        let input = &r[INPUT..];
        if <[u8; 32]>::from(Sha256::digest(input)) != bytes32(r, 48) { return fail(learning::Error::Evidence); }
        let word = |i| u64_at(input, i * 8);
        let count = usize::from(u16_at(r, 204));
        if count == 0 || count > 32 || word(15) != count as u64 || word(40) & !15 != 0
            || word(4) != snapshot(r).taken_ns || word(10) != target(r).id || word(11) != target(r).generation
            || word(13) != model(r).generation { return fail(learning::Error::Evidence); }
        let mut entries = [Candidate { action: Action::ConsoleBatch(8), features: RawFeatures::default() }; 32];
        for (i, entry) in entries[..count].iter_mut().enumerate() {
            let at = 64 + 10 * i;
            let action = action(r, i)?;
            let len = usize::try_from(word(at)).map_err(|_| Error::Capacity)?;
            if !(3..=16).contains(&len) || word(at + 7) & !15 != 0 || word(at + 9) != 0 { return fail(learning::Error::Evidence); }
            let mut payload = [0; 16]; payload[..8].copy_from_slice(&word(at + 1).to_le_bytes());
            payload[8..].copy_from_slice(&word(at + 2).to_le_bytes());
            if payload[len..].iter().any(|v| *v != 0)
                || policy_wire::decode_payload(action.domain(), action.kind(), &payload[..len])
                    .map_err(|_| Error::Capture(learning::Error::Evidence))? != (action, i as u16) {
                return fail(learning::Error::Evidence);
            }
            let mut target = TargetFeatures::default();
            for j in 0..4 {
                if word(at + 7) & (1 << j) != 0 { target.values[j] = Some(word(at + 3 + j)); }
                else if word(at + 3 + j) != 0 { return fail(learning::Error::Evidence); }
            }
            let control_capacity = if matches!(action, Action::ControlSet(_)) { Some(word(at + 8)) }
                else { if word(at + 8) != 0 { return fail(learning::Error::Evidence); } None };
            *entry = Candidate { action, features: RawFeatures { common: core::array::from_fn(|j| word(24 + j)),
                domain: core::array::from_fn(|j| word(32 + j)), domain_present: word(40) as u8, target, control_capacity } };
        }
        let domain = u16::try_from(word(8)).map_err(|_| Error::Capture(learning::Error::Evidence))?;
        let kind = u16::try_from(word(9)).map_err(|_| Error::Capture(learning::Error::Evidence))?;
        if entries[..count].iter().any(|entry| entry.action.domain() != domain || entry.action.kind() != kind) {
            return fail(learning::Error::Evidence);
        }
        let prior_len = usize::try_from(word(404)).map_err(|_| Error::Capacity)?;
        if !(3..=16).contains(&prior_len) { return fail(learning::Error::Evidence); }
        let mut prior = [0; 16]; prior[..8].copy_from_slice(&word(405).to_le_bytes());
        prior[8..].copy_from_slice(&word(406).to_le_bytes());
        if prior[prior_len..].iter().any(|byte| *byte != 0) { return fail(learning::Error::Evidence); }
        let current = learning::baseline::decode(domain, kind, &prior[..prior_len])
            .map_err(Error::Capture)?;
        let set = CandidateSet::new(snapshot(r), target(r), model(r), &entries[..count], Some(current))
            .map_err(|_| Error::Capture(learning::Error::Evidence))?;
        if set.hash() != bytes32(r, 16) { return fail(learning::Error::Evidence); }
        Ok(set)
    }
    pub fn adoption<'a>(&'a self, candidates: &'a CandidateSet, model: &'a [u8; MODEL_BYTES],
        target_request_id: Option<u64>, shared_policy_intervals: &'a [CpuInterval])
        -> Result<Adoption<'a>, Error> {
        let r = self.ready()?;
        let count = usize::from(u16_at(r, 204)); let concurrent = u64_at(r, 440) as usize;
        if u64_at(r, 0) & PUBLISHED == 0 || count > 32 || concurrent > 16
            || candidates.hash() != bytes32(r, 16) || shared_hash(shared_policy_intervals) != bytes32(r, 448) {
            return fail(learning::Error::Evidence);
        }
        Ok(Adoption { decision_seq: u64_at(r, 8), apply: read_id(r, 272), plan_version: u64_at(r, 344),
            executor_generation: u64_at(r, 392), candidates, model, scores: &self.scores[..count],
            selected: u16_at(r, 206), actual: action(r, u16_at(r, 206) as usize)?, executed: execution(r)?,
            issued_ns: decision_issued(r)?, accepted_ns: u64_at(r, 360), expires_local_ns: u64_at(r, 368), active_until_local_ns: u64_at(r, 376),
            target_request_id, started_ns: u64_at(r, 400), finished_ns: u64_at(r, 416), installed_until_ns: stamp(r).installed_until_ns,
            approved_deadline_ns: u64_at(r, 384), concurrent: &self.concurrent[..concurrent], shared_policy_intervals })
    }
}
fn execution(r: &[u8]) -> Result<ExecutionState, Error> {
    match u64_at(r, 424) { 0 => Ok(ExecutionState::Pending), 1 => Ok(ExecutionState::Applied),
        2 => Ok(ExecutionState::Unknown), 3 => fail(learning::Error::DataIncomplete),
        _ => fail(learning::Error::Evidence) }
}

/// This authority checks every borrowed row against immutable native owners.
/// The ordinary `Trial` structure is only a view; none of its claims are trusted.
pub struct Authority<'a> { seal: Seal, trace: Option<&'a crate::learning_evidence::SealedTrace<'a>>,
    #[cfg(not(test))] partner: Option<crate::peer_replay::PartnerSeal> }
impl Authority<'static> {
    pub fn new(seal: Seal) -> Result<Self, Error> {
        with(|owner, _| if owner.sealed == Some(seal) { Ok(Self { seal, trace: None,
            #[cfg(not(test))] partner: None }) } else { Err(Error::Stale) })
    }
}
impl<'a> Authority<'a> {
    pub fn from_trace(trace: &'a crate::learning_evidence::SealedTrace<'a>) -> Result<Self, Error> {
        let seal = trace.seal();
        with(|owner, _| if owner.sealed == Some(seal) { Ok(Self { seal, trace: Some(trace),
            #[cfg(not(test))] partner: None }) } else { Err(Error::Stale) })
    }
    /// The partner identity, raw count, signature and closure come from the
    /// fixed native peer owner. A caller-supplied CpuCoverage is never enough.
    #[cfg(not(test))]
    pub fn from_partner(trace: &'a crate::learning_evidence::SealedTrace<'a>) -> Result<Self, Error> {
        let mut authority = Self::from_trace(trace)?;
        let peer = crate::peer_replay::partner(trace.seal().key).map_err(Error::Capture)?;
        let frozen = scope()?;
        partner_frozen(&frozen, &peer).map_err(Error::Capture)?;
        if peer.binding.origin.node != trace.coverage().node
            || trace.staged_intervals().len() != trace.intervals().len() + peer.seal.count as usize {
            return fail(learning::Error::Evidence);
        }
        crate::peer_replay::attest(trace.seal().key,
            &trace.staged_intervals()[trace.intervals().len()..], peer.seal.coverage).map_err(Error::Capture)?;
        authority.partner = Some(peer); Ok(authority)
    }
}
#[cfg(not(test))]
pub(crate) fn partner_frozen(scope: &FrozenScope, peer: &crate::peer_replay::PartnerSeal)
    -> Result<[u8; 32], learning::Error> {
    let binding = peer.binding;
    if !matches!(scope.family.domain, 10 | 12 | 16) || binding.run != scope.key
        || binding.family != scope.family || binding.target != scope.target || binding.group != scope.group
        || binding.baseline != (scope.kind == TrialKind::Baseline)
        || binding.frozen_scope_hash != scope.frozen_scope_hash
        || binding.origin.boot != scope.key.boot_epoch || binding.origin.node == binding.participant.node
        || peer.seal.coverage.node != binding.participant.node
        || peer.seal.binding_hash != binding.hash().map_err(|_| learning::Error::Evidence)?
        || peer.seal.missing_events != 0 { return Err(learning::Error::Evidence); }
    peer.seal.validate().map_err(|_| learning::Error::Evidence)?;
    let mut hash = Sha256::new(); hash.update(b"CYXIA_NATIVE_PAIRED_NODE_CONFIGURATION_1.3\0");
    hash.update(binding.origin.node); hash.update(binding.origin.boot.to_le_bytes());
    hash.update(scope.frozen_other_domains);
    hash.update(binding.participant.node); hash.update(binding.participant.boot.to_le_bytes());
    hash.update(peer.seal.frozen_other_domains); Ok(hash.finalize().into())
}
impl EvidenceAuthority for Authority<'_> {
    fn attest(&self, trial: &Trial<'_>, digest: [u8; 32]) -> Result<(), learning::Error> {
        if digest == [0; 32] { return Err(learning::Error::Evidence); }
        #[cfg(test)]
        let (extra, warmup, later, proof) = (0usize, 0u64, 0u64, None);
        #[cfg(not(test))]
        let (extra, warmup, later, proof) = if let Some(peer) = self.partner {
            let actual = crate::peer_replay::partner(self.seal.key)?;
            if actual != peer { return Err(learning::Error::Stale); }
            (usize::try_from(peer.seal.count).map_err(|_| learning::Error::Capacity)?,
                peer.seal.ordinary_warmup_ns, peer.seal.later_workload_ns,
                Some((peer.seal.coverage, partner_frozen(&scope().map_err(learn)?, &peer)?)))
        } else { (0, 0, 0, None) };
        let status = if let Some(trace) = self.trace {
            verify_scope_with_partner(trial, self.seal, trace.coverage(), proof)?;
            let expected = if proof.is_some() { trace.staged_intervals() } else { trace.intervals() };
            if trial.cpu != expected || trial.requests != trace.requests() { return Err(learning::Error::Evidence); }
            #[cfg(not(test))]
            if let Some(peer) = self.partner {
                crate::peer_replay::attest(self.seal.key, &expected[trace.intervals().len()..], peer.seal.coverage)?;
            }
            trace.status()
        } else {
            verify_scope(trial, self.seal)?;
            crate::learning_evidence::status().map_err(learn)?.0
        };
        if status.sealed != Some(self.seal) || trial.cpu.len() != self.seal.intervals as usize + extra
            || trial.requests.len() != self.seal.requests as usize
            || trial.ordinary_warmup_cpu_ns != status.ordinary_warmup_ns.checked_add(warmup).ok_or(learning::Error::Numeric)?
            || trial.later_workload_cpu_ns != status.later_workload_ns.checked_add(later).ok_or(learning::Error::Numeric)? {
            return Err(learning::Error::Evidence);
        }
        if self.trace.is_none() {
        let mut cpus = [CpuInterval { node: [0; 32], core: 0, start_ns: 0, end_ns: 0, class: CpuClass::Policy }; 16];
        for at in (0..trial.cpu.len()).step_by(16) {
            let n = crate::learning_evidence::copy_intervals(self.seal, at, &mut cpus).map_err(learn)?;
            if n == 0 || trial.cpu[at..at + n] != cpus[..n] { return Err(learning::Error::Evidence); }
        }
        let empty = WorkRequest { id: 0, arrived_ns: 0, result: RequestResult::Pending };
        let mut requests = [(empty, None); 16];
        for at in (0..trial.requests.len()).step_by(16) {
            let n = crate::learning_evidence::copy_requests(self.seal, at, &mut requests).map_err(learn)?;
            if n == 0 || requests[..n].iter().enumerate().any(|(i, (row, issued))|
                *row != trial.requests[at + i] || issued.is_none()) { return Err(learning::Error::Evidence); }
        }
        }
        for adoption in trial.adoptions { verify_adoption(self.seal.key, adoption)?; }
        for baseline in trial.baseline { verify_baseline(self.seal.key, baseline)?; }
        let history = status_history(self.seal.key).map_err(learn)?;
        if history != (trial.adoptions.len(), trial.baseline.len()) { return Err(learning::Error::Evidence); }
        Ok(())
    }
}
fn status_history(run: RunKey) -> Result<(usize, usize), Error> {
    with(|owner, storage| {
        if owner.scope.map(|s| s.key) != Some(run) { return Err(Error::Stale); }
        let (mut adopted, mut baselines) = (0, 0);
        for i in 0..owner.used { let flags = u64_at(row(storage, i), 0);
            adopted += usize::from(flags & PUBLISHED != 0); baselines += usize::from(flags & BASELINE != 0); }
        Ok((adopted, baselines))
    })
}
