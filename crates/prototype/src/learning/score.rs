//! Independently scheduled integer scoring. Only Governance can prepare a job
//! from a validated model. Worker output alone has no publication authority.
use super::{
    Error, Family,
    governance::{Role as ExtraRole, ScoreProof, WINDOW_NS, WorkReceipt},
    manifest::Origin,
    score_wire as wire,
    validate::{ValidatedCandidate, integer_reference},
    worker::{CompletionAuthority, CompletionClaim, Progress},
    worker_wire::{JobBinding, JobIdentity, Role},
};
use crate::{
    domains::Action,
    features,
    model::{MODEL_BYTES, Model},
    policy::CandidateSet,
};
use sha2::{Digest, Sha256};

enum EncodePhase {
    Zero(usize),
    Models(usize),
    Input(usize),
    Hash(usize),
    Header,
    Done,
}
pub struct EncoderState<'a> {
    parent: &'a [u8; MODEL_BYTES],
    candidate: &'a [u8; MODEL_BYTES],
    set: &'a CandidateSet,
    header: wire::Header,
    phase: EncodePhase,
    hash: Sha256,
    steps: u64,
    failed: bool,
}
impl<'a> EncoderState<'a> {
    pub(super) fn new(
        candidate: &'a ValidatedCandidate<'_>,
        parent: &'a [u8; MODEL_BYTES],
        set: &'a CandidateSet,
        role: Role,
        binding: JobBinding,
        workspace_bytes: u32,
        now_ns: u64,
    ) -> Result<Self, Error> {
        let Origin::Learned(record) = candidate.model().manifest().origin else {
            return Err(Error::Untrained);
        };
        if <[u8; 32]>::from(Sha256::digest(parent)) != candidate.parent_hash() {
            return Err(Error::Evidence);
        }
        let first = set.get(0).ok_or(Error::Evidence)?;
        // Candidate entries are private and can only be constructed by the
        // policy constructor. Revalidate its exact canonical/scoped digest
        // without building two additional six-KiB candidate arrays on C1.
        set.verify_integrity().map_err(|_| Error::Evidence)?;
        let header = wire::Header {
            role,
            binding,
            parent_hash: candidate.parent_hash(),
            candidate_hash: candidate.model().manifest().parameters_hash,
            manifest_hash: candidate.model().hash(),
            registration_hash: candidate.registration_hash(),
            data_hash: record.data.hash,
            set_hash: set.hash(),
            payload_hash: [0; 32],
            model: set.model,
            snapshot: set.snapshot,
            target: set.target,
            count: set.len() as u16,
            family: Family {
                domain: first.action.domain(),
                kind: first.action.kind(),
            },
            workspace_bytes,
            prepared_ns: now_ns,
            permit: set.canary_permit(),
        };
        header.shape()?;
        Ok(Self {
            parent,
            candidate: candidate.model().bytes(),
            set,
            header,
            phase: EncodePhase::Zero(0),
            hash: Sha256::new(),
            steps: 0,
            failed: false,
        })
    }
    pub fn input_len(&self) -> usize {
        self.header.input_len()
    }
    pub(crate) fn header(&self) -> wire::Header {
        self.header
    }
    pub fn step(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if output.len() < self.input_len() {
            return Err(Error::Capacity);
        }
        if self.failed {
            return Err(Error::State);
        }
        if matches!(self.phase, EncodePhase::Done) {
            return Ok(Progress {
                completed: self.steps,
                done: true,
            });
        }
        let result = self.advance(output);
        if let Err(e) = result {
            self.failed = true;
            return Err(e);
        }
        self.steps = self.steps.checked_add(1).ok_or(Error::Numeric)?;
        Ok(Progress {
            completed: self.steps,
            done: matches!(self.phase, EncodePhase::Done),
        })
    }
    fn advance(&mut self, out: &mut [u8]) -> Result<(), Error> {
        match self.phase {
            EncodePhase::Zero(p) => {
                let end = (p + 1024).min(self.input_len());
                out[p..end].fill(0);
                self.phase = if end == self.input_len() {
                    EncodePhase::Models(0)
                } else {
                    EncodePhase::Zero(end)
                };
            }
            EncodePhase::Models(p) => {
                let end = (p + 1024).min(2 * MODEL_BYTES);
                for i in p..end {
                    out[wire::PARENT + i] = if i < MODEL_BYTES {
                        self.parent[i]
                    } else {
                        self.candidate[i - MODEL_BYTES]
                    };
                }
                self.phase = if end == 2 * MODEL_BYTES {
                    EncodePhase::Input(0)
                } else {
                    EncodePhase::Models(end)
                };
            }
            EncodePhase::Input(i) => {
                if i == self.set.len() {
                    self.phase = EncodePhase::Hash(wire::HEADER_BYTES)
                } else {
                    let c = self.set.get(i).ok_or(Error::Evidence)?;
                    if c.action.domain() != self.header.family.domain
                        || c.action.kind() != self.header.family.kind
                    {
                        return Err(Error::Evidence);
                    }
                    let input = features::encode(c.action, c.features)
                        .map_err(|_| Error::Evidence)?
                        .values;
                    for (j, v) in input.into_iter().enumerate() {
                        super::worker_wire::put16(out, wire::INPUTS + i * 128 + j * 2, v as u16);
                    }
                    self.phase = EncodePhase::Input(i + 1);
                }
            }
            EncodePhase::Hash(p) => {
                let end = (p + 1024).min(self.input_len());
                self.hash.update(&out[p..end]);
                self.phase = if end == self.input_len() {
                    self.header.payload_hash = self.hash.clone().finalize().into();
                    EncodePhase::Header
                } else {
                    EncodePhase::Hash(end)
                };
            }
            EncodePhase::Header => {
                self.header.encode(out)?;
                self.phase = EncodePhase::Done;
            }
            EncodePhase::Done => {}
        }
        Ok(())
    }
    pub fn finish(self, input: &[u8]) -> Result<PreparedScore, Error> {
        if self.failed || !matches!(self.phase, EncodePhase::Done) {
            return Err(Error::State);
        }
        let bytes = input
            .get(..self.header.input_len())
            .ok_or(Error::Capacity)?;
        if wire::Header::decode(bytes)? != self.header {
            return Err(Error::Evidence);
        }
        let identity = self.header.identity(bytes)?;
        let mut actions = [None; 32];
        for (i, c) in self.set.iter().enumerate() {
            actions[i] = Some(c.action);
        }
        Ok(PreparedScore {
            header: self.header,
            identity,
            actions,
            consumed: false,
        })
    }
}

/// Created only after a complete preparation from the real validated candidate
/// and registered candidate set. There is no wire-to-capability constructor.
pub struct PreparedScore {
    header: wire::Header,
    identity: JobIdentity,
    actions: [Option<Action>; 32],
    consumed: bool,
}
impl PreparedScore {
    pub fn identity(&self) -> JobIdentity {
        self.identity
    }
    pub fn header(&self) -> wire::Header {
        self.header
    }
    pub fn input_len(&self) -> usize {
        self.header.input_len()
    }
    pub fn consumed(&self) -> bool {
        self.consumed
    }
    pub(super) fn action(&self, index: u16) -> Result<Action, Error> {
        self.actions
            .get(usize::from(index))
            .copied()
            .flatten()
            .ok_or(Error::Evidence)
    }
    pub(super) fn authenticate(
        &mut self,
        output: &[u8],
        receipt: &WorkReceipt,
        authority: &impl CompletionAuthority,
        now_ns: u64,
    ) -> Result<wire::Report, Error> {
        if self.consumed {
            return Err(Error::State);
        }
        let report = wire::Report::decode(output)?;
        let cost = receipt.identity();
        let expected_role = match self.header.role {
            Role::ShadowScore => ExtraRole::Shadow,
            Role::CanaryScore => ExtraRole::Canary,
            _ => return Err(Error::State),
        };
        if report.identity != self.identity
            || report.registration_hash != self.header.registration_hash
            || report.set_hash != self.header.set_hash
            || report.count != self.header.count
            || report.steps != expected_steps(self.header)
            || cost.role != expected_role
            || cost.cpu != 1
            || cost.core_generation != self.header.binding.core_generation
            || cost.actual_ns == 0
            || now_ns < self.header.prepared_ns
            || now_ns < self.header.snapshot.taken_ns
            || now_ns - self.header.snapshot.taken_ns > 50_000_000
            || cost.window != now_ns / WINDOW_NS
        {
            return Err(Error::Evidence);
        }
        self.action(report.selected)?;
        authority.verify_score_completion(
            &CompletionClaim {
                identity: self.identity,
                output_hash: Sha256::digest(output).into(),
                output_bytes: output.len() as u32,
                completed_steps: report.steps,
            },
            receipt,
        )?;
        self.consumed = true;
        Ok(report)
    }
}
fn expected_steps(header: wire::Header) -> u64 {
    ((header.input_len() - wire::HEADER_BYTES).div_ceil(1024) + 1 + usize::from(header.count))
        as u64
}

pub struct Scored {
    proof: ScoreProof,
    report: wire::Report,
}
impl Scored {
    pub(super) fn new(proof: ScoreProof, report: wire::Report) -> Self {
        Self { proof, report }
    }
    pub fn proof(&self) -> &ScoreProof {
        &self.proof
    }
    pub fn scores(&self) -> &[i16] {
        &self.report.scores[..usize::from(self.report.count)]
    }
    pub fn prior_scores(&self) -> &[i16] {
        &self.report.prior[..usize::from(self.report.count)]
    }
    pub fn selected(&self) -> u16 {
        self.report.selected
    }
    pub fn into_proof(self) -> ScoreProof {
        self.proof
    }
}

enum Phase {
    Hash(usize),
    Models,
    Score(usize),
    Done,
}
pub struct Worker<'a> {
    input: &'a [u8],
    header: wire::Header,
    identity: JobIdentity,
    phase: Phase,
    payload: Sha256,
    transcript: Sha256,
    prior: [i16; 32],
    scores: [i16; 32],
    best: usize,
    steps: u64,
    failed: bool,
}
impl<'a> Worker<'a> {
    pub fn start(input: &'a [u8]) -> Result<Self, Error> {
        let header = wire::Header::decode(input)?;
        let identity = header.identity(input)?;
        let mut transcript = Sha256::new();
        transcript.update(b"CYXIA_COMPLETE_SCORE_TRANSCRIPT_1.3\0");
        transcript.update(identity.input_hash);
        transcript.update(header.registration_hash);
        transcript.update(header.set_hash);
        Ok(Self {
            input,
            header,
            identity,
            phase: Phase::Hash(wire::HEADER_BYTES),
            payload: Sha256::new(),
            transcript,
            prior: [0; 32],
            scores: [0; 32],
            best: 0,
            steps: 0,
            failed: false,
        })
    }
    pub fn step(&mut self) -> Result<Progress, Error> {
        if self.failed {
            return Err(Error::State);
        }
        if matches!(self.phase, Phase::Done) {
            return Ok(Progress {
                completed: self.steps,
                done: true,
            });
        }
        if let Err(e) = self.advance() {
            self.failed = true;
            return Err(e);
        }
        self.steps = self.steps.checked_add(1).ok_or(Error::Numeric)?;
        Ok(Progress {
            completed: self.steps,
            done: matches!(self.phase, Phase::Done),
        })
    }
    fn advance(&mut self) -> Result<(), Error> {
        match self.phase {
            Phase::Hash(p) => {
                let end = (p + 1024).min(self.input.len());
                self.payload.update(&self.input[p..end]);
                self.phase = if end == self.input.len() {
                    if <[u8; 32]>::from(self.payload.clone().finalize()) != self.header.payload_hash
                    {
                        return Err(Error::Evidence);
                    }
                    Phase::Models
                } else {
                    Phase::Hash(end)
                };
            }
            Phase::Models => {
                if <[u8; 32]>::from(Sha256::digest(&self.input[wire::PARENT..wire::CANDIDATE]))
                    != self.header.parent_hash
                    || <[u8; 32]>::from(Sha256::digest(&self.input[wire::CANDIDATE..wire::INPUTS]))
                        != self.header.candidate_hash
                {
                    return Err(Error::Manifest);
                }
                self.phase = Phase::Score(0);
            }
            Phase::Score(i) => {
                let parent: &[u8; MODEL_BYTES] = self.input[wire::PARENT..wire::CANDIDATE]
                    .try_into()
                    .map_err(|_| Error::Capacity)?;
                let candidate: &[u8; MODEL_BYTES] = self.input[wire::CANDIDATE..wire::INPUTS]
                    .try_into()
                    .map_err(|_| Error::Capacity)?;
                let mut input = [0i16; 64];
                for (j, v) in input.iter_mut().enumerate() {
                    *v = super::worker_wire::u16_at(self.input, wire::INPUTS + i * 128 + 2 * j)?
                        as i16;
                }
                let new = Model::parse(candidate)
                    .map_err(|_| Error::Model)?
                    .trace(&input);
                let old = Model::parse(parent)
                    .map_err(|_| Error::Model)?
                    .trace(&input);
                if new != integer_reference(candidate, &input)
                    || old != integer_reference(parent, &input)
                {
                    return Err(Error::Validation);
                }
                self.prior[i] = old.output;
                self.scores[i] = new.output;
                if i == 0 || new.output > self.scores[self.best] {
                    self.best = i;
                }
                for v in input {
                    self.transcript.update(v.to_le_bytes());
                }
                self.transcript.update(old.output.to_le_bytes());
                self.transcript.update(new.output.to_le_bytes());
                self.phase = if i + 1 == usize::from(self.header.count) {
                    Phase::Done
                } else {
                    Phase::Score(i + 1)
                };
            }
            Phase::Done => {}
        }
        Ok(())
    }
    pub fn finish(mut self, output: &mut [u8]) -> Result<usize, Error> {
        if self.failed
            || !matches!(self.phase, Phase::Done)
            || self.steps != expected_steps(self.header)
        {
            return Err(Error::State);
        }
        self.transcript.update((self.best as u16).to_le_bytes());
        wire::Report {
            identity: self.identity,
            registration_hash: self.header.registration_hash,
            set_hash: self.header.set_hash,
            transcript_hash: self.transcript.finalize().into(),
            steps: self.steps,
            count: self.header.count,
            selected: self.best as u16,
            prior: self.prior,
            scores: self.scores,
        }
        .encode(output)
    }
}
