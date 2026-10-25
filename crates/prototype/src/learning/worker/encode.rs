use super::{PreparedJob, Progress};
use crate::{
    features,
    learning::{
        Error, Family,
        data::FrozenData,
        manifest::{self, ModelManifest, Origin},
        reward::AcceptedSample,
        train,
        validate::ReferenceSuite,
        worker_wire::{self as wire, Header, JobBinding, Layout, Role},
    },
    model::MODEL_BYTES,
    policy::CandidateSet,
};
use sha2::{Digest, Sha256};

enum Phase {
    Zero(usize),
    Models(usize),
    Rows(usize),
    References(usize),
    Selections(usize),
    Probes(usize, usize),
    Hash(usize),
    Header,
    Done,
}

/// Each call writes at most 1024 bytes, one accepted row, one reference case,
/// or one normalized candidate. The pool owner charges every preparation turn.
/// The output loan lasts only for each call. The protected pool owner must
/// supply the same exclusive allocation for every step, then seal it before
/// executing the worker. The worker independently authenticates its contents;
/// no untrusted bytes can create this state or an accepted data manifest.
pub struct EncoderState<'a, 'samples> {
    parent: &'a [u8; MODEL_BYTES],
    candidate: Option<&'a [u8; MODEL_BYTES]>,
    data: &'a FrozenData<'samples>,
    vectors: Option<&'a ReferenceSuite<'a>>,
    probes: &'a [CandidateSet],
    header: Header,
    layout: Layout,
    phase: Phase,
    completed: u64,
    failed: bool,
    payload: Sha256,
    reference: Sha256,
    probe_hash: Sha256,
    probe_candidates: u16,
}
impl<'a, 'samples> EncoderState<'a, 'samples> {
    pub fn training(
        binding: JobBinding,
        parent: &'a [u8; MODEL_BYTES],
        data: &'a FrozenData<'samples>,
        workspace_bytes: u32,
    ) -> Result<Self, Error> {
        let header = Header {
            role: Role::Training,
            binding,
            parent_hash: Sha256::digest(parent).into(),
            candidate_hash: [0; 32],
            payload_hash: [0; 32],
            reference_hash: [0; 32],
            probes_hash: [0; 32],
            model_manifest_hash: [0; 32],
            workspace_bytes,
            references: 0,
            selections: 0,
            probes: 0,
            data: data.manifest(),
            record: None,
            model_workspace_bytes: 0,
        };
        Self::new(parent, None, data, None, &[], header)
    }
    pub fn validation(
        binding: JobBinding,
        parent: &'a [u8; MODEL_BYTES],
        candidate: &'a [u8; MODEL_BYTES],
        model_manifest: &ModelManifest,
        data: &'a FrozenData<'samples>,
        vectors: &'a ReferenceSuite<'a>,
        probes: &'a [CandidateSet],
        workspace_bytes: u32,
    ) -> Result<Self, Error> {
        let Origin::Learned(record) = model_manifest.origin else {
            return Err(Error::Untrained);
        };
        if model_manifest.runtime_abi != manifest::RUNTIME_ABI
            || model_manifest.shape != manifest::SHAPE
            || model_manifest.normalization != manifest::normalization()
            || model_manifest.schemas.feature != data.manifest().feature_schema
            || model_manifest.schemas.action != data.manifest().action_schema
            || model_manifest.schemas.reward != data.manifest().reward_schema
            || model_manifest.schemas.learning != data.manifest().learning_config
            || model_manifest.parameters_hash != <[u8; 32]>::from(Sha256::digest(candidate))
            || model_manifest.frozen_layers_hash != train::frozen_hash(candidate)
            || record.data != data.manifest()
            || vectors.parameters_hash != model_manifest.parameters_hash
        {
            return Err(Error::Manifest);
        }
        if vectors.cases.len() > 128 || vectors.selections.len() > 32 || probes.len() > 72 {
            return Err(Error::Capacity);
        }
        let header = Header {
            role: Role::Validation,
            binding,
            parent_hash: Sha256::digest(parent).into(),
            candidate_hash: model_manifest.parameters_hash,
            payload_hash: [0; 32],
            reference_hash: model_manifest.reference_vectors_hash,
            // Filled incrementally. A nonzero placeholder is never published.
            probes_hash: [1; 32],
            model_manifest_hash: model_manifest.hash(),
            workspace_bytes,
            references: vectors.cases.len() as u16,
            selections: vectors.selections.len() as u16,
            probes: probes.len() as u16,
            data: data.manifest(),
            record: Some(record),
            model_workspace_bytes: model_manifest.workspace_bytes,
        };
        Self::new(parent, Some(candidate), data, Some(vectors), probes, header)
    }
    fn new(
        parent: &'a [u8; MODEL_BYTES],
        candidate: Option<&'a [u8; MODEL_BYTES]>,
        data: &'a FrozenData<'samples>,
        vectors: Option<&'a ReferenceSuite<'a>>,
        probes: &'a [CandidateSet],
        header: Header,
    ) -> Result<Self, Error> {
        header.shape()?;
        let layout = header.layout()?;
        let mut reference = Sha256::new();
        reference.update(b"CYXIA_COMPLETE_INTEGER_REFERENCE_1.3\0");
        reference.update(header.candidate_hash);
        reference.update(u64::from(header.references).to_le_bytes());
        reference.update(u64::from(header.selections).to_le_bytes());
        let mut probe_hash = Sha256::new();
        probe_hash.update(b"CYXIA_WORKER_DISTINGUISH_PROBES_1.3\0");
        probe_hash.update(u64::from(header.probes).to_le_bytes());
        Ok(Self {
            parent,
            candidate,
            data,
            vectors,
            probes,
            header,
            layout,
            phase: Phase::Zero(0),
            completed: 0,
            failed: false,
            payload: Sha256::new(),
            reference,
            probe_hash,
            probe_candidates: 0,
        })
    }
    pub fn input_len(&self) -> usize {
        self.layout.total
    }
    pub fn step(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if output.len() < self.layout.total {
            return Err(Error::Capacity);
        }
        if self.failed {
            return Err(Error::State);
        }
        if matches!(self.phase, Phase::Done) {
            return Ok(Progress {
                completed: self.completed,
                done: true,
            });
        }
        match self.advance(output) {
            Ok(()) => {
                self.completed = self.completed.checked_add(1).ok_or(Error::Numeric)?;
                Ok(Progress {
                    completed: self.completed,
                    done: matches!(self.phase, Phase::Done),
                })
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    fn advance(&mut self, output: &mut [u8]) -> Result<(), Error> {
        match self.phase {
            Phase::Zero(offset) => {
                let end = (offset + 1024).min(self.layout.total);
                output[offset..end].fill(0);
                self.phase = if end == self.layout.total {
                    Phase::Models(0)
                } else {
                    Phase::Zero(end)
                };
            }
            Phase::Models(offset) => {
                let end = (offset + 1024).min(2 * MODEL_BYTES);
                for i in offset..end {
                    output[self.layout.parent + i] = if i < MODEL_BYTES {
                        self.parent[i]
                    } else {
                        self.candidate.map_or(0, |c| c[i - MODEL_BYTES])
                    };
                }
                self.phase = if end == 2 * MODEL_BYTES {
                    Phase::Rows(0)
                } else {
                    Phase::Models(end)
                };
            }
            Phase::Rows(index) => {
                if index == self.layout.row_count {
                    self.phase = Phase::References(0);
                } else {
                    let sample = if index < self.data.training().len() {
                        &self.data.training()[index]
                    } else {
                        &self.data.validation()[index - self.data.training().len()]
                    };
                    self.encode_sample(output, index, sample);
                    self.phase = Phase::Rows(index + 1);
                }
            }
            Phase::References(index) => {
                if index == self.header.references as usize {
                    self.phase = Phase::Selections(0);
                } else {
                    let case = &self.vectors.ok_or(Error::State)?.cases[index];
                    let p = self.layout.references + index * wire::REFERENCE_BYTES;
                    for (i, value) in case
                        .input
                        .into_iter()
                        .chain(case.trace.hidden1)
                        .chain(case.trace.hidden2)
                        .chain([case.trace.output])
                        .enumerate()
                    {
                        wire::put16(output, p + i * 2, value as u16);
                        self.reference.update(value.to_le_bytes());
                    }
                    self.phase = Phase::References(index + 1);
                }
            }
            Phase::Selections(index) => {
                if index == self.header.selections as usize {
                    if self.header.role == Role::Validation
                        && <[u8; 32]>::from(self.reference.clone().finalize())
                            != self.header.reference_hash
                    {
                        return Err(Error::Manifest);
                    }
                    self.phase = Phase::Probes(0, 0);
                } else {
                    let s = self.vectors.ok_or(Error::State)?.selections[index];
                    if s.count == 0
                        || s.count > 32
                        || s.selected >= s.count
                        || usize::from(s.first) + usize::from(s.count)
                            > self.header.references as usize
                    {
                        return Err(Error::Evidence);
                    }
                    let p = self.layout.selections + index * wire::SELECTION_BYTES;
                    for (i, v) in [s.first, s.count, s.selected].into_iter().enumerate() {
                        wire::put16(output, p + i * 2, v);
                        self.reference.update(v.to_le_bytes());
                    }
                    self.phase = Phase::Selections(index + 1);
                }
            }
            Phase::Probes(index, candidate) => {
                if index == self.probes.len() {
                    if self.header.role == Role::Validation {
                        self.header.probes_hash = self.probe_hash.clone().finalize().into();
                    }
                    self.phase = Phase::Hash(wire::HEADER_BYTES);
                } else {
                    let set = &self.probes[index];
                    if !(2..=32).contains(&set.len()) {
                        return Err(Error::Evidence);
                    }
                    let first = set.get(0).ok_or(Error::Evidence)?;
                    let family = Family {
                        domain: first.action.domain(),
                        kind: first.action.kind(),
                    };
                    family.index()?;
                    let p = self.layout.probes + index * wire::PROBE_BYTES;
                    if candidate == 0 {
                        wire::put16(output, p, family.domain);
                        wire::put16(output, p + 2, family.kind);
                        wire::put16(output, p + 4, set.len() as u16);
                        self.probe_hash.update(family.domain.to_le_bytes());
                        self.probe_hash.update(family.kind.to_le_bytes());
                        self.probe_hash.update((set.len() as u16).to_le_bytes());
                    }
                    let entry = set.get(candidate).ok_or(Error::Evidence)?;
                    if entry.action.domain() != family.domain || entry.action.kind() != family.kind
                    {
                        return Err(Error::Evidence);
                    }
                    let input = features::encode(entry.action, entry.features)
                        .map_err(|_| Error::Evidence)?
                        .values;
                    for (i, v) in input.into_iter().enumerate() {
                        wire::put16(output, p + 16 + candidate * 128 + i * 2, v as u16);
                        self.probe_hash.update(v.to_le_bytes());
                    }
                    self.probe_candidates += 1;
                    self.phase = if candidate + 1 == set.len() {
                        Phase::Probes(index + 1, 0)
                    } else {
                        Phase::Probes(index, candidate + 1)
                    };
                }
            }
            Phase::Hash(offset) => {
                let end = (offset + 1024).min(self.layout.total);
                self.payload.update(&output[offset..end]);
                self.phase = if end == self.layout.total {
                    self.header.payload_hash = self.payload.clone().finalize().into();
                    Phase::Header
                } else {
                    Phase::Hash(end)
                };
            }
            Phase::Header => {
                self.header.shape()?;
                self.header.encode(output)?;
                self.phase = Phase::Done;
            }
            Phase::Done => {}
        }
        Ok(())
    }
    fn encode_sample(&mut self, output: &mut [u8], index: usize, sample: &AcceptedSample) {
        let p = self.layout.rows + index * wire::ROW_BYTES;
        let q = self.layout.provenance + index * wire::PROVENANCE_BYTES;
        let family = sample.family();
        let group = sample.group();
        wire::put16(output, p, family.domain);
        wire::put16(output, p + 2, family.kind);
        for (i, value) in sample.input().iter().enumerate() {
            wire::put16(output, p + 8 + i * 2, *value as u16);
        }
        wire::put64(output, p + 136, sample.reward().value.to_bits());
        wire::put64(output, q, group.seed);
        output[q + 8..q + 40].copy_from_slice(&group.workload);
        output[q + 40..q + 72].copy_from_slice(&group.initial_image);
        output[q + 72..q + 104].copy_from_slice(&sample.evidence_hash());
    }
    pub fn finish(self, output: &[u8]) -> Result<PreparedJob, Error> {
        if self.failed || !matches!(self.phase, Phase::Done) {
            return Err(Error::State);
        }
        if output.len() < self.layout.total {
            return Err(Error::Capacity);
        }
        if Header::decode(&output[..self.layout.total])? != self.header {
            return Err(Error::Evidence);
        }
        let identity = wire::identity(
            self.header,
            Sha256::digest(&output[..wire::HEADER_BYTES]).into(),
        );
        Ok(PreparedJob::new(
            self.header,
            identity,
            train::frozen_hash(self.parent),
            self.probe_candidates,
        ))
    }
}

/// Convenience adapter for callers which can retain one output borrow. Native
/// pool preparation uses EncoderState so no mutable loan survives a turn.
pub struct Encoder<'a, 'samples> {
    state: EncoderState<'a, 'samples>,
    output: &'a mut [u8],
}
impl<'a, 'samples> Encoder<'a, 'samples> {
    pub fn training(
        binding: JobBinding,
        parent: &'a [u8; MODEL_BYTES],
        data: &'a FrozenData<'samples>,
        workspace_bytes: u32,
        output: &'a mut [u8],
    ) -> Result<Self, Error> {
        let state = EncoderState::training(binding, parent, data, workspace_bytes)?;
        Self::new(state, output)
    }
    pub fn validation(
        binding: JobBinding,
        parent: &'a [u8; MODEL_BYTES],
        candidate: &'a [u8; MODEL_BYTES],
        model_manifest: &ModelManifest,
        data: &'a FrozenData<'samples>,
        vectors: &'a ReferenceSuite<'a>,
        probes: &'a [CandidateSet],
        workspace_bytes: u32,
        output: &'a mut [u8],
    ) -> Result<Self, Error> {
        let state = EncoderState::validation(
            binding,
            parent,
            candidate,
            model_manifest,
            data,
            vectors,
            probes,
            workspace_bytes,
        )?;
        Self::new(state, output)
    }
    fn new(state: EncoderState<'a, 'samples>, output: &'a mut [u8]) -> Result<Self, Error> {
        if output.len() < state.input_len() {
            return Err(Error::Capacity);
        }
        Ok(Self { state, output })
    }
    pub fn input_len(&self) -> usize {
        self.state.input_len()
    }
    pub fn step(&mut self) -> Result<Progress, Error> {
        self.state.step(self.output)
    }
    pub fn finish(self) -> Result<PreparedJob, Error> {
        self.state.finish(self.output)
    }
}
