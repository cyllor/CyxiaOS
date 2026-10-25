use super::Progress;
use crate::{
    learning::{
        Error, FAMILIES,
        data::{MIN_TRAINING_PER_FAMILY, MIN_VALIDATION_PER_FAMILY},
        softfloat::F64,
        train::{self, Parameters, TrainingRecord},
        validate::{self, Comparison, Mse},
        worker_wire::{self as wire, Counts, NumericRow, Packet, Report, Role},
    },
    model::{MODEL_BYTES, Model, Trace},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy)]
enum Phase {
    Hash(usize),
    Operators,
    Models,
    Rows(usize),
    Train(usize),
    Pack,
    References(usize),
    Selections(usize),
    Probes(usize, usize),
    Mse(usize),
    MseFinish,
    Done,
}

/// All state is private to one independently scheduled worker context. A step
/// handles at most one numerical sample/candidate, a small fixed operator suite,
/// or a 1024-byte hash chunk. Hardware may preempt in the middle of any step.
pub struct Worker<'a> {
    packet: Packet<'a>,
    phase: Phase,
    failed: bool,
    payload: Sha256,
    split: Sha256,
    reference: Sha256,
    probe: Sha256,
    transcript: Sha256,
    parameters: Option<Parameters>,
    candidate: [u8; MODEL_BYTES],
    record: Option<TrainingRecord>,
    counts: Counts,
    training_counts: [u16; FAMILIES],
    validation_counts: [u16; FAMILIES],
    represented: [bool; FAMILIES],
    probe_first: Option<Trace>,
    probe_differs: bool,
    comparison: Comparison,
}
pub(crate) const fn empty_mse() -> Mse {
    Mse {
        overall: F64::ZERO,
        by_family: [F64::ZERO; FAMILIES],
        counts: [0; FAMILIES],
    }
}
pub(crate) const fn empty_comparison() -> Comparison {
    Comparison {
        old: empty_mse(),
        new: empty_mse(),
    }
}
pub(crate) fn check_comparison(c: Comparison, counts: [u16; FAMILIES]) -> Result<(), Error> {
    if c.old.counts != counts
        || c.new.counts != counts
        || counts.iter().any(|n| *n < 4)
        || c.old.overall.negative()
        || c.new.overall.negative()
        || c.new.overall.compare(c.old.overall).is_gt()
    {
        return Err(Error::Validation);
    }
    let tolerance = F64::ONE.div(F64::from_u64(65536))?;
    for i in 0..FAMILIES {
        if c.old.by_family[i].negative()
            || c.new.by_family[i].negative()
            || c.new.by_family[i]
                .compare(c.old.by_family[i].add(tolerance)?)
                .is_gt()
        {
            return Err(Error::Validation);
        }
    }
    Ok(())
}
pub(crate) fn registration_hash(
    manifest_hash: [u8; 32],
    parent: [u8; 32],
    data: [u8; 32],
    c: Comparison,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"CYXIA_INDEPENDENT_MODEL_REGISTRATION_1.3\0");
    h.update(manifest_hash);
    h.update(parent);
    h.update(data);
    for v in [c.old.overall, c.new.overall]
        .into_iter()
        .chain(c.old.by_family)
        .chain(c.new.by_family)
    {
        h.update(v.to_bits().to_le_bytes());
    }
    h.finalize().into()
}
fn split_hash(count: u16) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"CYXIA_ORDERED_REPLAY_SAMPLES_1.3\0");
    h.update(u64::from(count).to_le_bytes());
    h
}
fn hash_row(hash: &mut Sha256, row: NumericRow) {
    hash.update(row.family.domain.to_le_bytes());
    hash.update(row.family.kind.to_le_bytes());
    hash.update(row.group.seed.to_le_bytes());
    hash.update(row.group.workload);
    hash.update(row.group.initial_image);
    for v in row.input {
        hash.update(v.to_le_bytes());
    }
    hash.update(row.reward.to_bits().to_le_bytes());
    hash.update(row.evidence);
}
fn hash_trace(hash: &mut Sha256, trace: Trace) {
    for v in trace
        .hidden1
        .into_iter()
        .chain(trace.hidden2)
        .chain([trace.output])
    {
        hash.update(v.to_le_bytes());
    }
}
fn checked_trace(bytes: &[u8; MODEL_BYTES], input: &[i16; 64]) -> Result<Trace, Error> {
    let reference = validate::integer_reference(bytes, input);
    if Model::parse(bytes).map_err(|_| Error::Model)?.trace(input) != reference {
        return Err(Error::Validation);
    }
    Ok(reference)
}
impl<'a> Worker<'a> {
    pub fn start(input: &'a [u8]) -> Result<Self, Error> {
        let packet = Packet::decode(input)?;
        let d = packet.header.data;
        if usize::from(d.training_count) < FAMILIES * MIN_TRAINING_PER_FAMILY
            || usize::from(d.validation_count) < FAMILIES * MIN_VALIDATION_PER_FAMILY
            || d.training_per_family
                .iter()
                .any(|n| *n < MIN_TRAINING_PER_FAMILY as u16)
            || d.validation_per_family
                .iter()
                .any(|n| *n < MIN_VALIDATION_PER_FAMILY as u16)
        {
            return Err(Error::DataIncomplete);
        }
        let mut reference = Sha256::new();
        reference.update(b"CYXIA_COMPLETE_INTEGER_REFERENCE_1.3\0");
        reference.update(packet.header.candidate_hash);
        reference.update(u64::from(packet.header.references).to_le_bytes());
        reference.update(u64::from(packet.header.selections).to_le_bytes());
        let mut probe = Sha256::new();
        probe.update(b"CYXIA_WORKER_DISTINGUISH_PROBES_1.3\0");
        probe.update(u64::from(packet.header.probes).to_le_bytes());
        let mut transcript = Sha256::new();
        transcript.update(b"CYXIA_NUMERICAL_WORKER_1.3\0");
        transcript.update(packet.identity().input_hash);
        transcript.update((packet.header.role as u16).to_le_bytes());
        Ok(Self {
            packet,
            phase: Phase::Hash(wire::HEADER_BYTES),
            failed: false,
            payload: Sha256::new(),
            split: split_hash(d.training_count),
            reference,
            probe,
            transcript,
            parameters: None,
            candidate: [0; MODEL_BYTES],
            record: None,
            counts: Counts::default(),
            training_counts: [0; FAMILIES],
            validation_counts: [0; FAMILIES],
            represented: [false; FAMILIES],
            probe_first: None,
            probe_differs: false,
            comparison: empty_comparison(),
        })
    }
    pub fn step(&mut self) -> Result<Progress, Error> {
        if self.failed {
            return Err(Error::State);
        }
        if matches!(self.phase, Phase::Done) {
            return Ok(Progress {
                completed: self.counts.steps,
                done: true,
            });
        }
        match self.advance() {
            Ok(()) => {
                self.counts.steps = self.counts.steps.checked_add(1).ok_or(Error::Numeric)?;
                Ok(Progress {
                    completed: self.counts.steps,
                    done: matches!(self.phase, Phase::Done),
                })
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }
    fn advance(&mut self) -> Result<(), Error> {
        match self.phase {
            Phase::Hash(offset) => {
                let end = (offset + 1024).min(self.packet.layout.total);
                self.payload.update(&self.packet.bytes()[offset..end]);
                self.phase = if end == self.packet.layout.total {
                    if <[u8; 32]>::from(self.payload.clone().finalize())
                        != self.packet.header.payload_hash
                    {
                        return Err(Error::Evidence);
                    }
                    Phase::Operators
                } else {
                    Phase::Hash(end)
                };
            }
            Phase::Operators => {
                train::operator_selftest()?;
                validate::operator_selftest()?;
                self.counts.golden_cases = wire::SELFTEST_CASES as u16;
                self.transcript.update(b"operators:14\0");
                self.phase = Phase::Models;
            }
            Phase::Models => {
                let h = self.packet.header;
                if <[u8; 32]>::from(Sha256::digest(self.packet.parent())) != h.parent_hash {
                    return Err(Error::Model);
                }
                self.parameters = Some(Parameters::from_model(self.packet.parent())?);
                if h.role == Role::Validation {
                    if <[u8; 32]>::from(Sha256::digest(self.packet.candidate())) != h.candidate_hash
                    {
                        return Err(Error::Model);
                    }
                    if h.candidate_hash == h.parent_hash {
                        return Err(Error::NoChange);
                    }
                    if !train::frozen_equal(self.packet.parent(), self.packet.candidate()) {
                        return Err(Error::FrozenLayers);
                    }
                    if h.record.ok_or(Error::Untrained)?.frozen_layers_hash
                        != train::frozen_hash(self.packet.parent())
                    {
                        return Err(Error::FrozenLayers);
                    }
                    Parameters::from_model(self.packet.candidate())?;
                } else if self.packet.candidate().iter().any(|b| *b != 0) {
                    return Err(Error::Evidence);
                }
                self.phase = Phase::Rows(0);
            }
            Phase::Rows(index) => {
                if index == self.packet.layout.row_count {
                    let d = self.packet.header.data;
                    let mut h = Sha256::new();
                    h.update(b"CYXIA_FROZEN_DATA_1.3\0");
                    h.update(d.seed.to_le_bytes());
                    h.update(d.training_hash);
                    h.update(d.validation_hash);
                    for s in [
                        d.feature_schema,
                        d.action_schema,
                        d.reward_schema,
                        d.learning_config,
                    ] {
                        h.update(s.version.to_le_bytes());
                        h.update(s.hash);
                    }
                    if <[u8; 32]>::from(h.finalize()) != d.hash {
                        return Err(Error::Evidence);
                    }
                    self.phase = Phase::Train(0);
                } else {
                    self.inspect_row(index)?;
                    self.phase = Phase::Rows(index + 1);
                }
            }
            Phase::Train(index) => {
                if index == self.packet.header.data.training_count as usize {
                    self.phase = Phase::Pack;
                } else {
                    let row = self.packet.row(index)?;
                    let trace = checked_trace(self.packet.parent(), &row.input)?;
                    let step = self
                        .parameters
                        .ok_or(Error::State)?
                        .step(&trace.hidden2, row.reward)?;
                    self.transcript.update(b"sgd\0");
                    self.transcript.update((index as u64).to_le_bytes());
                    hash_trace(&mut self.transcript, trace);
                    self.transcript
                        .update(step.prediction.to_bits().to_le_bytes());
                    self.transcript.update(step.error.to_bits().to_le_bytes());
                    for v in step
                        .next
                        .weights()
                        .iter()
                        .copied()
                        .chain([step.next.bias()])
                    {
                        self.transcript.update(v.to_bits().to_le_bytes());
                    }
                    self.parameters = Some(step.next);
                    self.counts.training += 1;
                    self.phase = Phase::Train(index + 1);
                }
            }
            Phase::Pack => {
                let parameters = self.parameters.ok_or(Error::State)?;
                let (weights, bias) = parameters.quantized()?;
                self.candidate.copy_from_slice(self.packet.parent());
                for (i, w) in weights.into_iter().enumerate() {
                    self.candidate[train::LAST_WEIGHTS + i] = w as u8;
                }
                self.candidate[train::LAST_BIAS..].copy_from_slice(&bias.to_le_bytes());
                if !train::frozen_equal(self.packet.parent(), &self.candidate) {
                    return Err(Error::FrozenLayers);
                }
                let mut h = Sha256::new();
                h.update(b"CYXIA_SOFT_BINARY64_FINAL_PARAMETERS_1.3\0");
                for v in parameters
                    .weights()
                    .iter()
                    .copied()
                    .chain([parameters.bias()])
                {
                    h.update(v.to_bits().to_le_bytes());
                }
                let record = TrainingRecord {
                    parent_hash: self.packet.header.parent_hash,
                    frozen_layers_hash: train::frozen_hash(self.packet.parent()),
                    data: self.packet.header.data,
                    steps: self.counts.training,
                    shadow_parameters_hash: h.finalize().into(),
                    result_hash: Sha256::digest(self.candidate).into(),
                };
                self.record = Some(record);
                if self.packet.header.role == Role::Validation {
                    if self.packet.header.record != Some(record)
                        || self.packet.candidate() != &self.candidate
                    {
                        return Err(Error::Evidence);
                    }
                    self.phase = Phase::References(0);
                } else {
                    self.phase = Phase::Done;
                }
            }
            Phase::References(index) => {
                if index == self.packet.header.references as usize {
                    self.phase = Phase::Selections(0);
                } else {
                    let case = self.packet.reference(index)?;
                    let trace = checked_trace(&self.candidate, &case.input)?;
                    if trace != case.trace {
                        return Err(Error::Validation);
                    }
                    for v in case.input {
                        self.reference.update(v.to_le_bytes());
                    }
                    hash_trace(&mut self.reference, trace);
                    hash_trace(&mut self.transcript, trace);
                    self.counts.references += 1;
                    self.phase = Phase::References(index + 1);
                }
            }
            Phase::Selections(index) => {
                if index == self.packet.header.selections as usize {
                    if <[u8; 32]>::from(self.reference.clone().finalize())
                        != self.packet.header.reference_hash
                    {
                        return Err(Error::Manifest);
                    }
                    self.phase = Phase::Probes(0, 0);
                } else {
                    let s = self.packet.selection(index)?;
                    let mut best = 0;
                    let mut score = self.packet.reference(s.first as usize)?.trace.output;
                    for i in 1..s.count {
                        let next = self
                            .packet
                            .reference(usize::from(s.first) + usize::from(i))?
                            .trace
                            .output;
                        if next > score {
                            best = i;
                            score = next;
                        }
                    }
                    if best != s.selected {
                        return Err(Error::Validation);
                    }
                    for v in [s.first, s.count, s.selected] {
                        self.reference.update(v.to_le_bytes());
                    }
                    self.transcript.update(best.to_le_bytes());
                    self.counts.selections += 1;
                    self.phase = Phase::Selections(index + 1);
                }
            }
            Phase::Probes(index, candidate) => {
                if index == self.packet.header.probes as usize {
                    if !self.represented.iter().all(|v| *v) {
                        return Err(Error::Untrained);
                    }
                    if <[u8; 32]>::from(self.probe.clone().finalize())
                        != self.packet.header.probes_hash
                    {
                        return Err(Error::Evidence);
                    }
                    self.phase = Phase::Mse(0);
                } else {
                    let (family, count) = self.packet.probe(index)?;
                    if candidate == 0 {
                        self.probe.update(family.domain.to_le_bytes());
                        self.probe.update(family.kind.to_le_bytes());
                        self.probe.update((count as u16).to_le_bytes());
                        self.probe_first = None;
                        self.probe_differs = false;
                    }
                    let input = self.packet.probe_input(index, candidate)?;
                    for v in input {
                        self.probe.update(v.to_le_bytes());
                    }
                    let trace = checked_trace(&self.candidate, &input)?;
                    if let Some(first) = self.probe_first {
                        self.probe_differs |=
                            trace.hidden2 != first.hidden2 && trace.output != first.output;
                    } else {
                        self.probe_first = Some(trace);
                    }
                    hash_trace(&mut self.transcript, trace);
                    self.counts.probe_candidates += 1;
                    self.phase = if candidate + 1 == count {
                        self.represented[family.index()?] |= self.probe_differs;
                        self.counts.probes += 1;
                        Phase::Probes(index + 1, 0)
                    } else {
                        Phase::Probes(index, candidate + 1)
                    };
                }
            }
            Phase::Mse(index) => {
                if index == self.packet.header.data.validation_count as usize {
                    self.phase = Phase::MseFinish;
                } else {
                    let row = self
                        .packet
                        .row(self.packet.header.data.training_count as usize + index)?;
                    let old = Self::square(self.packet.parent(), row)?;
                    let new = Self::square(&self.candidate, row)?;
                    let family = row.family.index()?;
                    for (sum, square) in [
                        (&mut self.comparison.old, old),
                        (&mut self.comparison.new, new),
                    ] {
                        sum.overall = sum.overall.add(square)?;
                        sum.by_family[family] = sum.by_family[family].add(square)?;
                        sum.counts[family] += 1;
                    }
                    self.transcript.update(old.to_bits().to_le_bytes());
                    self.transcript.update(new.to_bits().to_le_bytes());
                    self.counts.validation += 1;
                    self.phase = Phase::Mse(index + 1);
                }
            }
            Phase::MseFinish => {
                for mse in [&mut self.comparison.old, &mut self.comparison.new] {
                    mse.overall = mse.overall.div(F64::from_u64(u64::from(
                        self.packet.header.data.validation_count,
                    )))?;
                    for i in 0..FAMILIES {
                        if mse.counts[i] < 4 {
                            return Err(Error::DataIncomplete);
                        }
                        mse.by_family[i] =
                            mse.by_family[i].div(F64::from_u64(u64::from(mse.counts[i])))?;
                    }
                }
                check_comparison(
                    self.comparison,
                    self.packet.header.data.validation_per_family,
                )?;
                self.phase = Phase::Done;
            }
            Phase::Done => {}
        }
        Ok(())
    }
    fn inspect_row(&mut self, index: usize) -> Result<(), Error> {
        let row = self.packet.row(index)?;
        let d = self.packet.header.data;
        if row.evidence == [0; 32] {
            return Err(Error::Evidence);
        }
        for i in 0..index {
            let p = self.packet.layout.provenance + i * wire::PROVENANCE_BYTES;
            if wire::array_at::<32>(self.packet.bytes(), p + 72)? == row.evidence {
                return Err(Error::Evidence);
            }
            if index >= d.training_count as usize
                && i < d.training_count as usize
                && wire::u64_at(self.packet.bytes(), p)? == row.group.seed
                && wire::array_at::<32>(self.packet.bytes(), p + 8)? == row.group.workload
                && wire::array_at::<32>(self.packet.bytes(), p + 40)? == row.group.initial_image
            {
                return Err(Error::GroupOverlap);
            }
        }
        let family = row.family.index()?;
        if index < d.training_count as usize {
            self.training_counts[family] += 1;
        } else {
            self.validation_counts[family] += 1;
        }
        hash_row(&mut self.split, row);
        self.transcript.update(row.evidence);
        self.counts.rows += 1;
        if index + 1 == d.training_count as usize {
            if self.training_counts != d.training_per_family
                || <[u8; 32]>::from(self.split.clone().finalize()) != d.training_hash
            {
                return Err(Error::Evidence);
            }
            self.split = split_hash(d.validation_count);
        }
        if index + 1 == self.packet.layout.row_count
            && (self.validation_counts != d.validation_per_family
                || <[u8; 32]>::from(self.split.clone().finalize()) != d.validation_hash)
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }
    fn square(bytes: &[u8; MODEL_BYTES], row: NumericRow) -> Result<F64, Error> {
        let output = checked_trace(bytes, &row.input)?.output;
        let prediction = F64::from_i64(i64::from(output)).div(F64::from_u64(256))?;
        let error = prediction.sub(row.reward)?;
        Ok(error.mul(error)?)
    }
    pub fn finish(self, output: &mut [u8]) -> Result<usize, Error> {
        if self.failed || !matches!(self.phase, Phase::Done) {
            return Err(Error::State);
        }
        let record = self.record.ok_or(Error::State)?;
        let manifest_hash = self.packet.header.model_manifest_hash;
        let registration_hash = if self.packet.header.role == Role::Validation {
            registration_hash(
                manifest_hash,
                self.packet.header.parent_hash,
                self.packet.header.data.hash,
                self.comparison,
            )
        } else {
            [0; 32]
        };
        Report {
            identity: self.packet.identity(),
            candidate_hash: record.result_hash,
            manifest_hash,
            registration_hash,
            transcript_hash: self.transcript.finalize().into(),
            counts: self.counts,
            record,
            comparison: self.comparison,
            candidate: self.candidate,
        }
        .encode(output)
    }
}
const _: () = assert!(core::mem::size_of::<Worker<'_>>() < 16 * 1024);
