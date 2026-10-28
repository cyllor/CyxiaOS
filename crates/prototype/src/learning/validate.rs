//! Independent integer reference and complete-MLP held-out acceptance.
use super::{
    Error, FAMILIES, Family,
    data::FrozenData,
    manifest::{Origin, SealedModel},
    softfloat::F64,
    train,
};
use crate::{
    features,
    model::{MODEL_BYTES, Model, Trace},
    policy::CandidateSet,
};
use sha2::{Digest, Sha256};

pub const MAX_REFERENCE_CASES: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceCase {
    pub input: [i16; 64],
    pub trace: Trace,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReferenceSelection {
    pub first: u16,
    pub count: u16,
    pub selected: u16,
}
pub struct ReferenceSuite<'a> {
    pub parameters_hash: [u8; 32],
    pub cases: &'a [ReferenceCase],
    pub selections: &'a [ReferenceSelection],
}

/// This implementation intentionally does not call Model::trace/neuron and
/// uses a distinct arithmetic formulation and wider accumulators.
pub fn integer_reference(bytes: &[u8; MODEL_BYTES], input: &[i16; 64]) -> Trace {
    fn layer<const N: usize, const M: usize>(
        bytes: &[u8; MODEL_BYTES],
        input: &[i16; N],
        weight: usize,
        bias: usize,
        relu: bool,
    ) -> [i16; M] {
        let mut output = [0; M];
        for row in 0..M {
            let offset = 2576 + (bias + row) * 4;
            let b = i32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let mut accumulator = i128::from(b) * 64;
            for col in 0..N {
                accumulator +=
                    i128::from(bytes[weight + row * N + col] as i8) * i128::from(input[col]);
            }
            let quotient = accumulator / 64;
            let remainder = accumulator % 64;
            let rounded = quotient
                + if remainder >= 32 {
                    1
                } else if remainder <= -32 {
                    -1
                } else {
                    0
                };
            let saturated = rounded.clamp(i128::from(i16::MIN), i128::from(i16::MAX)) as i16;
            output[row] = if relu { saturated.max(0) } else { saturated };
        }
        output
    }
    let hidden1 = layer::<64, 32>(bytes, input, 0, 0, true);
    let hidden2 = layer::<32, 16>(bytes, &hidden1, 2048, 32, true);
    let output = layer::<16, 1>(bytes, &hidden2, 2560, 48, false)[0];
    Trace {
        hidden1,
        hidden2,
        output,
    }
}

impl ReferenceSuite<'_> {
    pub fn hash(&self) -> Result<[u8; 32], Error> {
        if self.cases.is_empty()
            || self.cases.len() > MAX_REFERENCE_CASES
            || self.selections.is_empty()
            || self.selections.len() > 32
        {
            return Err(Error::Capacity);
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_COMPLETE_INTEGER_REFERENCE_1.3\0");
        hash.update(self.parameters_hash);
        hash.update((self.cases.len() as u64).to_le_bytes());
        hash.update((self.selections.len() as u64).to_le_bytes());
        for case in self.cases {
            for value in case
                .input
                .into_iter()
                .chain(case.trace.hidden1)
                .chain(case.trace.hidden2)
                .chain([case.trace.output])
            {
                hash.update(value.to_le_bytes());
            }
        }
        for selection in self.selections {
            if selection.count == 0
                || selection.count > 32
                || selection.selected >= selection.count
                || usize::from(selection.first) + usize::from(selection.count) > self.cases.len()
            {
                return Err(Error::Evidence);
            }
            hash.update(selection.first.to_le_bytes());
            hash.update(selection.count.to_le_bytes());
            hash.update(selection.selected.to_le_bytes());
        }
        Ok(hash.finalize().into())
    }
}

pub fn verify_reference(
    bytes: &[u8; MODEL_BYTES],
    vectors: &ReferenceSuite<'_>,
) -> Result<(), Error> {
    vectors.hash()?;
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    if hash != vectors.parameters_hash {
        return Err(Error::Manifest);
    }
    let runtime = Model::parse(bytes).map_err(|_| Error::Model)?;
    for case in vectors.cases {
        let reference = integer_reference(bytes, &case.input);
        if reference != case.trace || runtime.trace(&case.input) != reference {
            return Err(Error::Validation);
        }
    }
    for selection in vectors.selections {
        let first = usize::from(selection.first);
        let cases = &vectors.cases[first..first + usize::from(selection.count)];
        let mut expected = 0;
        for i in 1..cases.len() {
            if cases[i].trace.output > cases[expected].trace.output {
                expected = i;
            }
        }
        let mut inputs = [[0i16; 64]; 32];
        for (i, case) in cases.iter().enumerate() {
            inputs[i] = case.input;
        }
        if expected != usize::from(selection.selected)
            || runtime
                .select(&inputs[..cases.len()])
                .map_err(|_| Error::Model)?
                != expected
        {
            return Err(Error::Validation);
        }
    }
    operator_selftest()
}

/// The four fixed full-MLP operator cases are individually addressable so a
/// native EL0 verifier never has to combine them under one physical credit.
pub const OPERATOR_SELFTEST_CASES: usize = 4;

pub fn operator_selftest_case(index: usize) -> Result<(), Error> {
    let mut bytes = [0u8; MODEL_BYTES];
    bytes[0] = 32;
    bytes[64] = (-32i8) as u8;
    bytes[2576 + 8..2576 + 12].copy_from_slice(&i32::MAX.to_le_bytes());
    bytes[2576 + 12..2576 + 16].copy_from_slice(&i32::MIN.to_le_bytes());
    bytes[2048] = 64;
    bytes[2560] = 64;
    let mut input = [0i16; 64];
    input[0] = 1;
    match index {
        0 => {
            let plus = Model::parse(&bytes)
                .map_err(|_| Error::Model)?
                .trace(&input);
            if plus.hidden1[..4] == [1, 0, 32767, 0]
                && plus.hidden2[0] == 1
                && plus.output == 1
                && plus == integer_reference(&bytes, &input)
            {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        1 => {
            bytes[2560] = (-32i8) as u8;
            if Model::parse(&bytes)
                .map_err(|_| Error::Model)?
                .score(&input)
                == -1
            {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        2 | 3 => {
            let expected: i16 = if index == 2 { -32768 } else { 32767 };
            bytes[2768..]
                .copy_from_slice(&(if index == 2 { i32::MIN } else { i32::MAX }).to_le_bytes());
            if integer_reference(&bytes, &input).output == expected
                && Model::parse(&bytes)
                    .map_err(|_| Error::Model)?
                    .score(&input)
                    == expected
            {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        _ => Err(Error::Order),
    }
}

/// Fixed operator goldens are independent of a package's output goldens.
pub fn operator_selftest() -> Result<(), Error> {
    for index in 0..OPERATOR_SELFTEST_CASES {
        operator_selftest_case(index)?;
    }
    Ok(())
}

/// Candidate-aware probes reject an all-tie seed and hidden layers that erase
/// candidate differences. This is a model sanity gate, not A05 behavior proof.
pub fn distinguish_candidates(
    bytes: &[u8; MODEL_BYTES],
    probes: &[CandidateSet],
) -> Result<(), Error> {
    if probes.len() > 72 {
        return Err(Error::Capacity);
    }
    let mut represented = [false; FAMILIES];
    let model = Model::parse(bytes).map_err(|_| Error::Model)?;
    for set in probes {
        if set.len() < 2 {
            continue;
        }
        let first = set.get(0).ok_or(Error::Evidence)?;
        let family = Family {
            domain: first.action.domain(),
            kind: first.action.kind(),
        };
        let initial = model.trace(
            &features::encode(first.action, first.features)
                .map_err(|_| Error::Evidence)?
                .values,
        );
        let mut differs = false;
        for candidate in set.iter().skip(1) {
            let next = model.trace(
                &features::encode(candidate.action, candidate.features)
                    .map_err(|_| Error::Evidence)?
                    .values,
            );
            differs |= next.hidden2 != initial.hidden2 && next.output != initial.output;
        }
        represented[family.index()?] |= differs;
    }
    if represented.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(Error::Untrained)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mse {
    pub overall: F64,
    pub by_family: [F64; FAMILIES],
    pub counts: [u16; FAMILIES],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Comparison {
    pub old: Mse,
    pub new: Mse,
}
pub fn mse(bytes: &[u8; MODEL_BYTES], data: &FrozenData<'_>) -> Result<Mse, Error> {
    let runtime = Model::parse(bytes).map_err(|_| Error::Model)?;
    let mut result = Mse {
        overall: F64::ZERO,
        by_family: [F64::ZERO; FAMILIES],
        counts: [0; FAMILIES],
    };
    for sample in data.validation() {
        let reference = integer_reference(bytes, sample.input());
        if runtime.trace(sample.input()) != reference {
            return Err(Error::Validation);
        }
        // Never substitute the unsaturated binary64 training shadow output.
        let prediction = F64::from_i64(i64::from(reference.output)).div(F64::from_u64(256))?;
        let difference = prediction.sub(sample.reward().value)?;
        let square = difference.mul(difference)?;
        let family = sample.family().index()?;
        result.overall = result.overall.add(square)?;
        result.by_family[family] = result.by_family[family].add(square)?;
        result.counts[family] += 1;
    }
    result.overall = result
        .overall
        .div(F64::from_u64(data.validation().len() as u64))?;
    for i in 0..FAMILIES {
        if result.counts[i] < 4 {
            return Err(Error::DataIncomplete);
        }
        result.by_family[i] =
            result.by_family[i].div(F64::from_u64(u64::from(result.counts[i])))?;
    }
    Ok(result)
}

pub fn compare(
    old: &[u8; MODEL_BYTES],
    new: &[u8; MODEL_BYTES],
    data: &FrozenData<'_>,
) -> Result<Comparison, Error> {
    let comparison = Comparison {
        old: mse(old, data)?,
        new: mse(new, data)?,
    };
    if comparison
        .new
        .overall
        .compare(comparison.old.overall)
        .is_gt()
    {
        return Err(Error::Validation);
    }
    let tolerance = F64::ONE.div(F64::from_u64(65536))?;
    for family in 0..FAMILIES {
        if comparison.new.by_family[family]
            .compare(comparison.old.by_family[family].add(tolerance)?)
            .is_gt()
        {
            return Err(Error::Validation);
        }
    }
    Ok(comparison)
}

pub struct ValidatedCandidate<'a> {
    model: SealedModel<'a>,
    comparison: Comparison,
    parent_hash: [u8; 32],
    registration_hash: [u8; 32],
}
impl<'a> ValidatedCandidate<'a> {
    pub(super) fn from_worker(
        model: SealedModel<'a>,
        comparison: Comparison,
        parent_hash: [u8; 32],
        registration_hash: [u8; 32],
    ) -> Self {
        Self {
            model,
            comparison,
            parent_hash,
            registration_hash,
        }
    }
    pub fn register(
        old: &[u8; MODEL_BYTES],
        candidate: SealedModel<'a>,
        data: &FrozenData<'_>,
        probes: &[CandidateSet],
    ) -> Result<Self, Error> {
        let Origin::Learned(record) = candidate.manifest().origin else {
            return Err(Error::Untrained);
        };
        train::operator_selftest()?;
        let parent_hash: [u8; 32] = Sha256::digest(old).into();
        if record.parent_hash != parent_hash || record.data != data.manifest() {
            return Err(Error::Evidence);
        }
        if record.result_hash == parent_hash {
            return Err(Error::NoChange);
        }
        if !train::frozen_equal(old, candidate.bytes()) {
            return Err(Error::FrozenLayers);
        }
        // A caller cannot turn an arbitrary parameter edit into "trained" by
        // filling public manifest fields. Reproduce the exact ordered pass.
        let mut training = train::Trainer::start(old, data)?;
        while training.step_next()? {}
        let reproduced = training.finish()?;
        if reproduced.bytes() != candidate.bytes() || reproduced.record() != record {
            return Err(Error::Evidence);
        }
        distinguish_candidates(candidate.bytes(), probes)?;
        let comparison = compare(old, candidate.bytes(), data)?;
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_INDEPENDENT_MODEL_REGISTRATION_1.3\0");
        hash.update(candidate.hash());
        hash.update(parent_hash);
        hash.update(data.manifest().hash);
        for value in [comparison.old.overall, comparison.new.overall]
            .into_iter()
            .chain(comparison.old.by_family)
            .chain(comparison.new.by_family)
        {
            hash.update(value.to_bits().to_le_bytes());
        }
        Ok(Self {
            model: candidate,
            comparison,
            parent_hash,
            registration_hash: hash.finalize().into(),
        })
    }
    pub fn model(&self) -> &SealedModel<'a> {
        &self.model
    }
    /// Move this exact validated identity to an immutable copy owned by a
    /// different bank loan. This cannot validate new parameters or a new
    /// manifest; the existing independent validation proof is preserved.
    pub fn rebind<'b>(
        &self,
        frozen: &'b [u8; MODEL_BYTES],
    ) -> Result<ValidatedCandidate<'b>, Error> {
        if frozen != self.model.bytes()
            || <[u8; 32]>::from(Sha256::digest(frozen)) != self.model.manifest().parameters_hash
        {
            return Err(Error::Evidence);
        }
        Ok(ValidatedCandidate {
            model: SealedModel::from_worker(
                frozen,
                self.model.manifest().clone(),
                self.model.hash(),
            ),
            comparison: self.comparison,
            parent_hash: self.parent_hash,
            registration_hash: self.registration_hash,
        })
    }
    pub fn comparison(&self) -> Comparison {
        self.comparison
    }
    pub fn parent_hash(&self) -> [u8; 32] {
        self.parent_hash
    }
    pub fn registration_hash(&self) -> [u8; 32] {
        self.registration_hash
    }
}
