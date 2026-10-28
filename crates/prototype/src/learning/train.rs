//! One fixed-order pass of last-layer SGD using software binary64 only.
use super::{
    Error,
    data::{DataManifest, FrozenData},
    softfloat::F64,
};
use crate::model::{MODEL_BYTES, Model};
use sha2::{Digest, Sha256};

pub const LAST_WEIGHTS: usize = 2560;
pub const LAST_BIAS: usize = 2768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parameters {
    weights: [F64; 16],
    bias: F64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub prediction: F64,
    pub error: F64,
    pub clipped_gradients: [F64; 17],
    pub next: Parameters,
}

fn ratio(n: i64, d: u64) -> Result<F64, Error> {
    Ok(F64::from_i64(n).div(F64::from_u64(d))?)
}
fn limits() -> Result<(F64, F64, F64, F64), Error> {
    Ok((
        F64::from_i64(-2),
        ratio(127, 64)?,
        F64::from_i64(-128),
        ratio(32767, 256)?,
    ))
}

impl Parameters {
    pub fn from_quantized(weights: [i8; 16], bias: i32) -> Result<Self, Error> {
        if !(-32768..=32767).contains(&bias) {
            return Err(Error::Model);
        }
        let mut values = [F64::ZERO; 16];
        for (value, weight) in values.iter_mut().zip(weights) {
            *value = ratio(i64::from(weight), 64)?;
        }
        Ok(Self {
            weights: values,
            bias: ratio(i64::from(bias), 256)?,
        })
    }
    pub fn from_model(bytes: &[u8; MODEL_BYTES]) -> Result<Self, Error> {
        let mut weights = [0i8; 16];
        for (i, value) in weights.iter_mut().enumerate() {
            *value = bytes[LAST_WEIGHTS + i] as i8;
        }
        let bias = i32::from_le_bytes(bytes[LAST_BIAS..].try_into().map_err(|_| Error::Model)?);
        Self::from_quantized(weights, bias)
    }
    pub fn weights(&self) -> &[F64; 16] {
        &self.weights
    }
    pub fn bias(&self) -> F64 {
        self.bias
    }

    pub fn step(&self, hidden: &[i16; 16], reward: F64) -> Result<Step, Error> {
        let (weight_min, weight_max, bias_min, bias_max) = limits()?;
        let rate = ratio(1, 256)?;
        let mut h = [F64::ZERO; 16];
        let mut prediction = F64::ZERO;
        for j in 0..16 {
            if hidden[j] < 0 {
                return Err(Error::Evidence);
            }
            h[j] = ratio(i64::from(hidden[j]), 256)?;
            // Deliberately separate mul/add: each software operation rounds.
            prediction = prediction.add(self.weights[j].mul(h[j])?)?;
        }
        prediction = prediction.add(self.bias)?;
        let error = prediction.sub(reward)?;
        let mut gradients = [F64::ZERO; 17];
        for j in 0..16 {
            // mul rejects any non-finite intermediate before clipping it.
            gradients[j] = error.mul(h[j])?.clamp(F64::ONE.neg(), F64::ONE)?;
        }
        gradients[16] = error.clamp(F64::ONE.neg(), F64::ONE)?;
        let mut next = *self;
        for (j, gradient) in gradients[..16].iter().copied().enumerate() {
            next.weights[j] = self.weights[j]
                .sub(rate.mul(gradient)?)?
                .clamp(weight_min, weight_max)?;
            if next.weights[j]
                .sub(self.weights[j])?
                .abs()
                .compare(rate)
                .is_gt()
            {
                return Err(Error::Numeric);
            }
        }
        next.bias = self
            .bias
            .sub(rate.mul(gradients[16])?)?
            .clamp(bias_min, bias_max)?;
        if next.bias.sub(self.bias)?.abs().compare(rate).is_gt() {
            return Err(Error::Numeric);
        }
        Ok(Step {
            prediction,
            error,
            clipped_gradients: gradients,
            next,
        })
    }
    pub fn quantized(&self) -> Result<([i8; 16], i32), Error> {
        let mut weights = [0i8; 16];
        for (out, value) in weights.iter_mut().zip(self.weights) {
            *out = quantize_weight(value)?;
        }
        Ok((weights, quantize_bias(self.bias)?))
    }
}

fn half_away(value: F64, scale: u64) -> Result<i64, Error> {
    let magnitude = value
        .mul(F64::from_u64(scale))?
        .abs()
        .add(F64::HALF)?
        .floor()?
        .to_i64_trunc()?;
    Ok(if value.negative() {
        -magnitude
    } else {
        magnitude
    })
}
pub fn quantize_weight(value: F64) -> Result<i8, Error> {
    Ok(half_away(value, 64)?.clamp(i64::from(i8::MIN), i64::from(i8::MAX)) as i8)
}
pub fn quantize_bias(value: F64) -> Result<i32, Error> {
    let (.., low, high) = limits()?;
    if value.compare(low).is_lt() || value.compare(high).is_gt() {
        return Err(Error::Model);
    }
    let encoded = half_away(value, 256)?;
    if !(-32768..=32767).contains(&encoded) {
        return Err(Error::Model);
    }
    Ok(encoded as i32)
}

/// The ten fixed learning/packing boundary cases are addressable one at a
/// time so the independent EL0 role can surrender its exact 2.5 ms physical
/// credit after every case. `operator_selftest` retains the same monolithic
/// host/registration contract by running the complete ordered sequence.
pub const OPERATOR_SELFTEST_CASES: usize = 10;

pub fn operator_selftest_case(index: usize) -> Result<(), Error> {
    type OperatorVector = (i16, i8, i32, i64, u64, i64, u64, i8, i32, i64);
    const VECTORS: [OperatorVector; 4] = [
        (256, 127, -768, 127, 64, -767, 256, 127, -767, -259),
        (256, -128, 1024, -2, 1, 1023, 256, -128, 1023, 511),
        (16640, -128, 32767, -511, 256, 32767, 256, -128, 32767, -513),
        (16640, 127, -32768, 507, 256, -128, 1, 127, -32768, 252),
    ];
    if let Some(&(h0, w0, b0, wn, wd, bn, bd, wq, bq, output)) = VECTORS.get(index) {
        let mut weights = [0i8; 16];
        weights[0] = w0;
        let mut hidden = [0i16; 16];
        hidden[0] = h0;
        let step = Parameters::from_quantized(weights, b0)?.step(&hidden, F64::ZERO)?;
        let (quantized, bias) = step.next.quantized()?;
        let accumulated = i64::from(quantized[0]) * i64::from(h0) + 64 * i64::from(bias);
        let integer = accumulated.signum() * ((accumulated.abs() + 32) / 64);
        return if step.next.weights[0] == ratio(wn, wd)?
            && step.next.bias == ratio(bn, bd)?
            && (quantized[0], bias) == (wq, bq)
            && integer == output
        {
            Ok(())
        } else {
            Err(Error::Validation)
        };
    }
    match index {
        4 | 5 => {
            let sign: i64 = if index == 4 { -1 } else { 1 };
            if quantize_weight(ratio(sign, 128)?)? == sign as i8 {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        6 | 7 => {
            let sign: i64 = if index == 6 { -1 } else { 1 };
            if quantize_bias(ratio(sign, 512)?)? == sign as i32 {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        8 | 9 => {
            let bias = if index == 8 { 32768 } else { -32769 };
            if Parameters::from_quantized([0; 16], bias).is_err() {
                Ok(())
            } else {
                Err(Error::Validation)
            }
        }
        _ => Err(Error::Order),
    }
}

/// Fixed learning/packing boundary checks are also run by independent
/// registration, not merely by the host test harness.
pub fn operator_selftest() -> Result<(), Error> {
    for index in 0..OPERATOR_SELFTEST_CASES {
        operator_selftest_case(index)?;
    }
    Ok(())
}

/// Every byte outside W3 and b3 must be immutable, including full int32 b1/b2.
pub fn frozen_equal(left: &[u8; MODEL_BYTES], right: &[u8; MODEL_BYTES]) -> bool {
    left[..LAST_WEIGHTS] == right[..LAST_WEIGHTS] && left[2576..LAST_BIAS] == right[2576..LAST_BIAS]
}
pub fn frozen_hash(bytes: &[u8; MODEL_BYTES]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_FROZEN_FIRST_TWO_LAYERS_1.3\0");
    hash.update(&bytes[..LAST_WEIGHTS]);
    hash.update(&bytes[2576..LAST_BIAS]);
    hash.finalize().into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrainingRecord {
    pub parent_hash: [u8; 32],
    pub frozen_layers_hash: [u8; 32],
    pub data: DataManifest,
    pub steps: u16,
    pub shadow_parameters_hash: [u8; 32],
    pub result_hash: [u8; 32],
}
pub struct TrainedModel {
    bytes: [u8; MODEL_BYTES],
    record: TrainingRecord,
}
impl TrainedModel {
    pub(super) fn from_worker(bytes: [u8; MODEL_BYTES], record: TrainingRecord) -> Self {
        Self { bytes, record }
    }
    pub fn bytes(&self) -> &[u8; MODEL_BYTES] {
        &self.bytes
    }
    pub fn record(&self) -> TrainingRecord {
        self.record
    }
}

/// The borrowed data and original model remain immutable. The owner may yield
/// after any step; it must acquire control-pool CPU credit before resuming.
pub struct Trainer<'a, 'data> {
    original: &'a [u8; MODEL_BYTES],
    data: &'a FrozenData<'data>,
    parameters: Parameters,
    cursor: usize,
    rejected: bool,
}
impl<'a, 'data> Trainer<'a, 'data> {
    pub fn start(
        active: &'a [u8; MODEL_BYTES],
        data: &'a FrozenData<'data>,
    ) -> Result<Self, Error> {
        // Reject an unlearnable last bias; never silently project the seed.
        let parameters = Parameters::from_model(active)?;
        Ok(Self {
            original: active,
            data,
            parameters,
            cursor: 0,
            rejected: false,
        })
    }
    pub fn completed_steps(&self) -> usize {
        self.cursor
    }
    pub fn step_next(&mut self) -> Result<bool, Error> {
        if self.rejected {
            return Err(Error::State);
        }
        let Some(sample) = self.data.training().get(self.cursor) else {
            return Ok(false);
        };
        let model = Model::parse(self.original).map_err(|_| Error::Model)?;
        let h = model.trace(sample.input()).hidden2;
        match self.parameters.step(&h, sample.reward().value) {
            Ok(step) => {
                self.parameters = step.next;
                self.cursor += 1;
                Ok(true)
            }
            Err(error) => {
                self.rejected = true;
                Err(error)
            }
        }
    }
    pub fn finish(self) -> Result<TrainedModel, Error> {
        if self.rejected {
            return Err(Error::State);
        }
        if self.cursor != self.data.training().len() {
            return Err(Error::DataIncomplete);
        }
        let (weights, bias) = self.parameters.quantized()?;
        let mut bytes = *self.original;
        for j in 0..16 {
            bytes[LAST_WEIGHTS + j] = weights[j] as u8;
        }
        bytes[LAST_BIAS..].copy_from_slice(&bias.to_le_bytes());
        if !frozen_equal(self.original, &bytes) {
            return Err(Error::FrozenLayers);
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_SOFT_BINARY64_FINAL_PARAMETERS_1.3\0");
        for parameter in self
            .parameters
            .weights
            .into_iter()
            .chain([self.parameters.bias])
        {
            hash.update(parameter.to_bits().to_le_bytes());
        }
        let record = TrainingRecord {
            parent_hash: Sha256::digest(self.original).into(),
            frozen_layers_hash: frozen_hash(self.original),
            data: self.data.manifest(),
            steps: self.cursor as u16,
            shadow_parameters_hash: hash.finalize().into(),
            result_hash: Sha256::digest(bytes).into(),
        };
        Ok(TrainedModel { bytes, record })
    }
}
const _: () = assert!(core::mem::size_of::<Trainer<'_, '_>>() < 4096);
