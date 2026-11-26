//! Current LearningConfig v2 arithmetic. Shared with the historical
//! fixed integer MLP operator; no old data, topology or schema admission.
//! Only W3/b3 can change. Each actual protected sample is processed once.
//! Evidence custody and CPU credit must be supplied by the EL1 replay owner.
use crate::{
    native_v0199::integer_model::{MODEL_BYTES, Model},
    reward_v2::softfloat::{F64, FloatError},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Model,
    Evidence,
    Numeric,
    Validation,
    Order,
    State,
    Incomplete,
}
impl From<FloatError> for Error {
    fn from(_: FloatError) -> Self {
        Self::Numeric
    }
}
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
        // Bound the clipped update itself. Re-subtracting the rounded endpoints
        // can exceed the rate by one rounding unit when the update crosses a
        // binary64 binade boundary; that is not an oversized gradient. Preserve
        // the canonical RNE subtraction and projection without a tolerance.
        for (j, gradient) in gradients[..16].iter().copied().enumerate() {
            let delta = rate.mul(gradient)?;
            if delta.abs().compare(rate).is_gt() {
                return Err(Error::Numeric);
            }
            next.weights[j] = self.weights[j].sub(delta)?.clamp(weight_min, weight_max)?;
        }
        let delta = rate.mul(gradients[16])?;
        if delta.abs().compare(rate).is_gt() {
            return Err(Error::Numeric);
        }
        next.bias = self.bias.sub(delta)?.clamp(bias_min, bias_max)?;
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

pub struct LastLayer<'a> {
    original: &'a [u8; MODEL_BYTES],
    parameters: Parameters,
    completed: usize,
    expected: usize,
    failed: bool,
}
impl<'a> LastLayer<'a> {
    pub fn start(original: &'a [u8; MODEL_BYTES], expected: usize) -> Result<Self, Error> {
        if expected < 120 {
            return Err(Error::Incomplete);
        }
        Ok(Self {
            original,
            parameters: Parameters::from_model(original)?,
            completed: 0,
            expected,
            failed: false,
        })
    }
    pub fn completed(&self) -> usize {
        self.completed
    }
    pub fn step(&mut self, input: &[i16; 64], reward: F64) -> Result<(), Error> {
        if self.failed || self.completed >= self.expected {
            return Err(Error::State);
        }
        let model = Model::parse(self.original).map_err(|_| Error::Model)?;
        let h = model.trace(input).hidden2;
        match self.parameters.step(&h, reward) {
            Ok(s) => {
                self.parameters = s.next;
                self.completed += 1;
                Ok(())
            }
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }
    pub fn finish(self) -> Result<[u8; MODEL_BYTES], Error> {
        if self.failed || self.completed != self.expected {
            return Err(Error::Incomplete);
        }
        let (w, b) = self.parameters.quantized()?;
        let mut output = *self.original;
        for (i, v) in w.into_iter().enumerate() {
            output[LAST_WEIGHTS + i] = v as u8;
        }
        output[LAST_BIAS..].copy_from_slice(&b.to_le_bytes());
        if !frozen_equal(self.original, &output) {
            return Err(Error::Model);
        }
        Ok(output)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_last_layer_boundaries_and_exact_frozen_bytes() {
        operator_selftest().unwrap();
        let mut model = [0u8; MODEL_BYTES];
        model[0] = 64;
        model[2048] = 64;
        let mut t = LastLayer::start(&model, 120).unwrap();
        let mut x = [0; 64];
        x[0] = 256;
        for _ in 0..120 {
            t.step(&x, F64::ONE).unwrap();
        }
        let out = t.finish().unwrap();
        assert!(frozen_equal(&model, &out));
        assert_ne!(model, out);
        model[LAST_BIAS..].copy_from_slice(&32768i32.to_le_bytes());
        assert!(matches!(LastLayer::start(&model, 120), Err(Error::Model)));
    }
}
