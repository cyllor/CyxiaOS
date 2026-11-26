//! Version 1.3 bounded integer model.

/// Number of raw Q8.8 input activations.
pub const INPUT_FEATURES: usize = 64;

/// Maximum number of candidates evaluated by a selection request.
pub const MAX_CANDIDATES: usize = 32;

/// Exact size of the 2576 int8 weights and 49 little-endian int32 biases.
pub const MODEL_BYTES: usize = 2772;

/// Invalid model or inference request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The payload must contain exactly [`MODEL_BYTES`] bytes.
    InvalidModelLength { actual: usize },
    /// Selection requires at least one candidate.
    EmptyCandidates,
    /// Selection is bounded to [`MAX_CANDIDATES`] candidates.
    TooManyCandidates { actual: usize },
}

/// Actual post-saturation/ReLU hidden outputs and linear output of one inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Trace {
    pub hidden1: [i16; 32],
    pub hidden2: [i16; 16],
    pub output: i16,
}

/// An immutable borrowed integer model package.
#[derive(Clone, Copy, Debug)]
pub struct Model<'a> {
    bytes: &'a [u8],
}

/// Reuses only the unrounded first-layer contribution for identical
/// features 0..40. Bound to this model's immutable bytes; a changed
/// prefix falls back to full inference.
pub struct SharedPrefix<'a> {
    model: Model<'a>,
    prefix: [i16; 40],
    sums: [i64; 32],
}

impl SharedPrefix<'_> {
    pub fn score(&self, input: &[i16; INPUT_FEATURES]) -> i16 {
        self.trace(input).output
    }

    pub fn trace(&self, input: &[i16; INPUT_FEATURES]) -> Trace {
        if input[..40] != self.prefix {
            return self.model.trace(input);
        }
        let mut hidden1 = [0; 32];
        for (row, activation) in hidden1.iter_mut().enumerate() {
            let z = self.model.accumulate(
                &input[40..],
                row * INPUT_FEATURES + 40,
                self.sums[row],
            );
            *activation = Model::quantize(z).max(0);
        }
        self.model.finish_trace(hidden1)
    }
}

impl<'a> Model<'a> {
    pub fn prepare_prefix(&self, input: &[i16; INPUT_FEATURES]) -> SharedPrefix<'a> {
        let mut prefix = [0; 40];
        prefix.copy_from_slice(&input[..40]);
        let sums = core::array::from_fn(|row| {
            self.accumulate(&prefix, row * INPUT_FEATURES, self.bias_accumulator(row))
        });
        SharedPrefix {
            model: *self,
            prefix,
            sums,
        }
    }

    /// Return the index of the first maximum score among 1..=32 candidates.
    /// Length is checked before evaluating any candidate.
    pub fn select(&self, candidates: &[[i16; INPUT_FEATURES]]) -> Result<usize, Error> {
        if candidates.is_empty() {
            return Err(Error::EmptyCandidates);
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(Error::TooManyCandidates {
                actual: candidates.len(),
            });
        }
        let mut best_index = 0;
        let mut best_score = self.score(&candidates[0]);
        for (index, candidate) in candidates.iter().enumerate().skip(1) {
            let score = self.score(candidate);
            if score > best_score {
                best_index = index;
                best_score = score;
            }
        }
        Ok(best_index)
    }

    /// Evaluate the fixed 64→32→16→1 network on raw Q8.8 activations.
    ///
    /// Weights are signed int8 values in row-major W1/W2/W3 order. All
    /// biases follow the weights in b1/b2/b3 order as little-endian int32.
    /// Each neuron computes `z = sum(w*x) + 64*b`, rounds `z/64` with
    /// half values away from zero, and saturates to i16. The two hidden
    /// layers then apply ReLU; the output remains linear.
    pub fn score(&self, input: &[i16; INPUT_FEATURES]) -> i16 {
        self.trace(input).output
    }

    /// Evaluate the same integer kernel while retaining both hidden layers.
    /// This is an observation API, not a different validation-time algorithm.
    pub fn trace(&self, input: &[i16; INPUT_FEATURES]) -> Trace {
        let mut hidden1 = [0; 32];
        for (row, activation) in hidden1.iter_mut().enumerate() {
            *activation = self.neuron(input, row * INPUT_FEATURES, row).max(0);
        }
        self.finish_trace(hidden1)
    }

    fn finish_trace(&self, hidden1: [i16; 32]) -> Trace {
        let mut hidden2 = [0; 16];
        for (row, activation) in hidden2.iter_mut().enumerate() {
            *activation = self.neuron(&hidden1, 2048 + row * 32, 32 + row).max(0);
        }
        let output = self.neuron(&hidden2, 2560, 48);
        Trace {
            hidden1,
            hidden2,
            output,
        }
    }

    fn neuron(&self, input: &[i16], weight_offset: usize, bias_index: usize) -> i16 {
        Self::quantize(self.accumulate(input, weight_offset, self.bias_accumulator(bias_index)))
    }

    fn bias_accumulator(&self, bias_index: usize) -> i64 {
        let offset = 2576 + 4 * bias_index;
        let bias = i32::from_le_bytes([
            self.bytes[offset],
            self.bytes[offset + 1],
            self.bytes[offset + 2],
            self.bytes[offset + 3],
        ]);
        // For at most 64 inputs, |z| <= 64*128*32768 + 64*2147483648
        // = 137707388928. i64 safely holds z, its absolute value, and +32.
        i64::from(bias) * 64
    }

    fn accumulate(&self, input: &[i16], weight_offset: usize, mut z: i64) -> i64 {
        // Validate the whole row once, then traverse equally bounded slices.
        // Per-column indexing otherwise repeats checked offset arithmetic and
        // bounds tests in the mandatory 32-candidate inference path.
        let weights = &self.bytes[weight_offset..weight_offset + input.len()];
        for (&weight, &activation) in weights.iter().zip(input) {
            let weight = weight as i8;
            z += i64::from(weight) * i64::from(activation);
        }
        z
    }

    fn quantize(z: i64) -> i16 {
        let rounded = z.signum() * ((z.abs() + 32) / 64);
        rounded.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16
    }

    /// Validate the exact package length before any inference or parameter read.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() != MODEL_BYTES {
            return Err(Error::InvalidModelLength {
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;

    #[test]
    fn shared_prefix_matches_full_trace_including_changed_prefix() {
        for variant in 0..8 {
            let mut parameters = [0u8; MODEL_BYTES];
            for (i, weight) in parameters[..2576].iter_mut().enumerate() {
                *weight = (i * 73 + variant * 17) as u8;
            }
            for (i, bytes) in parameters[2576..].chunks_exact_mut(4).enumerate() {
                let bias = match variant {
                    0 => i32::MAX,
                    1 => i32::MIN,
                    _ => i as i32 - 24,
                };
                bytes.copy_from_slice(&bias.to_le_bytes());
            }
            let model = Model::parse(&parameters).unwrap();
            let mut input = [0i16; INPUT_FEATURES];
            for (i, x) in input.iter_mut().enumerate() {
                *x = (i as i16).wrapping_mul(997).wrapping_add(i16::MIN);
            }
            let prefix = model.prepare_prefix(&input);
            for candidate in 0..32i16 {
                for (i, x) in input[40..].iter_mut().enumerate() {
                    *x = candidate.wrapping_mul(1201).wrapping_add(i as i16);
                }
                assert_eq!(prefix.trace(&input), model.trace(&input));
            }
            input[0] = input[0].wrapping_add(1);
            assert_eq!(prefix.trace(&input), model.trace(&input));
        }
    }
}
