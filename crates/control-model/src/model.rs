use crate::abi::{CPUS, Error, Input, MODEL_BYTES, Output};
/// Trained linear classifier (three heads) and trained placement head. Weights
/// are Q12, features Q15; i64 accumulation avoids wrapping before saturation.
/// Model bytes are immutable and bounded; header and exact length are checked.
fn coefficients(bytes: &[u8]) -> Result<[i16; 22], Error> {
    if bytes.len() != 52 || &bytes[..8] != b"CYXMDL01" {
        return Err(Error::Model);
    }
    Ok(core::array::from_fn(|i| {
        i16::from_le_bytes([bytes[8 + 2 * i], bytes[9 + 2 * i]])
    }))
}
fn dot(w: &[i16], x: &[i16]) -> i16 {
    let sum: i64 = w
        .iter()
        .zip(x)
        .map(|(a, b)| i64::from(*a) * i64::from(*b))
        .sum();
    (sum / 4096).clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16
}
pub fn infer(input: &Input) -> Result<Output, Error> {
    infer_with(input, MODEL_BYTES)
}
pub fn infer_with(input: &Input, bytes: &[u8]) -> Result<Output, Error> {
    input.validate()?;
    let w = coefficients(bytes)?;
    let x = [
        32767,
        input.features[0],
        input.features[1],
        input.features[2],
        input.features[3],
    ];
    let logits = core::array::from_fn(|i| dot(&w[i * 5..i * 5 + 5], &x));
    // Ties prefer Hold, then Grow, then Shrink. No action is hidden in EL1.
    let mut action = 0;
    for i in 1..3 {
        if logits[i] > logits[action] {
            action = i;
        }
    }
    let mut desired = input.control;
    let mut best: Option<(usize, i16)> = None;
    for i in 0..CPUS {
        let bit = 1u64 << i;
        let eligible = match action {
            1 => {
                input.online & bit != 0
                    && input.control & bit == 0
                    && input.protected_business & bit == 0
            }
            2 => input.control & bit != 0 && input.protected_control & bit == 0,
            _ => false,
        };
        if !eligible {
            continue;
        }
        let f = &input.features[8 + i * 7..15 + i * 7];
        let score = dot(&w[15..22], f);
        // Add the highest predicted headroom; release the lowest on shrink.
        if best.is_none_or(|(_, prev)| {
            if action == 1 {
                score > prev
            } else {
                score < prev
            }
        }) {
            best = Some((i, score));
        }
    }
    if let Some((i, _)) = best {
        if action == 1 {
            desired |= 1 << i;
        } else {
            desired &= !(1 << i);
        }
    }
    Ok(Output {
        boot: input.boot,
        model_epoch: input.model_epoch,
        resources: input.resources,
        window: input.window,
        sequence: input.sequence,
        controller: input.controller,
        cores: input.cores,
        desired,
        action: action as u64,
        logits,
    })
}
