//! The fixed 1.3 feature schema. Raw values remain bound to the candidate hash.
use crate::domains::{Action, Error};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetFeatures {
    pub values: [Option<u64>; 4],
}

pub const DOMAIN_PRESENT_ALL: u8 = 0b1111;

/// An absent measurement is distinct from a measured zero. Adapters must
/// leave absent values at zero and preserve this mask through inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainObservation {
    pub values: [u64; 4],
    pub present: u8,
}
impl DomainObservation {
    pub const fn complete(values: [u64; 4]) -> Self {
        Self {
            values,
            present: DOMAIN_PRESENT_ALL,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawFeatures {
    pub common: [u64; 8],
    pub domain: [u64; 4],
    pub domain_present: u8,
    pub target: TargetFeatures,
    pub control_capacity: Option<u64>,
}
impl Default for RawFeatures {
    fn default() -> Self {
        Self {
            common: [0; 8],
            domain: [0; 4],
            domain_present: DOMAIN_PRESENT_ALL,
            target: TargetFeatures::default(),
            control_capacity: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Encoded {
    pub values: [i16; 64],
    pub clipped: u64,
}

pub const COMMON_LIMITS: [u64; 8] = [1000, 1000, 64, 1000, 1000, 1000, 100, 1];
pub const DOMAIN_LIMITS: [[u64; 4]; 16] = [
    [64, 100000, 1000, 10000],
    [1000, 64, 1000, 64],
    [262144, 10000, 1000, 100000],
    [1000, 4096, 1000000, 1000],
    [128, 100000, 100000, 1000],
    [100000, 100000, 1000, 1],
    [256, 10000, 1000, 100],
    [100000, 100000, 16, 1000],
    [256, 1000000, 1000, 1000],
    [1000000, 1000, 256, 16],
    [256, 100, 256, 100000],
    [10000, 1000, 4, 10000],
    [1000, 100000, 100000, 4],
    [5000, 1000, 8, 16],
    [4096, 1000, 100000, 1000000],
    [1000000, 4000, 1000, 100000],
];
pub const TARGET_LIMITS: [u64; 4] = [4000, 1000, 100000, 1];

/// Preserve the exact wide-arithmetic rounding rule. All schema limits fit
/// the native u64 path; very large caller-supplied limits retain the u128 path.
pub fn normalize(value: u64, upper: u64) -> Result<(i16, bool), Error> {
    if upper == 0 {
        return Err(Error::Schema);
    }
    let value_in_range = value.min(upper);
    if upper <= u64::MAX / 513 {
        // value_in_range <= upper, so both numerator and denominator fit.
        return Ok((
            ((512 * value_in_range + upper) / (2 * upper)) as i16,
            value > upper,
        ));
    }
    let v = u128::from(value_in_range);
    let h = u128::from(upper);
    Ok((((512 * v + h) / (2 * h)) as i16, value > upper))
}

/// Validate the raw candidate without computing model activations. Protected
/// candidate registration binds these raw bytes; its caller does not consume
/// normalized features. Inference still calls the same validation via encode.
pub fn validate(action: Action, raw: &RawFeatures) -> Result<(), Error> {
    action.validate()?;
    if raw.domain_present & !DOMAIN_PRESENT_ALL != 0
        || raw
            .domain
            .iter()
            .enumerate()
            .any(|(i, value)| raw.domain_present & (1 << i) == 0 && *value != 0)
    {
        return Err(Error::Format);
    }
    // A fresh local placement request needs its queue age. Peer metrics are
    // required only for REMOTE; every other family still requires all four.
    let required = match action {
        Action::Placement(0 | 2) => 0b1000,
        _ => DOMAIN_PRESENT_ALL,
    };
    if raw.domain_present & required != required {
        return Err(Error::NotReady);
    }
    if raw.common[7] > 1
        || (action.domain() == 6 && raw.domain[3] > 1)
        || raw.target.values[3].is_some_and(|v| v > 1)
    {
        return Err(Error::Range);
    }
    if matches!(action, Action::ControlSet(_)) && raw.control_capacity.is_none() {
        return Err(Error::NotReady);
    }
    Ok(())
}

pub fn encode(action: Action, raw: RawFeatures) -> Result<Encoded, Error> {
    validate(action, &raw)?;
    let mut out = Encoded {
        values: [0; 64],
        clipped: 0,
    };
    out.values[usize::from(action.domain() - 1)] = 256;
    let mut set = |index: usize, value: u64, limit: u64| -> Result<(), Error> {
        let (value, clipped) = normalize(value, limit)?;
        out.values[index] = value;
        if clipped {
            out.clipped |= 1u64 << index;
        }
        Ok(())
    };
    for (i, limit) in COMMON_LIMITS.iter().copied().enumerate() {
        set(16 + i, raw.common[i], limit)?;
    }
    for (i, limit) in DOMAIN_LIMITS[usize::from(action.domain() - 1)]
        .iter()
        .copied()
        .enumerate()
    {
        if raw.domain_present & (1 << i) != 0 {
            set(24 + i, raw.domain[i], limit)?;
        }
    }
    let (a1, h1, a2, h2) = match action {
        Action::ControlSet(mask) => (
            u64::from(mask.count_ones()),
            4,
            Some(raw.control_capacity.ok_or(Error::NotReady)?),
            4000,
        ),
        Action::Cache { pages, batch } => (u64::from(pages), 4096, Some(u64::from(batch)), 64),
        Action::Filesystem { readahead, flush } => {
            (u64::from(readahead), 16, Some(u64::from(flush)), 32)
        }
        Action::Ipc { budget, batch } => (u64::from(budget), 128, Some(u64::from(batch)), 16),
        Action::CpuWeight(v) | Action::SpawnTokens(v) => (u64::from(v), 8, None, 1),
        Action::IrqTarget(v) => (u64::from(v), 3, None, 1),
        Action::SoftCoalesce(v) => (u64::from(v), 1000, None, 1),
        Action::ServiceBatch(v) | Action::NotifyBatch(v) => (u64::from(v), 8, None, 1),
        Action::IoShare(v) => (u64::from(v), 750, None, 1),
        Action::TxBatch(v) => (u64::from(v), 16, None, 1),
        Action::UnauthRate(v) => (u64::from(v), 32, None, 1),
        Action::BackgroundBudget(v) => (u64::from(v), 400, None, 1),
        Action::RecoveryRecipe(v) | Action::Placement(v) => (u64::from(v), 2, None, 1),
        Action::ConsoleBatch(v) => (u64::from(v), 64, None, 1),
        Action::OfferCpu(v) => (u64::from(v), 1000, None, 1),
    };
    set(40, u64::from(action.kind()), 255)?;
    set(41, a1, h1)?;
    if let Some(v) = a2 {
        set(42, v, h2)?;
    }
    for (i, limit) in TARGET_LIMITS.iter().copied().enumerate() {
        if let Some(v) = raw.target.values[i] {
            set(56 + i, v, limit)?;
        }
    }
    for i in 0..4 {
        if raw.domain_present & (1 << i) != 0 {
            out.values[32 + i] = 256;
        }
    }
    out.values[48] = 256;
    out.values[49] = 256;
    if a2.is_some() {
        out.values[50] = 256;
    }
    for i in 0..4 {
        if raw.target.values[i].is_some() {
            out.values[60 + i] = 256;
        }
    }
    Ok(out)
}
