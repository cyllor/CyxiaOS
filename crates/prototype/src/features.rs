//! The fixed 1.3 feature schema. Raw values remain bound to the candidate hash.
use crate::domains::{Action, Error};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetFeatures {
    pub values: [Option<u64>; 4],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RawFeatures {
    pub common: [u64; 8],
    pub domain: [u64; 4],
    pub target: TargetFeatures,
    pub control_capacity: Option<u64>,
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

/// Wide arithmetic makes saturation independent of caller-sized integers.
pub fn normalize(value: u64, upper: u64) -> Result<(i16, bool), Error> {
    if upper == 0 {
        return Err(Error::Schema);
    }
    let v = u128::from(value.min(upper));
    let h = u128::from(upper);
    Ok((((512 * v + h) / (2 * h)) as i16, value > upper))
}

pub fn encode(action: Action, raw: RawFeatures) -> Result<Encoded, Error> {
    action.validate()?;
    if raw.common[7] > 1
        || (action.domain() == 6 && raw.domain[3] > 1)
        || raw.target.values[3].is_some_and(|v| v > 1)
    {
        return Err(Error::Range);
    }
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
    for i in 0..8 {
        set(16 + i, raw.common[i], COMMON_LIMITS[i])?;
    }
    for i in 0..4 {
        set(
            24 + i,
            raw.domain[i],
            DOMAIN_LIMITS[usize::from(action.domain() - 1)][i],
        )?;
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
    for i in 0..4 {
        if let Some(v) = raw.target.values[i] {
            set(56 + i, v, TARGET_LIMITS[i])?;
        }
    }
    for i in 0..4 {
        out.values[32 + i] = 256;
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
