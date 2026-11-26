//! V0.19.9 SnapshotReply v3, FeatureSchema v3 and SecurityBrainSchema v2.
//! Pure freestanding codec/inference; shared by native EL0 and trusted tests.
//! Model bytes, target identity and candidate metadata must come from the
//! independently authenticated startup/snapshot registries. This module
//! does not verify signatures, grant authority, or publish/execute actions.
//! No legacy CoreSet or D16 input can enter the current 64-feature layout.
#[path = "../../prototype/src/model.rs"]
pub mod integer_model;

pub const SNAPSHOT_BYTES: usize = 264;
pub const MAX_AGE_NS: u64 = 100_000_000;
const MAGIC: u32 = 0x4359_534e;
const COMMON_H: [u64; 8] = [1000, 1000, 64, 1000, 1000, 1000, 100000, 0];
const DOMAIN_H: [[u64; 4]; 15] = [
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
];
const U16: u64 = u16::MAX as u64;
const U32: u64 = u32::MAX as u64;
const DOMAIN_WIDTH: [[u64; 4]; 15] = [
    [U16, U32, U16, U32],
    [U32, U16, U16, U16],
    [U32, U32, U16, U32],
    [U16, U32, U32, U16],
    [U16, U32, U32, U16],
    [U32, U32, U16, 1],
    [U16, U32, U32, U32],
    [U32, U32, U16, U16],
    [U16, U32, U16, U16],
    [U32, U16, U16, U16],
    [U16, U32, U16, U32],
    [U32, U32, U16, U32],
    [U16, U32, U32, U16],
    [U32, U32, U16, U16],
    [U16, U16, U32, U32],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Format,
    Scope,
    Stale,
    Missing,
    Candidate,
    Model,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReplyV3 {
    pub snapshot_seq: u64,
    pub boot_epoch: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub sampled_ns: u64,
    pub domain: u16,
    /// Canonical field IDs 16..27, including the mandatory absent field 23.
    pub fields: [Option<u64>; 12],
}
fn u16at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put16(b: &mut [u8], at: usize, x: u16) {
    b[at..at + 2].copy_from_slice(&x.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, x: u32) {
    b[at..at + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, x: u64) {
    b[at..at + 8].copy_from_slice(&x.to_le_bytes());
}
impl SnapshotReplyV3 {
    fn valid(&self) -> bool {
        if !(1..=15).contains(&self.domain)
            || self.snapshot_seq == 0
            || self.boot_epoch == 0
            || self.ledger_generation == 0
            || self.core_generation == 0
            || self.target_id == 0
            || self.target_generation == 0
            || self.fields[7].is_some()
        {
            return false;
        }
        self.fields[8..]
            .iter()
            .zip(DOMAIN_WIDTH[usize::from(self.domain - 1)])
            .all(|(v, max)| v.is_none_or(|v| v <= max))
    }
    pub fn encode(&self) -> Result<[u8; SNAPSHOT_BYTES], Error> {
        if !self.valid() {
            return Err(Error::Format);
        }
        let mut b = [0; SNAPSHOT_BYTES];
        put32(&mut b, 0, MAGIC);
        put16(&mut b, 4, 3);
        put16(&mut b, 6, 72);
        for (i, v) in [
            self.snapshot_seq,
            self.boot_epoch,
            self.ledger_generation,
            self.core_generation,
            self.target_id,
            self.target_generation,
            self.sampled_ns,
        ]
        .into_iter()
        .enumerate()
        {
            put64(&mut b, 8 + i * 8, v);
        }
        put16(&mut b, 64, self.domain);
        put16(&mut b, 66, 12);
        for (i, v) in self.fields.iter().enumerate() {
            let at = 72 + i * 16;
            put16(&mut b, at, (16 + i) as u16);
            if let Some(v) = v {
                b[at + 2] = 1;
                put64(&mut b, at + 8, *v);
            }
        }
        Ok(b)
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != SNAPSHOT_BYTES
            || u32at(b, 0) != MAGIC
            || u16at(b, 4) != 3
            || u16at(b, 6) != 72
            || u16at(b, 66) != 12
            || u32at(b, 68) != 0
        {
            return Err(Error::Format);
        }
        let mut fields = [None; 12];
        for (i, field) in fields.iter_mut().enumerate() {
            let at = 72 + i * 16;
            let value = u64at(b, at + 8);
            if u16at(b, at) != (16 + i) as u16 || b[at + 3..at + 8].iter().any(|v| *v != 0) {
                return Err(Error::Format);
            }
            *field = match b[at + 2] {
                0 if value == 0 => None,
                1 => Some(value),
                _ => return Err(Error::Format),
            };
        }
        let s = Self {
            snapshot_seq: u64at(b, 8),
            boot_epoch: u64at(b, 16),
            ledger_generation: u64at(b, 24),
            core_generation: u64at(b, 32),
            target_id: u64at(b, 40),
            target_generation: u64at(b, 48),
            sampled_ns: u64at(b, 56),
            domain: u16at(b, 64),
            fields,
        };
        if !s.valid() {
            return Err(Error::Format);
        }
        Ok(s)
    }
    /// Scope is supplied by EL1, not inferred from user bytes. A normalized
    /// score never substitutes for an exact target/epoch comparison.
    pub fn check(&self, scope: SnapshotScope, now_ns: u64) -> Result<(), Error> {
        if !self.valid()
            || self.snapshot_seq != scope.snapshot_seq
            || self.boot_epoch != scope.boot_epoch
            || self.ledger_generation != scope.ledger_generation
            || self.core_generation != scope.core_generation
            || self.target_id != scope.target_id
            || self.target_generation != scope.target_generation
            || self.domain != scope.domain
        {
            return Err(Error::Scope);
        }
        if now_ns < self.sampled_ns || now_ns - self.sampled_ns >= MAX_AGE_NS {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn present_mask(&self) -> u16 {
        self.fields.iter().enumerate().fold(0, |mask, (i, v)| {
            mask | if v.is_some() { 1u16 << i } else { 0 }
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotScope {
    pub snapshot_seq: u64,
    pub boot_epoch: u64,
    pub ledger_generation: u64,
    pub core_generation: u64,
    pub target_id: u64,
    pub target_generation: u64,
    pub domain: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Features {
    pub values: [i16; 64],
    pub clipped: u64,
}
impl Features {
    fn new() -> Self {
        Self {
            values: [0; 64],
            clipped: 0,
        }
    }
    fn set(&mut self, i: usize, value: Option<u64>, h: u64) {
        if let Some(v) = value {
            assert!(h > 0);
            // All current schema scales are small enough for exact u64
            // arithmetic. Preserve the wide fallback for future scales.
            self.values[i] = if v >= h {
                256
            } else if h <= u64::MAX / 513 {
                ((512 * v + h) / (2 * h)) as i16
            } else {
                ((512u128 * u128::from(v) + u128::from(h)) / (2 * u128::from(h))) as i16
            };
            if v > h {
                self.clipped |= 1u64 << i;
            }
        }
    }
}

/// The EL1 candidate generator owns the canonical ordinal, raw action value
/// and target metadata. These values do not confer action authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub a1: u64,
    pub a2: Option<u64>,
    pub cpu: [Option<u64>; 4],
}
fn action_limits(domain: u16, c: Candidate) -> Result<(u64, u64), Error> {
    let (a, b) = (c.a1, c.a2);
    let limits = match domain {
        1 | 2 if matches!(a, 1 | 2 | 4 | 8) && b.is_none() => (8, 0),
        3 if matches!(
            (a, b),
            (64, Some(4)) | (256, Some(16)) | (1024, Some(32)) | (4096, Some(64))
        ) =>
        {
            (4096, 64)
        }
        4 if matches!(
            (a, b),
            (0, Some(4)) | (2, Some(8)) | (8, Some(16)) | (16, Some(32))
        ) =>
        {
            (16, 32)
        }
        5 if matches!(
            (a, b),
            (8, Some(1)) | (32, Some(4)) | (64, Some(8)) | (128, Some(16))
        ) =>
        {
            (128, 16)
        }
        6 if matches!(a, 1..=3) && b.is_none() => (3, 0),
        7 if matches!(a, 0 | 50 | 200 | 1000) && b.is_none() => (1000, 0),
        8 | 11 if matches!(a, 1 | 2 | 4 | 8) && b.is_none() => (8, 0),
        9 if matches!(a, 100 | 250 | 500 | 750) && b.is_none() => (750, 0),
        10 if matches!(a, 1 | 4 | 8 | 16) && b.is_none() => (16, 0),
        12 if matches!(a, 4 | 8 | 16 | 32) && b.is_none() => (32, 0),
        13 if matches!(a, 50 | 100 | 200 | 400) && b.is_none() => (400, 0),
        14 if matches!(a, 0..=2) && b.is_none() => (2, 0),
        15 if matches!(a, 1 | 8 | 32 | 64) && b.is_none() => (64, 0),
        _ => return Err(Error::Candidate),
    };
    if (domain != 6 && c.cpu.iter().any(Option::is_some)) || c.cpu[3].is_some_and(|v| v > 1) {
        return Err(Error::Candidate);
    }
    Ok(limits)
}
pub fn operations_features(s: &SnapshotReplyV3, c: Candidate) -> Result<Features, Error> {
    operations_candidate(operations_base(s)?, s.domain, c)
}

fn operations_base(s: &SnapshotReplyV3) -> Result<Features, Error> {
    if !s.valid() {
        return Err(Error::Format);
    }
    // Conservative startup subset: require the four declared domain
    // observations. Missing common fields (including reserved 23) stay 0.
    if s.present_mask() & 0xf00 != 0xf00 {
        return Err(Error::Missing);
    }
    let mut f = Features::new();
    f.values[usize::from(s.domain - 1)] = 256;
    for (i, &h) in COMMON_H.iter().enumerate() {
        f.set(16 + i, s.fields[i], h);
    }
    for (i, &h) in DOMAIN_H[usize::from(s.domain - 1)].iter().enumerate() {
        f.set(24 + i, s.fields[8 + i], h);
        f.values[32 + i] = 256;
    }
    Ok(f)
}

fn operations_candidate(mut f: Features, domain: u16, c: Candidate) -> Result<Features, Error> {
    let (h1, h2) = action_limits(domain, c)?;
    f.set(40, Some(1), 255);
    f.set(41, Some(c.a1), h1);
    f.set(42, c.a2, h2);
    f.values[48] = 256;
    f.values[49] = 256;
    if c.a2.is_some() {
        f.values[50] = 256;
    }
    for (i, h) in [900, 262144, 100000, 1].into_iter().enumerate() {
        f.set(56 + i, c.cpu[i], h);
        if c.cpu[i].is_some() {
            f.values[60 + i] = 256;
        }
    }
    Ok(f)
}
/// The kind is bound by EL1 to an observation, not selected from a score.
/// Required fields mask is likewise from the authenticated security view.
pub fn security_features(s: &SnapshotReplyV3, kind: u16, required: u16) -> Result<Features, Error> {
    if !s.valid() {
        return Err(Error::Format);
    }
    let domain = match kind {
        1 => 12,
        2 => 3,
        3 => 10,
        4 => 11,
        5 => 4,
        _ => return Err(Error::Scope),
    };
    if domain != s.domain {
        return Err(Error::Scope);
    }
    if required & !0xf7f != 0 || required & 0xf00 == 0 || s.present_mask() & required != required {
        return Err(Error::Missing);
    }
    let mut f = Features::new();
    f.values[usize::from(kind - 1)] = 256;
    f.values[5 + usize::from(s.domain - 1)] = 256;
    for (i, &h) in COMMON_H.iter().enumerate() {
        f.set(20 + i, s.fields[i], h);
        if s.fields[i].is_some() {
            f.values[32 + i] = 256;
        }
    }
    for (i, &h) in DOMAIN_H[usize::from(s.domain - 1)].iter().enumerate() {
        f.set(28 + i, s.fields[8 + i], h);
        if s.fields[8 + i].is_some() {
            f.values[40 + i] = 256;
        }
    }
    Ok(f)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scores {
    pub count: u8,
    pub recommended_index: u16,
    pub scores: [i16; 32],
}
/// Exact integer MLP, stable first-maximum tie break; no policy action.
pub fn score_operations(
    s: &SnapshotReplyV3,
    candidates: &[Candidate],
    parameters: &[u8],
) -> Result<Scores, Error> {
    if candidates.is_empty() || candidates.len() > 32 {
        return Err(Error::Candidate);
    }
    let model = integer_model::Model::parse(parameters).map_err(|_| Error::Model)?;
    // All candidates refer to this same immutable snapshot. Preserve model
    // and snapshot error precedence, then validate every candidate as before.
    let base = operations_base(s)?;
    let mut out = Scores {
        count: candidates.len() as u8,
        recommended_index: 0,
        scores: [0; 32],
    };
    let mut shared = None;
    for (i, &c) in candidates.iter().enumerate() {
        if candidates[..i]
            .iter()
            .any(|old| old.a1 == c.a1 && old.a2 == c.a2)
        {
            return Err(Error::Candidate);
        }
        let features = operations_candidate(base, s.domain, c)?;
        out.scores[i] = if candidates.len() == 1 {
            model.score(&features.values)
        } else {
            shared
                .get_or_insert_with(|| model.prepare_prefix(&features.values))
                .score(&features.values)
        };
        if out.scores[i] > out.scores[usize::from(out.recommended_index)] {
            out.recommended_index = i as u16;
        }
    }
    Ok(out)
}
pub fn score_security(
    s: &SnapshotReplyV3,
    kind: u16,
    required: u16,
    parameters: &[u8],
) -> Result<(i16, u8), Error> {
    let f = security_features(s, kind, required)?;
    let score = integer_model::Model::parse(parameters)
        .map_err(|_| Error::Model)?
        .score(&f.values);
    let severity = match score {
        ..=0 => 0,
        1..=255 => 1,
        256..=511 => 2,
        _ => 3,
    };
    Ok((score, severity))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(domain: u16) -> SnapshotReplyV3 {
        SnapshotReplyV3 {
            snapshot_seq: 2,
            boot_epoch: 3,
            ledger_generation: 4,
            core_generation: 5,
            target_id: 6,
            target_generation: 7,
            sampled_ns: 100,
            domain,
            fields: [
                Some(500),
                Some(1000),
                Some(32),
                Some(250),
                Some(750),
                None,
                Some(50000),
                None,
                Some(32),
                Some(64),
                Some(1),
                Some(1),
            ],
        }
    }
    #[test]
    fn wave10_normalization_matches_wide_reference_and_clipping() {
        let mut seed = 0x7c50_189d_2468_1357u64;
        let scales = [
            1,
            2,
            3,
            8,
            16,
            50,
            64,
            100,
            128,
            255,
            256,
            400,
            512,
            750,
            900,
            1000,
            4096,
            5000,
            10000,
            100000,
            262144,
            1000000,
            u64::MAX / 513,
            u64::MAX / 513 + 1,
            u64::MAX,
        ];
        for h in scales {
            for v in [0, 1, h / 2, h - 1, h, h.saturating_add(1), u64::MAX] {
                let mut f = Features::new();
                f.set(63, Some(v), h);
                let expected =
                    ((512u128 * u128::from(v.min(h)) + u128::from(h)) / (2 * u128::from(h))) as i16;
                assert_eq!(f.values[63], expected);
                assert_eq!(f.clipped, if v > h { 1 << 63 } else { 0 });
            }
            for _ in 0..256 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let v = if seed & 1 == 0 { seed % h } else { seed };
                let mut f = Features::new();
                f.set(17, Some(v), h);
                let expected =
                    ((512u128 * u128::from(v.min(h)) + u128::from(h)) / (2 * u128::from(h))) as i16;
                assert_eq!(f.values[17], expected);
                assert_eq!(f.clipped, if v > h { 1 << 17 } else { 0 });
            }
        }
        let mut f = Features::new();
        f.set(23, None, 0);
        assert_eq!(f, Features::new());
    }

    #[test]
    fn exact_snapshot_shape_presence_width_and_age() {
        let s = sample(1);
        let wire = s.encode().unwrap();
        assert_eq!(SnapshotReplyV3::decode(&wire), Ok(s));
        let scope = SnapshotScope {
            snapshot_seq: 2,
            boot_epoch: 3,
            ledger_generation: 4,
            core_generation: 5,
            target_id: 6,
            target_generation: 7,
            domain: 1,
        };
        assert_eq!(s.check(scope, 100), Ok(()));
        assert_eq!(s.check(scope, 100 + MAX_AGE_NS), Err(Error::Stale));
        assert_eq!(
            s.check(
                SnapshotScope {
                    target_generation: 8,
                    ..scope
                },
                100
            ),
            Err(Error::Scope)
        );
        for at in [4, 6, 66, 68, 72, 75] {
            let mut b = wire;
            b[at] ^= 1;
            assert!(SnapshotReplyV3::decode(&b).is_err());
        }
        let mut b = wire;
        b[72 + 7 * 16 + 2] = 1;
        assert!(SnapshotReplyV3::decode(&b).is_err());
        let mut b = wire;
        b[72 + 5 * 16 + 8] = 1;
        assert!(SnapshotReplyV3::decode(&b).is_err());
        let mut s = s;
        s.fields[8] = Some(65536);
        assert!(s.encode().is_err());
    }
    #[test]
    fn fixed_feature_layout_no_legacy_coreset_or_missing_domain() {
        let mut s = sample(1);
        s.fields[8] = Some(100);
        let c = Candidate {
            a1: 4,
            a2: None,
            cpu: [None; 4],
        };
        let f = operations_features(&s, c).unwrap();
        assert_eq!(
            (
                f.values[0],
                f.values[15],
                f.values[16],
                f.values[22],
                f.values[23]
            ),
            (256, 0, 128, 128, 0)
        );
        assert_eq!(
            (
                f.values[24],
                f.values[32],
                f.values[40],
                f.values[41],
                f.values[48],
                f.values[49]
            ),
            (256, 256, 1, 128, 256, 256)
        );
        assert_eq!(f.clipped, 1 << 24);
        assert_eq!(
            operations_features(
                &s,
                Candidate {
                    cpu: [Some(1), None, None, None],
                    ..c
                }
            ),
            Err(Error::Candidate)
        );
        s.fields[8] = None;
        assert_eq!(operations_features(&s, c), Err(Error::Missing));
        let mut s = sample(1);
        s.domain = 16;
        assert_eq!(operations_features(&s, c), Err(Error::Format));
    }
    #[test]
    fn operations_scores_match_full_inference_for_every_weight_candidate() {
        let s = sample(1);
        let candidates = [1, 2, 4, 8].map(|a1| Candidate {
            a1,
            a2: None,
            cpu: [None; 4],
        });
        let mut p = [0u8; integer_model::MODEL_BYTES];
        p[0] = 64;
        p[41] = 64;
        p[2048] = 64;
        p[2560] = 64;
        let result = score_operations(&s, &candidates, &p).unwrap();
        let model = integer_model::Model::parse(&p).unwrap();
        for (i, &candidate) in candidates.iter().enumerate() {
            let f = operations_features(&s, candidate).unwrap();
            assert_eq!(result.scores[i], model.score(&f.values));
        }
        assert_eq!(result.count, 4);
        assert_eq!(result.recommended_index, 3);
        assert_eq!(result.scores[3], 512);
    }

    #[test]
    fn wave7_snapshot_reuse_preserves_all_domain_scores_and_error_order() {
        let mut parameters = [0u8; integer_model::MODEL_BYTES];
        for (i, w) in parameters[..2576].iter_mut().enumerate() {
            *w = ((i * 73 % 31) as i8 - 15) as u8;
        }
        let model = integer_model::Model::parse(&parameters).unwrap();
        for domain in 1..=15 {
            let mut s = sample(domain);
            s.fields[0] = Some(u64::MAX);
            let actions: &[(u64, Option<u64>)] = match domain {
                1 | 2 | 8 | 11 => &[(1, None), (2, None), (4, None), (8, None)],
                3 => &[
                    (64, Some(4)),
                    (256, Some(16)),
                    (1024, Some(32)),
                    (4096, Some(64)),
                ],
                4 => &[(0, Some(4)), (2, Some(8)), (8, Some(16)), (16, Some(32))],
                5 => &[(8, Some(1)), (32, Some(4)), (64, Some(8)), (128, Some(16))],
                6 => &[(1, None), (2, None), (3, None)],
                7 => &[(0, None), (50, None), (200, None), (1000, None)],
                9 => &[(100, None), (250, None), (500, None), (750, None)],
                10 => &[(1, None), (4, None), (8, None), (16, None)],
                12 => &[(4, None), (8, None), (16, None), (32, None)],
                13 => &[(50, None), (100, None), (200, None), (400, None)],
                14 => &[(0, None), (1, None), (2, None)],
                15 => &[(1, None), (8, None), (32, None), (64, None)],
                _ => unreachable!(),
            };
            let mut candidates = [Candidate {
                a1: 0,
                a2: None,
                cpu: [None; 4],
            }; 4];
            for mask in 1usize..1usize << actions.len() {
                let mut count = 0;
                for (i, &(a1, a2)) in actions.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        candidates[count] = Candidate {
                            a1,
                            a2,
                            cpu: if domain == 6 {
                                [Some(a1 * 100), Some(262145), None, Some(1)]
                            } else {
                                [None; 4]
                            },
                        };
                        count += 1;
                    }
                }
                for reverse in [false, true] {
                    let batch = &mut candidates[..count];
                    if reverse {
                        batch.reverse();
                    }
                    let mut expected = Scores {
                        count: count as u8,
                        recommended_index: 0,
                        scores: [0; 32],
                    };
                    for (i, &candidate) in batch.iter().enumerate() {
                        let f = operations_features(&s, candidate).unwrap();
                        assert_ne!(f.clipped & (1 << 16), 0);
                        expected.scores[i] = model.score(&f.values);
                        if expected.scores[i]
                            > expected.scores[usize::from(expected.recommended_index)]
                        {
                            expected.recommended_index = i as u16;
                        }
                    }
                    assert_eq!(score_operations(&s, batch, &parameters), Ok(expected));
                }
            }
            let c = candidates[0];
            assert_eq!(
                score_operations(&s, &[c, c], &parameters),
                Err(Error::Candidate)
            );
            let bad = Candidate { a1: u64::MAX, ..c };
            assert_eq!(
                score_operations(&s, &[c, bad], &parameters),
                Err(Error::Candidate)
            );
            s.fields[8] = None;
            assert_eq!(
                score_operations(&s, &[bad], &parameters),
                Err(Error::Missing)
            );
            assert_eq!(score_operations(&s, &[bad], &[]), Err(Error::Model));
            assert_eq!(score_operations(&s, &[], &[]), Err(Error::Candidate));
            s.domain = 16;
            assert_eq!(score_operations(&s, &[c], &parameters), Err(Error::Format));
        }
    }

    #[test]
    fn security_redaction_and_integer_inference_are_advisory_only() {
        let mut s = sample(12);
        s.fields[9] = None;
        let f = security_features(&s, 1, 0x100).unwrap();
        assert_eq!(
            (
                f.values[0],
                f.values[16],
                f.values[20],
                f.values[25],
                f.values[37]
            ),
            (256, 256, 128, 0, 0)
        );
        assert_eq!((f.values[40], f.values[41]), (256, 0));
        assert!(f.values[44..].iter().all(|v| *v == 0));
        assert_eq!(security_features(&s, 2, 0x100), Err(Error::Scope));
        assert_eq!(security_features(&s, 1, 0x300), Err(Error::Missing));
        let mut p = [0u8; integer_model::MODEL_BYTES];
        p[0] = 64;
        p[2048] = 64;
        p[2560] = 64;
        assert_eq!(score_security(&s, 1, 0x100, &p), Ok((256, 2)));
        let ops = sample(1);
        let c = Candidate {
            a1: 1,
            a2: None,
            cpu: [None; 4],
        };
        let result = score_operations(&ops, &[c, Candidate { a1: 8, ..c }], &p).unwrap();
        assert_eq!(
            (result.recommended_index, result.scores[0], result.scores[1]),
            (0, 256, 256)
        );
        assert_eq!(score_operations(&ops, &[c, c], &p), Err(Error::Candidate));
    }
}
