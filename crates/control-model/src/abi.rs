//! Independent versioned control-service ABI. 64 signed Q15 input values;
//! masks/epochs/timestamps remain exact integers and are NEVER cast into Q15.
pub const CPUS: usize = 8;
pub const FEATURES: usize = 64;
pub const INPUT_WORDS: usize = 44;
pub const OUTPUT_WORDS: usize = 24;
pub const MAGIC: u64 = 0x4359584149435031;
pub const VERSION: u64 = 1;
pub const INPUT_VA: u64 = 0xa0000;
pub const OUTPUT_VA: u64 = 0xa1000;
pub const STACK_TOP: u64 = 0xb9000;
pub const SUBMIT_SVC: u64 = 0x431;
pub const MODEL_BYTES: &[u8] = include_bytes!("../../../ports/control-service/core-head.bin");
pub const MODEL_SHA256: [u64; 4] = include!("../../../ports/control-service/model-sha256.rs");
// Stable schema identifiers are the first 32 bytes of the SHA256 of the checked
// in UTF-8 schema descriptions, generated with the model, not inferred at runtime.
pub const SCHEMA_SHA256: [u64; 4] = include!("../../../ports/control-service/schema-sha256.rs");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Version,
    Schema,
    Model,
    Stale,
    Expired,
    Denied,
    Busy,
    Capacity,
    Clock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub boot: u64,
    pub controller: u64,
    pub model_epoch: u64,
    pub resources: u64,
    pub cores: u64,
    pub sequence: u64,
    pub window: u64,
    pub sample_start: u64,
    pub sampled_at: u64,
    pub issued: u64,
    pub expires: u64,
    pub online: u64,
    pub control: u64,
    pub protected_control: u64,
    pub protected_business: u64,
    /// [pressure, latency, estimated benefit, business pressure, 4 reserved],
    /// then per-core [online, control, protected_control, protected_business,
    /// spare capacity, energy efficiency, reserved]. All normalized to Q15.
    pub features: [i16; FEATURES],
}
impl Input {
    pub fn validate(&self) -> Result<(), Error> {
        if [
            self.boot,
            self.controller,
            self.model_epoch,
            self.resources,
            self.cores,
            self.sequence,
        ]
        .contains(&0)
            || self.window == 0
            || self.sample_start >= self.sampled_at
            || self.sampled_at > self.issued
            || self.expires <= self.issued
            || self.online == 0
            || self.online & !255 != 0
            || self.control == 0
            || self.control & !self.online != 0
            || self.control == self.online
            || self.protected_control & !self.control != 0
            || self.protected_business & !(self.online & !self.control) != 0
            || self.features.iter().any(|x| *x < 0)
            || self.features[4..8].iter().any(|x| *x != 0)
        {
            return Err(Error::Invalid);
        }
        for i in 0..CPUS {
            let f = &self.features[8 + i * 7..15 + i * 7];
            for (v, mask) in f[..4].iter().zip([
                self.online,
                self.control,
                self.protected_control,
                self.protected_business,
            ]) {
                if *v != if mask & (1 << i) != 0 { 32767 } else { 0 } {
                    return Err(Error::Invalid);
                }
            }
            if f[6] != 0 || (self.online & (1 << i) == 0 && f[4..].iter().any(|x| *x != 0)) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> [u64; INPUT_WORDS] {
        let mut w = [0; INPUT_WORDS];
        w[..16].copy_from_slice(&[
            MAGIC,
            VERSION,
            self.boot,
            self.controller,
            self.model_epoch,
            self.resources,
            self.cores,
            self.sequence,
            self.issued,
            self.expires,
            self.online,
            self.control,
            self.protected_control,
            self.protected_business,
            FEATURES as u64,
            self.window,
        ]);
        w[16..20].copy_from_slice(&MODEL_SHA256);
        w[20..24].copy_from_slice(&SCHEMA_SHA256);
        w[24] = self.sample_start;
        w[25] = self.sampled_at;
        for (i, f) in self.features.iter().enumerate() {
            w[28 + i / 4] |= (*f as u16 as u64) << (16 * (i % 4));
        }
        w
    }
    pub fn decode(w: [u64; INPUT_WORDS]) -> Result<Self, Error> {
        if w[0] != MAGIC || w[1] != VERSION {
            return Err(Error::Version);
        }
        if w[14] != FEATURES as u64 || w[26] != 0 || w[27] != 0 || w[20..24] != SCHEMA_SHA256 {
            return Err(Error::Schema);
        }
        if w[16..20] != MODEL_SHA256 {
            return Err(Error::Model);
        }
        let s = Self {
            boot: w[2],
            controller: w[3],
            model_epoch: w[4],
            resources: w[5],
            cores: w[6],
            sequence: w[7],
            window: w[15],
            sample_start: w[24],
            sampled_at: w[25],
            issued: w[8],
            expires: w[9],
            online: w[10],
            control: w[11],
            protected_control: w[12],
            protected_business: w[13],
            features: core::array::from_fn(|i| ((w[28 + i / 4] >> (16 * (i % 4))) as u16) as i16),
        };
        s.validate()?;
        Ok(s)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    pub boot: u64,
    pub model_epoch: u64,
    pub resources: u64,
    pub window: u64,
    pub sequence: u64,
    pub controller: u64,
    pub cores: u64,
    pub desired: u64,
    pub logits: [i16; 3],
    pub action: u64,
}
impl Output {
    pub fn encode(&self) -> [u64; OUTPUT_WORDS] {
        let mut w = [0; OUTPUT_WORDS];
        w[..8].copy_from_slice(&[
            MAGIC,
            VERSION,
            self.sequence,
            self.controller,
            self.cores,
            self.desired,
            self.action,
            self.boot,
        ]);
        w[8..12].copy_from_slice(&MODEL_SHA256);
        w[12..16].copy_from_slice(&SCHEMA_SHA256);
        for (dst, v) in w[16..19].iter_mut().zip(self.logits) {
            *dst = v as u16 as u64;
        }
        w[19] = self.model_epoch;
        w[20] = self.resources;
        w[21] = self.window;
        w
    }
    pub fn decode(w: [u64; OUTPUT_WORDS]) -> Result<Self, Error> {
        if w[0] != MAGIC || w[1] != VERSION {
            return Err(Error::Version);
        }
        if w[22..].iter().any(|x| *x != 0) || w[12..16] != SCHEMA_SHA256 {
            return Err(Error::Schema);
        }
        if w[8..12] != MODEL_SHA256 {
            return Err(Error::Model);
        }
        if [w[2], w[3], w[4], w[7], w[19], w[20], w[21]].contains(&0)
            || w[6] > 2
            || w[16..19].iter().any(|x| *x > u16::MAX as u64)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            boot: w[7],
            model_epoch: w[19],
            resources: w[20],
            window: w[21],
            sequence: w[2],
            controller: w[3],
            cores: w[4],
            desired: w[5],
            action: w[6],
            logits: core::array::from_fn(|i| w[16 + i] as u16 as i16),
        })
    }
}
