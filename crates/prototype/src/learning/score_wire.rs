//! Compact scoring transport. It carries no reward rows and cannot be decoded
//! as a trained model or independent-validation report. Input custody and the
//! validated-candidate capability remain exclusively with the protected owner.
use super::{
    Error, Family,
    governance::CanaryPermit,
    worker_wire::{self as w, JobBinding, JobIdentity, Role},
};
use crate::{
    domains::ObjectKey,
    model::MODEL_BYTES,
    policy::{ModelBinding, Snapshot},
};
use sha2::{Digest, Sha256};

pub const HEADER_BYTES: usize = w::HEADER_BYTES;
pub const RESULT_BYTES: usize = w::RESULT_BYTES;
pub const PARENT: usize = HEADER_BYTES;
pub const CANDIDATE: usize = PARENT + MODEL_BYTES;
pub const INPUTS: usize = CANDIDATE + MODEL_BYTES;
pub const MAX_INPUT_BYTES: usize = INPUTS + 32 * 128;
const MAGIC: &[u8; 8] = b"CXSCOI01";
const RESULT_MAGIC: &[u8; 8] = b"CXSCOO01";
pub fn is_input(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(MAGIC)
}
pub fn is_output(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(RESULT_MAGIC)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub role: Role,
    pub binding: JobBinding,
    pub parent_hash: [u8; 32],
    pub candidate_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub registration_hash: [u8; 32],
    pub data_hash: [u8; 32],
    pub set_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub model: ModelBinding,
    pub snapshot: Snapshot,
    pub target: ObjectKey,
    pub count: u16,
    pub family: Family,
    pub workspace_bytes: u32,
    pub prepared_ns: u64,
    pub permit: Option<CanaryPermit>,
}
impl Header {
    pub fn input_len(self) -> usize {
        INPUTS + usize::from(self.count) * 128
    }
    pub fn shape(self) -> Result<(), Error> {
        self.binding.validate()?;
        self.family.index()?;
        if self.count == 0
            || self.count > 32
            || self.workspace_bytes == 0
            || self.workspace_bytes > 1024 * 1024
            || self.target.id == 0
            || self.target.generation == 0
            || self.model.generation == 0
            || self.model.schema_hash == [0; 32]
            || self.model.generation != self.binding.model_generation
            || self.snapshot.sequence == 0
            || self.snapshot.ledger_generation == 0
            || self.snapshot.core_generation != self.binding.core_generation
            || self.prepared_ns < self.snapshot.taken_ns
            || self.prepared_ns - self.snapshot.taken_ns > 50_000_000
            || [
                self.parent_hash,
                self.candidate_hash,
                self.manifest_hash,
                self.registration_hash,
                self.data_hash,
                self.set_hash,
            ]
            .contains(&[0; 32])
        {
            return Err(Error::Evidence);
        }
        match (self.role, self.permit) {
            (Role::ShadowScore, None) if self.model.model_hash == self.parent_hash => {}
            (Role::CanaryScore, Some(p))
                if p.id != 0
                    && p.active_generation == self.model.generation
                    && p.candidate_hash == self.candidate_hash
                    && self.model.model_hash == self.candidate_hash
                    && p.target == self.target
                    && p.windows >= 100
                    && p.windows <= 300
                    && p.quota <= p.windows
                    && p.quota != 0
                    && self.prepared_ns >= p.start_ns
                    && self.prepared_ns < p.expires_ns
                    && p.expires_ns
                        == p.start_ns
                            .checked_add(u64::from(p.windows) * 100_000_000)
                            .ok_or(Error::Numeric)?
                    && self.family
                        == (Family {
                            domain: 15,
                            kind: 1,
                        }) => {}
            _ => return Err(Error::State),
        }
        Ok(())
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < HEADER_BYTES || input.len() > MAX_INPUT_BYTES {
            return Err(Error::Capacity);
        }
        if !is_input(input)
            || w::u16_at(input, 8)? != w::ABI
            || w::u32_at(input, 12)? as usize != input.len()
            || w::u16_at(input, 470)? != 0
            || w::u32_at(input, 476)? != 0
            || input[580..HEADER_BYTES].iter().any(|v| *v != 0)
        {
            return Err(Error::Schema);
        }
        let flag = w::u64_at(input, 488)?;
        let permit = match flag {
            0 if input[496..580].iter().all(|v| *v == 0) => None,
            1 => Some(CanaryPermit {
                id: w::u64_at(input, 496)?,
                active_generation: w::u64_at(input, 504)?,
                candidate_hash: w::array_at(input, 512)?,
                target: ObjectKey {
                    id: w::u64_at(input, 544)?,
                    generation: w::u64_at(input, 552)?,
                },
                start_ns: w::u64_at(input, 560)?,
                expires_ns: w::u64_at(input, 568)?,
                windows: w::u16_at(input, 576)?,
                quota: w::u16_at(input, 578)?,
            }),
            _ => return Err(Error::Evidence),
        };
        let h = Self {
            role: Role::decode(w::u16_at(input, 10)?)?,
            binding: w::decode_binding(&input[16..120])?,
            parent_hash: w::array_at(input, 120)?,
            candidate_hash: w::array_at(input, 152)?,
            manifest_hash: w::array_at(input, 184)?,
            registration_hash: w::array_at(input, 216)?,
            data_hash: w::array_at(input, 248)?,
            set_hash: w::array_at(input, 280)?,
            payload_hash: w::array_at(input, 312)?,
            model: ModelBinding {
                model_hash: w::array_at(input, 344)?,
                schema_hash: w::array_at(input, 376)?,
                generation: w::u64_at(input, 408)?,
            },
            snapshot: Snapshot {
                sequence: w::u64_at(input, 416)?,
                taken_ns: w::u64_at(input, 424)?,
                ledger_generation: w::u64_at(input, 432)?,
                core_generation: w::u64_at(input, 440)?,
            },
            target: ObjectKey {
                id: w::u64_at(input, 448)?,
                generation: w::u64_at(input, 456)?,
            },
            count: w::u16_at(input, 464)?,
            family: Family {
                domain: w::u16_at(input, 466)?,
                kind: w::u16_at(input, 468)?,
            },
            workspace_bytes: w::u32_at(input, 472)?,
            prepared_ns: w::u64_at(input, 480)?,
            permit,
        };
        h.shape()?;
        if h.input_len() != input.len() || h.payload_hash == [0; 32] {
            return Err(Error::Evidence);
        }
        Ok(h)
    }
    pub(crate) fn encode(self, output: &mut [u8]) -> Result<(), Error> {
        self.shape()?;
        if output.len() < HEADER_BYTES {
            return Err(Error::Capacity);
        }
        output[..HEADER_BYTES].fill(0);
        output[..8].copy_from_slice(MAGIC);
        w::put16(output, 8, w::ABI);
        w::put16(output, 10, self.role as u16);
        w::put32(output, 12, self.input_len() as u32);
        w::encode_binding(&mut output[16..120], self.binding);
        for (p, hash) in [
            (120, self.parent_hash),
            (152, self.candidate_hash),
            (184, self.manifest_hash),
            (216, self.registration_hash),
            (248, self.data_hash),
            (280, self.set_hash),
            (312, self.payload_hash),
            (344, self.model.model_hash),
            (376, self.model.schema_hash),
        ] {
            output[p..p + 32].copy_from_slice(&hash);
        }
        for (p, value) in [
            (408, self.model.generation),
            (416, self.snapshot.sequence),
            (424, self.snapshot.taken_ns),
            (432, self.snapshot.ledger_generation),
            (440, self.snapshot.core_generation),
            (448, self.target.id),
            (456, self.target.generation),
            (480, self.prepared_ns),
        ] {
            w::put64(output, p, value);
        }
        w::put16(output, 464, self.count);
        w::put16(output, 466, self.family.domain);
        w::put16(output, 468, self.family.kind);
        w::put32(output, 472, self.workspace_bytes);
        if let Some(p) = self.permit {
            w::put64(output, 488, 1);
            for (offset, value) in [
                (496, p.id),
                (504, p.active_generation),
                (544, p.target.id),
                (552, p.target.generation),
                (560, p.start_ns),
                (568, p.expires_ns),
            ] {
                w::put64(output, offset, value);
            }
            output[512..544].copy_from_slice(&p.candidate_hash);
            w::put16(output, 576, p.windows);
            w::put16(output, 578, p.quota);
        }
        Ok(())
    }
    pub fn identity(self, input: &[u8]) -> Result<JobIdentity, Error> {
        if input.len() != self.input_len() || input.len() < HEADER_BYTES {
            return Err(Error::Capacity);
        }
        Ok(identity(
            self.role,
            self.binding,
            Sha256::digest(&input[..HEADER_BYTES]).into(),
            self.payload_hash,
        ))
    }
}
fn identity(
    role: Role,
    binding: JobBinding,
    header_hash: [u8; 32],
    payload_hash: [u8; 32],
) -> JobIdentity {
    let mut h = Sha256::new();
    h.update(b"CYXIA_SCORE_WORKER_INPUT_1.3\0");
    h.update(header_hash);
    h.update(payload_hash);
    JobIdentity {
        role,
        binding,
        header_hash,
        payload_hash,
        input_hash: h.finalize().into(),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub identity: JobIdentity,
    pub registration_hash: [u8; 32],
    pub set_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub steps: u64,
    pub count: u16,
    pub selected: u16,
    pub prior: [i16; 32],
    pub scores: [i16; 32],
}
impl Report {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.shape()?;
        if out.len() < RESULT_BYTES {
            return Err(Error::Capacity);
        }
        out[..RESULT_BYTES].fill(0);
        out[..8].copy_from_slice(RESULT_MAGIC);
        w::put16(out, 8, w::ABI);
        w::put16(out, 10, self.identity.role as u16);
        w::put32(out, 12, RESULT_BYTES as u32);
        w::encode_binding(&mut out[16..120], self.identity.binding);
        for (p, h) in [
            (120, self.identity.header_hash),
            (152, self.identity.payload_hash),
            (184, self.registration_hash),
            (216, self.set_hash),
            (248, self.transcript_hash),
        ] {
            out[p..p + 32].copy_from_slice(&h);
        }
        w::put64(out, 280, self.steps);
        w::put16(out, 288, self.count);
        w::put16(out, 290, self.selected);
        for i in 0..32 {
            w::put16(out, 296 + 2 * i, self.prior[i] as u16);
            w::put16(out, 360 + 2 * i, self.scores[i] as u16);
        }
        Ok(RESULT_BYTES)
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != RESULT_BYTES {
            return Err(Error::Capacity);
        }
        if !is_output(input)
            || w::u16_at(input, 8)? != w::ABI
            || w::u32_at(input, 12)? as usize != RESULT_BYTES
            || w::u32_at(input, 292)? != 0
            || input[424..].iter().any(|v| *v != 0)
        {
            return Err(Error::Schema);
        }
        let role = Role::decode(w::u16_at(input, 10)?)?;
        let binding = w::decode_binding(&input[16..120])?;
        let mut r = Self {
            identity: identity(
                role,
                binding,
                w::array_at(input, 120)?,
                w::array_at(input, 152)?,
            ),
            registration_hash: w::array_at(input, 184)?,
            set_hash: w::array_at(input, 216)?,
            transcript_hash: w::array_at(input, 248)?,
            steps: w::u64_at(input, 280)?,
            count: w::u16_at(input, 288)?,
            selected: w::u16_at(input, 290)?,
            prior: [0; 32],
            scores: [0; 32],
        };
        for i in 0..32 {
            r.prior[i] = w::u16_at(input, 296 + 2 * i)? as i16;
            r.scores[i] = w::u16_at(input, 360 + 2 * i)? as i16;
        }
        r.shape()?;
        Ok(r)
    }
    fn shape(&self) -> Result<(), Error> {
        self.identity.binding.validate()?;
        if !matches!(self.identity.role, Role::ShadowScore | Role::CanaryScore)
            || self.count == 0
            || self.count > 32
            || self.selected >= self.count
            || self.steps == 0
            || [
                self.identity.header_hash,
                self.identity.payload_hash,
                self.registration_hash,
                self.set_hash,
                self.transcript_hash,
            ]
            .contains(&[0; 32])
            || self.prior[usize::from(self.count)..]
                .iter()
                .chain(&self.scores[usize::from(self.count)..])
                .any(|v| *v != 0)
        {
            return Err(Error::Evidence);
        }
        let best = (0..usize::from(self.count))
            .max_by_key(|i| (self.scores[*i], usize::MAX - *i))
            .ok_or(Error::Evidence)?;
        if best != usize::from(self.selected) {
            return Err(Error::Evidence);
        }
        Ok(())
    }
}
