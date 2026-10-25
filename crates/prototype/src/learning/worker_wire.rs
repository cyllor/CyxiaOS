//! Explicit little-endian numerical-worker transport. Decoding these bytes
//! never constructs an AcceptedSample or attests a replay. Only the protected
//! owner retains the prepared job that can authorize a completed worker result.
use super::{
    Error, FAMILIES, Family, ReplayGroup, SchemaBinding, Schemas,
    data::{DataManifest, MAX_TRAINING, MAX_VALIDATION},
    manifest::{self, ModelManifest, Origin},
    softfloat::F64,
    train::TrainingRecord,
    validate::{Comparison, Mse, ReferenceCase, ReferenceSelection},
};
use crate::{
    domains::ObjectKey,
    model::{MODEL_BYTES, Trace},
};
use sha2::{Digest, Sha256};

pub const ABI: u16 = 1;
pub const INPUT_LIMIT: usize = 512 * 1024;
pub const OUTPUT_LIMIT: usize = 16 * 1024;
pub const HEADER_BYTES: usize = 1024;
pub const ROW_BYTES: usize = 144;
pub const PROVENANCE_BYTES: usize = 104;
pub const REFERENCE_BYTES: usize = 240;
pub const SELECTION_BYTES: usize = 8;
pub const PROBE_BYTES: usize = 16 + 32 * 128;
pub const RESULT_BYTES: usize = 4096;
pub const MANIFEST_BYTES: usize = 324;
pub const RECORD_BYTES: usize = 456;
pub const SELFTEST_BYTES: usize = 32;
pub const SELFTEST_MAGIC: u64 = u64::from_le_bytes(*b"CXSELF01");
pub const SELFTEST_CASES: u64 = 14;
pub const SELFTEST_SUCCESS: u64 = 0;
const MAGIC: &[u8; 8] = b"CXLRN001";
const RESULT_MAGIC: &[u8; 8] = b"CXLRNO01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Role {
    Training = 1,
    Validation = 2,
    ShadowScore = 3,
    CanaryScore = 4,
}
impl Role {
    pub(crate) fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Training),
            2 => Ok(Self::Validation),
            3 => Ok(Self::ShadowScore),
            4 => Ok(Self::CanaryScore),
            _ => Err(Error::Schema),
        }
    }
}

/// The context/image are registered by EL1. A worker may echo this structure;
/// it has no authority to choose the context that actually completed its job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobBinding {
    pub boot_epoch: u64,
    pub job_id: u64,
    pub controller_epoch: u64,
    pub core_generation: u64,
    pub model_generation: u64,
    pub data_generation: u64,
    pub role_context: ObjectKey,
    pub image_hash: [u8; 32],
    pub ledger_generation: u64,
}
impl JobBinding {
    pub fn validate(self) -> Result<(), Error> {
        if [
            self.boot_epoch,
            self.job_id,
            self.controller_epoch,
            self.core_generation,
            self.model_generation,
            self.data_generation,
            self.role_context.id,
            self.role_context.generation,
            self.ledger_generation,
        ]
        .contains(&0)
            || self.image_hash == [0; 32]
        {
            Err(Error::Evidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub role: Role,
    pub binding: JobBinding,
    pub parent_hash: [u8; 32],
    pub candidate_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub reference_hash: [u8; 32],
    pub probes_hash: [u8; 32],
    pub model_manifest_hash: [u8; 32],
    pub workspace_bytes: u32,
    pub references: u16,
    pub selections: u16,
    pub probes: u16,
    pub data: DataManifest,
    pub record: Option<TrainingRecord>,
    pub model_workspace_bytes: u32,
}
impl Header {
    /// Constant-size header checks only; the independently scheduled worker
    /// checks every payload byte and numerical result before producing a report.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < HEADER_BYTES || input.len() > INPUT_LIMIT {
            return Err(Error::Capacity);
        }
        if &input[..8] != MAGIC || u16_at(input, 8)? != ABI {
            return Err(Error::Schema);
        }
        let role = Role::decode(u16_at(input, 10)?)?;
        let binding = JobBinding {
            boot_epoch: u64_at(input, 16)?,
            job_id: u64_at(input, 24)?,
            controller_epoch: u64_at(input, 32)?,
            core_generation: u64_at(input, 40)?,
            model_generation: u64_at(input, 48)?,
            data_generation: u64_at(input, 56)?,
            role_context: ObjectKey {
                id: u64_at(input, 64)?,
                generation: u64_at(input, 72)?,
            },
            image_hash: array_at(input, 80)?,
            ledger_generation: u64_at(input, 812)?,
        };
        binding.validate()?;
        let data = decode_data(&input[352..676])?;
        if u16_at(input, 340)? != data.training_count
            || u16_at(input, 342)? != data.validation_count
            || array_at::<32>(input, 176)? != data.hash
            || u16_at(input, 350)? != 0
            || input[820..HEADER_BYTES].iter().any(|b| *b != 0)
        {
            return Err(Error::Evidence);
        }
        let record = if role == Role::Validation {
            Some(decode_record_tail(&input[676..808], data)?)
        } else {
            if input[676..812].iter().any(|b| *b != 0) {
                return Err(Error::Evidence);
            }
            None
        };
        let header = Self {
            role,
            binding,
            parent_hash: array_at(input, 112)?,
            candidate_hash: array_at(input, 144)?,
            payload_hash: array_at(input, 208)?,
            reference_hash: array_at(input, 240)?,
            probes_hash: array_at(input, 272)?,
            model_manifest_hash: array_at(input, 304)?,
            workspace_bytes: u32_at(input, 336)?,
            references: u16_at(input, 344)?,
            selections: u16_at(input, 346)?,
            probes: u16_at(input, 348)?,
            data,
            record,
            model_workspace_bytes: u32_at(input, 808)?,
        };
        let layout = header.layout()?;
        if input.len() != layout.total || u32_at(input, 12)? as usize != layout.total {
            return Err(Error::Evidence);
        }
        header.shape()?;
        Ok(header)
    }
    pub fn schemas(&self) -> Schemas {
        Schemas {
            feature: self.data.feature_schema,
            action: self.data.action_schema,
            reward: self.data.reward_schema,
            learning: self.data.learning_config,
        }
    }
    pub fn layout(&self) -> Result<Layout, Error> {
        Layout::new(
            self.data.training_count,
            self.data.validation_count,
            self.references,
            self.selections,
            self.probes,
        )
    }
    pub fn shape(&self) -> Result<(), Error> {
        self.binding.validate()?;
        self.schemas().validate()?;
        if self.workspace_bytes == 0
            || self.workspace_bytes > manifest::MAX_WORKSPACE
            || self.parent_hash == [0; 32]
            || self.data.hash == [0; 32]
        {
            return Err(Error::Manifest);
        }
        match self.role {
            Role::Training => {
                if self.candidate_hash != [0; 32]
                    || self.reference_hash != [0; 32]
                    || self.model_manifest_hash != [0; 32]
                    || self.probes_hash != [0; 32]
                    || self.references != 0
                    || self.selections != 0
                    || self.probes != 0
                    || self.record.is_some()
                    || self.model_workspace_bytes != 0
                {
                    return Err(Error::Manifest);
                }
            }
            Role::Validation => {
                if self.candidate_hash == [0; 32]
                    || self.reference_hash == [0; 32]
                    || self.model_manifest_hash == [0; 32]
                    || self.probes_hash == [0; 32]
                    || self.references == 0
                    || self.selections == 0
                    || self.probes == 0
                    || self.model_workspace_bytes == 0
                    || self.model_workspace_bytes > manifest::MAX_WORKSPACE
                {
                    return Err(Error::Manifest);
                }
                let record = self.record.ok_or(Error::Untrained)?;
                if record.data != self.data
                    || record.parent_hash != self.parent_hash
                    || record.result_hash != self.candidate_hash
                    || record.steps != self.data.training_count
                    || record.shadow_parameters_hash == [0; 32]
                {
                    return Err(Error::Evidence);
                }
                if self.candidate_manifest()?.hash() != self.model_manifest_hash {
                    return Err(Error::Manifest);
                }
            }
            Role::ShadowScore | Role::CanaryScore => return Err(Error::Schema),
        }
        Ok(())
    }
    pub fn candidate_manifest(&self) -> Result<ModelManifest, Error> {
        let record = self.record.ok_or(Error::Untrained)?;
        Ok(ModelManifest {
            runtime_abi: manifest::RUNTIME_ABI,
            parameters_hash: self.candidate_hash,
            schemas: self.schemas(),
            normalization: manifest::normalization(),
            shape: manifest::SHAPE,
            workspace_bytes: self.model_workspace_bytes,
            reference_vectors_hash: self.reference_hash,
            frozen_layers_hash: record.frozen_layers_hash,
            origin: Origin::Learned(record),
        })
    }
    pub(crate) fn encode(&self, out: &mut [u8]) -> Result<(), Error> {
        if out.len() < HEADER_BYTES {
            return Err(Error::Capacity);
        }
        // Exactly one header, never the entire 512 KiB input region.
        out[..HEADER_BYTES].fill(0);
        out[..8].copy_from_slice(MAGIC);
        put16(out, 8, ABI);
        put16(out, 10, self.role as u16);
        put32(out, 12, self.layout()?.total as u32);
        let b = self.binding;
        for (i, value) in [
            b.boot_epoch,
            b.job_id,
            b.controller_epoch,
            b.core_generation,
            b.model_generation,
            b.data_generation,
            b.role_context.id,
            b.role_context.generation,
        ]
        .into_iter()
        .enumerate()
        {
            put64(out, 16 + i * 8, value);
        }
        out[80..112].copy_from_slice(&b.image_hash);
        for (offset, hash) in [
            (112, self.parent_hash),
            (144, self.candidate_hash),
            (176, self.data.hash),
            (208, self.payload_hash),
            (240, self.reference_hash),
            (272, self.probes_hash),
            (304, self.model_manifest_hash),
        ] {
            out[offset..offset + 32].copy_from_slice(&hash);
        }
        put32(out, 336, self.workspace_bytes);
        put16(out, 340, self.data.training_count);
        put16(out, 342, self.data.validation_count);
        put16(out, 344, self.references);
        put16(out, 346, self.selections);
        put16(out, 348, self.probes);
        encode_data(&mut out[352..676], self.data);
        if let Some(record) = self.record {
            encode_record_tail(&mut out[676..808], record);
        }
        put32(out, 808, self.model_workspace_bytes);
        put64(out, 812, b.ledger_generation);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub parent: usize,
    pub candidate: usize,
    pub rows: usize,
    pub provenance: usize,
    pub references: usize,
    pub selections: usize,
    pub probes: usize,
    pub total: usize,
    pub row_count: usize,
}
impl Layout {
    pub fn new(
        training: u16,
        validation: u16,
        references: u16,
        selections: u16,
        probes: u16,
    ) -> Result<Self, Error> {
        if training as usize > MAX_TRAINING
            || validation as usize > MAX_VALIDATION
            || references > 128
            || selections > 32
            || probes > 72
        {
            return Err(Error::Capacity);
        }
        let row_count = training as usize + validation as usize;
        let parent = HEADER_BYTES;
        let candidate = parent + MODEL_BYTES;
        let rows = candidate + MODEL_BYTES;
        let provenance = rows + row_count * ROW_BYTES;
        let reference_offset = provenance + row_count * PROVENANCE_BYTES;
        let selection_offset = reference_offset + references as usize * REFERENCE_BYTES;
        let probe_offset = selection_offset + selections as usize * SELECTION_BYTES;
        let total = probe_offset + probes as usize * PROBE_BYTES;
        if total > INPUT_LIMIT {
            return Err(Error::Capacity);
        }
        Ok(Self {
            parent,
            candidate,
            rows,
            provenance,
            references: reference_offset,
            selections: selection_offset,
            probes: probe_offset,
            total,
            row_count,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumericRow {
    pub family: Family,
    pub input: [i16; 64],
    pub reward: F64,
    pub group: ReplayGroup,
    pub evidence: [u8; 32],
}
pub struct Packet<'a> {
    pub header: Header,
    pub layout: Layout,
    bytes: &'a [u8],
}
impl<'a> Packet<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = Header::decode(bytes)?;
        Ok(Self {
            layout: header.layout()?,
            header,
            bytes,
        })
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn parent(&self) -> &'a [u8; MODEL_BYTES] {
        self.bytes[self.layout.parent..self.layout.candidate]
            .try_into()
            .expect("checked layout")
    }
    pub fn candidate(&self) -> &'a [u8; MODEL_BYTES] {
        self.bytes[self.layout.candidate..self.layout.rows]
            .try_into()
            .expect("checked layout")
    }
    pub fn row(&self, index: usize) -> Result<NumericRow, Error> {
        if index >= self.layout.row_count {
            return Err(Error::Order);
        }
        let start = self.layout.rows + index * ROW_BYTES;
        let p = self.layout.provenance + index * PROVENANCE_BYTES;
        if u32_at(self.bytes, start + 4)? != 0 {
            return Err(Error::Evidence);
        }
        let family = Family {
            domain: u16_at(self.bytes, start)?,
            kind: u16_at(self.bytes, start + 2)?,
        };
        family.index()?;
        let mut input = [0; 64];
        for (i, value) in input.iter_mut().enumerate() {
            *value = u16_at(self.bytes, start + 8 + i * 2)? as i16;
        }
        Ok(NumericRow {
            family,
            input,
            reward: F64::from_bits_checked(u64_at(self.bytes, start + 136)?)?,
            group: ReplayGroup {
                seed: u64_at(self.bytes, p)?,
                workload: array_at(self.bytes, p + 8)?,
                initial_image: array_at(self.bytes, p + 40)?,
            },
            evidence: array_at(self.bytes, p + 72)?,
        })
    }
    pub fn reference(&self, index: usize) -> Result<ReferenceCase, Error> {
        if index >= self.header.references as usize {
            return Err(Error::Order);
        }
        let p = self.layout.references + index * REFERENCE_BYTES;
        if self.bytes[p + 226..p + REFERENCE_BYTES]
            .iter()
            .any(|v| *v != 0)
        {
            return Err(Error::Evidence);
        }
        let mut input = [0; 64];
        let mut h1 = [0; 32];
        let mut h2 = [0; 16];
        for (i, v) in input
            .iter_mut()
            .chain(h1.iter_mut())
            .chain(h2.iter_mut())
            .enumerate()
        {
            *v = u16_at(self.bytes, p + i * 2)? as i16;
        }
        Ok(ReferenceCase {
            input,
            trace: Trace {
                hidden1: h1,
                hidden2: h2,
                output: u16_at(self.bytes, p + 224)? as i16,
            },
        })
    }
    pub fn selection(&self, index: usize) -> Result<ReferenceSelection, Error> {
        if index >= self.header.selections as usize {
            return Err(Error::Order);
        }
        let p = self.layout.selections + index * SELECTION_BYTES;
        let selected = ReferenceSelection {
            first: u16_at(self.bytes, p)?,
            count: u16_at(self.bytes, p + 2)?,
            selected: u16_at(self.bytes, p + 4)?,
        };
        if u16_at(self.bytes, p + 6)? != 0
            || selected.count == 0
            || selected.count > 32
            || selected.selected >= selected.count
            || u32::from(selected.first) + u32::from(selected.count)
                > u32::from(self.header.references)
        {
            return Err(Error::Evidence);
        }
        Ok(selected)
    }
    pub fn probe(&self, index: usize) -> Result<(Family, usize), Error> {
        if index >= self.header.probes as usize {
            return Err(Error::Order);
        }
        let p = self.layout.probes + index * PROBE_BYTES;
        let family = Family {
            domain: u16_at(self.bytes, p)?,
            kind: u16_at(self.bytes, p + 2)?,
        };
        family.index()?;
        let count = u16_at(self.bytes, p + 4)? as usize;
        if !(2..=32).contains(&count)
            || self.bytes[p + 6..p + 16].iter().any(|b| *b != 0)
            || self.bytes[p + 16 + count * 128..p + PROBE_BYTES]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(Error::Evidence);
        }
        Ok((family, count))
    }
    pub fn probe_input(&self, index: usize, candidate: usize) -> Result<[i16; 64], Error> {
        if index >= self.header.probes as usize {
            return Err(Error::Order);
        }
        let p = self.layout.probes + index * PROBE_BYTES;
        if candidate >= u16_at(self.bytes, p + 4)? as usize || candidate >= 32 {
            return Err(Error::Order);
        }
        let mut input = [0; 64];
        for (i, value) in input.iter_mut().enumerate() {
            *value = u16_at(self.bytes, p + 16 + candidate * 128 + i * 2)? as i16;
        }
        Ok(input)
    }
    pub fn identity(&self) -> JobIdentity {
        identity(
            self.header,
            Sha256::digest(&self.bytes[..HEADER_BYTES]).into(),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobIdentity {
    pub role: Role,
    pub binding: JobBinding,
    pub header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub input_hash: [u8; 32],
}
pub(crate) fn identity(header: Header, header_hash: [u8; 32]) -> JobIdentity {
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_WORKER_INPUT_1.3\0");
    hash.update(header_hash);
    hash.update(header.payload_hash);
    JobIdentity {
        role: header.role,
        binding: header.binding,
        header_hash,
        payload_hash: header.payload_hash,
        input_hash: hash.finalize().into(),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub steps: u64,
    pub rows: u16,
    pub training: u16,
    pub validation: u16,
    pub references: u16,
    pub selections: u16,
    pub probes: u16,
    pub probe_candidates: u16,
    pub golden_cases: u16,
}
/// A complete numerical transcript, not a trusted "PASS" flag.
pub struct Report {
    pub identity: JobIdentity,
    pub candidate_hash: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub registration_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub counts: Counts,
    pub record: TrainingRecord,
    pub comparison: Comparison,
    pub candidate: [u8; MODEL_BYTES],
}
impl Report {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < RESULT_BYTES {
            return Err(Error::Capacity);
        }
        out[..RESULT_BYTES].fill(0);
        out[..8].copy_from_slice(RESULT_MAGIC);
        put16(out, 8, ABI);
        put16(out, 10, self.identity.role as u16);
        put32(out, 12, RESULT_BYTES as u32);
        encode_binding(&mut out[16..120], self.identity.binding);
        for (p, hash) in [
            (120, self.identity.header_hash),
            (152, self.identity.payload_hash),
            (184, self.candidate_hash),
            (216, self.manifest_hash),
            (248, self.registration_hash),
            (280, self.transcript_hash),
        ] {
            out[p..p + 32].copy_from_slice(&hash);
        }
        put64(out, 312, self.counts.steps);
        for (i, count) in [
            self.counts.rows,
            self.counts.training,
            self.counts.validation,
            self.counts.references,
            self.counts.selections,
            self.counts.probes,
            self.counts.probe_candidates,
            self.counts.golden_cases,
        ]
        .into_iter()
        .enumerate()
        {
            put16(out, 320 + i * 2, count);
        }
        encode_record(&mut out[336..792], self.record);
        encode_mse(&mut out[792..980], self.comparison.old);
        encode_mse(&mut out[980..1168], self.comparison.new);
        out[1168..3940].copy_from_slice(&self.candidate);
        Ok(RESULT_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RESULT_BYTES {
            return Err(Error::Capacity);
        }
        if &bytes[..8] != RESULT_MAGIC
            || u16_at(bytes, 8)? != ABI
            || u32_at(bytes, 12)? as usize != RESULT_BYTES
            || bytes[3940..].iter().any(|b| *b != 0)
        {
            return Err(Error::Evidence);
        }
        let binding = decode_binding(&bytes[16..120])?;
        binding.validate()?;
        let role = Role::decode(u16_at(bytes, 10)?)?;
        let header_hash = array_at(bytes, 120)?;
        let payload_hash = array_at(bytes, 152)?;
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_WORKER_INPUT_1.3\0");
        hash.update(header_hash);
        hash.update(payload_hash);
        Ok(Self {
            identity: JobIdentity {
                role,
                binding,
                header_hash,
                payload_hash,
                input_hash: hash.finalize().into(),
            },
            candidate_hash: array_at(bytes, 184)?,
            manifest_hash: array_at(bytes, 216)?,
            registration_hash: array_at(bytes, 248)?,
            transcript_hash: array_at(bytes, 280)?,
            counts: Counts {
                steps: u64_at(bytes, 312)?,
                rows: u16_at(bytes, 320)?,
                training: u16_at(bytes, 322)?,
                validation: u16_at(bytes, 324)?,
                references: u16_at(bytes, 326)?,
                selections: u16_at(bytes, 328)?,
                probes: u16_at(bytes, 330)?,
                probe_candidates: u16_at(bytes, 332)?,
                golden_cases: u16_at(bytes, 334)?,
            },
            record: decode_record(&bytes[336..792])?,
            comparison: Comparison {
                old: decode_mse(&bytes[792..980])?,
                new: decode_mse(&bytes[980..1168])?,
            },
            candidate: array_at(bytes, 1168)?,
        })
    }
}

pub(crate) fn encode_data(out: &mut [u8], d: DataManifest) {
    put64(out, 0, d.seed);
    put16(out, 8, d.training_count);
    put16(out, 10, d.validation_count);
    for (i, n) in d
        .training_per_family
        .into_iter()
        .chain(d.validation_per_family)
        .enumerate()
    {
        put16(out, 12 + i * 2, n);
    }
    out[84..116].copy_from_slice(&d.training_hash);
    out[116..148].copy_from_slice(&d.validation_hash);
    out[148..180].copy_from_slice(&d.hash);
    for (i, s) in [
        d.feature_schema,
        d.action_schema,
        d.reward_schema,
        d.learning_config,
    ]
    .into_iter()
    .enumerate()
    {
        let p = 180 + i * 36;
        put32(out, p, s.version);
        out[p + 4..p + 36].copy_from_slice(&s.hash);
    }
}
pub(crate) fn decode_data(input: &[u8]) -> Result<DataManifest, Error> {
    if input.len() != MANIFEST_BYTES {
        return Err(Error::Capacity);
    }
    let mut train = [0; FAMILIES];
    let mut valid = [0; FAMILIES];
    for (i, n) in train.iter_mut().chain(valid.iter_mut()).enumerate() {
        *n = u16_at(input, 12 + i * 2)?;
    }
    let schema = |p| -> Result<SchemaBinding, Error> {
        Ok(SchemaBinding {
            version: u32_at(input, p)?,
            hash: array_at(input, p + 4)?,
        })
    };
    Ok(DataManifest {
        seed: u64_at(input, 0)?,
        training_count: u16_at(input, 8)?,
        validation_count: u16_at(input, 10)?,
        training_per_family: train,
        validation_per_family: valid,
        training_hash: array_at(input, 84)?,
        validation_hash: array_at(input, 116)?,
        hash: array_at(input, 148)?,
        feature_schema: schema(180)?,
        action_schema: schema(216)?,
        reward_schema: schema(252)?,
        learning_config: schema(288)?,
    })
}
fn encode_record_tail(out: &mut [u8], r: TrainingRecord) {
    out[..32].copy_from_slice(&r.parent_hash);
    out[32..64].copy_from_slice(&r.frozen_layers_hash);
    put16(out, 64, r.steps);
    put16(out, 66, 0);
    out[68..100].copy_from_slice(&r.shadow_parameters_hash);
    out[100..132].copy_from_slice(&r.result_hash);
}
fn decode_record_tail(input: &[u8], data: DataManifest) -> Result<TrainingRecord, Error> {
    if u16_at(input, 66)? != 0 {
        return Err(Error::Evidence);
    }
    Ok(TrainingRecord {
        parent_hash: array_at(input, 0)?,
        frozen_layers_hash: array_at(input, 32)?,
        data,
        steps: u16_at(input, 64)?,
        shadow_parameters_hash: array_at(input, 68)?,
        result_hash: array_at(input, 100)?,
    })
}
pub(crate) fn encode_record(out: &mut [u8], r: TrainingRecord) {
    encode_data(&mut out[..MANIFEST_BYTES], r.data);
    encode_record_tail(&mut out[MANIFEST_BYTES..RECORD_BYTES], r);
}
fn decode_record(input: &[u8]) -> Result<TrainingRecord, Error> {
    decode_record_tail(
        &input[MANIFEST_BYTES..RECORD_BYTES],
        decode_data(&input[..MANIFEST_BYTES])?,
    )
}
pub(crate) fn encode_binding(out: &mut [u8], b: JobBinding) {
    for (i, n) in [
        b.boot_epoch,
        b.job_id,
        b.controller_epoch,
        b.core_generation,
        b.model_generation,
        b.data_generation,
        b.role_context.id,
        b.role_context.generation,
        b.ledger_generation,
    ]
    .into_iter()
    .enumerate()
    {
        put64(out, i * 8, n);
    }
    out[72..104].copy_from_slice(&b.image_hash);
}
pub(crate) fn decode_binding(input: &[u8]) -> Result<JobBinding, Error> {
    Ok(JobBinding {
        boot_epoch: u64_at(input, 0)?,
        job_id: u64_at(input, 8)?,
        controller_epoch: u64_at(input, 16)?,
        core_generation: u64_at(input, 24)?,
        model_generation: u64_at(input, 32)?,
        data_generation: u64_at(input, 40)?,
        role_context: ObjectKey {
            id: u64_at(input, 48)?,
            generation: u64_at(input, 56)?,
        },
        ledger_generation: u64_at(input, 64)?,
        image_hash: array_at(input, 72)?,
    })
}
fn encode_mse(out: &mut [u8], mse: Mse) {
    put64(out, 0, mse.overall.to_bits());
    for (i, v) in mse.by_family.into_iter().enumerate() {
        put64(out, 8 + i * 8, v.to_bits());
    }
    for (i, v) in mse.counts.into_iter().enumerate() {
        put16(out, 152 + i * 2, v);
    }
}
fn decode_mse(input: &[u8]) -> Result<Mse, Error> {
    let mut mse = Mse {
        overall: F64::from_bits_checked(u64_at(input, 0)?)?,
        by_family: [F64::ZERO; FAMILIES],
        counts: [0; FAMILIES],
    };
    for i in 0..FAMILIES {
        mse.by_family[i] = F64::from_bits_checked(u64_at(input, 8 + i * 8)?)?;
        mse.counts[i] = u16_at(input, 152 + i * 2)?;
    }
    Ok(mse)
}
pub(crate) fn array_at<const N: usize>(bytes: &[u8], p: usize) -> Result<[u8; N], Error> {
    bytes
        .get(p..p.checked_add(N).ok_or(Error::Capacity)?)
        .ok_or(Error::Capacity)?
        .try_into()
        .map_err(|_| Error::Capacity)
}
pub(crate) fn u16_at(bytes: &[u8], p: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(array_at(bytes, p)?))
}
pub(crate) fn u32_at(bytes: &[u8], p: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(array_at(bytes, p)?))
}
pub(crate) fn u64_at(bytes: &[u8], p: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(array_at(bytes, p)?))
}
pub(crate) fn put16(out: &mut [u8], p: usize, n: u16) {
    out[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn put32(out: &mut [u8], p: usize, n: u32) {
    out[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn put64(out: &mut [u8], p: usize, n: u64) {
    out[p..p + 8].copy_from_slice(&n.to_le_bytes());
}

const _: () = assert!(
    HEADER_BYTES
        + 2 * MODEL_BYTES
        + 768 * (ROW_BYTES + PROVENANCE_BYTES)
        + 128 * REFERENCE_BYTES
        + 32 * SELECTION_BYTES
        + 72 * PROBE_BYTES
        <= INPUT_LIMIT
);
const _: () = assert!(RESULT_BYTES <= OUTPUT_LIMIT);

/// Constant-size role-dispatched native input inspection. All jobs retain the
/// same 1024-byte header boundary for the runtime's separately charged payload
/// hash, but score jobs have no data-row or training-manifest decoder.
pub fn input_identity(input: &[u8]) -> Result<(JobIdentity, u32), Error> {
    if super::score_wire::is_input(input) {
        let header = super::score_wire::Header::decode(input)?;
        Ok((header.identity(input)?, header.workspace_bytes))
    } else {
        let packet = Packet::decode(input)?;
        Ok((packet.identity(), packet.header.workspace_bytes))
    }
}
/// The native runtime authenticates complete immutable output bytes and the
/// last actual EL0 step. It does not manufacture a validation/score capability.
pub fn output_identity(output: &[u8]) -> Result<(JobIdentity, u64), Error> {
    if super::score_wire::is_output(output) {
        let report = super::score_wire::Report::decode(output)?;
        Ok((report.identity, report.steps))
    } else {
        let report = Report::decode(output)?;
        if !matches!(report.identity.role, Role::Training | Role::Validation) {
            return Err(Error::Schema);
        }
        Ok((report.identity, report.counts.steps))
    }
}
