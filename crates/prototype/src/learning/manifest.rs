//! Hash-bound, immutable model packages. A useful seed is still untrained.
use super::{
    Error, Schemas,
    train::{self, TrainedModel, TrainingRecord},
    validate::ReferenceSuite,
};
use crate::{features, model::MODEL_BYTES};
use sha2::{Digest, Sha256};
pub use super::seed::UNTRAINED_SEED0_BYTES;

/// Operator/package ABI, independent of the outer Plan/Shared IPC ABI.
pub const RUNTIME_ABI: u32 = 1;
pub const SHAPE: [u16; 4] = [64, 32, 16, 1];
pub const MAX_WORKSPACE: u32 = 1024 * 1024;

pub fn normalization() -> [u64; 76] {
    let mut values = [0; 76];
    values[..8].copy_from_slice(&features::COMMON_LIMITS);
    for (i, limits) in features::DOMAIN_LIMITS.iter().enumerate() {
        values[8 + i * 4..12 + i * 4].copy_from_slice(limits);
    }
    values[72..].copy_from_slice(&features::TARGET_LIMITS);
    values
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Explicit engineering initialization, never an admissible Active model.
    Untrained {
        seed: u64,
    },
    Learned(TrainingRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelManifest {
    pub runtime_abi: u32,
    pub parameters_hash: [u8; 32],
    pub schemas: Schemas,
    pub normalization: [u64; 76],
    pub shape: [u16; 4],
    pub workspace_bytes: u32,
    pub reference_vectors_hash: [u8; 32],
    pub frozen_layers_hash: [u8; 32],
    pub origin: Origin,
}

impl ModelManifest {
    pub fn untrained(
        seed: &UntrainedSeed,
        schemas: Schemas,
        vectors: &ReferenceSuite<'_>,
        workspace_bytes: u32,
    ) -> Result<Self, Error> {
        Self::make(
            seed.bytes(),
            schemas,
            vectors,
            workspace_bytes,
            Origin::Untrained { seed: seed.seed },
        )
    }
    pub fn learned(
        model: &TrainedModel,
        schemas: Schemas,
        vectors: &ReferenceSuite<'_>,
        workspace_bytes: u32,
    ) -> Result<Self, Error> {
        Self::make(
            model.bytes(),
            schemas,
            vectors,
            workspace_bytes,
            Origin::Learned(model.record()),
        )
    }
    fn make(
        bytes: &[u8; MODEL_BYTES],
        schemas: Schemas,
        vectors: &ReferenceSuite<'_>,
        workspace_bytes: u32,
        origin: Origin,
    ) -> Result<Self, Error> {
        schemas.validate()?;
        if workspace_bytes == 0 || workspace_bytes > MAX_WORKSPACE {
            return Err(Error::Capacity);
        }
        let parameters_hash = Sha256::digest(bytes).into();
        if vectors.parameters_hash != parameters_hash {
            return Err(Error::Manifest);
        }
        Ok(Self {
            runtime_abi: RUNTIME_ABI,
            parameters_hash,
            schemas,
            normalization: normalization(),
            shape: SHAPE,
            workspace_bytes,
            reference_vectors_hash: vectors.hash()?,
            frozen_layers_hash: train::frozen_hash(bytes),
            origin,
        })
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_MODEL_MANIFEST_1.3\0");
        hash.update(self.runtime_abi.to_le_bytes());
        hash.update(self.parameters_hash);
        for schema in [
            self.schemas.feature,
            self.schemas.action,
            self.schemas.reward,
            self.schemas.learning,
        ] {
            hash.update(schema.version.to_le_bytes());
            hash.update(schema.hash);
        }
        for value in self.normalization {
            hash.update(value.to_le_bytes());
        }
        for value in self.shape {
            hash.update(value.to_le_bytes());
        }
        hash.update(self.workspace_bytes.to_le_bytes());
        hash.update(self.reference_vectors_hash);
        hash.update(self.frozen_layers_hash);
        match self.origin {
            Origin::Untrained { seed } => {
                hash.update([0]);
                hash.update(seed.to_le_bytes());
            }
            Origin::Learned(record) => {
                hash.update([1]);
                hash.update(record.parent_hash);
                hash.update(record.frozen_layers_hash);
                hash.update(record.data.seed.to_le_bytes());
                hash.update(record.data.training_count.to_le_bytes());
                hash.update(record.data.validation_count.to_le_bytes());
                for value in record
                    .data
                    .training_per_family
                    .into_iter()
                    .chain(record.data.validation_per_family)
                {
                    hash.update(value.to_le_bytes());
                }
                hash.update(record.data.training_hash);
                hash.update(record.data.validation_hash);
                hash.update(record.data.hash);
                for schema in [
                    record.data.feature_schema,
                    record.data.action_schema,
                    record.data.reward_schema,
                    record.data.learning_config,
                ] {
                    hash.update(schema.version.to_le_bytes());
                    hash.update(schema.hash);
                }
                hash.update(record.steps.to_le_bytes());
                hash.update(record.shadow_parameters_hash);
                hash.update(record.result_hash);
            }
        }
        hash.finalize().into()
    }
}

/// Shared borrows guarantee that the parameters cannot be edited after sealing.
pub struct SealedModel<'a> {
    bytes: &'a [u8; MODEL_BYTES],
    manifest: ModelManifest,
    manifest_hash: [u8; 32],
}
impl<'a> SealedModel<'a> {
    pub(super) fn from_worker(bytes: &'a [u8; MODEL_BYTES], manifest: ModelManifest, manifest_hash: [u8; 32]) -> Self {
        Self { bytes, manifest, manifest_hash }
    }
    pub fn seal(
        bytes: &'a [u8; MODEL_BYTES],
        manifest: ModelManifest,
        expected: Schemas,
        vectors: &ReferenceSuite<'_>,
    ) -> Result<Self, Error> {
        expected.validate()?;
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        if manifest.runtime_abi != RUNTIME_ABI
            || manifest.parameters_hash != hash
            || manifest.schemas != expected
            || manifest.shape != SHAPE
            || manifest.normalization != normalization()
            || manifest.workspace_bytes == 0
            || manifest.workspace_bytes > MAX_WORKSPACE
            || manifest.reference_vectors_hash != vectors.hash()?
            || manifest.frozen_layers_hash != train::frozen_hash(bytes)
        {
            return Err(Error::Manifest);
        }
        // This does not narrow the ABI's frozen int32 biases, only b3 learning.
        train::Parameters::from_model(bytes)?;
        if let Origin::Learned(record) = manifest.origin {
            if record.result_hash != hash
                || record.frozen_layers_hash != manifest.frozen_layers_hash
                || record.parent_hash == [0; 32]
                || record.steps != record.data.training_count
                || record.shadow_parameters_hash == [0; 32]
                || record.data.reward_schema != expected.reward
                || record.data.learning_config != expected.learning
                || record.data.feature_schema != expected.feature
                || record.data.action_schema != expected.action
            {
                return Err(Error::Manifest);
            }
        }
        super::validate::verify_reference(bytes, vectors)?;
        let manifest_hash = manifest.hash();
        Ok(Self {
            bytes,
            manifest,
            manifest_hash,
        })
    }
    pub fn bytes(&self) -> &'a [u8; MODEL_BYTES] {
        self.bytes
    }
    pub fn manifest(&self) -> &ModelManifest {
        &self.manifest
    }
    pub fn hash(&self) -> [u8; 32] {
        self.manifest_hash
    }
}

pub struct UntrainedSeed {
    bytes: [u8; MODEL_BYTES],
    seed: u64,
}
impl UntrainedSeed {
    /// An explicit, deterministic starting point with action/target-sensitive
    /// frozen layers. No rewards, samples or trained provenance are invented.
    pub const fn new(seed: u64) -> Self {
        Self { bytes: super::seed::untrained_seed_bytes(seed), seed }
    }
    pub const fn bytes(&self) -> &[u8; MODEL_BYTES] {
        &self.bytes
    }
    pub const fn seed(&self) -> u64 {
        self.seed
    }
    pub const fn status(&self) -> Error {
        Error::Untrained
    }
}
