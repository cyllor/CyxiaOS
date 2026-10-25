//! Immutable, ordered replay splits. This module never synthesizes labels.
use super::{
    Error, FAMILIES, SchemaBinding, Schemas, learning_config, reward::AcceptedSample, reward_schema,
};
use sha2::{Digest, Sha256};

pub const MAX_TRAINING: usize = 512;
pub const MAX_VALIDATION: usize = 256;
pub const MIN_TRAINING_PER_FAMILY: usize = 8;
pub const MIN_VALIDATION_PER_FAMILY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataManifest {
    pub seed: u64,
    pub training_count: u16,
    pub validation_count: u16,
    pub training_per_family: [u16; FAMILIES],
    pub validation_per_family: [u16; FAMILIES],
    pub training_hash: [u8; 32],
    pub validation_hash: [u8; 32],
    pub hash: [u8; 32],
    pub reward_schema: SchemaBinding,
    pub learning_config: SchemaBinding,
    pub feature_schema: SchemaBinding,
    pub action_schema: SchemaBinding,
}

/// A shared borrow freezes sample contents and order for training/validation.
/// Labels can only be constructed by reward::pair after protected attestation.
pub struct FrozenData<'a> {
    training: &'a [AcceptedSample],
    validation: &'a [AcceptedSample],
    manifest: DataManifest,
}

fn sample_hash(hash: &mut Sha256, sample: &AcceptedSample) {
    hash.update(sample.family.domain.to_le_bytes());
    hash.update(sample.family.kind.to_le_bytes());
    hash.update(sample.group.seed.to_le_bytes());
    hash.update(sample.group.workload);
    hash.update(sample.group.initial_image);
    for value in sample.input {
        hash.update(value.to_le_bytes());
    }
    hash.update(sample.reward.value.to_bits().to_le_bytes());
    hash.update(sample.evidence);
}

fn inspect(
    samples: &[AcceptedSample],
    minimum: usize,
    cap: usize,
    schemas: Schemas,
) -> Result<([u16; FAMILIES], [u8; 32]), Error> {
    if samples.len() > cap {
        return Err(Error::Capacity);
    }
    let mut counts = [0u16; FAMILIES];
    let mut hash = Sha256::new();
    hash.update(b"CYXIA_ORDERED_REPLAY_SAMPLES_1.3\0");
    hash.update((samples.len() as u64).to_le_bytes());
    for (index, sample) in samples.iter().enumerate() {
        if sample.reward_schema != reward_schema()
            || sample.learning_config != learning_config()
            || sample.feature_schema != schemas.feature
            || sample.action_schema != schemas.action
        {
            return Err(Error::Schema);
        }
        if sample.evidence == [0; 32]
            || samples[..index]
                .iter()
                .any(|old| old.evidence == sample.evidence)
        {
            return Err(Error::Evidence);
        }
        counts[sample.family.index()?] += 1;
        sample_hash(&mut hash, sample);
    }
    if counts.iter().any(|n| usize::from(*n) < minimum) {
        return Err(Error::DataIncomplete);
    }
    Ok((counts, hash.finalize().into()))
}

impl<'a> FrozenData<'a> {
    pub fn freeze(
        training: &'a [AcceptedSample],
        validation: &'a [AcceptedSample],
        seed: u64,
        schemas: Schemas,
    ) -> Result<Self, Error> {
        schemas.validate()?;
        let (training_per_family, training_hash) =
            inspect(training, MIN_TRAINING_PER_FAMILY, MAX_TRAINING, schemas)?;
        let (validation_per_family, validation_hash) = inspect(
            validation,
            MIN_VALIDATION_PER_FAMILY,
            MAX_VALIDATION,
            schemas,
        )?;
        // The whole (seed, workload, initial image) group is exclusive. Merely
        // using a different action, request id, trial id or label is not a split.
        for train in training {
            if validation.iter().any(|valid| train.group == valid.group) {
                return Err(Error::GroupOverlap);
            }
            if validation
                .iter()
                .any(|valid| train.evidence == valid.evidence)
            {
                return Err(Error::Evidence);
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"CYXIA_FROZEN_DATA_1.3\0");
        hash.update(seed.to_le_bytes());
        hash.update(training_hash);
        hash.update(validation_hash);
        for s in [
            schemas.feature,
            schemas.action,
            schemas.reward,
            schemas.learning,
        ] {
            hash.update(s.version.to_le_bytes());
            hash.update(s.hash);
        }
        let manifest = DataManifest {
            seed,
            training_count: training.len() as u16,
            validation_count: validation.len() as u16,
            training_per_family,
            validation_per_family,
            training_hash,
            validation_hash,
            hash: hash.finalize().into(),
            reward_schema: reward_schema(),
            learning_config: learning_config(),
            feature_schema: schemas.feature,
            action_schema: schemas.action,
        };
        Ok(Self {
            training,
            validation,
            manifest,
        })
    }
    pub fn manifest(&self) -> DataManifest {
        self.manifest
    }
    pub fn training(&self) -> &'a [AcceptedSample] {
        self.training
    }
    pub fn validation(&self) -> &'a [AcceptedSample] {
        self.validation
    }
}

// The owning role also accounts the borrowed replay samples in its 1 MiB
// workspace. These caps leave room for the model, optimizer and validation.
const _: () =
    assert!((MAX_TRAINING + MAX_VALIDATION) * core::mem::size_of::<AcceptedSample>() < 768 * 1024);
