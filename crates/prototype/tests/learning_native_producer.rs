//! Executes the actual sealed-source producer and real pool/trainer/verifier.
//! Time, service grants and the protected replay witness are synthetic here;
//! this host test is never a native replay dataset or an Active-model claim.
extern crate self as cyxia_arch_aarch64;
pub const HIGH: u64 = 0;
pub mod cpu {
    use core::sync::atomic::{AtomicUsize, Ordering};
    static SLOT: AtomicUsize = AtomicUsize::new(0);
    pub fn slot() -> usize {
        SLOT.load(Ordering::Acquire)
    }
    pub fn set(value: usize) {
        SLOT.store(value, Ordering::Release);
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/control_pool.rs"]
mod control_pool;
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    domains::{Error as DomainError, ObjectKey},
    learning::{
        self, Error, SchemaBinding, Schemas,
        manifest::{SealedModel, UntrainedSeed},
        reward::{self, ReplayKind, RewardWorkspace},
        train::Trainer,
        validate::ValidatedCandidate,
        worker_wire::JobBinding,
    },
    policy::ModelBinding,
};
use sha2::{Digest, Sha256};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split {
    Training,
    Validation,
}
fn native_error(error: DomainError) -> Error {
    match error {
        DomainError::Busy | DomainError::Again | DomainError::NotReady => Error::Unknown,
        DomainError::Stale => Error::Stale,
        _ => Error::Evidence,
    }
}
fn domain_error(error: Error) -> DomainError {
    match error {
        Error::Unknown => DomainError::Busy,
        Error::Capacity => DomainError::Capacity,
        Error::Stale => DomainError::Stale,
        _ => DomainError::Conflict,
    }
}
pub mod smp {
    pub mod prototype_runtime {
        use core::sync::atomic::{AtomicBool, Ordering};
        pub static PAID: AtomicBool = AtomicBool::new(true);
        pub fn authorize_learning_turn() -> Result<(), cyxia_prototype::domains::Error> {
            if crate::cpu::slot() == 1 && PAID.load(Ordering::Acquire) {
                Ok(())
            } else {
                Err(cyxia_prototype::domains::Error::Auth)
            }
        }
    }
}
pub mod domain_control {
    pub mod replay {
        use cyxia_prototype::{learning::Family, policy::CandidateSet};
        // Only a compile-time stand-in for the separately tested root owner;
        // this fixture never uses it to add a validation probe.
        pub struct ValidationProbe {
            family: Family,
            candidates: CandidateSet,
        }
        impl ValidationProbe {
            pub fn family(&self) -> Family {
                self.family
            }
            pub fn candidates(&self) -> &CandidateSet {
                &self.candidates
            }
        }
    }
    pub mod learning_driver {
        use crate::{control_pool as pool, *};
        use cyxia_prototype::{
            learning::{
                data::FrozenData, manifest::ModelManifest, train::TrainedModel,
                validate::ReferenceSuite,
            },
            model::MODEL_BYTES,
            policy::CandidateSet,
        };
        use std::sync::Mutex;
        pub const MAX_SOURCE_BYTES: usize = 400 * 1024;
        #[derive(Clone, Copy)]
        pub struct Source {
            pub key: ObjectKey,
            pub data: &'static FrozenData<'static>,
            pub validation: Option<ValidationSource>,
            pub backing: [Option<pool::Allocation>; 8],
        }
        #[derive(Clone, Copy)]
        pub struct ValidationSource {
            pub bytes: &'static [u8; MODEL_BYTES],
            pub manifest: &'static ModelManifest,
            pub vectors: &'static ReferenceSuite<'static>,
            pub probes: &'static [CandidateSet],
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Outcome {
            Trained {
                parameters: [u8; 32],
            },
            Validated {
                binding: ModelBinding,
                registration: [u8; 32],
            },
            Rejected(Error),
            Cancelled,
        }
        pub struct ValidationDelivery;
        #[derive(Clone, Copy)]
        pub struct Provider {
            pub owner: ObjectKey,
            pub next: fn() -> Result<Option<Source>, Error>,
            pub training: fn(JobBinding, TrainedModel) -> Result<(), (Error, TrainedModel)>,
            pub validation: fn(ValidationDelivery) -> Result<(), (Error, ValidationDelivery)>,
            pub returned: fn(ObjectKey, Outcome) -> Result<(), Error>,
        }
        static PROVIDER: Mutex<Option<Provider>> = Mutex::new(None);
        pub fn register(provider: Provider) -> Result<(), DomainError> {
            if cpu::slot() != 0 {
                return Err(DomainError::Auth);
            }
            *PROVIDER.lock().unwrap() = Some(provider);
            Ok(())
        }
        pub fn provider() -> Provider {
            PROVIDER
                .lock()
                .unwrap()
                .expect("actual producer registered")
        }
    }
}
pub mod learning_session {
    use crate::domain_control::learning_driver::ValidationDelivery;
    pub fn accept(
        delivery: ValidationDelivery,
    ) -> Result<(), (cyxia_prototype::learning::Error, ValidationDelivery)> {
        Err((cyxia_prototype::learning::Error::State, delivery))
    }
}
#[allow(dead_code)]
#[path = "../../../kernel/src/learning_replay/data.rs"]
mod producer;
fn schemas() -> Schemas {
    Schemas {
        feature: SchemaBinding {
            version: 13,
            hash: Sha256::digest(include_bytes!("../src/features.rs")).into(),
        },
        action: SchemaBinding {
            version: 13,
            hash: Sha256::digest(include_bytes!("../src/policy_wire.rs")).into(),
        },
        reward: learning::reward_schema(),
        learning: learning::learning_config(),
    }
}
fn job() -> JobBinding {
    JobBinding {
        boot_epoch: 1,
        job_id: 1,
        controller_epoch: 1,
        core_generation: 1,
        model_generation: 1,
        data_generation: 1,
        role_context: ObjectKey {
            id: 7,
            generation: 1,
        },
        image_hash: [9; 32],
        ledger_generation: 1,
    }
}
#[test]
fn real_checked_pairs_freeze_and_deliver_trained_and_validated_sources() {
    use domain_control::learning_driver::Outcome;
    cpu::set(0);
    producer::init().unwrap();
    let provider = domain_control::learning_driver::provider();
    assert!((provider.next)().is_err());
    cpu::set(1);
    assert!((provider.next)().unwrap().is_none());
    let mut workspace = RewardWorkspace::new();
    // A genuine reset mismatch must exclude the pair but permit a fresh
    // baseline/candidate execution. It must not strand the held baseline or
    // let a different workload discard another group's capability.
    support::with_trials_schemas(
        support::FAMILIES[1],
        1,
        9000,
        Default::default(),
        schemas(),
        |candidate, baseline| {
            let checked = reward::verify_replay(
                baseline,
                ReplayKind::Baseline,
                &support::TestAuthority,
                &mut workspace,
            )?;
            let original_hash = checked.evidence_hash();
            let checked = producer::test_support::with_gate(|| {
                match producer::accept_bounded(checked, Split::Training, None) {
                    Err(producer::AcceptFailure::Busy(checked)) => checked,
                    _ => panic!("actual data-gate contention must retain the checked capability"),
                }
            });
            assert_eq!(checked.evidence_hash(), original_hash);
            assert!(!producer::status()?.pending_baseline);
            assert!(producer::accept_bounded(checked, Split::Training, None).is_ok());
            // An already retained baseline is a real collection-state Unknown,
            // not a try-lock miss. It must never acquire the retry classification.
            let duplicate = reward::verify_replay(
                baseline,
                ReplayKind::Baseline,
                &support::TestAuthority,
                &mut workspace,
            )?;
            match producer::accept_bounded(duplicate, Split::Training, None) {
                Err(producer::AcceptFailure::Rejected(Error::Unknown, original)) => {
                    assert_eq!(original.evidence_hash(), original_hash);
                }
                _ => panic!("actual Unknown was mistaken for a transient data gate"),
            }
            let changed = reward::Trial {
                group: learning::ReplayGroup {
                    initial_image: [42; 32],
                    ..candidate.group
                },
                ..*candidate
            };
            let checked = reward::verify_replay(
                &changed,
                ReplayKind::Candidate,
                &support::TestAuthority,
                &mut workspace,
            )?;
            assert_eq!(
                producer::accept(
                    checked,
                    Split::Training,
                    Some(candidate.adoptions[0].candidates)
                )
                .err()
                .map(|v| v.0),
                Some(Error::Evidence)
            );
            assert!(producer::status()?.pending_baseline);
            assert_eq!(producer::status()?.paired, 0);
            assert_eq!(
                producer::retry_pair(support::FAMILIES[0], changed.group),
                Err(Error::Conflict)
            );
            assert_eq!(
                producer::retry_pair(
                    changed.family,
                    learning::ReplayGroup {
                        seed: 99,
                        ..changed.group
                    }
                ),
                Err(Error::Conflict)
            );
            producer::retry_pair(changed.family, changed.group)?;
            assert!(!producer::status()?.pending_baseline);
            assert_eq!(producer::status()?.paired, 0);
            Ok(())
        },
    )
    .unwrap();
    let mut id = 1;
    for family in support::FAMILIES {
        for group in 1..=12 {
            let split = if group <= 8 {
                Split::Training
            } else {
                Split::Validation
            };
            support::with_trials_schemas(
                family,
                group,
                id,
                support::Faults {
                    saturated_cpu: true,
                    ..Default::default()
                },
                schemas(),
                |candidate, baseline| {
                    let checked = reward::verify_replay(
                        baseline,
                        ReplayKind::Baseline,
                        &support::TestAuthority,
                        &mut workspace,
                    )?;
                    producer::accept(checked, split, None).map_err(|(e, _)| e)?;
                    assert!(producer::status()?.pending_baseline);
                    let checked = reward::verify_replay(
                        candidate,
                        ReplayKind::Candidate,
                        &support::TestAuthority,
                        &mut workspace,
                    )?;
                    producer::accept(checked, split, Some(candidate.adoptions[0].candidates))
                        .map_err(|(e, _)| e)?;
                    Ok(())
                },
            )
            .unwrap();
            id += 1;
            if id < 217 {
                assert!((provider.next)().unwrap().is_none());
            }
            if id == 2 {
                support::with_trials_schemas(
                    family,
                    group,
                    1000,
                    Default::default(),
                    schemas(),
                    |_, baseline| {
                        let checked = reward::verify_replay(
                            baseline,
                            ReplayKind::Baseline,
                            &support::TestAuthority,
                            &mut workspace,
                        )?;
                        let error = producer::accept(checked, Split::Validation, None)
                            .err()
                            .map(|v| v.0);
                        assert_eq!(error, Some(Error::GroupOverlap));
                        Ok(())
                    },
                )
                .unwrap();
            }
        }
    }
    let status = producer::status().unwrap();
    assert_eq!(status.training, [8; 18]);
    assert_eq!(status.validation, [4; 18]);
    assert_eq!(status.paired, 216);
    assert_eq!(status.phase, producer::Phase::Freeze);
    while producer::control_step().unwrap() {}
    let source = (provider.next)().unwrap().unwrap();
    assert!(source.validation.is_none());
    assert_eq!(source.data.training().len(), 144);
    assert_eq!(source.data.validation().len(), 72);
    for bank in source.backing.iter().flatten() {
        let pin = control_pool::pin_readonly(*bank).unwrap();
        assert!(control_pool::write(*bank, 0, &[0xff]).is_err());
        control_pool::unpin(&pin).unwrap();
    }
    assert!((provider.next)().unwrap().is_none());
    let seed = UntrainedSeed::new(0);
    let mut trainer = Trainer::start(seed.bytes(), source.data).unwrap();
    while trainer.step_next().unwrap() {}
    let trained = trainer.finish().unwrap();
    let parameters = trained.record().result_hash;
    let mut invalid = job();
    invalid.data_generation = 0;
    let trained = match (provider.training)(invalid, trained) {
        Err((Error::Manifest, trained)) => trained,
        _ => panic!("bad job lost model custody"),
    };
    (provider.training)(job(), trained)
        .map_err(|(e, _)| e)
        .unwrap();
    assert_eq!(
        (provider.returned)(
            source.key,
            Outcome::Trained {
                parameters: [0; 32]
            }
        ),
        Err(Error::Manifest)
    );
    (provider.returned)(source.key, Outcome::Trained { parameters }).unwrap();
    while producer::control_step().unwrap() {}
    let next = (provider.next)().unwrap().unwrap();
    let validation = next.validation.unwrap();
    assert_eq!(next.key.generation, source.key.generation + 1);
    assert_eq!(validation.probes.len(), 18);
    let sealed = SealedModel::seal(
        validation.bytes,
        validation.manifest.clone(),
        schemas(),
        validation.vectors,
    )
    .unwrap();
    let validated =
        ValidatedCandidate::register(seed.bytes(), sealed, next.data, validation.probes).unwrap();
    let binding = ModelBinding {
        generation: 2,
        model_hash: parameters,
        schema_hash: schemas().feature.hash,
    };
    (provider.returned)(
        next.key,
        Outcome::Validated {
            binding,
            registration: validated.registration_hash(),
        },
    )
    .unwrap();
    assert_eq!(producer::status().unwrap().phase, producer::Phase::Complete);
    assert!((provider.next)().unwrap().is_none());
}
