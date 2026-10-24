#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::learning::{
    Error,
    data::FrozenData,
    manifest::{ModelManifest, SealedModel, UntrainedSeed},
    train::Trainer,
    validate::*,
};
use cyxia_prototype::model::MODEL_BYTES;
use sha2::{Digest, Sha256};

fn references(bytes: &[u8; MODEL_BYTES]) -> (Vec<ReferenceCase>, Vec<ReferenceSelection>) {
    let mut cases = Vec::new();
    let mut selections = Vec::new();
    for set in support::probes(bytes) {
        let first = cases.len();
        let mut best = 0;
        let mut score = i16::MIN;
        for (index, candidate) in set.iter().enumerate() {
            let input = cyxia_prototype::features::encode(candidate.action, candidate.features)
                .unwrap()
                .values;
            let trace = integer_reference(bytes, &input);
            if index == 0 || trace.output > score {
                best = index;
                score = trace.output;
            }
            cases.push(ReferenceCase { input, trace });
        }
        selections.push(ReferenceSelection {
            first: first as u16,
            count: set.len() as u16,
            selected: best as u16,
        });
    }
    (cases, selections)
}

#[test]
fn missing_data_and_leaking_full_replay_groups_cannot_be_sealed() {
    assert_eq!(
        FrozenData::freeze(&[], &[], 7, support::schemas()).err(),
        Some(Error::DataIncomplete)
    );
    let (mut training, mut validation) = support::dataset();
    let complete = FrozenData::freeze(&training, &validation, 7, support::schemas()).unwrap();
    assert_eq!(complete.manifest().training_count, 144);
    assert_eq!(complete.manifest().validation_count, 72);
    assert_eq!(complete.manifest().training_per_family, [8; 18]);
    assert_eq!(complete.manifest().validation_per_family, [4; 18]);
    validation[0] =
        support::sample(support::FAMILIES[0], 1, 5000, support::Faults::default()).unwrap();
    assert_eq!(
        FrozenData::freeze(&training, &validation, 7, support::schemas()).err(),
        Some(Error::GroupOverlap)
    );
    let (_, validation) = support::dataset();
    training.truncate(136);
    for i in 0..8 {
        training.push(
            support::sample(
                support::FAMILIES[0],
                1,
                6000 + i,
                support::Faults::default(),
            )
            .unwrap(),
        );
    }
    // An adequate aggregate cannot hide a missing action family.
    assert_eq!(training.len(), 144);
    assert_eq!(
        FrozenData::freeze(&training, &validation, 7, support::schemas()).err(),
        Some(Error::DataIncomplete)
    );
}

#[test]
fn training_is_one_frozen_ordered_pass_and_only_final_layer_bytes_change() {
    let (training, validation) = support::dataset();
    let data = FrozenData::freeze(&training, &validation, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    assert_eq!(
        Trainer::start(seed.bytes(), &data).unwrap().finish().err(),
        Some(Error::DataIncomplete)
    );
    let mut run = Trainer::start(seed.bytes(), &data).unwrap();
    while run.step_next().unwrap() {}
    assert_eq!(run.completed_steps(), 144);
    assert!(!run.step_next().unwrap());
    let result = run.finish().unwrap();
    assert!(cyxia_prototype::learning::train::frozen_equal(
        seed.bytes(),
        result.bytes()
    ));
    assert_ne!(seed.bytes(), result.bytes());
    let mut repeated = Trainer::start(seed.bytes(), &data).unwrap();
    while repeated.step_next().unwrap() {}
    let repeated = repeated.finish().unwrap();
    assert_eq!(result.bytes(), repeated.bytes());
    assert_eq!(result.record(), repeated.record());
    let mut reverse = training.clone();
    reverse.reverse();
    let other = FrozenData::freeze(&reverse, &validation, 7, support::schemas()).unwrap();
    assert_ne!(
        other.manifest().training_hash,
        data.manifest().training_hash
    );
}

#[test]
fn a_candidate_is_registered_only_after_full_reference_and_replayed_training() {
    let (training, validation) = support::dataset();
    let data = FrozenData::freeze(&training, &validation, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let mut run = Trainer::start(seed.bytes(), &data).unwrap();
    while run.step_next().unwrap() {}
    let model = run.finish().unwrap();
    let (cases, selections) = references(model.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&model, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let sealed = SealedModel::seal(
        model.bytes(),
        manifest.clone(),
        support::schemas(),
        &vectors,
    )
    .unwrap();
    let candidate =
        ValidatedCandidate::register(seed.bytes(), sealed, &data, &support::probes(model.bytes()))
            .unwrap();
    assert!(
        candidate
            .comparison()
            .new
            .overall
            .compare(candidate.comparison().old.overall)
            .is_lt()
    );
    // The evaluator uses the full quantized integer result, exactly /256.
    let mut sum = 0f64;
    for sample in data.validation() {
        let p = f64::from(integer_reference(model.bytes(), sample.input()).output) / 256.;
        let e = p - f64::from_bits(sample.reward().value.to_bits());
        sum += e * e;
    }
    assert_eq!(
        candidate.comparison().new.overall.to_bits(),
        (sum / data.validation().len() as f64).to_bits()
    );
    let mut wrong = manifest.clone();
    wrong.normalization[0] += 1;
    assert_eq!(
        SealedModel::seal(model.bytes(), wrong, support::schemas(), &vectors).err(),
        Some(Error::Manifest)
    );
    let mut wrong_cases = cases.clone();
    wrong_cases[0].trace.hidden1[0] ^= 1;
    let wrong_vectors = ReferenceSuite {
        parameters_hash: vectors.parameters_hash,
        cases: &wrong_cases,
        selections: &selections,
    };
    assert_eq!(
        verify_reference(model.bytes(), &wrong_vectors),
        Err(Error::Validation)
    );
    let mut forged = *model.bytes();
    forged[2768..].copy_from_slice(&0i32.to_le_bytes());
    let (forged_cases, forged_selections) = references(&forged);
    let forged_vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(forged).into(),
        cases: &forged_cases,
        selections: &forged_selections,
    };
    let mut forged_manifest = manifest;
    forged_manifest.parameters_hash = forged_vectors.parameters_hash;
    forged_manifest.reference_vectors_hash = forged_vectors.hash().unwrap();
    if let cyxia_prototype::learning::manifest::Origin::Learned(ref mut record) =
        forged_manifest.origin
    {
        record.result_hash = forged_manifest.parameters_hash;
    }
    let forged = SealedModel::seal(
        &forged,
        forged_manifest,
        support::schemas(),
        &forged_vectors,
    )
    .unwrap();
    assert_eq!(
        ValidatedCandidate::register(seed.bytes(), forged, &data, &support::probes(model.bytes()))
            .err(),
        Some(Error::Evidence)
    );
}

#[test]
fn untrained_and_action_blind_seeds_are_explicitly_refused() {
    let seed = UntrainedSeed::new(5);
    assert_eq!(seed.status(), Error::Untrained);
    distinguish_candidates(seed.bytes(), &support::probes(seed.bytes())).unwrap();
    let mut blind = [0u8; MODEL_BYTES];
    blind[0] = 64;
    blind[1] = (-64i8) as u8;
    blind[2048] = 64;
    blind[2560] = 64;
    assert_eq!(
        distinguish_candidates(&blind, &support::probes(&blind)),
        Err(Error::Untrained)
    );
    let (cases, selections) = references(seed.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(seed.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::untrained(&seed, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let sealed = SealedModel::seal(seed.bytes(), manifest, support::schemas(), &vectors).unwrap();
    let (training, validation) = support::dataset();
    let data = FrozenData::freeze(&training, &validation, 7, support::schemas()).unwrap();
    assert_eq!(
        ValidatedCandidate::register(seed.bytes(), sealed, &data, &support::probes(seed.bytes()))
            .err(),
        Some(Error::Untrained)
    );
}

#[test]
fn aggregate_improvement_cannot_hide_a_family_regression_and_tolerance_is_exact() {
    // Unit fixtures have dx=0, dl=-1/2 and C=1, hence exactly zero label.
    // These are arithmetic/gate tests, not a claim of measured native trials.
    let (training, validation) = support::dataset_with_cost(true);
    assert!(
        validation
            .iter()
            .all(|sample| sample.reward().value.to_bits() == 0)
    );
    let data = FrozenData::freeze(&training, &validation, 7, support::schemas()).unwrap();
    // Frozen front extracts a raw Q8.8 value of 64 for D01, zero otherwise.
    let mut old = [0u8; MODEL_BYTES];
    old[0] = 16;
    old[2048] = 64;
    old[2560] = (-1i8) as u8;
    old[2768..].copy_from_slice(&1i32.to_le_bytes());
    let mut within = old;
    within[2560] = 1;
    within[2768..].copy_from_slice(&0i32.to_le_bytes());
    let result = compare(&old, &within, &data).unwrap();
    let epsilon = cyxia_prototype::learning::softfloat::F64::ONE
        .div(cyxia_prototype::learning::softfloat::F64::from_u64(65536))
        .unwrap();
    assert!(result.new.overall.compare(result.old.overall).is_lt());
    assert_eq!(result.old.by_family[0].to_bits(), 0);
    assert_eq!(result.new.by_family[0], epsilon);
    let mut outside = within;
    outside[2560] = 2;
    let next = mse(&outside, &data).unwrap();
    assert!(next.overall.compare(result.old.overall).is_lt());
    assert_eq!(compare(&old, &outside, &data), Err(Error::Validation));
    assert!(cyxia_prototype::learning::train::frozen_equal(
        &old, &outside
    ));
}
