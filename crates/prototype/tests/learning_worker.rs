//! Synthetic numerical/authority fixtures only. None of these rows is native
//! replay evidence or a substitute for the required real 144/72 sample corpus.
#[path = "../../../user/prototype-learning/src/compute.rs"]
mod guest_compute;
#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::{
    domains::ObjectKey,
    features,
    learning::{
        Error,
        data::FrozenData,
        manifest::{ModelManifest, Origin, SealedModel, UntrainedSeed},
        train::{self, TrainedModel, Trainer},
        validate::*,
        worker::{
            CompletionAuthority, CompletionClaim, Encoder, EncoderState, PreparedJob, Worker,
        },
        worker_wire::{self as wire, Header, JobBinding, JobIdentity, Packet, Report},
    },
    model::MODEL_BYTES,
};
use sha2::{Digest, Sha256};

fn binding(id: u64) -> JobBinding {
    JobBinding {
        boot_epoch: 2,
        job_id: id,
        controller_epoch: 3,
        core_generation: 4,
        model_generation: 5,
        data_generation: 6,
        role_context: ObjectKey {
            id: 7,
            generation: id,
        },
        image_hash: [9; 32],
        ledger_generation: 8,
    }
}
fn training(parent: &[u8; MODEL_BYTES], data: &FrozenData<'_>, id: u64) -> (Vec<u8>, PreparedJob) {
    let mut input = vec![0xa5; wire::INPUT_LIMIT + 16];
    let mut encoder = Encoder::training(
        binding(id),
        parent,
        data,
        1024 * 1024,
        &mut input[..wire::INPUT_LIMIT],
    )
    .unwrap();
    let len = encoder.input_len();
    let mut last = 0;
    loop {
        let p = encoder.step().unwrap();
        assert!(p.completed > last);
        last = p.completed;
        if p.done {
            break;
        }
    }
    let job = encoder.finish().unwrap();
    assert!(input[len..].iter().all(|b| *b == 0xa5));
    input.truncate(len);
    (input, job)
}
fn run(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut worker = Worker::start(input)?;
    let mut steps = 0;
    loop {
        let p = worker.step()?;
        steps += 1;
        assert_eq!(p.completed, steps);
        assert!(steps < 10000);
        if p.done {
            break;
        }
    }
    let mut output = vec![0xa5; wire::OUTPUT_LIMIT];
    let n = worker.finish(&mut output)?;
    assert_eq!(n, wire::RESULT_BYTES);
    assert!(output[n..].iter().all(|b| *b == 0xa5));
    output.truncate(n);
    Ok(output)
}
#[derive(Clone, Copy)]
enum Terminal {
    StoppedAndSettled,
    Unknown,
}
struct SyntheticRuntime {
    identity: JobIdentity,
    output_hash: [u8; 32],
    steps: u64,
    terminal: Terminal,
}
impl SyntheticRuntime {
    fn complete(job: &PreparedJob, output: &[u8]) -> Self {
        Self {
            identity: job.identity(),
            output_hash: Sha256::digest(output).into(),
            steps: Report::decode(output).unwrap().counts.steps,
            terminal: Terminal::StoppedAndSettled,
        }
    }
}
impl CompletionAuthority for SyntheticRuntime {
    fn verify_completion(&self, claim: &CompletionClaim) -> Result<(), Error> {
        if matches!(self.terminal, Terminal::Unknown) {
            return Err(Error::Unknown);
        }
        if claim.identity != self.identity
            || claim.output_hash != self.output_hash
            || claim.completed_steps != self.steps
            || claim.output_bytes != wire::RESULT_BYTES as u32
        {
            return Err(Error::Evidence);
        }
        Ok(())
    }
}
fn references(bytes: &[u8; MODEL_BYTES]) -> (Vec<ReferenceCase>, Vec<ReferenceSelection>) {
    let mut cases = Vec::new();
    let mut selections = Vec::new();
    for set in support::probes(bytes) {
        let first = cases.len();
        let mut selected = 0;
        let mut score = i16::MIN;
        for (i, entry) in set.iter().enumerate() {
            let input = features::encode(entry.action, entry.features)
                .unwrap()
                .values;
            let trace = integer_reference(bytes, &input);
            if i == 0 || trace.output > score {
                selected = i;
                score = trace.output;
            }
            cases.push(ReferenceCase { input, trace });
        }
        selections.push(ReferenceSelection {
            first: first as u16,
            count: set.len() as u16,
            selected: selected as u16,
        });
    }
    (cases, selections)
}
fn validation(
    parent: &[u8; MODEL_BYTES],
    candidate: &[u8; MODEL_BYTES],
    manifest: &ModelManifest,
    data: &FrozenData<'_>,
    vectors: &ReferenceSuite<'_>,
    id: u64,
) -> (Vec<u8>, PreparedJob) {
    let probes = support::probes(candidate);
    let mut input = vec![0; wire::INPUT_LIMIT];
    let mut encoder = Encoder::validation(
        binding(id),
        parent,
        candidate,
        manifest,
        data,
        vectors,
        &probes,
        1024 * 1024,
        &mut input,
    )
    .unwrap();
    let n = encoder.input_len();
    while !encoder.step().unwrap().done {}
    let job = encoder.finish().unwrap();
    input.truncate(n);
    (input, job)
}
fn host_train(parent: &[u8; MODEL_BYTES], data: &FrozenData<'_>) -> TrainedModel {
    let mut trainer = Trainer::start(parent, data).unwrap();
    while trainer.step_next().unwrap() {}
    trainer.finish().unwrap()
}
fn rehash_payload(bytes: &mut [u8]) {
    let digest: [u8; 32] = Sha256::digest(&bytes[wire::HEADER_BYTES..]).into();
    bytes[208..240].copy_from_slice(&digest);
}

#[test]
fn resumable_training_and_independent_validation_match_host_exactly() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (input, mut job) = training(seed.bytes(), &data, 1);
    let output = run(&input).unwrap();
    let proof = SyntheticRuntime::complete(&job, &output);
    let model = job.accept_training(&output, &proof).unwrap();
    let host = host_train(seed.bytes(), &data);
    assert_eq!(model.bytes(), host.bytes());
    assert_eq!(model.record(), host.record());
    assert_eq!(
        job.accept_training(&output, &proof).err(),
        Some(Error::State)
    );
    let (cases, selections) = references(model.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&model, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let (input, mut job) = validation(seed.bytes(), model.bytes(), &manifest, &data, &vectors, 2);
    let output = run(&input).unwrap();
    let report = Report::decode(&output).unwrap();
    assert_eq!(report.counts.rows, 216);
    assert_eq!(report.counts.training, 144);
    assert_eq!(report.counts.validation, 72);
    assert_eq!(report.counts.probes, 18);
    assert_eq!(report.counts.probe_candidates, 36);
    assert_eq!(report.counts.references, 36);
    assert_eq!(report.counts.selections, 18);
    let runtime = SyntheticRuntime::complete(&job, &output);
    let candidate = job
        .accept_validation(model.bytes(), manifest.clone(), &output, &runtime)
        .unwrap();
    let sealed = SealedModel::seal(model.bytes(), manifest, support::schemas(), &vectors).unwrap();
    let host =
        ValidatedCandidate::register(seed.bytes(), sealed, &data, &support::probes(model.bytes()))
            .unwrap();
    assert_eq!(candidate.comparison(), host.comparison());
    assert_eq!(candidate.registration_hash(), host.registration_hash());
    assert_eq!(candidate.model().hash(), host.model().hash());
}

#[test]
fn output_loan_can_end_after_every_encoding_step_without_changing_the_job() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (expected, expected_job) = training(seed.bytes(), &data, 51);
    let mut state = EncoderState::training(binding(51), seed.bytes(), &data, 1024 * 1024).unwrap();
    let n = state.input_len();
    let mut input = vec![0xa5; n + 16];
    assert_eq!(state.step(&mut input[..n - 1]), Err(Error::Capacity));
    loop {
        let step = state.step(&mut input[..n]).unwrap();
        // This independent access is legal because no output borrow survives
        // a step. The actual owner keeps this allocation exclusively pinned.
        assert!(input[n..].iter().all(|byte| *byte == 0xa5));
        if step.done {
            break;
        }
    }
    let prepared = state.finish(&input).unwrap();
    assert_eq!(&input[..n], &expected);
    assert_eq!(prepared.identity(), expected_job.identity());
    assert_eq!(run(&input[..n]).unwrap(), run(&expected).unwrap());
}

#[test]
fn split_encoder_does_not_accept_a_replaced_header_at_seal() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let mut state = EncoderState::training(binding(52), seed.bytes(), &data, 1024 * 1024).unwrap();
    let mut input = vec![0; state.input_len()];
    while !state.step(&mut input).unwrap().done {}
    // The fixed job-id word stays syntactically valid but no longer names
    // the protected job which produced this preparation state.
    input[24] ^= 1;
    assert_eq!(state.finish(&input).err(), Some(Error::Evidence));
}

#[test]
fn validated_identity_can_move_to_an_identical_immutable_bank_copy() {
    support::with_candidate(|candidate, _| {
        let bank_copy = *candidate.model().bytes();
        let retained = candidate.rebind(&bank_copy).unwrap();
        assert_eq!(retained.model().bytes(), candidate.model().bytes());
        assert_eq!(retained.model().manifest(), candidate.model().manifest());
        assert_eq!(retained.model().hash(), candidate.model().hash());
        assert_eq!(retained.comparison(), candidate.comparison());
        assert_eq!(retained.parent_hash(), candidate.parent_hash());
        assert_eq!(retained.registration_hash(), candidate.registration_hash());
        assert_ne!(
            retained.model().bytes().as_ptr(),
            candidate.model().bytes().as_ptr()
        );
    });
}

#[test]
fn validated_identity_cannot_be_rebound_to_a_changed_parameter() {
    support::with_candidate(|candidate, _| {
        for index in [0, MODEL_BYTES / 2, MODEL_BYTES - 1] {
            let mut copy = *candidate.model().bytes();
            copy[index] ^= 1;
            assert_eq!(candidate.rebind(&copy).err(), Some(Error::Evidence));
        }
    });
}

#[test]
fn exact_context_input_output_and_settled_terminal_are_required_for_import() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (input, mut job) = training(seed.bytes(), &data, 3);
    let output = run(&input).unwrap();
    let mut runtime = SyntheticRuntime::complete(&job, &output);
    runtime.terminal = Terminal::Unknown;
    assert_eq!(
        job.accept_training(&output, &runtime).err(),
        Some(Error::Unknown)
    );
    assert!(!job.consumed());
    runtime.terminal = Terminal::StoppedAndSettled;
    runtime.identity.binding.role_context.generation += 1;
    assert_eq!(
        job.accept_training(&output, &runtime).err(),
        Some(Error::Evidence)
    );
    runtime.identity = job.identity();
    let mut corrupt = output.clone();
    corrupt[280] ^= 1; // syntactically valid transcript, different frozen output
    assert_eq!(
        job.accept_training(&corrupt, &runtime).err(),
        Some(Error::Evidence)
    );
    let (_, mut other_job) = training(seed.bytes(), &data, 4);
    assert_eq!(
        other_job.accept_training(&output, &runtime).err(),
        Some(Error::Evidence)
    );
    assert!(job.accept_training(&output, &runtime).is_ok());
}

#[test]
fn numerical_wire_rechecks_real_split_provenance_not_only_transport_digest() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (input, _) = training(seed.bytes(), &data, 5);
    let layout = Packet::decode(&input).unwrap().layout;
    let mut corrupt = input.clone();
    corrupt[layout.rows + 4] = 1;
    rehash_payload(&mut corrupt);
    assert_eq!(run(&corrupt).err(), Some(Error::Evidence));
    let mut corrupt = input.clone();
    let evidence = input[layout.provenance + 72..layout.provenance + 104].to_vec();
    corrupt[layout.provenance + wire::PROVENANCE_BYTES + 72
        ..layout.provenance + wire::PROVENANCE_BYTES + 104]
        .copy_from_slice(&evidence);
    rehash_payload(&mut corrupt);
    assert_eq!(run(&corrupt).err(), Some(Error::Evidence));
    let mut corrupt = input.clone();
    let group = input[layout.provenance..layout.provenance + 72].to_vec();
    let first_validation = layout.provenance + 144 * wire::PROVENANCE_BYTES;
    corrupt[first_validation..first_validation + 72].copy_from_slice(&group);
    rehash_payload(&mut corrupt);
    assert_eq!(run(&corrupt).err(), Some(Error::GroupOverlap));
    let mut corrupt = input.clone();
    corrupt[layout.rows + 136..layout.rows + 144]
        .copy_from_slice(&f64::NAN.to_bits().to_le_bytes());
    rehash_payload(&mut corrupt);
    assert_eq!(run(&corrupt).err(), Some(Error::Numeric));
    let mut corrupt = input;
    corrupt[layout.rows + 8] ^= 1;
    assert_eq!(run(&corrupt).err(), Some(Error::Evidence)); // payload digest catches this before any SGD
}

#[test]
fn validation_reproduces_training_and_rejects_an_action_blind_front() {
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let model = host_train(seed.bytes(), &data);
    let mut forged = *model.bytes();
    forged[train::LAST_BIAS] ^= 1;
    let (cases, selections) = references(&forged);
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(forged).into(),
        cases: &cases,
        selections: &selections,
    };
    let mut manifest = ModelManifest::learned(
        &model,
        support::schemas(),
        &ReferenceSuite {
            parameters_hash: Sha256::digest(model.bytes()).into(),
            cases: &cases,
            selections: &selections,
        },
        1024 * 1024,
    )
    .unwrap();
    manifest.parameters_hash = vectors.parameters_hash;
    manifest.reference_vectors_hash = vectors.hash().unwrap();
    if let Origin::Learned(ref mut record) = manifest.origin {
        record.result_hash = vectors.parameters_hash;
    }
    let (input, _) = validation(seed.bytes(), &forged, &manifest, &data, &vectors, 6);
    assert_eq!(run(&input).err(), Some(Error::Evidence));
    let blind = [0u8; MODEL_BYTES];
    let model = host_train(&blind, &data);
    let (cases, selections) = references(model.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&model, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let (input, _) = validation(&blind, model.bytes(), &manifest, &data, &vectors, 7);
    assert_eq!(run(&input).err(), Some(Error::Untrained));
}

#[test]
fn no_labels_remains_data_incomplete_and_lengths_never_truncate_silently() {
    assert_eq!(
        FrozenData::freeze(&[], &[], 7, support::schemas()).err(),
        Some(Error::DataIncomplete)
    );
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (mut input, _) = training(seed.bytes(), &data, 8);
    for len in [0, 1, 1023, input.len() - 1] {
        assert!(Header::decode(&input[..len]).is_err());
    }
    let empty_len = wire::HEADER_BYTES + 2 * MODEL_BYTES;
    input.truncate(empty_len);
    input[12..16].copy_from_slice(&(empty_len as u32).to_le_bytes());
    for p in [340, 342, 360, 362] {
        input[p..p + 2].copy_from_slice(&0u16.to_le_bytes());
    }
    rehash_payload(&mut input);
    assert_eq!(Worker::start(&input).err(), Some(Error::DataIncomplete));
    let largest = wire::Layout::new(512, 256, 128, 32, 72).unwrap();
    assert!(largest.total <= wire::INPUT_LIMIT);
    assert_eq!(
        wire::Layout::new(513, 256, 128, 32, 72),
        Err(Error::Capacity)
    );
    assert_eq!(
        wire::Layout::new(512, 256, 129, 32, 72),
        Err(Error::Capacity)
    );
}

#[test]
fn guest_entry_executes_same_steps_and_operator_receipt_is_never_a_candidate() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    fn yielded(n: u64) {
        let old = LAST.swap(n, Ordering::SeqCst);
        assert!(n > old);
    }
    let mut receipt = [0u8; wire::SELFTEST_BYTES];
    assert_eq!(
        guest_compute::selftest(&mut receipt, yielded),
        Ok(wire::SELFTEST_BYTES)
    );
    assert_eq!(
        u64::from_le_bytes(receipt[..8].try_into().unwrap()),
        wire::SELFTEST_MAGIC
    );
    assert_eq!(u64::from_le_bytes(receipt[16..24].try_into().unwrap()), 14);
    assert_eq!(Report::decode(&receipt).err(), Some(Error::Capacity));
    LAST.store(0, Ordering::SeqCst);
    let (t, v) = support::dataset();
    let data = FrozenData::freeze(&t, &v, 7, support::schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let (input, _) = training(seed.bytes(), &data, 9);
    let expected = run(&input).unwrap();
    let mut output = vec![0; wire::OUTPUT_LIMIT];
    let len = guest_compute::run(&input, &mut output, yielded).unwrap();
    assert_eq!(&output[..len], expected);
    assert_eq!(
        LAST.load(Ordering::SeqCst),
        Report::decode(&expected).unwrap().counts.steps
    );
    let mut not_finished = Worker::start(&input).unwrap();
    not_finished.step().unwrap();
    assert_eq!(not_finished.finish(&mut output), Err(Error::State));
}
