//! Host fault injection for the native model-bank owner. Numerical candidates
//! come from the real worker protocol with a synthetic completion authority;
//! these are mechanism tests, not native measurements or replay samples.
#[path = "../../../kernel/src/model_bank.rs"]
mod model_bank;
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::{
    domains::{Error, ObjectKey},
    features,
    learning::{
        Error as LearnError,
        data::FrozenData,
        manifest::{ModelManifest, UntrainedSeed},
        train::TrainedModel,
        validate::{
            ReferenceCase, ReferenceSelection, ReferenceSuite, ValidatedCandidate,
            integer_reference,
        },
        worker::{CompletionAuthority, CompletionClaim, Encoder, PreparedJob, Worker},
        worker_wire::{self as wire, JobBinding, JobIdentity, Report},
    },
    model::MODEL_BYTES,
    policy::ModelBinding,
};
use model_bank::{ChangeKind, Memory, ModelBank, Provenance};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone)]
struct Slot {
    bytes: [u8; MODEL_BYTES],
    owner: ObjectKey,
    sealed: bool,
    pins: Vec<u64>,
}
#[derive(Default)]
struct State {
    slots: Vec<Slot>,
    allocations: usize,
    writes: usize,
    next_pin: u64,
    fail_allocation: Option<usize>,
    partial_write: bool,
    fail_seal: bool,
    wrong_hash: bool,
    release_busy: bool,
}
struct MockMemory(Rc<RefCell<State>>);
struct Pin {
    slot: usize,
    serial: u64,
}
impl Memory for MockMemory {
    type Allocation = usize;
    type Pin = Pin;
    fn allocate(&mut self, owner: ObjectKey) -> Result<usize, Error> {
        let mut s = self.0.borrow_mut();
        if s.fail_allocation == Some(s.slots.len()) {
            s.fail_allocation = None;
            return Err(Error::Busy);
        }
        if s.slots.len() == 4 {
            return Err(Error::Capacity);
        }
        let index = s.slots.len();
        s.slots.push(Slot {
            bytes: [0; MODEL_BYTES],
            owner,
            sealed: false,
            pins: vec![],
        });
        s.allocations += 1;
        Ok(index)
    }
    fn unseal(&mut self, index: usize) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        let slot = s.slots.get_mut(index).ok_or(Error::Stale)?;
        if !slot.pins.is_empty() {
            return Err(Error::Busy);
        }
        slot.sealed = false;
        Ok(())
    }
    fn write(&mut self, index: usize, bytes: &[u8; MODEL_BYTES]) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        let slot = s.slots.get(index).ok_or(Error::Stale)?;
        if slot.sealed {
            return Err(Error::Auth);
        }
        if !slot.pins.is_empty() {
            return Err(Error::Busy);
        }
        s.writes += 1;
        if s.partial_write {
            s.partial_write = false;
            s.slots[index].bytes[..97].copy_from_slice(&bytes[..97]);
            // A failed device/owner copy may already have changed real bytes.
            s.slots[index].bytes[96] ^= 0x80;
            return Err(Error::Busy);
        }
        s.slots[index].bytes.copy_from_slice(bytes);
        Ok(())
    }
    fn seal(&mut self, index: usize) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        if s.fail_seal {
            s.fail_seal = false;
            return Err(Error::Busy);
        }
        let slot = s.slots.get_mut(index).ok_or(Error::Stale)?;
        if !slot.pins.is_empty() {
            return Err(Error::Busy);
        }
        slot.sealed = true;
        Ok(())
    }
    fn hash(&mut self, index: usize) -> Result<[u8; 32], Error> {
        let mut s = self.0.borrow_mut();
        let bytes = s.slots.get(index).ok_or(Error::Stale)?.bytes;
        let mut hash: [u8; 32] = Sha256::digest(bytes).into();
        if s.wrong_hash {
            s.wrong_hash = false;
            hash[0] ^= 1;
        }
        Ok(hash)
    }
    fn pin(&mut self, index: usize) -> Result<(Pin, u64), Error> {
        let mut s = self.0.borrow_mut();
        if !s.slots.get(index).ok_or(Error::Stale)?.sealed {
            return Err(Error::Auth);
        }
        s.next_pin = s.next_pin.checked_add(1).ok_or(Error::Overflow)?;
        let serial = s.next_pin;
        s.slots[index].pins.push(serial);
        Ok((
            Pin {
                slot: index,
                serial,
            },
            0x100000 + index as u64 * 4096,
        ))
    }
    fn release(&mut self, pin: &Pin) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        if s.release_busy {
            s.release_busy = false;
            return Err(Error::Busy);
        }
        let slot = s.slots.get_mut(pin.slot).ok_or(Error::Stale)?;
        let index = slot
            .pins
            .iter()
            .position(|serial| *serial == pin.serial)
            .ok_or(Error::Stale)?;
        slot.pins.remove(index);
        Ok(())
    }
}
fn memory() -> (ModelBank<MockMemory>, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State::default()));
    (ModelBank::new(MockMemory(state.clone())), state)
}
fn binding(bytes: &[u8; MODEL_BYTES], generation: u64) -> ModelBinding {
    ModelBinding {
        generation,
        model_hash: Sha256::digest(bytes).into(),
        schema_hash: support::schemas().feature.hash,
    }
}
fn ready(parent: &[u8; MODEL_BYTES]) -> (ModelBank<MockMemory>, Rc<RefCell<State>>, ModelBinding) {
    let (mut bank, state) = memory();
    let active = binding(parent, 7);
    bank.initialize(11, active, support::schemas(), parent)
        .unwrap();
    (bank, state, active)
}
fn job_binding(id: u64) -> JobBinding {
    JobBinding {
        boot_epoch: 11,
        job_id: id,
        controller_epoch: 9,
        core_generation: 1,
        model_generation: 7,
        data_generation: 1,
        role_context: ObjectKey {
            id: 700,
            generation: id,
        },
        image_hash: [8; 32],
        ledger_generation: 1,
    }
}
struct SyntheticRuntime {
    identity: JobIdentity,
    digest: [u8; 32],
    steps: u64,
    calls: Cell<usize>,
    unknown: bool,
}
impl SyntheticRuntime {
    fn new(job: &PreparedJob, bytes: &[u8]) -> Self {
        Self {
            identity: job.identity(),
            digest: Sha256::digest(bytes).into(),
            steps: Report::decode(bytes).unwrap().counts.steps,
            calls: Cell::new(0),
            unknown: false,
        }
    }
}
impl CompletionAuthority for SyntheticRuntime {
    fn verify_completion(&self, claim: &CompletionClaim) -> Result<(), LearnError> {
        self.calls.set(self.calls.get() + 1);
        if self.unknown {
            return Err(LearnError::Unknown);
        }
        if claim.identity != self.identity
            || claim.output_hash != self.digest
            || claim.output_bytes != wire::RESULT_BYTES as u32
            || claim.completed_steps != self.steps
        {
            return Err(LearnError::Evidence);
        }
        Ok(())
    }
}
fn run(input: &[u8]) -> Result<Vec<u8>, LearnError> {
    let mut worker = Worker::start(input)?;
    while !worker.step()?.done {}
    let mut output = vec![0; wire::RESULT_BYTES];
    worker.finish(&mut output)?;
    Ok(output)
}
fn train(
    parent: &[u8; MODEL_BYTES],
    data: &FrozenData<'_>,
    id: u64,
    generation: u64,
) -> TrainedModel {
    let mut input = vec![0; wire::INPUT_LIMIT];
    let binding = JobBinding {
        model_generation: generation,
        ..job_binding(id)
    };
    let mut encoder = Encoder::training(binding, parent, data, 1024 * 1024, &mut input).unwrap();
    let length = encoder.input_len();
    while !encoder.step().unwrap().done {}
    let mut prepared = encoder.finish().unwrap();
    let output = run(&input[..length]).unwrap();
    let authority = SyntheticRuntime::new(&prepared, &output);
    prepared.accept_training(&output, &authority).unwrap()
}
fn references(bytes: &[u8; MODEL_BYTES]) -> (Vec<ReferenceCase>, Vec<ReferenceSelection>) {
    let mut cases = vec![];
    let mut selections = vec![];
    for set in support::probes(bytes) {
        let first = cases.len();
        let mut selected = 0;
        let mut score = i16::MIN;
        for (index, entry) in set.iter().enumerate() {
            let input = features::encode(entry.action, entry.features)
                .unwrap()
                .values;
            let trace = integer_reference(bytes, &input);
            if index == 0 || trace.output > score {
                selected = index;
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
fn with_validated(
    parent: &[u8; MODEL_BYTES],
    variant: u64,
    run_checked: impl FnOnce(&ValidatedCandidate<'_>),
) {
    with_validated_at(parent, variant, 7, run_checked);
}
fn with_validated_at(
    parent: &[u8; MODEL_BYTES],
    variant: u64,
    generation: u64,
    run_checked: impl FnOnce(&ValidatedCandidate<'_>),
) {
    let (mut training, validation) = support::dataset_with_cost(variant & 1 != 0);
    let rotate = variant as usize * 17 % training.len();
    training.rotate_left(rotate);
    let data = FrozenData::freeze(&training, &validation, variant + 1, support::schemas()).unwrap();
    let model = train(parent, &data, variant * 10 + 1, generation);
    let (cases, selections) = references(model.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&model, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let probes = support::probes(model.bytes());
    let mut input = vec![0; wire::INPUT_LIMIT];
    let mut encoder = Encoder::validation(
        JobBinding {
            model_generation: generation,
            ..job_binding(variant * 10 + 2)
        },
        parent,
        model.bytes(),
        &manifest,
        &data,
        &vectors,
        &probes,
        1024 * 1024,
        &mut input,
    )
    .unwrap();
    let length = encoder.input_len();
    while !encoder.step().unwrap().done {}
    let mut prepared = encoder.finish().unwrap();
    let output = run(&input[..length]).unwrap();
    let authority = SyntheticRuntime::new(&prepared, &output);
    let candidate = prepared
        .accept_validation(model.bytes(), manifest, &output, &authority)
        .unwrap();
    run_checked(&candidate);
}

#[test]
fn initialization_busy_retains_allocations_and_binds_exact_boot_schema_and_seed() {
    let seed = UntrainedSeed::new(0);
    let active = binding(seed.bytes(), 7);
    let (mut bank, memory) = memory();
    memory.borrow_mut().fail_allocation = Some(2);
    assert_eq!(
        bank.initialize(11, active, support::schemas(), seed.bytes()),
        Err(Error::Busy)
    );
    assert_eq!(memory.borrow().allocations, 2);
    assert_eq!(bank.active(), Err(Error::NotReady));
    assert_eq!(
        bank.initialize(12, active, support::schemas(), seed.bytes()),
        Err(Error::Conflict)
    );
    assert_eq!(
        bank.initialize(
            11,
            ModelBinding {
                generation: 8,
                ..active
            },
            support::schemas(),
            seed.bytes()
        ),
        Err(Error::Conflict)
    );
    let mut other = support::schemas();
    other.feature.hash = [99; 32];
    assert_eq!(
        bank.initialize(
            11,
            ModelBinding {
                schema_hash: other.feature.hash,
                ..active
            },
            other,
            seed.bytes()
        ),
        Err(Error::Conflict)
    );
    let changed_seed = UntrainedSeed::new(1);
    assert_eq!(
        bank.initialize(
            11,
            binding(changed_seed.bytes(), 7),
            support::schemas(),
            changed_seed.bytes()
        ),
        Err(Error::Conflict)
    );
    assert_eq!(memory.borrow().allocations, 2);
    memory.borrow_mut().fail_seal = true;
    assert_eq!(
        bank.initialize(11, active, support::schemas(), seed.bytes()),
        Err(Error::Busy)
    );
    assert_eq!(memory.borrow().allocations, 4);
    assert_eq!(bank.active(), Err(Error::NotReady));
    bank.initialize(11, active, support::schemas(), seed.bytes())
        .unwrap();
    assert_eq!(bank.active(), Ok(active));
    assert_eq!(bank.active_provenance(), Ok(Provenance::Untrained));
    let writes = memory.borrow().writes;
    bank.initialize(11, active, support::schemas(), seed.bytes())
        .unwrap();
    assert_eq!(memory.borrow().writes, writes);
    assert_eq!(memory.borrow().allocations, 4);
    let slots = &memory.borrow().slots;
    for (i, slot) in slots.iter().enumerate() {
        assert_eq!(slot.owner.generation, 11);
        assert_eq!(slot.owner.id, slots[0].owner.id + i as u64);
    }
}

#[test]
fn real_validated_staging_is_idempotent_and_does_not_switch_active() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |candidate| {
        let (mut bank, memory, active) = ready(seed.bytes());
        let staged = bank.stage(candidate).unwrap();
        assert_eq!(staged.generation, active.generation);
        assert_eq!(
            staged.model_hash,
            candidate.model().manifest().parameters_hash
        );
        assert_eq!(bank.active(), Ok(active));
        assert_eq!(bank.active_provenance(), Ok(Provenance::Untrained));
        let writes = memory.borrow().writes;
        assert_eq!(bank.stage(candidate), Ok(staged));
        assert_eq!(memory.borrow().writes, writes);
        let pin = bank.pin(staged).unwrap();
        let slot = ((pin.physical_address() - 0x100000) / 4096) as usize;
        assert_eq!(
            memory.borrow().slots[slot].bytes,
            *candidate.model().bytes()
        );
        bank.release(&pin).unwrap();
        assert_eq!(bank.release(&pin), Err(Error::Stale));
    });
}

#[test]
fn failed_partial_stage_never_leaves_old_hash_advertised_or_changes_active() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |first| {
        with_validated(seed.bytes(), 1, |second| {
            let (mut bank, memory, active) = ready(seed.bytes());
            let old = bank.stage(first).unwrap();
            assert_ne!(old.model_hash, second.model().manifest().parameters_hash);
            memory.borrow_mut().partial_write = true;
            assert_eq!(bank.stage(second), Err(Error::Busy));
            assert_eq!(bank.pin(old).err(), Some(Error::Stale));
            assert_eq!(bank.active(), Ok(active));
            assert_eq!(memory.borrow().slots[0].bytes, *seed.bytes());
            let next = bank.stage(second).unwrap();
            let pin = bank.pin(next).unwrap();
            let slot = ((pin.physical_address() - 0x100000) / 4096) as usize;
            assert_eq!(memory.borrow().slots[slot].bytes, *second.model().bytes());
            bank.release(&pin).unwrap();
        });
    });
}

#[test]
fn stage_hash_or_seal_failure_does_not_expose_a_candidate_and_retry_is_safe() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |candidate| {
        let (mut bank, memory, active) = ready(seed.bytes());
        let expected = ModelBinding {
            model_hash: candidate.model().manifest().parameters_hash,
            ..active
        };
        memory.borrow_mut().wrong_hash = true;
        assert_eq!(bank.stage(candidate), Err(Error::Conflict));
        assert_eq!(bank.pin(expected).err(), Some(Error::Stale));
        memory.borrow_mut().fail_seal = true;
        assert_eq!(bank.stage(candidate), Err(Error::Busy));
        assert_eq!(bank.pin(expected).err(), Some(Error::Stale));
        assert_eq!(bank.stage(candidate), Ok(expected));
        assert_eq!(memory.borrow().allocations, 4);
        assert_eq!(bank.active(), Ok(active));
    });
}

#[test]
fn pinned_model_bytes_survive_other_staging_and_releases_are_exact() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |first| {
        with_validated(seed.bytes(), 1, |second| {
            let (mut bank, memory, _) = ready(seed.bytes());
            let old = bank.stage(first).unwrap();
            let pin_a = bank.pin(old).unwrap();
            let pin_b = bank.pin(old).unwrap();
            let next = bank.stage(second).unwrap();
            let pin_next = bank.pin(next).unwrap();
            assert_ne!(pin_a.physical_address(), pin_next.physical_address());
            assert_eq!(memory.borrow().slots[1].bytes, *first.model().bytes());
            memory.borrow_mut().release_busy = true;
            assert_eq!(bank.release(&pin_a), Err(Error::Busy));
            assert_eq!(memory.borrow().slots[1].pins.len(), 2);
            bank.release(&pin_a).unwrap();
            assert_eq!(bank.release(&pin_a), Err(Error::Stale));
            assert_eq!(memory.borrow().slots[1].pins.len(), 1);
            assert_eq!(pin_b.binding(), old);
            assert_eq!(memory.borrow().slots[1].bytes, *first.model().bytes());
            bank.release(&pin_b).unwrap();
            with_validated(seed.bytes(), 2, |third| {
                let staged = bank.stage(third).unwrap();
                let pin_third = bank.pin(staged).unwrap();
                assert_eq!(pin_third.physical_address(), pin_a.physical_address());
                assert_eq!(bank.pin(old).err(), Some(Error::Stale));
                assert_eq!(bank.release(&pin_a), Err(Error::Stale));
                assert_eq!(bank.release(&pin_b), Err(Error::Stale));
                assert_eq!(memory.borrow().slots[1].pins.len(), 1);
                assert_eq!(memory.borrow().slots[1].bytes, *third.model().bytes());
                bank.release(&pin_third).unwrap();
            });
            bank.release(&pin_next).unwrap();
        });
    });
}

#[test]
fn switches_require_generation_plus_one_and_rollback_only_the_previous_active() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |first| {
        let (mut bank, memory, a) = ready(seed.bytes());
        let pin_a = bank.pin(a).unwrap();
        let staged = bank.stage(first).unwrap();
        assert_eq!(
            bank.prepare_change(staged, ChangeKind::Promotion).err(),
            Some(Error::Stale)
        );
        assert_eq!(
            bank.prepare_change(
                ModelBinding {
                    generation: 9,
                    ..staged
                },
                ChangeKind::Promotion
            )
            .err(),
            Some(Error::Stale)
        );
        assert_eq!(
            bank.prepare_change(
                ModelBinding {
                    generation: 8,
                    schema_hash: [88; 32],
                    ..staged
                },
                ChangeKind::Promotion
            )
            .err(),
            Some(Error::Stale)
        );
        let b = ModelBinding {
            generation: 8,
            ..staged
        };
        assert_eq!(
            bank.prepare_change(b, ChangeKind::Rollback).err(),
            Some(Error::Stale)
        );
        let pin_b = bank.pin(staged).unwrap();
        with_validated(seed.bytes(), 1, |second| {
            let staged = bank.stage(second).unwrap();
            let c = ModelBinding {
                generation: 9,
                ..staged
            };
            bank.prepare_change(b, ChangeKind::Promotion)
                .unwrap()
                .commit();
            assert_eq!(
                bank.active_provenance(),
                Ok(Provenance::Validated {
                    registration: first.registration_hash(),
                    parent: a.model_hash,
                })
            );
            // A stored, validated candidate has never been Active and is not
            // an authorized rollback destination.
            assert_eq!(
                bank.prepare_change(c, ChangeKind::Rollback).err(),
                Some(Error::Stale)
            );
            let returned = ModelBinding { generation: 9, ..a };
            bank.prepare_change(returned, ChangeKind::Rollback)
                .unwrap()
                .commit();
            assert_eq!(bank.active(), Ok(returned));
            assert_ne!(returned, a);
            assert_eq!(
                bank.prepare_change(b, ChangeKind::Promotion).err(),
                Some(Error::Stale)
            );
            assert_eq!(bank.stage(first), Err(Error::Conflict));
            assert_eq!(
                bank.prepare_change(
                    ModelBinding {
                        generation: 10,
                        ..b
                    },
                    ChangeKind::Promotion
                )
                .err(),
                Some(Error::Auth)
            );
            bank.prepare_change(
                ModelBinding {
                    generation: 10,
                    ..b
                },
                ChangeKind::Rollback,
            )
            .unwrap()
            .commit();
            assert_eq!(
                bank.prepare_change(
                    ModelBinding {
                        generation: 11,
                        ..c
                    },
                    ChangeKind::Rollback
                )
                .err(),
                Some(Error::Stale)
            );
            assert_eq!(pin_a.binding(), a);
            assert_eq!(memory.borrow().slots[0].bytes, *seed.bytes());
        });
        bank.release(&pin_b).unwrap();
        bank.release(&pin_a).unwrap();
    });
}

#[test]
fn abandoned_or_failed_prepare_never_changes_active_and_commit_has_no_fallible_io() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |candidate| {
        let (mut bank, memory, active) = ready(seed.bytes());
        let staged = bank.stage(candidate).unwrap();
        let next = ModelBinding {
            generation: 8,
            ..staged
        };
        memory.borrow_mut().wrong_hash = true;
        assert_eq!(
            bank.prepare_change(next, ChangeKind::Promotion).err(),
            Some(Error::Conflict)
        );
        assert_eq!(bank.active(), Ok(active));
        drop(bank.prepare_change(next, ChangeKind::Promotion).unwrap());
        assert_eq!(bank.active(), Ok(active));
        let prepared = bank.prepare_change(next, ChangeKind::Promotion).unwrap();
        let writes = memory.borrow().writes;
        memory.borrow_mut().partial_write = true;
        memory.borrow_mut().wrong_hash = true;
        assert_eq!(prepared.commit(), next);
        assert_eq!(memory.borrow().writes, writes);
        assert!(memory.borrow().wrong_hash);
        assert!(memory.borrow().partial_write);
        assert_eq!(bank.active(), Ok(next));
    });
}

#[test]
fn incompatible_schema_parent_and_generation_overflow_fail_closed() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |candidate| {
        let (mut bank, state) = memory();
        let mut schemas = support::schemas();
        schemas.feature.hash = [89; 32];
        let active = ModelBinding {
            schema_hash: schemas.feature.hash,
            ..binding(seed.bytes(), 7)
        };
        bank.initialize(11, active, schemas, seed.bytes()).unwrap();
        assert_eq!(bank.stage(candidate), Err(Error::Stale));
        assert_eq!(state.borrow().writes, 1);
        let (mut bank, _) = memory();
        let other = UntrainedSeed::new(1);
        bank.initialize(
            11,
            binding(other.bytes(), 7),
            support::schemas(),
            other.bytes(),
        )
        .unwrap();
        assert_eq!(bank.stage(candidate), Err(Error::Stale));
        let (mut bank, _) = memory();
        bank.initialize(
            11,
            binding(seed.bytes(), u64::MAX),
            support::schemas(),
            seed.bytes(),
        )
        .unwrap();
        let staged = bank.stage(candidate).unwrap();
        assert_eq!(
            bank.prepare_change(
                ModelBinding {
                    generation: 0,
                    ..staged
                },
                ChangeKind::Promotion
            )
            .err(),
            Some(Error::Overflow)
        );
    });
}

#[test]
fn incomplete_or_mutated_validation_never_creates_a_stageable_candidate() {
    let seed = UntrainedSeed::new(0);
    let (training, validation) = support::dataset();
    let data = FrozenData::freeze(&training, &validation, 1, support::schemas()).unwrap();
    let model = train(seed.bytes(), &data, 1, 7);
    let (cases, selections) = references(model.bytes());
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest =
        ModelManifest::learned(&model, support::schemas(), &vectors, 1024 * 1024).unwrap();
    let probes = support::probes(model.bytes());
    let mut input = vec![0; wire::INPUT_LIMIT];
    let mut encoder = Encoder::validation(
        job_binding(2),
        seed.bytes(),
        model.bytes(),
        &manifest,
        &data,
        &vectors,
        &probes,
        1024 * 1024,
        &mut input,
    )
    .unwrap();
    let length = encoder.input_len();
    while !encoder.step().unwrap().done {}
    let mut prepared = encoder.finish().unwrap();
    let output = run(&input[..length]).unwrap();
    let mut authority = SyntheticRuntime::new(&prepared, &output);
    let (mut bank, memory, active) = ready(seed.bytes());
    authority.unknown = true;
    assert_eq!(
        prepared
            .accept_validation(model.bytes(), manifest.clone(), &output, &authority)
            .err(),
        Some(LearnError::Unknown)
    );
    assert!(!prepared.consumed());
    assert_eq!(memory.borrow().writes, 1);
    assert_eq!(bank.active(), Ok(active));
    authority.unknown = false;
    let calls = authority.calls.get();
    let mut changed = *model.bytes();
    changed[2560] ^= 1;
    assert_eq!(
        prepared
            .accept_validation(&changed, manifest.clone(), &output, &authority)
            .err(),
        Some(LearnError::Manifest)
    );
    let mut changed_manifest = manifest.clone();
    changed_manifest.workspace_bytes -= 1;
    assert_eq!(
        prepared
            .accept_validation(model.bytes(), changed_manifest, &output, &authority)
            .err(),
        Some(LearnError::Manifest)
    );
    assert_eq!(authority.calls.get(), calls);
    let candidate = prepared
        .accept_validation(model.bytes(), manifest, &output, &authority)
        .unwrap();
    bank.stage(&candidate).unwrap();
    assert_eq!(memory.borrow().writes, 2);
    assert_eq!(bank.active(), Ok(active));
}

#[test]
fn fresh_validated_same_hash_after_rollback_uses_current_generation_bank() {
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |first| {
        let (mut bank, _, initial) = ready(seed.bytes());
        let staged = bank.stage(first).unwrap();
        let prior_active = ModelBinding {
            generation: 8,
            ..staged
        };
        bank.prepare_change(prior_active, ChangeKind::Promotion)
            .unwrap()
            .commit();
        bank.prepare_change(
            ModelBinding {
                generation: 9,
                ..initial
            },
            ChangeKind::Rollback,
        )
        .unwrap()
        .commit();
        // This is a newly completed, independently validated job with the same
        // numeric rows/order but another frozen dataset identity. Determinism
        // gives identical parameter bytes; the registration is genuinely new.
        with_validated_at(seed.bytes(), 144, 9, |fresh| {
            assert_eq!(fresh.model().bytes(), first.model().bytes());
            assert_ne!(fresh.registration_hash(), first.registration_hash());
            let current = bank.stage(fresh).unwrap();
            assert_eq!(current.generation, 9);
            let old_pin = bank.pin(prior_active).unwrap();
            let current_pin = bank.pin(current).unwrap();
            assert_ne!(old_pin.physical_address(), current_pin.physical_address());
            let promoted = ModelBinding {
                generation: 10,
                ..current
            };
            bank.prepare_change(promoted, ChangeKind::Promotion)
                .unwrap()
                .commit();
            assert_eq!(bank.active(), Ok(promoted));
            assert_eq!(
                bank.active_provenance(),
                Ok(Provenance::Validated {
                    registration: fresh.registration_hash(),
                    parent: initial.model_hash,
                })
            );
            assert_eq!(old_pin.binding(), prior_active);
            bank.prepare_change(
                ModelBinding {
                    generation: 11,
                    ..initial
                },
                ChangeKind::Rollback,
            )
            .unwrap()
            .commit();
            // The stale B8 slot also must not hide the actual previous B10
            // bank when selecting a rollback target with the same hash.
            let restored = ModelBinding {
                generation: 12,
                ..promoted
            };
            bank.prepare_change(restored, ChangeKind::Rollback)
                .unwrap()
                .commit();
            assert_eq!(bank.active(), Ok(restored));
            assert_eq!(old_pin.binding(), prior_active);
            bank.release(&old_pin).unwrap();
            bank.release(&current_pin).unwrap();
        });
    });
}

#[test]
fn bank_registry_and_governance_switch_atomically_after_all_fallible_prepares() {
    use cyxia_prototype::{
        domains::{Action, ApplyId, PolicyStamp},
        learning::{
            governance::{
                CanaryPermit, CanaryReceipt, CommitGate, ControlAuthority, ExtraBudget, Governance,
                GovernanceAuthority, RestorationReceipt, RestorationRequest, Role, Stage,
                TargetRegistration, WINDOW_NS,
            },
            reward::{RequestResult, RewardWorkspace, WorkRequest},
        },
        policy::{Candidate, CandidateSet, ExecutionState, Publisher, Registry, Snapshot},
    };
    struct Authority;
    const TARGET: ObjectKey = ObjectKey {
        id: 15,
        generation: 1,
    };
    impl ControlAuthority for Authority {
        fn authorize(
            &self,
            _: Role,
            cpu: u16,
            generation: u64,
            bytes: u32,
        ) -> Result<(), LearnError> {
            if cpu == 1 && generation == 1 && bytes <= 1024 * 1024 {
                Ok(())
            } else {
                Err(LearnError::State)
            }
        }
    }
    impl GovernanceAuthority for Authority {
        fn registered_noncritical_console(
            &self,
            target: TargetRegistration,
        ) -> Result<(), LearnError> {
            if target.key == TARGET && target.baseline == Action::ConsoleBatch(1) {
                Ok(())
            } else {
                Err(LearnError::Evidence)
            }
        }
        fn legal_console(
            &self,
            target: ObjectKey,
            action: Action,
            _: u64,
        ) -> Result<(), LearnError> {
            if target == TARGET && matches!(action, Action::ConsoleBatch(1 | 8 | 32 | 64)) {
                Ok(())
            } else {
                Err(LearnError::Safety)
            }
        }
        fn verify_receipt(&self, receipt: &CanaryReceipt) -> Result<(), LearnError> {
            if receipt.evidence_hash == [7; 32] {
                Ok(())
            } else {
                Err(LearnError::Evidence)
            }
        }
        fn verify_measurement(
            &self,
            _: CanaryPermit,
            _: u16,
            _: &[WorkRequest],
            _: &[WorkRequest],
            digest: [u8; 32],
        ) -> Result<(), LearnError> {
            if digest != [0; 32] {
                Ok(())
            } else {
                Err(LearnError::Evidence)
            }
        }
        fn authorize_extension(
            &self,
            _: [u8; 32],
            _: CanaryPermit,
            _: u64,
            _: u16,
        ) -> Result<(), LearnError> {
            Ok(())
        }
        fn verify_restoration(
            &self,
            _: RestorationRequest,
            _: &RestorationReceipt,
        ) -> Result<(), LearnError> {
            Err(LearnError::Evidence)
        }
    }
    fn set(model: ModelBinding, at: u64, actions: &[Action]) -> CandidateSet {
        let choices: Vec<_> = actions
            .iter()
            .map(|action| Candidate {
                action: *action,
                features: features::RawFeatures {
                    control_capacity: Some(1000),
                    ..features::RawFeatures::default()
                },
            })
            .collect();
        CandidateSet::new(
            Snapshot {
                sequence: 1,
                taken_ns: at,
                ledger_generation: 1,
                core_generation: 1,
            },
            TARGET,
            model,
            &choices,
            Some(actions[0]),
        )
        .unwrap()
    }
    let seed = UntrainedSeed::new(0);
    with_validated(seed.bytes(), 0, |candidate| {
        let (mut bank, _, original) = ready(seed.bytes());
        let publisher = Publisher {
            object: ObjectKey {
                id: 7,
                generation: 1,
            },
            controller_epoch: 9,
        };
        let mut registry = Registry::new(11, publisher, original).unwrap();
        let mut gate = CommitGate::new(11, original).unwrap();
        let mut governance = Governance::new(&gate, candidate, seed.bytes(), 0).unwrap();
        let staged = bank.stage(candidate).unwrap();
        let old_pin = bank.pin(original).unwrap();
        let canary_pin = bank.pin(staged).unwrap();
        let mut budget = ExtraBudget::new();
        for window in 0..10 {
            let families = if window == 0 {
                &support::FAMILIES[..]
            } else {
                &support::FAMILIES[..1]
            };
            for (index, family) in families.iter().enumerate() {
                let at = window * WINDOW_NS + index as u64 * 10_000;
                let credit = budget
                    .reserve(Role::Shadow, 1, 1, 1024 * 1024, at, 10_000, &Authority)
                    .unwrap();
                let proof = governance
                    .score_shadow(&set(original, at, &support::choices(*family)), &credit)
                    .unwrap();
                let cost = budget.settle(credit, 1000, at + 1000).unwrap();
                governance.record_shadow(proof, cost).unwrap();
            }
            governance
                .close_shadow_window((window + 1) * WINDOW_NS)
                .unwrap();
        }
        let permit = governance
            .begin_canary(
                &mut gate,
                TargetRegistration {
                    key: TARGET,
                    baseline: Action::ConsoleBatch(1),
                },
                10 * WINDOW_NS,
                &Authority,
            )
            .unwrap();
        let mut candidate_set = set(staged, permit.start_ns, &[Action::ConsoleBatch(8)]);
        registry
            .register_canary(
                publisher,
                &mut candidate_set,
                permit,
                &gate,
                permit.start_ns,
            )
            .unwrap();
        let credit = budget
            .reserve(
                Role::Canary,
                1,
                1,
                1024 * 1024,
                permit.start_ns,
                10_000,
                &Authority,
            )
            .unwrap();
        let proof = governance.score_canary(&candidate_set, &credit).unwrap();
        proof
            .verify_selection(
                candidate_set.hash(),
                staged,
                TARGET,
                permit.start_ns,
                0,
                Action::ConsoleBatch(8),
            )
            .unwrap();
        let cost = budget.settle(credit, 1000, permit.start_ns + 1000).unwrap();
        let apply = ApplyId {
            boot_epoch: 11,
            controller_epoch: 9,
            plan_seq: 1,
            action_index: 0,
            target: TARGET,
        };
        let stamp = PolicyStamp::for_action(
            Action::ConsoleBatch(8),
            1,
            permit.start_ns,
            permit.start_ns + 1000,
        )
        .unwrap();
        governance
            .publish(
                &mut gate,
                permit.start_ns + 1000,
                proof,
                cost,
                apply,
                stamp,
                &Authority,
            )
            .unwrap();
        let receipt = CanaryReceipt {
            apply,
            plan_version: 1,
            executor_generation: 1,
            model: staged,
            state: ExecutionState::Unknown,
            actual: None,
            started_ns: permit.start_ns + 1001,
            finished_ns: permit.start_ns + 1002,
            installed_until_ns: stamp.installed_until_ns,
            evidence_hash: [7; 32],
        };
        governance
            .reconcile(&mut gate, receipt, &Authority)
            .unwrap();
        let mut work = RewardWorkspace::new();
        for second in 0..10 {
            let start = permit.start_ns + u64::from(second) * 1_000_000_000;
            let requests: Vec<_> = (0..100)
                .map(|i| WorkRequest {
                    id: i + 1,
                    arrived_ns: start + i * 1_000_000,
                    result: RequestResult::Completed {
                        finished_ns: start + i * 1_000_000 + 1000,
                    },
                })
                .collect();
            governance
                .observe_second(
                    &mut gate, second, &requests, &requests, &mut work, &Authority,
                )
                .unwrap();
        }
        governance.freeze().unwrap();
        let promoted = ModelBinding {
            generation: 8,
            ..staged
        };
        {
            let bank_change = bank
                .prepare_change(promoted, ChangeKind::Promotion)
                .unwrap();
            let registry_change = registry.prepare_model_change(publisher, promoted).unwrap();
            assert_eq!(
                governance.promote(&mut gate, permit.expires_ns),
                Err(LearnError::Unknown)
            );
            drop(registry_change);
            drop(bank_change);
        }
        assert_eq!(bank.active(), Ok(original));
        assert_eq!(registry.model(), original);
        assert_eq!(gate.active(), original);
        assert_eq!(governance.stage(), Stage::Frozen);
        governance
            .reconcile(
                &mut gate,
                CanaryReceipt {
                    state: ExecutionState::Applied,
                    actual: Some(Action::ConsoleBatch(8)),
                    ..receipt
                },
                &Authority,
            )
            .unwrap();
        {
            let bank_change = bank
                .prepare_change(promoted, ChangeKind::Promotion)
                .unwrap();
            let registry_change = registry.prepare_model_change(publisher, promoted).unwrap();
            assert_eq!(
                governance.promote(&mut gate, permit.expires_ns).unwrap(),
                promoted
            );
            assert_eq!(registry_change.commit(), promoted);
            assert_eq!(bank_change.commit(), promoted);
        }
        assert_eq!(bank.active(), Ok(promoted));
        assert_eq!(registry.model(), promoted);
        assert_eq!(gate.active(), promoted);
        assert_eq!(old_pin.binding(), original);
        assert_eq!(canary_pin.binding(), staged);
        let rollback = ModelBinding {
            generation: 9,
            ..original
        };
        {
            let bank_change = bank.prepare_change(rollback, ChangeKind::Rollback).unwrap();
            let stale = Publisher {
                controller_epoch: 10,
                ..publisher
            };
            assert_eq!(
                registry.prepare_model_change(stale, rollback).err(),
                Some(Error::Auth)
            );
            // The governor has not been called and the first reservation is
            // abandoned. No member of the three-owner state has switched.
            drop(bank_change);
        }
        assert_eq!(gate.active(), promoted);
        assert_eq!(governance.stage(), Stage::Active);
        {
            let bank_change = bank.prepare_change(rollback, ChangeKind::Rollback).unwrap();
            let registry_change = registry.prepare_model_change(publisher, rollback).unwrap();
            assert_eq!(governance.rollback(&mut gate).unwrap(), rollback);
            assert_eq!(registry_change.commit(), rollback);
            assert_eq!(bank_change.commit(), rollback);
        }
        assert_eq!(bank.active(), Ok(rollback));
        assert_eq!(registry.model(), rollback);
        assert_eq!(gate.active(), rollback);
        assert_eq!(gate.restoration_pending(), Some(TARGET));
        assert_eq!(
            gate.check_active_publication(rollback, TARGET),
            Err(LearnError::State)
        );
        assert_eq!(old_pin.binding(), original);
        assert_eq!(canary_pin.binding(), staged);
        bank.release(&old_pin).unwrap();
        bank.release(&canary_pin).unwrap();
    });
}
