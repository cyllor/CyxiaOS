//! Synthetic protected-owner fixtures for mechanism tests only. These records
//! are not native evidence and must never be exported as the 144/72 dataset.
#![allow(dead_code)]
use cyxia_prototype::learning::{
    Error, Family, ReplayGroup, SchemaBinding, Schemas, learning_config, manifest::UntrainedSeed,
    reward::*, reward_schema,
};
use cyxia_prototype::{
    domains::{Action, ApplyId, ObjectKey},
    features::RawFeatures,
    model::{MODEL_BYTES, Model},
    policy::{Candidate, CandidateSet, ExecutionState, ModelBinding, Snapshot},
};
use sha2::{Digest, Sha256};

pub fn schemas() -> Schemas {
    Schemas {
        feature: SchemaBinding {
            version: 13,
            hash: [17; 32],
        },
        action: SchemaBinding {
            version: 13,
            hash: [18; 32],
        },
        reward: reward_schema(),
        learning: learning_config(),
    }
}
pub const FAMILIES: [Family; 18] = [
    Family { domain: 1, kind: 1 },
    Family { domain: 1, kind: 2 },
    Family { domain: 2, kind: 1 },
    Family { domain: 3, kind: 1 },
    Family { domain: 4, kind: 1 },
    Family { domain: 5, kind: 1 },
    Family { domain: 6, kind: 1 },
    Family { domain: 7, kind: 1 },
    Family { domain: 8, kind: 1 },
    Family { domain: 9, kind: 1 },
    Family {
        domain: 10,
        kind: 1,
    },
    Family {
        domain: 11,
        kind: 1,
    },
    Family {
        domain: 12,
        kind: 1,
    },
    Family {
        domain: 13,
        kind: 1,
    },
    Family {
        domain: 14,
        kind: 1,
    },
    Family {
        domain: 15,
        kind: 1,
    },
    Family {
        domain: 16,
        kind: 1,
    },
    Family {
        domain: 16,
        kind: 2,
    },
];
pub fn choices(f: Family) -> Vec<Action> {
    match (f.domain, f.kind) {
        (1, 1) => vec![Action::CpuWeight(1), Action::CpuWeight(8)],
        (1, 2) => vec![Action::ControlSet(1), Action::ControlSet(3)],
        (2, _) => vec![Action::SpawnTokens(1), Action::SpawnTokens(8)],
        (3, _) => vec![
            Action::Cache {
                pages: 64,
                batch: 4,
            },
            Action::Cache {
                pages: 4096,
                batch: 64,
            },
        ],
        (4, _) => vec![
            Action::Filesystem {
                readahead: 0,
                flush: 4,
            },
            Action::Filesystem {
                readahead: 16,
                flush: 32,
            },
        ],
        (5, _) => vec![
            Action::Ipc {
                budget: 8,
                batch: 1,
            },
            Action::Ipc {
                budget: 128,
                batch: 16,
            },
        ],
        (6, _) => vec![Action::IrqTarget(0), Action::IrqTarget(3)],
        (7, _) => vec![Action::SoftCoalesce(0), Action::SoftCoalesce(1000)],
        (8, _) => vec![Action::ServiceBatch(1), Action::ServiceBatch(8)],
        (9, _) => vec![Action::IoShare(100), Action::IoShare(750)],
        (10, _) => vec![Action::TxBatch(1), Action::TxBatch(16)],
        (11, _) => vec![Action::NotifyBatch(1), Action::NotifyBatch(8)],
        (12, _) => vec![Action::UnauthRate(4), Action::UnauthRate(32)],
        (13, _) => vec![Action::BackgroundBudget(50), Action::BackgroundBudget(400)],
        (14, _) => vec![Action::RecoveryRecipe(0), Action::RecoveryRecipe(2)],
        (15, _) => vec![Action::ConsoleBatch(1), Action::ConsoleBatch(64)],
        (16, 1) => vec![Action::OfferCpu(100), Action::OfferCpu(1000)],
        (16, 2) => vec![Action::Placement(0), Action::Placement(2)],
        _ => panic!("family"),
    }
}
pub fn set(
    model: &[u8; MODEL_BYTES],
    family: Family,
    snapshot: u64,
    sequence: u64,
) -> CandidateSet {
    let actions = choices(family);
    let entries: Vec<_> = actions
        .iter()
        .map(|action| {
            let mut raw = RawFeatures::default();
            raw.control_capacity = Some(if let Action::ControlSet(mask) = action {
                u64::from(mask.count_ones()) * 1000
            } else {
                1000
            });
            Candidate {
                action: *action,
                features: raw,
            }
        })
        .collect();
    CandidateSet::new(
        Snapshot {
            sequence,
            taken_ns: snapshot,
            ledger_generation: 1,
            core_generation: 1,
        },
        ObjectKey {
            id: 1,
            generation: 1,
        },
        ModelBinding {
            generation: 1,
            model_hash: Sha256::digest(model).into(),
            schema_hash: schemas().feature.hash,
        },
        &entries,
        Some(actions[0]),
    )
    .unwrap()
}
pub fn probes(model: &[u8; MODEL_BYTES]) -> Vec<CandidateSet> {
    FAMILIES.into_iter().map(|f| set(model, f, 1, 1)).collect()
}
pub struct TestAuthority;
impl EvidenceAuthority for TestAuthority {
    fn attest(&self, trial: &Trial<'_>, hash: [u8; 32]) -> Result<(), Error> {
        if hash == [0; 32] || trial.local_node != [1; 32] {
            Err(Error::Evidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
pub struct Faults {
    pub unknown: bool,
    pub missing_partner: bool,
    pub mismatched_arrival: bool,
    pub wrong_score: bool,
    pub unsafe_candidate: bool,
    pub pending_request: bool,
    pub broken_renewal: bool,
    pub stale_schema: bool,
    pub saturated_cpu: bool,
}
pub fn sample(
    family: Family,
    group_seed: u64,
    id: u64,
    faults: Faults,
) -> Result<AcceptedSample, Error> {
    let seed = UntrainedSeed::new(0);
    let model = seed.bytes();
    let obs = 3_000_000_000;
    let end = obs + OBSERVATION_NS;
    let close = end + 100_000_000;
    let one = choices(family)[0].one_shot();
    let first_time = if one { obs } else { 1_000_000_000 };
    let sets = [
        set(model, family, first_time, 1),
        set(model, family, 9_000_000_000, 2),
    ];
    let scores: Vec<Vec<i16>> = sets
        .iter()
        .map(|s| {
            s.iter()
                .map(|c| {
                    Model::parse(model).unwrap().score(
                        &cyxia_prototype::features::encode(c.action, c.features)
                            .unwrap()
                            .values,
                    )
                })
                .collect()
        })
        .collect();
    let ids = [
        ApplyId {
            boot_epoch: 1,
            controller_epoch: 1,
            plan_seq: 1,
            action_index: 0,
            target: ObjectKey {
                id: 1,
                generation: 1,
            },
        },
        ApplyId {
            boot_epoch: 1,
            controller_epoch: 1,
            plan_seq: 2,
            action_index: 0,
            target: ObjectKey {
                id: 1,
                generation: 1,
            },
        },
    ];
    let concurrent = [[ids[0]], [ids[1]]];
    let mut actual_scores = scores.clone();
    if faults.wrong_score {
        actual_scores[0][0] = actual_scores[0][0].wrapping_add(1);
    }
    let mut adoptions = Vec::new();
    for i in 0..if one { 1 } else { 2 } {
        let selected = if scores[i][1] > scores[i][0] { 1 } else { 0 };
        let at = sets[i].snapshot.taken_ns;
        adoptions.push(Adoption {
            decision_seq: i as u64 + 1,
            apply: ids[i],
            plan_version: i as u64 + 1,
            executor_generation: 1,
            candidates: &sets[i],
            model,
            scores: &actual_scores[i],
            selected: selected as u16,
            actual: sets[i].get(selected).unwrap().action,
            executed: if faults.unknown {
                ExecutionState::Unknown
            } else {
                ExecutionState::Applied
            },
            issued_ns: at,
            accepted_ns: at,
            expires_local_ns: at + 100_000_000,
            active_until_local_ns: if one { 0 } else { at + OBSERVATION_NS },
            target_request_id: one.then_some(1),
            started_ns: at,
            finished_ns: at + 1000,
            installed_until_ns: if one {
                0
            } else if faults.broken_renewal && i == 1 {
                at + 1
            } else {
                at + 10_000_000_000
            },
            approved_deadline_ns: at + 50_000_000,
            concurrent: &concurrent[i],
            shared_policy_intervals: &[],
        });
    }
    let baseline_receipts = [BaselineAdoption {
        owner_boot: 1,
        receipt_sequence: 1,
        target: ObjectKey {
            id: 1,
            generation: 1,
        },
        executor_generation: 1,
        snapshot: Snapshot {
            sequence: 1,
            taken_ns: first_time,
            ledger_generation: 1,
            core_generation: 1,
        },
        actual: choices(family)[0],
        executed: ExecutionState::Applied,
        issued_ns: first_time,
        accepted_ns: first_time,
        target_request_id: one.then_some(1),
        started_ns: first_time,
        finished_ns: first_time + 1000,
        installed_until_ns: if one { 0 } else { u64::MAX },
        approved_deadline_ns: first_time + 50_000_000,
    }];
    let candidate_requests: Vec<_> = (0..100)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: obs + i * 1_000_000,
            result: if faults.pending_request && i == 99 {
                RequestResult::Pending
            } else {
                RequestResult::Completed {
                    finished_ns: obs + i * 1_000_000 + 5000,
                }
            },
        })
        .collect();
    let mut baseline_requests: Vec<_> = (0..100)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: obs + i * 1_000_000,
            result: RequestResult::Completed {
                finished_ns: obs + i * 1_000_000 + 10000,
            },
        })
        .collect();
    if faults.mismatched_arrival {
        baseline_requests[0].arrived_ns += 1;
    }
    let required = if family.domain == 13 { 7 } else { 3 };
    let coverage = [CpuCoverage {
        node: [1; 32],
        first_ns: first_time,
        observation_ns: obs,
        observation_end_ns: end,
        closing_ns: close,
        required,
        reported: required,
    }];
    let mut cpu = vec![
        CpuInterval {
            node: [1; 32],
            core: 1,
            start_ns: first_time,
            end_ns: first_time + 2000,
            class: CpuClass::Policy,
        },
        CpuInterval {
            node: [1; 32],
            core: 1,
            start_ns: first_time + 1000,
            end_ns: first_time + 3000,
            class: CpuClass::ExecutorAction,
        },
    ];
    if faults.saturated_cpu {
        cpu.push(CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: obs,
            end_ns: end,
            class: CpuClass::ExecutorWork,
        });
    }
    let nodes = if faults.missing_partner {
        vec![[1; 32], [2; 32]]
    } else {
        vec![[1; 32]]
    };
    let mut schema = schemas();
    if faults.stale_schema {
        schema.reward.hash[0] ^= 1;
    }
    let group = ReplayGroup {
        seed: group_seed,
        workload: [3; 32],
        initial_image: [4; 32],
    };
    let candidate = Trial {
        id: id * 2 + 1,
        family,
        group,
        frozen_other_domains: [5; 32],
        schemas: schema,
        local_node: [1; 32],
        controlled_nodes: &nodes,
        observation_ns: obs,
        observation_end_ns: end,
        warmed_from_ns: obs - 1_000_000_000,
        closing_ns: close,
        requests: &candidate_requests,
        adoptions: &adoptions,
        coverage: &coverage,
        cpu: &cpu,
        baseline: &[],
        joint_policy: &[],
        correct: !faults.unsafe_candidate,
        frozen: true,
        closing: ExecutionState::Applied,
        ordinary_warmup_cpu_ns: 12_000,
        later_workload_cpu_ns: 0,
        peak_workspace_bytes: 64 * 1024,
    };
    let baseline = Trial {
        id: id * 2 + 2,
        family,
        group,
        frozen_other_domains: [5; 32],
        schemas: schema,
        local_node: [1; 32],
        controlled_nodes: &nodes,
        observation_ns: obs,
        observation_end_ns: end,
        warmed_from_ns: obs - 1_000_000_000,
        closing_ns: close,
        requests: &baseline_requests,
        adoptions: &[],
        coverage: &coverage,
        cpu: &cpu,
        baseline: &baseline_receipts,
        joint_policy: &[],
        correct: true,
        frozen: true,
        closing: ExecutionState::Applied,
        ordinary_warmup_cpu_ns: 12_000,
        later_workload_cpu_ns: 0,
        peak_workspace_bytes: 64 * 1024,
    };
    pair(
        &candidate,
        &baseline,
        &TestAuthority,
        &mut RewardWorkspace::new(),
    )
}
pub fn dataset() -> (Vec<AcceptedSample>, Vec<AcceptedSample>) {
    dataset_with_cost(false)
}
pub fn dataset_with_cost(saturated_cpu: bool) -> (Vec<AcceptedSample>, Vec<AcceptedSample>) {
    let mut training = Vec::new();
    let mut validation = Vec::new();
    let mut id = 1;
    for family in FAMILIES {
        for _ in 0..8 {
            training.push(
                sample(
                    family,
                    1,
                    id,
                    Faults {
                        saturated_cpu,
                        ..Faults::default()
                    },
                )
                .unwrap(),
            );
            id += 1;
        }
        for _ in 0..4 {
            validation.push(
                sample(
                    family,
                    2,
                    id,
                    Faults {
                        saturated_cpu,
                        ..Faults::default()
                    },
                )
                .unwrap(),
            );
            id += 1;
        }
    }
    (training, validation)
}
pub fn with_candidate(
    run: impl FnOnce(&cyxia_prototype::learning::validate::ValidatedCandidate<'_>, &[u8; MODEL_BYTES]),
) {
    use cyxia_prototype::learning::{
        data::FrozenData,
        manifest::{ModelManifest, SealedModel},
        train::Trainer,
        validate::*,
    };
    let (training, validation) = dataset();
    let data = FrozenData::freeze(&training, &validation, 7, schemas()).unwrap();
    let seed = UntrainedSeed::new(0);
    let mut trainer = Trainer::start(seed.bytes(), &data).unwrap();
    while trainer.step_next().unwrap() {}
    let model = trainer.finish().unwrap();
    let mut cases = Vec::new();
    let mut selections = Vec::new();
    for set in probes(model.bytes()) {
        let first = cases.len();
        let mut selected = 0;
        let mut score = i16::MIN;
        for (index, c) in set.iter().enumerate() {
            let input = cyxia_prototype::features::encode(c.action, c.features)
                .unwrap()
                .values;
            let trace = integer_reference(model.bytes(), &input);
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
    let vectors = ReferenceSuite {
        parameters_hash: Sha256::digest(model.bytes()).into(),
        cases: &cases,
        selections: &selections,
    };
    let manifest = ModelManifest::learned(&model, schemas(), &vectors, 1024 * 1024).unwrap();
    let sealed = SealedModel::seal(model.bytes(), manifest, schemas(), &vectors).unwrap();
    let candidate =
        ValidatedCandidate::register(seed.bytes(), sealed, &data, &probes(model.bytes())).unwrap();
    run(&candidate, seed.bytes());
}
