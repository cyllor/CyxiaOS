//! Independent synthetic counterexamples for the paired-evidence verifier.
//! These are mechanism tests, never native replay data or learning labels.
#[path = "support/learning.rs"]
mod support;

use cyxia_prototype::{
    domains::{ApplyId, ObjectKey},
    features,
    learning::{
        Error, Family, ReplayGroup,
        manifest::UntrainedSeed,
        reward::{
            AcceptedSample, Adoption, BaselineAdoption, CpuClass, CpuCoverage, CpuInterval,
            JointPolicySplit, OBSERVATION_NS, RequestResult, RewardWorkspace, Trial, WorkRequest,
            pair, split_joint_policy, union_cpu,
        },
    },
    model::Model,
    policy::{ExecutionState, Snapshot},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    None,
    ExpiredAcceptance,
    OrdinaryDeadlineExtended,
    CoreDeadlineFromExecution,
    RecoveryDeadlineFromExecution,
    OneShotLease,
    RenewalGap,
    UnknownCleanup,
    MissingTargetRequest,
    UnexpectedTargetRequest,
    BaselineDeadlineExtended,
    JointValid,
    JointMissingManifest,
    JointOmittedSplit,
    JointDuplicateSplit,
    JointWholeSegment,
    JointWrongShare,
    JointSourceOutsideCoverage,
}

fn trial_pair(family: Family, change: Change) -> Result<AcceptedSample, Error> {
    let seed = UntrainedSeed::new(0);
    let model = seed.bytes();
    let one_shot = support::choices(family)[0].one_shot();
    let observation_ns = 3_000_000_000;
    let observation_end_ns = observation_ns + OBSERVATION_NS;
    let closing_ns = observation_end_ns + 100_000_000;
    let first = if one_shot {
        observation_ns
    } else {
        1_000_000_000
    };
    let sets = [
        support::set(model, family, first, 1),
        support::set(model, family, 9_000_000_000, 2),
    ];
    let scores: Vec<Vec<_>> = sets
        .iter()
        .map(|set| {
            set.iter()
                .map(|candidate| {
                    Model::parse(model).unwrap().score(
                        &features::encode(candidate.action, candidate.features)
                            .unwrap()
                            .values,
                    )
                })
                .collect()
        })
        .collect();
    let target = ObjectKey {
        id: 1,
        generation: 1,
    };
    let own_index = u16::from(change == Change::JointSourceOutsideCoverage);
    let ids = [1, 2].map(|plan_seq| ApplyId {
        boot_epoch: 1,
        controller_epoch: 1,
        plan_seq,
        action_index: own_index,
        target,
    });
    let joint = matches!(
        change,
        Change::JointValid
            | Change::JointMissingManifest
            | Change::JointOmittedSplit
            | Change::JointDuplicateSplit
            | Change::JointWholeSegment
            | Change::JointWrongShare
            | Change::JointSourceOutsideCoverage
    );
    let concurrent = ids.map(|id| {
        if joint {
            let other = ApplyId {
                action_index: 1 - own_index,
                target: ObjectKey {
                    id: 2,
                    generation: 1,
                },
                ..id
            };
            if own_index == 0 {
                vec![id, other]
            } else {
                vec![other, id]
            }
        } else {
            vec![id]
        }
    });
    let shared = sets.each_ref().map(|set| {
        let start = set.snapshot.taken_ns
            - if change == Change::JointSourceOutsideCoverage {
                30
            } else {
                0
            };
        [CpuInterval {
            node: [1; 32],
            core: 1,
            start_ns: start,
            end_ns: start + 101,
            class: CpuClass::Policy,
        }]
    });
    let mut adoptions = Vec::new();
    for i in 0..if one_shot { 1 } else { 2 } {
        let selected = usize::from(scores[i][1] > scores[i][0]);
        let snapshot = sets[i].snapshot.taken_ns;
        let issued_ns = snapshot;
        let mut accepted_ns = snapshot + 100_000;
        let expires_local_ns = snapshot + 100_000_000;
        if i == 0 && change == Change::ExpiredAcceptance {
            accepted_ns = expires_local_ns + 1;
        }
        let mut started_ns = accepted_ns + 5_000;
        let mut finished_ns = started_ns + 1_000;
        let bound = match family {
            Family { domain: 1, kind: 2 } => 200_000_000,
            Family {
                domain: 14,
                kind: 1,
            } => 1_000_000_000,
            _ => 50_000_000,
        };
        let mut approved_deadline_ns = accepted_ns + bound;
        if i == 0 && change == Change::OrdinaryDeadlineExtended {
            finished_ns = approved_deadline_ns + 1;
            approved_deadline_ns = finished_ns;
        }
        if i == 0
            && matches!(
                change,
                Change::CoreDeadlineFromExecution | Change::RecoveryDeadlineFromExecution
            )
        {
            // Only 2 ms of execution, but the root's accepted-to-terminal
            // deadline has already elapsed. An execution-relative bound is wrong.
            started_ns = accepted_ns + bound - 1_000_000;
            finished_ns = accepted_ns + bound + 1_000_000;
            approved_deadline_ns = finished_ns;
        }
        let active_until_local_ns = if one_shot {
            0
        } else {
            snapshot + OBSERVATION_NS
        };
        let mut installed_until_ns = active_until_local_ns;
        if i == 0 && change == Change::OneShotLease {
            installed_until_ns = snapshot + OBSERVATION_NS;
        }
        if i == 1 && change == Change::RenewalGap {
            finished_ns = first + OBSERVATION_NS + 1;
            approved_deadline_ns = finished_ns;
        }
        adoptions.push(Adoption {
            decision_seq: i as u64 + 1,
            apply: ids[i],
            plan_version: i as u64 + 1,
            executor_generation: 1,
            candidates: &sets[i],
            model,
            scores: &scores[i],
            selected: selected as u16,
            actual: sets[i].get(selected).unwrap().action,
            executed: ExecutionState::Applied,
            issued_ns,
            accepted_ns,
            expires_local_ns,
            active_until_local_ns,
            target_request_id: if change == Change::UnexpectedTargetRequest {
                Some(0)
            } else {
                one_shot.then_some(if change == Change::MissingTargetRequest {
                    101
                } else {
                    1
                })
            },
            started_ns,
            finished_ns,
            installed_until_ns,
            approved_deadline_ns,
            concurrent: &concurrent[i],
            shared_policy_intervals: if joint && change != Change::JointMissingManifest {
                &shared[i]
            } else {
                &[]
            },
        });
    }
    let mut baseline_receipts = [BaselineAdoption {
        owner_boot: 1,
        receipt_sequence: 1,
        target,
        executor_generation: 1,
        snapshot: Snapshot {
            sequence: 1,
            taken_ns: first,
            ledger_generation: 1,
            core_generation: 1,
        },
        actual: support::choices(family)[0],
        executed: ExecutionState::Applied,
        issued_ns: first,
        accepted_ns: first + 100_000,
        target_request_id: one_shot.then_some(1),
        started_ns: first + 105_000,
        finished_ns: first + 106_000,
        installed_until_ns: if one_shot { 0 } else { u64::MAX },
        approved_deadline_ns: first + 50_100_000,
    }];
    if change == Change::BaselineDeadlineExtended {
        let bound = if family.domain == 1 {
            200_000_000
        } else {
            1_000_000_000
        };
        let b = &mut baseline_receipts[0];
        b.started_ns = b.accepted_ns + bound - 1_000_000;
        b.finished_ns = b.accepted_ns + bound + 1_000_000;
        b.approved_deadline_ns = b.finished_ns;
    }
    let requests: Vec<_> = (0..100)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: observation_ns + i * 1_000_000,
            result: RequestResult::Completed {
                finished_ns: observation_ns + i * 1_000_000 + 500_000,
            },
        })
        .collect();
    let coverage = [CpuCoverage {
        node: [1; 32],
        first_ns: first,
        observation_ns,
        observation_end_ns,
        closing_ns,
        required: 3,
        reported: 3,
    }];
    let mut cpu = vec![
        CpuInterval {
            node: [1; 32],
            core: 1,
            start_ns: first,
            end_ns: first + 100_000,
            class: CpuClass::Policy,
        },
        CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: first + 105_000,
            end_ns: first + 106_000,
            class: CpuClass::ExecutorAction,
        },
    ];
    let mut joint_policy = Vec::new();
    if joint {
        cpu.clear();
        for i in 0..adoptions.len() {
            let mut allocated = split_joint_policy(shared[i][0], 2, own_index).unwrap();
            if change == Change::JointWrongShare {
                allocated.end_ns += 1;
            }
            cpu.push(allocated);
            cpu.push(CpuInterval {
                node: [1; 32],
                core: 0,
                start_ns: adoptions[i].started_ns,
                end_ns: adoptions[i].finished_ns,
                class: CpuClass::ExecutorAction,
            });
            if !matches!(
                change,
                Change::JointMissingManifest | Change::JointOmittedSplit
            ) {
                joint_policy.push(JointPolicySplit {
                    source: shared[i][0],
                    actions: &concurrent[i],
                    action_index: own_index,
                });
                if change == Change::JointDuplicateSplit {
                    joint_policy.push(JointPolicySplit {
                        source: shared[i][0],
                        actions: &concurrent[i],
                        action_index: own_index,
                    });
                }
            }
            if change == Change::JointWholeSegment {
                cpu.push(shared[i][0]);
            }
        }
    }
    let nodes = [[1; 32]];
    let group = ReplayGroup {
        seed: 1,
        workload: [3; 32],
        initial_image: [4; 32],
    };
    let candidate = Trial {
        id: 1,
        family,
        group,
        frozen_other_domains: [5; 32],
        schemas: support::schemas(),
        local_node: [1; 32],
        controlled_nodes: &nodes,
        observation_ns,
        observation_end_ns,
        warmed_from_ns: observation_ns - 1_000_000_000,
        closing_ns,
        requests: &requests,
        adoptions: &adoptions,
        coverage: &coverage,
        cpu: &cpu,
        baseline: &[],
        joint_policy: &joint_policy,
        correct: true,
        frozen: true,
        closing: if change == Change::UnknownCleanup {
            ExecutionState::Unknown
        } else {
            ExecutionState::Applied
        },
        ordinary_warmup_cpu_ns: 1_000,
        later_workload_cpu_ns: 0,
        peak_workspace_bytes: 512 * 1024,
    };
    let baseline = Trial {
        id: 2,
        adoptions: &[],
        baseline: &baseline_receipts,
        joint_policy: &[],
        closing: ExecutionState::Applied,
        ..candidate
    };
    pair(
        &candidate,
        &baseline,
        &support::TestAuthority,
        &mut RewardWorkspace::new(),
    )
}

#[test]
fn execution_may_start_after_the_single_one_shot_request_is_issued() {
    for family in [
        Family { domain: 1, kind: 2 },
        Family {
            domain: 14,
            kind: 1,
        },
    ] {
        assert!(trial_pair(family, Change::None).is_ok());
    }
    assert!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::None
        )
        .is_ok()
    );
}

#[test]
fn a_declared_late_deadline_cannot_extend_the_real_publication_deadline() {
    assert!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::OrdinaryDeadlineExtended
        )
        .is_err()
    );
    assert!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::ExpiredAcceptance
        )
        .is_err()
    );
}

#[test]
fn core_and_recovery_deadlines_start_at_acceptance_not_executor_entry() {
    assert!(
        trial_pair(
            Family { domain: 1, kind: 2 },
            Change::CoreDeadlineFromExecution
        )
        .is_err()
    );
    assert!(
        trial_pair(
            Family {
                domain: 14,
                kind: 1
            },
            Change::RecoveryDeadlineFromExecution
        )
        .is_err()
    );
}

#[test]
fn one_shot_actions_cannot_claim_a_persistent_lease() {
    assert!(trial_pair(Family { domain: 1, kind: 2 }, Change::OneShotLease).is_err());
    assert!(
        trial_pair(
            Family {
                domain: 14,
                kind: 1
            },
            Change::OneShotLease
        )
        .is_err()
    );
}

#[test]
fn the_single_affected_request_must_belong_to_the_frozen_arrival_table() {
    for family in [
        Family { domain: 1, kind: 2 },
        Family {
            domain: 14,
            kind: 1,
        },
        Family {
            domain: 16,
            kind: 2,
        },
    ] {
        assert!(trial_pair(family, Change::MissingTargetRequest).is_err());
    }
}

#[test]
fn persistent_evidence_cannot_alias_an_absent_target_request_with_some_zero() {
    assert!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::UnexpectedTargetRequest
        )
        .is_err()
    );
}

#[test]
fn deterministic_baseline_cannot_extend_the_same_one_shot_safety_deadline() {
    for family in [
        Family { domain: 1, kind: 2 },
        Family {
            domain: 14,
            kind: 1,
        },
    ] {
        assert!(trial_pair(family, Change::BaselineDeadlineExtended).is_err());
    }
}

#[test]
fn joint_cost_is_complete_unique_and_contains_only_the_owned_nanosecond_share() {
    let family = Family {
        domain: 10,
        kind: 1,
    };
    let sample = trial_pair(family, Change::JointValid).unwrap();
    // Two root publications, each a 101 ns span shared by two actions.
    // This action owns index zero, hence 51 ns per publication including remainder.
    assert_eq!(sample.reward().candidate_cpu.policy_ns, 102);
    assert_eq!(sample.reward().candidate_cpu.executor_ns, 2_000);
    assert_eq!(sample.reward().candidate_cpu.union_ns, 2_102);
    for change in [
        Change::JointMissingManifest,
        Change::JointOmittedSplit,
        Change::JointDuplicateSplit,
        Change::JointWholeSegment,
        Change::JointWrongShare,
        Change::JointSourceOutsideCoverage,
    ] {
        assert!(trial_pair(family, change).is_err());
    }
    for family in [
        Family { domain: 1, kind: 2 },
        Family {
            domain: 14,
            kind: 1,
        },
    ] {
        assert!(trial_pair(family, Change::JointValid).is_err());
    }
}

#[test]
fn renewal_gaps_and_unknown_cleanup_do_not_produce_a_training_label() {
    assert!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::RenewalGap
        )
        .is_err()
    );
    assert_eq!(
        trial_pair(
            Family {
                domain: 10,
                kind: 1
            },
            Change::UnknownCleanup
        )
        .unwrap_err(),
        Error::Unknown
    );
}

#[test]
fn randomized_union_matches_an_independent_nanosecond_occupancy_oracle() {
    let mut state = 0x0479_6a31_c04d_9871u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let local_clocks = [1_000, 9_000_000_000_000u64];
    let coverage = local_clocks.map(|observation_ns| CpuCoverage {
        node: if observation_ns == local_clocks[0] {
            [1; 32]
        } else {
            [2; 32]
        },
        first_ns: observation_ns - 100,
        observation_ns,
        observation_end_ns: observation_ns + OBSERVATION_NS,
        closing_ns: observation_ns + OBSERVATION_NS + 100,
        required: 7,
        reported: 7,
    });
    let mut work = RewardWorkspace::new();
    for _ in 0..128 {
        let mut occupied = [[[[false; 3]; 128]; 3]; 2];
        let mut raw = [0u64; 3];
        let mut intervals = Vec::new();
        for _ in 0..64 {
            let node = (next() % 2) as usize;
            let core = (next() % 3) as usize;
            let start = (next() % 129) as usize;
            let end = start + (next() % (129 - start) as u64) as usize;
            let class = match next() % 4 {
                0 => CpuClass::Policy,
                1 => CpuClass::ExecutorAction,
                2 => CpuClass::ExecutorWork,
                _ => CpuClass::Optional,
            };
            let category = match class {
                CpuClass::Policy => 0,
                CpuClass::Optional => 2,
                _ => 1,
            };
            for tick in start..end {
                occupied[node][core][tick][category] = true;
            }
            raw[category] += (end - start) as u64;
            intervals.push(CpuInterval {
                node: coverage[node].node,
                core: core as u16,
                start_ns: local_clocks[node] + start as u64,
                end_ns: local_clocks[node] + end as u64,
                class,
            });
        }
        let mut expected = [0u64; 3];
        for node in occupied {
            for core in node {
                for tick in core {
                    if let Some(category) = tick.iter().position(|present| *present) {
                        expected[category] += 1;
                    }
                }
            }
        }
        let actual = union_cpu(
            Family {
                domain: 13,
                kind: 1,
            },
            &intervals,
            &coverage,
            &mut work,
        )
        .unwrap();
        assert_eq!(
            [actual.policy_ns, actual.executor_ns, actual.optional_ns],
            expected
        );
        assert_eq!(actual.union_ns, expected.iter().sum());
        assert_eq!(actual.raw_tagged_ns, raw);
    }
}
