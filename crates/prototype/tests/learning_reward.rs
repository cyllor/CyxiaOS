#[path = "support/learning.rs"]
mod support;
use cyxia_prototype::learning::{Error, Family, reward::*};

#[test]
fn insufficient_windows_keep_raw_penalties_but_do_not_hide_malformed_requests() {
    let mut work = RewardWorkspace::new();
    let requests = [WorkRequest {
        id: 1,
        arrived_ns: 100,
        result: RequestResult::Pending,
    }];
    let raw = inspect_one_second(&requests, 100, &mut work)
        .unwrap()
        .unwrap();
    assert_eq!(
        (raw.emitted, raw.pending, raw.penalty_p99_ns),
        (1, 1, OBSERVATION_NS)
    );
    assert_eq!(raw.actual_completed_p99_ns, None);
    assert_eq!(
        one_second_performance(&requests, 100, &mut work),
        Err(Error::DataIncomplete)
    );
    assert_eq!(inspect_one_second(&[], 100, &mut work), Ok(None));
    assert_eq!(
        one_second_performance(&[requests[0], requests[0]], 100, &mut work),
        Err(Error::Evidence)
    );
    let future = [WorkRequest {
        result: RequestResult::Completed {
            finished_ns: 1_000_000_101,
        },
        ..requests[0]
    }];
    assert_eq!(
        inspect_one_second(&future, 100, &mut work),
        Err(Error::Evidence)
    );
}

#[test]
fn cpu_union_deduplicates_by_node_core_and_priority_without_cross_node_clock_comparisons() {
    let f = Family {
        domain: 13,
        kind: 1,
    };
    let start = 1_000_000_000;
    let obs = start + 1_000_000_000;
    let end = obs + OBSERVATION_NS;
    let coverage = [
        CpuCoverage {
            node: [1; 32],
            first_ns: start,
            observation_ns: obs,
            observation_end_ns: end,
            closing_ns: end + 100,
            required: 7,
            reported: 7,
        },
        CpuCoverage {
            node: [2; 32],
            first_ns: 7,
            observation_ns: 8,
            observation_end_ns: 8 + OBSERVATION_NS,
            closing_ns: 9 + OBSERVATION_NS,
            required: 7,
            reported: 7,
        },
    ];
    let intervals = [
        CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: obs,
            end_ns: obs + 10,
            class: CpuClass::Policy,
        },
        CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: obs + 5,
            end_ns: obs + 15,
            class: CpuClass::ExecutorWork,
        },
        CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: obs + 8,
            end_ns: obs + 20,
            class: CpuClass::Optional,
        },
        CpuInterval {
            node: [1; 32],
            core: 1,
            start_ns: obs,
            end_ns: obs + 3,
            class: CpuClass::ExecutorWork,
        },
        CpuInterval {
            node: [2; 32],
            core: 0,
            start_ns: 8,
            end_ns: 10,
            class: CpuClass::Policy,
        },
        CpuInterval {
            node: [1; 32],
            core: 0,
            start_ns: obs + 7,
            end_ns: obs + 7,
            class: CpuClass::Policy,
        },
    ];
    let result = union_cpu(f, &intervals, &coverage, &mut RewardWorkspace::new()).unwrap();
    assert_eq!(
        (
            result.union_ns,
            result.policy_ns,
            result.executor_ns,
            result.optional_ns
        ),
        (25, 12, 8, 5)
    );
    assert_eq!(result.raw_tagged_ns, [12, 13, 12]);
    assert_eq!(
        union_cpu(
            Family {
                domain: 12,
                kind: 1
            },
            &intervals,
            &coverage,
            &mut RewardWorkspace::new()
        ),
        Err(Error::Evidence)
    );
}

#[test]
fn joint_publication_remainder_is_contiguous_exact_and_deterministic() {
    let original = CpuInterval {
        node: [1; 32],
        core: 2,
        start_ns: 100,
        end_ns: 110,
        class: CpuClass::Policy,
    };
    let pieces: Vec<_> = (0..3)
        .map(|i| split_joint_policy(original, 3, i).unwrap())
        .collect();
    assert_eq!(
        pieces
            .iter()
            .map(|v| v.end_ns - v.start_ns)
            .collect::<Vec<_>>(),
        [4, 3, 3]
    );
    assert_eq!(
        (
            pieces[0].start_ns,
            pieces[0].end_ns,
            pieces[1].start_ns,
            pieces[1].end_ns,
            pieces[2].start_ns,
            pieces[2].end_ns
        ),
        (100, 104, 104, 107, 107, 110)
    );
    assert_eq!(split_joint_policy(original, 3, 3), Err(Error::Evidence));
}

#[test]
fn incomplete_or_unsafe_evidence_never_becomes_a_label() {
    use support::{Faults, sample};
    let f = Family {
        domain: 10,
        kind: 1,
    };
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                unknown: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Unknown
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                missing_partner: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Evidence
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                mismatched_arrival: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Evidence
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                wrong_score: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Evidence
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                unsafe_candidate: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Safety
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                broken_renewal: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Evidence
    );
    assert_eq!(
        sample(
            f,
            1,
            1,
            Faults {
                stale_schema: true,
                ..Faults::default()
            }
        )
        .unwrap_err(),
        Error::Schema
    );
}

#[test]
fn pending_work_is_penalized_without_faking_completion_and_absolute_cost_enters_reward() {
    let sample = support::sample(
        Family {
            domain: 10,
            kind: 1,
        },
        1,
        1,
        support::Faults {
            pending_request: true,
            ..support::Faults::default()
        },
    )
    .unwrap();
    let reward = sample.reward();
    assert_eq!(reward.candidate.pending, 1);
    assert_eq!(reward.candidate.completed, 99);
    // nearest-rank p99 of 100 observations is the 99th, so one penalty is
    // present in raw counts but does not incorrectly become the 100th p100.
    assert_eq!(reward.candidate.penalty_p99_ns, 5000);
    assert_eq!(reward.candidate_cpu.union_ns, 3000);
    assert_eq!(
        f64::from_bits(reward.raw_cost.to_bits()),
        3000f64 / 10_000_000_000f64
    );
    let expected = 0.4 * (-0.01) - 0.4 * (-0.5) - 0.2 * (3000f64 / 10_000_000_000f64);
    // delta throughput is computed from binary64 X values in written order.
    let x = 99f64 / 10.;
    let x0 = 100f64 / 10.;
    let expected_written =
        0.4 * ((x - x0) / x0) - 0.4 * (-0.5) - 0.2 * (3000f64 / 10_000_000_000f64);
    assert_eq!(reward.value.to_bits(), expected_written.to_bits());
    assert!((expected - expected_written).abs() < 1e-14);
    let mut requests: Vec<_> = (0..100)
        .map(|i| WorkRequest {
            id: i + 1,
            arrived_ns: 1,
            result: RequestResult::Completed { finished_ns: 2 },
        })
        .collect();
    requests[98].result = RequestResult::Rejected;
    requests[99].result = RequestResult::TimedOut;
    let p = performance(&requests, 1, &mut RewardWorkspace::new()).unwrap();
    assert_eq!(p.penalty_p99_ns, OBSERVATION_NS);
    assert_eq!(p.actual_completed_p99_ns, Some(1));
}
