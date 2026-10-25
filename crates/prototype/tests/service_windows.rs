//! Synthetic request events exercise the same native aggregation function;
//! these tests do not constitute actual SLO or replay measurements.
#[path = "../../../kernel/src/service_windows/aggregate.rs"]
mod aggregate;
#[path = "support/learning.rs"]
mod support;
use aggregate::*;
use cyxia_prototype::{
    domains::{
        Error, ObjectKey,
        stability::{Boundary, FreezeReason, Guard, ServiceStatus, ServiceWindow},
    },
    learning::reward::{OBSERVATION_NS, RequestResult, WorkRequest},
};
fn rows(start: u64, count: usize, completed: usize) -> Vec<(WorkRequest, Option<RequestResult>)> {
    (0..count)
        .map(|i| {
            let arrived = start + 100 + i as u64;
            let result = if i < completed {
                RequestResult::Completed {
                    finished_ns: arrived + i as u64 + 1,
                }
            } else {
                RequestResult::Pending
            };
            (
                WorkRequest {
                    id: i as u64 + 1,
                    arrived_ns: arrived,
                    result,
                },
                Some(result),
            )
        })
        .collect()
}
#[test]
fn actual_results_and_window_end_determine_counts_and_exact_percentiles() {
    let mut input = rows(0, 100, 100);
    let mut work = [0; 128];
    assert_eq!(
        summarize(&input, COMPLETED_P99_NS, 0, &mut work)
            .unwrap()
            .value,
        Some(99)
    );
    input[99].1 = Some(RequestResult::Completed {
        finished_ns: SECOND_NS + 1,
    });
    input[98].1 = Some(RequestResult::Rejected);
    let count = summarize(&input, COMPLETED_REQUESTS, 0, &mut work).unwrap();
    assert!(count.complete);
    assert_eq!((count.samples, count.value), (100, Some(98)));
    assert_eq!(
        summarize(&input, PENALIZED_P99_NS, 0, &mut work)
            .unwrap()
            .value,
        Some(OBSERVATION_NS)
    );
    // Arrival exactly at the next second belongs exclusively to that window.
    input.push((
        WorkRequest {
            id: 101,
            arrived_ns: SECOND_NS,
            result: RequestResult::Pending,
        },
        Some(RequestResult::Pending),
    ));
    assert_eq!(
        summarize(&input, COMPLETED_REQUESTS, 0, &mut work)
            .unwrap()
            .samples,
        100
    );
    assert_eq!(
        summarize(&input, COMPLETED_REQUESTS, SECOND_NS, &mut work)
            .unwrap()
            .samples,
        1
    );
}
#[test]
fn absent_issue_and_empty_window_never_supply_a_successful_metric() {
    let mut work = [0; 128];
    let mut input = rows(0, 100, 100);
    input[7].1 = None;
    for metric in [COMPLETED_REQUESTS, COMPLETED_P99_NS, PENALIZED_P99_NS] {
        let measured = summarize(&input, metric, 0, &mut work).unwrap();
        assert_eq!(
            (measured.samples, measured.complete, measured.value),
            (100, false, None)
        );
        assert_eq!(summarize(&[], metric, 0, &mut work).unwrap().value, None);
    }
}
#[test]
fn three_actual_complete_breaches_freeze_every_action_family() {
    for family in support::FAMILIES {
        let baseline = support::choices(family)[0];
        let target = ObjectKey {
            id: 100 + family.index().unwrap() as u64,
            generation: 1,
        };
        let boundary = Boundary {
            id: 1,
            metric: COMPLETED_REQUESTS,
            minimum: 3,
            maximum: 100,
            min_samples: 4,
        };
        let mut guard = Guard::new(target, baseline, 0).unwrap();
        guard.register_boundary(boundary, 0, 0).unwrap();
        let mut work = [0; 128];
        for second in 0..3 {
            let start = second * SECOND_NS;
            let actual = summarize(&rows(start, 4, 2), boundary.metric, start, &mut work).unwrap();
            let window = ServiceWindow {
                target,
                domain: family.domain,
                kind: family.kind,
                boundary_id: boundary.id,
                metric: boundary.metric,
                start_ns: start,
                end_ns: start + SECOND_NS,
                covered_ns: if actual.complete { SECOND_NS } else { 0 },
                samples: actual.samples,
                value: actual.value,
            };
            let result = guard.observe_service(window, window.end_ns).unwrap();
            assert_eq!(result.status, ServiceStatus::Breached);
            assert_eq!(
                result.frozen,
                (second == 2).then_some(FreezeReason::ServiceBoundary)
            );
        }
    }
}
#[test]
fn incomplete_middle_window_breaks_the_consecutive_breach_streak() {
    let target = ObjectKey {
        id: 1,
        generation: 1,
    };
    let mut guard = Guard::new(target, cyxia_prototype::domains::Action::IoShare(100), 0).unwrap();
    let boundary = Boundary {
        id: 1,
        metric: COMPLETED_REQUESTS,
        minimum: 3,
        maximum: 4,
        min_samples: 4,
    };
    guard.register_boundary(boundary, 0, 0).unwrap();
    let mut work = [0; 128];
    for second in 0..4 {
        let start = second * SECOND_NS;
        let mut input = rows(start, 4, 1);
        if second == 1 {
            input[0].1 = None;
        }
        let actual = summarize(&input, boundary.metric, start, &mut work).unwrap();
        let window = ServiceWindow {
            target,
            domain: 9,
            kind: 1,
            boundary_id: 1,
            metric: boundary.metric,
            start_ns: start,
            end_ns: start + SECOND_NS,
            covered_ns: if actual.complete { SECOND_NS } else { 0 },
            samples: actual.samples,
            value: actual.value,
        };
        let result = guard.observe_service(window, window.end_ns).unwrap();
        if second == 1 {
            assert_eq!(result.status, ServiceStatus::Incomplete);
        }
        assert!(result.frozen.is_none());
    }
    assert_eq!(guard.consecutive_breaches(), 2);
}
#[test]
fn malformed_identity_capacity_and_clock_are_explicit_errors() {
    let mut input = rows(0, 4, 4);
    let mut work = [0; 128];
    input[1].0.id = input[0].0.id;
    assert_eq!(
        summarize(&input, COMPLETED_REQUESTS, 0, &mut work),
        Err(Error::Conflict)
    );
    let input = rows(0, 4, 4);
    assert_eq!(
        summarize(&input, COMPLETED_REQUESTS, 0, &mut [0; 3]),
        Err(Error::Capacity)
    );
    assert_eq!(
        summarize(&input, 999, 0, &mut work),
        Err(Error::Unsupported)
    );
    assert_eq!(
        summarize(&input, COMPLETED_REQUESTS, u64::MAX, &mut work),
        Err(Error::Overflow)
    );
}
