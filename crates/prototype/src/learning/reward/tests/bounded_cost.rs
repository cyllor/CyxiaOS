//! Golden comparisons of the production cursors, not native CPU evidence.
extern crate std;

use super::super::{performance, union_cpu};
use super::*;
use std::{boxed::Box, vec, vec::Vec};

fn large_test(body: impl FnOnce() + Send + 'static) {
    // The oracle and incremental path each need their own full workspace.
    // Native stack bounds are checked against the actual AArch64 ELF.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}
fn coverage(node: u8, observation: u64, optional: bool) -> CpuCoverage {
    CpuCoverage {
        node: [node; 32],
        first_ns: observation.saturating_sub(10),
        observation_ns: observation,
        observation_end_ns: observation + OBSERVATION_NS,
        closing_ns: observation + OBSERVATION_NS + 10,
        required: if optional { 7 } else { 3 },
        reported: if optional { 7 } else { 3 },
    }
}
fn interval(node: u8, core: u16, start: u64, end: u64, class: CpuClass) -> CpuInterval {
    CpuInterval {
        node: [node; 32],
        core,
        start_ns: start,
        end_ns: end,
        class,
    }
}
fn compare_cpu(
    family: Family,
    rows: &[CpuInterval],
    coverage: &[CpuCoverage],
) -> (Result<CostTotals, Error>, usize) {
    let mut reference = Box::new(RewardWorkspace::new());
    let expected = union_cpu(family, rows, coverage, &mut reference);
    let mut work = Box::new(RewardWorkspace::new());
    let mut cursor = CpuCursor::new();
    assert_eq!(cursor.finish(), Err(Error::State));
    let mut turns = 0;
    let actual = loop {
        turns += 1;
        assert!(turns < 100_000, "bounded CPU traversal must converge");
        match cursor.step(family, rows, coverage, &mut work) {
            Ok(false) => assert_eq!(cursor.finish(), Err(Error::State)),
            Ok(true) => {
                let result = cursor.finish();
                assert_eq!(cursor.step(family, rows, coverage, &mut work), Ok(true));
                assert_eq!(cursor.finish(), result);
                break result;
            }
            Err(error) => {
                assert_eq!(cursor.finish(), Err(error));
                assert_eq!(cursor.step(family, rows, coverage, &mut work), Err(error));
                break Err(error);
            }
        }
    };
    assert_eq!(actual, expected);
    (actual, turns)
}
fn requests(count: usize, start: u64) -> Vec<WorkRequest> {
    (0..count)
        .map(|i| {
            let at = start + i as u64 * 1_000_000;
            WorkRequest {
                id: i as u64 + 1,
                arrived_ns: at,
                result: RequestResult::Completed {
                    finished_ns: at + (count - i) as u64 * 1000,
                },
            }
        })
        .collect()
}
fn compare_performance(rows: &[WorkRequest], start: u64) -> (Result<Performance, Error>, usize) {
    let mut reference = Box::new(RewardWorkspace::new());
    let expected = performance(rows, start, &mut reference);
    let mut work = Box::new(RewardWorkspace::new());
    let mut cursor = PerformanceCursor::new();
    assert_eq!(cursor.finish(), Err(Error::State));
    let mut turns = 0;
    let actual = loop {
        turns += 1;
        assert!(turns < 100_000, "bounded latency traversal must converge");
        match cursor.step(rows, start, &mut work) {
            Ok(false) => assert_eq!(cursor.finish(), Err(Error::State)),
            Ok(true) => {
                let result = cursor.finish();
                assert_eq!(cursor.step(rows, start, &mut work), Ok(true));
                break result;
            }
            Err(error) => {
                assert_eq!(cursor.finish(), Err(error));
                assert_eq!(cursor.step(rows, start, &mut work), Err(error));
                break Err(error);
            }
        }
    };
    assert_eq!(actual, expected);
    if actual.is_ok() {
        assert_eq!(
            &work.latencies[..rows.len()],
            &reference.latencies[..rows.len()]
        );
    }
    (actual, turns)
}

#[test]
fn overlaps_priorities_parallel_cores_and_node_clocks_match_the_sync_oracle() {
    large_test(|| {
        let family = Family {
            domain: 13,
            kind: 1,
        };
        let cov = [coverage(1, 20, true), coverage(2, 400, true)];
        let end = cov[0].observation_end_ns;
        let mut rows = vec![
            interval(1, 0, 20, 120, CpuClass::Optional),
            interval(1, 0, 30, 80, CpuClass::ExecutorWork),
            interval(1, 0, 40, 60, CpuClass::Policy),
            interval(1, 0, 50, 70, CpuClass::ExecutorAction),
            interval(1, 0, 70, 70, CpuClass::Policy),
            interval(1, 1, 20, 35, CpuClass::Policy),
            interval(2, 0, 400, 420, CpuClass::Optional),
            interval(2, 0, 405, 415, CpuClass::ExecutorWork),
            interval(2, 0, 410, 413, CpuClass::Policy),
            interval(1, 0, 10, 20, CpuClass::Policy),
            interval(1, 0, end, end + 10, CpuClass::ExecutorAction),
        ];
        for _ in 0..rows.len() {
            let total = compare_cpu(family, &rows, &cov).0.unwrap();
            assert_eq!(
                total,
                CostTotals {
                    union_ns: 155,
                    policy_ns: 48,
                    executor_ns: 47,
                    optional_ns: 60,
                    raw_tagged_ns: [48, 90, 120]
                }
            );
            rows.rotate_left(1);
        }
        rows.reverse();
        compare_cpu(family, &rows, &cov).0.unwrap();
        assert_eq!(compare_cpu(family, &[], &cov).0.unwrap().union_ns, 0);
    });
}

#[test]
fn randomized_event_order_and_the_8192_limit_are_resumable_and_exact() {
    large_test(|| {
        let family = Family {
            domain: 13,
            kind: 1,
        };
        let cov: Vec<_> = (1..=16)
            .map(|n| coverage(n, 1000 * u64::from(n), true))
            .collect();
        let mut seed = 0x6f4d_98ac_1234_5678u64;
        for len in [1, 2, 3, 31, 32, 63, 64, 65, 127, 511, MAX_CPU_INTERVALS] {
            let mut rows = Vec::with_capacity(len);
            for i in 0..len {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let n = (seed as usize % cov.len()) as u8 + 1;
                let at = cov[usize::from(n - 1)].observation_ns + (seed >> 17) % 10_000;
                let class = [
                    CpuClass::Policy,
                    CpuClass::ExecutorAction,
                    CpuClass::ExecutorWork,
                    CpuClass::Optional,
                ][i % 4];
                rows.push(interval(
                    n,
                    ((seed >> 9) % 64) as u16,
                    at,
                    at + (seed >> 32) % 800,
                    class,
                ));
            }
            let (result, turns) = compare_cpu(family, &rows, &cov);
            assert!(result.is_ok());
            if len == MAX_CPU_INTERVALS {
                assert!(turns > MAX_CPU_INTERVALS / OPERATIONS_PER_STEP);
                rows.push(rows[0]);
                assert_eq!(compare_cpu(family, &rows, &cov).0, Err(Error::Capacity));
            }
        }
    });
}

#[test]
fn cpu_coverage_boundaries_missing_evidence_and_numeric_errors_stay_identical() {
    large_test(|| {
        let family = Family {
            domain: 13,
            kind: 1,
        };
        let base = coverage(1, 100, true);
        let row = interval(1, 0, 100, 110, CpuClass::ExecutorWork);
        assert_eq!(compare_cpu(family, &[row], &[]).0, Err(Error::Capacity));
        assert_eq!(
            compare_cpu(family, &[row], &vec![base; 17]).0,
            Err(Error::Capacity)
        );
        assert!(
            compare_cpu(Family { domain: 0, kind: 1 }, &[row], &[base])
                .0
                .is_err()
        );
        assert_eq!(
            compare_cpu(family, &[row], &[base, base]).0,
            Err(Error::Evidence)
        );
        for bad in [
            CpuCoverage {
                node: [0; 32],
                ..base
            },
            CpuCoverage {
                required: 3,
                ..base
            },
            CpuCoverage {
                reported: 3,
                ..base
            },
            CpuCoverage {
                reported: 15,
                ..base
            },
            CpuCoverage {
                first_ns: 101,
                ..base
            },
            CpuCoverage {
                observation_end_ns: base.observation_end_ns - 1,
                ..base
            },
            CpuCoverage {
                closing_ns: base.observation_end_ns - 1,
                ..base
            },
            CpuCoverage {
                closing_ns: base.observation_end_ns + 5_000_000_001,
                ..base
            },
        ] {
            assert_eq!(compare_cpu(family, &[row], &[bad]).0, Err(Error::Evidence));
        }
        for bad in [
            CpuInterval {
                node: [2; 32],
                ..row
            },
            CpuInterval { core: 64, ..row },
            CpuInterval {
                start_ns: 111,
                ..row
            },
            CpuInterval {
                start_ns: 99,
                ..row
            },
            CpuInterval {
                end_ns: base.observation_end_ns + 1,
                ..row
            },
            interval(1, 0, 89, 100, CpuClass::Policy),
            interval(
                1,
                0,
                base.closing_ns,
                base.closing_ns + 1,
                CpuClass::ExecutorAction,
            ),
        ] {
            assert_eq!(compare_cpu(family, &[bad], &[base]).0, Err(Error::Evidence));
        }
        assert_eq!(
            compare_cpu(
                Family { domain: 1, kind: 1 },
                &[CpuInterval {
                    class: CpuClass::Optional,
                    ..row
                }],
                &[coverage(1, 100, false)]
            )
            .0,
            Err(Error::Evidence)
        );
        let huge = CpuCoverage {
            node: [1; 32],
            first_ns: 0,
            observation_ns: u64::MAX - OBSERVATION_NS - 1,
            observation_end_ns: u64::MAX - 1,
            closing_ns: u64::MAX,
            required: 7,
            reported: 7,
        };
        let full = interval(1, 0, 0, u64::MAX, CpuClass::Policy);
        assert_eq!(
            compare_cpu(family, &[full, full], &[huge]).0,
            Err(Error::Numeric)
        );
        assert_eq!(
            compare_cpu(
                family,
                &[
                    full,
                    CpuInterval {
                        core: 1,
                        class: CpuClass::ExecutorAction,
                        ..full
                    }
                ],
                &[huge]
            )
            .0,
            Err(Error::Numeric)
        );
    });
}

#[test]
fn latency_nearest_rank_and_all_noncompletion_penalties_match_exactly() {
    large_test(|| {
        let start = 700;
        let original = requests(100, start);
        let perfect = compare_performance(&original, start).0.unwrap();
        assert_eq!(perfect.penalty_p99_ns, 99_000);
        assert_eq!(perfect.actual_completed_p99_ns, Some(99_000));
        for missing in [1, 2, 25, 100] {
            let mut rows = original.clone();
            for (i, row) in rows[..missing].iter_mut().enumerate() {
                row.result = [
                    RequestResult::Rejected,
                    RequestResult::TimedOut,
                    RequestResult::Pending,
                ][i % 3];
            }
            let result = compare_performance(&rows, start).0.unwrap();
            if missing >= 2 {
                assert_eq!(result.penalty_p99_ns, OBSERVATION_NS);
            }
            if missing == 100 {
                assert_eq!(result.actual_completed_p99_ns, None);
            }
            rows.reverse();
            compare_performance(&rows, start).0.unwrap();
        }
        let mut mixed = original.clone();
        for (i, row) in mixed.iter_mut().enumerate() {
            if i % 4 != 0 {
                row.result = [
                    RequestResult::Pending,
                    RequestResult::Rejected,
                    RequestResult::TimedOut,
                ][i % 3];
            }
        }
        compare_performance(&mixed, start).0.unwrap();
        for n in [101, 255, 1024, MAX_REQUESTS] {
            let mut rows = requests(n, start);
            rows.rotate_left(n / 3);
            let (result, turns) = compare_performance(&rows, start);
            assert!(result.is_ok());
            assert!(turns > n / OPERATIONS_PER_STEP);
        }
    });
}

#[test]
fn malformed_or_short_requests_are_never_turned_into_samples() {
    large_test(|| {
        let start = 700;
        let end = start + OBSERVATION_NS;
        assert_eq!(
            compare_performance(&[], start).0,
            Err(Error::DataIncomplete)
        );
        assert_eq!(
            compare_performance(&requests(99, start), start).0,
            Err(Error::DataIncomplete)
        );
        let original = requests(100, start);
        for bad in [
            WorkRequest {
                id: 0,
                ..original[0]
            },
            WorkRequest {
                arrived_ns: start - 1,
                ..original[0]
            },
            WorkRequest {
                arrived_ns: end,
                ..original[0]
            },
            WorkRequest {
                result: RequestResult::Completed {
                    finished_ns: start - 1,
                },
                ..original[0]
            },
            WorkRequest {
                result: RequestResult::Completed {
                    finished_ns: end + 1,
                },
                ..original[0]
            },
        ] {
            let mut rows = original.clone();
            rows[0] = bad;
            assert_eq!(compare_performance(&rows, start).0, Err(Error::Evidence));
        }
        let mut rows = original.clone();
        rows[99].id = rows[0].id;
        assert_eq!(compare_performance(&rows, start).0, Err(Error::Evidence));
        rows.truncate(99);
        rows[1].id = rows[0].id;
        assert_eq!(compare_performance(&rows, start).0, Err(Error::Evidence));
        let mut rows = original.clone();
        rows[0].result = RequestResult::Completed {
            finished_ns: rows[0].arrived_ns,
        };
        rows[1].arrived_ns = end - 1;
        rows[1].result = RequestResult::Completed { finished_ns: end };
        rows[2].arrived_ns = start;
        rows[2].result = RequestResult::Completed { finished_ns: end };
        compare_performance(&rows, start).0.unwrap();
        assert_eq!(compare_performance(&[], u64::MAX).0, Err(Error::Numeric));
        assert_eq!(
            compare_performance(&requests(MAX_REQUESTS + 1, start), start).0,
            Err(Error::Capacity)
        );
        assert_eq!(
            compare_performance(&requests(MAX_REQUESTS + 1, start), u64::MAX).0,
            Err(Error::Capacity)
        );
    });
}

#[test]
fn rebuilt_coverage_views_must_keep_every_original_value() {
    large_test(|| {
        let family = Family {
            domain: 13,
            kind: 1,
        };
        let original: Vec<_> = (1..=16).map(|n| coverage(n, 100, true)).collect();
        let rebuilt = original.clone();
        assert_ne!(original.as_ptr(), rebuilt.as_ptr());
        let rows: Vec<_> = (0..256)
            .map(|i| interval((i % 16 + 1) as u8, 0, 100, 110, CpuClass::ExecutorWork))
            .collect();
        let mut work = Box::new(RewardWorkspace::new());
        let mut oracle = Box::new(RewardWorkspace::new());
        let expected = union_cpu(family, &rows, &original, &mut oracle);
        let mut cursor = CpuCursor::new();
        let mut turns = 0;
        loop {
            let view = if turns % 2 == 0 { &original } else { &rebuilt };
            turns += 1;
            assert!(turns < 100_000);
            if cursor.step(family, &rows, view, &mut work).unwrap() {
                break;
            }
        }
        assert!(turns > 2);
        assert_eq!(cursor.finish(), expected);

        let last = original[15];
        for changed in [
            CpuCoverage {
                node: [17; 32],
                ..last
            },
            CpuCoverage {
                first_ns: last.first_ns - 1,
                ..last
            },
            CpuCoverage {
                observation_ns: last.observation_ns + 1,
                ..last
            },
            CpuCoverage {
                observation_end_ns: last.observation_end_ns + 1,
                ..last
            },
            CpuCoverage {
                closing_ns: last.closing_ns + 1,
                ..last
            },
            CpuCoverage {
                required: 3,
                ..last
            },
            CpuCoverage {
                reported: 3,
                ..last
            },
        ] {
            let mut cursor = CpuCursor::new();
            assert_eq!(cursor.step(family, &rows, &original, &mut work), Ok(false));
            let mut changed_view = rebuilt.clone();
            changed_view[15] = changed;
            assert_eq!(
                cursor.step(family, &rows, &changed_view, &mut work),
                Err(Error::Stale)
            );
            assert_eq!(
                cursor.step(family, &rows, &original, &mut work),
                Err(Error::Stale)
            );
        }
    });
}

#[test]
fn continuation_cannot_change_its_input_or_workspace_and_heap_steps_are_bounded() {
    large_test(|| {
        let family = Family {
            domain: 13,
            kind: 1,
        };
        let cov = [coverage(1, 100, true)];
        let rows = vec![interval(1, 0, 100, 110, CpuClass::ExecutorWork); 100];
        let mut a = Box::new(RewardWorkspace::new());
        let mut b = Box::new(RewardWorkspace::new());
        let mut cpu = CpuCursor::new();
        assert_eq!(cpu.step(family, &rows, &cov, &mut a), Ok(false));
        assert_eq!(cpu.step(family, &rows, &cov, &mut b), Err(Error::Stale));
        assert_eq!(cpu.finish(), Err(Error::Stale));
        let mut cpu = CpuCursor::new();
        assert_eq!(cpu.step(family, &rows, &cov, &mut a), Ok(false));
        assert_eq!(
            cpu.step(family, &rows[..99], &cov, &mut a),
            Err(Error::Stale)
        );
        let requests = requests(100, 100);
        let mut performance = PerformanceCursor::new();
        assert_eq!(performance.step(&requests, 100, &mut a), Ok(false));
        assert_eq!(performance.step(&requests, 101, &mut a), Err(Error::Stale));
        assert_eq!(performance.finish(), Err(Error::Stale));

        for len in [0, 1, 2, 3, 16, 127, 4096] {
            let mut values: Vec<_> = (0..len).map(|i| ((i * 17) % 31) as u64).collect();
            let mut golden = values.clone();
            golden.sort_unstable();
            let mut heap = HeapCursor::new(len);
            let mut iterations = 0;
            loop {
                let comparisons = core::cell::Cell::new(0);
                let complete = heap.advance(&mut values, |a, b| {
                    comparisons.set(comparisons.get() + 1);
                    a.cmp(b)
                });
                assert!(comparisons.get() <= 1);
                iterations += 1;
                assert!(iterations < 200_000);
                if complete {
                    break;
                }
            }
            assert_eq!(values, golden);
        }
    });
}
