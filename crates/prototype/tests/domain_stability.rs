use cyxia_prototype::{
    domains::{
        Action, Error, ObjectKey,
        stability::{
            Boundary, ExecutionEffect, FreezeReason, Guard, SECOND_NS, ServiceStatus, ServiceWindow,
        },
    },
    policy::ExecutionState,
};

const MS: u64 = 1_000_000;
fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn guard() -> Guard {
    Guard::new(key(1), Action::CpuWeight(1), 0).unwrap()
}
fn boundary() -> Boundary {
    Boundary {
        id: 17,
        metric: 2,
        minimum: 10,
        maximum: 100,
        min_samples: 8,
    }
}
fn measured(g: &Guard, index: u64, value: Option<u64>) -> ServiceWindow {
    let origin = g.window_origin_ns().unwrap();
    let boundary = g.boundary().unwrap();
    let (domain, kind) = g.family();
    let start = origin + (index - 1) * SECOND_NS;
    ServiceWindow {
        target: g.target(),
        domain,
        kind,
        boundary_id: boundary.id,
        metric: boundary.metric,
        start_ns: start,
        end_ns: start + SECOND_NS,
        covered_ns: SECOND_NS,
        samples: boundary.min_samples,
        value,
    }
}
fn apply(g: &mut Guard, version: u64, value: u16, at: u64) {
    assert_eq!(
        g.observe_execution(
            version,
            Action::CpuWeight(value),
            ExecutionState::Applied,
            at
        ),
        Ok(ExecutionEffect::Changed)
    );
}
fn observe(g: &mut Guard, index: u64, value: Option<u64>) -> ServiceStatus {
    let evidence = measured(g, index, value);
    g.observe_service(evidence, evidence.end_ns).unwrap().status
}

#[test]
fn stopped_quote_baseline_opens_only_first_legal_tier_and_keeps_actual_hold() {
    use cyxia_prototype::domains::stability::adjacent;
    let legal = [100, 250, 500, 1000].map(|n| Some(Action::OfferCpu(n)));
    let mut g = Guard::new(key(16), Action::OfferCpu(0), 100).unwrap();
    assert!(Action::OfferCpu(0).validate().is_err());
    assert_eq!(
        adjacent(g.current(), Action::OfferCpu(100), &legal),
        Ok(true)
    );
    assert_eq!(
        adjacent(g.current(), Action::OfferCpu(250), &legal),
        Ok(false)
    );
    assert_eq!(
        adjacent(g.current(), Action::OfferCpu(0), &legal),
        Err(Error::Range)
    );
    g.observe_execution(1, Action::OfferCpu(100), ExecutionState::Unknown, 200)
        .unwrap();
    assert_eq!(g.current(), Action::OfferCpu(0));
    assert_eq!(g.last_change_ns(), 100);
    g.observe_execution(1, Action::OfferCpu(100), ExecutionState::Applied, 300)
        .unwrap();
    assert_eq!(g.last_change_ns(), 300);
    assert_eq!(
        adjacent(g.current(), Action::OfferCpu(250), &legal),
        Ok(true)
    );
    assert_eq!(
        adjacent(g.current(), Action::OfferCpu(500), &legal),
        Ok(false)
    );
    g.observe_stopped_offer(400).unwrap();
    assert_eq!(g.applied_version(), 1);
    assert_eq!(g.last_change_ns(), 400);
    g.observe_stopped_offer(450).unwrap();
    assert_eq!(g.last_change_ns(), 400, "polling cannot renew the hold");
    assert_eq!(
        g.observe_execution(2, Action::OfferCpu(0), ExecutionState::Applied, 500),
        Err(Error::Range)
    );
    assert_eq!(
        g.observe_execution(2, Action::OfferCpu(100), ExecutionState::Applied, 500),
        Ok(ExecutionEffect::Changed)
    );
    assert_eq!(g.last_change_ns(), 500);
}

#[test]
fn rolling_reversals_cannot_escape_across_a_fixed_second_boundary() {
    let mut g = guard();
    for (index, value) in [2, 1, 2, 1, 2, 1].into_iter().enumerate() {
        let at = (700 + index as u64 * 100) * MS;
        apply(&mut g, index as u64 + 1, value, at);
        assert_eq!(g.frozen(), index == 5);
    }
    assert_eq!(g.reversals_in_window(1_200 * MS), Ok(5));
    assert_eq!(g.freeze_reason(), Some(FreezeReason::Reversals));
    assert_eq!(g.reversals_in_window(20 * SECOND_NS), Ok(0));
    // The object remains frozen, while an already-started receipt can finish.
    apply(&mut g, 7, 2, 20 * SECOND_NS);
    assert!(g.frozen());
    assert_eq!(g.current(), Action::CpuWeight(2));
    assert_eq!(g.last_change_ns(), 20 * SECOND_NS);
}

#[test]
fn exact_one_second_is_included_and_one_nanosecond_older_is_evicted() {
    let mut exact = guard();
    let mut outside = guard();
    apply(&mut exact, 1, 2, 0);
    apply(&mut outside, 1, 2, 0);
    for (index, (at, value)) in [(100, 1), (350, 2), (600, 1), (850, 2)]
        .into_iter()
        .enumerate()
    {
        apply(&mut exact, index as u64 + 2, value, at * MS);
        apply(&mut outside, index as u64 + 2, value, at * MS);
    }
    assert!(!exact.frozen());
    assert_eq!(exact.reversals_in_window(1_100 * MS), Ok(4));
    apply(&mut exact, 6, 1, 1_100 * MS);
    apply(&mut outside, 6, 1, 1_100 * MS + 1);
    assert!(exact.frozen());
    assert!(!outside.frozen());
    assert_eq!(outside.reversals_in_window(1_100 * MS + 1), Ok(4));
}

#[test]
fn only_actual_changes_count_and_versions_cannot_be_rebound() {
    let mut g = guard();
    for (at, state) in [
        (100, ExecutionState::Pending),
        (200, ExecutionState::Unknown),
    ] {
        assert_eq!(
            g.observe_execution(1, Action::CpuWeight(2), state, at * MS),
            Ok(ExecutionEffect::Ignored)
        );
    }
    assert_eq!(g.current(), Action::CpuWeight(1));
    assert_eq!(g.last_change_ns(), 0);
    let before = g;
    assert_eq!(
        g.observe_execution(1, Action::CpuWeight(4), ExecutionState::Applied, 300 * MS),
        Err(Error::Conflict)
    );
    assert_eq!(g, before);
    apply(&mut g, 1, 2, 300 * MS);
    assert_eq!(
        g.observe_execution(1, Action::CpuWeight(2), ExecutionState::Applied, 400 * MS),
        Ok(ExecutionEffect::Duplicate)
    );
    assert_eq!(
        g.observe_execution(2, Action::CpuWeight(2), ExecutionState::Applied, 500 * MS),
        Ok(ExecutionEffect::Renewal)
    );
    assert_eq!(g.last_change_ns(), 300 * MS);
    assert_eq!(
        g.observe_execution(
            3,
            Action::CpuWeight(1),
            ExecutionState::Failed(Error::Io),
            600 * MS
        ),
        Ok(ExecutionEffect::Ignored)
    );
    assert_eq!(g.reversals_in_window(600 * MS), Ok(0));
    apply(&mut g, 3, 1, 700 * MS);
    assert_eq!(g.reversals_in_window(700 * MS), Ok(1));
    assert_eq!(
        g.observe_execution(2, Action::CpuWeight(2), ExecutionState::Applied, 800 * MS),
        Err(Error::Stale)
    );
    assert_eq!(
        g.observe_execution(4, Action::IoShare(100), ExecutionState::Applied, 800 * MS),
        Err(Error::Conflict)
    );
    assert_eq!(
        g.observe_execution(4, Action::CpuWeight(4), ExecutionState::Applied, 699 * MS),
        Err(Error::Stale)
    );
    assert_eq!(g.last_change_ns(), 700 * MS);
}

#[test]
fn categorical_routes_and_one_shots_do_not_acquire_a_numeric_direction() {
    for (baseline, alternative) in [
        (Action::IrqTarget(0), Action::IrqTarget(3)),
        (Action::ControlSet(2), Action::ControlSet(6)),
        (Action::RecoveryRecipe(0), Action::RecoveryRecipe(1)),
        (Action::Placement(0), Action::Placement(1)),
    ] {
        let mut g = Guard::new(key(1), baseline, 0).unwrap();
        for i in 1..=12 {
            let action = if i % 2 == 1 { alternative } else { baseline };
            assert_eq!(
                g.observe_execution(i, action, ExecutionState::Applied, i * MS),
                Ok(ExecutionEffect::Changed)
            );
        }
        assert_eq!(g.reversals_in_window(12 * MS), Ok(0));
        assert!(!g.frozen());
        assert_eq!(g.last_change_ns(), 12 * MS);
    }
    // Candidate pairs are one ordered action, not independent scalar changes.
    let a = Action::Filesystem {
        readahead: 0,
        flush: 4,
    };
    let b = Action::Filesystem {
        readahead: 2,
        flush: 8,
    };
    let mut filesystem = Guard::new(key(2), a, 0).unwrap();
    for i in 1..=6 {
        filesystem
            .observe_execution(
                i,
                if i % 2 == 1 { b } else { a },
                ExecutionState::Applied,
                i * 100 * MS,
            )
            .unwrap();
    }
    assert!(filesystem.frozen());
}

#[test]
fn each_real_object_has_its_own_guard_and_old_generation_evidence_is_rejected() {
    let mut hot = guard();
    let mut quiet = Guard::new(key(2), Action::CpuWeight(1), 0).unwrap();
    for i in 1..=6 {
        apply(&mut hot, i, if i % 2 == 1 { 2 } else { 1 }, i * 100 * MS);
    }
    apply(&mut quiet, 1, 2, 600 * MS);
    assert!(hot.frozen());
    assert!(!quiet.frozen());
    quiet
        .register_boundary(boundary(), SECOND_NS, 600 * MS)
        .unwrap();
    let mut sample = measured(&quiet, 1, Some(50));
    sample.target.generation += 1;
    assert_eq!(
        quiet.observe_service(sample, 2 * SECOND_NS),
        Err(Error::Auth)
    );
    fn copyable<T: Copy>(_: T) {}
    copyable(hot);
    assert!(core::mem::size_of::<Guard>() <= 256);
}

#[test]
fn boundary_is_registered_before_measurement_and_exact_retry_never_resets_history() {
    let mut g = guard();
    assert_eq!(g.service_status(0), Ok(ServiceStatus::Unregistered));
    g.register_boundary(boundary(), 0, 0).unwrap();
    assert_eq!(observe(&mut g, 1, Some(101)), ServiceStatus::Breached);
    g.register_boundary(boundary(), 0, SECOND_NS).unwrap();
    assert_eq!(g.consecutive_breaches(), 1);
    let saved = g;
    let mut changed = boundary();
    changed.maximum = 1_000;
    assert_eq!(
        g.register_boundary(changed, 0, SECOND_NS),
        Err(Error::Conflict)
    );
    assert_eq!(
        g.register_boundary(boundary(), SECOND_NS, SECOND_NS),
        Err(Error::Conflict)
    );
    assert_eq!(g, saved);
    let mut late = Guard::new(key(3), Action::CpuWeight(1), SECOND_NS).unwrap();
    assert_eq!(
        late.register_boundary(boundary(), 0, SECOND_NS),
        Err(Error::Stale)
    );
    assert_eq!(late.boundary(), None);
}

#[test]
fn three_real_complete_consecutive_breaches_freeze_and_good_service_cannot_unfreeze() {
    let mut g = guard();
    g.register_boundary(boundary(), 0, 0).unwrap();
    assert_eq!(observe(&mut g, 1, Some(10)), ServiceStatus::WithinBoundary);
    assert_eq!(observe(&mut g, 2, Some(100)), ServiceStatus::WithinBoundary);
    for (index, value) in [(3, 101), (4, 9), (5, 101)] {
        assert_eq!(observe(&mut g, index, Some(value)), ServiceStatus::Breached);
        assert_eq!(g.frozen(), index == 5);
    }
    assert_eq!(g.freeze_reason(), Some(FreezeReason::ServiceBoundary));
    assert_eq!(observe(&mut g, 6, Some(50)), ServiceStatus::WithinBoundary);
    assert_eq!(g.consecutive_breaches(), 0);
    assert!(g.frozen());
    g.observe_execution(
        1,
        Action::CpuWeight(1),
        ExecutionState::Applied,
        6 * SECOND_NS,
    )
    .unwrap();
    assert!(g.frozen());
}

#[test]
fn partial_coverage_missing_values_and_insufficient_samples_are_not_good_windows() {
    let mut g = guard();
    g.register_boundary(boundary(), 0, 0).unwrap();
    observe(&mut g, 1, Some(101));
    observe(&mut g, 2, Some(101));
    let mut partial = measured(&g, 3, Some(50));
    partial.covered_ns -= 1;
    assert_eq!(
        g.observe_service(partial, partial.end_ns).unwrap().status,
        ServiceStatus::Incomplete
    );
    assert_eq!(g.consecutive_breaches(), 0);
    assert_eq!(
        g.service_status(3 * SECOND_NS),
        Ok(ServiceStatus::Incomplete)
    );
    observe(&mut g, 4, Some(101));
    assert_eq!(observe(&mut g, 5, None), ServiceStatus::Incomplete);
    let mut few = measured(&g, 6, Some(50));
    few.samples -= 1;
    assert_eq!(
        g.observe_service(few, few.end_ns).unwrap().status,
        ServiceStatus::Incomplete
    );
    assert!(!g.frozen());
    assert_eq!(g.service_status(7 * SECOND_NS), Ok(ServiceStatus::Missing));
}

#[test]
fn missing_window_breaks_the_streak_and_duplicate_evidence_is_not_a_new_window() {
    let mut g = guard();
    g.register_boundary(boundary(), 0, 0).unwrap();
    observe(&mut g, 1, Some(101));
    observe(&mut g, 2, Some(101));
    assert_eq!(g.service_status(3 * SECOND_NS), Ok(ServiceStatus::Missing));
    let fourth = measured(&g, 4, Some(101));
    let out = g.observe_service(fourth, fourth.end_ns).unwrap();
    assert_eq!((out.missed_windows, out.consecutive_breaches), (1, 1));
    for _ in 0..10 {
        let out = g.observe_service(fourth, fourth.end_ns).unwrap();
        assert!(out.repeated);
        assert_eq!(out.consecutive_breaches, 1);
    }
    let mut rewritten = fourth;
    rewritten.value = Some(50);
    assert_eq!(
        g.observe_service(rewritten, fourth.end_ns),
        Err(Error::Conflict)
    );
    let old = measured(&g, 3, Some(101));
    assert_eq!(g.observe_service(old, fourth.end_ns), Err(Error::Stale));
    assert!(!g.frozen());
    observe(&mut g, 5, Some(101));
    observe(&mut g, 6, Some(101));
    assert!(g.frozen());
}

#[test]
fn malformed_future_foreign_and_unaligned_windows_never_change_the_guard() {
    let mut g = guard();
    g.register_boundary(boundary(), 0, 0).unwrap();
    let good = measured(&g, 1, Some(50));
    for (bad, expected) in [
        (
            ServiceWindow {
                target: key(2),
                ..good
            },
            Error::Auth,
        ),
        (ServiceWindow { domain: 2, ..good }, Error::Auth),
        (ServiceWindow { kind: 2, ..good }, Error::Auth),
        (
            ServiceWindow {
                boundary_id: 18,
                ..good
            },
            Error::Auth,
        ),
        (ServiceWindow { metric: 3, ..good }, Error::Auth),
        (
            ServiceWindow {
                end_ns: SECOND_NS - 1,
                ..good
            },
            Error::Range,
        ),
        (
            ServiceWindow {
                covered_ns: SECOND_NS + 1,
                ..good
            },
            Error::Range,
        ),
        (
            ServiceWindow {
                start_ns: 1,
                end_ns: SECOND_NS + 1,
                ..good
            },
            Error::Format,
        ),
        (
            ServiceWindow {
                start_ns: u64::MAX,
                end_ns: 0,
                ..good
            },
            Error::Overflow,
        ),
    ] {
        let saved = g;
        assert_eq!(g.observe_service(bad, 2 * SECOND_NS), Err(expected));
        assert_eq!(g, saved);
    }
    let saved = g;
    assert_eq!(g.observe_service(good, SECOND_NS - 1), Err(Error::NotReady));
    assert_eq!(g, saved);
    g.observe_service(good, SECOND_NS).unwrap();
    assert_eq!(g.observe_service(good, SECOND_NS - 1), Err(Error::Stale));
}

#[test]
fn service_freshness_and_time_overflow_are_explicit_without_synthetic_samples() {
    let mut g = guard();
    assert_eq!(
        g.register_boundary(
            Boundary {
                min_samples: 0,
                ..boundary()
            },
            0,
            0
        ),
        Err(Error::Range)
    );
    assert_eq!(
        g.register_boundary(
            Boundary {
                minimum: 101,
                ..boundary()
            },
            0,
            0
        ),
        Err(Error::Range)
    );
    assert_eq!(
        g.register_boundary(
            Boundary {
                id: 0,
                ..boundary()
            },
            0,
            0
        ),
        Err(Error::Format)
    );
    assert_eq!(
        g.register_boundary(boundary(), u64::MAX, 0),
        Err(Error::Overflow)
    );
    assert_eq!(g.boundary(), None);
    g.register_boundary(boundary(), SECOND_NS, 0).unwrap();
    assert_eq!(
        g.service_status(2 * SECOND_NS - 1),
        Ok(ServiceStatus::Awaiting)
    );
    assert_eq!(g.service_status(2 * SECOND_NS), Ok(ServiceStatus::Missing));
    observe(&mut g, 1, Some(50));
    assert_eq!(
        g.service_status(3 * SECOND_NS - 1),
        Ok(ServiceStatus::WithinBoundary)
    );
    assert_eq!(g.service_status(3 * SECOND_NS), Ok(ServiceStatus::Missing));
    let mut terminal = Guard::new(key(3), Action::CpuWeight(1), u64::MAX - SECOND_NS).unwrap();
    terminal
        .register_boundary(boundary(), u64::MAX - SECOND_NS, u64::MAX - SECOND_NS)
        .unwrap();
    let last = measured(&terminal, 1, Some(50));
    terminal.observe_service(last, u64::MAX).unwrap();
    assert_eq!(terminal.service_status(u64::MAX), Err(Error::Overflow));
}

#[test]
fn maximal_versions_are_never_wrapped_or_reused() {
    let mut g = guard();
    apply(&mut g, u64::MAX, 2, 100 * MS);
    assert_eq!(g.applied_version(), u64::MAX);
    assert_eq!(
        g.observe_execution(0, Action::CpuWeight(1), ExecutionState::Applied, 200 * MS),
        Err(Error::Stale)
    );
    assert_eq!(
        g.observe_execution(
            u64::MAX - 1,
            Action::CpuWeight(1),
            ExecutionState::Applied,
            200 * MS
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        g.observe_execution(
            u64::MAX,
            Action::CpuWeight(1),
            ExecutionState::Applied,
            200 * MS
        ),
        Err(Error::Conflict)
    );
    assert_eq!(
        g.observe_execution(
            u64::MAX,
            Action::CpuWeight(2),
            ExecutionState::Applied,
            200 * MS
        ),
        Ok(ExecutionEffect::Duplicate)
    );
    assert_eq!(g.last_change_ns(), 100 * MS);
}
