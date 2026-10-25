//! Synthetic ingress contracts; these are not native replay records.
use cyxia_prototype::{
    domains::ObjectKey,
    learning::{
        Error, Family,
        capture::{Capture, Config, FrozenRequest, MAX_OPEN, RunKey, Source},
        reward::{
            CpuClass, OBSERVATION_NS, RequestResult, RewardWorkspace, performance, union_cpu,
        },
    },
};
const FIRST: u64 = 1_000_000_000;
const OBS: u64 = 3_000_000_000;
const END: u64 = OBS + OBSERVATION_NS;
fn owner(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn config(optional: bool, generation: u64) -> Config {
    Config {
        key: RunKey {
            boot_epoch: 1,
            trial_id: generation,
            generation,
        },
        family: Family {
            domain: if optional { 13 } else { 15 },
            kind: 1,
        },
        node: [1; 32],
        first_ns: FIRST,
        observation_ns: OBS,
        frozen_scope_hash: [7; 32],
    }
}
fn sources(optional: bool) -> Vec<Source> {
    [
        CpuClass::Policy,
        CpuClass::ExecutorAction,
        CpuClass::ExecutorWork,
        CpuClass::Optional,
    ][..if optional { 4 } else { 3 }]
        .iter()
        .enumerate()
        .map(|(i, class)| Source {
            owner: owner(i as u64 + 1),
            class: *class,
            allowed_cores: u64::MAX,
        })
        .collect()
}
fn requests() -> Vec<FrozenRequest> {
    (0..100)
        .map(|i| FrozenRequest {
            id: i + 1,
            owner: owner(10),
            arrived_ns: OBS + i * 1_000_000,
        })
        .collect()
}
fn issued<const I: usize>(capture: &mut Capture<I, 100>) {
    for request in requests() {
        capture
            .issued(request.owner, request.id, request.arrived_ns)
            .unwrap();
    }
}
fn closed<const I: usize>(capture: &mut Capture<I, 100>, optional: bool) {
    for source in sources(optional) {
        let token = capture.source(source.owner, source.class).unwrap();
        capture.close_source(token, END + 1_000).unwrap();
    }
}

#[test]
fn real_intervals_clip_work_windows_but_keep_full_action_cost_and_raw_duration() {
    let mut capture = Capture::<32, 100>::empty();
    let cfg = config(true, 1);
    capture.start(cfg, &sources(true), &requests()).unwrap();
    let p = capture.source(owner(1), CpuClass::Policy).unwrap();
    let e = capture.source(owner(2), CpuClass::ExecutorAction).unwrap();
    let w = capture.source(owner(3), CpuClass::ExecutorWork).unwrap();
    let o = capture.source(owner(4), CpuClass::Optional).unwrap();
    let span = capture.begin(p, 1, FIRST).unwrap();
    capture.record(e, 1, FIRST + 50, FIRST + 150).unwrap();
    capture.end(span, 1, FIRST + 100).unwrap();
    capture.record(w, 0, OBS - 10, OBS + 20).unwrap();
    capture.record(o, 0, OBS + 5, OBS + 15).unwrap();
    issued(&mut capture);
    closed(&mut capture, true);
    let seal = capture.seal(END + 2_000).unwrap();
    assert_eq!(seal.exclusion, None);
    let coverage = capture.coverage(seal).unwrap();
    let total = union_cpu(
        cfg.family,
        capture.intervals(),
        &[coverage],
        &mut RewardWorkspace::new(),
    )
    .unwrap();
    assert_eq!(
        (
            total.union_ns,
            total.policy_ns,
            total.executor_ns,
            total.optional_ns
        ),
        (170, 100, 70, 0)
    );
    assert_eq!(capture.status().raw_tagged_ns, [100, 100, 30, 10]);
    assert_eq!(capture.status().ordinary_warmup_ns, 10);
    assert_eq!(capture.status().later_workload_ns, 0);
}

#[test]
fn unknown_open_source_is_not_zero_and_cannot_be_retired_or_replaced() {
    let mut capture = Capture::<32, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    issued(&mut capture);
    let source = capture.source(owner(2), CpuClass::ExecutorAction).unwrap();
    let span = capture.begin(source, 0, FIRST).unwrap();
    assert_eq!(capture.close_source(source, END), Err(Error::Unknown));
    assert_eq!(capture.seal(END), Err(Error::Unknown));
    assert_eq!(capture.seal_incomplete(END), Err(Error::Unknown));
    assert_eq!(
        capture.start(config(false, 2), &sources(false), &requests()),
        Err(Error::Unknown)
    );
    capture.end(span, 0, FIRST + 100).unwrap();
    assert_eq!(capture.seal(END), Err(Error::DataIncomplete));
    closed(&mut capture, false);
    assert!(capture.seal(END + 2_000).is_ok());
}

#[test]
fn late_real_completion_is_retained_without_faking_fixed_window_success() {
    let mut capture = Capture::<32, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    issued(&mut capture);
    let actual = RequestResult::Completed {
        finished_ns: END + 99,
    };
    capture.result(owner(10), 1, actual).unwrap();
    assert_eq!(capture.actual_result(1), Some(actual));
    assert_eq!(capture.requests()[0].result, RequestResult::Pending);
    closed(&mut capture, false);
    let seal = capture.seal(END + 2_000).unwrap();
    let p = performance(capture.requests(), OBS, &mut RewardWorkspace::new()).unwrap();
    assert_eq!(
        (p.emitted, p.completed, p.pending, p.penalty_p99_ns),
        (100, 0, 100, OBSERVATION_NS)
    );
    capture.retire_exported(seal).unwrap();
    // Retiring measurement storage does not contain a resource-release API.
    assert_eq!(
        capture.start(config(false, 1), &sources(false), &requests()),
        Err(Error::Stale)
    );
    capture
        .start(config(false, 2), &sources(false), &requests())
        .unwrap();
}

#[test]
fn scheduled_custody_keeps_release_and_actual_admission_separate() {
    let mut capture = Capture::<32, 100>::empty();
    capture.start(config(false, 1), &sources(false), &requests()).unwrap();
    for request in requests() {
        capture.arm_scheduled(request.owner, request.id, FIRST).unwrap();
        capture.arm_scheduled(request.owner, request.id, FIRST).unwrap();
    }
    let actual = OBS + 250_000_000;
    capture.result(owner(10), 1, RequestResult::Completed { finished_ns: actual }).unwrap();
    let timing = capture.request_timing(0).unwrap();
    assert!(timing.scheduled);
    assert_eq!(timing.frozen.arrived_ns, OBS);
    assert_eq!(timing.issued_observed_ns, Some(FIRST));
    assert_eq!(capture.requests()[0].arrived_ns, OBS);
    assert_eq!(capture.actual_result(1), Some(RequestResult::Completed { finished_ns: actual }));
    closed(&mut capture, false);
    assert!(capture.seal(END + 2_000).unwrap().exclusion.is_none());

    let mut late = Capture::<32, 100>::empty();
    late.start(config(false, 2), &sources(false), &requests()).unwrap();
    assert_eq!(late.arm_scheduled(owner(10), 1, OBS + 1), Err(Error::Deadline));
    assert!(late.status().fault.is_some());

    let mut observed = Capture::<32, 100>::empty();
    observed.start(config(false, 3), &sources(false), &requests()).unwrap();
    assert_eq!(observed.issued(owner(10), 1, OBS + 1), Err(Error::Evidence));
    assert_eq!(observed.request_timing(0).unwrap().issued_observed_ns, Some(OBS + 1));
    assert!(!observed.request_timing(0).unwrap().scheduled);
}

#[test]
fn foreign_trace_staging_never_changes_the_local_seal_or_coverage() {
    let mut capture = Capture::<32, 100>::empty();
    capture.start(config(false, 1), &sources(false), &requests()).unwrap();
    let policy = capture.source(owner(1), CpuClass::Policy).unwrap();
    capture.record(policy, 1, FIRST, FIRST + 100).unwrap();
    issued(&mut capture); closed(&mut capture, false);
    let seal = capture.seal(END + 2_000).unwrap();
    let coverage = capture.coverage(seal).unwrap();
    let local = capture.intervals().to_vec();
    let foreign = cyxia_prototype::learning::reward::CpuInterval {
        node: [2; 32], core: 3, start_ns: OBS, end_ns: OBS + 50, class: CpuClass::ExecutorWork,
    };
    capture.stage_intervals(seal, 0, &[foreign]).unwrap();
    assert_eq!(capture.sealed(), Some(seal));
    assert_eq!(capture.coverage(seal).unwrap(), coverage);
    assert_eq!(capture.intervals(), local);
    assert_eq!(capture.staged_intervals(seal, 1).unwrap(), &[local[0], foreign]);
    assert_eq!(seal.intervals, 1);
    assert_eq!(capture.stage_intervals(seal, 32, &[foreign]), Err(Error::Capacity));
    assert_eq!(capture.staged_intervals(seal, 32), Err(Error::Capacity));
}

#[test]
fn finite_storage_overflow_keeps_raw_cost_and_requires_excluded_export() {
    let mut capture = Capture::<1, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    let p = capture.source(owner(1), CpuClass::Policy).unwrap();
    capture.record(p, 1, FIRST, FIRST + 10).unwrap();
    assert_eq!(
        capture.record(p, 2, FIRST, FIRST + 20),
        Err(Error::Capacity)
    );
    assert_eq!(capture.status().raw_tagged_ns[0], 30);
    assert_eq!(capture.intervals().len(), 1);
    issued(&mut capture);
    closed(&mut capture, false);
    assert_eq!(capture.seal(END + 2_000), Err(Error::Capacity));
    let excluded = capture.seal_incomplete(END + 2_000).unwrap();
    assert_eq!(excluded.exclusion, Some(Error::Capacity));
    assert_eq!(capture.coverage(excluded), Err(Error::Capacity));
    assert_eq!(capture.seal(END + 2_000), Err(Error::Capacity));
    capture.retire_exported(excluded).unwrap();
    capture
        .start(config(false, 2), &sources(false), &requests())
        .unwrap();
}

#[test]
fn frozen_arrival_and_owner_are_checked_and_unissued_requests_never_count_as_emitted() {
    let mut capture = Capture::<32, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    assert_eq!(capture.issued(owner(11), 1, OBS), Err(Error::Evidence));
    assert_eq!(capture.status().issued, 0);
    assert_eq!(capture.issued(owner(10), 1, OBS + 1), Err(Error::Evidence));
    assert_eq!(capture.status().issued, 1);
    assert_eq!(capture.requests()[0].arrived_ns, OBS + 1);
    closed(&mut capture, false);
    assert_eq!(capture.seal(END + 2_000), Err(Error::Evidence));
    let seal = capture.seal_incomplete(END + 2_000).unwrap();
    assert_eq!(seal.exclusion, Some(Error::Evidence));
}

#[test]
fn instance_identity_and_real_cpu_bindings_cannot_be_reused() {
    let mut a = Capture::<32, 100>::empty();
    let mut b = Capture::<32, 100>::empty();
    a.start(config(false, 1), &sources(false), &requests())
        .unwrap();
    b.start(config(false, 1), &sources(false), &requests())
        .unwrap();
    let a_source = a.source(owner(1), CpuClass::Policy).unwrap();
    assert_eq!(b.record(a_source, 0, FIRST, FIRST + 1), Err(Error::Stale));
    let span = a.begin(a_source, 0, FIRST).unwrap();
    assert_eq!(a.end(span, 1, FIRST + 1), Err(Error::Stale));
    assert_eq!(a.status().open, 1);
    assert_eq!(a.close_source(a_source, END), Err(Error::Unknown));
}

#[test]
fn open_capacity_is_sticky_and_no_live_slot_is_replaced() {
    let mut capture = Capture::<256, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    let p = capture.source(owner(1), CpuClass::Policy).unwrap();
    let e = capture.source(owner(2), CpuClass::ExecutorAction).unwrap();
    let w = capture.source(owner(3), CpuClass::ExecutorWork).unwrap();
    let mut spans = Vec::new();
    for source in [p, e] {
        for core in 0..64 {
            spans.push((core, capture.begin(source, core, FIRST).unwrap()));
        }
    }
    assert_eq!(capture.status().open, MAX_OPEN);
    assert_eq!(capture.begin(w, 0, OBS).err(), Some(Error::Capacity));
    assert_eq!(capture.status().open, MAX_OPEN);
    for (core, span) in spans {
        capture.end(span, core, FIRST + 10).unwrap();
    }
    assert_eq!(capture.status().open, 0);
    assert_eq!(capture.status().fault, Some(Error::Capacity));
    assert_eq!(capture.status().raw_tagged_ns[..2], [640, 640]);
}

#[test]
fn sources_cannot_close_work_sampling_before_observation_end() {
    let mut capture = Capture::<32, 100>::empty();
    capture
        .start(config(false, 1), &sources(false), &requests())
        .unwrap();
    let w = capture.source(owner(3), CpuClass::ExecutorWork).unwrap();
    assert_eq!(capture.close_source(w, END - 1), Err(Error::Evidence));
    assert_eq!(capture.status().closed_sources, 0);
    capture.close_source(w, END).unwrap();
    assert_eq!(capture.record(w, 0, END, END + 1), Err(Error::State));
}
