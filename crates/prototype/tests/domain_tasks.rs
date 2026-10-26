use cyxia_prototype::domains::tasks::*;
use cyxia_prototype::domains::{Error, ObjectKey, POLICY_NS, PolicyStamp, WINDOW_NS};
use std::collections::BTreeMap;

fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn stamp(version: u64, snapshot: u64, now: u64) -> PolicyStamp {
    PolicyStamp::new(version, snapshot, now).unwrap()
}
fn layout(generation: u64) -> CpuLayout {
    CpuLayout {
        business_mask: 3,
        healthy_mask: 3,
        generation,
    }
}
fn spec(id: u64, group: u64, cpu: u16, minimum_ns: u64, budget_ns: u64) -> ThreadSpec {
    ThreadSpec {
        key: key(id),
        group: key(group),
        cpu,
        allowed_mask: 1u64 << cpu,
        minimum_ns,
        budget_ns,
    }
}

#[test]
fn ordinary_affinity_cannot_gain_control_or_an_unadmitted_cpu() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(1)).unwrap();
    let current = CpuLayout {
        business_mask: 13,
        healthy_mask: 15,
        generation: 1,
    };
    scheduler
        .admit(spec(10, 1, 3, 0, 10_000_000), current, 0)
        .unwrap();
    assert_eq!(
        scheduler.bind_affinity(key(10), 2, current),
        Err(Error::Auth)
    );
    assert_eq!(
        scheduler.bind_affinity(key(10), 9, current),
        Err(Error::Auth)
    );
    assert_eq!(scheduler.thread_affinity(key(10)), Ok(8));
    assert_eq!(scheduler.bind_affinity(key(10), 8, current), Ok(()));
    let excluded = CpuLayout {
        healthy_mask: 7,
        ..current
    };
    assert_eq!(
        scheduler.bind_affinity(key(10), 8, excluded),
        Err(Error::Auth)
    );
    assert_eq!(scheduler.thread_affinity(key(10)), Ok(8));
}

#[test]
fn delegated_syscall_uses_caller_budget_and_broker_physical_cpu_once() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.register_group(key(2)).unwrap();
    s.admit(spec(10, 1, 1, 0, 10_000_000), layout(1), 0)
        .unwrap();
    s.admit(spec(20, 2, 0, 20_000_000, 60_000_000), layout(1), 0)
        .unwrap();
    s.set_runnable(key(10), false, 0).unwrap();
    let d = s
        .dispatch_service(key(10), 0, layout(1), 0, 2_500_000)
        .unwrap()
        .unwrap();
    assert_eq!(d.reason, DispatchReason::Service);
    assert_eq!(d.cpu, 0);
    assert_eq!(s.remove(key(10)), Err(Error::Busy));
    assert_eq!(s.set_runnable(key(10), true, 0), Err(Error::Busy));
    assert_eq!(s.dispatch(0, layout(1), 0, 1), Err(Error::Busy));
    s.complete(d, 1_000_000, RunState::Blocked, 1_000_000)
        .unwrap();
    assert_eq!(s.cpu_window_usage(0, 1_000_000), Ok((1_000_000, 0)));
    assert_eq!(s.cpu_window_usage(1, 1_000_000), Ok((0, 0)));
    assert_eq!(s.thread_cpu_ns(key(10)), Ok(1_000_000));
    assert_eq!(s.thread_cpu_ns(key(20)), Ok(0));
    assert_eq!(s.stats().actual_ns, 1_000_000);
    s.set_runnable(key(10), true, 1_000_000).unwrap();
    let remaining = s
        .dispatch(1, layout(1), 1_000_000, 20_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(remaining.reserved_ns, 9_000_000);
    assert_eq!(remaining.thread, key(10));
}

#[test]
fn delegated_syscall_preserves_broker_promises_and_cannot_double_enter() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.register_group(key(2)).unwrap();
    s.admit(spec(10, 1, 1, 0, 80_000_000), layout(1), 0)
        .unwrap();
    s.admit(spec(20, 2, 0, 20_000_000, 60_000_000), layout(1), 0)
        .unwrap();
    assert_eq!(
        s.dispatch_service(key(10), 0, layout(1), 0, 1),
        Err(Error::Conflict)
    );
    s.set_runnable(key(10), false, 0).unwrap();
    let d = s
        .dispatch_service(key(10), 0, layout(1), 0, 80_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(d.reserved_ns, 30_000_000);
    assert_eq!(s.resize_dispatch(d, 30_000_001), Err(Error::Budget));
    assert_eq!(
        s.dispatch_service(key(10), 0, layout(1), 0, 1),
        Err(Error::Busy)
    );
    s.complete(d, 30_000_000, RunState::Blocked, 30_000_000)
        .unwrap();
    assert_eq!(
        s.dispatch_service(key(10), 0, layout(1), 30_000_000, 1),
        Ok(None)
    );
    let tls = s
        .dispatch(0, layout(1), 30_000_000, 60_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(tls.thread, key(20));
    assert_eq!(tls.reserved_ns, 20_000_000);
}

#[test]
fn delegated_late_completion_cannot_be_erased_by_source_cpu_window_roll() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 1, 0, 20_000_000), layout(1), 0)
        .unwrap();
    s.set_runnable(key(10), false, 0).unwrap();
    let d = s
        .dispatch_service(key(10), 0, layout(1), WINDOW_NS - 10, 10)
        .unwrap()
        .unwrap();
    assert_eq!(s.dispatch(1, layout(1), WINDOW_NS, 1), Err(Error::Busy));
    assert_eq!(
        s.complete(d, 11, RunState::Blocked, WINDOW_NS + 1),
        Err(Error::Budget)
    );
    assert_eq!(s.stats().quarantine_mask, 1);
    assert_eq!(s.stats().actual_ns, 11);
    assert_eq!(s.thread_cpu_ns(key(10)), Ok(11));
    assert_eq!(s.dispatch(1, layout(1), WINDOW_NS + 2, 1), Ok(None));
    assert_eq!(
        s.dispatch_service(key(10), 0, layout(1), WINDOW_NS + 2, 1),
        Err(Error::NotReady)
    );
}

#[test]
fn scheduler_executes_minima_before_weighted_surplus() {
    let mut s = Scheduler::new();
    for (i, weight) in [1, 2, 4, 8].into_iter().enumerate() {
        s.register_group(key(i as u64 + 1)).unwrap();
        s.install_weight(key(i as u64 + 1), weight, stamp(1, 0, 0), 0)
            .unwrap();
        s.admit(
            spec(100 + i as u64, i as u64 + 1, 0, 5_000_000, 22_500_000),
            layout(1),
            0,
        )
        .unwrap();
    }
    let mut now = 0;
    let mut minimum = 0;
    while now < 40_000_000 {
        let d = s.dispatch(0, layout(1), now, 100_000).unwrap().unwrap();
        if d.reason == DispatchReason::Minimum {
            minimum += 1;
        } else {
            assert_eq!(minimum, 200);
        }
        now += d.reserved_ns;
        s.complete(d, d.reserved_ns, RunState::Runnable, now)
            .unwrap();
    }
    let extra: Vec<_> = (0..4)
        .map(|i| s.thread_cpu_ns(key(100 + i)).unwrap() - 5_000_000)
        .collect();
    assert!(extra[3] > extra[0] * 5, "{extra:?}");
    assert!(extra[2] > extra[1] && extra[1] > extra[0], "{extra:?}");
    assert_eq!(s.stats().actual_ns, 40_000_000);
}

#[test]
fn nonpreemptible_file_segment_never_executes_on_a_partial_tail() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 1, 0, 5_000_000), layout(1), 0).unwrap();
    s.set_runnable(key(10), false, 0).unwrap();
    for i in 0..3 {
        let start = i * 900_000;
        let d = s
            .dispatch_service_exact(key(10), 0, layout(1), start, 2_500_000)
            .unwrap()
            .unwrap();
        assert_eq!(d.reserved_ns, 2_500_000);
        s.complete(d, 900_000, RunState::Blocked, start + 900_000)
            .unwrap();
    }
    assert_eq!(
        s.dispatch_service_exact(key(10), 0, layout(1), 2_700_000, 2_500_000),
        Ok(None)
    );
    assert_eq!(s.cpu_window_usage(0, 2_700_000), Ok((2_700_000, 0)));
    assert_eq!(s.thread_cpu_ns(key(10)), Ok(2_700_000));
    assert_eq!(
        s.dispatch_service_exact(key(10), 0, layout(1), WINDOW_NS - 1, 2_500_000),
        Ok(None)
    );
    assert!(
        s.dispatch_service_exact(key(10), 0, layout(1), WINDOW_NS, 2_500_000)
            .unwrap()
            .is_some()
    );
    let mut short = Scheduler::new();
    short.register_group(key(1)).unwrap();
    short
        .admit(spec(10, 1, 1, 0, 1_000_000), layout(1), 0)
        .unwrap();
    short.set_runnable(key(10), false, 0).unwrap();
    assert_eq!(
        short.dispatch_service_exact(key(10), 0, layout(1), 0, 2_500_000),
        Err(Error::Budget)
    );
    assert_eq!(short.cpu_window_usage(0, 0), Ok((0, 0)));
}

#[test]
fn mandatory_service_admission_waits_for_a_window_that_can_keep_its_minimum() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(14)).unwrap();
    let service = spec(0x101, 14, 0, 20_000_000, 60_000_000);
    assert_eq!(
        scheduler.admit(service, layout(1), WINDOW_NS - 1),
        Err(Error::Budget)
    );
    assert_eq!(scheduler.thread_count(), 0);
    assert_eq!(scheduler.committed_ns(0), 0);
    assert_eq!(
        scheduler.dispatch(0, layout(1), WINDOW_NS - 1, 1_000_000),
        Ok(None)
    );
    scheduler.admit(service, layout(1), WINDOW_NS).unwrap();
    let credit = scheduler
        .dispatch(0, layout(1), WINDOW_NS, 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(credit.thread, service.key);
    assert_eq!(credit.reason, DispatchReason::Minimum);
    scheduler
        .complete(credit, 1_000_000, RunState::Runnable, WINDOW_NS + 1_000_000)
        .unwrap();
    assert_eq!(scheduler.thread_cpu_ns(service.key), Ok(1_000_000));
}

#[test]
fn scheduler_policy_receipt_binds_completed_credit_to_its_dispatch_version() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(1)).unwrap();
    scheduler
        .admit(spec(10, 1, 0, 0, 20_000_000), layout(1), 0)
        .unwrap();
    scheduler
        .install_weight(key(1), 2, stamp(1, 0, 0), 0)
        .unwrap();
    assert_eq!(scheduler.policy_receipt(key(1)), Ok(0));
    let first = scheduler
        .dispatch(0, layout(1), 0, 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(first.policy_version, 1);
    scheduler
        .install_weight(key(1), 4, stamp(2, 0, 0), 0)
        .unwrap();
    scheduler.complete(first, 1, RunState::Runnable, 1).unwrap();
    assert_eq!(scheduler.policy_receipt(key(1)), Ok(1));
    let cancelled = scheduler
        .dispatch(0, layout(1), 2, 1_000_000)
        .unwrap()
        .unwrap();
    scheduler
        .complete(cancelled, 0, RunState::Runnable, 2)
        .unwrap();
    assert_eq!(scheduler.policy_receipt(key(1)), Ok(1));
    let executed = scheduler
        .dispatch(0, layout(1), 3, 1_000_000)
        .unwrap()
        .unwrap();
    scheduler
        .complete(executed, 1, RunState::Runnable, 4)
        .unwrap();
    assert_eq!(scheduler.policy_receipt(key(1)), Ok(2));
}

#[test]
fn scheduler_sixteen_groups_sixty_four_threads_and_exit_never_refills_credit() {
    let mut s = Scheduler::new();
    for i in 1..=16 {
        s.register_group(key(i)).unwrap();
    }
    assert_eq!(s.register_group(key(17)), Err(Error::Capacity));
    for i in 0..64 {
        s.admit(spec(100 + i, i / 4 + 1, 0, 0, 1_000_000), layout(1), 0)
            .unwrap();
    }
    assert_eq!(
        s.admit(spec(999, 1, 0, 0, 1_000_000), layout(1), 0),
        Err(Error::Capacity)
    );
    let d = s.dispatch(0, layout(1), 0, 1_000_000).unwrap().unwrap();
    s.complete(d, 1_000_000, RunState::Exited, 1_000_000)
        .unwrap();
    s.remove(d.thread).unwrap();
    assert_eq!(s.cpu_spent_ns(0), Ok(1_000_000));
    s.admit(spec(999, 1, 0, 0, 1_000_000), layout(1), 1_000_000)
        .unwrap();
    assert_eq!(s.cpu_spent_ns(0), Ok(1_000_000));
}

#[test]
fn scheduler_independent_receipts_out_of_order_and_isolated_overrun() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 0, 0, 10_000_000), layout(1), 0)
        .unwrap();
    s.admit(spec(11, 1, 1, 0, 10_000_000), layout(1), 0)
        .unwrap();
    let a = s.dispatch(0, layout(1), 0, 1_000_000).unwrap().unwrap();
    let b = s.dispatch(1, layout(1), 0, 1_000_000).unwrap().unwrap();
    s.complete(b, 500_000, RunState::Runnable, 900_000).unwrap();
    s.complete(a, 500_000, RunState::Runnable, 800_000).unwrap();
    let d = s
        .dispatch(0, layout(1), 1_000_000, 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        s.complete(d, 1_100_000, RunState::Runnable, 2_100_000),
        Err(Error::Budget)
    );
    assert_eq!(s.stats().quarantine_mask, 1);
    assert!(
        s.dispatch(1, layout(1), 2_100_000, 1_000_000)
            .unwrap()
            .is_some()
    );
    assert_eq!(s.recover_cpu(0, layout(1), 2_100_000), Err(Error::Stale));
    s.recover_cpu(0, layout(2), 2_100_000).unwrap();
    assert_eq!(s.cpu_spent_ns(0), Ok(1_600_000));
}

#[test]
fn scheduler_crossed_window_is_quarantined_until_the_tail_is_accounted() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 0, 0, 20_000_000), layout(1), 0)
        .unwrap();
    let d = s
        .dispatch(0, layout(1), WINDOW_NS - 1_000_000, 1_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        s.complete(d, 1_000_000, RunState::Runnable, WINDOW_NS + 1),
        Err(Error::Budget)
    );
    assert_eq!(s.recover_cpu(0, layout(2), WINDOW_NS + 1), Err(Error::Busy));
    s.recover_cpu(0, layout(2), 2 * WINDOW_NS).unwrap();
    assert_eq!(
        s.dispatch(0, layout(2), 2 * WINDOW_NS, 1_000_000)
            .unwrap()
            .unwrap()
            .reserved_ns,
        1_000_000
    );
}

#[test]
fn guarded_dispatch_defers_the_window_tail_without_reserving_credit() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 0, 0, 20_000_000), layout(1), 0)
        .unwrap();
    assert_eq!(
        s.dispatch_with_window_headroom(
            0,
            layout(1),
            WINDOW_NS - 10_000_000 + 1,
            1_000_000,
            10_000_000,
        ),
        Ok(None)
    );
    assert_eq!(
        s.cpu_window_usage(0, WINDOW_NS - 1),
        Ok((0, 0)),
        "tail deferral must not consume or retain a credit"
    );
    let d = s
        .dispatch_with_window_headroom(0, layout(1), WINDOW_NS, 1_000_000, 10_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(d.started_ns, WINDOW_NS);
    assert_eq!(d.reserved_ns, 1_000_000);
    s.complete(d, 250_000, RunState::Runnable, WINDOW_NS + 250_000)
        .unwrap();
    assert_eq!(s.stats().quarantine_mask, 0);
}

#[test]
fn unstarted_dispatch_can_be_refunded_after_its_window_expires() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 0, 0, 20_000_000), layout(1), 0)
        .unwrap();
    let d = s
        .dispatch_with_window_headroom(0, layout(1), 40_000_000, 10_000_000, 10_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(s.cpu_window_usage(0, 40_000_000), Ok((0, 10_000_000)));
    s.cancel_unstarted(d, WINDOW_NS + 1).unwrap();
    assert_eq!(s.stats().quarantine_mask, 0);
    assert_eq!(s.stats().overruns, 0);
    assert_eq!(s.thread_cpu_ns(key(10)), Ok(0));
    assert_eq!(s.cpu_window_usage(0, WINDOW_NS + 1), Ok((0, 0)));
    assert!(
        s.dispatch_with_window_headroom(0, layout(1), WINDOW_NS + 1, 1_000_000, 10_000_000)
            .unwrap()
            .is_some()
    );
}

#[test]
fn scheduler_native_margin_is_prepaid_and_stale_ticket_cannot_complete() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    s.admit(spec(10, 1, 0, 0, 2_000_000), layout(1), 0).unwrap();
    let old = s.dispatch(0, layout(1), 0, 100_000).unwrap().unwrap();
    let resized = s.resize_dispatch(old, 1_000_000).unwrap();
    assert_eq!(s.resize_dispatch(resized, 3_000_000), Err(Error::Budget));
    assert_eq!(s.complete(old, 1, RunState::Runnable, 1), Err(Error::Stale));
    assert_eq!(s.cpu_spent_ns(0), Ok(1_000_000));
    s.complete(resized, 200_000, RunState::Runnable, 200_000)
        .unwrap();
    assert_eq!(s.cpu_spent_ns(0), Ok(200_000));
}

#[test]
fn scheduler_migration_carries_spending_and_keeps_source_charge() {
    let mut s = Scheduler::new();
    s.register_group(key(1)).unwrap();
    let mut t = spec(10, 1, 0, 0, 20_000_000);
    t.allowed_mask = 3;
    s.admit(t, layout(1), 0).unwrap();
    let d = s.dispatch(0, layout(1), 0, 5_000_000).unwrap().unwrap();
    s.complete(d, 5_000_000, RunState::Runnable, 5_000_000)
        .unwrap();
    s.relocate(key(10), 1, layout(1), 5_000_000).unwrap();
    assert_eq!(s.cpu_spent_ns(0), Ok(5_000_000));
    assert_eq!(s.cpu_spent_ns(1), Ok(5_000_000));
    assert_eq!(
        s.dispatch(1, layout(1), 5_000_000, 20_000_000)
            .unwrap()
            .unwrap()
            .reserved_ns,
        15_000_000
    );
}

#[derive(Default)]
struct Creator {
    calls: Vec<SpawnRequest>,
    deny: bool,
    uncertain: bool,
    reject: bool,
}
impl TaskBackend for Creator {
    fn authorize(&mut self, r: &SpawnRequest) -> Result<(), Error> {
        if self.deny || r.package != key(1) || (r.recovery && r.caller != key(99)) {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }
    fn create(&mut self, r: &SpawnRequest) -> CreateOutcome {
        self.calls.push(*r);
        if self.uncertain {
            CreateOutcome::Uncertain
        } else if self.reject {
            CreateOutcome::Rejected(Error::Capacity)
        } else {
            CreateOutcome::Created(key(1000 + self.calls.len() as u64))
        }
    }
}
fn request(id: u64, recovery: bool) -> SpawnRequest {
    SpawnRequest {
        caller: if recovery { key(99) } else { key(1) },
        request_id: id,
        package: key(1),
        group: key(1),
        payload_hash: [id as u8; 32],
        recovery,
    }
}
#[test]
fn spawn_burst_tokens_are_overwritten_without_refilling_same_window() {
    let mut a = SpawnAdmission::new();
    a.register_group(key(1)).unwrap();
    let mut b = Creator::default();
    for id in 1..=64 {
        assert_eq!(
            a.submit(request(id, false), 0, &mut b),
            Ok(SpawnState::Queued)
        );
    }
    assert_eq!(a.submit(request(65, false), 0, &mut b), Err(Error::Again));
    assert_eq!(a.query(key(1), 65), Err(Error::NotFound));
    for _ in 0..2 {
        assert!(a.service_one(0, &mut b).unwrap().is_some());
    }
    assert_eq!(a.service_one(0, &mut b), Ok(None));
    a.install_tokens(key(1), 8, stamp(1, 0, 0), 0).unwrap();
    for _ in 0..6 {
        a.service_one(0, &mut b).unwrap();
    }
    a.install_tokens(key(1), 8, stamp(2, 0, 0), 0).unwrap();
    assert_eq!(a.service_one(0, &mut b), Ok(None));
    assert_eq!(b.calls.len(), 8);
    a.service_one(WINDOW_NS, &mut b).unwrap();
    assert_eq!(b.calls.len(), 9);
    let old = a.query(key(1), 1).unwrap();
    assert_eq!(a.submit(request(1, false), 0, &mut b), Ok(old));
    assert_eq!(b.calls.len(), 9);
    let mut changed = request(1, false);
    changed.payload_hash[0] ^= 1;
    assert_eq!(a.submit(changed, WINDOW_NS, &mut b), Err(Error::Conflict));
}
#[test]
fn spawn_uncertain_creation_is_never_retried_and_remains_reserved() {
    let mut a = SpawnAdmission::new();
    a.register_group(key(1)).unwrap();
    let mut b = Creator {
        uncertain: true,
        ..Default::default()
    };
    a.submit(request(1, false), 0, &mut b).unwrap();
    a.service_one(0, &mut b).unwrap();
    assert_eq!(a.query(key(1), 1), Ok(SpawnState::Unknown));
    assert_eq!(a.cancel(key(1), 1), Err(Error::Busy));
    assert_eq!(a.stats().live, 1);
    assert_eq!(a.service_one(WINDOW_NS, &mut b), Ok(None));
    assert_eq!(
        a.submit(request(1, false), WINDOW_NS, &mut b),
        Ok(SpawnState::Unknown)
    );
    assert_eq!(b.calls.len(), 1);
    a.reconcile(key(1), 1, CreateOutcome::Rejected(Error::Io))
        .unwrap();
    assert_eq!(a.stats().live, 0);
    assert_eq!(a.query(key(1), 1), Ok(SpawnState::Failed(Error::Io)));
}
#[test]
fn spawn_recovery_has_independent_tokens_slots_and_authority() {
    let mut a = SpawnAdmission::new();
    a.register_group(key(1)).unwrap();
    let mut b = Creator::default();
    a.install_tokens(key(1), 8, stamp(1, 0, 0), 0).unwrap();
    for id in 1..=64 {
        a.submit(request(id, false), 0, &mut b).unwrap();
    }
    for window in 0..8 {
        for _ in 0..8 {
            a.service_one(window * WINDOW_NS, &mut b).unwrap();
        }
    }
    assert_eq!(a.stats().live, 64);
    let mut bad = request(1, true);
    bad.caller = key(1);
    assert_eq!(a.submit(bad, 7 * WINDOW_NS, &mut b), Err(Error::Conflict));
    bad.request_id = 1000;
    assert_eq!(a.submit(bad, 7 * WINDOW_NS, &mut b), Err(Error::Auth));
    a.submit(request(1, true), 7 * WINDOW_NS, &mut b).unwrap();
    a.service_one(7 * WINDOW_NS, &mut b).unwrap();
    assert_eq!(a.stats().recovery_live, 1);
}
#[test]
fn spawn_cancel_and_failed_authorization_do_not_create() {
    let mut a = SpawnAdmission::new();
    a.register_group(key(1)).unwrap();
    let mut b = Creator::default();
    a.submit(request(1, false), 0, &mut b).unwrap();
    a.cancel(key(1), 1).unwrap();
    a.submit(request(2, false), 0, &mut b).unwrap();
    b.deny = true;
    a.service_one(0, &mut b).unwrap();
    assert_eq!(a.query(key(1), 2), Ok(SpawnState::Failed(Error::Auth)));
    assert!(b.calls.is_empty());
    assert_eq!(
        a.submit(request(1, false), 0, &mut b),
        Ok(SpawnState::Cancelled)
    );
}
#[test]
fn spawn_terminal_receipts_bound_memory_without_eviction_or_reexecution() {
    let mut a = SpawnAdmission::new();
    a.register_group(key(1)).unwrap();
    let mut b = Creator::default();
    for id in 1..=256 {
        a.submit(request(id, false), 0, &mut b).unwrap();
        a.cancel(key(1), id).unwrap();
    }
    assert_eq!(
        a.submit(request(257, false), 0, &mut b),
        Err(Error::Capacity)
    );
    assert_eq!(
        a.submit(request(1, false), 0, &mut b),
        Ok(SpawnState::Cancelled)
    );
    a.submit(request(1, true), 0, &mut b).unwrap();
    assert!(a.service_one(0, &mut b).unwrap().is_some());
}

#[test]
fn replay_caller_retirement_preserves_live_unknown_and_other_generations() {
    let mut admission = SpawnAdmission::new();
    admission.register_group(key(1)).unwrap();
    let mut creator = Creator::default();
    admission
        .submit(request(1, false), 0, &mut creator)
        .unwrap();
    assert_eq!(admission.retire_closed_caller(key(1)), Err(Error::Busy));
    admission.service_one(0, &mut creator).unwrap();
    let SpawnState::Created(child) = admission.query(key(1), 1).unwrap() else {
        panic!("real child");
    };
    assert_eq!(admission.retire_closed_caller(key(1)), Err(Error::Busy));
    admission.exited(child).unwrap();
    let next = ObjectKey {
        generation: 2,
        ..key(1)
    };
    let next_request = SpawnRequest {
        caller: next,
        ..request(2, false)
    };
    admission
        .submit(next_request, WINDOW_NS, &mut creator)
        .unwrap();
    assert_eq!(admission.retire_closed_caller(key(1)), Ok(1));
    assert_eq!(admission.query(key(1), 1), Err(Error::NotFound));
    assert_eq!(admission.query(next, 2), Ok(SpawnState::Queued));
    creator.uncertain = true;
    admission.service_one(WINDOW_NS, &mut creator).unwrap();
    assert_eq!(admission.query(next, 2), Ok(SpawnState::Unknown));
    assert_eq!(admission.retire_closed_caller(next), Err(Error::Busy));
    assert_eq!(admission.query(next, 2), Ok(SpawnState::Unknown));
    admission
        .reconcile(next, 2, CreateOutcome::Rejected(Error::Io))
        .unwrap();
    assert_eq!(admission.retire_closed_caller(next), Ok(1));
    // Revocation remains the real caller owner's obligation: an expired
    // caller cannot create a replacement after releasing its terminal rows.
    creator.deny = true;
    assert_eq!(
        admission.submit(request(1, false), 2 * WINDOW_NS, &mut creator),
        Err(Error::Auth)
    );
    assert_eq!(creator.calls.len(), 2);
}

struct Backing {
    pages: Vec<[u8; 4096]>,
    maps: BTreeMap<(ObjectKey, u64), (usize, bool)>,
    fail_map: bool,
    fail_revoke: bool,
    fail_load: bool,
    fail_drop: bool,
    drops: usize,
}
impl Backing {
    fn new(pages: usize) -> Self {
        Self {
            pages: vec![[0xa5; 4096]; pages],
            maps: BTreeMap::new(),
            fail_map: false,
            fail_revoke: false,
            fail_load: false,
            fail_drop: false,
            drops: 0,
        }
    }
}
impl MemoryBackend for Backing {
    fn zero(&mut self, frame: usize) -> Result<(), Error> {
        self.pages[frame].fill(0);
        Ok(())
    }
    fn map(
        &mut self,
        owner: ObjectKey,
        address: u64,
        frame: usize,
        write: bool,
    ) -> Result<(), Error> {
        self.maps.insert((owner, address), (frame, write));
        if self.fail_map {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
    fn revoke(&mut self, owner: ObjectKey, address: u64, _: usize) -> Result<(), Error> {
        if self.fail_revoke {
            return Err(Error::Busy);
        }
        self.maps.remove(&(owner, address));
        Ok(())
    }
    fn load_cache(&mut self, object: ObjectKey, page: u64, frame: usize) -> Result<(), Error> {
        self.pages[frame].fill((object.id + page) as u8);
        if self.fail_load {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
    fn drop_cache(&mut self, _: CacheHandle) -> Result<(), Error> {
        if self.fail_drop {
            return Err(Error::Busy);
        }
        self.drops += 1;
        Ok(())
    }
}
#[test]
fn anonymous_pages_are_zeroed_mapped_with_permissions_and_rezeroed_after_unmap() {
    let mut m = Memory::<8>::new();
    let mut b = Backing::new(8);
    m.register_owner(key(1), 2).unwrap();
    m.reserve(key(1), 0x10000, 2, true).unwrap();
    assert_eq!(m.stats().anonymous_pages, 0);
    let p = m.fault(key(1), 0x10008, true, &mut b).unwrap();
    assert!(b.pages[p].iter().all(|v| *v == 0));
    assert_eq!(b.maps[&(key(1), 0x10000)], (p, true));
    b.pages[p][8] = 99;
    m.unmap_step(key(1), 0x10000, 1, &mut b).unwrap();
    assert!(b.maps.is_empty());
    m.reserve(key(1), 0x10000, 1, false).unwrap();
    assert_eq!(m.fault(key(1), 0x10000, true, &mut b), Err(Error::Auth));
    let q = m.fault(key(1), 0x10000, false, &mut b).unwrap();
    assert_eq!(b.pages[q][8], 0);
}
#[test]
fn uncertain_mapping_retains_frame_until_revoke_and_zero_prove_release() {
    let mut m = Memory::<2>::new();
    let mut b = Backing::new(2);
    m.register_owner(key(1), 1).unwrap();
    m.reserve(key(1), 0x10000, 1, true).unwrap();
    b.fail_map = true;
    assert_eq!(m.fault(key(1), 0x10000, true, &mut b), Err(Error::Io));
    assert_eq!(m.owner_pages(key(1)), Ok(1));
    assert_eq!(m.stats().free_pages, 1);
    assert_eq!(
        m.fault(key(1), 0x10000, false, &mut b),
        Err(Error::NotReady)
    );
    b.fail_revoke = true;
    assert_eq!(m.unmap_step(key(1), 0x10000, 1, &mut b), Err(Error::Busy));
    assert_eq!(m.stats().free_pages, 1);
    b.fail_revoke = false;
    m.unmap_step(key(1), 0x10000, 1, &mut b).unwrap();
    m.unregister_owner(key(1)).unwrap();
    assert_eq!(m.stats().free_pages, 2);
    assert!(b.maps.is_empty());
}
#[test]
fn contract_backing_stays_private_across_unmap_until_owner_release() {
    let mut m = Memory::<4>::new();
    let mut b = Backing::new(4);
    m.register_owner(key(1), 3).unwrap();
    m.commit_pages(key(1)).unwrap();
    m.register_owner(key(2), 2).unwrap();
    m.reserve(key(2), 0x10000, 2, true).unwrap();
    m.fault(key(2), 0x10000, true, &mut b).unwrap();
    assert_eq!(m.fault(key(2), 0x11000, true, &mut b), Err(Error::Capacity));
    m.reserve(key(1), 0x20000, 1, true).unwrap();
    m.fault(key(1), 0x20000, true, &mut b).unwrap();
    m.unmap_step(key(1), 0x20000, 1, &mut b).unwrap();
    assert_eq!(m.stats().committed_pages, 3);
    assert_eq!(m.stats().free_pages, 0);
    m.unregister_owner(key(1)).unwrap();
    assert_eq!(m.stats().free_pages, 3);
}
#[test]
fn independent_progress_frames_survive_ordinary_exhaustion() {
    let mut m = Memory::<4>::new();
    let mut b = Backing::new(4);
    m.reserve_frames(0, 1).unwrap();
    m.reserve_progress_frames(3, 1).unwrap();
    m.register_owner(key(1), 4).unwrap();
    m.reserve(key(1), 0x10000, 3, true).unwrap();
    for va in [0x10000, 0x11000] {
        m.fault(key(1), va, true, &mut b).unwrap();
    }
    assert_eq!(m.fault(key(1), 0x12000, true, &mut b), Err(Error::Capacity));
    m.register_progress_owner(key(9), 1).unwrap();
    m.reserve(key(9), 0x20000, 1, true).unwrap();
    assert_eq!(m.fault(key(9), 0x20000, true, &mut b), Ok(3));
}
#[test]
fn clean_cache_reclaim_is_bounded_and_preserves_dirty_pinned_and_referenced_pages() {
    let mut m = Memory::<128>::new();
    let mut b = Backing::new(128);
    m.install_cache(64, 4, stamp(1, 0, 0), 0).unwrap();
    let mut pages = Vec::new();
    for page in 0..8 {
        pages.push(m.cache_page(key(1), page, 0, &mut b).unwrap());
    }
    m.dirty_cache(pages[0], true).unwrap();
    m.pin_cache(pages[1], true).unwrap();
    m.hold_cache(pages[2]).unwrap();
    assert_eq!(m.reclaim_step(8, 0, &mut b).unwrap().released, 4);
    assert_eq!(m.stats().cache_pages, 4);
    assert_eq!(m.reclaim_step(8, 0, &mut b).unwrap().released, 1);
    assert_eq!(m.stats().cache_pages, 3);
    m.dirty_cache(pages[0], false).unwrap();
    m.pin_cache(pages[1], false).unwrap();
    m.release_cache(pages[2]).unwrap();
    assert_eq!(m.reclaim_step(8, 0, &mut b).unwrap().released, 3);
}
#[test]
fn failed_cache_load_keeps_backing_until_callback_proves_stop() {
    let mut m = Memory::<4>::new();
    let mut b = Backing::new(4);
    b.fail_load = true;
    assert_eq!(m.cache_page(key(1), 0, 0, &mut b), Err(Error::Io));
    assert_eq!(m.stats().cache_pages, 1);
    assert_eq!(m.cache_page(key(1), 0, 0, &mut b), Err(Error::NotReady));
    b.fail_drop = true;
    assert_eq!(m.reclaim_step(1, 0, &mut b), Err(Error::Busy));
    assert_eq!(m.stats().free_pages, 3);
    b.fail_drop = false;
    m.reclaim_step(1, 0, &mut b).unwrap();
    assert_eq!(m.stats().free_pages, 4);
}
#[test]
fn invalidated_cache_rejects_old_hits_and_generation_handles_while_holders_drain() {
    let mut m = Memory::<4>::new();
    let mut b = Backing::new(4);
    let old = m.cache_page(key(1), 0, 0, &mut b).unwrap();
    m.hold_cache(old).unwrap();
    m.invalidate_cache(key(1));
    assert_eq!(m.lookup_cache(key(1), 0, 0), Ok(None));
    assert_eq!(m.hold_cache(old), Err(Error::Stale));
    assert_eq!(m.reclaim_step(1, 0, &mut b).unwrap().released, 0);
    m.release_cache(old).unwrap();
    m.reclaim_step(1, 0, &mut b).unwrap();
    let new = m.cache_page(key(1), 0, 0, &mut b).unwrap();
    assert_eq!(new.frame, old.frame);
    assert_ne!(new.generation, old.generation);
    assert_eq!(m.hold_cache(old), Err(Error::Stale));
}
#[test]
fn common_cache_partition_uses_only_its_grant_and_expiry_restores_partitioned_baseline() {
    let mut m = Memory::<128>::new();
    let mut b = Backing::new(128);
    m.configure_cache_baseline(16).unwrap();
    m.install_cache_partition(256, 16, 32, 16, stamp(1, 0, 0), 0)
        .unwrap();
    for page in 0..32 {
        m.cache_page(key(1), page, 0, &mut b).unwrap();
    }
    assert_eq!(m.cache_page(key(1), 32, 0, &mut b), Err(Error::Again));
    assert_eq!(m.cache_policy(0), (256, 16));
    assert_eq!(m.cache_authorized_pages(POLICY_NS), 16);
    assert_eq!(m.reclaim_step(0, POLICY_NS, &mut b).unwrap().released, 16);
}

#[derive(Default)]
struct Messages {
    got: Vec<(u64, u64, Vec<u8>)>,
    notices: usize,
    fail_notify: bool,
    fail_delivery: bool,
    fail_after: Option<usize>,
    deny: bool,
}
impl<const B: usize> IpcBackend<B> for Messages {
    fn authorize(&mut self, _: ObjectKey, _: ObjectKey, _: IpcOperation) -> Result<(), Error> {
        if self.deny { Err(Error::Auth) } else { Ok(()) }
    }
    fn notify(&mut self, _: ObjectKey, _: ObjectKey) -> Result<(), Error> {
        self.notices += 1;
        if self.fail_notify {
            Err(Error::Again)
        } else {
            Ok(())
        }
    }
    fn deliver(&mut self, _: ObjectKey, _: ObjectKey, m: &Message<B>) -> Result<(), Error> {
        if self.fail_delivery {
            return Err(Error::Io);
        }
        if self.fail_after == Some(self.got.len()) {
            return Err(Error::Again);
        }
        self.got
            .push((m.sequence, m.request_id, m.bytes[..m.len].to_vec()));
        Ok(())
    }
}
#[test]
fn ipc_shrink_preserves_128_messages_and_batch_changes_real_delivery() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Messages::default();
    let ep = ipc.open(key(1), false).unwrap();
    ipc.install(ep, 128, 16, stamp(1, 0, 0), 0).unwrap();
    for id in 1..=128 {
        ipc.send(key(2), ep, id, &[id as u8], 0, &mut b).unwrap();
    }
    ipc.install(ep, 8, 1, stamp(2, 0, 0), 0).unwrap();
    assert_eq!(ipc.stats(ep).unwrap().depth, 128);
    assert_eq!(
        ipc.send(key(2), ep, 129, b"x", 0, &mut b),
        Err(Error::Again)
    );
    for _ in 0..128 {
        assert_eq!(ipc.receive_batch(key(1), ep, 0, &mut b), Ok(1));
    }
    assert_eq!(
        b.got.iter().map(|m| m.0).collect::<Vec<_>>(),
        (1..=128).collect::<Vec<_>>()
    );
}
#[test]
fn ipc_waiter_cancellation_never_delivers_cancelled_message() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut b = Messages::default();
    let ep = ipc.open(key(1), false).unwrap();
    for id in 1..=32 {
        ipc.send(key(2), ep, id, b"x", 0, &mut b).unwrap();
    }
    let cancel = ipc.wait_send(key(2), ep, 33, b"cancel", 0, &mut b).unwrap();
    let live = ipc.wait_send(key(2), ep, 34, b"live", 0, &mut b).unwrap();
    assert_eq!(ipc.cancel(cancel, &mut b), Ok(WaitResult::Cancelled));
    ipc.receive_batch(key(1), ep, 1, &mut b).unwrap();
    assert!(matches!(ipc.wait_result(live), Ok(WaitResult::Sent(33))));
    while ipc.stats(ep).unwrap().depth != 0 {
        ipc.receive_batch(key(1), ep, 1, &mut b).unwrap();
    }
    assert!(!b.got.iter().any(|m| m.1 == 33));
    assert_eq!(b.got.len(), 33);
}
#[test]
fn ipc_closed_backing_cannot_leak_messages_into_reused_endpoint_generation() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut backend = Messages::default();
    let old = ipc.open(key(1), false).unwrap();
    for request in 1..=32 {
        ipc.send(key(2), old, request, b"old-data", 0, &mut backend)
            .unwrap();
    }
    let waiting = ipc
        .wait_send(key(2), old, 33, b"waiting", 0, &mut backend)
        .unwrap();
    ipc.close(key(1), old, &mut backend).unwrap();
    assert_eq!(
        ipc.wait_result(waiting),
        Ok(WaitResult::Failed(Error::NotFound))
    );
    let new = ipc.open(key(3), false).unwrap();
    assert_eq!(old.id, new.id);
    assert_ne!(old.generation, new.generation);
    assert_eq!(ipc.receive_batch(key(3), new, 1, &mut backend), Ok(0));
    assert_eq!(
        ipc.send(key(2), old, 34, b"stale", 1, &mut backend),
        Err(Error::Stale)
    );
    assert_eq!(ipc.send(key(3), new, 1, b"new", 1, &mut backend), Ok(1));
    assert_eq!(ipc.receive_batch(key(3), new, 1, &mut backend), Ok(1));
    assert_eq!(backend.got, vec![(1, 1, b"new".to_vec())]);
}
#[test]
fn ipc_limited_receive_preserves_fifo_and_remaining_custody() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut backend = Messages::default();
    let endpoint = ipc.open(key(1), false).unwrap();
    ipc.install(endpoint, 64, 8, stamp(1, 0, 0), 0).unwrap();
    for sequence in 1..=3 {
        ipc.send(
            key(2),
            endpoint,
            sequence,
            &[sequence as u8],
            0,
            &mut backend,
        )
        .unwrap();
    }
    assert_eq!(
        ipc.receive_batch_limited(key(1), endpoint, 1, 1, &mut backend),
        Ok(1)
    );
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 2);
    assert_eq!(
        ipc.receive_batch_limited(key(1), endpoint, 2, 1, &mut backend),
        Ok(1)
    );
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 1);
    assert_eq!(
        ipc.receive_batch_limited(key(1), endpoint, 3, 1, &mut backend),
        Ok(1)
    );
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 0);
    assert_eq!(
        backend
            .got
            .iter()
            .map(|message| message.0)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        ipc.receive_batch_limited(key(1), endpoint, 4, 0, &mut backend),
        Err(Error::Range)
    );
}

#[test]
fn ipc_partial_transmit_progress_keeps_failed_head_and_never_replays_prefix() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut backend = Messages {
        fail_after: Some(2),
        ..Default::default()
    };
    let endpoint = ipc.open(key(1), false).unwrap();
    ipc.install(endpoint, 64, 8, stamp(1, 0, 0), 0).unwrap();
    for sequence in 1..=6 {
        ipc.send(
            key(2),
            endpoint,
            sequence,
            &[sequence as u8],
            0,
            &mut backend,
        )
        .unwrap();
    }
    assert_eq!(ipc.receive_batch(key(1), endpoint, 1, &mut backend), Ok(2));
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 4);
    assert_eq!(
        ipc.receive_batch(key(1), endpoint, 2, &mut backend),
        Err(Error::Again)
    );
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 4);
    backend.fail_after = None;
    assert_eq!(ipc.receive_batch(key(1), endpoint, 3, &mut backend), Ok(4));
    assert_eq!(
        backend
            .got
            .iter()
            .map(|message| message.0)
            .collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
    assert_eq!(ipc.stats(endpoint).unwrap().depth, 0);
}
#[test]
fn ipc_policy_receipt_requires_an_actual_admission_or_delivery_under_that_version() {
    let mut ipc = Box::new(Ipc::<8>::new());
    let mut backend = Messages::default();
    let endpoint = ipc.open(key(1), false).unwrap();
    ipc.send(key(2), endpoint, 1, b"old", 0, &mut backend)
        .unwrap();
    ipc.install(endpoint, 8, 1, stamp(1, 0, 1), 1).unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(0));
    backend.fail_delivery = true;
    assert_eq!(
        ipc.receive_batch(key(1), endpoint, 1, &mut backend),
        Err(Error::Io)
    );
    assert_eq!(ipc.policy_receipt(endpoint), Ok(0));
    backend.fail_delivery = false;
    ipc.receive_batch(key(1), endpoint, 2, &mut backend)
        .unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(1));
    ipc.install(endpoint, 32, 4, stamp(2, 0, 2), 2).unwrap();
    ipc.send(key(2), endpoint, 2, b"new", 3, &mut backend)
        .unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(2));
    ipc.receive_batch(key(1), endpoint, 4, &mut backend)
        .unwrap();
    ipc.install(endpoint, 64, 8, stamp(3, 0, 4), 4).unwrap();
    assert_eq!(ipc.receive_batch(key(1), endpoint, 5, &mut backend), Ok(0));
    ipc.send(key(2), endpoint, 3, b"expired", POLICY_NS, &mut backend)
        .unwrap();
    assert_eq!(ipc.policy_receipt(endpoint), Ok(2));
}
#[test]
fn ipc_recovery_endpoints_and_notification_obligations_are_independent() {
    let mut ipc = Box::new(Ipc::<1>::new());
    let mut b = Messages {
        fail_notify: true,
        ..Default::default()
    };
    for _ in 0..32 {
        ipc.open(key(1), false).unwrap();
    }
    assert_eq!(ipc.open(key(1), false), Err(Error::Capacity));
    let ep = ipc.open(key(9), true).unwrap();
    assert_eq!(ipc.send(key(8), ep, 1, &[1], 0, &mut b), Ok(1));
    assert_eq!(ipc.stats(ep).unwrap().notifications, 0);
    b.fail_notify = false;
    ipc.flush_notifications(&mut b);
    assert_eq!(ipc.stats(ep).unwrap().notifications, 1);
    assert_eq!(ipc.receive_batch(key(9), ep, 0, &mut b), Ok(1));
}

#[derive(Default)]
struct Services {
    calls: Vec<(ObjectKey, Vec<ResolvedItem>)>,
    stale_object: Option<u64>,
    fail_transport: bool,
}
impl ServiceBackend for Services {
    fn validate_object(&mut self, object: ObjectKey, _: u16) -> Result<(), Error> {
        if self.stale_object == Some(object.id) {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn call_batch(
        &mut self,
        service: ObjectKey,
        items: &[ResolvedItem],
        out: &mut [Option<Result<u64, Error>>],
    ) -> Result<(), Error> {
        self.calls.push((service, items.to_vec()));
        for (i, (item, result)) in items.iter().zip(out).enumerate() {
            if self.fail_transport && i != 0 {
                return Err(Error::Io);
            }
            *result = Some(Ok(item.object.id + u64::from(item.op)));
        }
        Ok(())
    }
}
fn vector(batch: u8) -> (ServiceBatch, Vec<ServiceItem>) {
    let mut s = ServiceBatch::new();
    s.install(batch, stamp(1, 0, 0), 0).unwrap();
    let mut items = Vec::new();
    for i in 0..16 {
        let cap = s.grant(key(1), key(100 + i), key(50), 2).unwrap();
        items.push(ServiceItem {
            op: 2,
            flags: 0,
            cap,
            object_gen: 1,
            tag: i,
        });
    }
    (s, items)
}
#[test]
fn submitv_batching_changes_actual_calls_without_changing_tagged_results() {
    let mut results = Vec::new();
    for batch in [1, 2, 4, 8] {
        let (mut s, items) = vector(batch);
        let mut b = Services::default();
        let mut v = s.submit(key(1), &items, 1000, 0).unwrap();
        while !v.complete() {
            s.step(&mut v, 1, &mut b).unwrap();
        }
        assert_eq!(b.calls.len(), 16 / batch as usize);
        results.push(v.results().to_vec());
    }
    assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
}
#[test]
fn submitv_preflights_all_items_before_any_effect() {
    let (mut s, items) = vector(8);
    for invalid in 0..3 {
        let mut bad = items.clone();
        match invalid {
            0 => bad[15].op = 3,
            1 => bad[15].flags = 1,
            _ => bad[15].tag = bad[0].tag,
        };
        assert!(matches!(
            s.submit(key(1), &bad, 1000, 0),
            Err(Error::Format)
        ));
    }
    assert_eq!(s.stats().vectors, 0);
    assert_eq!(s.stats().ipc_calls, 0);
}
#[test]
fn submitv_rechecks_capability_generations_and_preserves_partial_transport_results() {
    let (mut s, items) = vector(4);
    let mut b = Services::default();
    let mut v = s.submit(key(1), &items, 1000, 0).unwrap();
    s.step(&mut v, 1, &mut b).unwrap();
    let first = v.results()[0];
    s.revoke(key(1), items[4].cap).unwrap();
    v.cancel(5).unwrap();
    b.stale_object = Some(106);
    b.fail_transport = true;
    while !v.complete() {
        s.step(&mut v, 2, &mut b).unwrap();
    }
    assert_eq!(v.results()[0], first);
    assert_eq!(v.results()[4].status, ItemStatus::Error(Error::Auth));
    assert_eq!(v.results()[5].status, ItemStatus::Cancelled);
    assert_eq!(v.results()[6].status, ItemStatus::Error(Error::Stale));
    assert!(
        v.results()[7..]
            .iter()
            .any(|r| r.status == ItemStatus::Error(Error::Io))
    );
}
#[test]
fn service_policy_receipt_ignores_preflight_and_failed_transport_without_effects() {
    struct Unavailable;
    impl ServiceBackend for Unavailable {
        fn validate_object(&mut self, _: ObjectKey, _: u16) -> Result<(), Error> {
            Ok(())
        }
        fn call_batch(
            &mut self,
            _: ObjectKey,
            _: &[ResolvedItem],
            _: &mut [Option<Result<u64, Error>>],
        ) -> Result<(), Error> {
            Err(Error::Busy)
        }
    }
    let mut service = ServiceBatch::new();
    let cap = service.grant(key(1), key(2), key(3), 2).unwrap();
    let item = ServiceItem {
        op: 2,
        flags: 0,
        cap,
        object_gen: 1,
        tag: 7,
    };
    service.install(4, stamp(1, 0, 0), 0).unwrap();
    let mut vector = service.submit(key(1), &[item], 1000, 0).unwrap();
    assert_eq!(service.policy_receipt(), 0);
    service.step(&mut vector, 1, &mut Unavailable).unwrap();
    assert_eq!(service.policy_receipt(), 0);
    service.install(8, stamp(2, 0, 2), 2).unwrap();
    let mut next = service.submit(key(1), &[item], 1000, 2).unwrap();
    service
        .step(&mut next, 3, &mut Services::default())
        .unwrap();
    assert_eq!(service.policy_receipt(), 2);
    service.install(1, stamp(3, 0, 4), 4).unwrap();
    service.revoke(key(1), cap).unwrap();
    let mut revoked = service.submit(key(1), &[item], 1000, 4).unwrap();
    service
        .step(&mut revoked, 5, &mut Services::default())
        .unwrap();
    assert_eq!(revoked.results()[0].status, ItemStatus::Error(Error::Auth));
    assert_eq!(service.policy_receipt(), 2);
}
#[test]
fn submitv_timeout_never_calls_service_and_foreign_cap_cannot_execute() {
    let (mut s, items) = vector(8);
    let mut b = Services::default();
    let mut timed = s.submit(key(1), &items, 1, 0).unwrap();
    s.step(&mut timed, 1, &mut b).unwrap();
    assert!(b.calls.is_empty());
    assert!(
        timed
            .results()
            .iter()
            .all(|r| r.status == ItemStatus::TimedOut)
    );
    let mut foreign = s.submit(key(2), &items, 1000, 1).unwrap();
    s.step(&mut foreign, 2, &mut b).unwrap();
    assert!(b.calls.is_empty());
    assert!(
        foreign
            .results()
            .iter()
            .all(|r| r.status == ItemStatus::Error(Error::Auth))
    );
}

#[test]
fn a_policy_version_cannot_be_rebound_to_different_executor_parameters() {
    let policy = stamp(1, 0, 0);
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(1)).unwrap();
    scheduler.install_weight(key(1), 4, policy, 0).unwrap();
    assert_eq!(
        scheduler.install_weight(key(1), 8, policy, 1),
        Err(Error::Conflict)
    );
    assert_eq!(scheduler.weight(key(1), 1), Ok(4));

    let mut spawn = SpawnAdmission::new();
    spawn.register_group(key(1)).unwrap();
    spawn.install_tokens(key(1), 4, policy, 0).unwrap();
    assert_eq!(
        spawn.install_tokens(key(1), 8, policy, 1),
        Err(Error::Conflict)
    );
    assert_eq!(spawn.tokens(key(1), 1), Ok(4));

    let mut memory = Memory::<1024>::new();
    memory
        .install_cache_partition(256, 16, 64, 64, policy, 0)
        .unwrap();
    assert_eq!(
        memory.install_cache_partition(256, 16, 128, 64, policy, 1),
        Err(Error::Conflict)
    );
    assert_eq!(memory.cache_authorized_pages(1), 64);

    let mut ipc = Ipc::<8>::new();
    let endpoint = ipc.open(key(1), false).unwrap();
    ipc.install(endpoint, 64, 8, policy, 0).unwrap();
    assert_eq!(
        ipc.install(endpoint, 128, 16, policy, 1),
        Err(Error::Conflict)
    );
    assert_eq!(ipc.policy(endpoint, 1), Ok((64, 8)));

    let mut service = ServiceBatch::new();
    service.install(4, policy, 0).unwrap();
    assert_eq!(service.install(8, policy, 1), Err(Error::Conflict));
    assert_eq!(service.policy(1), 4);
    // A byte-identical retransmission acknowledges the original lifetime; it
    // cannot extend it merely because the executor is contacted later.
    service.install(4, policy, POLICY_NS + 1).unwrap();
    assert_eq!(service.policy(POLICY_NS + 1), 1);
    assert_eq!(service.policy_receipt(), 0);
}

#[test]
fn control_round_trip_keeps_physical_cpu_cost_and_pending_business_credit() {
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(1)).unwrap();
    scheduler
        .admit(spec(1, 1, 0, 0, 80_000_000), layout(1), 0)
        .unwrap();
    let credit = scheduler
        .dispatch(0, layout(1), 0, 20_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        scheduler.cpu_window_usage(0, 0),
        Ok((0, credit.reserved_ns))
    );
    assert_eq!(scheduler.record_control_cost(0, 1, 1, 2), Err(Error::Busy));
    scheduler
        .complete(
            credit,
            credit.reserved_ns,
            RunState::Runnable,
            credit.reserved_ns,
        )
        .unwrap();
    let business = credit.reserved_ns;
    scheduler
        .record_control_cost(0, 60_000_000, business + 60_000_000, 2)
        .unwrap();
    assert_eq!(
        scheduler.cpu_window_usage(0, business + 60_000_000),
        Ok((business + 60_000_000, 0))
    );
    assert_eq!(scheduler.stats().actual_ns, business);
    // Switching plane/generation does not refill the physical 90ms budget.
    let next = scheduler
        .dispatch(0, layout(3), business + 60_000_000, 80_000_000)
        .unwrap()
        .unwrap();
    assert!(next.reserved_ns <= 90_000_000 - business - 60_000_000);
    scheduler
        .complete(next, 0, RunState::Runnable, business + 60_000_000)
        .unwrap();
    assert_eq!(scheduler.cpu_window_usage(0, WINDOW_NS), Ok((0, 0)));
}

#[test]
fn crossed_control_receipt_closes_the_tail_instead_of_refilling_on_plane_change() {
    let mut scheduler = Scheduler::new();
    assert_eq!(
        scheduler.record_control_cost(1, 2_000_000, WINDOW_NS + 1_000_000, 4),
        Err(Error::Budget)
    );
    assert_eq!(scheduler.stats().quarantine_mask, 2);
    assert_eq!(
        scheduler.cpu_window_usage(1, WINDOW_NS + 2_000_000),
        Ok((2_000_000, 0))
    );
    assert_eq!(
        scheduler.recover_cpu(1, layout(5), WINDOW_NS + 2_000_000),
        Err(Error::Busy)
    );
    scheduler.recover_cpu(1, layout(5), 2 * WINDOW_NS).unwrap();
    assert_eq!(scheduler.cpu_window_usage(1, 2 * WINDOW_NS), Ok((0, 0)));
}

fn control_layout(generation: u64) -> CpuLayout {
    CpuLayout {
        business_mask: 1,
        healthy_mask: 3,
        generation,
    }
}

#[test]
fn complete_control_chain_is_prepaid_on_its_actual_cpu_and_refunded_once() {
    let mut s = Scheduler::new();
    let c = s
        .reserve_control(1, control_layout(1), 0, 2_500_000)
        .unwrap()
        .unwrap();
    assert_eq!(s.cpu_window_usage(1, 0), Ok((0, 2_500_000)));
    assert_eq!(s.cpu_window_usage(0, 0), Ok((0, 0)));
    assert_eq!(
        s.reserve_control(1, control_layout(1), 0, 1),
        Err(Error::Busy)
    );
    assert_eq!(s.dispatch(1, layout(2), 0, 1), Err(Error::Busy));
    let mut forged = c;
    forged.sequence += 1;
    assert_eq!(s.complete_control(forged, 0, 0), Err(Error::Stale));
    assert_eq!(s.control_active(1), Some(c));
    s.complete_control(c, 1_000_000, 1_000_000).unwrap();
    assert_eq!(
        s.complete_control(c, 1_000_000, 1_000_000),
        Err(Error::Stale)
    );
    assert_eq!(s.cpu_window_usage(1, 1_000_000), Ok((1_000_000, 0)));
    assert_eq!(
        s.stats().actual_ns,
        0,
        "control must not inflate business-thread CPU"
    );
}

#[test]
fn control_seventy_ms_and_shared_ninety_ms_survive_plane_round_trip() {
    let mut s = Scheduler::new();
    for turn in 0..28 {
        let at = turn * 2_500_000;
        let c = s
            .reserve_control(1, control_layout(1), at, 2_500_000)
            .unwrap()
            .unwrap();
        s.complete_control(c, 2_500_000, at + 2_500_000).unwrap();
    }
    assert_eq!(
        s.reserve_control(1, control_layout(1), 70_000_000, 1),
        Ok(None)
    );
    s.register_group(key(1)).unwrap();
    s.admit(spec(1, 1, 1, 0, 20_000_000), layout(2), 70_000_000)
        .unwrap();
    let mut now = 70_000_000;
    while now < 90_000_000 {
        let b = s.dispatch(1, layout(2), now, 20_000_000).unwrap().unwrap();
        now += b.reserved_ns;
        s.complete(b, b.reserved_ns, RunState::Runnable, now)
            .unwrap();
    }
    assert_eq!(s.cpu_window_usage(1, now), Ok((90_000_000, 0)));
    assert_eq!(s.reserve_control(1, control_layout(3), now, 1), Ok(None));
    let c = s
        .reserve_control(1, control_layout(3), WINDOW_NS, 2_500_000)
        .unwrap()
        .unwrap();
    assert_eq!(c.control_total_ns, 2_500_000);
    assert_eq!(s.cpu_window_usage(1, WINDOW_NS), Ok((0, 2_500_000)));
    s.complete_control(c, 0, WINDOW_NS).unwrap();
}

#[test]
fn pending_control_receipt_cannot_roll_away_or_release_a_crossed_window() {
    let mut s = Scheduler::new();
    let c = s
        .reserve_control(1, control_layout(1), 98_000_000, 2_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(s.cpu_window_usage(1, WINDOW_NS), Ok((0, 2_000_000)));
    assert_eq!(
        s.reserve_control(1, control_layout(2), WINDOW_NS, 1),
        Err(Error::Busy)
    );
    assert_eq!(s.dispatch(1, layout(2), WINDOW_NS, 1), Err(Error::Busy));
    assert_eq!(
        s.complete_control(c, 3_000_000, 101_000_000),
        Err(Error::Budget)
    );
    assert_eq!(s.control_active(1), None);
    assert_eq!(s.cpu_window_usage(1, 102_000_000), Ok((3_000_000, 0)));
    assert_eq!(s.stats().quarantine_mask, 2);
    assert_eq!(s.stats().overruns, 1);
}

#[test]
fn control_work_never_starts_with_only_partial_window_credit() {
    let mut s = Scheduler::new();
    assert_eq!(
        s.reserve_control(0, control_layout(1), 0, 2_500_000),
        Err(Error::Auth)
    );
    assert_eq!(
        s.reserve_control(1, control_layout(1), 99_000_000, 2_500_000),
        Ok(None)
    );
    assert_eq!(s.cpu_window_usage(1, 99_000_000), Ok((0, 0)));
    assert!(s.control_active(1).is_none());
    assert!(
        s.reserve_control(1, control_layout(1), WINDOW_NS, 2_500_000)
            .unwrap()
            .is_some()
    );
}
