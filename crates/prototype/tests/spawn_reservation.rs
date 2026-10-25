//! Exercises the actual spawn queue and scheduler together. The backend's
//! construction boundary is after a real scheduler reservation, as in LOCAL.
use cyxia_prototype::domains::{
    Error, ObjectKey, WINDOW_NS,
    tasks::{
        CPU_BUDGET_NS, CpuLayout, CreateOutcome, RunState, Scheduler, SpawnAdmission, SpawnRequest,
        SpawnState, TaskBackend, ThreadSpec,
    },
};

fn key(id: u64) -> ObjectKey {
    ObjectKey { id, generation: 1 }
}
fn layout() -> CpuLayout {
    CpuLayout {
        business_mask: 13,
        healthy_mask: 15,
        generation: 7,
    }
}
fn spec(id: u64, minimum_ns: u64, budget_ns: u64) -> ThreadSpec {
    ThreadSpec {
        key: key(id),
        group: key(5),
        cpu: 3,
        allowed_mask: 12,
        minimum_ns,
        budget_ns,
    }
}
fn request(id: u64) -> SpawnRequest {
    SpawnRequest {
        caller: key(0x102),
        request_id: id,
        package: key(4),
        group: key(5),
        payload_hash: [id as u8; 32],
        recovery: false,
    }
}
fn queue() -> SpawnAdmission {
    let mut q = SpawnAdmission::new();
    q.register_group(key(5)).unwrap();
    q
}
struct Creator {
    scheduler: Scheduler,
    now: u64,
    deadline: u64,
    denied: bool,
    uncertain: bool,
    attempted: Vec<SpawnRequest>,
    constructed: Vec<ObjectKey>,
}
impl Creator {
    fn new(deadline: u64) -> Self {
        let mut scheduler = Scheduler::new();
        scheduler.register_group(key(5)).unwrap();
        Self {
            scheduler,
            now: 0,
            deadline,
            denied: false,
            uncertain: false,
            attempted: Vec::new(),
            constructed: Vec::new(),
        }
    }
    fn service(&mut self, q: &mut SpawnAdmission, now: u64) -> Option<(SpawnRequest, SpawnState)> {
        self.now = now;
        q.service_one(now, self).unwrap()
    }
}
impl TaskBackend for Creator {
    fn authorize(&mut self, r: &SpawnRequest) -> Result<(), Error> {
        if self.denied || r.caller != key(0x102) || r.package != key(4) {
            Err(Error::Auth)
        } else if self.now >= self.deadline {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
    fn create(&mut self, r: &SpawnRequest) -> CreateOutcome {
        self.attempted.push(*r);
        let thread = spec(0x1000 + r.request_id, 10_000_000, 10_000_000);
        let ready = match self.scheduler.prepare_admission(thread, layout(), self.now) {
            Ok(None) => return CreateOutcome::Deferred,
            Ok(Some(ready)) => ready,
            Err(e) => return CreateOutcome::Rejected(e),
        };
        assert_eq!(ready.key(), thread.key);
        assert_eq!(ready.cpu(), thread.cpu);
        assert_eq!(ready.core_generation(), layout().generation);
        assert_eq!(ready.admitted_ns(), self.now);
        // A granted reservation already owns the exact scheduler identity;
        // there is no second, time-dependent admission after construction.
        assert_eq!(self.scheduler.thread_cpu_ns(thread.key), Ok(0));
        self.constructed.push(thread.key);
        if self.uncertain {
            CreateOutcome::Uncertain
        } else {
            CreateOutcome::Created(thread.key)
        }
    }
}

#[test]
fn retired_cpu_spending_defers_the_original_spawn_until_a_real_new_window() {
    let mut c = Creator::new(2 * WINDOW_NS);
    // Real work exits, leaving 35,824 ns charged to this physical window.
    c.scheduler
        .admit(spec(700, 0, 1_000_000), layout(), 0)
        .unwrap();
    let d = c
        .scheduler
        .dispatch(3, layout(), 0, 35_824)
        .unwrap()
        .unwrap();
    c.scheduler
        .complete(d, 35_824, RunState::Exited, 35_824)
        .unwrap();
    c.scheduler.remove(key(700)).unwrap();
    c.scheduler
        .admit(spec(800, 0, 80_000_000), layout(), 35_824)
        .unwrap();
    assert_eq!(c.scheduler.cpu_spent_ns(3), Ok(35_824));
    assert_eq!(c.scheduler.admission_observation(3), (80_000_000, 0));
    let attempt_ns = 50_826_336;
    assert_eq!(
        c.scheduler
            .admit(spec(900, 10_000_000, 10_000_000), layout(), attempt_ns),
        Err(Error::Budget)
    );
    let mut q = queue();
    let original = request(1);
    q.submit(original, 1_000_000, &mut c).unwrap();
    assert_eq!(
        c.service(&mut q, attempt_ns),
        Some((original, SpawnState::Queued))
    );
    assert_eq!(
        q.request(original.caller, original.request_id),
        Ok(original)
    );
    assert_eq!(q.stats().live, 0);
    assert_eq!(q.stats().rejected, 0);
    assert_eq!(q.stats().wait_ns, 0);
    assert!(c.constructed.is_empty());
    assert_eq!(c.scheduler.thread_count(), 1);
    assert_eq!(c.scheduler.cpu_spent_ns(3), Ok(35_824));
    assert_eq!(
        c.service(&mut q, WINDOW_NS),
        Some((original, SpawnState::Created(key(0x1001))))
    );
    assert_eq!(c.constructed, [key(0x1001)]);
    assert_eq!(c.attempted, [original, original]);
    assert_eq!(c.scheduler.committed_ns(3), CPU_BUDGET_NS);
    assert_eq!(q.stats().wait_ns, WINDOW_NS - 1_000_000);
    assert_eq!(c.service(&mut q, WINDOW_NS + 1), None);
    assert_eq!(
        q.submit(original, WINDOW_NS + 1, &mut c),
        Ok(SpawnState::Created(key(0x1001)))
    );
    assert_eq!(c.constructed.len(), 1);
}

#[test]
fn four_original_requests_wait_for_actual_completion_and_removal_in_order() {
    let mut c = Creator::new(5 * WINDOW_NS);
    c.scheduler
        .admit(spec(800, 0, 80_000_000), layout(), 0)
        .unwrap();
    let mut q = queue();
    for id in 1..=4 {
        q.submit(request(id), 0, &mut c).unwrap();
    }
    assert_eq!(
        c.service(&mut q, 0),
        Some((request(1), SpawnState::Created(key(0x1001))))
    );
    for id in 1..=4 {
        let now = (id - 1) * WINDOW_NS;
        let child = key(0x1000 + id);
        assert_eq!(c.scheduler.committed_ns(3), CPU_BUDGET_NS);
        if id < 4 {
            assert_eq!(
                c.service(&mut q, now),
                Some((request(id + 1), SpawnState::Queued))
            );
            assert_eq!(q.stats().live, 1);
            assert_eq!(c.constructed.len(), id as usize);
        }
        let d = c
            .scheduler
            .dispatch(3, layout(), now, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(d.thread, child);
        c.scheduler
            .complete(d, 1_000, RunState::Exited, now + 1_000)
            .unwrap();
        let next_window = now + WINDOW_NS;
        if id < 4 {
            // Finishing execution alone does not retire the task's reservation.
            assert_eq!(
                c.service(&mut q, next_window),
                Some((request(id + 1), SpawnState::Queued))
            );
            assert_eq!(c.scheduler.committed_ns(3), CPU_BUDGET_NS);
        }
        c.scheduler.remove(child).unwrap();
        q.exited(child).unwrap();
        assert_eq!(c.scheduler.committed_ns(3), 80_000_000);
        if id < 4 {
            assert_eq!(
                c.service(&mut q, next_window),
                Some((request(id + 1), SpawnState::Created(key(0x1001 + id))))
            );
        }
    }
    assert_eq!(
        c.constructed,
        [key(0x1001), key(0x1002), key(0x1003), key(0x1004)]
    );
    assert_eq!(q.stats().created, 4);
    assert_eq!(q.stats().rejected, 0);
    assert_eq!(q.stats().live, 0);
    assert_eq!(q.stats().pending, 0);
    assert_eq!(c.scheduler.stats().actual_ns, 4_000);
    for id in 1..=4 {
        assert_eq!(q.request(request(id).caller, id), Ok(request(id)));
        assert_eq!(
            q.submit(request(id), 4 * WINDOW_NS, &mut c),
            Ok(SpawnState::Created(key(0x1000 + id)))
        );
    }
    assert_eq!(c.constructed.len(), 4);
    assert_eq!(c.deadline, 5 * WINDOW_NS);
}

#[test]
fn no_custody_deferral_consumes_neither_normal_nor_recovery_creation_tokens() {
    for first_recovery in [false, true] {
        let mut c = Creator::new(2 * WINDOW_NS);
        c.scheduler
            .admit(spec(800, 0, CPU_BUDGET_NS), layout(), 0)
            .unwrap();
        let mut q = queue();
        for id in 1..=4 {
            q.submit(
                SpawnRequest {
                    recovery: (id <= 2) == first_recovery,
                    ..request(id)
                },
                0,
                &mut c,
            )
            .unwrap();
        }
        for _ in 0..8 {
            let original = SpawnRequest {
                recovery: first_recovery,
                ..request(1)
            };
            assert_eq!(c.service(&mut q, 0), Some((original, SpawnState::Queued)));
        }
        assert_eq!(q.stats().live, 0);
        assert_eq!(q.stats().wait_ns, 0);
        assert!(c.constructed.is_empty());
        let d = c.scheduler.dispatch(3, layout(), 0, 100).unwrap().unwrap();
        c.scheduler.complete(d, 100, RunState::Exited, 100).unwrap();
        c.scheduler.remove(key(800)).unwrap();
        for id in 1..=4 {
            let original = SpawnRequest {
                recovery: (id <= 2) == first_recovery,
                ..request(id)
            };
            assert_eq!(
                c.service(&mut q, 1_000_000),
                Some((original, SpawnState::Created(key(0x1000 + id))))
            );
        }
        // The actual four constructions still consume their original two-per-class
        // limit. No retry grants additional normal or reserved recovery capacity.
        q.submit(request(5), 1_000_000, &mut c).unwrap();
        q.submit(
            SpawnRequest {
                recovery: true,
                ..request(6)
            },
            1_000_000,
            &mut c,
        )
        .unwrap();
        assert_eq!(c.service(&mut q, 1_000_000), None);
        assert_eq!(q.stats().live, 2);
        assert_eq!(q.stats().recovery_live, 2);
        assert_eq!(q.stats().wait_ns, 4_000_000);
    }
}

#[test]
fn old_window_credit_stays_unknown_to_admission_until_exact_actual_settlement() {
    let mut c = Creator::new(3 * WINDOW_NS);
    c.scheduler
        .admit(spec(800, 0, 10_000_000), layout(), 0)
        .unwrap();
    let first = WINDOW_NS - 1_000;
    let d = c
        .scheduler
        .dispatch(3, layout(), first, 1_000)
        .unwrap()
        .unwrap();
    let mut q = queue();
    q.submit(request(1), first, &mut c).unwrap();
    assert_eq!(
        c.service(&mut q, WINDOW_NS + 1),
        Some((request(1), SpawnState::Queued))
    );
    assert_eq!(c.scheduler.active(3), Some(d));
    assert_eq!(c.scheduler.stats().actual_ns, 0);
    assert_eq!(c.scheduler.cpu_spent_ns(3), Ok(d.reserved_ns));
    assert_eq!(c.scheduler.thread_count(), 1);
    assert_eq!(q.stats().live, 0);
    assert!(c.constructed.is_empty());
    c.scheduler
        .complete(d, 500, RunState::Blocked, first + 500)
        .unwrap();
    assert_eq!(
        c.service(&mut q, WINDOW_NS + 2),
        Some((request(1), SpawnState::Created(key(0x1001))))
    );
    assert_eq!(c.scheduler.stats().actual_ns, 500);
    assert_eq!(c.scheduler.thread_cpu_ns(key(800)), Ok(500));
    assert_eq!(c.scheduler.active(3), None);
}

#[test]
fn every_deferred_attempt_reauthorizes_and_retains_the_original_deadline() {
    for terminal in [Error::Auth, Error::Expired] {
        let deadline = 97_000_000;
        let mut c = Creator::new(deadline);
        let mut q = queue();
        q.submit(request(1), 90_000_000, &mut c).unwrap();
        assert_eq!(
            c.service(&mut q, 95_000_000),
            Some((request(1), SpawnState::Queued))
        );
        assert_eq!(c.scheduler.thread_count(), 0);
        assert_eq!(q.stats().wait_ns, 0);
        c.denied = terminal == Error::Auth;
        let now = if c.denied { 96_000_000 } else { deadline };
        assert_eq!(
            c.service(&mut q, now),
            Some((request(1), SpawnState::Failed(terminal)))
        );
        assert_eq!(
            c.attempted,
            [request(1)],
            "authorization failure cannot enter construction"
        );
        assert!(c.constructed.is_empty());
        assert_eq!(q.stats().live, 0);
        assert_eq!(q.stats().pending, 0);
        assert_eq!(q.stats().rejected, 1);
        assert_eq!(q.request(request(1).caller, 1), Ok(request(1)));
        assert_eq!(c.deadline, deadline);
        c.denied = false;
        assert_eq!(
            q.submit(request(1), WINDOW_NS, &mut c),
            Ok(SpawnState::Failed(terminal))
        );
        assert_eq!(c.service(&mut q, WINDOW_NS), None);
        assert_eq!(c.attempted.len(), 1);
        assert_eq!(c.scheduler.thread_count(), 0);
    }
}

#[test]
fn externally_unknown_or_failed_construction_can_never_become_deferred() {
    let mut c = Creator::new(4 * WINDOW_NS);
    c.uncertain = true;
    let mut q = queue();
    q.submit(request(1), 0, &mut c).unwrap();
    assert_eq!(
        c.service(&mut q, 0),
        Some((request(1), SpawnState::Unknown))
    );
    assert_eq!(q.stats().live, 1);
    assert_eq!(c.scheduler.thread_count(), 1);
    assert_eq!(
        q.reconcile(request(1).caller, 1, CreateOutcome::Deferred),
        Err(Error::Conflict)
    );
    assert_eq!(q.query(request(1).caller, 1), Ok(SpawnState::Unknown));
    assert_eq!(q.cancel(request(1).caller, 1), Err(Error::Busy));
    assert_eq!(
        q.submit(request(1), WINDOW_NS, &mut c),
        Ok(SpawnState::Unknown)
    );
    assert_eq!(c.service(&mut q, WINDOW_NS), None);
    assert_eq!(c.constructed, [key(0x1001)]);
    assert_eq!(q.stats().live, 1);
    // Only actual cleanup followed by a definitive terminal reconciliation may
    // release ownership; that retained failure is still never a new admission.
    c.scheduler.remove(key(0x1001)).unwrap();
    assert_eq!(
        q.reconcile(request(1).caller, 1, CreateOutcome::Rejected(Error::Io)),
        Ok(SpawnState::Failed(Error::Io))
    );
    assert_eq!(
        q.reconcile(request(1).caller, 1, CreateOutcome::Deferred),
        Err(Error::Conflict)
    );
    assert_eq!(
        q.submit(request(1), 2 * WINDOW_NS, &mut c),
        Ok(SpawnState::Failed(Error::Io))
    );
    assert_eq!(c.service(&mut q, 2 * WINDOW_NS), None);
    assert_eq!(c.constructed.len(), 1);
    assert_eq!(q.stats().live, 0);
}

#[test]
fn reservation_is_real_and_static_errors_remain_terminal_under_dynamic_pressure() {
    let mut s = Scheduler::new();
    s.register_group(key(5)).unwrap();
    let original = spec(800, 0, CPU_BUDGET_NS);
    let reservation = s.prepare_admission(original, layout(), 0).unwrap().unwrap();
    assert_eq!(reservation.key(), original.key);
    assert_eq!(s.thread_count(), 1);
    assert_eq!(s.committed_ns(3), CPU_BUDGET_NS);
    assert_eq!(
        s.prepare_admission(spec(900, 10_000_000, 10_000_000), layout(), 0),
        Ok(None)
    );
    assert_eq!(
        s.prepare_admission(original, layout(), 0),
        Err(Error::Exists)
    );
    for invalid in [
        spec(900, 0, 0),
        spec(900, 0, CPU_BUDGET_NS + 1),
        spec(900, 11, 10),
    ] {
        assert_eq!(
            s.prepare_admission(invalid, layout(), 0),
            Err(Error::Budget)
        );
    }
    assert_eq!(
        s.prepare_admission(
            ThreadSpec {
                allowed_mask: 0,
                ..spec(900, 0, 10)
            },
            layout(),
            0
        ),
        Err(Error::Auth)
    );
    assert_eq!(
        s.prepare_admission(
            ThreadSpec {
                group: key(6),
                ..spec(900, 0, 10)
            },
            layout(),
            0
        ),
        Err(Error::Stale)
    );
    assert_eq!(s.thread_count(), 1);
    assert_eq!(s.committed_ns(3), CPU_BUDGET_NS);
    assert_eq!(s.stats().actual_ns, 0);
}

#[test]
fn occupied_scheduler_slots_wait_for_real_retirement_without_evicting_identity() {
    let mut s = Scheduler::new();
    s.register_group(key(5)).unwrap();
    for id in 1..=64 {
        s.admit(spec(id, 0, 1_000), layout(), 0).unwrap();
    }
    let pending = spec(900, 10_000_000, 10_000_000);
    assert_eq!(s.prepare_admission(pending, layout(), 0), Ok(None));
    assert_eq!(s.thread_count(), 64);
    for id in 1..=64 {
        assert_eq!(s.thread_cpu_ns(key(id)), Ok(0));
    }
    let d = s.dispatch(3, layout(), 0, 100).unwrap().unwrap();
    assert_eq!(s.remove(d.thread), Err(Error::Busy));
    assert_eq!(s.prepare_admission(pending, layout(), 1), Ok(None));
    assert_eq!(s.active(3), Some(d));
    s.complete(d, 100, RunState::Exited, 100).unwrap();
    s.remove(d.thread).unwrap();
    let reservation = s
        .prepare_admission(pending, layout(), 100)
        .unwrap()
        .unwrap();
    assert_eq!(reservation.key(), pending.key);
    assert_eq!(s.thread_count(), 64);
    assert_eq!(
        s.cpu_spent_ns(3),
        Ok(100),
        "real retirement never refunds actual work"
    );
    assert_eq!(s.stats().actual_ns, 100);
    assert_eq!(
        s.prepare_admission(pending, layout(), 100),
        Err(Error::Exists)
    );
}
