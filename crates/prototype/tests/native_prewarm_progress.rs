//! Production scheduling seams with explicit host ownership/credit fixtures.
//! No replay receipt, label or adoption authority is created.
#[path = "../../../kernel/src/runtime/learning/learning_replay/prewarm_progress.rs"]
mod progress;
use progress::{Owner, Queue, Reason};
fn owner() -> Owner {
    Owner {
        phase: 3,
        trial_kind: 2,
        domain: 1,
        kind: 2,
        preparation: 7,
        boot: 1,
        trial: 9,
        token: 8,
        target: 3,
        seed: 1,
        claimed: true,
        prepared: true,
        scope: false,
        first: false,
        activated: false,
        paused: false,
        error: false,
    }
}
fn queue() -> Queue {
    Queue {
        serial: 4,
        seed: 1,
        target: 3,
        has_scope: false,
        first: false,
        stopped: false,
        fault: false,
        warm_queued: false,
        warm_phase: 0,
        warm_at: 100,
    }
}
#[test]
fn only_actual_owned_due_or_retired_core_warm_gets_service() {
    assert_eq!(
        progress::reason(owner(), queue(), true, true, 100, true, 0),
        Some(Reason::EnqueueDue)
    );
    assert_eq!(
        progress::reason(owner(), queue(), true, true, 99, true, 0),
        None
    );
    let mut q = queue();
    q.warm_queued = true;
    q.warm_phase = 1;
    assert_eq!(progress::reason(owner(), q, true, true, 100, true, 1), None);
    q.warm_phase = 3;
    assert_eq!(
        progress::reason(owner(), q, true, true, 100, true, 0),
        Some(Reason::RetiredReady)
    );
    for modify in 0..13 {
        let mut o = owner();
        match modify {
            0 => o.claimed = false,
            1 => o.prepared = false,
            2 => o.scope = true,
            3 => o.first = true,
            4 => o.activated = true,
            5 => o.paused = true,
            6 => o.error = true,
            7 => o.kind = 1,
            8 => o.preparation = 0,
            9 => o.token = 0,
            10 => o.boot = 0,
            11 => o.target = 0,
            _ => o.phase = 4,
        };
        assert_eq!(progress::reason(o, queue(), true, true, 100, true, 0), None);
    }
    assert_eq!(
        progress::reason(owner(), queue(), false, true, 100, true, 0),
        None
    );
    assert_eq!(
        progress::reason(owner(), queue(), true, false, 100, true, 0),
        None
    );
    let mut stale = queue();
    stale.seed = 2;
    assert_eq!(
        progress::reason(owner(), stale, true, true, 100, true, 0),
        None
    );
    let mut frozen = queue();
    frozen.first = true;
    assert_eq!(
        progress::reason(owner(), frozen, true, true, 100, true, 0),
        None
    );
}
#[test]
fn candidate_run_without_scope_and_stopped_admission_can_still_retry_freeze() {
    let mut candidate = owner();
    candidate.phase = 5;
    candidate.trial_kind = 1;
    assert_eq!(
        progress::reason(candidate, queue(), true, true, 100, true, 0),
        Some(Reason::EnqueueDue)
    );
    assert_eq!(
        progress::reason(candidate, queue(), true, true, 0, false, 0),
        Some(Reason::FreezeRetry)
    );
    assert_eq!(
        progress::reason(candidate, queue(), true, true, 0, false, 1),
        None
    );
    candidate.trial_kind = 2;
    assert_eq!(
        progress::reason(candidate, queue(), true, true, 100, true, 0),
        None
    );
}
#[test]
fn optional_piece_follows_every_general_rotation_even_when_credit_denied() {
    use core::cell::{Cell, RefCell};
    let phase = Cell::new(0);
    let events = RefCell::new(Vec::new());
    for _ in 0..22 {
        progress::after_general(
            || {
                events.borrow_mut().push("general");
                phase.set((phase.get() + 1) % 11);
            },
            || {
                events.borrow_mut().push("fresh-credit-denied");
                None::<()>
            },
        );
    }
    assert_eq!(phase.get(), 0);
    assert_eq!(events.borrow().len(), 44);
    assert!(
        events
            .borrow()
            .chunks_exact(2)
            .all(|e| e == ["general", "fresh-credit-denied"])
    );
}

#[path = "../../../kernel/src/runtime/tasks/domain_tasks/service_authority.rs"]
mod authority;
#[test]
fn additional_callback_uses_real_fresh_service_credit_and_settles_it_once() {
    use core::cell::Cell;
    use cyxia_prototype::domains::{
        ObjectKey,
        tasks::{CpuLayout, RunState, Scheduler, ThreadSpec},
    };
    let layout = CpuLayout {
        business_mask: 13,
        healthy_mask: 15,
        generation: 1,
    };
    let key = |id| ObjectKey { id, generation: 1 };
    let mut scheduler = Scheduler::new();
    scheduler.register_group(key(14)).unwrap();
    scheduler
        .admit(
            ThreadSpec {
                key: key(0x101),
                group: key(14),
                cpu: 0,
                allowed_mask: 1,
                minimum_ns: 20_000_000,
                budget_ns: 60_000_000,
            },
            layout,
            0,
        )
        .unwrap();
    let general = Cell::new(0);
    let work = Cell::new(0);
    progress::after_general(
        || general.set(general.get() + 1),
        || {
            let d = scheduler
                .dispatch_with_window_headroom(0, layout, 99_000_000, 2_500_000, 20_000_000)
                .unwrap()?;
            work.set(work.get() + 1);
            scheduler
                .complete(d, 10_000, RunState::Runnable, 99_010_000)
                .unwrap();
            Some(())
        },
    );
    assert_eq!((general.get(), work.get()), (1, 0));
    progress::after_general(
        || general.set(general.get() + 1),
        || {
            let d = scheduler
                .dispatch_with_window_headroom(0, layout, 100_000_000, 2_500_000, 20_000_000)
                .unwrap()?;
            authority::authorize(
                authority::View {
                    cpu: 0,
                    held: d,
                    actual: scheduler.active(0),
                    layout,
                    draining: 0,
                    quarantine: 0,
                    kind: 5,
                    published_credit_ns: d.reserved_ns,
                    settlement_pending: false,
                    execution_ns: Some(100),
                },
                100_000_100,
            )
            .unwrap();
            work.set(work.get() + 1);
            scheduler
                .complete(d, 10_000, RunState::Runnable, 100_010_000)
                .unwrap();
            assert!(scheduler.active(0).is_none());
            Some(())
        },
    );
    assert_eq!((general.get(), work.get()), (2, 1));
    assert_eq!(
        scheduler.cpu_window_usage(0, 100_010_000).unwrap(),
        (10_000, 0)
    );
}
